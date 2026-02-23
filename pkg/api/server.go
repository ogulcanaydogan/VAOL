// Package api provides the HTTP REST API server for the VAOL ledger.
package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/auth"
	"github.com/ogulcanaydogan/vaol/pkg/ingest"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/policy"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
	"github.com/ogulcanaydogan/vaol/pkg/verifier"
)

// Config holds the server configuration.
type Config struct {
	Version                     string        `json:"version"`
	Addr                        string        `json:"addr"`
	ReadTimeout                 time.Duration `json:"read_timeout"`
	WriteTimeout                time.Duration `json:"write_timeout"`
	WebDir                      string        `json:"web_dir"`                       // Path to auditor web UI directory (optional)
	VerificationRevocationsFile string        `json:"verification_revocations_file"` // Path to verifier key revocation list JSON
	CheckpointEvery             int64         `json:"checkpoint_every"`
	CheckpointInterval          time.Duration `json:"checkpoint_interval"`
	AnchorMode                  string        `json:"anchor_mode"` // off, local, http
	AnchorURL                   string        `json:"anchor_url"`
	AnchorContinuityRequired    bool          `json:"anchor_continuity_required"`
	AuthMode                    string        `json:"auth_mode"` // disabled, optional, required
	JWTIssuer                   string        `json:"jwt_issuer"`
	JWTAudience                 string        `json:"jwt_audience"`
	JWTTenantClaim              string        `json:"jwt_tenant_claim"`
	JWTSubjectClaim             string        `json:"jwt_subject_claim"`
	JWKSFile                    string        `json:"jwks_file"`
	JWKSURL                     string        `json:"jwks_url"`
	JWTHS256Secret              string        `json:"jwt_hs256_secret"`
	JWTClockSkew                time.Duration `json:"jwt_clock_skew"`
	RebuildOnStart              bool          `json:"rebuild_on_start"`
	FailOnStartupCheck          bool          `json:"fail_on_startup_check"`
	IngestMode                  string        `json:"ingest_mode"` // off, kafka
	IngestKafkaBrokers          []string      `json:"ingest_kafka_brokers"`
	IngestKafkaTopic            string        `json:"ingest_kafka_topic"`
	IngestKafkaClient           string        `json:"ingest_kafka_client"`
	IngestKafkaRequired         bool          `json:"ingest_kafka_required"`
	IngestPublishTimeout        time.Duration `json:"ingest_publish_timeout"`
	EmbeddedWebFS               fs.FS         `json:"-"` // Embedded web UI filesystem (fallback when WebDir is empty)
}

// DefaultConfig returns sensible defaults for the server.
func DefaultConfig() Config {
	return Config{
		Version:                  "dev",
		Addr:                     ":8080",
		ReadTimeout:              30 * time.Second,
		WriteTimeout:             30 * time.Second,
		CheckpointEvery:          100,
		CheckpointInterval:       5 * time.Minute,
		AnchorMode:               "local",
		AnchorContinuityRequired: false,
		AuthMode:                 string(auth.ModeDisabled),
		JWTTenantClaim:           "tenant_id",
		JWTSubjectClaim:          "sub",
		JWTClockSkew:             30 * time.Second,
		RebuildOnStart:           true,
		FailOnStartupCheck:       true,
		IngestMode:               "off",
		IngestPublishTimeout:     2 * time.Second,
	}
}

// Server is the VAOL HTTP API server.
type Server struct {
	config           Config
	store            store.Store
	signer           signer.Signer
	verifiers        []signer.Verifier
	tree             *merkle.Tree
	policy           policy.Engine
	verifier         *verifier.Verifier
	authVerifier     *auth.Verifier
	authMode         auth.Mode
	checkpointSigner *merkle.CheckpointSigner
	anchorClient     merkle.AnchorClient
	ingestPublisher  ingest.Publisher
	lastCheckpointAt time.Time
	checkpointMu     sync.Mutex
	startupErr       error
	logger           *slog.Logger
	http             *http.Server
}

// NewServer creates a new API server.
func NewServer(
	cfg Config,
	st store.Store,
	sig signer.Signer,
	vers []signer.Verifier,
	tree *merkle.Tree,
	pol policy.Engine,
	logger *slog.Logger,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		config:           cfg,
		store:            st,
		signer:           sig,
		verifiers:        vers,
		tree:             tree,
		policy:           pol,
		verifier:         verifier.New(vers...),
		checkpointSigner: merkle.NewCheckpointSigner(sig),
		anchorClient:     newAnchorClient(cfg),
		lastCheckpointAt: time.Now().UTC(),
		logger:           logger,
	}

	if revocationPath := strings.TrimSpace(cfg.VerificationRevocationsFile); revocationPath != "" {
		if err := s.verifier.SetRevocationsFromFile(revocationPath); err != nil {
			s.startupErr = errors.Join(s.startupErr, fmt.Errorf("applying verification revocations: %w", err))
		} else {
			s.logger.Info("loaded verification revocations", "path", revocationPath)
		}
	}

	ingestPublisher, ingestErr := newIngestPublisher(cfg)
	if ingestErr != nil {
		if cfg.IngestKafkaRequired {
			s.startupErr = errors.Join(s.startupErr, fmt.Errorf("ingest publisher initialization: %w", ingestErr))
		} else {
			logger.Warn("ingest publisher initialization failed; disabling ingest events", "error", ingestErr)
		}
		s.ingestPublisher = ingest.NewNoopPublisher()
	} else {
		s.ingestPublisher = ingestPublisher
	}

	mode, err := auth.ParseMode(cfg.AuthMode)
	if err != nil {
		s.startupErr = fmt.Errorf("auth config: %w", err)
	} else {
		s.authMode = mode
		authVerifier, authErr := auth.NewVerifier(auth.Config{
			Mode:         mode,
			Issuer:       cfg.JWTIssuer,
			Audience:     cfg.JWTAudience,
			TenantClaim:  cfg.JWTTenantClaim,
			SubjectClaim: cfg.JWTSubjectClaim,
			JWKSFile:     cfg.JWKSFile,
			JWKSURL:      cfg.JWKSURL,
			HS256Secret:  cfg.JWTHS256Secret,
			ClockSkew:    cfg.JWTClockSkew,
		})
		if authErr != nil {
			s.startupErr = fmt.Errorf("auth verifier initialization: %w", authErr)
		} else {
			s.authVerifier = authVerifier
		}
	}

	if cfg.RebuildOnStart {
		if err := s.rebuildMerkleTreeFromStore(context.Background()); err != nil {
			if cfg.FailOnStartupCheck {
				s.startupErr = fmt.Errorf("startup ledger rebuild failed: %w", err)
			} else {
				s.logger.Error("startup ledger rebuild failed (continuing)", "error", err)
			}
		}
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.http = &http.Server{
		Addr:         cfg.Addr,
		Handler:      s.withMiddleware(mux),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/records", s.handleAppendRecord)
	mux.HandleFunc("GET /v1/records/{id}", s.handleGetRecord)
	mux.HandleFunc("GET /v1/records", s.handleListRecords)
	mux.HandleFunc("GET /v1/records/{id}/proof", s.handleGetProof)
	mux.HandleFunc("GET /v1/proofs/{id}", s.handleGetProofByID)
	mux.HandleFunc("POST /v1/verify", s.handleVerifyRecord)
	mux.HandleFunc("POST /v1/verify/record", s.handleVerifyRecord)
	mux.HandleFunc("POST /v1/verify/bundle", s.handleVerifyBundle)
	mux.HandleFunc("GET /v1/ledger/checkpoint", s.handleGetCheckpoint)
	mux.HandleFunc("GET /v1/ledger/checkpoints/latest", s.handleGetCheckpoint)
	mux.HandleFunc("GET /v1/ledger/consistency", s.handleGetConsistencyProof)
	mux.HandleFunc("POST /v1/export", s.handleExport)
	mux.HandleFunc("GET /v1/health", s.handleHealth)

	// Serve auditor web UI if configured
	if s.config.WebDir != "" {
		webFS := http.FileServer(http.Dir(s.config.WebDir))
		mux.Handle("/ui/", http.StripPrefix("/ui/", webFS))
		s.logger.Info("serving auditor web UI", "path", "/ui/", "dir", s.config.WebDir)
	} else if s.config.EmbeddedWebFS != nil {
		mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(s.config.EmbeddedWebFS))))
		s.logger.Info("serving embedded auditor web UI", "path", "/ui/")
	}
}

// Start begins listening for HTTP requests.
func (s *Server) Start() error {
	if s.startupErr != nil {
		return s.startupErr
	}
	s.logger.Info("starting VAOL server", "addr", s.config.Addr)
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// StartupError returns any initialization error captured during server creation.
func (s *Server) StartupError() error {
	return s.startupErr
}

// Handler returns the http.Handler for use in tests (e.g., httptest.NewServer).
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down VAOL server")
	shutdownErr := s.http.Shutdown(ctx)
	closeErr := error(nil)
	if s.ingestPublisher != nil {
		if err := s.ingestPublisher.Close(); err != nil {
			closeErr = fmt.Errorf("closing ingest publisher: %w", err)
		}
	}
	if shutdownErr != nil || closeErr != nil {
		return errors.Join(shutdownErr, closeErr)
	}
	return nil
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Request ID
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = fmt.Sprintf("vaol-%d", time.Now().UnixNano())
		}
		w.Header().Set("X-Request-ID", reqID)
		w.Header().Set("X-VAOL-Version", s.config.Version)

		// CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-VAOL-Tenant-ID, X-Tenant-ID, X-Auth-Issuer, X-Auth-Subject, X-Auth-Source")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.startupErr != nil {
			writeError(w, http.StatusServiceUnavailable, "server startup checks failed: %v", s.startupErr)
			return
		}

		if !shouldBypassAuth(r.URL.Path) {
			claims, err := s.authenticateRequest(r)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "authentication failed: %v", err)
				return
			}
			if claims != nil {
				r = auth.InjectTrustedHeaders(r, claims)
			}
		}

		// Serve
		next.ServeHTTP(w, r)

		// Log
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"request_id", reqID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func shouldBypassAuth(path string) bool {
	return path == "/v1/health" || strings.HasPrefix(path, "/ui/")
}

func newAnchorClient(cfg Config) merkle.AnchorClient {
	switch cfg.AnchorMode {
	case "", "off":
		return &merkle.NoopAnchorClient{}
	case "local":
		return &merkle.HashAnchorClient{}
	case "http":
		if cfg.AnchorURL == "" {
			return &merkle.NoopAnchorClient{}
		}
		return &merkle.HTTPAnchorClient{Endpoint: cfg.AnchorURL}
	default:
		return &merkle.NoopAnchorClient{}
	}
}

func newIngestPublisher(cfg Config) (ingest.Publisher, error) {
	mode := strings.TrimSpace(strings.ToLower(cfg.IngestMode))
	switch mode {
	case "", "off":
		return ingest.NewNoopPublisher(), nil
	case "kafka":
		topic := cfg.IngestKafkaTopic
		if strings.TrimSpace(topic) == "" {
			topic = "vaol.decision-records"
		}
		return ingest.NewKafkaPublisher(ingest.KafkaConfig{
			Brokers:      cfg.IngestKafkaBrokers,
			Topic:        topic,
			ClientID:     cfg.IngestKafkaClient,
			BatchTimeout: 10 * time.Millisecond,
		})
	default:
		return nil, fmt.Errorf("unsupported ingest mode: %s", cfg.IngestMode)
	}
}
