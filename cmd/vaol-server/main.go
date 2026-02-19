// Command vaol-server runs the VAOL ledger server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yapay-ai/vaol/pkg/api"
	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/policy"
	"github.com/yapay-ai/vaol/pkg/signer"
	"github.com/yapay-ai/vaol/pkg/store"
)

func main() {
	var (
		addr               = flag.String("addr", ":8080", "server listen address")
		dsn                = flag.String("dsn", "", "PostgreSQL connection string")
		keyPath            = flag.String("key", "", "Ed25519 private key PEM path")
		signerMode         = flag.String("signer-mode", "ed25519", "signing backend: ed25519, sigstore, kms")
		sigstoreFulcioURL  = flag.String("sigstore-fulcio-url", "", "Sigstore Fulcio URL")
		sigstoreRekorURL   = flag.String("sigstore-rekor-url", "", "Sigstore Rekor URL")
		sigstoreOIDCIssuer = flag.String("sigstore-oidc-issuer", "", "Sigstore OIDC issuer")
		sigstoreOIDCClient = flag.String("sigstore-oidc-client-id", "", "Sigstore OIDC client ID")
		sigstoreToken      = flag.String("sigstore-identity-token", "", "Sigstore identity token")
		sigstoreRequireRek = flag.Bool("sigstore-rekor-required", false, "require Rekor entry creation/verification for Sigstore signatures")
		kmsProvider        = flag.String("kms-provider", string(signer.KMSProviderLocal), "KMS provider: aws-kms, gcp-kms, azure-keyvault, local-ecdsa")
		kmsKeyURI          = flag.String("kms-key-uri", "local://vaol-signing", "KMS key URI")
		kmsAccessToken     = flag.String("kms-access-token", "", "OAuth access token for GCP/Azure KMS REST backends")
		kmsEndpoint        = flag.String("kms-endpoint", "", "optional KMS endpoint override")
		opaURL             = flag.String("opa-url", "", "OPA endpoint URL (e.g., http://localhost:8181)")
		opaPolicy          = flag.String("opa-policy", "v1/data/vaol/decision", "OPA policy path")
		policyMode         = flag.String("policy-mode", "fail-closed", "policy mode: fail-closed or allow-all")
		authMode           = flag.String("auth-mode", "required", "auth mode: disabled, optional, required")
		jwtIssuer          = flag.String("jwt-issuer", "", "expected JWT issuer")
		jwtAudience        = flag.String("jwt-audience", "", "expected JWT audience")
		jwtTenantClaim     = flag.String("jwt-tenant-claim", "tenant_id", "JWT claim name containing tenant ID")
		jwtSubjectClaim    = flag.String("jwt-subject-claim", "sub", "JWT claim name containing subject ID")
		jwksFile           = flag.String("jwks-file", "", "path to JWKS file for JWT verification")
		jwksURL            = flag.String("jwks-url", "", "JWKS URL for JWT verification")
		jwtHS256Secret     = flag.String("jwt-hs256-secret", "", "shared secret for HS256 JWT verification (dev/test)")
		jwtClockSkew       = flag.Duration("jwt-clock-skew", 30*time.Second, "allowed JWT clock skew")
		webDir             = flag.String("web-dir", "", "path to auditor web UI directory (serves at /ui/)")
		checkpointEvery    = flag.Int64("checkpoint-every", 100, "persist a signed checkpoint every N records")
		checkpointInterval = flag.Duration("checkpoint-interval", 5*time.Minute, "persist a signed checkpoint at least every duration")
		anchorMode         = flag.String("anchor-mode", "local", "checkpoint anchoring mode: off, local, http")
		anchorURL          = flag.String("anchor-url", "", "checkpoint anchoring endpoint URL (required when anchor-mode=http)")
		rebuildOnStart     = flag.Bool("rebuild-on-start", true, "rebuild Merkle tree from persisted records on startup")
		failOnStartupCheck = flag.Bool("fail-on-startup-check", true, "fail startup when integrity rebuild/checkpoint validation fails")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Store
	var st store.Store
	if *dsn != "" {
		pgStore, err := store.Connect(context.Background(), *dsn)
		if err != nil {
			logger.Error("failed to connect to postgres", "error", err)
			os.Exit(1)
		}
		if err := pgStore.Migrate(context.Background()); err != nil {
			logger.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}
		st = pgStore
		logger.Info("using PostgreSQL store")
	} else {
		st = store.NewMemoryStore()
		logger.Info("using in-memory store (data will not persist)")
	}
	defer st.Close()

	sigstoreCfg := signer.DefaultSigstoreConfig()
	if *sigstoreFulcioURL != "" {
		sigstoreCfg.FulcioURL = *sigstoreFulcioURL
	}
	if *sigstoreRekorURL != "" {
		sigstoreCfg.RekorURL = *sigstoreRekorURL
	}
	if *sigstoreOIDCIssuer != "" {
		sigstoreCfg.OIDCIssuer = *sigstoreOIDCIssuer
	}
	if *sigstoreOIDCClient != "" {
		sigstoreCfg.OIDCClientID = *sigstoreOIDCClient
	}
	if *sigstoreToken != "" {
		sigstoreCfg.IdentityToken = *sigstoreToken
	}
	sigstoreCfg.RequireRekor = *sigstoreRequireRek

	kmsCfg := signer.KMSConfig{
		Provider:    signer.KMSProvider(*kmsProvider),
		KeyURI:      *kmsKeyURI,
		AccessToken: *kmsAccessToken,
		Endpoint:    *kmsEndpoint,
	}

	sig, verifiers, err := buildSignerAndVerifiers(*signerMode, *keyPath, sigstoreCfg, kmsCfg, logger)
	if err != nil {
		logger.Error("failed to configure signer", "error", err)
		os.Exit(1)
	}

	// Merkle tree
	tree := merkle.New()

	// Policy engine
	var pol policy.Engine
	mode := strings.ToLower(strings.TrimSpace(*policyMode))
	if mode != "fail-closed" && mode != "allow-all" {
		logger.Error("invalid policy mode", "policy_mode", *policyMode, "allowed", "fail-closed, allow-all")
		os.Exit(1)
	}

	if *opaURL != "" {
		opaCfg := policy.OPAConfig{
			Endpoint:   *opaURL,
			PolicyPath: *opaPolicy,
		}
		opaEngine := policy.NewOPAEngine(opaCfg)
		if mode == "fail-closed" {
			pol = policy.NewFailClosedEngine(opaEngine, logger)
			logger.Info("using OPA policy engine (fail-closed)", "endpoint", *opaURL)
		} else {
			pol = opaEngine
			logger.Warn("using OPA policy engine without fail-closed wrapper", "endpoint", *opaURL)
		}
	} else {
		if mode == "fail-closed" {
			pol = policy.NewDenyAllEngine("missing_policy_engine", "policy engine not configured")
			logger.Warn("no policy engine configured; denying all requests (fail-closed mode)")
		} else {
			pol = &policy.NoopEngine{}
			logger.Warn("no policy engine configured, using noop allow-all mode (development only)")
		}
	}

	// Server
	cfg := api.Config{
		Addr:               *addr,
		WebDir:             *webDir,
		CheckpointEvery:    *checkpointEvery,
		CheckpointInterval: *checkpointInterval,
		AnchorMode:         *anchorMode,
		AnchorURL:          *anchorURL,
		AuthMode:           *authMode,
		JWTIssuer:          *jwtIssuer,
		JWTAudience:        *jwtAudience,
		JWTTenantClaim:     *jwtTenantClaim,
		JWTSubjectClaim:    *jwtSubjectClaim,
		JWKSFile:           *jwksFile,
		JWKSURL:            *jwksURL,
		JWTHS256Secret:     *jwtHS256Secret,
		JWTClockSkew:       *jwtClockSkew,
		RebuildOnStart:     *rebuildOnStart,
		FailOnStartupCheck: *failOnStartupCheck,
	}

	srv := api.NewServer(cfg, st, sig, verifiers, tree, pol, logger)

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.Start(); err != nil {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	fmt.Fprintf(os.Stderr, "VAOL server listening on %s\n", *addr)
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10_000_000_000)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", "error", err)
	}
}

func buildSignerAndVerifiers(
	mode string,
	keyPath string,
	sigstoreCfg signer.SigstoreConfig,
	kmsCfg signer.KMSConfig,
	logger *slog.Logger,
) (signer.Signer, []signer.Verifier, error) {
	switch mode {
	case "ed25519":
		var sig *signer.Ed25519Signer
		if keyPath != "" {
			privKey, err := signer.LoadPrivateKeyPEM(keyPath)
			if err != nil {
				return nil, nil, fmt.Errorf("loading Ed25519 key: %w", err)
			}
			sig = signer.NewEd25519Signer(privKey)
			logger.Info("using Ed25519 signer", "key_id", sig.KeyID())
		} else {
			generated, err := signer.GenerateEd25519Signer()
			if err != nil {
				return nil, nil, fmt.Errorf("generating Ed25519 key: %w", err)
			}
			sig = generated
			logger.Warn("using ephemeral Ed25519 key (not for production)", "key_id", sig.KeyID())
		}
		return sig, []signer.Verifier{signer.NewEd25519Verifier(sig.PublicKey())}, nil

	case "sigstore":
		sig := signer.NewSigstoreSigner(sigstoreCfg)
		ver := signer.NewSigstoreVerifier(sigstoreCfg)
		logger.Info("using Sigstore keyless signer", "fulcio_url", sigstoreCfg.FulcioURL, "rekor_url", sigstoreCfg.RekorURL)
		return sig, []signer.Verifier{ver}, nil

	case "kms":
		if kmsCfg.Provider == "" {
			kmsCfg.Provider = signer.KMSProviderLocal
		}
		if kmsCfg.KeyURI == "" {
			kmsCfg.KeyURI = "local://vaol-signing"
		}
		backend, err := signer.NewKMSBackend(kmsCfg)
		if err != nil {
			return nil, nil, fmt.Errorf("creating KMS backend: %w", err)
		}

		sig := signer.NewKMSSigner(kmsCfg, backend)
		ver := signer.NewKMSVerifier(sig.KeyID(), backend)
		logger.Info("using KMS signer backend", "provider", kmsCfg.Provider, "key_uri", kmsCfg.KeyURI)
		return sig, []signer.Verifier{ver}, nil

	default:
		return nil, nil, fmt.Errorf("unsupported signer mode: %s", mode)
	}
}
