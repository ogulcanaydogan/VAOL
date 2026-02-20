// Command vaol-proxy is an OpenAI-compatible transparent proxy that
// automatically instruments LLM API calls and emits VAOL DecisionRecords.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/record"
)

func main() {
	var (
		addr       = flag.String("addr", ":8443", "proxy listen address")
		upstream   = flag.String("upstream", "https://api.openai.com", "upstream LLM API URL")
		vaolServer = flag.String("vaol-server", "http://localhost:8080", "VAOL server URL")
		tenantID   = flag.String("tenant-id", "default", "tenant identifier")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	upstreamURL, err := url.Parse(*upstream)
	if err != nil {
		logger.Error("invalid upstream URL", "error", err)
		os.Exit(1)
	}

	proxy := &Proxy{
		upstream:   upstreamURL,
		vaolServer: *vaolServer,
		tenantID:   *tenantID,
		logger:     logger,
		client:     &http.Client{Timeout: 120 * time.Second},
	}

	srv := &http.Server{
		Addr:         *addr,
		Handler:      proxy,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("VAOL proxy starting", "addr", *addr, "upstream", *upstream)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("proxy failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown failed", "error", err)
	}
}

// Proxy is the OpenAI-compatible transparent proxy.
type Proxy struct {
	upstream   *url.URL
	vaolServer string
	tenantID   string
	logger     *slog.Logger
	client     *http.Client
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.New()

	// Read and capture the request body
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(reqBody))

	// Forward to upstream
	proxyURL := *p.upstream
	proxyURL.Path = r.URL.Path
	proxyURL.RawQuery = r.URL.RawQuery

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, proxyURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "failed to create proxy request", http.StatusBadGateway)
		return
	}

	// Copy headers (except Host)
	for key, values := range r.Header {
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	proxyReq.Header.Del("Host")

	resp, err := p.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	latency := time.Since(start)

	// Add VAOL headers
	w.Header().Set("X-VAOL-Record-ID", requestID.String())
	w.Header().Set("X-VAOL-Proxy", "true")

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(respBody); err != nil {
		p.logger.Error("failed to write upstream response", "error", err)
		return
	}

	// Asynchronously emit DecisionRecord to VAOL server
	go p.emitRecord(requestID, reqBody, respBody, latency, r.URL.Path)
}

func (p *Proxy) emitRecord(requestID uuid.UUID, reqBody, respBody []byte, latency time.Duration, path string) {
	// Parse model info from request
	var chatReq struct {
		Model       string  `json:"model"`
		Temperature float64 `json:"temperature"`
		MaxTokens   int     `json:"max_tokens"`
	}
	if err := json.Unmarshal(reqBody, &chatReq); err != nil {
		p.logger.Warn("failed to parse request body for model metadata", "error", err)
	}

	rec := record.New()
	rec.RequestID = requestID
	rec.Identity.TenantID = p.tenantID
	rec.Identity.Subject = "vaol-proxy"
	rec.Identity.SubjectType = "service"
	rec.Model.Provider = p.upstream.Host
	rec.Model.Name = chatReq.Model
	rec.Model.Endpoint = p.upstream.String()

	temp := chatReq.Temperature
	rec.Parameters.Temperature = &temp
	if chatReq.MaxTokens > 0 {
		rec.Parameters.MaxTokens = &chatReq.MaxTokens
	}

	rec.PromptContext.UserPromptHash = vaolcrypto.SHA256Prefixed(reqBody)
	rec.Output.OutputHash = vaolcrypto.SHA256Prefixed(respBody)
	rec.Output.Mode = record.OutputModeHashOnly
	rec.Output.LatencyMs = float64(latency.Milliseconds())
	rec.PolicyContext.PolicyDecision = record.PolicyLogOnly

	// Post to VAOL server
	recJSON, err := json.Marshal(rec)
	if err != nil {
		p.logger.Error("failed to marshal record", "error", err)
		return
	}

	vaolURL := fmt.Sprintf("%s/v1/records", p.vaolServer)
	reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, vaolURL, bytes.NewReader(recJSON))
	if err != nil {
		p.logger.Error("failed to build VAOL request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VAOL-Tenant-ID", p.tenantID)
	req.Header.Set("X-Auth-Source", "vaol-proxy")
	req.Header.Set("X-Auth-Subject", "vaol-proxy")

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Error("failed to emit record to VAOL", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		p.logger.Error("VAOL server rejected record", "status", resp.StatusCode, "body", string(body))
		return
	}

	p.logger.Info("record emitted", "request_id", requestID, "model", chatReq.Model, "latency_ms", latency.Milliseconds())
}

// Ensure httputil is used (for potential future reverse proxy mode)
var _ = httputil.NewSingleHostReverseProxy
