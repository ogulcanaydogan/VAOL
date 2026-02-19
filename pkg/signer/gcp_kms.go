package signer

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GCPKMSBackend uses Cloud KMS REST APIs with OAuth bearer tokens.
type GCPKMSBackend struct {
	keyURI      string
	accessToken string
	endpoint    string
	client      *http.Client
}

// NewGCPKMSBackend creates a GCP KMS backend.
func NewGCPKMSBackend(cfg KMSConfig) (*GCPKMSBackend, error) {
	if cfg.KeyURI == "" {
		return nil, fmt.Errorf("gcp-kms requires key_uri")
	}
	if cfg.AccessToken == "" {
		return nil, fmt.Errorf("gcp-kms requires access token (config.access_token or GOOGLE_OAUTH_ACCESS_TOKEN)")
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		endpoint = "https://cloudkms.googleapis.com/v1"
	}
	return &GCPKMSBackend{
		keyURI:      strings.TrimPrefix(cfg.KeyURI, "/"),
		accessToken: cfg.AccessToken,
		endpoint:    endpoint,
		client:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (b *GCPKMSBackend) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	reqBody := map[string]any{
		"digest": map[string]string{
			"sha256": base64.StdEncoding.EncodeToString(digest),
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling gcp sign request: %w", err)
	}
	url := b.endpoint + "/" + b.keyURI + ":asymmetricSign"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating gcp sign request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling gcp sign endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp sign endpoint returned status %d", resp.StatusCode)
	}

	var parsed struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding gcp sign response: %w", err)
	}
	if parsed.Signature == "" {
		return nil, fmt.Errorf("gcp sign response missing signature")
	}
	return base64.StdEncoding.DecodeString(parsed.Signature)
}

func (b *GCPKMSBackend) PublicKey(ctx context.Context) ([]byte, error) {
	url := b.endpoint + "/" + b.keyURI + ":getPublicKey"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating gcp public key request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.accessToken)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling gcp public key endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp public key endpoint returned status %d", resp.StatusCode)
	}

	var parsed struct {
		PEM string `json:"pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding gcp public key response: %w", err)
	}
	if parsed.PEM == "" {
		return nil, fmt.Errorf("gcp public key response missing pem")
	}
	block, _ := pem.Decode([]byte(parsed.PEM))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in gcp public key response")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing gcp public key DER: %w", err)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

var _ KMSBackend = (*GCPKMSBackend)(nil)
