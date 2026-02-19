package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// AzureKeyVaultBackend uses Azure Key Vault REST APIs with OAuth bearer tokens.
type AzureKeyVaultBackend struct {
	keyURI      string
	accessToken string
	client      *http.Client
}

// NewAzureKeyVaultBackend creates an Azure Key Vault backend.
func NewAzureKeyVaultBackend(cfg KMSConfig) (*AzureKeyVaultBackend, error) {
	if cfg.KeyURI == "" {
		return nil, fmt.Errorf("azure-keyvault requires key_uri")
	}
	if cfg.AccessToken == "" {
		return nil, fmt.Errorf("azure-keyvault requires access token (config.access_token or AZURE_OAUTH_ACCESS_TOKEN)")
	}
	return &AzureKeyVaultBackend{
		keyURI:      strings.TrimRight(cfg.KeyURI, "/"),
		accessToken: cfg.AccessToken,
		client:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (b *AzureKeyVaultBackend) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	url := b.keyURI + "/sign?api-version=7.4"
	reqBody := map[string]string{
		"alg":   "ES256",
		"value": base64.RawURLEncoding.EncodeToString(digest),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling azure sign request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating azure sign request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling azure sign endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure sign endpoint returned status %d", resp.StatusCode)
	}

	var parsed struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding azure sign response: %w", err)
	}
	if parsed.Value == "" {
		return nil, fmt.Errorf("azure sign response missing value")
	}
	return base64.RawURLEncoding.DecodeString(parsed.Value)
}

func (b *AzureKeyVaultBackend) PublicKey(ctx context.Context) ([]byte, error) {
	url := b.keyURI + "?api-version=7.4"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating azure public key request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.accessToken)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling azure public key endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure public key endpoint returned status %d", resp.StatusCode)
	}

	var parsed struct {
		Key struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding azure public key response: %w", err)
	}

	if parsed.Key.Kty != "EC" || parsed.Key.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported azure key type: kty=%s crv=%s", parsed.Key.Kty, parsed.Key.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(parsed.Key.X)
	if err != nil {
		return nil, fmt.Errorf("decoding azure key.x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(parsed.Key.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding azure key.y: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	return x509.MarshalPKIXPublicKey(pub)
}

var _ KMSBackend = (*AzureKeyVaultBackend)(nil)
