// Package signer — KMS/HSM signing backend.
//
// This module provides a signing and verification interface for cloud KMS
// (AWS KMS, GCP KMS, Azure Key Vault) and hardware security modules (PKCS#11).
// At MVP stage, it implements the interface with a pluggable backend pattern.

package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// KMSProvider identifies the cloud KMS provider.
type KMSProvider string

const (
	KMSProviderAWS   KMSProvider = "aws-kms"
	KMSProviderGCP   KMSProvider = "gcp-kms"
	KMSProviderAzure KMSProvider = "azure-keyvault"
	KMSProviderLocal KMSProvider = "local-ecdsa" // For testing — local ECDSA P-256
)

// KMSConfig configures the KMS signing backend.
type KMSConfig struct {
	Provider KMSProvider `json:"provider"`
	// KeyURI is the provider-specific key identifier.
	// AWS: arn:aws:kms:region:account:key/key-id
	// GCP: projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
	// Azure: https://vault-name.vault.azure.net/keys/key-name/version
	KeyURI    string `json:"key_uri"`
	Region    string `json:"region,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	// OAuth access token for cloud APIs (GCP/Azure). If empty, provider-specific
	// environment variables are used.
	AccessToken string `json:"access_token,omitempty"`
	// Optional endpoint override for testing/self-hosted gateways.
	Endpoint string `json:"endpoint,omitempty"`
}

// KMSSigner signs payloads using a cloud KMS or HSM backend.
type KMSSigner struct {
	config  KMSConfig
	keyID   string
	backend KMSBackend
}

// KMSBackend is the interface that cloud-specific implementations must satisfy.
type KMSBackend interface {
	// Sign signs the digest with the KMS key and returns the signature bytes.
	Sign(ctx context.Context, digest []byte) ([]byte, error)

	// PublicKey returns the DER-encoded public key.
	PublicKey(ctx context.Context) ([]byte, error)
}

// NewKMSSigner creates a KMS signer with the given configuration and backend.
func NewKMSSigner(cfg KMSConfig, backend KMSBackend) *KMSSigner {
	return &KMSSigner{
		config:  cfg,
		keyID:   fmt.Sprintf("%s:%s", cfg.Provider, cfg.KeyURI),
		backend: backend,
	}
}

func (s *KMSSigner) Sign(ctx context.Context, payload []byte) (Signature, error) {
	digest := sha256.Sum256(payload)
	sigBytes, err := s.backend.Sign(ctx, digest[:])
	if err != nil {
		return Signature{}, fmt.Errorf("kms sign: %w", err)
	}

	return Signature{
		KeyID:     s.keyID,
		Sig:       b64Encode(sigBytes),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *KMSSigner) KeyID() string     { return s.keyID }
func (s *KMSSigner) Algorithm() string { return fmt.Sprintf("kms-%s", s.config.Provider) }

// KMSVerifier verifies signatures produced by a KMS signer.
type KMSVerifier struct {
	keyID   string
	backend KMSBackend
}

// NewKMSVerifier creates a KMS verifier.
func NewKMSVerifier(keyID string, backend KMSBackend) *KMSVerifier {
	return &KMSVerifier{keyID: keyID, backend: backend}
}

func (v *KMSVerifier) Verify(ctx context.Context, payload []byte, sig Signature) error {
	if expectedKeyID := strings.TrimSpace(v.keyID); expectedKeyID != "" {
		gotKeyID := strings.TrimSpace(sig.KeyID)
		if gotKeyID == "" {
			return fmt.Errorf("kms signature missing keyid")
		}
		if gotKeyID != expectedKeyID {
			return fmt.Errorf("kms keyid mismatch: got %q want %q", gotKeyID, expectedKeyID)
		}
	}
	if strings.TrimSpace(sig.Timestamp) != "" {
		if _, err := time.Parse(time.RFC3339, sig.Timestamp); err != nil {
			return fmt.Errorf("invalid kms signature timestamp: %w", err)
		}
	}

	sigBytes, err := b64Decode(sig.Sig)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	pubDER, err := v.backend.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("getting public key: %w", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}

	digest := sha256.Sum256(payload)

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

func (v *KMSVerifier) KeyID() string { return v.keyID }

// NewKMSBackend creates a provider-specific backend implementation.
func NewKMSBackend(cfg KMSConfig) (KMSBackend, error) {
	switch cfg.Provider {
	case KMSProviderLocal, "":
		return NewLocalECDSABackend()
	case KMSProviderAWS:
		return NewAWSKMSBackend(cfg)
	case KMSProviderGCP:
		if cfg.AccessToken == "" {
			cfg.AccessToken = os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN")
		}
		return NewGCPKMSBackend(cfg)
	case KMSProviderAzure:
		if cfg.AccessToken == "" {
			cfg.AccessToken = os.Getenv("AZURE_OAUTH_ACCESS_TOKEN")
		}
		return NewAzureKeyVaultBackend(cfg)
	default:
		return nil, fmt.Errorf("unsupported KMS provider %q", cfg.Provider)
	}
}

// --- Local ECDSA backend for testing ---

// LocalECDSABackend is a local ECDSA P-256 signer for testing the KMS interface
// without requiring an actual cloud KMS.
type LocalECDSABackend struct {
	privKey *ecdsa.PrivateKey
}

// NewLocalECDSABackend generates a new local ECDSA P-256 key pair.
func NewLocalECDSABackend() (*LocalECDSABackend, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}
	return &LocalECDSABackend{privKey: key}, nil
}

func (b *LocalECDSABackend) Sign(_ context.Context, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, b.privKey, digest)
}

func (b *LocalECDSABackend) PublicKey(_ context.Context) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&b.privKey.PublicKey)
}

// PublicKeyPEM returns the public key in PEM format.
func (b *LocalECDSABackend) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&b.privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Ensure LocalECDSABackend implements KMSBackend.
var _ KMSBackend = (*LocalECDSABackend)(nil)

// Ensure interface compliance.
var _ Signer = (*KMSSigner)(nil)
var _ Verifier = (*KMSVerifier)(nil)
