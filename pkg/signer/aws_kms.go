package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
)

// AWSKMSBackend uses AWS CLI for asymmetric signing and public key retrieval.
// This keeps VAOL self-hostable without mandatory SDK dependencies.
type AWSKMSBackend struct {
	keyURI string
	region string
}

// NewAWSKMSBackend creates an AWS CLI backed signer.
func NewAWSKMSBackend(cfg KMSConfig) (*AWSKMSBackend, error) {
	if cfg.KeyURI == "" {
		return nil, fmt.Errorf("aws-kms requires key_uri")
	}
	return &AWSKMSBackend{
		keyURI: cfg.KeyURI,
		region: cfg.Region,
	}, nil
}

func (b *AWSKMSBackend) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	args := []string{
		"kms", "sign",
		"--key-id", b.keyURI,
		"--message-type", "DIGEST",
		"--signing-algorithm", "ECDSA_SHA_256",
		"--message", base64.StdEncoding.EncodeToString(digest),
		"--output", "json",
	}
	if b.region != "" {
		args = append(args, "--region", b.region)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("aws kms sign failed: %w", err)
	}

	var resp struct {
		Signature string `json:"Signature"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("decoding aws sign response: %w", err)
	}
	if resp.Signature == "" {
		return nil, fmt.Errorf("aws sign response missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding aws signature: %w", err)
	}
	return sig, nil
}

func (b *AWSKMSBackend) PublicKey(ctx context.Context) ([]byte, error) {
	args := []string{
		"kms", "get-public-key",
		"--key-id", b.keyURI,
		"--output", "json",
	}
	if b.region != "" {
		args = append(args, "--region", b.region)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("aws kms get-public-key failed: %w", err)
	}

	var resp struct {
		PublicKey string `json:"PublicKey"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("decoding aws public key response: %w", err)
	}
	if resp.PublicKey == "" {
		return nil, fmt.Errorf("aws public key response missing key")
	}
	return base64.StdEncoding.DecodeString(resp.PublicKey)
}

var _ KMSBackend = (*AWSKMSBackend)(nil)
