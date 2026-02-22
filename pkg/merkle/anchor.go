package merkle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

// AnchorClient persists a signed checkpoint digest to an external witness.
// Returned value is a provider-specific anchor entry identifier.
type AnchorClient interface {
	Anchor(ctx context.Context, checkpoint *Checkpoint) (string, error)
}

// AnchorContinuityVerifier validates that a checkpoint exists at a specific
// external witness entry ID.
type AnchorContinuityVerifier interface {
	VerifyCheckpoint(ctx context.Context, checkpoint *Checkpoint, expectedEntryID string) error
}

// NoopAnchorClient disables external anchoring.
type NoopAnchorClient struct{}

func (c *NoopAnchorClient) Anchor(_ context.Context, _ *Checkpoint) (string, error) {
	return "", nil
}

func (c *NoopAnchorClient) VerifyCheckpoint(_ context.Context, _ *Checkpoint, _ string) error {
	return fmt.Errorf("anchor continuity verification is unavailable when anchor mode is off")
}

// HashAnchorClient provides deterministic local anchoring for environments
// where no external transparency log is available.
type HashAnchorClient struct{}

func (c *HashAnchorClient) Anchor(_ context.Context, checkpoint *Checkpoint) (string, error) {
	if checkpoint == nil {
		return "", fmt.Errorf("checkpoint is nil")
	}
	payload, err := json.Marshal(map[string]any{
		"tree_size": checkpoint.TreeSize,
		"root_hash": checkpoint.RootHash,
		"timestamp": checkpoint.Timestamp.UTC().Format(time.RFC3339Nano),
		"signature": checkpoint.Signature,
	})
	if err != nil {
		return "", fmt.Errorf("marshaling checkpoint for local anchor: %w", err)
	}
	return "local:" + vaolcrypto.SHA256Prefixed(payload), nil
}

func (c *HashAnchorClient) VerifyCheckpoint(ctx context.Context, checkpoint *Checkpoint, expectedEntryID string) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint is nil")
	}
	expectedEntryID = strings.TrimSpace(expectedEntryID)
	if expectedEntryID == "" {
		return fmt.Errorf("expected entry_id is required")
	}
	computed, err := c.Anchor(ctx, checkpoint)
	if err != nil {
		return fmt.Errorf("computing local anchor digest: %w", err)
	}
	if computed != expectedEntryID {
		return fmt.Errorf("anchor continuity mismatch: checkpoint=%s expected=%s", computed, expectedEntryID)
	}
	return nil
}

// HTTPAnchorClient posts checkpoints to an external witness endpoint.
// Endpoint should accept JSON payload and return {"entry_id":"..."}.
type HTTPAnchorClient struct {
	Endpoint string
	Client   *http.Client
}

func (c *HTTPAnchorClient) Anchor(ctx context.Context, checkpoint *Checkpoint) (string, error) {
	if checkpoint == nil {
		return "", fmt.Errorf("checkpoint is nil")
	}
	if c.Endpoint == "" {
		return "", fmt.Errorf("anchor endpoint is required")
	}

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	payload, err := json.Marshal(checkpoint)
	if err != nil {
		return "", fmt.Errorf("marshaling checkpoint: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("creating anchor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("posting checkpoint to anchor endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("anchor endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		EntryID string `json:"entry_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding anchor response: %w", err)
	}
	if result.EntryID == "" {
		return "", fmt.Errorf("anchor response missing entry_id")
	}
	return result.EntryID, nil
}

func (c *HTTPAnchorClient) VerifyCheckpoint(ctx context.Context, checkpoint *Checkpoint, expectedEntryID string) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint is nil")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("anchor endpoint is required")
	}
	expectedEntryID = strings.TrimSpace(expectedEntryID)
	if expectedEntryID == "" {
		return fmt.Errorf("expected entry_id is required")
	}

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	payload, err := json.Marshal(map[string]any{
		"entry_id":   expectedEntryID,
		"checkpoint": checkpoint,
	})
	if err != nil {
		return fmt.Errorf("marshaling anchor verification request: %w", err)
	}

	verifyURL := strings.TrimRight(c.Endpoint, "/") + "/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating anchor verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting checkpoint verification request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("anchor verification endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		OK bool `json:"ok"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("decoding anchor verification response: %w", err)
		}
		if !result.OK {
			return fmt.Errorf("anchor verification response marked checkpoint as invalid")
		}
	}

	return nil
}
