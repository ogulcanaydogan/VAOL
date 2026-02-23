package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

// RekorClient verifies transparency-log entries for strict profile checks.
type RekorClient interface {
	VerifyEntry(ctx context.Context, baseURL, entryID string, payload []byte) error
}

// HTTPRekorClient verifies Rekor entries over HTTP.
type HTTPRekorClient struct {
	client *http.Client
}

// NewHTTPRekorClient builds a Rekor client. If client is nil, http.DefaultClient is used.
func NewHTTPRekorClient(client *http.Client) *HTTPRekorClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPRekorClient{client: client}
}

// VerifyEntry validates that entryID exists and binds to payload bytes via spec.payload_hash.
func (c *HTTPRekorClient) VerifyEntry(ctx context.Context, baseURL, entryID string, payload []byte) error {
	baseURL = strings.TrimSpace(baseURL)
	entryID = strings.TrimSpace(entryID)

	if baseURL == "" {
		return fmt.Errorf("missing rekor url")
	}
	if entryID == "" {
		return fmt.Errorf("missing rekor entry id")
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/api/v1/log/entries/" + entryID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating Rekor request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("querying Rekor entry %q: %w", entryID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading Rekor response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Rekor entry lookup failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	payloadHash, err := extractRekorPayloadHash(body)
	if err != nil {
		return err
	}

	expected := vaolcrypto.SHA256Prefixed(payload)
	if payloadHash != expected {
		return fmt.Errorf("payload hash mismatch: expected %s got %s", expected, payloadHash)
	}
	return nil
}

func extractRekorPayloadHash(body []byte) (string, error) {
	hash, found, err := findPayloadHash(json.RawMessage(body), 0)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("missing spec.payload_hash in Rekor entry")
	}
	return hash, nil
}

func findPayloadHash(raw json.RawMessage, depth int) (string, bool, error) {
	if depth > 8 || len(raw) == 0 {
		return "", false, nil
	}

	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		str = strings.TrimSpace(str)
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			decoded, decodeErr := enc.DecodeString(str)
			if decodeErr != nil {
				continue
			}
			hash, found, err := findPayloadHash(json.RawMessage(decoded), depth+1)
			if err != nil || found {
				return hash, found, err
			}
		}
		return "", false, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", false, nil
	}

	if hash, found, err := payloadHashFromObject(obj, depth); found || err != nil {
		return hash, found, err
	}

	for _, child := range obj {
		hash, found, err := findPayloadHash(child, depth+1)
		if err != nil || found {
			return hash, found, err
		}
	}

	return "", false, nil
}

func payloadHashFromObject(obj map[string]json.RawMessage, depth int) (string, bool, error) {
	if specRaw, ok := obj["spec"]; ok {
		var spec map[string]json.RawMessage
		if err := json.Unmarshal(specRaw, &spec); err == nil {
			if payloadHashRaw, ok := spec["payload_hash"]; ok {
				var payloadHash string
				if err := json.Unmarshal(payloadHashRaw, &payloadHash); err != nil {
					return "", false, fmt.Errorf("invalid spec.payload_hash field: %w", err)
				}
				payloadHash = strings.TrimSpace(payloadHash)
				if payloadHash == "" {
					return "", false, fmt.Errorf("missing spec.payload_hash in Rekor entry")
				}
				return payloadHash, true, nil
			}
		}
	}

	if payloadHashRaw, ok := obj["payload_hash"]; ok {
		var payloadHash string
		if err := json.Unmarshal(payloadHashRaw, &payloadHash); err != nil {
			return "", false, fmt.Errorf("invalid payload_hash field: %w", err)
		}
		payloadHash = strings.TrimSpace(payloadHash)
		if payloadHash == "" {
			return "", false, fmt.Errorf("missing spec.payload_hash in Rekor entry")
		}
		return payloadHash, true, nil
	}

	if bodyRaw, ok := obj["body"]; ok {
		hash, found, err := findPayloadHash(bodyRaw, depth+1)
		if err != nil || found {
			return hash, found, err
		}
	}

	return "", false, nil
}
