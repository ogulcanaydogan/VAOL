package verifier

import (
	"testing"
	"time"
)

func TestParseRevocationListValid(t *testing.T) {
	raw := []byte(`{
		"version": "v1",
		"generated_at": "2026-02-23T00:00:00Z",
		"revocations": [
			{
				"keyid": "ed25519:abc123",
				"effective_at": "2026-02-01T00:00:00Z",
				"reason": "compromised"
			}
		]
	}`)

	rules, err := ParseRevocationList(raw)
	if err != nil {
		t.Fatalf("ParseRevocationList error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(rules))
	}
	if rules[0].KeyID != "ed25519:abc123" {
		t.Fatalf("unexpected keyid: %s", rules[0].KeyID)
	}
	if rules[0].Reason != "compromised" {
		t.Fatalf("unexpected reason: %s", rules[0].Reason)
	}
	if rules[0].EffectiveAt.Format(time.RFC3339) != "2026-02-01T00:00:00Z" {
		t.Fatalf("unexpected effective_at: %s", rules[0].EffectiveAt.Format(time.RFC3339))
	}
}

func TestParseRevocationListRejectsBadTimestamp(t *testing.T) {
	raw := []byte(`{
		"revocations": [
			{
				"keyid": "ed25519:abc123",
				"effective_at": "not-a-time"
			}
		]
	}`)

	if _, err := ParseRevocationList(raw); err == nil {
		t.Fatal("expected ParseRevocationList to fail on invalid effective_at")
	}
}
