package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

// RevocationRule blocks a key identifier at or after EffectiveAt.
type RevocationRule struct {
	KeyID       string    `json:"keyid"`
	EffectiveAt time.Time `json:"-"`
	Reason      string    `json:"reason,omitempty"`
}

// RevocationList is a file-backed rule set used by CLI and automation.
type RevocationList struct {
	Version     string               `json:"version,omitempty"`
	GeneratedAt string               `json:"generated_at,omitempty"`
	Revocations []RevocationListRule `json:"revocations"`
}

// RevocationListRule is the JSON-serializable form of a single revocation rule.
type RevocationListRule struct {
	KeyID       string `json:"keyid"`
	EffectiveAt string `json:"effective_at"`
	Reason      string `json:"reason,omitempty"`
}

type revocationWindow struct {
	effectiveAt time.Time
	reason      string
}

// ParseRevocationList parses and validates a revocation list JSON payload.
func ParseRevocationList(raw []byte) ([]RevocationRule, error) {
	var list RevocationList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parsing revocations json: %w", err)
	}

	if len(list.Revocations) == 0 {
		return nil, nil
	}

	out := make([]RevocationRule, 0, len(list.Revocations))
	for i, item := range list.Revocations {
		keyID := strings.TrimSpace(item.KeyID)
		if keyID == "" {
			return nil, fmt.Errorf("revocations[%d].keyid is required", i)
		}
		effective := strings.TrimSpace(item.EffectiveAt)
		if effective == "" {
			return nil, fmt.Errorf("revocations[%d].effective_at is required", i)
		}
		effectiveAt, err := time.Parse(time.RFC3339, effective)
		if err != nil {
			return nil, fmt.Errorf("revocations[%d].effective_at must be RFC3339: %w", i, err)
		}
		out = append(out, RevocationRule{
			KeyID:       keyID,
			EffectiveAt: effectiveAt.UTC(),
			Reason:      strings.TrimSpace(item.Reason),
		})
	}
	return out, nil
}

// LoadRevocationListFile reads and parses revocation rules from a JSON file.
func LoadRevocationListFile(path string) ([]RevocationRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading revocations file: %w", err)
	}
	return ParseRevocationList(raw)
}

// SetRevocationsFromFile loads and applies revocation rules from a JSON file.
func (v *Verifier) SetRevocationsFromFile(path string) error {
	rules, err := LoadRevocationListFile(path)
	if err != nil {
		return err
	}
	return v.SetRevocations(rules)
}

// SetRevocations replaces all revocation rules on the verifier.
func (v *Verifier) SetRevocations(rules []RevocationRule) error {
	compiled := make(map[string][]revocationWindow, len(rules))
	for i, rule := range rules {
		keyID := strings.TrimSpace(rule.KeyID)
		if keyID == "" {
			return fmt.Errorf("revocation rule %d has empty keyid", i)
		}
		if rule.EffectiveAt.IsZero() {
			return fmt.Errorf("revocation rule %d has zero effective_at", i)
		}
		compiled[keyID] = append(compiled[keyID], revocationWindow{
			effectiveAt: rule.EffectiveAt.UTC(),
			reason:      strings.TrimSpace(rule.Reason),
		})
	}

	for keyID := range compiled {
		sort.Slice(compiled[keyID], func(i, j int) bool {
			return compiled[keyID][i].effectiveAt.Before(compiled[keyID][j].effectiveAt)
		})
	}

	v.revocations = compiled
	return nil
}

func (v *Verifier) verifyRevocations(env *signer.Envelope, now time.Time) error {
	if len(v.revocations) == 0 {
		return nil
	}

	for i, sig := range env.Signatures {
		keyID := strings.TrimSpace(sig.KeyID)
		if keyID == "" {
			continue
		}

		windows := v.revocations[keyID]
		if len(windows) == 0 {
			continue
		}

		evaluationTime := now.UTC()
		if timestamp := strings.TrimSpace(sig.Timestamp); timestamp != "" {
			parsed, err := time.Parse(time.RFC3339, timestamp)
			if err != nil {
				return fmt.Errorf("invalid signatures[%d].timestamp for revocation check: %w", i, err)
			}
			evaluationTime = parsed.UTC()
		}

		for _, window := range windows {
			if evaluationTime.Before(window.effectiveAt) {
				continue
			}
			msg := fmt.Sprintf("signature key revoked: keyid=%s effective_at=%s", keyID, window.effectiveAt.Format(time.RFC3339))
			if window.reason != "" {
				msg = fmt.Sprintf("%s reason=%s", msg, window.reason)
			}
			return errors.New(msg)
		}
	}

	return nil
}
