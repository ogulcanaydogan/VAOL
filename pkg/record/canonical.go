package record

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	vaolcrypto "github.com/yapay-ai/vaol/pkg/crypto"
)

// integrityComputedFields are the integrity sub-fields that are excluded from
// the record hash computation (they are populated after hashing).
var integrityComputedFields = map[string]bool{
	"record_hash":          true,
	"previous_record_hash": true,
	"merkle_root":          true,
	"merkle_tree_size":     true,
	"inclusion_proof_ref":  true,
	"inclusion_proof":      true,
	"sequence_number":      true,
}

// Canonicalize produces the RFC 8785 (JCS) canonical JSON representation of a DecisionRecord.
// The integrity sub-fields that are computed (record_hash, previous_record_hash, etc.)
// are excluded from the canonical form, since they depend on the hash of the payload itself.
func Canonicalize(rec *DecisionRecord) ([]byte, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("marshaling record: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling to map: %w", err)
	}

	// Strip computed integrity fields
	if integrity, ok := m["integrity"].(map[string]any); ok {
		for field := range integrityComputedFields {
			delete(integrity, field)
		}
		// If integrity is now empty, keep it as empty object (it's still required by schema)
		m["integrity"] = integrity
	}

	return jcsSerialize(m)
}

// ComputeRecordHash computes the SHA-256 hash of the canonical payload.
func ComputeRecordHash(rec *DecisionRecord) (string, error) {
	canonical, err := Canonicalize(rec)
	if err != nil {
		return "", fmt.Errorf("canonicalizing record: %w", err)
	}
	return vaolcrypto.SHA256Prefixed(canonical), nil
}

// jcsSerialize implements RFC 8785 JSON Canonicalization Scheme.
// It produces deterministic JSON with:
// - Sorted object keys (lexicographic by Unicode code point)
// - No unnecessary whitespace
// - Numbers serialized per ES2015 Number.toString
// - No trailing commas
func jcsSerialize(v any) ([]byte, error) {
	var b strings.Builder
	if err := jcsWrite(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func jcsWrite(b *strings.Builder, v any) error {
	switch val := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if val {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		data, err := json.Marshal(val)
		if err != nil {
			return err
		}
		b.Write(data)
	case float64:
		b.WriteString(jcsFormatNumber(val))
	case json.Number:
		f, err := val.Float64()
		if err != nil {
			b.WriteString(val.String())
		} else {
			b.WriteString(jcsFormatNumber(f))
		}
	case map[string]any:
		b.WriteByte('{')
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			keyJSON, err := json.Marshal(k)
			if err != nil {
				return err
			}
			b.Write(keyJSON)
			b.WriteByte(':')
			if err := jcsWrite(b, val[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsWrite(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		// Fallback: use standard JSON marshaling
		data, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("jcs: unsupported type %T: %w", val, err)
		}
		b.Write(data)
	}
	return nil
}

// jcsFormatNumber formats a float64 per ES2015 Number.toString rules.
// Integers are rendered without decimal point; non-integers use shortest representation.
func jcsFormatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	// Check if integer
	if f == float64(int64(f)) && f >= -1e15 && f <= 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'G', -1, 64)
}
