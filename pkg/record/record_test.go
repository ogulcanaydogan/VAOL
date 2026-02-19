package record

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNew(t *testing.T) {
	rec := New()
	if rec.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", rec.SchemaVersion, SchemaVersion)
	}
	if rec.RequestID.String() == "00000000-0000-0000-0000-000000000000" {
		t.Error("RequestID should not be zero UUID")
	}
	if rec.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestDecisionRecordJSONRoundtrip(t *testing.T) {
	rec := makeTestRecord()

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded DecisionRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.SchemaVersion != rec.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", decoded.SchemaVersion, rec.SchemaVersion)
	}
	if decoded.RequestID != rec.RequestID {
		t.Errorf("RequestID mismatch")
	}
	if decoded.Identity.TenantID != rec.Identity.TenantID {
		t.Errorf("TenantID = %q, want %q", decoded.Identity.TenantID, rec.Identity.TenantID)
	}
	if decoded.Model.Provider != rec.Model.Provider {
		t.Errorf("Model.Provider = %q, want %q", decoded.Model.Provider, rec.Model.Provider)
	}
	if decoded.Output.OutputHash != rec.Output.OutputHash {
		t.Errorf("Output.OutputHash = %q, want %q", decoded.Output.OutputHash, rec.Output.OutputHash)
	}
}

func TestDecisionRecordOptionalRAGContext(t *testing.T) {
	rec := makeTestRecord()
	rec.RAGContext = nil

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// rag_context should be omitted
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if _, ok := raw["rag_context"]; ok {
		t.Error("rag_context should be omitted when nil")
	}
}

func TestDecisionRecordWithRAGContext(t *testing.T) {
	rec := makeTestRecord()
	rec.RAGContext = &RAGContext{
		ConnectorIDs: []string{"connector-1"},
		DocumentIDs:  []string{"doc-123"},
		ChunkHashes:  []string{"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
		PromptInjectionCheck: &PromptInjectionCheck{
			Performed: true,
			Result:    "pass",
		},
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded DecisionRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.RAGContext == nil {
		t.Fatal("RAGContext should not be nil")
	}
	if len(decoded.RAGContext.ConnectorIDs) != 1 {
		t.Errorf("ConnectorIDs len = %d, want 1", len(decoded.RAGContext.ConnectorIDs))
	}
}

func makeTestRecord() *DecisionRecord {
	temp := 0.7
	maxTok := 1024
	return &DecisionRecord{
		SchemaVersion: SchemaVersion,
		RequestID:     uuid.New(),
		Timestamp:     time.Now().UTC(),
		Identity: Identity{
			TenantID:    "test-tenant",
			Subject:     "test-user",
			SubjectType: "user",
		},
		Model: Model{
			Provider: "openai",
			Name:     "gpt-4o",
		},
		Parameters: Parameters{
			Temperature: &temp,
			MaxTokens:   &maxTok,
		},
		PromptContext: PromptContext{
			UserPromptHash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		PolicyContext: PolicyContext{
			PolicyDecision: PolicyAllow,
		},
		Output: Output{
			OutputHash: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Mode:       OutputModeHashOnly,
		},
		Trace: Trace{},
		Integrity: Integrity{
			RecordHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
}
