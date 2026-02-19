package record

import (
	"testing"
)

func TestValidateValidRecord(t *testing.T) {
	rec := makeTestRecord()
	if err := Validate(rec); err != nil {
		t.Errorf("Validate should pass for valid record, got: %v", err)
	}
}

func TestValidateSchemaVersion(t *testing.T) {
	rec := makeTestRecord()
	rec.SchemaVersion = "v99"
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for wrong schema version")
	}
}

func TestValidateMissingTenantID(t *testing.T) {
	rec := makeTestRecord()
	rec.Identity.TenantID = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing tenant_id")
	}
}

func TestValidateMissingSubject(t *testing.T) {
	rec := makeTestRecord()
	rec.Identity.Subject = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing subject")
	}
}

func TestValidateMissingModelProvider(t *testing.T) {
	rec := makeTestRecord()
	rec.Model.Provider = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing model provider")
	}
}

func TestValidateMissingModelName(t *testing.T) {
	rec := makeTestRecord()
	rec.Model.Name = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing model name")
	}
}

func TestValidateMissingUserPromptHash(t *testing.T) {
	rec := makeTestRecord()
	rec.PromptContext.UserPromptHash = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing user_prompt_hash")
	}
}

func TestValidateInvalidHashFormat(t *testing.T) {
	rec := makeTestRecord()
	rec.PromptContext.UserPromptHash = "md5:abc123"
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for invalid hash format")
	}
}

func TestValidateInvalidPolicyDecision(t *testing.T) {
	rec := makeTestRecord()
	rec.PolicyContext.PolicyDecision = "maybe"
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for invalid policy decision")
	}
}

func TestValidateAllPolicyDecisions(t *testing.T) {
	decisions := []PolicyDecision{PolicyAllow, PolicyDeny, PolicyAllowWithTransform, PolicyLogOnly}
	for _, d := range decisions {
		rec := makeTestRecord()
		rec.PolicyContext.PolicyDecision = d
		if err := Validate(rec); err != nil {
			t.Errorf("Validate should pass for policy_decision=%q, got: %v", d, err)
		}
	}
}

func TestValidateMissingOutputHash(t *testing.T) {
	rec := makeTestRecord()
	rec.Output.OutputHash = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing output_hash")
	}
}

func TestValidateInvalidOutputMode(t *testing.T) {
	rec := makeTestRecord()
	rec.Output.Mode = "raw"
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for invalid output mode")
	}
}

func TestValidateEncryptedModeRequiresEncryptedPayload(t *testing.T) {
	rec := makeTestRecord()
	rec.Output.Mode = OutputModeEncrypted
	rec.Output.OutputEncrypted = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail when mode=encrypted but output_encrypted is empty")
	}
}

func TestValidatePlaintextModeRequiresPlaintext(t *testing.T) {
	rec := makeTestRecord()
	rec.Output.Mode = OutputModePlaintext
	rec.Output.OutputPlaintext = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail when mode=plaintext but output_plaintext is empty")
	}
}

func TestValidateEncryptedModeWithPayload(t *testing.T) {
	rec := makeTestRecord()
	rec.Output.Mode = OutputModeEncrypted
	rec.Output.OutputEncrypted = "base64encrypteddata"
	if err := Validate(rec); err != nil {
		t.Errorf("Validate should pass for encrypted mode with payload, got: %v", err)
	}
}

func TestValidateMissingRecordHash(t *testing.T) {
	rec := makeTestRecord()
	rec.Integrity.RecordHash = ""
	if err := Validate(rec); err == nil {
		t.Error("Validate should fail for missing record_hash")
	}
}

func TestValidateHashFormatEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		hash  string
		valid bool
	}{
		{"valid", "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true},
		{"all zeros", "sha256:0000000000000000000000000000000000000000000000000000000000000000", true},
		{"too short", "sha256:abc", false},
		{"wrong prefix", "md5:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false},
		{"uppercase hex", "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHashFormat(tt.hash, "test_field")
			if tt.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
