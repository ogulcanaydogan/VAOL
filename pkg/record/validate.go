package record

import (
	"fmt"
)

// Validate performs structural validation of a DecisionRecord.
// This checks required fields and invariants that go beyond JSON Schema validation.
func Validate(rec *DecisionRecord) error {
	if rec.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version: %q (expected %q)", rec.SchemaVersion, SchemaVersion)
	}

	if rec.RequestID.String() == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("request_id is required")
	}

	if rec.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}

	// Identity
	if rec.Identity.TenantID == "" {
		return fmt.Errorf("identity.tenant_id is required")
	}
	if rec.Identity.Subject == "" {
		return fmt.Errorf("identity.subject is required")
	}

	// Model
	if rec.Model.Provider == "" {
		return fmt.Errorf("model.provider is required")
	}
	if rec.Model.Name == "" {
		return fmt.Errorf("model.name is required")
	}

	// Prompt context
	if rec.PromptContext.UserPromptHash == "" {
		return fmt.Errorf("prompt_context.user_prompt_hash is required")
	}
	if err := validateHashFormat(rec.PromptContext.UserPromptHash, "prompt_context.user_prompt_hash"); err != nil {
		return err
	}
	if rec.PromptContext.SystemPromptHash != "" {
		if err := validateHashFormat(rec.PromptContext.SystemPromptHash, "prompt_context.system_prompt_hash"); err != nil {
			return err
		}
	}
	if rec.PromptContext.UserPromptTemplateHash != "" {
		if err := validateHashFormat(rec.PromptContext.UserPromptTemplateHash, "prompt_context.user_prompt_template_hash"); err != nil {
			return err
		}
	}
	if rec.PromptContext.ToolSchemaHash != "" {
		if err := validateHashFormat(rec.PromptContext.ToolSchemaHash, "prompt_context.tool_schema_hash"); err != nil {
			return err
		}
	}
	if rec.PromptContext.SafetyPromptHash != "" {
		if err := validateHashFormat(rec.PromptContext.SafetyPromptHash, "prompt_context.safety_prompt_hash"); err != nil {
			return err
		}
	}

	// Policy context
	switch rec.PolicyContext.PolicyDecision {
	case PolicyAllow, PolicyDeny, PolicyAllowWithTransform, PolicyLogOnly:
		// valid
	default:
		return fmt.Errorf("policy_context.policy_decision must be one of: allow, deny, allow_with_transform, log_only; got %q", rec.PolicyContext.PolicyDecision)
	}
	if rec.PolicyContext.PolicyHash != "" {
		if err := validateHashFormat(rec.PolicyContext.PolicyHash, "policy_context.policy_hash"); err != nil {
			return err
		}
	}

	// Output
	if rec.Output.OutputHash == "" {
		return fmt.Errorf("output.output_hash is required")
	}
	if err := validateHashFormat(rec.Output.OutputHash, "output.output_hash"); err != nil {
		return err
	}
	switch rec.Output.Mode {
	case OutputModeHashOnly, OutputModeEncrypted, OutputModePlaintext:
		// valid
	default:
		return fmt.Errorf("output.mode must be one of: hash_only, encrypted, plaintext; got %q", rec.Output.Mode)
	}
	if rec.Output.Mode == OutputModeEncrypted {
		hasLegacyEncrypted := rec.Output.OutputEncrypted != ""
		hasRefEncrypted := rec.Output.OutputEncryptedRef != "" && rec.Output.OutputEncryptedHash != ""
		if !hasLegacyEncrypted && !hasRefEncrypted {
			return fmt.Errorf("encrypted output requires output.output_encrypted or both output.output_encrypted_ref and output.output_encrypted_hash")
		}
		if rec.Output.OutputEncryptedHash != "" {
			if err := validateHashFormat(rec.Output.OutputEncryptedHash, "output.output_encrypted_hash"); err != nil {
				return err
			}
		}
		if rec.Output.OutputEncryptedRef != "" && rec.Output.OutputEncryptedHash == "" {
			return fmt.Errorf("output.output_encrypted_hash is required when output.output_encrypted_ref is set")
		}
	}
	if rec.Output.Mode == OutputModePlaintext && rec.Output.OutputPlaintext == "" {
		return fmt.Errorf("output.output_plaintext is required when mode=plaintext")
	}

	// Optional auth context
	if rec.AuthContext != nil && rec.AuthContext.TokenHash != "" {
		if err := validateHashFormat(rec.AuthContext.TokenHash, "auth_context.token_hash"); err != nil {
			return err
		}
	}

	// Integrity
	if rec.Integrity.RecordHash == "" {
		return fmt.Errorf("integrity.record_hash is required")
	}
	if err := validateHashFormat(rec.Integrity.RecordHash, "integrity.record_hash"); err != nil {
		return err
	}
	if rec.Integrity.PreviousRecordHash != "" {
		if err := validateHashFormat(rec.Integrity.PreviousRecordHash, "integrity.previous_record_hash"); err != nil {
			return err
		}
	}
	if rec.Integrity.MerkleRoot != "" {
		if err := validateHashFormat(rec.Integrity.MerkleRoot, "integrity.merkle_root"); err != nil {
			return err
		}
	}

	return nil
}

// validateHashFormat checks that a hash string matches the expected "sha256:<64 hex chars>" format.
func validateHashFormat(hash, fieldName string) error {
	if len(hash) != 71 { // "sha256:" (7) + 64 hex chars
		return fmt.Errorf("%s: invalid hash length (expected 71, got %d)", fieldName, len(hash))
	}
	if hash[:7] != "sha256:" {
		return fmt.Errorf("%s: invalid hash prefix (expected 'sha256:')", fieldName)
	}
	for _, c := range hash[7:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%s: invalid hex character in hash: %c", fieldName, c)
		}
	}
	return nil
}
