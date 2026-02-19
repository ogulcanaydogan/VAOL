// Package record defines the DecisionRecord v1 data types and operations.
package record

import (
	"time"

	"github.com/google/uuid"
)

const SchemaVersion = "v1"

// DecisionRecord is the core evidence type for a single AI inference decision.
type DecisionRecord struct {
	SchemaVersion string        `json:"schema_version"`
	RequestID     uuid.UUID     `json:"request_id"`
	Timestamp     time.Time     `json:"timestamp"`
	Identity      Identity      `json:"identity"`
	AuthContext   *AuthContext  `json:"auth_context,omitempty"`
	Model         Model         `json:"model"`
	Parameters    Parameters    `json:"parameters"`
	PromptContext PromptContext `json:"prompt_context"`
	PolicyContext PolicyContext `json:"policy_context"`
	RAGContext    *RAGContext   `json:"rag_context,omitempty"`
	Output        Output        `json:"output"`
	Trace         Trace         `json:"trace"`
	Integrity     Integrity     `json:"integrity"`
}

type Identity struct {
	TenantID    string            `json:"tenant_id"`
	Subject     string            `json:"subject"`
	SubjectType string            `json:"subject_type,omitempty"`
	Claims      map[string]string `json:"claims,omitempty"`
}

// AuthContext captures server-populated authentication context to bind record
// identity to authenticated caller claims.
type AuthContext struct {
	Issuer        string `json:"issuer,omitempty"`
	Subject       string `json:"subject,omitempty"`
	TokenHash     string `json:"token_hash,omitempty"`
	Source        string `json:"source,omitempty"`
	Authenticated bool   `json:"authenticated,omitempty"`
}

type Model struct {
	Provider     string `json:"provider"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	DeploymentID string `json:"deployment_id,omitempty"`
}

type Parameters struct {
	Temperature      *float64 `json:"temperature,omitempty"`
	TopP             *float64 `json:"top_p,omitempty"`
	MaxTokens        *int     `json:"max_tokens,omitempty"`
	FrequencyPenalty *float64 `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64 `json:"presence_penalty,omitempty"`
	StopSequences    []string `json:"stop_sequences,omitempty"`
	Seed             *int     `json:"seed,omitempty"`
	ToolsEnabled     *bool    `json:"tools_enabled,omitempty"`
	ResponseFormat   string   `json:"response_format,omitempty"`
}

type PromptContext struct {
	SystemPromptHash       string `json:"system_prompt_hash,omitempty"`
	UserPromptHash         string `json:"user_prompt_hash"`
	UserPromptTemplateHash string `json:"user_prompt_template_hash,omitempty"`
	UserPromptTemplateID   string `json:"user_prompt_template_id,omitempty"`
	ToolSchemaHash         string `json:"tool_schema_hash,omitempty"`
	SafetyPromptHash       string `json:"safety_prompt_hash,omitempty"`
	MessageCount           int    `json:"message_count,omitempty"`
	TotalInputTokens       int    `json:"total_input_tokens,omitempty"`
}

type PolicyDecision string

const (
	PolicyAllow              PolicyDecision = "allow"
	PolicyDeny               PolicyDecision = "deny"
	PolicyAllowWithTransform PolicyDecision = "allow_with_transform"
	PolicyLogOnly            PolicyDecision = "log_only"
)

type PolicyContext struct {
	PolicyBundleID       string            `json:"policy_bundle_id,omitempty"`
	PolicyHash           string            `json:"policy_hash,omitempty"`
	PolicyDecision       PolicyDecision    `json:"policy_decision"`
	DecisionReasonCode   string            `json:"decision_reason_code,omitempty"`
	RuleIDs              []string          `json:"rule_ids,omitempty"`
	TransformsApplied    []TransformRecord `json:"transforms_applied,omitempty"`
	PolicyEngineVersion  string            `json:"policy_engine_version,omitempty"`
	EvaluationDurationMs float64           `json:"evaluation_duration_ms,omitempty"`
}

type TransformType string

const (
	TransformRedactPII TransformType = "redact_pii"
	TransformRedactPHI TransformType = "redact_phi"
	TransformMask      TransformType = "mask"
	TransformFilter    TransformType = "filter"
	TransformCustom    TransformType = "custom"
)

type TransformTarget string

const (
	TransformTargetInput  TransformTarget = "input"
	TransformTargetOutput TransformTarget = "output"
	TransformTargetBoth   TransformTarget = "both"
)

type TransformRecord struct {
	Type    TransformType   `json:"type"`
	Target  TransformTarget `json:"target"`
	Details string          `json:"details,omitempty"`
}

type RAGContext struct {
	ConnectorIDs            []string              `json:"connector_ids,omitempty"`
	DocumentIDs             []string              `json:"document_ids,omitempty"`
	ChunkHashes             []string              `json:"chunk_hashes,omitempty"`
	CitationHashes          []string              `json:"citation_hashes,omitempty"`
	RetrievalPolicyDecision string                `json:"retrieval_policy_decision,omitempty"`
	PromptInjectionCheck    *PromptInjectionCheck `json:"prompt_injection_check,omitempty"`
}

type PromptInjectionCheck struct {
	Performed       bool   `json:"performed"`
	Result          string `json:"result"`
	DetectorVersion string `json:"detector_version,omitempty"`
}

type OutputMode string

const (
	OutputModeHashOnly  OutputMode = "hash_only"
	OutputModeEncrypted OutputMode = "encrypted"
	OutputModePlaintext OutputMode = "plaintext"
)

type Output struct {
	OutputHash          string     `json:"output_hash"`
	Mode                OutputMode `json:"mode"`
	OutputEncrypted     string     `json:"output_encrypted,omitempty"`
	OutputEncryptedRef  string     `json:"output_encrypted_ref,omitempty"`
	OutputEncryptedHash string     `json:"output_encrypted_hash,omitempty"`
	OutputPlaintext     string     `json:"output_plaintext,omitempty"`
	OutputTokens        int        `json:"output_tokens,omitempty"`
	FinishReason        string     `json:"finish_reason,omitempty"`
	LatencyMs           float64    `json:"latency_ms,omitempty"`
}

type Trace struct {
	OtelTraceID     string `json:"otel_trace_id,omitempty"`
	OtelSpanID      string `json:"otel_span_id,omitempty"`
	ParentRequestID string `json:"parent_request_id,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
}

type Integrity struct {
	SequenceNumber     int64           `json:"sequence_number,omitempty"`
	RecordHash         string          `json:"record_hash"`
	PreviousRecordHash string          `json:"previous_record_hash,omitempty"`
	MerkleRoot         string          `json:"merkle_root,omitempty"`
	MerkleTreeSize     int64           `json:"merkle_tree_size,omitempty"`
	InclusionProofRef  string          `json:"inclusion_proof_ref,omitempty"`
	InclusionProof     *InclusionProof `json:"inclusion_proof,omitempty"`
}

type InclusionProof struct {
	LeafIndex int64    `json:"leaf_index"`
	Hashes    []string `json:"hashes"`
}

// Receipt is returned to the client after a record is appended to the ledger.
type Receipt struct {
	RequestID         uuid.UUID       `json:"request_id"`
	SequenceNumber    int64           `json:"sequence_number"`
	RecordHash        string          `json:"record_hash"`
	MerkleRoot        string          `json:"merkle_root"`
	MerkleTreeSize    int64           `json:"merkle_tree_size"`
	InclusionProofRef string          `json:"inclusion_proof_ref,omitempty"`
	InclusionProof    *InclusionProof `json:"inclusion_proof,omitempty"`
	Timestamp         time.Time       `json:"timestamp"`
}

// New creates a new DecisionRecord with the schema version set and a generated request ID.
func New() *DecisionRecord {
	return &DecisionRecord{
		SchemaVersion: SchemaVersion,
		RequestID:     uuid.New(),
		Timestamp:     time.Now().UTC(),
	}
}
