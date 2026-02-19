/** VAOL DecisionRecord v1 — TypeScript type definitions. */

export interface DecisionRecord {
  schema_version: "v1";
  request_id: string;
  timestamp: string;
  identity: Identity;
  auth_context?: AuthContext;
  model: Model;
  parameters: Parameters;
  prompt_context: PromptContext;
  policy_context: PolicyContext;
  rag_context?: RAGContext;
  output: Output;
  trace: Trace;
  integrity: Integrity;
}

export interface Identity {
  tenant_id: string;
  subject: string;
  subject_type?: "user" | "service" | "pipeline";
  claims?: Record<string, string>;
}

export interface AuthContext {
  issuer?: string;
  subject?: string;
  token_hash?: string;
  source?: string;
  authenticated?: boolean;
}

export interface Model {
  provider: string;
  name: string;
  version?: string;
  endpoint?: string;
  deployment_id?: string;
}

export interface Parameters {
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop_sequences?: string[];
  seed?: number;
  tools_enabled?: boolean;
  response_format?: string;
}

export interface PromptContext {
  system_prompt_hash?: string;
  user_prompt_hash: string;
  user_prompt_template_hash?: string;
  user_prompt_template_id?: string;
  tool_schema_hash?: string;
  safety_prompt_hash?: string;
  message_count?: number;
  total_input_tokens?: number;
}

export type PolicyDecision =
  | "allow"
  | "deny"
  | "allow_with_transform"
  | "log_only";

export interface PolicyContext {
  policy_bundle_id?: string;
  policy_hash?: string;
  policy_decision: PolicyDecision;
  decision_reason_code?: string;
  rule_ids?: string[];
  transforms_applied?: TransformRecord[];
  policy_engine_version?: string;
  evaluation_duration_ms?: number;
}

export interface TransformRecord {
  type: "redact_pii" | "redact_phi" | "mask" | "filter" | "custom";
  target: "input" | "output" | "both";
  details?: string;
}

export interface RAGContext {
  connector_ids?: string[];
  document_ids?: string[];
  chunk_hashes?: string[];
  citation_hashes?: string[];
  retrieval_policy_decision?: "allow" | "deny" | "partial";
  prompt_injection_check?: {
    performed: boolean;
    result: "pass" | "fail" | "skipped";
    detector_version?: string;
  };
}

export type OutputMode = "hash_only" | "encrypted" | "plaintext";

export interface Output {
  output_hash: string;
  mode: OutputMode;
  output_encrypted?: string;
  output_encrypted_ref?: string;
  output_encrypted_hash?: string;
  output_plaintext?: string;
  output_tokens?: number;
  finish_reason?: string;
  latency_ms?: number;
}

export interface Trace {
  otel_trace_id?: string;
  otel_span_id?: string;
  parent_request_id?: string;
  session_id?: string;
}

export interface Integrity {
  sequence_number?: number;
  record_hash: string;
  previous_record_hash?: string;
  merkle_root?: string;
  merkle_tree_size?: number;
  inclusion_proof_ref?: string;
  inclusion_proof?: InclusionProof;
}

export interface InclusionProof {
  leaf_index: number;
  hashes: string[];
}

export interface Receipt {
  request_id: string;
  sequence_number: number;
  record_hash: string;
  merkle_root: string;
  merkle_tree_size: number;
  inclusion_proof_ref?: string;
  inclusion_proof?: InclusionProof;
  timestamp: string;
}

export interface DSSEEnvelope {
  payloadType: string;
  payload: string;
  signatures: DSSESignature[];
}

export interface DSSESignature {
  keyid: string;
  sig: string;
  cert?: string;
  rekor_entry_id?: string;
  timestamp?: string;
}

export interface VerificationResult {
  request_id: string;
  valid: boolean;
  checks: CheckResult[];
  error?: string;
}

export interface CheckResult {
  name: string;
  passed: boolean;
  details?: string;
  error?: string;
}
