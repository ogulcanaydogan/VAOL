import { randomUUID } from "node:crypto";
import { VAOLClient } from "./client.js";
import type {
  DecisionRecord,
  Identity,
  Model,
  Parameters,
  PromptContext,
  PolicyContext,
  RAGContext,
  Output,
  Trace,
  Integrity,
  PolicyDecision,
  OutputMode,
} from "./types.js";

/**
 * DecisionRecordBuilder provides a fluent API for constructing DecisionRecords.
 *
 * Usage:
 * ```ts
 * const record = new DecisionRecordBuilder()
 *   .setTenant("my-tenant", "user-123")
 *   .setModel("openai", "gpt-4o")
 *   .setPromptHash(VAOLClient.sha256(userPrompt))
 *   .setPolicyDecision("allow")
 *   .setOutputHash(VAOLClient.sha256(outputText))
 *   .build();
 * ```
 */
export class DecisionRecordBuilder {
  private record: DecisionRecord;

  constructor() {
    this.record = {
      schema_version: "v1",
      request_id: randomUUID(),
      timestamp: new Date().toISOString(),
      identity: { tenant_id: "", subject: "" },
      model: { provider: "", name: "" },
      parameters: {},
      prompt_context: { user_prompt_hash: "" },
      policy_context: { policy_decision: "allow" },
      output: { output_hash: "", mode: "hash_only" },
      trace: {},
      integrity: { record_hash: "" },
    };
  }

  /** Set tenant and subject identity. */
  setTenant(
    tenantID: string,
    subject: string,
    subjectType?: "user" | "service" | "pipeline"
  ): this {
    this.record.identity = {
      tenant_id: tenantID,
      subject,
      subject_type: subjectType,
    };
    return this;
  }

  /** Set identity claims. */
  setClaims(claims: Record<string, string>): this {
    this.record.identity.claims = claims;
    return this;
  }

  /** Set the AI model used. */
  setModel(
    provider: string,
    name: string,
    version?: string,
    endpoint?: string
  ): this {
    this.record.model = { provider, name, version, endpoint };
    return this;
  }

  /** Set model parameters. */
  setParameters(params: Parameters): this {
    this.record.parameters = params;
    return this;
  }

  /** Set the prompt context hashes. */
  setPromptHash(
    userPromptHash: string,
    systemPromptHash?: string
  ): this {
    this.record.prompt_context.user_prompt_hash = userPromptHash;
    if (systemPromptHash) {
      this.record.prompt_context.system_prompt_hash = systemPromptHash;
    }
    return this;
  }

  /** Set prompt context metadata. */
  setPromptContext(ctx: Partial<PromptContext>): this {
    Object.assign(this.record.prompt_context, ctx);
    return this;
  }

  /** Set the policy decision and context. */
  setPolicyDecision(
    decision: PolicyDecision,
    bundleID?: string,
    ruleIDs?: string[]
  ): this {
    this.record.policy_context.policy_decision = decision;
    if (bundleID) this.record.policy_context.policy_bundle_id = bundleID;
    if (ruleIDs) this.record.policy_context.rule_ids = ruleIDs;
    return this;
  }

  /** Set full policy context. */
  setPolicyContext(ctx: Partial<PolicyContext>): this {
    Object.assign(this.record.policy_context, ctx);
    return this;
  }

  /** Set RAG context. */
  setRAGContext(ctx: RAGContext): this {
    this.record.rag_context = ctx;
    return this;
  }

  /** Set the output hash and mode. */
  setOutputHash(
    outputHash: string,
    mode: OutputMode = "hash_only"
  ): this {
    this.record.output.output_hash = outputHash;
    this.record.output.mode = mode;
    return this;
  }

  /** Set output metadata. */
  setOutputMeta(meta: {
    outputTokens?: number;
    finishReason?: string;
    latencyMs?: number;
  }): this {
    if (meta.outputTokens !== undefined)
      this.record.output.output_tokens = meta.outputTokens;
    if (meta.finishReason !== undefined)
      this.record.output.finish_reason = meta.finishReason;
    if (meta.latencyMs !== undefined)
      this.record.output.latency_ms = meta.latencyMs;
    return this;
  }

  /** Set encrypted output inline (legacy compatibility). */
  setEncryptedOutput(ciphertext: string, hash: string): this {
    this.record.output.mode = "encrypted";
    this.record.output.output_encrypted = ciphertext;
    this.record.output.output_hash = hash;
    return this;
  }

  /** Set encrypted output by external reference. */
  setEncryptedOutputRef(ref: string, encryptedHash: string, outputHash: string): this {
    this.record.output.mode = "encrypted";
    this.record.output.output_encrypted_ref = ref;
    this.record.output.output_encrypted_hash = encryptedHash;
    this.record.output.output_hash = outputHash;
    return this;
  }

  /** Set OpenTelemetry trace context. */
  setTrace(trace: Trace): this {
    this.record.trace = trace;
    return this;
  }

  /** Set a custom request ID (defaults to random UUID). */
  setRequestID(id: string): this {
    this.record.request_id = id;
    return this;
  }

  /** Build and return the DecisionRecord. */
  build(): DecisionRecord {
    // Compute the record hash client-side
    // The server will verify this hash matches
    const canonical = this.canonicalize();
    this.record.integrity.record_hash = VAOLClient.sha256(canonical);
    return structuredClone(this.record);
  }

  /**
   * Returns the canonical JSON for hash computation.
   * Excludes integrity computed fields per the VAOL spec.
   */
  private canonicalize(): string {
    const copy: Record<string, unknown> = { ...this.record };

    // Strip computed integrity fields
    const integrity: Record<string, unknown> = {};
    // Integrity is kept as empty object (required by schema)
    copy["integrity"] = integrity;

    return JSON.stringify(copy, Object.keys(copy).sort());
  }
}
