import { describe, it, expect } from "vitest";
import { VAOLClient } from "../src/client.js";
import { DecisionRecordBuilder } from "../src/record.js";

describe("VAOLClient", () => {
  it("should compute sha256 hash", () => {
    const hash = VAOLClient.sha256("hello world");
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("should produce deterministic hashes", () => {
    const hash1 = VAOLClient.sha256("test data");
    const hash2 = VAOLClient.sha256("test data");
    expect(hash1).toBe(hash2);
  });

  it("should produce different hashes for different data", () => {
    const hash1 = VAOLClient.sha256("data1");
    const hash2 = VAOLClient.sha256("data2");
    expect(hash1).not.toBe(hash2);
  });
});

describe("DecisionRecordBuilder", () => {
  it("should build a valid record", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test-tenant", "test-user", "user")
      .setModel("openai", "gpt-4o", "2025-03-01")
      .setPromptHash(VAOLClient.sha256("test prompt"))
      .setPolicyDecision("allow", "test-bundle", ["rule-1"])
      .setOutputHash(VAOLClient.sha256("test output"))
      .build();

    expect(record.schema_version).toBe("v1");
    expect(record.request_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    expect(record.identity.tenant_id).toBe("test-tenant");
    expect(record.identity.subject).toBe("test-user");
    expect(record.model.provider).toBe("openai");
    expect(record.model.name).toBe("gpt-4o");
    expect(record.prompt_context.user_prompt_hash).toMatch(/^sha256:/);
    expect(record.policy_context.policy_decision).toBe("allow");
    expect(record.output.output_hash).toMatch(/^sha256:/);
    expect(record.output.mode).toBe("hash_only");
    expect(record.integrity.record_hash).toMatch(/^sha256:/);
  });

  it("should produce different hashes for different records", () => {
    const r1 = new DecisionRecordBuilder()
      .setTenant("t1", "u1")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt1"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output1"))
      .build();

    const r2 = new DecisionRecordBuilder()
      .setTenant("t1", "u1")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt2"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output2"))
      .build();

    expect(r1.integrity.record_hash).not.toBe(r2.integrity.record_hash);
  });

  it("should support encrypted output mode", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setEncryptedOutput("encrypted-blob", VAOLClient.sha256("output"))
      .build();

    expect(record.output.mode).toBe("encrypted");
    expect(record.output.output_encrypted).toBe("encrypted-blob");
  });

  it("should support RAG context", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .setRAGContext({
        connector_ids: ["conn-1"],
        document_ids: ["doc-1", "doc-2"],
        chunk_hashes: [VAOLClient.sha256("chunk1")],
        retrieval_policy_decision: "allow",
      })
      .build();

    expect(record.rag_context).toBeDefined();
    expect(record.rag_context?.connector_ids).toHaveLength(1);
    expect(record.rag_context?.document_ids).toHaveLength(2);
  });

  it("should support trace context", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .setTrace({
        otel_trace_id: "a".repeat(32),
        otel_span_id: "b".repeat(16),
        session_id: "session-123",
      })
      .build();

    expect(record.trace.otel_trace_id).toBe("a".repeat(32));
    expect(record.trace.otel_span_id).toBe("b".repeat(16));
  });

  it("should set output metadata", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .setOutputMeta({
        outputTokens: 150,
        finishReason: "stop",
        latencyMs: 342.5,
      })
      .build();

    expect(record.output.output_tokens).toBe(150);
    expect(record.output.finish_reason).toBe("stop");
    expect(record.output.latency_ms).toBe(342.5);
  });
});
