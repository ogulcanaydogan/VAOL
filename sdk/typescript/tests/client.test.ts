import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VAOLClient } from "../src/client.js";
import { DecisionRecordBuilder } from "../src/record.js";
import { instrumentOpenAI } from "../src/wrapper.js";

// -- SHA-256 Utility Tests --

describe("VAOLClient.sha256", () => {
  it("should compute sha256 hash with prefix", () => {
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

  it("should handle empty string", () => {
    const hash = VAOLClient.sha256("");
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    // SHA-256 of empty string is well-known
    expect(hash).toBe(
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("should handle Buffer input", () => {
    const hash = VAOLClient.sha256(Buffer.from("hello world"));
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

// -- DecisionRecordBuilder Tests --

describe("DecisionRecordBuilder", () => {
  it("should build a valid record with all required fields", () => {
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
    expect(record.timestamp).toBeTruthy();
    expect(record.identity.tenant_id).toBe("test-tenant");
    expect(record.identity.subject).toBe("test-user");
    expect(record.identity.subject_type).toBe("user");
    expect(record.model.provider).toBe("openai");
    expect(record.model.name).toBe("gpt-4o");
    expect(record.model.version).toBe("2025-03-01");
    expect(record.prompt_context.user_prompt_hash).toMatch(/^sha256:/);
    expect(record.policy_context.policy_decision).toBe("allow");
    expect(record.policy_context.policy_bundle_id).toBe("test-bundle");
    expect(record.policy_context.rule_ids).toEqual(["rule-1"]);
    expect(record.output.output_hash).toMatch(/^sha256:/);
    expect(record.output.mode).toBe("hash_only");
    expect(record.integrity.record_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
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

  it("should support encrypted output by reference", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setEncryptedOutputRef(
        "s3://bucket/key",
        VAOLClient.sha256("encrypted-blob"),
        VAOLClient.sha256("output")
      )
      .build();

    expect(record.output.mode).toBe("encrypted");
    expect(record.output.output_encrypted_ref).toBe("s3://bucket/key");
    expect(record.output.output_encrypted_hash).toMatch(/^sha256:/);
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
    expect(record.rag_context?.chunk_hashes?.[0]).toMatch(/^sha256:/);
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
    expect(record.trace.session_id).toBe("session-123");
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

  it("should set parameters", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setParameters({
        temperature: 0.7,
        top_p: 0.9,
        max_tokens: 1024,
        seed: 42,
      })
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .build();

    expect(record.parameters.temperature).toBe(0.7);
    expect(record.parameters.top_p).toBe(0.9);
    expect(record.parameters.max_tokens).toBe(1024);
    expect(record.parameters.seed).toBe(42);
  });

  it("should set identity claims", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user", "service")
      .setClaims({ role: "admin", department: "engineering" })
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .build();

    expect(record.identity.claims).toEqual({
      role: "admin",
      department: "engineering",
    });
  });

  it("should allow custom request ID", () => {
    const customID = "11111111-2222-3333-4444-555555555555";
    const record = new DecisionRecordBuilder()
      .setRequestID(customID)
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .build();

    expect(record.request_id).toBe(customID);
  });

  it("should set full policy context", () => {
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyContext({
        policy_decision: "allow_with_transform",
        policy_bundle_id: "bundle-v3",
        policy_hash: VAOLClient.sha256("policy-content"),
        rule_ids: ["rule-a", "rule-b"],
        transforms_applied: [
          { type: "redact_pii", target: "output" },
        ],
        evaluation_duration_ms: 12.5,
      })
      .setOutputHash(VAOLClient.sha256("output"))
      .build();

    expect(record.policy_context.policy_decision).toBe(
      "allow_with_transform"
    );
    expect(record.policy_context.transforms_applied).toHaveLength(1);
    expect(record.policy_context.evaluation_duration_ms).toBe(12.5);
  });

  it("should produce immutable records (deep copy)", () => {
    const builder = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"));

    const r1 = builder.build();
    const r2 = builder.build();

    // Different request IDs since build() generates a new hash each time
    // but the identity should be the same
    expect(r1.identity.tenant_id).toBe(r2.identity.tenant_id);
    // Mutating r1 should not affect r2
    r1.identity.tenant_id = "mutated";
    expect(r2.identity.tenant_id).toBe("test");
  });
});

// -- VAOLClient HTTP Tests (mocked fetch) --

describe("VAOLClient HTTP", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function jsonResponse(data: unknown, status = 200) {
    return Promise.resolve({
      ok: status >= 200 && status < 400,
      status,
      json: () => Promise.resolve(data),
      text: () => Promise.resolve(JSON.stringify(data)),
    });
  }

  it("should call health endpoint", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ status: "ok", version: "0.1.0", record_count: 42 })
    );

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    const health = await client.health();

    expect(health.status).toBe("ok");
    expect(mockFetch).toHaveBeenCalledOnce();
    expect(mockFetch.mock.calls[0][0]).toBe(
      "http://localhost:8080/v1/health"
    );
  });

  it("should append a record", async () => {
    const receipt = {
      request_id: "test-id",
      sequence_number: 1,
      record_hash: "sha256:abc",
      merkle_root: "sha256:def",
      merkle_tree_size: 1,
    };
    mockFetch.mockReturnValueOnce(jsonResponse(receipt, 201));

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    const record = new DecisionRecordBuilder()
      .setTenant("test", "user")
      .setModel("openai", "gpt-4o")
      .setPromptHash(VAOLClient.sha256("prompt"))
      .setPolicyDecision("allow")
      .setOutputHash(VAOLClient.sha256("output"))
      .build();

    const result = await client.append(record);
    expect(result.sequence_number).toBe(1);
    expect(mockFetch.mock.calls[0][1]?.method).toBe("POST");
  });

  it("should get a record by ID", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ record: { request_id: "abc-123" } })
    );

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    const result = await client.get("abc-123");

    expect(mockFetch.mock.calls[0][0]).toBe(
      "http://localhost:8080/v1/records/abc-123"
    );
  });

  it("should list records with filters", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse([]));

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    await client.list({ limit: 10 });

    expect(mockFetch.mock.calls[0][0]).toContain("limit=10");
  });

  it("should get Merkle proof", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ leaf_index: 0, tree_size: 1, hashes: [] })
    );

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    await client.getProof("test-id");

    expect(mockFetch.mock.calls[0][0]).toBe(
      "http://localhost:8080/v1/records/test-id/proof"
    );
  });

  it("should verify an envelope", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({
        valid: true,
        checks: [{ name: "signature", passed: true }],
      })
    );

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    const result = await client.verify({
      payloadType: "application/vnd.vaol.decision-record.v1+json",
      payload: "dGVzdA==",
      signatures: [{ keyid: "key-1", sig: "c2ln" }],
    });

    expect(result.valid).toBe(true);
    expect(mockFetch.mock.calls[0][1]?.method).toBe("POST");
  });

  it("should get checkpoint", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ tree_size: 100, root_hash: "sha256:abc" })
    );

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    await client.checkpoint();

    expect(mockFetch.mock.calls[0][0]).toBe(
      "http://localhost:8080/v1/ledger/checkpoint"
    );
  });

  it("should export a bundle", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ records: [], metadata: {} })
    );

    const client = new VAOLClient({
      baseURL: "http://localhost:8080",
      tenantID: "my-org",
    });
    await client.exportBundle();

    expect(mockFetch.mock.calls[0][1]?.method).toBe("POST");
  });

  it("should include auth header when apiKey is set", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: "ok" }));

    const client = new VAOLClient({
      baseURL: "http://localhost:8080",
      apiKey: "test-token",
    });
    await client.health();

    const headers = mockFetch.mock.calls[0][1]?.headers;
    expect(headers?.Authorization).toBe("Bearer test-token");
  });

  it("should include tenant header when tenantID is set", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: "ok" }));

    const client = new VAOLClient({
      baseURL: "http://localhost:8080",
      tenantID: "my-org",
    });
    await client.health();

    const headers = mockFetch.mock.calls[0][1]?.headers;
    expect(headers?.["X-VAOL-Tenant-ID"]).toBe("my-org");
  });

  it("should throw on API error", async () => {
    mockFetch.mockReturnValueOnce(
      jsonResponse({ error: "not found" }, 404)
    );

    const client = new VAOLClient({ baseURL: "http://localhost:8080" });
    await expect(client.get("nonexistent")).rejects.toThrow(
      "VAOL API error 404"
    );
  });

  it("should strip trailing slash from baseURL", async () => {
    mockFetch.mockReturnValueOnce(jsonResponse({ status: "ok" }));

    const client = new VAOLClient({
      baseURL: "http://localhost:8080/",
    });
    await client.health();

    expect(mockFetch.mock.calls[0][0]).toBe(
      "http://localhost:8080/v1/health"
    );
  });
});

// -- instrumentOpenAI Tests --

describe("instrumentOpenAI", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
    mockFetch.mockReset();
    // Mock successful append for all instrumented calls
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: true,
        status: 201,
        json: () =>
          Promise.resolve({
            request_id: "test",
            sequence_number: 1,
            record_hash: "sha256:abc",
          }),
        text: () => Promise.resolve(""),
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("should throw if client lacks chat.completions.create", () => {
    const client = new VAOLClient({ baseURL: "http://localhost:8080" });

    expect(() => instrumentOpenAI({}, { client, tenantID: "t", subject: "s" })).toThrow(
      "Invalid OpenAI client"
    );

    expect(() =>
      instrumentOpenAI({ chat: {} }, { client, tenantID: "t", subject: "s" })
    ).toThrow("Invalid OpenAI client");
  });

  it("should replace chat.completions.create", () => {
    const originalCreate = vi.fn();
    const fakeClient = {
      chat: { completions: { create: originalCreate } },
    };
    const vaolClient = new VAOLClient({ baseURL: "http://localhost:8080" });

    instrumentOpenAI(fakeClient, {
      client: vaolClient,
      tenantID: "test",
      subject: "user",
    });

    expect(fakeClient.chat.completions.create).not.toBe(originalCreate);
  });

  it("should forward call and emit record", async () => {
    const mockResponse = {
      choices: [{ message: { content: "Paris" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 10, completion_tokens: 5 },
    };
    const originalCreate = vi.fn().mockResolvedValue(mockResponse);
    const fakeClient = {
      chat: { completions: { create: originalCreate } },
    };
    const vaolClient = new VAOLClient({ baseURL: "http://localhost:8080" });

    instrumentOpenAI(fakeClient, {
      client: vaolClient,
      tenantID: "test-org",
      subject: "test-user",
      async: false,
    });

    const result = await fakeClient.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "What is the capital of France?" }],
      temperature: 0.7,
    });

    // Original response is returned
    expect(result).toBe(mockResponse);
    // Original create was called
    expect(originalCreate).toHaveBeenCalledOnce();
    // VAOL append was called (POST to /v1/records)
    expect(mockFetch).toHaveBeenCalled();
    const fetchCall = mockFetch.mock.calls.find((c: any[]) =>
      c[0]?.includes("/v1/records")
    );
    expect(fetchCall).toBeDefined();
  });

  it("should call onError callback on failure", async () => {
    // Make VAOL append fail
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ error: "server error" }),
        text: () => Promise.resolve("server error"),
      })
    );

    const originalCreate = vi.fn().mockResolvedValue({
      choices: [{ message: { content: "Hi" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 5, completion_tokens: 2 },
    });
    const fakeClient = {
      chat: { completions: { create: originalCreate } },
    };
    const vaolClient = new VAOLClient({ baseURL: "http://localhost:8080" });
    const onError = vi.fn();

    instrumentOpenAI(fakeClient, {
      client: vaolClient,
      tenantID: "test",
      subject: "user",
      async: false,
      onError,
    });

    await fakeClient.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Hi" }],
    });

    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);
  });
});
