/**
 * Dedicated tests for instrumentOpenAI() wrapper.
 *
 * Mirrors the Python SDK's test_wrapper.py coverage, verifying that the
 * wrapper correctly captures evidence from OpenAI-style chat completion
 * calls and emits DecisionRecords to the VAOL server.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VAOLClient } from "../src/client.js";
import { instrumentOpenAI } from "../src/wrapper.js";

// ---------------------------------------------------------------------------
// Helpers — mock OpenAI client and fetch
// ---------------------------------------------------------------------------

interface MockOpenAIResponse {
  choices: Array<{
    message: { content: string };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
  };
}

function makeOpenAIResponse(overrides?: Partial<{
  content: string;
  finishReason: string;
  promptTokens: number;
  completionTokens: number;
}>): MockOpenAIResponse {
  return {
    choices: [
      {
        message: { content: overrides?.content ?? "Hello from GPT!" },
        finish_reason: overrides?.finishReason ?? "stop",
      },
    ],
    usage: {
      prompt_tokens: overrides?.promptTokens ?? 10,
      completion_tokens: overrides?.completionTokens ?? 5,
    },
  };
}

function makeMockOpenAIClient(response?: MockOpenAIResponse) {
  const resp = response ?? makeOpenAIResponse();
  const originalCreate = vi.fn().mockResolvedValue(resp);
  return {
    client: { chat: { completions: { create: originalCreate } } },
    originalCreate,
    response: resp,
  };
}

function makeVAOLClient() {
  return new VAOLClient({ baseURL: "http://localhost:8080" });
}

/** Captures the body of the POST /v1/records call made by the instrumented wrapper. */
function extractRecordFromFetchCalls(
  mockFetch: ReturnType<typeof vi.fn>
): Record<string, unknown> | undefined {
  const call = mockFetch.mock.calls.find(
    (c: unknown[]) => typeof c[0] === "string" && (c[0] as string).includes("/v1/records")
  );
  if (!call) return undefined;
  const opts = call[1] as { body?: string } | undefined;
  return opts?.body ? JSON.parse(opts.body) : undefined;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("instrumentOpenAI — wrapper tests", () => {
  const mockFetch = vi.fn();

  function stubFetchSuccess() {
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: true,
        status: 201,
        json: () =>
          Promise.resolve({
            request_id: "test-id",
            sequence_number: 1,
            record_hash: "sha256:abc",
          }),
        text: () => Promise.resolve(""),
      })
    );
  }

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
    mockFetch.mockReset();
    stubFetchSuccess();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // 1
  it("should throw if client lacks chat.completions.create", () => {
    const vaol = makeVAOLClient();

    expect(() =>
      instrumentOpenAI({}, { client: vaol, tenantID: "t", subject: "s" })
    ).toThrow("Invalid OpenAI client");

    expect(() =>
      instrumentOpenAI(
        { chat: {} },
        { client: vaol, tenantID: "t", subject: "s" }
      )
    ).toThrow("Invalid OpenAI client");

    expect(() =>
      instrumentOpenAI(
        { chat: { completions: {} } },
        { client: vaol, tenantID: "t", subject: "s" }
      )
    ).toThrow("Invalid OpenAI client");
  });

  // 2
  it("should replace chat.completions.create", () => {
    const { client, originalCreate } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "test",
      subject: "user",
    });

    expect(client.chat.completions.create).not.toBe(originalCreate);
  });

  // 3
  it("should forward call and return original response", async () => {
    const { client, originalCreate, response } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "test-org",
      subject: "test-user",
      async: false,
    });

    const result = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "What is the capital of France?" }],
    });

    expect(result).toBe(response);
    expect(originalCreate).toHaveBeenCalledOnce();
  });

  // 4
  it("should emit VAOL record on successful call", async () => {
    const { client } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Hi" }],
    });

    // POST to /v1/records should have been called
    const recordCall = mockFetch.mock.calls.find(
      (c: unknown[]) => typeof c[0] === "string" && (c[0] as string).includes("/v1/records")
    );
    expect(recordCall).toBeDefined();

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    expect((record as any).identity.tenant_id).toBe("acme");
    expect((record as any).identity.subject).toBe("user-1");
    expect((record as any).model.provider).toBe("openai");
    expect((record as any).model.name).toBe("gpt-4o");
  });

  // 5
  it("should capture system prompt hash via user prompt hash from full messages", async () => {
    const { client } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Hello" },
      ],
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    // The wrapper hashes the entire messages array as user_prompt_hash
    const promptHash = (record as any).prompt_context.user_prompt_hash;
    expect(promptHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    // Should be deterministic
    const expectedHash = VAOLClient.sha256(
      JSON.stringify([
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Hello" },
      ])
    );
    expect(promptHash).toBe(expectedHash);
  });

  // 6
  it("should capture output hash", async () => {
    const response = makeOpenAIResponse({ content: "The answer is 42." });
    const { client } = makeMockOpenAIClient(response);
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "What is the meaning of life?" }],
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    const outputHash = (record as any).output.output_hash;
    expect(outputHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    // The wrapper hashes the entire JSON response
    const expectedHash = VAOLClient.sha256(JSON.stringify(response));
    expect(outputHash).toBe(expectedHash);
  });

  // 7
  it("should capture token counts (prompt + completion)", async () => {
    const response = makeOpenAIResponse({
      promptTokens: 50,
      completionTokens: 25,
    });
    const { client } = makeMockOpenAIClient(response);
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Count tokens" }],
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    expect((record as any).output.output_tokens).toBe(25);
  });

  // 8
  it("should capture model parameter", async () => {
    const { client } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "Test" }],
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    expect((record as any).model.name).toBe("gpt-4o-mini");
  });

  // 9
  it("should capture temperature parameter", async () => {
    const { client } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Test" }],
      temperature: 0.5,
      top_p: 0.9,
      max_tokens: 200,
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    expect((record as any).parameters.temperature).toBe(0.5);
    expect((record as any).parameters.top_p).toBe(0.9);
    expect((record as any).parameters.max_tokens).toBe(200);
  });

  // 10
  it("should not block response when VAOL fails", async () => {
    // Make VAOL append fail
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ error: "server error" }),
        text: () => Promise.resolve("server error"),
      })
    );

    const openaiResponse = makeOpenAIResponse({ content: "still works" });
    const { client } = makeMockOpenAIClient(openaiResponse);
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    const result = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Hello" }],
    });

    // Original OpenAI response is returned despite VAOL failure
    expect(result).toBe(openaiResponse);
  });

  // 11
  it("should capture finish reason", async () => {
    const response = makeOpenAIResponse({ finishReason: "length" });
    const { client } = makeMockOpenAIClient(response);
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Long output" }],
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    expect((record as any).output.finish_reason).toBe("length");
  });

  // 12
  it("should capture latency", async () => {
    const { client } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "acme",
      subject: "user-1",
      async: false,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Test" }],
    });

    const record = extractRecordFromFetchCalls(mockFetch);
    expect(record).toBeDefined();
    // Latency should be a positive number (though mock calls are nearly instant)
    expect((record as any).output.latency_ms).toBeGreaterThanOrEqual(0);
  });

  // 13
  it("should call onError callback on VAOL failure", async () => {
    // Make VAOL append fail
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ error: "server error" }),
        text: () => Promise.resolve("server error"),
      })
    );

    const { client } = makeMockOpenAIClient();
    const vaol = makeVAOLClient();
    const onError = vi.fn();

    instrumentOpenAI(client, {
      client: vaol,
      tenantID: "test",
      subject: "user",
      async: false,
      onError,
    });

    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "Hi" }],
    });

    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);
  });
});
