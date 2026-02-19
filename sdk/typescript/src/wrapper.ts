import { VAOLClient } from "./client.js";
import { DecisionRecordBuilder } from "./record.js";

export interface InstrumentOptions {
  /** VAOL client instance for sending records. */
  client: VAOLClient;
  /** Tenant ID to associate with records. */
  tenantID: string;
  /** Subject identity (user ID, service name, etc.). */
  subject: string;
  /** Subject type. Default: "service". */
  subjectType?: "user" | "service" | "pipeline";
  /** Policy decision to attach. Default: "allow". */
  policyDecision?: "allow" | "deny" | "allow_with_transform" | "log_only";
  /** Whether to send records asynchronously (fire-and-forget). Default: true. */
  async?: boolean;
  /** Callback invoked on record send errors. */
  onError?: (error: Error) => void;
}

/**
 * Instruments an OpenAI client instance to automatically emit
 * VAOL DecisionRecords for every chat completion call.
 *
 * Usage:
 * ```ts
 * import OpenAI from "openai";
 * import { VAOLClient, instrumentOpenAI } from "@vaol/sdk";
 *
 * const openai = new OpenAI();
 * const vaol = new VAOLClient({ baseURL: "http://localhost:8080" });
 *
 * instrumentOpenAI(openai, {
 *   client: vaol,
 *   tenantID: "my-tenant",
 *   subject: "my-service",
 * });
 *
 * // Now every openai.chat.completions.create() call is recorded
 * const response = await openai.chat.completions.create({
 *   model: "gpt-4o",
 *   messages: [{ role: "user", content: "Hello" }],
 * });
 * ```
 */
export function instrumentOpenAI(
  openaiClient: unknown,
  options: InstrumentOptions
): void {
  const client = openaiClient as {
    chat?: {
      completions?: {
        create?: (...args: unknown[]) => Promise<unknown>;
      };
    };
  };

  if (!client?.chat?.completions?.create) {
    throw new Error(
      "Invalid OpenAI client: missing chat.completions.create method"
    );
  }

  const originalCreate = client.chat.completions.create.bind(
    client.chat.completions
  );

  client.chat.completions.create = async (
    ...args: unknown[]
  ): Promise<unknown> => {
    const params = args[0] as Record<string, unknown> | undefined;

    // Capture pre-call evidence
    const startTime = performance.now();
    const messagesJSON = JSON.stringify(params?.messages ?? []);
    const userPromptHash = VAOLClient.sha256(messagesJSON);

    // Forward the call to OpenAI
    const response = await originalCreate(...args);
    const endTime = performance.now();
    const latencyMs = endTime - startTime;

    // Capture post-call evidence
    const responseJSON = JSON.stringify(response);
    const outputHash = VAOLClient.sha256(responseJSON);

    // Build the DecisionRecord
    const builder = new DecisionRecordBuilder()
      .setTenant(
        options.tenantID,
        options.subject,
        options.subjectType ?? "service"
      )
      .setModel(
        "openai",
        String(params?.model ?? "unknown")
      )
      .setPromptHash(userPromptHash)
      .setPolicyDecision(options.policyDecision ?? "allow")
      .setOutputHash(outputHash)
      .setOutputMeta({
        latencyMs,
        finishReason: extractFinishReason(response),
        outputTokens: extractOutputTokens(response),
      });

    // Set parameters if available
    if (params) {
      builder.setParameters({
        temperature: params.temperature as number | undefined,
        top_p: params.top_p as number | undefined,
        max_tokens: params.max_tokens as number | undefined,
        frequency_penalty: params.frequency_penalty as number | undefined,
        presence_penalty: params.presence_penalty as number | undefined,
        seed: params.seed as number | undefined,
      });
    }

    const record = builder.build();

    // Send the record
    const sendRecord = async () => {
      try {
        await options.client.append(record);
      } catch (err) {
        if (options.onError) {
          options.onError(err instanceof Error ? err : new Error(String(err)));
        }
      }
    };

    if (options.async !== false) {
      // Fire and forget
      sendRecord();
    } else {
      await sendRecord();
    }

    return response;
  };
}

function extractFinishReason(response: unknown): string | undefined {
  const resp = response as {
    choices?: Array<{ finish_reason?: string }>;
  };
  return resp?.choices?.[0]?.finish_reason;
}

function extractOutputTokens(response: unknown): number | undefined {
  const resp = response as {
    usage?: { completion_tokens?: number };
  };
  return resp?.usage?.completion_tokens;
}
