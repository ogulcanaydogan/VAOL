/**
 * Example: VAOL TypeScript SDK with OpenAI auto-instrumentation.
 *
 * Demonstrates two patterns:
 * 1. Manual DecisionRecord construction and submission
 * 2. Auto-instrumented OpenAI client (zero-code-change integration)
 *
 * Usage:
 *   npm install @vaol/sdk
 *   npx tsx main.ts
 *
 * Requires:
 * - VAOL server at http://localhost:8080 (--auth-mode disabled --policy-mode allow-all)
 * - For Pattern 2: OPENAI_API_KEY environment variable
 */

import { VAOLClient, DecisionRecordBuilder } from "@vaol/sdk";

const VAOL_URL = "http://localhost:8080";

async function manualRecordExample() {
  console.log("=== VAOL TypeScript Example (Manual Record) ===\n");

  const client = new VAOLClient({ baseURL: VAOL_URL });

  // 1. Health check
  const health = await client.health();
  console.log(`1. Server health: ${health.status}\n`);

  // 2. Build a DecisionRecord
  console.log("2. Building DecisionRecord...");
  const record = new DecisionRecordBuilder()
    .setTenant("example-org", "demo-user", "user")
    .setModel("openai", "gpt-4o", "2025-01-01")
    .setParameters({ temperature: 0.7, max_tokens: 1024 })
    .setPromptHash(
      VAOLClient.sha256("What is the capital of France?"),
      VAOLClient.sha256("You are a helpful assistant.")
    )
    .setPolicyDecision("allow")
    .setOutputHash(VAOLClient.sha256("The capital of France is Paris."))
    .setOutputMeta({ outputTokens: 8, finishReason: "stop", latencyMs: 245.3 })
    .build();

  console.log(`   request_id: ${record.request_id}\n`);

  // 3. Append to ledger
  console.log("3. Appending to ledger...");
  const receipt = await client.append(record);
  console.log(`   sequence: ${receipt.sequence_number}\n`);

  // 4. Retrieve
  console.log("4. Retrieving record...");
  const stored = await client.get(record.request_id);
  console.log(`   Retrieved successfully\n`);

  // 5. Verify
  console.log("5. Verifying DSSE envelope...");
  const result = await client.verify((stored as any).envelope);
  console.log(`   Valid: ${result.valid}`);
  for (const check of result.checks ?? []) {
    const status = check.passed ? "PASS" : "FAIL";
    console.log(`   - ${check.name}: ${status}`);
  }
  console.log();

  // 6. Checkpoint
  console.log("6. Fetching checkpoint...");
  const checkpoint = (await client.checkpoint()) as any;
  console.log(`   Root: ${checkpoint.root_hash}`);
  console.log(`   Tree size: ${checkpoint.tree_size}\n`);

  // 7. Export
  console.log("7. Exporting audit bundle...");
  const bundle = (await client.exportBundle({
    tenantID: "example-org",
  })) as any;
  const records = bundle.records ?? [];
  console.log(`   Bundle contains ${records.length} record(s)`);

  console.log("\nDone.");
}

/*
 * Pattern 2: Auto-instrumented OpenAI client
 *
 * Uncomment to run against a real OpenAI API:
 *
 * import OpenAI from "openai";
 * import { instrumentOpenAI } from "@vaol/sdk";
 *
 * async function instrumentedExample() {
 *   const openai = new OpenAI();
 *   const vaol = new VAOLClient({ baseURL: VAOL_URL });
 *
 *   instrumentOpenAI(openai, {
 *     client: vaol,
 *     tenantID: "example-org",
 *     subject: "demo-service",
 *   });
 *
 *   const response = await openai.chat.completions.create({
 *     model: "gpt-4o",
 *     messages: [
 *       { role: "system", content: "You are a helpful assistant." },
 *       { role: "user", content: "What is the capital of France?" },
 *     ],
 *   });
 *
 *   console.log(`Response: ${response.choices[0].message.content}`);
 *   console.log("DecisionRecord was automatically emitted to VAOL.");
 * }
 */

manualRecordExample().catch(console.error);
