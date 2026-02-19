# VAOL TypeScript SDK

TypeScript client and instrumentation helpers for the Verifiable AI Output Ledger (VAOL).

## Install

```bash
npm install @vaol/sdk
```

## Quick Start

### Direct Client Usage

```typescript
import { VAOLClient, DecisionRecordBuilder } from "@vaol/sdk";

const client = new VAOLClient({ baseURL: "http://localhost:8080" });

// Build a DecisionRecord
const record = new DecisionRecordBuilder()
  .setTenant("my-org", "user-123", "user")
  .setModel("openai", "gpt-4o")
  .setPromptHash(VAOLClient.sha256("What is the capital of France?"))
  .setPolicyDecision("allow")
  .setOutputHash(VAOLClient.sha256("The capital of France is Paris."))
  .setOutputMeta({ latencyMs: 342, finishReason: "stop", outputTokens: 12 })
  .build();

// Append to ledger
const receipt = await client.append(record);
console.log(`Record stored at sequence ${receipt.sequence_number}`);

// Verify
const result = await client.verify(receipt.envelope);
console.log(`Valid: ${result.valid}`);
```

### OpenAI Auto-Instrumentation

```typescript
import OpenAI from "openai";
import { VAOLClient, instrumentOpenAI } from "@vaol/sdk";

const openai = new OpenAI();
const vaol = new VAOLClient({ baseURL: "http://localhost:8080" });

// Instrument — every chat completion now emits a DecisionRecord
instrumentOpenAI(openai, {
  client: vaol,
  tenantID: "my-org",
  subject: "my-service",
});

// Use OpenAI as usual — records are emitted automatically
const response = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Hello!" }],
});
```

## API Reference

### `VAOLClient`

| Method | Description |
|--------|-------------|
| `append(record)` | Append a DecisionRecord to the ledger |
| `get(requestID)` | Get a record by request ID |
| `list(options?)` | List records with filters |
| `getProof(requestID)` | Get Merkle inclusion proof |
| `verify(envelope)` | Verify a DSSE envelope |
| `checkpoint()` | Get latest Merkle checkpoint |
| `exportBundle(options?)` | Export audit bundle |
| `health()` | Health check |
| `VAOLClient.sha256(data)` | Compute `sha256:`-prefixed hash |

### `DecisionRecordBuilder`

Fluent builder for constructing DecisionRecords:

```typescript
new DecisionRecordBuilder()
  .setTenant(tenantID, subject, subjectType?)
  .setModel(provider, name, version?, endpoint?)
  .setParameters({ temperature, top_p, max_tokens, ... })
  .setPromptHash(userPromptHash, systemPromptHash?)
  .setPolicyDecision(decision, bundleID?, ruleIDs?)
  .setRAGContext({ connector_ids, document_ids, chunk_hashes })
  .setOutputHash(outputHash, mode?)
  .setOutputMeta({ outputTokens, finishReason, latencyMs })
  .setTrace({ otel_trace_id, otel_span_id })
  .build()
```

### `instrumentOpenAI(client, options)`

Auto-instruments an OpenAI client instance. Options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `client` | `VAOLClient` | required | VAOL client instance |
| `tenantID` | `string` | required | Tenant identifier |
| `subject` | `string` | required | User/service identity |
| `subjectType` | `string` | `"service"` | Identity type |
| `policyDecision` | `string` | `"allow"` | Policy decision to attach |
| `async` | `boolean` | `true` | Fire-and-forget record emission |
| `onError` | `function` | `undefined` | Error callback |

## Requirements

- Node.js >= 18.0
- TypeScript >= 5.4 (for development)

## Development

```bash
npm install
npm run build
npm test
npm run lint
```

## License

Apache License 2.0
