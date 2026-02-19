export { VAOLClient, type VAOLClientOptions } from "./client.js";
export { DecisionRecordBuilder } from "./record.js";
export { instrumentOpenAI, type InstrumentOptions } from "./wrapper.js";
export type {
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
  InclusionProof,
  Receipt,
  DSSEEnvelope,
  DSSESignature,
  VerificationResult,
  CheckResult,
} from "./types.js";
