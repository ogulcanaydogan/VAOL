import { createHash } from "node:crypto";
import type {
  DecisionRecord,
  Receipt,
  VerificationResult,
  DSSEEnvelope,
} from "./types.js";

export interface VAOLClientOptions {
  /** VAOL server base URL (e.g., "http://localhost:8080"). */
  baseURL: string;
  /** API key or bearer token for authentication. */
  apiKey?: string;
  /** Tenant ID to use for all requests. */
  tenantID?: string;
  /** Request timeout in milliseconds. Default: 30000. */
  timeout?: number;
}

interface ListOptions {
  tenantID?: string;
  after?: Date;
  before?: Date;
  model?: string;
  policyDecision?: string;
  limit?: number;
  cursor?: string;
}

/**
 * VAOLClient provides methods for interacting with a VAOL ledger server.
 */
export class VAOLClient {
  private baseURL: string;
  private apiKey?: string;
  private tenantID?: string;
  private timeout: number;

  constructor(options: VAOLClientOptions) {
    this.baseURL = options.baseURL.replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.tenantID = options.tenantID;
    this.timeout = options.timeout ?? 30_000;
  }

  /** Append a DecisionRecord to the ledger. Returns a Receipt. */
  async append(record: DecisionRecord): Promise<Receipt> {
    const tenantHeader =
      this.tenantID || !record.identity?.tenant_id
        ? undefined
        : { "X-VAOL-Tenant-ID": record.identity.tenant_id };
    const resp = await this.request<Receipt>(
      "POST",
      "/v1/records",
      record,
      tenantHeader
    );
    return resp;
  }

  /** Get a record by its request ID. */
  async get(requestID: string): Promise<DecisionRecord> {
    return this.request<DecisionRecord>("GET", `/v1/records/${requestID}`);
  }

  /** List records with optional filters. */
  async list(options?: ListOptions): Promise<DecisionRecord[]> {
    const params = new URLSearchParams();
    if (options?.tenantID) params.set("tenant_id", options.tenantID);
    if (options?.after) params.set("after", options.after.toISOString());
    if (options?.before) params.set("before", options.before.toISOString());
    if (options?.model) params.set("model", options.model);
    if (options?.policyDecision)
      params.set("policy_decision", options.policyDecision);
    if (options?.limit) params.set("limit", String(options.limit));
    if (options?.cursor) params.set("cursor", options.cursor);

    const query = params.toString();
    const path = query ? `/v1/records?${query}` : "/v1/records";
    const tenantHeader =
      this.tenantID || !options?.tenantID
        ? undefined
        : { "X-VAOL-Tenant-ID": options.tenantID };
    return this.request<DecisionRecord[]>("GET", path, undefined, tenantHeader);
  }

  /** Get a Merkle inclusion proof for a record. */
  async getProof(requestID: string): Promise<unknown> {
    return this.request("GET", `/v1/records/${requestID}/proof`);
  }

  /** Verify a single record or DSSE envelope. */
  async verify(envelope: DSSEEnvelope): Promise<VerificationResult> {
    return this.request<VerificationResult>("POST", "/v1/verify", envelope);
  }

  /** Get the latest signed Merkle checkpoint. */
  async checkpoint(): Promise<unknown> {
    return this.request("GET", "/v1/ledger/checkpoint");
  }

  /** Export records as an audit bundle. */
  async exportBundle(options?: {
    tenantID?: string;
    after?: Date;
    before?: Date;
  }): Promise<unknown> {
    const tenantHeader =
      this.tenantID || !options?.tenantID
        ? undefined
        : { "X-VAOL-Tenant-ID": options.tenantID };
    return this.request(
      "POST",
      "/v1/export",
      {
      tenant_id: options?.tenantID ?? this.tenantID,
      after: options?.after?.toISOString(),
      before: options?.before?.toISOString(),
      },
      tenantHeader
    );
  }

  /** Health check. */
  async health(): Promise<{ status: string }> {
    return this.request<{ status: string }>("GET", "/v1/health");
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>
  ): Promise<T> {
    const url = `${this.baseURL}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }
    if (this.tenantID) {
      headers["X-VAOL-Tenant-ID"] = this.tenantID;
    }
    if (extraHeaders) {
      Object.assign(headers, extraHeaders);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(
          `VAOL API error ${resp.status}: ${text.substring(0, 500)}`
        );
      }

      return (await resp.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Compute SHA-256 hash with "sha256:" prefix.
   * Utility method for hashing prompts and outputs before sending to VAOL.
   */
  static sha256(data: string | Buffer): string {
    const hash = createHash("sha256")
      .update(data)
      .digest("hex");
    return `sha256:${hash}`;
  }
}
