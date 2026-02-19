"""DecisionRecord builder for constructing VAOL evidence records."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OutputMode(StrEnum):
    HASH_ONLY = "hash_only"
    ENCRYPTED = "encrypted"
    PLAINTEXT = "plaintext"


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ALLOW_WITH_TRANSFORM = "allow_with_transform"
    LOG_ONLY = "log_only"


class Identity(BaseModel):
    tenant_id: str
    subject: str
    subject_type: str = "user"
    claims: dict[str, str] = Field(default_factory=dict)


class AuthContext(BaseModel):
    issuer: str = ""
    subject: str = ""
    token_hash: str = ""
    source: str = ""
    authenticated: bool = False


class ModelInfo(BaseModel):
    provider: str
    name: str
    version: str = ""
    endpoint: str = ""
    deployment_id: str = ""


class Parameters(BaseModel):
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    frequency_penalty: float | None = None
    presence_penalty: float | None = None
    stop_sequences: list[str] = Field(default_factory=list)
    seed: int | None = None
    tools_enabled: bool | None = None
    response_format: str = ""


class PromptContext(BaseModel):
    system_prompt_hash: str = ""
    user_prompt_hash: str
    user_prompt_template_hash: str = ""
    user_prompt_template_id: str = ""
    tool_schema_hash: str = ""
    safety_prompt_hash: str = ""
    message_count: int = 0
    total_input_tokens: int = 0


class PolicyContext(BaseModel):
    policy_bundle_id: str = ""
    policy_hash: str = ""
    policy_decision: PolicyDecision = PolicyDecision.LOG_ONLY
    decision_reason_code: str = ""
    rule_ids: list[str] = Field(default_factory=list)
    transforms_applied: list[dict[str, str]] = Field(default_factory=list)
    policy_engine_version: str = ""
    evaluation_duration_ms: float = 0


class Output(BaseModel):
    output_hash: str
    mode: OutputMode = OutputMode.HASH_ONLY
    output_encrypted: str = ""
    output_encrypted_ref: str = ""
    output_encrypted_hash: str = ""
    output_plaintext: str = ""
    output_tokens: int = 0
    finish_reason: str = ""
    latency_ms: float = 0


class Trace(BaseModel):
    otel_trace_id: str = ""
    otel_span_id: str = ""
    parent_request_id: str = ""
    session_id: str = ""


class Integrity(BaseModel):
    record_hash: str = ""
    sequence_number: int = 0
    previous_record_hash: str = ""
    merkle_root: str = ""
    merkle_tree_size: int = 0
    inclusion_proof_ref: str = ""


class DecisionRecord(BaseModel):
    """A VAOL DecisionRecord v1."""

    schema_version: str = "v1"
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    identity: Identity
    auth_context: AuthContext | None = None
    model: ModelInfo
    parameters: Parameters = Field(default_factory=Parameters)
    prompt_context: PromptContext
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    rag_context: dict[str, Any] | None = None
    output: Output
    trace: Trace = Field(default_factory=Trace)
    integrity: Integrity = Field(default_factory=Integrity)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary, excluding None values."""
        return self.model_dump(exclude_none=True)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return self.model_dump_json(exclude_none=True)


def sha256_hash(data: str | bytes) -> str:
    """Compute a SHA-256 hash with the 'sha256:' prefix."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def hash_messages(messages: list[dict[str, Any]]) -> str:
    """Hash a list of chat messages (OpenAI format) deterministically."""
    canonical = json.dumps(messages, sort_keys=True, separators=(",", ":"))
    return sha256_hash(canonical)
