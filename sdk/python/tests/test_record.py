"""Tests for the VAOL DecisionRecord builder and utilities."""

import json
import uuid

import pytest
from vaol.record import (
    DecisionRecord,
    Identity,
    Integrity,
    ModelInfo,
    Output,
    OutputMode,
    Parameters,
    PolicyContext,
    PolicyDecision,
    PromptContext,
    Trace,
    hash_messages,
    sha256_hash,
)


class TestSHA256Hash:
    def test_hash_string(self):
        h = sha256_hash("hello")
        assert h.startswith("sha256:")
        assert len(h) == 71  # "sha256:" (7) + 64 hex chars

    def test_hash_bytes(self):
        h = sha256_hash(b"hello")
        assert h.startswith("sha256:")

    def test_deterministic(self):
        h1 = sha256_hash("test data")
        h2 = sha256_hash("test data")
        assert h1 == h2

    def test_different_inputs(self):
        h1 = sha256_hash("input A")
        h2 = sha256_hash("input B")
        assert h1 != h2

    def test_empty_string(self):
        h = sha256_hash("")
        assert h.startswith("sha256:")
        assert len(h) == 71


class TestHashMessages:
    def test_single_message(self):
        msgs = [{"role": "user", "content": "Hello"}]
        h = hash_messages(msgs)
        assert h.startswith("sha256:")

    def test_deterministic(self):
        msgs = [{"role": "user", "content": "test"}]
        h1 = hash_messages(msgs)
        h2 = hash_messages(msgs)
        assert h1 == h2

    def test_order_independent_keys(self):
        # JSON sort_keys ensures key order doesn't matter
        msgs1 = [{"content": "Hello", "role": "user"}]
        msgs2 = [{"role": "user", "content": "Hello"}]
        h1 = hash_messages(msgs1)
        h2 = hash_messages(msgs2)
        assert h1 == h2

    def test_multiple_messages(self):
        msgs = [
            {"role": "system", "content": "Be helpful"},
            {"role": "user", "content": "Hello"},
        ]
        h = hash_messages(msgs)
        assert h.startswith("sha256:")


class TestDecisionRecord:
    @pytest.fixture()
    def minimal_record(self):
        return DecisionRecord(
            identity=Identity(tenant_id="test-org", subject="user-1"),
            model=ModelInfo(provider="openai", name="gpt-4o"),
            prompt_context=PromptContext(
                user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            output=Output(
                output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                mode=OutputMode.HASH_ONLY,
            ),
        )

    def test_schema_version(self, minimal_record):
        assert minimal_record.schema_version == "v1"

    def test_auto_request_id(self, minimal_record):
        # Should be a valid UUID
        uuid.UUID(minimal_record.request_id)

    def test_auto_timestamp(self, minimal_record):
        assert minimal_record.timestamp != ""

    def test_identity(self, minimal_record):
        assert minimal_record.identity.tenant_id == "test-org"
        assert minimal_record.identity.subject == "user-1"
        assert minimal_record.identity.subject_type == "user"

    def test_model(self, minimal_record):
        assert minimal_record.model.provider == "openai"
        assert minimal_record.model.name == "gpt-4o"

    def test_default_policy_context(self, minimal_record):
        assert minimal_record.policy_context.policy_decision == PolicyDecision.LOG_ONLY

    def test_to_dict(self, minimal_record):
        d = minimal_record.to_dict()
        assert isinstance(d, dict)
        assert d["schema_version"] == "v1"
        assert d["identity"]["tenant_id"] == "test-org"
        assert d["output"]["mode"] == "hash_only"

    def test_to_json(self, minimal_record):
        j = minimal_record.to_json()
        parsed = json.loads(j)
        assert parsed["schema_version"] == "v1"

    def test_custom_parameters(self):
        rec = DecisionRecord(
            identity=Identity(tenant_id="t", subject="s"),
            model=ModelInfo(provider="openai", name="gpt-4o"),
            parameters=Parameters(temperature=0.7, max_tokens=1000, top_p=0.9),
            prompt_context=PromptContext(
                user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            output=Output(
                output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                mode=OutputMode.HASH_ONLY,
            ),
        )
        d = rec.to_dict()
        assert d["parameters"]["temperature"] == 0.7
        assert d["parameters"]["max_tokens"] == 1000

    def test_encrypted_output_mode(self):
        rec = DecisionRecord(
            identity=Identity(tenant_id="t", subject="s"),
            model=ModelInfo(provider="openai", name="gpt-4o"),
            prompt_context=PromptContext(
                user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            output=Output(
                output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                mode=OutputMode.ENCRYPTED,
                output_encrypted="base64-encoded-ciphertext",
            ),
        )
        assert rec.output.mode == OutputMode.ENCRYPTED
        assert rec.output.output_encrypted == "base64-encoded-ciphertext"

    def test_rag_context(self):
        rec = DecisionRecord(
            identity=Identity(tenant_id="t", subject="s"),
            model=ModelInfo(provider="openai", name="gpt-4o"),
            prompt_context=PromptContext(
                user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            output=Output(
                output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                mode=OutputMode.HASH_ONLY,
            ),
            rag_context={
                "connector_ids": ["conn-1"],
                "document_ids": ["doc-1", "doc-2"],
                "chunk_hashes": ["sha256:aaa"],
            },
        )
        d = rec.to_dict()
        assert "rag_context" in d
        assert d["rag_context"]["connector_ids"] == ["conn-1"]

    def test_trace_fields(self):
        rec = DecisionRecord(
            identity=Identity(tenant_id="t", subject="s"),
            model=ModelInfo(provider="openai", name="gpt-4o"),
            prompt_context=PromptContext(
                user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            output=Output(
                output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                mode=OutputMode.HASH_ONLY,
            ),
            trace=Trace(
                otel_trace_id="a" * 32,
                otel_span_id="b" * 16,
                session_id="sess-123",
            ),
        )
        d = rec.to_dict()
        assert d["trace"]["otel_trace_id"] == "a" * 32
        assert d["trace"]["session_id"] == "sess-123"

    def test_policy_decisions(self):
        for decision in PolicyDecision:
            rec = DecisionRecord(
                identity=Identity(tenant_id="t", subject="s"),
                model=ModelInfo(provider="openai", name="gpt-4o"),
                prompt_context=PromptContext(
                    user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                ),
                policy_context=PolicyContext(policy_decision=decision),
                output=Output(
                    output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    mode=OutputMode.HASH_ONLY,
                ),
            )
            assert rec.policy_context.policy_decision == decision


class TestIdentity:
    def test_defaults(self):
        ident = Identity(tenant_id="org", subject="user")
        assert ident.subject_type == "user"
        assert ident.claims == {}

    def test_with_claims(self):
        ident = Identity(
            tenant_id="org",
            subject="user",
            claims={"role": "admin", "department": "engineering"},
        )
        assert ident.claims["role"] == "admin"


class TestOutputMode:
    def test_enum_values(self):
        assert OutputMode.HASH_ONLY.value == "hash_only"
        assert OutputMode.ENCRYPTED.value == "encrypted"
        assert OutputMode.PLAINTEXT.value == "plaintext"


class TestPolicyDecision:
    def test_enum_values(self):
        assert PolicyDecision.ALLOW.value == "allow"
        assert PolicyDecision.DENY.value == "deny"
        assert PolicyDecision.ALLOW_WITH_TRANSFORM.value == "allow_with_transform"
        assert PolicyDecision.LOG_ONLY.value == "log_only"
