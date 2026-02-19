"""Tests for the VAOL HTTP client (using httpx mock transport)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from vaol.client import AsyncVAOLClient, VAOLClient
from vaol.record import DecisionRecord, Identity, ModelInfo, Output, OutputMode, PromptContext


def _mock_record() -> DecisionRecord:
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


def _mock_transport(responses: dict[str, Any]) -> httpx.MockTransport:
    """Create a mock transport that returns canned responses keyed by path."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for key, resp_data in responses.items():
            if path.endswith(key) or path == key:
                return httpx.Response(
                    status_code=resp_data.get("status", 200),
                    json=resp_data.get("json", {}),
                )
        return httpx.Response(status_code=404, json={"error": "not found"})

    return httpx.MockTransport(handler)


class TestVAOLClient:
    def test_health(self):
        transport = _mock_transport(
            {"/v1/health": {"json": {"status": "ok", "version": "0.1.0"}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.health()
        assert result["status"] == "ok"
        client.close()

    def test_append(self):
        receipt = {
            "request_id": "123e4567-e89b-12d3-a456-426614174000",
            "sequence_number": 0,
            "record_hash": "sha256:abc",
        }
        transport = _mock_transport(
            {"/v1/records": {"status": 201, "json": receipt}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.append(_mock_record())
        assert result["sequence_number"] == 0
        client.close()

    def test_get(self):
        stored = {"request_id": "abc-123", "tenant_id": "test-org"}
        transport = _mock_transport(
            {"/v1/records/abc-123": {"json": stored}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.get("abc-123")
        assert result["request_id"] == "abc-123"
        client.close()

    def test_list(self):
        transport = _mock_transport(
            {"/v1/records": {"json": {"records": [], "count": 0}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.list(tenant_id="test-org", limit=10)
        assert result["count"] == 0
        client.close()

    def test_checkpoint(self):
        transport = _mock_transport(
            {"/v1/ledger/checkpoint": {"json": {"tree_size": 100, "root_hash": "sha256:abc"}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.checkpoint()
        assert result["tree_size"] == 100
        client.close()

    def test_export(self):
        transport = _mock_transport(
            {"/v1/export": {"json": {"records": [], "metadata": {"total_records": 0}}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.export(tenant_id="test-org")
        assert result["metadata"]["total_records"] == 0
        client.close()

    def test_context_manager(self):
        transport = _mock_transport(
            {"/v1/health": {"json": {"status": "ok"}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        with client:
            result = client.health()
            assert result["status"] == "ok"

    def test_verify(self):
        transport = _mock_transport(
            {"/v1/verify": {"json": {"valid": True, "checks": []}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.verify({"payloadType": "test", "payload": "dGVzdA", "signatures": []})
        assert result["valid"] is True
        client.close()

    def test_get_proof(self):
        transport = _mock_transport(
            {"/proof": {"json": {"proof_type": "inclusion", "leaf_index": 5}}}
        )
        client = VAOLClient.__new__(VAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")

        result = client.get_proof("abc-123")
        assert result["proof_type"] == "inclusion"
        client.close()


class TestAsyncVAOLClient:
    @pytest.mark.asyncio
    async def test_health(self):
        transport = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"status": "ok"})
        )
        client = AsyncVAOLClient.__new__(AsyncVAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8080")

        result = await client.health()
        assert result["status"] == "ok"
        await client.close()

    @pytest.mark.asyncio
    async def test_append(self):
        receipt = {"request_id": "abc", "sequence_number": 0}
        transport = httpx.MockTransport(
            lambda req: httpx.Response(201, json=receipt)
        )
        client = AsyncVAOLClient.__new__(AsyncVAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8080")

        result = await client.append(_mock_record())
        assert result["sequence_number"] == 0
        await client.close()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        transport = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"status": "ok"})
        )
        client = AsyncVAOLClient.__new__(AsyncVAOLClient)
        client.server_url = "http://localhost:8080"
        client._client = httpx.AsyncClient(transport=transport, base_url="http://localhost:8080")

        async with client:
            result = await client.health()
            assert result["status"] == "ok"
