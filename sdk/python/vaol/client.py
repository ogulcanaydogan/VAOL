"""VAOL server HTTP client for appending and querying decision records."""

from __future__ import annotations

from typing import Any, cast

import httpx

from vaol.record import DecisionRecord


def _decode_json_object(resp: httpx.Response) -> dict[str, Any]:
    """Decode JSON payloads as object responses for strict typing."""
    body = resp.json()
    if not isinstance(body, dict):
        raise TypeError("expected JSON object response")
    return cast(dict[str, Any], body)


class VAOLClient:
    """HTTP client for the VAOL ledger server."""

    def __init__(
        self,
        server_url: str = "http://localhost:8080",
        timeout: float = 30.0,
        tenant_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.tenant_id = tenant_id
        merged_headers = dict(headers or {})
        if tenant_id and "X-VAOL-Tenant-ID" not in merged_headers:
            merged_headers["X-VAOL-Tenant-ID"] = tenant_id
        self._client = httpx.Client(
            base_url=self.server_url,
            timeout=timeout,
            headers=merged_headers,
        )

    def append(self, record: DecisionRecord) -> dict[str, Any]:
        """Append a DecisionRecord to the ledger. Returns the receipt."""
        tenant_header = self._tenant_headers(record.identity.tenant_id)
        resp = self._client.post("/v1/records", json=record.to_dict(), headers=tenant_header)
        resp.raise_for_status()
        return _decode_json_object(resp)

    def get(self, request_id: str) -> dict[str, Any]:
        """Retrieve a record by request ID."""
        resp = self._client.get(f"/v1/records/{request_id}", headers=self._tenant_headers())
        resp.raise_for_status()
        return _decode_json_object(resp)

    def list(
        self,
        tenant_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 100,
        cursor: int | None = None,
    ) -> dict[str, Any]:
        """List records with optional filters."""
        params: dict[str, Any] = {"limit": limit}
        if tenant_id:
            params["tenant_id"] = tenant_id
        if after:
            params["after"] = after
        if before:
            params["before"] = before
        if cursor is not None:
            params["cursor"] = cursor

        resp = self._client.get("/v1/records", params=params, headers=self._tenant_headers(tenant_id))
        resp.raise_for_status()
        return _decode_json_object(resp)

    def get_proof(self, request_id: str) -> dict[str, Any]:
        """Get the Merkle inclusion proof for a record."""
        resp = self._client.get(f"/v1/records/{request_id}/proof", headers=self._tenant_headers())
        resp.raise_for_status()
        return _decode_json_object(resp)

    def verify(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Verify a DSSE envelope."""
        resp = self._client.post("/v1/verify", json=envelope)
        resp.raise_for_status()
        return _decode_json_object(resp)

    def export(
        self,
        tenant_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Export records as an audit bundle."""
        body: dict[str, Any] = {"limit": limit}
        if tenant_id:
            body["tenant_id"] = tenant_id
        if after:
            body["after"] = after
        if before:
            body["before"] = before

        resp = self._client.post("/v1/export", json=body, headers=self._tenant_headers(tenant_id))
        resp.raise_for_status()
        return _decode_json_object(resp)

    def health(self) -> dict[str, Any]:
        """Check server health."""
        resp = self._client.get("/v1/health")
        resp.raise_for_status()
        return _decode_json_object(resp)

    def checkpoint(self) -> dict[str, Any]:
        """Get the latest Merkle checkpoint."""
        resp = self._client.get("/v1/ledger/checkpoint")
        resp.raise_for_status()
        return _decode_json_object(resp)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> VAOLClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _tenant_headers(self, tenant_id: str | None = None) -> dict[str, str] | None:
        tenant = tenant_id or getattr(self, "tenant_id", None)
        if not tenant:
            return None
        return {"X-VAOL-Tenant-ID": tenant}


class AsyncVAOLClient:
    """Async HTTP client for the VAOL ledger server."""

    def __init__(
        self,
        server_url: str = "http://localhost:8080",
        timeout: float = 30.0,
        tenant_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.tenant_id = tenant_id
        merged_headers = dict(headers or {})
        if tenant_id and "X-VAOL-Tenant-ID" not in merged_headers:
            merged_headers["X-VAOL-Tenant-ID"] = tenant_id
        self._client = httpx.AsyncClient(
            base_url=self.server_url,
            timeout=timeout,
            headers=merged_headers,
        )

    async def append(self, record: DecisionRecord) -> dict[str, Any]:
        """Append a DecisionRecord to the ledger."""
        tenant_header = self._tenant_headers(record.identity.tenant_id)
        resp = await self._client.post("/v1/records", json=record.to_dict(), headers=tenant_header)
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def get(self, request_id: str) -> dict[str, Any]:
        """Retrieve a record by request ID."""
        resp = await self._client.get(f"/v1/records/{request_id}", headers=self._tenant_headers())
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def list(
        self,
        tenant_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 100,
        cursor: int | None = None,
    ) -> dict[str, Any]:
        """List records with optional filters."""
        params: dict[str, Any] = {"limit": limit}
        if tenant_id:
            params["tenant_id"] = tenant_id
        if after:
            params["after"] = after
        if before:
            params["before"] = before
        if cursor is not None:
            params["cursor"] = cursor

        resp = await self._client.get("/v1/records", params=params, headers=self._tenant_headers(tenant_id))
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def get_proof(self, request_id: str) -> dict[str, Any]:
        """Get the Merkle inclusion proof for a record."""
        resp = await self._client.get(f"/v1/records/{request_id}/proof", headers=self._tenant_headers())
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def verify(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Verify a DSSE envelope."""
        resp = await self._client.post("/v1/verify", json=envelope)
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def export(
        self,
        tenant_id: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Export records as an audit bundle."""
        body: dict[str, Any] = {"limit": limit}
        if tenant_id:
            body["tenant_id"] = tenant_id
        if after:
            body["after"] = after
        if before:
            body["before"] = before

        resp = await self._client.post("/v1/export", json=body, headers=self._tenant_headers(tenant_id))
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def health(self) -> dict[str, Any]:
        """Check server health."""
        resp = await self._client.get("/v1/health")
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def checkpoint(self) -> dict[str, Any]:
        """Get the latest Merkle checkpoint."""
        resp = await self._client.get("/v1/ledger/checkpoint")
        resp.raise_for_status()
        return _decode_json_object(resp)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncVAOLClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _tenant_headers(self, tenant_id: str | None = None) -> dict[str, str] | None:
        tenant = tenant_id or getattr(self, "tenant_id", None)
        if not tenant:
            return None
        return {"X-VAOL-Tenant-ID": tenant}
