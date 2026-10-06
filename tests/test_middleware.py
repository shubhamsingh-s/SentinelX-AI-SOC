"""Tests for RequestIDMiddleware and header propagation."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_middleware_generates_request_id(client: AsyncClient) -> None:
    """Ensure middleware generates X-Request-ID if absent in request headers."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    assert response.headers["X-Request-ID"].startswith("req-")


@pytest.mark.asyncio
async def test_middleware_preserves_custom_request_id(client: AsyncClient) -> None:
    """Ensure middleware preserves incoming X-Request-ID header."""
    custom_id = "req-custom-test-12345"
    response = await client.get("/health", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_id


@pytest.mark.asyncio
async def test_middleware_propagates_tenant_id(client: AsyncClient) -> None:
    """Ensure middleware propagates X-Tenant-ID header when supplied."""
    tenant_id = "00000000-0000-0000-0000-000000000001"
    response = await client.get("/health", headers={"X-Tenant-ID": tenant_id})
    assert response.status_code == 200
    assert response.headers.get("X-Tenant-ID") == tenant_id
