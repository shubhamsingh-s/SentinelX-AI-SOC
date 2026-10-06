"""Unit & Integration tests for /health and /ready endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient) -> None:
    """Verify /health returns HTTP 200 with service status."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ok", "service": "auth-service"}


@pytest.mark.asyncio
async def test_api_v1_health_check(client: AsyncClient) -> None:
    """Verify /api/v1/health returns HTTP 200 with service status."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ok", "service": "auth-service"}


@pytest.mark.asyncio
async def test_ready_check_healthy(client: AsyncClient, mock_db_redis_healthy: None) -> None:
    """Verify /ready returns HTTP 200 when DB and Redis are healthy."""
    response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ready", "database": "ok", "redis": "ok"}


@pytest.mark.asyncio
async def test_ready_check_unhealthy(client: AsyncClient, mock_db_unhealthy: None) -> None:
    """Verify /ready returns HTTP 503 when downstream service fails."""
    response = await client.get("/ready")
    assert response.status_code == 503
    data = response.json()
    assert data == {"status": "unhealthy", "database": "error", "redis": "ok"}
