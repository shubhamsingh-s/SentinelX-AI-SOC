"""Pytest fixtures for SentinelX testing."""

from collections.abc import AsyncGenerator, Generator
from unittest.mock import AsyncMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from services.auth_service.app.main import app


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client fixture."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def mock_db_redis_healthy() -> Generator[None, None, None]:
    """Fixture mocking DB and Redis health checks as operational."""
    with (
        patch("services.auth_service.app.api.v1.health.check_db_health", new_callable=AsyncMock) as mock_db,
        patch("services.auth_service.app.api.v1.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
    ):
        mock_db.return_value = True
        mock_redis.return_value = True
        yield


@pytest.fixture
def mock_db_unhealthy() -> Generator[None, None, None]:
    """Fixture mocking DB as failing health check."""
    with (
        patch("services.auth_service.app.api.v1.health.check_db_health", new_callable=AsyncMock) as mock_db,
        patch("services.auth_service.app.api.v1.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
    ):
        mock_db.return_value = False
        mock_redis.return_value = True
        yield
