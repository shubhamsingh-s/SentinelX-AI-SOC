"""Pytest fixtures for SentinelX testing with mock database and Redis dependencies."""

from collections.abc import AsyncGenerator, Generator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sentinel_common.db import Base, get_db_session
from sentinel_common.redis import get_redis_client
from services.auth_service.app.main import app

# SQLite Async Engine for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)


async def override_get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Override database session dependency with in-memory SQLite engine."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def override_get_redis_client() -> AsyncGenerator[AsyncMock, None]:
    """Override Redis client dependency with AsyncMock."""
    mock_redis = AsyncMock()
    mock_redis.ping.return_value = True
    mock_redis.xadd.return_value = "1600000000000-0"
    yield mock_redis


# Apply FastAPI dependency overrides for testing
app.dependency_overrides[get_db_session] = override_get_db_session
app.dependency_overrides[get_redis_client] = override_get_redis_client


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
