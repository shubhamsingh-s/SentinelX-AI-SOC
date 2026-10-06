"""Async Redis client pool and health check module."""

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from redis.asyncio import Redis

from sentinel_common.config import settings
from sentinel_common.logger import logger

# Global Redis pool
redis_client: Redis = aioredis.from_url(  # type: ignore[no-untyped-call]
    settings.get_redis_url,
    encoding="utf-8",
    decode_responses=True,
)


async def get_redis_client() -> AsyncGenerator[Redis, None]:
    """Dependency provider for async Redis client."""
    yield redis_client


async def check_redis_health() -> bool:
    """Verify Redis connection for /ready endpoint."""
    try:
        ping_res = await redis_client.ping()
        return bool(ping_res)
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return False
