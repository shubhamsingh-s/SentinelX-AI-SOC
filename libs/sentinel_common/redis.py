"""Async Redis client pool, health check, token blacklisting, and rate limiting module."""

from collections.abc import AsyncGenerator
from typing import Any

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


async def blacklist_jti(client: Any, jti: str, ttl_seconds: int = 900) -> None:
    """Blacklist a JWT JTI ID in Redis upon user logout or revocation."""
    key = f"jti_blacklist:{jti}"
    try:
        await client.setex(key, ttl_seconds, "true")
    except Exception as e:
        logger.error(f"Error blacklisting JTI {jti}: {e}")


async def is_jti_blacklisted(client: Any, jti: str) -> bool:
    """Check whether a JWT JTI ID is currently blacklisted in Redis."""
    key = f"jti_blacklist:{jti}"
    try:
        val = await client.get(key)
        return val in ("true", True, "1")
    except Exception as e:
        logger.error(f"Error checking JTI blacklist for {jti}: {e}")
        return False


async def record_failed_login(client: Any, identifier: str, max_attempts: int = 5, lockout_seconds: int = 900) -> int:
    """Record a failed login attempt and set brute-force lockout if limit is reached."""
    key = f"failed_logins:{identifier.lower()}"
    lockout_key = f"lockout:{identifier.lower()}"
    try:
        attempts = await client.incr(key)
        if isinstance(attempts, (int, float)):
            if attempts == 1:
                await client.expire(key, lockout_seconds)
            if attempts >= max_attempts:
                await client.setex(lockout_key, lockout_seconds, "locked")
            return int(attempts)
        return 1
    except Exception as e:
        logger.error(f"Error recording failed login for {identifier}: {e}")
        return 1


async def is_locked_out(client: Any, identifier: str) -> bool:
    """Check whether an account or IP identifier is locked out due to brute-force attempts."""
    lockout_key = f"lockout:{identifier.lower()}"
    try:
        val = await client.get(lockout_key)
        return val in ("locked", True, "1")
    except Exception as e:
        logger.error(f"Error checking lockout for {identifier}: {e}")
        return False


async def reset_failed_logins(client: Any, identifier: str) -> None:
    """Clear failed login attempts counter and lockout status upon successful authentication."""
    key = f"failed_logins:{identifier.lower()}"
    lockout_key = f"lockout:{identifier.lower()}"
    try:
        await client.delete(key, lockout_key)
    except Exception as e:
        logger.error(f"Error resetting failed logins for {identifier}: {e}")
