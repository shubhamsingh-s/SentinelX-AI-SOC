"""Auth service dependencies."""

from sentinel_common.db import get_db_session
from sentinel_common.redis import get_redis_client

__all__ = ["get_db_session", "get_redis_client"]
