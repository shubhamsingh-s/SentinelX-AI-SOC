"""Auth service dependencies including token authentication, RBAC, and permission guards."""

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from sentinel_common.exceptions import ForbiddenException, UnauthorizedException
from sentinel_common.redis import get_redis_client, is_jti_blacklisted
from sentinel_common.security import (
    DEFAULT_ROLE_PERMISSIONS,
    Role,
    check_role_permission,
    decode_access_token,
    has_permission,
    hash_api_key,
)
from services.auth_service.app.models.user import User
from services.auth_service.app.repositories.user_repository import UserRepository


async def get_current_user(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    session: AsyncSession = Depends(get_db_session),
    redis_client: Any = Depends(get_redis_client),
) -> User:
    """Dependency decoding RS256 JWT access token or X-API-Key and injecting active User with permissions."""
    repo = UserRepository(session)

    # 1. Bearer Token Authentication
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        payload = decode_access_token(token)

        jti = payload.get("jti")
        if jti and redis_client:
            blacklisted = await is_jti_blacklisted(redis_client, jti)
            if blacklisted:
                raise UnauthorizedException("Access token has been revoked", code="TOKEN_REVOKED")

        user_id = uuid.UUID(payload["sub"])
        user = await repo.get_user_by_id(user_id)
        if not user or not user.is_active:
            raise UnauthorizedException("User account is inactive or no longer exists")

        perms = payload.get("permissions") or DEFAULT_ROLE_PERMISSIONS.get(user.role, [])
        setattr(user, "permissions", perms)
        return user

    # 2. API Key Authentication
    if x_api_key:
        key_hash = hash_api_key(x_api_key)
        api_key = await repo.get_api_key_by_hash(key_hash)
        if not api_key or not api_key.is_active:
            raise UnauthorizedException("Invalid or inactive API key", code="INVALID_API_KEY")

        if api_key.expires_at and api_key.expires_at < datetime.now(UTC):
            raise UnauthorizedException("API key has expired", code="API_KEY_EXPIRED")

        await repo.touch_api_key_last_used(api_key.id)
        user = await repo.get_user_by_id(api_key.user_id)
        if not user or not user.is_active:
            raise UnauthorizedException("User account associated with API key is inactive")

        setattr(user, "permissions", api_key.scopes or DEFAULT_ROLE_PERMISSIONS.get(user.role, []))
        return user

    raise UnauthorizedException("Missing or invalid Authorization header or X-API-Key")


def require_roles(allowed_roles: list[Role]) -> Callable[..., Awaitable[User]]:
    """Dependency checking user RBAC role against allowed roles list."""

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if not check_role_permission(current_user.role, allowed_roles):
            raise ForbiddenException(f"Role '{current_user.role}' is not authorized to access this resource")
        return current_user

    return role_checker


def require_perm(required_permission: str) -> Callable[..., Awaitable[User]]:
    """Dependency checking if current user (or API key) has required_permission."""

    async def perm_checker(current_user: User = Depends(get_current_user)) -> User:
        user_perms = getattr(current_user, "permissions", None)
        if user_perms is None:
            user_perms = DEFAULT_ROLE_PERMISSIONS.get(current_user.role, [])
        if not has_permission(user_perms, required_permission):
            raise ForbiddenException(
                f"Permission '{required_permission}' required to access this resource",
                code="FORBIDDEN",
            )
        return current_user

    return perm_checker
