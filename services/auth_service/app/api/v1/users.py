"""User management and RBAC authorization endpoints."""

import uuid
from collections.abc import Callable

from fastapi import APIRouter, Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from sentinel_common.exceptions import ForbiddenException, UnauthorizedException
from sentinel_common.security import Role, check_role_permission, decode_access_token
from services.auth_service.app.models.user import User
from services.auth_service.app.repositories.user_repository import UserRepository
from services.auth_service.app.schemas.auth import UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


async def get_current_user(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    """Dependency decoding RS256 JWT access token and injecting active User."""
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedException("Missing or invalid Authorization header")

    token = authorization.split(" ")[1]
    payload = decode_access_token(token)

    user_id = uuid.UUID(payload["sub"])
    repo = UserRepository(session)
    user = await repo.get_user_by_id(user_id)

    if not user or not user.is_active:
        raise UnauthorizedException("User account is inactive or no longer exists")

    return user


def require_roles(allowed_roles: list[Role]) -> Callable[..., User]:
    """Dependency factory checking user RBAC role against allowed roles."""

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if not check_role_permission(current_user.role, allowed_roles):
            raise ForbiddenException(f"Role '{current_user.role}' is not authorized to access this resource")
        return current_user

    return role_checker


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    """Return identity details of currently authenticated user."""
    return UserResponse.model_validate(current_user)


@router.get(
    "/admin-only",
    summary="Admin Only Route Verification",
)
async def admin_only_check(
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.ORG_ADMIN])),
) -> dict[str, str]:
    """Protected route verifying RBAC permission guard."""
    return {
        "message": f"Hello {current_user.full_name}, you have administrative access.",
        "role": current_user.role,
    }
