"""User management and RBAC / Permission authorization endpoints."""

from fastapi import APIRouter, Depends

from sentinel_common.security import Role
from services.auth_service.app.deps import get_current_user, require_perm, require_roles
from services.auth_service.app.models.user import User
from services.auth_service.app.schemas.auth import UserProfileResponse, UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get Current User Profile",
)
async def get_me(current_user: User = Depends(get_current_user)) -> UserProfileResponse:
    """Return identity details of currently authenticated user."""
    perms = getattr(current_user, "permissions", [])
    profile_data = UserResponse.model_validate(current_user).model_dump()
    profile_data["permissions"] = perms
    return UserProfileResponse(**profile_data)


@router.get(
    "/admin-only",
    summary="Admin Only Route Verification",
)
async def admin_only_check(
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.ORG_ADMIN])),
) -> dict[str, str]:
    """Protected route verifying RBAC role guard."""
    return {
        "message": f"Hello {current_user.full_name}, you have administrative access.",
        "role": current_user.role,
    }


@router.get(
    "/perm-check",
    summary="Permission Guard Check Route",
)
async def permission_guarded_check(
    current_user: User = Depends(require_perm("alerts:write")),
) -> dict[str, str]:
    """Protected route verifying require_perm permission guard."""
    return {
        "message": f"Permission granted to {current_user.full_name}",
        "permission": "alerts:write",
    }
