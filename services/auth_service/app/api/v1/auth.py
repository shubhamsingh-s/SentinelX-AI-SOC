"""Authentication API V1 router."""

import uuid
from typing import Any

from fastapi import APIRouter, Cookie, Depends, Header, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from sentinel_common.exceptions import UnauthorizedException
from sentinel_common.redis import get_redis_client
from sentinel_common.security import DEFAULT_ROLE_PERMISSIONS, decode_access_token
from services.auth_service.app.deps import get_current_user
from services.auth_service.app.models import User
from services.auth_service.app.repositories.user_repository import UserRepository
from services.auth_service.app.schemas.auth import (
    APIKeyCreate,
    APIKeyResponse,
    LoginRequest,
    TokenResponse,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    UserCreate,
    UserProfileResponse,
    UserResponse,
)
from services.auth_service.app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_auth_service(session: AsyncSession = Depends(get_db_session)) -> AuthService:
    """Dependency provider for AuthService."""
    repo = UserRepository(session)
    return AuthService(repo)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register User / Organization",
)
async def register(
    payload: UserCreate,
    auth_service: AuthService = Depends(get_auth_service),
) -> UserResponse:
    """Register a new user and create or assign tenant organization."""
    user = await auth_service.register_user(payload)
    return UserResponse.model_validate(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
    redis_client: Any = Depends(get_redis_client),
) -> TokenResponse:
    """Authenticate user with Argon2, check brute-force lockout, and set HttpOnly refresh token cookie."""
    client_ip = request.client.host if request.client else None
    token_resp, refresh_token = await auth_service.authenticate_user(
        payload, redis_client=redis_client, ip_address=client_ip
    )

    if refresh_token:
        response.set_cookie(
            key="sentinel_refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="lax",
            path="/",
            max_age=7 * 24 * 3600,
        )

    return token_resp


@router.post(
    "/mfa/setup",
    response_model=TOTPSetupResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate TOTP MFA Setup",
)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> TOTPSetupResponse:
    """Generate TOTP secret and QR code provisioning URI."""
    return await auth_service.setup_mfa(current_user)


@router.post(
    "/mfa/verify",
    status_code=status.HTTP_200_OK,
    summary="Verify & Enable MFA",
)
async def verify_mfa(
    payload: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> dict[str, str]:
    """Verify TOTP 6-digit code and enable MFA on user account."""
    await auth_service.verify_and_enable_mfa(current_user, code=payload.code, secret=payload.secret)
    return {"message": "MFA successfully verified and enabled"}


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate Refresh Token",
)
async def refresh_token(
    request: Request,
    response: Response,
    sentinel_refresh_token: str | None = Cookie(default=None),
    x_refresh_token: str | None = Header(default=None),
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    """Rotate opaque refresh token from HttpOnly cookie or X-Refresh-Token header with reuse detection."""
    token_val = x_refresh_token or sentinel_refresh_token
    if not token_val:
        raise UnauthorizedException("Refresh token missing")

    client_ip = request.client.host if request.client else None
    token_resp, new_refresh = await auth_service.rotate_refresh_token(token_val, ip_address=client_ip)

    response.set_cookie(
        key="sentinel_refresh_token",
        value=new_refresh,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
        max_age=7 * 24 * 3600,
    )

    return token_resp


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="User Logout",
)
async def logout(
    response: Response,
    authorization: str | None = Header(default=None),
    sentinel_refresh_token: str | None = Cookie(default=None),
    auth_service: AuthService = Depends(get_auth_service),
    redis_client: Any = Depends(get_redis_client),
) -> dict[str, str]:
    """Blacklist RS256 JWT access token JTI in Redis and revoke refresh token cookie."""
    jti = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
        except Exception:
            pass

    await auth_service.logout_user(
        jti=jti,
        raw_refresh_token=sentinel_refresh_token,
        redis_client=redis_client,
    )
    response.delete_cookie(key="sentinel_refresh_token")
    return {"message": "Successfully logged out"}


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get Current User Profile & Permissions",
)
async def get_auth_me(current_user: User = Depends(get_current_user)) -> UserProfileResponse:
    """Return profile and active permissions list of currently authenticated user."""
    perms = getattr(current_user, "permissions", None)
    if perms is None:
        perms = DEFAULT_ROLE_PERMISSIONS.get(current_user.role, [])

    profile_data = UserResponse.model_validate(current_user).model_dump()
    profile_data["permissions"] = perms
    return UserProfileResponse(**profile_data)


@router.post(
    "/api-keys",
    response_model=APIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API Key",
)
async def create_api_key(
    payload: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> APIKeyResponse:
    """Generate a new API key for current user/tenant."""
    api_key_obj, raw_key = await auth_service.create_api_key(current_user, payload)
    res_data = APIKeyResponse.model_validate(api_key_obj).model_dump()
    res_data["raw_key"] = raw_key
    return APIKeyResponse(**res_data)


@router.get(
    "/api-keys",
    response_model=list[APIKeyResponse],
    summary="List API Keys",
)
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> list[APIKeyResponse]:
    """List active API keys for current user."""
    keys = await auth_service.list_api_keys(current_user.id)
    return [APIKeyResponse.model_validate(k) for k in keys]


@router.delete(
    "/api-keys/{key_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke API Key",
)
async def delete_api_key(
    key_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> dict[str, str]:
    """Revoke/Delete an API key."""
    await auth_service.delete_api_key(api_key_id=key_id, user_id=current_user.id)
    return {"message": "API key successfully revoked"}
