"""Authentication API V1 router."""

from fastapi import APIRouter, Cookie, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from sentinel_common.exceptions import UnauthorizedException
from services.auth_service.app.repositories.user_repository import UserRepository
from services.auth_service.app.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse
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
) -> TokenResponse:
    """Authenticate user with Argon2 and set HttpOnly rotating refresh token cookie."""
    client_ip = request.client.host if request.client else None
    token_resp, refresh_token = await auth_service.authenticate_user(payload, ip_address=client_ip)

    if refresh_token:
        # Set 7-day HttpOnly, Secure, SameSite cookie for rotating refresh token
        response.set_cookie(
            key="sentinel_refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=7 * 24 * 3600,
        )

    return token_resp


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
    auth_service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    """Rotate opaque refresh token from HttpOnly cookie with reuse detection."""
    token_val = sentinel_refresh_token
    if not token_val:
        raise UnauthorizedException("Refresh token cookie missing")

    client_ip = request.client.host if request.client else None
    token_resp, new_refresh = await auth_service.rotate_refresh_token(token_val, ip_address=client_ip)

    response.set_cookie(
        key="sentinel_refresh_token",
        value=new_refresh,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 3600,
    )

    return token_resp


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="User Logout",
)
async def logout(response: Response) -> dict[str, str]:
    """Clear HttpOnly refresh token cookie on user logout."""
    response.delete_cookie(key="sentinel_refresh_token")
    return {"message": "Successfully logged out"}
