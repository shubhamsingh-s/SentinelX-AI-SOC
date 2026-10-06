"""Authentication business logic service."""

from datetime import UTC, datetime, timedelta

from sentinel_common.exceptions import (
    BadRequestException,
    ConflictException,
    UnauthorizedException,
)
from sentinel_common.logger import logger
from sentinel_common.security import (
    REFRESH_TOKEN_EXPIRE_DAYS,
    create_access_token,
    generate_opaque_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
    verify_totp_code,
)
from services.auth_service.app.models.user import User
from services.auth_service.app.repositories.user_repository import UserRepository
from services.auth_service.app.schemas.auth import LoginRequest, TokenResponse, UserCreate


class AuthService:
    """Service encapsulating authentication, session rotation, and MFA business logic."""

    def __init__(self, repo: UserRepository) -> None:
        self.repo = repo

    async def register_user(self, payload: UserCreate) -> User:
        """Register a new user and manage tenant organization association."""
        existing_user = await self.repo.get_user_by_email(payload.email)
        if existing_user:
            raise ConflictException(f"User with email {payload.email} already exists")

        tenant_id = payload.tenant_id
        if not tenant_id:
            if not payload.tenant_name:
                raise BadRequestException("Either tenant_id or tenant_name must be provided")
            slug = payload.tenant_name.lower().replace(" ", "-")
            existing_tenant = await self.repo.get_tenant_by_slug(slug)
            if existing_tenant:
                tenant = existing_tenant
            else:
                tenant = await self.repo.create_tenant(name=payload.tenant_name, slug=slug)
            tenant_id = tenant.id

        password_hash = hash_password(payload.password)
        user = await self.repo.create_user(
            email=payload.email,
            password_hash=password_hash,
            full_name=payload.full_name,
            role=payload.role.value,
            tenant_id=tenant_id,
        )
        return user

    async def authenticate_user(
        self, payload: LoginRequest, ip_address: str | None = None
    ) -> tuple[TokenResponse, str]:
        """Authenticate user with Argon2 and optional TOTP MFA, returning tokens."""
        user = await self.repo.get_user_by_email(payload.email)
        if not user or not user.is_active:
            raise UnauthorizedException("Invalid email or password")

        if not verify_password(payload.password, user.password_hash):
            raise UnauthorizedException("Invalid email or password")

        # Handle TOTP MFA if enabled
        if user.mfa_enabled:
            if not payload.totp_code:
                return TokenResponse(
                    access_token="",
                    expires_in=0,
                    mfa_required=True,
                ), ""
            if not user.mfa_secret or not verify_totp_code(user.mfa_secret, payload.totp_code):
                raise UnauthorizedException("Invalid MFA authentication code")

        # Generate RS256 Access Token
        access_token = create_access_token(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            role=user.role,
        )

        # Generate Opaque Refresh Token
        raw_refresh, hashed_refresh = generate_opaque_refresh_token()
        expires_at = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        await self.repo.save_refresh_token(
            user_id=user.id,
            token_hash=hashed_refresh,
            expires_at=expires_at,
        )

        # Write audit entry
        await self.repo.create_audit_log(
            actor_id=user.id,
            actor_email=user.email,
            tenant_id=user.tenant_id,
            action="USER_LOGIN",
            resource_type="User",
            resource_id=str(user.id),
            ip_address=ip_address,
        )

        token_response = TokenResponse(
            access_token=access_token,
            expires_in=900,
            mfa_required=False,
        )
        return token_response, raw_refresh

    async def rotate_refresh_token(self, raw_token: str, ip_address: str | None = None) -> tuple[TokenResponse, str]:
        """Rotate opaque refresh token with reuse detection."""
        hashed_token = hash_refresh_token(raw_token)
        token_record = await self.repo.get_refresh_token_by_hash(hashed_token)

        if not token_record:
            raise UnauthorizedException("Invalid refresh token")

        # REUSE DETECTION: If token was already revoked, revoke ALL user sessions!
        if token_record.is_revoked:
            logger.warning(
                f"SECURITY ALERT: Refresh token reuse detected for user {token_record.user_id}! Revoking all sessions."
            )
            await self.repo.revoke_user_refresh_tokens(token_record.user_id)
            raise UnauthorizedException(
                "Security breach alert: Refresh token reuse detected. All sessions revoked.",
                code="TOKEN_REUSE_DETECTED",
            )

        now = datetime.now(UTC)
        if token_record.expires_at < now:
            raise UnauthorizedException("Refresh token has expired")

        user = await self.repo.get_user_by_id(token_record.user_id)
        if not user or not user.is_active:
            raise UnauthorizedException("User account is inactive")

        # Mark current token as revoked & replaced
        raw_new_refresh, hashed_new_refresh = generate_opaque_refresh_token()
        token_record.is_revoked = True
        token_record.replaced_by = hashed_new_refresh

        # Save new refresh token
        expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        await self.repo.save_refresh_token(
            user_id=user.id,
            token_hash=hashed_new_refresh,
            expires_at=expires_at,
        )

        # Generate new Access Token
        access_token = create_access_token(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            role=user.role,
        )

        token_response = TokenResponse(access_token=access_token, expires_in=900)
        return token_response, raw_new_refresh
