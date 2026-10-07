"""Authentication and authorization business logic service."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp

from sentinel_common.exceptions import (
    BadRequestException,
    ConflictException,
    UnauthorizedException,
)
from sentinel_common.logger import logger
from sentinel_common.redis import (
    blacklist_jti,
    is_locked_out,
    record_failed_login,
    reset_failed_logins,
)
from sentinel_common.security import (
    DEFAULT_ROLE_PERMISSIONS,
    REFRESH_TOKEN_EXPIRE_DAYS,
    create_access_token,
    generate_api_key,
    generate_opaque_refresh_token,
    generate_totp_secret,
    hash_password,
    hash_refresh_token,
    verify_password,
    verify_totp_code,
)
from services.auth_service.app.models import APIKey, User
from services.auth_service.app.repositories.user_repository import UserRepository
from services.auth_service.app.schemas.auth import (
    APIKeyCreate,
    LoginRequest,
    TokenResponse,
    TOTPSetupResponse,
    UserCreate,
)


class AuthService:
    """Service encapsulating authentication, token rotation, MFA, API keys, and lockout business logic."""

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
        self, payload: LoginRequest, redis_client: Any = None, ip_address: str | None = None
    ) -> tuple[TokenResponse, str]:
        """Authenticate user with Argon2, brute-force lockout, and optional TOTP MFA, returning tokens."""
        # 1. Brute-force lockout check
        if redis_client:
            email_locked = await is_locked_out(redis_client, payload.email)
            ip_locked = await is_locked_out(redis_client, ip_address) if ip_address else False
            if email_locked or ip_locked:
                raise UnauthorizedException(
                    "Account locked due to too many failed login attempts. Please try again later.",
                    code="TOO_MANY_REQUESTS",
                )

        user = await self.repo.get_user_by_email(payload.email)
        if not user or not user.is_active:
            if redis_client:
                await record_failed_login(redis_client, payload.email)
                if ip_address:
                    await record_failed_login(redis_client, ip_address)
            raise UnauthorizedException("Invalid email or password")

        if not verify_password(payload.password, user.password_hash):
            if redis_client:
                await record_failed_login(redis_client, payload.email)
                if ip_address:
                    await record_failed_login(redis_client, ip_address)
            raise UnauthorizedException("Invalid email or password")

        # Successful password verification -> reset failed logins counter
        if redis_client:
            await reset_failed_logins(redis_client, payload.email)
            if ip_address:
                await reset_failed_logins(redis_client, ip_address)

        # Handle TOTP MFA if enabled
        if user.mfa_enabled:
            if not payload.totp_code:
                return (
                    TokenResponse(
                        access_token="",
                        expires_in=0,
                        mfa_required=True,
                    ),
                    "",
                )
            if not user.mfa_secret or not verify_totp_code(user.mfa_secret, payload.totp_code):
                raise UnauthorizedException("Invalid MFA authentication code")

        # Get role permissions
        permissions = DEFAULT_ROLE_PERMISSIONS.get(user.role, [])

        # Generate RS256 Access Token
        access_token = create_access_token(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            role=user.role,
            permissions=permissions,
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

    async def setup_mfa(self, user: User) -> TOTPSetupResponse:
        """Initiate TOTP MFA setup for current user."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="SentinelX AI SOC")
        return TOTPSetupResponse(secret=secret, provisioning_uri=uri)

    async def verify_and_enable_mfa(self, user: User, code: str, secret: str | None = None) -> bool:
        """Verify TOTP code and enable MFA on user account."""
        mfa_secret = secret or user.mfa_secret
        if not mfa_secret:
            raise BadRequestException("MFA secret not initialized. Initiate setup first.")

        if not verify_totp_code(mfa_secret, code):
            raise UnauthorizedException("Invalid MFA verification code")

        await self.repo.update_user_mfa(user_id=user.id, mfa_secret=mfa_secret, mfa_enabled=True)
        return True

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
            await self.repo.session.commit()
            raise UnauthorizedException(
                "Security breach alert: Refresh token reuse detected. All sessions revoked.",
                code="TOKEN_REUSE_DETECTED",
            )

        now_dt = datetime.now(UTC)
        token_expires = (
            token_record.expires_at.replace(tzinfo=UTC)
            if token_record.expires_at.tzinfo is None
            else token_record.expires_at
        )
        if token_expires < now_dt:
            raise UnauthorizedException("Refresh token has expired")

        user = await self.repo.get_user_by_id(token_record.user_id)
        if not user or not user.is_active:
            raise UnauthorizedException("User account is inactive")

        # Mark current token as revoked & replaced
        raw_new_refresh, hashed_new_refresh = generate_opaque_refresh_token()
        token_record.is_revoked = True
        token_record.replaced_by = hashed_new_refresh

        # Save new refresh token
        expires_at = now_dt + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        await self.repo.save_refresh_token(
            user_id=user.id,
            token_hash=hashed_new_refresh,
            expires_at=expires_at,
        )

        permissions = DEFAULT_ROLE_PERMISSIONS.get(user.role, [])
        # Generate new Access Token
        access_token = create_access_token(
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            role=user.role,
            permissions=permissions,
        )

        token_response = TokenResponse(access_token=access_token, expires_in=900)
        return token_response, raw_new_refresh

    async def logout_user(self, jti: str | None, raw_refresh_token: str | None, redis_client: Any = None) -> None:
        """Blacklist JTI in Redis and revoke refresh token in database on logout."""
        if jti and redis_client:
            await blacklist_jti(redis_client, jti, ttl_seconds=900)

        if raw_refresh_token:
            hashed = hash_refresh_token(raw_refresh_token)
            token_rec = await self.repo.get_refresh_token_by_hash(hashed)
            if token_rec:
                token_rec.is_revoked = True

    async def create_api_key(self, user: User, payload: APIKeyCreate) -> tuple[APIKey, str]:
        """Create a new API Key for user with specified scopes."""
        raw_key, prefix, key_hash = generate_api_key()

        expires_at = None
        if payload.expires_in_days:
            expires_at = datetime.now(UTC) + timedelta(days=payload.expires_in_days)

        scopes = payload.scopes or DEFAULT_ROLE_PERMISSIONS.get(user.role, [])
        api_key = await self.repo.create_api_key(
            user_id=user.id,
            tenant_id=user.tenant_id,
            name=payload.name,
            prefix=prefix,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
        return api_key, raw_key

    async def list_api_keys(self, user_id: Any) -> list[APIKey]:
        """List all API keys for user."""
        return await self.repo.list_user_api_keys(user_id)

    async def delete_api_key(self, api_key_id: Any, user_id: Any) -> bool:
        """Delete / Revoke API key by ID."""
        deleted = await self.repo.delete_api_key(api_key_id=api_key_id, user_id=user_id)
        if not deleted:
            raise BadRequestException("API Key not found or unauthorized")
        return True
