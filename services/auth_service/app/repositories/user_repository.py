"""UserRepository providing async SQLAlchemy database queries."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.auth_service.app.models import APIKey, AuditLog, Permission, RefreshToken, RoleModel, Tenant, User


class UserRepository:
    """Repository managing User, Tenant, RefreshToken, APIKey, and AuditLog persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_user_by_email(self, email: str) -> User | None:
        """Fetch active user by email."""
        stmt = select(User).where(User.email == email.lower())
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        """Fetch user by primary key ID."""
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_user(
        self,
        email: str,
        password_hash: str,
        full_name: str,
        role: str,
        tenant_id: uuid.UUID,
    ) -> User:
        """Create and persist a new User."""
        user = User(
            email=email.lower(),
            password_hash=password_hash,
            full_name=full_name,
            role=role,
            tenant_id=tenant_id,
        )
        self.session.add(user)
        await self.session.flush()
        return user

    async def update_user_mfa(self, user_id: uuid.UUID, mfa_secret: str, mfa_enabled: bool = True) -> User | None:
        """Update MFA secret and status for a user."""
        user = await self.get_user_by_id(user_id)
        if user:
            user.mfa_secret = mfa_secret
            user.mfa_enabled = mfa_enabled
            await self.session.flush()
        return user

    async def get_tenant_by_id(self, tenant_id: uuid.UUID) -> Tenant | None:
        """Fetch tenant by UUID."""
        stmt = select(Tenant).where(Tenant.id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_tenant_by_slug(self, slug: str) -> Tenant | None:
        """Fetch tenant by URL slug."""
        stmt = select(Tenant).where(Tenant.slug == slug)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_tenant(self, name: str, slug: str) -> Tenant:
        """Create and persist a new multi-tenant organization."""
        tenant = Tenant(name=name, slug=slug)
        self.session.add(tenant)
        await self.session.flush()
        return tenant

    async def save_refresh_token(self, user_id: uuid.UUID, token_hash: str, expires_at: datetime) -> RefreshToken:
        """Store hashed refresh token."""
        token_entry = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self.session.add(token_entry)
        await self.session.flush()
        return token_entry

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Fetch refresh token record by token hash."""
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def revoke_user_refresh_tokens(self, user_id: uuid.UUID) -> None:
        """Revoke all active refresh tokens for a user (on reuse detection or password reset)."""
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.is_revoked == False)  # noqa: E712
            .values(is_revoked=True)
            .execution_options(synchronize_session="fetch")
        )
        await self.session.execute(stmt)
        await self.session.flush()

    async def create_api_key(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        name: str,
        prefix: str,
        key_hash: str,
        scopes: list[str],
        expires_at: datetime | None = None,
    ) -> APIKey:
        """Create a new API Key record."""
        api_key = APIKey(
            user_id=user_id,
            tenant_id=tenant_id,
            name=name,
            prefix=prefix,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
        self.session.add(api_key)
        await self.session.flush()
        return api_key

    async def get_api_key_by_hash(self, key_hash: str) -> APIKey | None:
        """Fetch APIKey record by its key_hash."""
        stmt = select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)  # noqa: E712
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_user_api_keys(self, user_id: uuid.UUID) -> list[APIKey]:
        """Fetch all API keys for a user."""
        stmt = select(APIKey).where(APIKey.user_id == user_id).order_by(APIKey.created_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete_api_key(self, api_key_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Revoke/Delete an API key by ID."""
        stmt = delete(APIKey).where(APIKey.id == api_key_id, APIKey.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def touch_api_key_last_used(self, api_key_id: uuid.UUID) -> None:
        """Update last_used_at timestamp on APIKey."""
        stmt = update(APIKey).where(APIKey.id == api_key_id).values(last_used_at=datetime.now(UTC))
        await self.session.execute(stmt)

    async def create_audit_log(
        self,
        actor_id: uuid.UUID,
        actor_email: str,
        tenant_id: uuid.UUID,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        ip_address: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Write an immutable audit log record."""
        audit = AuditLog(
            actor_id=actor_id,
            actor_email=actor_email,
            tenant_id=tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details=details or {},
        )
        self.session.add(audit)
        await self.session.flush()
        return audit
