"""UserRepository providing async SQLAlchemy database queries."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.auth_service.app.models.audit import AuditLog
from services.auth_service.app.models.tenant import Tenant
from services.auth_service.app.models.user import RefreshToken, User


class UserRepository:
    """Repository managing User, Tenant, RefreshToken, and AuditLog persistence."""

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
        )
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
