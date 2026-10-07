"""Role, Permission, and RolePermission database models for RBAC."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinel_common.db import Base

if TYPE_CHECKING:
    from services.auth_service.app.models.user import User


# Many-to-many join table for Role <-> Permission
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "permission_id",
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Permission(Base):
    """Permission entity defining discrete system access rights."""

    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    roles: Mapped[list[RoleModel]] = relationship(
        "RoleModel", secondary=role_permissions, back_populates="permissions"
    )


class RoleModel(Base):
    """Role entity grouping permissions for RBAC."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    permissions: Mapped[list[Permission]] = relationship(
        "Permission", secondary=role_permissions, back_populates="roles", lazy="selectin"
    )
