"""Tenant database model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinel_common.db import Base

if TYPE_CHECKING:
    from services.auth_service.app.models.user import User


class Tenant(Base):
    """Multi-tenant organization entity."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    users: Mapped[list[User]] = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
