"""LogSource database model for tracking telemetry providers and sensors."""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_common.db import Base


class LogSource(Base):
    """Log source configuration representing an external telemetry feed or agent."""

    __tablename__ = "log_sources"

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
