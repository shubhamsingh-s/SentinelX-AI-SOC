"""Event database model for TimescaleDB events hypertable."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_common.db import Base


class Event(Base):
    """Normalized security log event stored in the TimescaleDB events hypertable."""

    __tablename__ = "events"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    event_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str | None] = mapped_column(String(50), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True, default="info")
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    extra_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
