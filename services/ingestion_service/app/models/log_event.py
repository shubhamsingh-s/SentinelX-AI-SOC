"""LogEvent database model for TimescaleDB hypertables."""

from typing import Any

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_common.db import Base


class LogEvent(Base):
    """Raw & Normalized log event model (TimescaleDB hypertable candidate)."""

    __tablename__ = "log_events"

    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    event_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    extra_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
