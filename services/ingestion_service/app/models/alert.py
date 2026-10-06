"""Alert database model."""

from typing import Any

from sqlalchemy import JSON, Float, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_common.db import Base


class Alert(Base):
    """Alert entity containing 0-100 risk score, detection layers, and MITRE ATT&CK tags."""

    __tablename__ = "alerts"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # low, medium, high, critical
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)  # 0.0 to 100.0
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False, index=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    mitre_attack_tactics: Mapped[list[str]] = mapped_column(
        JSON().with_variant(ARRAY(String), "postgresql"), default=list, nullable=False
    )
    detection_rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    extra_details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
