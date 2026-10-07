"""DetectionRule database model for Sigma and Threshold threat detection rules."""

from typing import Any

from sqlalchemy import JSON, Boolean, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_common.db import Base


class DetectionRule(Base):
    """Detection rule entity supporting Sigma and Threshold based threat detection."""

    __tablename__ = "detection_rules"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), default="sigma", nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(50), default="medium", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    yaml_definition: Mapped[str | None] = mapped_column(Text, nullable=True)
    threshold_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    mitre_attack_tactics: Mapped[list[str]] = mapped_column(
        JSON().with_variant(ARRAY(String), "postgresql"), default=list, nullable=False
    )
