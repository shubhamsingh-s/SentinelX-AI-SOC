"""004 Migration for Detection Rules (Sigma and Threshold).

Revision ID: 004_detection_rules
Revises: 003_events_hypertable_log_sources
Create Date: 2026-10-07 03:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004_detection_rules"
down_revision: str | None = "003_events_hypertable_log_sources"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("rule_type", sa.String(50), nullable=False, server_default="sigma"),
        sa.Column("severity", sa.String(50), nullable=False, server_default="medium"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("yaml_definition", sa.Text(), nullable=True),
        sa.Column("threshold_config", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("mitre_attack_tactics", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_detection_rules_tenant_id", "detection_rules", ["tenant_id"])
    op.create_index("ix_detection_rules_rule_type", "detection_rules", ["rule_type"])
    op.create_index("ix_detection_rules_severity", "detection_rules", ["severity"])
    op.create_index("ix_detection_rules_is_active", "detection_rules", ["is_active"])


def downgrade() -> None:
    op.drop_table("detection_rules")
