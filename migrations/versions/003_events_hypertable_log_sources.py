"""003 Migration for Events Hypertable and LogSources.

Revision ID: 003_events_hypertable_log_sources
Revises: 002_auth_rbac_apikeys
Create Date: 2026-10-07 02:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003_events_hypertable_log_sources"
down_revision: str | None = "002_auth_rbac_apikeys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Events Table (TimescaleDB hypertable candidate)
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("event_name", sa.String(255), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(20), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("action", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True, server_default="info"),
        sa.Column("raw_payload", sa.Text(), nullable=False),
        sa.Column("extra_fields", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"])
    op.create_index("ix_events_source_type", "events", ["source_type"])
    op.create_index("ix_events_event_name", "events", ["event_name"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])
    op.create_index("ix_events_destination_ip", "events", ["destination_ip"])
    op.create_index("ix_events_username", "events", ["username"])

    # 2. TimescaleDB Hypertable Setup (executed conditionally if TimescaleDB extension is active)
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
                    PERFORM create_hypertable('events', 'timestamp', if_not_exists => TRUE);
                END IF;
            END $$;
        """)

    # 3. Log Sources Table
    op.create_table(
        "log_sources",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("config", postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_log_sources_tenant_id", "log_sources", ["tenant_id"])
    op.create_index("ix_log_sources_source_type", "log_sources", ["source_type"])


def downgrade() -> None:
    op.drop_table("log_sources")
    op.drop_table("events")
