"""Ingestion and Common Event Schema Pydantic V2 models."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class RawEventItem(BaseModel):
    """Individual raw or pre-parsed security event payload for ingestion."""

    timestamp: datetime | None = Field(
        default=None, description="Event generation timestamp (defaults to ingestion time)"
    )
    source_type: str = Field(
        default="generic",
        max_length=50,
        description="Log source type (e.g. syslog, firewall, cloudtrail, edr)",
    )
    event_name: str = Field(default="security_event", max_length=255, description="Event action or identifier")
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    source_port: int | None = Field(default=None)
    destination_port: int | None = Field(default=None)
    protocol: str | None = Field(default=None, max_length=20)
    username: str | None = Field(default=None, max_length=255)
    hostname: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=50)
    severity: str | None = Field(default="info", max_length=20)
    raw_payload: str | None = Field(default=None, description="Raw unparsed log line")
    extra_fields: dict[str, Any] = Field(default_factory=dict, description="Arbitrary unmapped metadata")


class EventBatchIngestRequest(BaseModel):
    """Batch event ingestion payload constrained to at most 1,000 events."""

    events: list[RawEventItem] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Array of events to ingest (1 to 1,000 events per batch)",
    )


class EventBatchIngestResponse(BaseModel):
    """Response returned upon successful batch ingestion acceptance."""

    status: str = "accepted"
    events_ingested: int
    stream: str = "events:raw"
    request_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IngestionResponse(BaseModel):
    """Log ingestion execution result response."""

    events_processed: int
    alerts_generated: int
    max_risk_score: float
    request_id: str | None = None


class SyslogIngestRequest(BaseModel):
    """Syslog payload ingestion request."""

    message: str = Field(
        ...,
        json_schema_extra={
            "example": (
                "<134>1 2026-10-07T00:00:00Z web01 sshd 1234 - - Failed password for invalid user"
                " admin from 192.168.1.100 port 54321 ssh2"
            )
        },
    )
    tenant_id: uuid.UUID


class WebhookIngestRequest(BaseModel):
    """Generic Webhook log ingestion payload."""

    event_type: str
    tenant_id: uuid.UUID
    data: dict[str, Any]
