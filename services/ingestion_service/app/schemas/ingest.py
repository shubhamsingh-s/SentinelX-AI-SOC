"""Ingestion Pydantic V2 schemas."""

import uuid
from typing import Any

from pydantic import BaseModel, Field


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
