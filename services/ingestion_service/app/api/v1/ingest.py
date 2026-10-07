"""Ingestion API V1 Router."""

import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from sentinel_common.detection.parsers import LogParser
from sentinel_common.logger import request_id_ctx
from sentinel_common.redis import get_redis_client
from services.auth_service.app.deps import get_current_user
from services.auth_service.app.models.user import User
from services.ingestion_service.app.schemas.ingest import (
    EventBatchIngestRequest,
    EventBatchIngestResponse,
    IngestionResponse,
    SyslogIngestRequest,
    WebhookIngestRequest,
)
from services.ingestion_service.app.services.ingest_service import IngestionService

router = APIRouter(prefix="/ingest", tags=["Ingestion & Threat Detection"])


def get_ingest_service(
    session: AsyncSession = Depends(get_db_session),
    redis_client: Redis = Depends(get_redis_client),
) -> IngestionService:
    """Dependency injection provider for IngestionService."""
    return IngestionService(session, redis_client)


@router.post(
    "/events",
    response_model=EventBatchIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Batch Ingest Security Events",
)
async def ingest_events(
    payload: EventBatchIngestRequest,
    current_user: User = Depends(get_current_user),
    x_tenant_id: uuid.UUID | None = Header(default=None),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> EventBatchIngestResponse:
    """Ingest batches of up to 1,000 security events with API-Key auth, normalize to common schema, push to Redis Stream events:raw, and persist to events hypertable."""
    target_tenant = x_tenant_id or current_user.tenant_id
    resp = await ingest_service.ingest_event_batch(
        tenant_id=target_tenant,
        events=payload.events,
    )
    resp.request_id = request_id_ctx.get()
    return resp


@router.post(
    "/syslog",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Syslog Telemetry",
)
async def ingest_syslog(
    payload: SyslogIngestRequest,
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> IngestionResponse:
    """Ingest RFC 5424 / RFC 3164 Syslog messages and process 3-Layer Threat Engine."""
    parsed_event = LogParser.parse_syslog(payload.message)
    processed, alerts, max_risk = await ingest_service.process_log_events(
        tenant_id=payload.tenant_id,
        parsed_events=[parsed_event],
    )
    return IngestionResponse(
        events_processed=processed,
        alerts_generated=alerts,
        max_risk_score=max_risk,
        request_id=request_id_ctx.get(),
    )


@router.post(
    "/cloudtrail",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest AWS CloudTrail Telemetry",
)
async def ingest_cloudtrail(
    payload: dict[str, Any],
    x_tenant_id: uuid.UUID = Header(...),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> IngestionResponse:
    """Ingest AWS CloudTrail event records and analyze for security threats."""
    parsed_events = LogParser.parse_cloudtrail(payload)
    processed, alerts, max_risk = await ingest_service.process_log_events(
        tenant_id=x_tenant_id,
        parsed_events=parsed_events,
    )
    return IngestionResponse(
        events_processed=processed,
        alerts_generated=alerts,
        max_risk_score=max_risk,
        request_id=request_id_ctx.get(),
    )


@router.post(
    "/vpc-flow",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest AWS VPC Flow Logs",
)
async def ingest_vpc_flow(
    payload: str = Body(..., media_type="text/plain"),
    x_tenant_id: uuid.UUID = Header(...),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> IngestionResponse:
    """Ingest AWS VPC Flow Log lines and process threat score."""
    lines = [line.strip() for line in payload.splitlines() if line.strip()]
    parsed_events = [LogParser.parse_vpc_flow(line) for line in lines]

    processed, alerts, max_risk = await ingest_service.process_log_events(
        tenant_id=x_tenant_id,
        parsed_events=parsed_events,
    )
    return IngestionResponse(
        events_processed=processed,
        alerts_generated=alerts,
        max_risk_score=max_risk,
        request_id=request_id_ctx.get(),
    )


@router.post(
    "/webhook",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Webhook Payload",
)
async def ingest_webhook(
    payload: WebhookIngestRequest,
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> IngestionResponse:
    """Ingest custom JSON webhook telemetry."""
    parsed_event = LogParser.parse_syslog(str(payload.data))
    parsed_event.source_type = f"webhook_{payload.event_type}"

    processed, alerts, max_risk = await ingest_service.process_log_events(
        tenant_id=payload.tenant_id,
        parsed_events=[parsed_event],
    )
    return IngestionResponse(
        events_processed=processed,
        alerts_generated=alerts,
        max_risk_score=max_risk,
        request_id=request_id_ctx.get(),
    )
