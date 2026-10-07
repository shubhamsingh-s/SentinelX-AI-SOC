"""Log Sources CRUD API V1 Router."""

import uuid

from fastapi import APIRouter, Depends, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.db import get_db_session
from sentinel_common.redis import get_redis_client
from services.auth_service.app.deps import get_current_user
from services.auth_service.app.models.user import User
from services.ingestion_service.app.schemas.log_source import (
    LogSourceCreate,
    LogSourceResponse,
    LogSourceUpdate,
)
from services.ingestion_service.app.services.ingest_service import IngestionService

router = APIRouter(prefix="/log-sources", tags=["Log Sources"])


def get_ingest_service(
    session: AsyncSession = Depends(get_db_session),
    redis_client: Redis = Depends(get_redis_client),
) -> IngestionService:
    """Dependency injection provider for IngestionService."""
    return IngestionService(session, redis_client)


@router.post(
    "",
    response_model=LogSourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Log Source",
)
async def create_log_source(
    payload: LogSourceCreate,
    current_user: User = Depends(get_current_user),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> LogSourceResponse:
    """Register a new telemetry log source provider for the authenticated tenant."""
    source = await ingest_service.create_log_source(
        tenant_id=current_user.tenant_id,
        payload=payload,
    )
    return LogSourceResponse.model_validate(source)


@router.get(
    "",
    response_model=list[LogSourceResponse],
    summary="List Log Sources",
)
async def list_log_sources(
    current_user: User = Depends(get_current_user),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> list[LogSourceResponse]:
    """Retrieve all configured log sources for the current tenant."""
    sources = await ingest_service.list_log_sources(tenant_id=current_user.tenant_id)
    return [LogSourceResponse.model_validate(s) for s in sources]


@router.get(
    "/{source_id}",
    response_model=LogSourceResponse,
    summary="Get Log Source Details",
)
async def get_log_source(
    source_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> LogSourceResponse:
    """Fetch configuration details of a specific log source."""
    source = await ingest_service.get_log_source(tenant_id=current_user.tenant_id, source_id=source_id)
    return LogSourceResponse.model_validate(source)


@router.put(
    "/{source_id}",
    response_model=LogSourceResponse,
    summary="Update Log Source",
)
async def update_log_source(
    source_id: uuid.UUID,
    payload: LogSourceUpdate,
    current_user: User = Depends(get_current_user),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> LogSourceResponse:
    """Update log source configuration settings."""
    source = await ingest_service.update_log_source(
        tenant_id=current_user.tenant_id,
        source_id=source_id,
        payload=payload,
    )
    return LogSourceResponse.model_validate(source)


@router.delete(
    "/{source_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Log Source",
)
async def delete_log_source(
    source_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    ingest_service: IngestionService = Depends(get_ingest_service),
) -> dict[str, str]:
    """Delete and deregister a log source."""
    await ingest_service.delete_log_source(tenant_id=current_user.tenant_id, source_id=source_id)
    return {"message": "Log source successfully deleted"}
