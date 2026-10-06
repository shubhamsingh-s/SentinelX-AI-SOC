"""Health check endpoints (/health and /ready)."""

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from sentinel_common.db import check_db_health
from sentinel_common.redis import check_redis_health

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Liveness probe response schema."""

    status: str = Field(..., json_schema_extra={"example": "ok"})
    service: str = Field(..., json_schema_extra={"example": "auth-service"})


class ReadinessResponse(BaseModel):
    """Readiness probe response schema."""

    status: str = Field(..., json_schema_extra={"example": "ready"})
    database: str = Field(..., json_schema_extra={"example": "ok"})
    redis: str = Field(..., json_schema_extra={"example": "ok"})


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Liveness Probe",
    description="Returns HTTP 200 if the service is running.",
)
async def health_check() -> HealthResponse:
    """Liveness check endpoint."""
    return HealthResponse(status="ok", service="auth-service")


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness Probe",
    description="Checks downstream database and Redis connections.",
)
async def ready_check(response: Response) -> ReadinessResponse:
    """Readiness check endpoint validating DB and Redis state."""
    db_ok = await check_db_health()
    redis_ok = await check_redis_health()

    is_ready = db_ok and redis_ok
    status_str = "ready" if is_ready else "unhealthy"

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status=status_str,
        database="ok" if db_ok else "error",
        redis="ok" if redis_ok else "error",
    )
