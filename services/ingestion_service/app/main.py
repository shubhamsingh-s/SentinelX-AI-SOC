"""Ingestion Service main application entrypoint."""

from fastapi import FastAPI

from sentinel_common.error_handlers import register_exception_handlers
from sentinel_common.middleware import RequestIDMiddleware
from services.ingestion_service.app.api.v1.ingest import router as ingest_router
from services.ingestion_service.app.api.v1.log_sources import router as log_sources_router

app = FastAPI(
    title="SentinelX Ingestion & Threat Detection Service",
    description="Ingests security logs, normalizes telemetry, and executes 3-layer threat detection engine",
    version="0.1.0",
)

app.add_middleware(RequestIDMiddleware)
register_exception_handlers(app)
app.include_router(ingest_router, prefix="/api/v1")
app.include_router(log_sources_router, prefix="/api/v1")
