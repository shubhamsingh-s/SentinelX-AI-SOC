"""Detection Engine Service main FastAPI application entrypoint."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinel_common.error_handlers import register_exception_handlers
from sentinel_common.logger import logger
from sentinel_common.middleware import RequestIDMiddleware
from services.detection_engine.app.api.v1.rules import router as rules_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Service lifespan startup and shutdown."""
    logger.info("Starting SentinelX Detection Engine Service")
    yield
    logger.info("Shutting down SentinelX Detection Engine Service")


app = FastAPI(
    title="SentinelX Detection Engine Service",
    description=(
        "3-layer threat detection engine (Sigma, Thresholds, IOC, ML Isolation Forest) with Redis Stream workers"
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIDMiddleware)
register_exception_handlers(app)

app.include_router(rules_router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Service health check endpoint."""
    return {"status": "ok", "service": "detection-engine"}
