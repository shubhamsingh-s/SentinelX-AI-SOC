"""Main FastAPI application entrypoint for SentinelX Auth Service."""

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from sentinel_common.error_handlers import register_exception_handlers
from sentinel_common.logger import logger
from sentinel_common.middleware import RequestIDMiddleware
from services.auth_service.app.api.v1.health import router as health_router
from services.auth_service.app.api.v1.router import api_v1_router
from services.auth_service.app.core.config import auth_settings

# Prometheus Metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP Request Count",
    ["method", "endpoint", "status_code"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP Request Latency in Seconds",
    ["method", "endpoint"],
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan event handler for startup and shutdown actions."""
    logger.info(f"Starting {auth_settings.SERVICE_NAME} in environment: {auth_settings.ENV}")
    yield
    logger.info(f"Shutting down {auth_settings.SERVICE_NAME}")


def create_app() -> FastAPI:
    """Factory function to build FastAPI instance."""
    app = FastAPI(
        title="SentinelX Auth Service",
        description="Auth & Identity service for SentinelX AI SOC platform",
        version="0.1.0",
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/v1/docs",
        redoc_url="/api/v1/redoc",
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add Request ID Middleware
    app.add_middleware(RequestIDMiddleware)

    # Register Exception Handlers
    register_exception_handlers(app)

    # Metrics Middleware
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next: any) -> Response:
        start_time = time.time()
        response: Response = await call_next(request)
        duration = time.time() - start_time

        endpoint = request.url.path
        REQUEST_COUNT.labels(method=request.method, endpoint=endpoint, status_code=response.status_code).inc()
        REQUEST_LATENCY.labels(method=request.method, endpoint=endpoint).observe(duration)

        return response

    # Mount health probes at root level as well as under /api/v1
    app.include_router(health_router)
    app.include_router(api_v1_router, prefix=auth_settings.API_V1_PREFIX)

    # Prometheus Metrics endpoint
    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("services.auth_service.app.main:app", host="0.0.0.0", port=8000, reload=True)
