"""V1 Router aggregator for Auth Service."""

from fastapi import APIRouter

from services.auth_service.app.api.v1.health import router as health_router

api_v1_router = APIRouter()

# Include health router
api_v1_router.include_router(health_router)
