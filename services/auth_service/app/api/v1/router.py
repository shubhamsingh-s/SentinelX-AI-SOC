"""V1 Router aggregator for Auth Service."""

from fastapi import APIRouter

from services.auth_service.app.api.v1.auth import router as auth_router
from services.auth_service.app.api.v1.health import router as health_router
from services.auth_service.app.api.v1.users import router as users_router

api_v1_router = APIRouter()

# Include routers
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(users_router)
