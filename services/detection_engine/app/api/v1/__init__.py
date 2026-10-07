"""Detection engine API V1 router package."""

from services.detection_engine.app.api.v1.rules import router as rules_router

__all__ = ["rules_router"]
