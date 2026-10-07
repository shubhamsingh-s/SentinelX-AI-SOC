"""Re-export DetectionRule for ingestion service models."""

from services.detection_engine.app.models.rule import DetectionRule

__all__ = ["DetectionRule"]
