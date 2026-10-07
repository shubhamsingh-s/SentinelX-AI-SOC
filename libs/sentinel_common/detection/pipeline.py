"""Threat Detection Pipeline orchestrating Sigma, Thresholds, IOC, ML UEBA, and Alerting."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.detection.ioc_engine import IOCEngine, IOCMatch
from sentinel_common.detection.ml_engine import RiskScorer, UEBAAnomalyDetector
from sentinel_common.detection.parsers import ParsedLogEvent
from sentinel_common.detection.sigma_engine import SigmaEngine, SigmaRule
from sentinel_common.detection.threshold_engine import ThresholdEngine, ThresholdMatch
from services.ingestion_service.app.models.alert import Alert


class DetectionResult:
    """Consolidated outcome of the threat detection pipeline."""

    def __init__(
        self,
        event: ParsedLogEvent | dict[str, Any],
        is_threat: bool,
        risk_score: float,
        severity: str,
        title: str,
        description: str,
        sigma_matches: list[SigmaRule],
        threshold_matches: list[ThresholdMatch],
        ioc_matches: list[IOCMatch],
        anomaly_score: float,
        mitre_tactics: list[str],
        alert: Alert | None = None,
    ) -> None:
        self.event = event
        self.is_threat = is_threat
        self.risk_score = risk_score
        self.severity = severity
        self.title = title
        self.description = description
        self.sigma_matches = sigma_matches
        self.threshold_matches = threshold_matches
        self.ioc_matches = ioc_matches
        self.anomaly_score = anomaly_score
        self.mitre_tactics = mitre_tactics
        self.alert = alert

    def to_dict(self) -> dict[str, Any]:
        """Convert detection result to dictionary."""
        return {
            "is_threat": self.is_threat,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "sigma_matches": [r.title for r in self.sigma_matches],
            "threshold_matches": [m.to_dict() for m in self.threshold_matches],
            "ioc_matches": [m.to_dict() for m in self.ioc_matches],
            "anomaly_score": self.anomaly_score,
            "mitre_tactics": self.mitre_tactics,
            "alert_id": str(self.alert.id) if self.alert else None,
        }


class ThreatDetectionPipeline:
    """Orchestrates multi-layer threat analysis for incoming security telemetry."""

    def __init__(
        self,
        sigma_engine: SigmaEngine | None = None,
        threshold_engine: ThresholdEngine | None = None,
        ioc_engine: IOCEngine | None = None,
        ueba_detector: UEBAAnomalyDetector | None = None,
    ) -> None:
        self.sigma_engine = sigma_engine or SigmaEngine()
        self.threshold_engine = threshold_engine or ThresholdEngine()
        self.ioc_engine = ioc_engine or IOCEngine()
        self.ueba_detector = ueba_detector or UEBAAnomalyDetector()

    async def analyze_event(
        self,
        event: ParsedLogEvent | dict[str, Any],
        redis_client: Any,
        db_session: AsyncSession | None = None,
        tenant_id: str = "default",
        publish_alert: bool = True,
    ) -> DetectionResult:
        """Execute all detection layers on the given event."""
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event

        # 1. Layer 1: Sigma Engine
        sigma_matches = self.sigma_engine.evaluate(event)

        # 2. Threshold Rules via Redis Sliding Window
        threshold_matches = await self.threshold_engine.evaluate(redis_client, event, tenant_id=tenant_id)

        # 3. Layer 2: IOC lookup against Redis cache
        ioc_matches = await self.ioc_engine.evaluate_redis(redis_client, event)

        # 4. Layer 3: Isolation Forest ML UEBA Anomaly Score
        feature_vector = self.ueba_detector.extract_features(event)
        anomaly_score = self.ueba_detector.predict_anomaly_score(feature_vector)

        # 5. Composite Risk Score
        risk_score = RiskScorer.calculate_risk_score(
            sigma_matches=sigma_matches,
            ioc_matches=ioc_matches,
            anomaly_score=anomaly_score,
            threshold_matches=threshold_matches,
        )

        # Determine threat outcome
        is_threat = bool(sigma_matches) or bool(threshold_matches) or bool(ioc_matches) or (risk_score >= 40.0)

        # Derive title, severity, mitre tactics
        severity = "low"
        if risk_score >= 80.0:
            severity = "critical"
        elif risk_score >= 60.0:
            severity = "high"
        elif risk_score >= 35.0:
            severity = "medium"

        title = "Security Anomaly Detected"
        description = f"Automated threat alert generated with composite risk score {risk_score}."
        mitre_tactics: list[str] = []
        rule_id: str | None = None

        if sigma_matches:
            top_rule = sigma_matches[0]
            title = top_rule.title
            description = top_rule.description or f"Triggered Sigma rule: {top_rule.title}"
            mitre_tactics.extend(top_rule.tags)
            rule_id = top_rule.rule_id
        elif threshold_matches:
            top_th = threshold_matches[0]
            title = f"Threshold Exceeded: {top_th.title}"
            description = (
                f"Count {top_th.count} exceeded threshold {top_th.threshold} "
                f"within {top_th.window_seconds}s for {top_th.group_by_field}={top_th.group_by_value}"
            )
            rule_id = top_th.rule_id
        elif ioc_matches:
            top_ioc = ioc_matches[0]
            title = f"Known IOC Match: {top_ioc.threat_name}"
            description = f"Matched malicious {top_ioc.ioc_type} indicator: {top_ioc.ioc_value}"
            mitre_tactics.append("attack.command-and-control")

        alert: Alert | None = None
        if is_threat:
            t_uuid = uuid.UUID(tenant_id) if isinstance(tenant_id, str) and len(tenant_id) == 36 else uuid.uuid4()
            alert = Alert(
                tenant_id=t_uuid,
                title=title,
                description=description,
                severity=severity,
                risk_score=risk_score,
                status="open",
                source_ip=event_dict.get("source_ip"),
                destination_ip=event_dict.get("destination_ip"),
                username=event_dict.get("username"),
                hostname=event_dict.get("hostname"),
                mitre_attack_tactics=mitre_tactics,
                detection_rule_id=rule_id,
                extra_details={
                    "anomaly_score": anomaly_score,
                    "sigma_matches": [r.rule_id for r in sigma_matches],
                    "threshold_matches": [m.rule_id for m in threshold_matches],
                    "ioc_matches": [m.ioc_value for m in ioc_matches],
                    "event_name": event_dict.get("event_name"),
                },
            )

            # Persist Alert to Database if session provided
            if db_session:
                db_session.add(alert)
                await db_session.flush()

            # Publish Alert to Redis Stream alerts:new
            if publish_alert and redis_client:
                alert_payload = {
                    "alert_id": str(alert.id),
                    "tenant_id": str(alert.tenant_id),
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity,
                    "risk_score": str(alert.risk_score),
                    "status": alert.status,
                    "source_ip": alert.source_ip or "",
                    "destination_ip": alert.destination_ip or "",
                    "username": alert.username or "",
                    "detection_rule_id": alert.detection_rule_id or "",
                    "mitre_tactics": json.dumps(alert.mitre_attack_tactics),
                    "timestamp": datetime.now(UTC).isoformat(),
                }
                try:
                    await redis_client.xadd("alerts:new", alert_payload)
                except Exception:
                    pass

        return DetectionResult(
            event=event,
            is_threat=is_threat,
            risk_score=risk_score,
            severity=severity,
            title=title,
            description=description,
            sigma_matches=sigma_matches,
            threshold_matches=threshold_matches,
            ioc_matches=ioc_matches,
            anomaly_score=anomaly_score,
            mitre_tactics=mitre_tactics,
            alert=alert,
        )
