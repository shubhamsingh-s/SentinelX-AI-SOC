"""Log Ingestion and 3-Layer Threat Detection Orchestrator."""

import uuid

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.detection.ioc_engine import IOCEngine
from sentinel_common.detection.ml_engine import RiskScorer, UEBAAnomalyDetector
from sentinel_common.detection.parsers import ParsedLogEvent
from sentinel_common.detection.sigma_engine import SigmaEngine, SigmaRule
from sentinel_common.logger import logger
from services.ingestion_service.app.models.alert import Alert
from services.ingestion_service.app.models.log_event import LogEvent


class IngestionService:
    """Ingestion orchestrator executing 3-Layer detection pipeline and publishing alerts."""

    def __init__(self, session: AsyncSession, redis_client: Redis) -> None:
        self.session = session
        self.redis = redis_client

        # Initialize Detection Engines
        self.sigma_engine = SigmaEngine()
        self.ioc_engine = IOCEngine()
        self.ueba_detector = UEBAAnomalyDetector()

        # Seed sample detection rules & IOCs
        self._seed_default_rules_and_iocs()

    def _seed_default_rules_and_iocs(self) -> None:
        """Seed sample Sigma rules and IOC threat intel feeds."""
        # Sample Sigma Rule: SSH Failed Login / Suspicious Execution
        rule_yaml = """
title: Suspicious Failed Password Attempt
id: sigma-auth-001
level: high
description: Detects multiple failed authentication attempts
detection:
  selection:
    raw_payload|contains:
      - "failed password"
      - "powershell -enc"
      - "cmd.exe /c"
tags:
  - attack.initial_access
  - attack.t1078
"""
        self.sigma_engine.add_rule(SigmaRule.from_yaml(rule_yaml))

        # Sample IOCs
        self.ioc_engine.load_ioc("ip", "192.168.1.100", "Malicious Botnet C2", confidence=95)
        self.ioc_engine.load_ioc("ip", "10.0.0.99", "APT29 Known Exploit Host", confidence=90)

    async def process_log_events(
        self, tenant_id: uuid.UUID, parsed_events: list[ParsedLogEvent]
    ) -> tuple[int, int, float]:
        """Execute 3-Layer Threat Engine on parsed events, store telemetry and emit alerts."""
        events_processed = 0
        alerts_generated = 0
        max_risk_score = 0.0

        for evt in parsed_events:
            events_processed += 1

            # Store log event in DB
            db_log = LogEvent(
                tenant_id=tenant_id,
                source_type=evt.source_type,
                event_name=evt.event_name,
                source_ip=evt.source_ip,
                destination_ip=evt.destination_ip,
                username=evt.username,
                hostname=evt.hostname,
                raw_payload=evt.raw_payload,
                extra_fields=evt.extra_fields,
            )
            self.session.add(db_log)

            # --- 3-LAYER DETECTION ENGINE ---
            # Layer 1: Sigma Rule Evaluation
            sigma_matches = self.sigma_engine.evaluate(evt)

            # Layer 2: Threat Intel IOC Matcher
            ioc_matches = self.ioc_engine.evaluate(evt)

            # Layer 3: UEBA Anomaly Scoring
            feature_vector = [
                float(evt.timestamp.hour),
                1.0 if sigma_matches else 0.0,
                1.0 if ioc_matches else 0.0,
            ]
            anomaly_score = self.ueba_detector.predict_anomaly_score(feature_vector)

            # Calculate Composite 0-100 Risk Score
            risk_score = RiskScorer.calculate_risk_score(
                sigma_matches=sigma_matches,
                ioc_matches=ioc_matches,
                anomaly_score=anomaly_score,
            )
            max_risk_score = max(max_risk_score, risk_score)

            # Trigger Alert if Risk Score >= 30.0
            if risk_score >= 30.0:
                alerts_generated += 1
                severity = (
                    "critical"
                    if risk_score >= 80.0
                    else "high"
                    if risk_score >= 60.0
                    else "medium"
                    if risk_score >= 40.0
                    else "low"
                )

                rule_title = sigma_matches[0].title if sigma_matches else "Threat Anomaly Detected"
                mitre_tags = sigma_matches[0].tags if sigma_matches else ["attack.anomaly"]

                alert = Alert(
                    tenant_id=tenant_id,
                    title=f"Alert: {rule_title}",
                    description=f"Detection triggered on {evt.source_type} (Source: {evt.source_ip or 'unknown'})",
                    severity=severity,
                    risk_score=risk_score,
                    status="open",
                    source_ip=evt.source_ip,
                    destination_ip=evt.destination_ip,
                    username=evt.username,
                    hostname=evt.hostname,
                    mitre_attack_tactics=mitre_tags,
                    detection_rule_id=sigma_matches[0].rule_id if sigma_matches else "ml-ueba-01",
                    extra_details={
                        "sigma_matches": [r.title for r in sigma_matches],
                        "ioc_matches": [m.threat_name for m in ioc_matches],
                        "anomaly_score": anomaly_score,
                    },
                )
                self.session.add(alert)
                await self.session.flush()

                # Publish alert to Redis Stream for real-time SOAR playbooks / WebSockets
                try:
                    await self.redis.xadd(
                        "sentinel_alerts",
                        {
                            "alert_id": str(alert.id),
                            "tenant_id": str(tenant_id),
                            "risk_score": str(risk_score),
                            "severity": severity,
                            "title": alert.title,
                        },
                    )
                except Exception as e:
                    logger.error(f"Failed to publish alert to Redis Stream: {e}")

        await self.session.flush()
        return events_processed, alerts_generated, max_risk_score
