"""Log Ingestion, Normalization, Event Stream, and Threat Detection Orchestrator."""

import uuid
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_common.detection.ioc_engine import IOCEngine
from sentinel_common.detection.ml_engine import RiskScorer, UEBAAnomalyDetector
from sentinel_common.detection.parsers import ParsedLogEvent
from sentinel_common.detection.sigma_engine import SigmaEngine, SigmaRule
from sentinel_common.exceptions import BadRequestException, NotFoundException
from sentinel_common.logger import logger
from services.ingestion_service.app.models.alert import Alert
from services.ingestion_service.app.models.event import Event
from services.ingestion_service.app.models.log_event import LogEvent
from services.ingestion_service.app.models.log_source import LogSource
from services.ingestion_service.app.schemas.ingest import (
    EventBatchIngestResponse,
    RawEventItem,
)
from services.ingestion_service.app.schemas.log_source import (
    LogSourceCreate,
    LogSourceUpdate,
)
from services.ingestion_service.app.services.normalizer import EventNormalizer


class IngestionService:
    """Ingestion orchestrator executing batch normalisation, Redis Stream publishing, and 3-Layer detection."""

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
        self.ioc_engine.load_ioc("ip", "192.168.1.100", "Malicious Botnet C2", confidence=95)
        self.ioc_engine.load_ioc("ip", "10.0.0.99", "APT29 Known Exploit Host", confidence=90)

    async def ingest_event_batch(
        self, tenant_id: uuid.UUID, events: list[RawEventItem]
    ) -> EventBatchIngestResponse:
        """Normalize event batch, push to Redis Stream events:raw, and write to events hypertable."""
        if not events:
            raise BadRequestException("Event batch cannot be empty")
        if len(events) > 1000:
            raise BadRequestException("Event batch size exceeds maximum limit of 1,000 events")

        db_models: list[Event] = []
        stream_payloads: list[dict[str, str]] = []

        # 1. Normalize each event into Common Event Schema
        for item in events:
            norm_dict = EventNormalizer.normalize_event(item, tenant_id=tenant_id)
            db_models.append(EventNormalizer.to_model(norm_dict))
            stream_payloads.append(EventNormalizer.to_stream_payload(norm_dict))

        # 2. Push events to Redis Stream events:raw
        try:
            for payload in stream_payloads:
                await self.redis.xadd("events:raw", payload)
        except Exception as e:
            logger.error(f"Error publishing event batch to Redis Stream 'events:raw': {e}")

        # 3. Batch write events to TimescaleDB events hypertable
        self.session.add_all(db_models)
        await self.session.flush()

        return EventBatchIngestResponse(
            status="accepted",
            events_ingested=len(db_models),
            stream="events:raw",
        )

    # --- Log Sources CRUD Operations ---

    async def create_log_source(self, tenant_id: uuid.UUID, payload: LogSourceCreate) -> LogSource:
        """Register a new log source telemetry provider."""
        source = LogSource(
            tenant_id=tenant_id,
            name=payload.name,
            source_type=payload.source_type,
            description=payload.description,
            is_active=payload.is_active,
            config=payload.config or {},
        )
        self.session.add(source)
        await self.session.flush()
        return source

    async def list_log_sources(self, tenant_id: uuid.UUID) -> list[LogSource]:
        """Fetch all log sources configured for the tenant."""
        stmt = select(LogSource).where(LogSource.tenant_id == tenant_id).order_by(LogSource.created_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_log_source(self, tenant_id: uuid.UUID, source_id: uuid.UUID) -> LogSource:
        """Fetch a specific log source by ID for tenant."""
        stmt = select(LogSource).where(LogSource.id == source_id, LogSource.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        source = result.scalar_one_or_none()
        if not source:
            raise NotFoundException("Log source not found")
        return source

    async def update_log_source(
        self, tenant_id: uuid.UUID, source_id: uuid.UUID, payload: LogSourceUpdate
    ) -> LogSource:
        """Update an existing log source configuration."""
        source = await self.get_log_source(tenant_id, source_id)
        if payload.name is not None:
            source.name = payload.name
        if payload.source_type is not None:
            source.source_type = payload.source_type
        if payload.description is not None:
            source.description = payload.description
        if payload.is_active is not None:
            source.is_active = payload.is_active
        if payload.config is not None:
            source.config = payload.config

        await self.session.flush()
        return source

    async def delete_log_source(self, tenant_id: uuid.UUID, source_id: uuid.UUID) -> bool:
        """Delete a log source configuration."""
        source = await self.get_log_source(tenant_id, source_id)
        await self.session.delete(source)
        await self.session.flush()
        return True

    # --- Legacy Parsing & Threat Engine Processing ---

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
            sigma_matches = self.sigma_engine.evaluate(evt)
            ioc_matches = self.ioc_engine.evaluate(evt)

            feature_vector = [
                float(evt.timestamp.hour),
                1.0 if sigma_matches else 0.0,
                1.0 if ioc_matches else 0.0,
            ]
            anomaly_score = self.ueba_detector.predict_anomaly_score(feature_vector)

            risk_score = RiskScorer.calculate_risk_score(
                sigma_matches=sigma_matches,
                ioc_matches=ioc_matches,
                anomaly_score=anomaly_score,
            )
            max_risk_score = max(max_risk_score, risk_score)

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
