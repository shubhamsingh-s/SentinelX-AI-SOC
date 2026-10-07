"""Event Normalizer converting heterogeneous security logs to the Common Event Schema."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from services.ingestion_service.app.models.event import Event
from services.ingestion_service.app.schemas.ingest import RawEventItem

# Recognized severity levels
SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info"}

# Action normalization mapping
ACTION_MAP = {
    "accept": "allow",
    "permitted": "allow",
    "passed": "allow",
    "success": "allow",
    "ok": "allow",
    "reject": "deny",
    "drop": "deny",
    "blocked": "deny",
    "failed": "deny",
    "failure": "deny",
    "denied": "deny",
}


class EventNormalizer:
    """Normalizes raw heterogeneous telemetry into SentinelX Common Event Schema (CES)."""

    @staticmethod
    def _clean_ip(ip: str | None) -> str | None:
        """Validate and clean IP address string."""
        if not ip:
            return None
        cleaned = ip.strip()
        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            return None

    @staticmethod
    def _clean_port(port: int | str | None) -> int | None:
        """Validate and return integer port within valid range."""
        if port is None:
            return None
        try:
            val = int(port)
            return val if 0 <= val <= 65535 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _normalize_severity(sev: str | None) -> str:
        """Normalize severity string to standard enum level."""
        if not sev:
            return "info"
        cleaned = str(sev).strip().lower()
        if cleaned in SEVERITY_LEVELS:
            return cleaned
        if cleaned in ("error", "fatal", "alert", "crit", "emergency"):
            return "critical"
        if cleaned in ("warn", "warning"):
            return "medium"
        return "info"

    @staticmethod
    def _normalize_action(act: str | None) -> str | None:
        """Map common firewall and authorization actions to standard terms."""
        if not act:
            return None
        cleaned = str(act).strip().lower()
        return ACTION_MAP.get(cleaned, cleaned)

    @classmethod
    def normalize_event(cls, item: RawEventItem, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Convert a RawEventItem into a Common Event Schema dictionary."""
        # 1. Normalize Timestamp
        ts = item.timestamp
        if ts is None:
            ts = datetime.now(UTC)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        # 2. Clean IPs & Ports
        src_ip = cls._clean_ip(item.source_ip)
        dst_ip = cls._clean_ip(item.destination_ip)
        src_port = cls._clean_port(item.source_port)
        dst_port = cls._clean_port(item.destination_port)

        # 3. Clean string tokens
        protocol = item.protocol.strip().upper() if item.protocol else None
        username = item.username.strip().lower() if item.username else None
        hostname = item.hostname.strip().lower() if item.hostname else None
        action = cls._normalize_action(item.action)
        severity = cls._normalize_severity(item.severity)

        # 4. Generate raw payload if absent
        raw_payload = item.raw_payload
        if not raw_payload:
            raw_payload = json.dumps(item.model_dump(mode="json", exclude_none=True))

        return {
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "timestamp": ts,
            "source_type": item.source_type.strip().lower() if item.source_type else "generic",
            "event_name": item.event_name.strip() if item.event_name else "security_event",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "username": username,
            "hostname": hostname,
            "action": action,
            "severity": severity,
            "raw_payload": raw_payload,
            "extra_fields": item.extra_fields or {},
        }

    @classmethod
    def to_model(cls, normalized_data: dict[str, Any]) -> Event:
        """Instantiate SQLAlchemy Event model from normalized dictionary."""
        return Event(
            id=normalized_data["id"],
            tenant_id=normalized_data["tenant_id"],
            timestamp=normalized_data["timestamp"],
            source_type=normalized_data["source_type"],
            event_name=normalized_data["event_name"],
            source_ip=normalized_data["source_ip"],
            destination_ip=normalized_data["destination_ip"],
            source_port=normalized_data["source_port"],
            destination_port=normalized_data["destination_port"],
            protocol=normalized_data["protocol"],
            username=normalized_data["username"],
            hostname=normalized_data["hostname"],
            action=normalized_data["action"],
            severity=normalized_data["severity"],
            raw_payload=normalized_data["raw_payload"],
            extra_fields=normalized_data["extra_fields"],
        )

    @classmethod
    def to_stream_payload(cls, normalized_data: dict[str, Any]) -> dict[str, str]:
        """Convert normalized data to Redis Stream flat string key-value dictionary."""
        return {
            "event_id": str(normalized_data["id"]),
            "tenant_id": str(normalized_data["tenant_id"]),
            "timestamp": normalized_data["timestamp"].isoformat(),
            "source_type": str(normalized_data["source_type"]),
            "event_name": str(normalized_data["event_name"]),
            "source_ip": str(normalized_data["source_ip"] or ""),
            "destination_ip": str(normalized_data["destination_ip"] or ""),
            "username": str(normalized_data["username"] or ""),
            "hostname": str(normalized_data["hostname"] or ""),
            "severity": str(normalized_data["severity"]),
            "action": str(normalized_data["action"] or ""),
            "raw_payload": str(normalized_data["raw_payload"]),
        }
