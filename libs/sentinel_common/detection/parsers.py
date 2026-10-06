"""Log parsers for Syslog, AWS CloudTrail, VPC Flow Logs, and Webhooks."""

import json
import re
from datetime import UTC, datetime
from typing import Any


class ParsedLogEvent:
    """Normalized security log event structure."""

    def __init__(
        self,
        source_type: str,
        timestamp: datetime,
        event_name: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
        raw_payload: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        self.source_type = source_type
        self.timestamp = timestamp
        self.event_name = event_name
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.username = username
        self.hostname = hostname
        self.raw_payload = raw_payload
        self.extra_fields = extra_fields or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize log event to dictionary."""
        return {
            "source_type": self.source_type,
            "timestamp": self.timestamp.isoformat(),
            "event_name": self.event_name,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "hostname": self.hostname,
            "raw_payload": self.raw_payload,
            "extra_fields": self.extra_fields,
        }


class LogParser:
    """Unified log parsing facade."""

    @staticmethod
    def parse_syslog(message: str) -> ParsedLogEvent:
        """Parse RFC 5424 / RFC 3164 Syslog format."""
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        source_ip = ip_match.group(0) if ip_match else None

        user_match = re.search(
            r"(?:user[=:\s]+|for\s+(?:invalid\s+user\s+)?)([a-zA-Z0-9_\-\.]+)", message, re.IGNORECASE
        )
        username = user_match.group(1) if user_match else None

        return ParsedLogEvent(
            source_type="syslog",
            timestamp=datetime.now(UTC),
            event_name="SYSLOG_MSG",
            source_ip=source_ip,
            username=username,
            raw_payload=message,
        )

    @staticmethod
    def parse_cloudtrail(payload: dict[str, Any] | str) -> list[ParsedLogEvent]:
        """Parse AWS CloudTrail event record(s)."""
        data = json.loads(payload) if isinstance(payload, str) else payload
        records = data.get("Records", [data]) if isinstance(data, dict) else [data]

        parsed_events: list[ParsedLogEvent] = []
        for rec in records:
            event_name = rec.get("eventName", "CloudTrailEvent")
            user_identity = rec.get("userIdentity", {})
            username = user_identity.get("userName") or user_identity.get("principalId")
            source_ip = rec.get("sourceIPAddress")

            evt = ParsedLogEvent(
                source_type="aws_cloudtrail",
                timestamp=datetime.now(UTC),
                event_name=event_name,
                source_ip=source_ip,
                username=username,
                raw_payload=json.dumps(rec),
                extra_fields={"eventSource": rec.get("eventSource"), "awsRegion": rec.get("awsRegion")},
            )
            parsed_events.append(evt)
        return parsed_events

    @staticmethod
    def parse_vpc_flow(line: str) -> ParsedLogEvent:
        """Parse AWS VPC Flow Log (default format: version account-id interface-id srcaddr dstaddr ...)."""
        parts = line.strip().split()
        if len(parts) >= 6:
            source_ip = parts[3]
            dest_ip = parts[4]
            action = parts[12] if len(parts) >= 13 else "ACCEPT"
        else:
            source_ip, dest_ip, action = None, None, "UNKNOWN"

        return ParsedLogEvent(
            source_type="vpc_flow_log",
            timestamp=datetime.now(UTC),
            event_name=f"VPC_FLOW_{action}",
            source_ip=source_ip,
            destination_ip=dest_ip,
            raw_payload=line,
        )
