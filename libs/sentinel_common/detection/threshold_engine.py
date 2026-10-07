"""Threshold Threat Detection Engine with Redis Sliding Windows."""

from __future__ import annotations

import time
import uuid
from typing import Any

from sentinel_common.detection.parsers import ParsedLogEvent


class ThresholdRule:
    """Specification for sliding window threshold detection rule."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str = "medium",
        window_seconds: int = 60,
        threshold: int = 5,
        group_by: str = "source_ip",
        event_filter: dict[str, Any] | None = None,
        description: str = "",
        mitre_attack_tactics: list[str] | None = None,
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.severity = severity.lower()
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.group_by = group_by
        self.event_filter = event_filter or {}
        self.description = description
        self.mitre_attack_tactics = mitre_attack_tactics or []

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThresholdRule:
        """Instantiate ThresholdRule from dictionary."""
        return cls(
            rule_id=str(data.get("id") or data.get("rule_id", "thresh-001")),
            title=str(data.get("title", "Untitled Threshold Rule")),
            severity=str(data.get("severity", "medium")),
            window_seconds=int(data.get("window_seconds", 60)),
            threshold=int(data.get("threshold", 5)),
            group_by=str(data.get("group_by", "source_ip")),
            event_filter=dict(data.get("event_filter", {})),
            description=str(data.get("description", "")),
            mitre_attack_tactics=list(data.get("mitre_attack_tactics", [])),
        )

    def matches_filter(self, event: ParsedLogEvent | dict[str, Any]) -> bool:
        """Check if event meets pre-filter criteria for threshold evaluation."""
        if not self.event_filter:
            return True

        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event
        raw_payload = str(event_dict.get("raw_payload", ""))

        for field, expected in self.event_filter.items():
            if field == "raw_payload|contains":
                if isinstance(expected, list):
                    if not any(item.lower() in raw_payload.lower() for item in expected):
                        return False
                elif str(expected).lower() not in raw_payload.lower():
                    return False
            else:
                actual = event_dict.get(field)
                if actual is None and "extra_fields" in event_dict:
                    actual = event_dict["extra_fields"].get(field)
                if actual is None:
                    return False
                if str(actual).lower() != str(expected).lower():
                    return False
        return True

    def extract_group_value(self, event: ParsedLogEvent | dict[str, Any]) -> str | None:
        """Extract the group_by key value from the event."""
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event
        val = event_dict.get(self.group_by)
        if val is None and "extra_fields" in event_dict:
            val = event_dict["extra_fields"].get(self.group_by)
        return str(val) if val is not None else None


class ThresholdMatch:
    """Result object when a sliding window threshold is triggered."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        count: int,
        threshold: int,
        window_seconds: int,
        group_by_field: str,
        group_by_value: str,
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.count = count
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.group_by_field = group_by_field
        self.group_by_value = group_by_value

    def to_dict(self) -> dict[str, Any]:
        """Convert match to dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "count": self.count,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "group_by_field": self.group_by_field,
            "group_by_value": self.group_by_value,
        }


class ThresholdEngine:
    """Threshold rule evaluator using Redis sorted sets (ZSET) for sliding windows."""

    def __init__(self, rules: list[ThresholdRule] | None = None) -> None:
        self.rules: list[ThresholdRule] = rules or []

    def add_rule(self, rule: ThresholdRule) -> None:
        """Register a threshold rule."""
        self.rules.append(rule)

    async def evaluate(
        self,
        redis_client: Any,
        event: ParsedLogEvent | dict[str, Any],
        tenant_id: str = "default",
    ) -> list[ThresholdMatch]:
        """Evaluate event against registered threshold rules using Redis sliding windows."""
        matches: list[ThresholdMatch] = []
        now = time.time()

        for rule in self.rules:
            if not rule.matches_filter(event):
                continue

            group_val = rule.extract_group_value(event)
            if not group_val:
                continue

            # Sliding window Redis key: sentinel:threshold:{tenant}:{rule}:{group_val}
            redis_key = f"sentinel:threshold:{tenant_id}:{rule.rule_id}:{group_val}"
            min_score = "-inf"
            max_expired_score = now - rule.window_seconds

            try:
                # 1. Prune expired entries outside sliding window
                await redis_client.zremrangebyscore(redis_key, min_score, max_expired_score)

                # 2. Add current event entry
                member = f"{uuid.uuid4().hex[:8]}:{now}"
                await redis_client.zadd(redis_key, {member: now})

                # 3. Set TTL to prevent stale key retention
                await redis_client.expire(redis_key, rule.window_seconds * 2)

                # 4. Count events within the sliding window
                count = await redis_client.zcard(redis_key)

                # 5. Check if threshold exceeded
                if count >= rule.threshold:
                    matches.append(
                        ThresholdMatch(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            count=count,
                            threshold=rule.threshold,
                            window_seconds=rule.window_seconds,
                            group_by_field=rule.group_by,
                            group_by_value=group_val,
                        )
                    )
            except Exception:
                # Allow non-fatal fallback in testing or Redis temporary issues
                pass

        return matches
