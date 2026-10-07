"""Layer 2: IOC Threat Intel Matching Engine with Redis Cache Lookup."""

from __future__ import annotations

import json
import re
from typing import Any

from sentinel_common.detection.parsers import ParsedLogEvent


class IOCMatch:
    """IOC match detection result."""

    def __init__(self, ioc_type: str, ioc_value: str, threat_name: str, confidence: int = 90) -> None:
        self.ioc_type = ioc_type
        self.ioc_value = ioc_value
        self.threat_name = threat_name
        self.confidence = confidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize match to dictionary."""
        return {
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "threat_name": self.threat_name,
            "confidence": self.confidence,
        }


class IOCEngine:
    """Threat intelligence IOC matching engine using in-memory set & Redis cache index."""

    def __init__(self) -> None:
        self.ip_iocs: dict[str, dict[str, Any]] = {}
        self.domain_iocs: dict[str, dict[str, Any]] = {}
        self.hash_iocs: dict[str, dict[str, Any]] = {}

    def load_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        threat_name: str,
        confidence: int = 90,
    ) -> None:
        """Register an IOC into the in-memory lookup index."""
        record = {"threat_name": threat_name, "confidence": confidence}
        ioc_type = ioc_type.lower()
        if ioc_type == "ip":
            self.ip_iocs[ioc_value] = record
        elif ioc_type == "domain":
            self.domain_iocs[ioc_value] = record
        elif ioc_type in ("hash", "md5", "sha256"):
            self.hash_iocs[ioc_value] = record

    @staticmethod
    def get_redis_key(ioc_type: str, ioc_value: str) -> str:
        """Generate canonical Redis key for an IOC."""
        return f"sentinel:ioc:{ioc_type.lower()}:{ioc_value.strip()}"

    @classmethod
    async def set_redis_ioc(
        cls,
        redis_client: Any,
        ioc_type: str,
        ioc_value: str,
        threat_name: str,
        confidence: int = 90,
        ttl_seconds: int = 86400 * 7,
    ) -> None:
        """Store an IOC indicator in the Redis threat cache."""
        key = cls.get_redis_key(ioc_type, ioc_value)
        data = json.dumps({"threat_name": threat_name, "confidence": confidence})
        await redis_client.set(key, data, ex=ttl_seconds)

    def evaluate(self, event: ParsedLogEvent | dict[str, Any]) -> list[IOCMatch]:
        """Check parsed log event fields against in-memory loaded IOC records."""
        matches: list[IOCMatch] = []
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event

        # Check IP indicators
        for ip_field in ("source_ip", "destination_ip"):
            ip_val = event_dict.get(ip_field)
            if ip_val and ip_val in self.ip_iocs:
                info = self.ip_iocs[ip_val]
                matches.append(
                    IOCMatch(
                        ioc_type="ip",
                        ioc_value=ip_val,
                        threat_name=info["threat_name"],
                        confidence=info["confidence"],
                    )
                )

        # Check domain indicators in extra_fields
        extra = event_dict.get("extra_fields", {})
        if isinstance(extra, dict):
            domain_val = extra.get("domain") or extra.get("query")
            if domain_val and domain_val in self.domain_iocs:
                info = self.domain_iocs[domain_val]
                matches.append(
                    IOCMatch(
                        ioc_type="domain",
                        ioc_value=domain_val,
                        threat_name=info["threat_name"],
                        confidence=info["confidence"],
                    )
                )

            hash_val = extra.get("hash") or extra.get("sha256") or extra.get("md5")
            if hash_val and hash_val in self.hash_iocs:
                info = self.hash_iocs[hash_val]
                matches.append(
                    IOCMatch(
                        ioc_type="hash",
                        ioc_value=hash_val,
                        threat_name=info["threat_name"],
                        confidence=info["confidence"],
                    )
                )

        return matches

    async def evaluate_redis(
        self,
        redis_client: Any,
        event: ParsedLogEvent | dict[str, Any],
    ) -> list[IOCMatch]:
        """Check event against Redis IOC cache, supplementing with in-memory rules."""
        # 1. Start with in-memory matches
        matches = self.evaluate(event)
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event
        matched_values = {m.ioc_value for m in matches}

        # 2. Extract potential IOCs from event
        candidates: list[tuple[str, str]] = []  # (ioc_type, ioc_value)

        for ip_field in ("source_ip", "destination_ip"):
            val = event_dict.get(ip_field)
            if val and val not in matched_values:
                candidates.append(("ip", str(val)))

        extra = event_dict.get("extra_fields", {})
        if isinstance(extra, dict):
            if extra.get("domain"):
                candidates.append(("domain", str(extra["domain"])))
            for hf in ("hash", "sha256", "md5"):
                if extra.get(hf):
                    candidates.append(("hash", str(extra[hf])))

        # Check raw payload for IP patterns if none found
        raw_payload = str(event_dict.get("raw_payload", ""))
        if not candidates and raw_payload:
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_payload)
            for ip in set(ips):
                if ip not in matched_values:
                    candidates.append(("ip", ip))

        # 3. Query Redis for each candidate
        for ioc_type, ioc_val in candidates:
            if ioc_val in matched_values:
                continue
            try:
                key = self.get_redis_key(ioc_type, ioc_val)
                raw_data = await redis_client.get(key)
                if raw_data:
                    data = json.loads(raw_data) if isinstance(raw_data, (str, bytes)) else raw_data
                    if isinstance(data, dict):
                        matches.append(
                            IOCMatch(
                                ioc_type=ioc_type,
                                ioc_value=ioc_val,
                                threat_name=data.get("threat_name", "Known Threat Indicator"),
                                confidence=int(data.get("confidence", 90)),
                            )
                        )
                        matched_values.add(ioc_val)
            except Exception:
                # Silently skip Redis read errors
                pass

        return matches
