"""Layer 2: IOC Threat Intel Matching Engine."""

from typing import Any

from sentinel_common.detection.parsers import ParsedLogEvent


class IOCMatch:
    """IOC match detection result."""

    def __init__(self, ioc_type: str, ioc_value: str, threat_name: str, confidence: int) -> None:
        self.ioc_type = ioc_type
        self.ioc_value = ioc_value
        self.threat_name = threat_name
        self.confidence = confidence


class IOCEngine:
    """Threat intelligence IOC matching engine using in-memory set / Redis index."""

    def __init__(self) -> None:
        self.ip_iocs: dict[str, dict[str, Any]] = {}
        self.domain_iocs: dict[str, dict[str, Any]] = {}
        self.hash_iocs: dict[str, dict[str, Any]] = {}

    def load_ioc(self, ioc_type: str, ioc_value: str, threat_name: str, confidence: int = 90) -> None:
        """Register an IOC into the lookup index."""
        record = {"threat_name": threat_name, "confidence": confidence}
        if ioc_type == "ip":
            self.ip_iocs[ioc_value] = record
        elif ioc_type == "domain":
            self.domain_iocs[ioc_value] = record
        elif ioc_type in ("hash", "md5", "sha256"):
            self.hash_iocs[ioc_value] = record

    def evaluate(self, event: ParsedLogEvent) -> list[IOCMatch]:
        """Check parsed log event fields against loaded IOC threat intelligence records."""
        matches: list[IOCMatch] = []

        if event.source_ip and event.source_ip in self.ip_iocs:
            info = self.ip_iocs[event.source_ip]
            matches.append(
                IOCMatch(
                    ioc_type="ip",
                    ioc_value=event.source_ip,
                    threat_name=info["threat_name"],
                    confidence=info["confidence"],
                )
            )

        if event.destination_ip and event.destination_ip in self.ip_iocs:
            info = self.ip_iocs[event.destination_ip]
            matches.append(
                IOCMatch(
                    ioc_type="ip",
                    ioc_value=event.destination_ip,
                    threat_name=info["threat_name"],
                    confidence=info["confidence"],
                )
            )

        return matches
