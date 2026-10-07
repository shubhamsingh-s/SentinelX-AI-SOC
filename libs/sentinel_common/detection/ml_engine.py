"""Layer 3: ML Anomaly Detector (Isolation Forest / UEBA) & Composite 0-100 Risk Scorer."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel_common.detection.ioc_engine import IOCMatch
from sentinel_common.detection.parsers import ParsedLogEvent
from sentinel_common.detection.sigma_engine import SigmaRule


class UEBAAnomalyDetector:
    """Isolation Forest based User and Entity Behavior Analytics (UEBA) anomaly detector."""

    def __init__(self, contamination: float = 0.05) -> None:
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self.is_fitted = False

    def train_baseline(self, feature_matrix: list[list[float]]) -> None:
        """Train Isolation Forest on normal baseline telemetry feature vectors."""
        X = np.array(feature_matrix)
        if len(X) >= 10:
            self.model.fit(X)
            self.is_fitted = True

    def extract_features(self, event: ParsedLogEvent | dict[str, Any]) -> list[float]:
        """Extract standardized numerical feature vector from a security log event.

        Vector components:
        1. Hour of day (0.0 to 23.0)
        2. Day of week (0.0 to 6.0)
        3. Normalized payload length (0.0 to 10.0)
        4. Privileged account indicator (1.0 if admin/root/system, else 0.0)
        5. Internal IP indicator (1.0 if private RFC1918, else 0.0)
        """
        event_dict = event.to_dict() if isinstance(event, ParsedLogEvent) else event

        # 1. Hour and Day
        hour = 12.0
        dow = 2.0
        ts_val = event_dict.get("timestamp")
        if isinstance(ts_val, datetime):
            hour = float(ts_val.hour)
            dow = float(ts_val.weekday())
        elif isinstance(ts_val, str):
            try:
                dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                hour = float(dt.hour)
                dow = float(dt.weekday())
            except Exception:
                pass

        # 2. Payload length (log-scaled)
        payload = str(event_dict.get("raw_payload", ""))
        payload_len = min(10.0, float(len(payload)) / 100.0)

        # 3. Privileged user indicator
        username = str(event_dict.get("username") or "").lower()
        is_priv = 1.0 if any(p in username for p in ("admin", "root", "system", "svc_")) else 0.0

        # 4. Internal IP indicator
        src_ip = str(event_dict.get("source_ip") or "")
        is_private = src_ip.startswith(("10.", "192.168.", "172.16."))
        is_internal = 1.0 if is_private else 0.0

        return [hour, dow, payload_len, is_priv, is_internal]

    def predict_anomaly_score(self, feature_vector: list[float]) -> float:
        """Predict anomaly score (0.0 normal -> 1.0 highly anomalous)."""
        if not self.is_fitted:
            # Baseline default if model not yet fitted
            return 0.2

        X = np.array([feature_vector])
        raw_score = self.model.decision_function(X)[0]
        # Normalize decision function score to 0.0 - 1.0 range
        normalized = float(np.clip(0.5 - (raw_score * 2.0), 0.0, 1.0))
        return normalized


class RiskScorer:
    """Composite 0-100 Risk Scorer integrating 3 Detection Layers + Thresholds."""

    @staticmethod
    def calculate_risk_score(
        sigma_matches: list[SigmaRule] | None = None,
        ioc_matches: list[IOCMatch] | None = None,
        anomaly_score: float = 0.0,
        threshold_matches: list[Any] | None = None,
    ) -> float:
        """Calculate composite 0-100 risk score.

        Formula:
        - Base Score from Sigma Rules / Threshold Rules:
            Low=15, Medium=30, High=60, Critical=85
        - Additive Score from IOC Matches: +20 to +40 based on confidence
        - Anomaly Multiplier: + (anomaly_score * 30.0)
        - Cap at 100.0 max.
        """
        score = 0.0
        sigma_matches = sigma_matches or []
        ioc_matches = ioc_matches or []
        threshold_matches = threshold_matches or []

        level_weights = {"low": 15.0, "medium": 30.0, "high": 60.0, "critical": 85.0}

        # Layer 1: Sigma rules weight
        for rule in sigma_matches:
            rule_level = getattr(rule, "level", "medium").lower()
            weight = level_weights.get(rule_level, 25.0)
            score = max(score, weight)

        # Threshold rules weight
        for t_match in threshold_matches:
            t_sev = getattr(t_match, "severity", "medium").lower()
            weight = level_weights.get(t_sev, 30.0)
            score = max(score, weight)

        # Layer 2: IOC matches weight
        for match in ioc_matches:
            conf = getattr(match, "confidence", 90)
            ioc_boost = (conf / 100.0) * 35.0
            score += ioc_boost

        # Layer 3: ML Anomaly score weight
        score += anomaly_score * 30.0

        final_score = float(np.clip(score, 0.0, 100.0))
        return round(final_score, 1)
