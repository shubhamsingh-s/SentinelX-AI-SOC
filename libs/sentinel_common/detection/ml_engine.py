"""Layer 3: ML Anomaly Detector (Isolation Forest / UEBA) & Composite 0-100 Risk Scorer."""

import numpy as np
from sklearn.ensemble import IsolationForest

from sentinel_common.detection.ioc_engine import IOCMatch
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

    def predict_anomaly_score(self, feature_vector: list[float]) -> float:
        """Predict anomaly score (0.0 normal -> 1.0 highly anomalous)."""
        if not self.is_fitted:
            # Return baseline threshold if model not yet trained
            return 0.2

        X = np.array([feature_vector])
        raw_score = self.model.decision_function(X)[0]
        # Normalize decision function score to 0.0 - 1.0 range
        normalized = float(np.clip(0.5 - (raw_score * 2.0), 0.0, 1.0))
        return normalized


class RiskScorer:
    """Composite 0-100 Risk Scorer integrating 3 Detection Layers."""

    @staticmethod
    def calculate_risk_score(
        sigma_matches: list[SigmaRule],
        ioc_matches: list[IOCMatch],
        anomaly_score: float,
    ) -> float:
        """Calculate composite 0-100 risk score.

        Formula:
        - Base Score from Sigma Rules: Low=15, Medium=30, High=60, Critical=85
        - Additive Score from IOC Matches: +20 to +40 based on confidence
        - Anomaly Multiplier / Score: + (anomaly_score * 30)
        - Cap at 100.0 max.
        """
        score = 0.0

        # Layer 1: Sigma rules weight
        level_weights = {"low": 15.0, "medium": 30.0, "high": 60.0, "critical": 85.0}
        for rule in sigma_matches:
            weight = level_weights.get(rule.level.lower(), 25.0)
            score = max(score, weight)

        # Layer 2: IOC matches weight
        for match in ioc_matches:
            ioc_boost = (match.confidence / 100.0) * 35.0
            score += ioc_boost

        # Layer 3: ML Anomaly score weight
        score += anomaly_score * 30.0

        final_score = float(np.clip(score, 0.0, 100.0))
        return round(final_score, 1)
