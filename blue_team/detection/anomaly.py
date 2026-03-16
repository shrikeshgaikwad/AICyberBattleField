"""
Anomaly Detection - ML-Based Network Anomaly Detection
========================================================
Uses Isolation Forest to detect anomalous network behavior.
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from django.conf import settings

from blue_team.models import Alert, TrafficLog

logger = logging.getLogger("blue_team.detection")


class AnomalyDetector:
    """
    ML-based network anomaly detection using Isolation Forest.
    Learns baseline behavior and flags deviations.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or str(Path(settings.BASE_DIR) / "models" / "anomaly_model.pkl")
        self.model = None
        self.scaler = None
        self.feature_names = [
            "packet_size",
            "dest_port",
            "packets_per_second",
            "unique_dest_ports",
            "connection_count",
            "avg_payload_size",
            "syn_count",
            "rst_count",
        ]
        self._load_model()

    def _load_model(self):
        """Load pre-trained model if available."""
        try:
            if Path(self.model_path).exists():
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.model = data["model"]
                    self.scaler = data.get("scaler")
                logger.info("Loaded anomaly detection model")
        except Exception as e:
            logger.warning(f"Could not load model: {e}")

    def train(self, traffic_data: list = None, contamination: float = 0.1):
        """
        Train the anomaly detection model on baseline traffic.

        Args:
            traffic_data: List of feature dicts. If None, loads from database.
            contamination: Expected proportion of anomalies (0.0-0.5).
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        if traffic_data is None:
            traffic_data = self._load_training_data()

        if len(traffic_data) < 10:
            logger.warning("Insufficient training data (need at least 10 samples)")
            return False

        # Extract features
        X = self._extract_features(traffic_data)

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        # Save model
        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)

        logger.info(f"Anomaly model trained on {len(traffic_data)} samples")
        return True

    def detect(self, traffic_entry: dict) -> dict:
        """
        Analyze a traffic entry for anomalies.

        Args:
            traffic_entry: Dict with traffic metrics.

        Returns:
            Dict with is_anomalous, anomaly_score, and confidence.
        """
        if self.model is None:
            return {"is_anomalous": False, "anomaly_score": 0.0, "confidence": 0.0, "reason": "Model not trained"}

        try:
            features = self._extract_single_features(traffic_entry)
            X = np.array([features])

            if self.scaler:
                X = self.scaler.transform(X)

            # Get prediction (-1 = anomaly, 1 = normal)
            prediction = self.model.predict(X)[0]
            score = self.model.score_samples(X)[0]

            is_anomalous = prediction == -1

            # Convert score to 0-1 range (lower score = more anomalous)
            anomaly_score = max(0.0, min(1.0, -score))

            result = {
                "is_anomalous": is_anomalous,
                "anomaly_score": float(anomaly_score),
                "confidence": float(min(anomaly_score * 1.5, 1.0)),
                "features": dict(zip(self.feature_names, features)),
            }

            if is_anomalous:
                # Determine most anomalous feature
                result["reason"] = self._identify_anomaly_reason(features, traffic_entry)

            return result

        except Exception as e:
            logger.error(f"Anomaly detection error: {e}", exc_info=True)
            return {"is_anomalous": False, "anomaly_score": 0.0, "confidence": 0.0, "error": str(e)}

    def detect_batch(self, traffic_entries: list) -> list:
        """Analyze multiple traffic entries for anomalies."""
        return [self.detect(entry) for entry in traffic_entries]

    def _extract_features(self, traffic_data: list) -> np.ndarray:
        """Extract feature matrix from traffic data."""
        return np.array([self._extract_single_features(entry) for entry in traffic_data])

    def _extract_single_features(self, entry: dict) -> list:
        """Extract feature vector from a single traffic entry."""
        return [
            entry.get("packet_size", 0),
            entry.get("dest_port", 0),
            entry.get("packets_per_second", 0),
            entry.get("unique_dest_ports", 1),
            entry.get("connection_count", 1),
            entry.get("avg_payload_size", 0),
            entry.get("syn_count", 0),
            entry.get("rst_count", 0),
        ]

    def _identify_anomaly_reason(self, features: list, entry: dict) -> str:
        """Identify the most likely reason for an anomaly."""
        reasons = []

        if features[0] > 1500:  # packet_size
            reasons.append("unusually large packet")
        if features[2] > 100:  # packets_per_second
            reasons.append("high packet rate (possible scan/DoS)")
        if features[3] > 20:  # unique_dest_ports
            reasons.append("port scanning behavior")
        if features[4] > 50:  # connection_count
            reasons.append("excessive connections")
        if features[6] > 10:  # syn_count
            reasons.append("SYN flood indicators")
        if features[7] > 5:  # rst_count
            reasons.append("connection reset storm")

        return "; ".join(reasons) if reasons else "statistical anomaly detected"

    def _load_training_data(self) -> list:
        """Load training data from the database."""
        logs = TrafficLog.objects.filter(is_anomalous=False).order_by("-timestamp")[:5000]
        return [
            {
                "packet_size": log.packet_size,
                "dest_port": log.destination_port or 0,
                "packets_per_second": 1,
                "unique_dest_ports": 1,
                "connection_count": 1,
                "avg_payload_size": log.packet_size,
                "syn_count": 1 if "SYN" in (log.flags or "") else 0,
                "rst_count": 1 if "RST" in (log.flags or "") else 0,
            }
            for log in logs
        ]

    def retrain(self, include_recent_alerts: bool = True):
        """
        Retrain the model with updated data.
        Optionally include confirmed alerts as positive samples.
        """
        logger.info("Retraining anomaly detection model...")
        data = self._load_training_data()

        if include_recent_alerts:
            # Use confirmed alerts as contamination examples
            confirmed_alerts = Alert.objects.filter(status=Alert.Status.CONFIRMED).order_by("-created_at")[:100]
            # This helps the model learn attack patterns
            for alert in confirmed_alerts:
                if alert.raw_data:
                    data.append(alert.raw_data)

        return self.train(data)
