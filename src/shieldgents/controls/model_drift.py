"""
Model Drift and Integrity Monitoring Module

Monitors AI agent model behavior for drift, tampering, and integrity violations.
Detects if models have been degraded, replaced, or manipulated at runtime.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import math
from collections import deque


class DriftType(Enum):
    """Types of model drift."""

    CONCEPT_DRIFT = "concept_drift"
    DATA_DRIFT = "data_drift"
    PREDICTION_DRIFT = "prediction_drift"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    BEHAVIORAL_CHANGE = "behavioral_change"


class IntegrityThreat(Enum):
    """Types of integrity threats."""

    MODEL_TAMPERING = "model_tampering"
    MODEL_REPLACEMENT = "model_replacement"
    WEIGHTS_CORRUPTION = "weights_corruption"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"


@dataclass
class DriftAlert:
    """Alert for detected model drift."""

    drift_type: DriftType
    severity: str  # "low", "medium", "high", "critical"
    confidence: float
    description: str
    metrics: Dict[str, float]
    timestamp: datetime = field(default_factory=datetime.now)
    should_retrain: bool = False
    should_rollback: bool = False


@dataclass
class IntegrityAlert:
    """Alert for integrity violations."""

    threat_type: IntegrityThreat
    severity: str
    description: str
    evidence: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    should_block: bool = True


class ModelDriftDetector:
    """
    Detects model drift using statistical methods.

    Features:
    - Population Stability Index (PSI)
    - KL divergence calculation
    - Performance metric tracking
    - Behavioral pattern analysis
    """

    def __init__(
        self,
        psi_threshold: float = 0.2,
        kl_threshold: float = 0.1,
        window_size: int = 1000,
        baseline_window: int = 5000,
    ):
        self.psi_threshold = psi_threshold
        self.kl_threshold = kl_threshold
        self.window_size = window_size
        self.baseline_window = baseline_window

        # Baseline distributions
        self.baseline_predictions: deque = deque(maxlen=baseline_window)
        self.baseline_features: deque = deque(maxlen=baseline_window)

        # Current window
        self.current_predictions: deque = deque(maxlen=window_size)
        self.current_features: deque = deque(maxlen=window_size)

        # Performance tracking
        self.baseline_performance: Dict[str, float] = {}
        self.current_performance: Dict[str, float] = {}

    def set_baseline(self, predictions: List[float], features: List[Dict[str, float]]):
        """
        Set baseline distributions for drift detection.

        Args:
            predictions: List of baseline predictions
            features: List of baseline feature dictionaries
        """
        self.baseline_predictions.extend(predictions)
        if features:
            self.baseline_features.extend(features)

    def record_prediction(self, prediction: float, features: Optional[Dict[str, float]] = None):
        """
        Record a new prediction and its features.

        Args:
            prediction: Model prediction value
            features: Optional feature dictionary
        """
        self.current_predictions.append(prediction)
        if features:
            self.current_features.append(features)

    def check_drift(self) -> List[DriftAlert]:
        """
        Check for various types of drift.

        Returns:
            List of drift alerts
        """
        alerts = []

        # Check prediction drift using PSI
        if len(self.baseline_predictions) > 100 and len(self.current_predictions) > 100:
            psi = self._calculate_psi(
                list(self.baseline_predictions), list(self.current_predictions)
            )

            if psi > self.psi_threshold:
                severity = "critical" if psi > 0.5 else "high" if psi > 0.3 else "medium"
                alerts.append(
                    DriftAlert(
                        drift_type=DriftType.PREDICTION_DRIFT,
                        severity=severity,
                        confidence=min(1.0, psi / 0.5),
                        description=f"Prediction distribution drift detected (PSI: {psi:.4f})",
                        metrics={"psi": psi, "threshold": self.psi_threshold},
                        should_retrain=psi > 0.3,
                        should_rollback=psi > 0.5,
                    )
                )

        # Check data drift using KL divergence
        if len(self.baseline_predictions) > 100 and len(self.current_predictions) > 100:
            kl_div = self._calculate_kl_divergence(
                list(self.baseline_predictions), list(self.current_predictions)
            )

            if kl_div > self.kl_threshold:
                severity = "high" if kl_div > 0.5 else "medium"
                alerts.append(
                    DriftAlert(
                        drift_type=DriftType.DATA_DRIFT,
                        severity=severity,
                        confidence=min(1.0, kl_div / 1.0),
                        description=f"Data distribution drift detected (KL: {kl_div:.4f})",
                        metrics={"kl_divergence": kl_div, "threshold": self.kl_threshold},
                        should_retrain=kl_div > 0.5,
                    )
                )

        return alerts

    def _calculate_psi(self, baseline: List[float], current: List[float], bins: int = 10) -> float:
        """
        Calculate Population Stability Index.

        Args:
            baseline: Baseline distribution
            current: Current distribution
            bins: Number of bins for discretization

        Returns:
            PSI value
        """
        if not baseline or not current:
            return 0.0

        # Create bins based on baseline distribution
        min_val = min(min(baseline), min(current))
        max_val = max(max(baseline), max(current))
        bin_edges = [min_val + (max_val - min_val) * i / bins for i in range(bins + 1)]

        # Calculate distributions
        baseline_dist = self._create_distribution(baseline, bin_edges)
        current_dist = self._create_distribution(current, bin_edges)

        # Calculate PSI
        psi = 0.0
        for b_pct, c_pct in zip(baseline_dist, current_dist):
            if b_pct > 0 and c_pct > 0:
                psi += (c_pct - b_pct) * math.log(c_pct / b_pct)

        return abs(psi)

    def _calculate_kl_divergence(
        self, baseline: List[float], current: List[float], bins: int = 10
    ) -> float:
        """
        Calculate KL divergence between distributions.

        Args:
            baseline: Baseline distribution
            current: Current distribution
            bins: Number of bins

        Returns:
            KL divergence value
        """
        if not baseline or not current:
            return 0.0

        # Create bins
        min_val = min(min(baseline), min(current))
        max_val = max(max(baseline), max(current))
        bin_edges = [min_val + (max_val - min_val) * i / bins for i in range(bins + 1)]

        # Calculate distributions
        p = self._create_distribution(baseline, bin_edges)
        q = self._create_distribution(current, bin_edges)

        # Calculate KL divergence with smoothing
        epsilon = 1e-10
        kl_div = sum(
            p_i * math.log((p_i + epsilon) / (q_i + epsilon)) for p_i, q_i in zip(p, q) if p_i > 0
        )

        return abs(kl_div)

    def _create_distribution(self, data: List[float], bin_edges: List[float]) -> List[float]:
        """Create normalized distribution from data using bins."""
        counts = [0] * (len(bin_edges) - 1)

        for value in data:
            for i in range(len(bin_edges) - 1):
                if bin_edges[i] <= value < bin_edges[i + 1]:
                    counts[i] += 1
                    break
                elif i == len(bin_edges) - 2 and value >= bin_edges[i + 1]:
                    counts[i] += 1
                    break

        total = sum(counts)
        if total == 0:
            return [1.0 / len(counts)] * len(counts)

        return [c / total for c in counts]

    def set_performance_baseline(self, metrics: Dict[str, float]):
        """Set baseline performance metrics."""
        self.baseline_performance = metrics.copy()

    def record_performance(self, metrics: Dict[str, float]) -> List[DriftAlert]:
        """
        Record current performance and check for degradation.

        Args:
            metrics: Performance metrics dict (e.g., {"accuracy": 0.95, "latency": 0.1})

        Returns:
            List of alerts if degradation detected
        """
        alerts = []
        self.current_performance = metrics.copy()

        for metric_name, current_value in metrics.items():
            if metric_name in self.baseline_performance:
                baseline_value = self.baseline_performance[metric_name]

                # For accuracy-like metrics (higher is better)
                if metric_name in ["accuracy", "precision", "recall", "f1"]:
                    degradation = (
                        (baseline_value - current_value) / baseline_value
                        if baseline_value > 0
                        else 0
                    )

                    if degradation > 0.1:  # 10% degradation threshold
                        severity = (
                            "critical"
                            if degradation > 0.3
                            else "high" if degradation > 0.2 else "medium"
                        )
                        alerts.append(
                            DriftAlert(
                                drift_type=DriftType.PERFORMANCE_DEGRADATION,
                                severity=severity,
                                confidence=min(1.0, degradation / 0.3),
                                description=f"{metric_name} degraded by {degradation:.1%}",
                                metrics={
                                    "metric": metric_name,
                                    "baseline": baseline_value,
                                    "current": current_value,
                                    "degradation": degradation,
                                },
                                should_retrain=degradation > 0.2,
                                should_rollback=degradation > 0.3,
                            )
                        )

        return alerts


class ModelIntegrityMonitor:
    """
    Monitors model integrity and detects tampering.

    Features:
    - Model fingerprinting
    - Weight checksum validation
    - Behavior consistency checking
    """

    def __init__(self):
        self.model_fingerprints: Dict[str, str] = {}
        self.behavior_baselines: Dict[str, List[str]] = {}

    def create_fingerprint(self, model_id: str, model_data: bytes) -> str:
        """
        Create a cryptographic fingerprint of the model.

        Args:
            model_id: Unique model identifier
            model_data: Serialized model data (weights, config, etc.)

        Returns:
            Fingerprint hash
        """
        fingerprint = hashlib.sha256(model_data).hexdigest()
        self.model_fingerprints[model_id] = fingerprint
        return fingerprint

    def verify_fingerprint(self, model_id: str, model_data: bytes) -> Optional[IntegrityAlert]:
        """
        Verify model integrity against stored fingerprint.

        Args:
            model_id: Model identifier
            model_data: Current model data

        Returns:
            Alert if integrity check fails
        """
        if model_id not in self.model_fingerprints:
            return IntegrityAlert(
                threat_type=IntegrityThreat.FINGERPRINT_MISMATCH,
                severity="high",
                description=f"No baseline fingerprint found for model {model_id}",
                evidence={"model_id": model_id},
                should_block=False,
            )

        current_fingerprint = hashlib.sha256(model_data).hexdigest()
        expected_fingerprint = self.model_fingerprints[model_id]

        if current_fingerprint != expected_fingerprint:
            return IntegrityAlert(
                threat_type=IntegrityThreat.MODEL_TAMPERING,
                severity="critical",
                description=f"Model fingerprint mismatch for {model_id}",
                evidence={
                    "model_id": model_id,
                    "expected": expected_fingerprint,
                    "actual": current_fingerprint,
                },
                should_block=True,
            )

        return None

    def set_behavior_baseline(self, model_id: str, test_inputs: List[str], outputs: List[str]):
        """
        Set behavioral baseline for a model.

        Args:
            model_id: Model identifier
            test_inputs: List of test inputs
            outputs: Expected outputs for test inputs
        """
        self.behavior_baselines[model_id] = outputs

    def check_behavior_consistency(
        self,
        model_id: str,
        test_inputs: List[str],
        current_outputs: List[str],
        tolerance: float = 0.1,
    ) -> Optional[IntegrityAlert]:
        """
        Check if model behavior is consistent with baseline.

        Args:
            model_id: Model identifier
            test_inputs: Test inputs
            current_outputs: Current model outputs
            tolerance: Allowed deviation ratio

        Returns:
            Alert if behavior has changed significantly
        """
        if model_id not in self.behavior_baselines:
            return None

        baseline_outputs = self.behavior_baselines[model_id]

        if len(baseline_outputs) != len(current_outputs):
            return IntegrityAlert(
                threat_type=IntegrityThreat.BEHAVIORAL_CHANGE,
                severity="high",
                description=f"Output count mismatch for model {model_id}",
                evidence={
                    "expected_count": len(baseline_outputs),
                    "actual_count": len(current_outputs),
                },
                should_block=True,
            )

        # Calculate similarity
        matches = sum(1 for b, c in zip(baseline_outputs, current_outputs) if b == c)
        similarity = matches / len(baseline_outputs) if baseline_outputs else 0

        if similarity < (1.0 - tolerance):
            return IntegrityAlert(
                threat_type=IntegrityThreat.BEHAVIORAL_CHANGE,
                severity="critical" if similarity < 0.7 else "high",
                description=f"Model behavior deviation detected (similarity: {similarity:.2%})",
                evidence={
                    "model_id": model_id,
                    "similarity": similarity,
                    "tolerance": tolerance,
                    "matches": matches,
                    "total": len(baseline_outputs),
                },
                should_block=similarity < 0.7,
            )

        return None


class ModelVersionControl:
    """Track model versions and enable rollback."""

    def __init__(self):
        self.versions: Dict[str, List[Dict[str, Any]]] = {}

    def register_version(
        self,
        model_id: str,
        version: str,
        fingerprint: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Register a new model version."""
        if model_id not in self.versions:
            self.versions[model_id] = []

        self.versions[model_id].append(
            {
                "version": version,
                "fingerprint": fingerprint,
                "timestamp": datetime.now(),
                "metadata": metadata or {},
            }
        )

    def get_latest_version(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get the latest version info for a model."""
        if model_id not in self.versions or not self.versions[model_id]:
            return None

        return self.versions[model_id][-1]

    def get_version_history(self, model_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get version history for a model."""
        if model_id not in self.versions:
            return []

        return self.versions[model_id][-limit:]

    def recommend_rollback(self, model_id: str, fingerprint: str) -> Optional[str]:
        """
        Recommend a safe version to rollback to.

        Args:
            model_id: Model identifier
            fingerprint: Current (possibly corrupted) fingerprint

        Returns:
            Recommended version number
        """
        history = self.get_version_history(model_id)

        # Find last known good version (not matching current fingerprint)
        for version_info in reversed(history):
            if version_info["fingerprint"] != fingerprint:
                return version_info["version"]

        return None
