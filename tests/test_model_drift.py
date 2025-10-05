"""Tests for model drift and integrity monitoring module."""

import pytest
from shieldgents.controls.model_drift import (
    ModelDriftDetector,
    ModelIntegrityMonitor,
    ModelVersionControl,
    DriftType,
    IntegrityThreat,
)


class TestModelDriftDetector:
    """Test model drift detection."""

    def test_baseline_setup(self):
        """Test setting baseline distributions."""
        detector = ModelDriftDetector()
        baseline_preds = [0.1, 0.2, 0.3, 0.4, 0.5] * 50
        baseline_features = [{"f1": 1.0, "f2": 2.0}] * 50

        detector.set_baseline(baseline_preds, baseline_features)

        assert len(detector.baseline_predictions) == 250
        assert len(detector.baseline_features) == 50

    def test_no_drift_similar_distribution(self):
        """Test that similar distributions don't trigger drift."""
        detector = ModelDriftDetector(psi_threshold=0.2)

        # Set baseline
        baseline = [0.5] * 100 + [0.6] * 100
        detector.set_baseline(baseline, [])

        # Record similar current predictions
        for pred in [0.5] * 50 + [0.6] * 50:
            detector.record_prediction(pred)

        alerts = detector.check_drift()

        # Should have minimal or no drift
        assert all(alert.severity in ["low", "medium"] for alert in alerts) or len(alerts) == 0

    def test_drift_detected_different_distribution(self):
        """Test that different distributions trigger drift."""
        detector = ModelDriftDetector(psi_threshold=0.1)

        # Set baseline
        baseline = [0.2] * 150
        detector.set_baseline(baseline, [])

        # Record very different predictions
        for pred in [0.8] * 150:
            detector.record_prediction(pred)

        alerts = detector.check_drift()

        # Should detect drift
        assert len(alerts) > 0
        assert any(alert.drift_type == DriftType.PREDICTION_DRIFT for alert in alerts)

    def test_performance_degradation(self):
        """Test performance degradation detection."""
        detector = ModelDriftDetector()

        baseline_metrics = {"accuracy": 0.95, "precision": 0.93}
        detector.set_performance_baseline(baseline_metrics)

        # Record degraded performance
        current_metrics = {"accuracy": 0.75, "precision": 0.70}
        alerts = detector.record_performance(current_metrics)

        assert len(alerts) > 0
        assert all(alert.drift_type == DriftType.PERFORMANCE_DEGRADATION for alert in alerts)
        assert any(alert.should_retrain for alert in alerts)

    def test_no_degradation_improved_performance(self):
        """Test that improved performance doesn't trigger alerts."""
        detector = ModelDriftDetector()

        baseline_metrics = {"accuracy": 0.85}
        detector.set_performance_baseline(baseline_metrics)

        # Record improved performance
        current_metrics = {"accuracy": 0.95}
        alerts = detector.record_performance(current_metrics)

        # No degradation alerts for improved performance
        degradation_alerts = [a for a in alerts if a.drift_type == DriftType.PERFORMANCE_DEGRADATION]
        assert len(degradation_alerts) == 0

    def test_psi_calculation(self):
        """Test PSI calculation."""
        detector = ModelDriftDetector()

        baseline = [0.1, 0.2, 0.3, 0.4, 0.5] * 40
        current = [0.1, 0.2, 0.3, 0.4, 0.5] * 40

        psi = detector._calculate_psi(baseline, current)

        # Identical distributions should have PSI near 0
        assert psi < 0.05


class TestModelIntegrityMonitor:
    """Test model integrity monitoring."""

    def test_fingerprint_creation(self):
        """Test creating model fingerprint."""
        monitor = ModelIntegrityMonitor()

        model_data = b"fake_model_weights_12345"
        fingerprint = monitor.create_fingerprint("model-1", model_data)

        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64  # SHA256 hex digest
        assert "model-1" in monitor.model_fingerprints

    def test_fingerprint_verification_success(self):
        """Test successful fingerprint verification."""
        monitor = ModelIntegrityMonitor()

        model_data = b"fake_model_weights_12345"
        monitor.create_fingerprint("model-1", model_data)

        alert = monitor.verify_fingerprint("model-1", model_data)

        assert alert is None  # No alert means verification passed

    def test_fingerprint_verification_failure(self):
        """Test fingerprint verification detects tampering."""
        monitor = ModelIntegrityMonitor()

        original_data = b"fake_model_weights_12345"
        monitor.create_fingerprint("model-1", original_data)

        # Try to verify with different data
        tampered_data = b"fake_model_weights_TAMPERED"
        alert = monitor.verify_fingerprint("model-1", tampered_data)

        assert alert is not None
        assert alert.threat_type == IntegrityThreat.MODEL_TAMPERING
        assert alert.should_block is True

    def test_behavior_baseline(self):
        """Test setting behavior baseline."""
        monitor = ModelIntegrityMonitor()

        test_inputs = ["input1", "input2", "input3"]
        expected_outputs = ["output1", "output2", "output3"]

        monitor.set_behavior_baseline("model-1", test_inputs, expected_outputs)

        assert "model-1" in monitor.behavior_baselines
        assert len(monitor.behavior_baselines["model-1"]) == 3

    def test_behavior_consistency_success(self):
        """Test behavior consistency check passes for consistent behavior."""
        monitor = ModelIntegrityMonitor()

        test_inputs = ["input1", "input2", "input3"]
        expected_outputs = ["output1", "output2", "output3"]

        monitor.set_behavior_baseline("model-1", test_inputs, expected_outputs)

        alert = monitor.check_behavior_consistency(
            "model-1",
            test_inputs,
            expected_outputs
        )

        assert alert is None  # No alert means behavior is consistent

    def test_behavior_consistency_failure(self):
        """Test behavior consistency check detects changes."""
        monitor = ModelIntegrityMonitor()

        test_inputs = ["input1", "input2", "input3"]
        expected_outputs = ["output1", "output2", "output3"]

        monitor.set_behavior_baseline("model-1", test_inputs, expected_outputs)

        # Different outputs
        current_outputs = ["different1", "different2", "different3"]
        alert = monitor.check_behavior_consistency(
            "model-1",
            test_inputs,
            current_outputs,
            tolerance=0.1
        )

        assert alert is not None
        assert alert.threat_type == IntegrityThreat.BEHAVIORAL_CHANGE
        assert alert.should_block is True


class TestModelVersionControl:
    """Test model version control."""

    def test_register_version(self):
        """Test registering a model version."""
        vcs = ModelVersionControl()

        vcs.register_version(
            "model-1",
            "v1.0.0",
            "abc123fingerprint",
            metadata={"accuracy": 0.95}
        )

        assert "model-1" in vcs.versions
        assert len(vcs.versions["model-1"]) == 1

    def test_get_latest_version(self):
        """Test getting latest version."""
        vcs = ModelVersionControl()

        vcs.register_version("model-1", "v1.0.0", "fp1")
        vcs.register_version("model-1", "v1.1.0", "fp2")
        vcs.register_version("model-1", "v1.2.0", "fp3")

        latest = vcs.get_latest_version("model-1")

        assert latest is not None
        assert latest["version"] == "v1.2.0"
        assert latest["fingerprint"] == "fp3"

    def test_version_history(self):
        """Test getting version history."""
        vcs = ModelVersionControl()

        for i in range(5):
            vcs.register_version("model-1", f"v1.{i}.0", f"fp{i}")

        history = vcs.get_version_history("model-1", limit=3)

        assert len(history) == 3
        assert history[-1]["version"] == "v1.4.0"

    def test_recommend_rollback(self):
        """Test rollback recommendation."""
        vcs = ModelVersionControl()

        vcs.register_version("model-1", "v1.0.0", "fp1")
        vcs.register_version("model-1", "v1.1.0", "fp2")
        vcs.register_version("model-1", "v1.2.0", "fp3_corrupted")

        # Current model has corrupted fingerprint
        recommended_version = vcs.recommend_rollback("model-1", "fp3_corrupted")

        # Should recommend v1.1.0 (last known good)
        assert recommended_version == "v1.1.0"

    def test_no_rollback_candidate(self):
        """Test rollback when no good version exists."""
        vcs = ModelVersionControl()

        vcs.register_version("model-1", "v1.0.0", "fp1")

        # No rollback candidate if all versions have same fingerprint
        recommended_version = vcs.recommend_rollback("model-1", "fp1")

        assert recommended_version is None
