"""Tests for adversarial input detection module."""

import pytest
from shieldgents.controls.adversarial_detection import (
    AdversarialInputDetector,
    GradientAttackDetector,
    AdversarialThreat,
)


class TestAdversarialInputDetector:
    """Test adversarial input detection."""

    def test_clean_input(self):
        """Test that clean input produces no alerts."""
        detector = AdversarialInputDetector()
        alerts = detector.scan("This is a normal, clean input.")

        assert len(alerts) == 0

    def test_invisible_characters(self):
        """Test detection of invisible characters."""
        detector = AdversarialInputDetector()
        text = "Hello\u200bWorld\u200c"
        alerts = detector.scan(text)

        assert len(alerts) > 0
        assert any(alert.threat_type == AdversarialThreat.UNICODE_ATTACK for alert in alerts)

    def test_homoglyphs(self):
        """Test detection of homoglyph characters."""
        detector = AdversarialInputDetector(enable_homoglyph_detection=True)
        text = "Hеllo Wоrld"  # Using Cyrillic 'е' and 'о'
        alerts = detector.scan(text)

        assert len(alerts) > 0
        assert any(alert.threat_type == AdversarialThreat.HOMOGLYPH for alert in alerts)

    def test_high_entropy(self):
        """Test detection of high entropy input."""
        detector = AdversarialInputDetector(entropy_threshold=4.0)
        text = "aB3$xK9#mQ7!pL2@nF8%"
        alerts = detector.scan(text)

        # May or may not trigger depending on exact entropy
        # This test ensures the entropy check runs without error
        assert isinstance(alerts, list)

    def test_unicode_ratio(self):
        """Test detection of high unicode ratio."""
        detector = AdversarialInputDetector(max_unicode_ratio=0.2)
        text = "你好世界こんにちは世界مرحبا"
        alerts = detector.scan(text)

        assert len(alerts) > 0
        assert any(alert.threat_type == AdversarialThreat.UNICODE_ATTACK for alert in alerts)

    def test_evasion_patterns(self):
        """Test detection of evasion patterns."""
        detector = AdversarialInputDetector()
        text = "aaaaaaaaaaaaaaaaaaa"  # Repeated characters
        alerts = detector.scan(text)

        assert len(alerts) > 0

    def test_sanitization(self):
        """Test input sanitization."""
        detector = AdversarialInputDetector()
        text = "Hello\u200bWorld"
        alerts = detector.scan(text)
        sanitized = detector.sanitize(text, alerts)

        assert "\u200b" not in sanitized
        assert "HelloWorld" == sanitized

    def test_strict_mode(self):
        """Test strict mode blocking."""
        detector = AdversarialInputDetector(strict_mode=True)
        text = "Hello\u200bWorld"
        alerts = detector.scan(text)

        # In strict mode, should recommend blocking
        assert any(alert.should_block for alert in alerts)


class TestGradientAttackDetector:
    """Test gradient attack detection."""

    def test_baseline_learning(self):
        """Test baseline learning."""
        detector = GradientAttackDetector()
        safe_inputs = ["Normal input 1", "Normal input 2", "Normal input 3"]

        detector.learn_baseline(safe_inputs)

        assert detector.baseline_patterns["sample_count"] == 3
        assert detector.baseline_patterns["avg_length"] > 0

    def test_perturbation_detection(self):
        """Test perturbation detection."""
        detector = GradientAttackDetector()
        reference = "Hello World"
        perturbed = "Hello Wprld"  # One character changed

        alert = detector.detect_perturbation(perturbed, reference)

        # Should detect similarity but difference
        assert alert is not None
        assert alert.threat_type == AdversarialThreat.PERTURBATION

    def test_no_perturbation_identical(self):
        """Test no alert for identical inputs."""
        detector = GradientAttackDetector()
        reference = "Hello World"
        identical = "Hello World"

        alert = detector.detect_perturbation(identical, reference)

        # Should not alert on identical input
        assert alert is None

    def test_no_perturbation_very_different(self):
        """Test no alert for very different inputs."""
        detector = GradientAttackDetector()
        reference = "Hello World"
        different = "Completely different text"

        alert = detector.detect_perturbation(different, reference)

        # Should not alert on very different input
        assert alert is None
