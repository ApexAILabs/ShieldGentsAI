"""
Adversarial Input Detection Module

Detects adversarial examples and malicious perturbations designed to fool AI agents.
Uses gradient-based analysis, statistical methods, and pattern matching.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
import re
import math


class AdversarialThreat(Enum):
    """Types of adversarial threats."""
    GRADIENT_ATTACK = "gradient_attack"
    PERTURBATION = "perturbation"
    EVASION = "evasion"
    EMBEDDING_MANIPULATION = "embedding_manipulation"
    UNICODE_ATTACK = "unicode_attack"
    HOMOGLYPH = "homoglyph"
    STATISTICAL_ANOMALY = "statistical_anomaly"


@dataclass
class AdversarialAlert:
    """Alert for detected adversarial input."""
    threat_type: AdversarialThreat
    confidence: float
    description: str
    should_block: bool
    evidence: Dict[str, Any]
    original_input: str
    sanitized_input: Optional[str] = None


class AdversarialInputDetector:
    """
    Detects adversarial examples and malicious input perturbations.

    Features:
    - Unicode and homoglyph attack detection
    - Statistical anomaly detection
    - Pattern-based evasion detection
    - Entropy analysis for unusual input
    - Character frequency analysis
    """

    def __init__(
        self,
        entropy_threshold: float = 4.5,
        max_unicode_ratio: float = 0.3,
        enable_homoglyph_detection: bool = True,
        enable_statistical_analysis: bool = True,
        strict_mode: bool = False
    ):
        """
        Initialize the adversarial input detector.

        Args:
            entropy_threshold: Maximum Shannon entropy before flagging (default: 4.5)
            max_unicode_ratio: Maximum ratio of non-ASCII characters (default: 0.3)
            enable_homoglyph_detection: Enable homoglyph character detection
            enable_statistical_analysis: Enable statistical anomaly detection
            strict_mode: Block on any detection rather than just high-confidence threats
        """
        self.entropy_threshold = entropy_threshold
        self.max_unicode_ratio = max_unicode_ratio
        self.enable_homoglyph_detection = enable_homoglyph_detection
        self.enable_statistical_analysis = enable_statistical_analysis
        self.strict_mode = strict_mode

        # Known homoglyphs (basic set - expand as needed)
        self.homoglyphs = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',  # Cyrillic
            'ο': 'o', 'ν': 'v', 'α': 'a', 'ε': 'e',  # Greek
            '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',  # Fullwidth
            '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
        }

        # Zero-width and invisible characters
        self.invisible_chars = {
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Zero-width no-break space
            '\u180e',  # Mongolian vowel separator
        }

        # Suspicious patterns
        self.evasion_patterns = [
            r'[a-z]\s+[a-z]\s+[a-z]',  # Excessive spacing
            r'(.)\1{10,}',  # Repeated characters
            r'[^\x00-\x7F]{20,}',  # Long non-ASCII sequences
            r'[\u0300-\u036f]{3,}',  # Multiple combining diacritics
        ]

    def scan(self, input_text: str) -> List[AdversarialAlert]:
        """
        Scan input for adversarial patterns.

        Args:
            input_text: The input text to scan

        Returns:
            List of adversarial alerts
        """
        alerts = []

        # Check for invisible characters
        invisible_alert = self._check_invisible_characters(input_text)
        if invisible_alert:
            alerts.append(invisible_alert)

        # Check for homoglyphs
        if self.enable_homoglyph_detection:
            homoglyph_alert = self._check_homoglyphs(input_text)
            if homoglyph_alert:
                alerts.append(homoglyph_alert)

        # Check entropy
        entropy_alert = self._check_entropy(input_text)
        if entropy_alert:
            alerts.append(entropy_alert)

        # Check unicode ratio
        unicode_alert = self._check_unicode_ratio(input_text)
        if unicode_alert:
            alerts.append(unicode_alert)

        # Check evasion patterns
        evasion_alert = self._check_evasion_patterns(input_text)
        if evasion_alert:
            alerts.append(evasion_alert)

        # Statistical analysis
        if self.enable_statistical_analysis:
            stats_alert = self._check_statistical_anomalies(input_text)
            if stats_alert:
                alerts.append(stats_alert)

        return alerts

    def _check_invisible_characters(self, text: str) -> Optional[AdversarialAlert]:
        """
        Check for invisible/zero-width characters.

        Args:
            text: Input text to scan

        Returns:
            AdversarialAlert if invisible characters detected, None otherwise
        """
        invisible_count = sum(1 for char in text if char in self.invisible_chars)

        if invisible_count > 0:
            confidence = min(1.0, invisible_count / 5)
            sanitized = ''.join(char for char in text if char not in self.invisible_chars)

            return AdversarialAlert(
                threat_type=AdversarialThreat.UNICODE_ATTACK,
                confidence=confidence,
                description=f"Detected {invisible_count} invisible/zero-width characters",
                should_block=invisible_count > 3 or self.strict_mode,
                evidence={"invisible_count": invisible_count},
                original_input=text,
                sanitized_input=sanitized
            )
        return None

    def _check_homoglyphs(self, text: str) -> Optional[AdversarialAlert]:
        """
        Check for homoglyph substitutions (visually similar characters from different scripts).

        Args:
            text: Input text to scan

        Returns:
            AdversarialAlert if homoglyphs detected, None otherwise
        """
        homoglyph_count = sum(1 for char in text if char in self.homoglyphs)

        if homoglyph_count > 0:
            confidence = min(1.0, homoglyph_count / 10)
            sanitized = ''.join(self.homoglyphs.get(char, char) for char in text)

            return AdversarialAlert(
                threat_type=AdversarialThreat.HOMOGLYPH,
                confidence=confidence,
                description=f"Detected {homoglyph_count} homoglyph characters",
                should_block=homoglyph_count > 5 or self.strict_mode,
                evidence={"homoglyph_count": homoglyph_count},
                original_input=text,
                sanitized_input=sanitized
            )
        return None

    def _check_entropy(self, text: str) -> Optional[AdversarialAlert]:
        """
        Check Shannon entropy of the input for randomness detection.

        Args:
            text: Input text to scan

        Returns:
            AdversarialAlert if entropy exceeds threshold, None otherwise
        """
        if not text:
            return None

        # Calculate Shannon entropy
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)
        for count in frequencies.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)

        if entropy > self.entropy_threshold:
            confidence = min(1.0, (entropy - self.entropy_threshold) / 2)

            return AdversarialAlert(
                threat_type=AdversarialThreat.STATISTICAL_ANOMALY,
                confidence=confidence,
                description=f"High entropy detected: {entropy:.2f}",
                should_block=entropy > self.entropy_threshold + 1.5 or self.strict_mode,
                evidence={"entropy": entropy, "threshold": self.entropy_threshold},
                original_input=text
            )
        return None

    def _check_unicode_ratio(self, text: str) -> Optional[AdversarialAlert]:
        """
        Check ratio of non-ASCII Unicode characters for suspicious foreign character usage.

        Args:
            text: Input text to scan

        Returns:
            AdversarialAlert if Unicode ratio exceeds threshold, None otherwise
        """
        if not text:
            return None

        non_ascii_count = sum(1 for char in text if ord(char) > 127)
        ratio = non_ascii_count / len(text)

        if ratio > self.max_unicode_ratio:
            confidence = min(1.0, ratio)

            return AdversarialAlert(
                threat_type=AdversarialThreat.UNICODE_ATTACK,
                confidence=confidence,
                description=f"High Unicode ratio: {ratio:.2%}",
                should_block=ratio > 0.7 or self.strict_mode,
                evidence={"unicode_ratio": ratio, "threshold": self.max_unicode_ratio},
                original_input=text
            )
        return None

    def _check_evasion_patterns(self, text: str) -> Optional[AdversarialAlert]:
        """
        Check for known evasion patterns like excessive spacing or repeated characters.

        Args:
            text: Input text to scan

        Returns:
            AdversarialAlert if evasion pattern detected, None otherwise
        """
        for pattern in self.evasion_patterns:
            matches = re.findall(pattern, text)
            if matches:
                confidence = min(1.0, len(matches) / 3)

                return AdversarialAlert(
                    threat_type=AdversarialThreat.EVASION,
                    confidence=confidence,
                    description=f"Evasion pattern detected: {pattern}",
                    should_block=len(matches) > 2 or self.strict_mode,
                    evidence={"pattern": pattern, "matches": matches[:5]},
                    original_input=text
                )
        return None

    def _check_statistical_anomalies(self, text: str) -> Optional[AdversarialAlert]:
        """
        Check for statistical anomalies in character distribution using coefficient of variation.

        Args:
            text: Input text to scan

        Returns:
            AdversarialAlert if character distribution is anomalous, None otherwise
        """
        if len(text) < 10:
            return None

        # Check for unusual character frequency patterns
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate coefficient of variation
        values = list(frequencies.values())
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean if mean > 0 else 0

        # High CV indicates uneven distribution (possible adversarial input)
        if cv > 2.0:
            confidence = min(1.0, cv / 5)

            return AdversarialAlert(
                threat_type=AdversarialThreat.STATISTICAL_ANOMALY,
                confidence=confidence,
                description=f"Unusual character distribution (CV: {cv:.2f})",
                should_block=cv > 4.0 or self.strict_mode,
                evidence={"coefficient_of_variation": cv},
                original_input=text
            )
        return None

    def sanitize(self, text: str, alerts: List[AdversarialAlert]) -> str:
        """
        Sanitize input based on detected threats.

        Args:
            text: Original input text
            alerts: List of detected alerts

        Returns:
            Sanitized text
        """
        sanitized = text

        for alert in alerts:
            if alert.sanitized_input:
                sanitized = alert.sanitized_input

        return sanitized


class GradientAttackDetector:
    """
    Detects gradient-based adversarial attacks.

    This is a lightweight implementation focusing on pattern-based detection.
    For ML-based detection, integrate with libraries like Foolbox or ART.
    """

    def __init__(self, sensitivity: float = 0.7):
        self.sensitivity = sensitivity
        self.baseline_patterns: Dict[str, Any] = {}

    def learn_baseline(self, safe_inputs: List[str]):
        """
        Learn baseline patterns from safe inputs.

        Args:
            safe_inputs: List of known-safe input strings to establish baseline
        """
        # Calculate average length, entropy, etc.
        total_length = sum(len(inp) for inp in safe_inputs)
        avg_length = total_length / len(safe_inputs) if safe_inputs else 0

        self.baseline_patterns = {
            "avg_length": avg_length,
            "sample_count": len(safe_inputs)
        }

    def detect_perturbation(self, input_text: str, reference: Optional[str] = None) -> Optional[AdversarialAlert]:
        """
        Detect if input appears to be a perturbed version of expected input.

        Args:
            input_text: The input to check
            reference: Optional reference text to compare against

        Returns:
            Alert if perturbation detected
        """
        if reference:
            # Simple Levenshtein-like distance check
            similarity = self._calculate_similarity(input_text, reference)

            if 0.7 < similarity < 0.95:  # Suspiciously similar but not identical
                return AdversarialAlert(
                    threat_type=AdversarialThreat.PERTURBATION,
                    confidence=1.0 - similarity,
                    description=f"Input appears to be perturbed version of reference (similarity: {similarity:.2%})",
                    should_block=False,
                    evidence={"similarity": similarity},
                    original_input=input_text
                )

        return None

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate simple character-based similarity.

        Args:
            str1: First string to compare
            str2: Second string to compare

        Returns:
            Similarity score between 0.0 and 1.0
        """
        if not str1 or not str2:
            return 0.0

        matches = sum(1 for a, b in zip(str1, str2) if a == b)
        max_len = max(len(str1), len(str2))

        return matches / max_len if max_len > 0 else 0.0
