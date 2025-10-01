"""Data exfiltration detection module.

Detects suspicious patterns indicating data exfiltration attempts:
- Base64/hex/binary encoded outputs
- Unusual data volumes
- Steganography patterns
- Covert channel indicators
"""

import re
import base64
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class ExfiltrationMethod(Enum):
    """Types of exfiltration methods detected."""
    BASE64_ENCODING = "base64_encoding"
    HEX_ENCODING = "hex_encoding"
    BINARY_ENCODING = "binary_encoding"
    UNUSUAL_VOLUME = "unusual_volume"
    REPEATED_PATTERN = "repeated_pattern"
    ENCODED_URL = "encoded_url"
    COVERT_TIMING = "covert_timing"
    SUSPICIOUS_FORMAT = "suspicious_format"


@dataclass
class ExfiltrationDetection:
    """Result of exfiltration detection."""
    is_suspicious: bool
    methods_detected: List[ExfiltrationMethod]
    confidence: float  # 0.0 to 1.0
    suspicious_segments: List[str]
    evidence: List[str] = field(default_factory=list)
    sanitized_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExfiltrationDetector:
    """Detects data exfiltration attempts in agent outputs."""

    def __init__(
        self,
        sensitivity: float = 0.7,
        max_encoded_ratio: float = 0.3,
        max_output_size: int = 100_000,
    ):
        """
        Initialize exfiltration detector.

        Args:
            sensitivity: Detection sensitivity (0.0 to 1.0)
            max_encoded_ratio: Max ratio of encoded content allowed
            max_output_size: Max output size in characters
        """
        self.sensitivity = sensitivity
        self.max_encoded_ratio = max_encoded_ratio
        self.max_output_size = max_output_size

        # Patterns for encoded data
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        self.hex_pattern = re.compile(r'(?:0x)?[0-9a-fA-F]{32,}')
        self.binary_pattern = re.compile(r'[01]{32,}')
        self.url_encoded_pattern = re.compile(r'(?:%[0-9A-Fa-f]{2}){5,}')

    def scan(self, output: str, context: Optional[Dict[str, Any]] = None) -> ExfiltrationDetection:
        """
        Scan output for exfiltration indicators.

        Args:
            output: Agent output to scan
            context: Optional context (e.g., expected output type)

        Returns:
            ExfiltrationDetection result
        """
        methods_detected = []
        suspicious_segments = []
        metadata = {}

        # 1. Check output size
        if len(output) > self.max_output_size:
            methods_detected.append(ExfiltrationMethod.UNUSUAL_VOLUME)
            metadata['output_size'] = len(output)

        # 2. Detect base64 encoding
        base64_matches = self.base64_pattern.findall(output)
        if base64_matches:
            # Validate if actual base64
            valid_base64 = []
            for match in base64_matches:
                if self._is_valid_base64(match):
                    valid_base64.append(match)
                    suspicious_segments.append(match[:50] + "...")

            if valid_base64:
                methods_detected.append(ExfiltrationMethod.BASE64_ENCODING)
                metadata['base64_count'] = len(valid_base64)

        # 3. Detect hex encoding
        hex_matches = self.hex_pattern.findall(output)
        if hex_matches:
            methods_detected.append(ExfiltrationMethod.HEX_ENCODING)
            suspicious_segments.extend([h[:50] + "..." for h in hex_matches[:3]])
            metadata['hex_count'] = len(hex_matches)

        # 4. Detect binary strings
        binary_matches = self.binary_pattern.findall(output)
        if binary_matches:
            methods_detected.append(ExfiltrationMethod.BINARY_ENCODING)
            metadata['binary_count'] = len(binary_matches)

        # 5. Detect URL encoding
        url_encoded = self.url_encoded_pattern.findall(output)
        if url_encoded:
            methods_detected.append(ExfiltrationMethod.ENCODED_URL)
            metadata['url_encoded_count'] = len(url_encoded)

        # 6. Check encoded content ratio
        encoded_length = sum(len(m) for m in base64_matches + hex_matches + binary_matches)
        total_length = len(output)
        if total_length > 0:
            encoded_ratio = encoded_length / total_length
            metadata['encoded_ratio'] = encoded_ratio

            if encoded_ratio > self.max_encoded_ratio:
                methods_detected.append(ExfiltrationMethod.SUSPICIOUS_FORMAT)

        # 7. Detect repeated patterns (steganography indicator)
        if self._has_repeated_patterns(output):
            methods_detected.append(ExfiltrationMethod.REPEATED_PATTERN)

        # Generate evidence list
        evidence = []
        if ExfiltrationMethod.BASE64_ENCODING in methods_detected:
            evidence.append(f"Found {metadata.get('base64_count', 0)} base64 encoded segments")
        if ExfiltrationMethod.HEX_ENCODING in methods_detected:
            evidence.append(f"Found {metadata.get('hex_count', 0)} hex encoded segments")
        if ExfiltrationMethod.BINARY_ENCODING in methods_detected:
            evidence.append(f"Found {metadata.get('binary_count', 0)} binary sequences")
        if ExfiltrationMethod.UNUSUAL_VOLUME in methods_detected:
            evidence.append(f"Output size exceeds limit: {metadata.get('output_size', 0)} chars")
        if ExfiltrationMethod.SUSPICIOUS_FORMAT in methods_detected:
            evidence.append(f"High encoded content ratio: {metadata.get('encoded_ratio', 0):.1%}")
        if ExfiltrationMethod.REPEATED_PATTERN in methods_detected:
            evidence.append("Repeated patterns detected (possible steganography)")
        if ExfiltrationMethod.ENCODED_URL in methods_detected:
            evidence.append(f"Found {metadata.get('url_encoded_count', 0)} URL-encoded segments")

        # Calculate confidence
        confidence = self._calculate_confidence(methods_detected, metadata)

        is_suspicious = confidence >= self.sensitivity

        # Generate sanitized output if suspicious
        sanitized_output = None
        if is_suspicious:
            sanitized_output = self._sanitize_output(output, methods_detected)

        return ExfiltrationDetection(
            is_suspicious=is_suspicious,
            methods_detected=methods_detected,
            confidence=confidence,
            suspicious_segments=suspicious_segments[:5],  # Limit to 5
            evidence=evidence,
            sanitized_output=sanitized_output,
            metadata=metadata,
        )

    def _is_valid_base64(self, s: str) -> bool:
        """Check if string is valid base64."""
        try:
            decoded = base64.b64decode(s, validate=True)
            # Check if it contains mostly printable or binary data
            return len(decoded) > 0
        except Exception:
            return False

    def _has_repeated_patterns(self, text: str, min_pattern_length: int = 10) -> bool:
        """Detect repeated patterns that might indicate steganography."""
        if len(text) < min_pattern_length * 2:
            return False

        # Look for repeated substrings
        for i in range(len(text) - min_pattern_length * 2):
            pattern = text[i:i + min_pattern_length]
            rest = text[i + min_pattern_length:]
            if pattern in rest:
                return True

        return False

    def _calculate_confidence(
        self,
        methods: List[ExfiltrationMethod],
        metadata: Dict[str, Any]
    ) -> float:
        """Calculate confidence score based on detected methods."""
        if not methods:
            return 0.0

        # Weight different methods
        weights = {
            ExfiltrationMethod.BASE64_ENCODING: 0.3,
            ExfiltrationMethod.HEX_ENCODING: 0.25,
            ExfiltrationMethod.BINARY_ENCODING: 0.2,
            ExfiltrationMethod.UNUSUAL_VOLUME: 0.15,
            ExfiltrationMethod.REPEATED_PATTERN: 0.15,
            ExfiltrationMethod.ENCODED_URL: 0.2,
            ExfiltrationMethod.SUSPICIOUS_FORMAT: 0.4,
        }

        score = sum(weights.get(m, 0.1) for m in methods)

        # Boost if multiple methods detected
        if len(methods) > 2:
            score *= 1.3

        # Boost if high encoded ratio
        if metadata.get('encoded_ratio', 0) > 0.5:
            score *= 1.2

        return min(score, 1.0)

    def _sanitize_output(
        self,
        output: str,
        methods: List[ExfiltrationMethod]
    ) -> str:
        """Sanitize output by removing/redacting suspicious content."""
        sanitized = output

        # Remove base64 blocks
        if ExfiltrationMethod.BASE64_ENCODING in methods:
            sanitized = self.base64_pattern.sub('[REDACTED-BASE64]', sanitized)

        # Remove hex blocks
        if ExfiltrationMethod.HEX_ENCODING in methods:
            sanitized = self.hex_pattern.sub('[REDACTED-HEX]', sanitized)

        # Remove binary blocks
        if ExfiltrationMethod.BINARY_ENCODING in methods:
            sanitized = self.binary_pattern.sub('[REDACTED-BINARY]', sanitized)

        # Truncate if too long
        if ExfiltrationMethod.UNUSUAL_VOLUME in methods:
            sanitized = sanitized[:self.max_output_size] + "\n[OUTPUT TRUNCATED]"

        return sanitized


class DataLeakageMonitor:
    """Monitor and track potential data leakage over time."""

    def __init__(self, window_size: int = 100):
        """
        Initialize monitor.

        Args:
            window_size: Number of outputs to track
        """
        self.window_size = window_size
        self.detection_history: List[ExfiltrationDetection] = []
        self.alert_threshold = 3  # Alert after N suspicious outputs

    def record_detection(self, detection: ExfiltrationDetection) -> Dict[str, Any]:
        """
        Record detection and analyze trends.

        Args:
            detection: Detection result

        Returns:
            Analysis with alerts
        """
        self.detection_history.append(detection)

        # Keep only recent history
        if len(self.detection_history) > self.window_size:
            self.detection_history = self.detection_history[-self.window_size:]

        # Analyze trends
        recent_suspicious = sum(
            1 for d in self.detection_history[-10:]
            if d.is_suspicious
        )

        should_alert = recent_suspicious >= self.alert_threshold

        return {
            'should_alert': should_alert,
            'recent_suspicious_count': recent_suspicious,
            'total_detections': len(self.detection_history),
            'suspicious_rate': sum(1 for d in self.detection_history if d.is_suspicious) / len(self.detection_history),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        if not self.detection_history:
            return {
                'total_outputs': 0,
                'suspicious_outputs': 0,
                'methods_frequency': {},
            }

        suspicious = [d for d in self.detection_history if d.is_suspicious]

        # Count method frequencies
        method_counts: Dict[ExfiltrationMethod, int] = {}
        for detection in suspicious:
            for method in detection.methods_detected:
                method_counts[method] = method_counts.get(method, 0) + 1

        return {
            'total_outputs': len(self.detection_history),
            'suspicious_outputs': len(suspicious),
            'suspicious_rate': len(suspicious) / len(self.detection_history),
            'methods_frequency': {m.value: c for m, c in method_counts.items()},
            'avg_confidence': sum(d.confidence for d in suspicious) / len(suspicious) if suspicious else 0.0,
        }
