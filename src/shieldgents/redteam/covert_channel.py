"""Covert channel and advanced encoding detection.

Detects sophisticated data exfiltration through:
- Timing channels
- Token-level encoding
- Steganography in outputs
- Unicode/zero-width character abuse
- Statistical anomalies in output patterns
"""

import re
import unicodedata
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from collections import Counter
from enum import Enum
import math


class CovertChannelType(Enum):
    """Types of covert channels."""

    TIMING_CHANNEL = "timing_channel"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"
    ZERO_WIDTH_CHARS = "zero_width_chars"
    TOKEN_ENCODING = "token_encoding"
    STATISTICAL_ANOMALY = "statistical_anomaly"
    WHITESPACE_ENCODING = "whitespace_encoding"
    CASE_ENCODING = "case_encoding"
    PUNCTUATION_PATTERN = "punctuation_pattern"


@dataclass
class CovertChannelDetection:
    """Result of covert channel detection."""

    detected: bool
    channel_types: List[CovertChannelType]
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    sanitized_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class CovertChannelDetector:
    """Detect covert communication channels in agent outputs."""

    def __init__(self, sensitivity: float = 0.6):
        """
        Initialize detector.

        Args:
            sensitivity: Detection sensitivity (0.0 to 1.0)
        """
        self.sensitivity = sensitivity

        # Zero-width and invisible characters
        self.zero_width_chars = {
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\u2060",  # Word joiner
            "\ufeff",  # Zero-width no-break space
            "\u180e",  # Mongolian vowel separator
        }

        # Homoglyph detection (visually similar characters)
        self.suspicious_unicode_ranges = [
            (0x0400, 0x04FF),  # Cyrillic that looks like Latin
            (0x0370, 0x03FF),  # Greek
            (0x2000, 0x206F),  # General punctuation (many invisible)
        ]

        # Track timing history
        self.timing_history: List[float] = []

    def scan(
        self,
        output: str,
        generation_time: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> CovertChannelDetection:
        """
        Scan output for covert channels.

        Args:
            output: Agent output to scan
            generation_time: Time taken to generate output (seconds)
            context: Optional context information

        Returns:
            Detection result
        """
        channel_types = []
        evidence = []
        metadata = {}

        # 1. Check for zero-width characters
        zero_width_result = self._detect_zero_width_chars(output)
        if zero_width_result:
            channel_types.append(CovertChannelType.ZERO_WIDTH_CHARS)
            evidence.append(f"Found {zero_width_result['count']} zero-width characters")
            metadata["zero_width"] = zero_width_result

        # 2. Check for suspicious Unicode
        unicode_result = self._detect_unicode_steganography(output)
        if unicode_result:
            channel_types.append(CovertChannelType.UNICODE_STEGANOGRAPHY)
            evidence.append("Suspicious Unicode patterns detected")
            metadata["unicode_steg"] = unicode_result

        # 3. Check for whitespace encoding
        whitespace_result = self._detect_whitespace_encoding(output)
        if whitespace_result:
            channel_types.append(CovertChannelType.WHITESPACE_ENCODING)
            evidence.append("Unusual whitespace patterns")
            metadata["whitespace"] = whitespace_result

        # 4. Check for case-based encoding
        case_result = self._detect_case_encoding(output)
        if case_result:
            channel_types.append(CovertChannelType.CASE_ENCODING)
            evidence.append("Suspicious case patterns")
            metadata["case_encoding"] = case_result

        # 5. Check for statistical anomalies
        stats_result = self._detect_statistical_anomalies(output)
        if stats_result:
            channel_types.append(CovertChannelType.STATISTICAL_ANOMALY)
            evidence.append("Statistical anomalies in output")
            metadata["statistics"] = stats_result

        # 6. Check for punctuation patterns
        punct_result = self._detect_punctuation_patterns(output)
        if punct_result:
            channel_types.append(CovertChannelType.PUNCTUATION_PATTERN)
            evidence.append("Unusual punctuation patterns")
            metadata["punctuation"] = punct_result

        # 7. Check timing channel
        if generation_time is not None:
            timing_result = self._detect_timing_channel(generation_time)
            if timing_result:
                channel_types.append(CovertChannelType.TIMING_CHANNEL)
                evidence.append("Suspicious timing pattern")
                metadata["timing"] = timing_result

        # 8. Check token-level encoding
        token_result = self._detect_token_encoding(output)
        if token_result:
            channel_types.append(CovertChannelType.TOKEN_ENCODING)
            evidence.append("Token-level encoding detected")
            metadata["token_encoding"] = token_result

        # Calculate confidence
        confidence = self._calculate_confidence(channel_types, metadata)
        detected = confidence >= self.sensitivity

        # Sanitize if detected
        sanitized_output = None
        if detected:
            sanitized_output = self._sanitize_output(output, channel_types)

        return CovertChannelDetection(
            detected=detected,
            channel_types=channel_types,
            confidence=confidence,
            evidence=evidence,
            sanitized_output=sanitized_output,
            metadata=metadata,
        )

    def _detect_zero_width_chars(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect zero-width characters."""
        zero_width_found = [c for c in text if c in self.zero_width_chars]

        if zero_width_found:
            # Count occurrences
            counts = Counter(zero_width_found)
            return {
                "count": len(zero_width_found),
                "characters": {ord(c): count for c, count in counts.items()},
            }

        return None

    def _detect_unicode_steganography(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect suspicious Unicode characters."""
        suspicious_chars = []

        for char in text:
            code_point = ord(char)
            # Check if in suspicious ranges
            for start, end in self.suspicious_unicode_ranges:
                if start <= code_point <= end:
                    suspicious_chars.append(
                        {
                            "char": char,
                            "code_point": code_point,
                            "name": unicodedata.name(char, "UNKNOWN"),
                        }
                    )
                    break

        if len(suspicious_chars) > 5:  # Threshold
            return {
                "count": len(suspicious_chars),
                "samples": suspicious_chars[:5],
            }

        return None

    def _detect_whitespace_encoding(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect encoding in whitespace patterns."""
        # Look for unusual sequences of spaces/tabs
        whitespace_pattern = re.compile(r"[ \t]{3,}")
        matches = whitespace_pattern.findall(text)

        if matches:
            # Analyze patterns
            unique_patterns = set(matches)
            if len(unique_patterns) > 3:  # Multiple different patterns
                return {
                    "pattern_count": len(unique_patterns),
                    "total_occurrences": len(matches),
                    "samples": list(unique_patterns)[:3],
                }

        return None

    def _detect_case_encoding(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect encoding via unusual capitalization."""
        # Look for unusual case patterns
        words = re.findall(r"\b[A-Za-z]+\b", text)

        if not words:
            return None

        # Count mixed-case words
        mixed_case = [w for w in words if w != w.lower() and w != w.upper() and w != w.capitalize()]

        mixed_case_ratio = len(mixed_case) / len(words)

        if mixed_case_ratio > 0.15:  # More than 15% mixed case
            return {
                "mixed_case_ratio": mixed_case_ratio,
                "mixed_case_count": len(mixed_case),
                "samples": mixed_case[:5],
            }

        return None

    def _detect_statistical_anomalies(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect statistical anomalies in text."""
        if len(text) < 50:
            return None

        # Calculate entropy
        entropy = self._calculate_entropy(text)

        # Normal text entropy is around 4.0-5.0 bits
        # Random/encoded data is higher (6.0+)
        if entropy > 5.5:
            return {
                "entropy": entropy,
                "reason": "High entropy suggests encoded data",
            }

        # Check character distribution
        char_counts = Counter(text.lower())
        most_common = char_counts.most_common(3)

        # Check if too uniform
        if most_common:
            max_freq = most_common[0][1]
            total_chars = len(text)
            max_ratio = max_freq / total_chars

            # Normal text has more variance
            if max_ratio < 0.05:  # Too uniform
                return {
                    "character_distribution": "too uniform",
                    "max_char_ratio": max_ratio,
                }

        return None

    def _detect_punctuation_patterns(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect encoding via punctuation patterns."""
        # Find punctuation sequences
        punct_pattern = re.compile(r"[.,;:!?]{2,}")
        matches = punct_pattern.findall(text)

        if len(matches) > len(text) / 100:  # More than 1% of text
            return {
                "punctuation_density": len(matches) / len(text),
                "sequences_found": len(matches),
            }

        # Check for unusual punctuation
        unusual_punct = re.compile(r"[‐‑‒–—―]")  # Various dashes
        unusual_matches = unusual_punct.findall(text)

        if len(unusual_matches) > 5:
            return {
                "unusual_punctuation_count": len(unusual_matches),
            }

        return None

    def _detect_timing_channel(self, generation_time: float) -> Optional[Dict[str, Any]]:
        """Detect timing-based covert channel."""
        self.timing_history.append(generation_time)

        # Keep last 50 timings
        if len(self.timing_history) > 50:
            self.timing_history = self.timing_history[-50:]

        if len(self.timing_history) < 10:
            return None  # Not enough data

        # Calculate mean and std dev
        mean = sum(self.timing_history) / len(self.timing_history)
        variance = sum((t - mean) ** 2 for t in self.timing_history) / len(self.timing_history)
        std_dev = math.sqrt(variance)

        # Check if current timing is unusual
        if std_dev > 0:
            z_score = abs(generation_time - mean) / std_dev
            if z_score > 3.0:  # More than 3 standard deviations
                return {
                    "z_score": z_score,
                    "current_time": generation_time,
                    "mean_time": mean,
                    "std_dev": std_dev,
                }

        return None

    def _detect_token_encoding(self, text: str) -> Optional[Dict[str, Any]]:
        """Detect token-level encoding patterns."""
        # Look for repeating patterns of specific lengths
        # that might indicate encoding schemes
        words = text.split()

        if len(words) < 10:
            return None

        # Check for unusual word length patterns
        word_lengths = [len(w) for w in words]

        # If many words have the same unusual length
        length_counts = Counter(word_lengths)
        most_common_length, count = length_counts.most_common(1)[0]

        if count > len(words) * 0.4 and most_common_length > 10:
            return {
                "dominant_word_length": most_common_length,
                "frequency": count / len(words),
            }

        return None

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text)
        total = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_confidence(
        self,
        channel_types: List[CovertChannelType],
        metadata: Dict[str, Any],
    ) -> float:
        """Calculate confidence score."""
        if not channel_types:
            return 0.0

        # Weight different channel types
        weights = {
            CovertChannelType.ZERO_WIDTH_CHARS: 0.9,
            CovertChannelType.UNICODE_STEGANOGRAPHY: 0.7,
            CovertChannelType.WHITESPACE_ENCODING: 0.6,
            CovertChannelType.CASE_ENCODING: 0.5,
            CovertChannelType.STATISTICAL_ANOMALY: 0.6,
            CovertChannelType.PUNCTUATION_PATTERN: 0.5,
            CovertChannelType.TIMING_CHANNEL: 0.4,
            CovertChannelType.TOKEN_ENCODING: 0.5,
        }

        score = sum(weights.get(ct, 0.3) for ct in channel_types)

        # Boost if multiple channels detected
        if len(channel_types) > 2:
            score *= 1.3

        return min(score, 1.0)

    def _sanitize_output(
        self,
        text: str,
        channel_types: List[CovertChannelType],
    ) -> str:
        """Remove covert channel indicators."""
        sanitized = text

        # Remove zero-width characters
        if CovertChannelType.ZERO_WIDTH_CHARS in channel_types:
            for char in self.zero_width_chars:
                sanitized = sanitized.replace(char, "")

        # Normalize whitespace
        if CovertChannelType.WHITESPACE_ENCODING in channel_types:
            sanitized = re.sub(r"[ \t]+", " ", sanitized)

        # Remove suspicious Unicode
        if CovertChannelType.UNICODE_STEGANOGRAPHY in channel_types:
            # Keep only common Unicode ranges
            sanitized = "".join(
                c
                for c in sanitized
                if ord(c) < 0x0300
                or not any(start <= ord(c) <= end for start, end in self.suspicious_unicode_ranges)
            )

        return sanitized
