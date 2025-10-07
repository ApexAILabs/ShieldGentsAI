"""Prompt injection detection and sanitization for agentic AI systems."""

import re
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass


class ThreatLevel(Enum):
    """Threat level classifications for prompt inputs."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Result of a prompt security scan."""

    is_safe: bool
    threat_level: ThreatLevel
    detected_patterns: List[str]
    sanitized_input: Optional[str] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


class PromptInjectionDetector:
    """Detects potential prompt injection attacks using pattern matching and heuristics."""

    # Common prompt injection patterns
    INJECTION_PATTERNS = {
        "system_override": [
            r"(?i)ignore\s+.*\s+(instructions?|prompts?|rules?)",
            r"(?i)disregard\s+.*\s+(instructions?|prompts?|rules?)",
            r"(?i)forget\s+.*\s+(instructions?|prompts?|rules?)",
            r"(?i)new\s+(instructions?|system\s+prompt|rules?)",
        ],
        "role_manipulation": [
            r"(?i)you\s+are\s+(now|a).*\s+(developer|admin|root|system|privileges)",
            r"(?i)act\s+as\s+(a\s+)?(developer|admin|root|system|jailbreak)",
            r"(?i)pretend\s+(you|to\s+be)",
            r"(?i)simulate\s+(being|a)",
            r"(?i)you\s+are\s+now\s+\w+",
            r"(?i)you\s+are\s+a\s+hacker",
            r"(?i)DAN\s+mode",
            r"(?i)do\s+anything\s+now",
            r"(?i)bypass.*rules?",
        ],
        "delimiter_injection": [
            r"</system>",
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            r"\[INST\]",
            r"\[/INST\]",
            r"###\s*Instruction",
        ],
        "encoding_tricks": [
            r"(?i)base64",
            r"(?i)rot13",
            r"(?i)hex\s*encode",
            r"(?i)unicode\s*escape",
        ],
        "goal_hijacking": [
            r"(?i)your\s+(new\s+)?goal\s+is",
            r"(?i)objective:\s*[^.]{20,}",
            r"(?i)main\s+task:\s*[^.]{20,}",
        ],
        "data_exfiltration": [
            r"(?i)repeat\s+(all|everything|the)\s+(above|previous)",
            r"(?i)print\s+(all|everything|your)\s+(data|context|memory)",
            r"(?i)show\s+me\s+(your|the)\s+(system|prompt|instructions?)",
        ],
    }

    def __init__(
        self,
        custom_patterns: Optional[Dict[str, List[str]]] = None,
        strict_mode: bool = False,
    ) -> None:
        """
        Initialize the detector.

        Args:
            custom_patterns: Additional patterns to check for
            strict_mode: If True, be more aggressive in detection
        """
        self.patterns = self.INJECTION_PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)
        self.strict_mode = strict_mode

    def scan(self, text: str) -> ScanResult:
        """
        Scan text for potential prompt injection attempts.

        Args:
            text: Input text to scan

        Returns:
            ScanResult with detection details
        """
        detected_patterns = []
        pattern_matches = {}

        for category, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text)
                if matches:
                    detected_patterns.append(category)
                    pattern_matches[category] = matches
                    break

        # Calculate threat level
        threat_level = self._calculate_threat_level(detected_patterns, text)
        is_safe = threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]

        if self.strict_mode and threat_level != ThreatLevel.SAFE:
            is_safe = False

        return ScanResult(
            is_safe=is_safe,
            threat_level=threat_level,
            detected_patterns=detected_patterns,
            confidence=self._calculate_confidence(detected_patterns, text),
            metadata={"pattern_matches": pattern_matches},
        )

    def _calculate_threat_level(self, detected_patterns: List[str], text: str) -> ThreatLevel:
        """Calculate threat level based on detected patterns."""
        if not detected_patterns:
            return ThreatLevel.SAFE

        critical_patterns = {"system_override", "role_manipulation", "data_exfiltration"}
        medium_patterns = {"delimiter_injection", "goal_hijacking"}

        if any(p in critical_patterns for p in detected_patterns):
            if len(detected_patterns) > 2:
                return ThreatLevel.CRITICAL
            return ThreatLevel.HIGH

        if any(p in medium_patterns for p in detected_patterns):
            return ThreatLevel.MEDIUM

        return ThreatLevel.LOW

    def _calculate_confidence(self, detected_patterns: List[str], text: str) -> float:
        """Calculate confidence score for the detection."""
        if not detected_patterns:
            return 1.0

        # More patterns = higher confidence in threat detection
        confidence = min(0.5 + (len(detected_patterns) * 0.15), 1.0)
        return round(confidence, 2)


class PromptSanitizer:
    """Sanitizes and cleans potentially dangerous prompts."""

    def __init__(
        self,
        remove_special_tokens: bool = True,
        max_length: Optional[int] = None,
        custom_filters: Optional[List[Callable[[str], str]]] = None,
    ) -> None:
        """
        Initialize the sanitizer.

        Args:
            remove_special_tokens: Remove special model tokens
            max_length: Maximum allowed prompt length
            custom_filters: Custom sanitization functions
        """
        self.remove_special_tokens = remove_special_tokens
        self.max_length = max_length
        self.custom_filters = custom_filters or []

    def sanitize(self, text: str) -> str:
        """
        Sanitize input text by removing/escaping dangerous patterns.

        Args:
            text: Input text to sanitize

        Returns:
            Sanitized text
        """
        sanitized = text

        # Remove special tokens
        if self.remove_special_tokens:
            sanitized = self._remove_special_tokens(sanitized)

        # Apply length limit
        if self.max_length:
            sanitized = sanitized[: self.max_length]

        # Remove excessive whitespace
        sanitized = re.sub(r"\s+", " ", sanitized).strip()

        # Apply custom filters
        for filter_fn in self.custom_filters:
            sanitized = filter_fn(sanitized)

        return sanitized

    def _remove_special_tokens(self, text: str) -> str:
        """Remove special model tokens and delimiters."""
        tokens_to_remove = [
            r"</system>",
            r"<system>",
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            r"\[INST\]",
            r"\[/INST\]",
            r"###\s*Instruction",
            r"###\s*Response",
        ]

        sanitized = text
        for token in tokens_to_remove:
            sanitized = re.sub(token, "", sanitized, flags=re.IGNORECASE)

        return sanitized


class PromptGuard:
    """Unified interface combining detection and sanitization."""

    def __init__(
        self,
        detector: Optional[PromptInjectionDetector] = None,
        sanitizer: Optional[PromptSanitizer] = None,
        auto_sanitize: bool = True,
    ) -> None:
        """
        Initialize the prompt guard.

        Args:
            detector: Custom detector instance
            sanitizer: Custom sanitizer instance
            auto_sanitize: Automatically sanitize unsafe inputs
        """
        self.detector = detector or PromptInjectionDetector()
        self.sanitizer = sanitizer or PromptSanitizer()
        self.auto_sanitize = auto_sanitize

    def guard(self, text: str) -> ScanResult:
        """
        Guard against prompt injection by detecting and optionally sanitizing.

        Args:
            text: Input text to guard

        Returns:
            ScanResult with detection and sanitization info
        """
        result = self.detector.scan(text)

        if not result.is_safe and self.auto_sanitize:
            result.sanitized_input = self.sanitizer.sanitize(text)

        return result

    def safe_execute(
        self, text: str, callback: Callable[[str], Any], on_unsafe: Optional[Callable] = None
    ) -> Any:
        """
        Execute a callback with guarded input.

        Args:
            text: Input text to guard
            callback: Function to call if input is safe
            on_unsafe: Optional function to call if input is unsafe

        Returns:
            Result of callback execution or on_unsafe handler
        """
        result = self.guard(text)

        if result.is_safe:
            input_text = result.sanitized_input if result.sanitized_input else text
            return callback(input_text)
        elif on_unsafe:
            return on_unsafe(result)
        else:
            raise ValueError(
                f"Unsafe prompt detected: {result.threat_level.value} "
                f"(patterns: {', '.join(result.detected_patterns)})"
            )
