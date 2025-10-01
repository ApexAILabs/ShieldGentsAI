"""Context window management and PII detection for agentic AI systems."""

import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class PIIType(Enum):
    """Types of personally identifiable information."""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"
    AWS_KEY = "aws_key"
    GITHUB_TOKEN = "github_token"


@dataclass
class PIIMatch:
    """Detected PII match."""
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float = 1.0


@dataclass
class PIIScanResult:
    """Result of PII scanning."""
    has_pii: bool
    matches: List[PIIMatch] = field(default_factory=list)
    redacted_text: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class PIIDetector:
    """Detects and redacts personally identifiable information."""

    # Regex patterns for common PII
    PATTERNS = {
        PIIType.EMAIL: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        PIIType.PHONE: r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b",
        PIIType.SSN: r"\b(?!000|666|9\d{2})\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b",
        PIIType.CREDIT_CARD: r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        PIIType.IP_ADDRESS: r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        PIIType.API_KEY: r"(?i)\b(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
        PIIType.AWS_KEY: r"\b(AKIA[0-9A-Z]{16})\b",
        PIIType.GITHUB_TOKEN: r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b",
    }

    def __init__(
        self,
        custom_patterns: Optional[Dict[PIIType, str]] = None,
        redaction_char: str = "*",
    ) -> None:
        """
        Initialize PII detector.

        Args:
            custom_patterns: Additional or override patterns
            redaction_char: Character to use for redaction
        """
        self.patterns = self.PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)
        self.redaction_char = redaction_char

    def scan(self, text: str) -> PIIScanResult:
        """
        Scan text for PII.

        Args:
            text: Text to scan

        Returns:
            PIIScanResult with detected PII
        """
        matches = []

        for pii_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, text):
                matches.append(
                    PIIMatch(
                        pii_type=pii_type,
                        value=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    )
                )

        # Sort by position
        matches.sort(key=lambda m: m.start)

        # Redact PII
        redacted = self._redact_text(text, matches)

        return PIIScanResult(
            has_pii=len(matches) > 0,
            matches=matches,
            redacted_text=redacted,
            metadata={"pii_count": len(matches)},
        )

    def _redact_text(self, text: str, matches: List[PIIMatch]) -> str:
        """Redact PII from text."""
        if not matches:
            return text

        result = []
        last_pos = 0

        for match in matches:
            # Add text before match
            result.append(text[last_pos : match.start])

            # Add redaction
            if match.pii_type in [PIIType.EMAIL, PIIType.PHONE]:
                # Keep some context
                redacted = f"[{match.pii_type.value.upper()}_REDACTED]"
            else:
                # Full redaction
                redacted = self.redaction_char * len(match.value)

            result.append(redacted)
            last_pos = match.end

        # Add remaining text
        result.append(text[last_pos:])

        return "".join(result)


class ContextWindowManager:
    """Manages conversation context and token limits."""

    def __init__(
        self,
        max_tokens: int = 4096,
        max_turns: Optional[int] = None,
        reserve_tokens: int = 512,
    ) -> None:
        """
        Initialize context window manager.

        Args:
            max_tokens: Maximum context tokens
            max_turns: Maximum conversation turns to keep
            reserve_tokens: Tokens to reserve for response
        """
        self.max_tokens = max_tokens
        self.max_turns = max_turns
        self.reserve_tokens = reserve_tokens
        self.context: List[Dict[str, str]] = []

    def add_message(self, role: str, content: str) -> None:
        """Add a message to context."""
        self.context.append({"role": role, "content": content})
        self._manage_context()

    def get_context(self) -> List[Dict[str, str]]:
        """Get current context."""
        return self.context.copy()

    def clear(self) -> None:
        """Clear all context."""
        self.context.clear()

    def _manage_context(self) -> None:
        """Manage context window by removing old messages."""
        # Simple turn-based truncation
        if self.max_turns and len(self.context) > self.max_turns * 2:
            # Keep system message if present
            system_msgs = [m for m in self.context if m["role"] == "system"]
            other_msgs = [m for m in self.context if m["role"] != "system"]

            # Keep last N turns
            other_msgs = other_msgs[-(self.max_turns * 2) :]
            self.context = system_msgs + other_msgs

        # TODO: Implement token-based truncation
        # This would require a tokenizer, which varies by model

    def estimate_tokens(self) -> int:
        """
        Rough estimate of token count.

        Returns:
            Estimated token count
        """
        # Very rough estimate: ~4 chars per token
        total_chars = sum(len(m["content"]) for m in self.context)
        return total_chars // 4

    def has_capacity(self) -> bool:
        """Check if context has capacity for more messages."""
        estimated = self.estimate_tokens()
        return estimated + self.reserve_tokens < self.max_tokens


class ConversationMemory:
    """Manages conversation memory with summarization support."""

    def __init__(
        self,
        context_manager: Optional[ContextWindowManager] = None,
        enable_summarization: bool = False,
    ) -> None:
        """
        Initialize conversation memory.

        Args:
            context_manager: Context window manager
            enable_summarization: Enable automatic summarization
        """
        self.context_manager = context_manager or ContextWindowManager()
        self.enable_summarization = enable_summarization
        self.summaries: List[str] = []

    def add_turn(self, user_input: str, assistant_response: str) -> None:
        """Add a conversation turn."""
        if not self.context_manager.has_capacity() and self.enable_summarization:
            self._summarize_and_compress()

        self.context_manager.add_message("user", user_input)
        self.context_manager.add_message("assistant", assistant_response)

    def get_context_for_prompt(self) -> str:
        """Get formatted context for LLM prompt."""
        parts = []

        # Add summaries
        if self.summaries:
            parts.append("Previous conversation summary:")
            parts.extend(self.summaries)
            parts.append("\nRecent conversation:")

        # Add recent context
        for msg in self.context_manager.get_context():
            parts.append(f"{msg['role']}: {msg['content']}")

        return "\n".join(parts)

    def _summarize_and_compress(self) -> None:
        """
        Summarize old context and compress.

        In production, this would use an LLM to summarize.
        This is a placeholder implementation.
        """
        context = self.context_manager.get_context()
        if len(context) > 4:
            # Take first half for summarization
            to_summarize = context[: len(context) // 2]

            # Simple summary (in production, use LLM)
            summary = f"Previous discussion covered {len(to_summarize)} messages."
            self.summaries.append(summary)

            # Keep only recent messages
            self.context_manager.context = context[len(context) // 2 :]


class RateLimiter:
    """Rate limiting for agent operations."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}

    def check_rate_limit(self, key: str) -> bool:
        """
        Check if request is within rate limit.

        Args:
            key: Rate limit key (e.g., user_id, agent_id)

        Returns:
            True if within limit
        """
        import time

        now = time.time()

        if key not in self.requests:
            self.requests[key] = []

        # Remove old requests
        self.requests[key] = [
            t for t in self.requests[key] if now - t < self.window_seconds
        ]

        # Check limit
        if len(self.requests[key]) >= self.max_requests:
            return False

        # Record request
        self.requests[key].append(now)
        return True

    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key."""
        import time

        now = time.time()

        if key not in self.requests:
            return self.max_requests

        # Clean old requests
        self.requests[key] = [
            t for t in self.requests[key] if now - t < self.window_seconds
        ]

        return max(0, self.max_requests - len(self.requests[key]))