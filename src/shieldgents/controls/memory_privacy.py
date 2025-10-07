"""Memory privacy and long-term context management.

**How it works:**
Manages conversation memory to prevent privacy leaks through cached contexts,
enforces data retention policies, and provides consent-based memory access.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MemoryEntry:
    """Entry in agent memory."""
    content: str
    timestamp: float
    user_id: Optional[str] = None
    sensitive: bool = False
    consent_given: bool = False
    ttl: Optional[float] = None  # Time-to-live in seconds


class MemoryPrivacyManager:
    """Manages memory with privacy controls."""

    def __init__(
        self,
        default_ttl: float = 86400.0,  # 24 hours
        require_consent: bool = True,
    ):
        self.default_ttl = default_ttl
        self.require_consent = require_consent
        self.memories: Dict[str, List[MemoryEntry]] = {}

    def store_memory(
        self,
        session_id: str,
        content: str,
        user_id: Optional[str] = None,
        sensitive: bool = False,
        consent: bool = False,
    ) -> None:
        """Store memory with privacy controls."""
        import time

        if self.require_consent and sensitive and not consent:
            return  # Don't store without consent

        entry = MemoryEntry(
            content=content,
            timestamp=time.time(),
            user_id=user_id,
            sensitive=sensitive,
            consent_given=consent,
            ttl=self.default_ttl if sensitive else None,
        )

        if session_id not in self.memories:
            self.memories[session_id] = []

        self.memories[session_id].append(entry)

    def retrieve_memory(
        self,
        session_id: str,
        user_id: Optional[str] = None,
    ) -> List[str]:
        """Retrieve memory with access control."""
        import time

        if session_id not in self.memories:
            return []

        current_time = time.time()
        valid_memories = []

        for entry in self.memories[session_id]:
            # Check TTL
            if entry.ttl and (current_time - entry.timestamp) > entry.ttl:
                continue

            # Check user access
            if entry.user_id and user_id and entry.user_id != user_id:
                continue

            # Check consent
            if entry.sensitive and self.require_consent and not entry.consent_given:
                continue

            valid_memories.append(entry.content)

        return valid_memories

    def clear_expired(self) -> int:
        """Clear expired memories."""
        import time

        current_time = time.time()
        cleared = 0

        for session_id in list(self.memories.keys()):
            original_count = len(self.memories[session_id])

            self.memories[session_id] = [
                entry for entry in self.memories[session_id]
                if not entry.ttl or (current_time - entry.timestamp) <= entry.ttl
            ]

            cleared += original_count - len(self.memories[session_id])

            if not self.memories[session_id]:
                del self.memories[session_id]

        return cleared
