"""Content safety and misuse prevention.

**How it works:**
Detects and blocks malicious use cases like malware generation, phishing,
social engineering scripts, and other harmful content creation.
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class MisuseType(Enum):
    """Types of misuse."""

    MALWARE_GENERATION = "malware_generation"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    EXPLOIT_DEVELOPMENT = "exploit_development"
    SPAM_GENERATION = "spam_generation"
    DISINFORMATION = "disinformation"


@dataclass
class ContentSafetyAlert:
    """Alert for content safety violation."""

    severity: str
    misuse_type: MisuseType
    description: str
    confidence: float
    should_block: bool
    metadata: Dict[str, Any] = None


class ContentSafetyFilter:
    """Filters harmful content requests."""

    def __init__(self):
        """
        Initialize content safety filter with keyword patterns.

        Sets up detection patterns for malware, phishing, and exploit keywords.
        """
        self.malware_keywords = [
            "keylogger",
            "ransomware",
            "trojan",
            "backdoor",
            "rootkit",
            "botnet",
            "cryptolocker",
            "payload",
            "malware",
            "virus",
            "worm",
            "spyware",
            "encrypt files",
        ]

        self.phishing_keywords = [
            "phishing email",
            "fake login",
            "credential harvest",
            "spoof domain",
            "fake website",
            "password stealing",
            "steal password",
            "steal login",
            "harvest credential",
        ]

        self.exploit_keywords = [
            "buffer overflow",
            "sql injection payload",
            "xss attack",
            "privilege escalation exploit",
            "zero-day exploit",
            "sql injection",
            "xss",
            "csrf",
        ]

    def check_request(self, prompt: str) -> List[ContentSafetyAlert]:
        """
        Check if request is attempting misuse.

        Args:
            prompt: User prompt to check for misuse patterns

        Returns:
            List of ContentSafetyAlert objects for detected violations
        """
        alerts = []
        prompt_lower = prompt.lower()

        # Check for malware generation
        if any(kw in prompt_lower for kw in self.malware_keywords):
            if any(
                gen in prompt_lower for gen in ["create", "generate", "write", "build", "develop"]
            ):
                alerts.append(
                    ContentSafetyAlert(
                        severity="critical",
                        misuse_type=MisuseType.MALWARE_GENERATION,
                        description="Malware generation attempt detected",
                        confidence=0.9,
                        should_block=True,
                        metadata={"prompt_preview": prompt[:100]},
                    )
                )

        # Check for phishing
        if any(kw in prompt_lower for kw in self.phishing_keywords):
            alerts.append(
                ContentSafetyAlert(
                    severity="critical",
                    misuse_type=MisuseType.PHISHING,
                    description="Phishing content generation detected",
                    confidence=0.85,
                    should_block=True,
                    metadata={"prompt_preview": prompt[:100]},
                )
            )

        # Check for exploit development
        if any(kw in prompt_lower for kw in self.exploit_keywords):
            if any(gen in prompt_lower for gen in ["create", "generate", "write", "craft"]):
                alerts.append(
                    ContentSafetyAlert(
                        severity="critical",
                        misuse_type=MisuseType.EXPLOIT_DEVELOPMENT,
                        description="Exploit development attempt detected",
                        confidence=0.8,
                        should_block=True,
                        metadata={"prompt_preview": prompt[:100]},
                    )
                )

        return alerts
