"""External content security guard for web scraping and crawling.

This module provides security scanning for externally-fetched content to prevent
malicious data from being injected into agent workflows. It's designed to work
with web scraping, API responses, and any external data sources.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from shieldgents.core.prompts import (
    PromptGuard,
    PromptInjectionDetector,
    ScanResult,
    ThreatLevel,
)


@dataclass
class ContentScanResult:
    """Result of external content security scan."""

    is_safe: bool
    threat_level: ThreatLevel
    detected_threats: List[str]
    sanitized_content: Optional[str] = None
    metadata: Dict[str, Any] = None
    source_url: Optional[str] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


class WebContentDetector:
    """Detects malicious patterns in web-scraped content."""

    MALICIOUS_PATTERNS = {
        "javascript_injection": [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on(?:load|error|click|mouse\w+)\s*=",
        ],
        "iframe_injection": [
            r"<iframe[^>]*>",
            r"<embed[^>]*>",
            r"<object[^>]*>",
        ],
        "phishing_indicators": [
            r"(?i)verify\s+your\s+account",
            r"(?i)confirm\s+your\s+identity",
            r"(?i)click\s+here\s+immediately",
            r"(?i)urgent.*action.*required",
            r"(?i)suspended.*account",
        ],
        "data_exfiltration": [
            r"(?i)submit.*password",
            r"(?i)enter.*credit\s*card",
            r"(?i)social\s*security",
            r"<form[^>]*action\s*=\s*['\"]?https?://(?![\w.-]+\.[\w]+)",
        ],
        "prompt_injection_attempts": [
            r"(?i)ignore\s+previous\s+instructions",
            r"(?i)system\s*:\s*you\s+are",
            r"(?i)new\s+instructions\s*:",
            r"(?i)\[INST\]|\[/INST\]",
        ],
        "encoded_attacks": [
            r"\\x[0-9a-fA-F]{2}",
            r"\\u[0-9a-fA-F]{4}",
            r"%[0-9a-fA-F]{2}",
            r"&#\d+;",
        ],
    }

    SUSPICIOUS_DOMAINS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
    }

    def __init__(
        self,
        custom_patterns: Optional[Dict[str, List[str]]] = None,
        suspicious_domains: Optional[Set[str]] = None,
        strict_mode: bool = False,
    ) -> None:
        """
        Initialize web content detector.

        Args:
            custom_patterns: Additional malicious patterns to detect
            suspicious_domains: Additional suspicious domains to flag
            strict_mode: If True, be more aggressive in threat detection
        """
        self.patterns = self.MALICIOUS_PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)

        self.suspicious_domains = self.SUSPICIOUS_DOMAINS.copy()
        if suspicious_domains:
            self.suspicious_domains.update(suspicious_domains)

        self.strict_mode = strict_mode

    def scan_content(
        self, content: str, source_url: Optional[str] = None
    ) -> ContentScanResult:
        """
        Scan web content for malicious patterns.

        Args:
            content: The scraped content to scan
            source_url: Optional URL where content was fetched from

        Returns:
            ContentScanResult with detection details
        """
        detected_threats = []
        threat_details = {}

        # Check for malicious patterns
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    detected_threats.append(category)
                    if category not in threat_details:
                        threat_details[category] = []
                    threat_details[category].append(pattern)
                    break

        # Check domain reputation if URL provided
        if source_url:
            domain_threat = self._check_domain(source_url)
            if domain_threat:
                detected_threats.append("suspicious_domain")
                threat_details["suspicious_domain"] = [domain_threat]

        # Calculate threat level
        threat_level = self._calculate_threat_level(detected_threats)
        is_safe = threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]

        if self.strict_mode and detected_threats:
            is_safe = False

        return ContentScanResult(
            is_safe=is_safe,
            threat_level=threat_level,
            detected_threats=detected_threats,
            metadata={"threat_details": threat_details},
            source_url=source_url,
        )

    def _check_domain(self, url: str) -> Optional[str]:
        """Check if URL domain is suspicious."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            for suspicious in self.suspicious_domains:
                if suspicious in domain:
                    return f"Suspicious domain: {domain}"
        except Exception:
            pass
        return None

    def _calculate_threat_level(self, detected_threats: List[str]) -> ThreatLevel:
        """Calculate overall threat level based on detected threats."""
        if not detected_threats:
            return ThreatLevel.SAFE

        critical_threats = {
            "javascript_injection",
            "data_exfiltration",
            "prompt_injection_attempts",
        }
        high_threats = {"iframe_injection", "phishing_indicators"}

        if any(t in critical_threats for t in detected_threats):
            return ThreatLevel.CRITICAL if len(detected_threats) > 2 else ThreatLevel.HIGH

        if any(t in high_threats for t in detected_threats):
            return ThreatLevel.MEDIUM

        return ThreatLevel.LOW


class ExternalContentSanitizer:
    """Sanitizes external content to remove potentially dangerous elements."""

    def __init__(
        self,
        strip_html: bool = True,
        strip_urls: bool = False,
        max_length: Optional[int] = None,
    ) -> None:
        """
        Initialize sanitizer.

        Args:
            strip_html: Remove all HTML tags
            strip_urls: Remove all URLs
            max_length: Maximum content length
        """
        self.strip_html = strip_html
        self.strip_urls = strip_urls
        self.max_length = max_length

    def sanitize(self, content: str) -> str:
        """
        Sanitize external content.

        Args:
            content: Content to sanitize

        Returns:
            Sanitized content
        """
        sanitized = content

        # Remove HTML tags
        if self.strip_html:
            sanitized = re.sub(r"<[^>]+>", "", sanitized)

        # Remove URLs
        if self.strip_urls:
            sanitized = re.sub(
                r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", "[URL_REMOVED]", sanitized
            )

        # Remove encoded characters
        sanitized = self._decode_entities(sanitized)

        # Remove excessive whitespace
        sanitized = re.sub(r"\s+", " ", sanitized).strip()

        # Apply length limit
        if self.max_length:
            sanitized = sanitized[: self.max_length]

        return sanitized

    def _decode_entities(self, text: str) -> str:
        """Decode HTML entities to prevent obfuscation."""
        # Remove hex entities
        text = re.sub(r"&#x[0-9a-fA-F]+;", "", text)
        # Remove decimal entities
        text = re.sub(r"&#\d+;", "", text)
        return text


class ExternalContentGuard:
    """Unified guard for external content from web scraping/crawling."""

    def __init__(
        self,
        web_detector: Optional[WebContentDetector] = None,
        prompt_guard: Optional[PromptGuard] = None,
        sanitizer: Optional[ExternalContentSanitizer] = None,
        auto_sanitize: bool = True,
        check_prompt_injection: bool = True,
    ) -> None:
        """
        Initialize external content guard.

        Args:
            web_detector: Custom web content detector
            prompt_guard: Prompt guard for injection detection
            sanitizer: Content sanitizer
            auto_sanitize: Automatically sanitize unsafe content
            check_prompt_injection: Also check for prompt injection in content
        """
        self.web_detector = web_detector or WebContentDetector()
        self.prompt_guard = prompt_guard or PromptGuard()
        self.sanitizer = sanitizer or ExternalContentSanitizer()
        self.auto_sanitize = auto_sanitize
        self.check_prompt_injection = check_prompt_injection

    def guard_scraped_content(
        self, content: str, source_url: Optional[str] = None
    ) -> ContentScanResult:
        """
        Guard scraped content before agent processes it.

        Args:
            content: Scraped content to guard
            source_url: Optional source URL

        Returns:
            ContentScanResult with scan details
        """
        # First check for web-specific threats
        web_scan = self.web_detector.scan_content(content, source_url)

        # Also check for prompt injection attempts in the content
        if self.check_prompt_injection:
            prompt_scan = self.prompt_guard.guard(content)
            if not prompt_scan.is_safe:
                web_scan.detected_threats.extend(
                    [f"prompt_injection:{p}" for p in prompt_scan.detected_patterns]
                )
                web_scan.threat_level = max(
                    web_scan.threat_level, prompt_scan.threat_level, key=lambda x: x.value
                )
                web_scan.is_safe = False

        # Auto-sanitize if enabled and unsafe
        if not web_scan.is_safe and self.auto_sanitize:
            web_scan.sanitized_content = self.sanitizer.sanitize(content)
            web_scan.metadata["sanitization_applied"] = True

        return web_scan

    def guard_api_response(
        self, response_data: Any, api_endpoint: Optional[str] = None
    ) -> ContentScanResult:
        """
        Guard API response data.

        Args:
            response_data: API response (dict, list, or string)
            api_endpoint: Optional API endpoint URL

        Returns:
            ContentScanResult with scan details
        """
        # Convert response to string for scanning
        if isinstance(response_data, dict):
            content = str(response_data)
        elif isinstance(response_data, list):
            content = " ".join(str(item) for item in response_data)
        else:
            content = str(response_data)

        return self.guard_scraped_content(content, api_endpoint)

    def create_safe_scraper_wrapper(self, scraper_func: callable) -> callable:
        """
        Wrap a scraper function to automatically guard its output.

        Args:
            scraper_func: Function that scrapes content (should return str or dict with 'content' key)

        Returns:
            Wrapped function that guards scraped content
        """

        def wrapped_scraper(*args, **kwargs):
            # Get source URL if provided
            source_url = kwargs.get("url") or (args[0] if args else None)

            # Call original scraper
            result = scraper_func(*args, **kwargs)

            # Extract content
            if isinstance(result, dict) and "content" in result:
                content = result["content"]
            else:
                content = str(result)

            # Guard the content
            scan = self.guard_scraped_content(content, source_url)

            if not scan.is_safe:
                if scan.sanitized_content:
                    # Return sanitized version
                    if isinstance(result, dict):
                        result["content"] = scan.sanitized_content
                        result["_security_scan"] = scan
                        return result
                    return scan.sanitized_content
                else:
                    # Block unsafe content
                    raise SecurityError(
                        f"Scraped content blocked: {scan.threat_level.value}",
                        scan=scan,
                    )

            # Content is safe, return original result
            if isinstance(result, dict):
                result["_security_scan"] = scan
            return result

        return wrapped_scraper


class SecurityError(Exception):
    """Raised when external content is blocked by security guard."""

    def __init__(self, message: str, scan: ContentScanResult) -> None:
        super().__init__(message)
        self.scan = scan
