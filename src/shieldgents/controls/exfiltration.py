"""Data exfiltration detection and prevention.

Detects attempts to leak sensitive data through covert channels, unusual encodings,
or suspicious output patterns in agent responses.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import re
import base64


class ExfiltrationMethod(Enum):
    """Methods of data exfiltration."""
    BASE64_ENCODING = "base64_encoding"
    HEX_ENCODING = "hex_encoding"
    URL_ENCODING = "url_encoding"
    STEGANOGRAPHY = "steganography"
    TIMING_CHANNEL = "timing_channel"
    SIZE_CHANNEL = "size_channel"
    ERROR_CHANNEL = "error_channel"
    DNS_TUNNEL = "dns_tunnel"
    FRAGMENTED_DATA = "fragmented_data"


@dataclass
class ExfiltrationAlert:
    """Alert for detected exfiltration attempt."""
    severity: str  # "low", "medium", "high", "critical"
    method: ExfiltrationMethod
    description: str
    confidence: float  # 0.0 to 1.0
    evidence: str
    should_block: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExfiltrationDetector:
    """Detects data exfiltration attempts in agent outputs.

    **How it works:**
    - Scans outputs for encoded data (base64, hex, URL encoding)
    - Detects unusually long strings that could contain hidden data
    - Identifies patterns of data fragmentation across responses
    - Monitors for covert timing and size-based channels
    - Tracks suspicious character distributions and entropy
    """

    def __init__(
        self,
        max_encoded_length: int = 500,
        max_entropy_threshold: float = 4.5,
        enable_fragmentation_detection: bool = True,
    ):
        """
        Initialize exfiltration detector.

        Args:
            max_encoded_length: Max allowed encoded string length
            max_entropy_threshold: Shannon entropy threshold for randomness
            enable_fragmentation_detection: Track fragmented data across calls
        """
        self.max_encoded_length = max_encoded_length
        self.max_entropy_threshold = max_entropy_threshold
        self.enable_fragmentation_detection = enable_fragmentation_detection

        # Track fragments across sessions
        self.session_fragments: Dict[str, List[str]] = {}
        self.session_encodings: Dict[str, List[str]] = {}

    def scan(
        self,
        output: str,
        session_id: Optional[str] = None,
    ) -> List[ExfiltrationAlert]:
        """
        Scan agent output for exfiltration attempts.

        Args:
            output: Agent output to scan
            session_id: Session ID for tracking fragments

        Returns:
            List of exfiltration alerts
        """
        alerts = []

        # Check for base64 encoding
        base64_alert = self._detect_base64(output)
        if base64_alert:
            alerts.append(base64_alert)

        # Check for hex encoding
        hex_alert = self._detect_hex(output)
        if hex_alert:
            alerts.append(hex_alert)

        # Check for URL encoding
        url_alert = self._detect_url_encoding(output)
        if url_alert:
            alerts.append(url_alert)

        # Check for high entropy (potential encrypted/encoded data)
        entropy_alert = self._detect_high_entropy(output)
        if entropy_alert:
            alerts.append(entropy_alert)

        # Check for fragmented data
        if self.enable_fragmentation_detection and session_id:
            frag_alert = self._detect_fragmentation(output, session_id)
            if frag_alert:
                alerts.append(frag_alert)

        # Check for DNS tunneling patterns
        dns_alert = self._detect_dns_tunnel(output)
        if dns_alert:
            alerts.append(dns_alert)

        return alerts

    def _detect_base64(self, text: str) -> Optional[ExfiltrationAlert]:
        """Detect base64-encoded data."""
        # Look for base64 patterns (groups of base64 chars)
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        matches = re.findall(base64_pattern, text)

        if not matches:
            return None

        # Check if matches are valid base64
        valid_base64 = []
        for match in matches:
            try:
                decoded = base64.b64decode(match, validate=True)
                # Check if decoded is printable or binary data
                if len(decoded) > 20:  # Significant data
                    valid_base64.append(match)
            except Exception:
                continue

        if valid_base64:
            total_length = sum(len(m) for m in valid_base64)

            severity = "high" if total_length > self.max_encoded_length else "medium"
            should_block = total_length > self.max_encoded_length

            return ExfiltrationAlert(
                severity=severity,
                method=ExfiltrationMethod.BASE64_ENCODING,
                description=f"Base64-encoded data detected ({len(valid_base64)} instances)",
                confidence=0.9,
                evidence=valid_base64[0][:100] + "..." if len(valid_base64[0]) > 100 else valid_base64[0],
                should_block=should_block,
                metadata={
                    'count': len(valid_base64),
                    'total_length': total_length,
                    'samples': valid_base64[:3],
                }
            )

        return None

    def _detect_hex(self, text: str) -> Optional[ExfiltrationAlert]:
        """Detect hex-encoded data."""
        # Look for long hex strings
        hex_pattern = r'\b[0-9a-fA-F]{40,}\b'
        matches = re.findall(hex_pattern, text)

        if matches:
            total_length = sum(len(m) for m in matches)

            severity = "high" if total_length > self.max_encoded_length else "medium"
            should_block = total_length > self.max_encoded_length

            return ExfiltrationAlert(
                severity=severity,
                method=ExfiltrationMethod.HEX_ENCODING,
                description=f"Hex-encoded data detected ({len(matches)} instances)",
                confidence=0.85,
                evidence=matches[0][:100] + "..." if len(matches[0]) > 100 else matches[0],
                should_block=should_block,
                metadata={
                    'count': len(matches),
                    'total_length': total_length,
                }
            )

        return None

    def _detect_url_encoding(self, text: str) -> Optional[ExfiltrationAlert]:
        """Detect URL-encoded data."""
        # Look for URL encoding patterns
        url_pattern = r'(?:%[0-9a-fA-F]{2}){10,}'
        matches = re.findall(url_pattern, text)

        if matches:
            return ExfiltrationAlert(
                severity="medium",
                method=ExfiltrationMethod.URL_ENCODING,
                description=f"URL-encoded data detected ({len(matches)} instances)",
                confidence=0.8,
                evidence=matches[0][:100],
                should_block=len(matches) > 5,
                metadata={'count': len(matches)}
            )

        return None

    def _detect_high_entropy(self, text: str) -> Optional[ExfiltrationAlert]:
        """Detect high entropy strings (potentially encrypted/encoded)."""
        # Calculate Shannon entropy for long strings
        long_strings = re.findall(r'\S{50,}', text)

        high_entropy_strings = []
        for s in long_strings:
            entropy = self._calculate_entropy(s)
            if entropy > self.max_entropy_threshold:
                high_entropy_strings.append((s, entropy))

        if high_entropy_strings:
            max_entropy_str, max_entropy = max(high_entropy_strings, key=lambda x: x[1])

            return ExfiltrationAlert(
                severity="high",
                method=ExfiltrationMethod.STEGANOGRAPHY,
                description=f"High entropy data detected (entropy={max_entropy:.2f})",
                confidence=0.75,
                evidence=max_entropy_str[:100],
                should_block=max_entropy > 5.0,
                metadata={
                    'entropy': max_entropy,
                    'count': len(high_entropy_strings),
                }
            )

        return None

    def _detect_fragmentation(
        self,
        text: str,
        session_id: str,
    ) -> Optional[ExfiltrationAlert]:
        """Detect data fragmentation across multiple responses."""
        # Track encoded strings in session
        if session_id not in self.session_encodings:
            self.session_encodings[session_id] = []

        # Find encoded-looking strings
        encoded_patterns = [
            r'[A-Za-z0-9+/]{20,}',  # base64-like
            r'[0-9a-fA-F]{20,}',     # hex-like
        ]

        for pattern in encoded_patterns:
            matches = re.findall(pattern, text)
            if matches:
                self.session_encodings[session_id].extend(matches)

        # Check if we have accumulated suspicious amount
        total_encoded = len(self.session_encodings[session_id])
        if total_encoded > 10:
            return ExfiltrationAlert(
                severity="critical",
                method=ExfiltrationMethod.FRAGMENTED_DATA,
                description=f"Fragmented data exfiltration detected ({total_encoded} fragments)",
                confidence=0.85,
                evidence=f"{total_encoded} encoded fragments across session",
                should_block=True,
                metadata={
                    'session_id': session_id,
                    'fragment_count': total_encoded,
                }
            )

        return None

    def _detect_dns_tunnel(self, text: str) -> Optional[ExfiltrationAlert]:
        """Detect DNS tunneling patterns."""
        # Look for suspicious subdomain patterns
        dns_pattern = r'\b[a-z0-9]{30,}\.[a-z0-9\-]+\.[a-z]{2,}\b'
        matches = re.findall(dns_pattern, text, re.IGNORECASE)

        if matches:
            return ExfiltrationAlert(
                severity="high",
                method=ExfiltrationMethod.DNS_TUNNEL,
                description=f"Potential DNS tunneling detected ({len(matches)} instances)",
                confidence=0.7,
                evidence=matches[0][:100],
                should_block=True,
                metadata={'count': len(matches), 'domains': matches[:5]}
            )

        return None

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0

        from collections import Counter
        import math

        # Count character frequencies
        counts = Counter(string)
        length = len(string)

        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def clear_session(self, session_id: str) -> None:
        """Clear tracked data for a session."""
        self.session_fragments.pop(session_id, None)
        self.session_encodings.pop(session_id, None)

    def get_statistics(self) -> Dict[str, Any]:
        """Get exfiltration detection statistics."""
        return {
            'tracked_sessions': len(self.session_encodings),
            'total_fragments': sum(len(f) for f in self.session_encodings.values()),
        }
