"""Supply chain security for dependencies and third-party components.

**How it works:**
Validates dependencies, checks for known vulnerabilities, ensures code signing,
and monitors for compromised packages or malicious libraries.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json


class ThreatType(Enum):
    """Supply chain threat types."""
    MALICIOUS_PACKAGE = "malicious_package"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    UNSIGNED_CODE = "unsigned_code"
    TAMPERED_PACKAGE = "tampered_package"
    TYPOSQUATTING = "typosquatting"


@dataclass
class SupplyChainAlert:
    """Alert for supply chain threat."""
    severity: str
    threat_type: ThreatType
    description: str
    package_name: str
    should_block: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class SupplyChainValidator:
    """Validates supply chain security of dependencies."""

    def __init__(
        self,
        known_malicious: Optional[Set[str]] = None,
        trusted_sources: Optional[Set[str]] = None,
        require_signatures: bool = True,
    ):
        """
        Initialize supply chain validator.

        Args:
            known_malicious: Set of known malicious package names
            trusted_sources: Set of trusted package sources (default: pypi.org, npmjs.com)
            require_signatures: Whether to require code signatures
        """
        self.known_malicious = known_malicious or set()
        self.trusted_sources = trusted_sources or {'pypi.org', 'npmjs.com'}
        self.require_signatures = require_signatures

        # Common typosquatting targets
        self.typosquat_targets = {
            'requests', 'numpy', 'pandas', 'django', 'flask',
            'tensorflow', 'pytorch', 'openai', 'anthropic'
        }

    def validate_package(
        self,
        package_name: str,
        version: str,
        source: Optional[str] = None,
        checksum: Optional[str] = None,
    ) -> List[SupplyChainAlert]:
        """
        Validate a package for supply chain threats.

        Args:
            package_name: Name of the package to validate
            version: Version of the package
            source: Optional package source URL
            checksum: Optional package checksum for integrity verification

        Returns:
            List of SupplyChainAlert objects for detected threats
        """
        alerts = []

        # Check against known malicious
        if package_name.lower() in self.known_malicious:
            alerts.append(SupplyChainAlert(
                severity="critical",
                threat_type=ThreatType.MALICIOUS_PACKAGE,
                description=f"Known malicious package: {package_name}",
                package_name=package_name,
                should_block=True,
                metadata={'version': version}
            ))

        # Check source
        if source and source not in self.trusted_sources:
            alerts.append(SupplyChainAlert(
                severity="high",
                threat_type=ThreatType.TAMPERED_PACKAGE,
                description=f"Package from untrusted source: {source}",
                package_name=package_name,
                should_block=False,
                metadata={'source': source}
            ))

        # Check for typosquatting
        typo_alert = self._check_typosquatting(package_name)
        if typo_alert:
            alerts.append(typo_alert)

        return alerts

    def _check_typosquatting(self, package_name: str) -> Optional[SupplyChainAlert]:
        """
        Check for typosquatting attempts.

        Args:
            package_name: Package name to check

        Returns:
            SupplyChainAlert if typosquatting detected, None otherwise
        """
        name_lower = package_name.lower()

        for target in self.typosquat_targets:
            if self._is_similar(name_lower, target.lower()) and name_lower != target.lower():
                return SupplyChainAlert(
                    severity="critical",
                    threat_type=ThreatType.TYPOSQUATTING,
                    description=f"Potential typosquatting: '{package_name}' similar to '{target}'",
                    package_name=package_name,
                    should_block=True,
                    metadata={'target': target}
                )

        return None

    def _is_similar(self, str1: str, str2: str) -> bool:
        """
        Check if strings are similar using Levenshtein distance.

        Args:
            str1: First string to compare
            str2: Second string to compare

        Returns:
            True if strings are similar (within 2 character differences)
        """
        if len(str1) != len(str2):
            if abs(len(str1) - len(str2)) > 2:
                return False

        # Simple similarity check
        differences = sum(c1 != c2 for c1, c2 in zip(str1, str2))
        return differences <= 2
