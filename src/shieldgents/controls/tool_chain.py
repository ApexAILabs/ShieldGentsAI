"""Chain-of-tool abuse and lateral movement detection.

Detects when agents use multiple tools in sequence to escalate privileges,
access unauthorized resources, or move laterally through infrastructure.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class ChainRiskLevel(Enum):
    """Risk levels for tool chains."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolCall:
    """Record of a tool invocation."""

    tool_name: str
    timestamp: float
    agent_id: str
    session_id: str
    parameters: Dict[str, Any]
    result: Optional[Any] = None
    success: bool = True


@dataclass
class ToolChainAlert:
    """Alert for suspicious tool chain."""

    severity: str  # "low", "medium", "high", "critical"
    risk_level: ChainRiskLevel
    description: str
    chain: List[str]  # Tool names in chain
    confidence: float
    should_block: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class ToolChainMonitor:
    """Monitors tool usage chains for abuse patterns.

    **How it works:**
    - Tracks sequences of tool calls within sessions
    - Identifies dangerous tool combinations (e.g., search → access → exfiltrate)
    - Detects privilege escalation patterns
    - Monitors for lateral movement attempts
    - Enforces policies on inter-tool authorization
    """

    def __init__(
        self,
        max_chain_length: int = 10,
        time_window_seconds: float = 300.0,
        enable_inter_tool_auth: bool = True,
    ):
        """
        Initialize tool chain monitor.

        Args:
            max_chain_length: Max allowed tool calls in sequence
            time_window_seconds: Time window for chain detection
            enable_inter_tool_auth: Require authorization between tool calls
        """
        self.max_chain_length = max_chain_length
        self.time_window_seconds = time_window_seconds
        self.enable_inter_tool_auth = enable_inter_tool_auth

        # Track tool calls per session
        self.session_chains: Dict[str, List[ToolCall]] = defaultdict(list)

        # Track alerts
        self.alerts: List[ToolChainAlert] = []

        # Define dangerous tool combinations
        self.dangerous_combinations = self._init_dangerous_combinations()

        # Define tool risk levels
        self.tool_risk_levels = self._init_tool_risk_levels()

    def record_tool_call(
        self,
        tool_name: str,
        agent_id: str,
        session_id: str,
        parameters: Dict[str, Any],
        result: Optional[Any] = None,
        success: bool = True,
    ) -> List[ToolChainAlert]:
        """
        Record a tool call and check for abuse patterns.

        Args:
            tool_name: Name of tool called
            agent_id: Agent identifier
            session_id: Session identifier
            parameters: Tool parameters
            result: Tool result
            success: Whether call succeeded

        Returns:
            List of alerts if suspicious patterns detected
        """
        import time

        # Create tool call record
        tool_call = ToolCall(
            tool_name=tool_name,
            timestamp=time.time(),
            agent_id=agent_id,
            session_id=session_id,
            parameters=parameters,
            result=result,
            success=success,
        )

        # Add to session chain
        self.session_chains[session_id].append(tool_call)

        # Clean old calls
        self._clean_old_calls(session_id, tool_call.timestamp)

        # Check for abuse patterns
        alerts = []

        # Check chain length
        length_alert = self._check_chain_length(session_id)
        if length_alert:
            alerts.append(length_alert)
            self.alerts.append(length_alert)

        # Check dangerous combinations
        combo_alerts = self._check_dangerous_combinations(session_id)
        alerts.extend(combo_alerts)
        self.alerts.extend(combo_alerts)

        # Check privilege escalation
        escalation_alert = self._check_privilege_escalation(session_id)
        if escalation_alert:
            alerts.append(escalation_alert)
            self.alerts.append(escalation_alert)

        # Check lateral movement
        lateral_alert = self._check_lateral_movement(session_id)
        if lateral_alert:
            alerts.append(lateral_alert)
            self.alerts.append(lateral_alert)

        # Check resource access pattern
        access_alert = self._check_resource_access_pattern(session_id)
        if access_alert:
            alerts.append(access_alert)
            self.alerts.append(access_alert)

        return alerts

    def _check_chain_length(self, session_id: str) -> Optional[ToolChainAlert]:
        """Check if chain is too long."""
        chain = self.session_chains[session_id]

        if len(chain) > self.max_chain_length:
            return ToolChainAlert(
                severity="high",
                risk_level=ChainRiskLevel.HIGH,
                description=f"Tool chain too long: {len(chain)} calls",
                chain=[c.tool_name for c in chain],
                confidence=0.9,
                should_block=True,
                metadata={
                    "chain_length": len(chain),
                    "limit": self.max_chain_length,
                },
            )

        return None

    def _check_dangerous_combinations(
        self,
        session_id: str,
    ) -> List[ToolChainAlert]:
        """Check for dangerous tool combinations."""
        alerts = []
        chain = self.session_chains[session_id]

        if len(chain) < 2:
            return alerts

        # Get last N tools
        recent_tools = [c.tool_name for c in chain[-5:]]

        # Check against dangerous patterns
        for pattern, info in self.dangerous_combinations.items():
            pattern_tools = pattern.split(" -> ")

            # Check if pattern matches
            if self._matches_pattern(recent_tools, pattern_tools):
                alerts.append(
                    ToolChainAlert(
                        severity=info["severity"],
                        risk_level=ChainRiskLevel(info["risk"]),
                        description=f"Dangerous tool combination detected: {pattern}",
                        chain=recent_tools,
                        confidence=info["confidence"],
                        should_block=info["should_block"],
                        metadata={
                            "pattern": pattern,
                            "description": info["description"],
                        },
                    )
                )

        return alerts

    def _check_privilege_escalation(
        self,
        session_id: str,
    ) -> Optional[ToolChainAlert]:
        """Check for privilege escalation patterns."""
        chain = self.session_chains[session_id]

        if len(chain) < 2:
            return None

        # Get risk levels for recent tools
        recent_risks = [self.tool_risk_levels.get(c.tool_name, "medium") for c in chain[-5:]]

        # Check for escalation (low -> high risk tools)
        risk_order = ["low", "medium", "high", "critical"]

        for i in range(len(recent_risks) - 1):
            current_idx = risk_order.index(recent_risks[i]) if recent_risks[i] in risk_order else 1
            next_idx = (
                risk_order.index(recent_risks[i + 1]) if recent_risks[i + 1] in risk_order else 1
            )

            # Escalation of 2+ levels
            if next_idx - current_idx >= 2:
                return ToolChainAlert(
                    severity="high",
                    risk_level=ChainRiskLevel.HIGH,
                    description=f"Privilege escalation detected: {recent_risks[i]} -> {recent_risks[i+1]}",
                    chain=[c.tool_name for c in chain[-5:]],
                    confidence=0.8,
                    should_block=True,
                    metadata={
                        "escalation": f"{recent_risks[i]} -> {recent_risks[i+1]}",
                    },
                )

        return None

    def _check_lateral_movement(
        self,
        session_id: str,
    ) -> Optional[ToolChainAlert]:
        """Check for lateral movement patterns."""
        chain = self.session_chains[session_id]

        if len(chain) < 3:
            return None

        # Lateral movement patterns
        lateral_keywords = [
            ("file_search", "credential"),
            ("file_read", "secret"),
            ("file_read", "ssh"),
            ("database_query", "credential"),
            ("network_scan", "connect"),
        ]

        recent_calls = chain[-10:]

        for i in range(len(recent_calls) - 1):
            current_tool = recent_calls[i].tool_name
            next_tool = recent_calls[i + 1].tool_name

            # Check if found credentials then used them
            current_params_str = str(recent_calls[i].parameters).lower()

            for keyword1, keyword2 in lateral_keywords:
                if keyword1 in current_tool.lower() and keyword2 in current_params_str:
                    if "connect" in next_tool.lower() or "access" in next_tool.lower():
                        return ToolChainAlert(
                            severity="critical",
                            risk_level=ChainRiskLevel.CRITICAL,
                            description=f"Lateral movement detected: {current_tool} -> {next_tool}",
                            chain=[c.tool_name for c in recent_calls],
                            confidence=0.85,
                            should_block=True,
                            metadata={
                                "pattern": f"{keyword1} -> {next_tool}",
                            },
                        )

        return None

    def _check_resource_access_pattern(
        self,
        session_id: str,
    ) -> Optional[ToolChainAlert]:
        """Check for suspicious resource access patterns."""
        chain = self.session_chains[session_id]

        if len(chain) < 3:
            return None

        # Count access to different resources
        resource_tools = [
            "file_read",
            "file_write",
            "database_query",
            "api_call",
            "web_scrape",
            "s3_access",
        ]

        recent_calls = chain[-10:]
        resource_accesses = [
            c for c in recent_calls if any(rt in c.tool_name.lower() for rt in resource_tools)
        ]

        # Too many resource accesses
        if len(resource_accesses) > 5:
            return ToolChainAlert(
                severity="medium",
                risk_level=ChainRiskLevel.MEDIUM,
                description=f"Excessive resource access: {len(resource_accesses)} accesses",
                chain=[c.tool_name for c in recent_calls],
                confidence=0.7,
                should_block=False,
                metadata={
                    "access_count": len(resource_accesses),
                    "resources": [c.tool_name for c in resource_accesses],
                },
            )

        return None

    def _matches_pattern(
        self,
        tools: List[str],
        pattern: List[str],
    ) -> bool:
        """Check if tool sequence matches pattern."""
        if len(tools) < len(pattern):
            return False

        # Check if pattern appears in tools
        for i in range(len(tools) - len(pattern) + 1):
            if all(pattern[j].lower() in tools[i + j].lower() for j in range(len(pattern))):
                return True

        return False

    def _clean_old_calls(self, session_id: str, current_time: float) -> None:
        """Remove calls outside time window."""
        cutoff = current_time - self.time_window_seconds
        self.session_chains[session_id] = [
            c for c in self.session_chains[session_id] if c.timestamp > cutoff
        ]

    def _init_dangerous_combinations(self) -> Dict[str, Dict[str, Any]]:
        """Initialize dangerous tool combinations."""
        return {
            "file_search -> file_read -> network": {
                "severity": "critical",
                "risk": "critical",
                "confidence": 0.9,
                "should_block": True,
                "description": "Search files, read, then exfiltrate via network",
            },
            "database_query -> file_write -> execute": {
                "severity": "critical",
                "risk": "critical",
                "confidence": 0.95,
                "should_block": True,
                "description": "Query DB, write file, then execute",
            },
            "credential -> ssh -> execute": {
                "severity": "critical",
                "risk": "critical",
                "confidence": 0.9,
                "should_block": True,
                "description": "Access credentials, SSH, then execute commands",
            },
            "user_list -> permission -> delete": {
                "severity": "high",
                "risk": "high",
                "confidence": 0.85,
                "should_block": True,
                "description": "List users, modify permissions, then delete",
            },
            "scan -> exploit -> execute": {
                "severity": "critical",
                "risk": "critical",
                "confidence": 0.95,
                "should_block": True,
                "description": "Scan for vulnerabilities, exploit, then execute",
            },
        }

    def _init_tool_risk_levels(self) -> Dict[str, str]:
        """Initialize tool risk levels."""
        return {
            # Low risk
            "read_public_data": "low",
            "search": "low",
            "calculate": "low",
            "translate": "low",
            # Medium risk
            "file_read": "medium",
            "database_query": "medium",
            "api_call": "medium",
            "web_scrape": "medium",
            # High risk
            "file_write": "high",
            "database_write": "high",
            "execute_code": "high",
            "ssh_connect": "high",
            "modify_permissions": "high",
            # Critical risk
            "delete_file": "critical",
            "delete_database": "critical",
            "system_command": "critical",
            "network_admin": "critical",
            "credential_access": "critical",
        }

    def get_session_chain(self, session_id: str) -> List[Dict[str, Any]]:
        """Get tool chain for a session."""
        return [
            {
                "tool": c.tool_name,
                "timestamp": c.timestamp,
                "success": c.success,
            }
            for c in self.session_chains[session_id]
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get tool chain monitoring statistics."""
        return {
            "active_sessions": len(self.session_chains),
            "total_alerts": len(self.alerts),
            "alerts_by_severity": {
                severity: sum(1 for a in self.alerts if a.severity == severity)
                for severity in ["low", "medium", "high", "critical"]
            },
            "avg_chain_length": (
                sum(len(chain) for chain in self.session_chains.values()) / len(self.session_chains)
                if self.session_chains
                else 0
            ),
        }

    def clear_session(self, session_id: str) -> None:
        """Clear chain for a session."""
        self.session_chains.pop(session_id, None)
