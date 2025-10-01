"""Tool chain abuse and lateral movement prevention.

Prevents agents from chaining tools to escalate privileges or
perform unauthorized lateral movement across systems.
"""

from typing import List, Dict, Set, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import re


class ToolRiskLevel(Enum):
    """Risk levels for tools."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ChainViolationType(Enum):
    """Types of chain violations."""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION_CHAIN = "data_exfiltration_chain"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    SUSPICIOUS_SEQUENCE = "suspicious_sequence"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    FORBIDDEN_COMBINATION = "forbidden_combination"


@dataclass
class ToolCall:
    """Record of a tool invocation."""
    tool_name: str
    timestamp: datetime
    user_id: str
    session_id: str
    risk_level: ToolRiskLevel
    parameters: Dict[str, Any] = field(default_factory=dict)
    result_summary: Optional[str] = None


@dataclass
class ChainViolation:
    """Detected chain abuse."""
    violation_type: ChainViolationType
    severity: str  # "low", "medium", "high", "critical"
    tools_involved: List[str]
    description: str
    should_block: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class ToolChainPolicy:
    """Define policies for tool chaining."""

    def __init__(self):
        """Initialize policy."""
        # Forbidden tool combinations
        self.forbidden_chains: Set[tuple] = {
            ('file_read', 'network_request'),  # Read then exfil
            ('database_query', 'file_write'),  # DB to file
            ('credential_fetch', 'ssh_connect'),  # Cred harvest + use
            ('list_secrets', 'http_post'),  # Secret enumeration + exfil
        }

        # High-risk tool sequences (3+ tools)
        self.high_risk_sequences = [
            ['file_search', 'file_read', 'network_request'],  # Search, read, exfil
            ['database_query', 'transform_data', 'external_api'],  # DB extraction chain
        ]

        # Tool risk levels
        self.tool_risks: Dict[str, ToolRiskLevel] = {
            'file_read': ToolRiskLevel.MEDIUM,
            'file_write': ToolRiskLevel.HIGH,
            'database_query': ToolRiskLevel.HIGH,
            'network_request': ToolRiskLevel.MEDIUM,
            'ssh_connect': ToolRiskLevel.CRITICAL,
            'execute_code': ToolRiskLevel.CRITICAL,
            'credential_fetch': ToolRiskLevel.CRITICAL,
            'list_secrets': ToolRiskLevel.HIGH,
            'modify_permissions': ToolRiskLevel.CRITICAL,
            'cloud_api': ToolRiskLevel.HIGH,
        }

        # Max calls per tool per session
        self.rate_limits: Dict[str, int] = {
            'database_query': 10,
            'file_read': 20,
            'network_request': 15,
            'credential_fetch': 3,
            'ssh_connect': 5,
        }

    def register_tool(
        self,
        tool_name: str,
        risk_level: ToolRiskLevel,
        rate_limit: Optional[int] = None
    ):
        """Register a tool with risk level and rate limit."""
        self.tool_risks[tool_name] = risk_level
        if rate_limit:
            self.rate_limits[tool_name] = rate_limit

    def add_forbidden_chain(self, *tools: str):
        """Add a forbidden tool combination."""
        self.forbidden_chains.add(tuple(tools))


class ToolChainMonitor:
    """Monitor and enforce tool chain policies."""

    def __init__(
        self,
        policy: Optional[ToolChainPolicy] = None,
        lookback_window: int = 300,  # seconds
    ):
        """
        Initialize monitor.

        Args:
            policy: Chain policy (creates default if None)
            lookback_window: Time window for chain detection (seconds)
        """
        self.policy = policy or ToolChainPolicy()
        self.lookback_window = lookback_window

        # Track tool calls by session
        self.session_history: Dict[str, List[ToolCall]] = {}

        # Track violations
        self.violations: List[ChainViolation] = []

    def record_tool_call(
        self,
        tool_name: str,
        user_id: str,
        session_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        result_summary: Optional[str] = None,
    ) -> List[ChainViolation]:
        """
        Record a tool call and check for chain violations.

        Args:
            tool_name: Name of the tool
            user_id: User identifier
            session_id: Session identifier
            parameters: Tool parameters
            result_summary: Summary of tool result

        Returns:
            List of detected violations
        """
        # Create tool call record
        call = ToolCall(
            tool_name=tool_name,
            timestamp=datetime.now(),
            user_id=user_id,
            session_id=session_id,
            risk_level=self.policy.tool_risks.get(tool_name, ToolRiskLevel.LOW),
            parameters=parameters or {},
            result_summary=result_summary,
        )

        # Add to history
        if session_id not in self.session_history:
            self.session_history[session_id] = []
        self.session_history[session_id].append(call)

        # Clean old history
        self._clean_old_history()

        # Check for violations
        violations = self._check_violations(session_id)

        # Store violations
        self.violations.extend(violations)

        return violations

    def _clean_old_history(self):
        """Remove old tool calls outside lookback window."""
        cutoff = datetime.now() - timedelta(seconds=self.lookback_window)

        for session_id in list(self.session_history.keys()):
            self.session_history[session_id] = [
                call for call in self.session_history[session_id]
                if call.timestamp > cutoff
            ]

            # Remove empty sessions
            if not self.session_history[session_id]:
                del self.session_history[session_id]

    def _check_violations(self, session_id: str) -> List[ChainViolation]:
        """Check for chain violations in a session."""
        violations = []
        history = self.session_history.get(session_id, [])

        if len(history) < 2:
            return violations

        # 1. Check forbidden pairs
        for i in range(len(history) - 1):
            tool1 = history[i].tool_name
            tool2 = history[i + 1].tool_name

            if (tool1, tool2) in self.policy.forbidden_chains:
                violations.append(ChainViolation(
                    violation_type=ChainViolationType.FORBIDDEN_COMBINATION,
                    severity="high",
                    tools_involved=[tool1, tool2],
                    description=f"Forbidden tool chain detected: {tool1} -> {tool2}",
                    should_block=True,
                    metadata={
                        'time_between_calls': (history[i + 1].timestamp - history[i].timestamp).total_seconds(),
                    }
                ))

        # 2. Check high-risk sequences
        if len(history) >= 3:
            recent_tools = [call.tool_name for call in history[-5:]]

            for risk_seq in self.policy.high_risk_sequences:
                if self._contains_subsequence(recent_tools, risk_seq):
                    violations.append(ChainViolation(
                        violation_type=ChainViolationType.SUSPICIOUS_SEQUENCE,
                        severity="high",
                        tools_involved=risk_seq,
                        description=f"High-risk tool sequence detected: {' -> '.join(risk_seq)}",
                        should_block=True,
                    ))

        # 3. Check rate limits
        tool_counts: Dict[str, int] = {}
        for call in history:
            tool_counts[call.tool_name] = tool_counts.get(call.tool_name, 0) + 1

        for tool_name, count in tool_counts.items():
            limit = self.policy.rate_limits.get(tool_name)
            if limit and count > limit:
                violations.append(ChainViolation(
                    violation_type=ChainViolationType.RATE_LIMIT_EXCEEDED,
                    severity="medium",
                    tools_involved=[tool_name],
                    description=f"Rate limit exceeded for {tool_name}: {count}/{limit}",
                    should_block=True,
                    metadata={'count': count, 'limit': limit}
                ))

        # 4. Detect credential harvesting pattern
        cred_tools = ['credential_fetch', 'list_secrets', 'get_api_key', 'read_env']
        cred_calls = [c for c in history if c.tool_name in cred_tools]

        if len(cred_calls) >= 2:
            # Check if followed by network/file operations
            last_cred_idx = None
            for i, call in enumerate(history):
                if call.tool_name in cred_tools:
                    last_cred_idx = i

            if last_cred_idx is not None and last_cred_idx < len(history) - 1:
                next_call = history[last_cred_idx + 1]
                if next_call.tool_name in ['network_request', 'file_write', 'ssh_connect']:
                    violations.append(ChainViolation(
                        violation_type=ChainViolationType.CREDENTIAL_HARVESTING,
                        severity="critical",
                        tools_involved=[history[last_cred_idx].tool_name, next_call.tool_name],
                        description="Credential harvesting followed by exfiltration attempt",
                        should_block=True,
                    ))

        # 5. Detect privilege escalation patterns
        escalation_tools = ['modify_permissions', 'assume_role', 'sudo_execute', 'grant_access']
        escalation_calls = [c for c in history if c.tool_name in escalation_tools]

        if escalation_calls:
            violations.append(ChainViolation(
                violation_type=ChainViolationType.PRIVILEGE_ESCALATION,
                severity="critical",
                tools_involved=[c.tool_name for c in escalation_calls],
                description="Privilege escalation attempt detected",
                should_block=True,
            ))

        return violations

    def _contains_subsequence(self, sequence: List[str], subseq: List[str]) -> bool:
        """Check if sequence contains subsequence."""
        for i in range(len(sequence) - len(subseq) + 1):
            if sequence[i:i + len(subseq)] == subseq:
                return True
        return False

    def should_allow_call(
        self,
        tool_name: str,
        session_id: str,
        user_id: str,
    ) -> tuple[bool, Optional[ChainViolation]]:
        """
        Check if a tool call should be allowed before execution.

        Args:
            tool_name: Tool to call
            session_id: Session ID
            user_id: User ID

        Returns:
            (should_allow, violation_reason)
        """
        # Simulate the call to check violations
        temp_violations = self.record_tool_call(
            tool_name=tool_name,
            user_id=user_id,
            session_id=session_id,
        )

        # Remove the temporary call
        if session_id in self.session_history and self.session_history[session_id]:
            self.session_history[session_id].pop()

        # Check if any violations should block
        blocking_violations = [v for v in temp_violations if v.should_block]

        if blocking_violations:
            return False, blocking_violations[0]

        return True, None

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get summary of tool usage for a session."""
        history = self.session_history.get(session_id, [])

        if not history:
            return {
                'session_id': session_id,
                'tool_count': 0,
                'tools_used': [],
                'risk_level': 'none',
            }

        tool_counts: Dict[str, int] = {}
        for call in history:
            tool_counts[call.tool_name] = tool_counts.get(call.tool_name, 0) + 1

        # Calculate overall risk (use highest numeric value)
        risk_values = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_risk_value = max((risk_values.get(call.risk_level.value, 1) for call in history), default=1)
        risk_names = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        max_risk = risk_names[max_risk_value]

        return {
            'session_id': session_id,
            'tool_count': len(history),
            'tools_used': list(tool_counts.keys()),
            'tool_counts': tool_counts,
            'risk_level': max_risk,
            'duration_seconds': (history[-1].timestamp - history[0].timestamp).total_seconds(),
            'recent_tools': [call.tool_name for call in history[-5:]],
        }

    def get_violations_summary(self) -> Dict[str, Any]:
        """Get summary of all violations."""
        if not self.violations:
            return {
                'total_violations': 0,
                'by_type': {},
                'by_severity': {},
            }

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for violation in self.violations:
            by_type[violation.violation_type.value] = by_type.get(violation.violation_type.value, 0) + 1
            by_severity[violation.severity] = by_severity.get(violation.severity, 0) + 1

        return {
            'total_violations': len(self.violations),
            'by_type': by_type,
            'by_severity': by_severity,
            'recent_violations': [
                {
                    'type': v.violation_type.value,
                    'severity': v.severity,
                    'tools': v.tools_involved,
                    'description': v.description,
                }
                for v in self.violations[-5:]
            ]
        }
