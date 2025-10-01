"""MCP (Model Context Protocol) server security module.

Provides security controls for MCP servers including:
- Request/response validation
- Tool call authorization
- Resource quota enforcement
- Server capability monitoring
- Malicious server detection
- Data leakage prevention in MCP responses
"""

from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re
import json


class MCPThreatType(Enum):
    """Types of MCP security threats."""
    MALICIOUS_TOOL_RESPONSE = "malicious_tool_response"
    UNAUTHORIZED_DATA_ACCESS = "unauthorized_data_access"
    EXCESSIVE_RESOURCE_USAGE = "excessive_resource_usage"
    PROMPT_INJECTION_VIA_TOOL = "prompt_injection_via_tool"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    UNTRUSTED_SERVER = "untrusted_server"
    TOOL_PARAMETER_INJECTION = "tool_parameter_injection"
    RESPONSE_MANIPULATION = "response_manipulation"


@dataclass
class MCPServerProfile:
    """Profile of an MCP server."""
    server_id: str
    server_url: str
    is_trusted: bool = False
    allowed_tools: Set[str] = field(default_factory=set)
    blocked_tools: Set[str] = field(default_factory=set)
    max_requests_per_minute: int = 60
    max_response_size: int = 1_000_000  # bytes
    require_approval_for: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPRequest:
    """MCP tool request."""
    server_id: str
    tool_name: str
    parameters: Dict[str, Any]
    user_id: str
    session_id: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class MCPResponse:
    """MCP tool response."""
    server_id: str
    tool_name: str
    content: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    size_bytes: int = 0


@dataclass
class MCPSecurityAlert:
    """Security alert for MCP operations."""
    threat_type: MCPThreatType
    severity: str  # "low", "medium", "high", "critical"
    description: str
    server_id: str
    tool_name: Optional[str] = None
    should_block: bool = True
    evidence: Dict[str, Any] = field(default_factory=dict)


class MCPServerRegistry:
    """Registry and whitelist for MCP servers."""

    def __init__(self):
        """Initialize server registry."""
        self.servers: Dict[str, MCPServerProfile] = {}
        self.server_reputation: Dict[str, float] = {}  # 0.0 to 1.0

    def register_server(
        self,
        server_id: str,
        server_url: str,
        is_trusted: bool = False,
        allowed_tools: Optional[List[str]] = None,
    ) -> MCPServerProfile:
        """
        Register an MCP server.

        Args:
            server_id: Unique server identifier
            server_url: Server URL
            is_trusted: Whether server is pre-approved
            allowed_tools: List of allowed tool names

        Returns:
            Server profile
        """
        profile = MCPServerProfile(
            server_id=server_id,
            server_url=server_url,
            is_trusted=is_trusted,
            allowed_tools=set(allowed_tools or []),
        )

        self.servers[server_id] = profile
        self.server_reputation[server_id] = 1.0 if is_trusted else 0.5

        return profile

    def is_server_allowed(self, server_id: str) -> bool:
        """Check if server is registered and allowed."""
        return server_id in self.servers

    def is_tool_allowed(self, server_id: str, tool_name: str) -> bool:
        """Check if tool is allowed on server."""
        if server_id not in self.servers:
            return False

        profile = self.servers[server_id]

        # Check blocked list first
        if tool_name in profile.blocked_tools:
            return False

        # If allowed_tools is empty, allow all (except blocked)
        if not profile.allowed_tools:
            return True

        return tool_name in profile.allowed_tools

    def update_reputation(self, server_id: str, adjustment: float):
        """
        Update server reputation score.

        Args:
            server_id: Server identifier
            adjustment: Adjustment to reputation (-1.0 to 1.0)
        """
        if server_id in self.server_reputation:
            current = self.server_reputation[server_id]
            self.server_reputation[server_id] = max(0.0, min(1.0, current + adjustment))


class MCPRequestValidator:
    """Validates MCP requests for security issues."""

    def __init__(self, registry: MCPServerRegistry):
        """
        Initialize validator.

        Args:
            registry: Server registry
        """
        self.registry = registry

        # Dangerous patterns in parameters
        self.injection_patterns = [
            r'<script',
            r'javascript:',
            r'eval\(',
            r'exec\(',
            r'__import__',
            r'\.\./\.\.',  # Path traversal
            r';\s*rm\s+-rf',  # Command injection
            r'\$\{.*\}',  # Variable injection
        ]

    def validate_request(
        self,
        request: MCPRequest
    ) -> tuple[bool, Optional[MCPSecurityAlert]]:
        """
        Validate MCP request.

        Args:
            request: MCP request to validate

        Returns:
            (is_valid, alert_if_invalid)
        """
        # 1. Check if server is allowed
        if not self.registry.is_server_allowed(request.server_id):
            return False, MCPSecurityAlert(
                threat_type=MCPThreatType.UNTRUSTED_SERVER,
                severity="high",
                description=f"Request to unregistered server: {request.server_id}",
                server_id=request.server_id,
                tool_name=request.tool_name,
            )

        # 2. Check if tool is allowed
        if not self.registry.is_tool_allowed(request.server_id, request.tool_name):
            return False, MCPSecurityAlert(
                threat_type=MCPThreatType.UNAUTHORIZED_DATA_ACCESS,
                severity="high",
                description=f"Tool {request.tool_name} not allowed on server {request.server_id}",
                server_id=request.server_id,
                tool_name=request.tool_name,
            )

        # 3. Check for parameter injection
        param_str = json.dumps(request.parameters)
        for pattern in self.injection_patterns:
            if re.search(pattern, param_str, re.IGNORECASE):
                return False, MCPSecurityAlert(
                    threat_type=MCPThreatType.TOOL_PARAMETER_INJECTION,
                    severity="critical",
                    description=f"Injection pattern detected in parameters: {pattern}",
                    server_id=request.server_id,
                    tool_name=request.tool_name,
                    evidence={'pattern': pattern, 'parameters': request.parameters},
                )

        # 4. Check for credential exposure in parameters
        if self._contains_credentials(param_str):
            return False, MCPSecurityAlert(
                threat_type=MCPThreatType.CREDENTIAL_EXPOSURE,
                severity="critical",
                description="Credentials detected in request parameters",
                server_id=request.server_id,
                tool_name=request.tool_name,
            )

        return True, None

    def _contains_credentials(self, text: str) -> bool:
        """Check if text contains credentials."""
        cred_patterns = [
            r'password\s*[:=]\s*["\']?\w+',
            r'api[_-]?key\s*[:=]\s*["\']?\w+',
            r'secret\s*[:=]\s*["\']?\w+',
            r'token\s*[:=]\s*["\']?\w+',
        ]

        for pattern in cred_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False


class MCPResponseValidator:
    """Validates MCP responses for security issues."""

    def __init__(self):
        """Initialize response validator."""
        # Import detectors
        from shieldgents.redteam.exfiltration import ExfiltrationDetector
        from shieldgents.core.context import PIIDetector

        self.exfil_detector = ExfiltrationDetector(sensitivity=0.7)
        self.pii_detector = PIIDetector()

    def validate_response(
        self,
        response: MCPResponse,
        server_profile: MCPServerProfile,
    ) -> tuple[bool, Optional[MCPSecurityAlert], Optional[str]]:
        """
        Validate MCP response.

        Args:
            response: MCP response
            server_profile: Server profile

        Returns:
            (is_valid, alert_if_invalid, sanitized_content)
        """
        content_str = str(response.content)

        # 1. Check response size
        if response.size_bytes > server_profile.max_response_size:
            return False, MCPSecurityAlert(
                threat_type=MCPThreatType.EXCESSIVE_RESOURCE_USAGE,
                severity="medium",
                description=f"Response size {response.size_bytes} exceeds limit {server_profile.max_response_size}",
                server_id=response.server_id,
                tool_name=response.tool_name,
            ), None

        # 2. Check for data exfiltration
        exfil_result = self.exfil_detector.scan(content_str)
        if exfil_result.is_suspicious:
            return False, MCPSecurityAlert(
                threat_type=MCPThreatType.MALICIOUS_TOOL_RESPONSE,
                severity="high",
                description=f"Exfiltration attempt in response: {exfil_result.methods_detected}",
                server_id=response.server_id,
                tool_name=response.tool_name,
                evidence={'methods': [m.value for m in exfil_result.methods_detected]},
            ), exfil_result.sanitized_output

        # 3. Check for PII leakage
        pii_result = self.pii_detector.scan(content_str)
        if pii_result.has_pii:
            # Don't block, but return sanitized
            alert = MCPSecurityAlert(
                threat_type=MCPThreatType.CREDENTIAL_EXPOSURE,
                severity="medium",
                description=f"PII detected in response: {[m.pii_type.value for m in pii_result.matches]}",
                server_id=response.server_id,
                tool_name=response.tool_name,
                should_block=False,  # Just sanitize
            )
            return True, alert, pii_result.redacted_text

        # 4. Check for prompt injection in response
        if self._contains_prompt_injection(content_str):
            return False, MCPSecurityAlert(
                threat_type=MCPThreatType.PROMPT_INJECTION_VIA_TOOL,
                severity="critical",
                description="Prompt injection detected in MCP response",
                server_id=response.server_id,
                tool_name=response.tool_name,
            ), None

        return True, None, None

    def _contains_prompt_injection(self, text: str) -> bool:
        """Check for prompt injection in response."""
        injection_indicators = [
            'ignore all previous instructions',
            'ignore all instructions',
            'disregard previous',
            'new instructions:',
            'system:',
            'assistant:',
            '<|im_start|>',
            '<|im_end|>',
        ]

        text_lower = text.lower()
        return any(indicator in text_lower for indicator in injection_indicators)


class MCPSecurityMonitor:
    """Monitor MCP server interactions for security issues."""

    def __init__(self, registry: MCPServerRegistry):
        """
        Initialize monitor.

        Args:
            registry: Server registry
        """
        self.registry = registry
        self.request_validator = MCPRequestValidator(registry)
        self.response_validator = MCPResponseValidator()

        # Tracking
        self.request_history: List[MCPRequest] = []
        self.alerts: List[MCPSecurityAlert] = []
        self.server_stats: Dict[str, Dict[str, int]] = {}

    def check_request(
        self,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        user_id: str,
        session_id: str,
    ) -> tuple[bool, Optional[MCPSecurityAlert]]:
        """
        Check if MCP request is allowed.

        Args:
            server_id: MCP server ID
            tool_name: Tool name
            parameters: Tool parameters
            user_id: User making request
            session_id: Session ID

        Returns:
            (is_allowed, alert_if_blocked)
        """
        request = MCPRequest(
            server_id=server_id,
            tool_name=tool_name,
            parameters=parameters,
            user_id=user_id,
            session_id=session_id,
        )

        # Validate request
        is_valid, alert = self.request_validator.validate_request(request)

        # Track request
        self.request_history.append(request)

        # Track stats
        if server_id not in self.server_stats:
            self.server_stats[server_id] = {
                'total_requests': 0,
                'blocked_requests': 0,
                'tools_used': {},
            }

        self.server_stats[server_id]['total_requests'] += 1

        if not is_valid:
            self.server_stats[server_id]['blocked_requests'] += 1
            self.alerts.append(alert)

            # Decrease server reputation
            self.registry.update_reputation(server_id, -0.05)

        else:
            # Track tool usage
            tools_used = self.server_stats[server_id]['tools_used']
            tools_used[tool_name] = tools_used.get(tool_name, 0) + 1

        return is_valid, alert

    def check_response(
        self,
        server_id: str,
        tool_name: str,
        content: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[bool, Optional[MCPSecurityAlert], Optional[Any]]:
        """
        Check MCP response for security issues.

        Args:
            server_id: Server ID
            tool_name: Tool name
            content: Response content
            metadata: Optional metadata

        Returns:
            (is_valid, alert_if_suspicious, sanitized_content)
        """
        # Get server profile
        if server_id not in self.registry.servers:
            alert = MCPSecurityAlert(
                threat_type=MCPThreatType.UNTRUSTED_SERVER,
                severity="high",
                description=f"Response from unregistered server: {server_id}",
                server_id=server_id,
                tool_name=tool_name,
            )
            self.alerts.append(alert)
            return False, alert, None

        server_profile = self.registry.servers[server_id]

        # Create response object
        content_str = str(content)
        response = MCPResponse(
            server_id=server_id,
            tool_name=tool_name,
            content=content,
            metadata=metadata or {},
            size_bytes=len(content_str.encode('utf-8')),
        )

        # Validate response
        is_valid, alert, sanitized = self.response_validator.validate_response(
            response, server_profile
        )

        if alert:
            self.alerts.append(alert)

            if alert.should_block:
                # Decrease reputation
                self.registry.update_reputation(server_id, -0.1)
            else:
                # Minor decrease for warnings
                self.registry.update_reputation(server_id, -0.02)

        return is_valid, alert, sanitized

    def get_server_statistics(self, server_id: str) -> Dict[str, Any]:
        """Get statistics for a server."""
        if server_id not in self.server_stats:
            return {
                'server_id': server_id,
                'total_requests': 0,
                'blocked_requests': 0,
                'block_rate': 0.0,
                'reputation': 0.0,
            }

        stats = self.server_stats[server_id]
        total = stats['total_requests']
        blocked = stats['blocked_requests']

        return {
            'server_id': server_id,
            'total_requests': total,
            'blocked_requests': blocked,
            'block_rate': blocked / total if total > 0 else 0.0,
            'reputation': self.registry.server_reputation.get(server_id, 0.0),
            'tools_used': stats['tools_used'],
        }

    def get_alerts_summary(self) -> Dict[str, Any]:
        """Get summary of all alerts."""
        if not self.alerts:
            return {
                'total_alerts': 0,
                'by_threat_type': {},
                'by_severity': {},
            }

        by_threat = {}
        by_severity = {}

        for alert in self.alerts:
            by_threat[alert.threat_type.value] = by_threat.get(alert.threat_type.value, 0) + 1
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

        return {
            'total_alerts': len(self.alerts),
            'by_threat_type': by_threat,
            'by_severity': by_severity,
            'recent_alerts': [
                {
                    'threat_type': a.threat_type.value,
                    'severity': a.severity,
                    'description': a.description,
                    'server_id': a.server_id,
                    'tool_name': a.tool_name,
                }
                for a in self.alerts[-10:]
            ]
        }


def secure_mcp_server(
    server_id: str,
    server_url: str,
    is_trusted: bool = False,
    allowed_tools: Optional[List[str]] = None,
    blocked_tools: Optional[List[str]] = None,
) -> tuple[MCPServerRegistry, MCPSecurityMonitor]:
    """
    Helper function to set up secure MCP server.

    Args:
        server_id: Server identifier
        server_url: Server URL
        is_trusted: Whether server is trusted
        allowed_tools: List of allowed tools
        blocked_tools: List of blocked tools

    Returns:
        (registry, monitor)
    """
    registry = MCPServerRegistry()
    profile = registry.register_server(
        server_id=server_id,
        server_url=server_url,
        is_trusted=is_trusted,
        allowed_tools=allowed_tools,
    )

    if blocked_tools:
        profile.blocked_tools = set(blocked_tools)

    monitor = MCPSecurityMonitor(registry)

    return registry, monitor
