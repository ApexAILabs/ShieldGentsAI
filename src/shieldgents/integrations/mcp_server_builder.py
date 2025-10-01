"""Shielded MCP Server Builder.

Build MCP servers with built-in ShieldGents security:
- Automatic request/response validation
- Rate limiting per user
- Audit logging
- PII detection and redaction
- Tool sandboxing
- Security monitoring

Example:
    from shieldgents.integrations import create_shielded_mcp_server

    # Define tools
    def search(query: str) -> str:
        return f"Results for: {query}"

    # Create secure server
    server = create_shielded_mcp_server(
        name="my-secure-server",
        tools=[search],
        enable_pii_redaction=True,
        enable_rate_limiting=True
    )

    # Server automatically has all security built-in!
    server.run(port=8080)
"""

from typing import Callable, List, Optional, Dict, Any
from dataclasses import dataclass, field
import functools
import json
from datetime import datetime

# Import ShieldGents security modules
from shieldgents.core.prompts import PromptGuard
from shieldgents.core.context import PIIDetector, RateLimiter
from shieldgents.core.sandbox import FunctionSandbox, ResourceLimits, ToolWrapper
from shieldgents.core.monitor import SecurityMonitor, EventType, Severity
from shieldgents.governance.audit import AuditLogger, AuditEventType
from shieldgents.redteam.exfiltration import ExfiltrationDetector
from shieldgents.integrations.mcp_security import MCPSecurityMonitor, MCPServerRegistry


@dataclass
class MCPToolDefinition:
    """Definition of an MCP tool."""
    name: str
    function: Callable
    description: str
    parameters_schema: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    sandbox: bool = True


@dataclass
class MCPServerConfig:
    """Configuration for shielded MCP server."""
    name: str
    description: str = "Secure MCP Server"

    # Security settings
    enable_prompt_guard: bool = True
    enable_pii_redaction: bool = True
    enable_rate_limiting: bool = True
    enable_exfiltration_detection: bool = True
    enable_sandboxing: bool = True
    enable_audit_logging: bool = True

    # Limits
    max_requests_per_minute: int = 60
    max_response_size: int = 1_000_000
    sandbox_cpu_time: float = 30.0
    sandbox_memory: int = 512 * 1024 * 1024
    sandbox_timeout: float = 60.0

    # Sensitivity
    pii_sensitivity: float = 0.8
    exfiltration_sensitivity: float = 0.7


class ShieldedMCPServer:
    """MCP Server with built-in ShieldGents security."""

    def __init__(
        self,
        config: MCPServerConfig,
        tools: List[MCPToolDefinition],
    ):
        """
        Initialize shielded MCP server.

        Args:
            config: Server configuration
            tools: List of tool definitions
        """
        self.config = config
        self.tools_dict: Dict[str, MCPToolDefinition] = {
            tool.name: tool for tool in tools
        }

        # Initialize security components
        if config.enable_prompt_guard:
            self.prompt_guard = PromptGuard(auto_sanitize=True)
        else:
            self.prompt_guard = None

        if config.enable_pii_redaction:
            self.pii_detector = PIIDetector()
        else:
            self.pii_detector = None

        if config.enable_rate_limiting:
            self.rate_limiter = RateLimiter(
                max_requests=config.max_requests_per_minute,
                window_seconds=60
            )
        else:
            self.rate_limiter = None

        if config.enable_exfiltration_detection:
            self.exfil_detector = ExfiltrationDetector(
                sensitivity=config.exfiltration_sensitivity
            )
        else:
            self.exfil_detector = None

        if config.enable_sandboxing:
            self.sandbox = FunctionSandbox(
                limits=ResourceLimits(
                    max_cpu_time=config.sandbox_cpu_time,
                    max_memory=config.sandbox_memory,
                    timeout=config.sandbox_timeout,
                )
            )
            self.tool_wrapper = ToolWrapper(sandbox=self.sandbox)
        else:
            self.sandbox = None
            self.tool_wrapper = None

        if config.enable_audit_logging:
            self.audit = AuditLogger(
                log_file=f"logs/{config.name}_audit.jsonl",
                enable_console=True,
                enable_signatures=True,
            )
        else:
            self.audit = None

        self.monitor = SecurityMonitor()

        # Server state
        self.request_count = 0
        self.error_count = 0

    def handle_request(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        user_id: str = "default",
        session_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Handle MCP tool request with security checks.

        Args:
            tool_name: Name of tool to call
            parameters: Tool parameters
            user_id: User identifier
            session_id: Session identifier

        Returns:
            Response dictionary
        """
        self.request_count += 1
        start_time = datetime.now()

        # Log request
        if self.audit:
            self.audit.log_event(
                event_type=AuditEventType.AGENT_START,
                action=f"MCP tool call: {tool_name}",
                agent_id=self.config.name,
                user_id=user_id,
                resource=tool_name,
                metadata={"session_id": session_id},
            )

        try:
            # 1. Check if tool exists
            if tool_name not in self.tools_dict:
                return self._error_response(
                    f"Tool not found: {tool_name}",
                    user_id,
                    session_id
                )

            tool_def = self.tools_dict[tool_name]

            # 2. Rate limiting
            if self.rate_limiter:
                if not self.rate_limiter.check_rate_limit(user_id):
                    self.monitor.record_event(
                        event_type=EventType.THRESHOLD_EXCEEDED,
                        severity=Severity.WARNING,
                        message=f"Rate limit exceeded for user {user_id}",
                    )

                    return self._error_response(
                        "Rate limit exceeded",
                        user_id,
                        session_id,
                        retry_after=60
                    )

            # 3. Parameter validation (prompt injection in params)
            if self.prompt_guard:
                params_str = json.dumps(parameters)
                guard_result = self.prompt_guard.guard(params_str)

                if not guard_result.is_safe:
                    self.monitor.record_event(
                        event_type=EventType.PROMPT_INJECTION,
                        severity=Severity.ERROR,
                        message=f"Prompt injection in parameters: {tool_name}",
                    )

                    return self._error_response(
                        "Invalid parameters detected",
                        user_id,
                        session_id
                    )

            # 4. PII detection in parameters
            if self.pii_detector:
                pii_result = self.pii_detector.scan(json.dumps(parameters))
                if pii_result.has_pii:
                    self.monitor.record_event(
                        event_type=EventType.DATA_ACCESS,
                        severity=Severity.WARNING,
                        message=f"PII in parameters: {[m.pii_type.value for m in pii_result.matches]}",
                    )

                    # Warn but don't block
                    if self.audit:
                        self.audit.log_event(
                            event_type=AuditEventType.DATA_ACCESS,
                            action="PII detected in request parameters",
                            user_id=user_id,
                            outcome="warning",
                        )

            # 5. Execute tool
            if tool_def.sandbox and self.tool_wrapper:
                # Execute in sandbox
                result = self.sandbox.execute(
                    tool_def.function,
                    args=(),
                    kwargs=parameters
                )

                if not result.success:
                    return self._error_response(
                        f"Tool execution failed: {result.error}",
                        user_id,
                        session_id
                    )

                response_content = result.return_value
            else:
                # Execute directly (not sandboxed)
                response_content = tool_def.function(**parameters)

            # 6. Response validation
            response_str = str(response_content)

            # Check exfiltration
            if self.exfil_detector:
                exfil_result = self.exfil_detector.scan(response_str)

                if exfil_result.is_suspicious:
                    self.monitor.record_event(
                        event_type=EventType.DATA_ACCESS,
                        severity=Severity.ERROR,
                        message=f"Exfiltration attempt in response: {exfil_result.methods_detected}",
                    )

                    if self.audit:
                        self.audit.log_event(
                            event_type=AuditEventType.DATA_ACCESS,
                            action="Exfiltration attempt blocked",
                            user_id=user_id,
                            outcome="blocked",
                        )

                    return self._error_response(
                        "Suspicious response blocked",
                        user_id,
                        session_id
                    )

            # Check PII in response
            if self.pii_detector:
                pii_result = self.pii_detector.scan(response_str)

                if pii_result.has_pii:
                    # Redact PII
                    response_content = pii_result.redacted_text

                    self.monitor.record_event(
                        event_type=EventType.DATA_ACCESS,
                        severity=Severity.INFO,
                        message=f"PII redacted in response: {[m.pii_type.value for m in pii_result.matches]}",
                    )

            # 7. Success audit log
            if self.audit:
                self.audit.log_event(
                    event_type=AuditEventType.AGENT_STOP,
                    action=f"MCP tool call successful: {tool_name}",
                    agent_id=self.config.name,
                    user_id=user_id,
                    outcome="success",
                )

            duration = (datetime.now() - start_time).total_seconds()

            return {
                "success": True,
                "tool": tool_name,
                "result": response_content,
                "metadata": {
                    "user_id": user_id,
                    "session_id": session_id,
                    "duration_seconds": duration,
                    "server_name": self.config.name,
                }
            }

        except Exception as e:
            self.error_count += 1
            return self._error_response(
                f"Tool execution error: {str(e)}",
                user_id,
                session_id
            )

    def _error_response(
        self,
        error: str,
        user_id: str,
        session_id: str,
        retry_after: Optional[int] = None
    ) -> Dict[str, Any]:
        """Create error response."""
        self.error_count += 1

        if self.audit:
            self.audit.log_event(
                event_type=AuditEventType.AGENT_STOP,
                action="MCP request failed",
                agent_id=self.config.name,
                user_id=user_id,
                outcome="failure",
                metadata={"error": error},
            )

        response = {
            "success": False,
            "error": error,
            "metadata": {
                "user_id": user_id,
                "session_id": session_id,
            }
        }

        if retry_after:
            response["retry_after"] = retry_after

        return response

    def get_server_info(self) -> Dict[str, Any]:
        """Get server information and capabilities."""
        return {
            "name": self.config.name,
            "description": self.config.description,
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters_schema,
                    "requires_approval": tool.requires_approval,
                }
                for tool in self.tools_dict.values()
            ],
            "security_features": {
                "prompt_guard": self.config.enable_prompt_guard,
                "pii_redaction": self.config.enable_pii_redaction,
                "rate_limiting": self.config.enable_rate_limiting,
                "exfiltration_detection": self.config.enable_exfiltration_detection,
                "sandboxing": self.config.enable_sandboxing,
                "audit_logging": self.config.enable_audit_logging,
            },
            "statistics": {
                "total_requests": self.request_count,
                "total_errors": self.error_count,
                "error_rate": self.error_count / self.request_count if self.request_count > 0 else 0.0,
            }
        }

    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics."""
        dashboard = self.monitor.get_dashboard_data()

        metrics = {
            "server_name": self.config.name,
            "security_events": dashboard["metrics"]["counters"],
            "recent_events": dashboard["recent_events"][-10:],
        }

        if self.audit:
            metrics["audit_report"] = self.audit.generate_report()

        return metrics


def create_shielded_mcp_server(
    name: str,
    tools: List[Callable],
    description: str = "Secure MCP Server",
    enable_all_security: bool = True,
    **security_options
) -> ShieldedMCPServer:
    """
    Create a shielded MCP server with automatic security.

    Args:
        name: Server name
        tools: List of tool functions
        description: Server description
        enable_all_security: Enable all security features
        **security_options: Override specific security settings

    Returns:
        ShieldedMCPServer instance

    Example:
        >>> def search(query: str) -> str:
        ...     return f"Results for {query}"
        ...
        >>> def calculator(expression: str) -> float:
        ...     return eval(expression, {"__builtins__": {}})
        ...
        >>> server = create_shielded_mcp_server(
        ...     name="my-server",
        ...     tools=[search, calculator],
        ...     enable_pii_redaction=True
        ... )
        ...
        >>> result = server.handle_request(
        ...     tool_name="search",
        ...     parameters={"query": "hello"},
        ...     user_id="user123"
        ... )
    """
    # Create config
    config = MCPServerConfig(name=name, description=description)

    if not enable_all_security:
        config.enable_prompt_guard = False
        config.enable_pii_redaction = False
        config.enable_rate_limiting = False
        config.enable_exfiltration_detection = False
        config.enable_sandboxing = False
        config.enable_audit_logging = False

    # Apply overrides
    for key, value in security_options.items():
        if hasattr(config, key):
            setattr(config, key, value)

    # Wrap tools
    tool_definitions = []
    for func in tools:
        tool_def = MCPToolDefinition(
            name=func.__name__,
            function=func,
            description=func.__doc__ or f"Tool: {func.__name__}",
            sandbox=config.enable_sandboxing,
        )
        tool_definitions.append(tool_def)

    return ShieldedMCPServer(config=config, tools=tool_definitions)


def tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    requires_approval: bool = False,
    sandbox: bool = True,
    **parameters_schema
):
    """
    Decorator to define MCP tools with metadata.

    Args:
        name: Tool name (defaults to function name)
        description: Tool description
        requires_approval: Whether tool requires approval
        sandbox: Whether to run in sandbox
        **parameters_schema: JSON schema for parameters

    Example:
        >>> @tool(description="Search the web", sandbox=True)
        ... def search(query: str) -> str:
        ...     return f"Results for {query}"
    """
    def decorator(func: Callable) -> Callable:
        func._mcp_tool_name = name or func.__name__
        func._mcp_description = description or func.__doc__ or ""
        func._mcp_requires_approval = requires_approval
        func._mcp_sandbox = sandbox
        func._mcp_parameters_schema = parameters_schema
        return func

    return decorator
