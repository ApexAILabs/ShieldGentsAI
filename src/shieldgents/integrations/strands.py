"""Strands SDK integration for ShieldGents.

This module provides secure wrappers for Strands agents and tools.
"""

from typing import Any, Dict, List, Optional

from shieldgents.core import (
    EventType,
    FunctionSandbox,
    PromptGuard,
    PIIDetector,
    RateLimiter,
    ResourceLimits,
    SecurityMonitor,
    Severity,
)
from shieldgents.governance import AuditEventType, AuditLogger


def create_secure_tool(
    tool_func: Any,
    tool_name: str,
    max_cpu_time: float = 5.0,
    max_memory: int = 256 * 1024 * 1024,
    timeout: float = 10.0,
) -> Any:
    """Wrap a Strands tool with security controls.

    Args:
        tool_func: Original tool function
        tool_name: Tool identifier
        max_cpu_time: Maximum CPU time (seconds)
        max_memory: Maximum memory (bytes)
        timeout: Maximum total time (seconds)

    Returns:
        Secured tool function

    Example:
        ```python
        from shieldgents.integrations.strands import create_secure_tool

        def my_tool(query: str) -> str:
            return f"Result for {query}"

        secure_tool = create_secure_tool(my_tool, "my_tool")
        ```
    """
    sandbox = FunctionSandbox(
        limits=ResourceLimits(
            max_cpu_time=max_cpu_time,
            max_memory=max_memory,
            timeout=timeout,
        )
    )

    monitor = SecurityMonitor()

    def secured_tool(*args: Any, **kwargs: Any) -> Any:
        """Secured version of tool."""
        # Log tool execution
        monitor.record_event(
            event_type=EventType.TOOL_EXECUTION,
            severity=Severity.INFO,
            message=f"Executing tool: {tool_name}",
            tool_name=tool_name,
        )

        # Execute in sandbox
        result = sandbox.execute(tool_func, args, kwargs)

        if not result.success:
            monitor.record_event(
                event_type=EventType.TOOL_EXECUTION,
                severity=Severity.ERROR,
                message=f"Tool execution failed: {result.error}",
                tool_name=tool_name,
            )
            raise RuntimeError(f"Tool {tool_name} failed: {result.error}")

        return result.return_value

    secured_tool.__name__ = f"secure_{tool_name}"
    secured_tool.__doc__ = tool_func.__doc__
    return secured_tool


class SecureStrandsAgent:
    """Security wrapper for Strands Agent.

    Provides multi-layer security:
    - Prompt injection protection
    - PII detection and redaction
    - Rate limiting per user
    - Comprehensive audit logging
    - Tool sandboxing with resource limits
    - Real-time security monitoring

    Example:
        ```python
        from shieldgents.integrations.strands import SecureStrandsAgent

        # Define your tools
        def calculator(expr: str) -> float:
            return eval(expr)

        # Create secure agent
        agent = SecureStrandsAgent(
            agent_id="my-strands-agent",
            tools=[calculator],
            max_requests_per_minute=60
        )

        # Run with security
        result = agent("What is 2 + 2?", user_id="user-123")
        if result["success"]:
            print(result["response"])
        ```
    """

    def __init__(
        self,
        agent_id: str,
        tools: Optional[List[Any]] = None,
        model: Any = None,
        max_requests_per_minute: int = 60,
        log_file: Optional[str] = None,
        enable_audit: bool = True,
        auto_sanitize: bool = True,
    ) -> None:
        """Initialize secure Strands agent.

        Args:
            agent_id: Unique agent identifier
            tools: List of tool functions to register
            model: Language model to use (optional)
            max_requests_per_minute: Rate limit per user
            log_file: Path to audit log file (default: logs/strands_{agent_id}.jsonl)
            enable_audit: Enable audit logging
            auto_sanitize: Automatically sanitize unsafe prompts
        """
        self.agent_id = agent_id

        # Security components
        self.prompt_guard = PromptGuard(auto_sanitize=auto_sanitize)
        self.pii_detector = PIIDetector()
        self.rate_limiter = RateLimiter(max_requests=max_requests_per_minute, window_seconds=60)
        self.monitor = SecurityMonitor()

        # Audit logging
        if enable_audit:
            log_path = log_file or f"logs/strands_{agent_id}.jsonl"
            self.audit = AuditLogger(
                log_file=log_path,
                enable_console=True,
                enable_signatures=True,
            )
        else:
            self.audit = None

        # Wrap tools with security
        self.secured_tools: List[Any] = []
        if tools:
            for idx, tool_func in enumerate(tools):
                tool_name = getattr(tool_func, "__name__", f"tool_{idx}")
                secured_tool = create_secure_tool(tool_func, tool_name)
                self.secured_tools.append(secured_tool)

                # Audit tool registration
                if self.audit:
                    self.audit.log_event(
                        event_type=AuditEventType.CONFIG_CHANGE,
                        action=f"Registered tool: {tool_name}",
                        agent_id=agent_id,
                        resource=tool_name,
                    )

        # Store model reference (for future Strands integration)
        self.model = model

    def __call__(
        self,
        prompt: str,
        user_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Invoke agent with security controls.

        Args:
            prompt: User's input
            user_id: User identifier for rate limiting and auditing
            context: Optional additional context

        Returns:
            Response dictionary with:
                - success: bool
                - response: str (if successful)
                - error: str (if failed)
                - remaining: int (rate limit remaining)
                - security: dict with security metadata
        """
        user_id = user_id or "anonymous"

        # Audit: Agent invocation start
        if self.audit:
            self.audit.log_event(
                event_type=AuditEventType.AGENT_START,
                action="Agent invoked",
                agent_id=self.agent_id,
                user_id=user_id,
            )

        try:
            # 1. Rate limiting
            if not self.rate_limiter.check_rate_limit(user_id):
                self.monitor.record_event(
                    event_type=EventType.THRESHOLD_EXCEEDED,
                    severity=Severity.WARNING,
                    message=f"Rate limit exceeded for user {user_id}",
                    agent_id=self.agent_id,
                )

                if self.audit:
                    self.audit.log_event(
                        event_type=AuditEventType.ACCESS_DENIED,
                        action="Rate limit exceeded",
                        agent_id=self.agent_id,
                        user_id=user_id,
                        outcome="blocked",
                    )

                return {
                    "success": False,
                    "error": "Rate limit exceeded. Please try again later.",
                    "remaining": 0,
                }

            # 2. PII detection
            pii_result = self.pii_detector.scan(prompt)
            if pii_result.has_pii:
                self.monitor.record_event(
                    event_type=EventType.DATA_ACCESS,
                    severity=Severity.WARNING,
                    message=f"PII detected: {[m.pii_type.value for m in pii_result.matches]}",
                    agent_id=self.agent_id,
                    metadata={"user_id": user_id},
                )

                # Use redacted prompt
                prompt = pii_result.redacted_text or prompt

            # 3. Prompt injection protection
            guard_result = self.prompt_guard.guard(prompt)

            if not guard_result.is_safe:
                self.monitor.record_event(
                    event_type=EventType.PROMPT_INJECTION,
                    severity=Severity.ERROR,
                    message=f"Prompt injection detected: {guard_result.threat_level.value}",
                    agent_id=self.agent_id,
                    metadata={
                        "user_id": user_id,
                        "patterns": guard_result.detected_patterns,
                    },
                )

                if self.audit:
                    self.audit.log_event(
                        event_type=AuditEventType.PROMPT_INJECTION,
                        action="Blocked unsafe prompt",
                        agent_id=self.agent_id,
                        user_id=user_id,
                        outcome="blocked",
                        metadata={
                            "threat_level": guard_result.threat_level.value,
                            "patterns": guard_result.detected_patterns,
                        },
                    )

                return {
                    "success": False,
                    "error": "Input blocked due to security concerns.",
                    "threat_level": guard_result.threat_level.value,
                    "patterns": guard_result.detected_patterns,
                }

            # Use sanitized prompt
            safe_prompt = guard_result.sanitized_input or prompt

            # 4. Invoke agent (override this in production with real Strands agent)
            response = self._execute_agent(safe_prompt, context)

            # 5. Audit successful execution
            if self.audit:
                self.audit.log_event(
                    event_type=AuditEventType.AGENT_STOP,
                    action="Agent completed successfully",
                    agent_id=self.agent_id,
                    user_id=user_id,
                    outcome="success",
                )

            return {
                "success": True,
                "response": response,
                "remaining": self.rate_limiter.get_remaining(user_id),
                "security": {
                    "pii_detected": pii_result.has_pii,
                    "threat_level": guard_result.threat_level.value,
                },
            }

        except Exception as e:
            # Log error
            self.monitor.record_event(
                event_type=EventType.TOOL_EXECUTION,
                severity=Severity.ERROR,
                message=f"Agent execution failed: {str(e)}",
                agent_id=self.agent_id,
                metadata={"user_id": user_id},
            )

            if self.audit:
                self.audit.log_event(
                    event_type=AuditEventType.AGENT_STOP,
                    action="Agent failed",
                    agent_id=self.agent_id,
                    user_id=user_id,
                    outcome="failure",
                    metadata={"error": str(e)},
                )

            return {
                "success": False,
                "error": "An error occurred processing your request.",
            }

    def _execute_agent(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Execute the actual agent logic.

        Override this method to integrate with real Strands SDK:
        ```python
        from strands import Agent

        class MySecureStrandsAgent(SecureStrandsAgent):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.strands_agent = Agent(
                    tools=self.secured_tools,
                    model=self.model
                )

            def _execute_agent(self, prompt, context):
                return self.strands_agent(prompt)
        ```

        Args:
            prompt: Sanitized user prompt
            context: Optional additional context

        Returns:
            Agent response string
        """
        # Simplified example - override in production
        return f"Processed: {prompt}"

    def get_metrics(self) -> Dict[str, Any]:
        """Get security metrics and audit summary.

        Returns:
            Dictionary with security metrics and audit data
        """
        metrics = {
            "agent_id": self.agent_id,
            "security_metrics": self.monitor.get_dashboard_data(),
        }

        if self.audit:
            metrics["audit_summary"] = self.audit.generate_report()

        return metrics


__all__ = [
    "SecureStrandsAgent",
    "create_secure_tool",
]
