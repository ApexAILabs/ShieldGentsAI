"""LangChain integration for ShieldGents.

This module provides secure wrappers for LangChain agents and tools.
"""

from typing import Any, Dict, Optional

from shieldgents.core import (
    EventType,
    FunctionSandbox,
    PromptGuard,
    PIIDetector,
    RateLimiter,
    ResourceLimits,
    SecurityMonitor,
    Severity,
    ToolWrapper,
)


class SecureLangChainAgent:
    """Security-hardened wrapper for LangChain agents.

    Features:
    - Prompt injection protection
    - PII detection and redaction
    - Rate limiting per user
    - Tool sandboxing with resource limits
    - Comprehensive security monitoring
    - Anomaly detection

    Example:
        ```python
        from shieldgents.integrations.langchain import SecureLangChainAgent

        # Create secure agent
        agent = SecureLangChainAgent(
            agent_id="my-agent",
            max_requests_per_minute=60
        )

        # Add tools
        agent.register_tool("web_search", web_search_func)

        # Run with security
        response = agent.run("Search for Python tutorials", user_id="user-123")
        ```
    """

    def __init__(
        self,
        agent_id: str = "langchain-agent",
        max_requests_per_minute: int = 60,
        max_cpu_time: float = 10.0,
        max_memory: int = 512 * 1024 * 1024,  # 512 MB
        timeout: float = 30.0,
        auto_sanitize: bool = True,
    ) -> None:
        """Initialize secure LangChain agent.

        Args:
            agent_id: Unique agent identifier
            max_requests_per_minute: Rate limit for user requests
            max_cpu_time: Maximum CPU time per tool execution (seconds)
            max_memory: Maximum memory per tool execution (bytes)
            timeout: Maximum total time per tool execution (seconds)
            auto_sanitize: Automatically sanitize unsafe prompts
        """
        self.agent_id = agent_id

        # Security components
        self.prompt_guard = PromptGuard(auto_sanitize=auto_sanitize)
        self.pii_detector = PIIDetector()
        self.rate_limiter = RateLimiter(
            max_requests=max_requests_per_minute,
            window_seconds=60
        )
        self.monitor = SecurityMonitor()
        self.tool_wrapper = ToolWrapper(
            sandbox=FunctionSandbox(
                limits=ResourceLimits(
                    max_cpu_time=max_cpu_time,
                    max_memory=max_memory,
                    timeout=timeout,
                )
            )
        )

        # Tool registry
        self.tools: Dict[str, Any] = {}

    def register_tool(self, name: str, func: Any) -> None:
        """Register a tool with security wrapping.

        Args:
            name: Tool name
            func: Tool function to wrap
        """
        self.tools[name] = self.tool_wrapper.wrap(name, func)

        self.monitor.record_event(
            event_type=EventType.TOOL_EXECUTION,
            severity=Severity.INFO,
            message=f"Registered tool: {name}",
            agent_id=self.agent_id,
        )

    def run(
        self,
        user_input: str,
        user_id: str = "unknown",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute agent with full security controls.

        Args:
            user_input: User's prompt
            user_id: User identifier for rate limiting and tracking
            context: Optional additional context

        Returns:
            Response dictionary with:
                - success: bool
                - response: str (if successful)
                - error: str (if failed)
                - security: dict with security metadata
        """
        # 1. Rate limiting
        if not self.rate_limiter.check_rate_limit(user_id):
            self.monitor.record_event(
                event_type=EventType.THRESHOLD_EXCEEDED,
                severity=Severity.WARNING,
                message=f"Rate limit exceeded for user {user_id}",
                agent_id=self.agent_id,
            )

            return {
                "success": False,
                "error": "Rate limit exceeded. Please try again later.",
                "remaining": 0,
            }

        # 2. PII detection and redaction
        pii_result = self.pii_detector.scan(user_input)
        pii_detected = pii_result.has_pii

        if pii_detected:
            self.monitor.record_event(
                event_type=EventType.DATA_ACCESS,
                severity=Severity.WARNING,
                message=f"PII detected: {[m.pii_type.value for m in pii_result.matches]}",
                agent_id=self.agent_id,
                metadata={"user_id": user_id},
            )
            # Use redacted version
            user_input = pii_result.redacted_text or user_input

        # 3. Prompt injection protection
        guard_result = self.prompt_guard.guard(user_input)

        if not guard_result.is_safe:
            self.monitor.record_event(
                event_type=EventType.PROMPT_INJECTION,
                severity=Severity.ERROR,
                message=f"Blocked unsafe input: {guard_result.threat_level.value}",
                agent_id=self.agent_id,
                metadata={
                    "user_id": user_id,
                    "patterns": guard_result.detected_patterns,
                },
            )

            return {
                "success": False,
                "error": "Input blocked due to security concerns.",
                "threat_level": guard_result.threat_level.value,
                "patterns": guard_result.detected_patterns,
            }

        # Use sanitized input if available
        safe_input = guard_result.sanitized_input or user_input

        # 4. Log execution start
        self.monitor.record_event(
            event_type=EventType.TOOL_EXECUTION,
            severity=Severity.INFO,
            message="Agent execution started",
            agent_id=self.agent_id,
            metadata={"user_id": user_id},
        )

        try:
            # 5. Execute agent logic
            response = self._execute_agent(safe_input, context)

            # 6. Monitor for anomalies
            response_length = len(response)
            self.monitor.check_anomaly(
                metric_name="response_length",
                value=float(response_length),
            )

            return {
                "success": True,
                "response": response,
                "remaining": self.rate_limiter.get_remaining(user_id),
                "security": {
                    "pii_detected": pii_detected,
                    "threat_level": guard_result.threat_level.value,
                },
            }

        except Exception as e:
            # Log errors
            self.monitor.record_event(
                event_type=EventType.TOOL_EXECUTION,
                severity=Severity.ERROR,
                message=f"Agent execution failed: {str(e)}",
                agent_id=self.agent_id,
                metadata={"user_id": user_id},
            )

            return {
                "success": False,
                "error": "An error occurred while processing your request.",
            }

    def _execute_agent(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Execute the actual agent logic.

        Override this method in subclasses to implement custom agent behavior.

        Args:
            prompt: Sanitized user prompt
            context: Optional additional context

        Returns:
            Agent response string
        """
        # Simplified example - override in production
        if "search" in prompt.lower() and "web_search" in self.tools:
            return self.tools["web_search"](prompt)
        else:
            return f"Processed: {prompt}"

    def get_metrics(self) -> Dict[str, Any]:
        """Get security metrics and monitoring data.

        Returns:
            Dictionary with security metrics
        """
        return {
            "agent_id": self.agent_id,
            "metrics": self.monitor.get_dashboard_data(),
        }


__all__ = ["SecureLangChainAgent"]
