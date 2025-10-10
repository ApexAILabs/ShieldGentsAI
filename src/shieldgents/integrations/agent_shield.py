"""Agent-centric security integration layer for external frameworks.

The :class:`AgentShield` orchestrates ShieldGents primitives into a single
interface that can be dropped into popular agent frameworks (e.g. LangChain,
Trands) to enforce prompt, behavior, and output security guarantees.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from shieldgents.core.prompts import PromptGuard, ScanResult, ThreatLevel
from shieldgents.core.behavior import (
    ActionType,
    AgentAction,
    BehaviorMonitor,
    BehaviorPolicy,
    OutputGuard,
    RiskLevel,
)
from shieldgents.core.sandbox import ExecutionResult, FunctionSandbox, ResourceLimits
from shieldgents.core.monitor import EventType, SecurityMonitor, Severity
from shieldgents.controls.access import ToolAccessControl
from shieldgents.controls.external_content import ExternalContentGuard, ContentScanResult


class SecurityViolation(Exception):
    """Raised when AgentShield blocks a potentially unsafe operation."""

    def __init__(
        self,
        message: str,
        *,
        violations: Optional[list[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.violations = violations or []
        self.context = context or {}


def _threat_to_severity(threat: ThreatLevel) -> Severity:
    """
    Map prompt threat levels to monitoring severities.

    Args:
        threat: ThreatLevel from prompt guard

    Returns:
        Corresponding Severity level for monitoring
    """
    mapping = {
        ThreatLevel.SAFE: Severity.INFO,
        ThreatLevel.LOW: Severity.INFO,
        ThreatLevel.MEDIUM: Severity.WARNING,
        ThreatLevel.HIGH: Severity.ERROR,
        ThreatLevel.CRITICAL: Severity.CRITICAL,
    }
    return mapping[threat]


@dataclass
class PromptCheck:
    """Structured result for prompt inspection."""

    sanitized_input: str
    scan: ScanResult


@dataclass
class OutputCheck:
    """Structured result for output inspection."""

    sanitized_output: str
    details: Dict[str, Any]


@dataclass
class ExternalContentCheck:
    """Structured result for external content inspection."""

    sanitized_content: str
    scan: ContentScanResult


class AgentShield:
    """Aggregate security layer for agent frameworks.

    The class exposes high-level helpers that tie prompt guarding, behavioral
    monitoring, tool sandboxing, and audit logging together so that security is
    consistently applied regardless of the underlying framework.
    """

    def __init__(
        self,
        *,
        prompt_guard: Optional[PromptGuard] = None,
        behavior_policy: Optional[BehaviorPolicy] = None,
        sandbox: Optional[FunctionSandbox] = None,
        monitor: Optional[SecurityMonitor] = None,
        tool_access: Optional[ToolAccessControl] = None,
        external_content_guard: Optional[ExternalContentGuard] = None,
        block_on_prompt_threat: bool = True,
        block_on_output_violation: bool = True,
        block_on_external_content_threat: bool = True,
        sandbox_limits: Optional[ResourceLimits] = None,
    ) -> None:
        self.prompt_guard = prompt_guard or PromptGuard()
        self.behavior_policy = behavior_policy or BehaviorPolicy(name="default")
        self.behavior_monitor = BehaviorMonitor(self.behavior_policy)
        self.output_guard = OutputGuard(self.behavior_policy)
        self.sandbox = sandbox or FunctionSandbox(limits=sandbox_limits)
        self.monitor = monitor or SecurityMonitor()
        self.tool_access = tool_access
        self.external_content_guard = external_content_guard or ExternalContentGuard()
        self.block_on_prompt_threat = block_on_prompt_threat
        self.block_on_output_violation = block_on_output_violation
        self.block_on_external_content_threat = block_on_external_content_threat
        self._action_observers: list[Callable[[AgentAction], None]] = []

    # ------------------------------------------------------------------
    # Registration utilities
    # ------------------------------------------------------------------
    def register_action_observer(self, observer: Callable[[AgentAction], None]) -> None:
        """Register a callback that sees every approved agent action."""
        self._action_observers.append(observer)

    # ------------------------------------------------------------------
    # Core security primitives
    # ------------------------------------------------------------------
    def guard_prompt(
        self,
        prompt: str,
        *,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        block: Optional[bool] = None,
    ) -> PromptCheck:
        """Inspect an incoming prompt and optionally block it."""
        block_decision = self.block_on_prompt_threat if block is None else block
        scan = self.prompt_guard.guard(prompt)
        sanitized = scan.sanitized_input or prompt

        if not scan.is_safe:
            event_metadata = {
                "patterns": scan.detected_patterns,
                "confidence": scan.confidence,
            }
            if metadata:
                event_metadata.update(metadata)

            self.monitor.record_event(
                event_type=EventType.PROMPT_INJECTION,
                severity=_threat_to_severity(scan.threat_level),
                message="Prompt threat detected",
                agent_id=agent_id,
                metadata=event_metadata,
            )

            if block_decision:
                raise SecurityViolation(
                    message=f"Prompt blocked ({scan.threat_level.value})",
                    violations=scan.detected_patterns,
                    context=event_metadata,
                )

        return PromptCheck(sanitized_input=sanitized, scan=scan)

    def guard_output(
        self,
        output: Any,
        *,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        block: Optional[bool] = None,
    ) -> OutputCheck:
        """Inspect outgoing content before it leaves the agent boundary."""
        block_decision = self.block_on_output_violation if block is None else block
        output_text = output if isinstance(output, str) else str(output)
        details = self.output_guard.check_output(output_text)

        if not details["safe"]:
            event_metadata = {
                "violations": details["violations"],
            }
            if metadata:
                event_metadata.update(metadata)

            self.monitor.record_event(
                event_type=EventType.DATA_ACCESS,
                severity=Severity.ERROR,
                message="Agent output flagged by policy",
                agent_id=agent_id,
                metadata=event_metadata,
            )

            if block_decision:
                raise SecurityViolation(
                    message="Output blocked by AgentShield",
                    violations=details["violations"],
                    context=event_metadata,
                )

        return OutputCheck(
            sanitized_output=details["sanitized_output"],
            details=details,
        )

    def track_action(
        self,
        action_type: ActionType,
        action_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        *,
        agent_id: Optional[str] = None,
        risk_level: Optional[RiskLevel] = None,
    ) -> Dict[str, Any]:
        """Record and validate an agent action coming from external frameworks."""
        action = AgentAction(
            action_type=action_type,
            action_name=action_name,
            parameters=parameters or {},
            agent_id=agent_id,
            risk_level=risk_level or RiskLevel.MEDIUM,
        )

        check = self.behavior_monitor.check_action(action)
        if not check["allowed"]:
            self.monitor.record_event(
                event_type=EventType.PERMISSION_DENIED,
                severity=Severity.ERROR,
                message=f"Action blocked: {action_name}",
                agent_id=agent_id,
                metadata={"violations": check["violations"]},
            )
            raise SecurityViolation(
                message=f"Action '{action_name}' blocked",
                violations=check["violations"],
                context={"action_type": action_type.value},
            )

        self.behavior_monitor.record_action(action, outcome="pending")
        for observer in self._action_observers:
            observer(action)
        return check

    def execute_tool(
        self,
        tool: Callable[..., Any],
        *,
        tool_name: str,
        args: Tuple[Any, ...] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        risk_assessor: Optional[Callable[[str, Dict[str, Any]], RiskLevel]] = None,
    ) -> Any:
        """Execute a tool within the security envelope."""
        kwargs = kwargs or {}

        if self.tool_access:
            if not agent_id:
                raise SecurityViolation(
                    message="Agent identifier required for tool access enforcement",
                    context={"tool": tool_name},
                )

            if not self.tool_access.can_use_tool(agent_id, tool_name):
                self.monitor.record_event(
                    event_type=EventType.PERMISSION_DENIED,
                    severity=Severity.WARNING,
                    message=f"Unauthorized tool access: {tool_name}",
                    agent_id=agent_id,
                    tool_name=tool_name,
                )
                raise SecurityViolation(
                    message=f"Tool '{tool_name}' denied by access policy",
                    context={"tool": tool_name},
                )

        risk = risk_assessor(tool_name, {"args": args, "kwargs": kwargs}) if risk_assessor else None
        check = self.track_action(
            action_type=ActionType.TOOL_CALL,
            action_name=tool_name,
            parameters={"args": args, "kwargs": kwargs},
            agent_id=agent_id,
            risk_level=risk or RiskLevel.MEDIUM,
        )

        execution: ExecutionResult = self.sandbox.execute(tool, args=args, kwargs=kwargs)
        outcome = "success" if execution.success else "failure"

        action = check.get("action")
        if action:
            action.metadata["outcome"] = outcome
            action.metadata["error"] = execution.error
            action.metadata["execution_time"] = execution.execution_time

        self.monitor.record_event(
            event_type=EventType.TOOL_EXECUTION,
            severity=Severity.INFO if execution.success else Severity.ERROR,
            message=f"Tool {tool_name} executed",
            agent_id=agent_id,
            tool_name=tool_name,
            metadata={
                "success": execution.success,
                "error": execution.error,
                "execution_time": execution.execution_time,
            },
        )

        if not execution.success:
            raise SecurityViolation(
                message=f"Tool '{tool_name}' execution failed",
                violations=[execution.error] if execution.error else None,
                context={"tool": tool_name},
            )

        return execution.return_value

    def guard_external_content(
        self,
        content: Any,
        *,
        source_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        block: Optional[bool] = None,
    ) -> ExternalContentCheck:
        """
        Guard external content from web scraping/crawling before agent processes it.

        Args:
            content: External content to guard (string or data structure)
            source_url: Optional source URL where content was fetched
            agent_id: Optional agent identifier
            metadata: Optional metadata for logging
            block: Override block decision (defaults to block_on_external_content_threat)

        Returns:
            ExternalContentCheck with scan results

        Raises:
            SecurityViolation: If content is unsafe and blocking is enabled
        """
        block_decision = (
            self.block_on_external_content_threat if block is None else block
        )

        # Convert content to string if needed
        content_str = content if isinstance(content, str) else str(content)

        # Scan external content
        scan = self.external_content_guard.guard_scraped_content(
            content_str, source_url
        )

        if not scan.is_safe:
            event_metadata = {
                "threats": scan.detected_threats,
                "threat_level": scan.threat_level.value,
                "source_url": source_url,
            }
            if metadata:
                event_metadata.update(metadata)

            self.monitor.record_event(
                event_type=EventType.DATA_ACCESS,
                severity=_threat_to_severity(scan.threat_level),
                message="External content threat detected",
                agent_id=agent_id,
                metadata=event_metadata,
            )

            if block_decision:
                raise SecurityViolation(
                    message=f"External content blocked ({scan.threat_level.value})",
                    violations=scan.detected_threats,
                    context=event_metadata,
                )

        sanitized = scan.sanitized_content or content_str
        return ExternalContentCheck(sanitized_content=sanitized, scan=scan)

    def execute_web_tool(
        self,
        tool: Callable[..., Any],
        *,
        tool_name: str,
        args: Tuple[Any, ...] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        risk_assessor: Optional[Callable[[str, Dict[str, Any]], RiskLevel]] = None,
        guard_result: bool = True,
    ) -> Any:
        """
        Execute a web scraping/crawling tool and automatically guard its output.

        This is a specialized version of execute_tool that adds external content
        guarding on top of standard tool execution security.

        Args:
            tool: Web scraping/crawling tool to execute
            tool_name: Name of the tool
            args: Positional arguments for the tool
            kwargs: Keyword arguments for the tool
            agent_id: Optional agent identifier
            risk_assessor: Optional risk assessment function
            guard_result: Whether to guard the tool's return value

        Returns:
            Tool result (sanitized if guard_result=True and threats detected)

        Raises:
            SecurityViolation: If tool execution fails or content is unsafe
        """
        # First execute the tool normally
        result = self.execute_tool(
            tool,
            tool_name=tool_name,
            args=args,
            kwargs=kwargs,
            agent_id=agent_id,
            risk_assessor=risk_assessor,
        )

        # Guard the result if it's external content
        if guard_result:
            # Try to extract URL from kwargs/args
            source_url = kwargs.get("url") if kwargs else None
            if not source_url and args:
                source_url = args[0] if isinstance(args[0], str) else None

            content_check = self.guard_external_content(
                result,
                source_url=source_url,
                agent_id=agent_id,
                metadata={"tool": tool_name},
            )

            return content_check.sanitized_content

        return result

    # ------------------------------------------------------------------
    # Framework adapters
    # ------------------------------------------------------------------
    def wrap_langchain_runnable(
        self,
        runnable: Any,
        *,
        agent_id: str = "langchain-agent",
        input_key: Optional[str] = None,
    ) -> Any:
        """Wrap a LangChain-style runnable with prompt/output security."""
        if not hasattr(runnable, "invoke"):
            raise TypeError("LangChain integration requires an object with 'invoke'")

        shield = self

        class ShieldedRunnable:
            def __init__(self, base: Any) -> None:
                self._base = base

            def invoke(
                self, input_data: Any, config: Optional[Dict[str, Any]] = None, **kwargs: Any
            ) -> Any:
                prompt_text = shield._extract_prompt(input_data, input_key)
                prompt = shield.guard_prompt(
                    prompt_text,
                    agent_id=agent_id,
                    metadata={"framework": "langchain"},
                ).sanitized_input

                wrapped_input = shield._apply_sanitized_input(input_data, prompt, input_key)
                result = self._base.invoke(wrapped_input, config=config, **kwargs)

                output = shield.guard_output(
                    result,
                    agent_id=agent_id,
                    metadata={"framework": "langchain"},
                )

                if isinstance(result, str):
                    return output.sanitized_output
                return result

            async def ainvoke(
                self, input_data: Any, config: Optional[Dict[str, Any]] = None, **kwargs: Any
            ) -> Any:
                if not hasattr(self._base, "ainvoke"):
                    raise AttributeError("Wrapped runnable does not define 'ainvoke'")

                prompt_text = shield._extract_prompt(input_data, input_key)
                prompt = shield.guard_prompt(
                    prompt_text,
                    agent_id=agent_id,
                    metadata={"framework": "langchain"},
                ).sanitized_input

                wrapped_input = shield._apply_sanitized_input(input_data, prompt, input_key)
                result = await self._base.ainvoke(wrapped_input, config=config, **kwargs)

                output = shield.guard_output(
                    result,
                    agent_id=agent_id,
                    metadata={"framework": "langchain"},
                )

                if isinstance(result, str):
                    return output.sanitized_output
                return result

            def __getattr__(self, item: str) -> Any:
                return getattr(self._base, item)

        return ShieldedRunnable(runnable)

    def wrap_trands_agent(
        self,
        agent: Any,
        *,
        agent_id: str = "trands-agent",
        input_key: Optional[str] = None,
    ) -> Any:
        """Wrap a Trands-style agent (callable/run method) with security hooks."""
        if callable(agent):
            run_callable = agent
        elif hasattr(agent, "run"):
            run_callable = getattr(agent, "run")
        else:
            raise TypeError("Trands integration expects a callable or object with 'run'")

        shield = self

        class ShieldedTrandsAgent:
            def __init__(self, base: Any, runner: Callable[..., Any]) -> None:
                self._base = base
                self._runner = runner

            def run(self, payload: Any, *args: Any, **kwargs: Any) -> Any:
                prompt_text = shield._extract_prompt(payload, input_key)
                prompt = shield.guard_prompt(
                    prompt_text,
                    agent_id=agent_id,
                    metadata={"framework": "trands"},
                ).sanitized_input

                wrapped_payload = shield._apply_sanitized_input(payload, prompt, input_key)
                result = self._runner(wrapped_payload, *args, **kwargs)

                output = shield.guard_output(
                    result,
                    agent_id=agent_id,
                    metadata={"framework": "trands"},
                )

                if isinstance(result, str):
                    return output.sanitized_output
                return result

            def __call__(self, payload: Any, *args: Any, **kwargs: Any) -> Any:
                return self.run(payload, *args, **kwargs)

            def __getattr__(self, item: str) -> Any:
                return getattr(self._base, item)

        return ShieldedTrandsAgent(agent, run_callable)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_prompt(input_data: Any, input_key: Optional[str]) -> str:
        """
        Extract prompt string from various input formats.

        Args:
            input_data: Input data (dict, list, tuple, or string)
            input_key: Optional key to extract from dict

        Returns:
            Extracted prompt string
        """
        if isinstance(input_data, dict):
            key = input_key or "input"
            return str(input_data.get(key, next(iter(input_data.values()), "")))
        if isinstance(input_data, (list, tuple)) and input_data:
            return str(input_data[0])
        return str(input_data)

    @staticmethod
    def _apply_sanitized_input(
        original_input: Any,
        sanitized_prompt: str,
        input_key: Optional[str],
    ) -> Any:
        """
        Apply sanitized prompt back to the original input structure.

        Args:
            original_input: Original input data structure
            sanitized_prompt: Sanitized prompt string
            input_key: Optional key for dict structures

        Returns:
            Input data with sanitized prompt applied
        """
        if isinstance(original_input, dict):
            key = input_key or "input"
            updated = dict(original_input)
            updated[key] = sanitized_prompt
            return updated
        if isinstance(original_input, (list, tuple)) and original_input:
            converted = list(original_input)
            converted[0] = sanitized_prompt
            return type(original_input)(converted)  # preserve tuple/list type
        return sanitized_prompt
