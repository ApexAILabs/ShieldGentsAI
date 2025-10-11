"""Behavioral security for agentic AI systems.

This module focuses on securing AGENT BEHAVIOR rather than just input validation.
It monitors and controls:
- What tools agents can use
- What actions agents take
- What resources agents access
- What data agents output
- What sequences of actions are allowed
"""

from typing import Any, Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import time


class ActionType(Enum):
    """Types of actions an agent can take."""

    TOOL_CALL = "tool_call"
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    DATA_DELETE = "data_delete"
    API_CALL = "api_call"
    FILE_ACCESS = "file_access"
    NETWORK_REQUEST = "network_request"
    MODEL_INFERENCE = "model_inference"


class RiskLevel(Enum):
    """Risk levels for agent actions."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentAction:
    """Represents an action taken by an agent."""

    action_type: ActionType
    action_name: str
    parameters: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    agent_id: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorPolicy:
    """Policy defining allowed/forbidden agent behaviors."""

    name: str

    # Tool restrictions
    allowed_tools: Optional[Set[str]] = None
    forbidden_tools: Set[str] = field(default_factory=set)

    # Action restrictions
    allowed_actions: Optional[Set[ActionType]] = None
    forbidden_actions: Set[ActionType] = field(default_factory=set)

    # Resource restrictions
    max_tool_calls_per_minute: int = 100
    max_api_calls_per_minute: int = 50
    max_data_access_per_minute: int = 100

    # Sequence restrictions
    forbidden_sequences: List[List[str]] = field(default_factory=list)

    # Output restrictions
    max_output_length: int = 10000
    forbidden_output_patterns: List[str] = field(default_factory=list)


class BehaviorMonitor:
    """
    Monitors agent behavior in real-time.

    This is the key difference: instead of just checking prompts,
    we monitor what the agent actually DOES.
    """

    def __init__(self, policy: BehaviorPolicy, window_size: int = 100):
        """
        Initialize behavior monitor.

        Args:
            policy: Behavior policy to enforce
            window_size: Size of action history window
        """
        self.policy = policy
        self.action_history: deque = deque(maxlen=window_size)
        self.action_counts: Dict[str, List[float]] = {}

    def check_action(self, action: AgentAction) -> Dict[str, Any]:
        """
        Check if an action is allowed before the agent executes it.

        Args:
            action: Action the agent wants to take

        Returns:
            Dict with allowed status and reason
        """
        violations = []

        # 1. Check tool restrictions
        if action.action_type == ActionType.TOOL_CALL:
            tool_name = action.action_name

            if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
                violations.append(f"Tool '{tool_name}' not in allowed list")

            if tool_name in self.policy.forbidden_tools:
                violations.append(f"Tool '{tool_name}' is forbidden")

        # 2. Check action type restrictions
        if self.policy.allowed_actions and action.action_type not in self.policy.allowed_actions:
            violations.append(f"Action type '{action.action_type.value}' not allowed")

        if action.action_type in self.policy.forbidden_actions:
            violations.append(f"Action type '{action.action_type.value}' is forbidden")

        # 3. Check rate limits
        rate_violation = self._check_rate_limits(action)
        if rate_violation:
            violations.append(rate_violation)

        # 4. Check dangerous sequences
        if self._is_dangerous_sequence(action):
            violations.append("Action creates dangerous sequence")

        # 5. Check risk level
        if action.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Require additional checks for high-risk actions
            violations.append(f"High-risk action requires approval: {action.risk_level.value}")

        return {
            "allowed": len(violations) == 0,
            "violations": violations,
            "action": action,
        }

    def record_action(self, action: AgentAction, outcome: str = "success") -> None:
        """
        Record an action that was actually executed.

        Args:
            action: Action that was executed
            outcome: Result of the action (success/failure)
        """
        action.metadata["outcome"] = outcome
        self.action_history.append(action)

        # Track for rate limiting
        action_key = f"{action.action_type.value}:{action.action_name}"
        if action_key not in self.action_counts:
            self.action_counts[action_key] = []
        self.action_counts[action_key].append(action.timestamp)

    def get_recent_actions(self, limit: int = 10) -> List[AgentAction]:
        """Get recent actions."""
        return list(self.action_history)[-limit:]

    def _check_rate_limits(self, action: AgentAction) -> Optional[str]:
        """Check if action exceeds rate limits."""
        now = time.time()
        one_minute_ago = now - 60

        action_key = f"{action.action_type.value}:{action.action_name}"
        recent_actions = [t for t in self.action_counts.get(action_key, []) if t > one_minute_ago]

        # Check specific rate limits
        if action.action_type == ActionType.TOOL_CALL:
            if len(recent_actions) >= self.policy.max_tool_calls_per_minute:
                return (
                    f"Tool call rate limit exceeded ({self.policy.max_tool_calls_per_minute}/min)"
                )

        elif action.action_type == ActionType.API_CALL:
            if len(recent_actions) >= self.policy.max_api_calls_per_minute:
                return f"API call rate limit exceeded ({self.policy.max_api_calls_per_minute}/min)"

        return None

    def _is_dangerous_sequence(self, action: AgentAction) -> bool:
        """Check if action creates a dangerous sequence."""
        recent = [a.action_name for a in list(self.action_history)[-5:]]
        recent.append(action.action_name)

        for forbidden_seq in self.policy.forbidden_sequences:
            if self._sequence_matches(recent, forbidden_seq):
                return True

        return False

    def _sequence_matches(self, actions: List[str], pattern: List[str]) -> bool:
        """Check if action sequence matches forbidden pattern."""
        if len(actions) < len(pattern):
            return False

        for i in range(len(actions) - len(pattern) + 1):
            if actions[i : i + len(pattern)] == pattern:
                return True

        return False


class OutputGuard:
    """
    Guards agent OUTPUT instead of input.

    Checks what the agent is about to return/do, not what the user asked.
    """

    def __init__(self, policy: BehaviorPolicy):
        """Initialize output guard."""
        self.policy = policy

    def check_output(self, output: str) -> Dict[str, Any]:
        """
        Check if agent output is safe to return.

        Args:
            output: What the agent wants to output

        Returns:
            Dict with safe status and sanitized output
        """
        violations = []

        # 1. Check length
        if len(output) > self.policy.max_output_length:
            violations.append(f"Output too long: {len(output)} > {self.policy.max_output_length}")
            output = output[: self.policy.max_output_length] + "... [truncated]"

        # 2. Check forbidden patterns
        import re

        for pattern in self.policy.forbidden_output_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                violations.append(f"Output contains forbidden pattern: {pattern}")
                # Redact the pattern
                output = re.sub(pattern, "[REDACTED]", output, flags=re.IGNORECASE)

        # 3. Check for data leakage
        # (e.g., system prompts, internal configs, credentials)
        sensitive_patterns = [
            r"system\s*prompt:",
            r"internal\s*config:",
            r"api[_-]key\s*[:=]",
            r"password\s*[:=]",
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                violations.append("Output may contain sensitive data")
                output = re.sub(pattern, "[SENSITIVE DATA REDACTED]", output, flags=re.IGNORECASE)

        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "sanitized_output": output,
            "original_length": len(output),
        }


class ToolExecutionGuard:
    """
    Guards tool execution - checks if agent should be allowed to execute a tool.

    This is BEHAVIORAL security: what the agent wants to DO, not what user said.
    """

    def __init__(self, monitor: BehaviorMonitor):
        """Initialize tool execution guard."""
        self.monitor = monitor

    def guard_execution(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_id: str,
        risk_assessment: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """
        Decide if tool execution should be allowed.

        Args:
            tool_name: Name of tool to execute
            tool_args: Arguments for the tool
            agent_id: ID of agent requesting execution
            risk_assessment: Optional function to assess risk

        Returns:
            Dict with allowed status and details
        """
        # Create action
        action = AgentAction(
            action_type=ActionType.TOOL_CALL,
            action_name=tool_name,
            parameters=tool_args,
            agent_id=agent_id,
        )

        # Assess risk
        if risk_assessment:
            action.risk_level = risk_assessment(tool_name, tool_args)
        else:
            action.risk_level = self._default_risk_assessment(tool_name, tool_args)

        # Check if allowed
        check_result = self.monitor.check_action(action)

        if check_result["allowed"]:
            # Record that we're allowing this
            self.monitor.record_action(action, outcome="pending")

        return check_result

    def record_execution_result(
        self,
        tool_name: str,
        success: bool,
        result: Any = None,
        error: Optional[str] = None,
    ) -> None:
        """Record the result of a tool execution."""
        # Find the pending action and update it
        recent = self.monitor.get_recent_actions(limit=10)
        for action in reversed(recent):
            if action.action_name == tool_name and action.metadata.get("outcome") == "pending":

                action.metadata["outcome"] = "success" if success else "failure"
                action.metadata["result_summary"] = str(result)[:100] if result else None
                action.metadata["error"] = error
                break

    def _default_risk_assessment(self, tool_name: str, tool_args: Dict[str, Any]) -> RiskLevel:
        """Default risk assessment for tool execution."""
        # High-risk tools
        if any(keyword in tool_name.lower() for keyword in ["delete", "remove", "drop", "destroy"]):
            return RiskLevel.HIGH

        # Medium-risk tools
        if any(keyword in tool_name.lower() for keyword in ["write", "update", "create", "modify"]):
            return RiskLevel.MEDIUM

        # Low-risk tools (read-only)
        return RiskLevel.LOW


def create_secure_agent_wrapper(
    agent: Any,
    policy: BehaviorPolicy,
) -> Callable:
    """
    Wrap an agent to enforce behavioral security.

    Args:
        agent: The agent to wrap
        policy: Behavior policy to enforce

    Returns:
        Wrapped agent function
    """
    monitor = BehaviorMonitor(policy)
    _ = ToolExecutionGuard(monitor)  # Initialize guard
    output_guard = OutputGuard(policy)

    def secure_agent(prompt: str, agent_id: str = "default") -> Dict[str, Any]:
        """Secured agent that enforces behavioral policies."""

        # Note: We don't check the PROMPT here!
        # We check what the AGENT wants to DO.

        try:
            # Execute agent (it will try to use tools)
            # In production, you'd intercept tool calls here
            result = agent(prompt)

            # Check OUTPUT behavior
            output_check = output_guard.check_output(str(result))

            if not output_check["safe"]:
                return {
                    "success": False,
                    "error": "Output blocked by security policy",
                    "violations": output_check["violations"],
                }

            return {
                "success": True,
                "result": output_check["sanitized_output"],
                "behavioral_checks": {
                    "actions_monitored": len(monitor.action_history),
                    "recent_actions": [a.action_name for a in monitor.get_recent_actions(5)],
                },
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    return secure_agent
