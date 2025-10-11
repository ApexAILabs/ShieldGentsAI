"""Audit logging and compliance for agentic AI systems."""

import json
import hashlib
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path


class AuditEventType(Enum):
    """Types of audit events."""

    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    TOOL_CALL = "tool_call"
    MODEL_CALL = "model_call"
    PROMPT_INJECTION = "prompt_injection"
    ACCESS_DENIED = "access_denied"
    DATA_ACCESS = "data_access"
    CONFIG_CHANGE = "config_change"
    USER_ACTION = "user_action"


@dataclass
class AuditEvent:
    """Audit event record."""

    event_id: str
    event_type: AuditEventType
    timestamp: float
    agent_id: Optional[str] = None
    user_id: Optional[str] = None
    action: str = ""
    resource: Optional[str] = None
    outcome: str = "success"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AuditLogger:
    """Audit logger for compliance and security."""

    def __init__(
        self,
        log_file: Optional[str] = None,
        enable_console: bool = False,
        enable_signatures: bool = True,
    ) -> None:
        """
        Initialize audit logger.

        Args:
            log_file: Path to audit log file
            enable_console: Also log to console
            enable_signatures: Sign events for tamper detection
        """
        self.log_file = Path(log_file) if log_file else None
        self.enable_console = enable_console
        self.enable_signatures = enable_signatures
        self.events: List[AuditEvent] = []

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: AuditEventType,
        action: str,
        agent_id: Optional[str] = None,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        outcome: str = "success",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            event_type: Type of event
            action: Action description
            agent_id: Agent identifier
            user_id: User identifier
            resource: Resource accessed
            outcome: Outcome (success/failure/blocked)
            metadata: Additional metadata

        Returns:
            Created audit event
        """
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=event_type,
            timestamp=time.time(),
            agent_id=agent_id,
            user_id=user_id,
            action=action,
            resource=resource,
            outcome=outcome,
            metadata=metadata or {},
        )

        # Add signature
        if self.enable_signatures:
            event.metadata["signature"] = self._sign_event(event)

        # Store event
        self.events.append(event)

        # Write to file
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(event.to_json() + "\n")

        # Console output
        if self.enable_console:
            print(f"[AUDIT] {event.event_type.value}: {event.action}")

        return event

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        import uuid

        return str(uuid.uuid4())

    def _sign_event(self, event: AuditEvent) -> str:
        """
        Create signature for event.

        In production, use proper HMAC with secret key.
        """
        data = json.dumps(event.to_dict(), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def query_events(
        self,
        event_type: Optional[AuditEventType] = None,
        agent_id: Optional[str] = None,
        user_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> List[AuditEvent]:
        """
        Query audit events.

        Args:
            event_type: Filter by event type
            agent_id: Filter by agent ID
            user_id: Filter by user ID
            start_time: Start timestamp
            end_time: End timestamp

        Returns:
            Filtered audit events
        """
        results = self.events

        if event_type:
            results = [e for e in results if e.event_type == event_type]

        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]

        if user_id:
            results = [e for e in results if e.user_id == user_id]

        if start_time:
            results = [e for e in results if e.timestamp >= start_time]

        if end_time:
            results = [e for e in results if e.timestamp <= end_time]

        return results

    def generate_report(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Generate audit report.

        Args:
            start_time: Start timestamp
            end_time: End timestamp

        Returns:
            Audit report
        """
        events = self.query_events(start_time=start_time, end_time=end_time)

        report = {
            "period": {
                "start": start_time or "all",
                "end": end_time or "all",
            },
            "total_events": len(events),
            "by_type": {},
            "by_outcome": {},
            "by_agent": {},
            "by_user": {},
        }

        for event in events:
            # Count by type
            event_type = event.event_type.value
            report["by_type"][event_type] = report["by_type"].get(event_type, 0) + 1

            # Count by outcome
            report["by_outcome"][event.outcome] = report["by_outcome"].get(event.outcome, 0) + 1

            # Count by agent
            if event.agent_id:
                report["by_agent"][event.agent_id] = report["by_agent"].get(event.agent_id, 0) + 1

            # Count by user
            if event.user_id:
                report["by_user"][event.user_id] = report["by_user"].get(event.user_id, 0) + 1

        return report


class ComplianceChecker:
    """Check compliance with security policies."""

    def __init__(self, audit_logger: AuditLogger) -> None:
        """
        Initialize compliance checker.

        Args:
            audit_logger: Audit logger instance
        """
        self.audit_logger = audit_logger
        self.policies: Dict[str, Any] = {}

    def register_policy(
        self,
        policy_id: str,
        max_tool_calls_per_hour: Optional[int] = None,
        required_user_auth: bool = False,
        allowed_tools: Optional[List[str]] = None,
    ) -> None:
        """
        Register a compliance policy.

        Args:
            policy_id: Policy identifier
            max_tool_calls_per_hour: Max tool calls per hour
            required_user_auth: Require user authentication
            allowed_tools: List of allowed tools
        """
        self.policies[policy_id] = {
            "max_tool_calls_per_hour": max_tool_calls_per_hour,
            "required_user_auth": required_user_auth,
            "allowed_tools": allowed_tools,
        }

    def check_compliance(
        self,
        policy_id: str,
        agent_id: str,
        user_id: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check compliance with policy.

        Args:
            policy_id: Policy to check
            agent_id: Agent identifier
            user_id: User identifier
            tool_name: Tool being called

        Returns:
            Compliance check result
        """
        if policy_id not in self.policies:
            return {"compliant": True, "violations": []}

        policy = self.policies[policy_id]
        violations = []

        # Check user authentication
        if policy.get("required_user_auth") and not user_id:
            violations.append("User authentication required")

        # Check tool allowlist
        if tool_name and policy.get("allowed_tools"):
            if tool_name not in policy["allowed_tools"]:
                violations.append(f"Tool '{tool_name}' not in allowed list")

        # Check rate limits
        if policy.get("max_tool_calls_per_hour"):
            one_hour_ago = time.time() - 3600
            recent_calls = self.audit_logger.query_events(
                event_type=AuditEventType.TOOL_CALL,
                agent_id=agent_id,
                start_time=one_hour_ago,
            )

            if len(recent_calls) >= policy["max_tool_calls_per_hour"]:
                violations.append("Tool call rate limit exceeded")

        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "policy_id": policy_id,
        }
