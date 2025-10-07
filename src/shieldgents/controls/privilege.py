"""Privilege escalation detection and prevention.

Monitors for attempts to gain elevated permissions, assume unauthorized roles,
or bypass access controls through social engineering or technical exploits.
"""

from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class PrivilegeLevel(Enum):
    """Privilege levels for operations."""
    PUBLIC = "public"
    USER = "user"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"
    SYSTEM = "system"


class EscalationMethod(Enum):
    """Methods of privilege escalation."""
    DIRECT_REQUEST = "direct_request"
    ROLE_ASSUMPTION = "role_assumption"
    PERMISSION_MODIFICATION = "permission_modification"
    CREDENTIAL_ABUSE = "credential_abuse"
    SOCIAL_ENGINEERING = "social_engineering"
    CONFIGURATION_CHANGE = "configuration_change"
    BYPASS_ATTEMPT = "bypass_attempt"


@dataclass
class PrivilegeChange:
    """Record of privilege change request."""
    user_id: str
    session_id: str
    timestamp: datetime
    from_level: PrivilegeLevel
    to_level: PrivilegeLevel
    method: EscalationMethod
    justification: Optional[str] = None
    approved: bool = False
    approver: Optional[str] = None


@dataclass
class EscalationAlert:
    """Alert for privilege escalation attempt."""
    severity: str  # "low", "medium", "high", "critical"
    method: EscalationMethod
    description: str
    user_id: str
    session_id: str
    should_block: bool
    requires_approval: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


class PrivilegePolicy:
    """Define privilege escalation policies."""

    def __init__(self):
        """Initialize policy."""
        # Operations requiring specific privilege levels
        self.operation_privileges: Dict[str, PrivilegeLevel] = {
            'read_public_data': PrivilegeLevel.PUBLIC,
            'read_user_data': PrivilegeLevel.USER,
            'write_user_data': PrivilegeLevel.USER,
            'read_all_users': PrivilegeLevel.ADMIN,
            'modify_permissions': PrivilegeLevel.ADMIN,
            'delete_user': PrivilegeLevel.ADMIN,
            'system_configuration': PrivilegeLevel.SUPERADMIN,
            'assume_role': PrivilegeLevel.ADMIN,
            'grant_privileges': PrivilegeLevel.SUPERADMIN,
        }

        # Operations that always require human approval
        self.approval_required: Set[str] = {
            'modify_permissions',
            'delete_user',
            'assume_role',
            'grant_privileges',
            'system_configuration',
            'access_secrets',
            'modify_firewall',
        }

        # Suspicious keywords in prompts/justifications
        self.escalation_keywords = [
            'sudo',
            'admin',
            'root',
            'override',
            'bypass',
            'disable security',
            'ignore policy',
            'grant me',
            'make me admin',
            'elevate',
            'privilege',
            'superuser',
            'emergency access',
            'need sudo',
            'need admin',
            'need root',
            'give me access',
            'grant access',
        ]

    def requires_privilege(self, operation: str) -> PrivilegeLevel:
        """Get required privilege level for operation."""
        return self.operation_privileges.get(operation, PrivilegeLevel.USER)

    def requires_approval(self, operation: str) -> bool:
        """Check if operation requires human approval."""
        return operation in self.approval_required


class PrivilegeMonitor:
    """Monitor and prevent privilege escalation."""

    def __init__(
        self,
        policy: Optional[PrivilegePolicy] = None,
        strict_mode: bool = True,
    ):
        """
        Initialize monitor.

        Args:
            policy: Privilege policy
            strict_mode: If True, block suspicious requests immediately
        """
        self.policy = policy or PrivilegePolicy()
        self.strict_mode = strict_mode

        # Track user privileges
        self.user_privileges: Dict[str, PrivilegeLevel] = {}

        # Track privilege changes
        self.privilege_changes: List[PrivilegeChange] = []

        # Track escalation attempts
        self.escalation_alerts: List[EscalationAlert] = []

        # Track pending approvals
        self.pending_approvals: List[Dict[str, Any]] = []

    def set_user_privilege(self, user_id: str, level: PrivilegeLevel):
        """Set user's privilege level."""
        self.user_privileges[user_id] = level

    def get_user_privilege(self, user_id: str) -> PrivilegeLevel:
        """Get user's current privilege level."""
        return self.user_privileges.get(user_id, PrivilegeLevel.USER)

    def check_operation(
        self,
        user_id: str,
        operation: str,
        session_id: str,
        justification: Optional[str] = None,
    ) -> tuple[bool, Optional[EscalationAlert]]:
        """
        Check if user can perform operation.

        Args:
            user_id: User identifier
            operation: Operation to perform
            session_id: Session ID
            justification: Reason for operation

        Returns:
            (is_allowed, alert_if_suspicious)
        """
        current_privilege = self.get_user_privilege(user_id)
        required_privilege = self.policy.requires_privilege(operation)

        # Check if user has sufficient privilege
        if not self._has_sufficient_privilege(current_privilege, required_privilege):
            alert = EscalationAlert(
                severity="high",
                method=EscalationMethod.DIRECT_REQUEST,
                description=f"User {user_id} attempted {operation} without sufficient privilege",
                user_id=user_id,
                session_id=session_id,
                should_block=True,
                requires_approval=True,
                metadata={
                    'current_privilege': current_privilege.value,
                    'required_privilege': required_privilege.value,
                    'operation': operation,
                }
            )
            self.escalation_alerts.append(alert)
            return False, alert

        # Check for suspicious justification
        if justification:
            suspicious_alert = self._check_suspicious_justification(
                user_id, session_id, justification, operation
            )
            if suspicious_alert:
                self.escalation_alerts.append(suspicious_alert)
                if self.strict_mode:
                    return False, suspicious_alert

        # Check if requires approval
        if self.policy.requires_approval(operation):
            alert = EscalationAlert(
                severity="medium",
                method=EscalationMethod.DIRECT_REQUEST,
                description=f"Operation {operation} requires human approval",
                user_id=user_id,
                session_id=session_id,
                should_block=False,
                requires_approval=True,
                metadata={'operation': operation}
            )

            # Add to pending approvals
            self.pending_approvals.append({
                'user_id': user_id,
                'session_id': session_id,
                'operation': operation,
                'justification': justification,
                'timestamp': datetime.now(),
            })

            return False, alert

        return True, None

    def request_privilege_change(
        self,
        user_id: str,
        session_id: str,
        target_level: PrivilegeLevel,
        method: EscalationMethod,
        justification: Optional[str] = None,
    ) -> tuple[bool, Optional[EscalationAlert]]:
        """
        Request a privilege level change.

        Args:
            user_id: User requesting change
            session_id: Session ID
            target_level: Desired privilege level
            method: Method of escalation
            justification: Reason for request

        Returns:
            (is_approved, alert)
        """
        current_level = self.get_user_privilege(user_id)

        # Check if this is an escalation
        if not self._is_escalation(current_level, target_level):
            # Not an escalation, allow
            self.set_user_privilege(user_id, target_level)
            return True, None

        # Record the change request
        change = PrivilegeChange(
            user_id=user_id,
            session_id=session_id,
            timestamp=datetime.now(),
            from_level=current_level,
            to_level=target_level,
            method=method,
            justification=justification,
            approved=False,
        )
        self.privilege_changes.append(change)

        # Create alert
        severity = self._calculate_escalation_severity(current_level, target_level)
        alert = EscalationAlert(
            severity=severity,
            method=method,
            description=f"Privilege escalation request: {current_level.value} -> {target_level.value}",
            user_id=user_id,
            session_id=session_id,
            should_block=True,
            requires_approval=True,
            metadata={
                'from_level': current_level.value,
                'to_level': target_level.value,
                'justification': justification,
            }
        )

        self.escalation_alerts.append(alert)

        # Always require approval for escalation
        return False, alert

    def approve_privilege_change(
        self,
        user_id: str,
        approver_id: str,
        session_id: Optional[str] = None,
    ) -> bool:
        """
        Approve a privilege change request.

        Args:
            user_id: User to approve
            approver_id: Who is approving
            session_id: Optional session ID

        Returns:
            True if approved
        """
        # Find pending change
        pending = None
        for change in reversed(self.privilege_changes):
            if change.user_id == user_id and not change.approved:
                if session_id is None or change.session_id == session_id:
                    pending = change
                    break

        if not pending:
            return False

        # Verify approver has sufficient privilege
        approver_level = self.get_user_privilege(approver_id)
        if not self._can_approve(approver_level, pending.to_level):
            return False

        # Approve
        pending.approved = True
        pending.approver = approver_id
        self.set_user_privilege(user_id, pending.to_level)

        return True

    def detect_social_engineering(
        self,
        user_id: str,
        session_id: str,
        prompt: str,
    ) -> Optional[EscalationAlert]:
        """
        Detect social engineering attempts to gain privileges.

        Args:
            user_id: User ID
            session_id: Session ID
            prompt: User prompt to analyze

        Returns:
            Alert if social engineering detected
        """
        prompt_lower = prompt.lower()

        # Check for escalation keywords
        detected_keywords = [
            kw for kw in self.policy.escalation_keywords
            if kw.lower() in prompt_lower
        ]

        if detected_keywords:
            alert = EscalationAlert(
                severity="high",
                method=EscalationMethod.SOCIAL_ENGINEERING,
                description=f"Potential social engineering detected: {', '.join(detected_keywords)}",
                user_id=user_id,
                session_id=session_id,
                should_block=self.strict_mode,
                requires_approval=True,
                metadata={'detected_keywords': detected_keywords}
            )
            self.escalation_alerts.append(alert)
            return alert

        # Check for impersonation attempts
        impersonation_patterns = [
            'i am admin',
            'i am the administrator',
            'i have permission',
            'i am authorized',
            'trust me',
            'emergency',
            'urgent access needed',
        ]

        for pattern in impersonation_patterns:
            if pattern in prompt_lower:
                alert = EscalationAlert(
                    severity="critical",
                    method=EscalationMethod.SOCIAL_ENGINEERING,
                    description=f"Impersonation attempt detected: '{pattern}'",
                    user_id=user_id,
                    session_id=session_id,
                    should_block=True,
                    requires_approval=True,
                    metadata={'pattern': pattern}
                )
                self.escalation_alerts.append(alert)
                return alert

        return None

    def _has_sufficient_privilege(
        self,
        current: PrivilegeLevel,
        required: PrivilegeLevel
    ) -> bool:
        """Check if current privilege is sufficient."""
        levels = [
            PrivilegeLevel.PUBLIC,
            PrivilegeLevel.USER,
            PrivilegeLevel.ADMIN,
            PrivilegeLevel.SUPERADMIN,
            PrivilegeLevel.SYSTEM,
        ]

        current_idx = levels.index(current)
        required_idx = levels.index(required)

        return current_idx >= required_idx

    def _is_escalation(self, from_level: PrivilegeLevel, to_level: PrivilegeLevel) -> bool:
        """Check if this is a privilege escalation."""
        levels = [
            PrivilegeLevel.PUBLIC,
            PrivilegeLevel.USER,
            PrivilegeLevel.ADMIN,
            PrivilegeLevel.SUPERADMIN,
            PrivilegeLevel.SYSTEM,
        ]

        from_idx = levels.index(from_level)
        to_idx = levels.index(to_level)

        return to_idx > from_idx

    def _calculate_escalation_severity(
        self,
        from_level: PrivilegeLevel,
        to_level: PrivilegeLevel
    ) -> str:
        """Calculate severity of escalation."""
        levels = [
            PrivilegeLevel.PUBLIC,
            PrivilegeLevel.USER,
            PrivilegeLevel.ADMIN,
            PrivilegeLevel.SUPERADMIN,
            PrivilegeLevel.SYSTEM,
        ]

        from_idx = levels.index(from_level)
        to_idx = levels.index(to_level)
        jump = to_idx - from_idx

        if jump >= 3:
            return "critical"
        elif jump == 2:
            return "high"
        elif jump == 1:
            return "medium"
        else:
            return "low"

    def _can_approve(self, approver_level: PrivilegeLevel, target_level: PrivilegeLevel) -> bool:
        """Check if approver can approve escalation to target level."""
        # Approver must be at least one level above target
        levels = [
            PrivilegeLevel.PUBLIC,
            PrivilegeLevel.USER,
            PrivilegeLevel.ADMIN,
            PrivilegeLevel.SUPERADMIN,
            PrivilegeLevel.SYSTEM,
        ]

        approver_idx = levels.index(approver_level)
        target_idx = levels.index(target_level)

        return approver_idx > target_idx

    def _check_suspicious_justification(
        self,
        user_id: str,
        session_id: str,
        justification: str,
        operation: str,
    ) -> Optional[EscalationAlert]:
        """Check if justification is suspicious."""
        just_lower = justification.lower()

        # Vague or generic justifications
        vague_patterns = ['because', 'just', 'need it', 'want to', 'testing']
        if any(p in just_lower for p in vague_patterns) and len(justification) < 20:
            return EscalationAlert(
                severity="medium",
                method=EscalationMethod.SOCIAL_ENGINEERING,
                description="Suspicious justification: too vague",
                user_id=user_id,
                session_id=session_id,
                should_block=False,
                requires_approval=True,
                metadata={'justification': justification}
            )

        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get privilege monitoring statistics."""
        return {
            'total_users': len(self.user_privileges),
            'privilege_distribution': {
                level.value: sum(1 for p in self.user_privileges.values() if p == level)
                for level in PrivilegeLevel
            },
            'total_escalation_attempts': len(self.escalation_alerts),
            'escalation_by_method': {
                method.value: sum(1 for a in self.escalation_alerts if a.method == method)
                for method in EscalationMethod
            },
            'pending_approvals': len(self.pending_approvals),
            'approved_changes': sum(1 for c in self.privilege_changes if c.approved),
        }
