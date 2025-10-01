"""Role-based access control (RBAC) for agent tools and resources."""

from typing import Any, Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from functools import wraps


class Permission(Enum):
    """Standard permission types."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"


@dataclass
class Role:
    """Role definition with permissions."""
    name: str
    permissions: Set[str] = field(default_factory=set)
    resource_patterns: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: str, resource: Optional[str] = None) -> bool:
        """
        Check if role has a specific permission.

        Args:
            permission: Permission to check
            resource: Optional resource to check against patterns

        Returns:
            True if permission is granted
        """
        # Check for admin permission (grants all)
        if Permission.ADMIN.value in self.permissions:
            return True

        # Check specific permission
        if permission not in self.permissions:
            return False

        # If no resource specified, permission is granted
        if resource is None:
            return True

        # Check resource patterns
        if not self.resource_patterns:
            return True

        return any(self._match_pattern(pattern, resource) for pattern in self.resource_patterns)

    def _match_pattern(self, pattern: str, resource: str) -> bool:
        """Match resource against pattern (supports wildcards)."""
        if pattern == "*":
            return True

        if "*" in pattern:
            prefix = pattern.split("*")[0]
            return resource.startswith(prefix)

        return pattern == resource


@dataclass
class User:
    """User with assigned roles."""
    id: str
    username: str
    roles: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AccessControlList:
    """Manages access control policies."""

    def __init__(self) -> None:
        """Initialize ACL."""
        self.roles: Dict[str, Role] = {}
        self.users: Dict[str, User] = {}

    def create_role(
        self,
        name: str,
        permissions: Optional[Set[str]] = None,
        resource_patterns: Optional[Set[str]] = None,
    ) -> Role:
        """
        Create a new role.

        Args:
            name: Role name
            permissions: Set of permissions
            resource_patterns: Resource access patterns

        Returns:
            Created role
        """
        role = Role(
            name=name,
            permissions=permissions or set(),
            resource_patterns=resource_patterns or set(),
        )
        self.roles[name] = role
        return role

    def create_user(self, user_id: str, username: str, roles: Optional[Set[str]] = None) -> User:
        """
        Create a new user.

        Args:
            user_id: User ID
            username: Username
            roles: Set of role names

        Returns:
            Created user
        """
        user = User(id=user_id, username=username, roles=roles or set())
        self.users[user_id] = user
        return user

    def assign_role(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user."""
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        if role_name not in self.roles:
            raise ValueError(f"Role {role_name} not found")

        self.users[user_id].roles.add(role_name)

    def revoke_role(self, user_id: str, role_name: str) -> None:
        """Revoke a role from a user."""
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")

        self.users[user_id].roles.discard(role_name)

    def check_permission(
        self, user_id: str, permission: str, resource: Optional[str] = None
    ) -> bool:
        """
        Check if user has permission for a resource.

        Args:
            user_id: User ID
            permission: Permission to check
            resource: Optional resource identifier

        Returns:
            True if permission is granted
        """
        if user_id not in self.users:
            return False

        user = self.users[user_id]

        for role_name in user.roles:
            if role_name in self.roles:
                role = self.roles[role_name]
                if role.has_permission(permission, resource):
                    return True

        return False

    def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all permissions for a user."""
        if user_id not in self.users:
            return set()

        user = self.users[user_id]
        permissions = set()

        for role_name in user.roles:
            if role_name in self.roles:
                permissions.update(self.roles[role_name].permissions)

        return permissions


class ToolAccessControl:
    """Access control specifically for agent tools."""

    def __init__(self, acl: Optional[AccessControlList] = None) -> None:
        """
        Initialize tool access control.

        Args:
            acl: Access control list instance
        """
        self.acl = acl or AccessControlList()
        self.tool_registry: Dict[str, Dict[str, Any]] = {}

    def register_tool(
        self,
        tool_name: str,
        required_permission: str,
        resource_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Register a tool with required permissions.

        Args:
            tool_name: Name of the tool
            required_permission: Permission required to use tool
            resource_type: Type of resource the tool accesses
            metadata: Additional metadata
        """
        self.tool_registry[tool_name] = {
            "required_permission": required_permission,
            "resource_type": resource_type,
            "metadata": metadata or {},
        }

    def can_use_tool(
        self, user_id: str, tool_name: str, resource: Optional[str] = None
    ) -> bool:
        """
        Check if user can use a specific tool.

        Args:
            user_id: User ID
            tool_name: Tool name
            resource: Optional specific resource

        Returns:
            True if user can use the tool
        """
        if tool_name not in self.tool_registry:
            return False

        tool_info = self.tool_registry[tool_name]
        required_permission = tool_info["required_permission"]

        # Build resource identifier
        if resource:
            resource_id = f"{tool_info.get('resource_type', 'tool')}:{resource}"
        else:
            resource_id = f"tool:{tool_name}"

        return self.acl.check_permission(user_id, required_permission, resource_id)

    def require_permission(self, permission: str, resource: Optional[str] = None) -> Callable:
        """
        Decorator to enforce permission checks on functions.

        Args:
            permission: Required permission
            resource: Optional resource identifier

        Returns:
            Decorator function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract user_id from kwargs or args
                user_id = kwargs.get("user_id") or (args[0] if args else None)

                if user_id is None:
                    raise PermissionError("User ID not provided")

                if not self.acl.check_permission(user_id, permission, resource):
                    raise PermissionError(
                        f"User {user_id} does not have {permission} permission"
                        + (f" for {resource}" if resource else "")
                    )

                return func(*args, **kwargs)

            return wrapper

        return decorator


class SessionManager:
    """Manages user sessions and tokens."""

    def __init__(self, acl: AccessControlList) -> None:
        """
        Initialize session manager.

        Args:
            acl: Access control list instance
        """
        self.acl = acl
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(self, user_id: str) -> str:
        """
        Create a new session for a user.

        Args:
            user_id: User ID

        Returns:
            Session token
        """
        if user_id not in self.acl.users:
            raise ValueError(f"User {user_id} not found")

        # Generate session token
        token_data = f"{user_id}:{hash(user_id)}"
        token = hashlib.sha256(token_data.encode()).hexdigest()

        self.sessions[token] = {
            "user_id": user_id,
            "created_at": __import__("time").time(),
        }

        return token

    def validate_session(self, token: str) -> Optional[str]:
        """
        Validate a session token.

        Args:
            token: Session token

        Returns:
            User ID if valid, None otherwise
        """
        session = self.sessions.get(token)
        if not session:
            return None

        # Check expiration (optional)
        # ... add expiration logic here ...

        return session["user_id"]

    def revoke_session(self, token: str) -> None:
        """Revoke a session token."""
        if token in self.sessions:
            del self.sessions[token]


def setup_default_roles(acl: AccessControlList) -> None:
    """
    Set up default roles for common use cases.

    Args:
        acl: Access control list instance
    """
    # Admin role - full access
    acl.create_role(
        "admin",
        permissions={Permission.ADMIN.value},
        resource_patterns={"*"},
    )

    # Developer role - read/write/execute
    acl.create_role(
        "developer",
        permissions={Permission.READ.value, Permission.WRITE.value, Permission.EXECUTE.value},
        resource_patterns={"*"},
    )

    # Operator role - read/execute
    acl.create_role(
        "operator",
        permissions={Permission.READ.value, Permission.EXECUTE.value},
        resource_patterns={"tool:*", "data:*"},
    )

    # Viewer role - read only
    acl.create_role(
        "viewer",
        permissions={Permission.READ.value},
        resource_patterns={"*"},
    )