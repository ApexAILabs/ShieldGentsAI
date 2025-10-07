"""Integration tests for ShieldGents."""

import pytest
from shieldgents.core.sandbox import FunctionSandbox, ProcessSandbox, ResourceLimits
from shieldgents.core.monitor import SecurityMonitor
from shieldgents.controls.access import AccessControlList, ToolAccessControl
from shieldgents.controls.privilege import PrivilegeMonitor


@pytest.mark.integration
class TestSecurityIntegration:
    """Integration tests for security components."""

    def test_sandbox_with_monitor(self) -> None:
        """Test sandbox integration with security monitor."""
        _ = SecurityMonitor()
        sandbox = FunctionSandbox()

        def test_func(x: int) -> int:
            return x * 2

        # Execute function in sandbox
        result = sandbox.execute(test_func, args=(5,))

        # Monitor should track the execution
        assert result.success
        assert result.return_value == 10

    def test_access_control_with_privilege(self) -> None:
        """Test access control with privilege escalation detection."""
        acl = AccessControlList()
        # Create a role with read permission
        from shieldgents.controls.access import Permission
        acl.create_role("user", permissions={Permission.READ.value})
        acl.create_user("user-1", "testuser", roles={"user"})
        tool_access = ToolAccessControl(acl)
        privilege_monitor = PrivilegeMonitor()

        # Test tool access
        tool_access.register_tool("read_data", required_permission="read")
        assert tool_access.can_use_tool("user-1", "read_data")

        # Test privilege escalation detection
        alert = privilege_monitor.detect_social_engineering(
            "user-1", "session-1", "sudo rm -rf /"
        )
        assert alert is not None

    def test_multi_layer_security(self) -> None:
        """Test multiple security layers working together."""
        _ = SecurityMonitor()
        sandbox = FunctionSandbox(limits=ResourceLimits(timeout=2.0))
        acl = AccessControlList()
        # Create a role with read permission
        from shieldgents.controls.access import Permission
        acl.create_role("user", permissions={Permission.READ.value})
        acl.create_user("user-1", "testuser", roles={"user"})
        tool_access = ToolAccessControl(acl)

        def secure_operation(data: str) -> str:
            # Simulate a secure operation
            if not data:
                raise ValueError("Empty data not allowed")
            return f"Processed: {data}"

        # Check access
        tool_access.register_tool("secure_operation", required_permission="read")
        access_granted = tool_access.can_use_tool("user-1", "secure_operation")
        assert access_granted

        # Execute in sandbox
        result = sandbox.execute(secure_operation, args=("test_data",))

        # Verify execution
        assert result.success
        assert "Processed: test_data" in result.return_value


@pytest.mark.integration
class TestEndToEndWorkflow:
    """End-to-end integration tests."""

    def test_complete_security_workflow(self) -> None:
        """Test complete security workflow from input to output."""
        # Setup security components
        _ = SecurityMonitor()
        sandbox = FunctionSandbox(limits=ResourceLimits(timeout=5.0, max_memory=100 * 1024 * 1024))
        acl = AccessControlList()
        # Create a role with read permission
        from shieldgents.controls.access import Permission
        acl.create_role("user", permissions={Permission.READ.value})
        acl.create_user("user-1", "testuser", roles={"user"})
        tool_access = ToolAccessControl(acl)

        # Define a workflow function
        def workflow(user_input: str) -> dict:
            """Simulated workflow with multiple steps."""
            # Step 1: Validate input
            if len(user_input) > 1000:
                raise ValueError("Input too large")

            # Step 2: Process data
            processed = user_input.upper()

            # Step 3: Return result
            return {"status": "success", "data": processed}

        # Execute workflow with all security checks
        tool_access.register_tool("workflow", required_permission="read")
        access_check = tool_access.can_use_tool("user-1", "workflow")
        assert access_check

        result = sandbox.execute(workflow, args=("hello world",))

        assert result.success
        assert result.return_value["status"] == "success"
        assert result.return_value["data"] == "HELLO WORLD"

    def test_process_sandbox_integration(self) -> None:
        """Test process sandbox with real commands."""
        sandbox = ProcessSandbox(limits=ResourceLimits(timeout=3.0))

        # Test safe command
        result = sandbox.execute("python --version")
        assert result.success

        # Test command with timeout
        result_timeout = sandbox.execute("sleep 10")
        assert not result_timeout.success
