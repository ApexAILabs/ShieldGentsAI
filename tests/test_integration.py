"""Integration tests for ShieldGents."""

import pytest
from shieldgents.core.sandbox import FunctionSandbox, ProcessSandbox, ResourceLimits
from shieldgents.core.monitor import SecurityMonitor
from shieldgents.controls.access import AccessControl
from shieldgents.controls.privilege import PrivilegeControl


@pytest.mark.integration
class TestSecurityIntegration:
    """Integration tests for security components."""

    def test_sandbox_with_monitor(self) -> None:
        """Test sandbox integration with security monitor."""
        monitor = SecurityMonitor()
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
        access_control = AccessControl()
        privilege_control = PrivilegeControl()

        # Test normal access
        assert access_control.check_access("user", "resource") is not None

        # Test privilege escalation detection
        result = privilege_control.check_privilege_escalation(
            current_level="user", requested_level="admin"
        )
        assert result is not None

    def test_multi_layer_security(self) -> None:
        """Test multiple security layers working together."""
        monitor = SecurityMonitor()
        sandbox = FunctionSandbox(limits=ResourceLimits(timeout=2.0))
        access_control = AccessControl()

        def secure_operation(data: str) -> str:
            # Simulate a secure operation
            if not data:
                raise ValueError("Empty data not allowed")
            return f"Processed: {data}"

        # Check access
        access_granted = access_control.check_access("test_user", "secure_operation")
        assert access_granted is not None

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
        monitor = SecurityMonitor()
        sandbox = FunctionSandbox(limits=ResourceLimits(timeout=5.0, memory_limit=100))
        access_control = AccessControl()

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
        access_check = access_control.check_access("test_user", "workflow")
        assert access_check is not None

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
