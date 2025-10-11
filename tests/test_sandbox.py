"""Tests for sandbox module."""

import time
from shieldgents.core.sandbox import (
    FunctionSandbox,
    ProcessSandbox,
    ResourceLimits,
)


class TestFunctionSandbox:
    """Test function sandbox."""

    def test_successful_execution(self) -> None:
        """Test successful function execution."""
        sandbox = FunctionSandbox()

        def safe_func(x: int, y: int) -> int:
            return x + y

        result = sandbox.execute(safe_func, args=(10, 20))

        assert result.success
        assert result.return_value == 30

    def test_timeout_enforcement(self) -> None:
        """Test timeout enforcement."""
        limits = ResourceLimits(timeout=1.0)
        sandbox = FunctionSandbox(limits=limits)

        def slow_func() -> None:
            time.sleep(5)

        result = sandbox.execute(slow_func)

        assert not result.success
        assert "timeout" in result.error.lower()

    def test_exception_handling(self) -> None:
        """Test exception handling in sandboxed execution."""
        sandbox = FunctionSandbox()

        def failing_func() -> None:
            raise ValueError("Test error")

        result = sandbox.execute(failing_func)

        assert not result.success
        assert "Test error" in result.error


class TestProcessSandbox:
    """Test process sandbox."""

    def test_command_execution(self) -> None:
        """Test command execution."""
        sandbox = ProcessSandbox()
        result = sandbox.execute("echo 'Hello World'")

        assert result.success
        assert "Hello World" in result.stdout

    def test_timeout(self) -> None:
        """Test process timeout."""
        limits = ResourceLimits(timeout=1.0)
        sandbox = ProcessSandbox(limits=limits)
        result = sandbox.execute("sleep 10")

        assert not result.success
        assert "timeout" in result.error.lower()

    def test_exit_code(self) -> None:
        """Test exit code capture."""
        sandbox = ProcessSandbox()
        result = sandbox.execute("exit 42")

        assert not result.success
        assert result.exit_code == 42
