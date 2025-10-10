"""Sandbox utilities for safe tool execution in agentic AI systems."""

import subprocess
import signal
import time
import psutil
import os
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager
import threading


class ResourceLimitType(Enum):
    """Types of resource limits that can be enforced."""

    CPU_TIME = "cpu_time"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK = "network"
    FILE_DESCRIPTORS = "file_descriptors"


@dataclass
class ResourceLimits:
    """Resource limits for sandboxed execution."""

    max_cpu_time: Optional[float] = 30.0  # seconds
    max_memory: Optional[int] = 512 * 1024 * 1024  # 512MB in bytes
    max_processes: Optional[int] = 5
    max_file_descriptors: Optional[int] = 100
    timeout: Optional[float] = 60.0  # seconds
    allowed_syscalls: Optional[List[str]] = None


@dataclass
class ExecutionResult:
    """Result of sandboxed execution."""

    success: bool
    return_value: Any = None
    error: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    execution_time: float = 0.0
    memory_used: int = 0
    exit_code: Optional[int] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


class TimeoutException(Exception):
    """Raised when execution exceeds timeout."""

    pass


class ResourceLimitException(Exception):
    """Raised when resource limits are exceeded."""

    pass


class ProcessSandbox:
    """Sandbox for executing subprocesses with resource limits."""

    def __init__(self, limits: Optional[ResourceLimits] = None) -> None:
        """
        Initialize process sandbox.

        Args:
            limits: Resource limits to enforce
        """
        self.limits = limits or ResourceLimits()

    def execute(
        self,
        command: Union[str, List[str]],
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Execute a command in a sandboxed subprocess.

        Args:
            command: Command to execute (string or list)
            env: Environment variables
            cwd: Working directory

        Returns:
            ExecutionResult with execution details
        """
        start_time = time.time()

        try:
            # Prepare command
            if isinstance(command, str):
                cmd = command
                shell = True
            else:
                cmd = command
                shell = False

            # Set up environment
            exec_env = os.environ.copy()
            if env:
                exec_env.update(env)

            # Execute with timeout
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=shell,
                env=exec_env,
                cwd=cwd,
            )

            # Monitor resource usage
            monitor_thread = threading.Thread(
                target=self._monitor_process,
                args=(process,),
                daemon=True,
            )
            monitor_thread.start()

            # Wait with timeout
            try:
                stdout, stderr = process.communicate(timeout=self.limits.timeout)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                self._kill_process_tree(process.pid)
                raise TimeoutException(f"Execution exceeded timeout of {self.limits.timeout}s")

            execution_time = time.time() - start_time

            return ExecutionResult(
                success=(exit_code == 0),
                stdout=stdout.decode("utf-8", errors="ignore"),
                stderr=stderr.decode("utf-8", errors="ignore"),
                execution_time=execution_time,
                exit_code=exit_code,
            )

        except TimeoutException as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                error=f"Execution failed: {str(e)}",
                execution_time=time.time() - start_time,
            )

    def _monitor_process(self, process: subprocess.Popen) -> None:
        """
        Monitor process resource usage and enforce limits.

        Args:
            process: subprocess.Popen process to monitor

        Raises:
            ResourceLimitException: If resource limits are exceeded
        """
        try:
            ps_process = psutil.Process(process.pid)

            while process.poll() is None:
                # Check memory usage
                if self.limits.max_memory:
                    memory_info = ps_process.memory_info()
                    if memory_info.rss > self.limits.max_memory:
                        self._kill_process_tree(process.pid)
                        raise ResourceLimitException(
                            f"Memory limit exceeded: {memory_info.rss} > {self.limits.max_memory}"
                        )

                # Check CPU time
                if self.limits.max_cpu_time:
                    cpu_times = ps_process.cpu_times()
                    total_cpu_time = cpu_times.user + cpu_times.system
                    if total_cpu_time > self.limits.max_cpu_time:
                        self._kill_process_tree(process.pid)
                        raise ResourceLimitException(
                            f"CPU time limit exceeded: {total_cpu_time} > {self.limits.max_cpu_time}"
                        )

                time.sleep(0.1)

        except psutil.NoSuchProcess:
            pass

    def _kill_process_tree(self, pid: int) -> None:
        """
        Kill a process and all its children.

        Args:
            pid: Process ID to kill
        """
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass

            try:
                parent.kill()
            except psutil.NoSuchProcess:
                pass

        except psutil.NoSuchProcess:
            pass


class FunctionSandbox:
    """Sandbox for executing Python functions with resource limits."""

    def __init__(self, limits: Optional[ResourceLimits] = None) -> None:
        """
        Initialize function sandbox.

        Args:
            limits: Resource limits to enforce
        """
        self.limits = limits or ResourceLimits()

    def execute(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """
        Execute a function in a sandboxed environment.

        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments

        Returns:
            ExecutionResult with execution details
        """
        if kwargs is None:
            kwargs = {}

        start_time = time.time()
        result = ExecutionResult(success=False)

        def timeout_handler(signum: int, frame: Any) -> None:
            raise TimeoutException(f"Execution exceeded timeout of {self.limits.timeout}s")

        # Set up timeout (Unix-like systems only)
        old_handler = None
        if self.limits.timeout and hasattr(signal, "SIGALRM"):
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(self.limits.timeout))

        try:
            return_value = func(*args, **kwargs)
            result = ExecutionResult(
                success=True,
                return_value=return_value,
                execution_time=time.time() - start_time,
            )
        except TimeoutException as e:
            result = ExecutionResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            result = ExecutionResult(
                success=False,
                error=f"Function execution failed: {str(e)}",
                execution_time=time.time() - start_time,
            )
        finally:
            # Reset alarm
            if self.limits.timeout and hasattr(signal, "SIGALRM"):
                signal.alarm(0)
                if old_handler:
                    signal.signal(signal.SIGALRM, old_handler)

        return result


class ToolWrapper:
    """Wrapper for safely executing agent tools with sandboxing."""

    def __init__(
        self,
        sandbox: Optional[Union[ProcessSandbox, FunctionSandbox]] = None,
        allowed_tools: Optional[List[str]] = None,
        denied_tools: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize tool wrapper.

        Args:
            sandbox: Sandbox to use for execution
            allowed_tools: Whitelist of allowed tool names
            denied_tools: Blacklist of denied tool names
        """
        self.sandbox = sandbox or FunctionSandbox()
        self.allowed_tools = set(allowed_tools) if allowed_tools else None
        self.denied_tools = set(denied_tools) if denied_tools else set()

    def wrap(self, tool_name: str, tool_func: Callable) -> Callable:
        """
        Wrap a tool function for safe execution.

        Args:
            tool_name: Name of the tool
            tool_func: Tool function to wrap

        Returns:
            Wrapped function
        """

        def wrapped_tool(*args: Any, **kwargs: Any) -> Any:
            # Check permissions
            if self.allowed_tools and tool_name not in self.allowed_tools:
                raise PermissionError(f"Tool '{tool_name}' is not in allowed list")

            if tool_name in self.denied_tools:
                raise PermissionError(f"Tool '{tool_name}' is denied")

            # Execute in sandbox
            if isinstance(self.sandbox, FunctionSandbox):
                result = self.sandbox.execute(tool_func, args, kwargs)
            else:
                # For process sandbox, tool must be a subprocess call
                raise ValueError("Process sandbox requires subprocess execution")

            if not result.success:
                raise RuntimeError(f"Tool execution failed: {result.error}")

            return result.return_value

        wrapped_tool.__name__ = f"sandboxed_{tool_name}"
        wrapped_tool.__doc__ = tool_func.__doc__
        return wrapped_tool

    @contextmanager
    def safe_context(self) -> Any:
        """Context manager for safe tool execution."""
        try:
            yield self
        except Exception as e:
            raise RuntimeError(f"Safe execution context failed: {str(e)}")
