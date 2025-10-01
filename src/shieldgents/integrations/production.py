"""Agent productionization utilities.

Tools for deploying agents to production safely:
- Health checks and readiness probes
- Circuit breakers and fallback handlers
- Request validation and sanitization pipelines
- Metrics collection and alerting
- Gradual rollout and A/B testing support
- Production monitoring and observability
"""

import time
from typing import Callable, Optional, Any, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import deque
import functools


class HealthStatus(Enum):
    """Agent health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class HealthCheck:
    """Health check result."""
    status: HealthStatus
    checks: Dict[str, bool]
    message: str
    timestamp: datetime
    latency_ms: float


@dataclass
class Metrics:
    """Production metrics."""
    request_count: int = 0
    error_count: int = 0
    success_count: int = 0
    total_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0


class CircuitBreaker:
    """Circuit breaker for fault tolerance."""

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: int = 60,
        expected_exception: type = Exception,
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening
            timeout: Seconds to wait before half-open
            expected_exception: Exception type to catch
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.success_count = 0

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Exception: If circuit is open or function fails
        """
        if self.state == CircuitState.OPEN:
            # Check if timeout has passed
            if self.last_failure_time and \
               datetime.now() - self.last_failure_time >= timedelta(seconds=self.timeout):
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)

            # Success
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= 3:  # Require 3 successes
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0

            return result

        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now()

            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN

            raise e

    def reset(self):
        """Manually reset circuit breaker."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0


class RateLimiterProduction:
    """Production-grade rate limiter with token bucket."""

    def __init__(
        self,
        rate: int,
        capacity: int,
        time_window: int = 60,
    ):
        """
        Initialize rate limiter.

        Args:
            rate: Tokens per time window
            capacity: Max token capacity
            time_window: Time window in seconds
        """
        self.rate = rate
        self.capacity = capacity
        self.time_window = time_window

        self.tokens: Dict[str, float] = {}
        self.last_update: Dict[str, datetime] = {}

    def allow_request(self, key: str) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed.

        Args:
            key: Rate limit key (e.g., user_id)

        Returns:
            (allowed, metadata)
        """
        now = datetime.now()

        # Initialize if new key
        if key not in self.tokens:
            self.tokens[key] = self.capacity
            self.last_update[key] = now

        # Refill tokens based on time passed
        time_passed = (now - self.last_update[key]).total_seconds()
        tokens_to_add = (time_passed / self.time_window) * self.rate
        self.tokens[key] = min(self.capacity, self.tokens[key] + tokens_to_add)
        self.last_update[key] = now

        # Check if request allowed
        if self.tokens[key] >= 1.0:
            self.tokens[key] -= 1.0
            return True, {
                'remaining': int(self.tokens[key]),
                'retry_after': 0,
            }
        else:
            # Calculate retry after
            tokens_needed = 1.0 - self.tokens[key]
            retry_after = (tokens_needed / self.rate) * self.time_window

            return False, {
                'remaining': 0,
                'retry_after': int(retry_after),
            }


class ProductionAgent:
    """Production-ready agent wrapper with observability."""

    def __init__(
        self,
        agent_func: Callable,
        agent_id: str,
        enable_circuit_breaker: bool = True,
        enable_rate_limiting: bool = True,
        rate_limit: int = 100,
    ):
        """
        Initialize production agent.

        Args:
            agent_func: The actual agent function
            agent_id: Unique agent identifier
            enable_circuit_breaker: Enable circuit breaker
            enable_rate_limiting: Enable rate limiting
            rate_limit: Requests per minute
        """
        self.agent_func = agent_func
        self.agent_id = agent_id

        # Circuit breaker
        self.circuit_breaker = CircuitBreaker() if enable_circuit_breaker else None

        # Rate limiter
        self.rate_limiter = RateLimiterProduction(
            rate=rate_limit,
            capacity=rate_limit * 2,
            time_window=60,
        ) if enable_rate_limiting else None

        # Metrics
        self.metrics = Metrics()
        self.latency_history: deque = deque(maxlen=1000)

        # Health tracking
        self.last_health_check: Optional[HealthCheck] = None
        self.startup_time = datetime.now()

    def invoke(
        self,
        user_input: str,
        user_id: str = "default",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Invoke agent with production safeguards.

        Args:
            user_input: User input
            user_id: User identifier
            **kwargs: Additional arguments

        Returns:
            Response dictionary
        """
        start_time = time.time()
        self.metrics.request_count += 1

        try:
            # 1. Rate limiting
            if self.rate_limiter:
                allowed, limit_info = self.rate_limiter.allow_request(user_id)
                if not allowed:
                    return {
                        'success': False,
                        'error': 'Rate limit exceeded',
                        'retry_after': limit_info['retry_after'],
                    }

            # 2. Circuit breaker
            if self.circuit_breaker:
                result = self.circuit_breaker.call(
                    self.agent_func,
                    user_input,
                    **kwargs
                )
            else:
                result = self.agent_func(user_input, **kwargs)

            # Success
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.success_count += 1
            self.metrics.total_latency_ms += latency_ms
            self.latency_history.append(latency_ms)
            self._update_latency_percentiles()

            return {
                'success': True,
                'result': result,
                'latency_ms': latency_ms,
                'agent_id': self.agent_id,
            }

        except Exception as e:
            # Error handling
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.error_count += 1

            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'latency_ms': latency_ms,
                'agent_id': self.agent_id,
            }

    def health_check(self) -> HealthCheck:
        """
        Perform health check.

        Returns:
            Health check result
        """
        start_time = time.time()
        checks = {}

        # Check 1: Circuit breaker state
        if self.circuit_breaker:
            checks['circuit_breaker'] = self.circuit_breaker.state == CircuitState.CLOSED
        else:
            checks['circuit_breaker'] = True

        # Check 2: Error rate
        if self.metrics.request_count > 0:
            error_rate = self.metrics.error_count / self.metrics.request_count
            checks['error_rate'] = error_rate < 0.1  # Less than 10%
        else:
            checks['error_rate'] = True

        # Check 3: Latency
        if self.metrics.p95_latency_ms > 0:
            checks['latency'] = self.metrics.p95_latency_ms < 5000  # Less than 5s
        else:
            checks['latency'] = True

        # Check 4: Uptime
        uptime = (datetime.now() - self.startup_time).total_seconds()
        checks['uptime'] = uptime > 10  # At least 10 seconds

        # Determine overall status
        if all(checks.values()):
            status = HealthStatus.HEALTHY
            message = "All checks passed"
        elif any(checks.values()):
            status = HealthStatus.DEGRADED
            message = f"Some checks failed: {[k for k, v in checks.items() if not v]}"
        else:
            status = HealthStatus.UNHEALTHY
            message = "All checks failed"

        latency_ms = (time.time() - start_time) * 1000

        health = HealthCheck(
            status=status,
            checks=checks,
            message=message,
            timestamp=datetime.now(),
            latency_ms=latency_ms,
        )

        self.last_health_check = health
        return health

    def readiness_check(self) -> bool:
        """
        Check if agent is ready to serve traffic.

        Returns:
            True if ready
        """
        # Check if initialized
        if (datetime.now() - self.startup_time).total_seconds() < 5:
            return False

        # Check health
        health = self.health_check()
        return health.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]

    def get_metrics(self) -> Dict[str, Any]:
        """Get production metrics."""
        return {
            'agent_id': self.agent_id,
            'request_count': self.metrics.request_count,
            'success_count': self.metrics.success_count,
            'error_count': self.metrics.error_count,
            'error_rate': self.metrics.error_count / self.metrics.request_count if self.metrics.request_count > 0 else 0,
            'avg_latency_ms': self.metrics.total_latency_ms / self.metrics.success_count if self.metrics.success_count > 0 else 0,
            'p50_latency_ms': self.metrics.p50_latency_ms,
            'p95_latency_ms': self.metrics.p95_latency_ms,
            'p99_latency_ms': self.metrics.p99_latency_ms,
            'uptime_seconds': (datetime.now() - self.startup_time).total_seconds(),
            'circuit_breaker_state': self.circuit_breaker.state.value if self.circuit_breaker else 'disabled',
        }

    def _update_latency_percentiles(self):
        """Update latency percentiles."""
        if not self.latency_history:
            return

        sorted_latencies = sorted(self.latency_history)
        n = len(sorted_latencies)

        self.metrics.p50_latency_ms = sorted_latencies[int(n * 0.5)]
        self.metrics.p95_latency_ms = sorted_latencies[int(n * 0.95)]
        self.metrics.p99_latency_ms = sorted_latencies[int(n * 0.99)]

    def reset_metrics(self):
        """Reset metrics (useful for testing)."""
        self.metrics = Metrics()
        self.latency_history.clear()


class FallbackHandler:
    """Handle failures with fallback responses."""

    def __init__(self, fallback_responses: Optional[List[str]] = None):
        """
        Initialize fallback handler.

        Args:
            fallback_responses: List of fallback messages
        """
        self.fallback_responses = fallback_responses or [
            "I'm experiencing technical difficulties. Please try again later.",
            "The service is temporarily unavailable.",
            "An error occurred. Our team has been notified.",
        ]
        self.fallback_index = 0

    def get_fallback_response(self, error: Exception) -> Dict[str, Any]:
        """
        Get fallback response for error.

        Args:
            error: The exception that occurred

        Returns:
            Fallback response
        """
        response = self.fallback_responses[self.fallback_index % len(self.fallback_responses)]
        self.fallback_index += 1

        return {
            'success': False,
            'response': response,
            'fallback': True,
            'error_type': type(error).__name__,
        }


def production_ready(
    agent_id: str,
    enable_circuit_breaker: bool = True,
    enable_rate_limiting: bool = True,
    rate_limit: int = 100,
):
    """
    Decorator to make an agent production-ready.

    Args:
        agent_id: Unique agent identifier
        enable_circuit_breaker: Enable circuit breaker
        enable_rate_limiting: Enable rate limiting
        rate_limit: Requests per minute

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        production_agent = ProductionAgent(
            agent_func=func,
            agent_id=agent_id,
            enable_circuit_breaker=enable_circuit_breaker,
            enable_rate_limiting=enable_rate_limiting,
            rate_limit=rate_limit,
        )

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return production_agent.invoke(*args, **kwargs)

        # Attach utility methods
        wrapper.health_check = production_agent.health_check
        wrapper.readiness_check = production_agent.readiness_check
        wrapper.get_metrics = production_agent.get_metrics
        wrapper.reset_metrics = production_agent.reset_metrics

        return wrapper

    return decorator


class GradualRollout:
    """Manage gradual rollout of agent versions."""

    def __init__(self):
        """Initialize rollout manager."""
        self.versions: Dict[str, Callable] = {}
        self.traffic_splits: Dict[str, float] = {}

    def register_version(self, version: str, agent_func: Callable, traffic_percent: float):
        """
        Register an agent version.

        Args:
            version: Version identifier
            agent_func: Agent function
            traffic_percent: Percentage of traffic (0.0 to 1.0)
        """
        self.versions[version] = agent_func
        self.traffic_splits[version] = traffic_percent

    def route_request(self, user_id: str) -> Callable:
        """
        Route request to appropriate version.

        Args:
            user_id: User identifier

        Returns:
            Agent function to use
        """
        # Simple hash-based routing
        user_hash = hash(user_id) % 100
        cumulative = 0.0

        for version, percent in self.traffic_splits.items():
            cumulative += percent * 100
            if user_hash < cumulative:
                return self.versions[version]

        # Default to first version
        return list(self.versions.values())[0]
