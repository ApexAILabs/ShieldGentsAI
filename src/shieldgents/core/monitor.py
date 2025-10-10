"""Monitoring and alerting for agent behavior and security events."""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from collections import defaultdict, deque
import threading


class EventType(Enum):
    """Types of security events."""

    PROMPT_INJECTION = "prompt_injection"
    RESOURCE_LIMIT = "resource_limit"
    PERMISSION_DENIED = "permission_denied"
    TOOL_EXECUTION = "tool_execution"
    ANOMALY_DETECTED = "anomaly_detected"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    AUTHENTICATION = "authentication"
    DATA_ACCESS = "data_access"


class Severity(Enum):
    """Event severity levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Security event data structure."""

    event_type: EventType
    severity: Severity
    timestamp: float = field(default_factory=time.time)
    agent_id: Optional[str] = None
    tool_name: Optional[str] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["severity"] = self.severity.value
        data["datetime"] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


class SecurityLogger:
    """Enhanced logger for security events."""

    def __init__(
        self,
        name: str = "shieldgents",
        log_file: Optional[str] = None,
        json_format: bool = True,
    ) -> None:
        """
        Initialize security logger.

        Args:
            name: Logger name
            log_file: Path to log file
            json_format: Use JSON format for logs
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.json_format = json_format

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(console_formatter)
            self.logger.addHandler(file_handler)

    def log_event(self, event: SecurityEvent) -> None:
        """
        Log a security event.

        Args:
            event: Security event to log
        """
        if self.json_format:
            message = json.dumps(event.to_dict())
        else:
            message = f"[{event.event_type.value}] {event.message}"

        level_map = {
            Severity.DEBUG: logging.DEBUG,
            Severity.INFO: logging.INFO,
            Severity.WARNING: logging.WARNING,
            Severity.ERROR: logging.ERROR,
            Severity.CRITICAL: logging.CRITICAL,
        }

        self.logger.log(level_map[event.severity], message)


class AlertManager:
    """Manages alerts based on security events."""

    def __init__(self) -> None:
        """Initialize alert manager."""
        self.handlers: Dict[EventType, List[Callable]] = defaultdict(list)
        self.global_handlers: List[Callable] = []

    def register_handler(
        self,
        handler: Callable[[SecurityEvent], None],
        event_type: Optional[EventType] = None,
    ) -> None:
        """
        Register an alert handler.

        Args:
            handler: Callback function to handle alerts
            event_type: Specific event type to handle (None for all)
        """
        if event_type is None:
            self.global_handlers.append(handler)
        else:
            self.handlers[event_type].append(handler)

    def trigger_alert(self, event: SecurityEvent) -> None:
        """
        Trigger alerts for a security event.

        Args:
            event: Security event that triggered the alert
        """
        # Trigger specific handlers
        for handler in self.handlers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                logging.error(f"Alert handler failed: {e}")

        # Trigger global handlers
        for handler in self.global_handlers:
            try:
                handler(event)
            except Exception as e:
                logging.error(f"Global alert handler failed: {e}")


class AnomalyDetector:
    """Detects anomalies in agent behavior using simple heuristics."""

    def __init__(
        self,
        window_size: int = 100,
        std_threshold: float = 3.0,
    ) -> None:
        """
        Initialize anomaly detector.

        Args:
            window_size: Size of sliding window for statistics
            std_threshold: Standard deviation threshold for anomaly
        """
        self.window_size = window_size
        self.std_threshold = std_threshold
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.lock = threading.Lock()

    def record_metric(self, metric_name: str, value: float) -> None:
        """
        Record a metric value.

        Args:
            metric_name: Name of the metric
            value: Metric value
        """
        with self.lock:
            self.metrics[metric_name].append(value)

    def is_anomaly(self, metric_name: str, value: float) -> bool:
        """
        Check if a value is anomalous.

        Args:
            metric_name: Name of the metric
            value: Value to check

        Returns:
            True if value is anomalous
        """
        with self.lock:
            history = list(self.metrics[metric_name])

        if len(history) < 10:
            return False

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std = variance**0.5

        if std == 0:
            return value != mean

        z_score = abs((value - mean) / std)
        return z_score > self.std_threshold


class MetricsCollector:
    """Collects and aggregates security metrics."""

    def __init__(self) -> None:
        """Initialize metrics collector."""
        self.counters: Dict[str, int] = defaultdict(int)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.gauges: Dict[str, float] = {}
        self.lock = threading.Lock()

    def increment_counter(self, name: str, value: int = 1) -> None:
        """
        Increment a counter metric.

        Args:
            name: Counter name
            value: Amount to increment (default: 1)
        """
        with self.lock:
            self.counters[name] += value

    def record_timing(self, name: str, duration: float) -> None:
        """
        Record a timing metric.

        Args:
            name: Timer name
            duration: Duration in seconds
        """
        with self.lock:
            self.timers[name].append(duration)

    def set_gauge(self, name: str, value: float) -> None:
        """
        Set a gauge metric.

        Args:
            name: Gauge name
            value: Gauge value
        """
        with self.lock:
            self.gauges[name] = value

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get all metrics.

        Returns:
            Dictionary containing all counters, gauges, and timers
        """
        with self.lock:
            metrics = {
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "timers": {},
            }

            for name, timings in self.timers.items():
                if timings:
                    metrics["timers"][name] = {
                        "count": len(timings),
                        "avg": sum(timings) / len(timings),
                        "min": min(timings),
                        "max": max(timings),
                    }

        return metrics

    def reset(self) -> None:
        """
        Reset all metrics.

        Clears all counters, timers, and gauges.
        """
        with self.lock:
            self.counters.clear()
            self.timers.clear()
            self.gauges.clear()


class SecurityMonitor:
    """Unified security monitoring interface."""

    def __init__(
        self,
        logger: Optional[SecurityLogger] = None,
        alert_manager: Optional[AlertManager] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
        metrics_collector: Optional[MetricsCollector] = None,
    ) -> None:
        """
        Initialize security monitor.

        Args:
            logger: Security logger instance
            alert_manager: Alert manager instance
            anomaly_detector: Anomaly detector instance
            metrics_collector: Metrics collector instance
        """
        self.logger = logger or SecurityLogger()
        self.alert_manager = alert_manager or AlertManager()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.metrics = metrics_collector or MetricsCollector()

    def record_event(
        self,
        event_type: EventType,
        severity: Severity,
        message: str = "",
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """
        Record a security event.

        Args:
            event_type: Type of event
            severity: Severity level
            message: Event message
            agent_id: ID of the agent
            tool_name: Name of the tool
            metadata: Additional metadata

        Returns:
            Created security event
        """
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            agent_id=agent_id,
            tool_name=tool_name,
            metadata=metadata or {},
        )

        # Log the event
        self.logger.log_event(event)

        # Update metrics
        self.metrics.increment_counter(f"events.{event_type.value}")
        self.metrics.increment_counter(f"severity.{severity.value}")

        # Trigger alerts for high severity
        if severity in [Severity.ERROR, Severity.CRITICAL]:
            self.alert_manager.trigger_alert(event)

        return event

    def check_anomaly(
        self,
        metric_name: str,
        value: float,
        agent_id: Optional[str] = None,
    ) -> bool:
        """
        Check for anomaly and record if detected.

        Args:
            metric_name: Name of the metric
            value: Metric value
            agent_id: ID of the agent

        Returns:
            True if anomaly detected
        """
        is_anomaly = self.anomaly_detector.is_anomaly(metric_name, value)

        if is_anomaly:
            self.record_event(
                event_type=EventType.ANOMALY_DETECTED,
                severity=Severity.WARNING,
                message=f"Anomaly detected in {metric_name}: {value}",
                agent_id=agent_id,
                metadata={"metric": metric_name, "value": value},
            )

        self.anomaly_detector.record_metric(metric_name, value)
        return is_anomaly

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for dashboard visualization."""
        return {
            "metrics": self.metrics.get_metrics(),
            "timestamp": time.time(),
        }
