"""Run the ShieldGents security dashboard.

This script demonstrates how to run the dashboard with live security data.

Usage:
    streamlit run examples/run_dashboard.py
"""

import streamlit as st
import time

from shieldgents.core import EventType, SecurityMonitor, Severity
from shieldgents.interface.dashboard import create_dashboard


# Initialize security monitor
if 'monitor' not in st.session_state:
    st.session_state.monitor = SecurityMonitor()

monitor = st.session_state.monitor

# Simulate some security events for demo
if st.sidebar.button("Generate Demo Events"):
    events = [
        (EventType.TOOL_EXECUTION, Severity.INFO, "User executed search tool", "agent-001"),
        (EventType.TOOL_EXECUTION, Severity.INFO, "User executed calculator", "agent-002"),
        (EventType.PROMPT_INJECTION, Severity.WARNING, "Detected injection attempt", "agent-001"),
        (EventType.ANOMALY_DETECTED, Severity.WARNING, "Unusual request rate", "agent-003"),
        (EventType.THRESHOLD_EXCEEDED, Severity.ERROR, "Rate limit exceeded", "agent-001"),
    ]

    for event_type, severity, message, agent_id in events:
        monitor.record_event(
            event_type=event_type,
            severity=severity,
            message=message,
            agent_id=agent_id,
        )

    st.success("Demo events generated!")

# Run the dashboard
create_dashboard(monitor)
