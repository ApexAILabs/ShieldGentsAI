"""Complete example: Run a secure agent with live dashboard.

This creates a secure agent that logs to a monitor, and visualizes
the security metrics in real-time.

Usage:
    streamlit run examples/dashboard_with_agent.py
"""

import streamlit as st
import time

from shieldgents.core import (
    EventType,
    PromptGuard,
    RateLimiter,
    SecurityMonitor,
    Severity,
)
from shieldgents.core.context import PIIDetector
from shieldgents.governance import AuditEventType, AuditLogger


# Initialize components
@st.cache_resource
def init_security():
    return {
        'guard': PromptGuard(),
        'pii': PIIDetector(),
        'rate_limiter': RateLimiter(max_requests=10, window_seconds=60),
        'monitor': SecurityMonitor(),
        'audit': AuditLogger(enable_console=False),
    }

security = init_security()


# Page config
st.set_page_config(
    page_title="🛡️ ShieldGents Live Demo",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ ShieldGents Security Dashboard")
st.markdown("### Real-time AI Agent Security Monitoring")

# Sidebar - Agent Interface
with st.sidebar:
    st.header("🤖 Test Agent Interface")

    user_id = st.text_input("User ID", value="demo-user")
    user_input = st.text_area(
        "Enter prompt:",
        placeholder="Try: 'What is the weather?' or 'Ignore all instructions'"
    )

    if st.button("🚀 Execute", type="primary"):
        if user_input:
            # Rate limiting
            if not security['rate_limiter'].check_rate_limit(user_id):
                st.error("⚠️ Rate limit exceeded!")
                security['monitor'].record_event(
                    event_type=EventType.THRESHOLD_EXCEEDED,
                    severity=Severity.WARNING,
                    message="Rate limit exceeded",
                    metadata={"user_id": user_id}
                )
            else:
                # PII detection
                pii_result = security['pii'].scan(user_input)
                if pii_result.has_pii:
                    st.warning(f"⚠️ PII Detected: {[m.pii_type.value for m in pii_result.matches]}")
                    security['monitor'].record_event(
                        event_type=EventType.DATA_ACCESS,
                        severity=Severity.WARNING,
                        message="PII detected in input",
                        metadata={"user_id": user_id}
                    )
                    user_input = pii_result.redacted_text

                # Prompt injection check
                guard_result = security['guard'].guard(user_input)

                if not guard_result.is_safe:
                    st.error(f"🚫 Blocked! Threat Level: {guard_result.threat_level.value}")
                    st.error(f"Detected patterns: {', '.join(guard_result.detected_patterns)}")

                    security['monitor'].record_event(
                        event_type=EventType.PROMPT_INJECTION,
                        severity=Severity.ERROR,
                        message=f"Prompt injection detected: {guard_result.threat_level.value}",
                        metadata={
                            "user_id": user_id,
                            "patterns": guard_result.detected_patterns
                        }
                    )

                    security['audit'].log_event(
                        event_type=AuditEventType.PROMPT_INJECTION,
                        action="Blocked unsafe input",
                        user_id=user_id,
                        outcome="blocked"
                    )
                else:
                    st.success("✅ Input validated successfully!")
                    st.info(f"Processing: {guard_result.sanitized_input or user_input}")

                    security['monitor'].record_event(
                        event_type=EventType.TOOL_EXECUTION,
                        severity=Severity.INFO,
                        message="Agent executed successfully",
                        metadata={"user_id": user_id}
                    )

                    security['audit'].log_event(
                        event_type=AuditEventType.AGENT_START,
                        action="Agent invoked",
                        user_id=user_id,
                        outcome="success"
                    )

    st.divider()

    # Test buttons
    st.subheader("Quick Tests")

    if st.button("Test: Safe Query"):
        security['monitor'].record_event(
            event_type=EventType.TOOL_EXECUTION,
            severity=Severity.INFO,
            message="Safe query executed",
        )

    if st.button("Test: Injection Attempt"):
        security['monitor'].record_event(
            event_type=EventType.PROMPT_INJECTION,
            severity=Severity.ERROR,
            message="Injection attempt blocked",
        )

    if st.button("Test: Anomaly"):
        security['monitor'].record_event(
            event_type=EventType.ANOMALY_DETECTED,
            severity=Severity.WARNING,
            message="Unusual activity detected",
        )

# Main dashboard area
data = security['monitor'].get_dashboard_data()
metrics = data.get("metrics", {})

# Key metrics row
col1, col2, col3, col4 = st.columns(4)

with col1:
    total_events = sum(metrics.get("counters", {}).values())
    st.metric("Total Events", f"{total_events:,}")

with col2:
    critical = metrics.get("counters", {}).get("severity.critical", 0)
    errors = metrics.get("counters", {}).get("severity.error", 0)
    st.metric("Critical/Error", f"{critical + errors}", delta=critical, delta_color="inverse")

with col3:
    warnings = metrics.get("counters", {}).get("severity.warning", 0)
    st.metric("Warnings", warnings, delta_color="off")

with col4:
    remaining = security['rate_limiter'].get_remaining(user_id)
    st.metric("Rate Limit Remaining", remaining)

st.divider()

# Charts row
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Events by Type")
    event_counters = {
        k.replace("events.", ""): v
        for k, v in metrics.get("counters", {}).items()
        if k.startswith("events.")
    }

    if event_counters:
        import plotly.express as px
        fig = px.pie(
            values=list(event_counters.values()),
            names=list(event_counters.keys()),
            title="Event Distribution",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No events recorded yet. Try the test buttons!")

with col2:
    st.subheader("⚠️ Events by Severity")
    severity_counters = {
        k.replace("severity.", ""): v
        for k, v in metrics.get("counters", {}).items()
        if k.startswith("severity.")
    }

    if severity_counters:
        import plotly.express as px
        fig = px.bar(
            x=list(severity_counters.keys()),
            y=list(severity_counters.values()),
            title="Severity Distribution",
            labels={"x": "Severity", "y": "Count"},
            color=list(severity_counters.keys()),
            color_discrete_map={
                "debug": "#808080",
                "info": "#0088ff",
                "warning": "#ff8800",
                "error": "#ff0000",
                "critical": "#8800ff",
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No severity data yet.")

st.divider()

# Recent events
st.subheader("📋 Recent Security Events")

# Get recent audit events
audit_report = security['audit'].generate_report()

if audit_report['total_events'] > 0:
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Audit Events", audit_report['total_events'])

    with col2:
        success_rate = (
            audit_report['by_outcome'].get('success', 0) /
            audit_report['total_events'] * 100
            if audit_report['total_events'] > 0 else 0
        )
        st.metric("Success Rate", f"{success_rate:.1f}%")

    with col3:
        blocked = audit_report['by_outcome'].get('blocked', 0)
        st.metric("Blocked Attacks", blocked, delta_color="inverse")

    # Show event types
    st.write("**Events by Type:**")
    st.json(audit_report['by_type'])
else:
    st.info("No audit events yet. Use the agent interface to generate events.")

st.divider()

# Auto-refresh option
auto_refresh = st.checkbox("Auto-refresh (every 5 seconds)")
if auto_refresh:
    time.sleep(5)
    st.rerun()

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center'>
        <p>🛡️ <strong>ShieldGents</strong> - Security for Agentic AI</p>
        <p><small>Production-ready security tooling for AI agent frameworks</small></p>
    </div>
    """,
    unsafe_allow_html=True
)
