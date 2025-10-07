"""Dashboard for visualizing security metrics and monitoring."""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from typing import Dict, Any, List
import time


def create_dashboard(monitor: Any) -> None:
    """
    Create Streamlit dashboard for security monitoring.

    Args:
        monitor: SecurityMonitor instance
    """
    st.set_page_config(
        page_title="ShieldGents Security Dashboard",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ ShieldGents Security Dashboard")
    st.markdown("Real-time security monitoring for agentic AI systems")

    # Sidebar
    with st.sidebar:
        st.header("Settings")
        auto_refresh = st.checkbox("Auto-refresh", value=True)
        refresh_interval = st.slider("Refresh interval (seconds)", 1, 60, 5)

        st.divider()

        st.header("Filters")
        _ = st.multiselect(
            "Severity Levels",
            ["debug", "info", "warning", "error", "critical"],
            default=["warning", "error", "critical"],
        )

    # Get dashboard data
    data = monitor.get_dashboard_data()
    metrics = data.get("metrics", {})

    # Key metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        total_events = sum(metrics.get("counters", {}).values())
        st.metric("Total Events", f"{total_events:,}")

    with col2:
        critical_events = metrics.get("counters", {}).get("severity.critical", 0)
        st.metric("Critical Events", critical_events, delta_color="inverse")

    with col3:
        anomalies = metrics.get("counters", {}).get("events.anomaly_detected", 0)
        st.metric("Anomalies Detected", anomalies, delta_color="inverse")

    with col4:
        blocked_attacks = metrics.get("counters", {}).get("events.prompt_injection", 0)
        st.metric("Blocked Attacks", blocked_attacks)

    st.divider()

    # Charts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Events by Type")
        event_counters = {
            k.replace("events.", ""): v
            for k, v in metrics.get("counters", {}).items()
            if k.startswith("events.")
        }

        if event_counters:
            fig = px.pie(
                values=list(event_counters.values()),
                names=list(event_counters.keys()),
                title="Event Distribution",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events recorded yet")

    with col2:
        st.subheader("Events by Severity")
        severity_counters = {
            k.replace("severity.", ""): v
            for k, v in metrics.get("counters", {}).items()
            if k.startswith("severity.")
        }

        if severity_counters:
            fig = px.bar(
                x=list(severity_counters.keys()),
                y=list(severity_counters.values()),
                title="Severity Distribution",
                labels={"x": "Severity", "y": "Count"},
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity data available")

    st.divider()

    # Timing metrics
    st.subheader("Performance Metrics")

    timers = metrics.get("timers", {})
    if timers:
        timing_df = pd.DataFrame(
            [
                {
                    "Operation": name,
                    "Count": data["count"],
                    "Avg (ms)": round(data["avg"] * 1000, 2),
                    "Min (ms)": round(data["min"] * 1000, 2),
                    "Max (ms)": round(data["max"] * 1000, 2),
                }
                for name, data in timers.items()
            ]
        )
        st.dataframe(timing_df, use_container_width=True)
    else:
        st.info("No timing metrics available")

    st.divider()

    # Gauges
    st.subheader("System Gauges")
    gauges = metrics.get("gauges", {})

    if gauges:
        gauge_cols = st.columns(min(len(gauges), 4))
        for idx, (name, value) in enumerate(gauges.items()):
            with gauge_cols[idx % 4]:
                fig = go.Figure(
                    go.Indicator(
                        mode="gauge+number",
                        value=value,
                        title={"text": name},
                        gauge={"axis": {"range": [0, 100]}},
                    )
                )
                fig.update_layout(height=250)
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No gauge metrics available")

    # Auto-refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


def create_red_team_report(results: List[Any]) -> None:
    """
    Create dashboard for red team test results.

    Args:
        results: List of TestResult objects
    """
    st.set_page_config(
        page_title="ShieldGents Red Team Report",
        page_icon="🔴",
        layout="wide",
    )

    st.title("🔴 Red Team Security Test Report")

    # Summary metrics
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    pass_rate = (passed / total * 100) if total > 0 else 0

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Tests", total)

    with col2:
        st.metric("Passed", passed, delta=f"{pass_rate:.1f}%")

    with col3:
        st.metric("Failed", failed, delta=f"-{100-pass_rate:.1f}%", delta_color="inverse")

    with col4:
        avg_time = sum(r.execution_time for r in results) / total if total > 0 else 0
        st.metric("Avg Time", f"{avg_time:.3f}s")

    st.divider()

    # Results by category
    st.subheader("Results by Attack Category")

    category_data: Dict[str, Dict[str, int]] = {}
    for result in results:
        category = result.attack_vector.category.value
        if category not in category_data:
            category_data[category] = {"passed": 0, "failed": 0}

        if result.passed:
            category_data[category]["passed"] += 1
        else:
            category_data[category]["failed"] += 1

    category_df = pd.DataFrame(category_data).T
    fig = px.bar(
        category_df,
        barmode="group",
        title="Test Results by Category",
        labels={"value": "Count", "variable": "Status"},
    )
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Failed tests detail
    st.subheader("Failed Tests")

    failed_results = [r for r in results if not r.passed]

    if failed_results:
        for result in failed_results:
            with st.expander(f"❌ {result.attack_vector.name} ({result.attack_vector.severity})"):
                st.write(f"**Category:** {result.attack_vector.category.value}")
                st.write(f"**Description:** {result.attack_vector.description}")
                st.write(f"**Expected:** {result.attack_vector.expected_behavior}")
                st.code(result.attack_vector.payload, language="text")
                if result.response:
                    st.write("**Response:**")
                    st.code(str(result.response), language="text")
    else:
        st.success("All tests passed! 🎉")

    st.divider()

    # Execution times
    st.subheader("Execution Times")

    time_df = pd.DataFrame(
        [
            {
                "Test": r.attack_vector.name,
                "Time (ms)": round(r.execution_time * 1000, 2),
                "Status": "✅ Passed" if r.passed else "❌ Failed",
            }
            for r in results
        ]
    )

    fig = px.bar(
        time_df,
        x="Test",
        y="Time (ms)",
        color="Status",
        title="Test Execution Times",
    )
    st.plotly_chart(fig, use_container_width=True)


def run_dashboard(monitor: Any, host: str = "localhost", port: int = 8501) -> None:
    """
    Run the dashboard server.

    Args:
        monitor: SecurityMonitor instance
        host: Host address
        port: Port number
    """
    # This would typically be called from command line
    # streamlit run dashboard.py
    pass
