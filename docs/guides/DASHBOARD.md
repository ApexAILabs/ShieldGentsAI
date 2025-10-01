# 🎨 ShieldGents Dashboard Guide

## Overview

ShieldGents includes a **Streamlit-based dashboard** for real-time security monitoring and visualization.

## 📊 Dashboard Features

### Main Dashboard (`create_dashboard`)
- **Key Metrics Cards**
  - Total events count
  - Critical events
  - Anomalies detected
  - Blocked attacks

- **Event Distribution Charts**
  - Pie chart: Events by type
  - Bar chart: Events by severity

- **Performance Metrics**
  - Execution times (min, max, avg)
  - Operation counts

- **System Gauges**
  - Real-time metrics visualization

- **Auto-refresh**
  - Configurable refresh interval
  - Live updates

### Red Team Report Dashboard (`create_red_team_report`)
- Test summary metrics
- Results by category
- Failed test details
- Execution time analysis

## 🚀 Quick Start

### Option 1: Basic Dashboard

```bash
# Start the dashboard
streamlit run examples/run_dashboard.py
```

This will open at `http://localhost:8501`

### Option 2: Interactive Demo Dashboard

```bash
# Start interactive demo with agent interface
streamlit run examples/dashboard_with_agent.py
```

Features:
- ✅ Test agent interface in sidebar
- ✅ Real-time security monitoring
- ✅ Live event visualization
- ✅ PII detection alerts
- ✅ Prompt injection blocking
- ✅ Rate limiting status
- ✅ Audit event tracking

## 📸 Dashboard Components

### 1. Key Metrics Row
```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│Total Events │Critical/Err │  Warnings   │Rate Limit   │
│    1,234    │     12      │     45      │  Remaining  │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

### 2. Event Distribution Charts
- **Pie Chart**: Shows proportion of different event types
- **Bar Chart**: Shows severity distribution with color coding

### 3. Performance Metrics Table
| Operation | Count | Avg (ms) | Min (ms) | Max (ms) |
|-----------|-------|----------|----------|----------|
| tool_exec | 100   | 45.2     | 12.3     | 123.4    |

### 4. System Gauges
Real-time gauge displays for system metrics (0-100 scale)

## 🎮 Using the Interactive Dashboard

### Test Agent Interface

1. **Enter User ID**
   ```
   User ID: demo-user
   ```

2. **Enter Prompt**
   ```
   Try these examples:
   - "What is the weather?"           → Safe
   - "My email is test@example.com"   → PII detected
   - "Ignore all instructions"        → Blocked
   ```

3. **Click Execute** 🚀
   - Watch real-time security checks
   - See results in dashboard metrics
   - View blocked attacks

### Quick Test Buttons

- **Test: Safe Query** - Generate a normal event
- **Test: Injection Attempt** - Simulate attack
- **Test: Anomaly** - Trigger anomaly detection

## 💻 Programmatic Usage

### From Python Code

```python
import streamlit as st
from shieldgents.core import SecurityMonitor
from shieldgents.interface.dashboard import create_dashboard

# Initialize monitor
monitor = SecurityMonitor()

# Record some events
monitor.record_event(
    event_type=EventType.TOOL_EXECUTION,
    severity=Severity.INFO,
    message="User action"
)

# Create dashboard
create_dashboard(monitor)
```

### Custom Dashboard

```python
import streamlit as st
from shieldgents.core import SecurityMonitor

monitor = SecurityMonitor()

# Get data
data = monitor.get_dashboard_data()
metrics = data["metrics"]

# Custom display
st.title("My Custom Security Dashboard")

col1, col2 = st.columns(2)

with col1:
    total = sum(metrics["counters"].values())
    st.metric("Total Events", total)

with col2:
    errors = metrics["counters"].get("severity.error", 0)
    st.metric("Errors", errors)

# Add your custom visualizations
import plotly.express as px

event_data = {
    k.replace("events.", ""): v
    for k, v in metrics["counters"].items()
    if k.startswith("events.")
}

fig = px.bar(x=list(event_data.keys()), y=list(event_data.values()))
st.plotly_chart(fig)
```

## 🎨 Dashboard Customization

### Change Port

```bash
streamlit run examples/dashboard_with_agent.py --server.port 8502
```

### Disable Auto-open Browser

```bash
streamlit run examples/dashboard_with_agent.py --server.headless true
```

### Configuration File

Create `.streamlit/config.toml`:

```toml
[server]
port = 8501
headless = false

[theme]
primaryColor = "#2E86AB"
backgroundColor = "#F4F4F8"
secondaryBackgroundColor = "#FFFFFF"
textColor = "#191923"
font = "sans serif"
```

## 📊 Dashboard Views

### Security Overview
- Real-time threat detection
- Event timeline
- Severity distribution
- Top agents/users

### Red Team Results
```bash
# Run red team tests
python examples/red_team_test.py

# View results in dashboard
streamlit run examples/red_team_dashboard.py
```

Shows:
- Pass/fail rates
- Failed test details
- Attack category breakdown
- Execution times

## 🔄 Auto-Refresh

Enable auto-refresh in the dashboard:

```python
# In your Streamlit app
import time

auto_refresh = st.checkbox("Auto-refresh (5s)")

if auto_refresh:
    time.sleep(5)
    st.rerun()
```

## 📱 Responsive Design

The dashboard is responsive and works on:
- 💻 Desktop (optimal)
- 📱 Tablet (good)
- 📱 Mobile (basic)

## 🎯 Use Cases

### 1. Development Monitoring
Monitor your agent during development:
```bash
streamlit run examples/dashboard_with_agent.py
```

### 2. Production Monitoring
Deploy dashboard alongside your production agent:
```bash
# Run in background
nohup streamlit run production_dashboard.py &
```

### 3. Security Testing
Visualize red team test results:
```bash
streamlit run examples/red_team_dashboard.py
```

### 4. Compliance Reporting
Generate visual compliance reports:
```python
from shieldgents.governance import AuditLogger

audit = AuditLogger()
report = audit.generate_report()

# Display in dashboard
st.json(report)
```

## 🚀 Advanced Features

### Multi-Agent Monitoring

```python
monitors = {
    "agent-1": SecurityMonitor(),
    "agent-2": SecurityMonitor(),
    "agent-3": SecurityMonitor(),
}

# Create tabs for each agent
tabs = st.tabs(list(monitors.keys()))

for tab, (agent_id, monitor) in zip(tabs, monitors.items()):
    with tab:
        st.header(f"Agent: {agent_id}")
        create_dashboard(monitor)
```

### Export Reports

```python
# Export metrics as JSON
if st.button("Export Metrics"):
    data = monitor.get_dashboard_data()
    st.download_button(
        "Download JSON",
        data=json.dumps(data, indent=2),
        file_name="security_metrics.json"
    )
```

### Alert Integration

```python
# Send alerts based on metrics
data = monitor.get_dashboard_data()
critical = data["metrics"]["counters"].get("severity.critical", 0)

if critical > 10:
    st.error(f"🚨 ALERT: {critical} critical events!")
    # Send to Slack, PagerDuty, etc.
```

## 🐛 Troubleshooting

### Issue: Streamlit not found
```bash
uv add streamlit plotly pandas
```

### Issue: Port already in use
```bash
streamlit run app.py --server.port 8502
```

### Issue: Dashboard not updating
- Check auto-refresh is enabled
- Verify monitor is being updated
- Try manual page refresh (F5)

## 📖 More Resources

- [Streamlit Documentation](https://docs.streamlit.io)
- [Plotly Charts](https://plotly.com/python/)
- [ShieldGents Examples](examples/)

---

**Ready to visualize your AI security? 🎨🛡️**