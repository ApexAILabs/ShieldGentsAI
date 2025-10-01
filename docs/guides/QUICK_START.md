# ShieldGents Quick Start Guide

## What is ShieldGents?

ShieldGents is a comprehensive security framework for AI agents, protecting against **20+ attack vectors** including prompt injection, data exfiltration, privilege escalation, and more.

---

## 5-Minute Quick Start

### Installation

```bash
pip install shieldgents
```

### Basic Usage

```python
from shieldgents import AgentShield

# Create shield
shield = AgentShield(agent_id="my-agent")

# Protect your agent
def my_secure_agent(prompt, user_id):
    # 1. Guard input
    guard_result = shield.prompt_guard.guard(prompt)
    if not guard_result.is_safe:
        return {"error": "Unsafe prompt blocked"}

    # 2. Your agent logic here
    response = your_agent_function(prompt)

    # 3. Monitor output
    shield.monitor.record_event(...)

    return {"response": response}
```

---

## New Advanced Features (v0.2.0)

### 🔥 **MCP Server Security** (Most Important for MCP Users!)

Secure your Model Context Protocol servers:

```python
from shieldgents.mcp_security import secure_mcp_server

# Register and secure MCP server
registry, monitor = secure_mcp_server(
    server_id="my-mcp-server",
    server_url="mcp://example.com",
    is_trusted=True,
    allowed_tools=["search", "calculator"],
    blocked_tools=["execute_code"]
)

# Before calling MCP tool
allowed, alert = monitor.check_request(
    server_id="my-mcp-server",
    tool_name="search",
    parameters={"query": user_input},
    user_id="user123",
    session_id="session456"
)

if not allowed:
    print(f"🚨 Blocked: {alert.description}")
else:
    # Call MCP tool
    response = mcp_client.call_tool("search", ...)

    # Validate response
    is_valid, alert, sanitized = monitor.check_response(
        server_id="my-mcp-server",
        tool_name="search",
        content=response
    )
```

**Protects Against:**
- Malicious MCP servers
- Parameter injection (command injection, path traversal)
- Data exfiltration via tool responses
- Prompt injection in responses
- Credential exposure
- Excessive resource usage

---

### 1. **Data Exfiltration Detection**

Catches attempts to leak data via encoding:

```python
from shieldgents.exfiltration import ExfiltrationDetector

detector = ExfiltrationDetector(sensitivity=0.7)
result = detector.scan(agent_output)

if result.is_suspicious:
    print(f"🚨 Exfiltration attempt: {result.methods_detected}")
    # Use sanitized output
    safe_output = result.sanitized_output
```

**Detects:**
- Base64/hex/binary encoding
- Unusual data volumes
- Steganography patterns
- URL-encoded data

---

### 2. **Tool Chain Abuse Prevention**

Prevents lateral movement via tool chaining:

```python
from shieldgents.tool_chain import ToolChainMonitor, ToolChainPolicy

policy = ToolChainPolicy()
policy.add_forbidden_chain('file_read', 'network_request')

monitor = ToolChainMonitor(policy=policy)

# Before each tool call
violations = monitor.record_tool_call(
    tool_name='file_read',
    user_id='user123',
    session_id='session456'
)

if violations:
    print(f"🚨 Tool chain violation: {violations[0].description}")
```

**Prevents:**
- Credential harvesting chains
- Data exfiltration sequences
- Privilege escalation via tools
- Suspicious tool combinations

---

### 3. **Privilege Escalation Detection**

Blocks unauthorized privilege elevation:

```python
from shieldgents.privilege import PrivilegeMonitor, PrivilegeLevel

monitor = PrivilegeMonitor(strict_mode=True)
monitor.set_user_privilege('user123', PrivilegeLevel.USER)

# Check operations
allowed, alert = monitor.check_operation(
    user_id='user123',
    operation='delete_user',
    session_id='session456'
)

if not allowed:
    print(f"🚨 Privilege escalation blocked: {alert.description}")
```

**Detects:**
- Direct escalation requests
- Social engineering attempts
- Impersonation
- Suspicious justifications

---

### 4. **Covert Channel Detection**

Finds hidden communication channels:

```python
from shieldgents.covert_channel import CovertChannelDetector

detector = CovertChannelDetector(sensitivity=0.6)
result = detector.scan(output, generation_time=1.5)

if result.detected:
    print(f"🚨 Covert channel: {result.channel_types}")
    # Use sanitized output
    safe_output = result.sanitized_output
```

**Detects:**
- Zero-width characters
- Unicode steganography
- Whitespace encoding
- Case-based encoding
- Timing channels
- Statistical anomalies

---

### 5. **Production Utilities**

Make your agent production-ready:

```python
from shieldgents.production import production_ready

@production_ready(
    agent_id="my-agent",
    enable_circuit_breaker=True,
    rate_limit=100  # requests per minute
)
def my_agent(prompt, user_id="default", **kwargs):
    return generate_response(prompt)

# Automatic features:
# - Circuit breaker for fault tolerance
# - Rate limiting per user
# - Health checks
# - Metrics (P50/P95/P99 latency)
# - Fallback handling

# Access utilities
health = my_agent.health_check()
metrics = my_agent.get_metrics()
ready = my_agent.readiness_check()
```

**Provides:**
- Circuit breakers
- Health/readiness checks
- Production metrics
- Gradual rollout support
- Fallback handlers

---

## Full Integration Example

```python
from shieldgents import AgentShield
from shieldgents.exfiltration import ExfiltrationDetector
from shieldgents.tool_chain import ToolChainMonitor
from shieldgents.privilege import PrivilegeMonitor
from shieldgents.covert_channel import CovertChannelDetector
from shieldgents.production import ProductionAgent

# Initialize all security layers
shield = AgentShield(agent_id="secure-agent")
exfil_detector = ExfiltrationDetector()
tool_monitor = ToolChainMonitor()
priv_monitor = PrivilegeMonitor()
covert_detector = CovertChannelDetector()

# Your agent function
def my_agent(prompt):
    return f"Response to: {prompt}"

# Wrap with production safeguards
production_agent = ProductionAgent(
    agent_func=my_agent,
    agent_id="secure-agent",
    enable_circuit_breaker=True,
    rate_limit=100
)

def secure_agent_call(prompt, user_id, session_id):
    # 1. Prompt injection guard
    guard_result = shield.prompt_guard.guard(prompt)
    if not guard_result.is_safe:
        return {"error": "Unsafe prompt blocked"}

    # 2. Privilege check
    allowed, alert = priv_monitor.check_operation(
        user_id, "execute_agent", session_id
    )
    if not allowed:
        return {"error": "Insufficient privileges"}

    # 3. Tool chain monitoring
    violations = tool_monitor.record_tool_call(
        tool_name="agent_execution",
        user_id=user_id,
        session_id=session_id
    )
    if violations:
        return {"error": "Tool chain violation"}

    # 4. Execute agent
    result = production_agent.invoke(prompt, user_id=user_id)

    # 5. Exfiltration detection
    if result.get('success'):
        exfil_result = exfil_detector.scan(result['result'])
        if exfil_result.is_suspicious:
            return {"error": "Suspicious output blocked"}

        # 6. Covert channel detection
        covert_result = covert_detector.scan(result['result'])
        if covert_result.detected:
            return {"error": "Covert channel detected"}

    return result

# Use it
response = secure_agent_call(
    prompt="What's the weather?",
    user_id="user123",
    session_id="session456"
)
```

---

## LangChain Integration

```python
from langchain.agents import create_openai_tools_agent
from shieldgents.core import ToolWrapper, FunctionSandbox

# Wrap LangChain tools with security
sandbox = FunctionSandbox()
tool_wrapper = ToolWrapper(sandbox=sandbox)

secure_tool = tool_wrapper.wrap_langchain_tool(my_langchain_tool)
```

---

## LangGraph Integration

```python
from langgraph.graph import StateGraph
from shieldgents.core import PromptGuard

def security_check_node(state):
    """Add security checks to your graph."""
    guard = PromptGuard()
    messages = state["messages"]
    last_message = messages[-1]

    guard_result = guard.guard(last_message.content)
    if not guard_result.is_safe:
        # Block or sanitize
        messages[-1].content = guard_result.sanitized_input

    return {"messages": messages}

# Add to your workflow
workflow = StateGraph(AgentState)
workflow.add_node("security_check", security_check_node)
workflow.add_node("agent", agent_node)
workflow.set_entry_point("security_check")
workflow.add_edge("security_check", "agent")
```

---

## Examples & Demos

### Run Interactive Demos

```bash
# Basic features
python examples/basic_usage.py

# Advanced security features
python examples/advanced_security_demo.py

# LangChain integration
python examples/langchain_integration.py

# Strands SDK integration
python examples/strands_sdk_integration.py
```

### Jupyter Notebook

```bash
jupyter notebook examples/agent_examples.ipynb
```

The notebook contains 5 comprehensive examples:
1. Basic security controls
2. LangChain + ShieldGents
3. LangGraph + ShieldGents
4. Web research agent with Firecrawl
5. Security monitoring & metrics

---

## Security Coverage

ShieldGents protects against:

✅ **Currently Protected:**
1. Prompt injection & jailbreaks
2. Credential & secret leakage
3. Unsafe tool execution
4. Data exfiltration (NEW)
5. Covert channels (NEW)
6. Tool chain abuse (NEW)
7. Privilege escalation (NEW)
8. Over-privileged connectors
9. Insecure logging
10. Rate limiting & DoS
11. Security monitoring
12. Production safety (NEW)

See `SECURITY_COVERAGE.md` for full details.

---

## Configuration Tips

### Tuning Sensitivity

```python
# More strict (fewer false negatives)
detector = ExfiltrationDetector(sensitivity=0.5)

# More lenient (fewer false positives)
detector = ExfiltrationDetector(sensitivity=0.9)
```

### Custom Policies

```python
# Tool chain policy
policy = ToolChainPolicy()
policy.register_tool('my_tool', ToolRiskLevel.HIGH, rate_limit=5)
policy.add_forbidden_chain('tool1', 'tool2', 'tool3')

# Privilege policy
policy = PrivilegePolicy()
policy.operation_privileges['my_operation'] = PrivilegeLevel.ADMIN
policy.approval_required.add('my_operation')
```

---

## Monitoring & Alerts

```python
# Get security metrics
dashboard_data = shield.monitor.get_dashboard_data()
print(f"Total events: {dashboard_data['metrics']['counters']}")

# Get audit logs
audit_report = shield.audit.generate_report()
print(f"Security events: {audit_report['by_type']}")

# Production metrics
metrics = production_agent.get_metrics()
print(f"Error rate: {metrics['error_rate']:.1%}")
print(f"P95 latency: {metrics['p95_latency_ms']:.2f}ms")
```

---

## Next Steps

1. **Start simple:** Use `AgentShield` for basic protection
2. **Add layers:** Integrate exfiltration, privilege, and tool chain monitors
3. **Production-ready:** Use `ProductionAgent` or `@production_ready` decorator
4. **Monitor:** Review security metrics and audit logs regularly
5. **Tune:** Adjust sensitivity based on your use case

---

## Support & Documentation

- 📖 Full docs: `SECURITY_COVERAGE.md`
- 🔬 Examples: `examples/` directory
- 📓 Jupyter: `examples/agent_examples.ipynb`
- 🐛 Issues: https://github.com/your-org/shieldgents/issues

---

## Comparison Table

| Feature | Without ShieldGents | With ShieldGents |
|---------|---------------------|------------------|
| Prompt Injection | ❌ Vulnerable | ✅ Blocked & logged |
| Data Exfiltration | ❌ Undetected | ✅ Detected & redacted |
| Tool Abuse | ❌ Unrestricted | ✅ Policy-enforced |
| Privilege Escalation | ❌ Possible | ✅ Requires approval |
| Covert Channels | ❌ Invisible | ✅ Detected & sanitized |
| Production Failures | ❌ Cascading | ✅ Circuit breaker |
| Security Monitoring | ❌ None | ✅ Real-time metrics |
| Audit Logs | ❌ Basic | ✅ Tamper-proof |

---

**Ready to secure your agents? Start with the Quick Start above! 🛡️**
