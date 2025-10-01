# ShieldGents Examples

This directory contains comprehensive examples demonstrating different use cases and integrations of ShieldGents.

## 📚 Table of Contents

### Getting Started
- **[basic_usage.py](basic_usage.py)** - Core security features (Prompt Guard, PII Detection, Sandboxing)
- **[welcome.py](welcome.py)** - Welcome script with basic setup

### Framework Integrations
- **[langchain_integration.py](langchain_integration.py)** - Basic LangChain + ShieldGents integration
- **[langchain_agentshield_demo.py](langchain_agentshield_demo.py)** - Full AgentShield with LangChain
- **[strands_sdk_integration.py](strands_sdk_integration.py)** - Strands SDK integration
- **[agent_examples.ipynb](agent_examples.ipynb)** - Interactive Jupyter notebook with LangGraph examples

### Advanced Security
- **[advanced_security_demo.py](advanced_security_demo.py)** - All 7 security shields in action
  - Content Safety Filter
  - Privilege Escalation Monitor
  - Model Security Monitor (extraction, stealing, membership inference)
  - Data Exfiltration Detector
  - Tool Chain Monitor
  - Supply Chain Validator
  - Memory Privacy Manager

- **[behavioral_security_demo.py](behavioral_security_demo.py)** - Behavioral analysis and anomaly detection

### MCP (Model Context Protocol)
- **[mcp_security_demo.py](mcp_security_demo.py)** - Secure MCP server implementation
- **[mcp_server_builder_demo.py](mcp_server_builder_demo.py)** - Build secure MCP servers from scratch

### Monitoring & Dashboards
- **[monitor_real_agent.py](monitor_real_agent.py)** - Real-time agent monitoring
- **[dashboard_with_agent.py](dashboard_with_agent.py)** - Agent with security dashboard
- **[run_dashboard.py](run_dashboard.py)** - Standalone security dashboard

---

## 🚀 Quick Start

### 1. Basic Protection
```bash
python examples/basic_usage.py
```

Demonstrates:
- Prompt injection detection
- PII detection and redaction
- Function sandboxing
- Security monitoring

### 2. LangChain Integration
```bash
python examples/langchain_integration.py
```

Shows how to secure LangChain agents with tool wrapping and monitoring.

### 3. Advanced Security (All Shields)
```bash
python examples/advanced_security_demo.py
```

Comprehensive demo of all 7 security shields protecting against:
- Prompt injection & jailbreaks
- Privilege escalation
- Model extraction attacks
- Data exfiltration
- Malicious tool chains
- Supply chain attacks
- Memory privacy violations

### 4. Interactive Notebook
```bash
jupyter notebook examples/agent_examples.ipynb
```

Hands-on tutorial with:
- LangChain integration
- LangGraph stateful agents
- Comprehensive security testing
- Web research agents with Firecrawl

### 5. Security Dashboard
```bash
python examples/run_dashboard.py
```

Launch the Streamlit dashboard for real-time security monitoring.

---

## 📖 Example Categories

### Security Shields

| Shield | Example | Description |
|--------|---------|-------------|
| Prompt Injection | `basic_usage.py` | Detects jailbreaks, role manipulation, system overrides |
| PII Detection | `basic_usage.py` | Finds and redacts SSN, credit cards, emails, phone numbers |
| Privilege Escalation | `advanced_security_demo.py` | Blocks sudo/admin/root access requests |
| Content Safety | `advanced_security_demo.py` | Prevents malware, phishing, exploit generation |
| Model Security | `advanced_security_demo.py` | Stops extraction, stealing, membership inference |
| Data Exfiltration | `advanced_security_demo.py` | Detects base64, DNS tunneling, high entropy leaks |
| Tool Chain Security | `advanced_security_demo.py` | Monitors dangerous tool sequences |
| Supply Chain | `advanced_security_demo.py` | Validates packages, detects typosquatting |
| Memory Privacy | `advanced_security_demo.py` | Consent-based storage with TTL |

### Framework Support

| Framework | Example | Features |
|-----------|---------|----------|
| LangChain | `langchain_integration.py` | Tool wrapping, agent executor security |
| LangGraph | `agent_examples.ipynb` | Stateful agents, security check nodes |
| Strands SDK | `strands_sdk_integration.py` | Tool sandboxing, monitoring |
| MCP | `mcp_security_demo.py` | Secure MCP server builder |

---

## 🎯 Use Case Examples

### E-commerce Agent
```python
# Protect against:
# - PII leakage (credit cards, addresses)
# - Privilege escalation (admin access)
# - Data exfiltration (customer data)

from shieldgents import AgentShield
from shieldgents.controls import ContentSafetyFilter, PrivilegeMonitor

shield = AgentShield()
# ... use in your agent
```

See: `advanced_security_demo.py`

### Research Agent
```python
# Protect against:
# - Prompt injection
# - Model extraction
# - Unsafe web scraping

from shieldgents.core import PromptGuard, FunctionSandbox
# ... secure your tools
```

See: `agent_examples.ipynb` (Web Research example)

### Code Assistant
```python
# Protect against:
# - Malicious code generation
# - Supply chain attacks
# - Privilege escalation

from shieldgents.controls import ContentSafetyFilter, SupplyChainValidator
# ... validate packages and code
```

See: `advanced_security_demo.py`

---

## 🧪 Testing Examples

All examples include test cases you can run:

```bash
# Test all security shields
PYTHONPATH=src python examples/advanced_security_demo.py

# Test LangChain integration
python examples/langchain_integration.py

# Test behavioral analysis
python examples/behavioral_security_demo.py
```

---

## 📝 Example Output

### Prompt Injection Detection
```
🔍 Testing: Ignore all previous instructions
  Safe: False
  Threat Level: high
  Detected Patterns: ['system_override']
```

### PII Redaction
```
🔍 Input: My SSN is 123-45-6789
  Has PII: True
  Redacted: My SSN is ***********
```

### Model Extraction Alert
```
🚫 Security Alert: Model extraction attempt detected
  Risk Score: 0.85
  Should Block: True
  Attack Type: extraction_probe
```

---

## 🛠️ Running Requirements

Most examples require:
```bash
pip install shieldgents langchain openai
```

For dashboard:
```bash
pip install streamlit plotly
```

For notebook:
```bash
pip install jupyter
```

For web research (optional):
```bash
pip install firecrawl-py
```

---

## 💡 Tips

1. **Start with `basic_usage.py`** to understand core concepts
2. **Try the notebook** for interactive learning
3. **Run `advanced_security_demo.py`** to see all shields in action
4. **Check the dashboard** for monitoring and analytics

## 📚 Documentation

- [Quick Start Guide](../QUICKSTART.md)
- [MCP Security Guide](../docs/guides/MCP_SECURITY_GUIDE.md)
- [Architecture](../docs/architecture/ARCHITECTURE.md)
- [Security Coverage](../docs/SECURITY_COVERAGE.md)

## 🤝 Contributing

Found a bug or want to add an example? See [CONTRIBUTING.md](../CONTRIBUTING.md)
