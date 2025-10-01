# ShieldGents Repository Structure

This document describes the organization of the ShieldGents repository.

## 📁 Directory Structure

```
ShieldGentsAI/
├── src/shieldgents/          # Main package source code
│   ├── core/                 # Core security primitives
│   │   ├── prompts.py        # Prompt injection detection
│   │   ├── context.py        # PII detection, context management
│   │   ├── sandbox.py        # Function sandboxing
│   │   ├── monitor.py        # Security monitoring
│   │   └── wrappers.py       # Tool wrappers
│   │
│   ├── controls/             # Advanced security shields
│   │   ├── model_security.py # Model extraction protection
│   │   ├── privilege.py      # Privilege escalation prevention
│   │   ├── content_safety.py # Content safety filter
│   │   ├── exfiltration.py   # Data exfiltration detection
│   │   ├── tool_chain.py     # Tool chain monitoring
│   │   ├── supply_chain.py   # Supply chain validation
│   │   ├── data_poisoning.py # Data poisoning detection
│   │   └── memory_privacy.py # Memory privacy management
│   │
│   ├── governance/           # Audit & compliance
│   │   ├── audit.py          # Audit logging
│   │   └── rbac.py           # Role-based access control
│   │
│   ├── integrations/         # Framework integrations
│   │   ├── agent_shield.py   # High-level AgentShield
│   │   ├── langchain.py      # LangChain integration
│   │   ├── strands.py        # Strands SDK integration
│   │   ├── mcp_security.py   # MCP security
│   │   └── production.py     # Production utilities
│   │
│   ├── interface/            # User interfaces
│   │   └── dashboard.py      # Streamlit dashboard
│   │
│   └── redteam/              # Security testing
│       ├── attacks.py        # Attack vectors
│       └── fuzzing.py        # Fuzzing utilities
│
├── examples/                 # Usage examples
│   ├── README.md             # Examples documentation
│   ├── basic_usage.py        # Getting started
│   ├── langchain_integration.py      # LangChain example
│   ├── strands_sdk_integration.py    # Strands example
│   ├── advanced_security_demo.py     # All shields demo
│   ├── agent_examples.ipynb          # Jupyter notebook
│   ├── mcp_security_demo.py          # MCP security
│   ├── behavioral_security_demo.py   # Behavioral analysis
│   └── run_dashboard.py              # Dashboard launcher
│
├── tests/                    # Test suite
│   ├── test_prompts.py
│   ├── test_sandbox.py
│   └── test_agent_shield.py
│
├── docs/                     # Documentation
│   ├── guides/               # User guides
│   │   ├── MCP_SECURITY_GUIDE.md
│   │   ├── DASHBOARD.md
│   │   └── QUICK_START.md
│   │
│   ├── architecture/         # Technical docs
│   │   └── ARCHITECTURE.md
│   │
│   ├── PROJECT_SUMMARY.md
│   ├── SECURITY_COVERAGE.md
│   ├── NEW_SHIELDS_SUMMARY.md
│   ├── LOGO_USAGE.md
│   └── RELEASE_NOTES_v0.2.0.md
│
├── assets/                   # Logos and images
│
├── README.md                 # Main readme
├── QUICKSTART.md             # Quick start guide
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # BSD 3-Clause License
├── pyproject.toml            # Package configuration
└── .gitignore                # Git ignore rules
```

## 📦 Package Modules

### Core (`shieldgents.core`)
Low-level security primitives that all other modules build upon.

**Key Components:**
- `PromptGuard` - Prompt injection detection
- `PIIDetector` - PII detection and redaction
- `FunctionSandbox` - Tool execution sandboxing
- `SecurityMonitor` - Event logging and anomaly detection
- `RateLimiter` - Rate limiting per user
- `ToolWrapper` - Secure tool wrapping

### Controls (`shieldgents.controls`)
Advanced security shields for specific attack vectors.

**Available Shields:**
1. **ModelSecurityMonitor** - Model extraction, stealing, membership inference
2. **PrivilegeMonitor** - Privilege escalation detection
3. **ContentSafetyFilter** - Malware, phishing, exploit detection
4. **ExfiltrationDetector** - Data exfiltration via encoding, DNS tunneling
5. **ToolChainMonitor** - Dangerous tool sequence detection
6. **SupplyChainValidator** - Package validation, typosquatting
7. **DataPoisoningDetector** - Training data validation
8. **MemoryPrivacyManager** - Consent-based memory with TTL

### Governance (`shieldgents.governance`)
Compliance, auditing, and access control.

**Key Components:**
- `AuditLogger` - Comprehensive audit logging with signatures
- `RBACManager` - Role-based access control

### Integrations (`shieldgents.integrations`)
Framework-specific wrappers and high-level APIs.

**Available Integrations:**
- `AgentShield` - High-level unified interface
- `SecureLangChainAgent` - LangChain integration
- `SecureStrandsAgent` - Strands SDK integration
- `secure_mcp_server()` - MCP server security
- `ProductionAgent` - Production-ready agent template

### Interface (`shieldgents.interface`)
User interfaces for monitoring and visualization.

**Available Interfaces:**
- Streamlit Dashboard - Real-time security metrics and alerts

### Red Team (`shieldgents.redteam`)
Security testing and validation tools.

**Key Components:**
- Attack vectors library
- Fuzzing utilities
- Adversarial testing

## 🎯 Examples Organization

The `examples/` directory is organized by use case:

### Getting Started
- `basic_usage.py` - Core features introduction
- `welcome.py` - Welcome script

### Framework Integrations
- `langchain_integration.py` - LangChain + ShieldGents
- `strands_sdk_integration.py` - Strands SDK + ShieldGents
- `agent_examples.ipynb` - Interactive Jupyter tutorial

### Advanced Security
- `advanced_security_demo.py` - All 7 shields in action
- `behavioral_security_demo.py` - Behavioral analysis

### MCP Security
- `mcp_security_demo.py` - Secure MCP servers
- `mcp_server_builder_demo.py` - Build MCP servers

### Monitoring
- `run_dashboard.py` - Launch security dashboard
- `monitor_real_agent.py` - Real-time monitoring
- `dashboard_with_agent.py` - Integrated dashboard

## 📚 Documentation Organization

### User Guides (`docs/guides/`)
Step-by-step guides for common tasks:
- Quick Start
- MCP Security Guide
- Dashboard Guide

### Technical Documentation (`docs/`)
- Architecture overview
- Security coverage matrix
- API reference
- Release notes

### API Documentation
Generated from docstrings in source code.

## 🧪 Testing

Tests are organized by module:
- `test_prompts.py` - Prompt injection tests
- `test_sandbox.py` - Sandboxing tests
- `test_agent_shield.py` - Integration tests

Run tests with:
```bash
pytest tests/
```

## 🔧 Development Workflow

1. **Source Code**: All package code lives in `src/shieldgents/`
2. **Examples**: Usage examples in `examples/` import from `shieldgents`
3. **Tests**: Tests in `tests/` verify package functionality
4. **Documentation**: Docs in `docs/` explain concepts and usage

## 📝 Import Conventions

### Core Primitives
```python
from shieldgents.core import PromptGuard, PIIDetector, FunctionSandbox
```

### Advanced Shields
```python
from shieldgents.controls import (
    ModelSecurityMonitor,
    PrivilegeMonitor,
    ContentSafetyFilter,
)
```

### Framework Integrations
```python
from shieldgents.integrations import (
    AgentShield,
    SecureLangChainAgent,
    SecureStrandsAgent,
)
```

### Governance
```python
from shieldgents.governance import AuditLogger, RBACManager
```

## 🎨 File Naming Conventions

- **Source files**: `snake_case.py`
- **Test files**: `test_*.py`
- **Example files**: `descriptive_name.py` or `*_demo.py`
- **Documentation**: `UPPERCASE.md` for main docs, `Title_Case.md` for guides

## 🚫 .gitignore

The repository ignores:
- Python bytecode (`__pycache__/`, `*.pyc`)
- Virtual environments (`.venv/`, `venv/`)
- IDE files (`.vscode/`, `.idea/`)
- Test artifacts (`.pytest_cache/`, `.coverage`)
- Logs (`logs/`, `*.log`)
- macOS files (`.DS_Store`)
- Temporary files (`*.tmp`, `test_cell.txt`)
- Environment files (`.env`)
- Claude Code (`.claude/`)

## 📊 Package Distribution

Build artifacts:
- `dist/` - Built packages (`.whl`, `.tar.gz`)
- `build/` - Build temporary files

Build with:
```bash
uv build
```

## 🤝 Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and guidelines.

## 📄 License

BSD 3-Clause License - See [LICENSE](../LICENSE)
