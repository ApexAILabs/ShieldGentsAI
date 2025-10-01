# ShieldGents Architecture

## Overview

ShieldGents is a modular security framework for agentic AI systems, designed following defense-in-depth principles and MLOps best practices.

## Core Modules

### 1. `prompts.py` - Prompt Security
**Purpose:** Detect and mitigate prompt injection attacks

**Components:**
- `PromptInjectionDetector` - Pattern-based detection using regex
- `PromptSanitizer` - Input sanitization and cleaning
- `PromptGuard` - Unified interface combining detection and sanitization

**Attack Patterns Covered:**
- System override attempts
- Role manipulation
- Delimiter injection
- Encoding tricks
- Goal hijacking
- Data exfiltration

### 2. `sandbox.py` - Safe Execution
**Purpose:** Isolate and limit agent tool execution

**Components:**
- `ProcessSandbox` - Execute subprocesses with resource limits
- `FunctionSandbox` - Execute Python functions with constraints
- `ToolWrapper` - Wrap agent tools for safe execution
- `ResourceLimits` - Define CPU, memory, and time limits

**Protection Against:**
- Resource exhaustion
- Infinite loops
- Memory leaks
- Unsafe system calls

### 3. `monitor.py` - Monitoring & Alerting
**Purpose:** Observe agent behavior and detect anomalies

**Components:**
- `SecurityMonitor` - Central monitoring interface
- `SecurityLogger` - Enhanced logging with structured events
- `AlertManager` - Event-driven alerting system
- `AnomalyDetector` - Statistical anomaly detection
- `MetricsCollector` - Metrics aggregation

**Capabilities:**
- Real-time event logging
- Statistical anomaly detection
- Custom alert handlers
- Metrics aggregation and reporting

### 4. `access.py` - Access Control
**Purpose:** Role-based access control for tools and resources

**Components:**
- `AccessControlList` - Core RBAC implementation
- `Role` - Role definitions with permissions
- `User` - User with role assignments
- `ToolAccessControl` - Tool-specific access control
- `SessionManager` - Session and token management

**Features:**
- Fine-grained permissions
- Resource pattern matching
- Session management
- Default role templates

### 5. `tests.py` - Red Team Testing
**Purpose:** Security testing and validation

**Components:**
- `RedTeamTester` - Automated security testing
- `AttackVectorLibrary` - Curated attack vectors
- `FuzzTester` - Fuzzing utilities
- `AttackVector` - Attack definition structure

**Attack Categories:**
- Prompt injection
- Jailbreak attempts
- Data exfiltration
- Resource exhaustion
- Tool misuse

### 6. `dashboard.py` - Visualization
**Purpose:** Real-time security monitoring UI

**Components:**
- `create_dashboard()` - Main dashboard interface
- `create_red_team_report()` - Test results visualization

**Features:**
- Real-time metrics
- Event distribution charts
- Performance metrics
- Auto-refresh capability

### 7. `context.py` - Context Management
**Purpose:** PII detection and context window management

**Components:**
- `PIIDetector` - Detect and redact PII
- `ContextWindowManager` - Manage conversation context
- `ConversationMemory` - Conversation tracking with summarization
- `RateLimiter` - Rate limiting for operations

**PII Types Detected:**
- Email addresses
- Phone numbers
- Social security numbers
- Credit cards
- API keys
- IP addresses

### 8. `audit.py` - Audit Logging
**Purpose:** Compliance and forensic logging

**Components:**
- `AuditLogger` - Tamper-evident audit logging
- `AuditEvent` - Structured audit event
- `ComplianceChecker` - Policy compliance verification

**Features:**
- Immutable audit trail
- Event signatures
- Query and reporting
- Compliance policy checking

## Design Principles

### 1. Defense in Depth
Multiple layers of security controls:
- Input validation (prompts)
- Execution isolation (sandbox)
- Access control (RBAC)
- Monitoring (events)
- Audit logging (compliance)

### 2. Fail Secure
Default to denying access when:
- Pattern detection is uncertain
- Resource limits are approached
- Permissions are ambiguous

### 3. Least Privilege
- Minimal permissions by default
- Explicit permission grants
- Resource-level access control

### 4. Observability
- Comprehensive logging
- Real-time monitoring
- Audit trails
- Metrics collection

### 5. Modularity
- Independent modules
- Composable components
- Optional features
- Plugin architecture

## Integration Patterns

### Pattern 1: Wrapper
Wrap existing agents with security controls:
```python
class SecureAgent:
    def __init__(self, base_agent):
        self.agent = base_agent
        self.guard = PromptGuard()
        self.monitor = SecurityMonitor()

    def invoke(self, prompt):
        result = self.guard.guard(prompt)
        if not result.is_safe:
            return "Blocked"
        return self.agent.invoke(result.sanitized_input)
```

### Pattern 2: Middleware
Insert security checks between components:
```python
@monitor.track_execution
@sandbox.isolate(limits=ResourceLimits())
@acl.require_permission("execute")
def tool_function(input):
    return process(input)
```

### Pattern 3: Decorator
Add security to individual functions:
```python
@prompt_guard.safe_execute
@rate_limiter.limit(key="user_id")
def chat(user_id, message):
    return llm.invoke(message)
```

## Data Flow

```
User Input
    ↓
[Prompt Guard] → Detect injection, sanitize
    ↓
[PII Detector] → Detect and redact PII
    ↓
[Rate Limiter] → Check rate limits
    ↓
[Access Control] → Verify permissions
    ↓
[Monitor] → Log execution start
    ↓
[Sandbox] → Execute with limits
    ↓
[Monitor] → Log execution end
    ↓
[Audit] → Record audit event
    ↓
Response
```

## Performance Considerations

### 1. Pattern Matching
- Compiled regex patterns
- Lazy evaluation
- Caching of results

### 2. Resource Monitoring
- Asynchronous monitoring threads
- Configurable check intervals
- Minimal overhead

### 3. Logging
- Structured logging
- Async writes
- Log rotation

### 4. Metrics
- In-memory aggregation
- Periodic flushing
- Sampling for high-volume

## Security Considerations

### 1. Pattern Evasion
- Multiple detection layers
- Semantic analysis (future)
- LLM-based detection (future)

### 2. Resource Limits
- Hard limits enforced
- Process isolation
- Timeout mechanisms

### 3. Audit Integrity
- Event signatures
- Append-only logs
- Tamper detection

### 4. Privacy
- PII redaction
- Secure log storage
- Data retention policies

## Future Enhancements

1. **ML-based Detection**
   - Train models on attack patterns
   - Semantic similarity detection
   - Behavioral profiling

2. **Advanced Sandboxing**
   - Container-based isolation
   - Network restrictions
   - Filesystem sandboxing

3. **Distributed Tracing**
   - OpenTelemetry integration
   - Cross-service tracing
   - Performance profiling

4. **Policy Engine**
   - Declarative policies
   - Policy-as-code
   - Dynamic policy updates

5. **Integration SDKs**
   - Framework-specific adapters
   - Cloud provider plugins
   - Observability integrations