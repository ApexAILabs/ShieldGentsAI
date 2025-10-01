"""Integration helpers that assemble ShieldGents primitives."""

from shieldgents.integrations import (
    agent_shield,
    tool_chain,
    mcp_security,
    mcp_server_builder,
    production,
    langchain,
    strands,
)
from shieldgents.integrations.agent_shield import (
    AgentShield,
    OutputCheck,
    PromptCheck,
    SecurityViolation,
)
from shieldgents.integrations.langchain import SecureLangChainAgent
from shieldgents.integrations.mcp_security import (
    MCPRequest,
    MCPResponse,
    MCPSecurityAlert,
    MCPSecurityMonitor,
    MCPServerProfile,
    MCPServerRegistry,
    MCPThreatType,
    secure_mcp_server,
)
from shieldgents.integrations.mcp_server_builder import create_shielded_mcp_server
from shieldgents.integrations.strands import SecureStrandsAgent, create_secure_tool
from shieldgents.integrations.tool_chain import (
    ChainViolationType,
    ToolChainMonitor,
    ToolRiskLevel,
)

__all__ = [
    # Modules
    "agent_shield",
    "tool_chain",
    "mcp_security",
    "mcp_server_builder",
    "production",
    "langchain",
    "strands",
    # AgentShield
    "AgentShield",
    "OutputCheck",
    "PromptCheck",
    "SecurityViolation",
    # LangChain
    "SecureLangChainAgent",
    # Strands
    "SecureStrandsAgent",
    "create_secure_tool",
    # MCP
    "MCPRequest",
    "MCPResponse",
    "MCPSecurityAlert",
    "MCPSecurityMonitor",
    "MCPServerProfile",
    "MCPServerRegistry",
    "MCPThreatType",
    "secure_mcp_server",
    "create_shielded_mcp_server",
    # Tool Chain
    "ChainViolationType",
    "ToolChainMonitor",
    "ToolRiskLevel",
]
