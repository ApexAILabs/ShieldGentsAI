"""ShieldGents: Security tooling for agentic AI frameworks."""

from importlib import import_module
import os as _os
import sys as _sys

from shieldgents.assets import get_logo_text


def _should_print_install_logo() -> bool:
    """Determine whether the logo should be shown on import/install."""
    if _os.environ.get("SHIELDGENTS_SUPPRESS_LOGO", "").lower() in {"1", "true", "yes"}:
        return False

    if _os.environ.get("PYTEST_CURRENT_TEST"):
        # Avoid noisy output in automated test runs
        return False

    stdout = getattr(_sys, "stdout", None)
    if stdout is None or not hasattr(stdout, "isatty"):
        return False

    try:
        return bool(stdout.isatty())
    except Exception:
        return False


if _should_print_install_logo() and _os.environ.get("SHIELDGENTS_LOGO_PRINTED") != "1":
    try:
        print(get_logo_text())
    except Exception:
        # Avoid breaking import/install flows if logo retrieval fails
        pass
    else:
        _os.environ["SHIELDGENTS_LOGO_PRINTED"] = "1"

from shieldgents import core, controls, governance, integrations, interface, redteam  # noqa: E402
from shieldgents.integrations.agent_shield import AgentShield  # noqa: E402
from shieldgents.integrations.mcp_server_builder import create_shielded_mcp_server  # noqa: E402

__version__ = "0.2.0"

# Backwards-compatible module aliases ---------------------------------------------------------
_ALIAS_MODULES = {
    "prompts": "shieldgents.core.prompts",
    "behavior": "shieldgents.core.behavior",
    "context": "shieldgents.core.context",
    "monitor": "shieldgents.core.monitor",
    "sandbox": "shieldgents.core.sandbox",
    "access": "shieldgents.controls.access",
    "privilege": "shieldgents.controls.privilege",
    "agent_shield": "shieldgents.integrations.agent_shield",
    "tool_chain": "shieldgents.integrations.tool_chain",
    "mcp_security": "shieldgents.integrations.mcp_security",
    "mcp_server_builder": "shieldgents.integrations.mcp_server_builder",
    "production": "shieldgents.integrations.production",
    "audit": "shieldgents.governance.audit",
    "dashboard": "shieldgents.interface.dashboard",
    "cli": "shieldgents.interface.cli",
    "covert_channel": "shieldgents.redteam.covert_channel",
    "exfiltration": "shieldgents.redteam.exfiltration",
    "tests": "shieldgents.redteam.vectors",
}

for name, target in _ALIAS_MODULES.items():
    module = import_module(target)
    globals()[name] = module
    _sys.modules[f"{__name__}.{name}"] = module

__all__ = [
    "core",
    "controls",
    "governance",
    "integrations",
    "interface",
    "redteam",
    "AgentShield",
    "create_shielded_mcp_server",
    *_ALIAS_MODULES.keys(),
]
