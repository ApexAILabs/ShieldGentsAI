"""User-facing surfaces such as CLI and dashboards."""

from shieldgents.assets import print_logo
from shieldgents.interface import cli, dashboard
from shieldgents.interface.cli import main as cli_main, print_banner
from shieldgents.interface.dashboard import (
    create_dashboard,
    create_red_team_report,
)

__all__ = [
    "cli",
    "dashboard",
    "cli_main",
    "print_banner",
    "print_logo",
    "create_dashboard",
    "create_red_team_report",
]
