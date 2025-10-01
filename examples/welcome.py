"""Welcome script that shows the ShieldGents logo and intro.

Run this to see the package branding and quick start info.
"""

LOGO = """
   _____ __    _      __    ________            __
  / ___// /_  (_)__  / /___/ / ____/__  ____  / /______
  \__ \/ __ \/ / _ \/ / __  / / __/ _ \/ __ \/ __/ ___/
 ___/ / / / / /  __/ / /_/ / /_/ /  __/ / / / /_(__  )
/____/_/ /_/_/\___/_/\__,_/\____/\___/_/ /_/\__/____/
"""

BANNER = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   _____ __    _      __    ________            __                ║
║  / ___// /_  (_)__  / /___/ / ____/__  ____  / /______          ║
║  \__ \/ __ \/ / _ \/ / __  / / __/ _ \/ __ \/ __/ ___/          ║
║ ___/ / / / / /  __/ / /_/ / /_/ /  __/ / / / /_(__  )           ║
║/____/_/ /_/_/\___/_/\__,_/\____/\___/_/ /_/\__/____/            ║
║                                                                   ║
║            🛡️  Security for AI Agents  🛡️                        ║
║                                                                   ║
║  Production-ready security tooling for agentic AI frameworks     ║
║  Version: 0.1.0  |  License: BSD-3-Clause                       ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""


def main():
    """Display welcome message with logo."""
    print("\033[1;36m")  # Cyan color
    print(BANNER)
    print("\033[0m")  # Reset color

    print("\n🚀 Quick Start:")
    print("─" * 70)
    print()
    print("  1️⃣  Protect against prompt injection:")
    print("     from shieldgents.core import PromptGuard")
    print()
    print("  2️⃣  Detect and redact PII:")
    print("     from shieldgents.core import PIIDetector")
    print()
    print("  3️⃣  Sandbox tool execution:")
    print("     from shieldgents.core import FunctionSandbox")
    print()
    print("  4️⃣  Monitor security events:")
    print("     from shieldgents.core import SecurityMonitor")
    print()
    print("  5️⃣  Test your security:")
    print("     from shieldgents.redteam import RedTeamTester")
    print()
    print("─" * 70)
    print()
    print("📚 Documentation:")
    print("   - Quick Start: QUICKSTART.md")
    print("   - Architecture: ARCHITECTURE.md")
    print("   - Examples: examples/")
    print()
    print("🎨 Interactive Dashboard:")
    print("   uv run streamlit run examples/dashboard_with_agent.py")
    print()
    print("🔗 Links:")
    print("   - GitHub: https://github.com/Mehranmzn/shieldgents")
    print("   - Docs: https://shieldgents.readthedocs.io")
    print()
    print("─" * 70)
    print()
    print("\033[1;32m")  # Green color
    print("✨ Ready to secure your AI agents! 🛡️")
    print("\033[0m")  # Reset color
    print()


if __name__ == "__main__":
    main()
