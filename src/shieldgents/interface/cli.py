"""Command-line interface for ShieldGents.

This module provides CLI commands for various ShieldGents operations.
"""

import sys


def print_banner() -> None:
    """Print startup banner."""
    from shieldgents.assets import get_logo_text
    from shieldgents import __version__

    print(get_logo_text())
    print("═" * 70)
    print("  Production-ready security tooling for agentic AI frameworks")
    print(f"  Version: {__version__}")
    print("  License: BSD-3-Clause")
    print("═" * 70)
    print()


def main() -> None:
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print_banner()
        print("Available commands:")
        print()
        print("  shieldgents dashboard    - Launch security dashboard")
        print("  shieldgents test         - Run red team security tests")
        print("  shieldgents scan <file>  - Scan a file for security issues")
        print("  shieldgents version      - Show version information")
        print("  shieldgents help         - Show this help message")
        print()
        return

    command = sys.argv[1]

    if command == "dashboard":
        print("🎨 Launching ShieldGents Dashboard...")
        print("Opening at: http://localhost:8501")
        print()
        import subprocess
        subprocess.run(["streamlit", "run", "-m", "shieldgents.interface.dashboard"])

    elif command == "test":
        print("🔴 Running Red Team Security Tests...")
        from shieldgents.redteam.vectors import RedTeamTester

        def mock_agent(prompt: str) -> str:
            return f"Response to: {prompt}"

        tester = RedTeamTester(mock_agent)
        results = tester.run_all_tests()
        report = tester.generate_report(results)

        print()
        print(f"Total Tests: {report['total_tests']}")
        print(f"Passed: {report['passed']} ({report['pass_rate']}%)")
        print(f"Failed: {report['failed']}")
        print()

        if report['failed_tests']:
            print("Failed Tests:")
            for test in report['failed_tests'][:5]:
                print(f"  ❌ {test['name']} ({test['severity']})")

    elif command == "scan":
        if len(sys.argv) < 3:
            print("Error: Please provide a file to scan")
            print("Usage: shieldgents scan <file>")
            return

        file_path = sys.argv[2]
        print(f"🔍 Scanning file: {file_path}")
        print()

        try:
            with open(file_path, 'r') as f:
                content = f.read()

            from shieldgents.core.prompts import PromptGuard
            from shieldgents.core.context import PIIDetector

            guard = PromptGuard()
            pii = PIIDetector()

            # Check for prompt injection
            guard_result = guard.guard(content)
            print(f"Prompt Security: {'✅ Safe' if guard_result.is_safe else '⚠️  Unsafe'}")
            if not guard_result.is_safe:
                print(f"  Threat Level: {guard_result.threat_level.value}")
                print(f"  Patterns: {', '.join(guard_result.detected_patterns)}")

            print()

            # Check for PII
            pii_result = pii.scan(content)
            print(f"PII Detection: {'⚠️  Found' if pii_result.has_pii else '✅ Clean'}")
            if pii_result.has_pii:
                print(f"  Types: {[m.pii_type.value for m in pii_result.matches]}")

        except Exception as e:
            print(f"Error scanning file: {e}")

    elif command == "version":
        print_banner()

    elif command in ["help", "--help", "-h"]:
        main()

    else:
        print(f"Unknown command: {command}")
        print("Run 'shieldgents help' for available commands")


if __name__ == "__main__":
    main()
