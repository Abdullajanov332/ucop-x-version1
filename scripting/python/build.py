#!/usr/bin/env python3
"""
UCOP-X Enterprise Build Orchestrator

Orchestrates multi-crate workspace compilation, testing, packaging,
and cross-compilation for the Rust microkernel platform.
"""

import argparse
import os
import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime

CURRENT_DATE = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

WORKSPACE_MEMBERS = [
    "kernel",
    "memory",
    "scheduler",
    "crypto",
    "net",
    "re-engine",
    "static-analysis",
    "dynamic-analysis",
    "malware-analysis",
    "forensics",
    "ir",
    "threat-intel",
    "reporting",
    "asset-inventory",
    "compliance",
    "rule-engine",
    "plugin-sdk",
    "cli",
    "docs-generator",
    "test-framework",
    "lua-runtime",
    "js-api",
    "telemetry",
    "os-integration/linux",
    "os-integration/windows",
    "os-integration/macos",
    "lang-analysis/dotnet",
    "lang-analysis/java",
    "lang-analysis/php",
    "lang-analysis/solidity",
    "lang-analysis/vba",
]


def run_command(cmd: list, cwd: str = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    print(f"[UCOP-X Build] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or str(PROJECT_ROOT),
                          capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[UCOP-X Build] ERROR: Command failed with exit code {result.returncode}")
        print(result.stderr)
        sys.exit(result.returncode)
    return result


def cmd_check():
    """Run cargo check on the entire workspace."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 1: cargo check (all features)")
    print(f"{'='*60}\n")
    return run_command(["cargo", "check", "--workspace", "--all-features"])


def cmd_fmt():
    """Check code formatting."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 2: cargo fmt check")
    print(f"{'='*60}\n")
    return run_command(["cargo", "fmt", "--all", "--", "--check"])


def cmd_clippy():
    """Run clippy linter."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 3: cargo clippy")
    print(f"{'='*60}\n")
    return run_command(["cargo", "clippy", "--workspace", "--all-features", "--", "-D", "warnings"])


def cmd_test(args: list = None):
    """Run tests."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 4: cargo test")
    print(f"{'='*60}\n")
    cmd = ["cargo", "test", "--workspace", "--all-features", "--no-fail-fast"]
    if args:
        cmd.extend(args)
    return run_command(cmd)


def cmd_build(release: bool = False):
    """Build the workspace."""
    mode = "release" if release else "debug"
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 5: cargo build ({mode})")
    print(f"{'='*60}\n")
    cmd = ["cargo", "build", "--workspace", "--all-features"]
    if release:
        cmd.append("--release")
    return run_command(cmd)


def cmd_docs():
    """Build documentation."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 6: cargo doc")
    print(f"{'='*60}\n")
    return run_command(["cargo", "doc", "--workspace", "--all-features", "--no-deps"])


def cmd_audit():
    """Run security audit."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Phase 7: cargo audit")
    print(f"{'='*60}\n")
    return run_command(["cargo", "audit"], check=False)


def cmd_list_members():
    """List all workspace member crates."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Workspace Members ({len(WORKSPACE_MEMBERS)})")
    print(f"{'='*60}\n")
    for member in WORKSPACE_MEMBERS:
        crate_path = PROJECT_ROOT / member / "Cargo.toml"
        exists = crate_path.exists()
        status = "\u2713" if exists else "\u2717"
        print(f"  {status} {member}")


def cmd_metadata():
    """Show workspace metadata as JSON."""
    result = run_command(["cargo", "metadata", "--format-version", "1"], check=False)
    if result.returncode == 0:
        data = json.loads(result.stdout)
        packages = data.get("packages", [])
        print(f"\n[UCOP-X Build] Workspace Packages: {len(packages)}")
        for pkg in packages:
            print(f"  - {pkg['name']} v{pkg['version']} ({pkg['manifest_path']})")
    else:
        print("[UCOP-X Build] Failed to read cargo metadata")


def cmd_clean():
    """Clean build artifacts."""
    print(f"\n{'='*60}")
    print(f"[UCOP-X Build] Cleaning build artifacts")
    print(f"{'='*60}\n")
    return run_command(["cargo", "clean"])


def cmd_full():
    """Run the full build pipeline."""
    steps = [
        ("Check", cmd_check),
        ("Format", cmd_fmt),
        ("Lint", cmd_clippy),
        ("Test", cmd_test),
        ("Build", lambda: cmd_build(release=False)),
        ("Docs", cmd_docs),
    ]
    for name, func in steps:
        print(f"\n>>> Starting: {name}")
        result = func()
        if result.returncode != 0:
            print(f"[UCOP-X Build] FAILED at: {name}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="UCOP-X Enterprise Build Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python build.py check       # cargo check
  python build.py test         # run tests
  python build.py build --release  # release build
  python build.py full         # full pipeline
  python build.py list         # list workspace members
        """
    )
    parser.add_argument("command", nargs="?",
                       choices=["check", "fmt", "clippy", "test", "build",
                                "docs", "audit", "list", "metadata", "clean", "full"],
                       help="Build command to execute")
    parser.add_argument("--release", action="store_true",
                       help="Build in release mode")
    parser.add_argument("test_args", nargs=argparse.REMAINDER,
                       help="Additional arguments for cargo test")
    parser.add_argument("--list", "-l", action="store_true",
                       help="List workspace members (shortcut)")

    args = parser.parse_args()

    print(f"UCOP-X Enterprise Build Orchestrator")
    print(f"Build Date: {CURRENT_DATE}")
    print(f"Project Root: {PROJECT_ROOT}\n")

    command_handlers = {
        "check": cmd_check,
        "fmt": cmd_fmt,
        "clippy": cmd_clippy,
        "test": lambda: cmd_test(args.test_args),
        "build": lambda: cmd_build(args.release),
        "docs": cmd_docs,
        "audit": cmd_audit,
        "list": cmd_list_members,
        "metadata": cmd_metadata,
        "clean": cmd_clean,
        "full": cmd_full,
    }

    if args.list:
        cmd_list_members()
        return

    if args.command:
        handler = command_handlers.get(args.command)
        if handler:
            handler()
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
