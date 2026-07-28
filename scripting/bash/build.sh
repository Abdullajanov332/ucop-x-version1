#!/usr/bin/env bash
set -euo pipefail

# UCOP-X Build Script (Bash)
# Usage: ./build.sh [command]
# Commands: check, fmt, clippy, test, build, docs, clean, list, full

UCOP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$UCOP_ROOT"

MODE="${1:-check}"

step() {
    echo -e "\n============================================================"
    echo "[UCOP-X] $1"
    echo "============================================================\n"
}

case "$MODE" in
    check)
        step "cargo check (all features)"
        cargo check --workspace --all-features
        ;;
    fmt)
        step "cargo fmt check"
        cargo fmt --all -- --check
        ;;
    clippy)
        step "cargo clippy"
        cargo clippy --workspace --all-features -- -D warnings
        ;;
    test)
        step "cargo test"
        shift
        cargo test --workspace --all-features --no-fail-fast "$@"
        ;;
    build)
        BUILD_MODE="${2:-debug}"
        step "cargo build ($BUILD_MODE)"
        if [ "$BUILD_MODE" = "release" ]; then
            cargo build --workspace --all-features --release
        else
            cargo build --workspace --all-features
        fi
        ;;
    docs)
        step "cargo doc"
        cargo doc --workspace --all-features --no-deps
        ;;
    clean)
        step "cargo clean"
        cargo clean
        ;;
    list)
        step "Workspace Member Crates"
        MEMBERS=(
            kernel memory scheduler crypto net
            re-engine static-analysis dynamic-analysis
            malware-analysis forensics ir threat-intel
            reporting asset-inventory compliance rule-engine
            plugin-sdk cli docs-generator test-framework
            lua-runtime js-api telemetry
            os-integration/linux os-integration/windows os-integration/macos
            lang-analysis/dotnet lang-analysis/java lang-analysis/php
            lang-analysis/solidity lang-analysis/vba
        )
        for member in "${MEMBERS[@]}"; do
            if [ -f "$UCOP_ROOT/$member/Cargo.toml" ]; then
                echo "  [OK] $member"
            else
                echo "  [MISSING] $member"
            fi
        done
        ;;
    full)
        step "Full Build Pipeline"
        cargo check --workspace --all-features
        cargo fmt --all -- --check
        cargo clippy --workspace --all-features -- -D warnings
        cargo test --workspace --all-features --no-fail-fast
        cargo build --workspace --all-features
        cargo doc --workspace --all-features --no-deps
        ;;
    *)
        echo "Usage: $0 [check|fmt|clippy|test|build|docs|clean|list|full]"
        exit 1
        ;;
esac

echo -e "\n[UCOP-X] $MODE completed successfully."
