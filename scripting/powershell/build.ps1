# UCOP-X Build Script (PowerShell)
# Usage: .\build.ps1 [-Command check|test|build|full] [-Release]

param(
    [ValidateSet("check", "fmt", "clippy", "test", "build", "docs", "clean", "full", "list")]
    [string]$Command = "check",
    [switch]$Release,
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$TestArgs
)

function Write-Step {
    param([string]$Message)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "[UCOP-X] $Message" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "" -NoNewline
}

function Invoke-Cargo {
    param([string[]]$Arguments)
    $cmd = "cargo"
    Write-Host "[UCOP-X] Running: $cmd $($Arguments -join ' ')" -ForegroundColor Yellow
    & $cmd @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[UCOP-X] Command failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

switch ($Command) {
    "check" {
        Write-Step "cargo check (all features)"
        Invoke-Cargo @("check", "--workspace", "--all-features")
    }
    "fmt" {
        Write-Step "cargo fmt check"
        Invoke-Cargo @("fmt", "--all", "--", "--check")
    }
    "clippy" {
        Write-Step "cargo clippy"
        Invoke-Cargo @("clippy", "--workspace", "--all-features", "--", "-D", "warnings")
    }
    "test" {
        Write-Step "cargo test"
        $args = @("test", "--workspace", "--all-features", "--no-fail-fast")
        if ($TestArgs) { $args += $TestArgs }
        Invoke-Cargo $args
    }
    "build" {
        $mode = if ($Release) { "release" } else { "debug" }
        Write-Step "cargo build ($mode)"
        $args = @("build", "--workspace", "--all-features")
        if ($Release) { $args += "--release" }
        Invoke-Cargo $args
    }
    "docs" {
        Write-Step "cargo doc"
        Invoke-Cargo @("doc", "--workspace", "--all-features", "--no-deps")
    }
    "clean" {
        Write-Step "cargo clean"
        Invoke-Cargo @("clean")
    }
    "list" {
        Write-Step "Workspace Member Crates"
        $members = @(
            "kernel", "memory", "scheduler", "crypto", "net",
            "re-engine", "static-analysis", "dynamic-analysis",
            "malware-analysis", "forensics", "ir", "threat-intel",
            "reporting", "asset-inventory", "compliance", "rule-engine",
            "plugin-sdk", "cli", "docs-generator", "test-framework",
            "lua-runtime", "js-api", "telemetry",
            "os-integration/linux", "os-integration/windows", "os-integration/macos",
            "lang-analysis/dotnet", "lang-analysis/java", "lang-analysis/php",
            "lang-analysis/solidity", "lang-analysis/vba"
        )
        foreach ($member in $members) {
            $path = Join-Path $PSScriptRoot "..\..\$member\Cargo.toml"
            $exists = Test-Path $path
            $mark = if ($exists) { "[OK]" } else { "[MISSING]" }
            Write-Host "  $mark $member"
        }
    }
    "full" {
        Write-Step "Full Build Pipeline"
        Invoke-Cargo @("check", "--workspace", "--all-features")
        Invoke-Cargo @("fmt", "--all", "--", "--check")
        Invoke-Cargo @("clippy", "--workspace", "--all-features", "--", "-D", "warnings")
        Invoke-Cargo @("test", "--workspace", "--all-features", "--no-fail-fast")
        Invoke-Cargo @("build", "--workspace", "--all-features")
        Invoke-Cargo @("doc", "--workspace", "--all-features", "--no-deps")
    }
}
