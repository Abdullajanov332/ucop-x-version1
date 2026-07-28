//! UCOP-X Enterprise CLI
//!
//! Entry point for the `ucx` command-line tool. Routes top-level
//! namespaces to their respective command handlers.

use clap::{Command, CommandFactory, Parser, Subcommand};
use std::process::ExitCode;

mod commands;
mod config;
mod output;

/// UCOP-X Enterprise — Offline-first cybersecurity platform.
#[derive(Parser, Debug)]
#[command(name = "ucx")]
#[command(about = "UCOP-X Enterprise CLI", long_about = None)]
#[command(version)]
#[command(propagate_version = true)]
#[command(arg_required_else_help = true)]
struct Cli {
    /// Enable verbose output.
    #[arg(short = 'v', long = "verbose", global = true)]
    verbose: bool,

    /// Output format.
    #[arg(short = 'f', long = "format", global = true, default_value = "plain")]
    format: String,

    /// Path to config file.
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Perform security analysis on binaries, pcap, and memory dumps.
    Analyze(commands::analyze::AnalyzeArgs),
    /// Scan targets for open ports and vulnerabilities.
    Scan(commands::scan::ScanArgs),
    /// Reverse engineering and disassembly.
    Reverse(commands::reverse::ReverseArgs),
    /// Sandbox execution and analysis.
    Sandbox(commands::sandbox::SandboxArgs),
    /// Memory inspection and manipulation.
    Memory(commands::memory::MemoryArgs),
    /// Network traffic and proxy operations.
    Network(commands::network::NetworkArgs),
    /// Cryptographic operations.
    Crypto(commands::crypto_cli::CryptoArgs),
    /// Report generation and management.
    Report(commands::report::ReportArgs),
    /// Plugin management.
    Plugin(commands::plugin::PluginArgs),
    /// System information and diagnostics.
    System(commands::system::SystemArgs),
    /// Configuration management.
    Config(commands::config::ConfigArgs),
    /// Update the platform.
    Update(commands::update::UpdateArgs),
    /// System monitoring.
    Monitor(commands::monitor::MonitorArgs),
    /// Log management.
    Logs(commands::logs::LogsArgs),
    /// Extended help system.
    Help(commands::help::HelpArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load config
    let _cli_config = config::CliConfig::load();
    if let Some(path) = &cli.config {
        tracing::info!(config_path = %path, "using custom config path");
    }

    let result = match &cli.command {
        Some(Commands::Analyze(args)) => commands::analyze::execute(args).await,
        Some(Commands::Scan(args)) => commands::scan::execute(args).await,
        Some(Commands::Reverse(args)) => commands::reverse::execute(args).await,
        Some(Commands::Sandbox(args)) => commands::sandbox::execute(args).await,
        Some(Commands::Memory(args)) => commands::memory::execute(args).await,
        Some(Commands::Network(args)) => commands::network::execute(args).await,
        Some(Commands::Crypto(args)) => commands::crypto_cli::execute(args).await,
        Some(Commands::Report(args)) => commands::report::execute(args).await,
        Some(Commands::Plugin(args)) => commands::plugin::execute(args).await,
        Some(Commands::System(args)) => commands::system::execute(args).await,
        Some(Commands::Config(args)) => commands::config::execute(args).await,
        Some(Commands::Update(args)) => commands::update::execute(args).await,
        Some(Commands::Monitor(args)) => commands::monitor::execute(args).await,
        Some(Commands::Logs(args)) => commands::logs::execute(args).await,
        Some(Commands::Help(args)) => commands::help::execute(args).await,
        None => {
            // No command provided — print help
            let mut cmd = Cli::command();
            cmd.print_help().ok();
            println!();
            Ok(())
        }
    };

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {}", colored::Colorize::red("error:"), e);
            ExitCode::FAILURE
        }
    }
}
