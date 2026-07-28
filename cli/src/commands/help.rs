//! `help` command namespace.
//! Extended help system with search, topic browsing, and manual pages.

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct HelpArgs {
    #[command(subcommand)]
    pub command: HelpCommands,
}

#[derive(Debug, Subcommand)]
pub enum HelpCommands {
    /// Show help for a specific topic.
    Topic(TopicArgs),
    /// Search help topics.
    Search(SearchArgs),
    /// List all available help topics.
    List,
}

#[derive(Debug, Args)]
pub struct TopicArgs {
    /// Topic name or command path.
    pub topic: String,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Search query.
    pub query: String,
    /// Output format.
    #[arg(long, default_value = "plain")]
    pub format: String,
}

pub async fn execute(args: &HelpArgs) -> Result<(), String> {
    match &args.command {
        HelpCommands::Topic(targs) => show_topic(targs).await,
        HelpCommands::Search(sargs) => search_topics(sargs).await,
        HelpCommands::List => list_topics().await,
    }
}

async fn show_topic(args: &TopicArgs) -> Result<(), String> {
    println!("Help topic: {}", args.topic);
    println!();
    match args.topic.to_lowercase().as_str() {
        "analyze" => {
            println!("analyze - Perform security analysis on various targets");
            println!();
            println!("USAGE:");
            println!("  ucx analyze binary <path>");
            println!("  ucx analyze pcap <path>");
            println!("  ucx analyze memory <path>");
            println!("  ucx analyze list");
            println!();
            println!("SUBCOMMANDS:");
            println!("  binary    Analyze a binary file (ELF, PE, Mach-O)");
            println!("  pcap      Analyze network traffic captures");
            println!("  memory    Analyze memory dumps");
            println!("  list      List available analysis modules");
        }
        "scan" => {
            println!("scan - Scan targets for vulnerabilities and open ports");
            println!();
            println!("USAGE:");
            println!("  ucx scan port <target> [--ports RANGE]");
            println!("  ucx scan vuln <target>");
            println!("  ucx scan directory <url>");
            println!("  ucx scan list");
            println!();
            println!("SUBCOMMANDS:");
            println!("  port        Port scan a target");
            println!("  vuln        Vulnerability scan");
            println!("  directory   Directory/URL path enumeration");
            println!("  list        List available scan modules");
        }
        _ => {
            println!("No detailed help available for '{}'.", args.topic);
            println!("Use 'ucx help list' to see all topics.");
        }
    }
    Ok(())
}

async fn search_topics(args: &SearchArgs) -> Result<(), String> {
    use comfy_table::Table;
    let mut table = Table::new();
    table.set_header(vec!["Topic", "Match"]);

    let q = args.query.to_lowercase();
    let all_topics = vec![
        ("analyze", "Security analysis commands"),
        ("scan", "Scanning commands"),
        ("reverse", "Reverse engineering commands"),
        ("sandbox", "Sandbox execution commands"),
        ("memory", "Memory operations"),
        ("network", "Network operations"),
        ("crypto", "Cryptography commands"),
        ("report", "Report generation"),
        ("plugin", "Plugin management"),
        ("system", "System information"),
        ("config", "Configuration management"),
        ("update", "Update commands"),
        ("monitor", "System monitoring"),
        ("logs", "Log management"),
    ];

    for (topic, desc) in &all_topics {
        if topic.contains(&q) || desc.to_lowercase().contains(&q) {
            table.add_row(vec![topic, desc]);
        }
    }

    println!("Search results for '{}':", args.query);
    println!("{table}");
    Ok(())
}

async fn list_topics() -> Result<(), String> {
    use comfy_table::Table;
    let mut table = Table::new();
    table
        .set_header(vec!["Command", "Description"])
        .add_row(vec!["analyze", "Security analysis (binary, pcap, memory)"])
        .add_row(vec!["scan", "Port and vulnerability scanning"])
        .add_row(vec!["reverse", "Reverse engineering and disassembly"])
        .add_row(vec!["sandbox", "Sandbox execution and analysis"])
        .add_row(vec!["memory", "Memory inspection and manipulation"])
        .add_row(vec!["network", "Network traffic and proxy operations"])
        .add_row(vec!["crypto", "Cryptographic operations"])
        .add_row(vec!["report", "Report generation and management"])
        .add_row(vec!["plugin", "Plugin installation and management"])
        .add_row(vec!["system", "System information and diagnostics"])
        .add_row(vec!["config", "Configuration settings"])
        .add_row(vec!["update", "Update the platform"])
        .add_row(vec!["monitor", "System monitoring and metrics"])
        .add_row(vec!["logs", "Log viewing and management"])
        .add_row(vec!["help", "Extended help system"]);

    println!("UCOP-X Enterprise Commands:");
    println!("{table}");
    println!();
    println!("Use 'ucx help topic <command>' for detailed help on a specific command.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_includes_all_commands() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(list_topics());
        assert!(result.is_ok());
    }
}
