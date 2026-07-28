//! `memory` command namespace.
//! Memory analysis and forensics operations.

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct MemoryArgs {
    #[command(subcommand)]
    pub command: MemoryCommands,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommands {
    /// Dump process memory.
    Dump(DumpArgs),
    /// Search memory for patterns.
    Search(SearchArgs),
    /// Analyze memory regions.
    Regions(RegionsArgs),
    /// Show memory statistics.
    Stats,
}

#[derive(Debug, Args)]
pub struct DumpArgs {
    /// Process ID or name.
    pub target: String,
    /// Output file path.
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Dump file to search.
    pub dump_path: String,
    /// Pattern to search for (hex or string).
    pub pattern: String,
    /// Context bytes to show around matches.
    #[arg(long, default_value = "16")]
    pub context: usize,
}

#[derive(Debug, Args)]
pub struct RegionsArgs {
    /// Dump file path.
    pub dump_path: String,
}

pub async fn execute(args: &MemoryArgs) -> Result<(), String> {
    match &args.command {
        MemoryCommands::Dump(dargs) => dump_memory(dargs).await,
        MemoryCommands::Search(sargs) => search_memory(sargs).await,
        MemoryCommands::Regions(rargs) => analyze_regions(rargs).await,
        MemoryCommands::Stats => show_memory_stats().await,
    }
}

async fn dump_memory(_args: &DumpArgs) -> Result<(), String> {
    println!("Memory dumping requires OS-level integration (process_vm_readv on Linux, ReadProcessMemory on Windows).");
    println!("This feature requires the memory analysis module to be loaded with appropriate capabilities.");
    Ok(())
}

async fn search_memory(args: &SearchArgs) -> Result<(), String> {
    let path = std::path::Path::new(&args.dump_path);
    if !path.exists() {
        return Err(format!("dump file not found: {}", args.dump_path));
    }

    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let pattern = if args.pattern.starts_with("0x") || args.pattern.len() == hex::encode_length(args.pattern.len()) {
        hex::decode(args.pattern.trim_start_matches("0x")).map_err(|e| format!("invalid hex pattern: {e}"))?
    } else {
        args.pattern.as_bytes().to_vec()
    };

    if pattern.is_empty() {
        return Err("empty search pattern".into());
    }

    let mut matches = 0;
    for (offset, window) in data.windows(pattern.len()).enumerate() {
        if window == &pattern[..] {
            let ctx_start = offset.saturating_sub(args.context);
            let ctx_end = (offset + pattern.len() + args.context).min(data.len());
            let context_bytes = &data[ctx_start..ctx_end];
            println!("Match at 0x{offset:x}: {}", hex::encode(context_bytes));
            matches += 1;
        }
    }

    println!("\nFound {matches} matches for pattern ({} bytes)", pattern.len());
    Ok(())
}

async fn analyze_regions(_args: &RegionsArgs) -> Result<(), String> {
    println!("Region analysis requires Volatility integration.");
    println!("Load the memory forensics module to enable this feature.");
    Ok(())
}

async fn show_memory_stats() -> Result<(), String> {
    use comfy_table::Table;

    let total = &ucx_memory::AllocatorStats::default();
    let mut table = Table::new();
    table
        .set_header(vec!["Metric", "Value"])
        .add_row(vec!["Total Allocated", &format!("{} bytes", total.current_allocated())])
        .add_row(vec!["Peak Usage", &format!("{} bytes", total.peak_allocated())])
        .add_row(vec!["Allocations", &total.allocation_count().to_string()])
        .add_row(vec!["Deallocations", &total.deallocation_count().to_string()]);

    println!("UCOP-X Memory Statistics:");
    println!("{table}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_memory_hex() {
        let args = SearchArgs {
            dump_path: "nonexistent.dmp".into(),
            pattern: "0xdeadbeef".into(),
            context: 8,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(search_memory(&args));
        assert!(result.is_err()); // file not found
    }
}
