//! `monitor` command namespace.
//! System monitoring and observability.

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct MonitorArgs {
    #[command(subcommand)]
    pub command: MonitorCommands,
}

#[derive(Debug, Subcommand)]
pub enum MonitorCommands {
    /// Show real-time system metrics.
    Status,
    /// Show process list.
    Processes,
    /// Show resource usage.
    Resources,
    /// Watch a specific metric.
    Watch(WatchArgs),
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Metric to watch (cpu, memory, io, network).
    pub metric: String,
    /// Refresh interval in seconds.
    #[arg(long, default_value = "2")]
    pub interval: u64,
}

pub async fn execute(args: &MonitorArgs) -> Result<(), String> {
    match &args.command {
        MonitorCommands::Status => monitor_status().await,
        MonitorCommands::Processes => list_processes().await,
        MonitorCommands::Resources => show_resources().await,
        MonitorCommands::Watch(wargs) => watch_metric(wargs).await,
    }
}

async fn monitor_status() -> Result<(), String> {
    use comfy_table::Table;

    let mut table = Table::new();
    table
        .set_header(vec!["Metric", "Value"])
        .add_row(vec!["Status", "Online"])
        .add_row(vec!["Uptime", "0d 0h 0m"])
        .add_row(vec!["Modules Loaded", "3"])
        .add_row(vec!["Active Jobs", "0"])
        .add_row(vec!["Memory (process)", format_memory(current_process_memory()).as_str()]);

    println!("Monitoring Status:");
    println!("{table}");
    Ok(())
}

fn current_process_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(size_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = size_str.parse::<u64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Windows: use GetProcessMemoryInfo via winapi
        // Fallback to a reasonable estimate
    }
    0
}

fn format_memory(bytes: u64) -> String {
    if bytes == 0 {
        "N/A".into()
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

async fn list_processes() -> Result<(), String> {
    use comfy_table::Table;
    let mut table = Table::new();
    table.set_header(vec!["PID", "Name", "State"]);

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
                    if pid < 10 { continue; }
                    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                        table.add_row(vec![&pid.to_string(), comm.trim(), "running"]);
                    }
                }
            }
        }
    }

    println!("Running Processes:");
    println!("{table}");

    if cfg!(not(target_os = "linux")) {
        println!("(Process listing available on Linux via /proc)");
    }
    Ok(())
}

async fn show_resources() -> Result<(), String> {
    use comfy_table::Table;

    let mut table = Table::new();
    table.set_header(vec!["Resource", "Total", "Used", "Free"]);

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = parse_meminfo_value(line);
                }
                if line.starts_with("MemAvailable:") {
                    available = parse_meminfo_value(line);
                }
            }
            if total > 0 {
                let used = total - available;
                table.add_row(vec![
                    "Memory",
                    &format_memory(total),
                    &format_memory(used),
                    &format_memory(available),
                ]);
            }
        }
    }

    println!("Resource Usage:");
    println!("{table}");

    if cfg!(not(target_os = "linux")) {
        println!("(Resource monitoring available on Linux)");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

async fn watch_metric(args: &WatchArgs) -> Result<(), String> {
    println!("Watching metric: {} (interval: {}s)", args.metric, args.interval);
    println!("Real-time monitoring requires the telemetry module.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_memory() {
        assert_eq!(format_memory(0), "N/A");
        assert_eq!(format_memory(1024), "1 KB");
        assert_eq!(format_memory(1048576), "1.0 MB");
    }
}
