//! `network` command namespace.
//! Network monitoring, traffic capture, and analysis.

use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub command: NetworkCommands,
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommands {
    /// Capture network traffic.
    Capture(CaptureArgs),
    /// List network connections.
    Connections,
    /// Monitor network interfaces.
    Interfaces,
    /// Analyze network traffic from PCAP.
    Analyze(AnalyzeArgs),
}

#[derive(Debug, Args)]
pub struct CaptureArgs {
    /// Interface to capture on.
    #[arg(long)]
    pub interface: Option<String>,
    /// BPF filter expression.
    #[arg(long)]
    pub filter: Option<String>,
    /// Output file.
    #[arg(short, long)]
    pub output: Option<String>,
    /// Capture duration in seconds.
    #[arg(long, default_value = "30")]
    pub duration: u64,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    /// PCAP file path.
    pub path: String,
    /// Protocol filter.
    #[arg(long)]
    pub proto: Option<String>,
}

pub async fn execute(args: &NetworkArgs) -> Result<(), String> {
    match &args.command {
        NetworkCommands::Capture(cargs) => capture_traffic(cargs).await,
        NetworkCommands::Connections => list_connections().await,
        NetworkCommands::Interfaces => list_interfaces().await,
        NetworkCommands::Analyze(aargs) => analyze_traffic(aargs).await,
    }
}

async fn capture_traffic(args: &CaptureArgs) -> Result<(), String> {
    println!("Packet capture: (requires pcap/BPF integration)");
    if let Some(iface) = &args.interface {
        println!("  Interface: {iface}");
    }
    if let Some(filter) = &args.filter {
        println!("  Filter: {filter}");
    }
    println!("  Duration: {}s", args.duration);
    println!("This feature requires the network capture module.");
    Ok(())
}

async fn list_connections() -> Result<(), String> {
    use comfy_table::Table;

    let mut table = Table::new();
    table.set_header(vec!["Protocol", "Local Address", "Remote Address", "State"]);

    // Cross-platform connection listing via parsing /proc/net or using system APIs
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local = parts[1];
                    let remote = parts[2];
                    let state_code = parts[3];
                    let state = tcp_state(state_code);
                    table.add_row(vec!["TCP", local, remote, state]);
                }
            }
        }
    }

    println!("Network Connections:");
    println!("{table}");

    if cfg!(not(target_os = "linux")) {
        println!("(Connection listing available on Linux via /proc/net)");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

async fn list_interfaces() -> Result<(), String> {
    use comfy_table::Table;

    let mut table = Table::new();
    table.set_header(vec!["Interface", "IP Address", "MAC Address", "Status"]);

    // List network interfaces using standard library
    if let Ok(interfaces) = std::net::lookup_host("localhost") {
        for addr in interfaces.take(5) {
            let ip = addr.ip();
            if !ip.is_loopback() {
                table.add_row(vec![
                    "interface",
                    &ip.to_string(),
                    "N/A",
                    "up",
                ]);
            }
        }
    }

    // Try system-specific interface listing
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let addr_path = entry.path().join("address");
                let oper_path = entry.path().join("operstate");
                if let Ok(mac) = std::fs::read_to_string(addr_path) {
                    let mac = mac.trim();
                    let state = std::fs::read_to_string(oper_path).unwrap_or_default();
                    table.add_row(vec![
                        &name.to_string_lossy(),
                        "dynamic",
                        mac,
                        state.trim(),
                    ]);
                }
            }
        }
    }

    println!("Network Interfaces:");
    println!("{table}");
    Ok(())
}

async fn analyze_traffic(_args: &AnalyzeArgs) -> Result<(), String> {
    println!("Traffic analysis requires the network analysis module (tcpdump/tshark integration).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_connections_runs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(list_connections());
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_interfaces_runs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(list_interfaces());
        assert!(result.is_ok());
    }
}
