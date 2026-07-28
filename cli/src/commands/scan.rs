//! `scan` command namespace.
//! Network scanning, port scanning, and vulnerability scanning.

use clap::{Args, Subcommand};

/// Scan command group — network and vulnerability scanning.
#[derive(Debug, Args)]
pub struct ScanArgs {
    #[command(subcommand)]
    pub command: ScanCommands,
}

#[derive(Debug, Subcommand)]
pub enum ScanCommands {
    /// Port scan a target.
    Port(PortScanArgs),
    /// Scan for vulnerabilities.
    Vuln(VulnScanArgs),
    /// Scan a directory/URL for paths.
    Directory(DirScanArgs),
    /// List available scan modules.
    List,
}

#[derive(Debug, Args)]
pub struct PortScanArgs {
    /// Target hostname or IP.
    pub target: String,
    /// Port range (e.g. 1-1000, 22,80,443).
    #[arg(long, default_value = "1-1024")]
    pub ports: String,
    /// Scan speed (slow, normal, fast).
    #[arg(long, default_value = "normal")]
    pub speed: String,
    /// Output format.
    #[arg(long, default_value = "plain")]
    pub format: String,
}

#[derive(Debug, Args)]
pub struct VulnScanArgs {
    /// Target hostname or IP.
    pub target: String,
    /// CVE ID to check for.
    #[arg(long)]
    pub cve: Option<String>,
    /// Scan intensity (light, normal, aggressive).
    #[arg(long, default_value = "normal")]
    pub intensity: String,
}

#[derive(Debug, Args)]
pub struct DirScanArgs {
    /// Target URL.
    pub url: String,
    /// Wordlist path.
    #[arg(long)]
    pub wordlist: Option<String>,
    /// File extensions to check.
    #[arg(long)]
    pub extensions: Option<String>,
}

/// Execute the scan command.
pub async fn execute(args: &ScanArgs) -> Result<(), String> {
    match &args.command {
        ScanCommands::Port(pargs) => scan_port(pargs).await,
        ScanCommands::Vuln(vargs) => scan_vuln(vargs).await,
        ScanCommands::Directory(dargs) => scan_directory(dargs).await,
        ScanCommands::List => list_scan_modules().await,
    }
}

async fn scan_port(args: &PortScanArgs) -> Result<(), String> {
    use comfy_table::Table;

    println!("Port scanning target: {}", args.target);
    println!("  Ports: {}", args.ports);
    println!("  Speed: {}", args.speed);

    // Resolve hostname
    let host = resolve_host(&args.target)?;

    let ports = parse_ports(&args.ports)?;

    let mut table = Table::new();
    table.set_header(vec!["Port", "State", "Service"]);

    // Quick scan of the specified ports (non-blocking connect scan)
    for port in ports.iter().take(100) {
        let state = probe_port(&host, *port);
        if state.0 {
            table.add_row(vec![
                &port.to_string(),
                "open",
                state.1,
            ]);
        }
    }

    println!("\nScan Results:");
    println!("{table}");
    Ok(())
}

fn resolve_host(target: &str) -> Result<std::net::IpAddr, String> {
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    match std::net::ToSocketAddrs::to_socket_addrs(&(target.to_string() + ":0")) {
        Ok(mut addrs) => addrs
            .next()
            .map(|a| a.ip())
            .ok_or_else(|| format!("could not resolve: {target}")),
        Err(e) => Err(format!("DNS resolution failed: {e}")),
    }
}

fn parse_ports(port_spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in port_spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .parse()
                .map_err(|_| format!("invalid port range: {part}"))?;
            let end: u16 = end
                .parse()
                .map_err(|_| format!("invalid port range: {part}"))?;
            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("invalid port: {part}"))?;
            ports.push(port);
        }
    }

    ports.sort_unstable();
    ports.dedup();

    if ports.len() > 65535 {
        return Err("too many ports specified".into());
    }

    Ok(ports)
}

fn probe_port(host: &std::net::IpAddr, port: u16) -> (bool, &'static str) {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = std::net::SocketAddr::new(*host, port);
    match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(mut stream) => {
            let service = match port {
                20 | 21 => "FTP",
                22 => "SSH",
                23 => "Telnet",
                25 => "SMTP",
                53 => "DNS",
                80 => "HTTP",
                110 => "POP3",
                143 => "IMAP",
                443 => "HTTPS",
                445 => "SMB",
                3306 => "MySQL",
                3389 => "RDP",
                5432 => "PostgreSQL",
                5900 => "VNC",
                6379 => "Redis",
                8080 => "HTTP-Proxy",
                8443 => "HTTPS-Alt",
                27017 => "MongoDB",
                _ => "unknown",
            };

            // Attempt banner grab
            if !port.is_privileged() && stream.set_read_timeout(Some(Duration::from_millis(200))).is_ok() {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf);
            }

            drop(stream);
            (true, service)
        }
        Err(_) => (false, ""),
    }
}

async fn scan_vuln(_args: &VulnScanArgs) -> Result<(), String> {
    println!("Vulnerability scanning (requires vuln-db module)");
    println!("This feature requires the vulnerability scanner module.");
    Ok(())
}

async fn scan_directory(_args: &DirScanArgs) -> Result<(), String> {
    println!("Directory scanning (requires wordlist and HTTP module)");
    println!("This feature requires the directory bruteforce module.");
    Ok(())
}

async fn list_scan_modules() -> Result<(), String> {
    use comfy_table::Table;
    let mut table = Table::new();
    table
        .set_header(vec!["Module", "Version", "Description"])
        .add_row(vec!["port-scanner", "1.0.0", "TCP port scanning engine"])
        .add_row(vec!["vuln-scanner", "0.9.0", "Vulnerability detection engine"])
        .add_row(vec!["dir-bruteforce", "1.0.0", "Directory and path enumeration"]);

    println!("Available Scan Modules:");
    println!("{table}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_ports_comma() {
        let ports = parse_ports("22,80,443").unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_invalid() {
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn test_probe_known_services() {
        // Localhost ports that are likely closed - should return (false, "")
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let (state, service) = probe_port(&local, 9999);
        assert!(!state);
        assert_eq!(service, "");
    }
}
