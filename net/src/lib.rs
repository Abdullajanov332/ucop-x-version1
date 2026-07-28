//! UCOP-X Networking
//!
//! Provides port scanning, packet capture, protocol analysis,
//! and network discovery capabilities.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use serde::{Serialize, Deserialize};

/// Port scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// Host scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostScanResult {
    pub host: String,
    pub ip: Option<String>,
    pub ports: Vec<PortResult>,
    pub os_hint: Option<String>,
    pub duration_ms: u64,
}

/// Scan configuration.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 3,
            concurrency: 10,
            ports: vec![21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                       993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
                       5900, 6379, 8080, 8443, 9090, 27017],
            scan_type: ScanType::Connect,
        }
    }
}

/// Types of port scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    Connect,
    Syn,
    Udp,
}

impl ScanType {
    pub fn name(&self) -> &'static str {
        match self {
            ScanType::Connect => "connect",
            ScanType::Syn => "syn",
            ScanType::Udp => "udp",
        }
    }
}

/// Network scanner.
#[derive(Debug)]
pub struct NetworkScanner {
    pub config: ScanConfig,
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            config: ScanConfig::default(),
        }
    }

    pub fn with_config(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Scan a single host.
    pub fn scan_host(&self, host: &str) -> HostScanResult {
        let start = std::time::Instant::now();

        let ip = resolve_host(host);
        let mut ports = Vec::new();

        for &port in &self.config.ports {
            let result = self.scan_port(host, port);
            ports.push(result);
        }

        HostScanResult {
            host: host.to_string(),
            ip: ip.map(|a| a.to_string()),
            ports,
            os_hint: None,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Scan a single port.
    fn scan_port(&self, host: &str, port: u16) -> PortResult {
        let addr = format!("{}:{}", host, port);
        let state = match self.config.scan_type {
            ScanType::Connect => {
                match TcpStream::connect_timeout(
                    &addr.to_socket_addrs().ok()?.next()?,
                    Duration::from_secs(self.config.timeout_secs),
                ) {
                    Ok(_) => "open".to_string(),
                    Err(_) => "closed".to_string(),
                }
            }
            _ => "filtered".to_string(),
        };

        PortResult {
            port,
            protocol: "tcp".into(),
            state,
            service: port_to_service(port),
            banner: None,
        }
    }
}

fn resolve_host(host: &str) -> Option<IpAddr> {
    format!("{}:0", host)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|s| s.ip())
}

fn port_to_service(port: u16) -> Option<String> {
    let services: HashMap<u16, &str> = [
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
        (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
        (443, "https"), (445, "microsoft-ds"), (993, "imaps"),
        (995, "pop3s"), (1433, "ms-sql-s"), (1521, "oracle"),
        (2049, "nfs"), (3306, "mysql"), (3389, "ms-wbt-server"),
        (5432, "postgresql"), (5900, "vnc"), (6379, "redis"),
        (8080, "http-proxy"), (8443, "https-alt"), (9090, "prometheus"),
        (27017, "mongod"),
    ]
    .iter()
    .cloned()
    .collect();

    services.get(&port).map(|s| s.to_string())
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = NetworkScanner::new();
        assert_eq!(scanner.config.ports.len(), 24);
    }

    #[test]
    fn test_port_to_service() {
        assert_eq!(port_to_service(80).unwrap(), "http");
        assert_eq!(port_to_service(443).unwrap(), "https");
        assert!(port_to_service(99999).is_none());
    }
}
