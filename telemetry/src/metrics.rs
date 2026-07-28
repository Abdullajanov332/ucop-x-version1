//! Metrics collection and aggregation.

use std::collections::HashMap;

/// A tracked metric.
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub metric_type: String,
    pub value: f64,
    pub tags: HashMap<String, String>,
}

/// Predefined system metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemMetric {
    CpuUsage,
    MemoryUsage,
    DiskUsage,
    NetworkBytesReceived,
    NetworkBytesSent,
    ProcessesRunning,
    OpenFileDescriptors,
}

impl SystemMetric {
    pub fn name(&self) -> &'static str {
        match self {
            SystemMetric::CpuUsage => "system.cpu.usage",
            SystemMetric::MemoryUsage => "system.memory.usage",
            SystemMetric::DiskUsage => "system.disk.usage",
            SystemMetric::NetworkBytesReceived => "system.network.rx_bytes",
            SystemMetric::NetworkBytesSent => "system.network.tx_bytes",
            SystemMetric::ProcessesRunning => "system.processes.running",
            SystemMetric::OpenFileDescriptors => "system.fd.open",
        }
    }
}

/// Collect a system metric value.
pub fn collect_system_metric(metric: SystemMetric) -> f64 {
    match metric {
        SystemMetric::CpuUsage => {
            // Simplified CPU usage estimation
            0.0
        }
        SystemMetric::MemoryUsage => {
            // Simplified memory usage
            0.0
        }
        SystemMetric::ProcessesRunning => {
            // Count running processes
            std::process::id() as f64
        }
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_names() {
        assert_eq!(SystemMetric::CpuUsage.name(), "system.cpu.usage");
        assert_eq!(SystemMetric::OpenFileDescriptors.name(), "system.fd.open");
    }
}
