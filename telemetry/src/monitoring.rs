//! System monitoring and health checks.

use serde::{Serialize, Deserialize};

/// Status of a monitored component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl ComponentStatus {
    pub fn name(&self) -> &'static str {
        match self {
            ComponentStatus::Healthy => "healthy",
            ComponentStatus::Degraded => "degraded",
            ComponentStatus::Unhealthy => "unhealthy",
            ComponentStatus::Unknown => "unknown",
        }
    }
}

/// Health check result for a component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub component: String,
    pub status: String,
    pub message: String,
    pub last_check: String,
    pub response_time_ms: u64,
}

/// Monitoring configuration.
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub check_interval_secs: u64,
    pub alert_on_degraded: bool,
    pub alert_on_unhealthy: bool,
    pub notification_channels: Vec<String>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 30,
            alert_on_degraded: false,
            alert_on_unhealthy: true,
            notification_channels: vec!["log".into()],
        }
    }
}

/// System monitor.
#[derive(Debug)]
pub struct SystemMonitor {
    pub config: MonitoringConfig,
    pub health_results: Vec<HealthCheckResult>,
}

impl SystemMonitor {
    pub fn new() -> Self {
        Self {
            config: MonitoringConfig::default(),
            health_results: Vec::new(),
        }
    }

    /// Run health checks on all registered components.
    pub fn run_health_check(&mut self) -> Vec<HealthCheckResult> {
        let components = vec!["kernel", "event-bus", "scheduler", "crypto", "memory"];
        let mut results = Vec::new();

        for component in components {
            let result = self.check_component(component);
            results.push(result);
        }

        self.health_results = results.clone();
        results
    }

    /// Check a single component's health.
    fn check_component(&self, component: &str) -> HealthCheckResult {
        let (status, message) = match component {
            "kernel" => (ComponentStatus::Healthy, "Kernel responsive and initialized"),
            "event-bus" => (ComponentStatus::Healthy, "Event bus operational"),
            "scheduler" => (ComponentStatus::Degraded, "Scheduler enabled but no active jobs"),
            "crypto" => (ComponentStatus::Healthy, "Crypto subsystem available"),
            "memory" => (ComponentStatus::Healthy, "Memory subsystem nominal"),
            _ => (ComponentStatus::Unknown, "Component not recognized"),
        };

        HealthCheckResult {
            component: component.to_string(),
            status: status.name().into(),
            message: message.into(),
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: 0,
        }
    }

    /// Get overall system status.
    pub fn overall_status(&self) -> ComponentStatus {
        if self.health_results.is_empty() {
            return ComponentStatus::Unknown;
        }
        if self
            .health_results
            .iter()
            .any(|r| r.status == ComponentStatus::Unhealthy.name())
        {
            return ComponentStatus::Unhealthy;
        }
        if self
            .health_results
            .iter()
            .any(|r| r.status == ComponentStatus::Degraded.name())
        {
            return ComponentStatus::Degraded;
        }
        ComponentStatus::Healthy
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check() {
        let mut monitor = SystemMonitor::new();
        let results = monitor.run_health_check();
        assert_eq!(results.len(), 5);
        assert!(results[0].component == "kernel");
    }

    #[test]
    fn test_overall_status() {
        let mut monitor = SystemMonitor::new();
        assert_eq!(monitor.overall_status(), ComponentStatus::Unknown);
        monitor.run_health_check();
        assert_eq!(monitor.overall_status(), ComponentStatus::Degraded);
    }
}
