//! UCOP-X Telemetry
//!
//! Provides metrics collection, distributed tracing, structured logging,
//! and system monitoring capabilities.

#![forbid(unsafe_code)]

pub mod metrics;
pub mod tracing;
pub mod monitoring;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// A telemetry data point (metric, log, or trace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPoint {
    pub timestamp: String,
    pub name: String,
    pub value: f64,
    pub tags: HashMap<String, String>,
    pub source: String,
}

/// Metric types supported by the telemetry system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Timer,
}

impl MetricType {
    pub fn name(&self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
            MetricType::Histogram => "histogram",
            MetricType::Timer => "timer",
        }
    }
}

/// Telemetry configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub sampling_rate: f64,
    pub export_interval_secs: u64,
    pub storage_backend: String,
    pub max_points_per_export: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sampling_rate: 1.0,
            export_interval_secs: 60,
            storage_backend: "memory".into(),
            max_points_per_export: 10_000,
        }
    }
}

/// Telemetry engine for collecting and exporting metrics.
#[derive(Debug)]
pub struct TelemetryEngine {
    pub config: TelemetryConfig,
    pub(crate) points: Vec<TelemetryPoint>,
}

impl TelemetryEngine {
    pub fn new() -> Self {
        Self {
            config: TelemetryConfig::default(),
            points: Vec::new(),
        }
    }

    pub fn with_config(config: TelemetryConfig) -> Self {
        Self {
            config,
            points: Vec::new(),
        }
    }

    /// Record a metric data point.
    pub fn record(&mut self, name: &str, value: f64, tags: HashMap<String, String>) {
        if !self.config.enabled {
            return;
        }
        self.points.push(TelemetryPoint {
            timestamp: chrono::Utc::now().to_rfc3339(),
            name: name.to_string(),
            value,
            tags,
            source: hostname(),
        });
    }

    /// Record a counter increment.
    pub fn increment(&mut self, name: &str) {
        self.record(name, 1.0, HashMap::new());
    }

    /// Record a gauge value.
    pub fn gauge(&mut self, name: &str, value: f64) {
        self.record(name, value, HashMap::new());
    }

    /// Export all collected telemetry points and clear the buffer.
    pub fn export(&mut self) -> Vec<TelemetryPoint> {
        let points = self.points.clone();
        self.points.clear();
        points
    }

    /// Get current point count.
    pub fn point_count(&self) -> usize {
        self.points.len()
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

impl Default for TelemetryEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_recording() {
        let mut engine = TelemetryEngine::new();
        engine.increment("requests.total");
        engine.gauge("memory.used", 42.0);
        assert_eq!(engine.point_count(), 2);
    }

    #[test]
    fn test_export_clears_buffer() {
        let mut engine = TelemetryEngine::new();
        engine.increment("test");
        let exported = engine.export();
        assert_eq!(exported.len(), 1);
        assert_eq!(engine.point_count(), 0);
    }

    #[test]
    fn test_disabled_no_recording() {
        let mut config = TelemetryConfig::default();
        config.enabled = false;
        let mut engine = TelemetryEngine::with_config(config);
        engine.increment("test");
        assert_eq!(engine.point_count(), 0);
    }
}
