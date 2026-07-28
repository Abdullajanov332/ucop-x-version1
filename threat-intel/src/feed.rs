//! Threat intelligence feed ingestion.

use crate::FeedFormat;

/// Configuration for a threat feed.
#[derive(Debug, Clone)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub api_key: Option<String>,
    pub update_interval_minutes: u32,
}

/// Result of ingesting a threat feed.
#[derive(Debug, Clone)]
pub struct FeedIngestionResult {
    pub feed_name: String,
    pub indicators_added: usize,
    pub indicators_updated: usize,
    pub errors: Vec<String>,
    pub duration_secs: f64,
}

/// Threat feed ingestion engine.
#[derive(Debug, Default)]
pub struct FeedIngestionEngine;

impl FeedIngestionEngine {
    pub fn new() -> Self {
        Self
    }

    /// Ingest indicators from a feed.
    pub fn ingest(&self, _config: &FeedConfig) -> FeedIngestionResult {
        FeedIngestionResult {
            feed_name: _config.name.clone(),
            indicators_added: 0,
            indicators_updated: 0,
            errors: Vec::new(),
            duration_secs: 0.0,
        }
    }

    /// Parse a line of CSV-formatted threat data.
    pub fn parse_csv_line(&self, line: &str) -> Option<(String, String, String)> {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 3 {
            Some((
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
                parts[2].trim().to_string(),
            ))
        } else {
            None
        }
    }
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            format: FeedFormat::Json,
            api_key: None,
            update_interval_minutes: 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_line() {
        let engine = FeedIngestionEngine::new();
        let result = engine.parse_csv_line("ip-address,192.168.1.1,C2 server");
        assert!(result.is_some());
        let (ioc_type, value, desc) = result.unwrap();
        assert_eq!(ioc_type, "ip-address");
        assert_eq!(value, "192.168.1.1");
        assert_eq!(desc, "C2 server");
    }

    #[test]
    fn test_parse_invalid_csv() {
        let engine = FeedIngestionEngine::new();
        assert!(engine.parse_csv_line("invalid").is_none());
    }
}
