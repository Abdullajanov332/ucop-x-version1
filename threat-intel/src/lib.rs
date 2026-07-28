//! UCOP-X Threat Intelligence Engine
//!
//! Provides IOC (Indicator of Compromise) management, threat feed
//! ingestion, enrichment, and threat scoring.

#![forbid(unsafe_code)]

pub mod ioc;
pub mod feed;
pub mod enrichment;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Types of threat indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoCType {
    IpAddress,
    Domain,
    Url,
    Hash,
    Email,
    FilePath,
    RegistryKey,
    Mutex,
    Cve,
}

impl IoCType {
    pub fn name(&self) -> &'static str {
        match self {
            IoCType::IpAddress => "ip-address",
            IoCType::Domain => "domain",
            IoCType::Url => "url",
            IoCType::Hash => "hash",
            IoCType::Email => "email",
            IoCType::FilePath => "file-path",
            IoCType::RegistryKey => "registry-key",
            IoCType::Mutex => "mutex",
            IoCType::Cve => "cve",
        }
    }
}

/// Confidence level of a threat indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

/// A threat intelligence indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: String,
    pub indicator_type: String,
    pub value: String,
    pub confidence: String,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub tags: Vec<String>,
    pub description: String,
    pub mitre_techniques: Vec<String>,
    pub tlp: String,
}

/// Threat intelligence feed source.
#[derive(Debug, Clone)]
pub struct FeedSource {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub enabled: bool,
    pub interval_minutes: u32,
}

/// Feed data format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    Stix,
    Misp,
    OpenIoC,
    Csv,
    Json,
}

/// Threat intelligence engine.
#[derive(Debug, Default)]
pub struct ThreatIntelEngine {
    pub indicators: Vec<ThreatIndicator>,
    pub feeds: Vec<FeedSource>,
}

impl ThreatIntelEngine {
    pub fn new() -> Self {
        Self {
            indicators: Vec::new(),
            feeds: Vec::new(),
        }
    }

    /// Add an indicator to the database.
    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        // Deduplicate by value and type
        if !self
            .indicators
            .iter()
            .any(|i| i.value == indicator.value && i.indicator_type == indicator.indicator_type)
        {
            self.indicators.push(indicator);
        }
    }

    /// Search for indicators matching a value.
    pub fn search(&self, query: &str) -> Vec<&ThreatIndicator> {
        let q = query.to_lowercase();
        self.indicators
            .iter()
            .filter(|i| i.value.to_lowercase().contains(&q) || i.tags.iter().any(|t| t.contains(&q)))
            .collect()
    }

    /// Get indicators of a specific type.
    pub fn by_type(&self, ioc_type: IoCType) -> Vec<&ThreatIndicator> {
        self.indicators
            .iter()
            .filter(|i| i.indicator_type == ioc_type.name())
            .collect()
    }

    /// Register a threat feed source.
    pub fn register_feed(&mut self, feed: FeedSource) {
        self.feeds.push(feed);
    }

    /// Count total indicators.
    pub fn count(&self) -> usize {
        self.indicators.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_dedup() {
        let mut engine = ThreatIntelEngine::new();
        engine.add_indicator(ThreatIndicator {
            id: "1".into(),
            indicator_type: "ip-address".into(),
            value: "192.168.1.1".into(),
            confidence: "high".into(),
            source: "test".into(),
            first_seen: "".into(),
            last_seen: "".into(),
            tags: vec![],
            description: "".into(),
            mitre_techniques: vec![],
            tlp: "white".into(),
        });
        engine.add_indicator(ThreatIndicator {
            id: "2".into(),
            indicator_type: "ip-address".into(),
            value: "192.168.1.1".into(),
            confidence: "medium".into(),
            source: "test2".into(),
            first_seen: "".into(),
            last_seen: "".into(),
            tags: vec![],
            description: "".into(),
            mitre_techniques: vec![],
            tlp: "white".into(),
        });
        assert_eq!(engine.count(), 1);
    }

    #[test]
    fn test_search_by_value() {
        let mut engine = ThreatIntelEngine::new();
        engine.add_indicator(ThreatIndicator {
            id: "1".into(),
            indicator_type: "domain".into(),
            value: "evil.example.com".into(),
            confidence: "high".into(),
            source: "test".into(),
            first_seen: "".into(),
            last_seen: "".into(),
            tags: vec!["malware".into()],
            description: "".into(),
            mitre_techniques: vec![],
            tlp: "white".into(),
        });
        assert_eq!(engine.search("evil").len(), 1);
    }
}
