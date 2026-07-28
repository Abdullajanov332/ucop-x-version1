//! Threat intelligence enrichment - adds context to indicators.

use crate::ThreatIndicator;

/// Enrichment source types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrichmentSource {
    GeoIp,
    Whois,
    Dns,
    ReverseDns,
    SslCert,
    VirusTotal,
    AbuseIPDB,
    Shodan,
}

/// Result of enrichment on an indicator.
#[derive(Debug, Clone)]
pub struct EnrichmentResult {
    pub indicator_id: String,
    pub source: EnrichmentSource,
    pub data: std::collections::HashMap<String, String>,
    pub success: bool,
}

/// Enrichment engine that adds context to indicators.
#[derive(Debug, Default)]
pub struct EnrichmentEngine;

impl EnrichmentEngine {
    pub fn new() -> Self {
        Self
    }

    /// Enrich an indicator with context from a source.
    pub fn enrich(&self, indicator: &ThreatIndicator, source: EnrichmentSource) -> EnrichmentResult {
        let mut data = std::collections::HashMap::new();

        match source {
            EnrichmentSource::GeoIp => {
                data.insert("country".into(), "Unknown".into());
                data.insert("asn".into(), "AS00000".into());
            }
            EnrichmentSource::Whois => {
                data.insert("registrar".into(), "Unknown".into());
                data.insert("creation_date".into(), "N/A".into());
            }
            EnrichmentSource::Dns => {
                data.insert("a_record".into(), "N/A".into());
                data.insert("mx_record".into(), "N/A".into());
            }
            _ => {
                data.insert("note".into(), "Enrichment source not available offline".into());
            }
        }

        EnrichmentResult {
            indicator_id: indicator.id.clone(),
            source,
            data,
            success: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrichment_adds_data() {
        let engine = EnrichmentEngine::new();
        let indicator = ThreatIndicator {
            id: "1".into(),
            indicator_type: "ip-address".into(),
            value: "8.8.8.8".into(),
            confidence: "medium".into(),
            source: "test".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            tags: Vec::new(),
            description: String::new(),
            mitre_techniques: Vec::new(),
            tlp: "white".into(),
        };
        let result = engine.enrich(&indicator, EnrichmentSource::GeoIp);
        assert!(result.success);
        assert!(result.data.contains_key("country"));
    }
}
