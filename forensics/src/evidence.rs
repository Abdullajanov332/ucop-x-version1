//! Evidence management for forensic cases.
//!
//! Handles chain of custody, evidence bagging, hashing, and integrity verification.

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// Evidence status in the chain of custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStatus {
    Collected,
    InTransit,
    UnderAnalysis,
    Completed,
    Sealed,
}

/// An evidence item with chain of custody.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub description: String,
    pub source: String,
    pub collected_by: String,
    pub collected_at: String,
    pub hash: String,
    pub hash_algorithm: String,
    pub status: String,
    pub custody_log: Vec<CustodyEntry>,
}

/// A custody transfer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub timestamp: String,
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// Evidence manager for forensics cases.
#[derive(Debug, Default)]
pub struct EvidenceManager {
    pub items: Vec<EvidenceItem>,
}

impl EvidenceManager {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Create a new evidence item.
    pub fn create_evidence(
        &mut self,
        id: &str,
        description: &str,
        source: &str,
        collected_by: &str,
        data: &[u8],
    ) -> EvidenceItem {
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(data));

        let item = EvidenceItem {
            id: id.to_string(),
            description: description.to_string(),
            source: source.to_string(),
            collected_by: collected_by.to_string(),
            collected_at: Utc::now().to_rfc3339(),
            hash,
            hash_algorithm: "SHA-256".into(),
            status: "collected".into(),
            custody_log: Vec::new(),
        };

        self.items.push(item.clone());
        item
    }

    /// Transfer custody of an evidence item.
    pub fn transfer_custody(
        &mut self,
        evidence_id: &str,
        from: &str,
        to: &str,
        reason: &str,
    ) -> Result<(), String> {
        let item = self
            .items
            .iter_mut()
            .find(|i| i.id == evidence_id)
            .ok_or_else(|| format!("evidence not found: {evidence_id}"))?;

        item.custody_log.push(CustodyEntry {
            timestamp: Utc::now().to_rfc3339(),
            from: from.to_string(),
            to: to.to_string(),
            reason: reason.to_string(),
        });

        Ok(())
    }

    /// Verify evidence integrity by checking hash.
    pub fn verify_integrity(&self, evidence_id: &str, data: &[u8]) -> Result<bool, String> {
        use sha2::Digest;
        let item = self
            .items
            .iter()
            .find(|i| i.id == evidence_id)
            .ok_or_else(|| format!("evidence not found: {evidence_id}"))?;

        let computed = hex::encode(sha2::Sha256::digest(data));
        Ok(computed == item.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_lifecycle() {
        let mut mgr = EvidenceManager::new();
        let item = mgr.create_evidence("E-001", "Suspicious file", "/tmp/test", "analyst", b"data");
        assert_eq!(item.status, "collected");
        assert_eq!(item.hash.len(), 64);

        mgr.transfer_custody("E-001", "analyst", "reviewer", "handover for analysis")
            .unwrap();
        assert_eq!(mgr.items[0].custody_log.len(), 1);
    }

    #[test]
    fn test_integrity_verification() {
        let mut mgr = EvidenceManager::new();
        mgr.create_evidence("E-002", "Test file", "/tmp/test2", "analyst", b"original data");
        assert!(mgr.verify_integrity("E-002", b"original data").unwrap());
        assert!(!mgr.verify_integrity("E-002", b"tampered data").unwrap());
    }
}
