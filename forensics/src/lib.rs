//! UCOP-X Forensics Engine
//!
//! Provides disk forensics, memory analysis, filesystem artifact
//! extraction, timeline reconstruction, and evidence management.

#![forbid(unsafe_code)]

pub mod disk;
pub mod filesystem;
pub mod timeline;
pub mod evidence;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Types of forensics artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    FileSystem,
    Registry,
    EventLog,
    Prefetch,
    RecentFiles,
    BrowserHistory,
    NetworkConnections,
    ProcessList,
    ServiceList,
    ScheduledTask,
    UsbHistory,
    MemoryDump,
}

impl ArtifactType {
    pub fn name(&self) -> &'static str {
        match self {
            ArtifactType::FileSystem => "filesystem",
            ArtifactType::Registry => "registry",
            ArtifactType::EventLog => "event-log",
            ArtifactType::Prefetch => "prefetch",
            ArtifactType::RecentFiles => "recent-files",
            ArtifactType::BrowserHistory => "browser-history",
            ArtifactType::NetworkConnections => "network-connections",
            ArtifactType::ProcessList => "process-list",
            ArtifactType::ServiceList => "service-list",
            ArtifactType::ScheduledTask => "scheduled-task",
            ArtifactType::UsbHistory => "usb-history",
            ArtifactType::MemoryDump => "memory-dump",
        }
    }
}

/// A collected forensics artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_type: String,
    pub source: String,
    pub timestamp: String,
    pub data: HashMap<String, String>,
    pub hash: String,
}

/// Forensics analysis case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsCase {
    pub case_id: String,
    pub case_name: String,
    pub examiner: String,
    pub created: String,
    pub artifacts: Vec<Artifact>,
    pub notes: Vec<String>,
}

impl ForensicsCase {
    pub fn new(case_id: &str, case_name: &str, examiner: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            case_name: case_name.to_string(),
            examiner: examiner.to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            artifacts: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Add an artifact to the case.
    pub fn add_artifact(&mut self, artifact: Artifact) {
        self.artifacts.push(artifact);
    }

    /// Add a note to the case.
    pub fn add_note(&mut self, note: &str) {
        self.notes.push(note.to_string());
    }
}

/// Forensics engine.
#[derive(Debug, Default)]
pub struct ForensicsEngine {
    pub active_case: Option<ForensicsCase>,
}

impl ForensicsEngine {
    pub fn new() -> Self {
        Self { active_case: None }
    }

    /// Create a new case and set it as active.
    pub fn create_case(&mut self, case_id: &str, case_name: &str, examiner: &str) {
        self.active_case = Some(ForensicsCase::new(case_id, case_name, examiner));
    }

    /// Get the active case, or return an error.
    pub fn active_case(&self) -> Result<&ForensicsCase, String> {
        self.active_case.as_ref().ok_or_else(|| "no active case".into())
    }

    /// Compute a SHA-256 hash of data.
    pub fn compute_hash(data: &[u8]) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_type_names() {
        assert_eq!(ArtifactType::Registry.name(), "registry");
        assert_eq!(ArtifactType::MemoryDump.name(), "memory-dump");
    }

    #[test]
    fn test_case_creation() {
        let mut engine = ForensicsEngine::new();
        engine.create_case("CASE-001", "Investigation Alpha", "analyst");
        let case = engine.active_case().unwrap();
        assert_eq!(case.case_id, "CASE-001");
        assert!(!case.created.is_empty());
    }

    #[test]
    fn test_hash_computation() {
        let hash = ForensicsEngine::compute_hash(b"test data");
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }
}
