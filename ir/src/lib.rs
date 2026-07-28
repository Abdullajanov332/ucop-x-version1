//! UCOP-X Incident Response Engine
//!
//! Provides incident case management, playbook automation, containment
//! strategies, and post-incident analysis.

#![forbid(unsafe_code)]

pub mod playbook;
pub mod incident;
pub mod containment;

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Severity levels for incidents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub fn name(&self) -> &'static str {
        match self {
            IncidentSeverity::Low => "low",
            IncidentSeverity::Medium => "medium",
            IncidentSeverity::High => "high",
            IncidentSeverity::Critical => "critical",
        }
    }
}

/// Status of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    Investigating,
    Contained,
    Eradicated,
    Recovered,
    Closed,
}

impl IncidentStatus {
    pub fn name(&self) -> &'static str {
        match self {
            IncidentStatus::New => "new",
            IncidentStatus::Investigating => "investigating",
            IncidentStatus::Contained => "contained",
            IncidentStatus::Eradicated => "eradicated",
            IncidentStatus::Recovered => "recovered",
            IncidentStatus::Closed => "closed",
        }
    }
}

/// An incident record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: String,
    pub discovered_at: String,
    pub reported_by: String,
    pub assigned_to: Option<String>,
    pub affected_assets: Vec<String>,
    pub indicators: Vec<String>,
    pub timeline: Vec<IncidentEvent>,
    pub playbook_applied: Option<String>,
    pub containment_actions: Vec<String>,
    pub remediation_notes: String,
}

/// An event in the incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub performed_by: String,
}

/// Incident response coordinator.
#[derive(Debug, Default)]
pub struct IncidentResponder {
    pub incidents: Vec<IncidentRecord>,
}

impl IncidentResponder {
    pub fn new() -> Self {
        Self { incidents: Vec::new() }
    }

    /// Create a new incident.
    pub fn create_incident(
        &mut self,
        title: &str,
        description: &str,
        severity: IncidentSeverity,
        reported_by: &str,
    ) -> IncidentRecord {
        let incident = IncidentRecord {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.to_string(),
            description: description.to_string(),
            severity: severity.name().into(),
            status: IncidentStatus::New.name().into(),
            discovered_at: Utc::now().to_rfc3339(),
            reported_by: reported_by.to_string(),
            assigned_to: None,
            affected_assets: Vec::new(),
            indicators: Vec::new(),
            timeline: Vec::new(),
            playbook_applied: None,
            containment_actions: Vec::new(),
            remediation_notes: String::new(),
        };

        self.incidents.push(incident.clone());
        incident
    }

    /// Assign an incident to a responder.
    pub fn assign(&mut self, incident_id: &str, responder: &str) -> Result<(), String> {
        let incident = self
            .incidents
            .iter_mut()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| "incident not found".to_string())?;
        incident.assigned_to = Some(responder.to_string());
        incident.status = IncidentStatus::Investigating.name().into();
        Ok(())
    }

    /// Update incident status.
    pub fn update_status(&mut self, incident_id: &str, status: IncidentStatus) -> Result<(), String> {
        let incident = self
            .incidents
            .iter_mut()
            .find(|i| i.id == incident_id)
            .ok_or_else(|| "incident not found".to_string())?;
        incident.status = status.name().into();
        Ok(())
    }

    /// Get all incidents with a given severity.
    pub fn by_severity(&self, severity: IncidentSeverity) -> Vec<&IncidentRecord> {
        self.incidents
            .iter()
            .filter(|i| i.severity == severity.name())
            .collect()
    }

    /// Get all open incidents.
    pub fn open_incidents(&self) -> Vec<&IncidentRecord> {
        self.incidents
            .iter()
            .filter(|i| i.status != IncidentStatus::Closed.name())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_lifecycle() {
        let mut ir = IncidentResponder::new();
        let inc = ir.create_incident("Suspicious Login", "Failed logins detected", IncidentSeverity::High, "soc-analyst");
        assert_eq!(inc.severity, "high");
        assert_eq!(inc.status, "new");

        ir.assign(&inc.id, "incident-lead").unwrap();
        let inc_ref = ir.incidents.iter().find(|i| i.id == inc.id).unwrap();
        assert_eq!(inc_ref.status, "investigating");
    }

    #[test]
    fn test_filter_by_severity() {
        let mut ir = IncidentResponder::new();
        ir.create_incident("Low issue", "desc", IncidentSeverity::Low, "analyst");
        ir.create_incident("Critical breach", "desc", IncidentSeverity::Critical, "analyst");
        assert_eq!(ir.by_severity(IncidentSeverity::Critical).len(), 1);
    }
}
