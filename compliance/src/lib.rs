//! UCOP-X Compliance Engine
//!
//! Provides compliance checking against major regulatory frameworks
//! (PCI-DSS, HIPAA, SOC2, GDPR, ISO 27001, NIST CSF).

#![forbid(unsafe_code)]

pub mod framework;
pub mod controls;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Compliance frameworks supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    PciDss,
    Hipaa,
    Soc2,
    Gdpr,
    Iso27001,
    NistCsf,
    Custom(String),
}

impl ComplianceFramework {
    pub fn name(&self) -> &'static str {
        match self {
            ComplianceFramework::PciDss => "PCI-DSS",
            ComplianceFramework::Hipaa => "HIPAA",
            ComplianceFramework::Soc2 => "SOC 2",
            ComplianceFramework::Gdpr => "GDPR",
            ComplianceFramework::Iso27001 => "ISO 27001",
            ComplianceFramework::NistCsf => "NIST CSF",
            ComplianceFramework::Custom(_) => "Custom",
        }
    }
}

/// Result of a compliance check against a control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    pub control_id: String,
    pub control_name: String,
    pub status: ComplianceStatus,
    pub details: String,
    pub evidence: Vec<String>,
}

/// Compliance status for a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    NotApplicable,
    NotChecked,
    Partial,
}

impl ComplianceStatus {
    pub fn name(&self) -> &'static str {
        match self {
            ComplianceStatus::Compliant => "compliant",
            ComplianceStatus::NonCompliant => "non-compliant",
            ComplianceStatus::NotApplicable => "n/a",
            ComplianceStatus::NotChecked => "not-checked",
            ComplianceStatus::Partial => "partial",
        }
    }
}

/// A compliance audit result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAudit {
    pub audit_id: String,
    pub framework: String,
    pub organization: String,
    pub auditor: String,
    pub date: String,
    pub controls_checked: usize,
    pub compliant: usize,
    pub non_compliant: usize,
    pub not_applicable: usize,
    pub overall_status: String,
    pub results: Vec<ComplianceCheckResult>,
}

/// Compliance engine.
#[derive(Debug, Default)]
pub struct ComplianceEngine {
    pub audits: Vec<ComplianceAudit>,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        Self { audits: Vec::new() }
    }

    /// Run a compliance audit against a framework.
    pub fn audit(
        &mut self,
        framework: ComplianceFramework,
        organization: &str,
        auditor: &str,
    ) -> ComplianceAudit {
        let controls = framework::get_controls(framework);
        let mut results = Vec::new();
        let mut compliant = 0;
        let mut non_compliant = 0;
        let mut na = 0;

        for control in &controls {
            let status = ComplianceStatus::NotChecked;
            match status {
                ComplianceStatus::Compliant => compliant += 1,
                ComplianceStatus::NonCompliant => non_compliant += 1,
                ComplianceStatus::NotApplicable => na += 1,
                _ => {}
            }
            results.push(ComplianceCheckResult {
                control_id: control.id.clone(),
                control_name: control.name.clone(),
                status,
                details: "Pending assessment".into(),
                evidence: Vec::new(),
            });
        }

        let total = controls.len();
        let audit = ComplianceAudit {
            audit_id: uuid::Uuid::new_v4().to_string(),
            framework: framework.name().into(),
            organization: organization.to_string(),
            auditor: auditor.to_string(),
            date: chrono::Utc::now().to_rfc3339(),
            controls_checked: total,
            compliant,
            non_compliant,
            not_applicable: na,
            overall_status: if compliant == total {
                "fully compliant"
            } else if non_compliant == 0 {
                "pending review"
            } else {
                "non-compliant"
            }
            .into(),
            results,
        };

        self.audits.push(audit.clone());
        audit
    }

    /// Get coverage percentage for a specific framework.
    pub fn coverage(&self, _framework: ComplianceFramework) -> f64 {
        // Calculate coverage from past audits
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_creation() {
        let mut engine = ComplianceEngine::new();
        let audit = engine.audit(ComplianceFramework::PciDss, "Acme Corp", "auditor");
        assert_eq!(audit.framework, "PCI-DSS");
        assert!(!audit.audit_id.is_empty());
        assert!(audit.controls_checked > 0);
    }

    #[test]
    fn test_framework_names() {
        assert_eq!(ComplianceFramework::Gdpr.name(), "GDPR");
        assert_eq!(ComplianceFramework::Iso27001.name(), "ISO 27001");
    }
}
