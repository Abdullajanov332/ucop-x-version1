//! Report templates for common security assessment types.

use crate::{ReportFinding, ReportSection, SecurityReport};

/// Types of report templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportTemplate {
    PenetrationTest,
    VulnerabilityAssessment,
    ComplianceAudit,
    IncidentResponse,
    MalwareAnalysis,
    NetworkAssessment,
}

impl ReportTemplate {
    pub fn name(&self) -> &'static str {
        match self {
            ReportTemplate::PenetrationTest => "Penetration Test Report",
            ReportTemplate::VulnerabilityAssessment => "Vulnerability Assessment Report",
            ReportTemplate::ComplianceAudit => "Compliance Audit Report",
            ReportTemplate::IncidentResponse => "Incident Response Report",
            ReportTemplate::MalwareAnalysis => "Malware Analysis Report",
            ReportTemplate::NetworkAssessment => "Network Security Assessment",
        }
    }
}

/// Apply a template to a report, generating standard sections.
pub fn apply_template(report: &mut SecurityReport, template: ReportTemplate) {
    report.title = template.name().to_string();

    let exec_summary = ReportSection {
        title: "Executive Summary".into(),
        content: "This section provides a high-level overview of the assessment findings, \
                  key risks identified, and recommended actions for remediation."
            .into(),
        findings: Vec::new(),
        subsections: Vec::new(),
    };
    report.add_section(exec_summary);

    let scope = ReportSection {
        title: "Scope and Methodology".into(),
        content: "Details the scope of the assessment and the methodology used.".into(),
        findings: Vec::new(),
        subsections: Vec::new(),
    };
    report.add_section(scope);

    let findings_section = ReportSection {
        title: "Findings".into(),
        content: "Detailed findings from the assessment.".into(),
        findings: Vec::new(),
        subsections: Vec::new(),
    };
    report.add_section(findings_section);

    let recommendations = ReportSection {
        title: "Recommendations".into(),
        content: "Prioritized recommendations for addressing the identified issues.".into(),
        findings: Vec::new(),
        subsections: Vec::new(),
    };
    report.add_section(recommendations);

    let appendix = ReportSection {
        title: "Appendix".into(),
        content: "Additional technical details, raw data, and references.".into(),
        findings: Vec::new(),
        subsections: Vec::new(),
    };
    report.add_section(appendix);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_application() {
        let mut report = SecurityReport::new("temp", "author");
        apply_template(&mut report, ReportTemplate::PenetrationTest);
        assert_eq!(report.sections.len(), 5);
        assert_eq!(report.sections[0].title, "Executive Summary");
    }
}
