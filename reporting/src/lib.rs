//! UCOP-X Reporting Engine
//!
//! Generates structured security reports in multiple formats (PDF, HTML,
//! Markdown, JSON). Supports templating and data-driven report generation.

#![forbid(unsafe_code)]

pub mod template;
pub mod format;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Supported report formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Markdown,
    Html,
    Json,
    Yaml,
    Plain,
}

impl ReportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
            ReportFormat::Json => "json",
            ReportFormat::Yaml => "yaml",
            ReportFormat::Plain => "txt",
        }
    }
}

/// A report section containing findings and data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub content: String,
    pub findings: Vec<ReportFinding>,
    pub subsections: Vec<ReportSection>,
}

/// A single report finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub affected_assets: Vec<String>,
    pub remediation: String,
    pub references: Vec<String>,
}

/// Complete security report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub title: String,
    pub report_id: String,
    pub created: String,
    pub version: String,
    pub author: String,
    pub summary: String,
    pub sections: Vec<ReportSection>,
    pub metadata: HashMap<String, String>,
}

impl SecurityReport {
    /// Create a new empty report.
    pub fn new(title: &str, author: &str) -> Self {
        Self {
            title: title.to_string(),
            report_id: uuid::Uuid::new_v4().to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").into(),
            author: author.to_string(),
            summary: String::new(),
            sections: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a section to the report.
    pub fn add_section(&mut self, section: ReportSection) {
        self.sections.push(section);
    }

    /// Render the report to a format.
    pub fn render(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            ReportFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
            ReportFormat::Markdown => self.render_markdown(),
            ReportFormat::Plain => self.render_plain(),
            ReportFormat::Html => self.render_html(),
        }
    }

    fn render_markdown(&self) -> String {
        let mut md = format!("# {}\n\n", self.title);
        md.push_str(&format!("**Report ID:** {}  \n", self.report_id));
        md.push_str(&format!("**Date:** {}  \n", self.created));
        md.push_str(&format!("**Author:** {}  \n", self.author));
        md.push_str(&format!("**Version:** {}  \n\n", self.version));

        if !self.summary.is_empty() {
            md.push_str("## Executive Summary\n\n");
            md.push_str(&self.summary);
            md.push_str("\n\n");
        }

        for section in &self.sections {
            md.push_str(&format!("## {}\n\n", section.title));
            if !section.content.is_empty() {
                md.push_str(&section.content);
                md.push_str("\n\n");
            }
            for finding in &section.findings {
                md.push_str(&format!("### {} [{}]\n\n", finding.title, finding.severity.to_uppercase()));
                md.push_str(&format!("**Description:** {}\n\n", finding.description));
                md.push_str(&format!("**Remediation:** {}\n\n", finding.remediation));
            }
        }

        md
    }

    fn render_plain(&self) -> String {
        let mut out = format!("=== {} ===\n\n", self.title);
        out.push_str(&format!("ID: {}\nDate: {}\nAuthor: {}\n\n", self.report_id, self.created, self.author));
        for section in &self.sections {
            out.push_str(&format!("--- {} ---\n\n", section.title));
            if !section.content.is_empty() {
                out.push_str(&section.content);
                out.push_str("\n\n");
            }
            for finding in &section.findings {
                out.push_str(&format!("[{}] {}: {}\n", finding.severity.to_uppercase(), finding.title, finding.description));
                out.push_str(&format!("  -> Remediation: {}\n\n", finding.remediation));
            }
        }
        out
    }

    fn render_html(&self) -> String {
        let mut html = format!(
            "<!DOCTYPE html><html><head><title>{}</title>",
            self.title
        );
        html.push_str("<style>body{font-family:sans-serif;margin:2em}</style>");
        html.push_str("</head><body>");
        html.push_str(&format!("<h1>{}</h1>", self.title));
        html.push_str(&format!("<p><strong>ID:</strong> {}<br><strong>Date:</strong> {}</p>", self.report_id, self.created));

        for section in &self.sections {
            html.push_str(&format!("<h2>{}</h2>", section.title));
            html.push_str(&format!("<p>{}</p>", section.content));
            for finding in &section.findings {
                let color = match finding.severity.as_str() {
                    "critical" => "red",
                    "high" => "orange",
                    "medium" => "gold",
                    _ => "gray",
                };
                html.push_str(&format!(
                    "<div style='border-left:4px solid {color};padding:8px;margin:8px 0'>\
                     <h3>{} <span style='color:{color}'>({})</span></h3>\
                     <p>{}</p></div>",
                    finding.title, finding.severity.to_uppercase(), finding.description
                ));
            }
        }

        html.push_str("</body></html>");
        html
    }
}

/// Reporting engine.
#[derive(Debug, Default)]
pub struct ReportEngine {
    pub reports: Vec<SecurityReport>,
}

impl ReportEngine {
    pub fn new() -> Self {
        Self { reports: Vec::new() }
    }

    /// Generate a new report from findings.
    pub fn generate(&mut self, title: &str, author: &str, findings: Vec<ReportFinding>) -> SecurityReport {
        let mut report = SecurityReport::new(title, author);

        // Group findings by severity for section organization
        let mut by_severity: HashMap<String, Vec<ReportFinding>> = HashMap::new();
        for finding in findings {
            by_severity.entry(finding.severity.clone()).or_default().push(finding);
        }

        for (severity, mut findings) in by_severity {
            findings.sort_by(|a, b| b.severity.cmp(&a.severity));
            let section = ReportSection {
                title: format!("{} Severity Findings", severity.to_uppercase()),
                content: String::new(),
                findings,
                subsections: Vec::new(),
            };
            report.add_section(section);
        }

        report.summary = format!("Report contains {} sections with findings.", report.sections.len());
        self.reports.push(report.clone());
        report
    }

    /// Export a report to a file.
    pub fn export(&self, report_id: &str, format: ReportFormat, path: &std::path::Path) -> Result<(), String> {
        let report = self
            .reports
            .iter()
            .find(|r| r.report_id == report_id)
            .ok_or_else(|| "report not found".to_string())?;

        let content = report.render(format);
        std::fs::write(path, content).map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_generation() {
        let mut engine = ReportEngine::new();
        let findings = vec![
            ReportFinding {
                id: "F-001".into(),
                title: "Open Port".into(),
                severity: "high".into(),
                description: "Port 22 exposed".into(),
                affected_assets: vec!["server-01".into()],
                remediation: "Restrict access".into(),
                references: vec![],
            },
        ];
        let report = engine.generate("Security Scan", "analyst", findings);
        assert_eq!(report.sections.len(), 1);
        assert!(!report.report_id.is_empty());
    }

    #[test]
    fn test_render_json() {
        let report = SecurityReport::new("Test", "author");
        let json = report.render(ReportFormat::Json);
        assert!(json.contains("Test"));
    }

    #[test]
    fn test_render_markdown() {
        let report = SecurityReport::new("Test", "author");
        let md = report.render(ReportFormat::Markdown);
        assert!(md.contains("# Test"));
    }
}
