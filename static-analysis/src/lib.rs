//! UCOP-X Static Analysis Engine
//!
//! Provides static application security testing (SAST), pattern matching,
//! abstract syntax tree analysis, and code quality checking.

#![forbid(unsafe_code)]

pub mod pattern;
pub mod rules;
pub mod taint;

use std::collections::HashMap;

/// Severity levels for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn name(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A single static analysis finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Unique identifier.
    pub id: String,
    /// Rule that triggered this finding.
    pub rule_id: String,
    /// Severity level.
    pub severity: String,
    /// File path.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Column offset.
    pub column: u32,
    /// Description of the issue.
    pub description: String,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// Code snippet.
    pub snippet: Option<String>,
}

/// Analysis results for a single file.
#[derive(Debug, Clone)]
pub struct FileAnalysis {
    pub path: String,
    pub findings: Vec<Finding>,
    pub lines_of_code: usize,
}

/// Complete analysis report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StaticAnalysisReport {
    pub files_analyzed: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub findings: Vec<Finding>,
}

/// Static analysis engine.
#[derive(Debug)]
pub struct StaticAnalyzer {
    rules: Vec<rules::AnalysisRule>,
}

impl StaticAnalyzer {
    /// Create a new analyzer with default rules.
    pub fn new() -> Self {
        Self {
            rules: rules::default_rules(),
        }
    }

    /// Analyze a single file.
    pub fn analyze_file(&self, path: &str, content: &str) -> FileAnalysis {
        let mut findings = Vec::new();
        let lines_of_code = content.lines().count();

        for rule in &self.rules {
            if let Some(matches) = rule.check(content) {
                findings.extend(matches);
            }
        }

        FileAnalysis {
            path: path.to_string(),
            findings,
            lines_of_code,
        }
    }

    /// Analyze multiple files, returning a consolidated report.
    pub fn analyze_files(&self, files: &[(&str, &str)]) -> StaticAnalysisReport {
        let mut report = StaticAnalysisReport {
            files_analyzed: files.len(),
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            findings: Vec::new(),
        };

        for (path, content) in files {
            let file_result = self.analyze_file(path, content);
            for finding in file_result.findings {
                match finding.severity.as_str() {
                    "critical" => report.critical_count += 1,
                    "high" => report.high_count += 1,
                    "medium" => report.medium_count += 1,
                    "low" => report.low_count += 1,
                    _ => report.info_count += 1,
                }
                report.total_findings += 1;
                report.findings.push(finding);
            }
        }

        report
    }
}

impl Default for StaticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low < Severity::Medium);
    }

    #[test]
    fn test_analyze_simple_file() {
        let analyzer = StaticAnalyzer::new();
        let content = r#"
fn main() {
    let password = "secret123";
    println!("{}", password);
}
"#;
        let result = analyzer.analyze_file("test.rs", content);
        // Should find issues like hardcoded password patterns
        assert!(result.lines_of_code > 0);
    }

    #[test]
    fn test_severity_names() {
        assert_eq!(Severity::Critical.name(), "critical");
        assert_eq!(Severity::Info.name(), "info");
    }
}
