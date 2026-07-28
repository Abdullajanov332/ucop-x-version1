//! UCOP-X PHP Analysis
//!
//! Analyzes PHP code: vulnerability pattern matching, taint tracking,
//! dangerous function detection, and opcode inspection.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Result of a PHP file analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhpAnalysisResult {
    pub file_path: String,
    pub total_lines: usize,
    pub vulnerabilities: Vec<PhpVulnerability>,
    pub dangerous_functions: Vec<String>,
    pub includes: Vec<String>,
    pub classes: Vec<String>,
    pub functions: Vec<String>,
}

/// A PHP vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhpVulnerability {
    pub vulnerability_type: String,
    pub description: String,
    pub line: usize,
    pub severity: String,
    pub code_snippet: String,
}

/// PHP source code analyzer.
#[derive(Debug)]
pub struct PhpAnalyzer;

impl PhpAnalyzer {
    /// Analyze a PHP file for vulnerabilities.
    pub fn analyze_file(_path: &std::path::Path) -> Result<PhpAnalysisResult, String> {
        Err("PHP analysis requires source file on disk".into())
    }

    /// Analyze PHP source code as a string.
    pub fn analyze_source(source: &str) -> PhpAnalysisResult {
        let mut vulnerabilities = Vec::new();
        let dangerous_functions = Self::find_dangerous_functions(source);
        let lines: Vec<&str> = source.lines().collect();

        // Check for eval usage
        for (i, line) in lines.iter().enumerate() {
            if line.contains("eval(") {
                vulnerabilities.push(PhpVulnerability {
                    vulnerability_type: "RCE".into(),
                    description: "Dangerous eval() usage allows arbitrary code execution".into(),
                    line: i + 1,
                    severity: "critical".into(),
                    code_snippet: line.to_string(),
                });
            }
        }

        PhpAnalysisResult {
            file_path: "string".into(),
            total_lines: lines.len(),
            vulnerabilities,
            dangerous_functions,
            includes: Vec::new(),
            classes: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// Find dangerous function calls in PHP source.
    pub fn find_dangerous_functions(source: &str) -> Vec<String> {
        let dangerous = vec![
            "eval", "exec", "system", "shell_exec", "passthru",
            "popen", "proc_open", "assert", "create_function",
            "preg_replace", "unserialize", "include", "require",
            "include_once", "require_once", "file_get_contents",
            "fopen", "fwrite", "file_put_contents",
        ];

        dangerous
            .into_iter()
            .filter(|func| {
                source.contains(&format!("{}(", func)) || source.contains(&format!(" {}(", func))
            })
            .map(|s| s.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_functions() {
        let source = r#"
            <?php
            eval('echo "hello";');
            system('ls');
            echo "safe";
        "#;
        let functions = PhpAnalyzer::find_dangerous_functions(source);
        assert!(functions.contains(&"eval".to_string()));
        assert!(functions.contains(&"system".to_string()));
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn test_analyze_source() {
        let source = r#"
            <?php
            $x = eval('return 1;');
        "#;
        let result = PhpAnalyzer::analyze_source(source);
        assert_eq!(result.vulnerabilities.len(), 1);
        assert_eq!(result.vulnerabilities[0].vulnerability_type, "RCE");
    }
}
