//! Built-in analysis rules for static code analysis.

use crate::Finding;

/// A single analysis rule.
#[derive(Debug, Clone)]
pub struct AnalysisRule {
    /// Unique rule identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Severity level.
    pub severity: String,
    /// Description of what the rule checks.
    pub description: String,
    /// Remediation advice.
    pub remediation: Option<String>,
    /// Patterns to search for.
    pub patterns: Vec<String>,
}

impl AnalysisRule {
    /// Check source content against this rule.
    pub fn check(&self, content: &str) -> Option<Vec<Finding>> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.patterns {
                if line.contains(pattern) {
                    findings.push(Finding {
                        id: format!("{}-{}", self.id, findings.len() + 1),
                        rule_id: self.id.clone(),
                        severity: self.severity.clone(),
                        file: String::new(),
                        line: (line_num + 1) as u32,
                        column: 0,
                        description: self.description.clone(),
                        remediation: self.remediation.clone(),
                        snippet: Some(line.trim().to_string()),
                    });
                }
            }
        }

        if findings.is_empty() {
            None
        } else {
            Some(findings)
        }
    }
}

/// Create the default set of analysis rules.
pub fn default_rules() -> Vec<AnalysisRule> {
    vec![
        AnalysisRule {
            id: "SEC-HARDCODED-PASSWORD".into(),
            name: "Hardcoded Password".into(),
            severity: "high".into(),
            description: "Hardcoded password detected in source code.".into(),
            remediation: Some("Use a secret manager or environment variables.".into()),
            patterns: vec!["password = \"".into(), "passwd = \"".into(), "pwd = \"".into()],
        },
        AnalysisRule {
            id: "SEC-HARDCODED-KEY".into(),
            name: "Hardcoded Cryptographic Key".into(),
            severity: "critical".into(),
            description: "Hardcoded cryptographic key or API secret detected.".into(),
            remediation: Some("Use a key management service or environment variables.".into()),
            patterns: vec![
                "api_key = \"".into(),
                "secret_key = \"".into(),
                "private_key = \"".into(),
                "token = \"".into(),
            ],
        },
        AnalysisRule {
            id: "SEC-SQL-INJECTION".into(),
            name: "Potential SQL Injection".into(),
            severity: "high".into(),
            description: "String concatenation in SQL query detected.".into(),
            remediation: Some("Use parameterized queries or prepared statements.".into()),
            patterns: vec!["SELECT * FROM ".into(), "WHERE ".into()],
        },
        AnalysisRule {
            id: "SEC-COMMAND-INJECTION".into(),
            name: "Potential Command Injection".into(),
            severity: "high".into(),
            description: "Shell command execution detected with string concatenation.".into(),
            remediation: Some("Avoid passing user input directly to shell commands.".into()),
            patterns: vec!["std::process::Command".into(), "os.system".into()],
        },
        AnalysisRule {
            id: "SEC-PATH-TRAVERSAL".into(),
            name: "Potential Path Traversal".into(),
            severity: "medium".into(),
            description: "User-controlled path concatenation detected.".into(),
            remediation: Some("Use path sanitization and validate user input.".into()),
            patterns: vec!["../".into(), "..\\".into()],
        },
        AnalysisRule {
            id: "QUAL-UNSAFE".into(),
            name: "Unsafe Code Block".into(),
            severity: "medium".into(),
            description: "Unsafe code block detected.".into(),
            remediation: Some(
                "Minimize unsafe blocks and verify memory safety invariants.".into(),
            ),
            patterns: vec!["unsafe {".into(), "unsafe{".into()],
        },
        AnalysisRule {
            id: "QUAL-TODO".into(),
            name: "TODO Comment".into(),
            severity: "info".into(),
            description: "TODO comment found in code.".into(),
            remediation: Some("Address the TODO before production release.".into()),
            patterns: vec!["TODO".into(), "FIXME".into(), "HACK".into(), "XXX".into()],
        },
        AnalysisRule {
            id: "SEC-HTTP-INSECURE".into(),
            name: "Insecure HTTP Usage".into(),
            severity: "medium".into(),
            description: "Plain HTTP usage detected instead of HTTPS.".into(),
            remediation: Some("Use HTTPS instead of HTTP for secure communication.".into()),
            patterns: vec!["http://".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_rule() {
        let rule = AnalysisRule {
            id: "TEST".into(),
            name: "Test".into(),
            severity: "high".into(),
            description: "Test rule".into(),
            remediation: None,
            patterns: vec!["password = \"".into()],
        };

        let content = r#"let password = "secret123";"#;
        let findings = rule.check(content);
        assert!(findings.is_some());
        assert_eq!(findings.unwrap().len(), 1);
    }

    #[test]
    fn test_no_false_positive() {
        let rule = AnalysisRule {
            id: "TEST".into(),
            name: "Test".into(),
            severity: "info".into(),
            description: "Safe code".into(),
            remediation: None,
            patterns: vec!["password = \"".into()],
        };

        let content = r#"let x = 42;"#;
        assert!(rule.check(content).is_none());
    }
}
