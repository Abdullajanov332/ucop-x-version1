//! Pattern matching utilities for static analysis.

/// A pattern that can match against source code lines.
#[derive(Debug, Clone)]
pub struct CodePattern {
    /// Human-readable name.
    pub name: String,
    /// Pattern to search for (substring match).
    pub pattern: String,
    /// Whether to use case-insensitive matching.
    pub case_insensitive: bool,
}

impl CodePattern {
    /// Check if a line matches this pattern.
    pub fn matches(&self, line: &str) -> bool {
        if self.case_insensitive {
            line.to_lowercase().contains(&self.pattern.to_lowercase())
        } else {
            line.contains(&self.pattern)
        }
    }
}

/// Compile a list of simple patterns.
pub fn compile_patterns(patterns: &[(&str, &str, bool)]) -> Vec<CodePattern> {
    patterns
        .iter()
        .map(|(name, pattern, ci)| CodePattern {
            name: name.to_string(),
            pattern: pattern.to_string(),
            case_insensitive: *ci,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_match() {
        let p = CodePattern {
            name: "test".into(),
            pattern: "TODO".into(),
            case_insensitive: false,
        };
        assert!(p.matches("// TODO: fix this"));
        assert!(!p.matches("// todo: fix this"));
    }

    #[test]
    fn test_case_insensitive() {
        let p = CodePattern {
            name: "test".into(),
            pattern: "password".into(),
            case_insensitive: true,
        };
        assert!(p.matches("let PASSWORD = \"secret\";"));
        assert!(p.matches("let password = \"secret\";"));
    }
}
