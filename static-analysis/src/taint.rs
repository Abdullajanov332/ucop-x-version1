//! Taint tracking engine for static analysis.
//!
//! Tracks the flow of untrusted data through a program to detect
//! security vulnerabilities such as injection flaws.

use std::collections::HashSet;

/// Source of tainted data.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TaintSource {
    UserInput,
    FileRead,
    NetworkRead,
    EnvironmentVariable,
    DatabaseQuery,
}

/// A taint label attached to a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintLabel {
    pub sources: HashSet<TaintSource>,
    pub sanitized: bool,
}

impl TaintLabel {
    pub fn new(source: TaintSource) -> Self {
        let mut sources = HashSet::new();
        sources.insert(source);
        Self {
            sources,
            sanitized: false,
        }
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut sources = self.sources.clone();
        sources.extend(&other.sources);
        Self {
            sources,
            sanitized: self.sanitized && other.sanitized,
        }
    }

    /// Mark this taint label as sanitized.
    pub fn sanitize(&mut self) {
        self.sanitized = true;
    }
}

/// Taint tracking state for a variable.
#[derive(Debug, Clone)]
pub struct TaintState {
    pub variable: String,
    pub label: Option<TaintLabel>,
}

/// Simple taint tracker that logs taint flows.
#[derive(Debug, Default)]
pub struct TaintTracker {
    pub states: Vec<TaintState>,
}

impl TaintTracker {
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }

    /// Mark a variable as tainted from a source.
    pub fn taint(&mut self, variable: &str, source: TaintSource) {
        self.states.push(TaintState {
            variable: variable.to_string(),
            label: Some(TaintLabel::new(source)),
        });
    }

    /// Check if a variable is tainted.
    pub fn is_tainted(&self, variable: &str) -> bool {
        self.states
            .iter()
            .any(|s| s.variable == variable && s.label.as_ref().map_or(false, |l| !l.sanitized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_propagation() {
        let mut tracker = TaintTracker::new();
        tracker.taint("user_input", TaintSource::UserInput);
        assert!(tracker.is_tainted("user_input"));
        assert!(!tracker.is_tainted("safe_var"));
    }

    #[test]
    fn test_taint_sanitize() {
        let mut label = TaintLabel::new(TaintSource::UserInput);
        assert!(!label.sanitized);
        label.sanitize();
        assert!(label.sanitized);
    }

    #[test]
    fn test_taint_merge() {
        let a = TaintLabel::new(TaintSource::UserInput);
        let b = TaintLabel::new(TaintSource::DatabaseQuery);
        let merged = a.merge(&b);
        assert_eq!(merged.sources.len(), 2);
    }
}
