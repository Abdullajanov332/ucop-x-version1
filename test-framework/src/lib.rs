//! UCOP-X Test Framework
//!
//! Provides integration testing utilities, mock objects, test harnesses,
//! and property-based testing helpers for the platform.

#![forbid(unsafe_code)]

pub mod harness;
pub mod mock;
pub mod assertions;

use std::collections::HashMap;

/// Test case result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestResult {
    Passed,
    Failed(String),
    Skipped(String),
    Error(String),
}

impl TestResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, TestResult::Passed)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, TestResult::Failed(_) | TestResult::Error(_))
    }
}

/// A single test case.
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub module: String,
    pub description: String,
    pub category: String,
    pub timeout_secs: u64,
    pub tags: Vec<String>,
}

/// Complete test suite result.
#[derive(Debug, Clone)]
pub struct TestSuiteResult {
    pub suite_name: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errored: usize,
    pub duration_secs: f64,
    pub results: Vec<(TestCase, TestResult)>,
    pub coverage_pct: f64,
}

/// Property-based testing configuration.
#[derive(Debug, Clone)]
pub struct PropertyConfig {
    pub min_cases: u64,
    pub max_cases: u64,
    pub seed: Option<u64>,
    pub max_shrink_attempts: u64,
}

impl Default for PropertyConfig {
    fn default() -> Self {
        Self {
            min_cases: 100,
            max_cases: 10_000,
            seed: None,
            max_shrink_attempts: 100,
        }
    }
}

/// Test framework orchestrator.
#[derive(Debug, Default)]
pub struct TestFramework {
    pub suites: Vec<String>,
}

impl TestFramework {
    pub fn new() -> Self {
        Self { suites: Vec::new() }
    }

    /// Register a test suite.
    pub fn register_suite(&mut self, name: &str) {
        self.suites.push(name.to_string());
    }

    /// Run all registered test suites (simulated).
    pub fn run_all(&self) -> Vec<TestSuiteResult> {
        self.suites
            .iter()
            .map(|name| TestSuiteResult {
                suite_name: name.clone(),
                total: 0,
                passed: 0,
                failed: 0,
                skipped: 0,
                errored: 0,
                duration_secs: 0.0,
                results: Vec::new(),
                coverage_pct: 0.0,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_states() {
        assert!(TestResult::Passed.is_pass());
        assert!(TestResult::Failed("err".into()).is_fail());
        assert!(!TestResult::Skipped("reason".into()).is_fail());
    }

    #[test]
    fn test_framework_registration() {
        let mut framework = TestFramework::new();
        framework.register_suite("kernel-tests");
        framework.register_suite("crypto-tests");
        assert_eq!(framework.suites.len(), 2);
    }
}
