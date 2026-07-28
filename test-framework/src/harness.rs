//! Test harness utilities for integration testing.

use crate::TestResult;

/// Configuration for a test harness.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub timeout_secs: u64,
    pub cleanup_on_fail: bool,
    pub log_output: bool,
    pub env_vars: std::collections::HashMap<String, String>,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            cleanup_on_fail: true,
            log_output: true,
            env_vars: std::collections::HashMap::new(),
        }
    }
}

/// A test harness for running integration tests.
#[derive(Debug)]
pub struct TestHarness {
    pub name: String,
    pub config: HarnessConfig,
}

impl TestHarness {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            config: HarnessConfig::default(),
        }
    }

    pub fn with_config(name: &str, config: HarnessConfig) -> Self {
        Self {
            name: name.to_string(),
            config,
        }
    }

    /// Run a test function within the harness.
    pub fn run<F>(&self, test_name: &str, f: F) -> TestResult
    where
        F: FnOnce() -> Result<(), String>,
    {
        match f() {
            Ok(_) => TestResult::Passed,
            Err(e) => TestResult::Failed(e),
        }
    }

    /// Assert that two values are equal.
    pub fn assert_eq<T: PartialEq + std::fmt::Debug>(&self, left: T, right: T) -> Result<(), String> {
        if left == right {
            Ok(())
        } else {
            Err(format!("assertion failed: {:?} != {:?}", left, right))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_basic_run() {
        let harness = TestHarness::new("test");
        let result = harness.run("passing", || Ok(()));
        assert_eq!(result, TestResult::Passed);

        let result = harness.run("failing", || Err("error".into()));
        assert!(result.is_fail());
    }

    #[test]
    fn test_harness_assertions() {
        let harness = TestHarness::new("assert-test");
        assert!(harness.assert_eq(1, 1).is_ok());
        assert!(harness.assert_eq(1, 2).is_err());
    }
}
