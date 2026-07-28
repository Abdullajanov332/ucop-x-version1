//! Mock objects and test doubles.

use std::collections::HashMap;

/// A recorded method call on a mock object.
#[derive(Debug, Clone)]
pub struct MockCall {
    pub method: String,
    pub args: Vec<String>,
    pub timestamp: std::time::Instant,
}

/// Generic mock object that records all calls.
#[derive(Debug, Default)]
pub struct Mock {
    pub expected_calls: HashMap<String, usize>,
    pub actual_calls: Vec<MockCall>,
    pub return_values: HashMap<String, String>,
}

impl Mock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an expected call count for a method.
    pub fn expect_call(&mut self, method: &str, count: usize) {
        self.expected_calls
            .insert(method.to_string(), count);
    }

    /// Set a return value for a method.
    pub fn return_value(&mut self, method: &str, value: &str) {
        self.return_values
            .insert(method.to_string(), value.to_string());
    }

    /// Record a method call and return the configured value.
    pub fn call(&mut self, method: &str, args: Vec<String>) -> Option<&String> {
        self.actual_calls.push(MockCall {
            method: method.to_string(),
            args,
            timestamp: std::time::Instant::now(),
        });
        self.return_values.get(method)
    }

    /// Verify that all expectations were met.
    pub fn verify(&self) -> Result<(), String> {
        for (method, expected_count) in &self.expected_calls {
            let actual_count = self
                .actual_calls
                .iter()
                .filter(|c| c.method == *method)
                .count();
            if actual_count != *expected_count {
                return Err(format!(
                    "method {method}: expected {expected_count} calls, got {actual_count}"
                ));
            }
        }
        Ok(())
    }

    /// Count calls to a specific method.
    pub fn call_count(&self, method: &str) -> usize {
        self.actual_calls
            .iter()
            .filter(|c| c.method == method)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_call_recording() {
        let mut mock = Mock::new();
        mock.call("read", vec!["file.txt".into()]);
        mock.call("write", vec!["file.txt".into(), "data".into()]);
        assert_eq!(mock.call_count("read"), 1);
        assert_eq!(mock.call_count("write"), 1);
        assert_eq!(mock.call_count("delete"), 0);
    }

    #[test]
    fn test_mock_verification() {
        let mut mock = Mock::new();
        mock.expect_call("process", 2);
        mock.call("process", vec!["a".into()]);
        mock.call("process", vec!["b".into()]);
        assert!(mock.verify().is_ok());
    }

    #[test]
    fn test_mock_verification_failure() {
        let mut mock = Mock::new();
        mock.expect_call("process", 3);
        mock.call("process", vec!["a".into()]);
        assert!(mock.verify().is_err());
    }
}
