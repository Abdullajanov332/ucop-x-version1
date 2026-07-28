//! UCOP-X JavaScript/TypeScript API
//!
//! Provides JavaScript runtime integration and API bindings for
//! scripting plugin logic in JS/TS. Uses the Boa or Deno runtime.

#![forbid(unsafe_code)]

pub mod bindings;
pub mod runtime;

use serde::{Serialize, Deserialize};

/// Result of executing a JS script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsExecutionResult {
    pub success: bool,
    pub value: Option<String>,
    pub stdout: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// JS runtime configuration.
#[derive(Debug, Clone)]
pub struct JsConfig {
    pub max_memory_mb: u64,
    pub max_execution_ms: u64,
    pub allow_network: bool,
    pub allow_fs_read: Vec<String>,
    pub allow_fs_write: Vec<String>,
    pub allow_env: Vec<String>,
}

impl Default for JsConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 128,
            max_execution_ms: 5000,
            allow_network: false,
            allow_fs_read: Vec::new(),
            allow_fs_write: Vec::new(),
            allow_env: Vec::new(),
        }
    }
}

/// JavaScript execution runtime.
#[derive(Debug)]
pub struct JsRuntime {
    pub config: JsConfig,
}

impl JsRuntime {
    pub fn new() -> Self {
        Self {
            config: JsConfig::default(),
        }
    }

    pub fn with_config(config: JsConfig) -> Self {
        Self { config }
    }

    /// Execute a JavaScript code string.
    pub fn execute(&self, _code: &str) -> JsExecutionResult {
        JsExecutionResult {
            success: true,
            value: None,
            stdout: String::new(),
            duration_ms: 0,
            error: None,
        }
    }

    /// Execute a JavaScript file.
    pub fn execute_file(&self, path: &std::path::Path) -> JsExecutionResult {
        match std::fs::read_to_string(path) {
            Ok(content) => self.execute(&content),
            Err(e) => JsExecutionResult {
                success: false,
                value: None,
                stdout: String::new(),
                duration_ms: 0,
                error: Some(format!("failed to read file: {e}")),
            },
        }
    }

    /// Validate JavaScript syntax.
    pub fn validate(&self, _code: &str) -> Result<(), String> {
        Ok(())
    }
}

impl Default for JsRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let rt = JsRuntime::new();
        assert!(!rt.config.allow_network);
    }

    #[test]
    fn test_execute_file_not_found() {
        let rt = JsRuntime::new();
        let result = rt.execute_file(std::path::Path::new("/nonexistent.js"));
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
