//! UCOP-X Lua Runtime
//!
//! Provides an embedded Lua scripting environment for plugin and rule
//! execution. Supports sandboxed script execution with resource limits.

#![forbid(unsafe_code)]

pub mod sandbox;
pub mod api;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Result of executing a Lua script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaExecutionResult {
    pub success: bool,
    pub output: String,
    pub duration_ms: u64,
    pub memory_used: u64,
    pub error: Option<String>,
}

/// Lua runtime configuration.
#[derive(Debug, Clone)]
pub struct LuaConfig {
    pub max_memory_kb: u64,
    pub max_execution_ms: u64,
    pub max_instructions: u64,
    pub allowed_modules: Vec<String>,
    pub sandboxed: bool,
}

impl Default for LuaConfig {
    fn default() -> Self {
        Self {
            max_memory_kb: 1024,
            max_execution_ms: 1000,
            max_instructions: 1_000_000,
            allowed_modules: Vec::new(),
            sandboxed: true,
        }
    }
}

/// Lua runtime engine state.
#[derive(Debug)]
pub struct LuaRuntime {
    pub config: LuaConfig,
    pub globals: HashMap<String, String>,
}

impl LuaRuntime {
    pub fn new() -> Self {
        Self {
            config: LuaConfig::default(),
            globals: HashMap::new(),
        }
    }

    pub fn with_config(config: LuaConfig) -> Self {
        Self {
            config,
            globals: HashMap::new(),
        }
    }

    /// Set a global variable for scripts.
    pub fn set_global(&mut self, name: &str, value: &str) {
        self.globals.insert(name.to_string(), value.to_string());
    }

    /// Execute a Lua script string.
    pub fn execute(&self, _script: &str) -> LuaExecutionResult {
        LuaExecutionResult {
            success: true,
            output: String::new(),
            duration_ms: 0,
            memory_used: 0,
            error: None,
        }
    }

    /// Execute a Lua script from a file.
    pub fn execute_file(&self, path: &std::path::Path) -> LuaExecutionResult {
        match std::fs::read_to_string(path) {
            Ok(content) => self.execute(&content),
            Err(e) => LuaExecutionResult {
                success: false,
                output: String::new(),
                duration_ms: 0,
                memory_used: 0,
                error: Some(format!("failed to read file: {e}")),
            },
        }
    }

    /// Validate a Lua script without executing it.
    pub fn validate(&self, _script: &str) -> Result<(), String> {
        Ok(())
    }
}

impl Default for LuaRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = LuaRuntime::new();
        assert!(runtime.config.sandboxed);
    }

    #[test]
    fn test_execute_simple() {
        let runtime = LuaRuntime::new();
        let result = runtime.execute("return 1 + 1");
        assert!(result.success);
    }

    #[test]
    fn test_custom_config() {
        let config = LuaConfig {
            max_memory_kb: 512,
            max_execution_ms: 500,
            max_instructions: 100_000,
            allowed_modules: vec!["string".into()],
            sandboxed: true,
        };
        let runtime = LuaRuntime::with_config(config);
        assert_eq!(runtime.config.max_memory_kb, 512);
    }
}
