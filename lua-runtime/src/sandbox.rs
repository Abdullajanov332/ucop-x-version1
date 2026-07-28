//! Lua sandboxing - restricts script capabilities for security.

use crate::LuaConfig;

/// Resource usage limits for sandboxed scripts.
#[derive(Debug, Clone)]
pub struct SandboxLimits {
    pub max_memory: u64,
    pub max_instructions: u64,
    pub max_execution_ms: u64,
    pub allowed_modules: Vec<String>,
    pub blocked_functions: Vec<String>,
}

impl SandboxLimits {
    pub fn from_config(config: &LuaConfig) -> Self {
        Self {
            max_memory: config.max_memory_kb,
            max_instructions: config.max_instructions,
            max_execution_ms: config.max_execution_ms,
            allowed_modules: config.allowed_modules.clone(),
            blocked_functions: Self::default_blocked_functions(),
        }
    }

    fn default_blocked_functions() -> Vec<String> {
        vec![
            "io.open".into(),
            "os.execute".into(),
            "os.exit".into(),
            "os.rename".into(),
            "os.remove".into(),
            "os.tmpname".into(),
            "dofile".into(),
            "loadfile".into(),
            "require".into(),
        ]
    }

    /// Check if a function is allowed to be called.
    pub fn is_function_allowed(&self, function_name: &str) -> bool {
        !self.blocked_functions.contains(&function_name.to_string())
    }

    /// Check if a module is allowed to be loaded.
    pub fn is_module_allowed(&self, module_name: &str) -> bool {
        self.allowed_modules.is_empty() || self.allowed_modules.contains(&module_name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_functions() {
        let config = LuaConfig::default();
        let limits = SandboxLimits::from_config(&config);
        assert!(!limits.is_function_allowed("os.execute"));
        assert!(!limits.is_function_allowed("io.open"));
        assert!(limits.is_function_allowed("string.find"));
    }

    #[test]
    fn test_module_restrictions() {
        let config = LuaConfig {
            allowed_modules: vec!["string".into()],
            ..LuaConfig::default()
        };
        let limits = SandboxLimits::from_config(&config);
        assert!(limits.is_module_allowed("string"));
        assert!(!limits.is_module_allowed("io"));
    }
}
