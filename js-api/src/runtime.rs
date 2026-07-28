//! JavaScript runtime abstraction layer.

use crate::JsConfig;

/// Available JS runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsRuntimeKind {
    Boa,
    QuickJs,
    V8,
    Deno,
}

impl JsRuntimeKind {
    pub fn name(&self) -> &'static str {
        match self {
            JsRuntimeKind::Boa => "Boa",
            JsRuntimeKind::QuickJs => "QuickJS",
            JsRuntimeKind::V8 => "V8",
            JsRuntimeKind::Deno => "Deno",
        }
    }
}

/// Capabilities available to JS code.
#[derive(Debug, Clone)]
pub struct RuntimePermissions {
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub env_vars: Vec<String>,
    pub network_allowed: bool,
}

impl RuntimePermissions {
    pub fn from_config(config: &JsConfig) -> Self {
        Self {
            read_paths: config.allow_fs_read.clone(),
            write_paths: config.allow_fs_write.clone(),
            env_vars: config.allow_env.clone(),
            network_allowed: config.allow_network,
        }
    }

    /// Check if reading a path is allowed.
    pub fn can_read(&self, path: &str) -> bool {
        self.read_paths.is_empty() || self.read_paths.iter().any(|p| path.starts_with(p))
    }

    /// Check if writing to a path is allowed.
    pub fn can_write(&self, path: &str) -> bool {
        self.write_paths.is_empty() || self.write_paths.iter().any(|p| path.starts_with(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_checks() {
        let config = JsConfig {
            allow_fs_read: vec!["/tmp".into()],
            allow_fs_write: vec!["/tmp/output".into()],
            ..JsConfig::default()
        };
        let perms = RuntimePermissions::from_config(&config);
        assert!(perms.can_read("/tmp/file.txt"));
        assert!(perms.can_write("/tmp/output/report.txt"));
        assert!(!perms.can_write("/etc/passwd"));
    }
}
