//! UCOP-X Plugin SDK
//!
//! Provides the framework for extending UCOP-X with plugins. Plugins are
//! dynamically loaded libraries that register capabilities with the kernel.

#![forbid(unsafe_code)]

pub mod manifest;
pub mod registry;
pub mod lifecycle;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Plugin capability types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Analysis,
    Scanning,
    Reporting,
    Monitoring,
    ThreatIntel,
    Forensics,
    Crypto,
    Networking,
    Storage,
    Ui,
}

/// Plugin metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub dependencies: Vec<String>,
    pub min_kernel_version: String,
    pub entry_point: String,
}

/// Plugin descriptor as registered with the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDescriptor {
    pub id: String,
    pub manifest: PluginManifest,
    pub state: PluginState,
    pub loaded_at: Option<String>,
    pub config: HashMap<String, String>,
}

/// Plugin lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginState {
    Discovered,
    Loaded,
    Running,
    Stopped,
    Error(String),
}

/// Plugin SDK core.
#[derive(Debug, Default)]
pub struct PluginSdk {
    pub plugins: HashMap<String, PluginDescriptor>,
}

impl PluginSdk {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin from its manifest.
    pub fn register(&mut self, manifest: PluginManifest) -> Result<String, String> {
        let id = format!("{}-{}", manifest.name, manifest.version);
        if self.plugins.contains_key(&id) {
            return Err(format!("plugin already registered: {id}"));
        }

        let descriptor = PluginDescriptor {
            id: id.clone(),
            manifest,
            state: PluginState::Discovered,
            loaded_at: None,
            config: HashMap::new(),
        };

        self.plugins.insert(id.clone(), descriptor);
        Ok(id)
    }

    /// Load a registered plugin.
    pub fn load(&mut self, plugin_id: &str) -> Result<(), String> {
        let plugin = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| format!("plugin not found: {plugin_id}"))?;

        if plugin.state != PluginState::Discovered {
            return Err(format!("plugin {plugin_id} is in state {:?}, expected Discovered", plugin.state));
        }

        plugin.state = PluginState::Loaded;
        plugin.loaded_at = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    /// Start a loaded plugin.
    pub fn start(&mut self, plugin_id: &str) -> Result<(), String> {
        let plugin = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| format!("plugin not found: {plugin_id}"))?;

        if plugin.state != PluginState::Loaded {
            return Err(format!("plugin {plugin_id} is in state {:?}, expected Loaded", plugin.state));
        }

        plugin.state = PluginState::Running;
        Ok(())
    }

    /// Stop a running plugin.
    pub fn stop(&mut self, plugin_id: &str) -> Result<(), String> {
        let plugin = self
            .plugins
            .get_mut(plugin_id)
            .ok_or_else(|| format!("plugin not found: {plugin_id}"))?;

        plugin.state = PluginState::Stopped;
        Ok(())
    }

    /// Find plugins by capability.
    pub fn with_capability(&self, capability: &str) -> Vec<&PluginDescriptor> {
        self.plugins
            .values()
            .filter(|p| p.manifest.capabilities.iter().any(|c| c == capability))
            .collect()
    }

    /// Get all running plugins.
    pub fn running(&self) -> Vec<&PluginDescriptor> {
        self.plugins
            .values()
            .filter(|p| p.state == PluginState::Running)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_lifecycle() {
        let mut sdk = PluginSdk::new();
        let manifest = PluginManifest {
            name: "test-plugin".into(),
            version: "1.0.0".into(),
            author: "developer".into(),
            description: "Test".into(),
            capabilities: vec!["analysis".into()],
            dependencies: vec![],
            min_kernel_version: "0.1.0".into(),
            entry_point: "lib".into(),
        };

        let id = sdk.register(manifest).unwrap();
        assert!(sdk.plugins.contains_key(&id));

        sdk.load(&id).unwrap();
        assert_eq!(sdk.plugins[&id].state, PluginState::Loaded);

        sdk.start(&id).unwrap();
        assert_eq!(sdk.plugins[&id].state, PluginState::Running);

        sdk.stop(&id).unwrap();
        assert_eq!(sdk.plugins[&id].state, PluginState::Stopped);
    }

    #[test]
    fn test_capability_filter() {
        let mut sdk = PluginSdk::new();
        let manifest = PluginManifest {
            name: "p1".into(),
            version: "1.0".into(),
            author: "a".into(),
            description: "".into(),
            capabilities: vec!["scanning".into()],
            dependencies: vec![],
            min_kernel_version: "0.1.0".into(),
            entry_point: "lib".into(),
        };
        sdk.register(manifest).unwrap();
        assert_eq!(sdk.with_capability("scanning").len(), 1);
        assert_eq!(sdk.with_capability("analysis").len(), 0);
    }
}
