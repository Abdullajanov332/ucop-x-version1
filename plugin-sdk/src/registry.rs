//! Plugin registry for discovering and indexing plugins.

use crate::{PluginDescriptor, PluginManifest};

/// Plugin registry for storing and retrieving plugin metadata.
#[derive(Debug, Default)]
pub struct PluginRegistry {
    pub(crate) known_plugins: Vec<PluginDescriptor>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            known_plugins: Vec::new(),
        }
    }

    /// Index a plugin descriptor.
    pub fn index(&mut self, descriptor: PluginDescriptor) {
        if !self.known_plugins.iter().any(|p| p.id == descriptor.id) {
            self.known_plugins.push(descriptor);
        }
    }

    /// Search plugins by name or capability.
    pub fn search(&self, query: &str) -> Vec<&PluginDescriptor> {
        let q = query.to_lowercase();
        self.known_plugins
            .iter()
            .filter(|p| {
                p.manifest.name.to_lowercase().contains(&q)
                    || p.manifest.description.to_lowercase().contains(&q)
                    || p.manifest.capabilities.iter().any(|c| c.contains(&q))
            })
            .collect()
    }

    /// Get all plugins with a given capability.
    pub fn by_capability(&self, capability: &str) -> Vec<&PluginDescriptor> {
        self.known_plugins
            .iter()
            .filter(|p| p.manifest.capabilities.iter().any(|c| c == capability))
            .collect()
    }

    /// Count registered plugins.
    pub fn count(&self) -> usize {
        self.known_plugins.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_index_and_search() {
        let mut registry = PluginRegistry::new();
        let descriptor = PluginDescriptor {
            id: "p1".into(),
            manifest: PluginManifest {
                name: "scanner".into(),
                version: "1.0".into(),
                author: "dev".into(),
                description: "A scanner plugin".into(),
                capabilities: vec!["scanning".into()],
                dependencies: vec![],
                min_kernel_version: "0.1.0".into(),
                entry_point: "lib".into(),
            },
            state: crate::PluginState::Discovered,
            loaded_at: None,
            config: std::collections::HashMap::new(),
        };
        registry.index(descriptor);
        assert_eq!(registry.search("scanner").len(), 1);
        assert_eq!(registry.search("scanning").len(), 1);
    }
}
