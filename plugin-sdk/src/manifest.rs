//! Plugin manifest parsing and validation.

use crate::PluginManifest;

/// Parse a plugin manifest from TOML content.
pub fn parse_manifest(toml_content: &str) -> Result<PluginManifest, String> {
    toml::from_str(toml_content).map_err(|e| format!("invalid manifest: {e}"))
}

/// Validate a plugin manifest for required fields.
pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), String> {
    if manifest.name.is_empty() {
        return Err("plugin name is required".into());
    }
    if manifest.version.is_empty() {
        return Err("plugin version is required".into());
    }
    if manifest.entry_point.is_empty() {
        return Err("plugin entry point is required".into());
    }
    if manifest.capabilities.is_empty() {
        return Err("at least one capability is required".into());
    }
    Ok(())
}

/// Generate a default manifest template.
pub fn default_manifest(name: &str, version: &str) -> PluginManifest {
    PluginManifest {
        name: name.to_string(),
        version: version.to_string(),
        author: "UCOP-X Developer".into(),
        description: format!("Plugin: {name}"),
        capabilities: vec!["analysis".into()],
        dependencies: Vec::new(),
        min_kernel_version: "0.1.0".into(),
        entry_point: format!("lib{name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_empty_name() {
        let mut manifest = default_manifest("test", "1.0");
        manifest.name.clear();
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn test_validation_empty_capabilities() {
        let mut manifest = default_manifest("test", "1.0");
        manifest.capabilities.clear();
        assert!(validate_manifest(&manifest).is_err());
    }
}
