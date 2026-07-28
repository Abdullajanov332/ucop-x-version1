//! UCOP-X Asset Inventory
//!
//! Manages hardware assets, software inventory, network devices,
//! and their relationships across the enterprise.

#![forbid(unsafe_code)]

pub mod discovery;

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Asset category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetCategory {
    Workstation,
    Server,
    NetworkDevice,
    Firewall,
    Database,
    Storage,
    MobileDevice,
    IoT,
    CloudInstance,
    Container,
    Application,
    Other,
}

impl AssetCategory {
    pub fn name(&self) -> &'static str {
        match self {
            AssetCategory::Workstation => "workstation",
            AssetCategory::Server => "server",
            AssetCategory::NetworkDevice => "network-device",
            AssetCategory::Firewall => "firewall",
            AssetCategory::Database => "database",
            AssetCategory::Storage => "storage",
            AssetCategory::MobileDevice => "mobile-device",
            AssetCategory::IoT => "iot",
            AssetCategory::CloudInstance => "cloud-instance",
            AssetCategory::Container => "container",
            AssetCategory::Application => "application",
            AssetCategory::Other => "other",
        }
    }
}

/// An asset in the inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub category: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub software: Vec<SoftwareItem>,
    pub open_ports: Vec<u16>,
    pub tags: Vec<String>,
    pub location: Option<String>,
    pub department: Option<String>,
    pub owner: Option<String>,
    pub notes: String,
    pub discovered: String,
    pub last_seen: String,
}

/// A software item installed on an asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareItem {
    pub name: String,
    pub version: String,
    pub vendor: String,
    pub install_date: Option<String>,
}

/// Asset inventory engine.
#[derive(Debug, Default)]
pub struct AssetInventory {
    pub assets: HashMap<String, Asset>,
}

impl AssetInventory {
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }

    /// Register a new asset.
    pub fn register(&mut self, asset: Asset) -> String {
        let id = if asset.id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            asset.id.clone()
        };
        self.assets.insert(id.clone(), asset);
        id
    }

    /// Find assets by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&Asset> {
        self.assets
            .values()
            .filter(|a| a.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Find assets by category.
    pub fn by_category(&self, category: AssetCategory) -> Vec<&Asset> {
        self.assets
            .values()
            .filter(|a| a.category == category.name())
            .collect()
    }

    /// Find an asset by hostname.
    pub fn by_hostname(&self, hostname: &str) -> Option<&Asset> {
        self.assets
            .values()
            .find(|a| a.hostname.to_lowercase() == hostname.to_lowercase())
    }

    /// Search assets by any field.
    pub fn search(&self, query: &str) -> Vec<&Asset> {
        let q = query.to_lowercase();
        self.assets
            .values()
            .filter(|a| {
                a.hostname.to_lowercase().contains(&q)
                    || a.ip_addresses.iter().any(|ip| ip.contains(&q))
                    || a.tags.iter().any(|t| t.contains(&q))
                    || a.notes.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Count total assets.
    pub fn count(&self) -> usize {
        self.assets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_registration() {
        let mut inventory = AssetInventory::new();
        let id = inventory.register(Asset {
            id: String::new(),
            hostname: "web-server-01".into(),
            ip_addresses: vec!["10.0.0.1".into()],
            mac_address: None,
            category: "server".into(),
            os: Some("Linux".into()),
            os_version: Some("Ubuntu 22.04".into()),
            software: Vec::new(),
            open_ports: vec![80, 443],
            tags: vec!["production".into(), "web".into()],
            location: None,
            department: None,
            owner: None,
            notes: String::new(),
            discovered: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
        });
        assert!(!id.is_empty());
        assert_eq!(inventory.count(), 1);
    }

    #[test]
    fn test_search() {
        let mut inventory = AssetInventory::new();
        inventory.register(Asset {
            id: "1".into(),
            hostname: "db-master".into(),
            ip_addresses: vec!["10.0.0.5".into()],
            mac_address: None,
            category: "server".into(),
            os: None,
            os_version: None,
            software: Vec::new(),
            open_ports: vec![3306],
            tags: vec!["database".into()],
            location: None,
            department: None,
            owner: None,
            notes: String::new(),
            discovered: String::new(),
            last_seen: String::new(),
        });
        assert_eq!(inventory.search("db-master").len(), 1);
        assert_eq!(inventory.search("10.0.0.5").len(), 1);
        assert_eq!(inventory.search("database").len(), 1);
    }
}
