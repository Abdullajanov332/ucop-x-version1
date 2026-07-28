//! Core type definitions for the UCOP-X microkernel.
//! Provides platform-independent identifiers, versions, and metadata structures.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// A unique identifier for any component, module, or entity in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComponentId(Uuid);

impl ComponentId {
    /// Create a new random component identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a nil/zero component identifier (for uninitialized state).
    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    /// Parse a component identifier from its hypenated string representation.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }

    /// Return the inner UUID value.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ComponentId {
    fn default() -> Self {
        Self::nil()
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Semantic versioning for all UCOP-X components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    /// Major version — incompatible API changes.
    pub major: u16,
    /// Minor version — backwards-compatible functionality added.
    pub minor: u16,
    /// Patch version — backwards-compatible bug fixes.
    pub patch: u16,
}

impl Version {
    /// Create a new semantic version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    /// Check if this version is compatible with another (same major, minor >= other.minor).
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Module category classification for the UCOP-X platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleCategory {
    /// Core kernel subsystem (memory, scheduler, crypto).
    Kernel,
    /// Analysis modules (static, dynamic, malware, RE).
    Analysis,
    /// Network scanning and monitoring modules.
    Network,
    /// Forensics and incident response modules.
    Forensics,
    /// Threat intelligence ingestion modules.
    ThreatIntel,
    /// Reporting and compliance modules.
    Reporting,
    /// Asset inventory and management modules.
    AssetInventory,
    /// Plugin/scripting runtime modules.
    Runtime,
    /// Utility and helper modules.
    Utility,
}

impl fmt::Display for ModuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel => write!(f, "kernel"),
            Self::Analysis => write!(f, "analysis"),
            Self::Network => write!(f, "network"),
            Self::Forensics => write!(f, "forensics"),
            Self::ThreatIntel => write!(f, "threat-intel"),
            Self::Reporting => write!(f, "reporting"),
            Self::AssetInventory => write!(f, "asset-inventory"),
            Self::Runtime => write!(f, "runtime"),
            Self::Utility => write!(f, "utility"),
        }
    }
}

/// Module execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleStatus {
    /// Module is registered but not yet initialized.
    Registered,
    /// Module is initialized and running.
    Running,
    /// Module has been paused/suspended.
    Paused,
    /// Module encountered an error and stopped.
    Error,
    /// Module has been unloaded.
    Unloaded,
}

/// A capability descriptor granting access to a specific resource or operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    /// The resource or operation this capability grants access to.
    pub resource: String,
    /// Access rights granted.
    pub rights: CapabilityRights,
    /// Optional resource-specific constraints.
    pub constraints: Vec<String>,
}

bitflags::bitflags! {
    /// Access rights associated with a capability.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct CapabilityRights: u8 {
        /// Read access to the resource.
        const READ     = 0b0001;
        /// Write access to the resource.
        const WRITE    = 0b0010;
        /// Execute access to the resource.
        const EXECUTE  = 0b0100;
        /// Delete access to the resource.
        const DELETE   = 0b1000;
        /// Full control over the resource.
        const FULL     = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits() | Self::DELETE.bits();
    }
}

impl CapabilityRights {
    /// Returns true if this set of rights includes read access.
    pub fn can_read(&self) -> bool {
        self.contains(Self::READ)
    }

    /// Returns true if this set of rights includes write access.
    pub fn can_write(&self) -> bool {
        self.contains(Self::WRITE)
    }

    /// Returns true if this set of rights includes execute access.
    pub fn can_execute(&self) -> bool {
        self.contains(Self::EXECUTE)
    }

    /// Returns true if this set of rights includes delete access.
    pub fn can_delete(&self) -> bool {
        self.contains(Self::DELETE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_id_creation() {
        let id = ComponentId::new();
        assert_ne!(id, ComponentId::nil());
    }

    #[test]
    fn test_component_id_parse_roundtrip() {
        let id = ComponentId::new();
        let s = id.to_string();
        let parsed = ComponentId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = Version::new(1, 2, 0);
        let v2 = Version::new(1, 3, 1);
        let v3 = Version::new(2, 0, 0);
        assert!(v1.is_compatible_with(&v1));
        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_capability_rights() {
        let full = CapabilityRights::FULL;
        assert!(full.can_read());
        assert!(full.can_write());
        assert!(full.can_execute());
        assert!(full.can_delete());

        let read_only = CapabilityRights::READ;
        assert!(read_only.can_read());
        assert!(!read_only.can_write());
    }
}
