//! Capability-based security model.
//! Implements a zero-trust capability system where each module must
//! explicitly request and be granted capabilities before accessing resources.

use crate::error::{KernelError, KernelResult};
use crate::types::{CapabilityDescriptor, CapabilityRights, ComponentId};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A capability is a unforgeable token that grants specific access rights
/// to a resource. Capabilities are created by the kernel and assigned to
/// modules during initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// The unique capability identifier.
    pub id: ComponentId,
    /// The owning component/module.
    pub owner: ComponentId,
    /// The resource this capability targets.
    pub resource: String,
    /// Granted access rights.
    pub rights: CapabilityRights,
    /// Whether this capability can be delegated to child components.
    pub delegatable: bool,
}

impl Capability {
    /// Create a new capability.
    pub fn new(
        owner: ComponentId,
        resource: impl Into<String>,
        rights: CapabilityRights,
        delegatable: bool,
    ) -> Self {
        Self {
            id: ComponentId::new(),
            owner,
            resource: resource.into(),
            rights,
            delegatable,
        }
    }

    /// Check if this capability grants the specified right on the resource.
    pub fn grants(&self, resource: &str, required_rights: CapabilityRights) -> bool {
        self.resource == resource && self.rights.contains(required_rights)
    }
}

/// Manages all capabilities in the kernel.
/// This is the central authority for the zero-trust capability model.
#[derive(Debug)]
pub struct CapabilityManager {
    /// All active capabilities indexed by their ID.
    capabilities: DashMap<ComponentId, Capability>,
    /// Capabilities indexed by owning component.
    by_owner: DashMap<ComponentId, Vec<ComponentId>>,
}

impl CapabilityManager {
    /// Create a new empty capability manager.
    pub fn new() -> Self {
        Self {
            capabilities: DashMap::new(),
            by_owner: DashMap::new(),
        }
    }

    /// Grant a capability to a component.
    pub fn grant(&self, cap: Capability) -> ComponentId {
        let id = cap.id;
        self.capabilities.insert(id, cap.clone());
        self.by_owner
            .entry(cap.owner)
            .or_insert_with(Vec::new)
            .push(id);
        id
    }

    /// Revoke a specific capability by ID.
    pub fn revoke(&self, cap_id: &ComponentId) -> KernelResult<()> {
        let cap = self
            .capabilities
            .remove(cap_id)
            .map(|(_, v)| v)
            .ok_or_else(|| KernelError::ResourceNotFound(format!("capability {cap_id}")))?;

        if let Some(mut entries) = self.by_owner.get_mut(&cap.owner) {
            entries.retain(|id| id != cap_id);
        }
        Ok(())
    }

    /// Revoke all capabilities owned by a component.
    pub fn revoke_all(&self, owner: &ComponentId) {
        if let Some((_, cap_ids)) = self.by_owner.remove(owner) {
            for id in cap_ids {
                self.capabilities.remove(&id);
            }
        }
    }

    /// Verify that a component has the required rights on a resource.
    pub fn check(
        &self,
        owner: &ComponentId,
        resource: &str,
        required: CapabilityRights,
    ) -> KernelResult<()> {
        let has_cap = self
            .capabilities
            .iter()
            .any(|entry| entry.value().owner == *owner && entry.value().grants(resource, required));

        if has_cap {
            Ok(())
        } else {
            Err(KernelError::CapabilityDenied(format!(
                "component {owner} lacks {:?} access to {resource}",
                required
            )))
        }
    }

    /// List all capabilities for a given component.
    pub fn list_for(&self, owner: &ComponentId) -> Vec<Capability> {
        self.capabilities
            .iter()
            .filter(|entry| entry.value().owner == *owner)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Delegate a subset of capabilities to a child component.
    pub fn delegate(
        &self,
        from: &ComponentId,
        to: ComponentId,
        resources: &[CapabilityDescriptor],
    ) -> KernelResult<Vec<ComponentId>> {
        let mut delegated = Vec::new();

        for desc in resources {
            match self
                .capabilities
                .iter()
                .find(|entry| {
                    entry.value().owner == *from
                        && entry.value().resource == desc.resource
                        && entry.value().delegatable
                }) {
                Some(parent_cap) => {
                    let child_cap = Capability {
                        id: ComponentId::new(),
                        owner: to,
                        resource: parent_cap.value().resource.clone(),
                        rights: desc.rights & parent_cap.value().rights,
                        delegatable: false,
                    };
                    delegated.push(self.grant(child_cap));
                }
                None => {
                    return Err(KernelError::CapabilityDenied(format!(
                        "cannot delegate {0}: parent lacks delegatable capability",
                        desc.resource
                    )));
                }
            }
        }

        Ok(delegated)
    }
}

impl Default for CapabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A capability guard that is held for the duration of an operation.
/// When dropped, it can optionally revoke the capability.
#[derive(Debug)]
pub struct CapabilityGuard {
    manager: Arc<CapabilityManager>,
    cap_id: ComponentId,
    revoke_on_drop: bool,
}

impl CapabilityGuard {
    /// Create a new capability guard.
    pub fn new(manager: Arc<CapabilityManager>, cap_id: ComponentId, revoke_on_drop: bool) -> Self {
        Self {
            manager,
            cap_id,
            revoke_on_drop,
        }
    }

    /// The managed capability ID.
    pub fn cap_id(&self) -> &ComponentId {
        &self.cap_id
    }
}

impl Drop for CapabilityGuard {
    fn drop(&mut self) {
        if self.revoke_on_drop {
            let _ = self.manager.revoke(&self.cap_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ComponentId;

    fn setup() -> (Arc<CapabilityManager>, ComponentId) {
        let manager = Arc::new(CapabilityManager::new());
        let owner = ComponentId::new();
        (manager, owner)
    }

    #[test]
    fn test_grant_and_check() {
        let (manager, owner) = setup();
        let cap = Capability::new(owner, "file:config.yaml", CapabilityRights::READ, false);
        manager.grant(cap);
        assert!(manager
            .check(&owner, "file:config.yaml", CapabilityRights::READ)
            .is_ok());
    }

    #[test]
    fn test_deny_without_capability() {
        let (manager, owner) = setup();
        let result = manager.check(&owner, "file:secret.key", CapabilityRights::READ);
        assert!(result.is_err());
        assert!(matches!(result, Err(KernelError::CapabilityDenied(_))));
    }

    #[test]
    fn test_deny_insufficient_rights() {
        let (manager, owner) = setup();
        let cap = Capability::new(owner, "file:config.yaml", CapabilityRights::READ, false);
        manager.grant(cap);
        let result = manager.check(&owner, "file:config.yaml", CapabilityRights::WRITE);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_single() {
        let (manager, owner) = setup();
        let cap = Capability::new(owner, "resource:test", CapabilityRights::FULL, false);
        let id = manager.grant(cap);
        assert!(manager.check(&owner, "resource:test", CapabilityRights::READ).is_ok());
        manager.revoke(&id).unwrap();
        assert!(manager.check(&owner, "resource:test", CapabilityRights::READ).is_err());
    }

    #[test]
    fn test_revoke_all() {
        let (manager, owner) = setup();
        for i in 0..5 {
            let cap = Capability::new(
                owner,
                format!("resource:{i}"),
                CapabilityRights::FULL,
                false,
            );
            manager.grant(cap);
        }
        assert_eq!(manager.list_for(&owner).len(), 5);
        manager.revoke_all(&owner);
        assert!(manager.list_for(&owner).is_empty());
    }

    #[test]
    fn test_delegation() {
        let (manager, parent) = setup();
        let child = ComponentId::new();

        let parent_cap = Capability::new(parent, "db:analytics", CapabilityRights::READ, true);
        manager.grant(parent_cap);

        let desc = CapabilityDescriptor {
            resource: "db:analytics".into(),
            rights: CapabilityRights::READ,
            constraints: vec![],
        };

        let result = manager.delegate(&parent, child, &[desc]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
        assert!(manager.check(&child, "db:analytics", CapabilityRights::READ).is_ok());
    }
}
