//! Module lifecycle management.
//! Provides the registry, loader, and lifecycle hooks for all platform modules.

use crate::capability::CapabilityManager;
use crate::error::{KernelError, KernelResult};
use crate::event::EventBus;
use crate::types::{
    CapabilityDescriptor, ComponentId, ModuleCategory, ModuleStatus, Version,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Module descriptor — metadata returned when a module is registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDescriptor {
    /// Unique module identifier.
    pub id: ComponentId,
    /// Human-readable module name.
    pub name: String,
    /// Module version.
    pub version: Version,
    /// Module category.
    pub category: ModuleCategory,
    /// Current execution status.
    pub status: ModuleStatus,
    /// Description of what this module does.
    pub description: String,
    /// Dependencies on other modules (by name).
    pub dependencies: Vec<String>,
    /// Capabilities required by this module.
    pub required_capabilities: Vec<CapabilityDescriptor>,
}

/// Trait that all UCOP-X modules must implement.
pub trait Module: Send + Sync {
    /// Return the module's descriptor.
    fn descriptor(&self) -> &ModuleDescriptor;

    /// Initialize the module with references to kernel services.
    /// Called once after registration.
    fn init(
        &mut self,
        kernel: &KernelContext,
    ) -> impl std::future::Future<Output = KernelResult<()>> + Send;

    /// Start the module's main processing.
    /// Called after init succeeds.
    fn start(
        &self,
        kernel: &KernelContext,
    ) -> impl std::future::Future<Output = KernelResult<()>> + Send;

    /// Gracefully stop the module.
    fn stop(
        &self,
        kernel: &KernelContext,
    ) -> impl std::future::Future<Output = KernelResult<()>> + Send;
}

/// Context provided to modules for accessing kernel services.
#[derive(Debug, Clone)]
pub struct KernelContext {
    /// The event bus for inter-module communication.
    pub event_bus: Arc<EventBus>,
    /// The capability manager for security checks.
    pub capability_manager: Arc<CapabilityManager>,
    /// This module's component ID.
    pub component_id: ComponentId,
}

impl KernelContext {
    /// Create a new kernel context.
    pub fn new(
        event_bus: Arc<EventBus>,
        capability_manager: Arc<CapabilityManager>,
        component_id: ComponentId,
    ) -> Self {
        Self {
            event_bus,
            capability_manager,
            component_id,
        }
    }
}

/// The module registry manages all loaded modules.
#[derive(Debug)]
pub struct ModuleRegistry {
    /// Registered modules by their component ID.
    modules: DashMap<ComponentId, Box<dyn Module>>,
    /// Module descriptors by name for fast lookup.
    by_name: DashMap<String, ComponentId>,
    /// Global kernel context shared with all modules.
    kernel_context: Arc<KernelContext>,
}

impl ModuleRegistry {
    /// Create a new module registry.
    pub fn new(kernel_context: Arc<KernelContext>) -> Self {
        Self {
            modules: DashMap::new(),
            by_name: DashMap::new(),
            kernel_context,
        }
    }

    /// Register and initialize a module.
    pub async fn register(&self, module: Box<dyn Module>) -> KernelResult<ComponentId> {
        let desc = module.descriptor().clone();
        let id = desc.id;

        // Check for name conflicts
        if self.by_name.contains_key(&desc.name) {
            return Err(KernelError::ModuleInitFailed(format!(
                "module '{}' already registered",
                desc.name
            )));
        }

        // Grant required capabilities
        for cap_desc in &desc.required_capabilities {
            let cap = crate::capability::Capability::new(
                id,
                &cap_desc.resource,
                cap_desc.rights,
                false,
            );
            self.kernel_context.capability_manager.grant(cap);
        }

        // Insert into registry
        self.by_name.insert(desc.name.clone(), id);
        self.modules.insert(id, module);

        // Perform async initialization
        if let Some(mut module) = self.modules.get_mut(&id) {
            module
                .init(&self.kernel_context)
                .await
                .map_err(|e| KernelError::ModuleInitFailed(format!("'{}': {e}", desc.name)))?;
        }

        info!(name = %desc.name, version = %desc.version, "module registered and initialized");
        Ok(id)
    }

    /// Start a registered module.
    pub async fn start(&self, id: &ComponentId) -> KernelResult<()> {
        let module = self
            .modules
            .get(id)
            .ok_or_else(|| KernelError::ModuleNotFound(format!("{id}")))?;

        module
            .start(&self.kernel_context)
            .await
            .map_err(|e| KernelError::ModuleExecutionError(format!("start failed: {e}")))?;

        info!(%id, "module started");
        Ok(())
    }

    /// Stop a running module.
    pub async fn stop(&self, id: &ComponentId) -> KernelResult<()> {
        let module = self
            .modules
            .get(id)
            .ok_or_else(|| KernelError::ModuleNotFound(format!("{id}")))?;

        module
            .stop(&self.kernel_context)
            .await
            .map_err(|e| KernelError::ModuleExecutionError(format!("stop failed: {e}")))?;

        // Revoke all capabilities for this module
        self.kernel_context
            .capability_manager
            .revoke_all(id);

        info!(%id, "module stopped");
        Ok(())
    }

    /// Unregister and remove a module from the registry.
    pub async fn unregister(&self, id: &ComponentId) -> KernelResult<()> {
        // Ensure module is stopped first
        self.stop(id).await?;

        let module = self
            .modules
            .remove(id)
            .ok_or_else(|| KernelError::ModuleNotFound(format!("{id}")))?;

        let name = module.1.descriptor().name.clone();
        self.by_name.remove(&name);

        info!(name = %name, %id, "module unregistered");
        Ok(())
    }

    /// Look up a module by name.
    pub fn find_by_name(&self, name: &str) -> Option<ComponentId> {
        self.by_name.get(name).map(|v| *v)
    }

    /// List all registered module descriptors.
    pub fn list_modules(&self) -> Vec<ModuleDescriptor> {
        self.modules
            .iter()
            .map(|entry| entry.value().descriptor().clone())
            .collect()
    }

    /// Get the number of registered modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestModule {
        descriptor: ModuleDescriptor,
        initialized: std::sync::atomic::AtomicBool,
    }

    impl TestModule {
        fn new(name: &str, category: ModuleCategory) -> Self {
            Self {
                descriptor: ModuleDescriptor {
                    id: ComponentId::new(),
                    name: name.to_string(),
                    version: Version::new(1, 0, 0),
                    category,
                    status: ModuleStatus::Registered,
                    description: format!("Test module: {name}"),
                    dependencies: vec![],
                    required_capabilities: vec![],
                },
                initialized: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl Module for TestModule {
        fn descriptor(&self) -> &ModuleDescriptor {
            &self.descriptor
        }

        async fn init(&mut self, _kernel: &KernelContext) -> KernelResult<()> {
            self.initialized
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn start(&self, _kernel: &KernelContext) -> KernelResult<()> {
            Ok(())
        }

        async fn stop(&self, _kernel: &KernelContext) -> KernelResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_register_module() {
        let bus = Arc::new(EventBus::new());
        let cap_mgr = Arc::new(CapabilityManager::new());
        let ctx = Arc::new(KernelContext::new(bus, cap_mgr, ComponentId::new()));
        let registry = ModuleRegistry::new(ctx);

        let module = Box::new(TestModule::new("test-mod", ModuleCategory::Analysis));
        let id = registry.register(module).await.unwrap();
        assert!(registry.find_by_name("test-mod").is_some());
        assert_eq!(registry.module_count(), 1);
    }

    #[tokio::test]
    async fn test_duplicate_name_rejected() {
        let bus = Arc::new(EventBus::new());
        let cap_mgr = Arc::new(CapabilityManager::new());
        let ctx = Arc::new(KernelContext::new(bus, cap_mgr, ComponentId::new()));
        let registry = ModuleRegistry::new(ctx);

        let m1 = Box::new(TestModule::new("dup", ModuleCategory::Kernel));
        let m2 = Box::new(TestModule::new("dup", ModuleCategory::Analysis));

        registry.register(m1).await.unwrap();
        let result = registry.register(m2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unregister_stops_module() {
        let bus = Arc::new(EventBus::new());
        let cap_mgr = Arc::new(CapabilityManager::new());
        let ctx = Arc::new(KernelContext::new(bus, cap_mgr, ComponentId::new()));
        let registry = ModuleRegistry::new(ctx);

        let module = Box::new(TestModule::new("temp", ModuleCategory::Utility));
        let id = registry.register(module).await.unwrap();
        assert_eq!(registry.module_count(), 1);

        registry.unregister(&id).await.unwrap();
        assert_eq!(registry.module_count(), 0);
    }
}
