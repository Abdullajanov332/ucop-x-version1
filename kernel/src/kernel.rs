//! Kernel orchestrator.
//! Top-level kernel that initializes all core subsystems and manages
//! the platform lifecycle.

use crate::capability::CapabilityManager;
use crate::error::{KernelError, KernelResult};
use crate::event::EventBus;
use crate::module::{KernelContext, Module, ModuleRegistry};
use crate::types::{CapabilityRights, ComponentId, ModuleCategory, Version};
use std::sync::Arc;
use tracing::{error, info};

/// Configuration for the UCOP-X kernel.
#[derive(Debug, Clone)]
pub struct KernelConfig {
    /// Maximum number of concurrent modules.
    pub max_modules: usize,
    /// Enable capability-based security enforcement.
    pub enable_capabilities: bool,
    /// Enable the event bus.
    pub enable_event_bus: bool,
    /// Root data directory for the platform.
    pub data_dir: Option<std::path::PathBuf>,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_modules: 256,
            enable_capabilities: true,
            enable_event_bus: true,
            data_dir: None,
        }
    }
}

/// UCOP-X Kernel — the central orchestrator for the platform.
/// Initializes core subsystems and manages module lifecycle.
#[derive(Debug)]
pub struct UcokKernel {
    /// Kernel configuration.
    config: KernelConfig,
    /// The event bus for inter-module communication.
    event_bus: Arc<EventBus>,
    /// The capability manager for zero-trust security.
    capability_manager: Arc<CapabilityManager>,
    /// The module registry.
    module_registry: Arc<ModuleRegistry>,
    /// Kernel component ID.
    component_id: ComponentId,
    /// Whether the kernel is initialized.
    initialized: std::sync::atomic::AtomicBool,
}

impl UcokKernel {
    /// Create a new UCOP-X kernel with default configuration.
    pub fn new() -> Self {
        Self::with_config(KernelConfig::default())
    }

    /// Create a new UCOP-X kernel with custom configuration.
    pub fn with_config(config: KernelConfig) -> Self {
        let event_bus = Arc::new(EventBus::new());
        let capability_manager = Arc::new(CapabilityManager::new());
        let kernel_id = ComponentId::new();

        let kernel_ctx = Arc::new(KernelContext::new(
            event_bus.clone(),
            capability_manager.clone(),
            kernel_id,
        ));

        let module_registry = Arc::new(ModuleRegistry::new(kernel_ctx));

        Self {
            config,
            event_bus,
            capability_manager,
            module_registry,
            component_id: kernel_id,
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Initialize the kernel and start core subsystems.
    pub async fn initialize(&self) -> KernelResult<()> {
        info!(
            component = %self.component_id,
            "UCOP-X kernel initializing"
        );

        // Start the event bus
        if self.config.enable_event_bus {
            self.event_bus.start()?;
            info!("event bus started");
        }

        // Grant kernel its bootstrap capabilities
        if self.config.enable_capabilities {
            let kernel_cap = crate::capability::Capability::new(
                self.component_id,
                "kernel:admin",
                CapabilityRights::FULL,
                true,
            );
            self.capability_manager.grant(kernel_cap);
            info!("kernel bootstrap capabilities granted");
        }

        self.initialized
            .store(true, std::sync::atomic::Ordering::Release);
        info!("UCOP-X kernel initialized successfully");
        Ok(())
    }

    /// Register a module with the kernel.
    pub async fn register_module(&self, module: Box<dyn Module>) -> KernelResult<ComponentId> {
        self.ensure_initialized()?;
        self.module_registry.register(module).await
    }

    /// Start a registered module.
    pub async fn start_module(&self, id: &ComponentId) -> KernelResult<()> {
        self.ensure_initialized()?;
        self.module_registry.start(id).await
    }

    /// Stop a running module.
    pub async fn stop_module(&self, id: &ComponentId) -> KernelResult<()> {
        self.ensure_initialized()?;
        self.module_registry.stop(id).await
    }

    /// Unregister a module.
    pub async fn unregister_module(&self, id: &ComponentId) -> KernelResult<()> {
        self.ensure_initialized()?;
        self.module_registry.unregister(id).await
    }

    /// Gracefully shut down the kernel.
    pub async fn shutdown(&self) -> KernelResult<()> {
        info!("UCOP-X kernel shutting down");

        // Stop all modules in reverse dependency order
        let modules = self.module_registry.list_modules();
        for desc in modules.iter().rev() {
            info!(name = %desc.name, "stopping module");
            if let Err(e) = self.module_registry.stop(&desc.id).await {
                error!(name = %desc.name, error = %e, "error stopping module");
            }
        }

        // Stop event bus
        if self.config.enable_event_bus {
            self.event_bus.stop();
        }

        self.initialized
            .store(false, std::sync::atomic::Ordering::Release);
        info!("UCOP-X kernel shutdown complete");
        Ok(())
    }

    /// Return the event bus reference.
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// Return the capability manager reference.
    pub fn capability_manager(&self) -> &Arc<CapabilityManager> {
        &self.capability_manager
    }

    /// Return the module registry reference.
    pub fn module_registry(&self) -> &Arc<ModuleRegistry> {
        &self.module_registry
    }

    /// Return the kernel's component ID.
    pub fn component_id(&self) -> &ComponentId {
        &self.component_id
    }

    /// List all registered modules.
    pub fn list_modules(&self) -> Vec<crate::types::ModuleDescriptor> {
        self.module_registry.list_modules()
    }

    fn ensure_initialized(&self) -> KernelResult<()> {
        if self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            Ok(())
        } else {
            Err(KernelError::Internal(
                "kernel not initialized".to_string(),
            ))
        }
    }
}

impl Default for UcokKernel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ModuleDescriptor;
    use crate::types::ModuleStatus;

    struct TestModule {
        desc: ModuleDescriptor,
    }

    impl TestModule {
        fn new(name: &str) -> Self {
            Self {
                desc: ModuleDescriptor {
                    id: ComponentId::new(),
                    name: name.to_string(),
                    version: Version::new(1, 0, 0),
                    category: ModuleCategory::Utility,
                    status: ModuleStatus::Registered,
                    description: String::new(),
                    dependencies: vec![],
                    required_capabilities: vec![],
                },
            }
        }
    }

    impl Module for TestModule {
        fn descriptor(&self) -> &ModuleDescriptor {
            &self.desc
        }

        async fn init(&mut self, _kernel: &KernelContext) -> KernelResult<()> {
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
    async fn test_kernel_lifecycle() {
        let kernel = UcokKernel::new();
        kernel.initialize().await.unwrap();

        let id = kernel
            .register_module(Box::new(TestModule::new("test")))
            .await
            .unwrap();
        kernel.start_module(&id).await.unwrap();
        assert_eq!(kernel.list_modules().len(), 1);

        kernel.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_operation_before_init_fails() {
        let kernel = UcokKernel::new();
        let result = kernel
            .register_module(Box::new(TestModule::new("fail")))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_kernel_default_config() {
        let config = KernelConfig::default();
        assert!(config.enable_capabilities);
        assert!(config.enable_event_bus);
        assert_eq!(config.max_modules, 256);
    }
}
