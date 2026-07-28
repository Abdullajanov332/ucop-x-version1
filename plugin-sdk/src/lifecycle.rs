//! Plugin lifecycle management.

use crate::PluginState;

/// Events in the plugin lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    BeforeLoad,
    AfterLoad,
    BeforeStart,
    AfterStart,
    BeforeStop,
    AfterStop,
    OnError,
}

/// Transition validation for plugin states.
pub fn can_transition(from: PluginState, to: PluginState) -> bool {
    match (from, to) {
        (PluginState::Discovered, PluginState::Loaded)
        | (PluginState::Loaded, PluginState::Running)
        | (PluginState::Running, PluginState::Stopped)
        | (PluginState::Stopped, PluginState::Loaded) => true,
        (PluginState::Error(_), PluginState::Stopped) => true,
        _ => false,
    }
}

/// Plugin lifecycle hook.
#[derive(Debug, Clone)]
pub struct LifecycleHook {
    pub event: LifecycleEvent,
    pub handler: String,
    pub priority: u32,
}

/// Lifecycle manager for a single plugin.
#[derive(Debug, Default)]
pub struct LifecycleManager {
    pub hooks: Vec<LifecycleHook>,
}

impl LifecycleManager {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Register a lifecycle hook.
    pub fn register_hook(&mut self, hook: LifecycleHook) {
        self.hooks.push(hook);
        self.hooks.sort_by_key(|h| h.priority);
    }

    /// Get hooks for a specific event.
    pub fn hooks_for(&self, event: LifecycleEvent) -> Vec<&LifecycleHook> {
        self.hooks.iter().filter(|h| h.event == event).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(can_transition(PluginState::Discovered, PluginState::Loaded));
        assert!(can_transition(PluginState::Running, PluginState::Stopped));
        assert!(!can_transition(PluginState::Discovered, PluginState::Running));
    }

    #[test]
    fn test_hook_ordering() {
        let mut mgr = LifecycleManager::new();
        mgr.register_hook(LifecycleHook {
            event: LifecycleEvent::AfterLoad,
            handler: "high".into(),
            priority: 10,
        });
        mgr.register_hook(LifecycleHook {
            event: LifecycleEvent::AfterLoad,
            handler: "low".into(),
            priority: 100,
        });
        let hooks = mgr.hooks_for(LifecycleEvent::AfterLoad);
        assert_eq!(hooks[0].priority, 10);
        assert_eq!(hooks[1].priority, 100);
    }
}
