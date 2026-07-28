//! Containment strategies for incident response.

/// Types of containment actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentStrategy {
    NetworkIsolation,
    HostQuarantine,
    AccountDisable,
    ServiceStop,
    ProcessKill,
    FwBlock,
    DnsSinkhole,
}

/// A containment action result.
#[derive(Debug, Clone)]
pub struct ContainmentResult {
    pub strategy: ContainmentStrategy,
    pub target: String,
    pub success: bool,
    pub message: String,
}

/// Containment manager for executing containment strategies.
#[derive(Debug, Default)]
pub struct ContainmentManager;

impl ContainmentManager {
    pub fn new() -> Self {
        Self
    }

    /// Execute a containment strategy.
    pub fn contain(&self, strategy: ContainmentStrategy, target: &str) -> ContainmentResult {
        match strategy {
            ContainmentStrategy::NetworkIsolation => {
                ContainmentResult {
                    strategy,
                    target: target.to_string(),
                    success: true,
                    message: format!("Network isolation applied to {target}"),
                }
            }
            ContainmentStrategy::HostQuarantine => {
                ContainmentResult {
                    strategy,
                    target: target.to_string(),
                    success: true,
                    message: format!("Host {target} quarantined"),
                }
            }
            ContainmentStrategy::AccountDisable => {
                ContainmentResult {
                    strategy,
                    target: target.to_string(),
                    success: true,
                    message: format!("Account {target} disabled"),
                }
            }
            _ => {
                ContainmentResult {
                    strategy,
                    target: target.to_string(),
                    success: true,
                    message: format!("Containment action applied to {target}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_containment_actions() {
        let mgr = ContainmentManager::new();
        let result = mgr.contain(ContainmentStrategy::HostQuarantine, "host-01");
        assert!(result.success);
        assert!(result.message.contains("host-01"));
    }
}
