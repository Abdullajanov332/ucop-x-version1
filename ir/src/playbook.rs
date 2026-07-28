//! Incident response playbooks - automated response workflows.

/// A single step in a playbook.
#[derive(Debug, Clone)]
pub struct PlaybookStep {
    pub name: String,
    pub description: String,
    pub action_type: ActionType,
    pub parameters: std::collections::HashMap<String, String>,
    pub timeout_secs: u64,
}

/// Types of automated response actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    CollectEvidence,
    RunCommand,
    BlockIp,
    BlockDomain,
    QuarantineHost,
    DisableUser,
    ResetPassword,
    KillProcess,
    CreateTicket,
    NotifyTeam,
    UpdateFirewall,
}

/// An incident response playbook.
#[derive(Debug, Clone)]
pub struct Playbook {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub steps: Vec<PlaybookStep>,
}

/// Playbook engine that executes response workflows.
#[derive(Debug, Default)]
pub struct PlaybookEngine {
    pub playbooks: Vec<Playbook>,
}

impl PlaybookEngine {
    pub fn new() -> Self {
        Self { playbooks: Vec::new() }
    }

    /// Register a playbook.
    pub fn register(&mut self, playbook: Playbook) {
        self.playbooks.push(playbook);
    }

    /// Find playbooks matching a severity level.
    pub fn for_severity(&self, severity: &str) -> Vec<&Playbook> {
        self.playbooks.iter().filter(|p| p.severity == severity).collect()
    }
}

/// Create default playbooks for common scenarios.
pub fn default_playbooks() -> Vec<Playbook> {
    vec![
        Playbook {
            name: "ransomware-response".into(),
            description: "Automated response to suspected ransomware infection".into(),
            severity: "critical".into(),
            steps: vec![
                PlaybookStep {
                    name: "isolate-host".into(),
                    description: "Isolate the affected host from the network".into(),
                    action_type: ActionType::QuarantineHost,
                    parameters: std::collections::HashMap::new(),
                    timeout_secs: 30,
                },
                PlaybookStep {
                    name: "collect-evidence".into(),
                    description: "Collect forensic evidence from the affected host".into(),
                    action_type: ActionType::CollectEvidence,
                    parameters: std::collections::HashMap::new(),
                    timeout_secs: 120,
                },
                PlaybookStep {
                    name: "notify-team".into(),
                    description: "Notify the incident response team".into(),
                    action_type: ActionType::NotifyTeam,
                    parameters: std::collections::HashMap::new(),
                    timeout_secs: 10,
                },
            ],
        },
        Playbook {
            name: "brute-force-response".into(),
            description: "Response to detected brute force login attempts".into(),
            severity: "high".into(),
            steps: vec![
                PlaybookStep {
                    name: "block-source".into(),
                    description: "Block the source IP at the firewall".into(),
                    action_type: ActionType::BlockIp,
                    parameters: std::collections::HashMap::from([
                        ("duration".into(), "3600".into()),
                    ]),
                    timeout_secs: 15,
                },
                PlaybookStep {
                    name: "disable-account".into(),
                    description: "Disable the targeted user account".into(),
                    action_type: ActionType::DisableUser,
                    parameters: std::collections::HashMap::new(),
                    timeout_secs: 30,
                },
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_matching() {
        let mut engine = PlaybookEngine::new();
        for pb in default_playbooks() {
            engine.register(pb);
        }
        assert_eq!(engine.for_severity("critical").len(), 1);
        assert_eq!(engine.for_severity("high").len(), 1);
    }
}
