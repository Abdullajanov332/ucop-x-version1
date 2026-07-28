//! UCOP-X Rule Engine
//!
//! Evaluates correlation, detection, and enrichment rules against
//! telemetry events and findings. Supports expression-based condition
//! evaluation with pluggable matchers.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::Utc;

/// Severity classification for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RuleSeverity {
    pub fn name(&self) -> &'static str {
        match self {
            RuleSeverity::Info => "info",
            RuleSeverity::Low => "low",
            RuleSeverity::Medium => "medium",
            RuleSeverity::High => "high",
            RuleSeverity::Critical => "critical",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(RuleSeverity::Info),
            "low" => Some(RuleSeverity::Low),
            "medium" => Some(RuleSeverity::Medium),
            "high" => Some(RuleSeverity::High),
            "critical" => Some(RuleSeverity::Critical),
            _ => None,
        }
    }
}

/// Rule types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    Detection,
    Correlation,
    Enrichment,
    Suppression,
    Threshold,
}

impl RuleType {
    pub fn name(&self) -> &'static str {
        match self {
            RuleType::Detection => "detection",
            RuleType::Correlation => "correlation",
            RuleType::Enrichment => "enrichment",
            RuleType::Suppression => "suppression",
            RuleType::Threshold => "threshold",
        }
    }
}

/// A single condition in a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

/// A complete rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rule_type: String,
    pub severity: String,
    pub enabled: bool,
    pub conditions: Vec<RuleCondition>,
    pub tags: Vec<String>,
    pub created: String,
    pub updated: String,
    pub version: u32,
}

/// Result of evaluating a rule against an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub event_id: String,
    pub matched_at: String,
    pub matched_conditions: Vec<String>,
    pub enrichment: Option<serde_json::Value>,
}

/// Rule engine state.
#[derive(Debug)]
pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub(crate) matches: Vec<RuleMatch>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            matches: Vec::new(),
        }
    }

    /// Register a rule.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Register multiple rules.
    pub fn add_rules(&mut self, rules: Vec<Rule>) {
        self.rules.extend(rules);
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&mut self, rule_id: &str) {
        self.rules.retain(|r| r.id != rule_id);
    }

    /// Evaluate all enabled rules against an event.
    pub fn evaluate(&mut self, event: &serde_json::Value, event_id: &str) -> Vec<RuleMatch> {
        let mut new_matches = Vec::new();

        for rule in self.rules.iter().filter(|r| r.enabled) {
            let matched = self.evaluate_conditions(&rule.conditions, event);
            if matched {
                let match_result = RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    event_id: event_id.to_string(),
                    matched_at: Utc::now().to_rfc3339(),
                    matched_conditions: rule.conditions.iter().map(|c| c.field.clone()).collect(),
                    enrichment: None,
                };
                new_matches.push(match_result);
            }
        }

        self.matches.extend(new_matches.clone());
        new_matches
    }

    /// Evaluate condition list against an event (AND logic).
    fn evaluate_conditions(&self, conditions: &[RuleCondition], event: &serde_json::Value) -> bool {
        conditions.iter().all(|cond| {
            let field_value = event.get(&cond.field);
            match cond.operator.as_str() {
                "eq" => field_value.map_or(false, |v| v == &cond.value),
                "neq" => field_value.map_or(true, |v| v != &cond.value),
                "gt" => field_value.and_then(|v| v.as_f64()).map_or(false, |v| {
                    cond.value.as_f64().map_or(false, |c| v > c)
                }),
                "lt" => field_value.and_then(|v| v.as_f64()).map_or(false, |v| {
                    cond.value.as_f64().map_or(false, |c| v < c)
                }),
                "contains" => field_value.and_then(|v| v.as_str()).map_or(false, |v| {
                    cond.value.as_str().map_or(false, |c| v.contains(c))
                }),
                "regex" => field_value.and_then(|v| v.as_str()).map_or(false, |v| {
                    cond.value.as_str().and_then(|p| regex::Regex::new(p).ok()).map_or(false, |re| re.is_match(v))
                }),
                "exists" => field_value.is_some(),
                _ => false,
            }
        })
    }

    /// Get all recent matches.
    pub fn recent_matches(&self) -> &[RuleMatch] {
        &self.matches
    }

    /// Clear match history.
    pub fn clear_matches(&mut self) {
        self.matches.clear();
    }

    /// Get enabled rule count.
    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_rule() -> Rule {
        Rule {
            id: "rule-001".into(),
            name: "High CPU Alert".into(),
            description: "Alert when CPU usage exceeds 90%".into(),
            rule_type: "detection".into(),
            severity: "high".into(),
            enabled: true,
            conditions: vec![RuleCondition {
                field: "cpu_usage".into(),
                operator: "gt".into(),
                value: json!(90.0),
            }],
            tags: vec!["performance".into()],
            created: Utc::now().to_rfc3339(),
            updated: Utc::now().to_rfc3339(),
            version: 1,
        }
    }

    #[test]
    fn test_rule_evaluation_match() {
        let mut engine = RuleEngine::new();
        engine.add_rule(sample_rule());

        let event = json!({"cpu_usage": 95.0});
        let matches = engine.evaluate(&event, "evt-001");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "rule-001");
    }

    #[test]
    fn test_rule_evaluation_no_match() {
        let mut engine = RuleEngine::new();
        engine.add_rule(sample_rule());

        let event = json!({"cpu_usage": 50.0});
        let matches = engine.evaluate(&event, "evt-002");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_disabled_rule() {
        let mut engine = RuleEngine::new();
        let mut rule = sample_rule();
        rule.enabled = false;
        engine.add_rule(rule);

        let event = json!({"cpu_usage": 95.0});
        let matches = engine.evaluate(&event, "evt-003");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_contains_operator() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule {
            id: "rule-002".into(),
            name: "Contains Test".into(),
            description: "".into(),
            rule_type: "detection".into(),
            severity: "info".into(),
            enabled: true,
            conditions: vec![RuleCondition {
                field: "message".into(),
                operator: "contains".into(),
                value: json!("error"),
            }],
            tags: vec![],
            created: Utc::now().to_rfc3339(),
            updated: Utc::now().to_rfc3339(),
            version: 1,
        });
        let event = json!({"message": "this is an error message"});
        let matches = engine.evaluate(&event, "evt-004");
        assert_eq!(matches.len(), 1);
    }
}
