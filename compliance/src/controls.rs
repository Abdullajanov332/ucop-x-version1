//! Compliance control checking and evidence collection.

use crate::{ComplianceCheckResult, ComplianceStatus};

/// Evaluate a compliance control based on provided evidence.
pub fn evaluate_control(
    control_id: &str,
    evidence: &[Evidence],
) -> ComplianceCheckResult {
    let total = evidence.len();
    let passed = evidence.iter().filter(|e| e.passed).count();

    let status = if total == 0 {
        ComplianceStatus::NotChecked
    } else if passed == total {
        ComplianceStatus::Compliant
    } else if passed == 0 {
        ComplianceStatus::NonCompliant
    } else {
        ComplianceStatus::Partial
    };

    ComplianceCheckResult {
        control_id: control_id.to_string(),
        control_name: String::new(),
        status,
        details: format!("{passed}/{total} checks passed"),
        evidence: evidence.iter().map(|e| e.description.clone()).collect(),
    }
}

/// A piece of evidence for compliance.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub description: String,
    pub passed: bool,
    pub detail: String,
}

/// Collect evidence for an access control check.
pub fn collect_access_control_evidence(users: &[(String, bool)]) -> Vec<Evidence> {
    users
        .iter()
        .map(|(name, has_mfa)| Evidence {
            description: format!("User {name} MFA status"),
            passed: *has_mfa,
            detail: if *has_mfa {
                "MFA enabled".into()
            } else {
                "MFA not enabled".into()
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_all_pass() {
        let evidence = vec![
            Evidence {
                description: "Firewall rule 1".into(),
                passed: true,
                detail: "OK".into(),
            },
        ];
        let result = evaluate_control("PCI-1.0", &evidence);
        assert_eq!(result.status, ComplianceStatus::Compliant);
    }

    #[test]
    fn test_evaluate_partial() {
        let evidence = vec![
            Evidence {
                description: "Check 1".into(),
                passed: true,
                detail: "OK".into(),
            },
            Evidence {
                description: "Check 2".into(),
                passed: false,
                detail: "Failed".into(),
            },
        ];
        let result = evaluate_control("TEST", &evidence);
        assert_eq!(result.status, ComplianceStatus::Partial);
    }
}
