//! Compliance framework control definitions.

use crate::ComplianceFramework;

/// A compliance control definition.
#[derive(Debug, Clone)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub risk_level: String,
}

/// Get the controls for a given framework.
pub fn get_controls(framework: ComplianceFramework) -> Vec<Control> {
    match framework {
        ComplianceFramework::PciDss => pci_dss_controls(),
        ComplianceFramework::Hipaa => hipaa_controls(),
        ComplianceFramework::Soc2 => soc2_controls(),
        ComplianceFramework::Gdpr => gdpr_controls(),
        ComplianceFramework::Iso27001 => iso27001_controls(),
        ComplianceFramework::NistCsf => nist_csf_controls(),
        ComplianceFramework::Custom(_) => Vec::new(),
    }
}

fn pci_dss_controls() -> Vec<Control> {
    vec![
        Control {
            id: "PCI-1.0".into(),
            name: "Firewall Configuration".into(),
            description: "Install and maintain firewall configuration to protect cardholder data".into(),
            category: "network-security".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-2.0".into(),
            name: "Secure Configurations".into(),
            description: "Do not use vendor-supplied defaults for passwords and security parameters".into(),
            category: "access-control".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-3.0".into(),
            name: "Protect Stored Cardholder Data".into(),
            description: "Protect stored cardholder data through encryption and access controls".into(),
            category: "data-protection".into(),
            risk_level: "critical".into(),
        },
        Control {
            id: "PCI-4.0".into(),
            name: "Encrypt Transmission".into(),
            description: "Encrypt transmission of cardholder data across open/public networks".into(),
            category: "cryptography".into(),
            risk_level: "critical".into(),
        },
        Control {
            id: "PCI-5.0".into(),
            name: "Protect Against Malware".into(),
            description: "Protect all systems against malware and regularly update anti-virus software".into(),
            category: "endpoint-security".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-6.0".into(),
            name: "Secure Development".into(),
            description: "Develop and maintain secure systems and applications".into(),
            category: "appsec".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-7.0".into(),
            name: "Access Control".into(),
            description: "Restrict access to cardholder data by business need-to-know".into(),
            category: "access-control".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-8.0".into(),
            name: "User Identification".into(),
            description: "Assign a unique ID to each person with computer access".into(),
            category: "identity".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "PCI-9.0".into(),
            name: "Physical Security".into(),
            description: "Restrict physical access to cardholder data".into(),
            category: "physical-security".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "PCI-10.0".into(),
            name: "Logging and Monitoring".into(),
            description: "Track and monitor all access to network resources and cardholder data".into(),
            category: "monitoring".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-11.0".into(),
            name: "Vulnerability Testing".into(),
            description: "Regularly test security systems and processes".into(),
            category: "testing".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "PCI-12.0".into(),
            name: "Information Security Policy".into(),
            description: "Maintain a policy that addresses information security for all personnel".into(),
            category: "governance".into(),
            risk_level: "medium".into(),
        },
    ]
}

fn hipaa_controls() -> Vec<Control> {
    vec![
        Control {
            id: "HIPAA-164.308".into(),
            name: "Security Management Process".into(),
            description: "Implement policies and procedures to prevent, detect, and correct security violations".into(),
            category: "administrative".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "HIPAA-164.310".into(),
            name: "Physical Safeguards".into(),
            description: "Limit physical access to electronic information systems".into(),
            category: "physical".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "HIPAA-164.312".into(),
            name: "Technical Safeguards".into(),
            description: "Implement technical policies for electronic protected health information".into(),
            category: "technical".into(),
            risk_level: "high".into(),
        },
    ]
}

fn soc2_controls() -> Vec<Control> {
    vec![
        Control {
            id: "SOC2-CC1".into(),
            name: "Control Environment".into(),
            description: "Commitment to integrity and ethical values".into(),
            category: "governance".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "SOC2-CC2".into(),
            name: "Risk Assessment".into(),
            description: "Identify and analyze risks to achieving objectives".into(),
            category: "risk-management".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "SOC2-CC3".into(),
            name: "Monitoring Activities".into(),
            description: "Monitor internal control system".into(),
            category: "monitoring".into(),
            risk_level: "medium".into(),
        },
    ]
}

fn gdpr_controls() -> Vec<Control> {
    vec![
        Control {
            id: "GDPR-5".into(),
            name: "Data Processing Principles".into(),
            description: "Lawful, fair, and transparent data processing".into(),
            category: "data-protection".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "GDPR-17".into(),
            name: "Right to Erasure".into(),
            description: "Data subjects have the right to request data deletion".into(),
            category: "data-rights".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "GDPR-32".into(),
            name: "Security of Processing".into(),
            description: "Implement appropriate technical measures for data security".into(),
            category: "security".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "GDPR-33".into(),
            name: "Breach Notification".into(),
            description: "Notify supervisory authority within 72 hours of a breach".into(),
            category: "incident-response".into(),
            risk_level: "high".into(),
        },
    ]
}

fn iso27001_controls() -> Vec<Control> {
    vec![
        Control {
            id: "ISO-A5".into(),
            name: "Information Security Policies".into(),
            description: "Management direction for information security".into(),
            category: "governance".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "ISO-A6".into(),
            name: "Organization of Security".into(),
            description: "Internal organization and mobile device policy".into(),
            category: "governance".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "ISO-A7".into(),
            name: "Human Resource Security".into(),
            description: "Prior to employment, during employment, and termination".into(),
            category: "hr".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "ISO-A8".into(),
            name: "Asset Management".into(),
            description: "Inventory, classification, and media handling".into(),
            category: "asset-management".into(),
            risk_level: "medium".into(),
        },
        Control {
            id: "ISO-A9".into(),
            name: "Access Control".into(),
            description: "Business requirements, user access, and system access control".into(),
            category: "access-control".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "ISO-A10".into(),
            name: "Cryptography".into(),
            description: "Cryptographic controls and key management".into(),
            category: "cryptography".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "ISO-A16".into(),
            name: "Incident Management".into(),
            description: "Responsibilities, reporting, and response to incidents".into(),
            category: "incident-response".into(),
            risk_level: "high".into(),
        },
    ]
}

fn nist_csf_controls() -> Vec<Control> {
    vec![
        Control {
            id: "NIST-ID".into(),
            name: "Identify".into(),
            description: "Develop organizational understanding of cybersecurity risks".into(),
            category: "governance".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "NIST-PR".into(),
            name: "Protect".into(),
            description: "Develop and implement safeguards to ensure delivery of services".into(),
            category: "security".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "NIST-DE".into(),
            name: "Detect".into(),
            description: "Develop and implement activities to identify cybersecurity events".into(),
            category: "monitoring".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "NIST-RS".into(),
            name: "Respond".into(),
            description: "Develop and implement activities to respond to cybersecurity events".into(),
            category: "incident-response".into(),
            risk_level: "high".into(),
        },
        Control {
            id: "NIST-RC".into(),
            name: "Recover".into(),
            description: "Develop and implement activities to maintain resilience".into(),
            category: "resilience".into(),
            risk_level: "medium".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_controls() {
        let controls = pci_dss_controls();
        assert_eq!(controls.len(), 12);
        assert_eq!(controls[0].id, "PCI-1.0");
    }

    #[test]
    fn test_get_controls() {
        let controls = get_controls(ComplianceFramework::Iso27001);
        assert!(!controls.is_empty());
    }
}
