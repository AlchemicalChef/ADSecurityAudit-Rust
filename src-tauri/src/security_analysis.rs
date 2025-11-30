use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an Access Control Entry (ACE) in a security descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlEntry {
    pub trustee: String,
    pub trustee_sid: String,
    pub access_mask: u32,
    pub ace_type: AceType,
    pub ace_flags: u32,
    pub object_type: Option<String>,
    pub inherited_object_type: Option<String>,
    pub permissions: Vec<String>,
    pub risk_level: RiskLevel,
    pub risk_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    AccessAllowedObject,
    AccessDeniedObject,
    SystemAudit,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// AdminSDHolder analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSDHolderAnalysis {
    pub distinguished_name: String,
    pub owner: String,
    pub owner_sid: String,
    pub group: String,
    pub control_flags: u32,
    pub dacl_entries: Vec<AccessControlEntry>,
    pub sacl_entries: Vec<AccessControlEntry>,
    pub analysis_timestamp: String,
    pub total_aces: usize,
    pub risky_aces: usize,
    pub risk_summary: RiskSummary,
    pub recommendations: Vec<SecurityRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub overall_risk: RiskLevel,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    pub priority: RiskLevel,
    pub title: String,
    pub description: String,
    pub affected_trustee: Option<String>,
    pub remediation_steps: Vec<String>,
}

/// Known dangerous SIDs and their descriptions
pub fn get_known_sids() -> HashMap<String, String> {
    let mut sids = HashMap::new();
    sids.insert("S-1-5-32-544".to_string(), "BUILTIN\\Administrators".to_string());
    sids.insert("S-1-5-32-548".to_string(), "BUILTIN\\Account Operators".to_string());
    sids.insert("S-1-5-32-549".to_string(), "BUILTIN\\Server Operators".to_string());
    sids.insert("S-1-5-32-550".to_string(), "BUILTIN\\Print Operators".to_string());
    sids.insert("S-1-5-32-551".to_string(), "BUILTIN\\Backup Operators".to_string());
    sids.insert("S-1-5-9".to_string(), "Enterprise Domain Controllers".to_string());
    sids.insert("S-1-5-18".to_string(), "SYSTEM".to_string());
    sids.insert("S-1-1-0".to_string(), "Everyone".to_string());
    sids.insert("S-1-5-11".to_string(), "Authenticated Users".to_string());
    sids.insert("S-1-5-7".to_string(), "Anonymous".to_string());
    sids
}

/// Dangerous permissions that could lead to privilege escalation
pub fn get_dangerous_permissions() -> Vec<(&'static str, u32, RiskLevel, &'static str)> {
    vec![
        ("GenericAll", 0x10000000, RiskLevel::Critical, "Full control over object - can modify any attribute or take ownership"),
        ("WriteDacl", 0x00040000, RiskLevel::Critical, "Can modify permissions - could grant themselves full control"),
        ("WriteOwner", 0x00080000, RiskLevel::Critical, "Can change owner - could take ownership of protected accounts"),
        ("GenericWrite", 0x40000000, RiskLevel::High, "Can write to most attributes - potential for privilege escalation"),
        ("WriteProperty", 0x00000020, RiskLevel::High, "Can modify properties - depends on which properties"),
        ("Self", 0x00000008, RiskLevel::Medium, "Self-write permission - can add self to groups"),
        ("Delete", 0x00010000, RiskLevel::Medium, "Can delete the object"),
        ("DeleteTree", 0x00000040, RiskLevel::Medium, "Can delete child objects"),
        ("CreateChild", 0x00000001, RiskLevel::Medium, "Can create child objects"),
        ("DeleteChild", 0x00000002, RiskLevel::Medium, "Can delete child objects"),
        ("ReadProperty", 0x00000010, RiskLevel::Low, "Can read properties"),
        ("ReadControl", 0x00020000, RiskLevel::Info, "Can read security descriptor"),
    ]
}

/// Dangerous object GUIDs for extended rights
pub fn get_dangerous_extended_rights() -> HashMap<String, (&'static str, RiskLevel)> {
    let mut rights = HashMap::new();
    rights.insert(
        "00299570-246d-11d0-a768-00aa006e0529".to_string(),
        ("User-Force-Change-Password", RiskLevel::Critical),
    );
    rights.insert(
        "ab721a54-1e2f-11d0-9819-00aa0040529b".to_string(),
        ("Send-As", RiskLevel::High),
    );
    rights.insert(
        "ab721a56-1e2f-11d0-9819-00aa0040529b".to_string(),
        ("Receive-As", RiskLevel::High),
    );
    rights.insert(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2".to_string(),
        ("DS-Replication-Get-Changes", RiskLevel::Critical),
    );
    rights.insert(
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2".to_string(),
        ("DS-Replication-Get-Changes-All", RiskLevel::Critical),
    );
    rights.insert(
        "89e95b76-444d-4c62-991a-0facbeda640c".to_string(),
        ("DS-Replication-Get-Changes-In-Filtered-Set", RiskLevel::Critical),
    );
    rights
}

/// Trustees that should NOT have permissions on AdminSDHolder
pub fn get_risky_trustees() -> Vec<(&'static str, RiskLevel, &'static str)> {
    vec![
        ("Everyone", RiskLevel::Critical, "Universal group - any user would have these permissions"),
        ("Authenticated Users", RiskLevel::Critical, "Any authenticated user could exploit these permissions"),
        ("Anonymous", RiskLevel::Critical, "Unauthenticated access could lead to immediate compromise"),
        ("Domain Users", RiskLevel::High, "All domain users would inherit these permissions on protected accounts"),
        ("INTERACTIVE", RiskLevel::High, "Any interactive logon user would have access"),
        ("NETWORK", RiskLevel::Medium, "Any network-authenticated user would have access"),
        ("Account Operators", RiskLevel::High, "Should not have permissions on AdminSDHolder"),
        ("Print Operators", RiskLevel::High, "Should not have permissions on AdminSDHolder"),
        ("Server Operators", RiskLevel::High, "Should not have permissions on AdminSDHolder"),
        ("Backup Operators", RiskLevel::Medium, "Has backup privileges - permissions here could be dangerous"),
    ]
}

/// Analyze an ACE for security risks
pub fn analyze_ace(ace: &mut AccessControlEntry) {
    let mut risk_reasons = Vec::new();
    let mut max_risk = RiskLevel::Info;

    // Check for dangerous trustees
    for (trustee_pattern, risk, reason) in get_risky_trustees() {
        if ace.trustee.to_lowercase().contains(&trustee_pattern.to_lowercase()) {
            risk_reasons.push(format!("{}: {}", trustee_pattern, reason));
            if risk > max_risk {
                max_risk = risk;
            }
        }
    }

    // Check for dangerous permissions
    for (perm_name, mask, risk, description) in get_dangerous_permissions() {
        if (ace.access_mask & mask) != 0 {
            ace.permissions.push(perm_name.to_string());
            
            // Only flag if it's an allow ACE
            if ace.ace_type == AceType::AccessAllowed || ace.ace_type == AceType::AccessAllowedObject {
                risk_reasons.push(format!("{}: {}", perm_name, description));
                if risk > max_risk {
                    max_risk = risk;
                }
            }
        }
    }

    // Check for dangerous extended rights
    if let Some(ref object_type) = ace.object_type {
        if let Some((right_name, risk)) = get_dangerous_extended_rights().get(&object_type.to_lowercase()) {
            ace.permissions.push(right_name.to_string());
            risk_reasons.push(format!("Extended right '{}' could enable privilege escalation", right_name));
            if *risk > max_risk {
                max_risk = risk.clone();
            }
        }
    }

    // Check inheritance flags
    if (ace.ace_flags & 0x02) != 0 {
        // CONTAINER_INHERIT_ACE
        risk_reasons.push("Permission inherits to child containers".to_string());
    }
    if (ace.ace_flags & 0x01) != 0 {
        // OBJECT_INHERIT_ACE
        risk_reasons.push("Permission inherits to child objects".to_string());
    }

    ace.risk_level = max_risk;
    ace.risk_reasons = risk_reasons;
}

/// Generate recommendations based on analysis
pub fn generate_recommendations(analysis: &AdminSDHolderAnalysis) -> Vec<SecurityRecommendation> {
    let mut recommendations = Vec::new();

    for ace in &analysis.dacl_entries {
        if ace.risk_level == RiskLevel::Critical || ace.risk_level == RiskLevel::High {
            // Check for specific dangerous scenarios
            if ace.permissions.contains(&"GenericAll".to_string()) {
                recommendations.push(SecurityRecommendation {
                    priority: RiskLevel::Critical,
                    title: "Remove Full Control Permission".to_string(),
                    description: format!(
                        "The trustee '{}' has Full Control (GenericAll) on AdminSDHolder. This permission will propagate to all protected accounts.",
                        ace.trustee
                    ),
                    affected_trustee: Some(ace.trustee.clone()),
                    remediation_steps: vec![
                        "Review if this trustee requires administrative access".to_string(),
                        "If not required, remove the ACE from AdminSDHolder".to_string(),
                        "Wait for SDProp to propagate changes (default: 60 minutes)".to_string(),
                        "Verify changes on protected accounts".to_string(),
                    ],
                });
            }

            if ace.permissions.contains(&"WriteDacl".to_string()) || ace.permissions.contains(&"WriteOwner".to_string()) {
                recommendations.push(SecurityRecommendation {
                    priority: RiskLevel::Critical,
                    title: "Remove Permission Modification Rights".to_string(),
                    description: format!(
                        "The trustee '{}' can modify permissions or ownership. This could be exploited to grant full access to protected accounts.",
                        ace.trustee
                    ),
                    affected_trustee: Some(ace.trustee.clone()),
                    remediation_steps: vec![
                        "Remove WriteDacl and WriteOwner permissions".to_string(),
                        "Audit who made this change and when".to_string(),
                        "Review security logs for suspicious activity".to_string(),
                    ],
                });
            }

            if ace.permissions.iter().any(|p| p.contains("Replication")) {
                recommendations.push(SecurityRecommendation {
                    priority: RiskLevel::Critical,
                    title: "DCSync Attack Vector Detected".to_string(),
                    description: format!(
                        "The trustee '{}' has replication rights. This could enable DCSync attacks to extract password hashes.",
                        ace.trustee
                    ),
                    affected_trustee: Some(ace.trustee.clone()),
                    remediation_steps: vec![
                        "Immediately remove replication rights from non-DC accounts".to_string(),
                        "Check for signs of credential theft".to_string(),
                        "Review recent authentication logs for anomalies".to_string(),
                        "Consider resetting the KRBTGT password twice".to_string(),
                    ],
                });
            }
        }
    }

    // Check owner
    let owner_lower = analysis.owner.to_lowercase();
    if !owner_lower.contains("domain admins") && !owner_lower.contains("enterprise admins") && owner_lower != "system" {
        recommendations.push(SecurityRecommendation {
            priority: RiskLevel::High,
            title: "Verify AdminSDHolder Owner".to_string(),
            description: format!(
                "AdminSDHolder is owned by '{}'. Typically this should be Domain Admins or Enterprise Admins.",
                analysis.owner
            ),
            affected_trustee: Some(analysis.owner.clone()),
            remediation_steps: vec![
                "Verify if the current owner is legitimate".to_string(),
                "Consider resetting ownership to Domain Admins".to_string(),
                "Investigate how ownership was changed".to_string(),
            ],
        });
    }

    // Sort by priority
    recommendations.sort_by(|a, b| a.priority.cmp(&b.priority));
    recommendations
}

/// Calculate overall risk summary
pub fn calculate_risk_summary(aces: &[AccessControlEntry]) -> RiskSummary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for ace in aces {
        if ace.ace_type == AceType::AccessAllowed || ace.ace_type == AceType::AccessAllowedObject {
            match ace.risk_level {
                RiskLevel::Critical => critical += 1,
                RiskLevel::High => high += 1,
                RiskLevel::Medium => medium += 1,
                RiskLevel::Low => low += 1,
                RiskLevel::Info => {}
            }
        }
    }

    let overall_risk = if critical > 0 {
        RiskLevel::Critical
    } else if high > 0 {
        RiskLevel::High
    } else if medium > 0 {
        RiskLevel::Medium
    } else if low > 0 {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    };

    let risk_score = (critical * 40) + (high * 20) + (medium * 10) + (low * 5);

    RiskSummary {
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        overall_risk,
        risk_score: risk_score as u32,
    }
}
