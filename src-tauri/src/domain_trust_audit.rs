// Domain Trust Audit Module - Implements domain trust security checks
// Based on DomainTrustAudits.ps1 functionality

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

impl std::fmt::Display for TrustDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustDirection::Inbound => write!(f, "Inbound"),
            TrustDirection::Outbound => write!(f, "Outbound"),
            TrustDirection::Bidirectional => write!(f, "Bidirectional"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustType {
    External,
    Forest,
    ParentChild,
    TreeRoot,
    Shortcut,
    Realm, // For Kerberos realm trusts
}

impl std::fmt::Display for TrustType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustType::External => write!(f, "External"),
            TrustType::Forest => write!(f, "Forest"),
            TrustType::ParentChild => write!(f, "Parent-Child"),
            TrustType::TreeRoot => write!(f, "Tree-Root"),
            TrustType::Shortcut => write!(f, "Shortcut"),
            TrustType::Realm => write!(f, "Kerberos Realm"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrust {
    pub target_domain: String,
    pub source_domain: String,
    pub direction: TrustDirection,
    pub trust_type: TrustType,
    pub sid_filtering_enabled: bool,
    pub selective_authentication: bool,
    pub is_transitive: bool,
    pub created: String,
    pub modified: String,
    pub trust_attributes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFinding {
    pub category: String,
    pub issue: String,
    pub severity: String,
    pub severity_level: u8,
    pub affected_object: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub details: TrustDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDetails {
    pub target: String,
    pub direction: String,
    pub trust_type: String,
    pub sid_filtering_quarantined: Option<bool>,
    pub selective_authentication: Option<bool>,
    pub created: Option<String>,
    pub last_modified: Option<String>,
    pub days_since_modified: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTrustAudit {
    pub total_trusts: u32,
    pub inbound_trusts: u32,
    pub outbound_trusts: u32,
    pub bidirectional_trusts: u32,
    pub forest_trusts: u32,
    pub external_trusts: u32,
    pub trusts_without_sid_filtering: u32,
    pub trusts_without_selective_auth: u32,
    pub trusts: Vec<DomainTrust>,
    pub findings: Vec<TrustFinding>,
    pub risk_score: u32,
    pub scan_timestamp: String,
    pub recommendations: Vec<TrustRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecommendation {
    pub priority: u8,
    pub title: String,
    pub description: String,
    pub command: String,
    pub steps: Vec<String>,
}

impl DomainTrustAudit {
    pub fn new() -> Self {
        Self {
            total_trusts: 0,
            inbound_trusts: 0,
            outbound_trusts: 0,
            bidirectional_trusts: 0,
            forest_trusts: 0,
            external_trusts: 0,
            trusts_without_sid_filtering: 0,
            trusts_without_selective_auth: 0,
            trusts: Vec::new(),
            findings: Vec::new(),
            risk_score: 0,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            recommendations: Vec::new(),
        }
    }

    pub fn analyze_trust(&mut self, trust: &DomainTrust, local_domain: &str) {
        self.total_trusts += 1;
        
        // Count by direction
        match trust.direction {
            TrustDirection::Inbound => self.inbound_trusts += 1,
            TrustDirection::Outbound => self.outbound_trusts += 1,
            TrustDirection::Bidirectional => self.bidirectional_trusts += 1,
        }

        // Count by type
        match trust.trust_type {
            TrustType::Forest => self.forest_trusts += 1,
            TrustType::External => self.external_trusts += 1,
            _ => {}
        }

        // Check for bidirectional trusts
        if matches!(trust.direction, TrustDirection::Bidirectional) {
            self.findings.push(TrustFinding {
                category: "Domain Trusts".to_string(),
                issue: "Bidirectional Domain Trust".to_string(),
                severity: "Medium".to_string(),
                severity_level: 2,
                affected_object: trust.target_domain.clone(),
                description: format!(
                    "Bidirectional trust exists with domain '{}', allowing authentication in both directions.",
                    trust.target_domain
                ),
                impact: "Increases attack surface as compromise of either domain could affect the other. Consider if bidirectional trust is necessary.".to_string(),
                remediation: "Review if bidirectional trust is required. If not, convert to one-way trust or implement selective authentication.".to_string(),
                details: TrustDetails {
                    target: trust.target_domain.clone(),
                    direction: trust.direction.to_string(),
                    trust_type: trust.trust_type.to_string(),
                    sid_filtering_quarantined: Some(trust.sid_filtering_enabled),
                    selective_authentication: Some(trust.selective_authentication),
                    created: Some(trust.created.clone()),
                    last_modified: Some(trust.modified.clone()),
                    days_since_modified: None,
                },
            });
            self.risk_score += 15;
        }

        // Check SID filtering on external trusts - CRITICAL
        if matches!(trust.trust_type, TrustType::External) && !trust.sid_filtering_enabled {
            self.trusts_without_sid_filtering += 1;
            self.findings.push(TrustFinding {
                category: "Domain Trusts".to_string(),
                issue: "SID Filtering Disabled on External Trust".to_string(),
                severity: "Critical".to_string(),
                severity_level: 4,
                affected_object: trust.target_domain.clone(),
                description: format!(
                    "SID filtering is disabled on external trust with '{}', allowing SID history injection attacks.",
                    trust.target_domain
                ),
                impact: "Attackers in the trusted domain could forge credentials with privileged SIDs from your domain, leading to privilege escalation.".to_string(),
                remediation: format!(
                    "Enable SID filtering: netdom trust {} /domain:{} /quarantine:yes",
                    local_domain, trust.target_domain
                ),
                details: TrustDetails {
                    target: trust.target_domain.clone(),
                    direction: trust.direction.to_string(),
                    trust_type: trust.trust_type.to_string(),
                    sid_filtering_quarantined: Some(false),
                    selective_authentication: None,
                    created: None,
                    last_modified: None,
                    days_since_modified: None,
                },
            });
            self.risk_score += 50;
        }

        // Check selective authentication on forest trusts - HIGH
        if matches!(trust.trust_type, TrustType::Forest) && !trust.selective_authentication {
            self.trusts_without_selective_auth += 1;
            self.findings.push(TrustFinding {
                category: "Domain Trusts".to_string(),
                issue: "Forest Trust Without Selective Authentication".to_string(),
                severity: "High".to_string(),
                severity_level: 3,
                affected_object: trust.target_domain.clone(),
                description: format!(
                    "Forest trust with '{}' does not use selective authentication, granting broad access.",
                    trust.target_domain
                ),
                impact: "All users in the trusted forest can authenticate to resources in this domain without explicit permission.".to_string(),
                remediation: "Enable selective authentication to require explicit permission for cross-forest access.".to_string(),
                details: TrustDetails {
                    target: trust.target_domain.clone(),
                    direction: trust.direction.to_string(),
                    trust_type: trust.trust_type.to_string(),
                    sid_filtering_quarantined: None,
                    selective_authentication: Some(false),
                    created: None,
                    last_modified: None,
                    days_since_modified: None,
                },
            });
            self.risk_score += 30;
        }

        // Check trust password age
        if let Ok(modified) = chrono::DateTime::parse_from_rfc3339(&trust.modified) {
            let now = chrono::Utc::now();
            let duration = now.signed_duration_since(modified);
            let days = duration.num_days() as u32;

            if days > 30 {
                self.findings.push(TrustFinding {
                    category: "Domain Trusts".to_string(),
                    issue: "Trust Password Not Recently Rotated".to_string(),
                    severity: "Low".to_string(),
                    severity_level: 1,
                    affected_object: trust.target_domain.clone(),
                    description: format!(
                        "Trust with '{}' has not been modified in {} days. Trust passwords should rotate automatically every 30 days.",
                        trust.target_domain, days
                    ),
                    impact: "May indicate trust relationship issues or lack of maintenance.".to_string(),
                    remediation: format!(
                        "Verify trust health: netdom trust {} /domain:{} /verify",
                        local_domain, trust.target_domain
                    ),
                    details: TrustDetails {
                        target: trust.target_domain.clone(),
                        direction: trust.direction.to_string(),
                        trust_type: trust.trust_type.to_string(),
                        sid_filtering_quarantined: None,
                        selective_authentication: None,
                        created: None,
                        last_modified: Some(trust.modified.clone()),
                        days_since_modified: Some(days),
                    },
                });
                self.risk_score += 5;
            }
        }
    }

    pub fn generate_recommendations(&mut self, local_domain: &str) {
        let mut recommendations = Vec::new();

        if self.trusts_without_sid_filtering > 0 {
            recommendations.push(TrustRecommendation {
                priority: 1,
                title: "Enable SID Filtering on External Trusts".to_string(),
                description: format!(
                    "{} external trust(s) have SID filtering disabled, exposing the domain to SID history injection attacks.",
                    self.trusts_without_sid_filtering
                ),
                command: format!("netdom trust {} /domain:<TRUSTED_DOMAIN> /quarantine:yes", local_domain),
                steps: vec![
                    "Identify all trusts without SID filtering".to_string(),
                    "Verify applications don't rely on SID history for cross-domain access".to_string(),
                    "Enable SID filtering using: netdom trust <YOUR_DOMAIN> /domain:<TRUSTED_DOMAIN> /quarantine:yes".to_string(),
                    "Test cross-domain authentication after enabling".to_string(),
                    "Monitor for access issues and adjust if needed".to_string(),
                ],
            });
        }

        if self.trusts_without_selective_auth > 0 {
            recommendations.push(TrustRecommendation {
                priority: 2,
                title: "Enable Selective Authentication on Forest Trusts".to_string(),
                description: format!(
                    "{} forest trust(s) allow any user from trusted forests to authenticate to any resource.",
                    self.trusts_without_selective_auth
                ),
                command: "Active Directory Domains and Trusts > Properties > Trust > Selective Authentication".to_string(),
                steps: vec![
                    "Open Active Directory Domains and Trusts".to_string(),
                    "Right-click your domain and select Properties".to_string(),
                    "Go to Trusts tab and select the forest trust".to_string(),
                    "Click Properties, then select 'Selective authentication'".to_string(),
                    "Grant 'Allowed to authenticate' permission on specific resources for trusted users".to_string(),
                ],
            });
        }

        if self.bidirectional_trusts > 0 {
            recommendations.push(TrustRecommendation {
                priority: 3,
                title: "Review Bidirectional Trust Requirements".to_string(),
                description: format!(
                    "{} bidirectional trust(s) found. Bidirectional trusts increase the attack surface.",
                    self.bidirectional_trusts
                ),
                command: "Get-ADTrust -Filter * | Where-Object {$_.Direction -eq 'Bidirectional'}".to_string(),
                steps: vec![
                    "List all bidirectional trusts".to_string(),
                    "For each trust, determine if bidirectional access is actually required".to_string(),
                    "If only one-way access is needed, recreate as a one-way trust".to_string(),
                    "Document the business justification for remaining bidirectional trusts".to_string(),
                    "Implement additional monitoring for cross-domain authentications".to_string(),
                ],
            });
        }

        self.recommendations = recommendations;
    }
}
