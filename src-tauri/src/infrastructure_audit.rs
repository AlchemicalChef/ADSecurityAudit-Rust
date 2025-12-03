//! Infrastructure Security Audit Module
//!
//! Evaluates network and protocol security settings in Active Directory environments:
//! - LDAP signing and channel binding configuration
//! - Anonymous LDAP access testing
//! - Print Spooler service exposure on Domain Controllers
//! - Authentication Policies and Silos
//! - Pre-Windows 2000 Compatible Access group membership
//! - Fine-Grained Password Policies (PSOs)
//!
//! # Security Checks
//!
//! | Check | Risk Level | Attack Vector |
//! |-------|------------|---------------|
//! | Anonymous LDAP | High | Unauthenticated AD enumeration |
//! | Print Spooler on DCs | High | PrintNightmare, SpoolSample attacks |
//! | No Authentication Silos | High | Credential theft, lateral movement |
//! | Pre-2000 Access with Everyone | Critical | Anonymous enumeration |
//! | Weak PSOs | Medium | Password policy bypass |

use serde::{Deserialize, Serialize};

// Use shared FindingSeverity and SeverityCounts from common_types
use crate::common_types::{FindingSeverity, SeverityCounts};

/// Type alias for backward compatibility - use FindingSeverity from common_types
pub type InfrastructureSeverity = FindingSeverity;

/// Infrastructure security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureFinding {
    pub id: String,
    pub category: String,
    pub issue: String,
    pub severity: InfrastructureSeverity,
    pub severity_level: u8,
    pub affected_object: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub details: serde_json::Value,
}

impl InfrastructureFinding {
    pub fn new(
        category: &str,
        issue: &str,
        severity: InfrastructureSeverity,
        affected_object: &str,
        description: &str,
        impact: &str,
        remediation: &str,
        details: serde_json::Value,
    ) -> Self {
        let severity_level = severity.level();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            category: category.to_string(),
            issue: issue.to_string(),
            severity,
            severity_level,
            affected_object: affected_object.to_string(),
            description: description.to_string(),
            impact: impact.to_string(),
            remediation: remediation.to_string(),
            details,
        }
    }
}

/// Complete infrastructure security audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureAudit {
    pub ldap_security: LdapSecurityStatus,
    pub print_spooler_exposure: Vec<PrintSpoolerExposure>,
    pub auth_silos: AuthSiloStatus,
    pub pre_2000_access: PreWindows2000Status,
    pub password_policies: Vec<FineGrainedPasswordPolicy>,
    pub findings: Vec<InfrastructureFinding>,
    pub total_findings: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub overall_risk_score: u32,
    pub risk_level: String,
    pub audit_timestamp: String,
}

impl InfrastructureAudit {
    /// Create a new InfrastructureAudit with counts calculated from findings
    pub fn new(
        ldap_security: LdapSecurityStatus,
        print_spooler_exposure: Vec<PrintSpoolerExposure>,
        auth_silos: AuthSiloStatus,
        pre_2000_access: PreWindows2000Status,
        password_policies: Vec<FineGrainedPasswordPolicy>,
        findings: Vec<InfrastructureFinding>,
    ) -> Self {
        // Calculate severity counts using shared utility
        let counts = SeverityCounts::from_iter(findings.iter().map(|f| &f.severity));
        let (critical_count, high_count, medium_count, low_count) =
            (counts.critical, counts.high, counts.medium, counts.low);

        let (overall_risk_score, risk_level) = calculate_infrastructure_risk_score(&findings);

        Self {
            ldap_security,
            print_spooler_exposure,
            auth_silos,
            pre_2000_access,
            password_policies,
            total_findings: findings.len() as u32,
            findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            overall_risk_score,
            risk_level,
            audit_timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for InfrastructureAudit {
    fn default() -> Self {
        Self {
            ldap_security: LdapSecurityStatus::default(),
            print_spooler_exposure: Vec::new(),
            auth_silos: AuthSiloStatus::default(),
            pre_2000_access: PreWindows2000Status::default(),
            password_policies: Vec::new(),
            findings: Vec::new(),
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            overall_risk_score: 0,
            risk_level: "Low".to_string(),
            audit_timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// LDAP security configuration status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapSecurityStatus {
    /// Whether LDAP signing is required (from GPO/registry)
    pub signing_required: Option<bool>,
    /// Whether LDAP channel binding is required
    pub channel_binding_required: Option<bool>,
    /// Whether anonymous LDAP bind is allowed
    pub anonymous_bind_allowed: bool,
    /// dsHeuristics attribute value (controls various AD behaviors)
    pub ds_heuristics: Option<String>,
    /// 7th character of dsHeuristics - controls anonymous access
    pub anonymous_access_setting: Option<char>,
}

impl Default for LdapSecurityStatus {
    fn default() -> Self {
        Self {
            signing_required: None,
            channel_binding_required: None,
            anonymous_bind_allowed: false,
            ds_heuristics: None,
            anonymous_access_setting: None,
        }
    }
}

/// Print Spooler service exposure on a Domain Controller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrintSpoolerExposure {
    /// Domain Controller name
    pub dc_name: String,
    /// Distinguished name of the DC computer object
    pub distinguished_name: String,
    /// DNS hostname
    pub dns_hostname: Option<String>,
    /// Whether Print Spooler-related SPNs are present
    pub spooler_spn_present: bool,
    /// List of SPNs that indicate spooler presence
    pub spooler_spns: Vec<String>,
    /// Operating system of the DC
    pub operating_system: Option<String>,
}

/// Authentication Silo configuration status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSiloStatus {
    /// Number of authentication silos configured
    pub silos_configured: usize,
    /// List of configured silos with details
    pub silos: Vec<AuthenticationSilo>,
    /// List of Tier 0 accounts not protected by any silo
    pub tier0_accounts_not_in_silo: Vec<UnprotectedTier0Account>,
    /// Whether authentication silos feature is being used
    pub silos_in_use: bool,
}

impl Default for AuthSiloStatus {
    fn default() -> Self {
        Self {
            silos_configured: 0,
            silos: vec![],
            tier0_accounts_not_in_silo: vec![],
            silos_in_use: false,
        }
    }
}

/// Individual authentication silo configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSilo {
    pub name: String,
    pub distinguished_name: String,
    pub description: Option<String>,
    /// Number of accounts assigned to this silo
    pub member_count: usize,
    /// TGT lifetime in minutes (shorter is more secure)
    pub tgt_lifetime_minutes: Option<u32>,
    /// Whether the silo is enforced or audit-only
    pub is_enforced: bool,
    /// Members of the silo
    pub members: Vec<String>,
}

/// Tier 0 account not protected by authentication silo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnprotectedTier0Account {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub is_domain_admin: bool,
    pub is_enterprise_admin: bool,
    pub is_schema_admin: bool,
}

/// Pre-Windows 2000 Compatible Access group status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreWindows2000Status {
    /// Whether the group exists and has members
    pub group_exists: bool,
    /// Whether the group contains dangerous members like Everyone or Anonymous
    pub has_dangerous_members: bool,
    /// List of group members
    pub members: Vec<String>,
    /// Whether Anonymous Logon is a member
    pub anonymous_logon_member: bool,
    /// Whether Everyone is a member
    pub everyone_member: bool,
    /// Whether Authenticated Users is a member (this is acceptable)
    pub authenticated_users_only: bool,
}

impl Default for PreWindows2000Status {
    fn default() -> Self {
        Self {
            group_exists: false,
            has_dangerous_members: false,
            members: vec![],
            anonymous_logon_member: false,
            everyone_member: false,
            authenticated_users_only: false,
        }
    }
}

/// Fine-Grained Password Policy (Password Settings Object)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FineGrainedPasswordPolicy {
    pub name: String,
    pub distinguished_name: String,
    /// Lower precedence = higher priority
    pub precedence: u32,
    pub min_password_length: u32,
    pub password_history_count: u32,
    /// Maximum password age in days (0 = never expires)
    pub max_password_age_days: u32,
    /// Minimum password age in days
    pub min_password_age_days: u32,
    pub complexity_enabled: bool,
    pub reversible_encryption_enabled: bool,
    pub lockout_threshold: u32,
    pub lockout_duration_minutes: u32,
    pub lockout_observation_window_minutes: u32,
    /// Users and groups this PSO applies to
    pub applies_to: Vec<String>,
    /// Whether this PSO is weaker than the Default Domain Policy
    pub is_weaker_than_domain: bool,
    /// Specific weaknesses compared to domain policy
    pub weaknesses: Vec<String>,
}

/// Infrastructure security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureRecommendation {
    pub priority: InfrastructureSeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected_count: usize,
    pub remediation_steps: Vec<String>,
    pub reference: Option<String>,
}

/// Generate recommendations based on infrastructure audit results
pub fn generate_infrastructure_recommendations(
    audit: &InfrastructureAudit,
) -> Vec<InfrastructureRecommendation> {
    let mut recommendations = Vec::new();

    // Anonymous LDAP access
    if audit.ldap_security.anonymous_bind_allowed {
        recommendations.push(InfrastructureRecommendation {
            priority: InfrastructureSeverity::High,
            category: "LDAP Security".to_string(),
            title: "Disable Anonymous LDAP Access".to_string(),
            description: "Anonymous LDAP bind is allowed, enabling unauthenticated enumeration of AD objects.".to_string(),
            affected_count: 1,
            remediation_steps: vec![
                "Set dsHeuristics 7th character to '0' to disable anonymous access".to_string(),
                "Review and restrict LDAP permissions for Anonymous Logon".to_string(),
                "Enable LDAP signing: GPO > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain controller: LDAP server signing requirements' = Require signing".to_string(),
            ],
            reference: Some("https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled".to_string()),
        });
    }

    // Print Spooler on DCs
    let dcs_with_spooler: Vec<_> = audit.print_spooler_exposure.iter()
        .filter(|p| p.spooler_spn_present)
        .collect();
    if !dcs_with_spooler.is_empty() {
        recommendations.push(InfrastructureRecommendation {
            priority: InfrastructureSeverity::High,
            category: "Service Security".to_string(),
            title: "Disable Print Spooler on Domain Controllers".to_string(),
            description: format!(
                "{} Domain Controller(s) have Print Spooler indicators. This service is vulnerable to PrintNightmare and SpoolSample attacks.",
                dcs_with_spooler.len()
            ),
            affected_count: dcs_with_spooler.len(),
            remediation_steps: vec![
                "Disable Print Spooler service on all DCs: Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled".to_string(),
                "Verify with: Get-Service -Name Spooler -ComputerName <DC>".to_string(),
                "For print server requirements, use dedicated print servers instead of DCs".to_string(),
            ],
            reference: Some("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527".to_string()),
        });
    }

    // Authentication Silos
    if !audit.auth_silos.silos_in_use && !audit.auth_silos.tier0_accounts_not_in_silo.is_empty() {
        recommendations.push(InfrastructureRecommendation {
            priority: InfrastructureSeverity::High,
            category: "Privileged Access".to_string(),
            title: "Implement Authentication Silos for Tier 0 Accounts".to_string(),
            description: format!(
                "No authentication silos are configured. {} Tier 0 accounts lack silo protection, allowing credential use from any system.",
                audit.auth_silos.tier0_accounts_not_in_silo.len()
            ),
            affected_count: audit.auth_silos.tier0_accounts_not_in_silo.len(),
            remediation_steps: vec![
                "Create Privileged Access Workstations (PAWs) for administrative tasks".to_string(),
                "Create authentication policy: New-ADAuthenticationPolicy -Name 'Tier0Policy' -UserTGTLifetimeMins 240 -Enforce".to_string(),
                "Create authentication silo: New-ADAuthenticationPolicySilo -Name 'Tier0Silo' -UserAuthenticationPolicy 'Tier0Policy' -Enforce".to_string(),
                "Add Tier 0 accounts: Set-ADAccountAuthenticationPolicySilo -Identity <account> -AuthenticationPolicySilo 'Tier0Silo'".to_string(),
            ],
            reference: Some("https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos".to_string()),
        });
    }

    // Pre-Windows 2000 Compatible Access
    if audit.pre_2000_access.has_dangerous_members {
        recommendations.push(InfrastructureRecommendation {
            priority: InfrastructureSeverity::Critical,
            category: "Access Control".to_string(),
            title: "Remove Dangerous Members from Pre-Windows 2000 Compatible Access".to_string(),
            description: format!(
                "Pre-Windows 2000 Compatible Access group contains dangerous members (Everyone or Anonymous Logon), allowing anonymous enumeration of all AD users and groups."
            ),
            affected_count: 1,
            remediation_steps: vec![
                "Remove 'Everyone' from the group if present".to_string(),
                "Remove 'Anonymous Logon' from the group if present".to_string(),
                "Verify only 'Authenticated Users' remains if legacy compatibility is needed".to_string(),
                "Test applications after changes to ensure compatibility".to_string(),
            ],
            reference: Some("https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sidname-translation".to_string()),
        });
    }

    // Weak Fine-Grained Password Policies
    let weak_psos: Vec<_> = audit.password_policies.iter()
        .filter(|p| p.is_weaker_than_domain)
        .collect();
    if !weak_psos.is_empty() {
        recommendations.push(InfrastructureRecommendation {
            priority: InfrastructureSeverity::Medium,
            category: "Password Policy".to_string(),
            title: "Review Weak Fine-Grained Password Policies".to_string(),
            description: format!(
                "{} Fine-Grained Password Policies (PSOs) are weaker than the Default Domain Policy, potentially allowing weaker passwords for specific users/groups.",
                weak_psos.len()
            ),
            affected_count: weak_psos.len(),
            remediation_steps: vec![
                "Review each PSO to determine if weaker settings are justified".to_string(),
                "Update PSOs to meet or exceed domain policy minimums".to_string(),
                "Document business justification for any exceptions".to_string(),
                "Consider removing unnecessary PSOs".to_string(),
            ],
            reference: Some("https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine-grained-password-policies".to_string()),
        });
    }

    recommendations
}

/// Calculate overall risk score from infrastructure findings
/// Uses diminishing returns (sqrt scaling) to prevent score saturation
pub fn calculate_infrastructure_risk_score(findings: &[InfrastructureFinding]) -> (u32, String) {
    if findings.is_empty() {
        return (0, "Low".to_string());
    }

    // Calculate base score from severity weights
    let base_score: u32 = findings.iter().map(|f| match f.severity {
        InfrastructureSeverity::Critical => 30,
        InfrastructureSeverity::High => 20,
        InfrastructureSeverity::Medium => 10,
        InfrastructureSeverity::Low => 5,
        InfrastructureSeverity::Informational => 0,
    }).sum();

    // Apply diminishing returns using sqrt scaling
    // This allows distinguishing between few vs many findings
    // sqrt(base) * 10 gives: 30->55, 60->77, 90->95, 150->122->100
    let score = ((base_score as f64).sqrt() * 10.0).min(100.0) as u32;

    let risk_level = match score {
        0..=25 => "Low",
        26..=50 => "Medium",
        51..=75 => "High",
        _ => "Critical",
    };

    (score, risk_level.to_string())
}
