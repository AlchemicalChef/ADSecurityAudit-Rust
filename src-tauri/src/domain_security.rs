//! Domain Security Audit Module
//! Evaluates domain security settings including password policies, functional levels,
//! legacy systems, Azure AD SSO, and AD Recycle Bin status.
//!
// Allow unused code - legacy OS patterns for future detection
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// Use shared FindingSeverity from common_types
use crate::common_types::FindingSeverity;

/// Type alias for backward compatibility - use FindingSeverity from common_types
pub type Severity = FindingSeverity;

/// Security finding category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    DomainSecurity,
    PasswordPolicy,
    FunctionalLevel,
    LegacySystems,
    AzureADSSO,
    RecycleBin,
    GroupPolicy,
    SysvolPermissions,
}

/// A security finding from the audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub category: FindingCategory,
    pub issue: String,
    pub severity: Severity,
    pub severity_level: u8,
    pub affected_object: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub details: serde_json::Value,
}

impl SecurityFinding {
    pub fn new(
        category: FindingCategory,
        issue: &str,
        severity: Severity,
        affected_object: &str,
        description: &str,
        impact: &str,
        remediation: &str,
        details: serde_json::Value,
    ) -> Self {
        let severity_level = severity.level();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            category,
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

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_password_length: u32,
    pub password_history_count: u32,
    pub max_password_age_days: u32,
    pub min_password_age_days: u32,
    pub complexity_enabled: bool,
    pub reversible_encryption_enabled: bool,
    pub lockout_threshold: u32,
    pub lockout_duration_minutes: u32,
    pub lockout_observation_window_minutes: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_password_length: 7,
            password_history_count: 24,
            max_password_age_days: 42,
            min_password_age_days: 1,
            complexity_enabled: true,
            reversible_encryption_enabled: false,
            lockout_threshold: 0,
            lockout_duration_minutes: 30,
            lockout_observation_window_minutes: 30,
        }
    }
}

/// Domain functional level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionalLevel {
    Windows2000,
    Windows2003,
    Windows2008,
    Windows2008R2,
    Windows2012,
    Windows2012R2,
    Windows2016,
    Windows2019,
    Windows2022,
    Unknown(String),
}

impl FunctionalLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "windows2000domain" | "0" => FunctionalLevel::Windows2000,
            "windows2003domain" | "2" => FunctionalLevel::Windows2003,
            "windows2008domain" | "3" => FunctionalLevel::Windows2008,
            "windows2008r2domain" | "4" => FunctionalLevel::Windows2008R2,
            "windows2012domain" | "5" => FunctionalLevel::Windows2012,
            "windows2012r2domain" | "6" => FunctionalLevel::Windows2012R2,
            "windows2016domain" | "7" => FunctionalLevel::Windows2016,
            "windows2019domain" | "windows2022domain" => FunctionalLevel::Windows2019,
            _ => FunctionalLevel::Unknown(s.to_string()),
        }
    }

    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            FunctionalLevel::Windows2000
                | FunctionalLevel::Windows2003
                | FunctionalLevel::Windows2008
                | FunctionalLevel::Windows2008R2
                | FunctionalLevel::Windows2012
        )
    }

    pub fn display_name(&self) -> String {
        match self {
            FunctionalLevel::Windows2000 => "Windows 2000".to_string(),
            FunctionalLevel::Windows2003 => "Windows Server 2003".to_string(),
            FunctionalLevel::Windows2008 => "Windows Server 2008".to_string(),
            FunctionalLevel::Windows2008R2 => "Windows Server 2008 R2".to_string(),
            FunctionalLevel::Windows2012 => "Windows Server 2012".to_string(),
            FunctionalLevel::Windows2012R2 => "Windows Server 2012 R2".to_string(),
            FunctionalLevel::Windows2016 => "Windows Server 2016".to_string(),
            FunctionalLevel::Windows2019 => "Windows Server 2019".to_string(),
            FunctionalLevel::Windows2022 => "Windows Server 2022".to_string(),
            FunctionalLevel::Unknown(s) => s.clone(),
        }
    }
}

/// Legacy computer detected in the domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyComputer {
    pub name: String,
    pub distinguished_name: String,
    pub operating_system: String,
    pub operating_system_version: Option<String>,
    pub last_logon: Option<String>,
    pub is_enabled: bool,
}

/// Azure AD SSO Account status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSsoAccountStatus {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub password_last_set: Option<String>,
    pub password_age_days: Option<u64>,
    pub is_enabled: bool,
    pub needs_rotation: bool,
}

/// AD Optional Feature status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionalFeatureStatus {
    pub name: String,
    pub is_enabled: bool,
    pub enabled_scopes: Vec<String>,
}

/// Complete domain security audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSecurityAudit {
    pub domain_name: String,
    pub domain_dns_root: String,
    pub domain_functional_level: String,
    pub forest_functional_level: String,
    pub password_policy: PasswordPolicy,
    pub recycle_bin_enabled: bool,
    pub optional_features: Vec<OptionalFeatureStatus>,
    pub legacy_computers: Vec<LegacyComputer>,
    pub azure_sso_accounts: Vec<AzureSsoAccountStatus>,
    pub findings: Vec<SecurityFinding>,
    pub total_findings: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub overall_risk_score: u32,
    pub risk_level: String,
    pub audit_timestamp: String,
}

/// Evaluates password policy against security best practices
pub fn evaluate_password_policy(policy: &PasswordPolicy, domain: &str) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // Check minimum password length
    if policy.min_password_length < 14 {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "Weak Minimum Password Length",
            if policy.min_password_length < 8 { Severity::Critical } else { Severity::High },
            "Default Domain Password Policy",
            &format!(
                "Minimum password length is set to {} characters.",
                policy.min_password_length
            ),
            "Short passwords are easier to crack through brute-force and dictionary attacks.",
            &format!(
                "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity {}",
                domain
            ),
            serde_json::json!({
                "current_length": policy.min_password_length,
                "recommended_length": 14
            }),
        ));
    }

    // Check complexity enabled
    if !policy.complexity_enabled {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "Password Complexity Disabled",
            Severity::Critical,
            "Default Domain Password Policy",
            "Password complexity requirements are disabled.",
            "Users can set simple, easily guessable passwords, significantly increasing the risk of compromise.",
            &format!(
                "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true -Identity {}",
                domain
            ),
            serde_json::json!({
                "complexity_enabled": policy.complexity_enabled
            }),
        ));
    }

    // Check reversible encryption
    if policy.reversible_encryption_enabled {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "Reversible Encryption Enabled Domain-Wide",
            Severity::Critical,
            "Default Domain Password Policy",
            "Reversible password encryption is enabled at the domain level.",
            "All passwords are stored in a format equivalent to plaintext, making them easily retrievable by attackers.",
            &format!(
                "Disable reversible encryption immediately: Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled $false -Identity {}",
                domain
            ),
            serde_json::json!({
                "reversible_encryption_enabled": policy.reversible_encryption_enabled
            }),
        ));
    }

    // Check account lockout policy
    if policy.lockout_threshold == 0 {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "No Account Lockout Policy",
            Severity::High,
            "Default Domain Password Policy",
            "Account lockout threshold is set to 0 (disabled).",
            "Attackers can attempt unlimited password guesses without triggering a lockout, enabling brute-force attacks.",
            &format!(
                "Enable account lockout: Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00 -Identity {}",
                domain
            ),
            serde_json::json!({
                "lockout_threshold": policy.lockout_threshold,
                "recommended_threshold": 5
            }),
        ));
    } else if policy.lockout_threshold > 10 {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "Weak Account Lockout Threshold",
            Severity::Medium,
            "Default Domain Password Policy",
            &format!(
                "Account lockout threshold is set to {} attempts, which is too permissive.",
                policy.lockout_threshold
            ),
            "High lockout thresholds allow attackers more password guessing attempts before lockout.",
            &format!(
                "Lower lockout threshold: Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -Identity {}",
                domain
            ),
            serde_json::json!({
                "current_threshold": policy.lockout_threshold,
                "recommended_threshold": 5
            }),
        ));
    }

    // Check password history
    if policy.password_history_count < 24 {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "Insufficient Password History",
            Severity::Medium,
            "Default Domain Password Policy",
            &format!(
                "Password history is set to remember {} passwords.",
                policy.password_history_count
            ),
            "Users may be able to reuse recent passwords, reducing the effectiveness of password rotation policies.",
            &format!(
                "Increase password history: Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24 -Identity {}",
                domain
            ),
            serde_json::json!({
                "current_history": policy.password_history_count,
                "recommended_history": 24
            }),
        ));
    }

    // Check max password age
    if policy.max_password_age_days > 365 || policy.max_password_age_days == 0 {
        findings.push(SecurityFinding::new(
            FindingCategory::PasswordPolicy,
            "Excessive Password Age",
            Severity::Medium,
            "Default Domain Password Policy",
            &format!(
                "Maximum password age is set to {} days (0 = never expires).",
                policy.max_password_age_days
            ),
            "Passwords that never expire or have very long lifetimes increase the risk of compromise over time.",
            &format!(
                "Set reasonable password age: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00 -Identity {}",
                domain
            ),
            serde_json::json!({
                "current_max_age": policy.max_password_age_days,
                "recommended_max_age": 90
            }),
        ));
    }

    findings
}

/// Evaluates functional level security
pub fn evaluate_functional_level(level: &FunctionalLevel, forest_level: &FunctionalLevel) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    if level.is_deprecated() {
        findings.push(SecurityFinding::new(
            FindingCategory::FunctionalLevel,
            "Outdated Domain Functional Level",
            Severity::Medium,
            "Domain Functional Level",
            &format!(
                "Domain functional level is set to '{}', which is outdated.",
                level.display_name()
            ),
            "Older functional levels lack modern security features and may support deprecated authentication protocols.",
            "Raise domain functional level after ensuring all DCs are running a supported OS: Set-ADDomainMode -DomainMode Windows2016Domain (or higher)",
            serde_json::json!({
                "current_level": level.display_name(),
                "forest_level": forest_level.display_name(),
                "recommended_level": "Windows Server 2016 or higher"
            }),
        ));
    }

    if forest_level.is_deprecated() {
        findings.push(SecurityFinding::new(
            FindingCategory::FunctionalLevel,
            "Outdated Forest Functional Level",
            Severity::Medium,
            "Forest Functional Level",
            &format!(
                "Forest functional level is set to '{}', which is outdated.",
                forest_level.display_name()
            ),
            "Older forest functional levels prevent the use of modern security features across the entire forest.",
            "Raise forest functional level: Set-ADForestMode -ForestMode Windows2016Forest (requires all domains to be at Windows Server 2016 level)",
            serde_json::json!({
                "current_forest_level": forest_level.display_name(),
                "recommended_level": "Windows Server 2016 or higher"
            }),
        ));
    }

    findings
}

/// Legacy operating systems to check for
pub const LEGACY_OS_PATTERNS: &[&str] = &[
    "Windows XP",
    "Windows Vista",
    "Windows 7",
    "Windows 8",
    "Windows 8.1",
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2012",
];

/// Evaluates legacy computers in the domain
pub fn evaluate_legacy_computers(computers: &[LegacyComputer]) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    if !computers.is_empty() {
        let active_legacy: Vec<_> = computers.iter().filter(|c| c.is_enabled).collect();
        
        if !active_legacy.is_empty() {
            findings.push(SecurityFinding::new(
                FindingCategory::LegacySystems,
                "Legacy Operating Systems in Domain",
                Severity::High,
                "Domain Computers",
                &format!(
                    "Found {} computer(s) running unsupported/legacy operating systems ({} active).",
                    computers.len(),
                    active_legacy.len()
                ),
                "Legacy systems lack security updates and are vulnerable to known exploits, providing easy entry points for attackers.",
                "Upgrade or isolate legacy systems. Remove computer accounts for decommissioned systems. Consider network segmentation for systems that cannot be upgraded.",
                serde_json::json!({
                    "total_count": computers.len(),
                    "active_count": active_legacy.len(),
                    "computers": computers.iter().take(20).map(|c| serde_json::json!({
                        "name": c.name,
                        "os": c.operating_system,
                        "enabled": c.is_enabled,
                        "last_logon": c.last_logon
                    })).collect::<Vec<_>>()
                }),
            ));
        }
    }

    findings
}

/// Evaluates Azure AD SSO account status
pub fn evaluate_azure_sso_accounts(accounts: &[AzureSsoAccountStatus]) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    for account in accounts {
        if account.needs_rotation {
            findings.push(SecurityFinding::new(
                FindingCategory::AzureADSSO,
                "Stale AzureADSSOACC Kerberos Key",
                Severity::High,
                &account.sam_account_name,
                "Azure AD Seamless SSO computer account password has not been rotated within the last 30 days.",
                "Stale Kerberos decryption keys increase the risk of credential compromise for Seamless SSO.",
                "Roll over the Azure AD Seamless SSO Kerberos decryption key using Azure AD Connect or the Update-AzureADSSOForest PowerShell cmdlet.",
                serde_json::json!({
                    "password_last_set": account.password_last_set,
                    "password_age_days": account.password_age_days,
                    "reference": "https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key"
                }),
            ));
        }
    }

    findings
}

/// Evaluates AD Recycle Bin status
pub fn evaluate_recycle_bin(enabled: bool) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    if !enabled {
        findings.push(SecurityFinding::new(
            FindingCategory::RecycleBin,
            "AD Recycle Bin Not Enabled",
            Severity::Low,
            "AD Recycle Bin Feature",
            "Active Directory Recycle Bin is not enabled.",
            "Deleted AD objects cannot be easily restored, making recovery from accidental deletions or attacks more difficult.",
            "Enable AD Recycle Bin: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <ForestDNSName>",
            serde_json::json!({
                "feature": "Recycle Bin",
                "status": "Disabled"
            }),
        ));
    }

    findings
}

/// Calculates overall risk score from findings
pub fn calculate_risk_score(findings: &[SecurityFinding]) -> (u32, String) {
    let mut score: u32 = 0;
    
    for finding in findings {
        score += match finding.severity {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
            Severity::Informational => 0,
        };
    }

    // Cap at 100
    let score = score.min(100);

    let risk_level = match score {
        0..=20 => "Low",
        21..=40 => "Medium",
        41..=70 => "High",
        _ => "Critical",
    };

    (score, risk_level.to_string())
}
