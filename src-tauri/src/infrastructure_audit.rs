//! Infrastructure Security Audit Module
//!
//! Evaluates network and protocol security settings in Active Directory environments:
//! - LDAP signing and channel binding configuration
//! - Anonymous LDAP access testing
//! - Print Spooler service exposure on Domain Controllers
//! - Authentication Policies and Silos
//! - Pre-Windows 2000 Compatible Access group membership
//! - Fine-Grained Password Policies (PSOs)
//! - Kerberos encryption settings (RC4 weak encryption detection)
//! - Computer account password age (stale accounts)
//! - DCShadow attack indicators (rogue DC SPNs)
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
//! | RC4 Kerberos Encryption | High | Offline credential cracking |
//! | Stale Computer Accounts | Medium | Orphaned systems, lateral movement |
//! | DCShadow Indicators | Critical | Rogue DC injection, persistence |

use serde::{Deserialize, Serialize};

// Use shared FindingSeverity and SeverityCounts from common_types
use crate::common_types::{FindingSeverity, SeverityCounts};

/// Type alias for backward compatibility - use FindingSeverity from common_types
pub(crate) type InfrastructureSeverity = FindingSeverity;

/// Infrastructure security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InfrastructureFinding {
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
    pub(crate) fn new(
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
pub(crate) struct InfrastructureAudit {
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
    pub(crate) fn new(
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
pub(crate) struct LdapSecurityStatus {
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
pub(crate) struct PrintSpoolerExposure {
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
pub(crate) struct AuthSiloStatus {
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
pub(crate) struct AuthenticationSilo {
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
pub(crate) struct UnprotectedTier0Account {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub is_domain_admin: bool,
    pub is_enterprise_admin: bool,
    pub is_schema_admin: bool,
}

/// Pre-Windows 2000 Compatible Access group status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PreWindows2000Status {
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
pub(crate) struct FineGrainedPasswordPolicy {
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

// ==========================================
// Phase 1 Gap Analysis: New Security Checks
// ==========================================

/// Kerberos encryption configuration for an account
/// Detects weak RC4 encryption that is vulnerable to offline cracking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct KerberosEncryptionStatus {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub account_type: String,
    /// Raw msDS-SupportedEncryptionTypes value
    pub supported_encryption_types: u32,
    /// Whether RC4_HMAC_MD5 (0x4) is enabled - WEAK
    pub rc4_enabled: bool,
    /// Whether AES128 (0x8) is enabled
    pub aes128_enabled: bool,
    /// Whether AES256 (0x10) is enabled - STRONG
    pub aes256_enabled: bool,
    /// Whether only weak encryption is supported (RC4 only, no AES)
    pub only_weak_encryption: bool,
    /// Whether this is a privileged account (increases severity)
    pub is_privileged: bool,
    /// Whether this is a service account with SPN
    pub has_spn: bool,
}

impl KerberosEncryptionStatus {
    /// Parse msDS-SupportedEncryptionTypes attribute value
    ///
    /// Encryption type flags:
    /// - 0x1: DES-CBC-CRC (deprecated, extremely weak)
    /// - 0x2: DES-CBC-MD5 (deprecated, extremely weak)
    /// - 0x4: RC4-HMAC-MD5 (weak, vulnerable to offline cracking)
    /// - 0x8: AES128-CTS-HMAC-SHA1-96 (strong)
    /// - 0x10: AES256-CTS-HMAC-SHA1-96 (strongest)
    #[allow(dead_code)]
    pub(crate) fn from_encryption_types(
        sam_account_name: &str,
        distinguished_name: &str,
        account_type: &str,
        encryption_types: u32,
        is_privileged: bool,
        has_spn: bool,
    ) -> Self {
        let rc4_enabled = (encryption_types & 0x4) != 0;
        let aes128_enabled = (encryption_types & 0x8) != 0;
        let aes256_enabled = (encryption_types & 0x10) != 0;

        // Only weak if RC4 is the ONLY modern encryption (no AES)
        // or if encryption_types is 0 (uses defaults which include RC4)
        let only_weak_encryption = if encryption_types == 0 {
            false // Default includes AES on modern DCs
        } else {
            rc4_enabled && !aes128_enabled && !aes256_enabled
        };

        Self {
            sam_account_name: sam_account_name.to_string(),
            distinguished_name: distinguished_name.to_string(),
            account_type: account_type.to_string(),
            supported_encryption_types: encryption_types,
            rc4_enabled,
            aes128_enabled,
            aes256_enabled,
            only_weak_encryption,
            is_privileged,
            has_spn,
        }
    }
}

/// Summary of Kerberos encryption audit findings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct KerberosEncryptionAudit {
    /// Total accounts with explicit encryption settings
    pub total_accounts_audited: u32,
    /// Accounts with RC4 enabled (any AES also enabled)
    pub rc4_enabled_count: u32,
    /// Accounts with ONLY weak encryption (RC4 only, no AES)
    pub weak_only_count: u32,
    /// Privileged accounts with weak encryption
    pub privileged_weak_count: u32,
    /// Service accounts (with SPNs) vulnerable to Kerberoasting with weak encryption
    pub kerberoastable_weak_count: u32,
    /// Detailed list of accounts with weak encryption
    pub weak_encryption_accounts: Vec<KerberosEncryptionStatus>,
}

impl Default for KerberosEncryptionAudit {
    fn default() -> Self {
        Self {
            total_accounts_audited: 0,
            rc4_enabled_count: 0,
            weak_only_count: 0,
            privileged_weak_count: 0,
            kerberoastable_weak_count: 0,
            weak_encryption_accounts: Vec::new(),
        }
    }
}

/// Stale computer account with old password
/// Computers should rotate passwords every 30 days by default
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct StaleComputerAccount {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub dns_hostname: Option<String>,
    pub operating_system: Option<String>,
    /// When the password was last set
    pub password_last_set: Option<String>,
    /// Days since password was last changed
    pub password_age_days: u32,
    /// When the account last logged on
    pub last_logon: Option<String>,
    /// Days since last logon
    pub last_logon_days: Option<u32>,
    /// Whether the account is enabled
    pub enabled: bool,
    /// Whether this is a Domain Controller (more critical)
    pub is_domain_controller: bool,
    /// Whether this is a server OS
    pub is_server: bool,
}

/// Summary of stale computer account audit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct StaleComputerAudit {
    /// Total computer accounts scanned
    pub total_computers: u32,
    /// Computers with password age > 60 days
    pub stale_60_days_count: u32,
    /// Computers with password age > 90 days
    pub stale_90_days_count: u32,
    /// Computers with password age > 180 days (likely orphaned)
    pub stale_180_days_count: u32,
    /// Computers that have never logged in
    pub never_logged_in_count: u32,
    /// Enabled computers with stale passwords (highest risk)
    pub enabled_stale_count: u32,
    /// Detailed list of stale computers
    pub stale_computers: Vec<StaleComputerAccount>,
}

impl Default for StaleComputerAudit {
    fn default() -> Self {
        Self {
            total_computers: 0,
            stale_60_days_count: 0,
            stale_90_days_count: 0,
            stale_180_days_count: 0,
            never_logged_in_count: 0,
            enabled_stale_count: 0,
            stale_computers: Vec::new(),
        }
    }
}

/// DCShadow attack indicator - rogue DC SPN on non-DC computer
///
/// DCShadow attack involves registering SPNs that make a computer appear
/// to be a Domain Controller, allowing rogue replication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct DCShadowIndicator {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub dns_hostname: Option<String>,
    /// The suspicious SPN that indicates potential DCShadow
    pub suspicious_spn: String,
    /// Type of suspicious SPN found
    pub indicator_type: DCShadowIndicatorType,
    /// Whether this computer is actually a Domain Controller
    pub is_actual_dc: bool,
    /// All SPNs on this computer object
    pub all_spns: Vec<String>,
    /// Operating system if available
    pub operating_system: Option<String>,
    /// When the object was created
    pub when_created: Option<String>,
    /// When the object was last modified
    pub when_changed: Option<String>,
}

/// Types of DCShadow indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) enum DCShadowIndicatorType {
    /// GC/ SPN - Global Catalog service, should only be on DCs
    GlobalCatalog,
    /// E3514235-4B06-11D1-AB04-00C04FC2DCD2/ - Directory Replication SPN
    DirectoryReplication,
    /// ldap/ SPN with DC-like naming - LDAP service
    LdapService,
    /// DNS/ SPN - DNS service (common on DCs)
    DnsService,
    /// Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ - DFS Replication
    DfsReplication,
}

impl std::fmt::Display for DCShadowIndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DCShadowIndicatorType::GlobalCatalog => write!(f, "Global Catalog (GC/)"),
            DCShadowIndicatorType::DirectoryReplication => write!(f, "Directory Replication Service"),
            DCShadowIndicatorType::LdapService => write!(f, "LDAP Service"),
            DCShadowIndicatorType::DnsService => write!(f, "DNS Service"),
            DCShadowIndicatorType::DfsReplication => write!(f, "DFS Replication"),
        }
    }
}

/// Summary of DCShadow detection audit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct DCShadowAudit {
    /// Total non-DC computers with suspicious SPNs
    pub suspicious_computers_count: u32,
    /// Computers with GC/ SPN but not actual DCs (CRITICAL)
    pub rogue_gc_count: u32,
    /// Computers with replication SPNs but not DCs (CRITICAL)
    pub rogue_replication_count: u32,
    /// Total domain controllers (for reference)
    pub actual_dc_count: u32,
    /// List of suspicious indicators found
    pub indicators: Vec<DCShadowIndicator>,
}

impl Default for DCShadowAudit {
    fn default() -> Self {
        Self {
            suspicious_computers_count: 0,
            rogue_gc_count: 0,
            rogue_replication_count: 0,
            actual_dc_count: 0,
            indicators: Vec::new(),
        }
    }
}

// ==========================================
// Phase 2 Gap Analysis: NTLM/Network Security
// ==========================================

/// NTLM and network protocol security audit results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct NtlmSecurityAudit {
    /// LDAP signing configuration
    pub ldap_signing: LdapSigningStatus,
    /// SMB signing configuration
    pub smb_signing: SmbSigningStatus,
    /// NTLM restriction level (LmCompatibilityLevel)
    pub ntlm_settings: NtlmRestrictionStatus,
    /// GPO settings parsed from SYSVOL
    pub gpo_security_settings: Vec<GpoSecuritySetting>,
    /// Overall NTLM security score (0-100)
    pub ntlm_security_score: u32,
    /// Security level assessment
    pub security_level: String,
}

impl Default for NtlmSecurityAudit {
    fn default() -> Self {
        Self {
            ldap_signing: LdapSigningStatus::default(),
            smb_signing: SmbSigningStatus::default(),
            ntlm_settings: NtlmRestrictionStatus::default(),
            gpo_security_settings: Vec::new(),
            ntlm_security_score: 0,
            security_level: "Unknown".to_string(),
        }
    }
}

/// LDAP signing configuration status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct LdapSigningStatus {
    /// Whether LDAP signing is required (2), negotiated (1), or none (0)
    pub server_signing_requirement: Option<u32>,
    /// Human-readable signing status
    pub signing_status: String,
    /// Whether channel binding is enabled
    pub channel_binding_enabled: Option<bool>,
    /// Channel binding token requirement level
    pub channel_binding_level: Option<u32>,
    /// Whether we detected signing enforcement via connection test
    pub signing_enforced_detected: bool,
    /// Source of the configuration (GPO, Registry, Detection)
    pub config_source: String,
    /// Is the configuration secure?
    pub is_secure: bool,
}

impl Default for LdapSigningStatus {
    fn default() -> Self {
        Self {
            server_signing_requirement: None,
            signing_status: "Unknown".to_string(),
            channel_binding_enabled: None,
            channel_binding_level: None,
            signing_enforced_detected: false,
            config_source: "Not detected".to_string(),
            is_secure: false,
        }
    }
}

impl LdapSigningStatus {
    /// Interpret the LDAPServerIntegrity registry value
    #[allow(dead_code)]
    pub(crate) fn interpret_signing_level(level: u32) -> &'static str {
        match level {
            0 => "None - No signing required (INSECURE)",
            1 => "Negotiated - Signing if client supports (WEAK)",
            2 => "Required - Always require signing (SECURE)",
            _ => "Unknown",
        }
    }

    /// Interpret channel binding level
    #[allow(dead_code)]
    pub(crate) fn interpret_channel_binding(level: u32) -> &'static str {
        match level {
            0 => "Never - Channel binding disabled (INSECURE)",
            1 => "When Supported - Binding if client supports (WEAK)",
            2 => "Always - Always require channel binding (SECURE)",
            _ => "Unknown",
        }
    }
}

/// SMB signing configuration status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct SmbSigningStatus {
    /// Whether SMB signing is required on domain controllers
    pub dc_signing_required: Option<bool>,
    /// Whether SMB signing is required on member servers
    pub server_signing_required: Option<bool>,
    /// Whether SMB signing is enabled (but not required)
    pub signing_enabled: Option<bool>,
    /// Whether SMBv1 is enabled (security risk)
    pub smb1_enabled: Option<bool>,
    /// Detected via GPO parsing
    pub detected_via_gpo: bool,
    /// Source GPO name if detected
    pub source_gpo: Option<String>,
    /// Is the configuration secure?
    pub is_secure: bool,
    /// Security issues found
    pub security_issues: Vec<String>,
}

impl Default for SmbSigningStatus {
    fn default() -> Self {
        Self {
            dc_signing_required: None,
            server_signing_required: None,
            signing_enabled: None,
            smb1_enabled: None,
            detected_via_gpo: false,
            source_gpo: None,
            is_secure: false,
            security_issues: Vec::new(),
        }
    }
}

/// NTLM restriction and LmCompatibilityLevel status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct NtlmRestrictionStatus {
    /// LmCompatibilityLevel value (0-5)
    pub lm_compatibility_level: Option<u32>,
    /// Human-readable interpretation
    pub compatibility_description: String,
    /// Whether NTLMv1 is allowed
    pub ntlmv1_allowed: bool,
    /// Whether LM hashes are stored
    pub lm_hash_storage: Option<bool>,
    /// Whether NTLM is restricted via GPO
    pub ntlm_restricted: Option<bool>,
    /// NTLM audit mode enabled
    pub ntlm_audit_enabled: Option<bool>,
    /// Is the configuration secure?
    pub is_secure: bool,
    /// Security recommendations
    pub recommendations: Vec<String>,
}

impl Default for NtlmRestrictionStatus {
    fn default() -> Self {
        Self {
            lm_compatibility_level: None,
            compatibility_description: "Unknown".to_string(),
            ntlmv1_allowed: true, // Assume insecure until proven otherwise
            lm_hash_storage: None,
            ntlm_restricted: None,
            ntlm_audit_enabled: None,
            is_secure: false,
            recommendations: Vec::new(),
        }
    }
}

impl NtlmRestrictionStatus {
    /// Interpret LmCompatibilityLevel value
    ///
    /// | Value | Send | Accept |
    /// |-------|------|--------|
    /// | 0 | LM & NTLM | LM, NTLM, NTLMv2 |
    /// | 1 | LM & NTLM (use NTLMv2 session if negotiated) | LM, NTLM, NTLMv2 |
    /// | 2 | NTLM only | LM, NTLM, NTLMv2 |
    /// | 3 | NTLMv2 only | LM, NTLM, NTLMv2 |
    /// | 4 | NTLMv2 only | NTLM, NTLMv2 (refuse LM) |
    /// | 5 | NTLMv2 only | NTLMv2 only (refuse LM & NTLM) |
    #[allow(dead_code)]
    pub(crate) fn interpret_lm_level(level: u32) -> (&'static str, bool) {
        match level {
            0 => ("Send LM & NTLM responses (CRITICAL - LM hashes sent)", false),
            1 => ("Send LM & NTLM, use NTLMv2 session security if negotiated (HIGH RISK)", false),
            2 => ("Send NTLM response only (MEDIUM RISK - NTLMv1 still used)", false),
            3 => ("Send NTLMv2 response only (ACCEPTABLE - but accepts LM/NTLM)", false),
            4 => ("Send NTLMv2 only, refuse LM (GOOD - still accepts NTLM)", true),
            5 => ("Send NTLMv2 only, refuse LM & NTLM (SECURE - NTLMv2 only)", true),
            _ => ("Unknown LmCompatibilityLevel", false),
        }
    }

    /// Create from detected LmCompatibilityLevel
    #[allow(dead_code)]
    pub(crate) fn from_level(level: u32) -> Self {
        let (description, is_secure) = Self::interpret_lm_level(level);
        let ntlmv1_allowed = level < 4;

        let mut recommendations = Vec::new();
        if level < 5 {
            recommendations.push(format!(
                "Increase LmCompatibilityLevel to 5 (current: {}). This ensures only NTLMv2 is used.",
                level
            ));
        }
        if level < 3 {
            recommendations.push(
                "CRITICAL: LM or NTLMv1 responses are being sent. These are easily cracked.".to_string()
            );
        }

        Self {
            lm_compatibility_level: Some(level),
            compatibility_description: description.to_string(),
            ntlmv1_allowed,
            lm_hash_storage: Some(level < 3), // LM hashes may be stored if level < 3
            ntlm_restricted: None,
            ntlm_audit_enabled: None,
            is_secure,
            recommendations,
        }
    }
}

/// Security setting extracted from GPO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct GpoSecuritySetting {
    /// GPO name or GUID
    pub gpo_name: String,
    /// GPO distinguished name
    pub gpo_dn: String,
    /// Setting category (e.g., "LDAP Signing", "SMB Signing", "NTLM")
    pub category: String,
    /// Setting name
    pub setting_name: String,
    /// Setting value
    pub setting_value: String,
    /// Whether this is a secure configuration
    pub is_secure: bool,
    /// Parsed from file path
    pub source_file: Option<String>,
}

/// Domain controller with NTLM security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct DcNtlmStatus {
    pub dc_name: String,
    pub distinguished_name: String,
    pub dns_hostname: Option<String>,
    /// Whether this DC requires LDAP signing (detected via connection)
    pub ldap_signing_required: Option<bool>,
    /// Whether this DC requires SMB signing
    pub smb_signing_required: Option<bool>,
    /// Operating system version
    pub operating_system: Option<String>,
}

/// Extended infrastructure audit including Phase 1 + Phase 2 gap analysis checks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct ExtendedInfrastructureAudit {
    /// Base infrastructure audit results
    #[serde(flatten)]
    pub base_audit: InfrastructureAudit,
    /// Kerberos encryption audit (RC4 weak encryption detection)
    pub kerberos_encryption: KerberosEncryptionAudit,
    /// Stale computer account audit
    pub stale_computers: StaleComputerAudit,
    /// DCShadow attack indicator detection
    pub dcshadow_indicators: DCShadowAudit,
    /// Phase 2: NTLM/Network security audit
    pub ntlm_security: NtlmSecurityAudit,
}

impl ExtendedInfrastructureAudit {
    #[allow(dead_code)]
    pub(crate) fn new(
        base_audit: InfrastructureAudit,
        kerberos_encryption: KerberosEncryptionAudit,
        stale_computers: StaleComputerAudit,
        dcshadow_indicators: DCShadowAudit,
        ntlm_security: NtlmSecurityAudit,
    ) -> Self {
        Self {
            base_audit,
            kerberos_encryption,
            stale_computers,
            dcshadow_indicators,
            ntlm_security,
        }
    }
}

/// Infrastructure security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct InfrastructureRecommendation {
    pub priority: InfrastructureSeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected_count: usize,
    pub remediation_steps: Vec<String>,
    pub reference: Option<String>,
}

/// Generate recommendations based on infrastructure audit results
#[allow(dead_code)]
pub(crate) fn generate_infrastructure_recommendations(
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
pub(crate) fn calculate_infrastructure_risk_score(findings: &[InfrastructureFinding]) -> (u32, String) {
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
