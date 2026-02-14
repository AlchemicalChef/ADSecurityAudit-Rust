//! Common Types Module
//!
//! Shared types used across multiple audit modules to reduce code duplication
//! and ensure consistency in severity levels, risk assessment, and security constants.
//!
//! # Contents
//!
//! - **FindingSeverity**: Unified severity levels for all audit findings
//! - **AccountType**: Unified account type classification
//! - **Finding<T>**: Generic finding structure with custom details
//! - **Recommendation**: Standard recommendation structure
//! - **Security Constants**: AD GUIDs, privileged groups, dangerous groups
//! - **UAC Flags**: User Account Control flag parsing

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity levels for security findings
///
/// Used by domain_security, infrastructure_audit, and other audit modules
/// to classify the severity of discovered security issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FindingSeverity {
    /// Lowest severity - informational only
    Informational,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Highest severity - critical issue
    Critical,
}

impl FindingSeverity {
    /// Returns a numeric level for the severity
    ///
    /// Critical = 4, High = 3, Medium = 2, Low = 1, Informational = 0
    pub fn level(&self) -> u8 {
        match self {
            FindingSeverity::Critical => 4,
            FindingSeverity::High => 3,
            FindingSeverity::Medium => 2,
            FindingSeverity::Low => 1,
            FindingSeverity::Informational => 0,
        }
    }

    /// Returns the severity as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSeverity::Critical => "Critical",
            FindingSeverity::High => "High",
            FindingSeverity::Medium => "Medium",
            FindingSeverity::Low => "Low",
            FindingSeverity::Informational => "Informational",
        }
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ==========================================
// Account Types
// ==========================================

/// Unified account type classification used across all audit modules
///
/// This consolidates account types from delegation_audit and privileged_accounts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum AccountType {
    /// Standard user account
    User,
    /// Service account (user account used for services)
    ServiceAccount,
    /// Managed Service Account (sMSA)
    ManagedServiceAccount,
    /// Group Managed Service Account (gMSA)
    GroupManagedServiceAccount,
    /// Computer account
    Computer,
}

impl fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::User => write!(f, "User Account"),
            AccountType::Computer => write!(f, "Computer Account"),
            AccountType::ServiceAccount => write!(f, "Service Account"),
            AccountType::ManagedServiceAccount => write!(f, "Managed Service Account"),
            AccountType::GroupManagedServiceAccount => write!(f, "Group Managed Service Account"),
        }
    }
}

impl AccountType {
    /// Check if this is a service-type account
    #[allow(dead_code)]
    pub fn is_service_account(&self) -> bool {
        matches!(
            self,
            AccountType::ServiceAccount
                | AccountType::ManagedServiceAccount
                | AccountType::GroupManagedServiceAccount
        )
    }
}

// ==========================================
// Generic Finding Structure
// ==========================================

/// Generic security finding with customizable details type
///
/// This provides a consistent structure for findings across all audit modules
/// while allowing module-specific detail types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Finding<T> {
    /// Unique identifier for this finding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Category of the finding (e.g., "Kerberos Delegation", "ADCS")
    pub category: String,
    /// Short description of the issue
    pub issue: String,
    /// Severity level
    pub severity: FindingSeverity,
    /// Numeric severity level (derived from severity)
    pub severity_level: u8,
    /// The affected object (account, GPO, template, etc.)
    pub affected_object: String,
    /// Detailed description of the finding
    pub description: String,
    /// Security impact if not remediated
    pub impact: String,
    /// Recommended remediation steps
    pub remediation: String,
    /// Module-specific details
    pub details: T,
}

impl<T> Finding<T> {
    /// Create a new finding with the given parameters
    #[allow(dead_code)]
    pub(crate) fn new(
        category: impl Into<String>,
        issue: impl Into<String>,
        severity: FindingSeverity,
        affected_object: impl Into<String>,
        description: impl Into<String>,
        impact: impl Into<String>,
        remediation: impl Into<String>,
        details: T,
    ) -> Self {
        let severity_level = severity.level();
        Self {
            id: None,
            category: category.into(),
            issue: issue.into(),
            severity,
            severity_level,
            affected_object: affected_object.into(),
            description: description.into(),
            impact: impact.into(),
            remediation: remediation.into(),
            details,
        }
    }

    /// Create a new finding with a UUID
    #[allow(dead_code)]
    pub(crate) fn with_id(
        category: impl Into<String>,
        issue: impl Into<String>,
        severity: FindingSeverity,
        affected_object: impl Into<String>,
        description: impl Into<String>,
        impact: impl Into<String>,
        remediation: impl Into<String>,
        details: T,
    ) -> Self {
        let severity_level = severity.level();
        Self {
            id: Some(uuid::Uuid::new_v4().to_string()),
            category: category.into(),
            issue: issue.into(),
            severity,
            severity_level,
            affected_object: affected_object.into(),
            description: description.into(),
            impact: impact.into(),
            remediation: remediation.into(),
            details,
        }
    }
}

/// Counts of findings grouped by severity level
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub informational: u32,
    pub total: u32,
}

impl SeverityCounts {
    /// Create counts from an iterator of severity levels
    pub fn from_iter<'a>(severities: impl Iterator<Item = &'a FindingSeverity>) -> Self {
        let mut counts = Self::default();
        for severity in severities {
            match severity {
                FindingSeverity::Critical => counts.critical += 1,
                FindingSeverity::High => counts.high += 1,
                FindingSeverity::Medium => counts.medium += 1,
                FindingSeverity::Low => counts.low += 1,
                FindingSeverity::Informational => counts.informational += 1,
            }
            counts.total += 1;
        }
        counts
    }
}

/// Common User Account Control (UAC) flag constants
///
/// These are the standard UAC flags from Active Directory
pub(crate) mod uac_flags {
    /// Account is disabled
    pub const ACCOUNTDISABLE: u32 = 0x0002;
    /// Account is locked out
    pub const LOCKOUT: u32 = 0x0010;
    /// Password never expires
    pub const DONT_EXPIRE_PASSWORD: u32 = 0x10000;
    /// Account doesn't require Kerberos pre-authentication (AS-REP roastable)
    pub const DONT_REQ_PREAUTH: u32 = 0x400000;
    /// Kerberos DES encryption types are enabled
    pub const USE_DES_KEY_ONLY: u32 = 0x200000;
    /// Account is trusted for delegation (unconstrained)
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x80000;
    /// Account is a domain controller
    pub const SERVER_TRUST_ACCOUNT: u32 = 0x2000;
    /// Password is stored using reversible encryption
    pub const ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 0x80;
    /// Smart card is required for interactive logon
    pub const SMARTCARD_REQUIRED: u32 = 0x40000;
    /// Account is sensitive and cannot be delegated
    pub const NOT_DELEGATED: u32 = 0x100000;
}

/// Helper struct for parsing UserAccountControl flags
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct UserAccountControlFlags {
    pub raw_value: u32,
    pub is_disabled: bool,
    pub is_locked: bool,
    pub password_never_expires: bool,
    pub is_asrep_roastable: bool,
    pub uses_des_only: bool,
    pub is_unconstrained_delegation: bool,
    pub is_domain_controller: bool,
    pub reversible_encryption: bool,
    pub smartcard_required: bool,
    pub is_sensitive: bool,
}

impl UserAccountControlFlags {
    /// Parse UAC flags from a u32 value
    pub fn from_value(uac: u32) -> Self {
        Self {
            raw_value: uac,
            is_disabled: (uac & uac_flags::ACCOUNTDISABLE) != 0,
            is_locked: (uac & uac_flags::LOCKOUT) != 0,
            password_never_expires: (uac & uac_flags::DONT_EXPIRE_PASSWORD) != 0,
            is_asrep_roastable: (uac & uac_flags::DONT_REQ_PREAUTH) != 0,
            uses_des_only: (uac & uac_flags::USE_DES_KEY_ONLY) != 0,
            is_unconstrained_delegation: (uac & uac_flags::TRUSTED_FOR_DELEGATION) != 0,
            is_domain_controller: (uac & uac_flags::SERVER_TRUST_ACCOUNT) != 0,
            reversible_encryption: (uac & uac_flags::ENCRYPTED_TEXT_PASSWORD_ALLOWED) != 0,
            smartcard_required: (uac & uac_flags::SMARTCARD_REQUIRED) != 0,
            is_sensitive: (uac & uac_flags::NOT_DELEGATED) != 0,
        }
    }

    /// Check if account is enabled (not disabled)
    pub fn is_enabled(&self) -> bool {
        !self.is_disabled
    }
}

/// Extract domain name from a distinguished name
///
/// # Example
/// ```
/// let dn = "CN=John,OU=Users,DC=example,DC=com";
/// let domain = extract_domain_from_dn(dn);
/// assert_eq!(domain, "example.com");
/// ```
pub(crate) fn extract_domain_from_dn(dn: &str) -> String {
    dn.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.to_uppercase().starts_with("DC=") {
                Some(&part[3..])
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Standard recommendation structure used across audit modules
///
/// This struct provides a consistent format for security recommendations
/// across different audit types (delegation, group, permissions, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Recommendation {
    /// Priority level (1 = highest/critical, 4 = lowest/informational)
    pub priority: u8,
    /// Short title for the recommendation
    pub title: String,
    /// Detailed description of the recommendation
    pub description: String,
    /// Step-by-step remediation steps
    pub steps: Vec<String>,
    /// Optional PowerShell/CLI command for remediation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Optional reference URL for documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl Recommendation {
    /// Create a new recommendation without a command or reference
    pub(crate) fn new(priority: u8, title: &str, description: &str, steps: Vec<String>) -> Self {
        Self {
            priority,
            title: title.to_string(),
            description: description.to_string(),
            steps,
            command: None,
            reference: None,
        }
    }

    /// Create a new recommendation with a remediation command
    pub fn with_command(priority: u8, title: &str, description: &str, steps: Vec<String>, command: &str) -> Self {
        Self {
            priority,
            title: title.to_string(),
            description: description.to_string(),
            steps,
            command: Some(command.to_string()),
            reference: None,
        }
    }

    /// Create a new recommendation with a reference URL
    #[allow(dead_code)]
    pub fn with_reference(priority: u8, title: &str, description: &str, steps: Vec<String>, reference: &str) -> Self {
        Self {
            priority,
            title: title.to_string(),
            description: description.to_string(),
            steps,
            command: None,
            reference: Some(reference.to_string()),
        }
    }
}

// ==========================================
// Security Constants
// ==========================================

/// Active Directory security-related constants and GUIDs
#[allow(dead_code)]
pub(crate) mod security_constants {
    /// Well-known dangerous builtin groups with attack path descriptions
    ///
    /// These groups grant significant privileges that can lead to domain compromise
    pub const DANGEROUS_BUILTIN_GROUPS: [(&str, &str); 5] = [
        ("Print Operators", "Load printer drivers on DCs -> Execute code as SYSTEM"),
        ("Server Operators", "Modify services on DCs -> Execute code as SYSTEM"),
        ("Backup Operators", "Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise"),
        ("Account Operators", "Modify non-protected accounts -> Add to privileged groups"),
        ("DnsAdmins", "Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM"),
    ];

    /// Well-known privileged RIDs that indicate high-value accounts
    pub const PRIVILEGED_RIDS: [&str; 3] = ["500", "512", "519"];

    /// DCSync required rights GUIDs
    pub const DCSYNC_RIGHTS: [(&str, &str); 3] = [
        ("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
        ("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
        ("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c"),
    ];

    /// Legitimate principals that normally have broad control
    pub const LEGITIMATE_PRINCIPALS: [&str; 9] = [
        "NT AUTHORITY\\SYSTEM",
        "BUILTIN\\Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Domain Controllers",
        "Enterprise Domain Controllers",
        "Read-only Domain Controllers",
        "Administrators",
    ];

    // ==========================================
    // AD Attribute GUIDs
    // ==========================================

    /// msDS-KeyCredentialLink attribute GUID (Shadow Credentials)
    pub const KEY_CREDENTIAL_LINK_GUID: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
    /// servicePrincipalName attribute GUID
    pub const SPN_GUID: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";
    /// msDS-AllowedToActOnBehalfOfOtherIdentity GUID (RBCD)
    pub const RBCD_GUID: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
    /// gPLink attribute GUID
    pub const GP_LINK_GUID: &str = "f30e3bc2-9ff0-11d1-b603-0000f80367c1";
    /// User-Force-Change-Password extended right GUID
    pub const PASSWORD_RESET_GUID: &str = "00299570-246d-11d0-a768-00aa006e0529";
    /// member attribute GUID
    pub const MEMBER_ATTRIBUTE_GUID: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";

    // ==========================================
    // PKI/ADCS Extended Rights GUIDs
    // ==========================================

    /// Certificate-Enrollment extended right
    pub const CERTIFICATE_ENROLLMENT_GUID: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    /// Certificate-AutoEnrollment extended right
    pub const CERTIFICATE_AUTOENROLLMENT_GUID: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
    /// Manage-CA extended right
    pub const MANAGE_CA_GUID: &str = "ee98ee94-de5f-4f4e-8e89-0adf6c2acc8c";

    // ==========================================
    // PKI EKUs (Extended Key Usage)
    // ==========================================

    /// Client Authentication EKU
    pub const CLIENT_AUTHENTICATION_EKU: &str = "1.3.6.1.5.5.7.3.2";
    /// Smart Card Logon EKU
    pub const SMART_CARD_LOGON_EKU: &str = "1.3.6.1.4.1.311.20.2.2";
    /// Any Purpose EKU (dangerous)
    pub const ANY_PURPOSE_EKU: &str = "2.5.29.37.0";
    /// Certificate Request Agent EKU
    pub const CERTIFICATE_REQUEST_AGENT_EKU: &str = "1.3.6.1.4.1.311.20.2.1";

    // ==========================================
    // Certificate Template Flags
    // ==========================================

    /// Enrollee can supply subject in request (ESC1)
    pub const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
    /// All requests require manager approval
    pub const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;
}

// ==========================================
// Privileged Group Definitions
// ==========================================

/// Privilege tier levels based on Microsoft's tiered administration model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum PrivilegeLevel {
    /// Domain/Forest Admin level - highest risk
    Tier0,
    /// Server Admin level
    Tier1,
    /// Workstation Admin level
    Tier2,
    /// Has delegated permissions via ACLs
    Delegated,
    /// Service account with elevated rights
    Service,
}

impl fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivilegeLevel::Tier0 => write!(f, "Tier 0"),
            PrivilegeLevel::Tier1 => write!(f, "Tier 1"),
            PrivilegeLevel::Tier2 => write!(f, "Tier 2"),
            PrivilegeLevel::Delegated => write!(f, "Delegated"),
            PrivilegeLevel::Service => write!(f, "Service"),
        }
    }
}

/// Well-known privileged group types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum PrivilegedGroupType {
    DomainAdmins,
    EnterpriseAdmins,
    SchemaAdmins,
    Administrators,
    AccountOperators,
    BackupOperators,
    ServerOperators,
    PrintOperators,
    DnsAdmins,
    GroupPolicyCreatorOwners,
    CryptoOperators,
    RemoteDesktopUsers,
    HyperVAdministrators,
    AccessControlAssistanceOperators,
    Custom(String),
}

/// Privileged group definition with risk information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct PrivilegedGroupDefinition {
    pub group_type: PrivilegedGroupType,
    pub name: &'static str,
    pub privilege_level: PrivilegeLevel,
    pub risk_score: u32,
    pub is_builtin: bool,
    pub attack_path: Option<&'static str>,
}

/// Get all privileged group definitions with risk scoring
pub(crate) fn get_privileged_group_definitions() -> Vec<PrivilegedGroupDefinition> {
    vec![
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::DomainAdmins,
            name: "Domain Admins",
            privilege_level: PrivilegeLevel::Tier0,
            risk_score: 100,
            is_builtin: true,
            attack_path: Some("Direct domain compromise"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::EnterpriseAdmins,
            name: "Enterprise Admins",
            privilege_level: PrivilegeLevel::Tier0,
            risk_score: 100,
            is_builtin: true,
            attack_path: Some("Forest-wide compromise"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::SchemaAdmins,
            name: "Schema Admins",
            privilege_level: PrivilegeLevel::Tier0,
            risk_score: 100,
            is_builtin: true,
            attack_path: Some("Schema modification -> Backdoor attributes"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::Administrators,
            name: "Administrators",
            privilege_level: PrivilegeLevel::Tier0,
            risk_score: 90,
            is_builtin: true,
            attack_path: Some("Local admin on all domain systems"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::AccountOperators,
            name: "Account Operators",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 70,
            is_builtin: true,
            attack_path: Some("Modify non-protected accounts -> Add to privileged groups"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::BackupOperators,
            name: "Backup Operators",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 70,
            is_builtin: true,
            attack_path: Some("Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::ServerOperators,
            name: "Server Operators",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 60,
            is_builtin: true,
            attack_path: Some("Modify services on DCs -> Execute code as SYSTEM"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::PrintOperators,
            name: "Print Operators",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 50,
            is_builtin: true,
            attack_path: Some("Load printer drivers on DCs -> Execute code as SYSTEM"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::DnsAdmins,
            name: "DnsAdmins",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 80,
            is_builtin: false,
            attack_path: Some("Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::GroupPolicyCreatorOwners,
            name: "Group Policy Creator Owners",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 75,
            is_builtin: true,
            attack_path: Some("Create GPO -> Link to DC OU -> Execute as SYSTEM"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::CryptoOperators,
            name: "Cryptographic Operators",
            privilege_level: PrivilegeLevel::Tier2,
            risk_score: 40,
            is_builtin: false,
            attack_path: None,
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::RemoteDesktopUsers,
            name: "Remote Desktop Users",
            privilege_level: PrivilegeLevel::Tier2,
            risk_score: 30,
            is_builtin: false,
            attack_path: None,
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::HyperVAdministrators,
            name: "Hyper-V Administrators",
            privilege_level: PrivilegeLevel::Tier1,
            risk_score: 85,
            is_builtin: false,
            attack_path: Some("Hyper-V admin -> VM escape -> Host compromise"),
        },
        PrivilegedGroupDefinition {
            group_type: PrivilegedGroupType::AccessControlAssistanceOperators,
            name: "Access Control Assistance Operators",
            privilege_level: PrivilegeLevel::Tier2,
            risk_score: 35,
            is_builtin: false,
            attack_path: None,
        },
    ]
}

/// Check if a principal name is a known legitimate high-privilege principal
#[allow(dead_code)]
pub(crate) fn is_legitimate_principal(principal: &str) -> bool {
    let lower = principal.to_lowercase();
    security_constants::LEGITIMATE_PRINCIPALS.iter()
        .any(|p| lower.contains(&p.to_lowercase()))
}

/// Check if a RID indicates a privileged account
#[allow(dead_code)]
pub(crate) fn is_privileged_rid(rid: &str) -> bool {
    security_constants::PRIVILEGED_RIDS.contains(&rid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_levels() {
        assert_eq!(FindingSeverity::Critical.level(), 4);
        assert_eq!(FindingSeverity::High.level(), 3);
        assert_eq!(FindingSeverity::Medium.level(), 2);
        assert_eq!(FindingSeverity::Low.level(), 1);
        assert_eq!(FindingSeverity::Informational.level(), 0);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(FindingSeverity::Critical > FindingSeverity::High);
        assert!(FindingSeverity::High > FindingSeverity::Medium);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
        assert!(FindingSeverity::Low > FindingSeverity::Informational);
    }

    #[test]
    fn test_severity_counts() {
        let severities = vec![
            FindingSeverity::Critical,
            FindingSeverity::Critical,
            FindingSeverity::High,
            FindingSeverity::Medium,
            FindingSeverity::Low,
        ];
        let counts = SeverityCounts::from_iter(severities.iter());
        assert_eq!(counts.critical, 2);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.informational, 0);
        assert_eq!(counts.total, 5);
    }

    #[test]
    fn test_uac_flags() {
        let uac = uac_flags::ACCOUNTDISABLE | uac_flags::DONT_EXPIRE_PASSWORD;
        let flags = UserAccountControlFlags::from_value(uac);
        assert!(flags.is_disabled);
        assert!(!flags.is_enabled());
        assert!(flags.password_never_expires);
        assert!(!flags.is_locked);
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain_from_dn("CN=John,OU=Users,DC=example,DC=com"),
            "example.com"
        );
        assert_eq!(
            extract_domain_from_dn("CN=Admin,DC=corp,DC=contoso,DC=local"),
            "corp.contoso.local"
        );
    }
}
