//! Common Types Module
//!
//! Shared types used across multiple audit modules to reduce code duplication
//! and ensure consistency in severity levels and risk assessment.

use serde::{Deserialize, Serialize};

/// Severity levels for security findings
///
/// Used by domain_security, infrastructure_audit, and other audit modules
/// to classify the severity of discovered security issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
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
}

/// Counts of findings grouped by severity level
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
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
pub mod uac_flags {
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
pub struct UserAccountControlFlags {
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
pub fn extract_domain_from_dn(dn: &str) -> String {
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
pub struct Recommendation {
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
}

impl Recommendation {
    /// Create a new recommendation without a command
    pub fn new(priority: u8, title: &str, description: &str, steps: Vec<String>) -> Self {
        Self {
            priority,
            title: title.to_string(),
            description: description.to_string(),
            steps,
            command: None,
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
        }
    }
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
