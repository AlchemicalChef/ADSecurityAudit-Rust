//! Kerberos Delegation Security Audit Module
//!
//! Analyzes Active Directory for dangerous Kerberos delegation configurations
//! that could enable privilege escalation and lateral movement attacks.
//!
//! # Kerberos Delegation Types
//!
//! ## Unconstrained Delegation (CRITICAL Risk)
//! - Account can impersonate ANY user to ANY service
//! - Collects TGTs from authenticating users in memory
//! - If compromised, attacker gains domain-wide access
//! - Should only exist on Domain Controllers
//!
//! ## Constrained Delegation (HIGH Risk)
//! - Account can impersonate users to SPECIFIC services only
//! - Limited blast radius compared to unconstrained
//! - Still dangerous if account is compromised
//!
//! ## Constrained with Protocol Transition / T2A4D (CRITICAL Risk)
//! - Can impersonate users WITHOUT their credentials
//! - Combines S4U2Self and S4U2Proxy Kerberos extensions
//! - Extremely dangerous on user accounts
//!
//! ## Resource-Based Constrained Delegation / RBCD (MEDIUM Risk)
//! - Target resource controls who can delegate to it
//! - More secure design than traditional delegation
//! - Can be abused if attacker modifies msDS-AllowedToActOnBehalfOfOtherIdentity
//!
//! # Attack Scenarios Detected
//!
//! | Finding | Risk | Attack |
//! |---------|------|--------|
//! | User with Unconstrained | Critical | Credential theft via TGT collection |
//! | User with T2A4D | Critical | Impersonate any user without creds |
//! | Computer with Unconstrained | High | Pivot point for lateral movement |
//! | Excessive RBCD | Medium | Potential unauthorized delegation |
//!
//! # Remediation Strategies
//!
//! 1. Replace unconstrained delegation with constrained
//! 2. Migrate user accounts to Group Managed Service Accounts (gMSA)
//! 3. Use RBCD instead of traditional constrained delegation
//! 4. Enable "Account is sensitive and cannot be delegated" for admins
//!
//! # References
//!
//! - [MS-SFU: Kerberos Protocol Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)
//! - [Kerberos Delegation Attack Overview](https://attack.mitre.org/techniques/T1134/)

use serde::{Deserialize, Serialize};

// Use shared types from common_types
pub use crate::common_types::{AccountType, Recommendation};

/// Type alias for backward compatibility - use Recommendation from common_types
pub type DelegationRecommendation = Recommendation;

/// Type alias for backward compatibility - use AccountType from common_types
pub type DelegationAccountType = AccountType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegationType {
    Unconstrained,
    Constrained,
    ConstrainedWithProtocolTransition,
    ResourceBased,
}

impl std::fmt::Display for DelegationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationType::Unconstrained => write!(f, "Unconstrained"),
            DelegationType::Constrained => write!(f, "Constrained"),
            DelegationType::ConstrainedWithProtocolTransition => write!(f, "Constrained with Protocol Transition (T2A4D)"),
            DelegationType::ResourceBased => write!(f, "Resource-Based Constrained Delegation (RBCD)"),
        }
    }
}

// Note: AccountType is now imported from common_types and re-exported as DelegationAccountType

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEntry {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub account_type: AccountType,
    pub delegation_type: DelegationType,
    pub enabled: bool,
    pub allowed_to_delegate_to: Vec<String>,
    pub trusted_for_delegation: bool,
    pub trusted_to_auth_for_delegation: bool,
    pub service_principal_names: Vec<String>,
    pub principals_allowed_to_delegate: Vec<String>, // For RBCD
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationFinding {
    pub category: String,
    pub issue: String,
    pub severity: String,
    pub severity_level: u8, // 1=Low, 2=Medium, 3=High, 4=Critical
    pub affected_object: String,
    pub account_type: AccountType,
    pub delegation_type: DelegationType,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub details: DelegationDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationDetails {
    pub distinguished_name: String,
    pub allowed_to_delegate_to: Vec<String>,
    pub trusted_to_auth_for_delegation: bool,
    pub enabled: bool,
    pub service_principal_names: Vec<String>,
    pub principals_allowed_to_delegate: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationAudit {
    pub total_delegations: u32,
    pub unconstrained_count: u32,
    pub constrained_count: u32,
    pub protocol_transition_count: u32,
    pub rbcd_count: u32,
    pub user_account_delegations: u32,
    pub computer_account_delegations: u32,
    pub findings: Vec<DelegationFinding>,
    pub delegations: Vec<DelegationEntry>,
    pub risk_score: u32,
    pub scan_timestamp: String,
    pub recommendations: Vec<DelegationRecommendation>,
}

impl DelegationAudit {
    pub fn new() -> Self {
        Self {
            total_delegations: 0,
            unconstrained_count: 0,
            constrained_count: 0,
            protocol_transition_count: 0,
            rbcd_count: 0,
            user_account_delegations: 0,
            computer_account_delegations: 0,
            findings: Vec::new(),
            delegations: Vec::new(),
            risk_score: 0,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            recommendations: Vec::new(),
        }
    }

    pub fn analyze_user_constrained_delegation(&mut self, entry: &DelegationEntry) {
        if entry.trusted_to_auth_for_delegation {
            // Protocol Transition (T2A4D) - CRITICAL
            let finding = DelegationFinding {
                category: "Kerberos Delegation".to_string(),
                issue: "User Account with Protocol Transition (T2A4D)".to_string(),
                severity: "Critical".to_string(),
                severity_level: 4,
                affected_object: entry.sam_account_name.clone(),
                account_type: entry.account_type.clone(),
                delegation_type: DelegationType::ConstrainedWithProtocolTransition,
                description: format!(
                    "User account '{}' has constrained delegation with protocol transition enabled (TrustedToAuthForDelegation).",
                    entry.sam_account_name
                ),
                impact: "Can impersonate ANY user to specified services without requiring their credentials. Highly exploitable for privilege escalation.".to_string(),
                remediation: "Disable protocol transition if not absolutely required. If needed, ensure the account has a very strong password (30+ characters) and is closely monitored. Consider migrating to Group Managed Service Accounts.".to_string(),
                details: DelegationDetails {
                    distinguished_name: entry.distinguished_name.clone(),
                    allowed_to_delegate_to: entry.allowed_to_delegate_to.clone(),
                    trusted_to_auth_for_delegation: entry.trusted_to_auth_for_delegation,
                    enabled: entry.enabled,
                    service_principal_names: entry.service_principal_names.clone(),
                    principals_allowed_to_delegate: Vec::new(),
                },
            };
            self.findings.push(finding);
            self.protocol_transition_count += 1;
            self.risk_score += 40;
        } else {
            // Standard constrained delegation - HIGH
            let finding = DelegationFinding {
                category: "Kerberos Delegation".to_string(),
                issue: "User Account with Constrained Delegation".to_string(),
                severity: "High".to_string(),
                severity_level: 3,
                affected_object: entry.sam_account_name.clone(),
                account_type: entry.account_type.clone(),
                delegation_type: DelegationType::Constrained,
                description: format!(
                    "User account '{}' has constrained delegation configured to specific services.",
                    entry.sam_account_name
                ),
                impact: "Can impersonate authenticated users to specified services. Less risky than unconstrained delegation but still requires strong security controls.".to_string(),
                remediation: format!(
                    "Verify this configuration is necessary. Ensure strong password policy and monitoring. Review delegated services: {}",
                    entry.allowed_to_delegate_to.join(", ")
                ),
                details: DelegationDetails {
                    distinguished_name: entry.distinguished_name.clone(),
                    allowed_to_delegate_to: entry.allowed_to_delegate_to.clone(),
                    trusted_to_auth_for_delegation: entry.trusted_to_auth_for_delegation,
                    enabled: entry.enabled,
                    service_principal_names: entry.service_principal_names.clone(),
                    principals_allowed_to_delegate: Vec::new(),
                },
            };
            self.findings.push(finding);
            self.constrained_count += 1;
            self.risk_score += 20;
        }
        self.user_account_delegations += 1;
    }

    pub fn analyze_computer_constrained_delegation(&mut self, entry: &DelegationEntry) {
        if entry.trusted_to_auth_for_delegation {
            // Computer with Protocol Transition - HIGH
            let finding = DelegationFinding {
                category: "Kerberos Delegation".to_string(),
                issue: "Computer Account with Protocol Transition (T2A4D)".to_string(),
                severity: "High".to_string(),
                severity_level: 3,
                affected_object: entry.sam_account_name.clone(),
                account_type: entry.account_type.clone(),
                delegation_type: DelegationType::ConstrainedWithProtocolTransition,
                description: format!(
                    "Computer account '{}' has constrained delegation with protocol transition enabled.",
                    entry.sam_account_name
                ),
                impact: "If compromised, attackers can impersonate any user to specified services. Common on Exchange servers but requires securing the host.".to_string(),
                remediation: format!(
                    "Verify this configuration is required (common for Exchange/IIS). Ensure the computer is hardened, patched, and monitored. Services: {}",
                    entry.allowed_to_delegate_to.join(", ")
                ),
                details: DelegationDetails {
                    distinguished_name: entry.distinguished_name.clone(),
                    allowed_to_delegate_to: entry.allowed_to_delegate_to.clone(),
                    trusted_to_auth_for_delegation: entry.trusted_to_auth_for_delegation,
                    enabled: entry.enabled,
                    service_principal_names: entry.service_principal_names.clone(),
                    principals_allowed_to_delegate: Vec::new(),
                },
            };
            self.findings.push(finding);
            self.protocol_transition_count += 1;
            self.risk_score += 25;
        }
        self.computer_account_delegations += 1;
    }

    pub fn analyze_unconstrained_delegation(&mut self, entry: &DelegationEntry) {
        let severity = match entry.account_type {
            AccountType::User => ("Critical", 4, 50),
            AccountType::Computer => ("High", 3, 30),
            _ => ("High", 3, 25),
        };

        let finding = DelegationFinding {
            category: "Kerberos Delegation".to_string(),
            issue: format!("{} with Unconstrained Delegation", entry.account_type),
            severity: severity.0.to_string(),
            severity_level: severity.1,
            affected_object: entry.sam_account_name.clone(),
            account_type: entry.account_type.clone(),
            delegation_type: DelegationType::Unconstrained,
            description: format!(
                "{} '{}' is trusted for unconstrained delegation, allowing it to impersonate any user to any service.",
                entry.account_type, entry.sam_account_name
            ),
            impact: "Unconstrained delegation is extremely dangerous. If this account is compromised, attackers can collect TGTs from any user who authenticates to it and use them to access any resource in the domain.".to_string(),
            remediation: "Convert to constrained delegation with specific SPNs, or better yet, use Resource-Based Constrained Delegation (RBCD). Never enable unconstrained delegation on user accounts.".to_string(),
            details: DelegationDetails {
                distinguished_name: entry.distinguished_name.clone(),
                allowed_to_delegate_to: Vec::new(),
                trusted_to_auth_for_delegation: false,
                enabled: entry.enabled,
                service_principal_names: entry.service_principal_names.clone(),
                principals_allowed_to_delegate: Vec::new(),
            },
        };
        self.findings.push(finding);
        self.unconstrained_count += 1;
        self.risk_score += severity.2;
    }

    pub fn analyze_rbcd(&mut self, entry: &DelegationEntry) {
        let finding = DelegationFinding {
            category: "Kerberos Delegation".to_string(),
            issue: "Resource-Based Constrained Delegation Configured".to_string(),
            severity: "Medium".to_string(),
            severity_level: 2,
            affected_object: entry.sam_account_name.clone(),
            account_type: entry.account_type.clone(),
            delegation_type: DelegationType::ResourceBased,
            description: format!(
                "Object '{}' has Resource-Based Constrained Delegation (RBCD) configured, allowing other accounts to impersonate users to this resource.",
                entry.sam_account_name
            ),
            impact: "RBCD can be exploited if an attacker can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute or compromise accounts listed in it.".to_string(),
            remediation: "Review RBCD configuration and ensure only necessary accounts are allowed. Monitor for unauthorized changes to this attribute.".to_string(),
            details: DelegationDetails {
                distinguished_name: entry.distinguished_name.clone(),
                allowed_to_delegate_to: Vec::new(),
                trusted_to_auth_for_delegation: false,
                enabled: entry.enabled,
                service_principal_names: entry.service_principal_names.clone(),
                principals_allowed_to_delegate: entry.principals_allowed_to_delegate.clone(),
            },
        };
        self.findings.push(finding);
        self.rbcd_count += 1;
        self.risk_score += 15;
    }

    pub fn generate_recommendations(&mut self) {
        let mut recommendations = Vec::new();

        if self.unconstrained_count > 0 {
            recommendations.push(Recommendation::new(
                1,
                "Eliminate Unconstrained Delegation",
                &format!(
                    "Found {} objects with unconstrained delegation. This is the most dangerous delegation type.",
                    self.unconstrained_count
                ),
                vec![
                    "Identify all accounts with unconstrained delegation using: Get-ADObject -Filter {TrustedForDelegation -eq $true}".to_string(),
                    "For each account, determine if delegation is actually needed".to_string(),
                    "Convert to constrained delegation with specific SPNs where required".to_string(),
                    "Consider using Resource-Based Constrained Delegation (RBCD) instead".to_string(),
                    "For Domain Controllers, this is expected but ensure they are properly protected".to_string(),
                ],
            ));
        }

        if self.protocol_transition_count > 0 {
            recommendations.push(Recommendation::new(
                2,
                "Review Protocol Transition (T2A4D) Configurations",
                &format!(
                    "Found {} accounts with protocol transition enabled, allowing impersonation without user interaction.",
                    self.protocol_transition_count
                ),
                vec![
                    "List accounts: Get-ADObject -Filter {TrustedToAuthForDelegation -eq $true}".to_string(),
                    "For user accounts, disable T2A4D unless absolutely required".to_string(),
                    "For service accounts, migrate to Group Managed Service Accounts (gMSA)".to_string(),
                    "Ensure all T2A4D accounts use very strong passwords (30+ characters)".to_string(),
                    "Implement monitoring for S4U2Self and S4U2Proxy ticket requests".to_string(),
                ],
            ));
        }

        if self.user_account_delegations > 0 {
            recommendations.push(Recommendation::new(
                3,
                "Migrate User Account Delegations to Service Accounts",
                &format!(
                    "Found {} user accounts with delegation configured. User accounts are more vulnerable to credential theft.",
                    self.user_account_delegations
                ),
                vec![
                    "Create Group Managed Service Accounts (gMSA) for each service".to_string(),
                    "Configure the gMSA with the minimum required delegation".to_string(),
                    "Update service configurations to use gMSA instead of user accounts".to_string(),
                    "Disable or delete the old user accounts after migration".to_string(),
                    "gMSAs have automatically rotated 120-character passwords".to_string(),
                ],
            ));
        }

        if self.rbcd_count > 0 {
            recommendations.push(Recommendation::new(
                4,
                "Audit Resource-Based Constrained Delegation",
                &format!(
                    "Found {} objects with RBCD configured. While RBCD is more secure, it still needs regular review.",
                    self.rbcd_count
                ),
                vec![
                    "List RBCD: Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'}".to_string(),
                    "Review each RBCD configuration for necessity".to_string(),
                    "Ensure only required accounts are in the delegation list".to_string(),
                    "Monitor for changes to msDS-AllowedToActOnBehalfOfOtherIdentity".to_string(),
                    "Consider implementing just-in-time RBCD where possible".to_string(),
                ],
            ));
        }

        self.recommendations = recommendations;
    }
}
