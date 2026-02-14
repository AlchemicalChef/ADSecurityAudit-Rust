//! Privileged Account Management and Risk Assessment
//!
//! Comprehensive analysis of privileged accounts in Active Directory environments,
//! implementing Microsoft's tiered administration model and security best practices.
//!
//!
//! # Microsoft Tier Model
//!
//! This module implements the recommended three-tier administrative model:
//!
//! | Tier | Description | Risk Level | Examples |
//! |------|-------------|------------|----------|
//! | Tier 0 | Domain/Forest Admin | Highest | Domain Admins, Enterprise Admins, Schema Admins |
//! | Tier 1 | Server Administration | High | Account Operators, Backup Operators, Server Operators |
//! | Tier 2 | Workstation Administration | Moderate | Remote Desktop Users, local admins |
//!
//! # Features
//!
//! - **Group Enumeration**: Identifies all privileged groups with risk scoring
//! - **Account Analysis**: Detailed assessment of each privileged account
//! - **Risk Factor Detection**: Identifies dangerous configurations (stale passwords, SPNs, etc.)
//! - **Nested Group Resolution**: Traces indirect privilege grants through group nesting
//! - **Recommendation Engine**: Generates actionable security recommendations
//!
//! # Risk Factors Detected
//!
//! - Password never expires on privileged accounts
//! - Service accounts with Domain Admin privileges
//! - Disabled accounts still in privileged groups
//! - Tier 0 accounts not protected by AdminSDHolder
//! - Kerberoastable SPNs on privileged accounts
//! - Excessive privilege accumulation (multiple admin groups)
//!
//! # Example
//!
//! ```rust,ignore
//! let summary = client.get_privileged_accounts_summary().await?;
//! println!("Tier 0 accounts: {}", summary.total_tier0_accounts);
//! println!("Risk level: {:?}", summary.risk_level);
//!
//! for rec in summary.recommendations {
//!     println!("[{:?}] {}: {}", rec.priority, rec.title, rec.description);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Import shared types from common_types
pub(crate) use crate::common_types::{
    AccountType, PrivilegeLevel, PrivilegedGroupType,
    get_privileged_group_definitions as get_privileged_group_definitions_full,
    FindingSeverity,
};

/// Type alias for backward compatibility - RiskSeverity uses the shared FindingSeverity enum
///
/// Note: RiskSeverity::Info is now RiskSeverity::Informational (from FindingSeverity)
pub(crate) type RiskSeverity = FindingSeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PrivilegedGroup {
    pub name: String,
    pub distinguished_name: String,
    pub sid: String,
    pub group_type: PrivilegedGroupType,
    pub privilege_level: PrivilegeLevel,
    pub member_count: usize,
    pub description: String,
    pub risk_score: u32,
    pub is_protected: bool, // Protected by AdminSDHolder
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PrivilegedAccount {
    pub distinguished_name: String,
    pub sam_account_name: String,
    pub display_name: String,
    pub email: Option<String>,
    pub is_enabled: bool,
    pub is_locked: bool,
    pub last_logon: Option<String>,
    pub password_last_set: Option<String>,
    pub password_never_expires: bool,
    pub account_type: AccountType,
    pub privilege_sources: Vec<PrivilegeSource>,
    pub highest_privilege_level: PrivilegeLevel,
    pub total_risk_score: u32,
    pub risk_factors: Vec<RiskFactor>,
    pub is_sensitive: bool, // "Account is sensitive and cannot be delegated"
    pub is_protected: bool, // Member of protected group (AdminSDHolder)
    /// Account has DONT_REQUIRE_PREAUTH flag (vulnerable to AS-REP Roasting)
    pub is_asrep_roastable: bool,
    /// Account is member of Protected Users group (enhanced Kerberos security)
    pub in_protected_users: bool,
    /// Raw userAccountControl value for additional flag checks
    pub user_account_control: u32,
}

// Note: AccountType, PrivilegeLevel, PrivilegedGroupType are now imported from common_types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PrivilegeSource {
    pub source_type: PrivilegeSourceType,
    pub source_name: String,
    pub source_dn: Option<String>,
    pub privilege_level: PrivilegeLevel,
    pub is_direct: bool, // Direct vs nested membership
    pub nested_path: Option<Vec<String>>, // Group nesting path
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum PrivilegeSourceType {
    GroupMembership,
    AclPermission,
    DelegatedPermission,
    ServicePrincipal,
    AdminCount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub description: String,
    pub severity: RiskSeverity,
    pub score_impact: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum RiskFactorType {
    PasswordNeverExpires,
    StalePassword,
    NoRecentLogon,
    ExcessivePrivileges,
    ServiceAccountAsAdmin,
    NestedPrivileges,
    UnconstrainedDelegation,
    KerberoastableSpn,
    NotProtected,
    PasswordNotRequired,
    DisabledWithPrivileges,
    /// Account has DONT_REQUIRE_PREAUTH flag - vulnerable to AS-REP Roasting
    AsRepRoastable,
    /// Tier 0 account not in Protected Users group - missing Kerberos hardening
    NotInProtectedUsers,
}

// RiskSeverity is now a type alias to FindingSeverity defined above

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct DelegatedPermission {
    pub target_dn: String,
    pub target_type: String,
    pub permissions: Vec<String>,
    pub is_inherited: bool,
    pub can_escalate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PrivilegedAccountSummary {
    // Total counts
    pub total_privileged_accounts: usize,
    pub total_tier0_accounts: usize,
    pub total_tier1_accounts: usize,
    pub total_tier2_accounts: usize,
    pub total_delegated_accounts: usize,
    pub total_service_accounts: usize,
    
    // Status breakdown
    pub enabled_accounts: usize,
    pub disabled_accounts: usize,
    pub locked_accounts: usize,
    
    // Risk metrics
    pub high_risk_accounts: usize,
    pub accounts_with_stale_passwords: usize,
    pub accounts_password_never_expires: usize,
    pub kerberoastable_accounts: usize,
    /// Accounts vulnerable to AS-REP Roasting (DONT_REQUIRE_PREAUTH flag)
    pub asrep_roastable_accounts: usize,
    /// Tier 0 accounts not in Protected Users group
    pub tier0_not_in_protected_users: usize,
    
    // Group statistics
    pub privileged_groups: Vec<PrivilegedGroup>,
    pub accounts_by_group: HashMap<String, usize>,
    
    // Overall assessment
    pub overall_risk_score: u32,
    pub risk_level: RiskSeverity,
    pub analysis_timestamp: String,
    
    // Recommendations
    pub recommendations: Vec<PrivilegedAccountRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PrivilegedAccountRecommendation {
    pub priority: RiskSeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected_count: usize,
    pub remediation_steps: Vec<String>,
}

/// Get privileged group definitions with risk scoring (tuple format for backward compatibility)
///
/// For the full struct-based definitions with attack paths, use `get_privileged_group_definitions_full()`
pub(crate) fn get_privileged_group_definitions() -> Vec<(PrivilegedGroupType, &'static str, PrivilegeLevel, u32, bool)> {
    get_privileged_group_definitions_full()
        .into_iter()
        .map(|def| (def.group_type, def.name, def.privilege_level, def.risk_score, def.is_builtin))
        .collect()
}

/// Calculate risk factors for an account
pub(crate) fn calculate_risk_factors(account: &PrivilegedAccount) -> Vec<RiskFactor> {
    let mut factors = Vec::new();
    
    // Password never expires
    if account.password_never_expires {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::PasswordNeverExpires,
            description: "Password is set to never expire".to_string(),
            severity: RiskSeverity::High,
            score_impact: 25,
        });
    }
    
    // Service account with admin privileges
    if account.account_type == AccountType::ServiceAccount 
        && matches!(account.highest_privilege_level, PrivilegeLevel::Tier0 | PrivilegeLevel::Tier1) {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::ServiceAccountAsAdmin,
            description: "Service account has administrative privileges".to_string(),
            severity: RiskSeverity::High,
            score_impact: 30,
        });
    }
    
    // Disabled account with privileges (should be removed from groups)
    if !account.is_enabled {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::DisabledWithPrivileges,
            description: "Disabled account still has privileged group memberships".to_string(),
            severity: RiskSeverity::Medium,
            score_impact: 15,
        });
    }
    
    // Not protected by AdminSDHolder when it should be
    if matches!(account.highest_privilege_level, PrivilegeLevel::Tier0) && !account.is_protected {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::NotProtected,
            description: "Tier 0 account not protected by AdminSDHolder".to_string(),
            severity: RiskSeverity::Critical,
            score_impact: 40,
        });
    }
    
    // Nested privileges (harder to audit)
    let has_nested = account.privilege_sources.iter().any(|s| !s.is_direct);
    if has_nested {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::NestedPrivileges,
            description: "Privileges obtained through nested group membership".to_string(),
            severity: RiskSeverity::Medium,
            score_impact: 10,
        });
    }
    
    // Excessive privileges (member of multiple admin groups)
    let tier0_count = account.privilege_sources.iter()
        .filter(|s| matches!(s.privilege_level, PrivilegeLevel::Tier0))
        .count();
    if tier0_count > 2 {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::ExcessivePrivileges,
            description: format!("Member of {} Tier 0 privileged groups", tier0_count),
            severity: RiskSeverity::High,
            score_impact: 20,
        });
    }

    // AS-REP Roasting vulnerability (DONT_REQUIRE_PREAUTH flag)
    // UAC flag 0x400000 (4194304) - allows attackers to request AS-REP without authentication
    if account.is_asrep_roastable {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::AsRepRoastable,
            description: "Account does not require Kerberos pre-authentication (AS-REP Roastable)".to_string(),
            severity: RiskSeverity::Critical,
            score_impact: 45,
        });
    }

    // Tier 0 accounts should be in Protected Users group for enhanced Kerberos security
    if matches!(account.highest_privilege_level, PrivilegeLevel::Tier0) && !account.in_protected_users {
        factors.push(RiskFactor {
            factor_type: RiskFactorType::NotInProtectedUsers,
            description: "Tier 0 account is not a member of Protected Users group".to_string(),
            severity: RiskSeverity::High,
            score_impact: 25,
        });
    }

    factors
}

/// Calculate overall risk score for summary
pub(crate) fn calculate_overall_risk(summary: &PrivilegedAccountSummary) -> (u32, RiskSeverity) {
    let mut score = 0u32;

    // Base score from account counts
    score += summary.total_tier0_accounts as u32 * 10;
    score += summary.total_tier1_accounts as u32 * 5;
    score += summary.high_risk_accounts as u32 * 15;
    score += summary.accounts_password_never_expires as u32 * 8;
    score += summary.kerberoastable_accounts as u32 * 12;
    // AS-REP Roasting is critical - high impact
    score += summary.asrep_roastable_accounts as u32 * 20;
    // Tier 0 accounts not in Protected Users - moderate impact
    score += summary.tier0_not_in_protected_users as u32 * 10;
    
    // Normalize to 0-100 with safe division
    const MAX_SCORE: u32 = 500;
    let normalized = if MAX_SCORE > 0 {
        (score.min(MAX_SCORE) * 100) / MAX_SCORE
    } else {
        0
    };
    
    let severity = match normalized {
        0..=20 => RiskSeverity::Low,
        21..=40 => RiskSeverity::Medium,
        41..=70 => RiskSeverity::High,
        _ => RiskSeverity::Critical,
    };
    
    (normalized, severity)
}

/// Generate recommendations based on analysis
pub(crate) fn generate_privileged_account_recommendations(
    summary: &PrivilegedAccountSummary,
    accounts: &[PrivilegedAccount],
) -> Vec<PrivilegedAccountRecommendation> {
    let mut recommendations = Vec::new();
    
    // Tier 0 account count
    if summary.total_tier0_accounts > 5 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::High,
            category: "Account Governance".to_string(),
            title: "Reduce Tier 0 Account Count".to_string(),
            description: format!(
                "You have {} Tier 0 accounts. Microsoft recommends limiting Domain Admins to 5 or fewer.",
                summary.total_tier0_accounts
            ),
            affected_count: summary.total_tier0_accounts,
            remediation_steps: vec![
                "Audit all Tier 0 accounts and their business justification".to_string(),
                "Remove accounts that don't require permanent admin access".to_string(),
                "Implement just-in-time (JIT) privileged access".to_string(),
                "Use Privileged Access Workstations (PAWs) for admin tasks".to_string(),
            ],
        });
    }
    
    // Password never expires
    if summary.accounts_password_never_expires > 0 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::High,
            category: "Password Security".to_string(),
            title: "Enable Password Expiration".to_string(),
            description: format!(
                "{} privileged accounts have 'Password never expires' set.",
                summary.accounts_password_never_expires
            ),
            affected_count: summary.accounts_password_never_expires,
            remediation_steps: vec![
                "Review each account to determine if flag is necessary".to_string(),
                "For service accounts, implement managed service accounts (gMSA)".to_string(),
                "Remove flag from user accounts and enforce password policies".to_string(),
                "Document exceptions with business justification".to_string(),
            ],
        });
    }
    
    // Disabled accounts with privileges
    let disabled_privileged = accounts.iter()
        .filter(|a| !a.is_enabled)
        .count();
    if disabled_privileged > 0 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::Medium,
            category: "Account Cleanup".to_string(),
            title: "Remove Disabled Accounts from Privileged Groups".to_string(),
            description: format!(
                "{} disabled accounts still have privileged group memberships.",
                disabled_privileged
            ),
            affected_count: disabled_privileged,
            remediation_steps: vec![
                "Remove disabled accounts from all privileged groups".to_string(),
                "Document reason for account disablement".to_string(),
                "Consider deleting accounts after retention period".to_string(),
            ],
        });
    }
    
    // Kerberoastable accounts
    if summary.kerberoastable_accounts > 0 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::Critical,
            category: "Kerberos Security".to_string(),
            title: "Address Kerberoastable Privileged Accounts".to_string(),
            description: format!(
                "{} privileged accounts have SPNs that can be Kerberoasted.",
                summary.kerberoastable_accounts
            ),
            affected_count: summary.kerberoastable_accounts,
            remediation_steps: vec![
                "Migrate service accounts to gMSA where possible".to_string(),
                "Use long, complex passwords (25+ characters) for legacy SPNs".to_string(),
                "Enable AES encryption and disable RC4 for Kerberos".to_string(),
                "Monitor for Kerberoasting attempts in security logs".to_string(),
            ],
        });
    }

    // AS-REP Roastable accounts (DONT_REQUIRE_PREAUTH)
    if summary.asrep_roastable_accounts > 0 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::Critical,
            category: "Kerberos Security".to_string(),
            title: "Remove DONT_REQUIRE_PREAUTH Flag (AS-REP Roasting Risk)".to_string(),
            description: format!(
                "{} accounts do not require Kerberos pre-authentication. Attackers can request encrypted \
                 AS-REP data for these accounts without any authentication and crack passwords offline.",
                summary.asrep_roastable_accounts
            ),
            affected_count: summary.asrep_roastable_accounts,
            remediation_steps: vec![
                "Enable Kerberos pre-authentication: Set-ADUser -Identity <user> -DoesNotRequirePreAuth $false".to_string(),
                "Audit why pre-authentication was disabled - this is rarely needed".to_string(),
                "Use strong, complex passwords (25+ characters) for accounts that must have this flag".to_string(),
                "Monitor Event ID 4768 with Pre-Authentication Type 0 for AS-REP Roasting attempts".to_string(),
                "Consider adding affected accounts to Protected Users group".to_string(),
            ],
        });
    }

    // Tier 0 accounts not in Protected Users group
    if summary.tier0_not_in_protected_users > 0 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::High,
            category: "Kerberos Security".to_string(),
            title: "Add Tier 0 Accounts to Protected Users Group".to_string(),
            description: format!(
                "{} Tier 0 accounts are not members of the Protected Users group. \
                 Protected Users provides enhanced Kerberos security including: no NTLM authentication, \
                 no delegation, shorter TGT lifetime, and AES-only encryption.",
                summary.tier0_not_in_protected_users
            ),
            affected_count: summary.tier0_not_in_protected_users,
            remediation_steps: vec![
                "Add Domain Admin and Enterprise Admin accounts to Protected Users: Add-ADGroupMember -Identity 'Protected Users' -Members <user>".to_string(),
                "Test application compatibility before adding service accounts".to_string(),
                "Note: Protected Users cannot use NTLM - ensure Kerberos is available for all admin tasks".to_string(),
                "Protected Users cannot be delegated - verify no delegation requirements exist".to_string(),
                "Consider implementing Privileged Access Workstations (PAWs) for Protected Users".to_string(),
            ],
        });
    }

    // Service accounts with admin rights
    let admin_service_accounts = accounts.iter()
        .filter(|a| {
            a.account_type == AccountType::ServiceAccount 
            && matches!(a.highest_privilege_level, PrivilegeLevel::Tier0)
        })
        .count();
    if admin_service_accounts > 0 {
        recommendations.push(PrivilegedAccountRecommendation {
            priority: RiskSeverity::High,
            category: "Service Account Security".to_string(),
            title: "Review Service Accounts with Admin Privileges".to_string(),
            description: format!(
                "{} service accounts have Tier 0 administrative privileges.",
                admin_service_accounts
            ),
            affected_count: admin_service_accounts,
            remediation_steps: vec![
                "Audit service accounts for minimum required permissions".to_string(),
                "Remove from Domain Admins and use delegated permissions".to_string(),
                "Convert to Group Managed Service Accounts (gMSA)".to_string(),
                "Implement credential tiering and isolation".to_string(),
            ],
        });
    }
    
    recommendations
}
