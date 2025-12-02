//! Privileged Group Membership Audit Module
//!
//! Analyzes Active Directory privileged groups for security issues including
//! excessive membership, nested groups, and stale accounts.
//!
//! # Security Best Practices
//!
//! ## Membership Thresholds
//!
//! | Group Type | Recommended Max | Rationale |
//! |------------|-----------------|-----------|
//! | Critical (DA, EA, SA) | 5 | Minimal attack surface |
//! | Protected Groups | 15 | Limited but operational |
//! | Delegated Groups | Varies | Based on business need |
//!
//! ## Critical Groups (Tier 0)
//!
//! - **Domain Admins**: Full control over the domain
//! - **Enterprise Admins**: Full control over the forest
//! - **Schema Admins**: Can modify AD schema (irreversible)
//! - **Administrators**: Built-in admin group on DCs
//!
//! ## Protected Groups (AdminSDHolder)
//!
//! These groups have their ACL reset every 60 minutes by SDProp:
//! - Domain Admins, Enterprise Admins, Schema Admins
//! - Administrators, Backup Operators, Account Operators
//! - Server Operators, Print Operators, DnsAdmins
//! - Domain Controllers, Cert Publishers, Key Admins
//!
//! # Issues Detected
//!
//! | Issue | Severity | Impact |
//! |-------|----------|--------|
//! | Excessive membership | Critical/High | Larger attack surface |
//! | Nested groups in DA/EA | High | Hidden privilege paths |
//! | Disabled users in groups | Medium | Should be cleaned up |
//! | Inactive users (>90 days) | Medium | Stale privileged access |
//!
//! # Why Nested Groups Are Dangerous
//!
//! Nested groups in critical privileged groups:
//! - Obscure actual membership - hard to audit
//! - Create "choke points" for privilege escalation
//! - Complicate access review and revocation
//! - May include users unintentionally
//!
//! **Best Practice**: Direct membership only in Tier 0 groups
//!
//! # Remediation Strategies
//!
//! 1. Implement Just-In-Time (JIT) privileged access
//! 2. Use Privileged Access Management (PAM) solutions
//! 3. Create role-based delegation instead of DA membership
//! 4. Conduct quarterly privileged access reviews
//! 5. Automate removal of disabled users from groups

use serde::{Deserialize, Serialize};

// Use shared Recommendation from common_types
use crate::common_types::Recommendation;

/// Type alias for backward compatibility - use Recommendation from common_types
pub type GroupRecommendation = Recommendation;

// ==========================================
// Group Audit Types
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub object_class: String, // user, group, computer
    pub enabled: Option<bool>,
    pub last_logon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedGroupInfo {
    pub name: String,
    pub distinguished_name: String,
    pub member_count: u32,
    pub threshold: u32,
    pub is_critical: bool,
    pub nested_groups: Vec<GroupMember>,
    pub disabled_users: Vec<GroupMember>,
    pub inactive_users: Vec<GroupMember>,
    pub all_members: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFinding {
    pub category: String,
    pub issue: String,
    pub severity: String,
    pub severity_level: u8,
    pub affected_object: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub details: GroupFindingDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupFindingDetails {
    pub group_dn: Option<String>,
    pub member_count: Option<u32>,
    pub threshold: Option<u32>,
    pub members: Option<Vec<String>>,
    pub nested_groups: Option<Vec<String>>,
    pub user_dn: Option<String>,
    pub last_logon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAudit {
    pub total_groups_scanned: u32,
    pub groups_with_issues: u32,
    pub excessive_membership_count: u32,
    pub nested_groups_count: u32,
    pub disabled_users_count: u32,
    pub inactive_users_count: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub groups: Vec<PrivilegedGroupInfo>,
    pub findings: Vec<GroupFinding>,
    pub risk_score: u32,
    pub scan_timestamp: String,
    pub recommendations: Vec<GroupRecommendation>,
}

// ==========================================
// Constants
// ==========================================

pub const CRITICAL_GROUPS: [&str; 4] = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
];

pub const PROTECTED_GROUPS: [&str; 12] = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Domain Controllers",
    "Cert Publishers",
    "Key Admins",
];

pub const THRESHOLD_CRITICAL_GROUP: u32 = 5;
pub const THRESHOLD_STANDARD_GROUP: u32 = 15;
pub const INACTIVE_DAYS_THRESHOLD: u32 = 90;

impl GroupAudit {
    pub fn new() -> Self {
        Self {
            total_groups_scanned: 0,
            groups_with_issues: 0,
            excessive_membership_count: 0,
            nested_groups_count: 0,
            disabled_users_count: 0,
            inactive_users_count: 0,
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            groups: Vec::new(),
            findings: Vec::new(),
            risk_score: 0,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            recommendations: Vec::new(),
        }
    }

    pub fn analyze_group(
        &mut self,
        group_name: &str,
        group_dn: &str,
        members: Vec<GroupMember>,
    ) {
        let is_critical = CRITICAL_GROUPS.contains(&group_name);
        let threshold = if is_critical {
            THRESHOLD_CRITICAL_GROUP
        } else {
            THRESHOLD_STANDARD_GROUP
        };

        let member_count = members.len() as u32;
        let nested_groups: Vec<GroupMember> = members
            .iter()
            .filter(|m| m.object_class == "group")
            .cloned()
            .collect();

        let disabled_users: Vec<GroupMember> = members
            .iter()
            .filter(|m| m.object_class == "user" && m.enabled == Some(false))
            .cloned()
            .collect();

        let inactive_users: Vec<GroupMember> = members
            .iter()
            .filter(|m| {
                if m.object_class != "user" {
                    return false;
                }
                // Check if last logon exceeds threshold
                if let Some(ref last_logon) = m.last_logon {
                    if let Ok(logon_time) = chrono::DateTime::parse_from_rfc3339(last_logon) {
                        let days_since = (chrono::Utc::now() - logon_time.with_timezone(&chrono::Utc)).num_days();
                        return days_since > INACTIVE_DAYS_THRESHOLD as i64;
                    }
                }
                false
            })
            .cloned()
            .collect();

        // Check for excessive membership
        if member_count > threshold {
            self.excessive_membership_count += 1;
            let severity = if is_critical { "Critical" } else { "High" };
            let severity_level = if is_critical { 4 } else { 3 };

            self.findings.push(GroupFinding {
                category: "Privileged Groups".to_string(),
                issue: "Excessive Privileged Group Membership".to_string(),
                severity: severity.to_string(),
                severity_level,
                affected_object: group_name.to_string(),
                description: format!(
                    "The '{}' group has {} members, exceeding the recommended threshold of {}.",
                    group_name, member_count, threshold
                ),
                impact: "Over-privileged accounts increase the attack surface and make it harder to maintain accountability.".to_string(),
                remediation: format!(
                    "Review and reduce membership. Remove unnecessary accounts and implement role-based access with custom delegated groups. Use temporary privileged access where possible.\n\nPowerShell: Get-ADGroupMember -Identity '{}' | Select-Object Name, SamAccountName",
                    group_name
                ),
                details: GroupFindingDetails {
                    group_dn: Some(group_dn.to_string()),
                    member_count: Some(member_count),
                    threshold: Some(threshold),
                    members: Some(members.iter().map(|m| m.sam_account_name.clone()).collect()),
                    nested_groups: None,
                    user_dn: None,
                    last_logon: None,
                },
            });

            if is_critical {
                self.critical_findings += 1;
            } else {
                self.high_findings += 1;
            }
        }

        // Check for nested groups in critical groups
        if is_critical && !nested_groups.is_empty() {
            self.nested_groups_count += nested_groups.len() as u32;
            self.findings.push(GroupFinding {
                category: "Privileged Groups".to_string(),
                issue: "Nested Groups in Critical Privileged Group".to_string(),
                severity: "High".to_string(),
                severity_level: 3,
                affected_object: group_name.to_string(),
                description: format!(
                    "The critical group '{}' contains {} nested group(s), which complicates access management.",
                    group_name, nested_groups.len()
                ),
                impact: "Nested groups create choke points and can lead to unintentional privileged access. They make it difficult to audit who has access.".to_string(),
                remediation: format!(
                    "Remove nested groups and add users directly, or create custom delegated groups instead.\n\nNested groups: {}\n\nPowerShell to list: Get-ADGroupMember -Identity '{}' | Where-Object {{$_.objectClass -eq 'group'}}",
                    nested_groups.iter().map(|g| g.sam_account_name.clone()).collect::<Vec<_>>().join(", "),
                    group_name
                ),
                details: GroupFindingDetails {
                    group_dn: Some(group_dn.to_string()),
                    member_count: None,
                    threshold: None,
                    members: None,
                    nested_groups: Some(nested_groups.iter().map(|g| g.sam_account_name.clone()).collect()),
                    user_dn: None,
                    last_logon: None,
                },
            });
            self.high_findings += 1;
        }

        // Check for disabled users
        for disabled_user in &disabled_users {
            self.disabled_users_count += 1;
            self.findings.push(GroupFinding {
                category: "Privileged Groups".to_string(),
                issue: "Disabled User in Privileged Group".to_string(),
                severity: "Medium".to_string(),
                severity_level: 2,
                affected_object: format!("{} - {}", group_name, disabled_user.sam_account_name),
                description: format!(
                    "Disabled user '{}' is still a member of privileged group '{}'.",
                    disabled_user.sam_account_name, group_name
                ),
                impact: "Disabled accounts in privileged groups should be removed to maintain clean access control.".to_string(),
                remediation: format!(
                    "Remove the disabled user:\n\nPowerShell: Remove-ADGroupMember -Identity '{}' -Members '{}' -Confirm:$false",
                    group_name, disabled_user.sam_account_name
                ),
                details: GroupFindingDetails {
                    group_dn: Some(group_dn.to_string()),
                    member_count: None,
                    threshold: None,
                    members: None,
                    nested_groups: None,
                    user_dn: Some(disabled_user.distinguished_name.clone()),
                    last_logon: None,
                },
            });
            self.medium_findings += 1;
        }

        // Check for inactive users
        for inactive_user in &inactive_users {
            self.inactive_users_count += 1;
            self.findings.push(GroupFinding {
                category: "Privileged Groups".to_string(),
                issue: "Inactive User in Privileged Group".to_string(),
                severity: "Medium".to_string(),
                severity_level: 2,
                affected_object: format!("{} - {}", group_name, inactive_user.sam_account_name),
                description: format!(
                    "User '{}' in privileged group '{}' has not logged in for over {} days.",
                    inactive_user.sam_account_name, group_name, INACTIVE_DAYS_THRESHOLD
                ),
                impact: "Stale privileged accounts increase risk if credentials are compromised.".to_string(),
                remediation: format!(
                    "Review if user still requires access. Consider removing or disabling:\n\nPowerShell: Remove-ADGroupMember -Identity '{}' -Members '{}' -Confirm:$false",
                    group_name, inactive_user.sam_account_name
                ),
                details: GroupFindingDetails {
                    group_dn: Some(group_dn.to_string()),
                    member_count: None,
                    threshold: None,
                    members: None,
                    nested_groups: None,
                    user_dn: Some(inactive_user.distinguished_name.clone()),
                    last_logon: inactive_user.last_logon.clone(),
                },
            });
            self.medium_findings += 1;
        }

        // Add group info
        let has_issues = member_count > threshold
            || (!nested_groups.is_empty() && is_critical)
            || !disabled_users.is_empty()
            || !inactive_users.is_empty();

        if has_issues {
            self.groups_with_issues += 1;
        }

        self.groups.push(PrivilegedGroupInfo {
            name: group_name.to_string(),
            distinguished_name: group_dn.to_string(),
            member_count,
            threshold,
            is_critical,
            nested_groups,
            disabled_users,
            inactive_users,
            all_members: members,
        });

        self.total_groups_scanned += 1;
    }

    pub fn calculate_risk_score(&mut self) {
        let mut score = 0u32;

        score += self.critical_findings * 25;
        score += self.high_findings * 15;
        score += self.medium_findings * 5;
        score += self.low_findings * 2;

        self.risk_score = score.min(100);
    }

    pub fn generate_recommendations(&mut self) {
        if self.excessive_membership_count > 0 {
            self.recommendations.push(Recommendation::new(
                1,
                "Reduce Privileged Group Membership",
                &format!(
                    "Found {} group(s) with excessive membership. Large privileged groups increase attack surface.",
                    self.excessive_membership_count
                ),
                vec![
                    "Audit each privileged group: Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name, SamAccountName".to_string(),
                    "Identify accounts that don't require permanent privileged access".to_string(),
                    "Implement Just-In-Time (JIT) administration using PAM or similar solutions".to_string(),
                    "Create role-based groups with delegated permissions instead of Domain Admin".to_string(),
                    "Document legitimate members and their business justification".to_string(),
                ],
            ));
        }

        if self.nested_groups_count > 0 {
            self.recommendations.push(Recommendation::new(
                2,
                "Remove Nested Groups from Critical Groups",
                &format!(
                    "Found {} nested group(s) in critical privileged groups. Nested groups obscure true membership.",
                    self.nested_groups_count
                ),
                vec![
                    "List nested groups: Get-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.objectClass -eq 'group'}".to_string(),
                    "Enumerate actual users in nested groups recursively".to_string(),
                    "Remove nested groups and add required users directly".to_string(),
                    "Consider creating delegated administration groups instead".to_string(),
                    "Document the change and update access control procedures".to_string(),
                ],
            ));
        }

        if self.disabled_users_count > 0 {
            self.recommendations.push(Recommendation::new(
                3,
                "Remove Disabled Users from Privileged Groups",
                &format!(
                    "Found {} disabled user(s) still in privileged groups. These should be removed immediately.",
                    self.disabled_users_count
                ),
                vec![
                    "Find disabled users in privileged groups:".to_string(),
                    "Get-ADGroupMember -Identity 'Domain Admins' | Get-ADUser | Where-Object {$_.Enabled -eq $false}".to_string(),
                    "Remove each disabled user from all privileged groups".to_string(),
                    "Implement automated offboarding process to prevent recurrence".to_string(),
                    "Consider using PAM solutions that auto-remove access on account disable".to_string(),
                ],
            ));
        }

        if self.inactive_users_count > 0 {
            self.recommendations.push(Recommendation::new(
                4,
                "Review Inactive Privileged Users",
                &format!(
                    "Found {} user(s) in privileged groups who haven't logged in for over {} days.",
                    self.inactive_users_count, INACTIVE_DAYS_THRESHOLD
                ),
                vec![
                    format!("Find inactive privileged users (>{} days):", INACTIVE_DAYS_THRESHOLD),
                    "$threshold = (Get-Date).AddDays(-90); Get-ADGroupMember -Identity 'Domain Admins' | Get-ADUser -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt $threshold}".to_string(),
                    "Verify if users still require privileged access".to_string(),
                    "Remove access for users who no longer need it".to_string(),
                    "Implement regular access reviews (quarterly recommended)".to_string(),
                ],
            ));
        }
    }
}
