//! GPO (Group Policy Object) Audit Module
//! Evaluates GPO security including permissions, links to sensitive OUs,
//! unlinked GPOs, and SYSVOL permissions.

use serde::{Deserialize, Serialize};
use crate::domain_security::{Severity, SecurityFinding, FindingCategory};

/// GPO permission level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GpoPermission {
    GpoApply,
    GpoRead,
    GpoEdit,
    GpoEditDeleteModifySecurity,
    GpoCustom,
}

impl GpoPermission {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "gpoapply" => GpoPermission::GpoApply,
            "gporead" => GpoPermission::GpoRead,
            "gpoedit" => GpoPermission::GpoEdit,
            "gpoeditdeletemodifysecurity" => GpoPermission::GpoEditDeleteModifySecurity,
            _ => GpoPermission::GpoCustom,
        }
    }

    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            GpoPermission::GpoEdit | GpoPermission::GpoEditDeleteModifySecurity
        )
    }

    pub fn display_name(&self) -> &str {
        match self {
            GpoPermission::GpoApply => "Apply",
            GpoPermission::GpoRead => "Read",
            GpoPermission::GpoEdit => "Edit Settings",
            GpoPermission::GpoEditDeleteModifySecurity => "Full Control",
            GpoPermission::GpoCustom => "Custom",
        }
    }
}

/// GPO permission entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoPermissionEntry {
    pub trustee: String,
    pub trustee_type: String, // User, Group, Computer
    pub permission: GpoPermission,
    pub permission_name: String,
    pub inherited: bool,
}

/// GPO link information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoLink {
    pub ou_name: String,
    pub ou_distinguished_name: String,
    pub link_enabled: bool,
    pub enforced: bool,
    pub link_order: u32,
}

/// Group Policy Object information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicyObject {
    pub id: String,
    pub display_name: String,
    pub path: String,
    pub created_time: Option<String>,
    pub modified_time: Option<String>,
    pub owner: String,
    pub permissions: Vec<GpoPermissionEntry>,
    pub links: Vec<GpoLink>,
    pub computer_settings_enabled: bool,
    pub user_settings_enabled: bool,
    pub wmi_filter: Option<String>,
}

/// SYSVOL permission entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysvolPermission {
    pub identity: String,
    pub access_type: String, // Allow, Deny
    pub rights: String,
    pub inherited: bool,
    pub is_dangerous: bool,
}

/// GPO audit summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoAuditSummary {
    pub total_gpos: u32,
    pub gpos_with_dangerous_permissions: u32,
    pub gpos_linked_to_dc_ou: u32,
    pub unlinked_gpos: u32,
    pub gpos_with_weak_dc_permissions: u32,
    pub sysvol_permission_issues: u32,
}

/// Complete GPO audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoAudit {
    pub domain_name: String,
    pub sysvol_path: String,
    pub gpos: Vec<GroupPolicyObject>,
    pub sysvol_permissions: Vec<SysvolPermission>,
    pub findings: Vec<SecurityFinding>,
    pub summary: GpoAuditSummary,
    pub total_findings: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub overall_risk_score: u32,
    pub risk_level: String,
    pub audit_timestamp: String,
}

/// Protected/privileged groups that are allowed to have GPO edit rights
pub const PRIVILEGED_TRUSTEES: &[&str] = &[
    "Domain Admins",
    "Enterprise Admins",
    "SYSTEM",
    "NT AUTHORITY\\SYSTEM",
    "Administrators",
    "BUILTIN\\Administrators",
    "Group Policy Creator Owners",
];

/// Check if trustee is privileged
pub fn is_privileged_trustee(trustee: &str) -> bool {
    PRIVILEGED_TRUSTEES.iter().any(|p| {
        trustee.eq_ignore_ascii_case(p) || 
        trustee.to_lowercase().contains(&p.to_lowercase())
    })
}

/// Evaluate GPO permissions for security issues
pub fn evaluate_gpo_permissions(gpo: &GroupPolicyObject) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    for perm in &gpo.permissions {
        if perm.permission.is_dangerous() && !is_privileged_trustee(&perm.trustee) {
            findings.push(SecurityFinding::new(
                FindingCategory::GroupPolicy,
                "Over-Permissioned GPO",
                Severity::High,
                &gpo.display_name,
                &format!(
                    "GPO '{}' grants '{}' to non-privileged principal '{}'.",
                    gpo.display_name,
                    perm.permission.display_name(),
                    perm.trustee
                ),
                "Low-privileged users or groups can modify the GPO, leading to privilege escalation, malware deployment, or persistence mechanisms.",
                &format!(
                    "Remove dangerous permission: Set-GPPermission -Guid {} -TargetName '{}' -TargetType {} -PermissionLevel None",
                    gpo.id,
                    perm.trustee,
                    perm.trustee_type
                ),
                serde_json::json!({
                    "gpo_id": gpo.id,
                    "gpo_path": gpo.path,
                    "trustee": perm.trustee,
                    "permission": perm.permission_name
                }),
            ));
        }
    }

    findings
}

/// Evaluate GPO links to sensitive OUs (like Domain Controllers)
pub fn evaluate_gpo_dc_links(gpo: &GroupPolicyObject) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    for link in &gpo.links {
        // Check if linked to Domain Controllers OU
        if link.ou_distinguished_name.to_lowercase().contains("ou=domain controllers") {
            // Check for non-admin edit rights on DC-linked GPO
            let non_admin_editors: Vec<_> = gpo.permissions.iter()
                .filter(|p| p.permission.is_dangerous() && !is_privileged_trustee(&p.trustee))
                .collect();

            if !non_admin_editors.is_empty() {
                let trustees: Vec<_> = non_admin_editors.iter()
                    .map(|p| p.trustee.as_str())
                    .collect();

                findings.push(SecurityFinding::new(
                    FindingCategory::GroupPolicy,
                    "GPO Linked to Domain Controllers with Weak Permissions",
                    Severity::Critical,
                    &gpo.display_name,
                    &format!(
                        "GPO '{}' is linked to Domain Controllers OU but has edit rights granted to non-admin principals.",
                        gpo.display_name
                    ),
                    "Attackers can deploy malicious packages or configurations to Domain Controllers with SYSTEM-level rights, leading to full domain compromise.",
                    "Restrict GPO permissions to only Domain Admins and Enterprise Admins. Remove all non-admin edit rights immediately.",
                    serde_json::json!({
                        "gpo_id": gpo.id,
                        "linked_ou": link.ou_distinguished_name,
                        "non_admin_trustees": trustees
                    }),
                ));
            }
        }
    }

    findings
}

/// Check for unlinked GPOs
pub fn evaluate_unlinked_gpos(gpo: &GroupPolicyObject) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    if gpo.links.is_empty() {
        findings.push(SecurityFinding::new(
            FindingCategory::GroupPolicy,
            "Unlinked GPO",
            Severity::Low,
            &gpo.display_name,
            &format!("GPO '{}' is not linked to any OU or domain.", gpo.display_name),
            "Unlinked GPOs create clutter and may contain misconfigurations that could cause issues if accidentally linked.",
            &format!("Review the GPO and delete if no longer needed: Remove-GPO -Guid {}", gpo.id),
            serde_json::json!({
                "gpo_id": gpo.id,
                "created_date": gpo.created_time,
                "modified_date": gpo.modified_time
            }),
        ));
    }

    findings
}

/// Evaluate SYSVOL permissions
pub fn evaluate_sysvol_permissions(permissions: &[SysvolPermission], sysvol_path: &str) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // Dangerous identities that should not have write access
    let safe_writers = [
        "NT AUTHORITY\\SYSTEM",
        "BUILTIN\\Administrators", 
        "Domain Admins",
        "Enterprise Admins",
        "CREATOR OWNER",
    ];

    for perm in permissions {
        if perm.is_dangerous {
            let is_safe = safe_writers.iter().any(|s| {
                perm.identity.eq_ignore_ascii_case(s) ||
                perm.identity.to_lowercase().contains(&s.to_lowercase())
            });

            if !is_safe && perm.access_type.eq_ignore_ascii_case("allow") {
                findings.push(SecurityFinding::new(
                    FindingCategory::SysvolPermissions,
                    "Insecure SYSVOL Permissions",
                    Severity::Critical,
                    &format!("SYSVOL - {}", perm.identity),
                    &format!(
                        "SYSVOL has write permissions ({}) granted to '{}'.",
                        perm.rights,
                        perm.identity
                    ),
                    "Attackers can tamper with GPO files, scripts, and policies that apply to all domain members, leading to widespread compromise.",
                    "Restrict SYSVOL permissions. Remove write access for non-admin principals. Only Domain Admins and SYSTEM should have write access.",
                    serde_json::json!({
                        "path": sysvol_path,
                        "identity": perm.identity,
                        "rights": perm.rights,
                        "access_type": perm.access_type
                    }),
                ));
            }
        }
    }

    findings
}

/// Run full GPO audit
pub fn run_gpo_audit(gpos: &[GroupPolicyObject], sysvol_permissions: &[SysvolPermission], sysvol_path: &str) -> Vec<SecurityFinding> {
    let mut all_findings = Vec::new();

    for gpo in gpos {
        all_findings.extend(evaluate_gpo_permissions(gpo));
        all_findings.extend(evaluate_gpo_dc_links(gpo));
        all_findings.extend(evaluate_unlinked_gpos(gpo));
    }

    all_findings.extend(evaluate_sysvol_permissions(sysvol_permissions, sysvol_path));

    all_findings
}

/// Calculate GPO audit summary
pub fn calculate_gpo_summary(gpos: &[GroupPolicyObject], findings: &[SecurityFinding]) -> GpoAuditSummary {
    let gpos_with_dangerous_permissions = gpos.iter()
        .filter(|g| g.permissions.iter().any(|p| p.permission.is_dangerous() && !is_privileged_trustee(&p.trustee)))
        .count() as u32;

    let gpos_linked_to_dc_ou = gpos.iter()
        .filter(|g| g.links.iter().any(|l| l.ou_distinguished_name.to_lowercase().contains("ou=domain controllers")))
        .count() as u32;

    let unlinked_gpos = gpos.iter()
        .filter(|g| g.links.is_empty())
        .count() as u32;

    let gpos_with_weak_dc_permissions = findings.iter()
        .filter(|f| f.issue == "GPO Linked to Domain Controllers with Weak Permissions")
        .count() as u32;

    let sysvol_permission_issues = findings.iter()
        .filter(|f| matches!(f.category, FindingCategory::SysvolPermissions))
        .count() as u32;

    GpoAuditSummary {
        total_gpos: gpos.len() as u32,
        gpos_with_dangerous_permissions,
        gpos_linked_to_dc_ou,
        unlinked_gpos,
        gpos_with_weak_dc_permissions,
        sysvol_permission_issues,
    }
}
