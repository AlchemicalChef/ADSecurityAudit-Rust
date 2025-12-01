//! Active Directory Permissions Audit Module
//!
//! Detects dangerous Access Control Entries (ACEs) that could enable
//! privilege escalation, persistence, and domain compromise attacks.
//!
//! # Critical Checks Performed
//!
//! ## Enterprise Key Admins Misconfiguration
//! A well-known Windows Server 2016+ bug where Enterprise Key Admins is granted
//! GenericAll instead of scoped WriteProperty for msDS-KeyCredentialLink.
//! This can unintentionally enable **DCSync attacks**.
//!
//! ## Dangerous Rights on Critical OUs
//! Non-privileged principals with excessive rights on:
//! - Domain Controllers OU
//! - AdminSDHolder container
//! - Domain root naming context
//!
//! # Dangerous Permission Reference
//!
//! | Permission | GUID | Impact |
//! |------------|------|--------|
//! | GenericAll | - | Full control - can do anything |
//! | WriteDacl | - | Modify ACL - grant self any rights |
//! | WriteOwner | - | Take ownership - then modify ACL |
//! | GenericWrite | - | Modify most attributes |
//! | WriteProperty | varies | Modify specific attributes |
//! | DS-Replication-Get-Changes | 1131f6aa-... | Read directory changes |
//! | DS-Replication-Get-Changes-All | 1131f6ad-... | **DCSync** - extract password hashes |
//!
//! # Extended Rights GUIDs
//!
//! - `msDS-KeyCredentialLink`: `5b47d60f-6090-40b2-9f37-2a4de88f3063`
//! - `DS-Replication-Get-Changes`: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
//! - `DS-Replication-Get-Changes-All`: `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
//! - `User-Force-Change-Password`: `00299570-246d-11d0-a768-00aa006e0529`
//!
//! # Attack Scenarios Detected
//!
//! | Finding | Risk | Attack |
//! |---------|------|--------|
//! | EKA GenericAll | Critical | DCSync via msDS-KeyCredentialLink |
//! | WriteDacl on DC OU | Critical | Grant self replication rights |
//! | WriteOwner on Domain | Critical | Take ownership, then full control |
//! | Non-admin with GenericWrite | High | Modify sensitive attributes |
//!
//! # Remediation
//!
//! 1. Remove over-privileged ACEs using ADSIEdit or PowerShell
//! 2. Scope Enterprise Key Admins to msDS-KeyCredentialLink only
//! 3. Implement regular permission audits with BloodHound
//! 4. Enable Directory Service Changes auditing (Event ID 5136)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DangerousRight {
    GenericAll,
    WriteDacl,
    WriteOwner,
    GenericWrite,
    WriteProperty,
    ExtendedRight,
    CreateChild,
    DeleteChild,
    Self_,
}

impl std::fmt::Display for DangerousRight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DangerousRight::GenericAll => write!(f, "GenericAll (Full Control)"),
            DangerousRight::WriteDacl => write!(f, "WriteDacl (Modify Permissions)"),
            DangerousRight::WriteOwner => write!(f, "WriteOwner (Take Ownership)"),
            DangerousRight::GenericWrite => write!(f, "GenericWrite"),
            DangerousRight::WriteProperty => write!(f, "WriteProperty"),
            DangerousRight::ExtendedRight => write!(f, "ExtendedRight"),
            DangerousRight::CreateChild => write!(f, "CreateChild"),
            DangerousRight::DeleteChild => write!(f, "DeleteChild"),
            DangerousRight::Self_ => write!(f, "Self"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionEntry {
    pub identity_reference: String,
    pub identity_sid: String,
    pub object_dn: String,
    pub object_type_name: String,
    pub active_directory_rights: String,
    pub access_control_type: String, // Allow or Deny
    pub object_type_guid: String, // Specific property/extended right GUID
    pub inherited_object_type_guid: String,
    pub is_inherited: bool,
    pub inheritance_flags: String,
    pub propagation_flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionFinding {
    pub category: String,
    pub issue: String,
    pub severity: String,
    pub severity_level: u8,
    pub affected_object: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub details: PermissionDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDetails {
    pub object_dn: String,
    pub identity: String,
    pub identity_sid: String,
    pub active_directory_rights: String,
    pub access_control_type: String,
    pub object_type: String,
    pub is_inherited: bool,
    pub expected_rights: Option<String>,
}

// Enterprise Key Admins specific check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseKeyAdminsAnalysis {
    pub exists: bool,
    pub group_dn: Option<String>,
    pub member_count: u32,
    pub has_excessive_rights: bool,
    pub has_dcsync_capability: bool,
    pub permissions: Vec<PermissionEntry>,
    pub findings: Vec<PermissionFinding>,
}

// Critical OUs analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalOuAnalysis {
    pub ou_dn: String,
    pub ou_name: String,
    pub dangerous_permissions: Vec<PermissionEntry>,
    pub findings: Vec<PermissionFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsAudit {
    pub total_dangerous_permissions: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub enterprise_key_admins: EnterpriseKeyAdminsAnalysis,
    pub critical_ous: Vec<CriticalOuAnalysis>,
    pub all_findings: Vec<PermissionFinding>,
    pub risk_score: u32,
    pub scan_timestamp: String,
    pub recommendations: Vec<PermissionRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRecommendation {
    pub priority: u8,
    pub title: String,
    pub description: String,
    pub steps: Vec<String>,
}

// Well-known GUIDs
pub const KEY_CREDENTIAL_LINK_GUID: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
pub const DS_REPLICATION_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
pub const DS_REPLICATION_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";

// Well-known SIDs for filtering
pub const SYSTEM_SID: &str = "S-1-5-18";
pub const DOMAIN_ADMINS_RID: &str = "-512";
pub const ENTERPRISE_ADMINS_RID: &str = "-519";

impl PermissionsAudit {
    pub fn new() -> Self {
        Self {
            total_dangerous_permissions: 0,
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            enterprise_key_admins: EnterpriseKeyAdminsAnalysis {
                exists: false,
                group_dn: None,
                member_count: 0,
                has_excessive_rights: false,
                has_dcsync_capability: false,
                permissions: Vec::new(),
                findings: Vec::new(),
            },
            critical_ous: Vec::new(),
            all_findings: Vec::new(),
            risk_score: 0,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            recommendations: Vec::new(),
        }
    }

    pub fn analyze_enterprise_key_admins(&mut self, permissions: &[PermissionEntry], domain_dn: &str) {
        self.enterprise_key_admins.exists = true;
        self.enterprise_key_admins.permissions = permissions.to_vec();

        for perm in permissions {
            // Check for GenericAll, WriteDacl, WriteOwner, GenericWrite
            let rights_upper = perm.active_directory_rights.to_uppercase();
            let has_excessive = rights_upper.contains("GENERICALL") 
                || rights_upper.contains("WRITEDACL")
                || rights_upper.contains("WRITEOWNER")
                || rights_upper.contains("GENERICWRITE");

            if has_excessive {
                self.enterprise_key_admins.has_excessive_rights = true;
                
                // Check for DCSync capability
                if rights_upper.contains("GENERICALL") || rights_upper.contains("WRITEDACL") {
                    self.enterprise_key_admins.has_dcsync_capability = true;
                }

                let finding = PermissionFinding {
                    category: "Dangerous Permissions".to_string(),
                    issue: "Enterprise Key Admins Over-Privileged (Misconfiguration Bug)".to_string(),
                    severity: "Critical".to_string(),
                    severity_level: 4,
                    affected_object: format!("Enterprise Key Admins - {}", domain_dn),
                    description: format!(
                        "Enterprise Key Admins group has excessive permissions '{}' on the Domain Naming Context. This is a known misconfiguration bug where EKA was granted full access instead of just ReadProperty/WriteProperty for msDS-KeyCredentialLink.",
                        perm.active_directory_rights
                    ),
                    impact: "This misconfiguration can unintentionally grant DCSync permissions, allowing members of Enterprise Key Admins to extract password hashes for all domain accounts. Attackers can exploit this for full domain compromise.".to_string(),
                    remediation: format!(
                        "Remove the over-privileged ACE and grant only the required permissions:\n\
                        1. Remove the current ACE using ADSIEdit or dsacls.exe\n\
                        2. Grant only ReadProperty and WriteProperty for msDS-KeyCredentialLink (GUID: {})\n\
                        3. Verify no GenericAll or WriteDacl rights remain\n\
                        4. Monitor for DCSync attempts: Check Event ID 4662 for DS-Replication-Get-Changes operations",
                        KEY_CREDENTIAL_LINK_GUID
                    ),
                    details: PermissionDetails {
                        object_dn: domain_dn.to_string(),
                        identity: perm.identity_reference.clone(),
                        identity_sid: perm.identity_sid.clone(),
                        active_directory_rights: perm.active_directory_rights.clone(),
                        access_control_type: perm.access_control_type.clone(),
                        object_type: perm.object_type_guid.clone(),
                        is_inherited: perm.is_inherited,
                        expected_rights: Some("ReadProperty, WriteProperty for msDS-KeyCredentialLink only".to_string()),
                    },
                };

                self.enterprise_key_admins.findings.push(finding.clone());
                self.all_findings.push(finding);
                self.critical_findings += 1;
                self.risk_score += 50;
            }

            // Check if permissions are not scoped to msDS-KeyCredentialLink
            let object_type_empty = perm.object_type_guid == "00000000-0000-0000-0000-000000000000";
            let not_key_cred = perm.object_type_guid != KEY_CREDENTIAL_LINK_GUID;
            let has_write_property = rights_upper.contains("WRITEPROPERTY");

            if object_type_empty || (not_key_cred && has_write_property) {
                if !has_excessive { // Don't double-count
                    let finding = PermissionFinding {
                        category: "Dangerous Permissions".to_string(),
                        issue: "Enterprise Key Admins Permissions Not Scoped to msDS-KeyCredentialLink".to_string(),
                        severity: "High".to_string(),
                        severity_level: 3,
                        affected_object: format!("Enterprise Key Admins - {}", domain_dn),
                        description: "Enterprise Key Admins has WriteProperty rights that are not scoped to the msDS-KeyCredentialLink attribute only.".to_string(),
                        impact: "Excessive property write permissions may allow unintended modifications to domain objects beyond the intended key credential management scope.".to_string(),
                        remediation: format!(
                            "Scope Enterprise Key Admins permissions specifically to msDS-KeyCredentialLink attribute (GUID: {}) only.",
                            KEY_CREDENTIAL_LINK_GUID
                        ),
                        details: PermissionDetails {
                            object_dn: domain_dn.to_string(),
                            identity: perm.identity_reference.clone(),
                            identity_sid: perm.identity_sid.clone(),
                            active_directory_rights: perm.active_directory_rights.clone(),
                            access_control_type: perm.access_control_type.clone(),
                            object_type: perm.object_type_guid.clone(),
                            is_inherited: perm.is_inherited,
                            expected_rights: Some(KEY_CREDENTIAL_LINK_GUID.to_string()),
                        },
                    };

                    self.enterprise_key_admins.findings.push(finding.clone());
                    self.all_findings.push(finding);
                    self.high_findings += 1;
                    self.risk_score += 25;
                }
            }
        }
    }

    pub fn analyze_critical_ou(&mut self, ou_dn: &str, permissions: &[PermissionEntry]) {
        let mut ou_analysis = CriticalOuAnalysis {
            ou_dn: ou_dn.to_string(),
            ou_name: ou_dn.split(',').next().unwrap_or(ou_dn).to_string(),
            dangerous_permissions: Vec::new(),
            findings: Vec::new(),
        };

        for perm in permissions {
            // Skip inherited ACEs and well-known principals
            if perm.is_inherited {
                continue;
            }

            let identity_upper = perm.identity_reference.to_uppercase();
            if identity_upper.contains("SYSTEM") 
                || identity_upper.contains("DOMAIN ADMINS")
                || identity_upper.contains("ENTERPRISE ADMINS")
                || perm.identity_sid == SYSTEM_SID
                || perm.identity_sid.ends_with(DOMAIN_ADMINS_RID)
                || perm.identity_sid.ends_with(ENTERPRISE_ADMINS_RID) {
                continue;
            }

            // Check for dangerous rights
            let rights_upper = perm.active_directory_rights.to_uppercase();
            let dangerous_rights = ["GENERICALL", "WRITEDACL", "WRITEOWNER", "GENERICWRITE"];
            
            let has_dangerous = dangerous_rights.iter().any(|r| rights_upper.contains(r));

            if has_dangerous {
                ou_analysis.dangerous_permissions.push(perm.clone());
                
                let finding = PermissionFinding {
                    category: "Dangerous Permissions".to_string(),
                    issue: "Dangerous Rights on Critical OU".to_string(),
                    severity: "High".to_string(),
                    severity_level: 3,
                    affected_object: format!("{} - {}", ou_dn, perm.identity_reference),
                    description: format!(
                        "Principal '{}' has dangerous rights '{}' on critical OU.",
                        perm.identity_reference, perm.active_directory_rights
                    ),
                    impact: "Attackers who compromise this principal can create/modify objects in this OU, potentially adding rogue Domain Controllers or admin accounts.".to_string(),
                    remediation: "Review and restrict permissions. Remove unnecessary rights using Active Directory Users and Computers > Advanced Security Settings.".to_string(),
                    details: PermissionDetails {
                        object_dn: ou_dn.to_string(),
                        identity: perm.identity_reference.clone(),
                        identity_sid: perm.identity_sid.clone(),
                        active_directory_rights: perm.active_directory_rights.clone(),
                        access_control_type: perm.access_control_type.clone(),
                        object_type: perm.object_type_guid.clone(),
                        is_inherited: perm.is_inherited,
                        expected_rights: None,
                    },
                };

                ou_analysis.findings.push(finding.clone());
                self.all_findings.push(finding);
                self.high_findings += 1;
                self.total_dangerous_permissions += 1;
                self.risk_score += 20;
            }
        }

        self.critical_ous.push(ou_analysis);
    }

    pub fn generate_recommendations(&mut self) {
        let mut recommendations = Vec::new();

        if self.enterprise_key_admins.has_excessive_rights {
            recommendations.push(PermissionRecommendation {
                priority: 1,
                title: "Fix Enterprise Key Admins Over-Privileged ACE".to_string(),
                description: "Enterprise Key Admins has excessive permissions that could enable DCSync attacks.".to_string(),
                steps: vec![
                    "Open ADSIEdit and connect to the Default naming context".to_string(),
                    format!("Navigate to the domain root and open Properties > Security"),
                    "Find the ACE for Enterprise Key Admins".to_string(),
                    "Remove the current ACE with excessive permissions".to_string(),
                    format!(
                        "Add a new ACE: Allow Enterprise Key Admins ReadProperty/WriteProperty on msDS-KeyCredentialLink (GUID: {})",
                        KEY_CREDENTIAL_LINK_GUID
                    ),
                    "Verify the change and test key credential operations".to_string(),
                ],
            });
        }

        if self.total_dangerous_permissions > 0 {
            recommendations.push(PermissionRecommendation {
                priority: 2,
                title: "Remove Dangerous Permissions on Critical OUs".to_string(),
                description: format!(
                    "Found {} dangerous permission(s) on critical OUs that could allow privilege escalation.",
                    self.total_dangerous_permissions
                ),
                steps: vec![
                    "Open Active Directory Users and Computers".to_string(),
                    "Enable Advanced Features (View > Advanced Features)".to_string(),
                    "For each affected OU, right-click and select Properties > Security > Advanced".to_string(),
                    "Review each non-inherited ACE and remove unnecessary permissions".to_string(),
                    "Document all changes for audit purposes".to_string(),
                    "Monitor Event ID 5136 for future permission changes".to_string(),
                ],
            });
        }

        // General recommendations
        recommendations.push(PermissionRecommendation {
            priority: 3,
            title: "Implement AD Permission Monitoring".to_string(),
            description: "Set up monitoring for permission changes on sensitive AD objects.".to_string(),
            steps: vec![
                "Enable Directory Service Changes auditing in Group Policy".to_string(),
                "Configure advanced audit policy: DS Access > Audit Directory Service Changes".to_string(),
                "Monitor Event IDs: 5136 (object modified), 5137 (object created), 5141 (object deleted)".to_string(),
                "Set up alerts for permission changes on Domain Controllers OU, AdminSDHolder, and domain root".to_string(),
                "Consider using tools like BloodHound to regularly audit AD permissions".to_string(),
            ],
        });

        self.recommendations = recommendations;
    }
}
