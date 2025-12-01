//! Domain Admin Equivalence Audit Module
//!
//! Comprehensive detection of "shadow admins" - principals that have Domain Admin
//! equivalent privileges through indirect attack paths, misconfigurations, or
//! overlooked permissions.
//!
//! # What is Domain Admin Equivalence?
//!
//! A principal has "Domain Admin Equivalence" if they can gain Domain Admin
//! privileges through exploitation, even without being a direct member of
//! Domain Admins. These are often called "shadow admins" or "hidden admins".
//!
//! # Attack Paths Detected
//!
//! ## Direct Privilege Paths
//!
//! | Attack Path | Description | Risk |
//! |-------------|-------------|------|
//! | DCSync Rights | Can replicate domain credentials | Critical |
//! | Password Reset on DA | Can reset Domain Admin passwords | Critical |
//! | WriteDACL on Domain | Can grant self any domain rights | Critical |
//! | WriteOwner on Domain | Can take domain ownership | Critical |
//!
//! ## Delegation Attacks
//!
//! | Attack Path | Description | Risk |
//! |-------------|-------------|------|
//! | Unconstrained Delegation | Collects TGTs, impersonate anyone | Critical |
//! | Constrained to DC | Can impersonate to Domain Controller | Critical |
//! | RBCD on DC | Configure delegation to Domain Controller | Critical |
//!
//! ## Credential Theft Paths
//!
//! | Attack Path | Description | Risk |
//! |-------------|-------------|------|
//! | Shadow Credentials | Write msDS-KeyCredentialLink for TGT | Critical |
//! | Write SPN | Kerberoast to obtain service credentials | High |
//! | Ghost Accounts | AdminCount=1 but not in protected group | Medium |
//!
//! ## AD Certificate Services (ADCS) Attacks
//!
//! | Attack Path | Description | Risk |
//! |-------------|-------------|------|
//! | ESC1 | Template allows subject alt name | Critical |
//! | ESC2 | Any Purpose or No EKU template | Critical |
//! | ESC3 | Enrollment Agent template abuse | Critical |
//! | ESC4 | Write access to certificate template | Critical |
//! | ESC5 | Write access to PKI objects | High |
//! | ESC8 | NTLM relay to web enrollment | High |
//!
//! ## Infrastructure Control
//!
//! | Attack Path | Description | Risk |
//! |-------------|-------------|------|
//! | DNS Zone Control | Modify DNS to redirect traffic | High |
//! | GPO Link Rights | Link malicious GPO to DCs | Critical |
//! | OU Control (DC OU) | Modify Domain Controllers OU | Critical |
//! | Computer Object Control | Modify DC computer objects | Critical |
//! | Exchange PrivExchange | WriteDACL via Exchange groups | Critical |
//!
//! ## Sync Account Compromise
//!
//! | Attack Path | Description | Risk |
//! |-------------|-------------|------|
//! | Azure AD Connect | Has DCSync rights by design | Critical |
//! | MSOL Account | Password stored in SQL, extractable | Critical |
//!
//! # Usage
//!
//! ```rust,ignore
//! let audit = DAEquivalenceAudit::new();
//!
//! // Analyze for shadow admin paths
//! let results = client.analyze_da_equivalence().await?;
//!
//! // Results contain all detected attack paths
//! for principal in results.equivalent_principals {
//!     println!("Shadow Admin: {} via {} paths",
//!         principal.principal,
//!         principal.total_paths
//!     );
//! }
//! ```
//!
//! # References
//!
//! - [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Attack path analysis
//! - [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) - ADCS attacks
//! - [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

use serde::{Deserialize, Serialize};

// ==========================================
// Domain Admin Equivalence Audit Types
// ==========================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivalenceEvidence {
    pub reason: String,
    pub target: String,
    pub attack_path: Option<String>,
    pub rights: Option<String>,
    pub distinguished_name: Option<String>,
    pub additional_context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivalentPrincipal {
    pub principal: String,
    pub evidence: Vec<EquivalenceEvidence>,
    pub is_critical: bool,
    pub total_paths: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostAccount {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub admin_count: i32,
    pub in_protected_group: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCredential {
    pub object_name: String,
    pub distinguished_name: String,
    pub object_class: String,
    pub has_key_credential_link: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCredentialWriteAccess {
    pub principal: String,
    pub target_name: String,
    pub target_dn: String,
    pub target_type: String, // "Computer" or "User"
    pub rights: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteSPNVulnerability {
    pub principal: String,
    pub target_account: String,
    pub target_dn: String,
    pub rights: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconstrainedDelegation {
    pub account_name: String,
    pub distinguished_name: String,
    pub account_type: String, // "Computer" or "User"
    pub operating_system: Option<String>,
    pub spns: Vec<String>,
    pub is_domain_controller: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBCDWriteAccess {
    pub principal: String,
    pub target_name: String,
    pub target_dn: String,
    pub is_domain_controller: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSZoneControl {
    pub principal: String,
    pub zone_name: String,
    pub zone_dn: String,
    pub rights: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPOLinkRights {
    pub principal: String,
    pub target: String,
    pub target_dn: String,
    pub rights: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangePrivExchange {
    pub principal: String,
    pub group_name: String,
    pub has_writedacl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedAccountTakeover {
    pub principal: String,
    pub target_account: String,
    pub target_dn: String,
    pub rights: String,
    pub can_reset_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembershipControl {
    pub principal: String,
    pub group_name: String,
    pub group_dn: String,
    pub rights: String,
    pub is_add_member_right: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OUControl {
    pub principal: String,
    pub ou_name: String,
    pub ou_dn: String,
    pub rights: String,
    pub contains_privileged_objects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputerObjectControl {
    pub principal: String,
    pub computer_name: String,
    pub computer_dn: String,
    pub rights: String,
    pub is_domain_controller: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstrainedDelegationToDC {
    pub account_name: String,
    pub distinguished_name: String,
    pub delegation_target: String,
    pub is_protocol_transition: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC1Vulnerability {
    pub template_name: String,
    pub template_dn: String,
    pub enrollee_supplies_subject: bool,
    pub dangerous_eku: bool,
    pub no_manager_approval: bool,
    pub enroller: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC4Vulnerability {
    pub template_name: String,
    pub template_dn: String,
    pub principal: String,
    pub write_access_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC8Vulnerability {
    pub ca_name: String,
    pub web_enrollment_server: String,
    pub ntlm_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureADConnect {
    pub account_name: String,
    pub distinguished_name: String,
    pub is_enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC2Vulnerability {
    pub template_name: String,
    pub template_dn: String,
    pub has_any_purpose_eku: bool,
    pub has_no_eku: bool,
    pub enroller: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC3Vulnerability {
    pub template_name: String,
    pub template_dn: String,
    pub is_enrollment_agent: bool,
    pub authorized_signatures_required: u32,
    pub enroller: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC5Vulnerability {
    pub object_name: String,
    pub object_dn: String,
    pub object_type: String, // "CA", "NTAuthCertificates", etc.
    pub principal: String,
    pub write_access_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESC7Vulnerability {
    pub ca_name: String,
    pub ca_dn: String,
    pub principal: String,
    pub has_manage_ca: bool,
    pub has_manage_certificates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPOControl {
    pub principal: String,
    pub gpo_name: String,
    pub gpo_guid: String,
    pub gpo_dn: String,
    pub rights: String,
    pub linked_to_privileged_scope: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGroupMembership {
    pub principal: String,
    pub group_name: String,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyLogonScript {
    pub account_name: String,
    pub distinguished_name: String,
    pub script_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidHistoryEntry {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub injected_sid: String,
    pub is_same_domain: bool,
    pub is_privileged_rid: bool,
    pub rid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousGroupMember {
    pub group_name: String,
    pub member_sam_account_name: String,
    pub member_dn: String,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DCSyncRight {
    pub principal: String,
    pub rights: Vec<String>,
    pub has_full_dcsync: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PKIVulnerability {
    pub target_type: String, // CA, Template, NTAuth
    pub target_name: String,
    pub principal: String,
    pub rights: String,
    pub attack_vector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LapsExposure {
    pub computer_name: String,
    pub principal: String,
    pub can_read_password: bool,
    pub can_write_expiration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmsaExposure {
    pub gmsa_name: String,
    pub principal: String,
    pub can_read_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPasswordConfig {
    pub account: String,
    pub issue: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAEquivalenceFinding {
    pub category: String,
    pub issue: String,
    pub severity: String,
    pub severity_level: u8,
    pub affected_object: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub evidence: Vec<EquivalenceEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAEquivalenceRecommendation {
    pub priority: u8,
    pub title: String,
    pub description: String,
    pub steps: Vec<String>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAEquivalenceAudit {
    pub total_equivalent_principals: u32,
    pub critical_principals: u32,
    pub ghost_accounts_count: u32,
    pub shadow_credentials_count: u32,
    pub sid_history_issues: u32,
    pub dcsync_principals: u32,
    pub pki_vulnerabilities: u32,
    pub laps_exposures: u32,
    pub gmsa_exposures: u32,
    pub dangerous_group_members: u32,
    pub weak_password_configs: u32,
    
    pub shadow_credential_write_count: u32,
    pub write_spn_count: u32,
    pub unconstrained_delegation_count: u32,
    pub rbcd_write_count: u32,
    pub dns_zone_control_count: u32,
    pub gpo_link_rights_count: u32,
    pub exchange_privexchange_count: u32,
    pub privileged_takeover_count: u32,
    pub group_membership_control_count: u32,
    pub ou_control_count: u32,
    pub computer_control_count: u32,
    pub gpo_control_count: u32,
    pub session_group_count: u32,
    pub legacy_logon_script_count: u32,
    pub constrained_delegation_to_dc_count: u32,
    pub esc1_count: u32,
    pub esc2_count: u32,
    pub esc3_count: u32,
    pub esc4_count: u32,
    pub esc5_count: u32,
    pub esc7_count: u32,
    pub esc8_count: u32,
    pub azure_ad_connect_count: u32,

    pub equivalent_principals: Vec<EquivalentPrincipal>,
    pub ghost_accounts: Vec<GhostAccount>,
    pub shadow_credentials: Vec<ShadowCredential>,
    pub sid_history_entries: Vec<SidHistoryEntry>,
    pub dcsync_rights: Vec<DCSyncRight>,
    pub pki_vulnerabilities_list: Vec<PKIVulnerability>,
    pub laps_exposures_list: Vec<LapsExposure>,
    pub gmsa_exposures_list: Vec<GmsaExposure>,
    pub dangerous_members: Vec<DangerousGroupMember>,
    pub weak_passwords: Vec<WeakPasswordConfig>,
    
    pub shadow_credential_writes: Vec<ShadowCredentialWriteAccess>,
    pub write_spn_vulnerabilities: Vec<WriteSPNVulnerability>,
    pub unconstrained_delegations: Vec<UnconstrainedDelegation>,
    pub rbcd_write_accesses: Vec<RBCDWriteAccess>,
    pub dns_zone_controls: Vec<DNSZoneControl>,
    pub gpo_link_rights_list: Vec<GPOLinkRights>,
    pub exchange_privexchanges: Vec<ExchangePrivExchange>,
    pub privileged_takeovers: Vec<PrivilegedAccountTakeover>,
    pub group_membership_controls: Vec<GroupMembershipControl>,
    pub ou_controls: Vec<OUControl>,
    pub computer_controls: Vec<ComputerObjectControl>,
    pub gpo_controls: Vec<GPOControl>,
    pub session_group_memberships: Vec<SessionGroupMembership>,
    pub legacy_logon_scripts: Vec<LegacyLogonScript>,
    pub constrained_delegation_to_dcs: Vec<ConstrainedDelegationToDC>,
    pub esc1_vulnerabilities: Vec<ESC1Vulnerability>,
    pub esc2_vulnerabilities: Vec<ESC2Vulnerability>,
    pub esc3_vulnerabilities: Vec<ESC3Vulnerability>,
    pub esc4_vulnerabilities: Vec<ESC4Vulnerability>,
    pub esc5_vulnerabilities: Vec<ESC5Vulnerability>,
    pub esc7_vulnerabilities: Vec<ESC7Vulnerability>,
    pub esc8_vulnerabilities: Vec<ESC8Vulnerability>,
    pub azure_ad_connects: Vec<AzureADConnect>,

    pub findings: Vec<DAEquivalenceFinding>,
    pub risk_score: u32,
    pub scan_timestamp: String,
    pub recommendations: Vec<DAEquivalenceRecommendation>,
}

// ==========================================
// Well-Known Dangerous Groups
// ==========================================

pub const DANGEROUS_BUILTIN_GROUPS: [(&str, &str); 5] = [
    ("Print Operators", "Load printer drivers on DCs -> Execute code as SYSTEM"),
    ("Server Operators", "Modify services on DCs -> Execute code as SYSTEM"),
    ("Backup Operators", "Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise"),
    ("Account Operators", "Modify non-protected accounts -> Add to privileged groups"),
    ("DnsAdmins", "Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM"),
];

// Well-known privileged RIDs
pub const PRIVILEGED_RIDS: [&str; 3] = ["500", "512", "519"];

// DCSync required rights GUIDs
pub const DCSYNC_RIGHTS: [(&str, &str); 3] = [
    ("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
    ("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
    ("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c"),
];

// Legitimate principals that normally have broad control
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

pub const KEY_CREDENTIAL_LINK_GUID: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
pub const SPN_GUID: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";
pub const RBCD_GUID: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
pub const GP_LINK_GUID: &str = "f30e3bc2-9ff0-11d1-b603-0000f80367c1";
pub const PASSWORD_RESET_GUID: &str = "00299570-246d-11d0-a768-00aa006e0529";
pub const MEMBER_ATTRIBUTE_GUID: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";

// PKI/ADCS Extended Rights GUIDs
pub const CERTIFICATE_ENROLLMENT_GUID: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
pub const CERTIFICATE_AUTOENROLLMENT_GUID: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
pub const MANAGE_CA_GUID: &str = "ee98ee94-de5f-4f4e-8e89-0adf6c2acc8c";

// PKI EKUs (Extended Key Usage)
pub const CLIENT_AUTHENTICATION_EKU: &str = "1.3.6.1.5.5.7.3.2";
pub const SMART_CARD_LOGON_EKU: &str = "1.3.6.1.4.1.311.20.2.2";
pub const ANY_PURPOSE_EKU: &str = "2.5.29.37.0";
pub const CERTIFICATE_REQUEST_AGENT_EKU: &str = "1.3.6.1.4.1.311.20.2.1";

// Certificate Template Flags
pub const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
pub const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;

impl DAEquivalenceAudit {
    pub fn new() -> Self {
        Self {
            total_equivalent_principals: 0,
            critical_principals: 0,
            ghost_accounts_count: 0,
            shadow_credentials_count: 0,
            sid_history_issues: 0,
            dcsync_principals: 0,
            pki_vulnerabilities: 0,
            laps_exposures: 0,
            gmsa_exposures: 0,
            dangerous_group_members: 0,
            weak_password_configs: 0,
            // Initialize new counters
            shadow_credential_write_count: 0,
            write_spn_count: 0,
            unconstrained_delegation_count: 0,
            rbcd_write_count: 0,
            dns_zone_control_count: 0,
            gpo_link_rights_count: 0,
            exchange_privexchange_count: 0,
            privileged_takeover_count: 0,
            group_membership_control_count: 0,
            ou_control_count: 0,
            computer_control_count: 0,
            gpo_control_count: 0,
            session_group_count: 0,
            legacy_logon_script_count: 0,
            constrained_delegation_to_dc_count: 0,
            esc1_count: 0,
            esc2_count: 0,
            esc3_count: 0,
            esc4_count: 0,
            esc5_count: 0,
            esc7_count: 0,
            esc8_count: 0,
            azure_ad_connect_count: 0,
            equivalent_principals: Vec::new(),
            ghost_accounts: Vec::new(),
            shadow_credentials: Vec::new(),
            sid_history_entries: Vec::new(),
            dcsync_rights: Vec::new(),
            pki_vulnerabilities_list: Vec::new(),
            laps_exposures_list: Vec::new(),
            gmsa_exposures_list: Vec::new(),
            dangerous_members: Vec::new(),
            weak_passwords: Vec::new(),
            // Initialize new lists
            shadow_credential_writes: Vec::new(),
            write_spn_vulnerabilities: Vec::new(),
            unconstrained_delegations: Vec::new(),
            rbcd_write_accesses: Vec::new(),
            dns_zone_controls: Vec::new(),
            gpo_link_rights_list: Vec::new(),
            exchange_privexchanges: Vec::new(),
            privileged_takeovers: Vec::new(),
            group_membership_controls: Vec::new(),
            ou_controls: Vec::new(),
            computer_controls: Vec::new(),
            gpo_controls: Vec::new(),
            session_group_memberships: Vec::new(),
            legacy_logon_scripts: Vec::new(),
            constrained_delegation_to_dcs: Vec::new(),
            esc1_vulnerabilities: Vec::new(),
            esc2_vulnerabilities: Vec::new(),
            esc3_vulnerabilities: Vec::new(),
            esc4_vulnerabilities: Vec::new(),
            esc5_vulnerabilities: Vec::new(),
            esc7_vulnerabilities: Vec::new(),
            esc8_vulnerabilities: Vec::new(),
            azure_ad_connects: Vec::new(),
            findings: Vec::new(),
            risk_score: 0,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
            recommendations: Vec::new(),
        }
    }

    pub fn add_ghost_account(&mut self, account: GhostAccount) {
        self.ghost_accounts_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "AdminSDHolder Ghost Account".to_string(),
            severity: "Medium".to_string(),
            severity_level: 2,
            affected_object: account.sam_account_name.clone(),
            description: format!(
                "User '{}' has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account or a persistence backdoor where ACLs are frozen by SDProp.",
                account.sam_account_name
            ),
            impact: "Ghost accounts retain protected ACLs even after removal from privileged groups, potentially hiding malicious access.".to_string(),
            remediation: format!(
                "Clear the 'adminCount' attribute and enable permission inheritance:\n\nPowerShell:\nSet-ADUser -Identity '{}' -Clear adminCount\nEnable inheritance on the object in AD Users and Computers -> Security -> Advanced -> Enable inheritance\n\nReference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups",
                account.sam_account_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "adminCount=1 without protected group membership".to_string(),
                target: account.distinguished_name.clone(),
                attack_path: Some("Frozen ACLs may hide unauthorized access".to_string()),
                rights: None,
                distinguished_name: Some(account.distinguished_name.clone()),
                additional_context: None,
            }],
        });
        self.ghost_accounts.push(account);
    }

    pub fn add_shadow_credential(&mut self, cred: ShadowCredential) {
        self.shadow_credentials_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "Shadow Credentials Detected".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: cred.object_name.clone(),
            description: format!(
                "Object '{}' has 'msDS-KeyCredentialLink' populated. Unless Windows Hello for Business is deployed, this indicates a potential 'Shadow Credentials' attack (Whisker/Certipy) allowing account takeover.",
                cred.object_name
            ),
            impact: "Shadow Credentials allow attackers to authenticate as the target account without knowing the password.".to_string(),
            remediation: format!(
                "Investigate the msDS-KeyCredentialLink attribute. If not legitimate WHfB, clear immediately:\n\nPowerShell:\nGet-ADObject -Identity '{}' -Properties msDS-KeyCredentialLink\nSet-ADObject -Identity '{}' -Clear msDS-KeyCredentialLink\n\nReference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8",
                cred.distinguished_name, cred.distinguished_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "msDS-KeyCredentialLink attribute populated".to_string(),
                target: cred.object_name.clone(),
                attack_path: Some("Shadow Credentials -> Request TGT -> Full account takeover".to_string()),
                rights: None,
                distinguished_name: Some(cred.distinguished_name.clone()),
                additional_context: Some(format!("Object class: {}", cred.object_class)),
            }],
        });
        self.shadow_credentials.push(cred);
    }

    pub fn add_shadow_credential_write(&mut self, write_access: ShadowCredentialWriteAccess) {
        self.shadow_credential_write_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "Shadow Credentials Write Access".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: write_access.principal.clone(),
            description: format!(
                "Principal '{}' can write msDS-KeyCredentialLink on {} '{}'. This allows authentication as the target without knowing the password.",
                write_access.principal, write_access.target_type, write_access.target_name
            ),
            impact: format!("Write msDS-KeyCredentialLink -> Request TGT as {} -> Compromise system", write_access.target_type.to_lowercase()),
            remediation: format!(
                "Remove write permissions on msDS-KeyCredentialLink:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReferences:\n- Shadow Credentials: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8\n- Elad Shamir's Research: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab\n- Detection Guide: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials",
                write_access.target_dn, write_access.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Write access to msDS-KeyCredentialLink on {}", write_access.target_name),
                target: write_access.target_name.clone(),
                attack_path: Some("Write msDS-KeyCredentialLink -> Request TGT as target -> Full compromise".to_string()),
                rights: Some(write_access.rights.clone()),
                distinguished_name: Some(write_access.target_dn.clone()),
                additional_context: Some(format!("Target type: {}", write_access.target_type)),
            }],
        });
        self.shadow_credential_writes.push(write_access);
    }

    pub fn add_write_spn(&mut self, vuln: WriteSPNVulnerability) {
        self.write_spn_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "WriteSPN (Targeted Kerberoasting)".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: vuln.principal.clone(),
            description: format!(
                "Principal '{}' can write servicePrincipalName on privileged account '{}'. This enables targeted Kerberoasting (SPN Jacking).",
                vuln.principal, vuln.target_account
            ),
            impact: "Add fake SPN -> Request service ticket -> Offline password cracking -> Account compromise".to_string(),
            remediation: format!(
                "Remove write permissions on servicePrincipalName:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}' -and $_.ObjectType -eq '{}'}}\n# Remove the ACE\n\nReferences:\n- SPN Jacking: https://www.semperis.com/blog/spn-jacking/\n- Targeted Kerberoasting: https://www.thehacker.recipes/ad/movement/kerberos/kerberoast\n- ACE Abuse Guide: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse",
                vuln.target_dn, vuln.principal, SPN_GUID
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("WriteSPN on {}", vuln.target_account),
                target: vuln.target_account.clone(),
                attack_path: Some("Add fake SPN -> Request service ticket -> Offline password cracking".to_string()),
                rights: Some(vuln.rights.clone()),
                distinguished_name: Some(vuln.target_dn.clone()),
                additional_context: None,
            }],
        });
        self.write_spn_vulnerabilities.push(vuln);
    }

    pub fn add_unconstrained_delegation(&mut self, delegation: UnconstrainedDelegation) {
        if delegation.is_domain_controller {
            return; // DCs are expected to have unconstrained delegation
        }
        
        self.unconstrained_delegation_count += 1;
        let severity = if delegation.account_type == "Computer" { "High" } else { "Critical" };
        
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: format!("Unconstrained Delegation ({})", delegation.account_type),
            severity: severity.to_string(),
            severity_level: if severity == "Critical" { 4 } else { 3 },
            affected_object: delegation.account_name.clone(),
            description: format!(
                "{} '{}' has unconstrained Kerberos delegation enabled. Any user authenticating to this system will have their TGT cached, allowing impersonation.",
                delegation.account_type, delegation.account_name
            ),
            impact: "Compromise host -> Extract TGTs from memory -> Impersonate any user including Domain Admins".to_string(),
            remediation: format!(
                "Disable unconstrained delegation:\n\nPowerShell:\nSet-AD{} -Identity '{}' -TrustedForDelegation $false\n\nConsider using constrained delegation or RBCD instead.\n\nReferences:\n- Microsoft Constrained Delegation: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview\n- Delegation Abuse: https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained\n- Mitigation Strategies: https://adsecurity.org/?p=1667",
                delegation.account_type, delegation.account_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Unconstrained delegation on {} '{}'", delegation.account_type.to_lowercase(), delegation.account_name),
                target: delegation.account_name.clone(),
                attack_path: Some("Coerce authentication -> Capture TGT -> Impersonate user".to_string()),
                rights: None,
                distinguished_name: Some(delegation.distinguished_name.clone()),
                additional_context: delegation.operating_system.clone(),
            }],
        });
        self.unconstrained_delegations.push(delegation);
    }

    pub fn add_rbcd_write(&mut self, rbcd: RBCDWriteAccess) {
        self.rbcd_write_count += 1;
        let severity = if rbcd.is_domain_controller { "Critical" } else { "High" };
        
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "RBCD Write Access (AddAllowedToAct)".to_string(),
            severity: severity.to_string(),
            severity_level: if severity == "Critical" { 4 } else { 3 },
            affected_object: rbcd.principal.clone(),
            description: format!(
                "Principal '{}' can write msDS-AllowedToActOnBehalfOfOtherIdentity on '{}'. This allows configuring RBCD to impersonate users.",
                rbcd.principal, rbcd.target_name
            ),
            impact: if rbcd.is_domain_controller {
                "Add controlled machine to RBCD -> Impersonate DA to DC -> Full domain compromise".to_string()
            } else {
                "Add controlled machine to RBCD -> S4U2Self impersonation -> Compromise target".to_string()
            },
            remediation: format!(
                "Remove write permissions on msDS-AllowedToActOnBehalfOfOtherIdentity:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReferences:\n- RBCD Attack Guide: https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd\n- Elad Shamir's Research: https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html\n- Detection & Defense: https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1",
                rbcd.target_dn, rbcd.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Write RBCD on {}", rbcd.target_name),
                target: rbcd.target_name.clone(),
                attack_path: Some("Write msDS-AllowedToActOnBehalfOfOtherIdentity -> S4U2Self -> Impersonate users".to_string()),
                rights: Some("WriteProperty".to_string()),
                distinguished_name: Some(rbcd.target_dn.clone()),
                additional_context: if rbcd.is_domain_controller { Some("Target is Domain Controller".to_string()) } else { None },
            }],
        });
        self.rbcd_write_accesses.push(rbcd);
    }

    pub fn add_dns_zone_control(&mut self, dns: DNSZoneControl) {
        self.dns_zone_control_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "DNS Zone Control".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: dns.principal.clone(),
            description: format!(
                "Principal '{}' has control over DNS zone '{}'. This enables DNS poisoning and WPAD attacks.",
                dns.principal, dns.zone_name
            ),
            impact: "Modify DNS records -> Redirect traffic -> Capture credentials -> Lateral movement".to_string(),
            remediation: format!(
                "Remove excessive DNS zone permissions:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReference: https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/",
                dns.zone_dn, dns.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Control over DNS zone '{}'", dns.zone_name),
                target: dns.zone_name.clone(),
                attack_path: Some("Modify DNS -> Redirect traffic -> Credential capture".to_string()),
                rights: Some(dns.rights.clone()),
                distinguished_name: Some(dns.zone_dn.clone()),
                additional_context: None,
            }],
        });
        self.dns_zone_controls.push(dns);
    }

    pub fn add_gpo_link_rights(&mut self, gpo_link: GPOLinkRights) {
        self.gpo_link_rights_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "GPO Link Rights (WriteGPLink)".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: gpo_link.principal.clone(),
            description: format!(
                "Principal '{}' can write gpLink attribute on '{}'. This allows linking malicious GPOs.",
                gpo_link.principal, gpo_link.target
            ),
            impact: "Link malicious GPO -> Execute code on all computers in scope -> Domain compromise".to_string(),
            remediation: format!(
                "Remove WriteGPLink permissions:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}' -and $_.ObjectType -eq '{}'}}\n# Remove the ACE\n\nReference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/gp-permission-model",
                gpo_link.target_dn, gpo_link.principal, GP_LINK_GUID
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("WriteGPLink on {}", gpo_link.target),
                target: gpo_link.target.clone(),
                attack_path: Some("Link malicious GPO -> Code execution on all affected computers".to_string()),
                rights: Some(gpo_link.rights.clone()),
                distinguished_name: Some(gpo_link.target_dn.clone()),
                additional_context: None,
            }],
        });
        self.gpo_link_rights_list.push(gpo_link);
    }

    pub fn add_exchange_privexchange(&mut self, exchange: ExchangePrivExchange) {
        self.exchange_privexchange_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "Exchange PrivExchange Vulnerability".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: exchange.principal.clone(),
            description: format!(
                "Principal '{}' is member of '{}' with WriteDacl on domain. This enables the PrivExchange attack.",
                exchange.principal, exchange.group_name
            ),
            impact: "Compromise Exchange server -> Coerce authentication -> Relay to LDAP -> Grant DCSync rights -> Full domain compromise".to_string(),
            remediation: format!(
                "Remove WriteDacl from Exchange groups:\n\n1. Remove '{}' from '{}'\n2. Or remove WriteDacl permission from domain root for Exchange groups\n\nPowerShell:\nRemove-ADGroupMember -Identity '{}' -Members '{}' -Confirm:$false\n\nReference: https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/",
                exchange.principal, exchange.group_name, exchange.group_name, exchange.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Member of {} with WriteDacl on domain", exchange.group_name),
                target: "Domain Root".to_string(),
                attack_path: Some("PrivExchange -> Coerce auth -> LDAP relay -> DCSync -> Full compromise".to_string()),
                rights: Some("WriteDacl".to_string()),
                distinguished_name: None,
                additional_context: None,
            }],
        });
        self.exchange_privexchanges.push(exchange);
    }

    pub fn add_privileged_takeover(&mut self, takeover: PrivilegedAccountTakeover) {
        self.privileged_takeover_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "Privileged Account Takeover Rights".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: takeover.principal.clone(),
            description: format!(
                "Principal '{}' can {} privileged account '{}'. This allows direct privilege escalation.",
                takeover.principal,
                if takeover.can_reset_password { "reset password of" } else { "modify" },
                takeover.target_account
            ),
            impact: "Reset password or modify account -> Authenticate as privileged user -> Full access".to_string(),
            remediation: format!(
                "Remove takeover permissions:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReferences:\n- ACL Attack Paths: https://adsecurity.org/?p=3164\n- ACE Abuse Guide: https://www.thehacker.recipes/ad/movement/dacl\n- Bloodhound Analysis: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword",
                takeover.target_dn, takeover.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Takeover rights on {}", takeover.target_account),
                target: takeover.target_account.clone(),
                attack_path: Some("Modify privileged account -> Authenticate as victim -> Inherit privileges".to_string()),
                rights: Some(takeover.rights.clone()),
                distinguished_name: Some(takeover.target_dn.clone()),
                additional_context: if takeover.can_reset_password { Some("Can reset password".to_string()) } else { None },
            }],
        });
        self.privileged_takeovers.push(takeover);
    }

    pub fn add_group_membership_control(&mut self, control: GroupMembershipControl) {
        self.group_membership_control_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: if control.is_add_member_right { "AddMember/Self Right on Privileged Group".to_string() } else { "Group Membership Control".to_string() },
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: control.principal.clone(),
            description: format!(
                "Principal '{}' can modify membership of '{}'. This allows adding accounts to privileged groups.",
                control.principal, control.group_name
            ),
            impact: "Add controlled account to group -> Inherit privileges -> Domain compromise".to_string(),
            remediation: format!(
                "Remove membership modification rights:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReferences:\n- Least Privilege Models: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models\n- Group Control Abuse: https://www.thehacker.recipes/ad/movement/dacl/addmember\n- Protected Groups: https://adsecurity.org/?p=3700",
                control.group_dn, control.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Modify membership of {}", control.group_name),
                target: control.group_name.clone(),
                attack_path: Some("Add account to privileged group -> Inherit privileges".to_string()),
                rights: Some(control.rights.clone()),
                distinguished_name: Some(control.group_dn.clone()),
                additional_context: if control.is_add_member_right { Some("AddMember/Self right".to_string()) } else { None },
            }],
        });
        self.group_membership_controls.push(control);
    }

    pub fn add_ou_control(&mut self, ou: OUControl) {
        self.ou_control_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "OU Control (Privileged Resources)".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: ou.principal.clone(),
            description: format!(
                "Principal '{}' has control over OU '{}' which contains privileged objects.",
                ou.principal, ou.ou_name
            ),
            impact: "Modify OU permissions -> Control child objects (users/groups) -> Privilege escalation".to_string(),
            remediation: format!(
                "Remove excessive OU permissions:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
                ou.ou_dn, ou.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Control over OU '{}'", ou.ou_name),
                target: ou.ou_name.clone(),
                attack_path: Some("Modify OU -> Control privileged child objects".to_string()),
                rights: Some(ou.rights.clone()),
                distinguished_name: Some(ou.ou_dn.clone()),
                additional_context: if ou.contains_privileged_objects { Some("Contains privileged objects".to_string()) } else { None },
            }],
        });
        self.ou_controls.push(ou);
    }

    pub fn add_computer_control(&mut self, computer: ComputerObjectControl) {
        self.computer_control_count += 1;
        let severity = if computer.is_domain_controller { "Critical" } else { "High" };
        
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: if computer.is_domain_controller { "Domain Controller Object Control".to_string() } else { "Computer Object Control".to_string() },
            severity: severity.to_string(),
            severity_level: if severity == "Critical" { 4 } else { 3 },
            affected_object: computer.principal.clone(),
            description: format!(
                "Principal '{}' has control over {} '{}'. This enables RBCD attacks and lateral movement.",
                computer.principal,
                if computer.is_domain_controller { "Domain Controller" } else { "computer" },
                computer.computer_name
            ),
            impact: if computer.is_domain_controller {
                "Control DC object -> Modify sensitive attributes -> Domain compromise".to_string()
            } else {
                "Write msDS-AllowedToActOnBehalfOfOtherIdentity -> S4U2Self impersonation -> Local admin -> Lateral movement".to_string()
            },
            remediation: format!(
                "Remove excessive permissions:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReferences:\n- Computer Object Control: https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd\n- ACL Abuse Techniques: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse\n- Domain Controller Security: https://adsecurity.org/?p=3377",
                computer.computer_dn, computer.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Control over computer '{}'", computer.computer_name),
                target: computer.computer_name.clone(),
                attack_path: Some("RBCD -> S4U2Self -> Impersonate users".to_string()),
                rights: Some(computer.rights.clone()),
                distinguished_name: Some(computer.computer_dn.clone()),
                additional_context: if computer.is_domain_controller { Some("Domain Controller".to_string()) } else { None },
            }],
        });
        self.computer_controls.push(computer);
    }

    pub fn add_constrained_delegation_to_dc(&mut self, delegation: ConstrainedDelegationToDC) {
        self.constrained_delegation_to_dc_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "Constrained Delegation to Domain Controller".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: delegation.account_name.clone(),
            description: format!(
                "Account '{}' has constrained delegation to DC service '{}'. This enables DCSync via S4U2Proxy{}.",
                delegation.account_name,
                delegation.delegation_target,
                if delegation.is_protocol_transition { " with protocol transition" } else { "" }
            ),
            impact: "S4U2Self + S4U2Proxy to DC -> DCSync -> Extract all domain credentials".to_string(),
            remediation: format!(
                "Remove constrained delegation to DC:\n\nPowerShell:\nSet-ADUser -Identity '{}' -Remove @{{'msDS-AllowedToDelegateTo'='{}'}}\n\nReferences:\n- Constrained Delegation: https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained\n- S4U2Proxy Abuse: https://www.semperis.com/blog/new-attack-paths-as-requested-sts/\n- Delegation Security: https://adsecurity.org/?p=1729",
                delegation.account_name, delegation.delegation_target
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Constrained delegation to DC service"),
                target: delegation.delegation_target.clone(),
                attack_path: Some("S4U2Proxy to DC -> DCSync".to_string()),
                rights: Some("Constrained Delegation".to_string()),
                distinguished_name: Some(delegation.distinguished_name.clone()),
                additional_context: Some(format!("Target: {}", delegation.delegation_target)),
            }],
        });
        self.constrained_delegation_to_dcs.push(delegation);
    }

    pub fn add_esc1_vulnerability(&mut self, vuln: ESC1Vulnerability) {
        self.esc1_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC1 - Misconfigured Certificate Template".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.template_name.clone(),
            description: format!(
                "Certificate template '{}' allows enrollee to supply subject name (SAN) and can be used for authentication. Principal '{}' can enroll.",
                vuln.template_name, vuln.enroller
            ),
            impact: "Request certificate for any user (including Domain Admins) -> Full domain compromise".to_string(),
            remediation: format!(
                "Fix certificate template configuration:\n\nPowerShell:\n# Remove ENROLLEE_SUPPLIES_SUBJECT flag\n# Restrict enrollment permissions\n# Add manager approval requirement\n\nReferences:\n- ESC1 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- Certificate Templates: https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates\n- ADCS Hardening: https://www.microsoft.com/en-us/security/blog/2022/12/15/protecting-active-directory-certificate-services/"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "Enrollee supplies subject with authentication EKU".to_string(),
                target: vuln.enroller.clone(),
                attack_path: Some("Enroll with SAN -> Authenticate as DA -> Full domain access".to_string()),
                rights: Some("Certificate Enrollment".to_string()),
                distinguished_name: Some(vuln.template_dn.clone()),
                additional_context: Some(format!("Template: {}", vuln.template_name)),
            }],
        });
        self.esc1_vulnerabilities.push(vuln);
    }

    pub fn add_esc4_vulnerability(&mut self, vuln: ESC4Vulnerability) {
        self.esc4_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC4 - Certificate Template Write Access".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.template_name.clone(),
            description: format!(
                "Principal '{}' has {} access to certificate template '{}'. This allows modifying template to enable ESC1.",
                vuln.principal, vuln.write_access_type, vuln.template_name
            ),
            impact: "Modify template to allow SAN -> ESC1 exploitation -> Full domain compromise".to_string(),
            remediation: format!(
                "Remove write permissions from certificate template:\n\nPowerShell:\n# Review and remove excessive permissions\n# Restrict template modification to PKI admins only\n\nReferences:\n- ESC4 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- Template Security: https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates\n- PKI Hardening: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-security"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("{} on certificate template", vuln.write_access_type),
                target: vuln.principal.clone(),
                attack_path: Some("Modify template -> Enable ESC1 -> Domain compromise".to_string()),
                rights: Some(vuln.write_access_type.clone()),
                distinguished_name: Some(vuln.template_dn.clone()),
                additional_context: Some(format!("Template: {}", vuln.template_name)),
            }],
        });
        self.esc4_vulnerabilities.push(vuln);
    }

    pub fn add_esc8_vulnerability(&mut self, vuln: ESC8Vulnerability) {
        self.esc8_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC8 - Web Enrollment NTLM Relay Risk".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: vuln.ca_name.clone(),
            description: format!(
                "Certificate Authority '{}' has web enrollment enabled on '{}' with NTLM authentication. Vulnerable to NTLM relay attacks.",
                vuln.ca_name, vuln.web_enrollment_server
            ),
            impact: "NTLM relay to web enrollment -> Request certificate as relayed user -> Privilege escalation".to_string(),
            remediation: format!(
                "Mitigate ESC8:\n\n1. Disable NTLM authentication on web enrollment\n2. Enable EPA (Extended Protection for Authentication)\n3. Require HTTPS with certificate authentication\n\nReferences:\n- ESC8 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- Web Enrollment Security: https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints\n- NTLM Relay Defense: https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "Web enrollment with NTLM enabled".to_string(),
                target: vuln.web_enrollment_server.clone(),
                attack_path: Some("NTLM relay -> Request certificate -> Authenticate as victim".to_string()),
                rights: Some("Web Enrollment".to_string()),
                distinguished_name: None,
                additional_context: Some(format!("CA: {}, Server: {}", vuln.ca_name, vuln.web_enrollment_server)),
            }],
        });
        self.esc8_vulnerabilities.push(vuln);
    }

    pub fn add_esc2_vulnerability(&mut self, vuln: ESC2Vulnerability) {
        self.esc2_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC2 - Any Purpose or No EKU Certificate Template".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.template_name.clone(),
            description: format!(
                "Certificate template '{}' allows {} and can be used for any purpose including authentication. Principal '{}' can enroll.",
                vuln.template_name,
                if vuln.has_any_purpose_eku { "Any Purpose EKU" } else { "no EKU restriction" },
                vuln.enroller
            ),
            impact: "Request certificate with arbitrary EKU -> Authenticate as any user -> Full domain compromise".to_string(),
            remediation: format!(
                "Fix certificate template:\n\n1. Remove Any Purpose EKU or set specific EKUs\n2. Restrict enrollment permissions\n3. Require manager approval\n\nReferences:\n- ESC2 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- Certificate Templates: https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates\n- ADCS Hardening: https://www.microsoft.com/en-us/security/blog/2022/12/15/protecting-active-directory-certificate-services/"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: if vuln.has_any_purpose_eku { "Any Purpose EKU" } else { "No EKU specified" }.to_string(),
                target: vuln.enroller.clone(),
                attack_path: Some("Enroll certificate -> Use for arbitrary purpose -> Domain compromise".to_string()),
                rights: Some("Certificate Enrollment".to_string()),
                distinguished_name: Some(vuln.template_dn.clone()),
                additional_context: Some(format!("Template: {}", vuln.template_name)),
            }],
        });
        self.esc2_vulnerabilities.push(vuln);
    }

    pub fn add_esc3_vulnerability(&mut self, vuln: ESC3Vulnerability) {
        self.esc3_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC3 - Enrollment Agent Certificate Template".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.template_name.clone(),
            description: format!(
                "Certificate template '{}' allows Certificate Request Agent EKU. Principal '{}' can enroll on behalf of others.",
                vuln.template_name, vuln.enroller
            ),
            impact: "Request enrollment agent certificate -> Enroll on behalf of Domain Admins -> Full domain compromise".to_string(),
            remediation: format!(
                "Secure enrollment agent template:\n\n1. Restrict enrollment agent permissions to authorized PKI admins only\n2. Require multiple authorized signatures\n3. Enable manager approval\n4. Monitor enrollment agent usage\n\nReferences:\n- ESC3 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- Enrollment Agents: https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates#enrollment-agent\n- Certificate Request Agent: https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "Certificate Request Agent EKU enabled".to_string(),
                target: vuln.enroller.clone(),
                attack_path: Some("Get enrollment agent cert -> Request cert for DA -> Authenticate as DA".to_string()),
                rights: Some("Certificate Enrollment (Agent)".to_string()),
                distinguished_name: Some(vuln.template_dn.clone()),
                additional_context: Some(format!("Template: {}, Required signatures: {}", vuln.template_name, vuln.authorized_signatures_required)),
            }],
        });
        self.esc3_vulnerabilities.push(vuln);
    }

    pub fn add_esc5_vulnerability(&mut self, vuln: ESC5Vulnerability) {
        self.esc5_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC5 - PKI Object Write Access".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.object_name.clone(),
            description: format!(
                "Principal '{}' has {} access to PKI object '{}' ({}). This allows modifying critical PKI configuration.",
                vuln.principal, vuln.write_access_type, vuln.object_name, vuln.object_type
            ),
            impact: "Modify PKI objects -> Create vulnerable templates -> ESC1/ESC2 exploitation -> Domain compromise".to_string(),
            remediation: format!(
                "Remove excessive PKI permissions:\n\n1. Review and restrict PKI object permissions\n2. Limit write access to PKI admins only\n3. Monitor PKI configuration changes\n\nReferences:\n- ESC5 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- PKI Security: https://www.thehacker.recipes/ad/movement/ad-cs/access-controls\n- ADCS Hardening: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-security"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("{} on PKI {}", vuln.write_access_type, vuln.object_type),
                target: vuln.principal.clone(),
                attack_path: Some("Modify PKI config -> Create vulnerable template -> Exploit template".to_string()),
                rights: Some(vuln.write_access_type.clone()),
                distinguished_name: Some(vuln.object_dn.clone()),
                additional_context: Some(format!("Object: {} ({})", vuln.object_name, vuln.object_type)),
            }],
        });
        self.esc5_vulnerabilities.push(vuln);
    }

    pub fn add_esc7_vulnerability(&mut self, vuln: ESC7Vulnerability) {
        self.esc7_count += 1;

        self.findings.push(DAEquivalenceFinding {
            category: "PKI Vulnerability".to_string(),
            issue: "ESC7 - CA Management Rights".to_string(),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.ca_name.clone(),
            description: format!(
                "Principal '{}' has management rights on Certificate Authority '{}' (ManageCA: {}, ManageCertificates: {}).",
                vuln.principal, vuln.ca_name, vuln.has_manage_ca, vuln.has_manage_certificates
            ),
            impact: "ManageCA -> Enable vulnerable flags -> ManageCertificates -> Issue arbitrary certificates -> Domain compromise".to_string(),
            remediation: format!(
                "Restrict CA management permissions:\n\n1. Remove ManageCA and ManageCertificates rights from non-admins\n2. Limit CA management to dedicated PKI admins\n3. Enable CA auditing and monitoring\n4. Review certificate issuance policies\n\nReferences:\n- ESC7 Explained: https://posts.specterops.io/certified-pre-owned-d95910965cd2\n- CA Security: https://www.thehacker.recipes/ad/movement/ad-cs/access-controls#esc7-vulnerable-ca-access-control\n- CA Permissions: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-security#ca-permissions"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("CA management rights (ManageCA: {}, ManageCertificates: {})", vuln.has_manage_ca, vuln.has_manage_certificates),
                target: vuln.principal.clone(),
                attack_path: Some("ManageCA -> Set vulnerable flags -> ManageCertificates -> Issue cert as DA".to_string()),
                rights: Some(format!("ManageCA: {}, ManageCertificates: {}", vuln.has_manage_ca, vuln.has_manage_certificates)),
                distinguished_name: Some(vuln.ca_dn.clone()),
                additional_context: Some(format!("CA: {}", vuln.ca_name)),
            }],
        });
        self.esc7_vulnerabilities.push(vuln);
    }

    pub fn add_azure_ad_connect(&mut self, aad_connect: AzureADConnect) {
        self.azure_ad_connect_count += 1;

        let severity = if aad_connect.is_enabled { "Critical" } else { "High" };
        let severity_level = if aad_connect.is_enabled { 4 } else { 3 };

        self.findings.push(DAEquivalenceFinding {
            category: "High-Value Account".to_string(),
            issue: "Azure AD Connect Account Detected".to_string(),
            severity: severity.to_string(),
            severity_level,
            affected_object: aad_connect.account_name.clone(),
            description: format!(
                "Azure AD Connect account '{}' detected{}. This account has DCSync permissions and can extract all domain credentials.",
                aad_connect.account_name,
                if aad_connect.is_enabled { " (ENABLED)" } else { " (disabled)" }
            ),
            impact: "Compromise of this account -> DCSync -> All domain password hashes -> Full domain compromise".to_string(),
            remediation: format!(
                "Protect Azure AD Connect account:\n\n1. Ensure strong password (30+ characters)\n2. Enable MFA if possible\n3. Restrict interactive logon\n4. Monitor for suspicious activity\n5. Review permissions regularly\n\nReferences:\n- AAD Connect Security: https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-configure-ad-ds-connector-account\n- DCSync Abuse: https://attack.mitre.org/techniques/T1003/006/\n- Hardening Guide: https://www.semperis.com/blog/azure-ad-connect-security-best-practices/"
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "Azure AD Connect service account with DCSync rights".to_string(),
                target: aad_connect.account_name.clone(),
                attack_path: Some("Compromise AAD Connect account -> DCSync -> Extract all credentials".to_string()),
                rights: Some("DCSync (Replicating Directory Changes)".to_string()),
                distinguished_name: Some(aad_connect.distinguished_name.clone()),
                additional_context: aad_connect.description.clone(),
            }],
        });
        self.azure_ad_connects.push(aad_connect);
    }

    pub fn add_gpo_control(&mut self, gpo: GPOControl) {
        self.gpo_control_count += 1;
        let severity = if gpo.linked_to_privileged_scope { "Critical" } else { "High" };
        
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "GPO Control".to_string(),
            severity: severity.to_string(),
            severity_level: if severity == "Critical" { 4 } else { 3 },
            affected_object: gpo.principal.clone(),
            description: format!(
                "Principal '{}' has control over GPO '{}'{}.This allows arbitrary code execution.",
                gpo.principal, gpo.gpo_name,
                if gpo.linked_to_privileged_scope { " which is linked to Domain/DC scope" } else { "" }
            ),
            impact: "Modify GPO -> Add malicious settings -> Code execution on affected computers".to_string(),
            remediation: format!(
                "Remove GPO modification permissions:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\{}'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACE\n\nReference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/gp-permission-model",
                gpo.gpo_dn, gpo.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Control over GPO '{}'", gpo.gpo_name),
                target: gpo.gpo_name.clone(),
                attack_path: Some("Modify GPO -> Add scheduled task/startup script -> Code execution".to_string()),
                rights: Some(gpo.rights.clone()),
                distinguished_name: Some(gpo.gpo_dn.clone()),
                additional_context: if gpo.linked_to_privileged_scope { Some("Linked to privileged scope".to_string()) } else { None },
            }],
        });
        self.gpo_controls.push(gpo);
    }

    pub fn add_session_group(&mut self, session: SessionGroupMembership) {
        self.session_group_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "Session Group Membership (ExecuteDCOM/PSRemote)".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: session.principal.clone(),
            description: format!(
                "Principal '{}' is member of '{}'. This allows remote code execution on Domain Controllers.",
                session.principal, session.group_name
            ),
            impact: session.attack_path.clone(),
            remediation: format!(
                "Remove from session group:\n\nPowerShell:\nRemove-ADGroupMember -Identity '{}' -Members '{}' -Confirm:$false\n\nReference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-management-users-group",
                session.group_name, session.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Member of {}", session.group_name),
                target: "Domain Controllers".to_string(),
                attack_path: Some(session.attack_path.clone()),
                rights: None,
                distinguished_name: None,
                additional_context: None,
            }],
        });
        self.session_group_memberships.push(session);
    }

    pub fn add_legacy_logon_script(&mut self, script: LegacyLogonScript) {
        self.legacy_logon_script_count += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Legacy Attack Vector".to_string(),
            issue: "Legacy Logon Script Defined".to_string(),
            severity: "Low".to_string(),
            severity_level: 1,
            affected_object: script.account_name.clone(),
            description: format!(
                "User '{}' has a legacy logon script defined: '{}'. Attackers can modify this file to achieve code execution upon user logon.",
                script.account_name, script.script_path
            ),
            impact: "Modify script file -> Code execution at user logon".to_string(),
            remediation: format!(
                "Migrate to Group Policy Preferences and clear the scriptPath attribute:\n\nPowerShell:\nSet-ADUser -Identity '{}' -Clear scriptPath\n\nReferences:\n- Logon Script Best Practices: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/logon-script-issues\n- GPO Preferences: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn789194(v=ws.11)\n- Securing Logon Scripts: https://adsecurity.org/?p=2716",
                script.account_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Logon script: {}", script.script_path),
                target: script.account_name.clone(),
                attack_path: Some("Modify script -> Code execution at logon".to_string()),
                rights: None,
                distinguished_name: Some(script.distinguished_name.clone()),
                additional_context: Some(format!("Script path: {}", script.script_path)),
            }],
        });
        self.legacy_logon_scripts.push(script);
    }

    pub fn add_sid_history_entry(&mut self, entry: SidHistoryEntry) {
        self.sid_history_issues += 1;
        
        let (severity, severity_level, issue) = if entry.is_same_domain {
            ("Critical", 4u8, "SID History Injection (Same Domain)")
        } else if entry.is_privileged_rid {
            ("Critical", 4u8, "Privileged SID in History")
        } else {
            ("High", 3u8, "SID History Present")
        };

        let description = if entry.is_same_domain {
            format!(
                "User '{}' contains a SID from the CURRENT domain in its SID History ({}). This is a definitive sign of a Golden Ticket or SID History injection attack.",
                entry.sam_account_name, entry.injected_sid
            )
        } else if entry.is_privileged_rid {
            format!(
                "User '{}' has a highly privileged SID ({}) in their SID History. They possess Domain Admin rights regardless of group membership.",
                entry.sam_account_name, entry.injected_sid
            )
        } else {
            format!(
                "User '{}' has SID History entries ({}). Review if this is from a legitimate migration.",
                entry.sam_account_name, entry.injected_sid
            )
        };

        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: issue.to_string(),
            severity: severity.to_string(),
            severity_level,
            affected_object: entry.sam_account_name.clone(),
            description,
            impact: "SID History entries grant the user all permissions of the injected SID, potentially including Domain Admin rights.".to_string(),
            remediation: format!(
                "Clear the sIDHistory attribute immediately unless this is a verified migration account:\n\nPowerShell:\nSet-ADUser -Identity '{}' -Clear sIDHistory\n\nReference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory",
                entry.sam_account_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("SID History contains: {}", entry.injected_sid),
                target: entry.sam_account_name.clone(),
                attack_path: Some("SID History injection -> Instant privilege escalation".to_string()),
                rights: None,
                distinguished_name: Some(entry.distinguished_name.clone()),
                additional_context: entry.rid.clone(),
            }],
        });
        self.sid_history_entries.push(entry);
    }

    pub fn add_dcsync_right(&mut self, right: DCSyncRight) {
        if right.has_full_dcsync {
            self.dcsync_principals += 1;
            self.findings.push(DAEquivalenceFinding {
                category: "Admin Equivalence".to_string(),
                issue: "DCSync Replication Rights".to_string(),
                severity: "Critical".to_string(),
                severity_level: 4,
                affected_object: right.principal.clone(),
                description: format!(
                    "Principal '{}' has DCSync replication rights: {}. This allows extraction of all password hashes from the domain.",
                    right.principal, right.rights.join(", ")
                ),
                impact: "DCSync allows complete domain compromise by extracting all user password hashes including krbtgt.".to_string(),
                remediation: format!(
                    "Remove replication rights from non-DC accounts:\n\nPowerShell:\n$acl = Get-Acl 'AD:\\DC=domain,DC=com'\n$acl.Access | Where-Object {{$_.IdentityReference -match '{}'}}\n# Remove the ACEs granting replication rights\n\nReference: https://adsecurity.org/?p=1729",
                    right.principal
                ),
                evidence: vec![EquivalenceEvidence {
                    reason: format!("Replication rights: {}", right.rights.join(", ")),
                    target: "Domain Root".to_string(),
                    attack_path: Some("DCSync -> Extract all hashes -> Golden Ticket -> Full compromise".to_string()),
                    rights: Some(right.rights.join(", ")),
                    distinguished_name: None,
                    additional_context: None,
                }],
            });
        }
        self.dcsync_rights.push(right);
    }

    pub fn add_pki_vulnerability(&mut self, vuln: PKIVulnerability) {
        self.pki_vulnerabilities += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: format!("PKI Control - {}", vuln.target_type),
            severity: "Critical".to_string(),
            severity_level: 4,
            affected_object: vuln.principal.clone(),
            description: format!(
                "Principal '{}' has control over PKI {} '{}' via {}. This enables certificate-based attacks (ESC1-ESC8).",
                vuln.principal, vuln.target_type, vuln.target_name, vuln.rights
            ),
            impact: "Control over PKI infrastructure allows issuance of certificates for any user, enabling authentication as Domain Admin.".to_string(),
            remediation: format!(
                "Remove excessive permissions from PKI objects:\n\n1. Review permissions on: {}\n2. Remove Write/Modify rights for '{}'\n3. Restrict Enroll rights to authorized groups only\n\nReference: https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                vuln.target_name, vuln.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Control over {} '{}'", vuln.target_type, vuln.target_name),
                target: vuln.target_name.clone(),
                attack_path: Some(vuln.attack_vector.clone()),
                rights: Some(vuln.rights.clone()),
                distinguished_name: None,
                additional_context: None,
            }],
        });
        self.pki_vulnerabilities_list.push(vuln);
    }

    pub fn add_laps_exposure(&mut self, exposure: LapsExposure) {
        self.laps_exposures += 1;
        let issue = if exposure.can_read_password {
            "LAPS Password Read Access"
        } else {
            "LAPS Expiration Write Access"
        };

        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: issue.to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: format!("{} on {}", exposure.principal, exposure.computer_name),
            description: format!(
                "Principal '{}' can {} LAPS on computer '{}'.",
                exposure.principal,
                if exposure.can_read_password { "read password" } else { "control expiration" },
                exposure.computer_name
            ),
            impact: if exposure.can_read_password {
                "Reading LAPS password provides local administrator access to the computer.".to_string()
            } else {
                "Controlling expiration allows maintaining access with stolen credentials.".to_string()
            },
            remediation: format!(
                "Review LAPS permissions:\n\nPowerShell:\nGet-ADComputer '{}' | Get-Acl | Select-Object -ExpandProperty Access | Where-Object {{$_.IdentityReference -match '{}'}}\n\nRemove excessive permissions from non-admin groups.\n\nReference: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
                exposure.computer_name, exposure.principal
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("LAPS {} access", if exposure.can_read_password { "read" } else { "write" }),
                target: exposure.computer_name.clone(),
                attack_path: Some("Read LAPS -> Local Admin -> Lateral Movement".to_string()),
                rights: None,
                distinguished_name: None,
                additional_context: None,
            }],
        });
        self.laps_exposures_list.push(exposure);
    }

    pub fn add_gmsa_exposure(&mut self, exposure: GmsaExposure) {
        self.gmsa_exposures += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: "GMSA Password Read Access".to_string(),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: format!("{} on {}", exposure.principal, exposure.gmsa_name),
            description: format!(
                "Principal '{}' can retrieve the password for Group Managed Service Account '{}'.",
                exposure.principal, exposure.gmsa_name
            ),
            impact: "Reading GMSA password allows authentication as the service account, potentially with elevated privileges.".to_string(),
            remediation: format!(
                "Review GMSA password retrieval permissions:\n\nPowerShell:\nGet-ADServiceAccount -Identity '{}' -Properties PrincipalsAllowedToRetrieveManagedPassword\n\nRemove unauthorized principals from PrincipalsAllowedToRetrieveManagedPassword.\n\nReference: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
                exposure.gmsa_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: "Can retrieve GMSA password".to_string(),
                target: exposure.gmsa_name.clone(),
                attack_path: Some("Read GMSA password -> Authenticate as service -> Lateral movement".to_string()),
                rights: None,
                distinguished_name: None,
                additional_context: None,
            }],
        });
        self.gmsa_exposures_list.push(exposure);
    }

    pub fn add_dangerous_group_member(&mut self, member: DangerousGroupMember) {
        self.dangerous_group_members += 1;
        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: format!("Dangerous Built-in Group Membership: {}", member.group_name),
            severity: "High".to_string(),
            severity_level: 3,
            affected_object: member.member_sam_account_name.clone(),
            description: format!(
                "User '{}' is a member of dangerous built-in group '{}', which provides privilege escalation paths.",
                member.member_sam_account_name, member.group_name
            ),
            impact: format!("Attack path: {}", member.attack_path),
            remediation: format!(
                "Remove user from dangerous group:\n\nPowerShell:\nRemove-ADGroupMember -Identity '{}' -Members '{}' -Confirm:$false\n\nConsider if this membership is truly required for job function.\n\nReference: https://aka.ms/PrivilegedGroups",
                member.group_name, member.member_sam_account_name
            ),
            evidence: vec![EquivalenceEvidence {
                reason: format!("Member of {}", member.group_name),
                target: member.group_name.clone(),
                attack_path: Some(member.attack_path.clone()),
                rights: None,
                distinguished_name: Some(member.member_dn.clone()),
                additional_context: None,
            }],
        });
        self.dangerous_members.push(member);
    }

    pub fn add_weak_password_config(&mut self, config: WeakPasswordConfig) {
        self.weak_password_configs += 1;
        let severity = match config.issue.as_str() {
            "Password Not Required" => ("Critical", 4u8),
            "Reversible Encryption Enabled" => ("High", 3u8),
            _ => ("Medium", 2u8),
        };

        self.findings.push(DAEquivalenceFinding {
            category: "Admin Equivalence".to_string(),
            issue: format!("Weak Password Configuration: {}", config.issue),
            severity: severity.0.to_string(),
            severity_level: severity.1,
            affected_object: config.account.clone(),
            description: format!(
                "Privileged account '{}' has weak password configuration: {}",
                config.account, config.issue
            ),
            impact: config.risk.clone(),
            remediation: format!(
                "Fix password configuration for privileged account:\n\nPowerShell:\n{}\n\nEnsure all privileged accounts have strong password policies.",
                match config.issue.as_str() {
                    "Password Not Required" => format!("Set-ADUser -Identity '{}' -PasswordNotRequired $false", config.account),
                    "Reversible Encryption Enabled" => format!("Set-ADUser -Identity '{}' -AllowReversiblePasswordEncryption $false", config.account),
                    "Password Never Expires" => format!("Set-ADUser -Identity '{}' -PasswordNeverExpires $false", config.account),
                    _ => "Review account settings in Active Directory Users and Computers".to_string(),
                }
            ),
            evidence: vec![EquivalenceEvidence {
                reason: config.issue.clone(),
                target: config.account.clone(),
                attack_path: Some(config.risk.clone()),
                rights: None,
                distinguished_name: None,
                additional_context: None,
            }],
        });
        self.weak_passwords.push(config);
    }

    pub fn calculate_risk_score(&mut self) {
        let mut score = 0u32;

        // Weight by finding severity
        for finding in &self.findings {
            score += match finding.severity.as_str() {
                "Critical" => 25,
                "High" => 15,
                "Medium" => 5,
                "Low" => 2,
                _ => 1,
            };
        }

        // Additional weight for specific high-risk items
        score += self.dcsync_principals * 20;
        score += self.pki_vulnerabilities * 15;
        score += self.sid_history_issues * 15;
        score += self.shadow_credential_write_count * 15;
        score += self.unconstrained_delegation_count * 10;
        score += self.rbcd_write_count * 12;
        score += self.gpo_link_rights_count * 15;
        score += self.exchange_privexchange_count * 20;
        score += self.privileged_takeover_count * 18;
        score += self.group_membership_control_count * 18;

        self.risk_score = score.min(100);
        self.total_equivalent_principals = self.findings.iter()
            .filter(|f| f.severity == "Critical" || f.severity == "High")
            .count() as u32;
        self.critical_principals = self.findings.iter()
            .filter(|f| f.severity == "Critical")
            .count() as u32;
    }

    pub fn generate_recommendations(&mut self) {
        if self.ghost_accounts_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 1,
                title: "Clear AdminSDHolder Ghost Accounts".to_string(),
                description: format!(
                    "Found {} ghost account(s) with adminCount=1 but no protected group membership.",
                    self.ghost_accounts_count
                ),
                steps: vec![
                    "Find ghost accounts: Get-ADUser -LDAPFilter '(adminCount=1)' | ForEach-Object { $g = Get-ADPrincipalGroupMembership $_; if (-not ($g.Name -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Backup Operators|Account Operators|Server Operators|Print Operators')) { $_ } }".to_string(),
                    "Clear adminCount: Set-ADUser -Identity <user> -Clear adminCount".to_string(),
                    "Enable inheritance: Use AD Users and Computers -> Security -> Advanced -> Enable inheritance".to_string(),
                    "Verify permissions are correct after clearing".to_string(),
                ],
                reference: Some("https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups".to_string()),
            });
        }

        if self.shadow_credentials_count > 0 || self.shadow_credential_write_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 2,
                title: "Investigate Shadow Credentials".to_string(),
                description: format!(
                    "Found {} object(s) with msDS-KeyCredentialLink populated and {} principal(s) with write access.",
                    self.shadow_credentials_count, self.shadow_credential_write_count
                ),
                steps: vec![
                    "Find objects: Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink".to_string(),
                    "Verify if Windows Hello for Business is legitimately deployed".to_string(),
                    "If not WHfB, clear immediately: Set-ADObject -Identity <dn> -Clear msDS-KeyCredentialLink".to_string(),
                    "Remove write permissions from unauthorized principals".to_string(),
                    "Monitor for re-creation using advanced threat detection".to_string(),
                ],
                reference: Some("https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8".to_string()),
            });
        }

        if self.sid_history_issues > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 3,
                title: "Clear SID History Injection".to_string(),
                description: format!(
                    "Found {} SID History issue(s). Same-domain or privileged SIDs indicate potential attack.",
                    self.sid_history_issues
                ),
                steps: vec![
                    "Find SID History: Get-ADUser -LDAPFilter '(sIDHistory=*)' -Properties sIDHistory".to_string(),
                    "Analyze each SID - same domain SIDs are ALWAYS malicious".to_string(),
                    "Clear immediately: Set-ADUser -Identity <user> -Clear sIDHistory".to_string(),
                    "Enable SID filtering on all trusts to prevent future attacks".to_string(),
                ],
                reference: Some("https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory".to_string()),
            });
        }

        if self.dcsync_principals > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 4,
                title: "Remove Unauthorized DCSync Rights".to_string(),
                description: format!(
                    "Found {} non-DC principal(s) with DCSync replication rights.",
                    self.dcsync_principals
                ),
                steps: vec![
                    "List replication rights: (Get-Acl 'AD:\\DC=domain,DC=com').Access | Where-Object {$_.ObjectType -match '1131f6a'}".to_string(),
                    "Only Domain Controllers should have these rights".to_string(),
                    "Remove unauthorized ACEs from the domain root".to_string(),
                    "Monitor Event ID 4662 for replication attempts".to_string(),
                ],
                reference: Some("https://adsecurity.org/?p=1729".to_string()),
            });
        }

        if self.pki_vulnerabilities > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 5,
                title: "Secure PKI Infrastructure".to_string(),
                description: format!(
                    "Found {} PKI vulnerability(ies) that could enable certificate-based attacks.",
                    self.pki_vulnerabilities
                ),
                steps: vec![
                    "Audit certificate templates: certutil -v -template".to_string(),
                    "Remove Enroll rights from broad groups on sensitive templates".to_string(),
                    "Disable templates that allow SAN specification without manager approval".to_string(),
                    "Use Certify or Certipy to identify ESC1-ESC8 vulnerabilities".to_string(),
                ],
                reference: Some("https://posts.specterops.io/certified-pre-owned-d95910965cd2".to_string()),
            });
        }

        if self.unconstrained_delegation_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 6,
                title: "Disable Unconstrained Delegation".to_string(),
                description: format!(
                    "Found {} non-DC system(s) with unconstrained delegation.",
                    self.unconstrained_delegation_count
                ),
                steps: vec![
                    "Find unconstrained delegation: Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516}".to_string(),
                    "Disable: Set-ADComputer -Identity <computer> -TrustedForDelegation $false".to_string(),
                    "Consider constrained delegation or RBCD instead".to_string(),
                    "Enable Protected Users group for sensitive accounts".to_string(),
                ],
                reference: Some("https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview".to_string()),
            });
        }

        if self.rbcd_write_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 7,
                title: "Remove RBCD Write Permissions".to_string(),
                description: format!(
                    "Found {} principal(s) with write access to msDS-AllowedToActOnBehalfOfOtherIdentity.",
                    self.rbcd_write_count
                ),
                steps: vec![
                    "Audit RBCD permissions on critical computers".to_string(),
                    "Remove write permissions from non-admin principals".to_string(),
                    "Monitor for RBCD configuration changes".to_string(),
                    "Clear existing unauthorized RBCD entries".to_string(),
                ],
                reference: Some("https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd".to_string()),
            });
        }

        if self.gpo_link_rights_count > 0 || self.gpo_control_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 8,
                title: "Secure GPO Permissions".to_string(),
                description: format!(
                    "Found {} WriteGPLink permission(s) and {} GPO control issue(s).",
                    self.gpo_link_rights_count, self.gpo_control_count
                ),
                steps: vec![
                    "Review GPO permissions: Get-GPPermission -All".to_string(),
                    "Remove excessive GPO modification rights".to_string(),
                    "Remove WriteGPLink from non-admin accounts".to_string(),
                    "Audit linked GPOs on Domain and DC containers".to_string(),
                ],
                reference: Some("https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/gp-permission-model".to_string()),
            });
        }

        if self.privileged_takeover_count > 0 || self.group_membership_control_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 9,
                title: "Remove Account Takeover Permissions".to_string(),
                description: format!(
                    "Found {} privileged account takeover path(s) and {} group membership control(s).",
                    self.privileged_takeover_count, self.group_membership_control_count
                ),
                steps: vec![
                    "Audit permissions on privileged accounts and groups".to_string(),
                    "Remove password reset rights from non-admin accounts".to_string(),
                    "Remove WriteMember/AddMember rights on privileged groups".to_string(),
                    "Use AdminSDHolder protection appropriately".to_string(),
                ],
                reference: Some("https://adsecurity.org/?p=3164".to_string()),
            });
        }

        if self.dangerous_group_members > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 10,
                title: "Review Dangerous Built-in Group Membership".to_string(),
                description: format!(
                    "Found {} member(s) in dangerous built-in groups (Print/Server/Backup/Account Operators, DnsAdmins).",
                    self.dangerous_group_members
                ),
                steps: vec![
                    "List members: @('Print Operators','Server Operators','Backup Operators','Account Operators','DnsAdmins') | ForEach-Object { Get-ADGroupMember -Identity $_ }".to_string(),
                    "Remove users unless absolutely required for job function".to_string(),
                    "Use delegated administration groups with limited scope instead".to_string(),
                    "Document any required membership with business justification".to_string(),
                ],
                reference: Some("https://aka.ms/PrivilegedGroups".to_string()),
            });
        }

        if self.exchange_privexchange_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 11,
                title: "Mitigate Exchange PrivExchange".to_string(),
                description: format!(
                    "Found {} principal(s) vulnerable to PrivExchange attack.",
                    self.exchange_privexchange_count
                ),
                steps: vec![
                    "Remove WriteDacl from Exchange Windows Permissions on domain root".to_string(),
                    "Apply Exchange security updates".to_string(),
                    "Consider Split Permissions model".to_string(),
                    "Monitor for NTLM relay attacks".to_string(),
                ],
                reference: Some("https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/".to_string()),
            });
        }

        if self.dns_zone_control_count > 0 {
            self.recommendations.push(DAEquivalenceRecommendation {
                priority: 12,
                title: "Secure DNS Zone Permissions".to_string(),
                description: format!(
                    "Found {} principal(s) with DNS zone control.",
                    self.dns_zone_control_count
                ),
                steps: vec![
                    "Review DNS zone permissions".to_string(),
                    "Remove write/modify permissions from non-admin accounts".to_string(),
                    "Disable WPAD if not required".to_string(),
                    "Monitor DNS record changes".to_string(),
                ],
                reference: Some("https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/".to_string()),
            });
        }
    }
}
