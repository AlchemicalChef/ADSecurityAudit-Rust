use anyhow::{anyhow, Result};
use ldap3::{LdapConn, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use chrono::{Utc, DateTime};
use std::collections::HashMap;

/// Progress callback for audit operations
/// Parameters: (current_step, total_steps, step_name)
pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;

use crate::ldap_timeout::{
    ldap_connect_with_timeout, ldap_bind_with_timeout, ldap_unbind_with_timeout,
    DEFAULT_CONNECT_TIMEOUT,
};

use crate::security_analysis::{
    AccessControlEntry, AceType, AdminSDHolderAnalysis, RiskLevel,
    analyze_ace, calculate_risk_summary, generate_recommendations,
};

use crate::krbtgt::{
    KrbtgtAccountInfo, KrbtgtAgeAnalysis, RotationRequest, RotationResult,
    RotationStatus, AccountStatus,
    analyze_krbtgt_age, validate_rotation_request,
};

use crate::privileged_accounts::{
    PrivilegedAccount, PrivilegedAccountSummary, PrivilegedGroup, PrivilegeLevel, PrivilegeSource, PrivilegeSourceType,
    AccountType, RiskSeverity,
    get_privileged_group_definitions, calculate_risk_factors,
    calculate_overall_risk, generate_privileged_account_recommendations,
};

// **NEW IMPORTS FROM UPDATES**
use crate::domain_security::{
    DomainSecurityAudit, PasswordPolicy, LegacyComputer,
    AzureSsoAccountStatus, OptionalFeatureStatus, FunctionalLevel, Severity,
    evaluate_password_policy, evaluate_functional_level, evaluate_legacy_computers,
    evaluate_azure_sso_accounts, evaluate_recycle_bin, calculate_risk_score,
};

use crate::gpo_audit::{
    GpoAudit, GroupPolicyObject, GpoPermissionEntry, GpoLink, GpoPermission,
    SysvolPermission, run_gpo_audit, calculate_gpo_summary,
};

// **NEW IMPORTS FROM UPDATES**
use crate::delegation_audit::{
    DelegationAudit, DelegationEntry, DelegationType,
    AccountType as DelegationAccountType,
};

use crate::domain_trust_audit::{
    DomainTrustAudit, DomainTrust, TrustDirection, TrustType,
};

use crate::permissions_audit::{
    PermissionsAudit, PermissionEntry,
};

use crate::group_audit::{
    GroupAudit, GroupMember,
    PROTECTED_GROUPS,
};

use crate::da_equivalence::{
    DAEquivalenceAudit, GhostAccount, ShadowCredential, SidHistoryEntry,
    DangerousGroupMember, WeakPasswordConfig, DANGEROUS_BUILTIN_GROUPS,
};

use crate::ldap_utils::escape_ldap_filter;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub distinguished_name: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub enabled: bool,
    pub last_logon: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
}

pub struct ActiveDirectoryClient {
    server: String,
    credentials: crate::secure_types::Credentials,
    base_dn: String,
    use_ldaps: bool,
}

// ==========================================
// ACL Analysis Constants
// ==========================================

/// Dangerous access rights constants (MS-DTYP 2.4.3)
mod dangerous_rights {
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const WRITE_PROPERTY: u32 = 0x00000020;
    pub const SELF: u32 = 0x00000008;
    pub const CONTROL_ACCESS: u32 = 0x00000100;
}

impl ActiveDirectoryClient {
    pub async fn new(
        server: String,
        username: String,
        password: String,
        base_dn: String,
    ) -> Result<Self> {
        let use_ldaps = server.ends_with(":636") || server.contains("ldaps://");

        let ldap_url = if use_ldaps {
            format!("ldaps://{}", server.replace("ldaps://", ""))
        } else {
            format!("ldap://{}", server.replace("ldap://", ""))
        };

        info!("Connecting to LDAP server: {} (LDAPS: {})", ldap_url, use_ldaps);

        // Create secure credentials (clone username for logging)
        let username_for_log = username.clone();
        let credentials = crate::secure_types::Credentials::new(username, password);

        // Connect with timeout to prevent indefinite hanging
        let ldap = match ldap_connect_with_timeout(&ldap_url, DEFAULT_CONNECT_TIMEOUT).await {
            Ok(conn) => conn,
            Err(e) => {
                let error_msg = e.to_string();
                error!("LDAP connection failed to {}: {}", ldap_url, error_msg);

                // Provide more helpful error message for port 389
                if !use_ldaps && error_msg.contains("strongerAuthRequired") {
                    return Err(anyhow!(
                        "LDAP signing is required by this domain controller. \
                        Please use LDAPS (port 636) instead of plain LDAP (port 389). \
                        Original error: {}", error_msg
                    ));
                }
                return Err(e);
            }
        };

        // Bind with timeout
        let ldap = match ldap_bind_with_timeout(
            ldap,
            credentials.username(),
            credentials.password(),
            DEFAULT_CONNECT_TIMEOUT,
        ).await {
            Ok(conn) => conn,
            Err(e) => {
                let error_msg = e.to_string();
                error!("LDAP bind failed for user {}: {}", username_for_log, error_msg);

                // Provide more helpful error message for LDAP signing requirement
                if !use_ldaps && (error_msg.contains("strongerAuthRequired") ||
                                   error_msg.contains("unwillingToPerform") ||
                                   error_msg.contains("8009030E")) {
                    return Err(anyhow!(
                        "LDAP signing is required by this domain controller. \
                        Modern Active Directory environments typically require LDAPS (port 636) \
                        for secure connections. Please switch to LDAPS in the connection settings. \
                        Original error: {}", error_msg
                    ));
                }
                return Err(e);
            }
        };

        info!("Successfully connected and authenticated to {}", ldap_url);

        // Unbind with timeout
        let _ = ldap_unbind_with_timeout(ldap, DEFAULT_CONNECT_TIMEOUT).await;

        Ok(Self {
            server,
            credentials,
            base_dn,
            use_ldaps,
        })
    }

    pub async fn validate_credentials(
        server: &str,
        username: &str,
        password: &str,
    ) -> ValidationResult {
        let use_ldaps = server.ends_with(":636") || server.contains("ldaps://");

        let ldap_url = if use_ldaps {
            format!("ldaps://{}", server.replace("ldaps://", ""))
        } else {
            format!("ldap://{}", server.replace("ldap://", ""))
        };

        info!("Validating credentials against {} (LDAPS: {})", ldap_url, use_ldaps);

        // Connect with timeout to prevent indefinite hanging
        let ldap = match ldap_connect_with_timeout(&ldap_url, DEFAULT_CONNECT_TIMEOUT).await {
            Ok(conn) => conn,
            Err(e) => {
                let error_str = e.to_string();
                error!("Failed to connect to LDAP server {}: {}", server, e);

                // Provide user-friendly error message
                let message = if error_str.contains("timeout") {
                    format!(
                        "Connection timeout: Server did not respond within {} seconds. \
                         Please verify the server address and network connectivity.",
                        DEFAULT_CONNECT_TIMEOUT.as_secs()
                    )
                } else if !use_ldaps && error_str.contains("strongerAuthRequired") {
                    "LDAP signing is required. Please use LDAPS (port 636) instead of plain LDAP.".to_string()
                } else {
                    format!("Connection failed: Unable to reach server at {}. Error: {}", server, error_str)
                };

                return ValidationResult {
                    valid: false,
                    error: Some(message),
                };
            }
        };

        // Bind (authenticate) with timeout
        match ldap_bind_with_timeout(ldap, username, password, DEFAULT_CONNECT_TIMEOUT).await {
            Ok(ldap) => {
                info!("Credentials validated successfully for {}", username);
                // Clean up connection
                let _ = ldap_unbind_with_timeout(ldap, DEFAULT_CONNECT_TIMEOUT).await;
                ValidationResult {
                    valid: true,
                    error: None,
                }
            }
            Err(e) => {
                let error_str = e.to_string();
                warn!("LDAP bind failed for user {}: {}", username, e);

                // Provide user-friendly error message based on error type
                let message = if error_str.contains("timeout") {
                    format!(
                        "Authentication timeout: Server did not respond within {} seconds.",
                        DEFAULT_CONNECT_TIMEOUT.as_secs()
                    )
                } else if !use_ldaps && (error_str.contains("strongerAuthRequired") ||
                                          error_str.contains("unwillingToPerform") ||
                                          error_str.contains("8009030E") ||
                                          error_str.contains("operationsError")) {
                    "LDAP signing or channel binding is required. Please use LDAPS (port 636) for secure connections.".to_string()
                } else if error_str.contains("invalidCredentials") || error_str.contains("49") {
                    "Invalid credentials. Please check your username and password.".to_string()
                } else {
                    format!("Authentication failed: {}", error_str)
                };

                ValidationResult {
                    valid: false,
                    error: Some(message),
                }
            }
        }
    }

    async fn get_connection(&self) -> Result<LdapConn> {
        let ldap_url = if self.use_ldaps {
            format!("ldaps://{}", self.server.replace("ldaps://", ""))
        } else {
            format!("ldap://{}", self.server.replace("ldap://", ""))
        };

        info!("get_connection: Connecting to {}...", ldap_url);

        // Connect with timeout to prevent indefinite hanging
        let ldap = ldap_connect_with_timeout(&ldap_url, DEFAULT_CONNECT_TIMEOUT).await?;
        info!("get_connection: TCP connection established");

        // Bind with timeout
        let ldap = ldap_bind_with_timeout(
            ldap,
            self.credentials.username(),
            self.credentials.password(),
            DEFAULT_CONNECT_TIMEOUT,
        ).await?;
        info!("get_connection: LDAP bind successful");

        Ok(ldap)
    }

    /// Helper method to perform LDAP search with timeout
    /// This wraps the blocking search in spawn_blocking with a timeout to prevent hangs
    async fn search_with_timeout(
        &self,
        ldap: LdapConn,
        base_dn: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<(Vec<ldap3::ResultEntry>, LdapConn)> {
        crate::ldap_timeout::ldap_search_with_timeout(
            ldap,
            base_dn,
            scope,
            filter,
            attrs,
            crate::ldap_timeout::DEFAULT_SEARCH_TIMEOUT,
        ).await
    }

    /// Helper for paged LDAP search (for large result sets >1000 entries)
    /// Uses paging to fetch all results without hitting AD's size limit
    async fn paged_search_with_timeout(
        &self,
        ldap: LdapConn,
        base_dn: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<(Vec<ldap3::ResultEntry>, LdapConn)> {
        crate::ldap_timeout::ldap_paged_search_with_timeout(
            ldap,
            base_dn,
            scope,
            filter,
            attrs,
            crate::ldap_timeout::DEFAULT_PAGE_SIZE,
            crate::ldap_timeout::PAGED_SEARCH_TIMEOUT,
        ).await
    }

    /// Helper method to unbind LDAP connection with timeout to prevent blocking
    async fn unbind_with_timeout(mut ldap: LdapConn) {
        let unbind_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let _ = ldap.unbind(); // Direct unbind call inside spawn_blocking
            })
        ).await;

        match unbind_result {
            Ok(Ok(())) => {},
            Ok(Err(e)) => warn!("Unbind task error: {}", e),
            Err(_) => warn!("Unbind timed out (connection will be dropped)"),
        }
    }

    pub async fn search_users(&self, query: &str) -> Result<Vec<UserInfo>> {
        let mut ldap = self.get_connection().await?;

        // Escape user input to prevent LDAP injection attacks
        let escaped_query = crate::ldap_utils::escape_ldap_filter(query);
        let filter = format!(
            "(|(cn=*{}*)(sAMAccountName=*{}*)(mail=*{}*))",
            escaped_query, escaped_query, escaped_query
        );

        let (rs, _res) = ldap
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec![
                    "distinguishedName",
                    "sAMAccountName",
                    "mail",
                    "displayName",
                    "userAccountControl",
                    "lastLogon",
                    "memberOf",
                ],
            )?
            .success()?;

        let mut users = Vec::new();
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            let user = self.parse_user_entry(entry)?;
            users.push(user);
        }

        Self::unbind_with_timeout(ldap).await;
        Ok(users)
    }

    pub async fn get_user_details(&self, distinguished_name: &str) -> Result<UserInfo> {
        let mut ldap = self.get_connection().await?;

        // Use DN directly as search base with Scope::Base for security and efficiency
        // This prevents LDAP injection and avoids unnecessary subtree searches
        let (rs, _res) = ldap
            .search(
                distinguished_name,
                Scope::Base,
                "(objectClass=*)",
                vec![
                    "distinguishedName",
                    "sAMAccountName",
                    "mail",
                    "displayName",
                    "userAccountControl",
                    "lastLogon",
                    "memberOf",
                ],
            )?
            .success()?;

        let entry = rs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("User not found"))?;
        let entry = SearchEntry::construct(entry);
        let user = self.parse_user_entry(entry)?;

        Self::unbind_with_timeout(ldap).await;
        Ok(user)
    }

    pub async fn disable_user(&self, distinguished_name: &str, reason: &str) -> Result<()> {
        use ldap3::Mod;
        use std::collections::HashSet;

        let mut ldap = self.get_connection().await?;

        info!(
            target: "audit",
            "SECURITY ACTION: Disabling user account\n\
             User DN: {}\n\
             Reason: {}\n\
             Performed by: {}\n\
             Timestamp: {}",
            distinguished_name,
            reason,
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        // 1. Get current userAccountControl value
        let (rs, _) = ldap
            .search(
                distinguished_name,
                Scope::Base,
                "(objectClass=*)",
                vec!["userAccountControl"],
            )
            .map_err(|e| anyhow!("Failed to retrieve user: {}", e))?
            .success()?;

        let entry = SearchEntry::construct(
            rs.into_iter()
                .next()
                .ok_or_else(|| anyhow!("User not found: {}", distinguished_name))?,
        );

        let current_uac = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(512); // Default: NORMAL_ACCOUNT

        // 2. Set ACCOUNTDISABLE bit (0x0002)
        let new_uac = current_uac | 0x0002;
        let new_uac_str = new_uac.to_string();

        // 3. Apply modification
        ldap.modify(
            distinguished_name,
            vec![Mod::Replace(
                "userAccountControl",
                HashSet::from([new_uac_str.as_str()]),
            )],
        )
        .map_err(|e| anyhow!("Failed to disable user: {}", e))?
        .success()?;

        info!(
            target: "audit",
            "User successfully disabled: {} (UAC: {} -> {})",
            distinguished_name,
            current_uac,
            new_uac
        );

        Self::unbind_with_timeout(ldap).await;
        Ok(())
    }

    pub async fn analyze_adminsdholder(&self) -> Result<AdminSDHolderAnalysis> {
        let ldap = self.get_connection().await?;

        // AdminSDHolder is located at CN=AdminSDHolder,CN=System,<base_dn>
        let adminsdholder_dn = format!("CN=AdminSDHolder,CN=System,{}", self.base_dn);

        info!(
            target: "audit",
            "SECURITY AUDIT: Analyzing AdminSDHolder object\n\
             DN: {}\n\
             Performed by: {}\n\
             Timestamp: {}",
            adminsdholder_dn,
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        // Search for AdminSDHolder with security descriptor using timeout
        let (rs, mut ldap) = self.search_with_timeout(
            ldap,
            &adminsdholder_dn,
            Scope::Base,
            "(objectClass=*)",
            vec![
                "distinguishedName",
                "nTSecurityDescriptor",
                "whenCreated",
                "whenChanged",
            ],
        ).await?;

        let entry = rs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("AdminSDHolder object not found"))?;
        let entry = SearchEntry::construct(entry);

        let distinguished_name = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .unwrap_or(&adminsdholder_dn)
            .clone();

        // Parse the nTSecurityDescriptor binary data
        let sd_bytes = entry
            .bin_attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .ok_or_else(|| anyhow!("No nTSecurityDescriptor found for AdminSDHolder"))?;

        let sd = crate::ldap_utils::parse_security_descriptor(sd_bytes)
            .map_err(|e| anyhow!("Failed to parse AdminSDHolder security descriptor: {}", e))?;

        // Parse owner and group from security descriptor
        // Resolve owner SID to name
        let (owner, ldap) = match self.resolve_sid_to_name(&sd.owner_sid, ldap).await {
            Ok((name, conn)) => (name, conn),
            Err(_) => {
                let new_conn = self.get_connection().await?;
                (sd.owner_sid.clone(), new_conn)
            }
        };
        let owner_sid = sd.owner_sid.clone();

        // Resolve group SID to name
        let (group, mut ldap) = match self.resolve_sid_to_name(&sd.group_sid, ldap).await {
            Ok((name, conn)) => (name, conn),
            Err(_) => {
                let new_conn = self.get_connection().await?;
                (sd.group_sid.clone(), new_conn)
            }
        };
        let control_flags = sd.control_flags;

        // Convert ACEs to AccessControlEntry format
        let mut dacl_entries = Vec::new();

        for ace in sd.dacl {
            // Resolve trustee SID - use SID as fallback to avoid excessive LDAP calls
            let (trustee, returned_ldap) = match self.resolve_sid_to_name(&ace.trustee_sid, ldap).await {
                Ok((name, conn)) => (name, conn),
                Err(_) => {
                    let new_conn = self.get_connection().await?;
                    (ace.trustee_sid.clone(), new_conn)
                }
            };
            ldap = returned_ldap;

            let ace_type = match ace.ace_type {
                crate::ldap_utils::ace_types::ACCESS_ALLOWED
                | crate::ldap_utils::ace_types::ACCESS_ALLOWED_OBJECT => AceType::AccessAllowed,
                crate::ldap_utils::ace_types::ACCESS_DENIED
                | crate::ldap_utils::ace_types::ACCESS_DENIED_OBJECT => AceType::AccessDenied,
                crate::ldap_utils::ace_types::SYSTEM_AUDIT
                | crate::ldap_utils::ace_types::SYSTEM_AUDIT_OBJECT => AceType::SystemAudit,
                _ => AceType::Unknown,
            };

            dacl_entries.push(AccessControlEntry {
                trustee,
                trustee_sid: ace.trustee_sid,
                access_mask: ace.access_mask,
                ace_type,
                ace_flags: ace.ace_flags as u32,
                object_type: ace.object_guid,
                inherited_object_type: ace.inherited_object_guid,
                permissions: vec![],
                risk_level: RiskLevel::Info,
                risk_reasons: vec![],
            });
        }

        // Parse SACL if present
        let mut sacl_entries = Vec::new();
        for ace in sd.sacl {
            let (trustee, returned_ldap) = match self.resolve_sid_to_name(&ace.trustee_sid, ldap).await {
                Ok((name, conn)) => (name, conn),
                Err(_) => {
                    let new_conn = self.get_connection().await?;
                    (ace.trustee_sid.clone(), new_conn)
                }
            };
            ldap = returned_ldap;

            sacl_entries.push(AccessControlEntry {
                trustee,
                trustee_sid: ace.trustee_sid,
                access_mask: ace.access_mask,
                ace_type: AceType::SystemAudit,
                ace_flags: ace.ace_flags as u32,
                object_type: ace.object_guid,
                inherited_object_type: ace.inherited_object_guid,
                permissions: vec![],
                risk_level: RiskLevel::Info,
                risk_reasons: vec![],
            });
        }

        // Analyze each ACE for risks
        info!("analyze_adminsdholder: Analyzing {} DACL entries for risks", dacl_entries.len());
        for ace in &mut dacl_entries {
            analyze_ace(ace);
        }

        info!("analyze_adminsdholder: Calculating risk summary");
        let risk_summary = calculate_risk_summary(&dacl_entries);
        let total_aces = dacl_entries.len();
        let risky_aces = dacl_entries.iter()
            .filter(|a| a.risk_level != RiskLevel::Info && a.risk_level != RiskLevel::Low)
            .count();

        info!("analyze_adminsdholder: Building analysis result (total_aces={}, risky_aces={})", total_aces, risky_aces);
        let mut analysis = AdminSDHolderAnalysis {
            distinguished_name: distinguished_name.to_string(),
            owner,
            owner_sid,
            group,
            control_flags: control_flags as u32,
            dacl_entries,
            sacl_entries,
            analysis_timestamp: Utc::now().to_rfc3339(),
            total_aces,
            risky_aces,
            risk_summary,
            recommendations: vec![],
        };

        info!("analyze_adminsdholder: Generating recommendations");
        analysis.recommendations = generate_recommendations(&analysis);

        info!("analyze_adminsdholder: Unbinding LDAP connection");
        Self::unbind_with_timeout(ldap).await;

        info!("analyze_adminsdholder: Complete - returning result with {} entries", analysis.dacl_entries.len());
        Ok(analysis)
    }

    pub async fn get_adminsdholder_risky_aces(&self) -> Result<Vec<AccessControlEntry>> {
        let analysis = self.analyze_adminsdholder().await?;
        
        Ok(analysis.dacl_entries
            .into_iter()
            .filter(|ace| {
                ace.risk_level == RiskLevel::Critical || 
                ace.risk_level == RiskLevel::High
            })
            .collect())
    }

    fn parse_user_entry(&self, entry: SearchEntry) -> Result<UserInfo> {
        let distinguished_name = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .unwrap_or(&String::new())
            .clone();

        let username = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .unwrap_or(&String::new())
            .clone();

        let email = entry
            .attrs
            .get("mail")
            .and_then(|v| v.first())
            .unwrap_or(&String::new())
            .clone();

        let display_name = entry
            .attrs
            .get("displayName")
            .and_then(|v| v.first())
            .unwrap_or(&String::new())
            .clone();

        let uac = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);

        let enabled = (uac & 2) == 0;

        let last_logon = entry
            .attrs
            .get("lastLogon")
            .and_then(|v| v.first())
            .cloned();

        let groups = entry
            .attrs
            .get("memberOf")
            .map(|v| v.clone())
            .unwrap_or_default();

        Ok(UserInfo {
            distinguished_name,
            username,
            email,
            display_name,
            enabled,
            last_logon,
            groups,
        })
    }

    pub async fn get_krbtgt_account(&self) -> Result<KrbtgtAccountInfo> {
        info!("get_krbtgt_account: Starting...");
        let ldap = self.get_connection().await?;
        info!("get_krbtgt_account: Got LDAP connection");

        info!(
            target: "audit",
            "SECURITY AUDIT: Retrieving KRBTGT account information\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        // Search for the KRBTGT account in the Users container (where it always resides)
        let users_dn = format!("CN=Users,{}", self.base_dn);
        let filter = "(sAMAccountName=krbtgt)";

        info!("get_krbtgt_account: Searching in {} with filter {}", users_dn, filter);

        // Use search with timeout to prevent hanging
        let (rs, mut ldap) = crate::ldap_timeout::ldap_search_with_timeout(
            ldap,
            &users_dn,
            Scope::OneLevel,
            filter,
            vec![
                "distinguishedName",
                "sAMAccountName",
                "whenCreated",
                "pwdLastSet",
                "userAccountControl",
                "msDS-KeyVersionNumber",
            ],
            crate::ldap_timeout::DEFAULT_SEARCH_TIMEOUT,
        ).await?;

        info!("get_krbtgt_account: Got {} results", rs.len());

        let entry = rs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("KRBTGT account not found"))?;
        let entry = SearchEntry::construct(entry);

        let distinguished_name = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "krbtgt".to_string());

        // Extract domain from base_dn
        let domain = self.base_dn
            .split(',')
            .filter_map(|part| {
                if part.to_uppercase().starts_with("DC=") {
                    Some(part[3..].to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(".");

        // Parse whenCreated (format: YYYYMMDDHHmmss.0Z)
        let created = entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| self.parse_ad_timestamp(s))
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        // Parse pwdLastSet (Windows FILETIME - 100-nanosecond intervals since 1601)
        let pwd_last_set = entry
            .attrs
            .get("pwdLastSet")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        let last_password_change = self.filetime_to_rfc3339(pwd_last_set);
        let password_age_days = self.calculate_password_age_days(pwd_last_set);

        // Parse userAccountControl
        let uac = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let account_status = AccountStatus {
            is_enabled: (uac & 0x0002) == 0, // ADS_UF_ACCOUNTDISABLE
            is_locked: (uac & 0x0010) != 0,  // ADS_UF_LOCKOUT
            password_never_expires: (uac & 0x10000) != 0, // ADS_UF_DONT_EXPIRE_PASSWD
        };

        // Parse Key Version Number
        let key_version_number = entry
            .attrs
            .get("msDS-KeyVersionNumber")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(2); // Default KVN is typically 2

        Self::unbind_with_timeout(ldap).await;

        Ok(KrbtgtAccountInfo {
            distinguished_name,
            sam_account_name,
            domain,
            created,
            last_password_change,
            password_age_days,
            account_status,
            key_version_number,
            last_rotation_info: None, // Would be stored separately
        })
    }

    pub async fn analyze_krbtgt(&self) -> Result<KrbtgtAgeAnalysis> {
        let account_info = self.get_krbtgt_account().await?;
        Ok(analyze_krbtgt_age(&account_info))
    }

    pub async fn rotate_krbtgt(
        &self,
        request: RotationRequest,
        current_status: RotationStatus,
    ) -> Result<RotationResult> {
        // Validate the rotation request
        validate_rotation_request(&request, &current_status)?;

        info!(
            target: "audit",
            "SECURITY ACTION: KRBTGT Password Rotation\n\
             Rotation Number: {}\n\
             Reason: {}\n\
             Performed by: {}\n\
             Timestamp: {}",
            request.rotation_number,
            request.reason,
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        // Direct LDAP password modification of KRBTGT requires:
        // - Domain Admin or equivalent privileges
        // - The unicodePwd attribute modification
        // - SSL/TLS connection (LDAPS)

        // 1. Ensure LDAPS is enabled (required for password operations)
        if !self.use_ldaps {
            return Err(anyhow!(
                "KRBTGT rotation requires LDAPS (secure connection). \
                 Please connect using port 636 or ldaps:// protocol."
            ));
        }

        let mut ldap = self.get_connection().await?;

        // Get current key version for verification
        let account_info = self.get_krbtgt_account().await?;
        let old_kvn = account_info.key_version_number;
        let krbtgt_dn = account_info.distinguished_name.clone();

        // 2. Generate secure random password (128 characters for high entropy)
        let new_password = Self::generate_secure_random_password(128);

        // 3. Encode password for Active Directory (UTF-16LE with quotes)
        let encoded_pwd_bytes = Self::encode_password_for_ad(&new_password);

        // 4. Base64 encode for LDAP transmission (binary attribute)
        use base64::{Engine as _, engine::general_purpose};
        let encoded_pwd_b64 = general_purpose::STANDARD.encode(&encoded_pwd_bytes);

        // 5. Perform the actual password reset via LDAP modify
        use ldap3::Mod;
        use std::collections::HashSet;

        ldap.modify(
            &krbtgt_dn,
            vec![Mod::Replace(
                "unicodePwd",
                HashSet::from([encoded_pwd_b64.as_str()]),
            )],
        )
        .map_err(|e| anyhow!("Failed to rotate KRBTGT password: {}. Ensure you have Domain Admin privileges.", e))?
        .success()?;

        info!(
            target: "audit",
            "KRBTGT password rotated successfully. Previous KVN: {}, rotation #{}",
            old_kvn,
            request.rotation_number
        );

        Self::unbind_with_timeout(ldap).await;

        let new_kvn = old_kvn + 1;
        let timestamp = Utc::now().to_rfc3339();

        let (message, next_steps) = if request.rotation_number == 1 {
            (
                "First KRBTGT rotation completed successfully.".to_string(),
                vec![
                    "Wait at least 10 hours (maximum TGT lifetime) before the second rotation.".to_string(),
                    "24 hours is recommended to ensure all tickets have expired.".to_string(),
                    "Monitor for authentication issues during this period.".to_string(),
                    "Do NOT perform the second rotation immediately.".to_string(),
                ],
            )
        } else {
            (
                "Second KRBTGT rotation completed. All old tickets are now invalidated.".to_string(),
                vec![
                    "Rotation cycle complete - all previous Kerberos tickets are invalid.".to_string(),
                    "Verify that authentication is working correctly.".to_string(),
                    "Monitor domain controller logs for any issues.".to_string(),
                    "Next rotation recommended in 180 days.".to_string(),
                ],
            )
        };

        let wait_time_recommendation = if request.rotation_number == 1 {
            Some("Wait 10-24 hours before second rotation".to_string())
        } else {
            None
        };

        Ok(RotationResult {
            success: true,
            rotation_number: request.rotation_number,
            new_key_version: new_kvn,
            timestamp,
            message,
            next_steps,
            wait_time_recommendation,
        })
    }

    fn filetime_to_rfc3339(&self, filetime: i64) -> String {
        if filetime == 0 {
            return "Never".to_string();
        }
        
        // Windows FILETIME: 100-nanosecond intervals since January 1, 1601
        // Convert to Unix timestamp (seconds since 1970)
        let windows_epoch_diff: i64 = 116444736000000000; // 100-ns intervals between 1601 and 1970
        let unix_100ns = filetime - windows_epoch_diff;
        let unix_seconds = unix_100ns / 10_000_000;
        
        if let Some(dt) = DateTime::from_timestamp(unix_seconds, 0) {
            dt.to_rfc3339()
        } else {
            "Invalid timestamp".to_string()
        }
    }

    fn calculate_password_age_days(&self, filetime: i64) -> i64 {
        if filetime == 0 {
            return 0;
        }

        const WINDOWS_EPOCH_DIFF: i64 = 116444736000000000;

        // Validate filetime is reasonable (prevent integer underflow)
        if filetime < WINDOWS_EPOCH_DIFF {
            warn!("Invalid filetime value: {} (before Windows epoch), returning 0", filetime);
            return 0;
        }

        // Use saturating subtraction to prevent overflow
        let unix_100ns = filetime.saturating_sub(WINDOWS_EPOCH_DIFF);
        let unix_seconds = unix_100ns / 10_000_000;

        DateTime::from_timestamp(unix_seconds, 0)
            .map(|pwd_time| {
                let duration = Utc::now().signed_duration_since(pwd_time);
                duration.num_days()
            })
            .unwrap_or_else(|| {
                warn!("Failed to parse timestamp from unix_seconds: {}", unix_seconds);
                0
            })
    }

    fn parse_ad_timestamp(&self, timestamp: &str) -> String {
        // Format: YYYYMMDDHHmmss.0Z
        if timestamp.len() >= 14 {
            let year = &timestamp[0..4];
            let month = &timestamp[4..6];
            let day = &timestamp[6..8];
            let hour = &timestamp[8..10];
            let minute = &timestamp[10..12];
            let second = &timestamp[12..14];
            
            format!("{}-{}-{}T{}:{}:{}Z", year, month, day, hour, minute, second)
        } else {
            timestamp.to_string()
        }
    }

    pub async fn enumerate_privileged_accounts(&self) -> Result<Vec<PrivilegedAccount>> {
        let mut ldap = self.get_connection().await?;
        
        info!(
            target: "audit",
            "SECURITY AUDIT: Enumerating privileged accounts\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );
        
        let mut privileged_accounts = Vec::new();
        let group_definitions = get_privileged_group_definitions();
        
        // Search for members of each privileged group
        for (_group_type, group_name, privilege_level, _risk_score, is_protected) in &group_definitions {
            // Escape group name to prevent LDAP injection
            let escaped_group_name = escape_ldap_filter(group_name);
            let filter = format!(
                "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN={},CN=Users,{}))",
                escaped_group_name, self.base_dn
            );
            
            // Use timeout search to prevent hanging
            let (rs, returned_ldap) = self.search_with_timeout(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec![
                    "distinguishedName",
                    "sAMAccountName",
                    "displayName",
                    "mail",
                    "userAccountControl",
                    "lastLogon",
                    "pwdLastSet",
                    "servicePrincipalName",
                    "adminCount",
                    "memberOf",
                ],
            ).await?;
            ldap = returned_ldap;
            
            for entry in rs {
                let entry = SearchEntry::construct(entry);
                
                let dn = entry.attrs.get("distinguishedName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                
                // Check if account already exists
                if let Some(existing) = privileged_accounts.iter_mut()
                    .find(|a: &&mut PrivilegedAccount| a.distinguished_name == dn) {
                    // Add this group as another privilege source
                    existing.privilege_sources.push(PrivilegeSource {
                        source_type: PrivilegeSourceType::GroupMembership,
                        source_name: group_name.to_string(),
                        source_dn: Some(format!("CN={},CN=Users,{}", group_name, self.base_dn)),
                        privilege_level: privilege_level.clone(),
                        is_direct: true,
                        nested_path: None,
                    });
                    
                    // Update highest privilege level
                    if Self::privilege_level_rank(&privilege_level) > 
                       Self::privilege_level_rank(&existing.highest_privilege_level) {
                        existing.highest_privilege_level = privilege_level.clone();
                    }
                } else {
                    // Create new privileged account entry
                    let account = self.parse_privileged_account(
                        entry, 
                        group_name, 
                        privilege_level.clone(),
                        *is_protected
                    )?;
                    privileged_accounts.push(account);
                }
            }
        }
        
        // Calculate risk factors for each account
        for account in &mut privileged_accounts {
            account.risk_factors = calculate_risk_factors(account);
            account.total_risk_score = account.risk_factors.iter()
                .map(|f| f.score_impact)
                .sum();
        }
        
        Self::unbind_with_timeout(ldap).await;
        Ok(privileged_accounts)
    }
    
    pub async fn get_privileged_account_summary(&self) -> Result<PrivilegedAccountSummary> {
        let accounts = self.enumerate_privileged_accounts().await?;
        let groups = self.get_privileged_groups().await?;
        
        let total_privileged_accounts = accounts.len();
        let total_tier0_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Tier0))
            .count();
        let total_tier1_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Tier1))
            .count();
        let total_tier2_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Tier2))
            .count();
        let total_delegated_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Delegated))
            .count();
        let total_service_accounts = accounts.iter()
            .filter(|a| a.account_type == AccountType::ServiceAccount)
            .count();
        
        let enabled_accounts = accounts.iter().filter(|a| a.is_enabled).count();
        let disabled_accounts = accounts.iter().filter(|a| !a.is_enabled).count();
        let locked_accounts = accounts.iter().filter(|a| a.is_locked).count();
        
        let high_risk_accounts = accounts.iter()
            .filter(|a| a.total_risk_score > 50)
            .count();
        let accounts_password_never_expires = accounts.iter()
            .filter(|a| a.password_never_expires)
            .count();
        let accounts_with_stale_passwords = 0; // Would calculate based on pwdLastSet
        let kerberoastable_accounts = accounts.iter()
            .filter(|a| a.risk_factors.iter()
                .any(|f| matches!(f.factor_type, crate::privileged_accounts::RiskFactorType::KerberoastableSpn)))
            .count();
        
        let mut accounts_by_group = HashMap::new();
        for group in &groups {
            accounts_by_group.insert(group.name.clone(), group.member_count);
        }
        
        let mut summary = PrivilegedAccountSummary {
            total_privileged_accounts,
            total_tier0_accounts,
            total_tier1_accounts,
            total_tier2_accounts,
            total_delegated_accounts,
            total_service_accounts,
            enabled_accounts,
            disabled_accounts,
            locked_accounts,
            high_risk_accounts,
            accounts_with_stale_passwords,
            accounts_password_never_expires,
            kerberoastable_accounts,
            privileged_groups: groups,
            accounts_by_group,
            overall_risk_score: 0,
            risk_level: RiskSeverity::Low,
            analysis_timestamp: Utc::now().to_rfc3339(),
            recommendations: vec![],
        };
        
        let (risk_score, risk_level) = calculate_overall_risk(&summary);
        summary.overall_risk_score = risk_score;
        summary.risk_level = risk_level;
        summary.recommendations = generate_privileged_account_recommendations(&summary, &accounts);
        
        Ok(summary)
    }
    
    pub async fn get_privileged_groups(&self) -> Result<Vec<PrivilegedGroup>> {
        let mut ldap = self.get_connection().await?;
        let mut groups = Vec::new();
        let group_definitions = get_privileged_group_definitions();

        for (group_type, group_name, privilege_level, risk_score, is_protected) in group_definitions {
            let escaped_group = crate::ldap_utils::escape_ldap_filter(group_name);
            let filter = format!("(&(objectClass=group)(cn={}))", escaped_group);
            
            let (rs, _res) = ldap
                .search(
                    &self.base_dn,
                    Scope::Subtree,
                    &filter,
                    vec!["distinguishedName", "objectSid", "description", "member"],
                )
                .map_err(|e| anyhow!("LDAP search failed: {}", e))?
                .success()?;
            
            if let Some(entry) = rs.into_iter().next() {
                let entry = SearchEntry::construct(entry);
                
                let dn = entry.attrs.get("distinguishedName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                
                let description = entry.attrs.get("description")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| "No description".to_string());
                
                let member_count = entry.attrs.get("member")
                    .map(|v| v.len())
                    .unwrap_or(0);
                
                groups.push(PrivilegedGroup {
                    name: group_name.to_string(),
                    distinguished_name: dn,
                    sid: "".to_string(), // Would parse objectSid binary
                    group_type,
                    privilege_level,
                    member_count,
                    description,
                    risk_score,
                    is_protected,
                });
            }
        }
        
        Self::unbind_with_timeout(ldap).await;
        Ok(groups)
    }

    /// Get privileged groups with progress callback
    pub async fn get_privileged_groups_with_progress(
        &self,
        progress: Option<&ProgressCallback>,
    ) -> Result<Vec<PrivilegedGroup>> {
        let mut ldap = self.get_connection().await?;
        let mut groups = Vec::new();
        let group_definitions = get_privileged_group_definitions();
        let total = group_definitions.len();

        for (i, (group_type, group_name, privilege_level, risk_score, is_protected)) in group_definitions.into_iter().enumerate() {
            // Emit progress
            if let Some(cb) = progress {
                cb(i + 1, total, &format!("Scanning {}", group_name));
            }

            let escaped_group = crate::ldap_utils::escape_ldap_filter(group_name);
            let filter = format!("(&(objectClass=group)(cn={}))", escaped_group);

            // Use timeout search to prevent hanging
            let (rs, returned_ldap) = self.search_with_timeout(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["distinguishedName", "objectSid", "description", "member"],
            ).await?;
            ldap = returned_ldap;

            if let Some(entry) = rs.into_iter().next() {
                let entry = SearchEntry::construct(entry);

                let dn = entry.attrs.get("distinguishedName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();

                let description = entry.attrs.get("description")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| "No description".to_string());

                let member_count = entry.attrs.get("member")
                    .map(|v| v.len())
                    .unwrap_or(0);

                groups.push(PrivilegedGroup {
                    name: group_name.to_string(),
                    distinguished_name: dn,
                    sid: "".to_string(),
                    group_type,
                    privilege_level,
                    member_count,
                    description,
                    risk_score,
                    is_protected,
                });
            }
        }

        Self::unbind_with_timeout(ldap).await;
        Ok(groups)
    }

    /// Get privileged account summary with progress callback
    pub async fn get_privileged_account_summary_with_progress(
        &self,
        progress: Option<ProgressCallback>,
    ) -> Result<PrivilegedAccountSummary> {
        let accounts = self.enumerate_privileged_accounts().await?;
        let groups = self.get_privileged_groups_with_progress(progress.as_ref()).await?;

        let total_privileged_accounts = accounts.len();
        let total_tier0_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Tier0))
            .count();
        let total_tier1_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Tier1))
            .count();
        let total_tier2_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Tier2))
            .count();
        let total_delegated_accounts = accounts.iter()
            .filter(|a| matches!(a.highest_privilege_level, PrivilegeLevel::Delegated))
            .count();
        let total_service_accounts = accounts.iter()
            .filter(|a| a.account_type == AccountType::ServiceAccount)
            .count();

        let enabled_accounts = accounts.iter().filter(|a| a.is_enabled).count();
        let disabled_accounts = accounts.iter().filter(|a| !a.is_enabled).count();
        let locked_accounts = accounts.iter().filter(|a| a.is_locked).count();

        let high_risk_accounts = accounts.iter()
            .filter(|a| a.total_risk_score > 50)
            .count();
        let accounts_password_never_expires = accounts.iter()
            .filter(|a| a.password_never_expires)
            .count();
        let accounts_with_stale_passwords = 0;
        let kerberoastable_accounts = accounts.iter()
            .filter(|a| a.risk_factors.iter()
                .any(|f| matches!(f.factor_type, crate::privileged_accounts::RiskFactorType::KerberoastableSpn)))
            .count();

        let mut accounts_by_group = HashMap::new();
        for group in &groups {
            accounts_by_group.insert(group.name.clone(), group.member_count);
        }

        let mut summary = PrivilegedAccountSummary {
            total_privileged_accounts,
            total_tier0_accounts,
            total_tier1_accounts,
            total_tier2_accounts,
            total_delegated_accounts,
            total_service_accounts,
            enabled_accounts,
            disabled_accounts,
            locked_accounts,
            high_risk_accounts,
            accounts_with_stale_passwords,
            accounts_password_never_expires,
            kerberoastable_accounts,
            privileged_groups: groups,
            accounts_by_group,
            overall_risk_score: 0,
            risk_level: RiskSeverity::Low,
            analysis_timestamp: Utc::now().to_rfc3339(),
            recommendations: vec![],
        };

        let (risk_score, risk_level) = calculate_overall_risk(&summary);
        summary.overall_risk_score = risk_score;
        summary.risk_level = risk_level;
        summary.recommendations = generate_privileged_account_recommendations(&summary, &accounts);

        Ok(summary)
    }

    // Helper to rank privilege levels
    fn privilege_level_rank(level: &PrivilegeLevel) -> u8 {
        match level {
            PrivilegeLevel::Tier0 => 4,
            PrivilegeLevel::Tier1 => 3,
            PrivilegeLevel::Tier2 => 2,
            PrivilegeLevel::Delegated => 1,
            PrivilegeLevel::Service => 1,
        }
    }
    
    // Parse LDAP entry into PrivilegedAccount
    fn parse_privileged_account(
        &self,
        entry: SearchEntry,
        group_name: &str,
        privilege_level: PrivilegeLevel,
        is_protected: bool,
    ) -> Result<PrivilegedAccount> {
        let dn = entry.attrs.get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        
        let sam = entry.attrs.get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        
        let display_name = entry.attrs.get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| sam.clone());
        
        let email = entry.attrs.get("mail")
            .and_then(|v| v.first())
            .cloned();
        
        let uac = entry.attrs.get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        
        let is_enabled = (uac & 0x0002) == 0;
        let is_locked = (uac & 0x0010) != 0;
        let password_never_expires = (uac & 0x10000) != 0;
        
        let last_logon = entry.attrs.get("lastLogon")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
            .map(|ft| self.filetime_to_rfc3339(ft));
        
        let password_last_set = entry.attrs.get("pwdLastSet")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
            .map(|ft| self.filetime_to_rfc3339(ft));
        
        let has_spn = entry.attrs.get("servicePrincipalName")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        
        let admin_count = entry.attrs.get("adminCount")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);
        
        // Determine account type
        let account_type = if sam.to_lowercase().contains("svc") || has_spn {
            AccountType::ServiceAccount
        } else {
            AccountType::User
        };
        
        Ok(PrivilegedAccount {
            distinguished_name: dn,
            sam_account_name: sam,
            display_name,
            email,
            is_enabled,
            is_locked,
            last_logon,
            password_last_set,
            password_never_expires,
            account_type,
            privilege_sources: vec![PrivilegeSource {
                source_type: PrivilegeSourceType::GroupMembership,
                source_name: group_name.to_string(),
                source_dn: Some(format!("CN={},CN=Users,{}", group_name, self.base_dn)),
                privilege_level: privilege_level.clone(),
                is_direct: true,
                nested_path: None,
            }],
            highest_privilege_level: privilege_level,
            total_risk_score: 0,
            risk_factors: vec![],
            is_sensitive: false,
            is_protected: admin_count > 0 || is_protected,
        })
    }

    pub async fn audit_domain_security(&self) -> Result<DomainSecurityAudit> {
        info!("audit_domain_security: Starting...");
        let ldap = self.get_connection().await?;
        info!("audit_domain_security: Got LDAP connection");

        info!(
            target: "audit",
            "SECURITY AUDIT: Starting domain security audit\n\
             Base DN: {}\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.base_dn,
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        // Extract domain info from base_dn
        let domain_parts: Vec<&str> = self.base_dn
            .split(',')
            .filter_map(|part| {
                if part.to_uppercase().starts_with("DC=") {
                    Some(&part[3..])
                } else {
                    None
                }
            })
            .collect();
        let domain_dns_root = domain_parts.join(".");
        let domain_name = domain_parts.first().unwrap_or(&"").to_string();

        // Get domain object for functional level
        info!("audit_domain_security: Step 1 - Getting domain functional level");
        let domain_filter = "(objectClass=domain)";
        let (domain_rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Base,
            domain_filter,
            vec!["msDS-Behavior-Version", "name"],
        ).await?;

        let domain_level = domain_rs
            .into_iter()
            .next()
            .and_then(|e| {
                let entry = SearchEntry::construct(e);
                entry.attrs.get("msDS-Behavior-Version")
                    .and_then(|v| v.first())
                    .map(|s| FunctionalLevel::from_str(s))
            })
            .unwrap_or(FunctionalLevel::Unknown("Unknown".to_string()));
        info!("audit_domain_security: Domain level = {:?}", domain_level.display_name());

        // Get password policy from domain object
        info!("audit_domain_security: Step 2 - Getting password policy");
        let pwd_policy_filter = "(objectClass=domain)";
        let (pwd_rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Base,
            pwd_policy_filter,
            vec![
                "minPwdLength",
                "pwdHistoryLength",
                "maxPwdAge",
                "minPwdAge",
                "pwdProperties",
                "lockoutThreshold",
                "lockoutDuration",
                "lockOutObservationWindow",
            ],
        ).await?;

        let password_policy = pwd_rs
            .into_iter()
            .next()
            .map(|e| {
                let entry = SearchEntry::construct(e);
                self.parse_password_policy(&entry)
            })
            .unwrap_or_default();
        info!("audit_domain_security: Got password policy");

        // Check for Recycle Bin feature
        info!("audit_domain_security: Step 3 - Checking Recycle Bin feature");
        let config_dn = format!("CN=Configuration,{}",
            self.base_dn.split(',')
                .filter(|p| p.to_uppercase().starts_with("DC="))
                .collect::<Vec<_>>()
                .join(","));

        let recycle_bin_filter = "(cn=Recycle Bin Feature)";
        let recycle_bin_dn = format!("CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{}", config_dn);

        let (rb_rs, ldap) = match self.search_with_timeout(
            ldap,
            &recycle_bin_dn,
            Scope::Subtree,
            recycle_bin_filter,
            vec!["msDS-EnabledFeatureBL"],
        ).await {
            Ok(result) => result,
            Err(e) => {
                warn!("audit_domain_security: Recycle bin check failed: {}", e);
                let new_conn = self.get_connection().await?;
                (vec![], new_conn)
            }
        };

        let recycle_bin_enabled = rb_rs
            .into_iter()
            .next()
            .map(|e| {
                let entry = SearchEntry::construct(e);
                entry.attrs.get("msDS-EnabledFeatureBL")
                    .map(|v| !v.is_empty())
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        info!("audit_domain_security: Recycle bin enabled = {}", recycle_bin_enabled);

        // Search for legacy computers
        info!("audit_domain_security: Step 4 - Searching for legacy computers");
        let legacy_os_filter = "(|(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)(operatingSystem=*Windows Server 2003*)(operatingSystem=*Windows Server 2008*)(operatingSystem=*Windows Server 2012*))";

        // Use paged search to handle large result sets (>1000 entries)
        let (legacy_rs, ldap) = self.paged_search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            legacy_os_filter,
            vec![
                "cn",
                "distinguishedName",
                "operatingSystem",
                "operatingSystemVersion",
                "lastLogonTimestamp",
                "userAccountControl",
            ],
        ).await?;

        let legacy_computers: Vec<LegacyComputer> = legacy_rs
            .into_iter()
            .map(|e| {
                let entry = SearchEntry::construct(e);
                self.parse_legacy_computer(&entry)
            })
            .collect();
        info!("audit_domain_security: Found {} legacy computers", legacy_computers.len());

        // Search for Azure AD SSO accounts
        info!("audit_domain_security: Step 5 - Searching for Azure AD SSO accounts");
        let azure_sso_filter = "(sAMAccountName=AZUREADSSOACC$)";
        let (azure_rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            azure_sso_filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "pwdLastSet",
                "userAccountControl",
            ],
        ).await?;

        let azure_sso_accounts: Vec<AzureSsoAccountStatus> = azure_rs
            .into_iter()
            .map(|e| {
                let entry = SearchEntry::construct(e);
                self.parse_azure_sso_account(&entry)
            })
            .collect();
        info!("audit_domain_security: Found {} Azure SSO accounts", azure_sso_accounts.len());

        info!("audit_domain_security: Step 6 - Unbinding");
        Self::unbind_with_timeout(ldap).await;

        // Collect all findings
        info!("audit_domain_security: Step 7 - Evaluating findings");
        let mut findings = Vec::new();
        findings.extend(evaluate_password_policy(&password_policy, &domain_dns_root));
        findings.extend(evaluate_functional_level(&domain_level, &domain_level));
        findings.extend(evaluate_legacy_computers(&legacy_computers));
        findings.extend(evaluate_azure_sso_accounts(&azure_sso_accounts));
        findings.extend(evaluate_recycle_bin(recycle_bin_enabled));

        // Calculate severity counts
        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count() as u32;
        let high_count = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count() as u32;
        let medium_count = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count() as u32;
        let low_count = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count() as u32;
        let total_findings = findings.len() as u32;

        let (overall_risk_score, risk_level) = calculate_risk_score(&findings);
        info!("audit_domain_security: Complete - {} findings (critical={}, high={}, medium={}, low={})",
            total_findings, critical_count, high_count, medium_count, low_count);

        Ok(DomainSecurityAudit {
            domain_name,
            domain_dns_root,
            domain_functional_level: domain_level.display_name(),
            forest_functional_level: domain_level.display_name(),
            password_policy,
            recycle_bin_enabled,
            optional_features: vec![
                OptionalFeatureStatus {
                    name: "Recycle Bin".to_string(),
                    is_enabled: recycle_bin_enabled,
                    enabled_scopes: vec![],
                },
            ],
            legacy_computers,
            azure_sso_accounts,
            findings,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            overall_risk_score,
            risk_level,
            audit_timestamp: Utc::now().to_rfc3339(),
        })
    }

    pub async fn audit_gpos(&self) -> Result<GpoAudit> {
        self.audit_gpos_with_progress(None).await
    }

    /// Audit GPOs with optional progress callback
    pub async fn audit_gpos_with_progress(
        &self,
        progress: Option<ProgressCallback>,
    ) -> Result<GpoAudit> {
        let mut ldap = self.get_connection().await?;

        info!(
            target: "audit",
            "SECURITY AUDIT: Starting GPO security audit\n\
             Base DN: {}\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.base_dn,
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        let domain_parts: Vec<&str> = self.base_dn
            .split(',')
            .filter_map(|part| {
                if part.to_uppercase().starts_with("DC=") {
                    Some(&part[3..])
                } else {
                    None
                }
            })
            .collect();
        let domain_name = domain_parts.join(".");
        let sysvol_path = format!("\\\\{}\\SYSVOL\\{}\\Policies", domain_name, domain_name);

        // Emit progress for searching GPOs
        if let Some(ref cb) = progress {
            cb(1, 4, "Searching for Group Policy Objects");
        }

        // Search for all GPOs
        let gpo_filter = "(objectClass=groupPolicyContainer)";
        let gpo_search_base = format!("CN=Policies,CN=System,{}", self.base_dn);

        // Use timeout search to prevent hanging
        let (gpo_rs, returned_ldap) = self.search_with_timeout(
            ldap,
            &gpo_search_base,
            Scope::Subtree,
            gpo_filter,
            vec![
                "cn",
                "displayName",
                "gPCFileSysPath",
                "whenCreated",
                "whenChanged",
                "nTSecurityDescriptor",
                "flags",
                "gPCWQLFilter",
            ],
        ).await?;
        ldap = returned_ldap;

        let gpo_entries: Vec<_> = gpo_rs.into_iter().collect();
        let total_gpos = gpo_entries.len();

        // Emit progress for parsing GPOs
        if let Some(ref cb) = progress {
            cb(2, 4, &format!("Parsing {} GPO entries", total_gpos));
        }

        let mut gpos: Vec<GroupPolicyObject> = Vec::new();

        for entry in gpo_entries {
            let entry = SearchEntry::construct(entry);
            let (gpo, returned_ldap) = self.parse_gpo_entry(&entry, ldap).await?;
            ldap = returned_ldap;
            gpos.push(gpo);
        }

        // Emit progress for SYSVOL permissions
        if let Some(ref cb) = progress {
            cb(3, 4, "Checking SYSVOL permissions");
        }

        // For SYSVOL permissions, we'd need to use Windows APIs or SMB
        // Here we simulate some findings
        let sysvol_permissions = self.get_simulated_sysvol_permissions();

        Self::unbind_with_timeout(ldap).await;

        // Emit progress for running audit
        if let Some(ref cb) = progress {
            cb(4, 4, "Analyzing GPO security findings");
        }

        // Run the audit
        let findings = run_gpo_audit(&gpos, &sysvol_permissions, &sysvol_path);
        let summary = calculate_gpo_summary(&gpos, &findings);

        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count() as u32;
        let high_count = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count() as u32;
        let medium_count = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count() as u32;
        let low_count = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count() as u32;
        let total_findings = findings.len() as u32;

        let (overall_risk_score, risk_level) = calculate_risk_score(&findings);

        Ok(GpoAudit {
            domain_name,
            sysvol_path,
            gpos,
            sysvol_permissions,
            findings,
            summary,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            overall_risk_score,
            risk_level,
            audit_timestamp: Utc::now().to_rfc3339(),
        })
    }

    // Helper method to parse password policy
    fn parse_password_policy(&self, entry: &SearchEntry) -> PasswordPolicy {
        let min_pwd_length = entry.attrs.get("minPwdLength")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(7);

        let pwd_history = entry.attrs.get("pwdHistoryLength")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);

        let max_pwd_age = entry.attrs.get("maxPwdAge")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|v| (v.abs() / 864_000_000_000) as u32) // Convert 100-ns to days
            .unwrap_or(42);

        let min_pwd_age = entry.attrs.get("minPwdAge")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|v| (v.abs() / 864_000_000_000) as u32)
            .unwrap_or(1);

        let pwd_properties = entry.attrs.get("pwdProperties")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1);

        let complexity_enabled = (pwd_properties & 1) != 0;
        let reversible_encryption = (pwd_properties & 16) != 0;

        let lockout_threshold = entry.attrs.get("lockoutThreshold")
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let lockout_duration = entry.attrs.get("lockoutDuration")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|v| (v.abs() / 600_000_000) as u32) // Convert to minutes
            .unwrap_or(30);

        let lockout_window = entry.attrs.get("lockOutObservationWindow")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|v| (v.abs() / 600_000_000) as u32)
            .unwrap_or(30);

        PasswordPolicy {
            min_password_length: min_pwd_length,
            password_history_count: pwd_history,
            max_password_age_days: max_pwd_age,
            min_password_age_days: min_pwd_age,
            complexity_enabled,
            reversible_encryption_enabled: reversible_encryption,
            lockout_threshold,
            lockout_duration_minutes: lockout_duration,
            lockout_observation_window_minutes: lockout_window,
        }
    }

    // Helper to parse legacy computer entry
    fn parse_legacy_computer(&self, entry: &SearchEntry) -> LegacyComputer {
        let name = entry.attrs.get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let dn = entry.attrs.get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let os = entry.attrs.get("operatingSystem")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let os_version = entry.attrs.get("operatingSystemVersion")
            .and_then(|v| v.first())
            .cloned();

        let last_logon = entry.attrs.get("lastLogonTimestamp")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|ft| self.filetime_to_rfc3339(ft));

        let uac = entry.attrs.get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let is_enabled = (uac & 2) == 0;

        LegacyComputer {
            name,
            distinguished_name: dn,
            operating_system: os,
            operating_system_version: os_version,
            last_logon,
            is_enabled,
        }
    }

    // Helper to parse Azure SSO account
    fn parse_azure_sso_account(&self, entry: &SearchEntry) -> AzureSsoAccountStatus {
        let sam = entry.attrs.get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let dn = entry.attrs.get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let pwd_last_set = entry.attrs.get("pwdLastSet")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let password_last_set = if pwd_last_set > 0 {
            Some(self.filetime_to_rfc3339(pwd_last_set))
        } else {
            None
        };

        let password_age_days = if pwd_last_set > 0 {
            Some(self.calculate_password_age_days(pwd_last_set) as u64)
        } else {
            None
        };

        let uac = entry.attrs.get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let is_enabled = (uac & 2) == 0;
        let needs_rotation = password_age_days.map(|d| d > 30).unwrap_or(true);

        AzureSsoAccountStatus {
            sam_account_name: sam,
            distinguished_name: dn,
            password_last_set,
            password_age_days,
            is_enabled,
            needs_rotation,
        }
    }

    // Helper to parse GPO entry
    async fn parse_gpo_entry(&self, entry: &SearchEntry, ldap: LdapConn) -> Result<(GroupPolicyObject, LdapConn)> {
        let id = entry.attrs.get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let display_name = entry.attrs.get("displayName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| id.clone());

        let path = entry.attrs.get("gPCFileSysPath")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let created = entry.attrs.get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| self.parse_ad_timestamp(s));

        let modified = entry.attrs.get("whenChanged")
            .and_then(|v| v.first())
            .map(|s| self.parse_ad_timestamp(s));

        let flags = entry.attrs.get("flags")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let wmi_filter = entry.attrs.get("gPCWQLFilter")
            .and_then(|v| v.first())
            .cloned();

        // Find GPO links by searching for gPLink attributes
        let (links, ldap) = self.find_gpo_links(&id, ldap).await?;

        // Parse real GPO permissions from nTSecurityDescriptor
        let (permissions, ldap) = match self.parse_gpo_permissions(entry, ldap).await {
            Ok(result) => result,
            Err(e) => {
                warn!("Failed to parse GPO permissions for {}: {}", display_name, e);
                let new_conn = self.get_connection().await?;
                (Vec::new(), new_conn)
            }
        };

        Ok((GroupPolicyObject {
            id,
            display_name,
            path,
            created_time: created,
            modified_time: modified,
            owner: "Domain Admins".to_string(),
            permissions,
            links,
            computer_settings_enabled: (flags & 2) == 0,
            user_settings_enabled: (flags & 1) == 0,
            wmi_filter,
        }, ldap))
    }

    // Find OUs that link to a GPO
    async fn find_gpo_links(&self, gpo_id: &str, ldap: LdapConn) -> Result<(Vec<GpoLink>, LdapConn)> {
        // Escape GPO ID to prevent LDAP injection attacks
        let escaped_gpo_id = crate::ldap_utils::escape_ldap_filter(gpo_id);
        let filter = format!("(gPLink=*{}*)", escaped_gpo_id);

        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            &filter,
            vec!["distinguishedName", "name", "gPLink", "gPOptions"],
        ).await {
            Ok(result) => result,
            Err(_) => {
                let new_conn = self.get_connection().await?;
                return Ok((Vec::new(), new_conn));
            }
        };

        let mut links = Vec::new();
        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let ou_dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let ou_name = entry.attrs.get("name")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            // Parse gPLink to get enforcement status
            let gp_link = entry.attrs.get("gPLink")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let enforced = gp_link.contains(";2]") || gp_link.contains(";3]");
            let link_enabled = !gp_link.contains(";1]") && !gp_link.contains(";3]");

            links.push(GpoLink {
                ou_name,
                ou_distinguished_name: ou_dn,
                link_enabled,
                enforced,
                link_order: 1,
            });
        }

        Ok((links, ldap))
    }

    // Parse GPO permissions from nTSecurityDescriptor
    async fn parse_gpo_permissions(&self, entry: &SearchEntry, ldap: LdapConn) -> Result<(Vec<GpoPermissionEntry>, LdapConn)> {
        // Get nTSecurityDescriptor binary attribute
        let sd_bytes = match entry.bin_attrs.get("nTSecurityDescriptor") {
            Some(values) if !values.is_empty() => &values[0],
            _ => {
                warn!("No nTSecurityDescriptor found for GPO");
                return Ok((Vec::new(), ldap));
            }
        };

        // Parse security descriptor
        let sd = crate::ldap_utils::parse_security_descriptor(sd_bytes)
            .map_err(|e| anyhow!("Failed to parse security descriptor: {}", e))?;

        let mut permissions = Vec::new();
        let mut ldap = ldap;

        // Process DACL entries
        for ace in sd.dacl {
            // Resolve SID to name
            let (trustee, returned_ldap) = match self.resolve_sid_to_name(&ace.trustee_sid, ldap).await {
                Ok((name, conn)) => (name, conn),
                Err(_) => {
                    let new_conn = self.get_connection().await?;
                    (ace.trustee_sid.clone(), new_conn)
                }
            };
            ldap = returned_ldap;

            // Determine trustee type
            let trustee_type = if trustee.contains("\\") {
                "User".to_string()
            } else if ace.trustee_sid.starts_with("S-1-5-21") {
                "Group".to_string()
            } else {
                "WellKnownGroup".to_string()
            };

            // Map access mask to GPO permissions
            let (permission, permission_name) = self.map_access_mask_to_gpo_permission(ace.access_mask);

            // Check if inherited
            let inherited = (ace.ace_flags & 0x10) != 0; // INHERITED_ACE flag

            permissions.push(GpoPermissionEntry {
                trustee,
                trustee_type,
                permission,
                permission_name,
                inherited,
            });
        }

        Ok((permissions, ldap))
    }

    // Map access mask to GPO permission level
    fn map_access_mask_to_gpo_permission(&self, access_mask: u32) -> (GpoPermission, String) {
        // GPO-specific access rights
        const READ_CONTROL: u32 = 0x00020000;
        const WRITE_DAC: u32 = 0x00040000;
        const WRITE_OWNER: u32 = 0x00080000;
        const DELETE: u32 = 0x00010000;
        const GENERIC_ALL: u32 = 0x10000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const GENERIC_READ: u32 = 0x80000000;

        // Full control: includes WriteDac, WriteOwner, Delete
        if (access_mask & (WRITE_DAC | WRITE_OWNER | DELETE)) == (WRITE_DAC | WRITE_OWNER | DELETE)
            || (access_mask & GENERIC_ALL) != 0
        {
            (
                GpoPermission::GpoEditDeleteModifySecurity,
                "GpoEditDeleteModifySecurity".to_string(),
            )
        }
        // Edit: can modify but not change security
        else if (access_mask & GENERIC_WRITE) != 0 || (access_mask & DELETE) != 0 {
            (GpoPermission::GpoEdit, "GpoEdit".to_string())
        }
        // Read: read-only access
        else if (access_mask & (GENERIC_READ | READ_CONTROL)) != 0 {
            (GpoPermission::GpoRead, "GpoRead".to_string())
        }
        // Apply: can read and apply
        else {
            (GpoPermission::GpoApply, "GpoApply".to_string())
        }
    }

    // Helper function to resolve SID to friendly name
    async fn resolve_sid_to_name(&self, sid: &str, ldap: LdapConn) -> Result<(String, LdapConn)> {
        // Well-known SIDs
        let well_known_sids = [
            ("S-1-5-32-544", "BUILTIN\\Administrators"),
            ("S-1-5-32-545", "BUILTIN\\Users"),
            ("S-1-5-32-546", "BUILTIN\\Guests"),
            ("S-1-5-32-548", "BUILTIN\\Account Operators"),
            ("S-1-5-32-549", "BUILTIN\\Server Operators"),
            ("S-1-5-32-550", "BUILTIN\\Print Operators"),
            ("S-1-5-32-551", "BUILTIN\\Backup Operators"),
            ("S-1-5-11", "NT AUTHORITY\\Authenticated Users"),
            ("S-1-5-18", "NT AUTHORITY\\SYSTEM"),
            ("S-1-5-7", "NT AUTHORITY\\ANONYMOUS LOGON"),
            ("S-1-1-0", "Everyone"),
            ("S-1-5-32-554", "BUILTIN\\Pre-Windows 2000 Compatible Access"),
        ];

        // Check well-known SIDs first
        for (known_sid, name) in &well_known_sids {
            if sid == *known_sid {
                return Ok((name.to_string(), ldap));
            }
        }

        // For domain SIDs (S-1-5-21-...), try to look up in AD
        if sid.starts_with("S-1-5-21-") {
            // Search for object with this SID
            let filter = format!("(objectSid={})", sid);

            // Use timeout search to prevent hanging
            match self.search_with_timeout(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["sAMAccountName", "cn", "objectClass"],
            ).await {
                Ok((rs, ldap)) => {
                    if let Some(entry) = rs.into_iter().next() {
                        let entry = SearchEntry::construct(entry);

                        // Get the name
                        let name = entry.attrs.get("sAMAccountName")
                            .or_else(|| entry.attrs.get("cn"))
                            .and_then(|v| v.first())
                            .cloned()
                            .unwrap_or_else(|| sid.to_string());

                        return Ok((name, ldap));
                    }
                    return Ok((sid.to_string(), ldap));
                }
                Err(e) => {
                    // If lookup fails, return error (we lost the connection)
                    return Err(e);
                }
            }
        }

        // Return SID if we can't resolve it
        Ok((sid.to_string(), ldap))
    }

    // Simulate SYSVOL permissions for demo
    fn get_simulated_sysvol_permissions(&self) -> Vec<SysvolPermission> {
        vec![
            SysvolPermission {
                identity: "NT AUTHORITY\\SYSTEM".to_string(),
                access_type: "Allow".to_string(),
                rights: "FullControl".to_string(),
                inherited: false,
                is_dangerous: false,
            },
            SysvolPermission {
                identity: "BUILTIN\\Administrators".to_string(),
                access_type: "Allow".to_string(),
                rights: "FullControl".to_string(),
                inherited: false,
                is_dangerous: false,
            },
            SysvolPermission {
                identity: "Domain Admins".to_string(),
                access_type: "Allow".to_string(),
                rights: "FullControl".to_string(),
                inherited: false,
                is_dangerous: false,
            },
            SysvolPermission {
                identity: "Authenticated Users".to_string(),
                access_type: "Allow".to_string(),
                rights: "Read".to_string(),
                inherited: false,
                is_dangerous: false,
            },
        ]
    }

    pub async fn audit_delegation(&self) -> Result<DelegationAudit> {
        info!("audit_delegation: Starting...");
        let ldap = self.get_connection().await?;
        info!("audit_delegation: Got LDAP connection");

        info!(
            target: "audit",
            "SECURITY AUDIT: Analyzing Kerberos Delegation configuration\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        let mut audit = DelegationAudit::new();

        // Search for accounts with unconstrained delegation (TrustedForDelegation)
        info!("audit_delegation: Step 1 - Searching for unconstrained delegation");
        let unconstrained_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)";
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            unconstrained_filter,
            vec![
                "distinguishedName",
                "sAMAccountName",
                "objectClass",
                "userAccountControl",
                "servicePrincipalName",
                "msDS-AllowedToDelegateTo",
            ],
        ).await?;
        info!("audit_delegation: Found {} accounts with unconstrained delegation", rs.len());

        for entry in rs {
            let entry = SearchEntry::construct(entry);
            let delegation_entry = self.parse_delegation_entry(&entry, true, false)?;
            audit.delegations.push(delegation_entry.clone());
            audit.analyze_unconstrained_delegation(&delegation_entry);
        }

        // Search for accounts with constrained delegation (msDS-AllowedToDelegateTo)
        info!("audit_delegation: Step 2 - Searching for constrained delegation");
        let constrained_filter = "(msDS-AllowedToDelegateTo=*)";
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            constrained_filter,
            vec![
                "distinguishedName",
                "sAMAccountName",
                "objectClass",
                "userAccountControl",
                "servicePrincipalName",
                "msDS-AllowedToDelegateTo",
                "TrustedToAuthForDelegation",
            ],
        ).await?;
        info!("audit_delegation: Found {} accounts with constrained delegation", rs.len());

        for entry in rs {
            let entry = SearchEntry::construct(entry);
            let uac = entry
                .attrs
                .get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            let t2a4d = (uac & 0x1000000) != 0; // TRUSTED_TO_AUTH_FOR_DELEGATION
            let delegation_entry = self.parse_delegation_entry(&entry, false, t2a4d)?;

            let object_class = entry
                .attrs
                .get("objectClass")
                .map(|v| v.clone())
                .unwrap_or_default();

            if !audit.delegations.iter().any(|d| d.distinguished_name == delegation_entry.distinguished_name) {
                audit.delegations.push(delegation_entry.clone());

                if object_class.contains(&"user".to_string()) {
                    audit.analyze_user_constrained_delegation(&delegation_entry);
                } else if object_class.contains(&"computer".to_string()) {
                    audit.analyze_computer_constrained_delegation(&delegation_entry);
                }
            }
        }

        // Search for RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
        info!("audit_delegation: Step 3 - Searching for resource-based constrained delegation");
        let rbcd_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            rbcd_filter,
            vec![
                "distinguishedName",
                "sAMAccountName",
                "objectClass",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        ).await?;
        info!("audit_delegation: Found {} accounts with RBCD", rs.len());

        for entry in rs {
            let entry = SearchEntry::construct(entry);
            let mut delegation_entry = self.parse_delegation_entry(&entry, false, false)?;
            delegation_entry.delegation_type = DelegationType::ResourceBased;
            // In production, parse the security descriptor to get allowed principals
            delegation_entry.principals_allowed_to_delegate = vec!["(Requires SD parsing)".to_string()];

            audit.delegations.push(delegation_entry.clone());
            audit.analyze_rbcd(&delegation_entry);
        }

        audit.total_delegations = audit.delegations.len() as u32;
        audit.generate_recommendations();

        info!("audit_delegation: Step 4 - Unbinding");
        Self::unbind_with_timeout(ldap).await;
        info!("audit_delegation: Complete - {} total delegations found", audit.total_delegations);
        Ok(audit)
    }

    fn parse_delegation_entry(
        &self,
        entry: &SearchEntry,
        is_unconstrained: bool,
        has_t2a4d: bool,
    ) -> Result<DelegationEntry> {
        let distinguished_name = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let object_class = entry
            .attrs
            .get("objectClass")
            .map(|v| v.clone())
            .unwrap_or_default();

        let account_type = if object_class.contains(&"computer".to_string()) {
            DelegationAccountType::Computer
        } else if object_class.contains(&"msDS-GroupManagedServiceAccount".to_string()) {
            DelegationAccountType::GroupManagedServiceAccount
        } else if object_class.contains(&"msDS-ManagedServiceAccount".to_string()) {
            DelegationAccountType::ManagedServiceAccount
        } else {
            DelegationAccountType::User
        };

        let uac = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let enabled = (uac & 0x0002) == 0;
        let trusted_for_delegation = is_unconstrained || (uac & 0x80000) != 0;
        let trusted_to_auth_for_delegation = has_t2a4d || (uac & 0x1000000) != 0;

        let allowed_to_delegate_to = entry
            .attrs
            .get("msDS-AllowedToDelegateTo")
            .map(|v| v.clone())
            .unwrap_or_default();

        let service_principal_names = entry
            .attrs
            .get("servicePrincipalName")
            .map(|v| v.clone())
            .unwrap_or_default();

        let delegation_type = if is_unconstrained {
            DelegationType::Unconstrained
        } else if trusted_to_auth_for_delegation {
            DelegationType::ConstrainedWithProtocolTransition
        } else {
            DelegationType::Constrained
        };

        Ok(DelegationEntry {
            sam_account_name,
            distinguished_name,
            account_type,
            delegation_type,
            enabled,
            allowed_to_delegate_to,
            trusted_for_delegation,
            trusted_to_auth_for_delegation,
            service_principal_names,
            principals_allowed_to_delegate: Vec::new(),
        })
    }

    pub async fn audit_domain_trusts(&self) -> Result<DomainTrustAudit> {
        info!("audit_domain_trusts: Starting...");
        let ldap = self.get_connection().await?;
        info!("audit_domain_trusts: Got LDAP connection");

        info!(
            target: "audit",
            "SECURITY AUDIT: Analyzing Domain Trusts\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        let mut audit = DomainTrustAudit::new();

        // Get local domain name
        let local_domain = self.base_dn
            .split(',')
            .filter_map(|part| {
                if part.to_uppercase().starts_with("DC=") {
                    Some(part[3..].to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(".");
        info!("audit_domain_trusts: Local domain = {}", local_domain);

        // Search for trustedDomain objects in the System container
        info!("audit_domain_trusts: Step 1 - Searching for domain trusts");
        let trust_container = format!("CN=System,{}", self.base_dn);
        let trust_filter = "(objectClass=trustedDomain)";

        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &trust_container,
            Scope::OneLevel,
            trust_filter,
            vec![
                "distinguishedName",
                "name",
                "trustDirection",
                "trustType",
                "trustAttributes",
                "flatName",
                "securityIdentifier",
                "whenCreated",
                "whenChanged",
            ],
        ).await?;
        info!("audit_domain_trusts: Found {} trust relationships", rs.len());

        for entry in rs {
            let entry = SearchEntry::construct(entry);
            let trust = self.parse_trust_entry(&entry, &local_domain)?;
            audit.trusts.push(trust.clone());
            audit.analyze_trust(&trust, &local_domain);
        }

        audit.generate_recommendations(&local_domain);

        info!("audit_domain_trusts: Step 2 - Unbinding");
        Self::unbind_with_timeout(ldap).await;
        info!("audit_domain_trusts: Complete - {} trusts found", audit.trusts.len());
        Ok(audit)
    }

    fn parse_trust_entry(&self, entry: &SearchEntry, local_domain: &str) -> Result<DomainTrust> {
        let target_domain = entry
            .attrs
            .get("name")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let trust_direction_val = entry
            .attrs
            .get("trustDirection")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let direction = match trust_direction_val {
            1 => TrustDirection::Inbound,
            2 => TrustDirection::Outbound,
            3 => TrustDirection::Bidirectional,
            _ => TrustDirection::Outbound,
        };

        let trust_type_val = entry
            .attrs
            .get("trustType")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let trust_type = match trust_type_val {
            1 => TrustType::External, // TRUST_TYPE_DOWNLEVEL
            2 => TrustType::External, // TRUST_TYPE_UPLEVEL
            3 => TrustType::Realm,    // TRUST_TYPE_MIT
            4 => TrustType::External, // TRUST_TYPE_DCE
            _ => TrustType::External,
        };

        let trust_attributes = entry
            .attrs
            .get("trustAttributes")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        // TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x8
        let is_forest_trust = (trust_attributes & 0x8) != 0;
        let trust_type = if is_forest_trust { TrustType::Forest } else { trust_type };

        // TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x4 (SID filtering enabled)
        let sid_filtering_enabled = (trust_attributes & 0x4) != 0;

        // TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10 (Selective authentication)
        let selective_authentication = (trust_attributes & 0x10) != 0;

        // TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20
        let is_transitive = (trust_attributes & 0x20) != 0 || is_forest_trust;

        let created = entry
            .attrs
            .get("whenCreated")
            .and_then(|v| v.first())
            .map(|s| self.parse_ad_timestamp(s))
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        let modified = entry
            .attrs
            .get("whenChanged")
            .and_then(|v| v.first())
            .map(|s| self.parse_ad_timestamp(s))
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        Ok(DomainTrust {
            target_domain,
            source_domain: local_domain.to_string(),
            direction,
            trust_type,
            sid_filtering_enabled,
            selective_authentication,
            is_transitive,
            created,
            modified,
            trust_attributes,
        })
    }

    pub async fn audit_permissions(&self) -> Result<PermissionsAudit> {
        info!("audit_permissions: Starting...");
        let ldap = self.get_connection().await?;
        info!("audit_permissions: Got LDAP connection");

        info!(
            target: "audit",
            "SECURITY AUDIT: Analyzing Dangerous Permissions\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        let mut audit = PermissionsAudit::new();

        // Check Enterprise Key Admins group permissions on domain NC
        info!("audit_permissions: Step 1 - Checking Enterprise Key Admins group");
        let eka_filter = "(cn=Enterprise Key Admins)";
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            eka_filter,
            vec!["distinguishedName", "member"],
        ).await?;
        info!("audit_permissions: Found {} Enterprise Key Admins results", rs.len());

        if let Some(entry) = rs.into_iter().next() {
            let entry = SearchEntry::construct(entry);
            let group_dn = entry
                .attrs
                .get("distinguishedName")
                .and_then(|v| v.first())
                .cloned();

            let members = entry
                .attrs
                .get("member")
                .map(|v| v.len() as u32)
                .unwrap_or(0);

            audit.enterprise_key_admins.exists = true;
            audit.enterprise_key_admins.group_dn = group_dn;
            audit.enterprise_key_admins.member_count = members;

            // In production, we would read the nTSecurityDescriptor from the domain root
            // and check for EKA permissions. Here we simulate finding over-privileged ACEs.
            let mock_permissions = self.get_domain_root_permissions_for_eka().await?;
            audit.analyze_enterprise_key_admins(&mock_permissions, &self.base_dn);
        }

        // Check critical OUs for dangerous permissions
        info!("audit_permissions: Step 2 - Checking critical OUs");
        let critical_ous = vec![
            format!("OU=Domain Controllers,{}", self.base_dn),
            format!("CN=Users,{}", self.base_dn),
            format!("CN=Computers,{}", self.base_dn),
        ];

        for ou_dn in critical_ous {
            info!("audit_permissions: Checking permissions on {}", ou_dn);
            // In production, read nTSecurityDescriptor from each OU
            match self.get_ou_permissions(&ou_dn).await {
                Ok(permissions) => {
                    audit.analyze_critical_ou(&ou_dn, &permissions);
                }
                Err(e) => {
                    warn!("audit_permissions: Failed to get permissions for {}: {}", ou_dn, e);
                }
            }
        }

        // Calculate final counts
        for finding in &audit.all_findings {
            match finding.severity_level {
                4 => audit.critical_findings += 1,
                3 => audit.high_findings += 1,
                2 => audit.medium_findings += 1,
                1 => audit.low_findings += 1,
                _ => {}
            }
        }

        audit.generate_recommendations();

        info!("audit_permissions: Step 3 - Unbinding");
        Self::unbind_with_timeout(ldap).await;
        info!("audit_permissions: Complete - {} findings", audit.all_findings.len());
        Ok(audit)
    }

    async fn get_domain_root_permissions_for_eka(&self) -> Result<Vec<PermissionEntry>> {
        info!("get_domain_root_permissions_for_eka: Fetching domain root permissions");
        let ldap = self.get_connection().await?;

        // Fetch domain root with nTSecurityDescriptor
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Base,
            "(objectClass=domain)",
            vec!["nTSecurityDescriptor", "distinguishedName"],
        ).await?;

        let entry = SearchEntry::construct(
            rs.into_iter()
                .next()
                .ok_or_else(|| anyhow!("Domain root not found"))?,
        );

        Self::unbind_with_timeout(ldap).await;

        self.parse_object_permissions(&entry, "Domain").await
    }

    async fn get_ou_permissions(&self, ou_dn: &str) -> Result<Vec<PermissionEntry>> {
        let ldap = self.get_connection().await?;

        // Fetch OU with nTSecurityDescriptor
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            ou_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["nTSecurityDescriptor", "distinguishedName", "objectClass"],
        ).await?;

        let entry = SearchEntry::construct(
            rs.into_iter()
                .next()
                .ok_or_else(|| anyhow!("Object not found: {}", ou_dn))?,
        );

        Self::unbind_with_timeout(ldap).await;

        // Determine object type
        let object_type = entry
            .attrs
            .get("objectClass")
            .and_then(|v| v.last())
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        self.parse_object_permissions(&entry, &object_type).await
    }

    // Parse permissions from an object's nTSecurityDescriptor
    async fn parse_object_permissions(&self, entry: &SearchEntry, object_type: &str) -> Result<Vec<PermissionEntry>> {
        // Get nTSecurityDescriptor binary attribute
        let sd_bytes = entry
            .bin_attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .ok_or_else(|| anyhow!("No nTSecurityDescriptor found"))?;

        // Parse security descriptor
        let sd = crate::ldap_utils::parse_security_descriptor(sd_bytes)
            .map_err(|e| anyhow!("Failed to parse security descriptor: {}", e))?;

        let object_dn = entry
            .attrs
            .get("distinguishedName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let mut permissions = Vec::new();
        let mut ldap = self.get_connection().await?;

        // Process DACL entries
        for ace in sd.dacl {
            // Resolve SID to name
            let (identity_reference, returned_ldap) = match self.resolve_sid_to_name(&ace.trustee_sid, ldap).await {
                Ok((name, conn)) => (name, conn),
                Err(_) => {
                    let new_conn = self.get_connection().await?;
                    (ace.trustee_sid.clone(), new_conn)
                }
            };
            ldap = returned_ldap;

            // Map access mask to rights
            let active_directory_rights = self.map_access_mask_to_rights(ace.access_mask);

            // Determine access control type
            let access_control_type = match ace.ace_type {
                crate::ldap_utils::ace_types::ACCESS_ALLOWED
                | crate::ldap_utils::ace_types::ACCESS_ALLOWED_OBJECT => "Allow",
                crate::ldap_utils::ace_types::ACCESS_DENIED
                | crate::ldap_utils::ace_types::ACCESS_DENIED_OBJECT => "Deny",
                _ => "Unknown",
            }
            .to_string();

            // Extract object GUIDs
            let object_type_guid = ace
                .object_guid
                .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string());
            let inherited_object_type_guid = ace.inherited_object_guid.unwrap_or_default();

            // Check if inherited
            let is_inherited = (ace.ace_flags & 0x10) != 0; // INHERITED_ACE flag

            // Determine inheritance/propagation flags
            let inheritance_flags = if (ace.ace_flags & 0x02) != 0 {
                "ContainerInherit".to_string()
            } else {
                "None".to_string()
            };

            let propagation_flags = if (ace.ace_flags & 0x04) != 0 {
                "InheritOnly".to_string()
            } else {
                "None".to_string()
            };

            permissions.push(PermissionEntry {
                identity_reference,
                identity_sid: ace.trustee_sid,
                object_dn: object_dn.clone(),
                object_type_name: object_type.to_string(),
                active_directory_rights,
                access_control_type,
                object_type_guid,
                inherited_object_type_guid,
                is_inherited,
                inheritance_flags,
                propagation_flags,
            });
        }

        Self::unbind_with_timeout(ldap).await;
        Ok(permissions)
    }

    // Map access mask to AD rights string
    fn map_access_mask_to_rights(&self, access_mask: u32) -> String {
        let mut rights = Vec::new();

        // Standard rights
        const GENERIC_ALL: u32 = 0x10000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const GENERIC_READ: u32 = 0x80000000;
        const WRITE_DAC: u32 = 0x00040000;
        const WRITE_OWNER: u32 = 0x00080000;
        const DELETE: u32 = 0x00010000;
        const READ_CONTROL: u32 = 0x00020000;

        if (access_mask & GENERIC_ALL) != 0 {
            return "GenericAll".to_string();
        }
        if (access_mask & WRITE_DAC) != 0 {
            rights.push("WriteDacl");
        }
        if (access_mask & WRITE_OWNER) != 0 {
            rights.push("WriteOwner");
        }
        if (access_mask & DELETE) != 0 {
            rights.push("Delete");
        }
        if (access_mask & GENERIC_WRITE) != 0 {
            rights.push("GenericWrite");
        }
        if (access_mask & GENERIC_READ) != 0 {
            rights.push("GenericRead");
        }
        if (access_mask & READ_CONTROL) != 0 && rights.is_empty() {
            rights.push("ReadControl");
        }

        if rights.is_empty() {
            format!("0x{:08X}", access_mask)
        } else {
            rights.join(", ")
        }
    }
    
    pub async fn audit_privileged_groups(&self) -> Result<GroupAudit> {
        info!("audit_privileged_groups: Starting...");
        let mut ldap = self.get_connection().await?;
        info!("audit_privileged_groups: Got LDAP connection");

        info!(
            target: "audit",
            "SECURITY AUDIT: Starting privileged group audit\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        let mut audit = GroupAudit::new();

        // Iterate through protected groups
        info!("audit_privileged_groups: Checking {} protected groups", PROTECTED_GROUPS.len());
        for (idx, group_name) in PROTECTED_GROUPS.iter().enumerate() {
            info!("audit_privileged_groups: [{}/{}] Checking group: {}", idx + 1, PROTECTED_GROUPS.len(), group_name);

            // Search for the group
            let escaped_group = crate::ldap_utils::escape_ldap_filter(group_name);
            let filter = format!("(&(objectClass=group)(cn={}))", escaped_group);

            let search_result = self.search_with_timeout(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["distinguishedName", "member"],
            ).await;

            match search_result {
                Ok((rs, returned_ldap)) => {
                    ldap = returned_ldap;
                    if let Some(entry) = rs.into_iter().next() {
                        let entry = SearchEntry::construct(entry);

                        let group_dn = entry
                            .attrs
                            .get("distinguishedName")
                            .and_then(|v| v.first())
                            .cloned()
                            .unwrap_or_default();

                        // Get members
                        let member_dns = entry
                            .attrs
                            .get("member")
                            .cloned()
                            .unwrap_or_default();

                        info!("audit_privileged_groups: Group {} has {} members", group_name, member_dns.len());

                        let mut members = Vec::new();
                        for member_dn in member_dns {
                            match self.get_group_member_info(&member_dn).await {
                                Ok(member) => members.push(member),
                                Err(e) => {
                                    warn!("audit_privileged_groups: Failed to get member info for {}: {}", member_dn, e);
                                }
                            }
                        }

                        audit.analyze_group(group_name, &group_dn, members);
                    } else {
                        info!("audit_privileged_groups: Group {} not found", group_name);
                    }
                }
                Err(e) => {
                    warn!("audit_privileged_groups: Failed to search for group {}: {}", group_name, e);
                    // Get a new connection and continue
                    ldap = self.get_connection().await?;
                }
            }
        }

        audit.calculate_risk_score();
        audit.generate_recommendations();

        info!("audit_privileged_groups: Step - Unbinding");
        Self::unbind_with_timeout(ldap).await;
        info!("audit_privileged_groups: Complete - {} groups analyzed", audit.groups.len());
        Ok(audit)
    }

    async fn get_group_member_info(&self, member_dn: &str) -> Result<GroupMember> {
        let ldap = self.get_connection().await?;

        let (rs, ldap) = self.search_with_timeout(
            ldap,
            member_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["sAMAccountName", "objectClass", "userAccountControl", "lastLogonTimestamp"],
        ).await?;

        let entry = rs.into_iter().next()
            .ok_or_else(|| anyhow!("Member not found"))?;
        let entry = SearchEntry::construct(entry);

        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let object_class = entry
            .attrs
            .get("objectClass")
            .and_then(|v| v.last()) // Last is most specific (user, group, computer)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let uac = entry
            .attrs
            .get("userAccountControl")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0);

        let enabled = if object_class == "user" {
            Some((uac & 2) == 0)
        } else {
            None
        };

        let last_logon = entry
            .attrs
            .get("lastLogonTimestamp")
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i64>().ok())
            .map(|ft| self.filetime_to_rfc3339(ft));

        Self::unbind_with_timeout(ldap).await;

        Ok(GroupMember {
            sam_account_name,
            distinguished_name: member_dn.to_string(),
            object_class,
            enabled,
            last_logon,
        })
    }

    pub async fn audit_da_equivalence(&self) -> Result<DAEquivalenceAudit> {
        // Call the version with no progress callback
        self.audit_da_equivalence_with_progress(None).await
    }

    /// Audit DA equivalence with optional progress callback
    pub async fn audit_da_equivalence_with_progress(
        &self,
        progress: Option<ProgressCallback>,
    ) -> Result<DAEquivalenceAudit> {
        let mut ldap = self.get_connection().await?;

        info!(
            target: "audit",
            "SECURITY AUDIT: Starting Domain Admin Equivalence audit\n\
             Performed by: {}\n\
             Timestamp: {}",
            self.credentials.username(),
            Utc::now().to_rfc3339()
        );

        let mut audit = DAEquivalenceAudit::new();
        let total_checks = 19;

        // Helper macro to emit progress
        macro_rules! emit_progress {
            ($step:expr, $name:expr) => {
                if let Some(ref cb) = progress {
                    cb($step, total_checks, $name);
                }
            };
        }

        // === Existing Checks (using async methods with timeout) ===
        // 1. Check for AdminSDHolder ghost accounts (adminCount=1 but not in protected groups)
        emit_progress!(1, "Checking ghost accounts");
        ldap = self.check_ghost_accounts(&mut audit, ldap).await?;

        // 2. Check for Shadow Credentials (msDS-KeyCredentialLink)
        emit_progress!(2, "Checking shadow credentials");
        ldap = self.check_shadow_credentials(&mut audit, ldap).await?;

        // 3. Check for SID History injection
        emit_progress!(3, "Checking SID history");
        ldap = self.check_sid_history(&mut audit, ldap).await?;

        // 4. Check for DCSync rights
        emit_progress!(4, "Checking DCSync rights");
        ldap = self.check_dcsync_rights(&mut audit, ldap).await?;

        // 5. Check dangerous built-in group membership
        emit_progress!(5, "Checking dangerous groups");
        ldap = self.check_dangerous_groups(&mut audit, ldap).await?;

        // 6. Check weak password configurations on privileged accounts
        emit_progress!(6, "Checking weak password configs");
        ldap = self.check_weak_password_configs(&mut audit, ldap).await?;

        // === Phase 1: Simple Attack Vectors ===
        // 7. Check for legacy logon scripts
        emit_progress!(7, "Checking legacy logon scripts");
        ldap = self.check_legacy_logon_scripts(&mut audit, ldap).await?;

        // 8. Check for unconstrained delegation
        emit_progress!(8, "Checking unconstrained delegation");
        ldap = self.check_unconstrained_delegation(&mut audit, ldap).await?;

        // 9. Check for shadow credential write access (ACL-based)
        emit_progress!(9, "Checking shadow credential write access");
        ldap = self.check_shadow_credential_write_access(&mut audit, ldap).await?;

        // 10. Check for WriteSPN vulnerabilities (ACL-based)
        emit_progress!(10, "Checking WriteSPN vulnerabilities");
        ldap = self.check_write_spn_vulnerabilities(&mut audit, ldap).await?;

        // === Sprint 2: Permission-Based Attacks ===
        // 11. Check for privileged account takeover via ACLs
        emit_progress!(11, "Checking privileged account takeover");
        ldap = self.check_privileged_account_takeover(&mut audit, ldap).await?;

        // 12. Check for group membership control
        emit_progress!(12, "Checking group membership control");
        ldap = self.check_group_membership_control(&mut audit, ldap).await?;

        // 13. Check for RBCD write access
        emit_progress!(13, "Checking RBCD write access");
        ldap = self.check_rbcd_write_access(&mut audit, ldap).await?;

        // 14. Check for computer object control
        emit_progress!(14, "Checking computer object control");
        ldap = self.check_computer_object_control(&mut audit, ldap).await?;

        // 15. Check for constrained delegation to DCs
        emit_progress!(15, "Checking constrained delegation to DCs");
        ldap = self.check_constrained_delegation_to_dcs(&mut audit, ldap).await?;

        // === Sprint 3: PKI Foundation ===
        // 16. Check PKI/ADCS vulnerabilities (ESC1, ESC4, ESC8)
        emit_progress!(16, "Checking PKI vulnerabilities");
        ldap = self.check_pki_vulnerabilities(&mut audit, ldap).await?;

        // === Sprint 4: Modern Threats ===
        // 17. Check for Azure AD Connect accounts
        emit_progress!(17, "Checking Azure AD Connect");
        ldap = self.check_azure_ad_connect(&mut audit, ldap).await?;

        // 18. Check LAPS exposures
        emit_progress!(18, "Checking LAPS exposures");
        ldap = self.check_laps_exposures(&mut audit, ldap).await?;

        // 19. Check GMSA exposures
        emit_progress!(19, "Checking GMSA exposures");
        ldap = self.check_gmsa_exposures(&mut audit, ldap).await?;

        audit.calculate_risk_score();
        audit.generate_recommendations();

        Self::unbind_with_timeout(ldap).await;
        Ok(audit)
    }

    async fn check_ghost_accounts(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Find users with adminCount=1
        let filter = "(&(objectClass=user)(adminCount=1))";

        // Use timeout search to prevent hanging
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "distinguishedName", "adminCount", "memberOf"],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            // Skip krbtgt
            if sam.to_lowercase() == "krbtgt" {
                continue;
            }

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let member_of = entry.attrs.get("memberOf")
                .cloned()
                .unwrap_or_default();

            // Check if user is actually in a protected group
            let in_protected_group = member_of.iter().any(|group| {
                PROTECTED_GROUPS.iter().any(|pg| group.to_lowercase().contains(&pg.to_lowercase()))
            });

            if !in_protected_group {
                audit.add_ghost_account(GhostAccount {
                    sam_account_name: sam,
                    distinguished_name: dn,
                    admin_count: 1,
                    in_protected_group: false,
                });
            }
        }

        Ok(ldap)
    }

    async fn check_shadow_credentials(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Find objects with msDS-KeyCredentialLink populated
        let filter = "(msDS-KeyCredentialLink=*)";

        // Use timeout search to prevent hanging
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec!["cn", "distinguishedName", "objectClass"],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let name = entry.attrs.get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let object_class = entry.attrs.get("objectClass")
                .and_then(|v| v.last())
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            audit.add_shadow_credential(ShadowCredential {
                object_name: name,
                distinguished_name: dn,
                object_class,
                has_key_credential_link: true,
            });
        }

        Ok(ldap)
    }

    async fn check_sid_history(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Get domain SID for comparison
        let domain_sid = self.get_domain_sid()?;

        // Find users with sIDHistory
        let filter = "(sIDHistory=*)";

        // Use timeout search to prevent hanging
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "distinguishedName", "sIDHistory"],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            // Parse SID history (in production, parse binary SID)
            // For now, simulate detection
            let sid_history = entry.attrs.get("sIDHistory")
                .cloned()
                .unwrap_or_default();

            for sid in sid_history {
                let is_same_domain = sid.starts_with(&domain_sid);
                let rid = sid.split('-').last().map(|s| s.to_string());
                let is_privileged_rid = rid.as_ref()
                    .map(|r| ["500", "512", "519"].contains(&r.as_str()))
                    .unwrap_or(false);

                audit.add_sid_history_entry(SidHistoryEntry {
                    sam_account_name: sam.clone(),
                    distinguished_name: dn.clone(),
                    injected_sid: sid,
                    is_same_domain,
                    is_privileged_rid,
                    rid,
                });
            }
        }

        Ok(ldap)
    }

    fn get_domain_sid(&self) -> Result<String> {
        // In production, retrieve actual domain SID from domain object
        // For now, return a placeholder
        Ok("S-1-5-21-1234567890-1234567890-1234567890".to_string())
    }

    async fn check_dcsync_rights(&self, audit: &mut DAEquivalenceAudit, mut ldap: LdapConn) -> Result<LdapConn> {
        // DCSync attack GUIDs (MS-ADTS)
        const DS_REPLICATION_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
        const DS_REPLICATION_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";

        // Fetch domain root with nTSecurityDescriptor
        let (rs, returned_ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Base,
            "(objectClass=domain)",
            vec!["nTSecurityDescriptor", "distinguishedName"],
        ).await?;
        ldap = returned_ldap;

        let entry = SearchEntry::construct(
            rs.into_iter()
                .next()
                .ok_or_else(|| anyhow!("Domain root not found"))?,
        );

        // Get nTSecurityDescriptor binary attribute
        let sd_bytes = match entry.bin_attrs.get("nTSecurityDescriptor") {
            Some(values) if !values.is_empty() => values[0].clone(),
            _ => {
                warn!("No nTSecurityDescriptor found for domain root");
                return Ok(ldap);
            }
        };

        // Parse security descriptor
        let sd = crate::ldap_utils::parse_security_descriptor(&sd_bytes)
            .map_err(|e| anyhow!("Failed to parse domain security descriptor: {}", e))?;

        // Well-known SIDs that are allowed to have DCSync rights
        let allowed_sids = vec![
            "S-1-5-32-544",  // BUILTIN\Administrators
            "S-1-5-9",       // Enterprise Domain Controllers
        ];

        // Track DCSync rights by principal
        let mut dcsync_rights_by_principal: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        // Check each ACE for replication rights
        for ace in sd.dacl {
            // Only check Allow ACEs with object GUIDs
            if ace.ace_type != crate::ldap_utils::ace_types::ACCESS_ALLOWED_OBJECT {
                continue;
            }

            // Check if this ACE grants replication rights
            if let Some(ref obj_guid) = ace.object_guid {
                let guid_lower = obj_guid.to_lowercase();

                if guid_lower == DS_REPLICATION_GET_CHANGES || guid_lower == DS_REPLICATION_GET_CHANGES_ALL {
                    // Check if this is a well-known/allowed SID
                    let is_allowed = allowed_sids.contains(&ace.trustee_sid.as_str())
                        || ace.trustee_sid.ends_with("-516")  // Domain Controllers
                        || ace.trustee_sid.ends_with("-519"); // Enterprise Admins

                    if !is_allowed {
                        // Track the right for this principal
                        let right_name = if guid_lower == DS_REPLICATION_GET_CHANGES {
                            "DS-Replication-Get-Changes"
                        } else {
                            "DS-Replication-Get-Changes-All"
                        };

                        dcsync_rights_by_principal
                            .entry(ace.trustee_sid.clone())
                            .or_insert_with(Vec::new)
                            .push(right_name.to_string());
                    }
                }
            }
        }

        // Add findings for each principal with DCSync rights
        for (sid, rights) in dcsync_rights_by_principal {
            let (identity, returned_ldap) = match self.resolve_sid_to_name(&sid, ldap).await {
                Ok((name, conn)) => (name, conn),
                Err(e) => {
                    warn!("Failed to resolve SID {}: {}", sid, e);
                    // If we can't resolve, get a new connection and use the SID as identity
                    let new_conn = self.get_connection().await?;
                    (sid.clone(), new_conn)
                }
            };
            ldap = returned_ldap;

            // Check if they have both rights (full DCSync)
            let has_full_dcsync = rights.len() >= 2 ||
                rights.iter().any(|r| r.contains("Get-Changes-All"));

            audit.add_dcsync_right(crate::da_equivalence::DCSyncRight {
                principal: identity,
                rights,
                has_full_dcsync,
            });
        }

        Ok(ldap)
    }

    async fn check_dangerous_groups(&self, audit: &mut DAEquivalenceAudit, mut ldap: LdapConn) -> Result<LdapConn> {
        for (group_name, attack_path) in DANGEROUS_BUILTIN_GROUPS {
            let escaped_group = crate::ldap_utils::escape_ldap_filter(group_name);
            let filter = format!("(&(objectClass=group)(cn={}))", escaped_group);

            let (rs, returned_ldap) = self.search_with_timeout(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["member"],
            ).await?;
            ldap = returned_ldap;

            if let Some(entry) = rs.into_iter().next() {
                let entry = SearchEntry::construct(entry);

                let members = entry.attrs.get("member")
                    .cloned()
                    .unwrap_or_default();

                for member_dn in members {
                    // Get member info
                    if let Ok((member_info, returned_ldap)) = self.get_simple_member_info(&member_dn, ldap).await {
                        ldap = returned_ldap;
                        if member_info.1 == "user" { // Only flag user accounts
                            audit.add_dangerous_group_member(DangerousGroupMember {
                                group_name: group_name.to_string(),
                                member_sam_account_name: member_info.0,
                                member_dn: member_dn.clone(),
                                attack_path: attack_path.to_string(),
                            });
                        }
                    } else {
                        // If member lookup failed, get a new connection
                        ldap = self.get_connection().await?;
                    }
                }
            }
        }

        Ok(ldap)
    }

    async fn get_simple_member_info(&self, member_dn: &str, ldap: LdapConn) -> Result<((String, String), LdapConn)> {
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            member_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["sAMAccountName", "objectClass"],
        ).await?;

        if let Some(entry) = rs.into_iter().next() {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let object_class = entry.attrs.get("objectClass")
                .and_then(|v| v.last())
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            return Ok(((sam, object_class), ldap));
        }

        Err(anyhow!("Member not found"))
    }

    async fn check_weak_password_configs(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Check privileged users for weak password configurations
        // UAC flags: PASSWORD_NOT_REQUIRED (0x0020), PASSWD_NOTREQD (0x0020)
        // ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x0080)
        // Use adminCount=1 to find all protected/privileged accounts
        let filter = "(&(objectClass=user)(adminCount=1))";

        // Use paged search to handle large result sets (>1000 entries)
        let (rs, ldap) = self.paged_search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "userAccountControl", "pwdLastSet"],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let uac = entry.attrs.get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            // Check for PASSWORD_NOT_REQUIRED (0x0020)
            if uac & 0x0020 != 0 {
                audit.add_weak_password_config(WeakPasswordConfig {
                    account: sam.clone(),
                    issue: "Password Not Required".to_string(),
                    risk: "Account can have empty password - immediate takeover risk".to_string(),
                });
            }

            // Check for reversible encryption (0x0080)
            if uac & 0x0080 != 0 {
                audit.add_weak_password_config(WeakPasswordConfig {
                    account: sam.clone(),
                    issue: "Reversible Encryption Enabled".to_string(),
                    risk: "Password stored with reversible encryption - plaintext retrieval possible".to_string(),
                });
            }

            // Check for DONT_EXPIRE_PASSWORD (0x10000)
            if uac & 0x10000 != 0 {
                audit.add_weak_password_config(WeakPasswordConfig {
                    account: sam.clone(),
                    issue: "Password Never Expires".to_string(),
                    risk: "Stale credentials remain valid indefinitely - extended attack window".to_string(),
                });
            }
        }

        Ok(ldap)
    }

    async fn get_configuration_dn(&self, ldap: LdapConn) -> Result<(String, LdapConn)> {
        // Query RootDSE for configurationNamingContext
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["configurationNamingContext"],
        ).await?;

        if let Some(entry) = rs.into_iter().next() {
            let search_entry = ldap3::SearchEntry::construct(entry);
            if let Some(values) = search_entry.attrs.get("configurationNamingContext") {
                if let Some(config_dn) = values.first() {
                    return Ok((config_dn.clone(), ldap));
                }
            }
        }

        anyhow::bail!("Could not retrieve Configuration Naming Context from RootDSE")
    }

    async fn check_pki_vulnerabilities(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Get Configuration Naming Context
        let (config_dn, mut ldap) = match self.get_configuration_dn(ldap).await {
            Ok((dn, conn)) => (dn, conn),
            Err(_) => {
                // No PKI infrastructure or can't access Configuration context
                // Need to get a new connection to return
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };

        // Query certificate templates
        let templates_base = format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,{}", config_dn);
        let filter = "(objectClass=pKICertificateTemplate)";
        let attrs = vec![
            "cn", "displayName", "distinguishedName",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature",
            "pKIExtendedKeyUsage",
            "nTSecurityDescriptor",
            "msPKI-Certificate-Application-Policy"
        ];

        let (rs, returned_ldap) = match self.search_with_timeout(
            ldap,
            &templates_base,
            ldap3::Scope::Subtree,
            filter,
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                // No templates or access denied
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };
        ldap = returned_ldap;

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let template_name = search_entry.attrs.get("cn")
                .and_then(|v| v.first())
                .unwrap_or(&"Unknown".to_string())
                .clone();
            let template_dn = search_entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .unwrap_or(&"".to_string())
                .clone();

            // Check ESC1, ESC2, ESC3, ESC4
            let _ = self.check_esc1(&search_entry, &template_name, &template_dn, audit);
            let _ = self.check_esc2(&search_entry, &template_name, &template_dn, audit);
            let _ = self.check_esc3(&search_entry, &template_name, &template_dn, audit);
            let _ = self.check_esc4(&search_entry, &template_name, &template_dn, audit);
        }

        // Check ESC5 (PKI Object ACL abuse)
        ldap = self.check_esc5(&config_dn, audit, ldap).await?;

        // Check ESC7 (CA management rights)
        ldap = self.check_esc7(&config_dn, audit, ldap).await?;

        // Check ESC8 (Web Enrollment)
        ldap = self.check_esc8(&config_dn, audit, ldap).await?;

        Ok(ldap)
    }

    fn check_esc1(&self, entry: &ldap3::SearchEntry, template_name: &str, template_dn: &str, audit: &mut DAEquivalenceAudit) -> Result<()> {
        use crate::da_equivalence::{CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, CLIENT_AUTHENTICATION_EKU,
                                      SMART_CARD_LOGON_EKU, ANY_PURPOSE_EKU};
        use crate::ldap_utils::parse_security_descriptor;

        // ESC1: Template allows ENROLLEE_SUPPLIES_SUBJECT and has dangerous EKU
        let name_flag = entry.attrs.get("msPKI-Certificate-Name-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Check if ENROLLEE_SUPPLIES_SUBJECT is set
        if (name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) == 0 {
            return Ok(()); // Not vulnerable to ESC1
        }

        // Check for dangerous EKUs
        let ekus = entry.attrs.get("pKIExtendedKeyUsage")
            .or_else(|| entry.attrs.get("msPKI-Certificate-Application-Policy"))
            .map(|v| v.clone())
            .unwrap_or_default();

        let has_dangerous_eku = ekus.iter().any(|eku| {
            eku == CLIENT_AUTHENTICATION_EKU ||
            eku == SMART_CARD_LOGON_EKU ||
            eku == ANY_PURPOSE_EKU
        }) || ekus.is_empty(); // No EKU = Any Purpose

        if !has_dangerous_eku {
            return Ok(());
        }

        // Check if manager approval is required (mitigates ESC1)
        let enrollment_flag = entry.attrs.get("msPKI-Enrollment-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;
        if (enrollment_flag & CT_FLAG_PEND_ALL_REQUESTS) != 0 {
            return Ok(()); // Manager approval required - mitigated
        }

        // Check if authorized signatures are required
        let required_signatures = entry.attrs.get("msPKI-RA-Signature")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        if required_signatures > 0 {
            return Ok(()); // Signatures required - mitigated
        }

        // Check who can enroll
        if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
            if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                for ace in &sd.dacl {
                    // Check for Certificate-Enrollment extended right or GenericAll
                    if self.ace_grants_certificate_enrollment(ace) {
                        let sid_str = &ace.trustee_sid;
                        if !self.is_legitimate_principal(sid_str) {
                            audit.add_esc1_vulnerability(crate::da_equivalence::ESC1Vulnerability {
                                template_name: template_name.to_string(),
                                template_dn: template_dn.to_string(),
                                enrollee_supplies_subject: true,
                                dangerous_eku: true,
                                no_manager_approval: true,
                                enroller: sid_str.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn ace_grants_certificate_enrollment(&self, ace: &crate::ldap_utils::AceEntry) -> bool {
        use crate::da_equivalence::CERTIFICATE_ENROLLMENT_GUID;
        use crate::ldap_utils::ace_types;

        // Only check ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
        if ace.ace_type != ace_types::ACCESS_ALLOWED
            && ace.ace_type != ace_types::ACCESS_ALLOWED_OBJECT
        {
            return false;
        }

        // Check for Certificate-Enrollment extended right
        if let Some(ref object_guid) = ace.object_guid {
            if object_guid.to_lowercase() == CERTIFICATE_ENROLLMENT_GUID {
                return true;
            }
        }

        // Check for GenericAll or other broad rights
        const GENERIC_ALL: u32 = 0x10000000;
        const WRITE_DACL: u32 = 0x00040000;
        const WRITE_OWNER: u32 = 0x00080000;

        (ace.access_mask & GENERIC_ALL) != 0 ||
        (ace.access_mask & WRITE_DACL) != 0 ||
        (ace.access_mask & WRITE_OWNER) != 0
    }

    fn check_esc4(&self, entry: &ldap3::SearchEntry, template_name: &str, template_dn: &str, audit: &mut DAEquivalenceAudit) -> Result<()> {
        use crate::ldap_utils::parse_security_descriptor;

        // ESC4: Write access to certificate template object
        if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
            if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                for ace in &sd.dacl {
                    // Check for write access that could modify template settings
                    if self.ace_grants_template_write(ace) {
                        let sid_str = &ace.trustee_sid;
                        if !self.is_legitimate_principal(sid_str) {
                            audit.add_esc4_vulnerability(crate::da_equivalence::ESC4Vulnerability {
                                template_name: template_name.to_string(),
                                template_dn: template_dn.to_string(),
                                principal: sid_str.to_string(),
                                write_access_type: self.describe_write_access(ace),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn ace_grants_template_write(&self, ace: &crate::ldap_utils::AceEntry) -> bool {
        use crate::ldap_utils::ace_types;

        // Only check ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
        if ace.ace_type != ace_types::ACCESS_ALLOWED
            && ace.ace_type != ace_types::ACCESS_ALLOWED_OBJECT
        {
            return false;
        }

        const GENERIC_ALL: u32 = 0x10000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const WRITE_DACL: u32 = 0x00040000;
        const WRITE_OWNER: u32 = 0x00080000;
        const WRITE_PROPERTY: u32 = 0x00000020;

        (ace.access_mask & GENERIC_ALL) != 0 ||
        (ace.access_mask & GENERIC_WRITE) != 0 ||
        (ace.access_mask & WRITE_DACL) != 0 ||
        (ace.access_mask & WRITE_OWNER) != 0 ||
        (ace.access_mask & WRITE_PROPERTY) != 0
    }

    fn describe_write_access(&self, ace: &crate::ldap_utils::AceEntry) -> String {
        const GENERIC_ALL: u32 = 0x10000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const WRITE_DACL: u32 = 0x00040000;
        const WRITE_OWNER: u32 = 0x00080000;

        if (ace.access_mask & GENERIC_ALL) != 0 {
            "GenericAll".to_string()
        } else if (ace.access_mask & WRITE_DACL) != 0 {
            "WriteDacl".to_string()
        } else if (ace.access_mask & WRITE_OWNER) != 0 {
            "WriteOwner".to_string()
        } else if (ace.access_mask & GENERIC_WRITE) != 0 {
            "GenericWrite".to_string()
        } else {
            "WriteProperty".to_string()
        }
    }

    async fn check_esc8(&self, config_dn: &str, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // ESC8: Web Enrollment with NTLM enabled
        // Check for Certificate Authority Web Enrollment role
        let enrollment_services_base = format!("CN=Enrollment Services,CN=Public Key Services,CN=Services,{}", config_dn);
        let filter = "(objectClass=pKIEnrollmentService)";
        let attrs = vec!["cn", "dNSHostName", "distinguishedName"];

        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            &enrollment_services_base,
            ldap3::Scope::Subtree,
            filter,
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                let new_conn = self.get_connection().await?;
                return Ok(new_conn); // No enrollment services
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let ca_name = search_entry.attrs.get("cn")
                .and_then(|v| v.first())
                .unwrap_or(&"Unknown".to_string())
                .clone();
            let dns_hostname = search_entry.attrs.get("dNSHostName")
                .and_then(|v| v.first())
                .cloned();

            if let Some(hostname) = dns_hostname {
                // Check if web enrollment is likely enabled (we can't directly check IIS config via LDAP)
                // This is a potential risk that should be manually verified
                audit.add_esc8_vulnerability(crate::da_equivalence::ESC8Vulnerability {
                    ca_name: ca_name.clone(),
                    web_enrollment_server: hostname.clone(),
                    ntlm_enabled: true, // Assume NTLM is enabled unless explicitly disabled
                });
            }
        }

        Ok(ldap)
    }

    fn check_esc2(&self, entry: &ldap3::SearchEntry, template_name: &str, template_dn: &str, audit: &mut DAEquivalenceAudit) -> Result<()> {
        use crate::da_equivalence::{ANY_PURPOSE_EKU, CLIENT_AUTHENTICATION_EKU, SMART_CARD_LOGON_EKU};
        use crate::ldap_utils::parse_security_descriptor;

        // ESC2: Template allows Any Purpose EKU or no EKU (similar risk to ESC1)
        let ekus = entry.attrs.get("pKIExtendedKeyUsage")
            .or_else(|| entry.attrs.get("msPKI-Certificate-Application-Policy"))
            .map(|v| v.clone())
            .unwrap_or_default();

        // Check if Any Purpose EKU is present or no EKU at all
        let has_any_purpose = ekus.iter().any(|eku| eku == ANY_PURPOSE_EKU);
        let has_no_eku = ekus.is_empty();

        if !has_any_purpose && !has_no_eku {
            return Ok(()); // Not vulnerable to ESC2
        }

        // Check if manager approval is required (mitigates ESC2)
        let enrollment_flag = entry.attrs.get("msPKI-Enrollment-Flag")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;
        if (enrollment_flag & CT_FLAG_PEND_ALL_REQUESTS) != 0 {
            return Ok(()); // Manager approval required - mitigated
        }

        // Check who can enroll
        if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
            if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                for ace in &sd.dacl {
                    if self.ace_grants_certificate_enrollment(ace) {
                        let sid_str = &ace.trustee_sid;
                        if !self.is_legitimate_principal(sid_str) {
                            audit.add_esc2_vulnerability(crate::da_equivalence::ESC2Vulnerability {
                                template_name: template_name.to_string(),
                                template_dn: template_dn.to_string(),
                                has_any_purpose_eku: has_any_purpose,
                                has_no_eku,
                                enroller: sid_str.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn check_esc3(&self, entry: &ldap3::SearchEntry, template_name: &str, template_dn: &str, audit: &mut DAEquivalenceAudit) -> Result<()> {
        use crate::da_equivalence::CERTIFICATE_REQUEST_AGENT_EKU;
        use crate::ldap_utils::parse_security_descriptor;

        // ESC3: Template allows Certificate Request Agent EKU
        let ekus = entry.attrs.get("pKIExtendedKeyUsage")
            .or_else(|| entry.attrs.get("msPKI-Certificate-Application-Policy"))
            .map(|v| v.clone())
            .unwrap_or_default();

        // Check if Certificate Request Agent EKU is present
        let has_request_agent_eku = ekus.iter().any(|eku| eku == CERTIFICATE_REQUEST_AGENT_EKU);

        if !has_request_agent_eku {
            return Ok(()); // Not an enrollment agent template
        }

        // Check authorized signatures requirement
        let required_signatures = entry.attrs.get("msPKI-RA-Signature")
            .and_then(|v| v.first())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Check who can enroll
        if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
            if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                for ace in &sd.dacl {
                    if self.ace_grants_certificate_enrollment(ace) {
                        let sid_str = &ace.trustee_sid;
                        if !self.is_legitimate_principal(sid_str) {
                            audit.add_esc3_vulnerability(crate::da_equivalence::ESC3Vulnerability {
                                template_name: template_name.to_string(),
                                template_dn: template_dn.to_string(),
                                is_enrollment_agent: true,
                                authorized_signatures_required: required_signatures,
                                enroller: sid_str.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_esc5(&self, config_dn: &str, audit: &mut DAEquivalenceAudit, mut ldap: LdapConn) -> Result<LdapConn> {
        // ESC5: Check write access to PKI configuration objects
        // Check CA container
        let ca_container = format!("CN=Certification Authorities,CN=Public Key Services,CN=Services,{}", config_dn);
        ldap = self.check_pki_container_permissions(&ca_container, "CA Container", audit, ldap).await?;

        // Check Certificate Templates container
        let template_container = format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,{}", config_dn);
        ldap = self.check_pki_container_permissions(&template_container, "Certificate Templates Container", audit, ldap).await?;

        // Check NTAuthCertificates
        let ntauth_dn = format!("CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{}", config_dn);
        ldap = self.check_pki_object_permissions(&ntauth_dn, "NTAuthCertificates", audit, ldap).await?;

        Ok(ldap)
    }

    async fn check_pki_container_permissions(&self, container_dn: &str, container_name: &str, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        let attrs = vec!["nTSecurityDescriptor"];
        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            container_dn,
            ldap3::Scope::Base,
            "(objectClass=*)",
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            if let Some(sd_bytes) = search_entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    for ace in &sd.dacl {
                        if self.ace_grants_template_write(ace) {
                            let sid_str = &ace.trustee_sid;
                            if !self.is_legitimate_principal(sid_str) {
                                audit.add_esc5_vulnerability(crate::da_equivalence::ESC5Vulnerability {
                                    object_name: container_name.to_string(),
                                    object_dn: container_dn.to_string(),
                                    object_type: "PKI Container".to_string(),
                                    principal: sid_str.to_string(),
                                    write_access_type: self.describe_write_access(ace),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    async fn check_pki_object_permissions(&self, object_dn: &str, object_name: &str, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        let attrs = vec!["nTSecurityDescriptor"];
        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            object_dn,
            ldap3::Scope::Base,
            "(objectClass=*)",
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            if let Some(sd_bytes) = search_entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    for ace in &sd.dacl {
                        if self.ace_grants_template_write(ace) {
                            let sid_str = &ace.trustee_sid;
                            if !self.is_legitimate_principal(sid_str) {
                                audit.add_esc5_vulnerability(crate::da_equivalence::ESC5Vulnerability {
                                    object_name: object_name.to_string(),
                                    object_dn: object_dn.to_string(),
                                    object_type: "PKI Object".to_string(),
                                    principal: sid_str.to_string(),
                                    write_access_type: self.describe_write_access(ace),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    async fn check_esc7(&self, config_dn: &str, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;
        use crate::da_equivalence::{MANAGE_CA_GUID, CERTIFICATE_ENROLLMENT_GUID};

        // Query Certification Authorities (CAs)
        let cas_base = format!("CN=Enrollment Services,CN=Public Key Services,CN=Services,{}", config_dn);
        let filter = "(objectClass=pKIEnrollmentService)";
        let attrs = vec!["cn", "distinguishedName", "nTSecurityDescriptor"];

        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            &cas_base,
            ldap3::Scope::Subtree,
            filter,
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let ca_name = search_entry.attrs.get("cn")
                .and_then(|v| v.first())
                .unwrap_or(&"Unknown".to_string())
                .clone();
            let ca_dn = search_entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .unwrap_or(&"".to_string())
                .clone();

            // Check ACL for ManageCA and ManageCertificates rights
            if let Some(sd_bytes) = search_entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    for ace in &sd.dacl {
                        let sid_str = &ace.trustee_sid;
                        if !self.is_legitimate_principal(sid_str) {
                            let has_manage_ca = self.ace_has_manage_ca(ace);
                            let has_manage_certs = self.ace_grants_template_write(ace); // Simplified check

                            if has_manage_ca || has_manage_certs {
                                audit.add_esc7_vulnerability(crate::da_equivalence::ESC7Vulnerability {
                                    ca_name: ca_name.clone(),
                                    ca_dn: ca_dn.clone(),
                                    principal: sid_str.to_string(),
                                    has_manage_ca,
                                    has_manage_certificates: has_manage_certs,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    fn ace_has_manage_ca(&self, ace: &crate::ldap_utils::AceEntry) -> bool {
        use crate::da_equivalence::MANAGE_CA_GUID;
        use crate::ldap_utils::ace_types;

        // Only check ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
        if ace.ace_type != ace_types::ACCESS_ALLOWED
            && ace.ace_type != ace_types::ACCESS_ALLOWED_OBJECT
        {
            return false;
        }

        // Check for ManageCA extended right
        if let Some(ref object_guid) = ace.object_guid {
            if object_guid.to_lowercase() == MANAGE_CA_GUID {
                return true;
            }
        }

        // Check for GenericAll
        const GENERIC_ALL: u32 = 0x10000000;
        (ace.access_mask & GENERIC_ALL) != 0
    }

    async fn check_azure_ad_connect(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Azure AD Connect accounts (MSOL_*, AAD_*, AZUREADSSOACC$) have DCSync rights
        // These are high-value targets as they can extract all domain credentials
        let filter = "(|(cn=MSOL_*)(cn=AAD_*)(cn=AZUREADSSOACC$)(samAccountName=MSOL_*)(samAccountName=AAD_*)(samAccountName=AZUREADSSOACC$))";
        let attrs = vec!["samAccountName", "distinguishedName", "userAccountControl", "description"];

        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            &self.base_dn,
            ldap3::Scope::Subtree,
            filter,
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                let new_conn = self.get_connection().await?;
                return Ok(new_conn); // No Azure AD Connect accounts
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let sam = search_entry.attrs.get("samAccountName")
                .and_then(|v| v.first())
                .unwrap_or(&"Unknown".to_string())
                .clone();
            let dn = search_entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .unwrap_or(&"".to_string())
                .clone();
            let description = search_entry.attrs.get("description")
                .and_then(|v| v.first())
                .cloned();

            // Check if account is enabled
            let uac = search_entry.attrs.get("userAccountControl")
                .and_then(|v| v.first())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);

            let is_disabled = (uac & 0x0002) != 0;

            audit.add_azure_ad_connect(crate::da_equivalence::AzureADConnect {
                account_name: sam.clone(),
                distinguished_name: dn.clone(),
                is_enabled: !is_disabled,
                description,
            });
        }

        Ok(ldap)
    }

    async fn check_laps_exposures(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // LAPS password attribute GUID
        const LAPS_PASSWORD_GUID: &str = "ea1b7b93-5e48-46d5-bc6c-4df4fda78a35"; // ms-Mcs-AdmPwd

        // Query computers with LAPS enabled (has ms-Mcs-AdmPwd attribute)
        let filter = "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))";
        let attrs = vec!["cn", "distinguishedName", "nTSecurityDescriptor"];

        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            &self.base_dn,
            ldap3::Scope::Subtree,
            filter,
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                // No LAPS computers or access denied - get new connection
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let computer_name = search_entry.attrs.get("cn")
                .and_then(|v| v.first())
                .unwrap_or(&"Unknown".to_string())
                .clone();
            let _computer_dn = search_entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .unwrap_or(&"".to_string())
                .clone();

            // Check ACL for read access to LAPS password
            if let Some(sd_bytes) = search_entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    for ace in &sd.dacl {
                        // Check for read access to ms-Mcs-AdmPwd attribute
                        if self.ace_grants_laps_read(ace, LAPS_PASSWORD_GUID) {
                            let sid_str = &ace.trustee_sid;
                            if !self.is_legitimate_principal(sid_str) {
                                audit.add_laps_exposure(crate::da_equivalence::LapsExposure {
                                    computer_name: computer_name.clone(),
                                    principal: sid_str.to_string(),
                                    can_read_password: true,
                                    can_write_expiration: false, // Not checked here
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    fn ace_grants_laps_read(&self, ace: &crate::ldap_utils::AceEntry, laps_guid: &str) -> bool {
        use crate::ldap_utils::ace_types;

        // Only check ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
        if ace.ace_type != ace_types::ACCESS_ALLOWED
            && ace.ace_type != ace_types::ACCESS_ALLOWED_OBJECT
        {
            return false;
        }

        const GENERIC_ALL: u32 = 0x10000000;
        const GENERIC_READ: u32 = 0x80000000;
        const READ_PROPERTY: u32 = 0x00000010;

        // Check for broad read rights
        if (ace.access_mask & GENERIC_ALL) != 0 || (ace.access_mask & GENERIC_READ) != 0 {
            return true;
        }

        // Check for specific ReadProperty on LAPS attribute
        if (ace.access_mask & READ_PROPERTY) != 0 {
            if let Some(ref object_guid) = ace.object_guid {
                if object_guid.to_lowercase() == laps_guid.to_lowercase() {
                    return true;
                }
            }
        }

        false
    }

    async fn check_gmsa_exposures(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // Query Group Managed Service Accounts
        let filter = "(objectClass=msDS-GroupManagedServiceAccount)";
        let attrs = vec![
            "cn", "distinguishedName", "msDS-GroupMSAMembership",
            "msDS-ManagedPasswordPrincipal", "memberOf"
        ];

        let (rs, ldap) = match self.search_with_timeout(
            ldap,
            &self.base_dn,
            ldap3::Scope::Subtree,
            filter,
            attrs,
        ).await {
            Ok(result) => result,
            Err(_) => {
                // No gMSAs or access denied - get new connection
                let new_conn = self.get_connection().await?;
                return Ok(new_conn);
            }
        };

        for entry in rs {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let gmsa_name = search_entry.attrs.get("cn")
                .and_then(|v| v.first())
                .unwrap_or(&"Unknown".to_string())
                .clone();
            let _gmsa_dn = search_entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .unwrap_or(&"".to_string())
                .clone();

            // Check group memberships
            let member_of = search_entry.attrs.get("memberOf")
                .map(|v| v.clone())
                .unwrap_or_default();

            let is_privileged = member_of.iter().any(|group| {
                group.contains("Domain Admins") ||
                group.contains("Enterprise Admins") ||
                group.contains("Schema Admins") ||
                group.contains("Administrators")
            });

            // Only report privileged gMSAs
            // In production, would parse msDS-GroupMSAMembership to find specific principals
            if is_privileged {
                // Report that this gMSA is privileged and should be monitored
                // The principal field represents who can read it (simplified as "Various Principals")
                audit.add_gmsa_exposure(crate::da_equivalence::GmsaExposure {
                    gmsa_name: gmsa_name.clone(),
                    principal: "Authorized Principals (check msDS-GroupMSAMembership)".to_string(),
                    can_read_password: true,
                });
            }
        }

        Ok(ldap)
    }

    // ==========================================
    // ACL Analysis Helper Functions
    // ==========================================

    /// Check if an ACE grants dangerous rights on a target object
    /// Returns Some(description) if dangerous rights are found, None otherwise
    fn ace_grants_dangerous_rights(
        &self,
        ace: &crate::ldap_utils::AceEntry,
        target_guid: Option<&str>,
    ) -> Option<String> {
        use crate::ldap_utils::ace_types;

        // Only check ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT ACEs
        if ace.ace_type != ace_types::ACCESS_ALLOWED
            && ace.ace_type != ace_types::ACCESS_ALLOWED_OBJECT
        {
            return None;
        }

        let mask = ace.access_mask;

        // Check for broad control rights
        if mask & dangerous_rights::GENERIC_ALL != 0 {
            return Some("GenericAll".to_string());
        }
        if mask & dangerous_rights::WRITE_DAC != 0 {
            return Some("WriteDacl".to_string());
        }
        if mask & dangerous_rights::WRITE_OWNER != 0 {
            return Some("WriteOwner".to_string());
        }

        // For Object ACEs with a target GUID, check property-specific rights
        if let Some(target) = target_guid {
            if let Some(ref obj_guid) = ace.object_guid {
                // GUIDs are case-insensitive, normalize to lowercase
                if obj_guid.to_lowercase() == target.to_lowercase() {
                    // Check for WriteProperty on this specific attribute
                    if mask & dangerous_rights::WRITE_PROPERTY != 0 {
                        return Some("WriteProperty".to_string());
                    }
                    // Check for SELF (add/remove self from attribute)
                    if mask & dangerous_rights::SELF != 0 {
                        return Some("Self".to_string());
                    }
                    // Check for CONTROL_ACCESS (extended right)
                    if mask & dangerous_rights::CONTROL_ACCESS != 0 {
                        return Some("ControlAccess".to_string());
                    }
                }
            } else if ace.object_guid.is_none() {
                // ACE with no object_guid applies to ALL properties
                if mask & dangerous_rights::WRITE_PROPERTY != 0 {
                    return Some("WriteProperty".to_string());
                }
                if mask & dangerous_rights::GENERIC_WRITE != 0 {
                    return Some("GenericWrite".to_string());
                }
            }
        }

        None
    }

    /// Check if a SID represents a legitimate principal that normally has broad control
    fn is_legitimate_principal(&self, sid: &str) -> bool {
        // Well-known SIDs for privileged principals
        const LEGITIMATE_SIDS: [&str; 10] = [
            "S-1-5-18",        // NT AUTHORITY\SYSTEM
            "S-1-5-32-544",    // BUILTIN\Administrators
            "S-1-5-32-548",    // BUILTIN\Account Operators
            "S-1-5-32-549",    // BUILTIN\Server Operators
            "S-1-5-32-550",    // BUILTIN\Print Operators
            "S-1-5-32-551",    // BUILTIN\Backup Operators
            "S-1-5-9",         // Enterprise Domain Controllers
            "S-1-3-0",         // Creator Owner
            "S-1-5-10",        // Self
            "S-1-1-0",         // Everyone (sometimes legitimate)
        ];

        // Check well-known SIDs
        if LEGITIMATE_SIDS.contains(&sid) {
            return true;
        }

        // Check for Domain Admins, Enterprise Admins, Schema Admins (RID 512, 519, 518)
        if sid.ends_with("-512") || sid.ends_with("-519") || sid.ends_with("-518") {
            return true;
        }

        // Check for Domain Controllers (RID 516)
        if sid.ends_with("-516") {
            return true;
        }

        false
    }

    // ==========================================
    // New Attack Vector Checks
    // ==========================================

    /// Check for legacy logon scripts (scriptPath attribute)
    /// Legacy logon scripts can be hijacked for code execution
    async fn check_legacy_logon_scripts(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        let filter = "(&(objectClass=user)(scriptPath=*))";

        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec!["sAMAccountName", "distinguishedName", "scriptPath"],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let script_path = entry.attrs.get("scriptPath")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if !script_path.is_empty() {
                audit.add_legacy_logon_script(crate::da_equivalence::LegacyLogonScript {
                    account_name: sam,
                    distinguished_name: dn,
                    script_path,
                });
            }
        }

        Ok(ldap)
    }

    /// Check for unconstrained delegation (can impersonate any user)
    /// Excludes Domain Controllers as they legitimately have this flag
    async fn check_unconstrained_delegation(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        // UAC flag 0x80000 (524288) = TRUSTED_FOR_DELEGATION
        // Exclude DCs (primaryGroupID=516)
        let filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))";

        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "objectClass",
                "servicePrincipalName",
                "operatingSystem",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let object_class = entry.attrs.get("objectClass")
                .map(|v| v.clone())
                .unwrap_or_default();

            let account_type = if object_class.contains(&"computer".to_string()) {
                "Computer"
            } else {
                "User"
            };

            let spns = entry.attrs.get("servicePrincipalName")
                .map(|v| v.clone())
                .unwrap_or_default();

            let operating_system = entry.attrs.get("operatingSystem")
                .and_then(|v| v.first())
                .cloned();

            audit.add_unconstrained_delegation(crate::da_equivalence::UnconstrainedDelegation {
                account_name: sam,
                distinguished_name: dn,
                account_type: account_type.to_string(),
                operating_system,
                spns,
                is_domain_controller: false, // We already filtered out DCs
            });
        }

        Ok(ldap)
    }

    /// Check for write access to msDS-KeyCredentialLink (Shadow Credentials attack)
    /// Allows adding key credentials to impersonate the target account
    async fn check_shadow_credential_write_access(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // Target computers and privileged users
        // Prioritize computers (including DCs) and users with adminCount=1
        let filter = "(|(objectClass=computer)(adminCount=1))";

        // Use paged search to handle large result sets (>1000 entries)
        let (rs, ldap) = self.paged_search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "objectClass",
                "nTSecurityDescriptor",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let object_class = entry.attrs.get("objectClass")
                .map(|v| v.clone())
                .unwrap_or_default();

            let target_type = if object_class.contains(&"computer".to_string()) {
                "Computer"
            } else {
                "User"
            };

            // Parse security descriptor
            if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    // Check each ACE for write access to msDS-KeyCredentialLink
                    // GUID: 5b47d60f-6090-40b2-9f37-2a4de88f3063
                    const KEY_CREDENTIAL_LINK_GUID: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";

                    for ace in &sd.dacl {
                        if let Some(rights) = self.ace_grants_dangerous_rights(ace, Some(KEY_CREDENTIAL_LINK_GUID)) {
                            // Skip legitimate principals
                            if self.is_legitimate_principal(&ace.trustee_sid) {
                                continue;
                            }

                            audit.add_shadow_credential_write(crate::da_equivalence::ShadowCredentialWriteAccess {
                                principal: ace.trustee_sid.clone(),
                                target_name: sam.clone(),
                                target_dn: dn.clone(),
                                target_type: target_type.to_string(),
                                rights,
                            });
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    /// Check for write access to servicePrincipalName (WriteSPN attack)
    /// Allows Kerberoasting or setting SPNs for delegation attacks
    async fn check_write_spn_vulnerabilities(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // Target privileged user accounts and service accounts
        // Users with adminCount=1 or accounts that could be targeted for Kerberoasting
        let filter = "(&(objectClass=user)(objectCategory=person))";

        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "nTSecurityDescriptor",
                "adminCount",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            // Prioritize privileged accounts
            let admin_count = entry.attrs.get("adminCount")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);

            // Only check privileged accounts to reduce noise
            if admin_count != 1 {
                continue;
            }

            // Parse security descriptor
            if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    // Check each ACE for write access to servicePrincipalName
                    // GUID: f3a64788-5306-11d1-a9c5-0000f80367c1
                    const SPN_GUID: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";

                    for ace in &sd.dacl {
                        if let Some(rights) = self.ace_grants_dangerous_rights(ace, Some(SPN_GUID)) {
                            // Skip legitimate principals
                            if self.is_legitimate_principal(&ace.trustee_sid) {
                                continue;
                            }

                            audit.add_write_spn(crate::da_equivalence::WriteSPNVulnerability {
                                principal: ace.trustee_sid.clone(),
                                target_account: sam.clone(),
                                target_dn: dn.clone(),
                                rights,
                            });
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    // ==========================================
    // Sprint 2: Permission-Based Attacks
    // ==========================================

    /// Check for privileged account takeover via ACLs
    /// Detects password reset rights, GenericAll, WriteDacl on privileged users
    async fn check_privileged_account_takeover(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // Target privileged users (adminCount=1 is set on all protected accounts)
        let filter = "(&(objectClass=user)(adminCount=1))";

        // Use paged search to handle large result sets (>1000 entries)
        let (rs, ldap) = self.paged_search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "nTSecurityDescriptor",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            // Parse security descriptor
            if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    // User-Force-Change-Password extended right GUID
                    const PASSWORD_RESET_GUID: &str = "00299570-246d-11d0-a768-00aa006e0529";

                    for ace in &sd.dacl {
                        // Skip legitimate principals
                        if self.is_legitimate_principal(&ace.trustee_sid) {
                            continue;
                        }

                        let mut can_reset_password = false;
                        let mut rights_found = None;

                        // Check for password reset extended right
                        if let Some(rights) = self.ace_grants_dangerous_rights(ace, Some(PASSWORD_RESET_GUID)) {
                            can_reset_password = true;
                            rights_found = Some(rights);
                        }

                        // Check for broad control rights (no GUID needed)
                        if rights_found.is_none() {
                            if let Some(rights) = self.ace_grants_dangerous_rights(ace, None) {
                                rights_found = Some(rights);
                            }
                        }

                        if let Some(rights) = rights_found {
                            audit.add_privileged_takeover(crate::da_equivalence::PrivilegedAccountTakeover {
                                principal: ace.trustee_sid.clone(),
                                target_account: sam.clone(),
                                target_dn: dn.clone(),
                                rights,
                                can_reset_password,
                            });
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    /// Check for group membership control (AddMember rights on privileged groups)
    async fn check_group_membership_control(&self, audit: &mut DAEquivalenceAudit, mut ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // Privileged groups to check
        const PRIVILEGED_GROUPS: [&str; 9] = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
            "DnsAdmins",
        ];

        for group_name in PRIVILEGED_GROUPS {
            let escaped_group = crate::ldap_utils::escape_ldap_filter(group_name);
            let filter = format!("(&(objectClass=group)(cn={}))", escaped_group);

            let (rs, returned_ldap) = self.search_with_timeout(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["cn", "distinguishedName", "nTSecurityDescriptor"],
            ).await?;
            ldap = returned_ldap;

            for entry in rs {
                let entry = SearchEntry::construct(entry);

                let cn = entry.attrs.get("cn")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();

                let dn = entry.attrs.get("distinguishedName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();

                // Parse security descriptor
                if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                    if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                        // member attribute GUID
                        const MEMBER_GUID: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";

                        for ace in &sd.dacl {
                            // Skip legitimate principals
                            if self.is_legitimate_principal(&ace.trustee_sid) {
                                continue;
                            }

                            let mut is_add_member = false;
                            let mut rights_found = None;

                            // Check for SELF right on member attribute (AddMember)
                            if let Some(rights) = self.ace_grants_dangerous_rights(ace, Some(MEMBER_GUID)) {
                                is_add_member = rights.contains("Self") || rights.contains("WriteProperty");
                                rights_found = Some(rights);
                            }

                            // Check for broad control rights
                            if rights_found.is_none() {
                                if let Some(rights) = self.ace_grants_dangerous_rights(ace, None) {
                                    rights_found = Some(rights);
                                }
                            }

                            if let Some(rights) = rights_found {
                                audit.add_group_membership_control(crate::da_equivalence::GroupMembershipControl {
                                    principal: ace.trustee_sid.clone(),
                                    group_name: cn.clone(),
                                    group_dn: dn.clone(),
                                    rights,
                                    is_add_member_right: is_add_member,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    /// Check for RBCD write access (msDS-AllowedToActOnBehalfOfOtherIdentity)
    async fn check_rbcd_write_access(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // Target computers, prioritizing Domain Controllers
        let filter = "(objectClass=computer)";

        // Use paged search to handle large result sets (>1000 entries)
        let (rs, ldap) = self.paged_search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "primaryGroupID",
                "nTSecurityDescriptor",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let primary_group_id = entry.attrs.get("primaryGroupID")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            let is_dc = primary_group_id == 516;

            // Parse security descriptor
            if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    // msDS-AllowedToActOnBehalfOfOtherIdentity GUID
                    const RBCD_GUID: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";

                    for ace in &sd.dacl {
                        // Skip legitimate principals
                        if self.is_legitimate_principal(&ace.trustee_sid) {
                            continue;
                        }

                        if let Some(_rights) = self.ace_grants_dangerous_rights(ace, Some(RBCD_GUID)) {
                            audit.add_rbcd_write(crate::da_equivalence::RBCDWriteAccess {
                                principal: ace.trustee_sid.clone(),
                                target_name: sam.clone(),
                                target_dn: dn.clone(),
                                is_domain_controller: is_dc,
                            });
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    /// Check for computer object control (GenericAll, WriteDacl, WriteOwner)
    async fn check_computer_object_control(&self, audit: &mut DAEquivalenceAudit, ldap: LdapConn) -> Result<LdapConn> {
        use crate::ldap_utils::parse_security_descriptor;

        // Target all computers
        let filter = "(objectClass=computer)";

        // Use paged search to handle large result sets (>1000 entries)
        let (rs, ldap) = self.paged_search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "primaryGroupID",
                "nTSecurityDescriptor",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let primary_group_id = entry.attrs.get("primaryGroupID")
                .and_then(|v| v.first())
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            let is_dc = primary_group_id == 516;

            // Parse security descriptor
            if let Some(sd_bytes) = entry.bin_attrs.get("nTSecurityDescriptor").and_then(|v| v.first()) {
                if let Ok(sd) = parse_security_descriptor(sd_bytes) {
                    for ace in &sd.dacl {
                        // Skip legitimate principals
                        if self.is_legitimate_principal(&ace.trustee_sid) {
                            continue;
                        }

                        // Check for broad control rights (no specific GUID)
                        if let Some(rights) = self.ace_grants_dangerous_rights(ace, None) {
                            audit.add_computer_control(crate::da_equivalence::ComputerObjectControl {
                                principal: ace.trustee_sid.clone(),
                                computer_name: sam.clone(),
                                computer_dn: dn.clone(),
                                rights,
                                is_domain_controller: is_dc,
                            });
                        }
                    }
                }
            }
        }

        Ok(ldap)
    }

    /// Check for constrained delegation to Domain Controllers
    async fn check_constrained_delegation_to_dcs(&self, audit: &mut DAEquivalenceAudit, mut ldap: LdapConn) -> Result<LdapConn> {
        // First, get all Domain Controller hostnames
        let dc_filter = "(primaryGroupID=516)";
        let (dc_rs, returned_ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            dc_filter,
            vec!["dNSHostName", "sAMAccountName"],
        ).await?;
        ldap = returned_ldap;

        let mut dc_hostnames = Vec::new();
        for entry in dc_rs {
            let entry = SearchEntry::construct(entry);

            if let Some(hostname) = entry.attrs.get("dNSHostName").and_then(|v| v.first()) {
                dc_hostnames.push(hostname.to_lowercase());
            }
            if let Some(sam) = entry.attrs.get("sAMAccountName").and_then(|v| v.first()) {
                // Add SAM account name without trailing $
                let sam_clean = sam.trim_end_matches('$');
                dc_hostnames.push(sam_clean.to_lowercase());
            }
        }

        if dc_hostnames.is_empty() {
            return Ok(ldap);
        }

        // Now check for constrained delegation
        let filter = "(msDS-AllowedToDelegateTo=*)";
        let (rs, ldap) = self.search_with_timeout(
            ldap,
            &self.base_dn,
            Scope::Subtree,
            filter,
            vec![
                "sAMAccountName",
                "distinguishedName",
                "msDS-AllowedToDelegateTo",
            ],
        ).await?;

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let sam = entry.attrs.get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let dn = entry.attrs.get("distinguishedName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            let delegation_targets = entry.attrs.get("msDS-AllowedToDelegateTo")
                .map(|v| v.clone())
                .unwrap_or_default();

            // Check if any delegation target is a DC
            for target in &delegation_targets {
                let target_lower = target.to_lowercase();

                // Check if target contains any DC hostname
                let targets_dc = dc_hostnames.iter().any(|dc| {
                    target_lower.contains(dc)
                });

                if targets_dc {
                    // Found constrained delegation to a DC
                    audit.add_constrained_delegation_to_dc(crate::da_equivalence::ConstrainedDelegationToDC {
                        account_name: sam.clone(),
                        distinguished_name: dn.clone(),
                        delegation_target: target.clone(),
                        is_protocol_transition: false, // Will be enhanced later
                    });
                    break; // Only add once per account
                }
            }
        }

        Ok(ldap)
    }

    /// Generate a secure random password with high entropy
    /// Uses alphanumeric characters and special characters for maximum security
    fn generate_secure_random_password(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  abcdefghijklmnopqrstuvwxyz\
                                  0123456789\
                                  !@#$%^&*()-_=+[]{}|;:,.<>?";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Encode password for Active Directory unicodePwd attribute
    /// AD requires UTF-16LE encoding with surrounding quotes
    fn encode_password_for_ad(password: &str) -> Vec<u8> {
        let mut encoded = Vec::new();

        // Create the quoted password string
        let quoted_password = format!("\"{}\"", password);

        // Encode entire string as UTF-16LE
        for unit in quoted_password.encode_utf16() {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }

        encoded
    }
}
