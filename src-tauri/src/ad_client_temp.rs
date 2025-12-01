//! Active Directory Client Module
//!
//! Core LDAP client for interacting with Active Directory domain controllers.
//! Provides comprehensive audit and security analysis capabilities including:
//!
//! - **User Management**: Search, retrieve details, and disable user accounts
//! - **KRBTGT Security**: Analyze and rotate the Kerberos ticket-granting service account
//! - **AdminSDHolder Analysis**: Audit protected account permissions and ACLs
//! - **Privileged Account Enumeration**: Identify and analyze high-privilege accounts
//! - **Domain Security Audits**: GPO, delegation, trust, and permissions analysis
//! - **DA Equivalence Detection**: Find shadow admins and privilege escalation paths
//!
//! # Architecture
//!
//! The client uses synchronous LDAP operations wrapped in async timeout handlers
//! to prevent indefinite blocking. All operations use secure credential handling
//! with automatic memory zeroization.
//!
//! # Security Features
//!
//! - LDAP injection prevention via input escaping
//! - Secure credential storage with `zeroize` trait
//! - TLS/LDAPS support for encrypted communications
//! - Comprehensive audit logging for all security actions
//!
//! # Example
//!
//! ```rust,ignore
//! let client = ActiveDirectoryClient::new(
//!     "dc.example.com:636".to_string(),
//!     "admin@example.com".to_string(),
//!     "password".to_string(),
//!     "DC=example,DC=com".to_string(),
//! ).await?;
//!
//! // Search for users
//! let users = client.search_users("john").await?;
//!
//! // Analyze KRBTGT security
//! let analysis = client.analyze_krbtgt().await?;
//! ```

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
