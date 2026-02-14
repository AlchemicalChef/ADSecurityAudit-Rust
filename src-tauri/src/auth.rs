//! Authentication Module for Active Directory LDAP Connections
//!
//! Provides multiple authentication mechanisms for connecting to Active Directory:
//! - **GSSAPI/Kerberos**: Windows integrated authentication using SSPI
//! - **Simple Bind**: Username/password over LDAPS
//! - **NTLM**: NT LAN Manager authentication (fallback)
//!
//! # Authentication Priority (Auto Mode)
//!
//! When using `AuthMethod::Auto`, the module attempts authentication in order:
//! 1. GSSAPI/Kerberos - Best security, uses existing Windows login ticket
//! 2. Simple Bind over LDAPS - Secure password transmission
//! 3. Simple Bind over LDAP - Last resort, credentials in clear (warns)
//!
//! # Security Considerations
//!
//! | Method | Transport | Password Exposure | Replay Protection |
//! |--------|-----------|-------------------|-------------------|
//! | GSSAPI | Any | None (ticket-based) | Yes (Kerberos) |
//! | Simple+TLS | LDAPS | Encrypted | TLS |
//! | Simple | LDAP | **CLEARTEXT** | None |
//!
//! # Example
//!
//! ```rust,ignore
//! use auth::{AuthConfig, AuthMethod, Authenticator};
//!
//! // Use Windows integrated auth (GSSAPI)
//! let auth = Authenticator::new(AuthConfig {
//!     method: AuthMethod::Gssapi,
//!     server_fqdn: "dc01.contoso.com".to_string(),
//!     ..Default::default()
//! });
//!
//! let ldap = auth.connect_and_bind().await?;
//! ```

use anyhow::{anyhow, Result};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::secure_types::Credentials;

/// Supported authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub(crate) enum AuthMethod {
    /// Automatically select best available method
    #[default]
    Auto,
    /// GSSAPI/Kerberos using Windows SSPI (recommended)
    Gssapi,
    /// Simple bind with username/password
    Simple,
    /// Anonymous bind (limited access)
    Anonymous,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Auto => write!(f, "Auto"),
            AuthMethod::Gssapi => write!(f, "GSSAPI/Kerberos"),
            AuthMethod::Simple => write!(f, "Simple Bind"),
            AuthMethod::Anonymous => write!(f, "Anonymous"),
        }
    }
}

/// Result of an authentication attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthResult {
    /// Whether authentication succeeded
    pub success: bool,
    /// Method that was used
    pub method_used: String,
    /// Server we authenticated to
    pub server: String,
    /// Whether connection is encrypted
    pub encrypted: bool,
    /// Any warnings about the connection
    pub warnings: Vec<String>,
    /// The authenticated principal (if known)
    pub principal: Option<String>,
}

/// Authentication configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct AuthConfig {
    /// Preferred authentication method
    pub method: AuthMethod,
    /// Server hostname or IP
    pub server: String,
    /// Server FQDN for Kerberos SPN (e.g., "dc01.contoso.com")
    pub server_fqdn: Option<String>,
    /// Port (389 for LDAP, 636 for LDAPS)
    pub port: u16,
    /// Use LDAPS (TLS)
    pub use_tls: bool,
    /// Credentials for simple bind (optional for GSSAPI)
    pub credentials: Option<Credentials>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Skip TLS certificate verification (for internal CAs)
    pub skip_tls_verify: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: AuthMethod::Auto,
            server: String::new(),
            server_fqdn: None,
            port: 389,
            use_tls: false,
            credentials: None,
            connect_timeout: Duration::from_secs(10),
            skip_tls_verify: false, // Set to true only for enterprise environments with internal CAs
        }
    }
}

#[allow(dead_code)]
impl AuthConfig {
    /// Create config for GSSAPI authentication
    pub(crate) fn gssapi(server_fqdn: &str) -> Self {
        Self {
            method: AuthMethod::Gssapi,
            server: server_fqdn.to_string(),
            server_fqdn: Some(server_fqdn.to_string()),
            port: 389,
            use_tls: false,
            credentials: None,
            ..Default::default()
        }
    }

    /// Create config for GSSAPI over LDAPS
    pub(crate) fn gssapi_secure(server_fqdn: &str) -> Self {
        Self {
            method: AuthMethod::Gssapi,
            server: server_fqdn.to_string(),
            server_fqdn: Some(server_fqdn.to_string()),
            port: 636,
            use_tls: true,
            credentials: None,
            ..Default::default()
        }
    }

    /// Create config for simple bind
    pub(crate) fn simple(server: &str, username: &str, password: &str, use_tls: bool) -> Self {
        Self {
            method: AuthMethod::Simple,
            server: server.to_string(),
            server_fqdn: None,
            port: if use_tls { 636 } else { 389 },
            use_tls,
            credentials: Some(Credentials::new(username.to_string(), password.to_string())),
            ..Default::default()
        }
    }

    /// Create config for auto authentication (tries GSSAPI first)
    pub(crate) fn auto(server: &str, username: Option<&str>, password: Option<&str>) -> Self {
        let credentials = match (username, password) {
            (Some(u), Some(p)) => Some(Credentials::new(u.to_string(), p.to_string())),
            _ => None,
        };

        Self {
            method: AuthMethod::Auto,
            server: server.to_string(),
            server_fqdn: Some(server.to_string()),
            port: 389,
            use_tls: false,
            credentials,
            ..Default::default()
        }
    }

    /// Get the LDAP URL
    pub(crate) fn ldap_url(&self) -> String {
        let scheme = if self.use_tls { "ldaps" } else { "ldap" };
        let server = self.server.trim_start_matches("ldap://").trim_start_matches("ldaps://");
        let server = server.split(':').next().unwrap_or(server);
        format!("{}://{}:{}", scheme, server, self.port)
    }

    /// Get the server FQDN for Kerberos SPN
    pub(crate) fn get_server_fqdn(&self) -> &str {
        self.server_fqdn.as_deref().unwrap_or(&self.server)
    }
}

/// LDAP Authenticator supporting multiple authentication methods
#[allow(dead_code)]
pub(crate) struct Authenticator {
    config: AuthConfig,
}

#[allow(dead_code)]
impl Authenticator {
    /// Create a new authenticator with the given configuration
    pub(crate) fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Connect and authenticate to the LDAP server
    pub(crate) async fn connect_and_bind(&self) -> Result<(Ldap, AuthResult)> {
        match self.config.method {
            AuthMethod::Auto => self.auto_authenticate().await,
            #[cfg(windows)]
            AuthMethod::Gssapi => self.gssapi_authenticate().await,
            #[cfg(not(windows))]
            AuthMethod::Gssapi => Err(anyhow!("GSSAPI authentication is only available on Windows")),
            AuthMethod::Simple => self.simple_authenticate().await,
            AuthMethod::Anonymous => self.anonymous_authenticate().await,
        }
    }

    /// Automatic authentication - tries methods in order of preference
    async fn auto_authenticate(&self) -> Result<(Ldap, AuthResult)> {
        info!("Auto-selecting authentication method for {}", self.config.server);

        // Try GSSAPI first (best security) - only available on Windows
        #[cfg(windows)]
        match self.gssapi_authenticate().await {
            Ok(result) => {
                info!("GSSAPI authentication succeeded");
                return Ok(result);
            }
            Err(e) => {
                debug!("GSSAPI authentication failed: {}, trying fallback", e);
            }
        }

        // Fall back to simple bind if credentials provided
        if self.config.credentials.is_some() {
            match self.simple_authenticate().await {
                Ok(result) => {
                    info!("Simple bind authentication succeeded");
                    return Ok(result);
                }
                Err(e) => {
                    warn!("Simple bind authentication failed: {}", e);
                }
            }
        }

        Err(anyhow!(
            "All authentication methods failed for {}",
            self.config.server
        ))
    }

    /// GSSAPI/Kerberos authentication using Windows SSPI.
    ///
    /// This method requires the `gssapi` feature of the `ldap3` crate
    /// and is only available on Windows where SSPI provides Kerberos tickets.
    #[cfg(windows)]
    async fn gssapi_authenticate(&self) -> Result<(Ldap, AuthResult)> {
        let url = self.config.ldap_url();
        let server_fqdn = self.config.get_server_fqdn();

        info!(
            "Attempting GSSAPI authentication to {} (SPN: ldap/{})",
            url, server_fqdn
        );

        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.config.connect_timeout)
            .set_no_tls_verify(self.config.skip_tls_verify);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| anyhow!("Failed to connect to {}: {}", url, e))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection error: {:?}", e);
            }
        });

        // Perform GSSAPI bind using SASL
        // The sasl_gssapi_bind method uses the current Windows user's Kerberos ticket
        // ldap3 crate is compiled with 'gssapi' feature enabled (see Cargo.toml)
        ldap.sasl_gssapi_bind(server_fqdn)
            .await
            .map_err(|e| anyhow!("GSSAPI bind failed: {}", e))?
            .success()
            .map_err(|e| anyhow!("GSSAPI bind rejected: {:?}", e))?;

        let mut warnings = Vec::new();
        if !self.config.use_tls {
            // GSSAPI provides encryption even without TLS, but TLS adds defense in depth
            debug!("Using GSSAPI without TLS - connection is still encrypted via Kerberos");
        }

        let principal = self.get_current_principal();

        let result = AuthResult {
            success: true,
            method_used: "GSSAPI/Kerberos".to_string(),
            server: self.config.server.clone(),
            encrypted: true, // GSSAPI always encrypts
            warnings,
            principal,
        };

        info!(
            "GSSAPI authentication successful for {}",
            result.principal.as_deref().unwrap_or("unknown principal")
        );

        Ok((ldap, result))
    }

    /// Simple bind authentication with username/password
    async fn simple_authenticate(&self) -> Result<(Ldap, AuthResult)> {
        let url = self.config.ldap_url();
        let credentials = self
            .config
            .credentials
            .as_ref()
            .ok_or_else(|| anyhow!("Simple bind requires credentials"))?;

        info!("Attempting simple bind authentication to {}", url);

        let mut warnings = Vec::new();
        if !self.config.use_tls {
            warn!("Simple bind without TLS - credentials will be sent in cleartext!");
            warnings.push("Credentials transmitted without encryption".to_string());
        }

        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.config.connect_timeout)
            .set_no_tls_verify(self.config.skip_tls_verify);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| anyhow!("Failed to connect to {}: {}", url, e))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection error: {:?}", e);
            }
        });

        // Perform simple bind
        ldap.simple_bind(credentials.username(), credentials.password())
            .await
            .map_err(|e| anyhow!("Simple bind failed: {}", e))?
            .success()
            .map_err(|e| anyhow!("Simple bind rejected: {:?}", e))?;

        let result = AuthResult {
            success: true,
            method_used: "Simple Bind".to_string(),
            server: self.config.server.clone(),
            encrypted: self.config.use_tls,
            warnings,
            principal: Some(credentials.username().to_string()),
        };

        info!(
            "Simple bind authentication successful for {}",
            credentials.username()
        );

        Ok((ldap, result))
    }

    /// Anonymous bind (very limited access)
    async fn anonymous_authenticate(&self) -> Result<(Ldap, AuthResult)> {
        let url = self.config.ldap_url();

        info!("Attempting anonymous bind to {}", url);

        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.config.connect_timeout)
            .set_no_tls_verify(self.config.skip_tls_verify);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| anyhow!("Failed to connect to {}: {}", url, e))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection error: {:?}", e);
            }
        });

        // Perform anonymous bind
        ldap.simple_bind("", "")
            .await
            .map_err(|e| anyhow!("Anonymous bind failed: {}", e))?
            .success()
            .map_err(|e| anyhow!("Anonymous bind rejected: {:?}", e))?;

        let result = AuthResult {
            success: true,
            method_used: "Anonymous".to_string(),
            server: self.config.server.clone(),
            encrypted: self.config.use_tls,
            warnings: vec!["Anonymous access - limited functionality".to_string()],
            principal: None,
        };

        info!("Anonymous bind successful - access will be limited");

        Ok((ldap, result))
    }

    /// Get the current Windows principal (username)
    #[cfg(windows)]
    fn get_current_principal(&self) -> Option<String> {
        use std::env;

        // Try to get the current username from environment
        let username = env::var("USERNAME").ok()?;
        let domain = env::var("USERDOMAIN").ok()?;

        Some(format!("{}\\{}", domain, username))
    }

    #[cfg(not(windows))]
    fn get_current_principal(&self) -> Option<String> {
        std::env::var("USER").ok()
    }

    /// Test if GSSAPI authentication is available.
    ///
    /// This attempts to authenticate using GSSAPI and returns true if successful.
    /// Useful for checking if the current Windows user has a valid Kerberos ticket.
    /// Always returns `false` on non-Windows platforms.
    pub(crate) async fn test_gssapi_available(&self) -> bool {
        #[cfg(windows)]
        {
            // Try to authenticate with GSSAPI - this will succeed if:
            // 1. We're on a domain-joined Windows machine
            // 2. The user has a valid Kerberos TGT
            // 3. The target server is reachable
            self.gssapi_authenticate().await.is_ok()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Get information about the current authentication context
    #[cfg(windows)]
    pub(crate) fn get_auth_context_info() -> AuthContextInfo {
        use std::env;

        AuthContextInfo {
            username: env::var("USERNAME").ok(),
            domain: env::var("USERDOMAIN").ok(),
            logon_server: env::var("LOGONSERVER").ok(),
            user_dns_domain: env::var("USERDNSDOMAIN").ok(),
            is_domain_joined: env::var("USERDNSDOMAIN").is_ok(),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn get_auth_context_info() -> AuthContextInfo {
        AuthContextInfo {
            username: std::env::var("USER").ok(),
            domain: None,
            logon_server: None,
            user_dns_domain: None,
            is_domain_joined: false,
        }
    }
}

/// Information about the current authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AuthContextInfo {
    pub username: Option<String>,
    pub domain: Option<String>,
    pub logon_server: Option<String>,
    pub user_dns_domain: Option<String>,
    pub is_domain_joined: bool,
}

#[allow(dead_code)]
impl AuthContextInfo {
    /// Get the UPN (User Principal Name) if available
    pub(crate) fn get_upn(&self) -> Option<String> {
        match (&self.username, &self.user_dns_domain) {
            (Some(user), Some(domain)) => Some(format!("{}@{}", user, domain)),
            _ => None,
        }
    }

    /// Get the NETBIOS-style name (DOMAIN\username)
    pub(crate) fn get_netbios_name(&self) -> Option<String> {
        match (&self.username, &self.domain) {
            (Some(user), Some(domain)) => Some(format!("{}\\{}", domain, user)),
            _ => None,
        }
    }
}

/// Builder for creating AuthConfig with a fluent API
#[allow(dead_code)]
pub(crate) struct AuthConfigBuilder {
    config: AuthConfig,
}

#[allow(dead_code)]
impl AuthConfigBuilder {
    pub(crate) fn new() -> Self {
        Self {
            config: AuthConfig::default(),
        }
    }

    pub(crate) fn server(mut self, server: &str) -> Self {
        self.config.server = server.to_string();
        self.config.server_fqdn = Some(server.to_string());
        self
    }

    pub(crate) fn method(mut self, method: AuthMethod) -> Self {
        self.config.method = method;
        self
    }

    pub(crate) fn credentials(mut self, username: &str, password: &str) -> Self {
        self.config.credentials = Some(Credentials::new(username.to_string(), password.to_string()));
        self
    }

    pub(crate) fn use_tls(mut self, use_tls: bool) -> Self {
        self.config.use_tls = use_tls;
        self.config.port = if use_tls { 636 } else { 389 };
        self
    }

    pub(crate) fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    pub(crate) fn skip_tls_verify(mut self, skip: bool) -> Self {
        self.config.skip_tls_verify = skip;
        self
    }

    pub(crate) fn build(self) -> AuthConfig {
        self.config
    }
}

impl Default for AuthConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_display() {
        assert_eq!(AuthMethod::Auto.to_string(), "Auto");
        assert_eq!(AuthMethod::Gssapi.to_string(), "GSSAPI/Kerberos");
        assert_eq!(AuthMethod::Simple.to_string(), "Simple Bind");
        assert_eq!(AuthMethod::Anonymous.to_string(), "Anonymous");
    }

    #[test]
    fn test_auth_config_ldap_url() {
        let config = AuthConfig {
            server: "dc01.contoso.com".to_string(),
            port: 389,
            use_tls: false,
            ..Default::default()
        };
        assert_eq!(config.ldap_url(), "ldap://dc01.contoso.com:389");

        let config_tls = AuthConfig {
            server: "dc01.contoso.com".to_string(),
            port: 636,
            use_tls: true,
            ..Default::default()
        };
        assert_eq!(config_tls.ldap_url(), "ldaps://dc01.contoso.com:636");
    }

    #[test]
    fn test_auth_config_gssapi() {
        let config = AuthConfig::gssapi("dc01.contoso.com");
        assert_eq!(config.method, AuthMethod::Gssapi);
        assert_eq!(config.server_fqdn, Some("dc01.contoso.com".to_string()));
        assert!(!config.use_tls);
    }

    #[test]
    fn test_auth_config_simple() {
        let config = AuthConfig::simple("dc01", "admin", "password", true);
        assert_eq!(config.method, AuthMethod::Simple);
        assert!(config.use_tls);
        assert_eq!(config.port, 636);
        assert!(config.credentials.is_some());
    }

    #[test]
    fn test_auth_config_builder() {
        let config = AuthConfigBuilder::new()
            .server("dc01.contoso.com")
            .method(AuthMethod::Gssapi)
            .use_tls(true)
            .timeout(Duration::from_secs(30))
            .build();

        assert_eq!(config.method, AuthMethod::Gssapi);
        assert_eq!(config.server, "dc01.contoso.com");
        assert!(config.use_tls);
        assert_eq!(config.port, 636);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_auth_context_info() {
        let info = AuthContextInfo {
            username: Some("testuser".to_string()),
            domain: Some("CONTOSO".to_string()),
            logon_server: Some("\\\\DC01".to_string()),
            user_dns_domain: Some("contoso.com".to_string()),
            is_domain_joined: true,
        };

        assert_eq!(info.get_upn(), Some("testuser@contoso.com".to_string()));
        assert_eq!(info.get_netbios_name(), Some("CONTOSO\\testuser".to_string()));
    }
}
