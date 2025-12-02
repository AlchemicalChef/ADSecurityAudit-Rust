// Allow unused code - error types for future error handling migration
#![allow(dead_code)]

//! Error handling module
//!
//! This module provides structured error types for the IRP application,
//! replacing silent failures and ensuring proper error propagation.

use thiserror::Error;

/// Main error type for Active Directory operations
#[derive(Error, Debug)]
pub enum ADError {
    /// LDAP connection error
    #[error("LDAP connection failed: {0}")]
    ConnectionError(String),

    /// LDAP query/search error
    #[error("LDAP query failed: {0}")]
    QueryError(String),

    /// Authentication error
    #[error("Authentication failed: {0}")]
    AuthError(String),

    /// Input validation error
    #[error("Invalid input: {0}")]
    ValidationError(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Parse error
    #[error("Failed to parse data: {0}")]
    ParseError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<ldap3::LdapError> for ADError {
    fn from(err: ldap3::LdapError) -> Self {
        match err {
            ldap3::LdapError::LdapResult { result } => {
                match result.rc {
                    // 49 = Invalid credentials
                    49 => ADError::AuthError(format!(
                        "Invalid credentials: {}",
                        result.text
                    )),
                    // 32 = No such object
                    32 => ADError::NotFound(format!(
                        "Object not found: {}",
                        result.text
                    )),
                    // 50 = Insufficient access rights
                    50 => ADError::PermissionDenied(format!(
                        "Insufficient access rights: {}",
                        result.text
                    )),
                    // 51 = Busy
                    51 => ADError::Timeout(format!(
                        "Server is busy: {}",
                        result.text
                    )),
                    // 52 = Unavailable
                    52 => ADError::ConnectionError(format!(
                        "Server unavailable: {}",
                        result.text
                    )),
                    // 53 = Unwilling to perform
                    53 => ADError::PermissionDenied(format!(
                        "Server unwilling to perform operation: {}",
                        result.text
                    )),
                    // Other errors
                    _ => ADError::QueryError(format!(
                        "LDAP error code {}: {}",
                        result.rc, result.text
                    )),
                }
            }
            // Connection-related errors
            ldap3::LdapError::EndOfStream => {
                ADError::ConnectionError("Connection closed unexpectedly".to_string())
            }
            ldap3::LdapError::Io { source } => {
                ADError::ConnectionError(format!("I/O error: {}", source))
            }
            ldap3::LdapError::Timeout { elapsed: _ } => {
                ADError::Timeout("LDAP operation timed out".to_string())
            }
            // Generic fallback
            _ => ADError::QueryError(format!("LDAP error: {}", err)),
        }
    }
}

impl From<anyhow::Error> for ADError {
    fn from(err: anyhow::Error) -> Self {
        ADError::InternalError(err.to_string())
    }
}

impl From<std::io::Error> for ADError {
    fn from(err: std::io::Error) -> Self {
        ADError::ConnectionError(format!("I/O error: {}", err))
    }
}

impl From<serde_json::Error> for ADError {
    fn from(err: serde_json::Error) -> Self {
        ADError::ParseError(format!("JSON parse error: {}", err))
    }
}

/// Result type alias for AD operations
pub type Result<T> = std::result::Result<T, ADError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ADError::ConnectionError("test".to_string());
        assert_eq!(err.to_string(), "LDAP connection failed: test");

        let err = ADError::AuthError("bad password".to_string());
        assert_eq!(err.to_string(), "Authentication failed: bad password");

        let err = ADError::NotFound("user not found".to_string());
        assert_eq!(err.to_string(), "Resource not found: user not found");
    }

    #[test]
    fn test_error_variants() {
        let _err = ADError::ConnectionError("test".to_string());
        let _err = ADError::QueryError("test".to_string());
        let _err = ADError::AuthError("test".to_string());
        let _err = ADError::ValidationError("test".to_string());
        let _err = ADError::NotFound("test".to_string());
        let _err = ADError::PermissionDenied("test".to_string());
        let _err = ADError::Timeout("test".to_string());
        let _err = ADError::ParseError("test".to_string());
        let _err = ADError::InternalError("test".to_string());
        let _err = ADError::RateLimitExceeded("test".to_string());
        let _err = ADError::ConfigError("test".to_string());
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let ad_err: ADError = io_err.into();
        assert!(matches!(ad_err, ADError::ConnectionError(_)));
    }

    #[test]
    fn test_anyhow_error_conversion() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let ad_err: ADError = anyhow_err.into();
        assert!(matches!(ad_err, ADError::InternalError(_)));
    }
}
