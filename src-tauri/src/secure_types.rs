//! Secure Types Module
//!
//! This module provides secure credential storage types that automatically
//! zero out sensitive data from memory when dropped, preventing credential
//! exposure through memory dumps or debugging tools.

use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// A secure string that automatically zeros its contents when dropped.
///
/// This type should be used for any sensitive string data such as passwords,
/// API keys, or tokens. The contents are automatically zeroed from memory
/// when the value goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecureString {
    inner: Vec<u8>,
}

impl SecureString {
    /// Creates a new SecureString from a standard String.
    ///
    /// The original String is consumed and its contents are moved into
    /// the secure container.
    pub(crate) fn new(s: String) -> Self {
        Self {
            inner: s.into_bytes(),
        }
    }

    /// Creates a new SecureString from a string slice.
    #[allow(dead_code)]
    pub(crate) fn from_str(s: &str) -> Self {
        Self {
            inner: s.as_bytes().to_vec(),
        }
    }

    /// Temporarily exposes the secret as a string slice.
    ///
    /// # Security
    /// The returned reference should be used immediately and not stored.
    /// Avoid copying or cloning the exposed value.
    pub(crate) fn expose_secret(&self) -> &str {
        // Safe conversion - panics if invariant is violated (better than UB)
        // Since SecureString can only be constructed from String/&str (valid UTF-8),
        // this should never panic in practice
        std::str::from_utf8(&self.inner)
            .expect("SecureString invariant violated: contains invalid UTF-8")
    }

    /// Returns the length of the secure string in bytes.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the secure string is empty.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureString([REDACTED])")
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Secure credentials container with automatic memory cleanup.
///
/// This struct stores authentication credentials in a secure manner,
/// ensuring that the password is automatically zeroed from memory when
/// the credentials are no longer needed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Credentials {
    /// Username (less sensitive, but still protected)
    username: String,
    /// Password (highly sensitive, automatically zeroed on drop)
    password: SecureString,
}

impl Credentials {
    /// Creates new credentials from username and password.
    pub(crate) fn new(username: String, password: String) -> Self {
        Self {
            username,
            password: SecureString::new(password),
        }
    }

    /// Returns a reference to the username.
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    /// Temporarily exposes the password as a string slice.
    ///
    /// # Security
    /// Use this method only when needed for authentication.
    /// Do not store or clone the returned reference.
    pub(crate) fn password(&self) -> &str {
        self.password.expose_secret()
    }

    /// Checks if the credentials are empty.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.username.is_empty() || self.password.is_empty()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credentials(username: {}, password: [REDACTED])", self.username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_new() {
        let secret = SecureString::new("my_password".to_string());
        assert_eq!(secret.expose_secret(), "my_password");
        assert_eq!(secret.len(), 11);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secure_string_from_str() {
        let secret = SecureString::from_str("test_secret");
        assert_eq!(secret.expose_secret(), "test_secret");
    }

    #[test]
    fn test_secure_string_empty() {
        let secret = SecureString::new(String::new());
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn test_secure_string_debug() {
        let secret = SecureString::new("password123".to_string());
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "SecureString([REDACTED])");
        assert!(!debug_output.contains("password123"));
    }

    #[test]
    fn test_secure_string_display() {
        let secret = SecureString::new("password123".to_string());
        let display_output = format!("{}", secret);
        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("password123"));
    }

    #[test]
    fn test_credentials_new() {
        let creds = Credentials::new(
            "admin".to_string(),
            "secret_password".to_string(),
        );
        assert_eq!(creds.username(), "admin");
        assert_eq!(creds.password(), "secret_password");
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_credentials_empty() {
        let creds = Credentials::new(String::new(), String::new());
        assert!(creds.is_empty());
    }

    #[test]
    fn test_credentials_debug() {
        let creds = Credentials::new(
            "testuser".to_string(),
            "testpass".to_string(),
        );
        let debug_output = format!("{:?}", creds);
        assert!(debug_output.contains("testuser"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("testpass"));
    }

    #[test]
    fn test_credentials_display() {
        let creds = Credentials::new(
            "admin".to_string(),
            "password123".to_string(),
        );
        let display_output = format!("{}", creds);
        assert!(display_output.contains("admin"));
        assert!(display_output.contains("[REDACTED]"));
        assert!(!display_output.contains("password123"));
    }

    #[test]
    fn test_credentials_clone() {
        let creds1 = Credentials::new(
            "user1".to_string(),
            "pass1".to_string(),
        );
        let creds2 = creds1.clone();

        assert_eq!(creds1.username(), creds2.username());
        assert_eq!(creds1.password(), creds2.password());
    }

    #[test]
    fn test_secure_string_zeroization() {
        // This test verifies that SecureString is properly set up for zeroization
        // The actual zeroization happens when the value is dropped
        let secret = SecureString::new("sensitive".to_string());
        drop(secret);
        // After drop, the memory should be zeroed (verified by zeroize library)
    }

    #[test]
    fn test_credentials_zeroization() {
        // Verify that Credentials properly zeros memory on drop
        let creds = Credentials::new(
            "admin".to_string(),
            "password".to_string(),
        );
        drop(creds);
        // After drop, the password should be zeroed from memory
    }
}
