//! LDAP Utilities
//!
//! This module provides RFC 4515 and RFC 4514 compliant escaping functions
//! to prevent LDAP injection attacks.

/// Escapes a string for safe use in an LDAP search filter (RFC 4515).
///
/// The following characters are escaped:
/// - `*` (asterisk) -> `\2a`
/// - `(` (left parenthesis) -> `\28`
/// - `)` (right parenthesis) -> `\29`
/// - `\` (backslash) -> `\5c`
/// - `\0` (NUL) -> `\00`
///
/// # Examples
///
/// ```
/// use crate::ldap_utils::escape_ldap_filter;
///
/// let safe = escape_ldap_filter("admin*");
/// assert_eq!(safe, "admin\\2a");
/// ```
pub(crate) fn escape_ldap_filter(input: &str) -> String {
    input.chars().fold(String::new(), |mut acc, c| {
        match c {
            '*' => acc.push_str("\\2a"),
            '(' => acc.push_str("\\28"),
            ')' => acc.push_str("\\29"),
            '\\' => acc.push_str("\\5c"),
            '\0' => acc.push_str("\\00"),
            _ => acc.push(c),
        }
        acc
    })
}

/// Escapes a string for safe use in an LDAP Distinguished Name (RFC 4514).
///
/// The following characters are escaped when they appear in a DN:
/// - `,` (comma)
/// - `+` (plus)
/// - `"` (quote)
/// - `\` (backslash)
/// - `<` (less than)
/// - `>` (greater than)
/// - `;` (semicolon)
/// - Leading or trailing spaces
/// - `#` at the beginning
///
/// # Examples
///
/// ```
/// use crate::ldap_utils::escape_ldap_dn;
///
/// let safe = escape_ldap_dn("Smith, John");
/// assert_eq!(safe, "Smith\\, John");
/// ```
#[allow(dead_code)]
pub(crate) fn escape_ldap_dn(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = String::with_capacity(input.len() * 2);
    let chars: Vec<char> = input.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == chars.len() - 1;

        match c {
            // Always escape these special characters
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                result.push('\\');
                result.push(c);
            }
            // Escape leading space
            ' ' if is_first => {
                result.push_str("\\ ");
            }
            // Escape trailing space
            ' ' if is_last => {
                result.push_str("\\ ");
            }
            // Escape # at the beginning
            '#' if is_first => {
                result.push_str("\\#");
            }
            // NUL byte
            '\0' => {
                result.push_str("\\00");
            }
            // Normal character
            _ => {
                result.push(c);
            }
        }
    }

    result
}

/// Validates that a string is a safe LDAP filter attribute value.
///
/// Returns `true` if the input contains only alphanumeric characters,
/// hyphens, underscores, and spaces. Returns `false` otherwise.
///
/// This can be used as a pre-validation step before escaping.
#[allow(dead_code)]
pub(crate) fn is_safe_ldap_value(input: &str) -> bool {
    input.chars().all(|c| {
        c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.'
    })
}

// ============================================================================
// Security Descriptor Parsing (MS-DTYP)
// ============================================================================

use serde::{Deserialize, Serialize};

/// Represents a Windows Security Descriptor (MS-DTYP 2.4.6)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecurityDescriptor {
    pub revision: u8,
    pub control_flags: u16,
    pub owner_sid: String,
    pub group_sid: String,
    pub dacl: Vec<AceEntry>,
    pub sacl: Vec<AceEntry>,
}

/// Represents an Access Control Entry (ACE) in a DACL or SACL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AceEntry {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub access_mask: u32,
    pub trustee_sid: String,
    pub object_guid: Option<String>,            // For Object ACEs
    pub inherited_object_guid: Option<String>,  // For Object ACEs
}

/// ACE Type constants (MS-DTYP 2.4.4.1)
pub(crate) mod ace_types {
    pub const ACCESS_ALLOWED: u8 = 0x00;
    pub const ACCESS_DENIED: u8 = 0x01;
    pub const SYSTEM_AUDIT: u8 = 0x02;
    pub const ACCESS_ALLOWED_OBJECT: u8 = 0x05;
    pub const ACCESS_DENIED_OBJECT: u8 = 0x06;
    pub const SYSTEM_AUDIT_OBJECT: u8 = 0x07;
}

/// Parse a Windows Security Descriptor from binary format
///
/// # Arguments
/// * `bytes` - The binary security descriptor data from nTSecurityDescriptor
///
/// # Returns
/// * `Result<SecurityDescriptor>` - Parsed security descriptor or error
///
/// # Format (MS-DTYP 2.4.6):
/// ```text
/// Offset  Size  Field
/// 0       1     Revision
/// 1       1     Sbz1 (padding)
/// 2       2     Control flags
/// 4       4     Owner SID offset
/// 8       4     Group SID offset
/// 12      4     SACL offset
/// 16      4     DACL offset
/// ```
pub(crate) fn parse_security_descriptor(bytes: &[u8]) -> Result<SecurityDescriptor, String> {
    if bytes.len() < 20 {
        return Err("Security descriptor too short (minimum 20 bytes)".to_string());
    }

    // Parse header (20 bytes)
    let revision = bytes[0];
    let control_flags = u16::from_le_bytes([bytes[2], bytes[3]]);
    let owner_offset = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let group_offset = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let sacl_offset = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let dacl_offset = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;

    // Parse Owner SID
    let owner_sid = if owner_offset > 0 && owner_offset < bytes.len() {
        sid_to_string(&bytes[owner_offset..])?
    } else {
        "S-1-0-0".to_string() // NULL SID
    };

    // Parse Group SID
    let group_sid = if group_offset > 0 && group_offset < bytes.len() {
        sid_to_string(&bytes[group_offset..])?
    } else {
        "S-1-0-0".to_string() // NULL SID
    };

    // Parse DACL
    let dacl = if dacl_offset > 0 && dacl_offset < bytes.len() {
        parse_acl(&bytes[dacl_offset..])?
    } else {
        Vec::new()
    };

    // Parse SACL
    let sacl = if sacl_offset > 0 && sacl_offset < bytes.len() {
        parse_acl(&bytes[sacl_offset..])?
    } else {
        Vec::new()
    };

    Ok(SecurityDescriptor {
        revision,
        control_flags,
        owner_sid,
        group_sid,
        dacl,
        sacl,
    })
}

/// Parse an Access Control List (ACL) from binary format
///
/// # Format (MS-DTYP 2.4.5):
/// ```text
/// Offset  Size  Field
/// 0       1     Revision
/// 1       1     Sbz1 (padding)
/// 2       2     ACL size
/// 4       2     ACE count
/// 6       2     Sbz2 (padding)
/// 8       ...   ACE entries
/// ```
fn parse_acl(bytes: &[u8]) -> Result<Vec<AceEntry>, String> {
    if bytes.len() < 8 {
        return Err("ACL too short (minimum 8 bytes)".to_string());
    }

    let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let mut aces = Vec::with_capacity(ace_count);
    let mut offset = 8; // Start after ACL header

    for _ in 0..ace_count {
        if offset + 4 > bytes.len() {
            break; // Not enough data for ACE header
        }

        let ace_type = bytes[offset];
        let ace_flags = bytes[offset + 1];
        let ace_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;

        if offset + ace_size > bytes.len() {
            break; // Not enough data for full ACE
        }

        let ace_data = &bytes[offset..offset + ace_size];

        match parse_ace(ace_type, ace_flags, ace_data) {
            Ok(ace) => aces.push(ace),
            Err(_) => {
                // Skip malformed ACEs
                offset += ace_size;
                continue;
            }
        }

        offset += ace_size;
    }

    Ok(aces)
}

/// Parse a single ACE from binary format
fn parse_ace(ace_type: u8, ace_flags: u8, data: &[u8]) -> Result<AceEntry, String> {
    if data.len() < 12 {
        return Err("ACE too short".to_string());
    }

    // Standard ACE header: type(1) + flags(1) + size(2) + access_mask(4) + SID(variable)
    let access_mask = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    // Check if this is an Object ACE (has GUIDs)
    let is_object_ace = matches!(
        ace_type,
        ace_types::ACCESS_ALLOWED_OBJECT
            | ace_types::ACCESS_DENIED_OBJECT
            | ace_types::SYSTEM_AUDIT_OBJECT
    );

    let (trustee_sid, object_guid, inherited_object_guid) = if is_object_ace {
        // Object ACE format: header(8) + flags(4) + [object_guid(16)] + [inherited_guid(16)] + SID
        let object_flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let mut sid_offset = 12;

        let obj_guid = if object_flags & 0x01 != 0 && data.len() >= sid_offset + 16 {
            let guid = guid_to_string(&data[sid_offset..sid_offset + 16])?;
            sid_offset += 16;
            Some(guid)
        } else {
            None
        };

        let inh_guid = if object_flags & 0x02 != 0 && data.len() >= sid_offset + 16 {
            let guid = guid_to_string(&data[sid_offset..sid_offset + 16])?;
            sid_offset += 16;
            Some(guid)
        } else {
            None
        };

        let sid = sid_to_string(&data[sid_offset..])?;
        (sid, obj_guid, inh_guid)
    } else {
        // Standard ACE: SID starts at offset 8
        let sid = sid_to_string(&data[8..])?;
        (sid, None, None)
    };

    Ok(AceEntry {
        ace_type,
        ace_flags,
        access_mask,
        trustee_sid,
        object_guid,
        inherited_object_guid,
    })
}

/// Convert a binary SID to string format (S-1-5-21-...)
///
/// # Format (MS-DTYP 2.4.2):
/// ```text
/// Offset  Size  Field
/// 0       1     Revision
/// 1       1     SubAuthorityCount
/// 2       6     IdentifierAuthority
/// 8       4*N   SubAuthorities (N = SubAuthorityCount)
/// ```
pub(crate) fn sid_to_string(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 8 {
        return Err("SID too short (minimum 8 bytes)".to_string());
    }

    let revision = bytes[0];
    let sub_auth_count = bytes[1] as usize;

    if bytes.len() < 8 + (sub_auth_count * 4) {
        return Err(format!(
            "SID data insufficient for {} sub-authorities",
            sub_auth_count
        ));
    }

    // Parse 48-bit identifier authority (big-endian)
    let id_auth = u64::from_be_bytes([
        0,
        0,
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
    ]);

    let mut sid = format!("S-{}-{}", revision, id_auth);

    // Parse sub-authorities (little-endian)
    for i in 0..sub_auth_count {
        let offset = 8 + (i * 4);
        let sub_auth = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        sid.push_str(&format!("-{}", sub_auth));
    }

    Ok(sid)
}

/// Parse a binary SID into its string representation, returning a placeholder on failure.
///
/// This is a convenience wrapper around [`sid_to_string`] for use cases where
/// a fallback value is acceptable (e.g., collecting SID histories).
pub(crate) fn parse_sid(bytes: &[u8]) -> String {
    sid_to_string(bytes).unwrap_or_else(|_| format!("(invalid SID: {} bytes)", bytes.len()))
}

/// Convert a binary GUID to string format
///
/// # Format (MS-DTYP 2.3.4.2):
/// ```text
/// GUID = Data1(4) + Data2(2) + Data3(2) + Data4(8)
/// String format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
/// ```
pub(crate) fn guid_to_string(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 16 {
        return Err("GUID too short (requires 16 bytes)".to_string());
    }

    // GUID components (little-endian for first 3 fields)
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);

    // Data4 is big-endian - use try_into for explicit bounds checking
    let data4: [u8; 8] = bytes[8..16]
        .try_into()
        .map_err(|_| "Invalid Data4 bytes for GUID".to_string())?;

    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        data1,
        data2,
        data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_ldap_filter_asterisk() {
        assert_eq!(escape_ldap_filter("admin*"), "admin\\2a");
        assert_eq!(escape_ldap_filter("*"), "\\2a");
    }

    #[test]
    fn test_escape_ldap_filter_parentheses() {
        assert_eq!(escape_ldap_filter("test(value)"), "test\\28value\\29");
        assert_eq!(escape_ldap_filter("("), "\\28");
        assert_eq!(escape_ldap_filter(")"), "\\29");
    }

    #[test]
    fn test_escape_ldap_filter_backslash() {
        assert_eq!(escape_ldap_filter("path\\to\\file"), "path\\5cto\\5cfile");
    }

    #[test]
    fn test_escape_ldap_filter_null() {
        let input = "test\0value";
        assert_eq!(escape_ldap_filter(input), "test\\00value");
    }

    #[test]
    fn test_escape_ldap_filter_combined() {
        let malicious = "*)(objectClass=*))(|(objectClass=*";
        let escaped = escape_ldap_filter(malicious);
        assert_eq!(
            escaped,
            "\\2a\\29\\28objectClass=\\2a\\29\\29\\28|\\28objectClass=\\2a"
        );
    }

    #[test]
    fn test_escape_ldap_filter_safe_input() {
        assert_eq!(escape_ldap_filter("admin123"), "admin123");
        assert_eq!(escape_ldap_filter("user@example.com"), "user@example.com");
    }

    #[test]
    fn test_escape_ldap_dn_comma() {
        assert_eq!(escape_ldap_dn("Smith, John"), "Smith\\, John");
    }

    #[test]
    fn test_escape_ldap_dn_special_chars() {
        assert_eq!(escape_ldap_dn("test+value"), "test\\+value");
        assert_eq!(escape_ldap_dn("\"quoted\""), "\\\"quoted\\\"");
        assert_eq!(escape_ldap_dn("<value>"), "\\<value\\>");
    }

    #[test]
    fn test_escape_ldap_dn_leading_space() {
        assert_eq!(escape_ldap_dn(" leading"), "\\ leading");
    }

    #[test]
    fn test_escape_ldap_dn_trailing_space() {
        assert_eq!(escape_ldap_dn("trailing "), "trailing\\ ");
    }

    #[test]
    fn test_escape_ldap_dn_leading_hash() {
        assert_eq!(escape_ldap_dn("#value"), "\\#value");
    }

    #[test]
    fn test_escape_ldap_dn_middle_hash() {
        assert_eq!(escape_ldap_dn("test#value"), "test#value");
    }

    #[test]
    fn test_escape_ldap_dn_empty() {
        assert_eq!(escape_ldap_dn(""), "");
    }

    #[test]
    fn test_escape_ldap_dn_combined() {
        assert_eq!(
            escape_ldap_dn(" Smith, John+ "),
            "\\ Smith\\, John\\+\\ "
        );
    }

    #[test]
    fn test_is_safe_ldap_value_safe() {
        assert!(is_safe_ldap_value("admin"));
        assert!(is_safe_ldap_value("user123"));
        assert!(is_safe_ldap_value("john_doe"));
        assert!(is_safe_ldap_value("server-01"));
        assert!(is_safe_ldap_value("domain.local"));
    }

    #[test]
    fn test_is_safe_ldap_value_unsafe() {
        assert!(!is_safe_ldap_value("admin*"));
        assert!(!is_safe_ldap_value("user(test)"));
        assert!(!is_safe_ldap_value("value\\path"));
        assert!(!is_safe_ldap_value("test;command"));
    }
}
