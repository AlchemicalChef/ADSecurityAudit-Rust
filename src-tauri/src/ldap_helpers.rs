//! LDAP Helper Utilities
//!
//! Extension traits and utilities for working with LDAP search results,
//! reducing boilerplate code for common attribute extraction patterns.

use ldap3::SearchEntry;
use crate::common_types::UserAccountControlFlags;

/// Extension trait for SearchEntry to simplify attribute extraction
///
/// Provides convenient methods to extract common attribute types
/// without repeating the verbose `.get().and_then().cloned().unwrap_or_default()` pattern.
#[allow(dead_code)]
pub(crate) trait SearchEntryExt {
    /// Get a string attribute, returning empty string if not found
    fn get_string_attr(&self, name: &str) -> String;

    /// Get an optional string attribute (returns None if missing)
    fn get_optional_attr(&self, name: &str) -> Option<String>;

    /// Get a u32 attribute, returning 0 if not found or invalid
    fn get_u32_attr(&self, name: &str) -> u32;

    /// Get an optional u32 attribute (returns None if missing, Some(0) if value is "0")
    fn get_optional_u32_attr(&self, name: &str) -> Option<u32>;

    /// Get a u64 attribute, returning 0 if not found or invalid
    fn get_u64_attr(&self, name: &str) -> u64;

    /// Get an i64 attribute, returning 0 if not found or invalid
    fn get_i64_attr(&self, name: &str) -> i64;

    /// Get an optional i64 attribute (returns None if missing, distinguishes from 0)
    fn get_optional_i64_attr(&self, name: &str) -> Option<i64>;

    /// Get all values for a multi-valued attribute
    fn get_multi_attr(&self, name: &str) -> Vec<String>;

    /// Get binary attribute as bytes
    fn get_binary_attr(&self, name: &str) -> Option<Vec<u8>>;

    /// Get the distinguished name
    fn get_dn(&self) -> String;

    /// Get the sAMAccountName
    fn get_sam_account_name(&self) -> String;

    /// Get userAccountControl flags parsed into a helper struct
    fn get_uac_flags(&self) -> UserAccountControlFlags;

    /// Check if attribute key exists in the entry (may have empty vector)
    fn has_attr(&self, name: &str) -> bool;

    /// Check if attribute exists AND has at least one value
    /// Use this to check for presence of multi-valued attributes like servicePrincipalName
    fn has_values(&self, name: &str) -> bool;
}

impl SearchEntryExt for SearchEntry {
    fn get_string_attr(&self, name: &str) -> String {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    }

    fn get_optional_attr(&self, name: &str) -> Option<String> {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .cloned()
    }

    fn get_u32_attr(&self, name: &str) -> u32 {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn get_optional_u32_attr(&self, name: &str) -> Option<u32> {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
    }

    fn get_u64_attr(&self, name: &str) -> u64 {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn get_i64_attr(&self, name: &str) -> i64 {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn get_optional_i64_attr(&self, name: &str) -> Option<i64> {
        self.attrs
            .get(name)
            .and_then(|v| v.first())
            .and_then(|v| v.parse().ok())
    }

    fn get_multi_attr(&self, name: &str) -> Vec<String> {
        self.attrs
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    fn get_binary_attr(&self, name: &str) -> Option<Vec<u8>> {
        self.bin_attrs
            .get(name)
            .and_then(|v| v.first())
            .cloned()
    }

    fn get_dn(&self) -> String {
        // dn is a field on SearchEntry, not in attrs
        self.dn.clone()
    }

    fn get_sam_account_name(&self) -> String {
        self.get_string_attr("sAMAccountName")
    }

    fn get_uac_flags(&self) -> UserAccountControlFlags {
        let uac = self.get_u32_attr("userAccountControl");
        UserAccountControlFlags::from_value(uac)
    }

    fn has_attr(&self, name: &str) -> bool {
        self.attrs.contains_key(name)
    }

    fn has_values(&self, name: &str) -> bool {
        self.attrs
            .get(name)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }
}

/// Common LDAP attribute name constants
///
/// These are the most frequently used attribute names in AD queries.
/// Using constants prevents typos and enables IDE completion.
#[allow(dead_code)]
pub(crate) mod attrs {
    // Identity attributes
    pub const DISTINGUISHED_NAME: &str = "distinguishedName";
    pub const SAM_ACCOUNT_NAME: &str = "sAMAccountName";
    pub const OBJECT_SID: &str = "objectSid";
    pub const OBJECT_GUID: &str = "objectGUID";
    pub const OBJECT_CLASS: &str = "objectClass";
    pub const OBJECT_CATEGORY: &str = "objectCategory";

    // User attributes
    pub const DISPLAY_NAME: &str = "displayName";
    pub const GIVEN_NAME: &str = "givenName";
    pub const SN: &str = "sn";
    pub const MAIL: &str = "mail";
    pub const USER_PRINCIPAL_NAME: &str = "userPrincipalName";
    pub const USER_ACCOUNT_CONTROL: &str = "userAccountControl";
    pub const MEMBER_OF: &str = "memberOf";
    pub const PRIMARY_GROUP_ID: &str = "primaryGroupID";
    pub const ADMIN_COUNT: &str = "adminCount";

    // Password attributes
    pub const PWD_LAST_SET: &str = "pwdLastSet";
    pub const LAST_LOGON: &str = "lastLogon";
    pub const LAST_LOGON_TIMESTAMP: &str = "lastLogonTimestamp";
    pub const ACCOUNT_EXPIRES: &str = "accountExpires";
    pub const WHEN_CREATED: &str = "whenCreated";
    pub const WHEN_CHANGED: &str = "whenChanged";

    // Group attributes
    pub const MEMBER: &str = "member";
    pub const GROUP_TYPE: &str = "groupType";

    // Computer attributes
    pub const DNS_HOST_NAME: &str = "dNSHostName";
    pub const OPERATING_SYSTEM: &str = "operatingSystem";
    pub const OPERATING_SYSTEM_VERSION: &str = "operatingSystemVersion";
    pub const SERVICE_PRINCIPAL_NAME: &str = "servicePrincipalName";

    // Security attributes
    pub const NT_SECURITY_DESCRIPTOR: &str = "nTSecurityDescriptor";
    pub const SID_HISTORY: &str = "sIDHistory";
    pub const MS_DS_KEY_CREDENTIAL_LINK: &str = "msDS-KeyCredentialLink";
    pub const MS_DS_ALLOWED_TO_DELEGATE_TO: &str = "msDS-AllowedToDelegateTo";
    pub const MS_DS_ALLOWED_TO_ACT_ON_BEHALF: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";

    // Domain/forest attributes
    pub const MS_DS_BEHAVIOR_VERSION: &str = "msDS-Behavior-Version";
    pub const FOREST_FUNCTIONALITY: &str = "forestFunctionality";
    pub const DOMAIN_FUNCTIONALITY: &str = "domainFunctionality";

    // Certificate attributes (ADCS)
    pub const CERTIFICATE_TEMPLATES: &str = "certificateTemplates";
    pub const PKI_ENROLLMENT_FLAG: &str = "msPKI-Enrollment-Flag";
    pub const PKI_CERTIFICATE_NAME_FLAG: &str = "msPKI-Certificate-Name-Flag";
    pub const PKI_EXTENDED_KEY_USAGE: &str = "pKIExtendedKeyUsage";
}

/// Common LDAP filter patterns
#[allow(dead_code)]
pub(crate) mod filters {
    /// All users (person objects)
    pub const ALL_USERS: &str = "(&(objectClass=user)(objectCategory=person))";

    /// All enabled users
    pub const ENABLED_USERS: &str = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    /// All groups
    pub const ALL_GROUPS: &str = "(objectClass=group)";

    /// All computers
    pub const ALL_COMPUTERS: &str = "(objectClass=computer)";

    /// Domain controllers
    pub const DOMAIN_CONTROLLERS: &str = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

    /// Accounts with adminCount=1 (protected by AdminSDHolder)
    pub const ADMIN_COUNT: &str = "(&(objectClass=user)(adminCount=1))";

    /// AS-REP roastable accounts (DONT_REQUIRE_PREAUTH)
    pub const ASREP_ROASTABLE: &str = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";

    /// Kerberoastable accounts (users with SPNs)
    pub const KERBEROASTABLE: &str = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))";

    /// Accounts with unconstrained delegation
    pub const UNCONSTRAINED_DELEGATION: &str = "(&(objectCategory=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
}

/// Standard attribute lists for common query types
#[allow(dead_code)]
pub(crate) mod attr_lists {
    /// Basic user attributes for listing
    pub const USER_BASIC: &[&str] = &[
        "distinguishedName",
        "sAMAccountName",
        "displayName",
        "mail",
        "userAccountControl",
        "memberOf",
    ];

    /// Extended user attributes for detailed analysis
    pub const USER_EXTENDED: &[&str] = &[
        "distinguishedName",
        "sAMAccountName",
        "displayName",
        "mail",
        "userAccountControl",
        "memberOf",
        "pwdLastSet",
        "lastLogon",
        "lastLogonTimestamp",
        "whenCreated",
        "adminCount",
        "userPrincipalName",
        "servicePrincipalName",
    ];

    /// Privileged account attributes
    pub const PRIVILEGED_ACCOUNT: &[&str] = &[
        "distinguishedName",
        "sAMAccountName",
        "displayName",
        "userAccountControl",
        "memberOf",
        "pwdLastSet",
        "lastLogon",
        "adminCount",
        "servicePrincipalName",
        "sIDHistory",
    ];

    /// Group attributes
    pub const GROUP: &[&str] = &[
        "distinguishedName",
        "sAMAccountName",
        "objectSid",
        "member",
        "memberOf",
        "groupType",
        "adminCount",
    ];

    /// Computer/DC attributes
    pub const COMPUTER: &[&str] = &[
        "distinguishedName",
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "userAccountControl",
        "servicePrincipalName",
        "lastLogon",
    ];

    /// Security descriptor query (requires special handling)
    pub const SECURITY_DESCRIPTOR: &[&str] = &[
        "distinguishedName",
        "nTSecurityDescriptor",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_entry(attrs: Vec<(&str, Vec<&str>)>) -> SearchEntry {
        let mut attr_map = HashMap::new();
        for (key, values) in attrs {
            attr_map.insert(key.to_string(), values.into_iter().map(|s| s.to_string()).collect());
        }
        SearchEntry {
            dn: "CN=Test,DC=example,DC=com".to_string(),
            attrs: attr_map,
            bin_attrs: HashMap::new(),
        }
    }

    #[test]
    fn test_get_string_attr() {
        let entry = create_test_entry(vec![("sAMAccountName", vec!["testuser"])]);
        assert_eq!(entry.get_string_attr("sAMAccountName"), "testuser");
        assert_eq!(entry.get_string_attr("nonexistent"), "");
    }

    #[test]
    fn test_get_optional_attr() {
        let entry = create_test_entry(vec![("mail", vec!["test@example.com"])]);
        assert_eq!(entry.get_optional_attr("mail"), Some("test@example.com".to_string()));
        assert_eq!(entry.get_optional_attr("nonexistent"), None);
    }

    #[test]
    fn test_get_u32_attr() {
        let entry = create_test_entry(vec![("userAccountControl", vec!["512"])]);
        assert_eq!(entry.get_u32_attr("userAccountControl"), 512);
        assert_eq!(entry.get_u32_attr("nonexistent"), 0);
    }

    #[test]
    fn test_get_optional_u32_attr() {
        let entry = create_test_entry(vec![
            ("userAccountControl", vec!["512"]),
            ("zeroValue", vec!["0"]),
        ]);
        // Existing attribute with value
        assert_eq!(entry.get_optional_u32_attr("userAccountControl"), Some(512));
        // Existing attribute with zero value (distinguishable from missing)
        assert_eq!(entry.get_optional_u32_attr("zeroValue"), Some(0));
        // Missing attribute
        assert_eq!(entry.get_optional_u32_attr("nonexistent"), None);
    }

    #[test]
    fn test_get_optional_i64_attr() {
        let entry = create_test_entry(vec![
            ("lastLogon", vec!["132456789012345678"]),
            ("neverLoggedOn", vec!["0"]),
        ]);
        // Existing attribute with value
        assert_eq!(entry.get_optional_i64_attr("lastLogon"), Some(132456789012345678));
        // Existing attribute with zero (distinguishable from missing)
        assert_eq!(entry.get_optional_i64_attr("neverLoggedOn"), Some(0));
        // Missing attribute
        assert_eq!(entry.get_optional_i64_attr("nonexistent"), None);
    }

    #[test]
    fn test_get_multi_attr() {
        let entry = create_test_entry(vec![("memberOf", vec!["CN=Group1,DC=test", "CN=Group2,DC=test"])]);
        let groups = entry.get_multi_attr("memberOf");
        assert_eq!(groups.len(), 2);
        // Missing attribute returns empty vec
        assert_eq!(entry.get_multi_attr("nonexistent"), Vec::<String>::new());
    }

    #[test]
    fn test_get_uac_flags() {
        // 514 = NORMAL_ACCOUNT (512) + ACCOUNTDISABLE (2)
        let entry = create_test_entry(vec![("userAccountControl", vec!["514"])]);
        let flags = entry.get_uac_flags();
        assert!(flags.is_disabled);
        assert!(!flags.is_enabled());
    }

    #[test]
    fn test_has_attr() {
        let entry = create_test_entry(vec![("mail", vec!["test@example.com"])]);
        assert!(entry.has_attr("mail"));
        assert!(!entry.has_attr("nonexistent"));
    }

    #[test]
    fn test_has_values() {
        let entry = create_test_entry(vec![
            ("servicePrincipalName", vec!["HTTP/server.example.com"]),
            ("emptyAttr", vec![]),
        ]);
        // Attribute with values
        assert!(entry.has_values("servicePrincipalName"));
        // Attribute key exists but empty vector (edge case)
        assert!(!entry.has_values("emptyAttr"));
        // Missing attribute
        assert!(!entry.has_values("nonexistent"));
    }

    #[test]
    fn test_get_dn() {
        let entry = create_test_entry(vec![]);
        assert_eq!(entry.get_dn(), "CN=Test,DC=example,DC=com");
    }
}
