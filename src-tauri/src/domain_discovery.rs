//! Domain Discovery Module
//!
//! Uses Windows native APIs to automatically discover:
//! - Current user's domain information
//! - Domain controller addresses
//! - Machine join status

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Result of domain discovery operation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct DiscoveredDomainInfo {
    /// Whether the machine is joined to a domain
    pub is_domain_joined: bool,
    /// DNS domain name (e.g., "corp.example.com")
    pub domain_name: Option<String>,
    /// NetBIOS domain name (e.g., "CORP")
    pub netbios_name: Option<String>,
    /// Current user in DOMAIN\username format
    pub current_user: Option<String>,
    /// Current user in UPN format (user@domain.com)
    pub current_user_upn: Option<String>,
    /// Domain controller hostname
    pub domain_controller: Option<String>,
    /// Domain controller IP address
    pub dc_ip_address: Option<String>,
    /// Forest name
    pub forest_name: Option<String>,
    /// AD site name
    pub site_name: Option<String>,
    /// Suggested LDAP base DN (e.g., "DC=corp,DC=example,DC=com")
    pub suggested_base_dn: Option<String>,
    /// Suggested server connection string (e.g., "dc01.corp.example.com:389")
    pub suggested_server: Option<String>,
    /// Any warnings encountered during discovery
    pub warnings: Vec<String>,
}

/// Convert a DNS domain name to an LDAP base DN
/// e.g., "corp.example.com" -> "DC=corp,DC=example,DC=com"
#[allow(dead_code)]
pub(crate) fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ptr;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NETSETUP_JOIN_STATUS,
        NetSetupDomainName, NetSetupUnjoined, NetSetupWorkgroupName,
    };
    use windows::Win32::Networking::ActiveDirectory::{
        DsGetDcNameW, DOMAIN_CONTROLLER_INFOW,
        DS_DIRECTORY_SERVICE_REQUIRED, DS_RETURN_DNS_NAME,
    };
    use windows::Win32::Security::Authentication::Identity::{
        GetUserNameExW, NameSamCompatible, NameUserPrincipal,
    };

    /// Check if the machine is joined to a domain
    pub fn is_machine_domain_joined() -> Result<(bool, Option<String>), String> {
        unsafe {
            let mut name_buffer: PWSTR = PWSTR::null();
            let mut buffer_type: NETSETUP_JOIN_STATUS = NETSETUP_JOIN_STATUS::default();

            let status = NetGetJoinInformation(PCWSTR::null(), &mut name_buffer, &mut buffer_type);

            if status != ERROR_SUCCESS.0 {
                return Err(format!("NetGetJoinInformation failed with error: {}", status));
            }

            #[allow(non_upper_case_globals)]
            let result = match buffer_type {
                NetSetupDomainName => {
                    let domain = pwstr_to_string(name_buffer.0);
                    info!("Machine is domain-joined to: {:?}", domain);
                    (true, domain)
                }
                NetSetupWorkgroupName => {
                    let workgroup = pwstr_to_string(name_buffer.0);
                    info!("Machine is in workgroup: {:?}", workgroup);
                    (false, workgroup)
                }
                NetSetupUnjoined => {
                    info!("Machine is not joined to any domain or workgroup");
                    (false, None)
                }
                _ => {
                    warn!("Unknown join status: {:?}", buffer_type);
                    (false, None)
                }
            };

            // Free the buffer
            if !name_buffer.is_null() {
                let _ = NetApiBufferFree(Some(name_buffer.0 as *const _));
            }

            Ok(result)
        }
    }

    /// Get current user in SAM format (DOMAIN\username)
    pub fn get_current_user_sam() -> Result<String, String> {
        unsafe {
            // First call to get required buffer size
            let mut size: u32 = 0;
            let _ = GetUserNameExW(NameSamCompatible, PWSTR::null(), &mut size);

            if size == 0 {
                return Err("Failed to get buffer size for SAM username".to_string());
            }

            let mut buffer: Vec<u16> = vec![0; size as usize];
            let result = GetUserNameExW(
                NameSamCompatible,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );

            if result.0 != 0 {
                let username = String::from_utf16_lossy(&buffer[..size as usize - 1]);
                debug!("Current user (SAM): {}", username);
                Ok(username)
            } else {
                Err("GetUserNameExW (SAM) failed".to_string())
            }
        }
    }

    /// Get current user in UPN format (user@domain.com)
    pub fn get_current_user_upn() -> Result<String, String> {
        unsafe {
            // First call to get required buffer size
            let mut size: u32 = 0;
            let _ = GetUserNameExW(NameUserPrincipal, PWSTR::null(), &mut size);

            if size == 0 {
                // UPN might not be available for local accounts
                return Err("UPN not available (local account?)".to_string());
            }

            let mut buffer: Vec<u16> = vec![0; size as usize];
            let result = GetUserNameExW(
                NameUserPrincipal,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            );

            if result.0 != 0 {
                let upn = String::from_utf16_lossy(&buffer[..size as usize - 1]);
                debug!("Current user (UPN): {}", upn);
                Ok(upn)
            } else {
                Err("GetUserNameExW (UPN) failed".to_string())
            }
        }
    }

    /// Get domain controller information
    pub fn get_domain_controller(domain_name: Option<&str>) -> Result<DcInfo, String> {
        unsafe {
            let domain_wide: Option<Vec<u16>> = domain_name.map(|d| {
                d.encode_utf16().chain(std::iter::once(0)).collect()
            });

            let domain_ptr = domain_wide
                .as_ref()
                .map(|v| PCWSTR(v.as_ptr()))
                .unwrap_or(PCWSTR::null());

            let mut dc_info: *mut DOMAIN_CONTROLLER_INFOW = ptr::null_mut();

            let status = DsGetDcNameW(
                PCWSTR::null(),
                domain_ptr,
                None,
                PCWSTR::null(),
                DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
                &mut dc_info,
            );

            if status != ERROR_SUCCESS.0 {
                return Err(format!("DsGetDcNameW failed with error: {}", status));
            }

            if dc_info.is_null() {
                return Err("DsGetDcNameW returned null".to_string());
            }

            let info = &*dc_info;
            let result = DcInfo {
                dc_name: pwstr_to_string(info.DomainControllerName.0),
                dc_address: pwstr_to_string(info.DomainControllerAddress.0),
                domain_name: pwstr_to_string(info.DomainName.0),
                dns_forest_name: pwstr_to_string(info.DnsForestName.0),
                _dc_site_name: pwstr_to_string(info.DcSiteName.0),
                client_site_name: pwstr_to_string(info.ClientSiteName.0),
            };

            info!("Found DC: {:?}", result.dc_name);

            // Free the buffer
            let _ = NetApiBufferFree(Some(dc_info as *const _));

            Ok(result)
        }
    }

    /// Helper to convert PWSTR to String with bounded traversal
    fn pwstr_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        const MAX_LEN: usize = 4096; // Reasonable upper bound for domain strings
        unsafe {
            let mut len = 0;
            while len < MAX_LEN && *ptr.add(len) != 0 {
                len += 1;
            }
            if len == 0 {
                return None;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            Some(String::from_utf16_lossy(slice))
        }
    }

    /// Domain controller information
    #[derive(Debug)]
    pub struct DcInfo {
        pub dc_name: Option<String>,
        pub dc_address: Option<String>,
        pub domain_name: Option<String>,
        pub dns_forest_name: Option<String>,
        pub _dc_site_name: Option<String>,
        pub client_site_name: Option<String>,
    }
}

#[cfg(windows)]
use windows_impl::*;

/// Perform comprehensive domain discovery
pub(crate) fn discover_domain() -> DiscoveredDomainInfo {
    info!("=== DOMAIN DISCOVERY ===");
    let mut info = DiscoveredDomainInfo::default();

    #[cfg(windows)]
    {
        // Step 1: Check domain membership
        match is_machine_domain_joined() {
            Ok((joined, domain)) => {
                info.is_domain_joined = joined;
                info.netbios_name = domain;
                info!("Domain joined: {}, NetBIOS: {:?}", joined, info.netbios_name);
            }
            Err(e) => {
                warn!("NetGetJoinInformation failed: {}", e);
                info.warnings.push(format!("Could not check domain membership: {}", e));
            }
        }

        // Step 2: Get current user (SAM format)
        match get_current_user_sam() {
            Ok(user) => {
                info.current_user = Some(user.clone());
                info!("Current user (SAM): {}", user);
            }
            Err(e) => {
                warn!("Could not get SAM username: {}", e);
                info.warnings.push(format!("Could not get username: {}", e));
            }
        }

        // Step 3: Get current user (UPN format)
        match get_current_user_upn() {
            Ok(upn) => {
                info.current_user_upn = Some(upn.clone());
                info!("Current user (UPN): {}", upn);
            }
            Err(e) => {
                debug!("UPN not available: {}", e);
                // Don't add to warnings - UPN might not be available for local accounts
            }
        }

        // Step 4: Get domain controller (only if domain-joined)
        if info.is_domain_joined {
            match get_domain_controller(info.netbios_name.as_deref()) {
                Ok(dc) => {
                    // Clean up DC name (remove leading \\)
                    info.domain_controller = dc.dc_name.map(|n| n.trim_start_matches('\\').to_string());
                    // Clean up DC address (remove leading \\ and trailing port)
                    info.dc_ip_address = dc.dc_address.map(|a| {
                        a.trim_start_matches('\\')
                            .split(':')
                            .next()
                            .unwrap_or(&a)
                            .to_string()
                    });
                    info.domain_name = dc.domain_name;
                    info.forest_name = dc.dns_forest_name;
                    info.site_name = dc.client_site_name;

                    info!(
                        "DC: {:?}, Domain: {:?}, Forest: {:?}",
                        info.domain_controller, info.domain_name, info.forest_name
                    );
                }
                Err(e) => {
                    warn!("DsGetDcNameW failed: {}", e);
                    info.warnings.push(format!("Could not find domain controller: {}", e));
                }
            }
        }

        // Step 5: Calculate base DN from domain name
        if let Some(ref domain) = info.domain_name {
            info.suggested_base_dn = Some(domain_to_base_dn(domain));
            info!("Suggested Base DN: {:?}", info.suggested_base_dn);
        }

        // Step 6: Build suggested server string
        if let Some(ref dc) = info.domain_controller {
            // Default to LDAP port 389
            info.suggested_server = Some(format!("{}:389", dc));
            info!("Suggested Server: {:?}", info.suggested_server);
        }
    }

    #[cfg(not(windows))]
    {
        info.warnings.push("Domain discovery requires Windows".to_string());
        warn!("Domain discovery is only supported on Windows");
    }

    info!("=== DISCOVERY COMPLETE ===");
    info!(
        "Domain joined: {}, DC: {:?}, Warnings: {}",
        info.is_domain_joined,
        info.domain_controller,
        info.warnings.len()
    );

    info
}

/// Quick check if machine is domain-joined (without full discovery)
pub(crate) fn check_domain_joined() -> bool {
    #[cfg(windows)]
    {
        is_machine_domain_joined()
            .map(|(joined, _)| joined)
            .unwrap_or(false)
    }

    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_base_dn() {
        assert_eq!(
            domain_to_base_dn("corp.example.com"),
            "DC=corp,DC=example,DC=com"
        );
        assert_eq!(domain_to_base_dn("example.com"), "DC=example,DC=com");
        assert_eq!(domain_to_base_dn("local"), "DC=local");
    }
}
