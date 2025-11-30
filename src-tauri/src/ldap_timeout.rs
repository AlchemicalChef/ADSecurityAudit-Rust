//! Timeout wrappers for synchronous LDAP operations
//!
//! The ldap3 crate's `LdapConn::new()` is a blocking call that can hang indefinitely
//! if the server is unreachable. This module provides async wrappers that use
//! `tokio::task::spawn_blocking` with timeouts to prevent indefinite hangs.

use anyhow::{anyhow, Result};
use ldap3::{LdapConn, LdapConnSettings, Scope, ResultEntry};
use ldap3::controls::{PagedResults, ControlParser};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, error};

/// Default connection timeout (15 seconds)
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Default search timeout (30 seconds)
pub const DEFAULT_SEARCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Attempts to create an LDAP connection with a timeout.
///
/// Wraps the blocking `LdapConn::with_settings()` in `spawn_blocking` with a timeout
/// to prevent the async runtime from blocking indefinitely.
///
/// TLS certificate verification is disabled for both LDAPS and plain LDAP to support
/// enterprise environments with self-signed or internal CA certificates.
pub async fn ldap_connect_with_timeout(
    url: &str,
    connect_timeout: Duration,
) -> Result<LdapConn> {
    let url = url.to_string();

    let result = timeout(connect_timeout, async {
        tokio::task::spawn_blocking(move || {
            // Configure connection settings
            // Disable TLS cert verification to support enterprise environments
            // with self-signed certificates or internal CAs
            let settings = LdapConnSettings::new()
                .set_conn_timeout(connect_timeout)
                .set_no_tls_verify(true);

            LdapConn::with_settings(settings, &url)
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))?
        .map_err(|e| anyhow!("LDAP connection failed: {}", e))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(anyhow!(
            "Connection timeout: Server did not respond within {} seconds. \
             Please verify the server address and network connectivity.",
            connect_timeout.as_secs()
        )),
    }
}

/// Performs LDAP bind (authentication) with a timeout.
///
/// Takes ownership of the LdapConn to move it into the blocking task,
/// then returns it after successful bind.
pub async fn ldap_bind_with_timeout(
    ldap: LdapConn,
    username: &str,
    password: &str,
    bind_timeout: Duration,
) -> Result<LdapConn> {
    let username = username.to_string();
    let password = password.to_string();

    let result = timeout(bind_timeout, async {
        tokio::task::spawn_blocking(move || {
            let mut ldap = ldap;
            ldap.simple_bind(&username, &password)?
                .success()?;
            Ok::<LdapConn, anyhow::Error>(ldap)
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))?
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(anyhow!(
            "Authentication timeout: Bind operation did not complete within {} seconds.",
            bind_timeout.as_secs()
        )),
    }
}

/// Unbinds from LDAP connection with a timeout.
///
/// This is a quick operation but we still wrap it to be safe.
pub async fn ldap_unbind_with_timeout(
    ldap: LdapConn,
    unbind_timeout: Duration,
) -> Result<()> {
    let result = timeout(unbind_timeout, async {
        tokio::task::spawn_blocking(move || {
            let mut ldap = ldap;
            ldap.unbind()
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))?
        .map_err(|e| anyhow!("Unbind failed: {}", e))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => {
            // Unbind timeout is not critical - connection will be dropped anyway
            Ok(())
        }
    }
}

/// Performs an LDAP search with a timeout.
///
/// Wraps the blocking search operation in `spawn_blocking` with a timeout
/// to prevent indefinite hangs on slow or unresponsive servers.
///
/// Handles sizeLimitExceeded (rc=4) gracefully by returning partial results.
pub async fn ldap_search_with_timeout(
    mut ldap: LdapConn,
    base_dn: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
    search_timeout: Duration,
) -> Result<(Vec<ResultEntry>, LdapConn)> {
    let base_dn = base_dn.to_string();
    let filter = filter.to_string();
    let attrs: Vec<String> = attrs.into_iter().map(|s| s.to_string()).collect();

    info!("ldap_search_with_timeout: Starting search in {} with filter {} (timeout: {}s)",
        base_dn, filter, search_timeout.as_secs());

    let result = timeout(search_timeout, async {
        tokio::task::spawn_blocking(move || {
            let attrs_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

            let search_result = ldap.search(
                &base_dn,
                scope,
                &filter,
                attrs_refs,
            );

            match search_result {
                Ok(search_result) => {
                    // SearchResult is a tuple struct: (Vec<ResultEntry>, LdapResult)
                    let entries = search_result.0;
                    let ldap_result = search_result.1;

                    // rc=4 is sizeLimitExceeded - return partial results with a warning
                    if ldap_result.rc == 4 {
                        tracing::warn!(
                            "ldap_search_with_timeout: Size limit exceeded (rc=4), returning {} partial entries",
                            entries.len()
                        );
                        Ok((entries, ldap))
                    } else if ldap_result.rc == 0 {
                        info!("ldap_search_with_timeout: Search returned {} entries", entries.len());
                        Ok((entries, ldap))
                    } else {
                        // Other error codes should still be treated as errors
                        error!(
                            "ldap_search_with_timeout: Search failed with rc={}: {}",
                            ldap_result.rc, ldap_result.text
                        );
                        Err(anyhow!(
                            "LDAP search failed: rc={}, text={}",
                            ldap_result.rc,
                            ldap_result.text
                        ))
                    }
                }
                Err(e) => {
                    error!("ldap_search_with_timeout: Search failed: {}", e);
                    Err(anyhow!("LDAP search failed: {}", e))
                }
            }
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))?
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => {
            error!("ldap_search_with_timeout: Search timed out after {}s", search_timeout.as_secs());
            Err(anyhow!(
                "LDAP search timeout: Query did not complete within {} seconds. \
                 The server may be slow or the search scope too broad.",
                search_timeout.as_secs()
            ))
        }
    }
}

/// Default page size for paged searches
pub const DEFAULT_PAGE_SIZE: i32 = 500;

/// Extended timeout for paged searches (2 minutes)
pub const PAGED_SEARCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Performs a paged LDAP search with timeout.
///
/// Automatically fetches all pages to handle result sets larger than 1000 entries.
/// Uses the Simple Paged Results control (OID 1.2.840.113556.1.4.319) which is
/// supported by Active Directory.
///
/// This is essential for queries that may return more than 1000 results, as AD
/// has a default size limit of 1000 entries per search.
pub async fn ldap_paged_search_with_timeout(
    ldap: LdapConn,
    base_dn: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
    page_size: i32,
    search_timeout: Duration,
) -> Result<(Vec<ResultEntry>, LdapConn)> {
    let base_dn = base_dn.to_string();
    let filter = filter.to_string();
    let attrs: Vec<String> = attrs.into_iter().map(|s| s.to_string()).collect();

    info!(
        "ldap_paged_search: Starting paged search in {} with filter {} (page_size: {}, timeout: {}s)",
        base_dn, filter, page_size, search_timeout.as_secs()
    );

    let result = timeout(search_timeout, async {
        tokio::task::spawn_blocking(move || {
            let attrs_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
            let mut all_entries: Vec<ResultEntry> = Vec::new();
            let mut ldap = ldap;
            let mut page_count = 0;
            let mut cookie: Vec<u8> = Vec::new();

            loop {
                page_count += 1;
                info!("ldap_paged_search: Fetching page {}", page_count);

                // Create paged results control for this request
                let paged_control = PagedResults {
                    size: page_size,
                    cookie: cookie.clone(),
                };

                // Perform search with paging control
                let search_result = ldap
                    .with_controls(vec![paged_control.into()])
                    .search(
                        &base_dn,
                        scope,
                        &filter,
                        attrs_refs.clone(),
                    );

                match search_result {
                    Ok(result) => {
                        // SearchResult is a tuple struct (Vec<ResultEntry>, LdapResult)
                        let entries = result.0;
                        let ldap_result = result.1;

                        let entries_in_page = entries.len();
                        all_entries.extend(entries);

                        info!(
                            "ldap_paged_search: Page {} returned {} entries (total so far: {})",
                            page_count, entries_in_page, all_entries.len()
                        );

                        // Check result code
                        if ldap_result.rc != 0 && ldap_result.rc != 4 {
                            error!(
                                "ldap_paged_search: Search failed with rc={}: {}",
                                ldap_result.rc, ldap_result.text
                            );
                            return Err(anyhow!(
                                "LDAP paged search failed: rc={}, text={}",
                                ldap_result.rc,
                                ldap_result.text
                            ));
                        }

                        // Extract the response cookie from controls
                        // Control is a tuple struct where .1 is RawControl
                        let mut has_more_pages = false;
                        for ctrl in &ldap_result.ctrls {
                            // PagedResults control OID
                            let raw_ctrl = &ctrl.1;
                            if raw_ctrl.ctype == "1.2.840.113556.1.4.319" {
                                if let Some(ref val) = raw_ctrl.val {
                                    // Parse the paged results response
                                    let pr: PagedResults = PagedResults::parse(val);
                                    cookie = pr.cookie;
                                    has_more_pages = !cookie.is_empty();
                                }
                                break;
                            }
                        }

                        if !has_more_pages {
                            info!(
                                "ldap_paged_search: Completed {} pages, {} total entries",
                                page_count, all_entries.len()
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        error!("ldap_paged_search: Search failed: {}", e);
                        return Err(anyhow!("LDAP paged search failed: {}", e));
                    }
                }
            }

            Ok((all_entries, ldap))
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))?
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => {
            error!(
                "ldap_paged_search: Search timed out after {}s",
                search_timeout.as_secs()
            );
            Err(anyhow!(
                "Paged LDAP search timeout: Query did not complete within {} seconds.",
                search_timeout.as_secs()
            ))
        }
    }
}
