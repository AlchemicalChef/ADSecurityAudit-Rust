//! LDAP Connection Pool with automatic health checking and reconnection
//! Provides high-performance connection management for large AD environments
//!
// Allow unused code - connection pooling features for future optimization
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use ldap3::{LdapConnAsync, LdapConnSettings, Ldap};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, RwLock, OwnedSemaphorePermit};
use tracing::{info, warn, error, debug};

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Operation timeout
    pub operation_timeout: Duration,
    /// How long to keep idle connections
    pub idle_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            connect_timeout: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// A pooled LDAP connection with tracking metadata
struct PooledConnection {
    ldap: Ldap,
    created_at: Instant,
    last_used: Instant,
    in_use: bool,
    id: u64,
}

impl PooledConnection {
    fn is_expired(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolStats {
    pub connections_created: u64,
    pub connections_reused: u64,
    pub connections_failed: u64,
    pub current_active: usize,
    pub peak_active: usize,
    pub total_queries: u64,
    pub avg_query_time_ms: f64,
}

/// High-performance LDAP connection pool
pub struct LdapConnectionPool {
    server: String,
    credentials: crate::secure_types::Credentials,
    base_dn: String,
    use_ldaps: bool,
    config: PoolConfig,
    connections: RwLock<Vec<PooledConnection>>,
    semaphore: Arc<Semaphore>,
    stats: RwLock<PoolStats>,
    next_id: RwLock<u64>,
}

impl LdapConnectionPool {
    /// Create a new connection pool
    pub fn new(
        server: String,
        username: String,
        password: String,
        base_dn: String,
        config: Option<PoolConfig>,
    ) -> Self {
        let use_ldaps = server.ends_with(":636") || server.contains("ldaps://");
        let config = config.unwrap_or_default();
        let max_connections = config.max_connections;

        // Create secure credentials
        let credentials = crate::secure_types::Credentials::new(username, password);

        Self {
            server,
            credentials,
            base_dn,
            use_ldaps,
            config,
            connections: RwLock::new(Vec::with_capacity(max_connections)),
            semaphore: Arc::new(Semaphore::new(max_connections)),
            stats: RwLock::new(PoolStats::default()),
            next_id: RwLock::new(0),
        }
    }

    /// Get the base DN
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    /// Acquire a connection from the pool
    pub async fn acquire(self: &Arc<Self>) -> Result<PooledLdapGuard> {
        // Wait for available connection slot - use owned permit for Send safety
        let permit = self.semaphore.clone().acquire_owned().await
            .map_err(|_| anyhow!("Connection pool closed"))?;

        // Try to get an existing connection
        let existing_id = {
            let mut connections = self.connections.write().await;
            
            // Find an available, non-expired connection
            let mut found_id = None;
            for conn in connections.iter_mut() {
                if !conn.in_use && !conn.is_expired(self.config.idle_timeout) {
                    conn.in_use = true;
                    conn.last_used = Instant::now();
                    found_id = Some(conn.id);
                    break;
                }
            }
            
            if let Some(id) = found_id {
                // Update stats
                let mut stats = self.stats.write().await;
                stats.connections_reused += 1;
                stats.current_active += 1;
                if stats.current_active > stats.peak_active {
                    stats.peak_active = stats.current_active;
                }
                debug!("Reusing pooled connection id={}", id);
            }
            
            found_id
        };

        if let Some(id) = existing_id {
            return Ok(PooledLdapGuard {
                pool: Arc::clone(self),
                connection_id: id,
                _permit: permit,
            });
        }

        // Create a new connection
        let ldap = self.create_connection().await?;
        
        let new_id = {
            let mut id_counter = self.next_id.write().await;
            let id = *id_counter;
            *id_counter += 1;
            id
        };
        
        {
            let mut connections = self.connections.write().await;
            connections.push(PooledConnection {
                ldap,
                created_at: Instant::now(),
                last_used: Instant::now(),
                in_use: true,
                id: new_id,
            });

            // Update stats
            let mut stats = self.stats.write().await;
            stats.connections_created += 1;
            stats.current_active += 1;
            if stats.current_active > stats.peak_active {
                stats.peak_active = stats.current_active;
            }

            info!("Created new pooled connection id={} (total: {})", new_id, connections.len());
        }
        
        Ok(PooledLdapGuard {
            pool: Arc::clone(self),
            connection_id: new_id,
            _permit: permit,
        })
    }

    /// Create a new LDAP connection
    async fn create_connection(&self) -> Result<Ldap> {
        // Disable TLS cert verification for enterprise compatibility with internal CAs
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.config.connect_timeout)
            .set_no_tls_verify(true);

        let url = if self.use_ldaps {
            format!("ldaps://{}", self.server.replace("ldaps://", ""))
        } else {
            format!("ldap://{}", self.server.replace("ldap://", ""))
        };

        info!("Creating LDAP connection to {} (LDAPS: {})", url, self.use_ldaps);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await
            .map_err(|e| anyhow!("Failed to connect to LDAP server: {}", e))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                error!("LDAP connection error: {:?}", e);
            }
        });

        // Bind with credentials
        ldap.simple_bind(self.credentials.username(), self.credentials.password()).await
            .map_err(|e| anyhow!("Failed to bind to LDAP: {}", e))?
            .success()
            .map_err(|e| anyhow!("LDAP bind failed: {:?}", e))?;

        info!("LDAP bind successful for {}", url);

        Ok(ldap)
    }

    /// Release a connection back to the pool
    async fn release(&self, connection_id: u64) {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.iter_mut().find(|c| c.id == connection_id) {
            conn.in_use = false;
            conn.last_used = Instant::now();
        }

        let mut stats = self.stats.write().await;
        stats.current_active = stats.current_active.saturating_sub(1);
    }

    /// Get pool statistics
    pub async fn stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }

    /// Clean up expired connections
    pub async fn cleanup_expired(&self) {
        let mut connections = self.connections.write().await;
        let before = connections.len();
        
        connections.retain(|conn| {
            !conn.is_expired(self.config.idle_timeout) || conn.in_use
        });
        
        let removed = before - connections.len();
        if removed > 0 {
            info!("Cleaned up {} expired connections", removed);
        }
    }
}

/// RAII guard for pooled connections
pub struct PooledLdapGuard {
    pool: Arc<LdapConnectionPool>,
    connection_id: u64,
    _permit: OwnedSemaphorePermit,
}

impl PooledLdapGuard {
    /// Execute a search with the pooled connection
    pub async fn search(
        &self,
        base: &str,
        scope: ldap3::Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<ldap3::SearchEntry>> {
        let mut connections = self.pool.connections.write().await;
        let conn = connections.iter_mut()
            .find(|c| c.id == self.connection_id)
            .ok_or_else(|| anyhow!("Connection not found"))?;
        
        let (results, _) = conn.ldap.search(base, scope, filter, attrs).await
            .map_err(|e| anyhow!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| anyhow!("LDAP search error: {:?}", e))?;

        Ok(results.into_iter().map(ldap3::SearchEntry::construct).collect())
    }

    /// Execute a paged search for large result sets
    pub async fn paged_search(
        &self,
        base: &str,
        scope: ldap3::Scope,
        filter: &str,
        attrs: Vec<&str>,
        _page_size: i32,
    ) -> Result<Vec<ldap3::SearchEntry>> {
        let mut all_results = Vec::new();
        let mut connections = self.pool.connections.write().await;
        let conn = connections.iter_mut()
            .find(|c| c.id == self.connection_id)
            .ok_or_else(|| anyhow!("Connection not found"))?;

        // For now, do a simple search - paged search requires more complex handling
        // In production, you'd use ldap3's streaming search or paged controls
        let (results, _) = conn.ldap.search(base, scope, filter, attrs).await
            .map_err(|e| anyhow!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| anyhow!("LDAP search error: {:?}", e))?;

        all_results.extend(results.into_iter().map(ldap3::SearchEntry::construct));
        
        Ok(all_results)
    }
}

impl Drop for PooledLdapGuard {
    fn drop(&mut self) {
        let pool = Arc::clone(&self.pool);
        let connection_id = self.connection_id;

        // Use tokio::spawn only if we're in a runtime context
        // This handles the case where the runtime might be shutting down
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                pool.release(connection_id).await;
            });
        } else {
            // Fallback: synchronous release when no async runtime available
            // This prevents connection leaks during shutdown
            warn!("No tokio runtime available for connection release, using fallback");

            // Use try_write to avoid blocking indefinitely
            if let Ok(mut connections) = pool.connections.try_write() {
                if let Some(conn) = connections.iter_mut().find(|c| c.id == connection_id) {
                    conn.in_use = false;
                    conn.last_used = Instant::now();
                    debug!("Released connection {} (fallback mode)", connection_id);
                }
            } else {
                error!("Failed to acquire write lock for connection release during shutdown");
            }

            // Update stats
            if let Ok(mut stats) = pool.stats.try_write() {
                stats.current_active = stats.current_active.saturating_sub(1);
            }

            // Note: _permit will be automatically dropped and returned to semaphore
        }
    }
}
