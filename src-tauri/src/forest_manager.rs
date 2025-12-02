//! Forest Manager for Multi-Domain Active Directory Operations
//!
//! Manages multiple domain connections, coordinates forest-wide audits,
//! and provides seamless domain switching capabilities.
//!
// Allow unused code - multi-domain features for future expansion
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use serde::{Deserialize, Serialize};

use crate::ad_client::ActiveDirectoryClient;
use crate::connection_pool::{LdapConnectionPool, PoolConfig};
use crate::database::{Database, DomainConfig};
use chrono::Utc;

/// Domain connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Error(String),
}

/// Information about a connected domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub id: i64,
    pub name: String,
    pub server: String,
    pub base_dn: String,
    pub is_active: bool,
    pub status: ConnectionStatus,
    pub last_connected: Option<String>,
}

/// Manages multiple Active Directory domain connections
pub struct ForestManager {
    /// Database for persistent storage
    database: Arc<Database>,

    /// Map of domain ID to AD client
    clients: RwLock<HashMap<i64, Arc<ActiveDirectoryClient>>>,

    /// Map of domain ID to connection pool
    pools: RwLock<HashMap<i64, Arc<LdapConnectionPool>>>,

    /// Currently active domain ID
    active_domain_id: RwLock<Option<i64>>,
}

impl ForestManager {
    /// Create a new ForestManager
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            database,
            clients: RwLock::new(HashMap::new()),
            pools: RwLock::new(HashMap::new()),
            active_domain_id: RwLock::new(None),
        }
    }

    /// Clear all domain connections and data
    pub async fn clear_all_domains(&self) {
        // Clear in-memory connections
        self.clients.write().await.clear();
        self.pools.write().await.clear();
        *self.active_domain_id.write().await = None;

        // Clear database
        if let Err(e) = self.database.clear_all_domains() {
            warn!("Failed to clear domains from database: {}", e);
        }

        info!("All domain connections and data cleared");
    }

    /// Initialize from database and restore active connection
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing ForestManager from database");

        // Load active domain from database
        if let Some(active_domain) = self.database.get_active_domain()? {
            info!("Restoring connection to active domain: {}", active_domain.name);

            match self.connect_domain_internal(&active_domain).await {
                Ok(()) => {
                    *self.active_domain_id.write().await = active_domain.id;
                    info!("Successfully restored connection to {}", active_domain.name);
                }
                Err(e) => {
                    warn!("Failed to restore connection to {}: {}", active_domain.name, e);
                }
            }
        }

        Ok(())
    }

    /// Add a new domain configuration to the database
    pub async fn add_domain(
        &self,
        name: String,
        server: String,
        username: String,
        password: String,
        base_dn: String,
    ) -> Result<i64> {
        info!("Adding new domain: {}", name);

        // Check if domain already exists
        if self.database.get_domain_by_name(&name)?.is_some() {
            return Err(anyhow!("Domain '{}' already exists", name));
        }

        let use_ldaps = server.ends_with(":636") || server.contains("ldaps://");

        let domain_config = DomainConfig {
            id: None,
            name,
            server,
            username,
            password,
            base_dn,
            use_ldaps,
            is_active: false,
            last_connected: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let id = self.database.save_domain(&domain_config)?;
        info!("Domain added successfully with ID: {}", id);

        Ok(id)
    }

    /// Connect to a domain by ID
    pub async fn connect_domain(&self, domain_id: i64) -> Result<()> {
        let domain_config = self.database.get_domain(domain_id)?
            .ok_or_else(|| anyhow!("Domain with ID {} not found", domain_id))?;

        info!("Connecting to domain: {}", domain_config.name);

        self.connect_domain_internal(&domain_config).await?;

        // Update active domain
        self.database.set_active_domain(domain_id)?;
        *self.active_domain_id.write().await = Some(domain_id);

        // Update last connected timestamp
        self.database.update_last_connected(domain_id)?;

        info!("Successfully connected to domain: {}", domain_config.name);

        Ok(())
    }

    /// Internal connection logic
    async fn connect_domain_internal(&self, config: &DomainConfig) -> Result<()> {
        // Create AD client
        let client = ActiveDirectoryClient::new(
            config.server.clone(),
            config.username.clone(),
            config.password.clone(),
            config.base_dn.clone(),
        ).await?;

        // Create connection pool
        let pool_config = PoolConfig {
            max_connections: 10,
            ..Default::default()
        };

        let pool = LdapConnectionPool::new(
            config.server.clone(),
            config.username.clone(),
            config.password.clone(),
            config.base_dn.clone(),
            Some(pool_config),
        );

        // Store client and pool
        let id = config.id.ok_or_else(|| anyhow!("Domain config missing ID"))?;
        self.clients.write().await.insert(id, Arc::new(client));
        self.pools.write().await.insert(id, Arc::new(pool));

        Ok(())
    }

    /// Disconnect from a domain
    pub async fn disconnect_domain(&self, domain_id: i64) -> Result<()> {
        info!("Disconnecting from domain ID: {}", domain_id);

        self.clients.write().await.remove(&domain_id);
        self.pools.write().await.remove(&domain_id);

        // If this was the active domain, clear it
        let mut active = self.active_domain_id.write().await;
        if *active == Some(domain_id) {
            *active = None;
        }

        Ok(())
    }

    /// Get the currently active domain client
    pub async fn get_active_client(&self) -> Result<Arc<ActiveDirectoryClient>> {
        let active_id = self.active_domain_id.read().await
            .ok_or_else(|| anyhow!("No active domain connection"))?;

        self.clients.read().await
            .get(&active_id)
            .cloned()
            .ok_or_else(|| anyhow!("Active domain client not found"))
    }

    /// Get the currently active domain pool
    pub async fn get_active_pool(&self) -> Result<Arc<LdapConnectionPool>> {
        let active_id = self.active_domain_id.read().await
            .ok_or_else(|| anyhow!("No active domain connection"))?;

        self.pools.read().await
            .get(&active_id)
            .cloned()
            .ok_or_else(|| anyhow!("Active domain pool not found"))
    }

    /// Get client for a specific domain
    pub async fn get_client(&self, domain_id: i64) -> Result<Arc<ActiveDirectoryClient>> {
        self.clients.read().await
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow!("Domain client not found for ID {}", domain_id))
    }

    /// Get pool for a specific domain
    pub async fn get_pool(&self, domain_id: i64) -> Result<Arc<LdapConnectionPool>> {
        self.pools.read().await
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow!("Domain pool not found for ID {}", domain_id))
    }

    /// Get all domain configurations from database
    pub fn get_all_domains(&self) -> Result<Vec<DomainConfig>> {
        self.database.get_all_domains()
    }

    /// Get a specific domain configuration by ID
    pub fn get_domain_config(&self, domain_id: i64) -> Result<Option<DomainConfig>> {
        self.database.get_domain(domain_id)
    }

    /// Get domain information with connection status
    pub async fn get_domains_info(&self) -> Result<Vec<DomainInfo>> {
        let configs = self.database.get_all_domains()?;
        let clients = self.clients.read().await;
        let active_id = *self.active_domain_id.read().await;

        let mut domains_info = Vec::new();

        for config in configs {
            let Some(id) = config.id else {
                warn!("Skipping domain config without ID: {}", config.name);
                continue;
            };
            let status = if clients.contains_key(&id) {
                ConnectionStatus::Connected
            } else {
                ConnectionStatus::Disconnected
            };

            domains_info.push(DomainInfo {
                id,
                name: config.name,
                server: config.server,
                base_dn: config.base_dn,
                is_active: active_id == Some(id),
                status,
                last_connected: config.last_connected.map(|dt| dt.to_rfc3339()),
            });
        }

        Ok(domains_info)
    }

    /// Delete a domain configuration
    pub async fn delete_domain(&self, domain_id: i64) -> Result<()> {
        info!("Deleting domain ID: {}", domain_id);

        // Disconnect if connected
        self.disconnect_domain(domain_id).await?;

        // Delete from database
        self.database.delete_domain(domain_id)?;

        Ok(())
    }

    /// Update domain configuration
    pub async fn update_domain(
        &self,
        domain_id: i64,
        name: Option<String>,
        server: Option<String>,
        username: Option<String>,
        password: Option<String>,
        base_dn: Option<String>,
    ) -> Result<()> {
        info!("Updating domain ID: {}", domain_id);

        let mut config = self.database.get_domain(domain_id)?
            .ok_or_else(|| anyhow!("Domain with ID {} not found", domain_id))?;

        // Update fields if provided
        if let Some(name) = name {
            config.name = name;
        }
        if let Some(server) = server {
            config.server = server;
        }
        if let Some(username) = username {
            config.username = username;
        }
        if let Some(password) = password {
            config.password = password;
        }
        if let Some(base_dn) = base_dn {
            config.base_dn = base_dn;
        }

        config.updated_at = Utc::now();

        // Save updated config
        self.database.save_domain(&config)?;

        // If this domain is connected, reconnect with new settings
        if self.clients.read().await.contains_key(&domain_id) {
            info!("Reconnecting domain {} with updated settings", config.name);
            self.disconnect_domain(domain_id).await?;
            self.connect_domain(domain_id).await?;
        }

        Ok(())
    }

    /// Test connection to a domain without saving
    pub async fn test_connection(
        &self,
        server: String,
        username: String,
        password: String,
        base_dn: String,
    ) -> Result<bool> {
        debug!("Testing connection to server: {}", server);

        match ActiveDirectoryClient::new(server, username, password, base_dn).await {
            Ok(_) => {
                debug!("Connection test successful");
                Ok(true)
            }
            Err(e) => {
                debug!("Connection test failed: {}", e);
                Err(e)
            }
        }
    }

    /// Get the active domain ID
    pub async fn get_active_domain_id(&self) -> Option<i64> {
        *self.active_domain_id.read().await
    }

    /// Check if a domain is connected
    pub async fn is_domain_connected(&self, domain_id: i64) -> bool {
        self.clients.read().await.contains_key(&domain_id)
    }

    /// Get count of connected domains
    pub async fn connected_domains_count(&self) -> usize {
        self.clients.read().await.len()
    }
}
