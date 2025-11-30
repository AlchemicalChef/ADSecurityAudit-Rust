//! SQLite database for persistent storage of domain configurations,
//! scheduled audits, and historical trends

use anyhow::{anyhow, Result};
use rusqlite::{Connection, params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use argon2::{Argon2, password_hash::SaltString};
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose};

/// Domain configuration stored in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub id: Option<i64>,
    pub name: String,
    pub server: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,  // Encrypted in database
    pub base_dn: String,
    pub use_ldaps: bool,
    pub is_active: bool,
    pub last_connected: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database manager with connection pooling
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Create a new database connection
    pub fn new(db_path: Option<PathBuf>) -> Result<Self> {
        let path = db_path.unwrap_or_else(|| {
            let mut p = dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."));
            p.push("IRP");
            std::fs::create_dir_all(&p).ok();
            p.push("irp.db");
            p
        });

        info!("Opening database at: {:?}", path);

        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        // Set busy timeout to prevent hangs when database is locked (5 seconds)
        conn.pragma_update(None, "busy_timeout", "5000")?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.initialize_schema()?;

        Ok(db)
    }

    /// Initialize database schema
    fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        // Domain configurations table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                server TEXT NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                base_dn TEXT NOT NULL,
                use_ldaps BOOLEAN NOT NULL DEFAULT 1,
                is_active BOOLEAN NOT NULL DEFAULT 0,
                last_connected TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        // Create indices for performance
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_domains_active ON domains(is_active)",
            [],
        )?;

        info!("Database schema initialized successfully");
        Ok(())
    }

    /// Save or update domain configuration
    pub fn save_domain(&self, domain: &DomainConfig) -> Result<i64> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        let now = Utc::now().to_rfc3339();
        let encrypted_password = self.encrypt_password(&domain.password)?;

        if let Some(id) = domain.id {
            // Update existing domain
            conn.execute(
                "UPDATE domains SET
                    name = ?1, server = ?2, username = ?3, password_encrypted = ?4,
                    base_dn = ?5, use_ldaps = ?6, is_active = ?7,
                    last_connected = ?8, updated_at = ?9
                WHERE id = ?10",
                params![
                    domain.name,
                    domain.server,
                    domain.username,
                    encrypted_password,
                    domain.base_dn,
                    domain.use_ldaps,
                    domain.is_active,
                    domain.last_connected.map(|dt| dt.to_rfc3339()),
                    now,
                    id
                ],
            )?;
            Ok(id)
        } else {
            // Insert new domain
            let created_at = domain.created_at.to_rfc3339();
            conn.execute(
                "INSERT INTO domains
                    (name, server, username, password_encrypted, base_dn, use_ldaps, is_active, last_connected, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    domain.name,
                    domain.server,
                    domain.username,
                    encrypted_password,
                    domain.base_dn,
                    domain.use_ldaps,
                    domain.is_active,
                    domain.last_connected.map(|dt| dt.to_rfc3339()),
                    created_at,
                    now
                ],
            )?;
            Ok(conn.last_insert_rowid())
        }
    }

    /// Get domain configuration by ID
    pub fn get_domain(&self, id: i64) -> Result<Option<DomainConfig>> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        let result = conn.query_row(
            "SELECT id, name, server, username, password_encrypted, base_dn, use_ldaps, is_active, last_connected, created_at, updated_at
            FROM domains WHERE id = ?1",
            params![id],
            |row| {
                let encrypted_password: String = row.get(4)?;
                let password = self.decrypt_password(&encrypted_password)
                    .map_err(|e| {
                        error!("Password decryption failed for domain ID {}: {}", id, e);
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Password decryption failed: {}", e)
                            ))
                        )
                    })?;

                Ok(DomainConfig {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    server: row.get(2)?,
                    username: row.get(3)?,
                    password,
                    base_dn: row.get(5)?,
                    use_ldaps: row.get(6)?,
                    is_active: row.get(7)?,
                    last_connected: row.get::<_, Option<String>>(8)?
                        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Utc)),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            },
        ).optional()?;

        Ok(result)
    }

    /// Get domain configuration by name
    pub fn get_domain_by_name(&self, name: &str) -> Result<Option<DomainConfig>> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        let result = conn.query_row(
            "SELECT id, name, server, username, password_encrypted, base_dn, use_ldaps, is_active, last_connected, created_at, updated_at
            FROM domains WHERE name = ?1",
            params![name],
            |row| {
                let encrypted_password: String = row.get(4)?;
                let password = self.decrypt_password(&encrypted_password)
                    .map_err(|e| {
                        error!("Password decryption failed for domain '{}': {}", name, e);
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Password decryption failed: {}", e)
                            ))
                        )
                    })?;

                Ok(DomainConfig {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    server: row.get(2)?,
                    username: row.get(3)?,
                    password,
                    base_dn: row.get(5)?,
                    use_ldaps: row.get(6)?,
                    is_active: row.get(7)?,
                    last_connected: row.get::<_, Option<String>>(8)?
                        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Utc)),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            },
        ).optional()?;

        Ok(result)
    }

    /// Get all domain configurations
    pub fn get_all_domains(&self) -> Result<Vec<DomainConfig>> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        let mut stmt = conn.prepare(
            "SELECT id, name, server, username, password_encrypted, base_dn, use_ldaps, is_active, last_connected, created_at, updated_at
            FROM domains ORDER BY name"
        )?;

        let rows = stmt.query_map([], |row| {
            let encrypted_password: String = row.get(4)?;
            let password = self.decrypt_password(&encrypted_password)
                .map_err(|e| {
                    let domain_name: String = row.get(1).unwrap_or_else(|_| "unknown".to_string());
                    error!("Password decryption failed for domain '{}': {}", domain_name, e);
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Password decryption failed: {}", e)
                        ))
                    )
                })?;

            Ok(DomainConfig {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                server: row.get(2)?,
                username: row.get(3)?,
                password,
                base_dn: row.get(5)?,
                use_ldaps: row.get(6)?,
                is_active: row.get(7)?,
                last_connected: row.get::<_, Option<String>>(8)?
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                    .unwrap()
                    .with_timezone(&Utc),
            })
        })?;

        let mut domains = Vec::new();
        for row in rows {
            domains.push(row?);
        }

        Ok(domains)
    }

    /// Get active domain
    pub fn get_active_domain(&self) -> Result<Option<DomainConfig>> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        let result = conn.query_row(
            "SELECT id, name, server, username, password_encrypted, base_dn, use_ldaps, is_active, last_connected, created_at, updated_at
            FROM domains WHERE is_active = 1 LIMIT 1",
            [],
            |row| {
                let encrypted_password: String = row.get(4)?;
                let password = self.decrypt_password(&encrypted_password)
                    .map_err(|e| {
                        error!("Password decryption failed for active domain: {}", e);
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Password decryption failed: {}", e)
                            ))
                        )
                    })?;

                Ok(DomainConfig {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    server: row.get(2)?,
                    username: row.get(3)?,
                    password,
                    base_dn: row.get(5)?,
                    use_ldaps: row.get(6)?,
                    is_active: row.get(7)?,
                    last_connected: row.get::<_, Option<String>>(8)?
                        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Utc)),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            },
        ).optional()?;

        Ok(result)
    }

    /// Set active domain (deactivates all others)
    pub fn set_active_domain(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        // Use a single atomic UPDATE to avoid race conditions
        // This sets is_active = 1 for the specified domain and 0 for all others
        conn.execute(
            "UPDATE domains SET is_active = CASE WHEN id = ?1 THEN 1 ELSE 0 END",
            params![id]
        )?;

        Ok(())
    }

    /// Delete domain configuration
    pub fn delete_domain(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        conn.execute("DELETE FROM domains WHERE id = ?1", params![id])?;

        Ok(())
    }

    /// Clear all domains from the database
    pub fn clear_all_domains(&self) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        conn.execute("DELETE FROM domains", [])?;

        info!("All domains cleared from database");
        Ok(())
    }

    /// Update last connected timestamp
    pub fn update_last_connected(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow!("Failed to acquire database lock: {}", e))?;

        let now = Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE domains SET last_connected = ?1, updated_at = ?2 WHERE id = ?3",
            params![now, now, id],
        )?;

        Ok(())
    }

    /// Get machine-specific identifier for key derivation
    fn get_machine_identifier(&self) -> Result<String> {
        // Use a combination of machine-specific data
        // In production, consider using hardware IDs, MAC addresses, etc.
        use std::env;

        let mut identifier = String::new();

        // Use hostname
        if let Ok(hostname) = hostname::get() {
            identifier.push_str(&hostname.to_string_lossy());
        }

        // Use username
        if let Ok(username) = env::var("USER").or_else(|_| env::var("USERNAME")) {
            identifier.push_str(&username);
        }

        // If we couldn't get any machine-specific data, use a fallback
        if identifier.is_empty() {
            warn!("Could not determine machine identifier, using fallback");
            identifier = "IRP_FALLBACK_IDENTIFIER".to_string();
        }

        Ok(identifier)
    }

    /// Encrypt password using AES-256-GCM with machine-specific key derivation
    fn encrypt_password(&self, password: &str) -> Result<String> {
        // 1. Get machine-specific identifier
        let machine_id = self.get_machine_identifier()?;

        // 2. Generate a random salt for key derivation
        let salt = SaltString::generate(&mut OsRng);

        // 3. Derive encryption key using Argon2
        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(machine_id.as_bytes(), salt.as_str().as_bytes(), &mut key_bytes)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

        // 4. Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // 5. Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 6. Encrypt the password
        let ciphertext = cipher
            .encrypt(nonce, password.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // 7. Combine salt, nonce, and ciphertext for storage
        // Format: base64(salt):base64(nonce):base64(ciphertext)
        let encrypted = format!(
            "{}:{}:{}",
            general_purpose::STANDARD.encode(salt.as_str()),
            general_purpose::STANDARD.encode(nonce),
            general_purpose::STANDARD.encode(&ciphertext)
        );

        Ok(encrypted)
    }

    /// Decrypt password using AES-256-GCM
    fn decrypt_password(&self, encrypted: &str) -> Result<String> {
        // 1. Parse the encrypted string
        let parts: Vec<&str> = encrypted.split(':').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid encrypted password format"));
        }

        let salt_str = general_purpose::STANDARD.decode(parts[0])
            .map_err(|e| anyhow!("Failed to decode salt: {}", e))?;
        let salt = SaltString::from_b64(&String::from_utf8(salt_str)?)
            .map_err(|e| anyhow!("Invalid salt format: {}", e))?;

        let nonce_bytes = general_purpose::STANDARD.decode(parts[1])
            .map_err(|e| anyhow!("Failed to decode nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = general_purpose::STANDARD.decode(parts[2])
            .map_err(|e| anyhow!("Failed to decode ciphertext: {}", e))?;

        // 2. Get machine-specific identifier
        let machine_id = self.get_machine_identifier()?;

        // 3. Derive the same encryption key using Argon2
        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(machine_id.as_bytes(), salt.as_str().as_bytes(), &mut key_bytes)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

        // 4. Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // 5. Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        // 6. Convert to string
        String::from_utf8(plaintext)
            .map_err(|e| anyhow!("Invalid UTF-8 in decrypted password: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_operations() {
        let db = Database::new(None).unwrap();

        let domain = DomainConfig {
            id: None,
            name: "test.local".to_string(),
            server: "dc.test.local:389".to_string(),
            username: "admin".to_string(),
            password: "password123".to_string(),
            base_dn: "DC=test,DC=local".to_string(),
            use_ldaps: false,
            is_active: false,
            last_connected: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Test save
        let id = db.save_domain(&domain).unwrap();
        assert!(id > 0);

        // Test get by ID
        let retrieved = db.get_domain(id).unwrap().unwrap();
        assert_eq!(retrieved.name, "test.local");
        assert_eq!(retrieved.password, "password123");

        // Test get by name
        let by_name = db.get_domain_by_name("test.local").unwrap().unwrap();
        assert_eq!(by_name.id, Some(id));

        // Test get all
        let all = db.get_all_domains().unwrap();
        assert!(all.len() >= 1);

        // Test set active
        db.set_active_domain(id).unwrap();
        let active = db.get_active_domain().unwrap().unwrap();
        assert_eq!(active.id, Some(id));

        // Test delete
        db.delete_domain(id).unwrap();
        let deleted = db.get_domain(id).unwrap();
        assert!(deleted.is_none());
    }

    #[test]
    fn test_password_encryption() {
        let db = Database::new(None).unwrap();

        let password = "my_secret_password";
        let encrypted = db.encrypt_password(password).unwrap();
        let decrypted = db.decrypt_password(&encrypted).unwrap();

        assert_eq!(password, decrypted);
        assert_ne!(password, encrypted);
    }
}
