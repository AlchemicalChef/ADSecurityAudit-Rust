//! Advanced Caching System with TTL, Invalidation, and Cache Warming
//!
//! This module provides an intelligent caching layer with:
//! - Time-to-live (TTL) expiration
//! - Cache invalidation strategies
//! - Cache warming and predictive loading
//! - Statistics tracking
//! - Multi-domain support
//!
// Allow unused code - cache warming/eviction features for future optimization
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

/// Cache entry with metadata for tracking usage and expiration
///
/// Each cache entry contains:
/// - The actual cached data
/// - Timestamps for creation and expiration
/// - Access statistics (count and last access time)
/// - Size information for memory management
#[derive(Clone, Debug)]
pub struct CacheEntry<T> {
    /// The actual data stored in cache (serialized as JSON string)
    pub data: T,
    /// When this entry was first created
    pub created_at: DateTime<Utc>,
    /// When this entry should be considered stale and removed
    pub expires_at: DateTime<Utc>,
    /// How many times this entry has been accessed (thread-safe counter)
    pub access_count: Arc<AtomicU64>,
    /// When this entry was last accessed (used for LRU eviction)
    pub last_accessed: Arc<RwLock<DateTime<Utc>>>,
    /// Size of the data in bytes (for memory management)
    pub size_bytes: usize,
}

impl<T: Clone> CacheEntry<T> {
    /// Creates a new cache entry with the given data and TTL
    ///
    /// # Arguments
    /// * `data` - The data to cache
    /// * `ttl_seconds` - How long this entry should live before expiring
    /// * `size_bytes` - Size of the data in bytes
    ///
    /// # Returns
    /// A new CacheEntry with expiration set to now + ttl_seconds
    pub fn new(data: T, ttl_seconds: i64, size_bytes: usize) -> Self {
        let now = Utc::now();
        Self {
            data,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            access_count: Arc::new(AtomicU64::new(0)),
            last_accessed: Arc::new(RwLock::new(now)),
            size_bytes,
        }
    }

    /// Checks if this cache entry has expired
    ///
    /// # Returns
    /// `true` if current time is past the expiration time, `false` otherwise
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Records an access to this entry and returns the data
    ///
    /// This method:
    /// 1. Increments the access counter (for usage statistics)
    /// 2. Updates the last accessed timestamp (for LRU eviction)
    /// 3. Returns a clone of the cached data
    ///
    /// # Returns
    /// A clone of the cached data
    pub async fn access(&self) -> T {
        // Atomically increment access counter
        self.access_count.fetch_add(1, Ordering::Relaxed);
        // Update last access time (needs write lock)
        *self.last_accessed.write().await = Utc::now();
        // Return a clone of the data
        self.data.clone()
    }
}

/// Cache key with domain awareness for multi-domain support
///
/// Each cache key is unique per domain, allowing the same query type
/// to be cached separately for different domains.
///
/// # Example
/// ```
/// let key = CacheKey {
///     domain_id: Some(1),
///     key_type: CacheKeyType::PrivilegedAccounts,
/// };
/// // This caches privileged accounts specifically for domain 1
/// ```
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct CacheKey {
    /// Optional domain ID - None means global/cross-domain cache
    pub domain_id: Option<i64>,
    /// Type of data being cached
    pub key_type: CacheKeyType,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum CacheKeyType {
    PrivilegedAccounts,
    DomainSecurity,
    GpoAudit,
    DelegationAudit,
    TrustAudit,
    PermissionsAudit,
    GroupAudit,
    DAEquivalence,
    AdminSDHolder,
    KrbtgtInfo,
    UserSearch(String),
    UserDetails(String),
    Custom(String),
}

/// Cache invalidation strategy (reserved for future use)
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum InvalidationStrategy {
    /// Invalidate after time-to-live expires
    TTL,
    /// Invalidate on explicit command
    Manual,
    /// Invalidate on domain changes
    OnChange,
    /// Invalidate based on dependency chain
    Dependency(Vec<CacheKeyType>),
}

/// Cache statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheStatistics {
    pub total_entries: usize,
    pub total_size_bytes: usize,
    pub hit_count: u64,
    pub miss_count: u64,
    pub hit_rate: f64,
    pub eviction_count: u64,
    pub avg_entry_age_seconds: f64,
    pub most_accessed_keys: Vec<String>,
}

/// Advanced cache manager
pub struct AdvancedCache {
    /// Cache storage
    cache: Arc<DashMap<CacheKey, CacheEntry<String>>>,

    /// Hit/miss counters
    hit_count: Arc<AtomicU64>,
    miss_count: Arc<AtomicU64>,
    eviction_count: Arc<AtomicU64>,

    /// Configuration
    max_size_bytes: usize,
    default_ttl_seconds: i64,

    /// Cache warming tasks
    warming_enabled: Arc<RwLock<bool>>,
}

impl AdvancedCache {
    /// Create a new advanced cache
    pub fn new(max_size_bytes: usize, default_ttl_seconds: i64) -> Self {
        info!(
            "Initializing advanced cache (max_size: {} MB, default_ttl: {}s)",
            max_size_bytes / 1024 / 1024,
            default_ttl_seconds
        );

        Self {
            cache: Arc::new(DashMap::new()),
            hit_count: Arc::new(AtomicU64::new(0)),
            miss_count: Arc::new(AtomicU64::new(0)),
            eviction_count: Arc::new(AtomicU64::new(0)),
            max_size_bytes,
            default_ttl_seconds,
            warming_enabled: Arc::new(RwLock::new(true)),
        }
    }

    /// Retrieves a value from the cache
    ///
    /// This method performs the following steps:
    /// 1. Checks if the key exists in cache
    /// 2. Validates the entry hasn't expired
    /// 3. Records the access for statistics
    /// 4. Deserializes and returns the data
    ///
    /// # Arguments
    /// * `key` - The cache key to look up
    ///
    /// # Returns
    /// * `Some(T)` - If the key exists, isn't expired, and deserializes successfully
    /// * `None` - If the key doesn't exist, is expired, or deserialization fails
    ///
    /// # Type Parameters
    /// * `T` - The type to deserialize the cached data into (must implement Deserialize)
    ///
    /// # Examples
    /// ```
    /// let user_list: Option<Vec<User>> = cache.get(&key).await;
    /// ```
    pub async fn get<T>(&self, key: &CacheKey) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        debug!("Cache lookup: {:?}", key);

        // Check if key exists in cache
        if let Some(entry) = self.cache.get(key) {
            // Validate entry hasn't expired
            if entry.is_expired() {
                debug!("Cache entry expired: {:?}", key);
                // Drop the reference before removing to avoid deadlock
                drop(entry);
                // Remove expired entry
                self.cache.remove(key);
                // Record as cache miss
                self.miss_count.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Record access and get data
            let data = entry.access().await;
            // Record cache hit
            self.hit_count.fetch_add(1, Ordering::Relaxed);

            // Deserialize JSON string to requested type
            match serde_json::from_str::<T>(&data) {
                Ok(value) => {
                    debug!("Cache hit: {:?}", key);
                    Some(value)
                }
                Err(e) => {
                    // Data exists but can't be deserialized - corrupted or type mismatch
                    warn!("Failed to deserialize cached value: {}", e);
                    None
                }
            }
        } else {
            // Key not found in cache
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            debug!("Cache miss: {:?}", key);
            None
        }
    }

    /// Stores a value in the cache with optional TTL override
    ///
    /// This method:
    /// 1. Serializes the value to JSON
    /// 2. Checks if cache needs eviction to make space
    /// 3. Creates a cache entry with TTL
    /// 4. Stores the entry in the cache
    ///
    /// # Arguments
    /// * `key` - The cache key to store under
    /// * `value` - The value to cache (must be serializable)
    /// * `ttl_seconds` - Optional TTL override (uses default if None)
    ///
    /// # Returns
    /// * `Ok(())` - If caching succeeds
    /// * `Err` - If serialization fails
    ///
    /// # Examples
    /// ```
    /// // Cache with default TTL
    /// cache.set(key, &user_data, None).await?;
    ///
    /// // Cache with custom TTL of 1 hour
    /// cache.set(key, &user_data, Some(3600)).await?;
    /// ```
    pub async fn set<T>(&self, key: CacheKey, value: &T, ttl_seconds: Option<i64>) -> Result<()>
    where
        T: Serialize,
    {
        // Serialize value to JSON string for storage
        let json = serde_json::to_string(value)?;
        let size = json.len();
        // Use provided TTL or fall back to default
        let ttl = ttl_seconds.unwrap_or(self.default_ttl_seconds);

        // Ensure we have space in cache before adding
        self.evict_if_needed(size).await;

        // Create cache entry with metadata
        let entry = CacheEntry::new(json, ttl, size);
        // Insert into cache (overwrites if key exists)
        self.cache.insert(key.clone(), entry);

        debug!("Cached entry: {:?} (size: {} bytes, ttl: {}s)", key, size, ttl);
        Ok(())
    }

    /// Invalidate cache entries by key
    pub fn invalidate(&self, key: &CacheKey) {
        if self.cache.remove(key).is_some() {
            debug!("Invalidated cache entry: {:?}", key);
        }
    }

    /// Invalidate all cache entries for a domain
    pub fn invalidate_domain(&self, domain_id: i64) {
        let mut removed_count = 0;
        self.cache.retain(|k, _| {
            if k.domain_id == Some(domain_id) {
                removed_count += 1;
                false
            } else {
                true
            }
        });
        info!("Invalidated {} cache entries for domain {}", removed_count, domain_id);
    }

    /// Invalidate all cache entries
    pub fn invalidate_all(&self) {
        let count = self.cache.len();
        self.cache.clear();
        info!("Invalidated all {} cache entries", count);
    }

    /// Invalidate expired entries
    pub async fn cleanup_expired(&self) {
        let mut removed_count = 0;
        self.cache.retain(|_, v| {
            if v.is_expired() {
                removed_count += 1;
                false
            } else {
                true
            }
        });
        if removed_count > 0 {
            debug!("Cleaned up {} expired cache entries", removed_count);
        }
    }

    /// Evicts least-recently-used entries if cache size limit is exceeded
    ///
    /// This implements an LRU (Least Recently Used) eviction policy:
    /// 1. Checks if adding new entry would exceed max cache size
    /// 2. If so, collects all entries with their access counts
    /// 3. Sorts by access count (least accessed first)
    /// 4. Removes entries until enough space is freed
    ///
    /// # Arguments
    /// * `incoming_size` - Size of the entry about to be added
    ///
    /// # Algorithm
    /// The eviction uses access count as a proxy for LRU:
    /// - Entries with fewer accesses are evicted first
    /// - This prevents frequently accessed data from being removed
    /// - Balances between recency and frequency of access
    async fn evict_if_needed(&self, incoming_size: usize) {
        let current_size = self.get_total_size();

        // Check if eviction is needed
        if current_size + incoming_size > self.max_size_bytes {
            info!(
                "Cache size limit reached ({} / {} bytes), evicting entries",
                current_size, self.max_size_bytes
            );

            // Collect all entries with their access statistics
            // We need to do this in a separate step to avoid holding locks
            let mut entries: Vec<_> = self.cache.iter()
                .map(|entry| {
                    let access_count = entry.value().access_count.load(Ordering::Relaxed);
                    (entry.key().clone(), access_count, entry.value().size_bytes)
                })
                .collect();

            // Sort by access count (ascending) - least accessed entries first
            entries.sort_by_key(|(_, count, _)| *count);

            // Calculate how much space we need to free
            let needed_space = current_size + incoming_size - self.max_size_bytes;
            let mut freed_space = 0;
            let mut evicted = 0;

            // Remove entries until we've freed enough space
            for (key, _, size) in entries {
                if freed_space >= needed_space {
                    break;
                }
                self.cache.remove(&key);
                freed_space += size;
                evicted += 1;
                self.eviction_count.fetch_add(1, Ordering::Relaxed);
            }

            info!("Evicted {} entries, freed {} bytes", evicted, freed_space);
        }
    }

    /// Get total cache size in bytes
    fn get_total_size(&self) -> usize {
        self.cache.iter().map(|entry| entry.value().size_bytes).sum()
    }

    /// Get cache statistics
    pub async fn get_statistics(&self) -> CacheStatistics {
        let hits = self.hit_count.load(Ordering::Relaxed);
        let misses = self.miss_count.load(Ordering::Relaxed);
        let total_requests = hits + misses;

        let hit_rate = if total_requests > 0 {
            (hits as f64) / (total_requests as f64)
        } else {
            0.0
        };

        // Calculate average entry age
        let now = Utc::now();
        let mut total_age_seconds = 0i64;
        let entry_count = self.cache.len();

        if entry_count > 0 {
            for entry in self.cache.iter() {
                let age = now.signed_duration_since(entry.value().created_at);
                total_age_seconds += age.num_seconds();
            }
        }

        let avg_entry_age_seconds = if entry_count > 0 {
            (total_age_seconds as f64) / (entry_count as f64)
        } else {
            0.0
        };

        // Find most accessed keys
        let mut access_counts: Vec<_> = self.cache.iter()
            .map(|entry| {
                let key_str = format!("{:?}", entry.key());
                let count = entry.value().access_count.load(Ordering::Relaxed);
                (key_str, count)
            })
            .collect();

        access_counts.sort_by(|a, b| b.1.cmp(&a.1));
        let most_accessed_keys = access_counts.into_iter()
            .take(10)
            .map(|(key, _)| key)
            .collect();

        CacheStatistics {
            total_entries: entry_count,
            total_size_bytes: self.get_total_size(),
            hit_count: hits,
            miss_count: misses,
            hit_rate,
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
            avg_entry_age_seconds,
            most_accessed_keys,
        }
    }

    /// Enable cache warming
    pub async fn enable_warming(&self) {
        *self.warming_enabled.write().await = true;
        info!("Cache warming enabled");
    }

    /// Disable cache warming
    pub async fn disable_warming(&self) {
        *self.warming_enabled.write().await = false;
        info!("Cache warming disabled");
    }

    /// Check if cache warming is enabled
    pub async fn is_warming_enabled(&self) -> bool {
        *self.warming_enabled.read().await
    }

    /// Pre-populates cache with commonly accessed data (cache warming)
    ///
    /// Cache warming improves performance by loading frequently accessed data
    /// before it's requested. This is useful on application startup or after
    /// cache invalidation.
    ///
    /// # Arguments
    /// * `keys` - List of cache keys to warm
    /// * `fetch_fn` - Async function that fetches data for a given key
    ///
    /// # Returns
    /// * `Ok(())` - If warming completes (individual failures are logged but not returned)
    ///
    /// # Algorithm
    /// 1. Checks if warming is enabled (can be disabled for testing)
    /// 2. For each key:
    ///    - Skips if already cached and fresh
    ///    - Fetches data using provided function
    ///    - Stores in cache with default TTL
    /// 3. Logs success/failure for each key
    ///
    /// # Examples
    /// ```
    /// let keys = vec![
    ///     CacheKey { domain_id: Some(1), key_type: CacheKeyType::PrivilegedAccounts },
    ///     CacheKey { domain_id: Some(1), key_type: CacheKeyType::DomainSecurity },
    /// ];
    ///
    /// cache.warm_cache(keys, |key| async move {
    ///     fetch_data_for_key(key).await
    /// }).await?;
    /// ```
    pub async fn warm_cache<F, Fut, T>(&self, keys: Vec<CacheKey>, fetch_fn: F) -> Result<()>
    where
        F: Fn(CacheKey) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
        T: Serialize,
    {
        // Check if warming is enabled (can be disabled for testing/debugging)
        if !self.is_warming_enabled().await {
            debug!("Cache warming is disabled");
            return Ok(());
        }

        info!("Warming cache with {} keys", keys.len());

        // Iterate through all keys to warm
        for key in keys {
            // Skip if already cached and not expired (no need to re-fetch)
            if let Some(entry) = self.cache.get(&key) {
                if !entry.is_expired() {
                    debug!("Skipping warm for already cached key: {:?}", key);
                    continue;
                }
            }

            // Fetch data using provided async function
            match fetch_fn(key.clone()).await {
                Ok(data) => {
                    // Store in cache with default TTL
                    if let Err(e) = self.set(key.clone(), &data, None).await {
                        warn!("Failed to warm cache for {:?}: {}", key, e);
                    } else {
                        debug!("Warmed cache for {:?}", key);
                    }
                }
                Err(e) => {
                    // Log but don't fail the entire warming process
                    warn!("Failed to fetch data for warming {:?}: {}", key, e);
                }
            }
        }

        info!("Cache warming completed");
        Ok(())
    }

    /// Generates predictions for cache preloading based on access patterns
    ///
    /// This implements a simple machine learning-inspired algorithm:
    /// 1. Analyzes which cache entries are frequently accessed
    /// 2. Predicts related data that users are likely to request next
    /// 3. Returns keys that should be preloaded
    ///
    /// # Returns
    /// Vector of cache keys predicted to be accessed soon
    ///
    /// # Algorithm
    /// The prediction works by:
    /// - Finding frequently accessed entries (>5 accesses)
    /// - For each frequent entry, predicting related queries
    /// - Example: If PrivilegedAccounts is accessed often,
    ///   predict GroupAudit and DAEquivalence will be needed
    ///
    /// # Use Case
    /// Call this method periodically (e.g., every 5 minutes) to:
    /// 1. Get list of predicted keys
    /// 2. Use warm_cache() to preload them
    /// 3. Improve cache hit rate for subsequent requests
    ///
    /// # Examples
    /// ```
    /// // Get predictions
    /// let predicted_keys = cache.predictive_load().await;
    ///
    /// // Preload predicted data
    /// cache.warm_cache(predicted_keys, fetch_fn).await?;
    /// ```
    pub async fn predictive_load(&self) -> Vec<CacheKey> {
        let mut predictions = Vec::new();

        // Step 1: Analyze access patterns to find frequently accessed data
        let mut patterns: Vec<_> = self.cache.iter()
            .filter_map(|entry| {
                let count = entry.value().access_count.load(Ordering::Relaxed);
                // Only consider entries accessed more than 5 times
                if count > 5 {
                    Some((entry.key().clone(), count))
                } else {
                    None
                }
            })
            .collect();

        // Sort by access count (most accessed first)
        patterns.sort_by(|a, b| b.1.cmp(&a.1));

        // Step 2: Predict related keys based on access patterns
        // Take top 20 most accessed entries
        for (key, _) in patterns.into_iter().take(20) {
            // Only predict for domain-specific data
            if let Some(domain_id) = key.domain_id {
                match key.key_type {
                    // If privileged accounts are frequently checked,
                    // user likely wants to see groups and DA equivalents
                    CacheKeyType::PrivilegedAccounts => {
                        predictions.push(CacheKey {
                            domain_id: Some(domain_id),
                            key_type: CacheKeyType::GroupAudit,
                        });
                        predictions.push(CacheKey {
                            domain_id: Some(domain_id),
                            key_type: CacheKeyType::DAEquivalence,
                        });
                    }
                    // If domain security is checked,
                    // user likely wants GPO and permissions audits
                    CacheKeyType::DomainSecurity => {
                        predictions.push(CacheKey {
                            domain_id: Some(domain_id),
                            key_type: CacheKeyType::GpoAudit,
                        });
                        predictions.push(CacheKey {
                            domain_id: Some(domain_id),
                            key_type: CacheKeyType::PermissionsAudit,
                        });
                    }
                    // Add more prediction rules as patterns are discovered
                    _ => {}
                }
            }
        }

        // Remove duplicates
        predictions.dedup();
        debug!("Predicted {} keys for preloading", predictions.len());
        predictions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_cache_operations() {
        let cache = AdvancedCache::new(1024 * 1024, 300);

        let key = CacheKey {
            domain_id: Some(1),
            key_type: CacheKeyType::PrivilegedAccounts,
        };

        // Test miss
        let result: Option<String> = cache.get(&key).await;
        assert!(result.is_none());

        // Test set and hit
        cache.set(key.clone(), &"test data".to_string(), None).await.unwrap();
        let result: Option<String> = cache.get(&key).await;
        assert_eq!(result, Some("test data".to_string()));

        // Test invalidation
        cache.invalidate(&key);
        let result: Option<String> = cache.get(&key).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_statistics() {
        let cache = AdvancedCache::new(1024 * 1024, 300);

        let key = CacheKey {
            domain_id: Some(1),
            key_type: CacheKeyType::DomainSecurity,
        };

        // Generate some cache activity
        let _: Option<String> = cache.get(&key).await; // miss
        cache.set(key.clone(), &"data".to_string(), None).await.unwrap();
        let _: Option<String> = cache.get(&key).await; // hit

        let stats = cache.get_statistics().await;
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 1);
        assert_eq!(stats.total_entries, 1);
    }
}
