//! Query result caching with TTL for improved performance.
//! Reduces load on Active Directory by caching frequently accessed data.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// A cached value with expiration tracking
struct CachedValue<V> {
    value: V,
    cached_at: Instant,
    ttl: Duration,
}

impl<V> CachedValue<V> {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// High-performance concurrent cache with TTL
pub(crate) struct QueryCache<K, V> 
where 
    K: Eq + Hash + Clone,
    V: Clone,
{
    cache: DashMap<K, CachedValue<V>>,
    default_ttl: Duration,
    stats: Arc<CacheStats>,
}

#[derive(Debug, Default)]
pub(crate) struct CacheStats {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

impl CacheStats {
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn misses(&self) -> u64 {
        self.misses.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub(crate) fn evictions(&self) -> u64 {
        self.evictions.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn hit_rate(&self) -> f64 {
        let hits = self.hits() as f64;
        let total = hits + self.misses() as f64;
        if total > 0.0 { hits / total } else { 0.0 }
    }
}

impl<K, V> QueryCache<K, V> 
where 
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Create a new cache with default TTL
    pub(crate) fn new(default_ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl,
            stats: Arc::new(CacheStats::default()),
        }
    }

    /// Get a value from the cache
    pub(crate) fn get(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.cache.get(key) {
            if !entry.is_expired() {
                self.stats.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Some(entry.value.clone());
            }
            // Remove expired entry
            drop(entry);
            self.cache.remove(key);
        }
        self.stats.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }

    /// Insert a value with default TTL
    pub(crate) fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Insert a value with custom TTL
    pub(crate) fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        self.cache.insert(key, CachedValue {
            value,
            cached_at: Instant::now(),
            ttl,
        });
    }

    /// Remove a specific key
    pub(crate) fn invalidate(&self, key: &K) {
        self.cache.remove(key);
        self.stats.evictions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Clear all cached values
    pub(crate) fn clear(&self) {
        let count = self.cache.len();
        self.cache.clear();
        self.stats.evictions.fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
        info!("Cache cleared: {} entries removed", count);
    }

    /// Remove expired entries
    #[allow(dead_code)]
    pub(crate) fn cleanup_expired(&self) {
        let before = self.cache.len();
        self.cache.retain(|_, v| !v.is_expired());
        let removed = before.saturating_sub(self.cache.len());
        if removed > 0 {
            self.stats.evictions.fetch_add(removed as u64, std::sync::atomic::Ordering::Relaxed);
            debug!("Cache cleanup: {} expired entries removed", removed);
        }
    }

    /// Get cache statistics
    pub(crate) fn stats(&self) -> Arc<CacheStats> {
        self.stats.clone()
    }

    /// Get current cache size
    pub(crate) fn len(&self) -> usize {
        self.cache.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Cache key types for different query types
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum CacheKey {
    UserSearch(String),
    UserDetails(String),
    GroupMembers(String),
    PrivilegedAccounts,
    DomainSecurityAudit,
    GpoAudit,
    DelegationAudit,
    TrustAudit,
    PermissionsAudit,
    GroupAudit,
    DAEquivalenceAudit,
    AdminSDHolder,
    KrbtgtAnalysis,
}

/// Application-wide cache manager
pub(crate) struct CacheManager {
    /// Cache for serializable query results
    pub results: QueryCache<CacheKey, String>,
    /// Short TTL cache for frequently changing data
    pub realtime: QueryCache<CacheKey, String>,
}

impl CacheManager {
    pub(crate) fn new() -> Self {
        Self {
            // 5 minute TTL for audit results
            results: QueryCache::new(Duration::from_secs(300)),
            // 30 second TTL for realtime data
            realtime: QueryCache::new(Duration::from_secs(30)),
        }
    }

    /// Invalidate all audit caches (call after modifications)
    pub(crate) fn invalidate_audits(&self) {
        self.results.invalidate(&CacheKey::PrivilegedAccounts);
        self.results.invalidate(&CacheKey::DomainSecurityAudit);
        self.results.invalidate(&CacheKey::GpoAudit);
        self.results.invalidate(&CacheKey::DelegationAudit);
        self.results.invalidate(&CacheKey::TrustAudit);
        self.results.invalidate(&CacheKey::PermissionsAudit);
        self.results.invalidate(&CacheKey::GroupAudit);
        self.results.invalidate(&CacheKey::DAEquivalenceAudit);
        self.results.invalidate(&CacheKey::AdminSDHolder);
        self.results.invalidate(&CacheKey::KrbtgtAnalysis);
        info!("Audit caches invalidated");
    }

    pub(crate) fn combined_stats(&self) -> CombinedCacheStats {
        let results_stats = self.results.stats();
        let realtime_stats = self.realtime.stats();
        
        CombinedCacheStats {
            results_size: self.results.len(),
            results_hits: results_stats.hits(),
            results_misses: results_stats.misses(),
            results_hit_rate: results_stats.hit_rate(),
            realtime_size: self.realtime.len(),
            realtime_hits: realtime_stats.hits(),
            realtime_misses: realtime_stats.misses(),
            realtime_hit_rate: realtime_stats.hit_rate(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CombinedCacheStats {
    pub results_size: usize,
    pub results_hits: u64,
    pub results_misses: u64,
    pub results_hit_rate: f64,
    pub realtime_size: usize,
    pub realtime_hits: u64,
    pub realtime_misses: u64,
    pub realtime_hit_rate: f64,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}
