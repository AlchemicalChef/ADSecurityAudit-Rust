//! Parallel query execution for large-scale AD environments
//! Provides efficient concurrent operations with progress tracking

use anyhow::Result;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{info, warn};

/// Progress update for long-running operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub operation: String,
    pub current: u32,
    pub total: u32,
    pub percentage: f32,
    pub message: String,
    pub elapsed_ms: u64,
    pub estimated_remaining_ms: Option<u64>,
}

/// A sender for progress updates to the UI
pub type ProgressSender = mpsc::Sender<ProgressUpdate>;
pub type ProgressReceiver = mpsc::Receiver<ProgressUpdate>;

/// Create a progress channel
pub fn progress_channel(buffer: usize) -> (ProgressSender, ProgressReceiver) {
    mpsc::channel(buffer)
}

/// Execution statistics for performance monitoring
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionStats {
    pub total_operations: u32,
    pub successful: u32,
    pub failed: u32,
    pub total_duration_ms: u64,
    pub avg_operation_ms: f64,
    pub parallel_efficiency: f64,
    pub last_execution: Option<String>,
}

/// Configuration for parallel execution
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Maximum concurrent operations
    pub max_concurrency: usize,
    /// Timeout per operation
    pub operation_timeout: Duration,
    /// Whether to continue on individual failures
    pub continue_on_error: bool,
    /// Chunk size for batched operations
    pub batch_size: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 5,
            operation_timeout: Duration::from_secs(60),
            continue_on_error: true,
            batch_size: 100,
        }
    }
}

/// High-performance parallel executor for AD operations
pub struct ParallelExecutor {
    config: ParallelConfig,
    semaphore: Arc<Semaphore>,
    stats: RwLock<ExecutionStats>,
}

impl ParallelExecutor {
    pub fn new(config: ParallelConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrency));
        Self {
            config,
            semaphore,
            stats: RwLock::new(ExecutionStats::default()),
        }
    }

    /// Execute multiple async operations in parallel with controlled concurrency
    pub async fn execute_parallel<F, T, Fut>(
        &self,
        operations: Vec<F>,
        progress_tx: Option<ProgressSender>,
        operation_name: &str,
    ) -> Result<Vec<Result<T>>>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        let total = operations.len() as u32;
        let start = Instant::now();
        let completed = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let semaphore = self.semaphore.clone();
        let timeout = self.config.operation_timeout;

        let futures: Vec<_> = operations
            .into_iter()
            .map(|op| {
                let sem = semaphore.clone();
                let completed = completed.clone();
                let progress_tx = progress_tx.clone();
                let op_name = operation_name.to_string();
                let start_time = start;

                async move {
                    // Acquire semaphore permit
                    let _permit = sem.acquire().await.map_err(|e| anyhow::anyhow!("Semaphore error: {}", e))?;

                    // Execute with timeout
                    let result = tokio::time::timeout(timeout, op()).await;
                    
                    // Update progress
                    let current = completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    
                    if let Some(tx) = progress_tx {
                        let elapsed = start_time.elapsed();
                        let percentage = (current as f32 / total as f32) * 100.0;
                        let avg_time = elapsed.as_millis() as f64 / current as f64;
                        // Prevent integer overflow in remaining time calculation
                        let remaining = ((total - current) as f64 * avg_time)
                            .min(u64::MAX as f64) as u64;

                        let _ = tx.send(ProgressUpdate {
                            operation: op_name.clone(),
                            current,
                            total,
                            percentage,
                            message: format!("Processing {} of {}", current, total),
                            elapsed_ms: elapsed.as_millis() as u64,
                            estimated_remaining_ms: Some(remaining),
                        }).await;
                    }

                    match result {
                        Ok(r) => r,
                        Err(_) => Err(anyhow::anyhow!("Operation timed out")),
                    }
                }
            })
            .collect();

        let results = join_all(futures).await;

        // Update stats
        let elapsed = start.elapsed();
        let successful = results.iter().filter(|r| r.is_ok()).count() as u32;
        let failed = results.iter().filter(|r| r.is_err()).count() as u32;

        let mut stats = self.stats.write().await;
        stats.total_operations += total;
        stats.successful += successful;
        stats.failed += failed;
        stats.total_duration_ms += elapsed.as_millis() as u64;
        if stats.total_operations > 0 {
            stats.avg_operation_ms = stats.total_duration_ms as f64 / stats.total_operations as f64;
        }
        stats.last_execution = Some(chrono::Utc::now().to_rfc3339());

        // Calculate parallel efficiency (sequential time / parallel time)
        let elapsed_ms = elapsed.as_millis() as f64;
        if elapsed_ms > 0.0 && stats.avg_operation_ms > 0.0 {
            let sequential_estimate = stats.avg_operation_ms * total as f64;
            stats.parallel_efficiency = sequential_estimate / elapsed_ms;
        } else {
            stats.parallel_efficiency = 1.0;
        }

        info!(
            "Parallel execution complete: {}/{} successful in {:?} (efficiency: {:.2}x)",
            successful, total, elapsed, stats.parallel_efficiency
        );

        Ok(results)
    }

    /// Execute operations in batches with progress reporting
    pub async fn execute_batched<T, F, Fut>(
        &self,
        items: Vec<T>,
        operation: F,
        progress_tx: Option<ProgressSender>,
        operation_name: &str,
    ) -> Result<Vec<Result<T>>>
    where
        T: Clone + Send + 'static,
        F: Fn(Vec<T>) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<Vec<T>>> + Send,
    {
        let total_items = items.len();
        let batch_size = self.config.batch_size;
        let batches: Vec<Vec<T>> = items
            .chunks(batch_size)
            .map(|c| c.to_vec())
            .collect();

        let total_batches = batches.len() as u32;
        let start = Instant::now();

        let mut all_results = Vec::with_capacity(total_items);
        
        for (batch_idx, batch) in batches.into_iter().enumerate() {
            let batch_result = operation(batch).await;
            
            match batch_result {
                Ok(items) => {
                    all_results.extend(items.into_iter().map(Ok));
                }
                Err(e) => {
                    warn!("Batch {} failed: {}", batch_idx, e);
                    if !self.config.continue_on_error {
                        return Err(e);
                    }
                }
            }

            // Send progress update
            if let Some(ref tx) = progress_tx {
                let current = (batch_idx + 1) as u32;
                let elapsed = start.elapsed();
                let percentage = (current as f32 / total_batches as f32) * 100.0;

                let _ = tx.send(ProgressUpdate {
                    operation: operation_name.to_string(),
                    current,
                    total: total_batches,
                    percentage,
                    message: format!("Processed batch {} of {}", current, total_batches),
                    elapsed_ms: elapsed.as_millis() as u64,
                    estimated_remaining_ms: None,
                }).await;
            }
        }

        Ok(all_results)
    }

    /// Get execution statistics
    pub async fn stats(&self) -> ExecutionStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        *self.stats.write().await = ExecutionStats::default();
    }
    
    pub fn config(&self) -> &ParallelConfig {
        &self.config
    }
}

/// Run multiple independent audit operations in parallel
#[macro_export]
macro_rules! parallel_audits {
    ($($audit:expr),+ $(,)?) => {
        tokio::join!($($audit),+)
    };
}
