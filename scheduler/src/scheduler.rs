//! Central scheduler orchestrator.
//! Manages worker pools, job dispatch, NUMA-aware scheduling,
//! and recurring/cron-style jobs.

use crate::job::{Job, JobId, JobResult, JobState};
use crate::queue::ConcurrentJobQueue;
use crossbeam::channel;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Scheduler statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct SchedulerStats {
    /// Total jobs queued.
    pub total_queued: u64,
    /// Total jobs started.
    pub total_started: u64,
    /// Total jobs completed successfully.
    pub total_completed: u64,
    /// Total jobs failed.
    pub total_failed: u64,
    /// Total jobs cancelled.
    pub total_cancelled: u64,
    /// Currently running jobs.
    pub running_count: usize,
    /// Queued jobs awaiting execution.
    pub queued_count: usize,
}

/// Configuration for the scheduler.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Number of worker threads (0 = use CPU count).
    pub worker_count: usize,
    /// Maximum queue depth per priority level.
    pub max_queue_depth: usize,
    /// Worker idle timeout before parking.
    pub idle_timeout_ms: u64,
    /// Enable NUMA-aware scheduling (Linux only).
    pub enable_numa: bool,
    /// Enable job dependency resolution.
    pub enable_dependencies: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            worker_count: num_cpus::get(),
            max_queue_depth: 10_000,
            idle_timeout_ms: 100,
            enable_numa: false,
            enable_dependencies: true,
        }
    }
}

/// The UCOP-X job scheduler.
/// Distributes work across a pool of worker threads.
pub struct Scheduler {
    config: SchedulerConfig,
    queue: Arc<ConcurrentJobQueue>,
    running: Arc<AtomicBool>,
    worker_handles: Vec<thread::JoinHandle<()>>,
    stats: Arc<std::sync::Mutex<SchedulerStats>>,
    job_results: Arc<std::sync::Mutex<HashMap<JobId, JobResult>>>,
    completed_jobs: Arc<std::sync::Mutex<Vec<JobId>>>,
    shutdown_tx: channel::Sender<()>,
    shutdown_rx: channel::Receiver<()>,
}

impl Scheduler {
    /// Create a new scheduler with default configuration.
    pub fn new() -> Self {
        Self::with_config(SchedulerConfig::default())
    }

    /// Create a new scheduler with custom configuration.
    pub fn with_config(config: SchedulerConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = channel::bounded(1);
        Self {
            queue: Arc::new(ConcurrentJobQueue::new()),
            running: Arc::new(AtomicBool::new(false)),
            worker_handles: Vec::new(),
            stats: Arc::new(std::sync::Mutex::new(SchedulerStats::default())),
            job_results: Arc::new(std::sync::Mutex::new(HashMap::new())),
            completed_jobs: Arc::new(std::sync::Mutex::new(Vec::new())),
            shutdown_tx,
            shutdown_rx,
            config,
        }
    }

    /// Start the scheduler and spawn worker threads.
    pub fn start(&mut self) {
        let worker_count = if self.config.worker_count == 0 {
            num_cpus::get()
        } else {
            self.config.worker_count
        };

        self.running.store(true, Ordering::Release);
        info!(workers = worker_count, "scheduler starting");

        for id in 0..worker_count {
            let queue = self.queue.clone();
            let running = self.running.clone();
            let stats = self.stats.clone();
            let job_results = self.job_results.clone();
            let completed_jobs = self.completed_jobs.clone();
            let shutdown_rx = self.shutdown_rx.clone();
            let idle_timeout = Duration::from_millis(self.config.idle_timeout_ms);

            let handle = thread::spawn(move || {
                debug!(worker = id, "worker started");
                loop {
                    if !running.load(Ordering::Acquire) {
                        break;
                    }

                    match queue.try_pop() {
                        Some(job) => {
                            {
                                let mut s = stats.lock().unwrap();
                                s.total_started += 1;
                                s.running_count += 1;
                            }

                            debug!(name = %job.name, worker = id, "executing job");
                            let result = job.execute();
                            queue.complete(&job.id);

                            {
                                let mut s = stats.lock().unwrap();
                                s.running_count = s.running_count.saturating_sub(1);
                                if result.success {
                                    s.total_completed += 1;
                                } else {
                                    s.total_failed += 1;
                                }
                            }

                            let mut results = job_results.lock().unwrap();
                            results.insert(job.id, result);

                            let mut completed = completed_jobs.lock().unwrap();
                            completed.push(job.id);
                        }
                        None => {
                            // Check for shutdown signal with timeout
                            if shutdown_rx.recv_timeout(idle_timeout).is_ok() {
                                break;
                            }
                        }
                    }
                }
                debug!(worker = id, "worker stopped");
            });

            self.worker_handles.push(handle);
        }

        info!("scheduler started with {worker_count} workers");
    }

    /// Submit a job to the scheduler for execution.
    pub fn submit(&self, job: Job) {
        {
            let mut s = self.stats.lock().unwrap();
            s.total_queued += 1;
        }
        self.queue.push(job);
    }

    /// Submit multiple jobs at once.
    pub fn submit_batch(&self, jobs: Vec<Job>) {
        for job in jobs {
            self.submit(job);
        }
    }

    /// Wait for a specific job to complete (blocking).
    pub fn wait_for_job(&self, id: &JobId, timeout: Duration) -> Option<JobResult> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            {
                let results = self.job_results.lock().unwrap();
                if let Some(result) = results.get(id) {
                    return Some(result.clone());
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    }

    /// Get a job result if available.
    pub fn get_result(&self, id: &JobId) -> Option<JobResult> {
        let results = self.job_results.lock().unwrap();
        results.get(id).cloned()
    }

    /// Get the current scheduler statistics.
    pub fn stats(&self) -> SchedulerStats {
        let s = self.stats.lock().unwrap();
        SchedulerStats {
            queued_count: self.queue.len(),
            running_count: s.running_count,
            ..*s
        }
    }

    /// Gracefully shut down the scheduler.
    pub fn shutdown(&mut self) {
        info!("scheduler shutting down");
        self.running.store(false, Ordering::Release);

        // Signal all workers to stop
        for _ in 0..self.worker_handles.len() {
            let _ = self.shutdown_tx.send(());
        }

        // Wait for workers to finish
        for handle in self.worker_handles.drain(..) {
            if let Err(e) = handle.join() {
                error!("worker join error: {:?}", e);
            }
        }

        let stats = self.stats.lock().unwrap();
        info!(
            queued = stats.total_queued,
            completed = stats.total_completed,
            failed = stats.total_failed,
            "scheduler shutdown complete"
        );
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        if self.running.load(Ordering::Acquire) {
            self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::job::JobPriority;

    #[test]
    fn test_scheduler_lifecycle() {
        let mut scheduler = Scheduler::with_config(SchedulerConfig {
            worker_count: 2,
            ..SchedulerConfig::default()
        });
        scheduler.start();

        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_clone = flag.clone();
        let job = Job::new("lifecycle-test", JobPriority::Normal, Arc::new(move || {
            flag_clone.store(true, Ordering::SeqCst);
            JobResult {
                success: true,
                data: None,
                error: None,
                duration_ms: 1,
            }
        }));
        let job_id = job.id;

        scheduler.submit(job);
        let result = scheduler.wait_for_job(&job_id, Duration::from_secs(5));
        assert!(result.is_some());
        assert!(result.unwrap().success);
        assert!(flag.load(Ordering::SeqCst));

        scheduler.shutdown();
    }

    #[test]
    fn test_batch_submission() {
        let mut scheduler = Scheduler::with_config(SchedulerConfig {
            worker_count: 4,
            ..SchedulerConfig::default()
        });
        scheduler.start();

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for i in 0..10 {
            let cnt = counter.clone();
            jobs.push(Job::new(format!("batch-{i}"), JobPriority::Normal, Arc::new(move || {
                cnt.fetch_add(1, Ordering::SeqCst);
                JobResult {
                    success: true,
                    data: None,
                    error: None,
                    duration_ms: 1,
                }
            })));
        }
        scheduler.submit_batch(jobs);
        thread::sleep(Duration::from_millis(500));
        assert_eq!(counter.load(Ordering::SeqCst), 10);
        scheduler.shutdown();
    }
}
