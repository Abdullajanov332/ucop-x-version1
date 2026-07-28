//! Priority-based job queue implementations.
//! Provides a lock-free priority queue and a standard priority queue.

use crate::job::{Job, JobId, JobPriority, JobState};
use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// A wrapper for jobs stored in the priority queue.
/// Implements Ord so higher-priority jobs are dequeued first.
#[derive(Debug)]
struct PriorityJob {
    job: Job,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl PartialEq for PriorityJob {
    fn eq(&self, other: &Self) -> bool {
        self.job.id == other.job.id
    }
}

impl Eq for PriorityJob {}

impl PartialOrd for PriorityJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then earlier creation time
        other
            .job
            .priority
            .cmp(&self.job.priority)
            .then_with(|| self.created_at.cmp(&other.created_at))
    }
}

/// A bounded, priority-based job queue using a binary heap.
#[derive(Debug)]
pub struct PriorityQueue {
    inner: BinaryHeap<PriorityJob>,
    max_size: usize,
    job_count: usize,
}

impl PriorityQueue {
    /// Create a new priority queue with the given maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: BinaryHeap::with_capacity(max_size.min(1024)),
            max_size,
            job_count: 0,
        }
    }

    /// Push a job onto the queue.
    pub fn push(&mut self, job: Job) -> Result<(), Job> {
        if self.job_count >= self.max_size {
            return Err(job);
        }
        self.job_count += 1;
        self.inner.push(PriorityJob {
            created_at: chrono::Utc::now(),
            job,
        });
        Ok(())
    }

    /// Pop the highest priority job from the queue.
    pub fn pop(&mut self) -> Option<Job> {
        let pj = self.inner.pop()?;
        self.job_count -= 1;
        Some(pj.job)
    }

    /// Peek at the highest priority job without removing it.
    pub fn peek(&self) -> Option<&Job> {
        self.inner.peek().map(|pj| &pj.job)
    }

    /// Number of jobs in the queue.
    pub fn len(&self) -> usize {
        self.job_count
    }

    pub fn is_empty(&self) -> bool {
        self.job_count == 0
    }

    /// Maximum capacity of the queue.
    pub fn capacity(&self) -> usize {
        self.max_size
    }

    /// Clear all jobs from the queue.
    pub fn clear(&mut self) {
        self.inner.clear();
        self.job_count = 0;
    }
}

/// A lock-free, multi-producer multi-consumer job queue.
/// Suitable for high-throughput worker pools.
#[derive(Debug)]
pub struct ConcurrentJobQueue {
    queue: SegQueue<Job>,
    state: DashMap<JobId, JobState>,
    counts: DashMap<JobPriority, usize>,
}

impl ConcurrentJobQueue {
    /// Create a new concurrent job queue.
    pub fn new() -> Self {
        Self {
            queue: SegQueue::new(),
            state: DashMap::new(),
            counts: DashMap::new(),
        }
    }

    /// Enqueue a job.
    pub fn push(&self, job: Job) {
        let priority = job.priority;
        let id = job.id;
        self.state.insert(id, JobState::Queued);
        *self.counts.entry(priority).or_insert(0) += 1;
        self.queue.push(job);
    }

    /// Dequeue a job (non-blocking).
    pub fn try_pop(&self) -> Option<Job> {
        let job = self.queue.try_pop()?;
        if let Some(mut entry) = self.counts.get_mut(&job.priority) {
            *entry = entry.saturating_sub(1);
        }
        self.state.insert(job.id, JobState::Running);
        Some(job)
    }

    /// Mark a job as completed.
    pub fn complete(&self, id: &JobId) {
        self.state.insert(*id, JobState::Completed);
    }

    /// Get the state of a job.
    pub fn job_state(&self, id: &JobId) -> Option<JobState> {
        self.state.get(id).map(|e| *e.value())
    }

    /// Total number of queued jobs.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Count of jobs by priority.
    pub fn count_by_priority(&self, priority: JobPriority) -> usize {
        self.counts.get(&priority).map_or(0, |c| *c)
    }
}

impl Default for ConcurrentJobQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_job(name: &str, priority: JobPriority) -> Job {
        Job::new(name, priority, Arc::new(|| JobResult {
            success: true,
            data: None,
            error: None,
            duration_ms: 0,
        }))
    }

    #[test]
    fn test_priority_queue_ordering() {
        let mut pq = PriorityQueue::new(100);
        pq.push(make_job("low", JobPriority::Low)).unwrap();
        pq.push(make_job("critical", JobPriority::Critical)).unwrap();
        pq.push(make_job("normal", JobPriority::Normal)).unwrap();

        assert_eq!(pq.pop().unwrap().name, "critical");
        assert_eq!(pq.pop().unwrap().name, "normal");
        assert_eq!(pq.pop().unwrap().name, "low");
    }

    #[test]
    fn test_priority_queue_capacity() {
        let mut pq = PriorityQueue::new(2);
        pq.push(make_job("a", JobPriority::Normal)).unwrap();
        pq.push(make_job("b", JobPriority::Normal)).unwrap();
        assert!(pq.push(make_job("c", JobPriority::Normal)).is_err());
        assert_eq!(pq.len(), 2);
    }

    #[test]
    fn test_concurrent_queue_basic() {
        let queue = ConcurrentJobQueue::new();
        queue.push(make_job("test1", JobPriority::High));
        queue.push(make_job("test2", JobPriority::Low));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.count_by_priority(JobPriority::High), 1);

        let job = queue.try_pop().unwrap();
        assert_eq!(job.state, JobState::Running);
        queue.complete(&job.id);
        assert_eq!(
            queue.job_state(&job.id),
            Some(JobState::Completed)
        );
    }
}
