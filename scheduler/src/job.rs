//! Job types and lifecycle management.
//! Defines the job abstraction used throughout the UCOP-X scheduler.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

/// Unique job identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(Uuid);

impl JobId {
    /// Create a new random job ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Job priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum JobPriority {
    /// Background — lowest priority, runs when idle.
    Background = 0,
    /// Low priority.
    Low = 1,
    /// Normal priority.
    Normal = 2,
    /// High priority.
    High = 3,
    /// Critical — runs immediately.
    Critical = 4,
}

/// Current job state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JobState {
    /// Job is queued awaiting execution.
    Queued,
    /// Job is currently running.
    Running,
    /// Job completed successfully.
    Completed,
    /// Job failed with an error.
    Failed,
    /// Job was cancelled.
    Cancelled,
    /// Job is paused.
    Paused,
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Paused => write!(f, "paused"),
        }
    }
}

/// The core job type for the UCOP-X scheduler.
///
/// Jobs encapsulate a unit of work with full lifecycle tracking,
/// priority, dependency management, and result handling.
pub struct Job {
    /// Unique job identifier.
    pub id: JobId,
    /// Human-readable job name.
    pub name: String,
    /// Job priority.
    pub priority: JobPriority,
    /// Current job state.
    pub state: JobState,
    /// Job creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Job start timestamp.
    pub started_at: Option<DateTime<Utc>>,
    /// Job completion timestamp.
    pub completed_at: Option<DateTime<Utc>>,
    /// IDs of jobs that must complete before this one runs.
    pub dependencies: Vec<JobId>,
    /// The actual work function.
    pub work: Arc<dyn Fn() -> JobResult + Send + Sync>,
}

/// Result returned by a completed job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// Whether the job succeeded.
    pub success: bool,
    /// Optional result data as JSON bytes.
    pub data: Option<Vec<u8>>,
    /// Error message if the job failed.
    pub error: Option<String>,
    /// Duration of job execution in milliseconds.
    pub duration_ms: u64,
}

impl Job {
    /// Create a new job with the given name and work function.
    pub fn new(
        name: impl Into<String>,
        priority: JobPriority,
        work: Arc<dyn Fn() -> JobResult + Send + Sync>,
    ) -> Self {
        Self {
            id: JobId::new(),
            name: name.into(),
            priority,
            state: JobState::Queued,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            dependencies: Vec::new(),
            work,
        }
    }

    /// Add a dependency on another job.
    pub fn depends_on(mut self, dep: JobId) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Mark the job as started.
    pub fn mark_started(&mut self) {
        self.state = JobState::Running;
        self.started_at = Some(Utc::now());
    }

    /// Mark the job as completed.
    pub fn mark_completed(&mut self) {
        self.state = JobState::Completed;
        self.completed_at = Some(Utc::now());
    }

    /// Mark the job as failed.
    pub fn mark_failed(&mut self) {
        self.state = JobState::Failed;
        self.completed_at = Some(Utc::now());
    }

    /// Mark the job as cancelled.
    pub fn mark_cancelled(&mut self) {
        self.state = JobState::Cancelled;
        self.completed_at = Some(Utc::now());
    }

    /// Check if all dependencies are satisfied (given a set of completed job IDs).
    pub fn dependencies_satisfied(&self, completed: &[JobId]) -> bool {
        self.dependencies
            .iter()
            .all(|dep| completed.contains(dep))
    }

    /// Execute the job's work function and return the result.
    pub fn execute(&self) -> JobResult {
        (self.work)()
    }

    /// Get the duration of job execution if it has completed.
    pub fn duration(&self) -> Option<std::time::Duration> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => {
                Some(end.signed_duration_since(start).to_std().unwrap_or_default())
            }
            _ => None,
        }
    }
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("state", &self.state)
            .field("dependencies", &self.dependencies.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_job_lifecycle() {
        let mut job = Job::new("test", JobPriority::Normal, Arc::new(|| JobResult {
            success: true,
            data: None,
            error: None,
            duration_ms: 0,
        }));
        assert_eq!(job.state, JobState::Queued);
        job.mark_started();
        assert_eq!(job.state, JobState::Running);
        job.mark_completed();
        assert_eq!(job.state, JobState::Completed);
        assert!(job.completed_at.is_some());
    }

    #[test]
    fn test_job_execution() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();
        let job = Job::new("exec-test", JobPriority::High, Arc::new(move || {
            flag_clone.store(true, Ordering::SeqCst);
            JobResult {
                success: true,
                data: None,
                error: None,
                duration_ms: 1,
            }
        }));
        let result = job.execute();
        assert!(result.success);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_dependency_satisfaction() {
        let dep1 = JobId::new();
        let dep2 = JobId::new();
        let job = Job::new("dependent", JobPriority::Normal, Arc::new(|| JobResult {
            success: true,
            data: None,
            error: None,
            duration_ms: 0,
        }))
        .depends_on(dep1)
        .depends_on(dep2);

        assert!(!job.dependencies_satisfied(&[dep1]));
        assert!(job.dependencies_satisfied(&[dep1, dep2]));
    }

    #[test]
    fn test_job_priority_ordering() {
        assert!(JobPriority::Critical > JobPriority::High);
        assert!(JobPriority::High > JobPriority::Normal);
        assert!(JobPriority::Normal > JobPriority::Low);
        assert!(JobPriority::Low > JobPriority::Background);
    }
}
