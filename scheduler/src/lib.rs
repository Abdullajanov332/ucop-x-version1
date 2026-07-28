//! UCOP-X Enterprise Job Scheduler
//!
//! A NUMA-aware, parallel job scheduler for distributing analysis tasks
//! across available worker threads. Supports priority queues, dependency
//! graphs, and recurring schedule-based jobs.

#![forbid(unsafe_code)]
#![deny(missing_docs, missing_debug_implementations)]
#![warn(clippy::all, clippy::pedantic)]

pub use job::*;
pub use queue::*;
pub use scheduler::*;

pub mod job;
pub mod queue;
pub mod scheduler;
