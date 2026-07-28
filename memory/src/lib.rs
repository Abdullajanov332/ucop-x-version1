//! UCOP-X Enterprise Memory Subsystem
//!
//! Provides memory-safe, zero-copy buffer management, memory-mapped I/O,
//! region-based allocation tracking, and SIMD-accelerated memory operations.

#![forbid(unsafe_code)]
#![deny(missing_docs, missing_debug_implementations)]
#![warn(clippy::all, clippy::pedantic)]

pub use allocator::*;
pub use buffer::*;
pub use pool::*;
pub use region::*;

pub mod allocator;
pub mod buffer;
pub mod pool;
pub mod region;

use ucx_kernel;
