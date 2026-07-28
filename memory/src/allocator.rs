//! Memory allocator abstractions and statistics tracking.
//! Provides pluggable allocator metrics for monitoring memory pressure.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Tracks memory allocation statistics across the platform.
#[derive(Debug, Default)]
pub struct AllocatorStats {
    /// Total bytes currently allocated.
    total_allocated: AtomicUsize,
    /// Peak memory usage in bytes.
    peak_allocated: AtomicUsize,
    /// Total number of allocation calls.
    allocation_count: AtomicUsize,
    /// Total number of deallocation calls.
    deallocation_count: AtomicUsize,
}

impl AllocatorStats {
    /// Record an allocation of `size` bytes.
    pub fn record_allocate(&self, size: usize) {
        let prev = self.total_allocated.fetch_add(size, Ordering::Relaxed);
        let new = prev + size;
        self.peak_allocated.fetch_max(new, Ordering::Relaxed);
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a deallocation of `size` bytes.
    pub fn record_deallocate(&self, size: usize) {
        self.total_allocated.fetch_sub(size, Ordering::Relaxed);
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current total allocated bytes.
    pub fn current_allocated(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }

    /// Get the peak allocated bytes.
    pub fn peak_allocated(&self) -> usize {
        self.peak_allocated.load(Ordering::Relaxed)
    }

    /// Get the total number of allocations.
    pub fn allocation_count(&self) -> usize {
        self.allocation_count.load(Ordering::Relaxed)
    }

    /// Get the total number of deallocations.
    pub fn deallocation_count(&self) -> usize {
        self.deallocation_count.load(Ordering::Relaxed)
    }

    /// Get the number of outstanding allocations.
    pub fn outstanding_count(&self) -> usize {
        self.allocation_count
            .load(Ordering::Relaxed)
            .saturating_sub(self.deallocation_count.load(Ordering::Relaxed))
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.total_allocated.store(0, Ordering::Relaxed);
        self.peak_allocated.store(0, Ordering::Relaxed);
        self.allocation_count.store(0, Ordering::Relaxed);
        self.deallocation_count.store(0, Ordering::Relaxed);
    }
}

/// Memory pressure level for backpressure signaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryPressure {
    /// Normal operation — no memory pressure.
    None,
    /// Mild memory pressure — consider reducing cache sizes.
    Mild,
    /// Moderate memory pressure — GC and cache eviction recommended.
    Moderate,
    /// Severe memory pressure — emergency thrift mode.
    Severe,
    /// Critical — system may OOM.
    Critical,
}

impl MemoryPressure {
    /// Compute memory pressure level from current usage vs limit.
    pub fn from_usage(current: usize, limit: usize) -> Self {
        if limit == 0 {
            return Self::None;
        }
        let ratio = (current as f64) / (limit as f64);
        match ratio {
            r if r >= 0.95 => Self::Critical,
            r if r >= 0.85 => Self::Severe,
            r if r >= 0.70 => Self::Moderate,
            r if r >= 0.50 => Self::Mild,
            _ => Self::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_stats() {
        let stats = AllocatorStats::default();
        stats.record_allocate(1024);
        stats.record_allocate(2048);
        assert_eq!(stats.current_allocated(), 3072);
        assert_eq!(stats.peak_allocated(), 3072);
        assert_eq!(stats.allocation_count(), 2);

        stats.record_deallocate(1024);
        assert_eq!(stats.current_allocated(), 2048);
        assert_eq!(stats.outstanding_count(), 1);
    }

    #[test]
    fn test_memory_pressure_levels() {
        assert_eq!(MemoryPressure::from_usage(0, 100), MemoryPressure::None);
        assert_eq!(MemoryPressure::from_usage(55, 100), MemoryPressure::Mild);
        assert_eq!(MemoryPressure::from_usage(75, 100), MemoryPressure::Moderate);
        assert_eq!(MemoryPressure::from_usage(90, 100), MemoryPressure::Severe);
        assert_eq!(MemoryPressure::from_usage(98, 100), MemoryPressure::Critical);
    }

    #[test]
    fn test_stats_reset() {
        let stats = AllocatorStats::default();
        stats.record_allocate(4096);
        stats.reset();
        assert_eq!(stats.current_allocated(), 0);
        assert_eq!(stats.allocation_count(), 0);
    }
}
