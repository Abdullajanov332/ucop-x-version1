//! Memory region management for allocating and tracking memory regions.
//! Supports arena-style allocation for bulk deallocation patterns.

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use std::alloc::{alloc, dealloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A memory region descriptor tracking allocated blocks.
#[derive(Debug)]
struct RegionBlock {
    ptr: *mut u8,
    layout: Layout,
}

/// A memory region (arena) for bulk allocations that can be freed all at once.
/// Useful for short-lived analysis passes that allocate many small objects.
#[derive(Debug)]
pub struct MemoryRegion {
    blocks: Vec<RegionBlock>,
    total_size: usize,
}

impl MemoryRegion {
    /// Create a new empty memory region.
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            total_size: 0,
        }
    }

    /// Allocate memory within this region.
    /// # Safety
    /// The caller must ensure that the memory is used correctly.
    /// The memory will be deallocated when the region is reset or dropped.
    pub unsafe fn allocate(&mut self, size: usize, align: usize) -> *mut u8 {
        let layout = Layout::from_size_align(size, align).expect("invalid layout");
        let ptr = alloc(layout);
        if ptr.is_null() {
            panic!("allocation failed: out of memory");
        }
        self.blocks.push(RegionBlock { ptr, layout });
        self.total_size += size;
        ptr
    }

    /// Reset the region, freeing all allocated memory.
    pub fn reset(&mut self) {
        for block in self.blocks.drain(..) {
            unsafe {
                dealloc(block.ptr, block.layout);
            }
        }
        self.total_size = 0;
    }

    /// Total bytes allocated in this region.
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Number of allocations in this region.
    pub fn allocation_count(&self) -> usize {
        self.blocks.len()
    }
}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        self.reset();
    }
}

/// Global memory region tracker for monitoring region-based allocations.
#[derive(Debug)]
pub struct RegionTracker {
    regions: DashMap<String, usize, FxBuildHasher>,
    total_region_memory: AtomicUsize,
}

impl RegionTracker {
    /// Create a new region tracker.
    pub fn new() -> Self {
        Self {
            regions: DashMap::with_hasher(FxBuildHasher::default()),
            total_region_memory: AtomicUsize::new(0),
        }
    }

    /// Record a region allocation.
    pub fn record(&self, name: impl Into<String>, size: usize) {
        let name = name.into();
        *self.regions.entry(name).or_insert(0) += size;
        self.total_region_memory.fetch_add(size, Ordering::Relaxed);
    }

    /// Record a region deallocation.
    pub fn record_free(&self, name: &str, size: usize) {
        if let Some(mut entry) = self.regions.get_mut(name) {
            *entry = entry.saturating_sub(size);
        }
        self.total_region_memory.fetch_sub(size, Ordering::Relaxed);
    }

    /// Get the total memory tracked across all regions.
    pub fn total_tracked(&self) -> usize {
        self.total_region_memory.load(Ordering::Relaxed)
    }

    /// Get memory usage for a specific region.
    pub fn region_usage(&self, name: &str) -> usize {
        self.regions.get(name).map_or(0, |e| *e)
    }

    /// List all tracked regions and their sizes.
    pub fn list_regions(&self) -> Vec<(String, usize)> {
        self.regions
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }
}

impl Default for RegionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_lifecycle() {
        let mut region = MemoryRegion::new();
        unsafe {
            let p1 = region.allocate(64, 8);
            let p2 = region.allocate(128, 16);
            assert!(!p1.is_null());
            assert!(!p2.is_null());
            std::ptr::write_bytes(p1, 0xAB, 64);
            assert_eq!(std::ptr::read::<u8>(p1), 0xAB);
        }
        assert_eq!(region.allocation_count(), 2);
        assert_eq!(region.total_size(), 192);
        region.reset();
        assert_eq!(region.allocation_count(), 0);
        assert_eq!(region.total_size(), 0);
    }

    #[test]
    fn test_region_tracker() {
        let tracker = RegionTracker::new();
        tracker.record("analysis.elf", 4096);
        tracker.record("analysis.elf", 1024);
        tracker.record("analysis.pe", 8192);
        assert_eq!(tracker.region_usage("analysis.elf"), 5120);
        assert_eq!(tracker.region_usage("analysis.pe"), 8192);
        assert_eq!(tracker.total_tracked(), 13312);
        tracker.record_free("analysis.elf", 1024);
        assert_eq!(tracker.region_usage("analysis.elf"), 4096);
    }
}
