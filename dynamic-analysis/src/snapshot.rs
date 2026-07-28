//! Snapshot comparison engine for dynamic analysis.
//!
//! Captures and compares memory snapshots before and after
//! operations to detect changes and side effects.

/// A memory snapshot at a point in time.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub label: String,
    pub timestamp: std::time::Instant,
    pub regions: Vec<MemoryRegion>,
}

/// A tracked memory region.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub address: u64,
    pub size: usize,
    pub data: Vec<u8>,
}

impl Snapshot {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            timestamp: std::time::Instant::now(),
            regions: Vec::new(),
        }
    }

    /// Add a memory region to this snapshot.
    pub fn capture_region(&mut self, address: u64, data: Vec<u8>) {
        let size = data.len();
        self.regions.push(MemoryRegion {
            address,
            size,
            data,
        });
    }
}

/// Result of comparing two snapshots.
#[derive(Debug, Clone)]
pub struct SnapshotDiff {
    pub regions_changed: Vec<RegionChange>,
    pub total_bytes_changed: usize,
}

/// A change detected in a memory region.
#[derive(Debug, Clone)]
pub struct RegionChange {
    pub address: u64,
    pub old_size: usize,
    pub new_size: usize,
    pub bytes_changed: usize,
}

/// Compare two snapshots and produce a diff.
pub fn diff_snapshots(before: &Snapshot, after: &Snapshot) -> SnapshotDiff {
    let mut regions_changed = Vec::new();
    let mut total_bytes_changed = 0;

    for after_region in &after.regions {
        let before_region = before
            .regions
            .iter()
            .find(|r| r.address == after_region.address);

        match before_region {
            Some(before_region) => {
                let min_len = before_region.data.len().min(after_region.data.len());
                let mut bytes_changed = 0;
                for i in 0..min_len {
                    if before_region.data[i] != after_region.data[i] {
                        bytes_changed += 1;
                    }
                }
                bytes_changed += (before_region.data.len().max(after_region.data.len())) - min_len;

                if bytes_changed > 0 {
                    total_bytes_changed += bytes_changed;
                    regions_changed.push(RegionChange {
                        address: after_region.address,
                        old_size: before_region.data.len(),
                        new_size: after_region.data.len(),
                        bytes_changed,
                    });
                }
            }
            None => {
                // New region in after snapshot
                total_bytes_changed += after_region.data.len();
                regions_changed.push(RegionChange {
                    address: after_region.address,
                    old_size: 0,
                    new_size: after_region.data.len(),
                    bytes_changed: after_region.data.len(),
                });
            }
        }
    }

    SnapshotDiff {
        regions_changed,
        total_bytes_changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_diff_no_changes() {
        let mut before = Snapshot::new("before");
        before.capture_region(0x1000, vec![0; 16]);
        let after = before.clone();
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.total_bytes_changed, 0);
    }

    #[test]
    fn test_snapshot_diff_with_changes() {
        let mut before = Snapshot::new("before");
        before.capture_region(0x1000, vec![0; 16]);
        let mut after = Snapshot::new("after");
        after.capture_region(0x1000, vec![1; 16]);
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.total_bytes_changed, 16);
    }
}
