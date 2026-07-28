//! Code coverage tracking for dynamic analysis.

use std::collections::HashSet;

/// Coverage information for a run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageInfo {
    pub covered_blocks: usize,
    pub total_blocks: usize,
    pub coverage_pct: f64,
    pub edges: Vec<(u64, u64)>,
}

/// Coverage tracker using edge-based coverage.
#[derive(Debug, Default)]
pub struct CoverageTracker {
    pub(crate) edges: HashSet<(u64, u64)>,
    total_blocks: usize,
}

impl CoverageTracker {
    pub fn new(total_blocks: usize) -> Self {
        Self {
            edges: HashSet::new(),
            total_blocks,
        }
    }

    /// Record a transition from one block to another.
    pub fn record_edge(&mut self, from: u64, to: u64) {
        self.edges.insert((from, to));
    }

    /// Get current coverage statistics.
    pub fn coverage(&self) -> CoverageInfo {
        let covered = self
            .edges
            .iter()
            .flat_map(|(a, b)| vec![*a, *b])
            .collect::<HashSet<_>>()
            .len();
        let pct = if self.total_blocks > 0 {
            (covered as f64 / self.total_blocks as f64) * 100.0
        } else {
            0.0
        };
        CoverageInfo {
            covered_blocks: covered,
            total_blocks: self.total_blocks,
            coverage_pct: pct,
            edges: self.edges.iter().copied().collect(),
        }
    }

    /// Reset coverage data.
    pub fn reset(&mut self) {
        self.edges.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_tracking() {
        let mut tracker = CoverageTracker::new(5);
        tracker.record_edge(0x1000, 0x1004);
        tracker.record_edge(0x1004, 0x1008);
        let info = tracker.coverage();
        assert_eq!(info.edges.len(), 2);
    }

    #[test]
    fn test_coverage_reset() {
        let mut tracker = CoverageTracker::new(10);
        tracker.record_edge(0x1000, 0x1004);
        tracker.reset();
        assert_eq!(tracker.edges.len(), 0);
    }
}
