//! Binary instrumentation for dynamic analysis.

/// Types of instrumentation probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeType {
    FunctionEntry,
    FunctionExit,
    BasicBlock,
    MemoryRead,
    MemoryWrite,
    Syscall,
}

/// An instrumentation probe.
#[derive(Debug, Clone)]
pub struct Probe {
    pub probe_type: ProbeType,
    pub address: u64,
    pub callback: Option<String>,
}

/// Instrumentation engine state.
#[derive(Debug, Default)]
pub struct InstrumentationEngine {
    pub probes: Vec<Probe>,
    pub hit_counts: std::collections::HashMap<(ProbeType, u64), u64>,
}

impl InstrumentationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a probe at a given address.
    pub fn add_probe(&mut self, probe_type: ProbeType, address: u64) {
        self.probes.push(Probe {
            probe_type,
            address,
            callback: None,
        });
    }

    /// Record a probe hit.
    pub fn record_hit(&mut self, probe_type: ProbeType, address: u64) {
        *self.hit_counts.entry((probe_type, address)).or_insert(0) += 1;
    }

    /// Get total probe hits.
    pub fn total_hits(&self) -> u64 {
        self.hit_counts.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instrumentation_basic() {
        let mut engine = InstrumentationEngine::new();
        engine.add_probe(ProbeType::FunctionEntry, 0x1000);
        engine.add_probe(ProbeType::FunctionExit, 0x2000);

        engine.record_hit(ProbeType::FunctionEntry, 0x1000);
        engine.record_hit(ProbeType::FunctionEntry, 0x1000);

        assert_eq!(engine.total_hits(), 2);
        assert_eq!(engine.probes.len(), 2);
    }
}
