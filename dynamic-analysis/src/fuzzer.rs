//! Fuzzing engine for dynamic analysis.

/// Fuzzer mutation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    BitFlip,
    ByteSwap,
    Arithmetic,
    Dictionary,
    Splice,
    Havoc,
}

/// Fuzzer configuration.
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    pub max_input_size: usize,
    pub min_input_size: usize,
    pub mutation_strategy: MutationStrategy,
    pub dictionary: Vec<Vec<u8>>,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            max_input_size: 4096,
            min_input_size: 1,
            mutation_strategy: MutationStrategy::Havoc,
            dictionary: Vec::new(),
        }
    }
}

/// Core fuzzer state.
#[derive(Debug)]
pub struct Fuzzer {
    pub config: FuzzerConfig,
    pub corpus: Vec<Vec<u8>>,
    pub iterations: u64,
    pub crashes_found: u64,
}

impl Fuzzer {
    pub fn new() -> Self {
        Self {
            config: FuzzerConfig::default(),
            corpus: Vec::new(),
            iterations: 0,
            crashes_found: 0,
        }
    }

    /// Mutate input bytes using the configured strategy.
    pub fn mutate(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![0; 1];
        }

        let mut result = input.to_vec();

        match self.config.mutation_strategy {
            MutationStrategy::BitFlip => {
                let bit_pos = (self.iterations as usize) % (result.len() * 8);
                let byte_pos = bit_pos / 8;
                let bit_offset = bit_pos % 8;
                result[byte_pos] ^= 1 << bit_offset;
            }
            MutationStrategy::ByteSwap => {
                if result.len() >= 2 {
                    let a = (self.iterations as usize) % result.len();
                    let b = (a + 1) % result.len();
                    result.swap(a, b);
                }
            }
            MutationStrategy::Havoc => {
                // Apply multiple random mutations
                for _ in 0..(self.iterations % 10 + 1) {
                    if result.len() > 1 {
                        let pos = (self.iterations as usize) % result.len();
                        result[pos] = result[pos].wrapping_add(1);
                    }
                }
            }
            _ => {
                if !result.is_empty() {
                    if let Some(pos) = result.len().checked_sub(1) {
                        result[pos] = result[pos].wrapping_add(1);
                    }
                }
            }
        }

        result
    }

    /// Add an input to the corpus.
    pub fn add_to_corpus(&mut self, input: Vec<u8>) {
        if !self.corpus.contains(&input) {
            self.corpus.push(input);
        }
    }
}

impl Default for Fuzzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_mutation_produces_different_output() {
        let fuzzer = Fuzzer::new();
        let input = b"hello world";
        let mutated = fuzzer.mutate(input);
        assert_ne!(mutated, input);
    }

    #[test]
    fn test_corpus_dedup() {
        let mut fuzzer = Fuzzer::new();
        fuzzer.add_to_corpus(b"test".to_vec());
        fuzzer.add_to_corpus(b"test".to_vec());
        assert_eq!(fuzzer.corpus.len(), 1);
    }
}
