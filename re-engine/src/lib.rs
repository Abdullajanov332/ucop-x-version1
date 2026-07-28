//! UCOP-X Reverse Engineering Engine
//!
//! Provides disassembly, decompilation, and binary analysis capabilities
//! supporting ELF, PE, and Mach-O formats across multiple architectures.

#![forbid(unsafe_code)]

pub mod error;
pub mod elf;
pub mod pe;
pub mod macho;

use std::collections::HashMap;

/// Architecture types supported by the RE engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    PowerPc,
    RiscV,
    Wasm,
}

impl Architecture {
    /// Return the name of this architecture.
    pub fn name(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86_64",
            Architecture::Arm => "ARM",
            Architecture::Arm64 => "ARM64",
            Architecture::Mips => "MIPS",
            Architecture::PowerPc => "PowerPC",
            Architecture::RiscV => "RISC-V",
            Architecture::Wasm => "WebAssembly",
        }
    }
}

/// Known binary format types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Raw,
}

impl BinaryFormat {
    /// Detect format from magic bytes.
    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        match &data[..4] {
            [0x7F, b'E', b'L', b'F'] => Some(BinaryFormat::Elf),
            [0x4D, 0x5A, _, _] => Some(BinaryFormat::Pe),
            [0xCF, 0xFA, 0xED, 0xFE] => Some(BinaryFormat::MachO),
            [0xFE, 0xED, 0xFA, 0xCF] => Some(BinaryFormat::MachO),
            [0xCA, 0xFE, 0xBA, 0xBE] => Some(BinaryFormat::MachO),
            _ => None,
        }
    }
}

/// Analysis result for a single function.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name if known.
    pub name: Option<String>,
    /// Start address.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Number of basic blocks.
    pub basic_blocks: usize,
    /// Number of instructions.
    pub instructions: usize,
    /// Whether this is an entry point.
    pub is_entry_point: bool,
}

/// Cross-reference entry.
#[derive(Debug, Clone)]
pub struct Xref {
    /// Source address.
    pub from: u64,
    /// Target address.
    pub to: u64,
    /// Type of reference.
    pub xref_type: XrefType,
}

/// Type of cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefType {
    Call,
    Jump,
    DataRef,
}

/// Reverse engineering engine state.
#[derive(Debug)]
pub struct ReEngine {
    /// Currently loaded binary data.
    pub(crate) data: Vec<u8>,
    /// Detected format.
    pub format: Option<BinaryFormat>,
    /// Functions discovered during analysis.
    pub functions: Vec<FunctionInfo>,
    /// Cross-references.
    pub xrefs: Vec<Xref>,
    /// Architecture detection.
    pub architecture: Option<Architecture>,
}

impl ReEngine {
    /// Create a new RE engine instance.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            format: None,
            functions: Vec::new(),
            xrefs: Vec::new(),
            architecture: None,
        }
    }

    /// Load a binary file for analysis.
    pub fn load(&mut self, data: Vec<u8>) -> Result<(), String> {
        self.data = data;
        self.format = BinaryFormat::detect(&self.data);
        self.functions.clear();
        self.xrefs.clear();
        Ok(())
    }

    /// Run analysis on the loaded binary.
    pub fn analyze(&mut self) -> Result<AnalysisReport, String> {
        if self.data.is_empty() {
            return Err("no data loaded".into());
        }
        let format_name = self
            .format
            .map(|f| format!("{f:?}"))
            .unwrap_or_else(|| "Unknown".into());
        Ok(AnalysisReport {
            format: format_name,
            architecture: self
                .architecture
                .map(|a| a.name().into())
                .unwrap_or_else(|| "Detecting...".into()),
            file_size: self.data.len(),
            functions_found: self.functions.len(),
            xrefs_found: self.xrefs.len(),
            segments: Vec::new(),
        })
    }

    /// Get the loaded binary data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Default for ReEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level analysis report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalysisReport {
    /// Binary format.
    pub format: String,
    /// Target architecture.
    pub architecture: String,
    /// Total file size.
    pub file_size: usize,
    /// Number of functions found.
    pub functions_found: usize,
    /// Number of cross-references found.
    pub xrefs_found: usize,
    /// Segment listing.
    pub segments: Vec<SegmentInfo>,
}

/// Information about a binary segment/section.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SegmentInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub permissions: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        let elf = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        assert_eq!(BinaryFormat::detect(&elf), Some(BinaryFormat::Elf));

        let pe = [0x4D, 0x5A, 0x90, 0x00];
        assert_eq!(BinaryFormat::detect(&pe), Some(BinaryFormat::Pe));
    }

    #[test]
    fn test_engine_analyze_empty() {
        let mut engine = ReEngine::new();
        let result = engine.analyze();
        assert!(result.is_err());
    }

    #[test]
    fn test_engine_load_and_analyze() {
        let mut engine = ReEngine::new();
        engine.load(vec![0x7F, b'E', b'L', b'F', 0; 100]).unwrap();
        let report = engine.analyze().unwrap();
        assert_eq!(report.file_size, 104);
    }

    #[test]
    fn test_architecture_names() {
        assert_eq!(Architecture::X86_64.name(), "x86_64");
        assert_eq!(Architecture::Arm64.name(), "ARM64");
    }
}
