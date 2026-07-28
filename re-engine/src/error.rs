//! Error types for the RE engine.

use thiserror::Error;

/// Errors produced by the reverse engineering engine.
#[derive(Error, Debug)]
pub enum ReError {
    #[error("unsupported binary format")]
    UnsupportedFormat,
    #[error("invalid binary: {0}")]
    InvalidBinary(String),
    #[error("analysis failed: {0}")]
    AnalysisFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
