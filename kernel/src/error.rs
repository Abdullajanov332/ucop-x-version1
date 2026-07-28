//! Kernel error types and result aliases.
//! All kernel operations return structured errors with context.

use thiserror::Error;

/// Unified error type for all kernel-level operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// The requested capability was not granted.
    #[error("capability denied: {0}")]
    CapabilityDenied(String),

    /// The requested module was not found.
    #[error("module not found: {0}")]
    ModuleNotFound(String),

    /// Module initialization failed.
    #[error("module initialization failed: {0}")]
    ModuleInitFailed(String),

    /// Module execution produced an error.
    #[error("module execution error: {0}")]
    ModuleExecutionError(String),

    /// An invalid or malformed event was provided.
    #[error("invalid event: {0}")]
    InvalidEvent(String),

    /// An event bus subscription error occurred.
    #[error("subscription error: {0}")]
    SubscriptionError(String),

    /// A resource was not found.
    #[error("resource not found: {0}")]
    ResourceNotFound(String),

    /// The requested operation is not supported.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// A timeout occurred waiting for an operation.
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// Internal kernel state inconsistency.
    #[error("internal error: {0}")]
    Internal(String),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Convenience alias for kernel results.
pub type KernelResult<T> = Result<T, KernelError>;

impl From<std::io::Error> for KernelError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = KernelError::CapabilityDenied("read:secret_key".into());
        assert_eq!(err.to_string(), "capability denied: read:secret_key");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let kernel_err: KernelError = io_err.into();
        assert!(matches!(kernel_err, KernelError::Io(_)));
    }

    #[test]
    fn test_result_alias() {
        let ok: KernelResult<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);
    }
}
