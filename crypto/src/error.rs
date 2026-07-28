//! Cryptographic error types.

use std::fmt;
use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Encryption operation failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed (wrong key, corrupted data, etc).
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Invalid key material (wrong length, bad format).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid nonce or IV.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Hashing operation failed.
    #[error("hashing failed: {0}")]
    HashingFailed(String),

    /// Key exchange failed.
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// Random number generation failed.
    #[error("random generation failed: {0}")]
    RandomGenerationFailed(String),
}

/// Convenience alias for crypto results.
pub type CryptoResult<T> = Result<T, CryptoError>;
