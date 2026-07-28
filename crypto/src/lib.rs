//! UCOP-X Enterprise Cryptography Module
//!
//! Provides memory-safe cryptographic operations for the platform:
//! - Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
//! - Asymmetric cryptography (Ed25519, X25519)
//! - Hashing (SHA-256/512, BLAKE3)
//! - Key derivation and management
//! - Secure random number generation
//! - Password hashing (Argon2)

#![forbid(unsafe_code)]
#![deny(missing_docs, missing_debug_implementations)]
#![warn(clippy::all, clippy::pedantic)]

pub use cipher::*;
pub use hash::*;
pub use key::*;
pub use kex::*;
pub use sign::*;

pub mod cipher;
pub mod hash;
pub mod key;
pub mod kex;
pub mod sign;
pub mod error;

use zeroize::Zeroize;

/// Trait for types that contain sensitive cryptographic material
/// and should be zeroed on drop.
pub trait SensitiveData: Zeroize {
    /// Type of the underlying key data.
    type RawData: AsRef<[u8]>;

    /// Get a reference to the raw key bytes.
    fn as_bytes(&self) -> &[u8];

    /// Get the length of the key in bytes.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
