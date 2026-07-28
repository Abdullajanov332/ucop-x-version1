//! Key generation, derivation, and management.
//! Provides secure key types with automatic zeroing on drop.

use crate::error::{CryptoError, CryptoResult};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A symmetric encryption key (32 bytes = AES-256).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    #[zeroize]
    key: [u8; 32],
}

impl SymmetricKey {
    /// Generate a new random symmetric key.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        Self { key }
    }

    /// Create a symmetric key from a byte slice (must be exactly 32 bytes).
    pub fn from_slice(data: &[u8]) -> CryptoResult<Self> {
        if data.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "expected 32 bytes, got {}",
                data.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(data);
        Ok(Self { key })
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricKey([REDACTED])")
    }
}

/// A 256-bit key for HMAC operations.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HmacKey {
    #[zeroize]
    key: [u8; 32],
}

impl HmacKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut key);
        Self { key }
    }

    pub fn from_slice(data: &[u8]) -> CryptoResult<Self> {
        if data.is_empty() || data.len() > 64 {
            return Err(CryptoError::InvalidKey(format!(
                "HMAC key length {} invalid (1-64 bytes)",
                data.len()
            )));
        }
        let mut key = [0u8; 32];
        let len = data.len().min(32);
        key[..len].copy_from_slice(&data[..len]);
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// A nonce/IV for symmetric encryption.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Nonce {
    #[zeroize]
    inner: Vec<u8>,
}

impl Nonce {
    /// Generate a random 12-byte nonce (standard for AES-GCM).
    pub fn generate_12() -> Self {
        let mut inner = vec![0u8; 12];
        rand::RngCore::fill_bytes(&mut OsRng, &mut inner);
        Self { inner }
    }

    /// Generate a random 24-byte nonce (standard for XChaCha20).
    pub fn generate_24() -> Self {
        let mut inner = vec![0u8; 24];
        rand::RngCore::fill_bytes(&mut OsRng, &mut inner);
        Self { inner }
    }

    /// Create a nonce from a byte slice.
    pub fn from_slice(data: &[u8]) -> CryptoResult<Self> {
        if data.len() != 12 && data.len() != 24 {
            return Err(CryptoError::InvalidNonce(format!(
                "nonce must be 12 or 24 bytes, got {}",
                data.len()
            )));
        }
        Ok(Self {
            inner: data.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// An encrypted data envelope containing ciphertext and nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// The nonce used during encryption.
    pub nonce: Vec<u8>,
    /// Optional additional authenticated data (AAD).
    pub aad: Option<Vec<u8>>,
}

/// Password hash using a memory-hard KDF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHash {
    /// Hash bytes.
    pub hash: Vec<u8>,
    /// Salt used during hashing.
    pub salt: Vec<u8>,
    /// Argon2 parameters.
    pub params: Argon2Params,
}

/// Argon2 hashing parameters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Memory cost in KiB.
    pub memory_cost: u32,
    /// Parallelism factor.
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            time_cost: 3,
            memory_cost: 65536, // 64 MiB
            parallelism: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_key_generation() {
        let key = SymmetricKey::generate();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_symmetric_key_from_slice() {
        let data = [0xABu8; 32];
        let key = SymmetricKey::from_slice(&data).unwrap();
        assert_eq!(key.as_bytes(), &data);
    }

    #[test]
    fn test_symmetric_key_wrong_length() {
        let result = SymmetricKey::from_slice(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_generation() {
        let nonce12 = Nonce::generate_12();
        assert_eq!(nonce12.len(), 12);
        let nonce24 = Nonce::generate_24();
        assert_eq!(nonce24.len(), 24);
    }

    #[test]
    fn test_key_debug_redaction() {
        let key = SymmetricKey::generate();
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
    }
}
