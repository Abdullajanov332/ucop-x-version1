//! Hashing implementations for the UCOP-X platform.
//! Provides SHA-256, SHA-512, BLAKE3, and HMAC operations.

use crate::error::{CryptoError, CryptoResult};
use crate::key::HmacKey;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-512 (64 bytes).
    Sha512,
    /// BLAKE3 (variable output, default 32 bytes).
    Blake3,
}

/// A computed hash value with metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct HashValue {
    /// The raw hash bytes.
    bytes: Vec<u8>,
    /// The algorithm used.
    algorithm: HashAlgorithm,
}

impl HashValue {
    /// Get the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the hash algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Get the hex-encoded hash string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Get the hash length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashValue")
            .field("algorithm", &self.algorithm)
            .field("hex", &self.to_hex())
            .finish()
    }
}

impl fmt::Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm_prefix(), self.to_hex())
    }
}

impl HashValue {
    fn algorithm_prefix(&self) -> &'static str {
        match self.algorithm {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Blake3 => "blake3",
        }
    }
}

/// Compute a hash of the given data.
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> HashValue {
    let bytes = match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => {
            let hasher = blake3::Hasher::new();
            hasher.update(data).finalize().as_bytes().to_vec()
        }
    };

    HashValue { bytes, algorithm }
}

/// Compute a hash of a file at the given path.
pub fn hash_file(path: &std::path::Path, algorithm: HashAlgorithm) -> CryptoResult<HashValue> {
    let data = std::fs::read(path)
        .map_err(|e| CryptoError::HashingFailed(format!("cannot read file: {e}")))?;
    Ok(hash(&data, algorithm))
}

/// Compute a hash from multiple data chunks (streaming).
pub fn hash_chunks<'a>(
    chunks: impl IntoIterator<Item = &'a [u8]>,
    algorithm: HashAlgorithm,
) -> HashValue {
    let bytes = match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for chunk in chunks {
                hasher.update(chunk);
            }
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            for chunk in chunks {
                hasher.update(chunk);
            }
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            for chunk in chunks {
                hasher.update(chunk);
            }
            hasher.finalize().as_bytes().to_vec()
        }
    };

    HashValue { bytes, algorithm }
}

/// Compute an HMAC using the given key and data.
pub fn hmac(key: &HmacKey, data: &[u8]) -> HashValue {
    use hmac::{Hmac, Mac};

    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC key length is valid");
    mac.update(data);
    let result = mac.finalize();

    HashValue {
        bytes: result.into_bytes().to_vec(),
        algorithm: HashAlgorithm::Sha256,
    }
}

/// Verify a hash against expected bytes.
pub fn verify_hash(data: &[u8], expected: &HashValue) -> bool {
    let computed = hash(data, expected.algorithm());
    computed.bytes == expected.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let result = hash(data, HashAlgorithm::Sha256);
        assert_eq!(result.len(), 32);
        assert_eq!(
            result.to_hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let result = hash(data, HashAlgorithm::Blake3);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_verify_hash() {
        let data = b"verify me";
        let hash_val = hash(data, HashAlgorithm::Sha256);
        assert!(verify_hash(data, &hash_val));
        assert!(!verify_hash(b"wrong data", &hash_val));
    }

    #[test]
    fn test_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"file content").unwrap();
        let result = hash_file(&path, HashAlgorithm::Sha256).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_chunked_hashing() {
        let chunks = [b"hello ", b"world", b"!"];
        let result = hash_chunks(chunks.iter().map(|c| &c[..]), HashAlgorithm::Blake3);
        let single = hash(b"hello world!", HashAlgorithm::Blake3);
        assert_eq!(result, single);
    }

    #[test]
    fn test_hmac_computation() {
        let key = HmacKey::generate();
        let data = b"authenticate this message";
        let tag = hmac(&key, data);
        assert_eq!(tag.len(), 32);
    }
}
