//! Symmetric encryption implementations.
//! Provides AES-256-GCM and ChaCha20-Poly1305 with AEAD support.

use crate::error::{CryptoError, CryptoResult};
use crate::key::{EncryptedData, Nonce, SymmetricKey};
use aes_gcm::aead::{Aead, KeyInit, OsRng as AeadOsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::ChaCha20Poly1305;

/// Trait for symmetric encryption ciphers.
pub trait SymmetricCipher: Send + Sync {
    /// Encrypt data with the given key and nonce.
    fn encrypt(&self, key: &SymmetricKey, nonce: &Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> CryptoResult<EncryptedData>;

    /// Decrypt data with the given key and nonce.
    fn decrypt(&self, key: &SymmetricKey, data: &EncryptedData) -> CryptoResult<Vec<u8>>;

    /// Name of the cipher algorithm.
    fn name(&self) -> &'static str;
}

/// AES-256-GCM encryption engine.
#[derive(Debug, Clone)]
pub struct Aes256GcmCipher;

impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher engine.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Aes256GcmCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricCipher for Aes256GcmCipher {
    fn encrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce(
                "AES-256-GCM requires a 12-byte nonce".into(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(format!("key setup: {e}")))?;

        let aes_nonce = AesNonce::from_slice(nonce.as_bytes());

        let payload = match aad {
            Some(aad_data) => Payload {
                msg: plaintext,
                aad: aad_data,
            },
            None => Payload {
                msg: plaintext,
                aad: &[],
            },
        };

        let ciphertext = cipher
            .encrypt(aes_nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            aad: aad.map(|v| v.to_vec()),
        })
    }

    fn decrypt(&self, key: &SymmetricKey, data: &EncryptedData) -> CryptoResult<Vec<u8>> {
        if data.nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce(
                "AES-256-GCM requires a 12-byte nonce".into(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::DecryptionFailed(format!("key setup: {e}")))?;

        let aes_nonce = AesNonce::from_slice(&data.nonce);

        let payload = match &data.aad {
            Some(aad_data) => Payload {
                msg: &data.ciphertext,
                aad: aad_data,
            },
            None => Payload {
                msg: &data.ciphertext,
                aad: &[],
            },
        };

        let plaintext = cipher
            .decrypt(aes_nonce, payload)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }
}

/// ChaCha20-Poly1305 encryption engine.
#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305Cipher;

impl ChaCha20Poly1305Cipher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ChaCha20Poly1305Cipher {
    fn default() -> Self {
        Self::new()
    }
}

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    fn encrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce(
                "ChaCha20-Poly1305 requires a 12-byte nonce".into(),
            ));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(format!("key setup: {e}")))?;

        let chacha_nonce = chacha20poly1305::Nonce::from_slice(nonce.as_bytes());

        let payload = match aad {
            Some(aad_data) => Payload {
                msg: plaintext,
                aad: aad_data,
            },
            None => Payload {
                msg: plaintext,
                aad: &[],
            },
        };

        let ciphertext = cipher
            .encrypt(chacha_nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.as_bytes().to_vec(),
            aad: aad.map(|v| v.to_vec()),
        })
    }

    fn decrypt(&self, key: &SymmetricKey, data: &EncryptedData) -> CryptoResult<Vec<u8>> {
        if data.nonce.len() != 12 {
            return Err(CryptoError::InvalidNonce(
                "ChaCha20-Poly1305 requires a 12-byte nonce".into(),
            ));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| CryptoError::DecryptionFailed(format!("key setup: {e}")))?;

        let chacha_nonce = chacha20poly1305::Nonce::from_slice(&data.nonce);

        let payload = match &data.aad {
            Some(aad_data) => Payload {
                msg: &data.ciphertext,
                aad: aad_data,
            },
            None => Payload {
                msg: &data.ciphertext,
                aad: &[],
            },
        };

        let plaintext = cipher
            .decrypt(chacha_nonce, payload)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_encrypt_decrypt_roundtrip() {
        let cipher = Aes256GcmCipher::new();
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate_12();
        let plaintext = b"This is sensitive data that must be encrypted.";

        let encrypted = cipher
            .encrypt(&key, &nonce, plaintext, Some(b"aad-data"))
            .unwrap();
        assert_ne!(encrypted.ciphertext, plaintext);

        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_wrong_key_fails() {
        let cipher = Aes256GcmCipher::new();
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let nonce = Nonce::generate_12();
        let plaintext = b"secret";

        let encrypted = cipher.encrypt(&key1, &nonce, plaintext, None).unwrap();
        let result = cipher.decrypt(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let cipher = ChaCha20Poly1305Cipher::new();
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate_12();
        let plaintext = b"ChaCha20 test data";

        let encrypted = cipher.encrypt(&key, &nonce, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let cipher = Aes256GcmCipher::new();
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate_12();
        let plaintext = b"tamper test";

        let mut encrypted = cipher.encrypt(&key, &nonce, plaintext, None).unwrap();
        encrypted.ciphertext[0] ^= 0xFF; // flip a bit
        let result = cipher.decrypt(&key, &encrypted);
        assert!(result.is_err());
    }
}
