//! Digital signature implementations using Ed25519.
//! Provides key generation, signing, and verification.

use crate::error::{CryptoError, CryptoResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An Ed25519 keypair for digital signatures.
pub struct SignatureKeypair {
    /// The secret signing key.
    signing: SigningKey,
    /// The public verifying key.
    verifying: VerifyingKey,
}

impl SignatureKeypair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Create a keypair from secret key bytes.
    pub fn from_secret(secret: &[u8]) -> CryptoResult<Self> {
        let secret_array: [u8; 32] = secret
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Ed25519 secret must be 32 bytes".into()))?;
        let signing = SigningKey::from_bytes(&secret_array);
        let verifying = signing.verifying_key();
        Ok(Self { signing, verifying })
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// Get the secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8; 32] {
        self.signing.as_bytes()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Verify a signature on a message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> CryptoResult<()> {
        self.verifying
            .verify(message, signature)
            .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))
    }
}

impl fmt::Debug for SignatureKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureKeypair")
            .field("public", &hex::encode(self.verifying.as_bytes()))
            .finish()
    }
}

/// A public key for signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    bytes: [u8; 32],
    #[serde(skip)]
    inner: Option<VerifyingKey>,
}

impl PublicKey {
    /// Create a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> CryptoResult<Self> {
        let inner = VerifyingKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Ok(Self {
            bytes: *bytes,
            inner: Some(inner),
        })
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> CryptoResult<()> {
        let sig = Signature::from_bytes(signature);
        match &self.inner {
            Some(key) => key
                .verify(message, &sig)
                .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string())),
            None => Err(CryptoError::InvalidKey("public key not initialized".into())),
        }
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// A signed message with embedded signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The message content.
    pub message: Vec<u8>,
    /// The Ed25519 signature (64 bytes).
    pub signature: [u8; 64],
    /// The signer's public key.
    pub signer: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let kp = SignatureKeypair::generate();
        let message = b"This is an authenticated message";
        let signature = kp.sign(message);
        assert!(kp.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_tampered_signature_fails() {
        let kp = SignatureKeypair::generate();
        let message = b"original message";
        let signature = kp.sign(message);
        // Verify with different message
        assert!(kp.verify(b"tampered message", &signature).is_err());
    }

    #[test]
    fn test_public_key_verification() {
        let kp = SignatureKeypair::generate();
        let pub_key = PublicKey::from_bytes(kp.public_key().as_bytes()).unwrap();
        let message = b"test";
        let sig = kp.sign(message);
        assert!(pub_key.verify(message, sig.to_bytes()).is_ok());
    }

    #[test]
    fn test_keypair_from_secret() {
        let kp1 = SignatureKeypair::generate();
        let secret = *kp1.secret_key_bytes();
        let kp2 = SignatureKeypair::from_secret(&secret).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_signature_keypair_debug_safe() {
        let kp = SignatureKeypair::generate();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("public"));
        assert!(!debug.contains("secret"));
    }
}
