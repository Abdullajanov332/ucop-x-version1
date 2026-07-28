//! Key exchange implementations using X25519.
//! Provides Diffie-Hellman key agreement for secure channel establishment.

use crate::error::{CryptoError, CryptoResult};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An X25519 key exchange participant.
/// Each side generates an ephemeral key pair, exchanges public keys,
/// and computes a shared secret.
#[derive(Debug)]
pub struct KeyExchange {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl KeyExchange {
    /// Create a new key exchange participant, generating an ephemeral key pair.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key to send to the other party.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Compute the shared secret given the other party's public key.
    pub fn complete(self, peer_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(peer_public)
    }

    /// Compute the shared secret from raw peer public key bytes.
    pub fn complete_raw(self, peer_public_bytes: &[u8; 32]) -> CryptoResult<SharedSecret> {
        let peer_public = PublicKey::from(*peer_public_bytes);
        Ok(self.secret.diffie_hellman(&peer_public))
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

/// A derived shared secret that can be used for symmetric encryption.
pub struct DerivedKey {
    shared: [u8; 32],
}

impl DerivedKey {
    /// Create a derived key from a shared secret.
    pub fn from_shared(shared: &SharedSecret) -> Self {
        Self { shared: *shared.as_bytes() }
    }

    /// Derive an encryption key using BLAKE3 KDF.
    pub fn derive_encryption_key(&self, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        let result = blake3::derive_key("ucop-x-kex-encryption", &self.shared, salt);
        key.copy_from_slice(&result[..32]);
        key
    }

    /// Derive a MAC key.
    pub fn derive_mac_key(&self, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        let result = blake3::derive_key("ucop-x-kex-mac", &self.shared, salt);
        key.copy_from_slice(&result[..32]);
        key
    }

    /// Get the raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.shared
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let alice = KeyExchange::new();
        let bob = KeyExchange::new();

        let alice_shared = alice.complete(bob.public_key());
        let bob_shared = bob.complete(alice.public_key());

        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes()
        );
    }

    #[test]
    fn test_derived_keys() {
        let alice = KeyExchange::new();
        let bob = KeyExchange::new();

        let alice_shared = alice.complete(bob.public_key());
        let bob_shared = bob.complete(alice.public_key());

        let alice_derived = DerivedKey::from_shared(&alice_shared);
        let bob_derived = DerivedKey::from_shared(&bob_shared);

        let salt = b"unique-salt-for-testing";
        assert_eq!(
            alice_derived.derive_encryption_key(salt),
            bob_derived.derive_encryption_key(salt)
        );
    }
}
