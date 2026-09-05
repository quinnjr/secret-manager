//! Diffie-Hellman over the RFC 2409 second Oakley group (1024-bit MODP, g = 2),
//! with HKDF-SHA256 to a 128-bit AES key. Matches libsecret and gnome-keyring:
//! the shared secret is left-padded to 128 bytes before HKDF, salt and info are empty.

use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::One;
use sha2::Sha256;
use zeroize::Zeroizing;

const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
pub const PRIME_BYTES: usize = 128;

pub fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid constant")
}

#[derive(Debug, thiserror::Error)]
pub enum DhError {
    #[error("invalid peer public key")]
    InvalidPeerKey,
    #[error("hkdf expansion failed")]
    Hkdf,
}

/// Ephemeral DH key pair. The private exponent is not zeroized on drop
/// (`BigUint` has no zeroize support); keys live only for one session.
pub struct KeyPair {
    private: BigUint,
    public: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let p = prime();
        let two = BigUint::from(2u32);
        let raw = crate::vault::crypto::random_bytes::<PRIME_BYTES>();
        // x in [2, p-2]
        let private = BigUint::from_bytes_be(&raw) % (&p - BigUint::from(3u32)) + &two;
        let public = two.modpow(&private, &p).to_bytes_be();
        KeyPair { private, public }
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    pub fn derive_aes_key(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 16]>, DhError> {
        let p = prime();
        let peer = BigUint::from_bytes_be(peer_public);
        if peer <= BigUint::one() || peer >= &p - BigUint::one() {
            return Err(DhError::InvalidPeerKey);
        }
        let shared = peer.modpow(&self.private, &p).to_bytes_be();
        if shared.len() > PRIME_BYTES {
            return Err(DhError::InvalidPeerKey);
        }
        let mut ikm = Zeroizing::new([0u8; PRIME_BYTES]);
        ikm[PRIME_BYTES - shared.len()..].copy_from_slice(&shared);
        let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
        let mut okm = Zeroizing::new([0u8; 16]);
        hk.expand(&[], &mut okm[..]).map_err(|_| DhError::Hkdf)?;
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_key() {
        let client = KeyPair::generate();
        let server = KeyPair::generate();
        let k1 = client.derive_aes_key(server.public_bytes()).unwrap();
        let k2 = server.derive_aes_key(client.public_bytes()).unwrap();
        assert_eq!(*k1, *k2);
        assert!(client.public_bytes().len() <= PRIME_BYTES);
        let other = KeyPair::generate();
        assert_ne!(*k1, *client.derive_aes_key(other.public_bytes()).unwrap());
    }

    #[test]
    fn degenerate_peer_keys_are_rejected() {
        let me = KeyPair::generate();
        let p = prime();
        for bad in [
            BigUint::from(0u32),
            BigUint::from(1u32),
            &p - BigUint::from(1u32),
            p.clone(),
        ] {
            assert!(matches!(
                me.derive_aes_key(&bad.to_bytes_be()),
                Err(DhError::InvalidPeerKey)
            ));
        }
    }

    #[test]
    fn prime_is_1024_bits() {
        assert_eq!(prime().bits(), 1024);
    }
}
