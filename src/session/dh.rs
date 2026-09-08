//! Diffie-Hellman over the RFC 2409 second Oakley group (1024-bit MODP, g = 2),
//! with HKDF-SHA256 to a 128-bit AES key. Matches libsecret and gnome-keyring:
//! the shared secret is left-padded to 128 bytes before HKDF, salt and info are empty.
//!
//! Arithmetic is `crypto-bigint`: exponentiation runs in constant time with
//! respect to the private exponent, and the exponent is zeroized on drop.

use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{NonZero, Odd, U1024};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::LazyLock;
use zeroize::{Zeroize, Zeroizing};

const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
pub const PRIME_BYTES: usize = 128;

pub const PRIME: U1024 = U1024::from_be_hex(PRIME_HEX);

/// Montgomery parameters for [`PRIME`], built once.
///
/// `MontyParams::new_vartime` performs a 1024-bit modular inversion. The
/// modulus is a fixed public constant, so recomputing it on every
/// `generate()` and every `derive_aes_key()` - both on the per-D-Bus-call
/// `OpenSession` path - buys nothing.
static MONTY: LazyLock<MontyParams<{ U1024::LIMBS }>> =
    LazyLock::new(|| MontyParams::new_vartime(Odd::new(PRIME).expect("group prime is odd")));

fn monty() -> MontyParams<{ U1024::LIMBS }> {
    *MONTY
}

#[derive(Debug, thiserror::Error)]
pub enum DhError {
    #[error("invalid peer public key")]
    InvalidPeerKey,
    #[error("hkdf expansion failed")]
    Hkdf,
}

/// Ephemeral DH key pair. The private exponent is zeroized on drop.
pub struct KeyPair {
    private: U1024,
    public: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

/// Big-endian bytes without leading zeros, as libsecret encodes them.
fn minimal_be(x: &U1024) -> Vec<u8> {
    let bytes = x.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// Left-pad arbitrary-length big-endian bytes into a `U1024`.
fn from_be_padded(bytes: &[u8]) -> Option<U1024> {
    if bytes.len() > PRIME_BYTES {
        return None;
    }
    let mut buf = [0u8; PRIME_BYTES];
    buf[PRIME_BYTES - bytes.len()..].copy_from_slice(bytes);
    Some(U1024::from_be_slice(&buf))
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let params = monty();
        let raw = Zeroizing::new(crate::vault::crypto::random_bytes::<PRIME_BYTES>());
        // x in [2, p-2]
        let range = NonZero::new(PRIME.wrapping_sub(&U1024::from(3u32))).expect("p > 3");
        let mut reduced = U1024::from_be_slice(&raw[..]).rem(&range);
        let private = reduced.wrapping_add(&U1024::from(2u32));
        reduced.zeroize();
        let public = MontyForm::new(&U1024::from(2u32), params)
            .pow(&private)
            .retrieve();
        KeyPair {
            private,
            public: minimal_be(&public),
        }
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    pub fn derive_aes_key(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 16]>, DhError> {
        let peer = from_be_padded(peer_public).ok_or(DhError::InvalidPeerKey)?;
        // Reject 0, 1 and p-1 (the order-1 and order-2 elements of a safe-prime
        // group) and anything not reduced modulo p.
        if peer <= U1024::ONE || peer >= PRIME.wrapping_sub(&U1024::ONE) {
            return Err(DhError::InvalidPeerKey);
        }
        let mut shared = MontyForm::new(&peer, monty()).pow(&self.private).retrieve();
        let ikm = Zeroizing::new(shared.to_be_bytes());
        // The shared secret is equivalent to the session key; do not leave it
        // on the stack for a reader of process memory to find.
        shared.zeroize();
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
        assert_ne!(client.public_bytes()[0], 0, "minimal encoding");
        let other = KeyPair::generate();
        assert_ne!(*k1, *client.derive_aes_key(other.public_bytes()).unwrap());
    }

    #[test]
    fn degenerate_peer_keys_are_rejected() {
        let me = KeyPair::generate();
        for bad in [
            U1024::ZERO,
            U1024::ONE,
            PRIME.wrapping_sub(&U1024::ONE),
            PRIME,
        ] {
            assert!(matches!(
                me.derive_aes_key(&minimal_be(&bad)),
                Err(DhError::InvalidPeerKey)
            ));
        }
        assert!(matches!(
            me.derive_aes_key(&[1u8; PRIME_BYTES + 1]),
            Err(DhError::InvalidPeerKey)
        ));
    }

    /// `U1024::zeroize` actually clears the exponent - the operation
    /// `impl Drop for KeyPair` performs.
    ///
    /// This is deliberately *not* named for the drop: observing memory after
    /// a value is dropped needs `unsafe` and is not worth it, so the wipe and
    /// the fact that a drop performs it are pinned separately - here, and in
    /// `key_pair_implements_drop` below.
    #[test]
    fn zeroizing_the_private_exponent_clears_it() {
        let mut pair = KeyPair::generate();
        assert_ne!(pair.private, U1024::ZERO);
        pair.private.zeroize();
        assert_eq!(pair.private, U1024::ZERO);
    }

    /// The other half: `KeyPair` must have a `Drop` impl at all. Without
    /// this, deleting `impl Drop for KeyPair` leaves every other test in this
    /// module green while the exponent is never wiped.
    #[test]
    fn key_pair_implements_drop() {
        // `needs_drop` would be true from the `Vec<u8>` public key alone, so
        // name the impl itself: this bound resolves only while
        // `impl Drop for KeyPair` exists, and deleting it breaks the build
        // here instead of silently leaving the exponent unwiped.
        #[allow(drop_bounds)]
        fn assert_impls_drop<T: Drop>() {}
        assert_impls_drop::<KeyPair>();
    }

    #[test]
    fn prime_is_1024_bits() {
        assert_eq!(PRIME.bits(), 1024);
    }

    /// Peer keys arrive with or without leading zeros; both must work.
    #[test]
    fn padded_and_minimal_peer_encodings_agree() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let mut padded = vec![0u8; PRIME_BYTES - b.public_bytes().len()];
        padded.extend_from_slice(b.public_bytes());
        assert_eq!(
            *a.derive_aes_key(b.public_bytes()).unwrap(),
            *a.derive_aes_key(&padded).unwrap()
        );
    }
}
