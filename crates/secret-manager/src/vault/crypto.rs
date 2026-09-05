//! Key derivation and authenticated encryption for vault files.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Fast parameters for unit tests only.
    pub const FAST_FOR_TESTS: KdfParams = KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl From<crate::config::KdfConfig> for KdfParams {
    fn from(c: crate::config::KdfConfig) -> Self {
        Self {
            m_cost_kib: c.m_cost_kib,
            t_cost: c.t_cost,
            p_cost: c.p_cost,
        }
    }
}

/// A derived vault key. Zeroized on drop, never printed.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("authentication failed")]
    Auth,
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Key, CryptoError> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut out[..])
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(Key(out))
}

pub fn seal(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Auth)
}

pub fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Auth)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [9u8; NONCE_LEN];

    #[test]
    fn derive_is_deterministic_and_password_sensitive() {
        let a = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let b = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let c = derive_key(b"other", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn seal_open_round_trip() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let ct = seal(&key, &NONCE, b"aad", b"hello").unwrap();
        assert_ne!(&ct[..5], b"hello");
        let pt = open(&key, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn tampered_ciphertext_aad_or_key_fails() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let other = derive_key(b"pw2", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let mut ct = seal(&key, &NONCE, b"aad", b"hello").unwrap();
        assert!(matches!(
            open(&key, &NONCE, b"AAD", &ct),
            Err(CryptoError::Auth)
        ));
        assert!(matches!(
            open(&other, &NONCE, b"aad", &ct),
            Err(CryptoError::Auth)
        ));
        ct[0] ^= 1;
        assert!(matches!(
            open(&key, &NONCE, b"aad", &ct),
            Err(CryptoError::Auth)
        ));
    }

    #[test]
    fn random_bytes_differ() {
        let a: [u8; 24] = random_bytes();
        let b: [u8; 24] = random_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        assert_eq!(format!("{key:?}"), "Key(..)");
    }
}
