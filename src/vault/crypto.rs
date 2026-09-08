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

/// Mixed into every key derivation so the result is specific to this
/// application: a salt borrowed from some other Argon2-based credential can
/// never make us reproduce that credential's key.
pub const KDF_CONTEXT: &[u8] = b"secret-manager vault key v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Ceilings applied to every parameter set before Argon2 runs, whether it
    /// came from a config file or from an unauthenticated vault header. The
    /// `argon2` crate itself accepts `m_cost` up to 4 TiB and `t_cost` up to
    /// `u32::MAX`, so without these a tampered header could abort the process
    /// on allocation or spin it for hours. 256 MiB is four times the shipped
    /// default and small enough that several concurrent derivations still fit
    /// under the unit's `MemoryMax`.
    pub const MAX_M_COST_KIB: u32 = 256 * 1024;
    pub const MAX_T_COST: u32 = 64;
    pub const MAX_P_COST: u32 = 16;

    /// Reject parameter sets outside the ceilings (or below Argon2's own
    /// minimum of 8 KiB per lane).
    pub fn validate(&self) -> Result<(), CryptoError> {
        let reason = if self.p_cost == 0 || self.p_cost > Self::MAX_P_COST {
            Some(format!(
                "p_cost {} outside 1..={}",
                self.p_cost,
                Self::MAX_P_COST
            ))
        } else if self.t_cost == 0 || self.t_cost > Self::MAX_T_COST {
            Some(format!(
                "t_cost {} outside 1..={}",
                self.t_cost,
                Self::MAX_T_COST
            ))
        } else if self.m_cost_kib > Self::MAX_M_COST_KIB {
            Some(format!(
                "m_cost_kib {} exceeds {}",
                self.m_cost_kib,
                Self::MAX_M_COST_KIB
            ))
        } else if self.m_cost_kib < 8 * self.p_cost {
            Some(format!(
                "m_cost_kib {} below Argon2 minimum {}",
                self.m_cost_kib,
                8 * self.p_cost
            ))
        } else {
            None
        };
        match reason {
            Some(r) => Err(CryptoError::UnsafeKdf(r)),
            None => Ok(()),
        }
    }

    /// Fast parameters for unit tests only.
    #[cfg(any(test, feature = "test-util"))]
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

/// A derived vault key. Zeroized on drop, never printed.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// A wiping copy of the key material, for callers that must hand it to an
    /// API taking ownership (the control protocol's request types).
    ///
    /// Cloning the `Zeroizing` directly is preferred over
    /// `Zeroizing::new(*key.as_bytes())`: that spells out a dereference of
    /// the inner array into a temporary that nothing wipes, whereas the
    /// clone's only named value is already `Zeroizing`. Whether either form
    /// actually materialises an intermediate is a codegen question the source
    /// cannot settle - the compiler is free to elide or to spill - so the
    /// claim here is about what the code *writes down*, not about what the
    /// machine does. Callers should treat it as the smaller of two
    /// stack-copy surfaces, not as a guarantee of none.
    pub fn to_zeroizing(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.0.clone()
    }

    /// Wrap key material that was derived elsewhere (the PAM module or the
    /// CLI, arriving over the control socket).
    ///
    /// Takes the buffer already wrapped so the bytes are never copied through
    /// a bare array that nothing wipes: `Key::from_bytes(*zeroizing)` would
    /// leave two unwiped stack copies behind.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; KEY_LEN]>) -> Key {
        Key(bytes)
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
    #[error("refusing unsafe KDF parameters: {0}")]
    UnsafeKdf(String),
    #[error("system random number generator unavailable: {0}")]
    Rng(String),
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Key, CryptoError> {
    params.validate()?;
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    // Domain separation: the hash is bound to this application, so a salt
    // taken from some other Argon2id-derived credential cannot make us
    // reproduce that credential's key.
    let mut input = Zeroizing::new(Vec::with_capacity(KDF_CONTEXT.len() + password.len()));
    input.extend_from_slice(KDF_CONTEXT);
    input.extend_from_slice(password);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(&input, salt, &mut out[..])
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

/// Fallible randomness, for callers that must never panic: the PAM module
/// runs inside someone else's login and cannot unwind across the FFI
/// boundary if `getrandom(2)` is unavailable.
pub fn try_random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(out)
}

/// Randomness for the daemon and CLI, where an unavailable system RNG is a
/// fatal environment error rather than something to degrade around.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    try_random_bytes().expect("getrandom(2) is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [9u8; NONCE_LEN];

    /// `to_zeroizing` had no test at all: nothing pinned that the copy it
    /// hands out is the key.
    #[test]
    fn to_zeroizing_yields_the_key_bytes() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let copy = key.to_zeroizing();
        assert_eq!(&*copy, key.as_bytes());
        // And it is a copy, not an alias: the round trip through
        // `from_zeroizing` reproduces the same key.
        assert_eq!(Key::from_zeroizing(copy).as_bytes(), key.as_bytes());
    }

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
    fn kdf_params_above_ceiling_are_rejected() {
        let huge_memory = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(matches!(
            huge_memory.validate(),
            Err(CryptoError::UnsafeKdf(_))
        ));
        assert!(matches!(
            derive_key(b"pw", &SALT, huge_memory),
            Err(CryptoError::UnsafeKdf(_))
        ));
        let huge_time = KdfParams {
            t_cost: u32::MAX,
            ..KdfParams::FAST_FOR_TESTS
        };
        assert!(huge_time.validate().is_err());
        let huge_lanes = KdfParams {
            p_cost: 1 << 20,
            m_cost_kib: 1 << 20,
            t_cost: 1,
        };
        assert!(huge_lanes.validate().is_err());
        assert!(KdfParams::default().validate().is_ok());
        assert!(KdfParams::FAST_FOR_TESTS.validate().is_ok());
        assert_eq!(KdfParams::MAX_M_COST_KIB, 256 * 1024);
        assert_eq!(KdfParams::MAX_T_COST, 64);
        assert_eq!(KdfParams::MAX_P_COST, 16);
    }

    #[test]
    fn kdf_params_zero_and_below_minimum_are_rejected() {
        let zero_lanes = KdfParams {
            p_cost: 0,
            ..KdfParams::FAST_FOR_TESTS
        };
        assert!(matches!(
            zero_lanes.validate(),
            Err(CryptoError::UnsafeKdf(_))
        ));
        let zero_passes = KdfParams {
            t_cost: 0,
            ..KdfParams::FAST_FOR_TESTS
        };
        assert!(matches!(
            zero_passes.validate(),
            Err(CryptoError::UnsafeKdf(_))
        ));
        let below_minimum = KdfParams {
            m_cost_kib: 31,
            t_cost: 1,
            p_cost: 4,
        };
        assert!(matches!(
            below_minimum.validate(),
            Err(CryptoError::UnsafeKdf(_))
        ));
        let at_minimum = KdfParams {
            m_cost_kib: 32,
            t_cost: 1,
            p_cost: 4,
        };
        assert!(at_minimum.validate().is_ok());
    }

    /// The derived key is bound to this application: the same password and
    /// salt fed to plain Argon2id yield a different key, so a salt borrowed
    /// from another Argon2-based credential cannot make us reproduce its key.
    #[test]
    fn derive_key_is_domain_separated() {
        let ours = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let p = Params::new(8, 1, 1, Some(KEY_LEN)).unwrap();
        let mut plain = [0u8; KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
            .hash_password_into(b"pw", &SALT, &mut plain)
            .unwrap();
        assert_ne!(ours.as_bytes(), &plain);
        assert!(KDF_CONTEXT.starts_with(b"secret-manager"));
    }

    #[test]
    fn try_random_bytes_succeeds_and_matches_shape() {
        let a: [u8; 16] = try_random_bytes().unwrap();
        let b: [u8; 16] = try_random_bytes().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn key_round_trips_through_zeroizing() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let again = Key::from_zeroizing(Zeroizing::new(*key.as_bytes()));
        assert_eq!(key.as_bytes(), again.as_bytes());
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        assert_eq!(format!("{key:?}"), "Key(..)");
    }
}
