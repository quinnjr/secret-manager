//! The peer's DH public key, straight off the bus.
//!
//! `OpenSession(dh-ietf1024-sha256-aes128-cbc-pkcs7, ...)` takes a byte array
//! from any client on the session bus, with no length constraint and no
//! validation the D-Bus layer could do for us. It lands in
//! `KeyPair::derive_aes_key`, which left-pads it into a 1024-bit integer and
//! exponentiates. Two things can go wrong there: a length or value that
//! panics the bignum code (a client-triggered daemon abort), and a
//! degenerate group element that forces the shared secret to a value the
//! client already knows, which would let it read every secret the session
//! carries.
//!
//! The group has been verified elsewhere to be the RFC 2409 group-2 safe
//! prime with g = 2 generating the order-q subgroup. In a safe-prime group
//! the only elements of small order are 1 and p-1, so rejecting {0, 1, p-1},
//! everything at or above p, and everything longer than the modulus is the
//! complete contract — and that is what this target holds the code to,
//! recomputed independently from the bytes rather than read back out of the
//! implementation.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::session::dh::{DhError, KeyPair, PRIME_BYTES};
use secret_manager::session::{SessionCipher, SessionError};
use std::sync::OnceLock;

/// The RFC 2409 second Oakley group prime, big-endian. Duplicated here on
/// purpose: a target that asked the implementation for its own modulus would
/// agree with it no matter what it had been changed to.
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);

fn prime() -> [u8; PRIME_BYTES] {
    let mut out = [0u8; PRIME_BYTES];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&PRIME_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// One key pair for the whole run. Generation is the expensive part (a
/// 1024-bit modexp) and it is not what is under test; reusing it also makes
/// the determinism check below meaningful.
fn pair() -> &'static KeyPair {
    static P: OnceLock<KeyPair> = OnceLock::new();
    P.get_or_init(KeyPair::generate)
}

/// What the peer sent, as a big-endian integer of exactly `PRIME_BYTES`, or
/// `None` if it was too long to be one. Equal-length big-endian byte strings
/// compare lexicographically exactly as the integers do, so the whole
/// contract can be decided without a bignum library.
fn padded(peer: &[u8]) -> Option<[u8; PRIME_BYTES]> {
    if peer.len() > PRIME_BYTES {
        return None;
    }
    let mut out = [0u8; PRIME_BYTES];
    out[PRIME_BYTES - peer.len()..].copy_from_slice(peer);
    Some(out)
}

#[derive(Debug, arbitrary::Arbitrary)]
enum Peer {
    /// Any bytes at all, including the over-long ones the padding must
    /// refuse rather than truncate.
    Bytes(Vec<u8>),
    /// The boundary values, which random bytes will never produce: 0, 1, 2,
    /// p-2, p-1, p, p+1, and p with an arbitrary number of leading zeros.
    Boundary { which: u8, leading_zeros: u8 },
}

/// `n` as `PRIME_BYTES` big-endian bytes, where `n` is the prime offset by a
/// small signed delta.
fn prime_plus(delta: i32) -> [u8; PRIME_BYTES] {
    let mut b = prime();
    let mut carry = delta;
    for i in (0..PRIME_BYTES).rev() {
        if carry == 0 {
            break;
        }
        let v = b[i] as i32 + carry;
        b[i] = v.rem_euclid(256) as u8;
        carry = v.div_euclid(256);
    }
    b
}

impl Peer {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Peer::Bytes(b) => b.clone(),
            Peer::Boundary {
                which,
                leading_zeros,
            } => {
                let core: Vec<u8> = match which % 7 {
                    0 => vec![0],
                    1 => vec![1],
                    2 => vec![2],
                    3 => prime_plus(-2).to_vec(),
                    4 => prime_plus(-1).to_vec(),
                    5 => prime().to_vec(),
                    _ => prime_plus(1).to_vec(),
                };
                let mut out = vec![0u8; *leading_zeros as usize % 8];
                out.extend_from_slice(&core);
                out
            }
        }
    }
}

fuzz_target!(|peer: Peer| {
    let bytes = peer.bytes();
    let me = pair();
    let got = me.derive_aes_key(&bytes);
    // One shared call: a 1024-bit modexp dominates this target's cost, so
    // every derivation the target does itself is throughput it gives up.
    let via_session = SessionCipher::from_dh(me, &bytes);

    // Decide the contract from the bytes alone.
    let acceptable = match padded(&bytes) {
        // Longer than the modulus: refused, never truncated into range.
        None => None,
        Some(v) => {
            let one = {
                let mut o = [0u8; PRIME_BYTES];
                o[PRIME_BYTES - 1] = 1;
                o
            };
            let p_minus_1 = prime_plus(-1);
            if v <= one || v >= p_minus_1 {
                None
            } else {
                Some(v)
            }
        }
    };

    match (acceptable, got) {
        (None, Err(DhError::InvalidPeerKey)) => {
            // A rejection must never become anything but a Dh error: a
            // hostile client must not be able to talk a session that asked
            // for encryption down to `Plain` by sending nonsense.
            match via_session {
                Err(SessionError::Dh(DhError::InvalidPeerKey)) => {}
                Err(e) => panic!("from_dh gave the wrong error for a bad peer key: {e:?}"),
                Ok(_) => panic!("from_dh accepted a peer key derive_aes_key rejected"),
            }
        }
        (None, other) => panic!(
            "degenerate or out-of-range peer key of {} bytes was not rejected: {other:?}",
            bytes.len()
        ),
        (Some(v), Ok(key)) => {
            assert_eq!(key.len(), 16, "the session key must be AES-128");

            // Same pair, same peer, same key — the exponentiation must not
            // depend on anything but its inputs.
            let again = me
                .derive_aes_key(&bytes)
                .expect("a key that derived once must derive again");
            assert_eq!(*key, *again, "derivation is not deterministic");

            // Leading zeros are a client's encoding choice, not a different
            // key: libsecret sends the minimal form, other clients pad.
            if bytes.len() != PRIME_BYTES {
                let full = me
                    .derive_aes_key(&v)
                    .expect("the zero-padded form of an accepted key must also be accepted");
                assert_eq!(
                    *key, *full,
                    "the same integer derived two different keys depending on its padding"
                );
            }

            // The session wrapper must agree with the primitive it wraps.
            match via_session {
                Ok(c) => assert_eq!(c.algorithm(), secret_manager::session::ALGORITHM_DH),
                Err(e) => panic!("from_dh rejected a key derive_aes_key accepted: {e:?}"),
            }
        }
        (Some(_), other) => panic!(
            "a peer key in [2, p-2] was refused: {other:?} for {} bytes",
            bytes.len()
        ),
    }
});
