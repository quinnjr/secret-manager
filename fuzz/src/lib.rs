//! Shared machinery for the fuzz targets.
//!
//! The point of this module is **structure-aware** generation. A fuzzer fed
//! uniformly random bytes spends essentially all of its budget being rejected
//! by the first four checks in the parser: the 8-byte magic, the length
//! prefix, the postcard tag bytes, and the AEAD tag. It never reaches the
//! code that actually manipulates attacker-controlled values.
//!
//! So the generators here build inputs that are *already* well-formed in the
//! uninteresting respects and hostile in the interesting ones — a real magic
//! number with an absurd length prefix, a valid header with a 4 GiB index
//! count, a correct frame prefix wrapping a truncated body. Targets that want
//! the dumb case still get it: every generator is reachable from raw bytes,
//! and several targets deliberately fuzz the raw form alongside the
//! structured one.

use arbitrary::{Arbitrary, Unstructured};
use secret_manager::vault::crypto::{KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN};
use secret_manager::vault::format::{self, Header, IndexEntry, Item};
use std::collections::BTreeMap;

/// Cheap Argon2 parameters. Real ones make a fuzz target useless: a single
/// derivation costs more than the whole run's budget, so the fuzzer would
/// measure Argon2's throughput rather than explore the parser.
pub const FAST: KdfParams = KdfParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

/// A `String` built from the fuzzer's bytes, biased towards the characters
/// that actually matter for the sanitisers: quotes, parens, controls, bidi
/// overrides, invisible formatters and multi-byte scalars. Uniform random
/// bytes almost never produce these, and they are the entire attack surface
/// of `display_label` and friends.
pub fn hostile_string(u: &mut Unstructured) -> arbitrary::Result<String> {
    const INTERESTING: &[char] = &[
        '"', '(', ')', '\'', '\\', '\n', '\r', '\t', '\0', '\u{7}', '\u{1b}', '\u{7f}', '\u{00ad}',
        '\u{061c}', '\u{200b}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}',
        '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2060}', '\u{2066}', '\u{2069}',
        '\u{feff}', '\u{fffd}', 'é', '中', '🔐', '/', ':', '=', ' ',
    ];
    let len = u.arbitrary_len::<u8>()?.min(256);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        if u.is_empty() {
            break;
        }
        // Roughly half the characters come from the interesting set, so a
        // label is a plausible forgery attempt rather than line noise.
        if u.ratio(1, 2)? {
            s.push(*u.choose(INTERESTING)?);
        } else if u.ratio(1, 4)? {
            // Anywhere in Unicode, not just Latin-1. This arm exists because
            // its absence hid a real bug: `escape_control` carried its own,
            // narrower table of invisible characters that omitted the
            // private-use planes, and no amount of fuzzing could find it
            // while every generated char came from a `u8`. A proptest using
            // `any::<char>()` found it immediately. Anything that classifies
            // characters must be fed the whole space, including the upper
            // planes and the surrogate gap's neighbours.
            let n = u.int_in_range(0u32..=0x10_FFFF)?;
            s.push(char::from_u32(n).unwrap_or('\u{fffd}'));
        } else {
            s.push(char::from(u.arbitrary::<u8>()?));
        }
    }
    Ok(s)
}

/// KDF parameters spanning the ceilings `format` enforces: mostly cheap, but
/// deliberately reaching the absurd values a hostile header would carry.
pub fn kdf_params(u: &mut Unstructured) -> arbitrary::Result<KdfParams> {
    if u.ratio(3, 4)? {
        Ok(KdfParams {
            m_cost_kib: u.int_in_range(0..=64)?,
            t_cost: u.int_in_range(0..=4)?,
            p_cost: u.int_in_range(0..=4)?,
        })
    } else {
        // The unbounded case: these must be refused by the ceiling check
        // *before* Argon2 is ever called, which is the property under test.
        Ok(KdfParams {
            m_cost_kib: u.arbitrary()?,
            t_cost: u.arbitrary()?,
            p_cost: u.arbitrary()?,
        })
    }
}

/// A structurally valid `Header` with hostile field contents.
pub fn header(u: &mut Unstructured) -> arbitrary::Result<Header> {
    let entries = u.arbitrary_len::<u8>()?.min(32);
    let mut index = Vec::with_capacity(entries);
    for _ in 0..entries {
        if u.is_empty() {
            break;
        }
        let hashes = u.arbitrary_len::<u8>()?.min(8);
        let mut attr_hashes = Vec::with_capacity(hashes);
        for _ in 0..hashes {
            attr_hashes.push(u.arbitrary::<[u8; 32]>()?);
        }
        index.push(IndexEntry {
            id: hostile_string(u)?,
            attr_hashes,
        });
    }
    Ok(Header {
        // Mostly the real version, so the parser gets past the version gate
        // and into the fields that follow it.
        version: if u.ratio(4, 5)? {
            format::VERSION
        } else {
            u.arbitrary()?
        },
        label: hostile_string(u)?,
        created: u.arbitrary()?,
        modified: u.arbitrary()?,
        kdf: kdf_params(u)?,
        salt: u.arbitrary::<[u8; SALT_LEN]>()?,
        index_salt: u.arbitrary::<[u8; SALT_LEN]>()?,
        nonce: u.arbitrary::<[u8; NONCE_LEN]>()?,
        index,
    })
}

/// An `Item` with hostile strings and a bounded secret.
pub fn item(u: &mut Unstructured) -> arbitrary::Result<Item> {
    let n = u.arbitrary_len::<u8>()?.min(8);
    let mut attributes = BTreeMap::new();
    for _ in 0..n {
        if u.is_empty() {
            break;
        }
        attributes.insert(hostile_string(u)?, hostile_string(u)?);
    }
    let secret_len = u.arbitrary_len::<u8>()?.min(4096);
    let mut secret = vec![0u8; secret_len];
    u.fill_buffer(&mut secret)?;
    Ok(Item {
        id: hostile_string(u)?,
        label: hostile_string(u)?,
        attributes,
        secret: zeroize::Zeroizing::new(secret),
        content_type: hostile_string(u)?,
        created: u.arbitrary()?,
        modified: u.arbitrary()?,
    })
}

/// A byte string shaped like a vault file: real magic, a length prefix that
/// may or may not agree with the header that follows, and a tail.
///
/// This is what gets a fuzzer past `decode`'s first two checks. `Corrupt`
/// deliberately keeps the prefix honest and damages what follows, which is
/// where the AEAD and the postcard decoder live.
#[derive(Debug)]
pub enum VaultBytes {
    /// Entirely the fuzzer's bytes — the dumb case, kept so the target still
    /// covers "not a vault at all".
    Raw(Vec<u8>),
    /// Correct magic, fuzzer-chosen length prefix, fuzzer-chosen tail.
    Framed { declared_len: u32, tail: Vec<u8> },
    /// Correct magic and a correct length for a real encoded header, with the
    /// bytes after it (ciphertext, or the header itself) corrupted.
    Corrupt { header: Box<Header>, tail: Vec<u8> },
}

impl<'a> Arbitrary<'a> for VaultBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(VaultBytes::Raw(u.arbitrary()?)),
            1 => Ok(VaultBytes::Framed {
                declared_len: if u.ratio(1, 2)? {
                    // Absurd lengths: the allocation-bound check is the
                    // property under test.
                    u.arbitrary()?
                } else {
                    u.int_in_range(0..=4096)?
                },
                tail: u.arbitrary()?,
            }),
            _ => Ok(VaultBytes::Corrupt {
                header: Box::new(header(u)?),
                tail: u.arbitrary()?,
            }),
        }
    }
}

impl VaultBytes {
    /// Render to the bytes a real `VaultFile::decode` would be handed.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VaultBytes::Raw(b) => b.clone(),
            VaultBytes::Framed { declared_len, tail } => {
                let mut out = Vec::with_capacity(12 + tail.len());
                out.extend_from_slice(&format::MAGIC);
                out.extend_from_slice(&declared_len.to_le_bytes());
                out.extend_from_slice(tail);
                out
            }
            VaultBytes::Corrupt { header, tail } => {
                let Ok(hb) = format::VaultFile::header_bytes(header) else {
                    return format::MAGIC.to_vec();
                };
                let mut out = Vec::with_capacity(12 + hb.len() + tail.len());
                out.extend_from_slice(&format::MAGIC);
                out.extend_from_slice(&(hb.len() as u32).to_le_bytes());
                out.extend_from_slice(&hb);
                out.extend_from_slice(tail);
                out
            }
        }
    }
}

/// A key built from fuzzer bytes.
pub fn key(u: &mut Unstructured) -> arbitrary::Result<secret_manager::vault::crypto::Key> {
    Ok(secret_manager::vault::crypto::Key::from_zeroizing(
        zeroize::Zeroizing::new(u.arbitrary::<[u8; KEY_LEN]>()?),
    ))
}
