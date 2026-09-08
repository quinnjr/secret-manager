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
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

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
                // `header_bytes` already returns `MAGIC || len || body`, so it
                // *is* the prefix — prepending a second magic and length made
                // the postcard body start with `"SMVAULT\0"`, which decodes as
                // `version = 0x53` and is refused by the version gate. That
                // kept `VaultFile::decode` from ever succeeding on a `Corrupt`
                // input, so this arm silently re-tested `Framed`'s bad-header
                // path and the target's aad assertions were unreachable.
                // `VaultBytes::decodes` below pins the fix.
                let Ok(hb) = format::VaultFile::header_bytes(header) else {
                    return format::MAGIC.to_vec();
                };
                let mut out = Vec::with_capacity(hb.len() + tail.len());
                out.extend_from_slice(&hb);
                out.extend_from_slice(tail);
                out
            }
        }
    }

    /// Whether [`format::VaultFile::decode`] **must** accept these bytes.
    ///
    /// Only a `Corrupt` value can be knowable in advance: it renders a real
    /// `header_bytes` prefix, so the magic, the length and the postcard body
    /// all agree by construction and the only gates left are the version and
    /// the KDF ceilings. `Raw` and `Framed` are whatever the fuzzer made of
    /// them and may legitimately fail.
    ///
    /// The point of this method is that a target can assert on it: the
    /// `Corrupt` arm was dead for exactly this reason once already, and
    /// nothing said so.
    pub fn decodes(&self) -> bool {
        match self {
            VaultBytes::Raw(_) | VaultBytes::Framed { .. } => false,
            VaultBytes::Corrupt { header, .. } => {
                header.version == format::VERSION
                    && header.kdf.validate().is_ok()
                    && format::VaultFile::header_bytes(header).is_ok()
            }
        }
    }
}

/// Records the largest single allocation Rust code makes.
///
/// A target installs it as `#[global_allocator]` and then asserts the *real*
/// allocation bound — that nothing is sized by a length the attacker declared
/// — rather than trusting that a length check happens to come first, or
/// leaning on libFuzzer's `-rss_limit_mb`, which only notices after a
/// gigabyte has already been committed. libFuzzer itself is C++ and allocates
/// through `malloc` directly, so it does not pollute the counter.
pub struct PeakAlloc;

/// The counter [`PeakAlloc`] feeds. Use [`reset_peak`] and [`peak`].
pub static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Start a measurement window.
pub fn reset_peak() {
    PEAK.store(0, Ordering::Relaxed);
}

/// The largest single allocation since the last [`reset_peak`].
pub fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

unsafe impl GlobalAlloc for PeakAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        PEAK.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        PEAK.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        PEAK.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
}

/// Slack for bookkeeping a decoder does around its buffers: the `Zeroizing`
/// wrapper, a length prefix, and serde's own "cautious" sequence pre-allocation
/// (capped at 4 KiB of elements, regardless of the length the input declared).
/// Doubled, because a `Vec` that outgrows that capacity reallocates to twice it.
pub const ALLOC_OVERHEAD: usize = 8 << 10;

/// Bytes a decoder may allocate in a single request while parsing `len` bytes
/// of hostile input.
///
/// The bound that matters is that it is a function of the bytes actually
/// supplied and **not** of the length the header declares — a 12-byte file
/// claiming a 16 MiB header must allocate nothing. The linear factor covers
/// the parsed representation being wider than its encoding: postcard writes an
/// empty `IndexEntry` in 2 bytes and an `attr_hashes` element in 1, while the
/// in-memory forms are `size_of::<IndexEntry>()` and 32 bytes, and a growing
/// `Vec` doubles. `GROWTH` is the ceiling over both, with room to spare; it is
/// a constant, which is the whole point.
pub fn decode_alloc_bound(len: usize) -> usize {
    const GROWTH: usize = 128;
    ALLOC_OVERHEAD + len.saturating_mul(GROWTH)
}

/// A key built from fuzzer bytes.
pub fn key(u: &mut Unstructured) -> arbitrary::Result<secret_manager::vault::crypto::Key> {
    Ok(secret_manager::vault::crypto::Key::from_zeroizing(
        zeroize::Zeroizing::new(u.arbitrary::<[u8; KEY_LEN]>()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secret_manager::vault::crypto::KdfParams;

    // The allocation assertions below only mean anything if the counter is
    // actually installed for this binary.
    #[global_allocator]
    static ALLOC: PeakAlloc = PeakAlloc;

    fn good_header() -> Header {
        Header {
            version: format::VERSION,
            label: "L".into(),
            created: 1,
            modified: 2,
            kdf: FAST,
            salt: [1u8; SALT_LEN],
            index_salt: [2u8; SALT_LEN],
            nonce: [3u8; NONCE_LEN],
            index: vec![IndexEntry {
                id: "i".into(),
                attr_hashes: vec![[4u8; 32]],
            }],
        }
    }

    /// The regression this whole file exists to prevent.
    ///
    /// `Corrupt` renders `header_bytes`, which is *already* `MAGIC || len ||
    /// body`. An earlier version prepended a second magic and length, so the
    /// postcard body began `"SMVAULT\0"`, `version` parsed as the varint
    /// `0x53` and `check_header` refused every single input from this arm. A
    /// third of the generator was therefore re-testing `Framed`'s bad-header
    /// path, and `vault_decode`'s aad assertions were unreachable — with
    /// nothing to say so.
    #[test]
    fn a_corrupt_input_with_a_valid_header_actually_decodes() {
        let bytes = VaultBytes::Corrupt {
            header: Box::new(good_header()),
            tail: vec![9, 9, 9, 9],
        }
        .to_bytes();

        assert_eq!(&bytes[..8], &format::MAGIC, "the prefix is not a vault");
        // The byte after the length prefix is the start of the postcard body:
        // the version varint, never another magic.
        assert_ne!(
            &bytes[format::PREFIX_LEN..format::PREFIX_LEN + 8],
            &format::MAGIC,
            "a second magic was prepended inside the header body"
        );

        let file = format::VaultFile::decode(&bytes)
            .expect("a Corrupt input carrying a valid header must decode");
        assert_eq!(file.header, good_header());
        assert_eq!(file.ciphertext, vec![9, 9, 9, 9]);
        assert!(bytes.starts_with(&file.aad));
        assert_eq!(file.aad.len() + file.ciphertext.len(), bytes.len());
    }

    /// `decodes()` is what the target asserts on, so it must agree with the
    /// decoder on every shape of header the generator can produce.
    #[test]
    fn decodes_agrees_with_the_real_decoder() {
        let cases: Vec<Header> = vec![
            good_header(),
            Header {
                version: 0,
                ..good_header()
            },
            Header {
                version: format::VERSION + 1,
                ..good_header()
            },
            Header {
                kdf: KdfParams {
                    m_cost_kib: u32::MAX,
                    t_cost: 1,
                    p_cost: 1,
                },
                ..good_header()
            },
            Header {
                kdf: KdfParams {
                    m_cost_kib: 8,
                    t_cost: 0,
                    p_cost: 1,
                },
                ..good_header()
            },
            Header {
                index: Vec::new(),
                label: String::new(),
                ..good_header()
            },
        ];
        let mut decoded = 0;
        for h in cases {
            for tail in [Vec::new(), vec![1, 2, 3]] {
                let v = VaultBytes::Corrupt {
                    header: Box::new(h.clone()),
                    tail,
                };
                let bytes = v.to_bytes();
                let got = format::VaultFile::decode(&bytes).is_ok();
                assert_eq!(
                    got,
                    v.decodes(),
                    "decodes() disagrees with the decoder on {h:?}"
                );
                decoded += usize::from(got);
            }
        }
        assert!(decoded >= 4, "no case reached Ok; the arm is dead again");
    }

    /// The `Framed` and `Raw` arms must stay unable to promise a decode, or
    /// the target's assertion would be checking the wrong thing.
    #[test]
    fn only_the_corrupt_arm_promises_a_decode() {
        assert!(!VaultBytes::Raw(vec![0; 64]).decodes());
        assert!(
            !VaultBytes::Framed {
                declared_len: 4,
                tail: vec![0; 64]
            }
            .decodes()
        );
    }

    /// The bound `vault_decode` asserts must actually hold, on every shape of
    /// input the generator emits — otherwise the target would fail on the
    /// first corpus entry rather than on a real regression.
    #[test]
    fn the_declared_allocation_bound_holds_for_real_inputs() {
        let mut worst = 0f64;
        for seed in 0u64..4096 {
            // A cheap deterministic byte source; `Unstructured` turns it into
            // every arm of the generator.
            let raw: Vec<u8> = (0..256u32)
                .map(|i| (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64) >> 33) as u8)
                .collect();
            let mut u = Unstructured::new(&raw);
            let Ok(v) = VaultBytes::arbitrary(&mut u) else {
                continue;
            };
            let bytes = v.to_bytes();
            reset_peak();
            let got = format::VaultFile::decode(&bytes);
            let p = peak();
            assert!(
                p <= decode_alloc_bound(bytes.len()),
                "decoding {} bytes allocated {p}, over the bound {}",
                bytes.len(),
                decode_alloc_bound(bytes.len())
            );
            if bytes.len() > 32 {
                worst = worst.max(p as f64 / bytes.len() as f64);
            }
            drop(got);
        }
        // Reported so the constant can be re-derived rather than guessed at.
        assert!(worst < 128.0, "observed growth factor {worst}");
    }

    /// A declared length far larger than the input must allocate nothing
    /// sized by it. This is the property `-rss_limit_mb` cannot express.
    #[test]
    fn a_declared_length_never_drives_an_allocation() {
        let bytes = VaultBytes::Framed {
            declared_len: format::MAX_HEADER as u32,
            tail: vec![0; 16],
        }
        .to_bytes();
        reset_peak();
        assert!(format::VaultFile::decode(&bytes).is_err());
        let p = peak();
        assert!(
            p <= decode_alloc_bound(bytes.len()),
            "a 28-byte file declaring a {} byte header allocated {p}",
            format::MAX_HEADER
        );
        assert!(p < format::MAX_HEADER, "allocated {p} from the prefix alone");
    }
}
