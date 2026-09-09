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
use secret_manager::import::formats as import_formats;
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

    /// A cheap deterministic byte source. `Unstructured` turns it into every
    /// arm of a generator, and the same seed gives the same case on every
    /// run, so a failure here is reproducible without a corpus.
    fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
        (0..n as u32)
            .map(|i| {
                (seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(i as u64)
                    >> 33) as u8
            })
            .collect()
    }

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
            let raw = lcg_bytes(seed, 256);
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

    // ----------------------------------------------------------------------
    // The import generators, which had no self-tests at all
    // ----------------------------------------------------------------------
    //
    // `VaultBytes` has had these two since the day its `Corrupt` arm was
    // found to be decoding nothing. `KeyringBytes` and `WalletBytes` assert
    // the same two things in their targets and had nothing checking the
    // *generators* — so a `parses()` that disagreed with its own encoder
    // would have surfaced as a libFuzzer artifact reading like a parser bug.

    /// The bound `import_keyring_header` asserts must hold on every shape the
    /// generator emits, and an input honest in every respect must parse to
    /// exactly the fields it was built from.
    #[test]
    fn the_keyring_generator_agrees_with_the_parser() {
        let mut honest = 0;
        let mut with_items = 0;
        for seed in 0u64..4096 {
            let raw = lcg_bytes(seed, 512);
            let mut u = Unstructured::new(&raw);
            let Ok(spec) = KeyringBytes::arbitrary(&mut u) else {
                continue;
            };
            let bytes = spec.to_bytes();

            reset_peak();
            let parsed = import_formats::parse_keyring_header(&bytes);
            let p = peak();
            assert!(
                p <= decode_alloc_bound(bytes.len()),
                "parsing {} bytes allocated {p}, over the bound {}; a declared count \
                 drove an allocation",
                bytes.len(),
                decode_alloc_bound(bytes.len())
            );

            if !spec.parses() {
                continue;
            }
            honest += 1;
            let inv = parsed.unwrap_or_else(|e| panic!("an honest keyring was refused: {e}"));
            // The same oracle the target asserts, field for field: a parser
            // reading the right number of items out of the wrong offsets
            // still satisfies every bound above.
            assert_eq!(inv.display_name, spec.honest_display_name().unwrap());
            assert_eq!(inv.created, KEYRING_CREATED);
            assert_eq!(inv.modified, 0);
            assert_eq!(inv.flags, 0);
            assert_eq!(inv.lock_timeout, 0);
            assert_eq!(inv.hash_iterations, spec.hash_iterations);
            assert_eq!(inv.salt, KEYRING_SALT);
            assert_eq!(inv.item_count(), spec.items.len());
            assert_eq!(inv.ciphertext_len, spec.ciphertext.len());
            assert_eq!(inv.ciphertext_offset + inv.ciphertext_len, bytes.len());
            if !spec.items.is_empty() {
                with_items += 1;
            }
            for (got, want) in inv.items.iter().zip(&spec.items) {
                assert_eq!(got.id, want.id);
                assert_eq!(got.item_type, want.item_type);
                let names: std::collections::BTreeSet<String> =
                    got.attribute_keys.iter().map(str::to_string).collect();
                assert_eq!(names, want.names());
                assert_eq!(got.is_unlock_credential(), matches!(want.item_type, 3 | 4));
            }
        }
        // Without these the test passes on a `parses()` that is never true,
        // which is the vacuous form of exactly the same bug. The floors are
        // set from a measurement — 1743 honest of 4096 draws, 1410 of them
        // carrying an item — with enough room for a retune and not enough to
        // sit through an order-of-magnitude regression.
        assert!(honest >= 1024, "only {honest} honest keyrings in 4096 draws");
        assert!(
            with_items >= 512,
            "only {with_items} honest keyrings carried an item, so the oracle \
             never checked the item loop"
        );
    }

    /// The same two properties for the wallet index, whose nested folder and
    /// entry loops are the ones a trusted `folderCount` would blow up.
    #[test]
    fn the_wallet_generator_agrees_with_the_parser() {
        let mut honest = 0;
        let mut with_entries = 0;
        for seed in 0u64..4096 {
            let raw = lcg_bytes(seed, 512);
            let mut u = Unstructured::new(&raw);
            let Ok(spec) = WalletBytes::arbitrary(&mut u) else {
                continue;
            };
            let bytes = spec.to_bytes();

            reset_peak();
            let parsed = import_formats::parse_wallet_header(&bytes);
            let p = peak();
            assert!(
                p <= decode_alloc_bound(bytes.len()),
                "parsing {} bytes allocated {p}, over the bound {}; a declared folder \
                 or entry count drove an allocation",
                bytes.len(),
                decode_alloc_bound(bytes.len())
            );

            if !spec.parses() {
                continue;
            }
            honest += 1;
            let inv = parsed.unwrap_or_else(|e| panic!("an honest wallet index was refused: {e}"));
            assert_eq!((inv.cipher, inv.hash), (3, 2));
            assert_eq!(inv.folder_count(), spec.folders.len());
            let entries: usize = spec.folders.iter().map(|f| f.entries.len()).sum();
            assert_eq!(inv.entry_count(), entries);
            if entries > 0 {
                with_entries += 1;
            }
            // Arithmetic, not a guess: the parser stops at the index end and
            // never looks at the encrypted half.
            assert_eq!(inv.ciphertext_offset, spec.index_end());
            for (got, want) in inv.folders.iter().zip(&spec.folders) {
                assert_eq!(got.folder_hash, want.hash);
                assert_eq!(got.entry_hashes, want.entries);
                assert_eq!(got.is_empty(), want.entries.is_empty());
                for e in &want.entries {
                    assert!(inv.contains_entry(&want.hash, e));
                }
            }
        }
        // Measured: 2179 honest of 4096 draws, 1244 of them with an entry.
        assert!(honest >= 1024, "only {honest} honest wallets in 4096 draws");
        assert!(
            with_entries >= 512,
            "only {with_entries} honest wallets carried an entry, so the oracle \
             never checked the entry-hash loop"
        );
    }

    /// The named seeds must exercise the arm they are named for. This one was
    /// byte-identical to `seed-empty` — it declared *zero* items — so the one
    /// seed whose job is to put libFuzzer a mutation away from the item-count
    /// guard seeded the same input as its neighbour.
    #[test]
    fn the_absurd_item_count_seed_hits_the_item_count_guard() {
        let seed = include_bytes!("../corpus/import_keyring_header/seed-absurd-item-count");
        let empty = include_bytes!("../corpus/import_keyring_header/seed-empty");
        assert_ne!(
            seed.as_slice(),
            empty.as_slice(),
            "the seed is byte-identical to seed-empty again"
        );
        match import_formats::parse_keyring_header(seed) {
            Err(import_formats::HeaderError::ImpossibleLength { field, declared }) => {
                assert_eq!(field, "item count");
                assert_eq!(declared, u64::from(u32::MAX));
            }
            other => panic!("expected an item-count refusal, got {other:?}"),
        }
        // And `seed-empty` still parses, so the pair really is a contrast.
        let inv = import_formats::parse_keyring_header(empty).expect("seed-empty must parse");
        assert_eq!(inv.item_count(), 0);
    }
}

// --------------------------------------------------------------------------
// `sm import`: the cleartext headers of foreign keyring files
// --------------------------------------------------------------------------
//
// These are the only files this project parses that it did not write, read by
// `sm import --inventory` with **no authentication of any kind** — the source
// formats keep their integrity check inside the encrypted half, which the
// parsers never touch. A `.keyring` or a `.kwl` in `~/.local/share/` may have
// been written by anything.
//
// Random bytes bounce off a 16- or 12-byte magic and a version gate before a
// single length is read, so the generators below emit a real magic and,
// usually, the accepted version — and put the hostility where it belongs: in
// the counts, the length prefixes, the attribute types and the NULL marker.
// They mirror `tests/prop_import.rs`, which is the same invariants at
// `cargo test` speed.

/// Big-endian, which is what both formats use throughout.
fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// A declared count or length: mostly honest and small, sometimes one of the
/// boundary values that decide the parser's `count` check, sometimes anything.
fn declared_count(u: &mut Unstructured) -> arbitrary::Result<u32> {
    Ok(match u.int_in_range(0..=9)? {
        0..=5 => u.int_in_range(0..=4)?,
        6 | 7 => *u.choose(&[0, 1, u32::MAX, u32::MAX - 1, 1 << 30, 0x0F00_0000])?,
        _ => u.arbitrary()?,
    })
}

/// `None` encodes the honest length; `Some(n)` overrides it.
fn maybe_declared(u: &mut Unstructured) -> arbitrary::Result<Option<u32>> {
    if u.ratio(7, 10)? {
        Ok(None)
    } else {
        Ok(Some(declared_count(u)?))
    }
}

/// A short byte string, biased towards the attribute names a real keyring
/// carries — `xdg:schema` above all, since the whole import classification
/// turns on it — but reaching arbitrary, possibly non-UTF-8, bytes too.
fn attribute_name_bytes(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    if u.ratio(4, 5)? {
        Ok(u.choose(&["xdg:schema", "server", "user", "account", "port", "keyring", ""])?
            .as_bytes()
            .to_vec())
    } else {
        let n = u.int_in_range(0..=6)?;
        let mut out = vec![0u8; n];
        u.fill_buffer(&mut out)?;
        Ok(out)
    }
}

/// One attribute in a gnome-keyring cleartext index.
#[derive(Debug)]
pub struct KeyringAttr {
    pub name: Vec<u8>,
    /// Encode the name as the format's NULL (`0xffffffff`) instead.
    pub null_name: bool,
    pub declared_name_len: Option<u32>,
    pub attr_type: u32,
    pub value: Vec<u8>,
    pub declared_value_len: Option<u32>,
}

impl<'a> Arbitrary<'a> for KeyringAttr {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let name = attribute_name_bytes(u)?;
        let null_name = u.ratio(1, 10)?;
        let declared_name_len = maybe_declared(u)?;
        // Weighted onto the two types the format defines, so the value
        // encodings are reached; the third arm is the unknown-type refusal.
        let attr_type = match u.int_in_range(0..=9)? {
            0..=4 => 0,
            5..=8 => 1,
            _ => u.arbitrary()?,
        };
        let vlen = u.int_in_range(0..=34)?;
        let mut value = vec![0u8; vlen];
        u.fill_buffer(&mut value)?;
        let declared_value_len = maybe_declared(u)?;
        Ok(Self {
            name,
            null_name,
            declared_name_len,
            attr_type,
            value,
            declared_value_len,
        })
    }
}

impl KeyringAttr {
    fn encode(&self, out: &mut Vec<u8>) {
        if self.null_name {
            out.extend_from_slice(&be32(u32::MAX));
        } else {
            out.extend_from_slice(&be32(
                self.declared_name_len.unwrap_or(self.name.len() as u32)
            ));
            out.extend_from_slice(&self.name);
        }
        out.extend_from_slice(&be32(self.attr_type));
        match self.attr_type {
            0 => {
                out.extend_from_slice(&be32(
                    self.declared_value_len.unwrap_or(self.value.len() as u32)
                ));
                out.extend_from_slice(&self.value);
            }
            1 => out.extend_from_slice(&be32(0xDEAD_BEEF)),
            // Refused before a value is read, so none is written.
            _ => {}
        }
    }

    /// The name this attribute contributes to the parsed key set.
    pub fn honest_name(&self) -> Option<&str> {
        if self.null_name || self.declared_name_len.is_some() {
            return None;
        }
        std::str::from_utf8(&self.name).ok()
    }

    fn is_honest(&self) -> bool {
        self.honest_name().is_some()
            && matches!(self.attr_type, 0 | 1)
            && (self.attr_type != 0 || self.declared_value_len.is_none())
    }
}

/// One item in a gnome-keyring cleartext index.
#[derive(Debug)]
pub struct KeyringItemSpec {
    pub id: u32,
    pub item_type: u32,
    pub attrs: Vec<KeyringAttr>,
    pub declared_attr_count: Option<u32>,
}

impl<'a> Arbitrary<'a> for KeyringItemSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let id = u.arbitrary()?;
        // Mostly a type the format defines, including the two unlock
        // credentials the importer refuses.
        let item_type = if u.ratio(4, 5)? {
            u.int_in_range(0..=5)?
        } else {
            u.arbitrary()?
        };
        let n = u.int_in_range(0..=3)?;
        let mut attrs = Vec::new();
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            attrs.push(KeyringAttr::arbitrary(u)?);
        }
        let declared_attr_count = maybe_declared(u)?;
        Ok(Self {
            id,
            item_type,
            attrs,
            declared_attr_count,
        })
    }
}

impl KeyringItemSpec {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&be32(self.id));
        out.extend_from_slice(&be32(self.item_type));
        out.extend_from_slice(&be32(
            self.declared_attr_count.unwrap_or(self.attrs.len() as u32)
        ));
        for a in &self.attrs {
            a.encode(out);
        }
    }

    fn is_honest(&self) -> bool {
        self.declared_attr_count.is_none() && self.attrs.iter().all(KeyringAttr::is_honest)
    }

    /// The attribute names, as the set the index yields.
    pub fn names(&self) -> std::collections::BTreeSet<String> {
        self.attrs
            .iter()
            .filter_map(|a| a.honest_name().map(str::to_string))
            .collect()
    }
}

/// A `.keyring` file's cleartext half.
#[derive(Debug)]
pub struct KeyringBytes {
    /// Entirely the fuzzer's bytes — "not a keyring at all", kept so the
    /// target still covers the dumb case.
    pub raw: Option<Vec<u8>>,
    pub major: u8,
    pub minor: u8,
    pub name: Vec<u8>,
    pub null_name: bool,
    pub declared_name_len: Option<u32>,
    pub hash_iterations: u32,
    pub items: Vec<KeyringItemSpec>,
    pub declared_item_count: Option<u32>,
    pub ciphertext: Vec<u8>,
    pub declared_ciphertext_len: Option<u32>,
}

/// The fixed fields the generator writes, so a target can assert on them.
pub const KEYRING_CREATED: u64 = 1_699_383_593;
pub const KEYRING_SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

impl<'a> Arbitrary<'a> for KeyringBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // One case in eight is raw bytes; the rest are structured.
        let raw = if u.ratio(1, 8)? {
            Some(u.arbitrary()?)
        } else {
            None
        };
        // Weighted hard onto 0.0: the version gate runs before any length is
        // read, so an even spread here filters everything below it.
        let (major, minor) = if u.ratio(4, 5)? {
            (0, 0)
        } else {
            (u.int_in_range(0..=2)?, u.int_in_range(0..=2)?)
        };
        let name = if u.ratio(3, 4)? {
            u.choose(&["Sample keyring", "login", ""])?.as_bytes().to_vec()
        } else {
            let n = u.int_in_range(0..=12)?;
            let mut b = vec![0u8; n];
            u.fill_buffer(&mut b)?;
            b
        };
        let null_name = u.ratio(1, 10)?;
        let declared_name_len = maybe_declared(u)?;
        let hash_iterations = if u.ratio(4, 5)? { 3457 } else { u.arbitrary()? };
        let n = u.int_in_range(0..=3)?;
        let mut items = Vec::new();
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            items.push(KeyringItemSpec::arbitrary(u)?);
        }
        let declared_item_count = maybe_declared(u)?;
        let clen = u.int_in_range(0..=48)?;
        let mut ciphertext = vec![0u8; clen];
        u.fill_buffer(&mut ciphertext)?;
        let declared_ciphertext_len = maybe_declared(u)?;
        Ok(Self {
            raw,
            major,
            minor,
            name,
            null_name,
            declared_name_len,
            hash_iterations,
            items,
            declared_item_count,
            ciphertext,
            declared_ciphertext_len,
        })
    }
}

impl KeyringBytes {
    pub fn to_bytes(&self) -> Vec<u8> {
        if let Some(raw) = &self.raw {
            return raw.clone();
        }
        let mut out = import_formats::KEYRING_MAGIC.to_vec();
        // The crypto and hash ids describe the encrypted half and are read
        // past, never validated.
        out.extend_from_slice(&[self.major, self.minor, 0, 0]);
        if self.null_name {
            out.extend_from_slice(&be32(u32::MAX));
        } else {
            out.extend_from_slice(&be32(
                self.declared_name_len.unwrap_or(self.name.len() as u32)
            ));
            out.extend_from_slice(&self.name);
        }
        out.extend_from_slice(&KEYRING_CREATED.to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&be32(0)); // flags
        out.extend_from_slice(&be32(0)); // lock timeout
        out.extend_from_slice(&be32(self.hash_iterations));
        out.extend_from_slice(&KEYRING_SALT);
        out.extend_from_slice(&[0; 16]); // four reserved words
        out.extend_from_slice(&be32(
            self.declared_item_count.unwrap_or(self.items.len() as u32)
        ));
        for item in &self.items {
            item.encode(&mut out);
        }
        out.extend_from_slice(&be32(
            self.declared_ciphertext_len
                .unwrap_or(self.ciphertext.len() as u32),
        ));
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// The display name a parse of an honest file must produce.
    pub fn honest_display_name(&self) -> Option<String> {
        if self.null_name {
            return Some(String::new());
        }
        if self.declared_name_len.is_some() {
            return None;
        }
        std::str::from_utf8(&self.name).ok().map(str::to_string)
    }

    /// Whether [`import_formats::parse_keyring_header`] **must** accept these
    /// bytes, and produce exactly the fields they were built from.
    ///
    /// This is the point of the type: a target that only asserts "no panic"
    /// would pass on a parser that returned an empty inventory for every
    /// input, and would not notice a generator that stopped reaching the item
    /// loop at all.
    pub fn parses(&self) -> bool {
        self.raw.is_none()
            && (self.major, self.minor) == (0, 0)
            && self.honest_display_name().is_some()
            && self.declared_item_count.is_none()
            && self.declared_ciphertext_len.is_none()
            && self.items.iter().all(KeyringItemSpec::is_honest)
    }
}

/// One folder in a KWallet cleartext index.
#[derive(Debug)]
pub struct WalletFolderSpec {
    pub hash: [u8; 16],
    pub entries: Vec<[u8; 16]>,
    pub declared_entry_count: Option<u32>,
}

impl<'a> Arbitrary<'a> for WalletFolderSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let hash = u.arbitrary::<[u8; 16]>()?;
        let n = u.int_in_range(0..=3)?;
        let mut entries = Vec::new();
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            entries.push(u.arbitrary::<[u8; 16]>()?);
        }
        Ok(Self {
            hash,
            entries,
            declared_entry_count: maybe_declared(u)?,
        })
    }
}

impl WalletFolderSpec {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&be32(
            self.declared_entry_count
                .unwrap_or(self.entries.len() as u32),
        ));
        for e in &self.entries {
            out.extend_from_slice(e);
        }
    }

    fn is_honest(&self) -> bool {
        self.declared_entry_count.is_none()
    }

    /// Bytes this folder occupies in the index when honestly encoded.
    pub fn encoded_len(&self) -> usize {
        20 + 16 * self.entries.len()
    }
}

/// A `.kwl` file's cleartext index.
#[derive(Debug)]
pub struct WalletBytes {
    pub raw: Option<Vec<u8>>,
    pub major: u8,
    pub minor: u8,
    pub folders: Vec<WalletFolderSpec>,
    pub declared_folder_count: Option<u32>,
    /// The encrypted half, which the parser must stop before.
    pub ciphertext: Vec<u8>,
}

impl<'a> Arbitrary<'a> for WalletBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw = if u.ratio(1, 8)? {
            Some(u.arbitrary()?)
        } else {
            None
        };
        // Minor 0 is the KWallet4 layout, a different file entirely, so 0.1
        // is the one accepted version and the one to weight towards.
        let (major, minor) = if u.ratio(4, 5)? {
            (0, 1)
        } else {
            (u.int_in_range(0..=2)?, u.int_in_range(0..=2)?)
        };
        let n = u.int_in_range(0..=4)?;
        let mut folders = Vec::new();
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            folders.push(WalletFolderSpec::arbitrary(u)?);
        }
        let declared_folder_count = maybe_declared(u)?;
        let clen = u.int_in_range(0..=32)?;
        let mut ciphertext = vec![0u8; clen];
        u.fill_buffer(&mut ciphertext)?;
        Ok(Self {
            raw,
            major,
            minor,
            folders,
            declared_folder_count,
            ciphertext,
        })
    }
}

impl WalletBytes {
    pub fn to_bytes(&self) -> Vec<u8> {
        if let Some(raw) = &self.raw {
            return raw.clone();
        }
        let mut out = import_formats::KWALLET_MAGIC.to_vec();
        out.extend_from_slice(&[self.major, self.minor, 3, 2]);
        out.extend_from_slice(&be32(
            self.declared_folder_count
                .unwrap_or(self.folders.len() as u32),
        ));
        for f in &self.folders {
            f.encode(&mut out);
        }
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Where an honest index ends, which is where the parser must stop.
    pub fn index_end(&self) -> usize {
        import_formats::KWALLET_MAGIC.len()
            + 4
            + 4
            + self
                .folders
                .iter()
                .map(WalletFolderSpec::encoded_len)
                .sum::<usize>()
    }

    /// Whether [`import_formats::parse_wallet_header`] **must** accept these
    /// bytes.
    pub fn parses(&self) -> bool {
        self.raw.is_none()
            && (self.major, self.minor) == (0, 1)
            && self.declared_folder_count.is_none()
            && self.folders.iter().all(WalletFolderSpec::is_honest)
    }
}
