//! Properties that must hold for any input, checked directly rather than
//! through the code paths that happen to use them.
//!
//! These came out of a security audit: each one is a claim the design makes
//! that reading alone cannot settle — that no attacker-supplied byte string
//! panics a parser, that the AEAD covers every header field, that a nonce is
//! never reused, and that no object path escapes its namespace.
use secret_manager::protocol::{Request, Response, decode_frame};
use secret_manager::vault::Vault;
use secret_manager::vault::crypto::{self, KdfParams, SALT_LEN};
use secret_manager::vault::format::{self, VaultFile};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Records the largest single allocation made **on the measuring thread**, so
/// a test can assert that a parser never sizes a buffer from a length its
/// input merely declared. `cargo test` runs this binary's tests in parallel,
/// so the counter is armed per thread; an unarmed thread's allocations are
/// invisible to it and cannot inflate the reading.
struct PeakAlloc;

static PEAK: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

unsafe impl GlobalAlloc for PeakAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
}

/// `Cell<bool>` has no destructor, so `try_with` cannot re-enter the
/// allocator here; it still returns `Err` during thread teardown, which is
/// exactly when we want to record nothing.
fn record(n: usize) {
    let _ = ARMED.try_with(|a| {
        if a.get() {
            PEAK.fetch_max(n, Ordering::Relaxed);
        }
    });
}

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

/// Run `f`, returning its value and the largest single allocation it made.
fn measure_peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
    PEAK.store(0, Ordering::Relaxed);
    ARMED.with(|a| a.set(true));
    let out = f();
    ARMED.with(|a| a.set(false));
    (out, PEAK.load(Ordering::Relaxed))
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// No attacker-supplied byte string may panic a parser.
#[test]
fn parsers_never_panic_on_hostile_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.vault");
    Vault::create(&path, "L", b"pw", KdfParams::FAST_FOR_TESTS).unwrap();
    let good = std::fs::read(&path).unwrap();

    let mut st = 0x12345678u64;
    let mut cases = 0;
    for _ in 0..20_000 {
        let mut b = good.clone();
        match lcg(&mut st) % 4 {
            0 => {
                // flip bytes
                for _ in 0..(1 + lcg(&mut st) % 8) {
                    let i = (lcg(&mut st) as usize) % b.len();
                    b[i] ^= (lcg(&mut st) % 256) as u8;
                }
            }
            1 => {
                // truncate
                let n = (lcg(&mut st) as usize) % b.len();
                b.truncate(n);
            }
            2 => {
                // extend
                let n = (lcg(&mut st) as usize) % 64;
                for _ in 0..n {
                    b.push((lcg(&mut st) % 256) as u8);
                }
            }
            _ => {
                // random of random length
                let n = (lcg(&mut st) as usize) % 512;
                b = (0..n).map(|_| (lcg(&mut st) % 256) as u8).collect();
            }
        }
        let _ = VaultFile::decode(&b);
        let _ = format::decode_header(&b);
        if b.len() >= 12 {
            let _ = format::header_prefix_len(&b[..12]);
        }
        let _ = format::decode_items(&b);
        let _ = decode_frame::<Request>(&b);
        let _ = decode_frame::<Response>(&b);
        cases += 1;
    }
    assert_eq!(cases, 20_000);
}

/// A giant declared header length must not allocate; only the real file size
/// counts.
///
/// The refusal alone is not the property — an implementation that allocated
/// 4 GiB and *then* returned an error would satisfy `is_err()` while being
/// precisely the denial of service this exists to rule out. So the allocation
/// is measured, and the bound is a small constant rather than anything the
/// input's own length prefix could grow.
#[test]
fn absurd_header_length_is_rejected_without_allocating() {
    // Enough to hold the 44-byte input itself and the bookkeeping around it,
    // and many orders of magnitude below every declared length below.
    const CEILING: usize = 4096;

    let mut b = Vec::new();
    b.extend_from_slice(b"SMVAULT\0");
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&[0u8; 32]);

    for (declared, prefix_is_err) in [
        (u32::MAX, true),
        (u32::MAX - 1, true),
        (i32::MAX as u32, true),
        (format::MAX_HEADER as u32 + 1, true),
        // Exactly at the cap the prefix is legal — `header_prefix_len` says
        // "you need this many bytes", and the two decoders then refuse
        // because the file does not have them. Allocating nothing matters
        // most here: this is the largest length a caller must not trust.
        (format::MAX_HEADER as u32, false),
    ] {
        b[8..12].copy_from_slice(&declared.to_le_bytes());
        let (results, peak) = measure_peak(|| {
            (
                VaultFile::decode(&b).is_err(),
                format::decode_header(&b).is_err(),
                format::header_prefix_len(&b[..12]).is_err(),
            )
        });
        assert_eq!(
            results,
            (true, true, prefix_is_err),
            "a {declared}-byte header was accepted from a {}-byte file",
            b.len()
        );
        assert!(
            peak <= CEILING,
            "a {}-byte file declaring a {declared}-byte header allocated {peak} \
             bytes in one request; nothing may be sized by the declared length",
            b.len()
        );
    }

    // The counter is observing this thread: a deliberate allocation of a
    // known size must show up, or every bound above would hold vacuously.
    let (_, peak) = measure_peak(|| std::hint::black_box(vec![0u8; 1 << 20]).len());
    assert!(
        peak >= (1 << 20),
        "the allocation counter saw {peak} for a 1 MiB vector; it is not observing this thread"
    );
}

/// Every header field is covered by the AEAD's associated data: changing any
/// one of them must make the correct password fail.
///
/// "Every" is meant literally, and the table below is checked against
/// `format::Header`'s field list — `version`, `label`, `created`, `modified`,
/// `kdf` (all three costs), `salt`, `index_salt`, `nonce`, `index` (both the
/// id and the attribute hashes). Two of them are not caught by the AEAD and
/// are marked as such rather than left out:
///
/// * `salt` changes the derived key, so the failure comes from decryption
///   with the wrong key, not from the tag.
/// * `version` is refused by the parser before any key is derived, so
///   `Vault::open` never returns. That is a *stronger* outcome, but it is a
///   different mechanism, so the field's AEAD coverage is asserted separately
///   and directly against `crypto::open`.
///
/// `nonce` matters more than it looks: it is passed to `crypto::open`
/// separately as well as living in the associated data, so an encoder that
/// stopped putting the header in the AAD entirely would still fail on it —
/// which is exactly why it must be in the table alongside the fields that
/// have no second line of defence.
/// One tweak to a decoded header, so the AEAD-coverage test can name each
/// field it flips.
type HeaderMutation = Box<dyn Fn(&mut format::Header)>;

/// Which layer is expected to reject a given forgery.
enum CaughtBy {
    /// `Vault::open` succeeds and `unlock` fails: the tag, or a key derived
    /// from changed parameters.
    Crypto,
    /// The header never parses, so no key is derived at all.
    Parser,
}

#[test]
fn every_header_field_is_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.vault");
    // Not `FAST_FOR_TESTS`: Argon2 requires `m_cost_kib >= 8 * p_cost`, and at
    // the 8 KiB floor a `p_cost` of 2 is refused by the parameter check rather
    // than by the AEAD — which would test the wrong gate. 64 KiB leaves room
    // to move both memory and parallelism and is still trivially fast.
    let kdf = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let mut v = Vault::create(&path, "Label", b"pw", kdf).unwrap();
    v.insert_item(
        "i",
        BTreeMap::from([("a".into(), "b".into())]),
        b"s".to_vec(),
        "text/plain",
        false,
    )
    .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let file = VaultFile::decode(&bytes).unwrap();

    // The table below is only "every field" for as long as something ties it
    // to the struct. This destructure is that tie: it names every field of
    // `format::Header` with no `..`, so adding one is a compile error here —
    // `E0027`, missing field — and not a green run over an uncovered field.
    //
    // **Every binding named here must appear as a row in `mutate` below**,
    // and `kdf` appears as three rows: its costs are separate fields in the
    // postcard encoding, so a partial associated data would leave the two
    // that are not `t_cost` writable.
    let format::Header {
        version: _,
        label: _,
        created: _,
        modified: _,
        kdf: _,
        salt: _,
        index_salt: _,
        nonce: _,
        index: _,
    } = &file.header;

    let mutate: Vec<(&str, HeaderMutation, CaughtBy)> = vec![
        (
            "label",
            Box::new(|h: &mut format::Header| h.label = "evil".into()),
            CaughtBy::Crypto,
        ),
        (
            "created",
            Box::new(|h: &mut format::Header| h.created ^= 1),
            CaughtBy::Crypto,
        ),
        (
            "modified",
            Box::new(|h: &mut format::Header| h.modified ^= 1),
            CaughtBy::Crypto,
        ),
        (
            "index_salt",
            Box::new(|h: &mut format::Header| h.index_salt[0] ^= 1),
            CaughtBy::Crypto,
        ),
        (
            "index id",
            Box::new(|h: &mut format::Header| {
                if let Some(e) = h.index.first_mut() {
                    e.id = "zzz".into();
                }
            }),
            CaughtBy::Crypto,
        ),
        (
            "index hash",
            Box::new(|h: &mut format::Header| {
                if let Some(e) = h.index.first_mut()
                    && let Some(x) = e.attr_hashes.first_mut()
                {
                    x[0] ^= 1;
                }
            }),
            CaughtBy::Crypto,
        ),
        (
            "kdf t_cost",
            Box::new(|h: &mut format::Header| h.kdf.t_cost += 1),
            CaughtBy::Crypto,
        ),
        // The other two costs were covered only through `t_cost`, which
        // proves nothing about them: they are separate fields in the postcard
        // encoding and a partial AAD would leave them writable.
        (
            "kdf m_cost_kib",
            Box::new(|h: &mut format::Header| h.kdf.m_cost_kib += 8),
            CaughtBy::Crypto,
        ),
        (
            "kdf p_cost",
            Box::new(|h: &mut format::Header| h.kdf.p_cost += 1),
            CaughtBy::Crypto,
        ),
        // The nonce is handed to `crypto::open` separately, so this row would
        // stay green even without the AAD — see the direct check below, which
        // is the one that pins its AAD coverage.
        (
            "nonce",
            Box::new(|h: &mut format::Header| h.nonce[0] ^= 1),
            CaughtBy::Crypto,
        ),
        // The salt is detected by deriving a different key rather than by the
        // tag, but it is still a header field and still must not be flippable.
        (
            "salt",
            Box::new(|h: &mut format::Header| h.salt[0] ^= 1),
            CaughtBy::Crypto,
        ),
        (
            "version",
            Box::new(|h: &mut format::Header| h.version ^= 1),
            CaughtBy::Parser,
        ),
    ];
    for (name, f, caught_by) in mutate {
        let mut h = file.header.clone();
        f(&mut h);
        let forged = VaultFile::new(h, file.ciphertext.clone()).unwrap();
        std::fs::write(&path, forged.encode()).unwrap();
        match caught_by {
            CaughtBy::Crypto => {
                let mut v = Vault::open(&path)
                    .unwrap_or_else(|e| panic!("tampering with {name} broke the parser: {e}"));
                assert!(
                    v.unlock(b"pw").is_err(),
                    "tampering with {name} was not detected"
                );
            }
            CaughtBy::Parser => {
                assert!(
                    Vault::open(&path).is_err(),
                    "tampering with {name} was not refused by the parser"
                );
            }
        }
    }

    // `version` and `nonce`, checked directly against the AEAD rather than
    // through `Vault`, because their `CaughtBy` above is satisfied by a
    // mechanism other than the associated data. This is what makes the test's
    // name true for them: the *only* thing that changes is a header field, the
    // key and the nonce argument are the originals, and the tag must still
    // refuse it.
    let key = crypto::derive_key(b"pw", &file.header.salt, kdf).unwrap();
    assert!(
        crypto::open(&key, &file.header.nonce, &file.aad, &file.ciphertext).is_ok(),
        "the untampered file must open, or the checks below prove nothing"
    );
    for (name, f) in [
        (
            "version",
            Box::new(|h: &mut format::Header| h.version ^= 1) as HeaderMutation,
        ),
        ("nonce", Box::new(|h: &mut format::Header| h.nonce[0] ^= 1)),
    ] {
        let mut h = file.header.clone();
        f(&mut h);
        let forged = VaultFile::new(h, file.ciphertext.clone()).unwrap();
        assert_ne!(forged.aad, file.aad, "{name} is not in the associated data");
        assert!(
            crypto::open(
                &key,
                // The *original* nonce and key: the associated data is the
                // only thing that differs.
                &file.header.nonce,
                &forged.aad,
                &forged.ciphertext
            )
            .is_err(),
            "a header with a forged {name} passed the AEAD"
        );
    }
}

/// Every save must use a fresh nonce, including across key rotations.
#[test]
fn nonces_are_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.vault");
    let mut v = Vault::create(&path, "L", b"pw", KdfParams::FAST_FOR_TESTS).unwrap();
    let mut seen = std::collections::HashSet::new();
    for i in 0..60 {
        v.insert_item(
            &format!("i{i}"),
            BTreeMap::new(),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
        assert!(seen.insert(h.nonce), "nonce reused after {i} saves");
    }
    for i in 0..10 {
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_key(
            format!("pw{i}").as_bytes(),
            &salt,
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        let old = if i == 0 {
            crypto::derive_key(
                b"pw",
                &{
                    let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
                    h.salt
                },
                KdfParams::FAST_FOR_TESTS,
            )
            .unwrap()
        } else {
            let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
            crypto::derive_key(
                format!("pw{}", i - 1).as_bytes(),
                &h.salt,
                KdfParams::FAST_FOR_TESTS,
            )
            .unwrap()
        };
        v.change_key(&old, &salt, KdfParams::FAST_FOR_TESTS, &key)
            .unwrap();
        let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
        assert!(seen.insert(h.nonce), "nonce reused after rotation {i}");
    }
}

/// Object paths must never escape their namespace.
#[test]
fn object_paths_cannot_escape() {
    use secret_manager::dbus::paths;
    for hostile in [
        "/org/freedesktop/secrets/collection/../../../etc/passwd",
        "/org/freedesktop/secrets/collection/a%2Fb",
        "/org/freedesktop/secrets/collection/",
        "/org/freedesktop/secrets/collection//x",
        "/org/freedesktop/secrets/collection/a/b/c",
        "/org/freedesktop/secrets/collection/a b",
        "/org/freedesktop/secrets/collection/a\0b",
        "/org/freedesktop/secrets/collection/.",
        "/org/freedesktop/secrets/collection/..",
        "/org/freedesktop/secrets/aliases/../collection/x",
    ] {
        match paths::parse(hostile) {
            None => {}
            Some(t) => {
                let ids: Vec<String> = match t {
                    paths::Target::Collection(c) => vec![c],
                    paths::Target::Alias(a) => vec![a],
                    paths::Target::Item { collection, item } => vec![collection, item],
                    paths::Target::AliasItem { alias, item } => vec![alias, item],
                };
                for id in ids {
                    assert!(
                        paths::is_segment(&id),
                        "{hostile} yielded unsafe segment {id:?}"
                    );
                    assert!(!id.contains('/') && !id.contains("..") && !id.contains('\0'));
                }
            }
        }
    }
}
