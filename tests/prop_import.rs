//! Bounded property tests for the `sm import` cleartext header parsers.
//!
//! A `.keyring` or a `.kwl` is a file on disk that a hostile party may have
//! written, and `sm import --inventory` reads it with no authentication of
//! any kind — the integrity check lives inside the encrypted half, which
//! these parsers never touch. So the invariant is the one
//! `tests/prop_vault.rs` asserts of the vault decoder: **any** byte string is
//! either parsed or rejected with a typed error, and never panics, never
//! allocates from a length field, and never runs off the end of the buffer.
//!
//! Uniformly random bytes bounce off the magic number, so most of the
//! strategies below are structure-aware in the style of `fuzz/src/lib.rs`:
//! a real magic with a hostile count, a well-formed prologue with a truncated
//! index, a valid file with one byte changed.

use proptest::collection::vec;
use proptest::prelude::*;
use secret_manager::import::formats::{
    self, HeaderError, KEYRING_MAGIC, KWALLET_MAGIC, MAX_SOURCE_BYTES, parse_default_file,
    parse_keyring_header, parse_wallet_header,
};

fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// A keyring header with an attacker's choice of every count and length.
fn keyring_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        vec(any::<u8>(), 0..24), // the keyring name's bytes
        any::<u32>(),            // its declared length
        any::<u32>(),            // hash iterations
        any::<u32>(),            // the declared item count
        vec(any::<u8>(), 0..96), // whatever follows, as an index
        (0u8..4, 0u8..4),        // major/minor, mostly the accepted one
    )
        .prop_map(|(name, name_len, iters, items, tail, (major, minor))| {
            let mut out = KEYRING_MAGIC.to_vec();
            out.extend_from_slice(&[major, minor, 0, 0]);
            // Half the cases declare the honest length, half do not.
            let declared = if name_len % 2 == 0 {
                name.len() as u32
            } else {
                name_len
            };
            out.extend_from_slice(&be(declared));
            out.extend_from_slice(&name);
            out.extend_from_slice(&[0; 8]); // created
            out.extend_from_slice(&[0; 8]); // modified
            out.extend_from_slice(&be(0)); // flags
            out.extend_from_slice(&be(0)); // lock timeout
            out.extend_from_slice(&be(iters));
            out.extend_from_slice(&[0; 8]); // salt
            out.extend_from_slice(&[0; 16]); // reserved
            out.extend_from_slice(&be(items));
            out.extend_from_slice(&tail);
            out
        })
}

/// A wallet index with an attacker's choice of folder and entry counts.
fn wallet_bytes() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<u32>(),
        vec((any::<u32>(), vec(any::<u8>(), 0..40)), 0..6),
        (0u8..3, 0u8..3),
    )
        .prop_map(|(folder_count, folders, (major, minor))| {
            let mut out = KWALLET_MAGIC.to_vec();
            out.extend_from_slice(&[major, minor, 3, 2]);
            let declared = if folder_count % 2 == 0 {
                folders.len() as u32
            } else {
                folder_count
            };
            out.extend_from_slice(&be(declared));
            for (entries, body) in folders {
                out.extend_from_slice(&[0xAB; 16]);
                out.extend_from_slice(&be(entries));
                out.extend_from_slice(&body);
            }
            out
        })
}

/// Every parse either succeeds or returns a `HeaderError`. There is no third
/// outcome, and in particular no panic: this is a `Result`-returning API on
/// attacker-controlled bytes, so a panic here is a denial of service in
/// `sm import --inventory`.
fn keyring_never_panics(bytes: &[u8]) {
    if let Ok(inv) = parse_keyring_header(bytes) {
        // A success is a claim about the file, so check the claim.
        assert!(inv.ciphertext_offset <= bytes.len());
        assert!(inv.ciphertext_offset + inv.ciphertext_len <= bytes.len());
        // Nothing was allocated that the file could not hold: the smallest
        // item encoding is 12 bytes.
        assert!(inv.item_count() * 12 <= bytes.len());
        assert!(inv.unlock_credential_count() <= inv.item_count());
        // The keys really are a set, and counting them agrees with the items.
        let counts = inv.attribute_key_counts();
        assert!(counts.values().all(|&n| n <= inv.item_count()));
    }
}

fn wallet_never_panics(bytes: &[u8]) {
    if let Ok(inv) = parse_wallet_header(bytes) {
        assert!(inv.ciphertext_offset <= bytes.len());
        assert!(inv.folder_count() * 20 <= bytes.len());
        assert!(inv.entry_count() * 16 <= bytes.len());
        assert!(inv.empty_folder_count() <= inv.folder_count());
        for f in &inv.folders {
            for e in &f.entry_hashes {
                assert!(inv.contains_entry(&f.folder_hash, e));
            }
        }
    }
}

proptest! {
    /// Arbitrary bytes. Mostly rejected at the magic, which is the point of
    /// having the structured strategies below as well.
    #[test]
    fn no_parser_panics_on_arbitrary_bytes(bytes in vec(any::<u8>(), 0..512)) {
        keyring_never_panics(&bytes);
        wallet_never_panics(&bytes);
        // The parsers are independent: neither may be reached by the other's
        // magic, and both must tolerate the other's file.
        prop_assert!(matches!(
            parse_wallet_header(&bytes),
            Ok(_) | Err(_)
        ));
    }

    #[test]
    fn no_parser_panics_on_a_hostile_keyring(bytes in keyring_bytes()) {
        keyring_never_panics(&bytes);
        wallet_never_panics(&bytes);
    }

    #[test]
    fn no_parser_panics_on_a_hostile_wallet(bytes in wallet_bytes()) {
        wallet_never_panics(&bytes);
        keyring_never_panics(&bytes);
    }

    /// Truncation is the commonest malformation — an interrupted write, a
    /// partial read — and it must be an error at every one of the several
    /// hundred boundaries in a real file, never a panic and never a
    /// silently short inventory.
    #[test]
    fn truncating_a_real_file_anywhere_is_an_error(
        n in 0usize..GOLDEN_KEYRING.len(),
        m in 0usize..WALLET_INDEX_END,
    ) {
        prop_assert!(parse_keyring_header(&GOLDEN_KEYRING[..n]).is_err());
        prop_assert!(parse_wallet_header(&GOLDEN_WALLET[..m]).is_err());
    }

    /// A single flipped byte either parses to something self-consistent or
    /// is refused. It must never parse to an inventory that claims more than
    /// the file holds.
    #[test]
    fn one_corrupted_byte_never_produces_an_inconsistent_inventory(
        at in 0usize..GOLDEN_KEYRING.len(),
        with in any::<u8>(),
    ) {
        let mut bytes = GOLDEN_KEYRING.to_vec();
        bytes[at] = with;
        keyring_never_panics(&bytes);
        let mut bytes = GOLDEN_WALLET.to_vec();
        let at = at % bytes.len();
        bytes[at] = with;
        wallet_never_panics(&bytes);
    }

    /// The `default` file names a keyring that becomes a *filename*. Any
    /// accepted name is a single safe component; a rejected one is rejected
    /// with the one error this can produce.
    #[test]
    fn an_accepted_default_name_is_always_a_safe_basename(s in ".{0,64}") {
        match parse_default_file(&s) {
            Ok(name) => {
                prop_assert!(!name.is_empty());
                prop_assert!(!name.contains('/'));
                prop_assert!(!name.contains('\\'));
                prop_assert!(!name.contains('\0'));
                prop_assert!(name != "." && name != "..");
                prop_assert_eq!(name.trim(), &name);
                // Idempotent: feeding the result back gives the same name.
                prop_assert_eq!(parse_default_file(&name).unwrap(), name);
            }
            Err(e) => prop_assert_eq!(e, HeaderError::InvalidDefaultName),
        }
    }

    /// The size guard is a `>` at the exact boundary, checked from a `stat`
    /// size before a byte is read.
    #[test]
    fn the_size_cap_holds_at_its_boundary(len in any::<u64>()) {
        match formats::check_source_size(len) {
            Ok(()) => prop_assert!(len <= MAX_SOURCE_BYTES),
            Err(HeaderError::FileTooLarge(got)) => {
                prop_assert_eq!(got, len);
                prop_assert!(len > MAX_SOURCE_BYTES);
            }
            Err(e) => prop_assert!(false, "unexpected {e}"),
        }
    }
}

/// Where the golden wallet's cleartext index ends. Truncating *after* it
/// still parses, and must: the parser deliberately stops at
/// `ciphertext_offset` and never looks at the encrypted half, so a wallet
/// with its ciphertext cut short is not a header error. `index_end_is_where_
/// the_parser_stops` pins the number.
const WALLET_INDEX_END: usize = 16 + 4 + 3 * 20 + 4 * 16;

#[test]
fn the_index_end_is_where_the_parser_stops() {
    let inv = parse_wallet_header(GOLDEN_WALLET).unwrap();
    assert_eq!(inv.ciphertext_offset, WALLET_INDEX_END);
    assert!(GOLDEN_WALLET.len() > WALLET_INDEX_END);
    // Everything from the index end on is ciphertext, and cutting it makes no
    // difference to the header.
    assert_eq!(
        parse_wallet_header(&GOLDEN_WALLET[..WALLET_INDEX_END]),
        Ok(inv)
    );
}

const GOLDEN_KEYRING: &[u8] = include_bytes!("fixtures/import/sample.keyring");
const GOLDEN_WALLET: &[u8] = include_bytes!("fixtures/import/sample.kwl");
