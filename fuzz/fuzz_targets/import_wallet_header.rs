//! A KWallet `.kwl` file's **cleartext** index.
//!
//! Same trust story as `import_keyring_header`: a `.kwl` in
//! `~/.local/share/kwalletd/` is a file `sm import --inventory` reads with no
//! authentication, because KWallet's integrity check is inside the encrypted
//! half this parser stops before. The index is nothing but a folder count, a
//! folder name hash, an entry count and a run of entry name hashes — four
//! attacker-chosen numbers guarding two nested loops, which is precisely the
//! shape that produces an unbounded allocation when a count is trusted.
//!
//! `folderCount` is the field that would hurt: 20 bytes per folder times
//! `u32::MAX` is 85 GB, and the parser must refuse it from the bytes actually
//! remaining rather than reserve for it. That refusal is asserted here
//! against a measured peak allocation, not against `-rss_limit_mb`, which
//! only notices after the gigabyte is already committed.
//!
//! As with the keyring target, the assertion that carries the weight is the
//! oracle: an index that is honest in every respect must parse, and must
//! parse to the folders and entry hashes it was built from — including
//! `contains_entry`, which is what verification uses to prove no name was
//! mangled between the file and the vault.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secret_manager::import::formats::{HeaderError, WalletInventory, parse_wallet_header};

#[global_allocator]
static ALLOC: smfuzz::PeakAlloc = smfuzz::PeakAlloc;

fn check_self_consistent(inv: &WalletInventory, bytes: &[u8]) {
    assert!(
        inv.ciphertext_offset <= bytes.len(),
        "the index ends past the end of the file"
    );
    // 20 bytes is the smallest encoding of a folder, 16 of an entry hash.
    assert!(
        inv.folder_count().saturating_mul(20) <= bytes.len(),
        "{} folders cannot fit in {} bytes",
        inv.folder_count(),
        bytes.len()
    );
    assert!(
        inv.entry_count().saturating_mul(16) <= bytes.len(),
        "{} entries cannot fit in {} bytes",
        inv.entry_count(),
        bytes.len()
    );
    assert!(inv.empty_folder_count() <= inv.folder_count());
    for f in &inv.folders {
        for e in &f.entry_hashes {
            assert!(
                inv.contains_entry(&f.folder_hash, e),
                "an entry the index holds is not found by contains_entry"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Arbitrary bytes: a wrong file, a truncated write, a `.kwl` from a
    // version this build does not read.
    smfuzz::reset_peak();
    if let Ok(inv) = parse_wallet_header(data) {
        check_self_consistent(&inv, data);
    }
    assert!(
        smfuzz::peak() <= smfuzz::decode_alloc_bound(data.len()),
        "parsing {} raw bytes allocated {}",
        data.len(),
        smfuzz::peak()
    );

    let Ok(spec) = smfuzz::WalletBytes::arbitrary(&mut u) else {
        return;
    };
    let bytes = spec.to_bytes();

    smfuzz::reset_peak();
    let parsed = parse_wallet_header(&bytes);
    let peak = smfuzz::peak();
    assert!(
        peak <= smfuzz::decode_alloc_bound(bytes.len()),
        "parsing {} bytes allocated {peak}, over the bound {}; a declared folder or \
         entry count drove an allocation",
        bytes.len(),
        smfuzz::decode_alloc_bound(bytes.len())
    );

    match parsed {
        Ok(inv) => {
            check_self_consistent(&inv, &bytes);
            if spec.parses() {
                assert_eq!((inv.cipher, inv.hash), (3, 2));
                assert_eq!(inv.folder_count(), spec.folders.len());
                assert_eq!(
                    inv.entry_count(),
                    spec.folders.iter().map(|f| f.entries.len()).sum::<usize>()
                );
                // The parser stops at the index and never looks at the
                // encrypted half, so this offset is arithmetic, not a guess.
                assert_eq!(inv.ciphertext_offset, spec.index_end());
                for (got, want) in inv.folders.iter().zip(&spec.folders) {
                    assert_eq!(got.folder_hash, want.hash);
                    assert_eq!(got.entry_hashes, want.entries);
                    assert_eq!(got.is_empty(), want.entries.is_empty());
                }
                // Cutting the ciphertext makes no difference to the header.
                assert_eq!(parse_wallet_header(&bytes[..spec.index_end()]), Ok(inv));
            }
        }
        Err(e) => {
            assert!(
                !spec.parses(),
                "an honest wallet index was refused with {e}: {spec:?}"
            );
            match e {
                HeaderError::BadMagic(_) => {
                    assert!(spec.raw.is_some(), "the structured generator lost its magic")
                }
                HeaderError::FileTooLarge(_)
                | HeaderError::InvalidDefaultName
                | HeaderError::NonUtf8 { .. }
                | HeaderError::NullName { .. }
                | HeaderError::UnknownAttributeType { .. } => {
                    unreachable!("{e} cannot come from parse_wallet_header")
                }
                _ => {}
            }
        }
    }

    // Every truncation of the same index is an error or a shorter, still
    // self-consistent inventory — never a panic.
    if let Ok(cut) = u.int_in_range(0..=bytes.len().saturating_sub(1)) {
        smfuzz::reset_peak();
        if let Ok(inv) = parse_wallet_header(&bytes[..cut]) {
            check_self_consistent(&inv, &bytes[..cut]);
        }
        assert!(smfuzz::peak() <= smfuzz::decode_alloc_bound(cut));
    }
});
