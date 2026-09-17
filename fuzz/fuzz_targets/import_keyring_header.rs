//! A gnome-keyring `.keyring` file's **cleartext** half.
//!
//! This is the only kind of file this project parses that it did not write.
//! `sm import --inventory` reads it with no authentication of any kind —
//! gnome-keyring's integrity check lives inside the encrypted half, which the
//! parser deliberately never touches — so a `.keyring` in
//! `~/.local/share/keyrings/` is attacker-controlled input in the fullest
//! sense: every count, every length prefix, every attribute type is a number
//! somebody else chose.
//!
//! Uniformly random bytes are stopped by a 16-byte magic and a version gate
//! before a single length is read, so `smfuzz::KeyringBytes` emits a real
//! magic and usually the accepted 0.0, and puts the hostility where the
//! interesting code is: the item count, the per-item attribute count, both
//! attribute value encodings, the `0xffffffff` NULL name marker and the
//! unknown-type refusal.
//!
//! Three things are asserted, and the third is the one that matters most:
//!
//! 1. no panic, on any input;
//! 2. an accepted inventory is bounded by the file it came from — nothing was
//!    sized by a number the file merely *declared*, which is measured with
//!    `smfuzz::PeakAlloc` rather than left to `-rss_limit_mb`;
//! 3. an input that is honest in every respect **must** parse, and must parse
//!    to the values it was built from. Without that a target passes happily
//!    on a parser that refuses everything, and — the failure this target was
//!    added for — on a generator that never reaches the item loop at all.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secret_manager::import::formats::{
    HeaderError, KeyringInventory, parse_default_file, parse_keyring_header,
};
use std::collections::BTreeSet;

#[global_allocator]
static ALLOC: smfuzz::PeakAlloc = smfuzz::PeakAlloc;

/// What a successful parse claims about the file, checked against the file.
fn check_self_consistent(inv: &KeyringInventory, bytes: &[u8]) {
    assert!(
        inv.ciphertext_offset <= bytes.len(),
        "ciphertext begins past the end of the file"
    );
    assert!(
        inv.ciphertext_offset + inv.ciphertext_len <= bytes.len(),
        "the declared ciphertext runs past the end of the file"
    );
    // The smallest encoding of an index item is 12 bytes, so an inventory
    // claiming more items than that allows was sized by a declared number.
    assert!(
        inv.item_count().saturating_mul(12) <= bytes.len(),
        "{} items cannot fit in {} bytes",
        inv.item_count(),
        bytes.len()
    );
    assert!(inv.unlock_credential_count() <= inv.item_count());
    for (key, n) in inv.attribute_key_counts() {
        assert!(
            n <= inv.item_count(),
            "attribute {key:?} counted {n} times across {} items",
            inv.item_count()
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // The dumb case first: arbitrary bytes, which is what a truncated write
    // or an entirely wrong file actually looks like.
    // The peak is snapshotted *before* `check_self_consistent`, which
    // allocates a `BTreeMap` cloning every attribute name. Sampling after it
    // would make the assertion's subject "the parser plus this helper"
    // rather than the parser — the structured path below gets this right,
    // and all three paths must.
    smfuzz::reset_peak();
    let parsed = parse_keyring_header(data);
    let peak = smfuzz::peak();
    assert!(
        peak <= smfuzz::decode_alloc_bound(data.len()),
        "parsing {} raw bytes allocated {peak}",
        data.len(),
    );
    if let Ok(inv) = parsed {
        check_self_consistent(&inv, data);
    }

    // The structured case.
    let Ok(spec) = smfuzz::KeyringBytes::arbitrary(&mut u) else {
        return;
    };
    let bytes = spec.to_bytes();

    smfuzz::reset_peak();
    let parsed = parse_keyring_header(&bytes);
    let peak = smfuzz::peak();
    assert!(
        peak <= smfuzz::decode_alloc_bound(bytes.len()),
        "parsing {} bytes allocated {peak}, over the bound {}; a declared count \
         drove an allocation",
        bytes.len(),
        smfuzz::decode_alloc_bound(bytes.len())
    );

    match parsed {
        Ok(inv) => {
            check_self_consistent(&inv, &bytes);
            if spec.parses() {
                // The oracle. Every field, because a parser that reads the
                // right number of items out of the wrong offsets still
                // satisfies every bound above.
                assert_eq!(inv.display_name, spec.honest_display_name().unwrap());
                assert_eq!(inv.created, smfuzz::KEYRING_CREATED);
                assert_eq!(inv.modified, 0);
                assert_eq!(inv.flags, 0);
                assert_eq!(inv.lock_timeout, 0);
                assert_eq!(inv.hash_iterations, spec.hash_iterations);
                assert_eq!(inv.salt, smfuzz::KEYRING_SALT);
                assert_eq!(inv.item_count(), spec.items.len());
                assert_eq!(inv.ciphertext_len, spec.ciphertext.len());
                assert_eq!(inv.ciphertext_offset + inv.ciphertext_len, bytes.len());
                for (got, want) in inv.items.iter().zip(&spec.items) {
                    assert_eq!(got.id, want.id);
                    assert_eq!(got.item_type, want.item_type);
                    // Duplicate names collapse: the index yields a set.
                    let names: BTreeSet<String> =
                        got.attribute_keys.iter().map(str::to_string).collect();
                    assert_eq!(names, want.names());
                    assert_eq!(got.is_unlock_credential(), matches!(want.item_type, 3 | 4));
                }
            }
        }
        Err(e) => {
            assert!(
                !spec.parses(),
                "an honest keyring was refused with {e}: {spec:?}"
            );
            // A refusal names a field, and every variant is one a caller can
            // report. `BadMagic` in particular must be unreachable here: the
            // generator writes a real one, and a target that only ever sees
            // this error is testing a memcmp.
            match e {
                HeaderError::BadMagic(_) => {
                    assert!(spec.raw.is_some(), "the structured generator lost its magic")
                }
                HeaderError::FileTooLarge(_) | HeaderError::InvalidDefaultName => {
                    unreachable!("{e} cannot come from parse_keyring_header")
                }
                _ => {}
            }
        }
    }

    // Truncating the same file anywhere is an error, never a panic: an
    // interrupted write is the commonest malformation there is.
    if let Ok(cut) = u.int_in_range(0..=bytes.len().saturating_sub(1)) {
        smfuzz::reset_peak();
        let parsed = parse_keyring_header(&bytes[..cut]);
        let peak = smfuzz::peak();
        assert!(
            peak <= smfuzz::decode_alloc_bound(cut),
            "parsing a {cut}-byte prefix allocated {peak}"
        );
        if let Ok(inv) = parsed {
            check_self_consistent(&inv, &bytes[..cut]);
        }
    }

    // The `default` file rides along: it is read from the same directory, by
    // the same command, and its contents become a *filename*.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(name) = parse_default_file(text) {
            assert!(!name.is_empty());
            assert!(!name.contains('/') && !name.contains('\\') && !name.contains('\0'));
            assert!(name != "." && name != "..");
            assert_eq!(name.trim(), name, "an accepted name carries whitespace");
            // Reading the result back gives the same name — *unless* the
            // input ended in a doubled suffix, since `x.keyring.keyring` is
            // the honest `default` contents for a file called
            // `x.keyring.keyring` and only one suffix may come off. The
            // weaker form is the true one, and it still catches the case
            // this target found: `login  .keyring` accepted as `login  `,
            // which does not survive being read back.
            if !name.ends_with(".keyring") {
                assert_eq!(parse_default_file(&name).unwrap(), name, "not idempotent");
            }
        }
    }
});
