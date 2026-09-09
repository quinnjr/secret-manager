//! Bounded property tests for the vault format and crypto layer.
//!
//! These are the same invariants the `fuzz/` targets assert — header identity
//! under encode/decode, the AEAD covering every byte of the file, the KDF
//! ceilings holding before Argon2 runs, and the hashed index agreeing with
//! the plaintext comparison it stands in for. The fuzz targets need nightly
//! and as much wall clock as you give them, which means in practice they run
//! when someone remembers; these run on every `cargo test`, so a regression
//! in one of those properties fails a normal build rather than waiting for
//! the next fuzzing session.
//!
//! Everything that derives a key uses `KdfParams::FAST_FOR_TESTS`. At the
//! shipped cost a single case would take longer than this whole file.

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use secret_manager::vault::crypto::{
    self, CryptoError, KEY_LEN, KdfParams, Key, NONCE_LEN, SALT_LEN,
};
use secret_manager::vault::format::{
    self, FormatError, Header, IndexEntry, Item, VaultFile, attribute_hash, build_index,
    decode_items, encode_items,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Strings biased towards the characters that break naive encoders and
/// sanitisers, rather than towards `[a-z]+`. Attribute keys, labels and
/// content types are all client-supplied, so this is the realistic alphabet.
fn hostile_string() -> impl Strategy<Value = String> {
    prop_oneof![
        2 => "[a-z][a-z0-9_.:-]{0,16}",
        1 => "[\\PC]{0,24}",
        1 => Just(String::new()),
        1 => prop::sample::select(vec![
            "xdg:schema".to_string(),
            "org.freedesktop.Secret.Generic".to_string(),
            "\u{202e}reversed".to_string(),
            "with\0nul".to_string(),
            "quote\"and\\slash".to_string(),
            "\u{200b}zero width".to_string(),
        ]),
    ]
}

fn attributes() -> impl Strategy<Value = BTreeMap<String, String>> {
    btree_map(hostile_string(), hostile_string(), 0..4)
}

fn item() -> impl Strategy<Value = Item> {
    (
        hostile_string(),
        hostile_string(),
        attributes(),
        vec(any::<u8>(), 0..64),
        hostile_string(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(id, label, attributes, secret, content_type, created, modified)| Item {
                id,
                label,
                attributes,
                secret: Zeroizing::new(secret),
                content_type,
                created,
                modified,
            },
        )
}

fn index_entry() -> impl Strategy<Value = IndexEntry> {
    (hostile_string(), vec(any::<[u8; 32]>(), 0..4)).prop_map(|(id, mut attr_hashes)| {
        // `IndexEntry::matches` binary-searches, so an entry that never came
        // from `build_index` still has to be sorted to be meaningful.
        attr_hashes.sort_unstable();
        IndexEntry { id, attr_hashes }
    })
}

/// A header whose version and KDF are mostly, but not always, acceptable —
/// the two gates `decode` applies have to be exercised from both sides.
fn header() -> impl Strategy<Value = Header> {
    (
        prop_oneof![4 => Just(format::VERSION), 1 => any::<u16>()],
        hostile_string(),
        any::<u64>(),
        any::<u64>(),
        kdf_params(),
        any::<[u8; SALT_LEN]>(),
        any::<[u8; SALT_LEN]>(),
        any::<[u8; NONCE_LEN]>(),
        vec(index_entry(), 0..4),
    )
        .prop_map(
            |(version, label, created, modified, kdf, salt, index_salt, nonce, index)| Header {
                version,
                label,
                created,
                modified,
                kdf,
                salt,
                index_salt,
                nonce,
                index,
            },
        )
}

/// Mostly cheap parameters, with a quarter of them ranging over the whole
/// `u32` space so the ceilings are hit from outside as well as inside.
fn kdf_params() -> impl Strategy<Value = KdfParams> {
    prop_oneof![
        3 => (8u32..64, 1u32..3, 1u32..2),
        1 => (any::<u32>(), any::<u32>(), any::<u32>()),
    ]
    .prop_map(|(m_cost_kib, t_cost, p_cost)| KdfParams {
        m_cost_kib,
        t_cost,
        p_cost,
    })
}

/// The ceilings as documented, restated rather than read from the code, so
/// this cannot pass by recomputing whatever the implementation happens to do.
fn within_ceilings(p: KdfParams) -> bool {
    (1..=16).contains(&p.p_cost)
        && (1..=64).contains(&p.t_cost)
        && p.m_cost_kib <= 256 * 1024
        && p.m_cost_kib >= 8u32.saturating_mul(p.p_cost)
}

/// Whether the two header gates should let this header through.
fn should_decode(h: &Header) -> bool {
    h.version == format::VERSION && h.kdf.validate().is_ok()
}

const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The header must be an identity under `header_bytes`/`decode_header`.
    /// If it is not, the AEAD authenticates a byte string that describes
    /// something other than the header the daemon then acts on.
    #[test]
    fn header_survives_encode_and_decode(h in header()) {
        let bytes = VaultFile::header_bytes(&h).expect("small header");
        prop_assert_eq!(&bytes[..8], &format::MAGIC);
        prop_assert_eq!(
            format::header_prefix_len(&bytes[..format::PREFIX_LEN]).unwrap(),
            bytes.len(),
            "length prefix disagrees with the body it precedes"
        );
        match format::decode_header(&bytes) {
            Ok(back) => {
                prop_assert!(should_decode(&h));
                prop_assert_eq!(back, h, "header is not an identity under encode/decode");
            }
            Err(e) => prop_assert!(
                !should_decode(&h),
                "decode_header refused a well-formed header: {e}"
            ),
        }
    }

    /// The whole file, with the aad compared byte for byte rather than by
    /// what it parses to.
    #[test]
    fn vault_file_survives_encode_and_decode(h in header(), ct in vec(any::<u8>(), 0..64)) {
        let file = VaultFile::new(h.clone(), ct.clone()).expect("small header");
        let encoded = file.encode();
        prop_assert!(encoded.starts_with(&file.aad));
        prop_assert_eq!(encoded.len(), file.aad.len() + ct.len());
        match VaultFile::decode(&encoded) {
            Ok(back) => {
                prop_assert!(should_decode(&h));
                prop_assert_eq!(&back.aad, &file.aad, "aad changed across the round trip");
                prop_assert_eq!(&back.ciphertext, &ct);
                prop_assert_eq!(back, file);
            }
            Err(e) => prop_assert!(!should_decode(&h), "decode refused what it wrote: {e}"),
        }
    }

    /// Items, including their secrets, survive the codec unchanged, and the
    /// encoding is a function of the value alone.
    #[test]
    fn items_survive_the_codec(items in vec(item(), 0..6)) {
        let encoded = encode_items(&items).unwrap();
        let back = decode_items(&encoded).unwrap();
        prop_assert_eq!(&back, &items);
        prop_assert_eq!(&encode_items(&back).unwrap()[..], &encoded[..],
            "re-encoding a decoded list changed the bytes");
    }

    /// `decode_items` on bytes nobody sealed: never a panic, and never more
    /// payload than the input could have carried. postcard length-prefixes
    /// every string and byte slice, so a decoder that allocated on an
    /// unvalidated prefix would break this bound long before it exhausted
    /// memory.
    #[test]
    fn decode_items_is_bounded_by_its_input(raw in vec(any::<u8>(), 0..512)) {
        if let Ok(decoded) = decode_items(&raw) {
            let payload: usize = decoded
                .iter()
                .map(|i| i.id.len() + i.label.len() + i.secret.len() + i.content_type.len())
                .sum();
            prop_assert!(
                payload <= raw.len(),
                "{payload} bytes of payload from {} bytes of input",
                raw.len()
            );
        }
    }

    /// The validator must agree exactly with the documented ceilings, and a
    /// refusal must happen before Argon2 is constructed — which is why the
    /// out-of-range cases can be driven through `derive_key` at all.
    #[test]
    fn kdf_ceilings_hold_before_argon2_runs(params in kdf_params()) {
        prop_assert_eq!(
            params.validate().is_ok(),
            within_ceilings(params),
            "validate() and the documented ceilings disagree on {:?}",
            params
        );
        if !within_ceilings(params) {
            prop_assert!(matches!(
                crypto::derive_key(b"pw", &[0u8; SALT_LEN], params),
                Err(CryptoError::UnsafeKdf(_))
            ), "derive_key reached Argon2 with out-of-range parameters");

            // The same refusal on the parse path: the header is
            // unauthenticated, so this is where a hostile file is stopped.
            let mut h = fixed_header();
            h.kdf = params;
            let bytes = VaultFile::new(h, vec![0u8; 16]).unwrap().encode();
            prop_assert!(matches!(
                VaultFile::decode(&bytes),
                Err(FormatError::UnsafeKdf(_))
            ));
        }
    }

    /// A header whose declared length runs past its encoded body must be
    /// refused, not accepted with the surplus quietly absorbed into the
    /// associated data. `postcard` stops at the end of the first complete
    /// message, so padding is invisible to the decoder unless the remainder
    /// is checked — the same non-canonical encoding `protocol::decode_frame`
    /// refuses, and for the same reason.
    ///
    /// The round-trip half matters as much: this tightens only what is
    /// *accepted*, and no file we write can hit it, because `header_bytes`
    /// declares exactly the length it encoded. So the canonical encoding of
    /// the very same header must still decode, to the same header and the
    /// same associated data.
    #[test]
    fn a_padded_vault_header_is_refused(
        label in hostile_string(),
        pad in vec(any::<u8>(), 1..8),
        ciphertext in vec(any::<u8>(), 0..16),
    ) {
        let mut header = fixed_header();
        header.label = label;
        let file = VaultFile::new(header.clone(), ciphertext.clone()).unwrap();
        let canonical = file.encode();

        let decoded = VaultFile::decode(&canonical).unwrap();
        prop_assert_eq!(&decoded.header, &header);
        prop_assert_eq!(&decoded.aad, &file.aad);
        prop_assert_eq!(&decoded.ciphertext, &ciphertext);
        prop_assert_eq!(format::decode_header(&canonical).unwrap(), header);

        // The same header body, padded, with the length prefix bumped to
        // cover the padding.
        let body_len = file.aad.len() - format::PREFIX_LEN;
        let mut padded = file.aad.clone();
        padded.extend_from_slice(&pad);
        padded.extend_from_slice(&ciphertext);
        padded[8..format::PREFIX_LEN]
            .copy_from_slice(&((body_len + pad.len()) as u32).to_le_bytes());

        prop_assert!(
            matches!(
                VaultFile::decode(&padded),
                Err(FormatError::TrailingHeaderBytes(n)) if n == pad.len()
            ),
            "a padded header was accepted by VaultFile::decode"
        );
        prop_assert!(
            matches!(
                format::decode_header(&padded),
                Err(FormatError::TrailingHeaderBytes(n)) if n == pad.len()
            ),
            "a padded header was accepted by decode_header"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The three claims the vault rests on, against the in-memory crypto
    /// layer: the right key opens an intact file, a key one bit away never
    /// does, and a single flipped byte *anywhere* in the file — header,
    /// length prefix, nonce or ciphertext — is fatal, because everything
    /// before the ciphertext is the associated data.
    #[test]
    fn sealed_vault_opens_only_intact_and_only_with_the_right_key(
        password in vec(any::<u8>(), 0..24),
        other_password in vec(any::<u8>(), 0..24),
        salt in any::<[u8; SALT_LEN]>(),
        nonce in any::<[u8; NONCE_LEN]>(),
        items in vec(item(), 0..3),
        corrupt_at in any::<prop::sample::Index>(),
        corrupt_mask in 1u8..=255,
    ) {
        let key = crypto::derive_key(&password, &salt, FAST).unwrap();
        let header = Header {
            version: format::VERSION,
            label: "prop".into(),
            created: 0,
            modified: 1,
            kdf: FAST,
            salt,
            index_salt: [7u8; SALT_LEN],
            nonce,
            index: build_index(&[7u8; SALT_LEN], &items, true),
        };
        let plain = encode_items(&items).unwrap();
        let shell = VaultFile::new(header, Vec::new()).unwrap();
        let ciphertext = crypto::seal(&key, &shell.header.nonce, &shell.aad, &plain).unwrap();
        let file = VaultFile::new(shell.header, ciphertext).unwrap();
        let bytes = file.encode();

        // Intact, right key: the items come back exactly.
        let decoded = VaultFile::decode(&bytes).unwrap();
        prop_assert_eq!(&decoded.aad, &file.aad);
        let opened =
            crypto::open(&key, &decoded.header.nonce, &decoded.aad, &decoded.ciphertext).unwrap();
        prop_assert_eq!(decode_items(&opened).unwrap(), items);

        // A key one bit away is still the wrong key.
        let mut wrong = *key.as_bytes();
        wrong[usize::from(corrupt_mask) % KEY_LEN] ^= 1;
        let wrong_key = Key::from_zeroizing(Zeroizing::new(wrong));
        prop_assert!(crypto::open(
            &wrong_key, &decoded.header.nonce, &decoded.aad, &decoded.ciphertext
        ).is_err());

        if other_password != password {
            let other = crypto::derive_key(&other_password, &salt, FAST).unwrap();
            prop_assert_ne!(other.as_bytes(), key.as_bytes());
            prop_assert!(crypto::open(
                &other, &decoded.header.nonce, &decoded.aad, &decoded.ciphertext
            ).is_err());
        }

        // One flipped byte, anywhere.
        let mut damaged = bytes.clone();
        let at = corrupt_at.index(damaged.len());
        damaged[at] ^= corrupt_mask;
        if let Ok(bad) = VaultFile::decode(&damaged) {
            prop_assert!(
                crypto::open(&key, &bad.header.nonce, &bad.aad, &bad.ciphertext).is_err(),
                "a file corrupted at offset {at} still decrypted"
            );
        }
    }

    /// The hashed index and the plaintext attribute comparison must return
    /// the same answer for every query. `search_ids` uses the first while a
    /// vault is locked and `search` uses the second once it is open; a client
    /// that sees different results from the two has either been shown ids it
    /// did not match or lost items it did.
    #[test]
    fn hashed_index_agrees_with_plaintext_search(
        salt in any::<[u8; SALT_LEN]>(),
        other_salt in any::<[u8; SALT_LEN]>(),
        items in vec(item(), 0..4),
        extra_query in attributes(),
        with_attributes in any::<bool>(),
        pick in any::<prop::sample::Index>(),
    ) {
        // Half the queries are lifted from a real item, so the "should match"
        // branch is reached rather than only the misses.
        let mut query = extra_query;
        if !items.is_empty() {
            let item = &items[pick.index(items.len())];
            if let Some((k, v)) = item.attributes.iter().next() {
                query.insert(k.clone(), v.clone());
            }
        }

        for (k, v) in &query {
            prop_assert_eq!(attribute_hash(&salt, k, v), attribute_hash(&salt, k, v));
            if salt != other_salt {
                prop_assert_ne!(
                    attribute_hash(&salt, k, v),
                    attribute_hash(&other_salt, k, v),
                    "attribute_hash ignores the index salt"
                );
            }
            // The length prefix keeps ("a","bc") and ("ab","c") apart.
            if let Some(last) = k.chars().last() {
                let (head, moved) = k.split_at(k.len() - last.len_utf8());
                prop_assert_ne!(
                    attribute_hash(&salt, k, v),
                    attribute_hash(&salt, head, &format!("{moved}{v}"))
                );
            }
        }

        let index = build_index(&salt, &items, with_attributes);
        prop_assert_eq!(index.len(), items.len());
        prop_assert_eq!(&index, &build_index(&salt, &items, with_attributes),
            "build_index is not deterministic");

        for (entry, item) in index.iter().zip(items.iter()) {
            prop_assert_eq!(&entry.id, &item.id);
            prop_assert!(entry.attr_hashes.windows(2).all(|w| w[0] <= w[1]),
                "index hashes are not sorted; binary_search would miss matches");
            let plaintext_hit = query.iter().all(|(k, v)| item.attributes.get(k) == Some(v));
            if with_attributes {
                prop_assert_eq!(entry.attr_hashes.len(), item.attributes.len());
                prop_assert_eq!(
                    entry.matches(&salt, &query),
                    plaintext_hit,
                    "hashed index and plaintext comparison disagree on {:?}",
                    query
                );
            } else {
                prop_assert!(entry.attr_hashes.is_empty(),
                    "attribute hashes written despite locked_search being off");
                prop_assert_eq!(entry.matches(&salt, &query), query.is_empty());
            }
        }
    }
}

proptest! {
    // The on-disk path costs a temp directory, an Argon2 derivation and a
    // save per item, so it runs on far fewer cases than the in-memory ones.
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// The same claims through the real store: create, reopen, refuse the
    /// wrong password, unlock with the right one, and read back what was
    /// written. Then damage the file and confirm it can no longer be opened.
    #[test]
    fn vault_on_disk_round_trips_and_refuses_a_damaged_file(
        password in vec(any::<u8>(), 1..16),
        other_password in vec(any::<u8>(), 1..16),
        items in vec(item(), 0..3),
        corrupt_at in any::<prop::sample::Index>(),
        corrupt_mask in 1u8..=255,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prop.vault");
        let mut vault =
            secret_manager::vault::Vault::create(&path, "prop", &password, FAST).unwrap();
        for i in &items {
            vault
                .insert_item(&i.label, i.attributes.clone(), i.secret.to_vec(), &i.content_type, false)
                .unwrap();
        }

        let mut reopened = secret_manager::vault::Vault::open(&path).unwrap();
        prop_assert!(reopened.is_locked());
        prop_assert_eq!(reopened.item_ids().len(), items.len());
        if other_password != password {
            prop_assert!(reopened.unlock(&other_password).is_err(),
                "the wrong password unlocked a vault");
            prop_assert!(reopened.is_locked(), "a failed unlock left the vault unlocked");
        }
        reopened.unlock(&password).unwrap();
        let read_back = reopened.items().unwrap();
        prop_assert_eq!(read_back.len(), items.len());
        for (a, b) in read_back.iter().zip(items.iter()) {
            prop_assert_eq!(&a.label, &b.label);
            prop_assert_eq!(&a.attributes, &b.attributes);
            prop_assert_eq!(&a.secret[..], &b.secret[..]);
            prop_assert_eq!(&a.content_type, &b.content_type);
        }

        // One flipped byte on disk. Either the parser refuses the file or the
        // AEAD does; what must never happen is a successful unlock.
        let raw = std::fs::read(&path).unwrap();
        let mut damaged = raw.clone();
        let at = corrupt_at.index(damaged.len());
        damaged[at] ^= corrupt_mask;
        std::fs::write(&path, &damaged).unwrap();
        if let Ok(mut v) = secret_manager::vault::Vault::open(&path) {
            // A flipped bit inside the `m_cost_kib` varint can turn 8 KiB
            // into a legal 256 MiB, which is in range and so not a bug — but
            // deriving with it would make this test allocate a quarter of a
            // gigabyte, so skip those rather than pay for them.
            if v.kdf().m_cost_kib <= 1024 && v.kdf().t_cost <= 4 {
                prop_assert!(v.unlock(&password).is_err(),
                    "a vault damaged at offset {at} still unlocked");
                prop_assert!(!v.verify_password(&password).unwrap_or(false),
                    "verify_password accepted a damaged vault");
            }
        }
    }
}

/// A minimal header that differs from the default only where a test changes
/// it, so a refusal is attributable to that one field.
fn fixed_header() -> Header {
    Header {
        version: format::VERSION,
        label: "default".into(),
        created: 0,
        modified: 0,
        kdf: FAST,
        salt: [1u8; SALT_LEN],
        index_salt: [2u8; SALT_LEN],
        nonce: [3u8; NONCE_LEN],
        index: Vec::new(),
    }
}
