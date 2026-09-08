//! The hashed attribute index — search that works while the vault is locked.
//!
//! This index is a deliberate, documented trade: the header is plaintext, so
//! anyone holding the file (and, through `SearchItems`, any bus client) can
//! confirm an attribute guess by hashing it. What must *not* leak is anything
//! more than that, and what must not break is the equivalence the daemon
//! relies on: a locked search returns exactly the ids an unlocked search
//! would. `search_ids` answers from the index while `search` answers from the
//! plaintext attributes, and the two are used interchangeably — if they can
//! disagree, a client either sees ids for items it did not match or misses
//! items it did.
//!
//! The salt is the other half. It is a *separate* random value from the KDF
//! salt, so the same attribute pair hashes differently in two vaults and a
//! precomputed table is worthless against a second file. That is only true if
//! the salt actually reaches the hash.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secret_manager::vault::crypto::SALT_LEN;
use secret_manager::vault::format::{attribute_hash, build_index, Item};
use smfuzz::hostile_string;
use std::collections::BTreeMap;

#[derive(Debug)]
struct Input {
    salt: [u8; SALT_LEN],
    other_salt: [u8; SALT_LEN],
    items: Vec<Item>,
    /// Attribute pairs to search for. Drawn separately from the items so the
    /// fuzzer can produce both hits and misses; the interesting queries are
    /// the near misses, which is what `hostile_string` is for.
    query: BTreeMap<String, String>,
    with_attributes: bool,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n = u.arbitrary_len::<u8>()?.min(6);
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            items.push(smfuzz::item(u)?);
        }
        let q = u.arbitrary_len::<u8>()?.min(4);
        let mut query = BTreeMap::new();
        for _ in 0..q {
            if u.is_empty() {
                break;
            }
            // Half the queries are lifted from an item that exists, so the
            // fuzzer reaches the "should match" branch without having to
            // rediscover a hostile string byte for byte.
            if u.ratio(1, 2)? && !items.is_empty() {
                let item = u.choose(&items)?;
                if let Some((k, v)) = item.attributes.iter().next() {
                    query.insert(k.clone(), v.clone());
                    continue;
                }
            }
            query.insert(hostile_string(u)?, hostile_string(u)?);
        }
        Ok(Input {
            salt: u.arbitrary()?,
            other_salt: u.arbitrary()?,
            items,
            query,
            with_attributes: u.arbitrary()?,
        })
    }
}

/// The plaintext predicate the index stands in for: `Vault::search` keeps an
/// item when every queried pair is present in its attributes.
fn matches_plaintext(item: &Item, query: &BTreeMap<String, String>) -> bool {
    query.iter().all(|(k, v)| item.attributes.get(k) == Some(v))
}

fuzz_target!(|input: Input| {
    let Input {
        salt,
        other_salt,
        items,
        query,
        with_attributes,
    } = input;

    // Determinism, and dependence on the salt. A hash that ignored the salt
    // would make one precomputed dictionary work against every vault on the
    // system, which is the whole reason `index_salt` exists as a field.
    for (k, v) in &query {
        assert_eq!(
            attribute_hash(&salt, k, v),
            attribute_hash(&salt, k, v),
            "attribute_hash is not deterministic"
        );
        if salt != other_salt {
            assert_ne!(
                attribute_hash(&salt, k, v),
                attribute_hash(&other_salt, k, v),
                "attribute_hash ignores the index salt"
            );
        }
        // The length prefix is what stops ("a", "bc") and ("ab", "c") from
        // hashing alike; without it an index hit would not pin down which
        // pair produced it.
        if let Some(last) = k.chars().last() {
            let (head, moved) = k.split_at(k.len() - last.len_utf8());
            assert_ne!(
                attribute_hash(&salt, k, v),
                attribute_hash(&salt, head, &format!("{moved}{v}")),
                "moving a character across the key/value boundary did not change the hash"
            );
        }
    }

    let index = build_index(&salt, &items, with_attributes);
    assert_eq!(
        index.len(),
        items.len(),
        "the index must carry exactly one entry per item"
    );

    for (entry, item) in index.iter().zip(items.iter()) {
        assert_eq!(entry.id, item.id, "index entry is bound to the wrong item");
        // `matches` binary-searches `attr_hashes`, so an unsorted entry would
        // silently miss real matches. This is the precondition that check
        // depends on and nothing else enforces.
        assert!(
            entry.attr_hashes.windows(2).all(|w| w[0] <= w[1]),
            "index entry hashes are not sorted; binary_search would miss matches"
        );
        if with_attributes {
            assert_eq!(
                entry.attr_hashes.len(),
                item.attributes.len(),
                "an attribute pair was dropped from (or invented in) the index"
            );
            for (k, v) in &item.attributes {
                assert!(
                    entry.attr_hashes.contains(&attribute_hash(&salt, k, v)),
                    "an attribute the item carries is missing from its index entry"
                );
            }
        } else {
            // The `locked_search = false` promise: ids only, so a file holder
            // learns the item count and nothing about the attributes.
            assert!(
                entry.attr_hashes.is_empty(),
                "attribute hashes were written despite locked_search being off"
            );
        }

        // The equivalence the daemon relies on. With attributes indexed the
        // hashed search must agree with the plaintext one on every query; a
        // hit that is not a real match is a false id disclosure, and a miss
        // that is a real match is a search that loses items.
        let hashed = entry.matches(&salt, &query);
        if with_attributes {
            assert_eq!(
                hashed,
                matches_plaintext(item, &query),
                "hashed index and plaintext attribute comparison disagree \
                 for item {:?} on query {query:?}",
                item.id
            );
        } else {
            // Without attribute hashes only the empty query can match, and
            // it must still match: an empty search lists every id.
            assert_eq!(
                hashed,
                query.is_empty(),
                "an id-only index matched a non-empty query"
            );
        }

        // A query hashed under a different salt must not match. This is the
        // property that makes the index file-specific.
        if salt != other_salt && !query.is_empty() && with_attributes {
            let cross: BTreeMap<String, String> = query.clone();
            let wrong_salt_hit = cross.iter().all(|(k, v)| {
                entry
                    .attr_hashes
                    .binary_search(&attribute_hash(&other_salt, k, v))
                    .is_ok()
            });
            assert!(
                !wrong_salt_hit,
                "an index entry matched a query hashed under a different salt"
            );
        }
    }

    // Building twice must give the same index: the header is re-encoded on
    // every save, and an index whose contents depended on iteration order
    // would make the ciphertext and the aad churn on every write.
    assert_eq!(
        index,
        build_index(&salt, &items, with_attributes),
        "build_index is not deterministic"
    );
});
