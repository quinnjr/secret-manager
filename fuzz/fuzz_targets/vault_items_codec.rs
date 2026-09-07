//! The item list, on both sides of the AEAD.
//!
//! `decode_items` runs on plaintext, so reaching it means the key was right —
//! but "right key" is not "trustworthy input". The plaintext is whatever the
//! last writer sealed, and on a shared-uid box that writer may not be the
//! daemon; the PAM path decrypts a file the target user fully controls. A
//! panic here aborts the process holding every other collection's key, and an
//! unbounded allocation driven by a postcard length prefix is the same
//! outcome with a different name.
//!
//! The encode side matters for a different reason: items carry entirely
//! client-supplied strings — a D-Bus label, an attribute key, a content type
//! from `CreateItem` — so if any of those can survive a write and come back
//! different, the daemon returns one client's secret under another client's
//! attributes.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secret_manager::vault::format::{decode_items, encode_items, Item};

/// Hostile items to round-trip, plus raw bytes to throw straight at the
/// decoder. Both directions in one target so the corpus that finds an
/// interesting item shape also feeds the parser.
#[derive(Debug)]
struct Input {
    items: Vec<Item>,
    raw: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Bounded: the property is about the content of an item, not about
        // how many of them fit in a run's memory budget.
        let n = u.arbitrary_len::<u8>()?.min(8);
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            items.push(smfuzz::item(u)?);
        }
        Ok(Input {
            items,
            raw: u.arbitrary()?,
        })
    }
}

fuzz_target!(|input: Input| {
    let Input { items, raw } = input;

    let encoded = encode_items(&items).expect("postcard cannot fail on an owned item list");
    let back = decode_items(&encoded).expect("what encode_items wrote, decode_items must read");

    assert_eq!(
        back.len(),
        items.len(),
        "item count changed across the codec"
    );
    for (a, b) in back.iter().zip(items.iter()) {
        // Named individually so a regression says which field lost data;
        // `Item: PartialEq` compares the same set, secret included.
        assert_eq!(a.id, b.id, "item id did not survive the codec");
        assert_eq!(a.label, b.label, "item label did not survive the codec");
        assert_eq!(
            a.attributes, b.attributes,
            "attributes did not survive the codec"
        );
        assert_eq!(
            &a.secret[..],
            &b.secret[..],
            "secret bytes did not survive the codec"
        );
        assert_eq!(
            a.content_type, b.content_type,
            "content type did not survive the codec"
        );
        assert_eq!(a.created, b.created);
        assert_eq!(a.modified, b.modified);
        assert_eq!(a, b, "item is not an identity under the codec");
    }
    assert_eq!(back, items, "item list is not an identity under the codec");

    // Encoding is a function of the value, so the second pass must produce
    // the same bytes: a codec whose output depends on anything else (map
    // iteration order, say) would make the ciphertext non-reproducible and
    // every `save` a spurious rewrite.
    assert_eq!(
        &encode_items(&back).unwrap()[..],
        &encoded[..],
        "re-encoding a decoded item list changed the bytes"
    );

    // The dumb case, and the one that matters for availability: raw bytes
    // through the decoder. Whatever comes back must itself be re-encodable,
    // which is where a decoder that invents an item larger than its input
    // would show up.
    if let Ok(decoded) = decode_items(&raw) {
        // postcard is length-prefixed, so no item can decode from fewer
        // bytes than its own contents. A decoder that allocates on an
        // unvalidated length prefix breaks this long before it OOMs, which
        // is what makes it a usable assertion rather than a memory limit.
        let payload: usize = decoded
            .iter()
            .map(|i| i.id.len() + i.label.len() + i.secret.len() + i.content_type.len())
            .sum();
        assert!(
            payload <= raw.len(),
            "decode_items produced {payload} bytes of payload from {} bytes of input",
            raw.len()
        );
        assert_eq!(
            decode_items(&encode_items(&decoded).unwrap()).unwrap(),
            decoded,
            "an item list parsed from raw bytes does not survive re-encoding"
        );
    }
});
