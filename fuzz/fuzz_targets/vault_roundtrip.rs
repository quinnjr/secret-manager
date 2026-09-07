//! The header must survive a write/read cycle unchanged.
//!
//! This is what makes the AEAD binding mean anything. The bytes before the
//! ciphertext *are* the associated data, so the daemon authenticates the
//! encoded form of the header while every decision it later makes — which
//! salt to derive with, which KDF cost to pay, which nonce to open with —
//! comes from the *parsed* form. If some header can encode and then decode to
//! a different value, an attacker who can write the file gets a decoder that
//! disagrees with the thing that was signed, and the AEAD no longer covers
//! what it appears to cover.
//!
//! So the property is identity, on every field, for every header the
//! generator can build — including the ones with hostile labels and index
//! ids, which is where a length-prefix or encoding disagreement would live.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secret_manager::vault::format::{self, FormatError, Header, VaultFile};

/// A header plus the ciphertext it will be paired with. `Header` has no
/// `Arbitrary` impl of its own — deriving one would produce uniformly random
/// versions and KDF costs, which the two gates reject before the round trip
/// under test is reached — so this defers to the structure-aware builder.
#[derive(Debug)]
struct Input {
    header: Header,
    ciphertext: Vec<u8>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Input {
            header: smfuzz::header(u)?,
            ciphertext: u.arbitrary()?,
        })
    }
}

/// Whether `decode_header`/`decode` are *supposed* to accept this header.
/// Both apply the same two gates before returning it, and neither depends on
/// anything but the header's own fields, so the target can predict the
/// verdict rather than merely observe it.
fn should_decode(h: &Header) -> bool {
    h.version == format::VERSION && h.kdf.validate().is_ok()
}

fuzz_target!(|input: Input| {
    let Input { header, ciphertext } = input;

    let Ok(bytes) = VaultFile::header_bytes(&header) else {
        // Only `HeaderTooLarge` may stop the writer, and the generator does
        // not build headers anywhere near 16 MiB; anything else here is a
        // postcard failure on a value we just constructed.
        assert!(
            matches!(
                VaultFile::header_bytes(&header),
                Err(FormatError::HeaderTooLarge(_))
            ),
            "header_bytes failed for a reason other than the size ceiling"
        );
        return;
    };

    // The prefix must describe exactly the bytes that follow it, or a reader
    // that trusts the prefix (the PAM module reads a header without the
    // ciphertext) sees a different header than the writer wrote.
    assert_eq!(
        &bytes[..8],
        &format::MAGIC,
        "writer emitted the wrong magic"
    );
    assert_eq!(
        format::header_prefix_len(&bytes[..format::PREFIX_LEN]).unwrap(),
        bytes.len(),
        "length prefix disagrees with the header body it precedes"
    );

    match format::decode_header(&bytes) {
        Ok(back) => {
            assert!(
                should_decode(&header),
                "decode_header accepted a header the gates should have refused"
            );
            // Field-by-field identity. `Header: PartialEq` is derived, so the
            // single comparison covers every field; the individual asserts
            // exist to name the field when one of them regresses.
            assert_eq!(back.version, header.version);
            assert_eq!(back.label, header.label, "label did not survive encoding");
            assert_eq!(back.created, header.created);
            assert_eq!(back.modified, header.modified);
            assert_eq!(
                back.kdf, header.kdf,
                "kdf parameters changed under encoding"
            );
            assert_eq!(back.salt, header.salt, "kdf salt changed under encoding");
            assert_eq!(
                back.index_salt, header.index_salt,
                "index salt changed under encoding"
            );
            assert_eq!(back.nonce, header.nonce, "nonce changed under encoding");
            assert_eq!(back.index, header.index, "index changed under encoding");
            assert_eq!(
                back, header,
                "header is not an identity under encode/decode"
            );
        }
        Err(e) => {
            assert!(
                !should_decode(&header),
                "decode_header refused a well-formed header: {e}"
            );
        }
    }

    // Now the whole file. `new` recomputes the aad from the header, so this
    // also checks that the aad a `VaultFile` carries is the same bytes the
    // standalone header writer produces.
    let Ok(file) = VaultFile::new(header.clone(), ciphertext.clone()) else {
        return;
    };
    assert_eq!(file.aad, bytes, "VaultFile::new and header_bytes disagree");

    let encoded = file.encode();
    assert!(
        encoded.starts_with(&file.aad),
        "encode did not place the aad at the front of the file"
    );
    assert_eq!(encoded.len(), file.aad.len() + ciphertext.len());

    match VaultFile::decode(&encoded) {
        Ok(back) => {
            assert!(should_decode(&header), "decode accepted a refused header");
            assert_eq!(back.header, header, "header changed across encode/decode");
            // Byte-identical aad is the actual invariant: the decoder must
            // hand the AEAD the same associated data the encoder sealed
            // against, not merely an aad that parses to the same header.
            assert_eq!(back.aad, file.aad, "aad changed across encode/decode");
            assert_eq!(
                back.ciphertext, ciphertext,
                "ciphertext changed across encode/decode"
            );
            assert_eq!(back.encode(), encoded, "re-encoding is not stable");
            assert_eq!(
                back, file,
                "VaultFile is not an identity under the round trip"
            );
        }
        Err(e) => {
            assert!(
                !should_decode(&header),
                "decode refused a file it had just written: {e}"
            );
        }
    }
});
