//! The vault file as handed to us by whoever holds the file.
//!
//! `VaultFile::decode` runs *before* any authentication — the header is not
//! covered by the AEAD until a successful decrypt — so every byte it reads is
//! attacker-controlled. A panic here is a denial of service on the daemon's
//! startup path, and an unbounded allocation is the same thing by another
//! route.
//!
//! The allocation bound is *measured*, not delegated to libFuzzer's
//! `-rss_limit_mb`: the counter in `smfuzz` sees the peak single allocation
//! per execution, so a decoder that sized a buffer from the header length the
//! attacker declared fails here on the first such input rather than after a
//! gigabyte has been committed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::vault::format::{self, VaultFile};
use smfuzz::VaultBytes;

#[global_allocator]
static ALLOC: smfuzz::PeakAlloc = smfuzz::PeakAlloc;

fuzz_target!(|input: VaultBytes| {
    let bytes = input.to_bytes();

    // The header-length prefix must be rejected on its own, before anything
    // sized by it is allocated.
    if bytes.len() >= format::PREFIX_LEN {
        let _ = format::header_prefix_len(&bytes[..format::PREFIX_LEN]);
    }
    let _ = format::decode_header(&bytes);
    let _ = format::decode_items(&bytes);

    smfuzz::reset_peak();
    let decoded = VaultFile::decode(&bytes);
    let peak = smfuzz::peak();
    let bound = smfuzz::decode_alloc_bound(bytes.len());
    assert!(
        peak <= bound,
        "decoding {} bytes allocated {peak}, over the {bound} bound: an \
         allocation sized by something other than the input",
        bytes.len()
    );

    // A generator arm that can no longer reach the decoder is a third of the
    // budget spent re-testing another arm, and it says nothing when it
    // happens: this arm was dead for exactly that reason once already. If the
    // input carries a valid version and in-range KDF parameters, the decode
    // is not allowed to fail.
    if input.decodes() {
        assert!(
            decoded.is_ok(),
            "an input built to decode did not: {:?}",
            decoded.as_ref().err()
        );
    }

    if let Ok(file) = decoded {
        // Anything that decodes must re-encode to exactly the bytes the
        // decoder claimed to consume: the aad is the authenticated prefix, so
        // a mismatch here is a signature-bypass primitive.
        let re = file.encode();
        assert_eq!(
            &re[..file.aad.len()],
            &file.aad[..],
            "aad is not a prefix of the re-encoded file"
        );
        assert!(
            bytes.starts_with(&file.aad),
            "aad is not a prefix of the input it was parsed from"
        );
        assert_eq!(
            file.aad.len() + file.ciphertext.len(),
            bytes.len(),
            "decode did not account for every byte"
        );
    }
});
