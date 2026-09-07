//! The vault file as handed to us by whoever holds the file.
//!
//! `VaultFile::decode` runs *before* any authentication — the header is not
//! covered by the AEAD until a successful decrypt — so every byte it reads is
//! attacker-controlled. A panic here is a denial of service on the daemon's
//! startup path, and an unbounded allocation is the same thing by another
//! route.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::vault::format::{self, VaultFile};
use smfuzz::VaultBytes;

fuzz_target!(|input: VaultBytes| {
    let bytes = input.to_bytes();

    // The header-length prefix must be rejected on its own, before anything
    // sized by it is allocated.
    if bytes.len() >= format::PREFIX_LEN {
        let _ = format::header_prefix_len(&bytes[..format::PREFIX_LEN]);
    }
    let _ = format::decode_header(&bytes);
    let _ = format::decode_items(&bytes);

    if let Ok(file) = VaultFile::decode(&bytes) {
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
