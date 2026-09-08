//! The AES-CBC session transport, from both directions.
//!
//! Every secret that crosses the bus goes through `SessionCipher`. The
//! encrypt side sees plaintext the daemon owns; the decrypt side sees an
//! `(oayays)` struct — IV and ciphertext — supplied entirely by the client,
//! with lengths of the client's choosing. `decrypt` is therefore called with
//! attacker bytes on every `CreateItem` and `SetSecret`, and an IV of the
//! wrong length or a ciphertext that is not a whole number of blocks must be
//! an error rather than a slice panic.
//!
//! Be precise about what integrity property exists: the Secret Service spec
//! fixes this construction at AES-128-CBC with PKCS#7 and **no MAC**, so a
//! corrupted ciphertext is not detectable in general — roughly 255 times in
//! 256 the padding check happens to fail, but the rest of the time
//! decryption succeeds and returns garbage. Asserting "corruption is an
//! error" would be asserting something false. What *is* guaranteed, and what
//! this target asserts, is that corruption never yields the original
//! plaintext: CBC decryption is a bijection on (IV, ciphertext) blocks and
//! PKCS#7 padding is injective, so a different (IV, ciphertext) pair cannot
//! unpad to the plaintext the real pair encrypted.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::session::{dh, SessionCipher, SessionError, ALGORITHM_PLAIN};
use std::sync::OnceLock;

/// One agreed session for the whole run: two key pairs and the cipher each
/// side derives. Generating these is a pair of 1024-bit modexps and is not
/// what is under test.
fn session() -> &'static (SessionCipher, SessionCipher) {
    static S: OnceLock<(SessionCipher, SessionCipher)> = OnceLock::new();
    S.get_or_init(|| {
        let client = dh::KeyPair::generate();
        let server = dh::KeyPair::generate();
        let c = SessionCipher::from_dh(&client, server.public_bytes()).expect("client cipher");
        let s = SessionCipher::from_dh(&server, client.public_bytes()).expect("server cipher");
        (c, s)
    })
}

#[derive(Debug, arbitrary::Arbitrary)]
struct Case {
    /// Exercise the `plain` transport too: it is what a client that skipped
    /// `OpenSession`'s DH negotiation gets, and it must still be a faithful
    /// pass-through.
    plain: bool,
    plaintext: Vec<u8>,
    /// A byte to flip somewhere in the IV or the ciphertext.
    corrupt_at: u16,
    corrupt_xor: u8,
    corrupt_iv: bool,
    /// Bytes handed to `decrypt` with no relationship to anything encrypted.
    hostile_params: Vec<u8>,
    hostile_value: Vec<u8>,
}

fuzz_target!(|case: Case| {
    let plain = SessionCipher::Plain;
    let (enc, dec) = if case.plain {
        (&plain, &plain)
    } else {
        let (c, s) = session();
        (c, s)
    };
    let pt = &case.plaintext[..];

    // --- the honest path ---
    let (iv, ct) = enc.encrypt(pt);
    if case.plain {
        assert!(iv.is_empty(), "the plain transport has no IV");
        assert_eq!(ct, pt, "the plain transport must not alter the secret");
        assert_eq!(enc.algorithm(), ALGORITHM_PLAIN);
    } else {
        assert_eq!(iv.len(), 16, "AES-128-CBC needs a 16-byte IV");
        // PKCS#7 always adds a block; a ciphertext the same length as the
        // plaintext would mean the padding was skipped.
        assert_eq!(
            ct.len(),
            (pt.len() / 16 + 1) * 16,
            "ciphertext is not the PKCS#7-padded length"
        );
        assert_ne!(&ct[..], pt, "the ciphertext is the plaintext");
    }
    let back = dec
        .decrypt(&iv, &ct)
        .expect("the other side of the session must decrypt what this side wrote");
    assert_eq!(
        back.as_slice(),
        pt,
        "the secret did not survive the session"
    );

    // --- corruption ---
    //
    // Not "must fail": unauthenticated CBC cannot promise that. Must not
    // silently become the original secret, which it also cannot do.
    if !case.plain && case.corrupt_xor != 0 {
        let (mut civ, mut cct) = (iv.clone(), ct.clone());
        if case.corrupt_iv {
            let i = case.corrupt_at as usize % civ.len();
            civ[i] ^= case.corrupt_xor;
        } else {
            let i = case.corrupt_at as usize % cct.len();
            cct[i] ^= case.corrupt_xor;
        }
        match dec.decrypt(&civ, &cct) {
            Err(SessionError::Decrypt) => {}
            Err(e) => panic!("corrupted input gave an unexpected error: {e:?}"),
            Ok(garbage) => assert_ne!(
                garbage.as_slice(),
                pt,
                "a corrupted ciphertext decrypted to the original plaintext"
            ),
        }

        // Truncating the ciphertext changes the padded length, so it cannot
        // unpad to the same plaintext either.
        if cct.len() > 16 {
            let short = &ct[..ct.len() - 16];
            if let Ok(garbage) = dec.decrypt(&iv, short) {
                assert_ne!(
                    garbage.as_slice(),
                    pt,
                    "a truncated ciphertext decrypted to the original plaintext"
                );
            }
        }
    }

    // --- arbitrary client input ---
    //
    // These lengths are whatever a bus client put in the `(oayays)` struct.
    let out = dec.decrypt(&case.hostile_params, &case.hostile_value);
    if case.plain {
        // The plain transport is defined to hand the value straight back.
        assert_eq!(
            out.expect("plain decrypt cannot fail").as_slice(),
            &case.hostile_value[..]
        );
    } else {
        match out {
            Err(SessionError::BadIv(n)) => assert_eq!(
                n,
                case.hostile_params.len(),
                "the IV-length error must report the length it saw"
            ),
            Err(SessionError::Decrypt) => assert_eq!(
                case.hostile_params.len(),
                16,
                "a decrypt failure implies the IV length was accepted"
            ),
            Err(e) => panic!("unexpected error decrypting client bytes: {e:?}"),
            Ok(plain) => {
                // A success is only possible for a 16-byte IV and a whole
                // number of blocks whose last block happened to unpad.
                assert_eq!(case.hostile_params.len(), 16);
                assert_eq!(case.hostile_value.len() % 16, 0);
                assert!(!case.hostile_value.is_empty());
                assert!(
                    plain.len() < case.hostile_value.len(),
                    "unpadding did not remove a padded block"
                );
            }
        }
        // Every non-16-byte IV must be refused on length, before any block
        // is touched.
        if case.hostile_params.len() != 16 {
            assert!(
                matches!(
                    dec.decrypt(&case.hostile_params, &ct),
                    Err(SessionError::BadIv(_))
                ),
                "a {}-byte IV was not refused",
                case.hostile_params.len()
            );
        }
    }
});
