//! Assuan percent-escaping, in both directions.
//!
//! `unescape` parses a line from the pinentry **server**, which is a separate
//! process named by `[prompt] pinentry` in the config and reached through
//! `PATH`. Whoever that is decides every byte of the reply, so the decoder
//! sits directly on hostile input: a malformed escape, a truncated one, a
//! lone `%` at end of input, non-hex digits after the `%`, or a percent
//! sequence that decodes to bytes which are not valid UTF-8 are all reachable
//! from a hostile or merely buggy pinentry, and a panic in the CLI's PIN path
//! is a denial of service on unlocking.
//!
//! `escape` runs the other way, on text this daemon puts *into* the protocol:
//! a description string built from a client-supplied label. Assuan is
//! line-oriented, so a raw newline there is a protocol injection — an extra
//! command the dialog was never asked to run. The round-trip property is what
//! ties the two together: escaping must be lossless, or a passphrase would
//! come back altered and unlock nothing.
#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use secret_manager::prompt::pinentry::{escape, unescape};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(text) = smfuzz::hostile_string(&mut u) else {
        return;
    };

    // --- escape ---------------------------------------------------------
    let escaped = escape(&text);
    for b in escaped.bytes() {
        assert!(
            b >= 0x20 && b != 0x7f,
            "byte {b:#04x} survived into an Assuan line from {text:?}: {escaped:?}"
        );
    }
    // Named explicitly because they are the two that end an Assuan line and
    // so turn one command into two.
    assert!(
        !escaped.contains('\n') && !escaped.contains('\r'),
        "Assuan line injection from {text:?}: {escaped:?}"
    );

    // Lossless: the pinentry echoes back what we send, and a PIN is compared
    // byte for byte, so any loss here is a silent authentication failure.
    match unescape(&escaped) {
        Ok(back) => assert_eq!(
            *back, text,
            "escape/unescape is not a round trip on {text:?}"
        ),
        Err(e) => panic!("our own escaping did not decode: {text:?} -> {escaped:?}: {e}"),
    }

    // --- unescape on a hostile reply ------------------------------------
    // The raw string, unescaped: this is the decoder's real input.
    if let Ok(pin) = unescape(&text) {
        // Whatever comes back is a `String`, so it is valid UTF-8 by
        // construction — the decoder builds bytes and validates at the end,
        // and that check is the one that must not be skipped.
        assert!(std::str::from_utf8(pin.as_bytes()).is_ok());
        // Decoding only ever shortens: `%XX` is three characters in and one
        // byte out, so a reply cannot be amplified into a larger allocation.
        assert!(pin.len() <= text.len());
    }

    // The same reply with escapes deliberately damaged: truncated at a `%`,
    // followed by non-hex, or a bare `%` at end of input.
    for suffix in ["%", "%2", "%zz", "%%", "%ff", "%c3", "%0"] {
        let _ = unescape(&format!("{text}{suffix}"));
        let _ = unescape(&format!("{suffix}{text}"));
    }

    // A reply built from the fuzzer's raw bytes as latin-1, which reaches
    // percent sequences that `hostile_string` rarely produces in a row.
    let mut dense = String::new();
    for b in data.iter().take(256) {
        dense.push(if b % 4 == 0 { '%' } else { char::from(*b) });
    }
    let _ = unescape(&dense);
});
