//! The two sanitisers that stand between hostile text and an operator's eyes.
//!
//! `escape_control` (`src/cli/secrets.rs`) is applied to attribute values
//! printed by `sm ssh list`. Attributes are settable by any client on the
//! session bus, so an attribute value is an arbitrary string being written to
//! a terminal: an unescaped `\x1b[2K` erases the row above it and a bidi
//! override reverses a path, and either lets a planted item impersonate a
//! real one in the listing a human is reading before deciding what to delete.
//!
//! `sanitize` (`src/pam/mod.rs`) is applied to everything the PAM module
//! writes to syslog. That module runs as **root inside a hostile user's
//! login**, and the text it logs includes the user's own vault path and the
//! daemon's error strings, so a newline there is a forged authpriv line
//! attributing something to another user.
//!
//! Both are asserted from both directions: the escape must be complete, and
//! it must not mangle benign text — a sanitiser that rewrites ordinary input
//! trains operators to ignore it, which is its own failure.
#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use secret_manager::fuzz_api::{escape_control, is_invisible_format, sanitize};

/// `MAX_LOGGED_ERROR` in `src/pam/mod.rs`: the character bound `sanitize`
/// applies so one hostile string cannot flood the log.
const MAX_LOGGED: usize = 200;

/// The bidi embeddings, overrides and isolates. This is `is_bidi_format` in
/// `src/pam/mod.rs`, restated so the target asserts the contract `sanitize`
/// actually has rather than the wider one `display_label` has — see the note
/// on `sanitize_strips_exactly_the_bidi_range` below.
fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// A string drawn from the *whole* scalar range, not just Latin-1 and the
/// curated set `smfuzz::hostile_string` uses. That generator cannot reach the
/// private-use planes or the tag characters at all, and those are exactly
/// where the two `is_invisible_format` tables had drifted apart — a gap this
/// target missed for a full run until the proptest mirror, whose `any::<char>`
/// covers the range, found U+F0000. Kept local because `smfuzz` is shared.
fn wide_string(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.arbitrary_len::<u32>()?.min(64);
    let mut s = String::new();
    for _ in 0..len {
        if u.is_empty() {
            break;
        }
        // Biased towards the upper planes, which uniform bytes never reach.
        let hi = u.int_in_range(0u32..=0x10)?;
        let lo = u.arbitrary::<u16>()? as u32;
        if let Some(c) = char::from_u32((hi << 16) | lo) {
            s.push(c);
        }
    }
    Ok(s)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(mut text) = smfuzz::hostile_string(&mut u) else {
        return;
    };
    if let Ok(wide) = wide_string(&mut u) {
        text.push_str(&wide);
    }

    // --- escape_control -------------------------------------------------
    let escaped = escape_control(&text);
    for c in escaped.chars() {
        assert!(
            !c.is_control(),
            "control U+{:04X} reached the terminal from {text:?}: {escaped:?}",
            c as u32
        );
        assert!(
            !is_invisible_format(c),
            "invisible U+{:04X} reached the terminal from {text:?}: {escaped:?}",
            c as u32
        );
    }
    // Escaping is a fixed point: `\x1b` is spelled with characters that are
    // themselves safe, so re-escaping cannot double up or re-expose anything.
    assert_eq!(
        escape_control(&escaped),
        escaped,
        "escape_control is not a fixed point on {text:?}"
    );

    // --- sanitize -------------------------------------------------------
    let clean = sanitize(&text);
    for c in clean.chars() {
        assert!(
            !c.is_control(),
            "control U+{:04X} reached syslog from {text:?}: {clean:?}",
            c as u32
        );
        assert!(
            !is_bidi_format(c),
            "bidi U+{:04X} reached syslog from {text:?}: {clean:?}",
            c as u32
        );
    }
    assert!(
        !clean.contains('\n') && !clean.contains('\r'),
        "a log line could be forged from {text:?}: {clean:?}"
    );
    // The bound is on characters, and a multi-byte scalar is never split:
    // `take` operates on `chars`, so the result is always valid UTF-8 of at
    // most `MAX_LOGGED` characters however wide they are.
    assert!(
        clean.chars().count() <= MAX_LOGGED,
        "{} characters logged from {text:?}",
        clean.chars().count()
    );
    assert_eq!(
        sanitize(&clean),
        clean,
        "sanitize is not a fixed point on {text:?}"
    );
    // Appending can only ever add: what survives from a prefix of the input
    // is a prefix of what survives from the whole. A filter without this
    // property would let trailing bytes change how earlier text is rendered.
    assert!(
        sanitize(&format!("{text}{text}")).starts_with(&clean),
        "sanitize is not a prefix-stable filter on {text:?}"
    );

    // --- benign text is left alone --------------------------------------
    // Printable ASCII is exactly what both functions are supposed to pass
    // through untouched; mangling it would hide the real content of a row or
    // a log line just as effectively as failing to escape.
    let Ok(n) = u.arbitrary_len::<u8>() else {
        return;
    };
    let mut plain = String::new();
    for _ in 0..n.min(MAX_LOGGED) {
        let Ok(b) = u.int_in_range(0x20u8..=0x7e) else {
            break;
        };
        plain.push(char::from(b));
    }
    assert_eq!(
        escape_control(&plain),
        plain,
        "escape_control mangled {plain:?}"
    );
    assert_eq!(sanitize(&plain), plain, "sanitize mangled {plain:?}");
});
