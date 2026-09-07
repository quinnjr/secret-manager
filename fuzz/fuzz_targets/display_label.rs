//! The collection label as it reaches a consent dialog.
//!
//! Any bus client may set `Collection.Label` — the spec requires no
//! authorization for it — and the label is then interpolated into the text of
//! a destructive-consent dialog that a human reads and acts on. The verified
//! attack (third audit, HIGH) was a 58-character label that reproduced the
//! `"` and `()` the dialog's authoritative clause is built from and so forged
//! a complete, plausible clause naming a *different* collection.
//!
//! `display_label` is the only thing standing between that label and the
//! dialog, so every property the dialog's integrity rests on is asserted
//! here: no control characters, none of the punctuation the daemon's own
//! sentence uses, no invisible formatter that could hide or reorder text, a
//! bounded length so the label cannot push the real clause off the dialog,
//! and idempotence — the label is rendered by more than one dialog, and a
//! filter that is not a fixed point could be walked back into an unsafe form
//! by a second pass.
#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use secret_manager::fuzz_api::{display_label, is_invisible_format};

/// Everything `display_label` promises about a single rendering.
fn check(shown: &str, label: &str) {
    for c in shown.chars() {
        assert!(
            !c.is_control(),
            "control U+{:04X} survived from {label:?}: {shown:?}",
            c as u32
        );
        assert!(
            !is_invisible_format(c),
            "invisible U+{:04X} survived from {label:?}: {shown:?}",
            c as u32
        );
        assert!(
            !matches!(c, '"' | '(' | ')'),
            "the label reproduced the dialog's own punctuation {c:?}: {shown:?}"
        );
    }
    // `\n`/`\r` are control characters, but they are the two that turn one
    // dialog line into two, so they are named explicitly.
    assert!(!shown.contains('\n'), "newline survived: {shown:?}");
    assert!(!shown.contains('\r'), "return survived: {shown:?}");

    // 64 characters plus the ellipsis. Counted in characters, not bytes: a
    // byte bound would split a scalar and the dialog would show U+FFFD.
    let n = shown.chars().count();
    assert!(n <= 65, "{n} characters shown from {label:?}: {shown:?}");
    if n == 65 {
        assert!(
            shown.ends_with('\u{2026}'),
            "a 65-character rendering is the truncated form: {shown:?}"
        );
    }
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
    let Ok(mut label) = smfuzz::hostile_string(&mut u) else {
        return;
    };
    if let Ok(wide) = wide_string(&mut u) {
        label.push_str(&wide);
    }

    let shown = display_label(&label);
    check(&shown, &label);

    // Idempotence. The truncating branch is the interesting one: it appends a
    // character of its own and can leave a space just before it, so a second
    // pass runs the whitespace collapse over output the first pass produced.
    let twice = display_label(&shown);
    check(&twice, &shown);
    assert_eq!(
        shown, twice,
        "display_label is not a fixed point on {label:?}"
    );

    // A rendering never invents characters: everything shown was either in
    // the label already, or is one of the two the filter itself introduces.
    for c in shown.chars() {
        assert!(
            label.contains(c) || c == ' ' || c == '\u{2026}',
            "U+{:04X} appeared from nowhere: {shown:?}",
            c as u32
        );
    }
});
