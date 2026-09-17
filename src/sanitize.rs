//! Peer-text rendering shared by the daemon, the CLI, and the vault.
//!
//! Always compiled: `src/vault/` is the PAM cdylib's half of the crate too
//! and may not reach into anything behind the `daemon` feature, so the table
//! and the terminal escaper live here rather than in `cli` or `dbus`.
//! `vault::format` keeps encoding and caps; this module owns display.

/// Characters that are neither `char::is_control` nor visible: bidi
/// overrides, zero-width joiners, the private-use planes, the tag block.
///
/// `char::is_control` is general category `Cc` only, so everything here
/// survives it while still being able to reorder or hide the text around it
/// in a terminal or a dialog.
pub fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{08E2}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{E000}'..='\u{F8FF}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}'
        | '\u{110CD}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}'
        | '\u{F0000}'..='\u{FFFFD}'
        | '\u{100000}'..='\u{10FFFD}'
    )
}

/// Render peer-supplied text so it cannot move a cursor, clear a line or
/// reorder what is printed around it: every control character and every
/// invisible formatter becomes `\xNN` per UTF-8 byte.
///
/// `CLAUDE.md`: "text from a peer is sanitized before it reaches a log or a
/// dialog."
pub fn escape_control(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    let mut scratch = [0u8; 4];
    for ch in s.chars() {
        if ch.is_control() || is_invisible_format(ch) {
            for b in ch.encode_utf8(&mut scratch).as_bytes() {
                let _ = write!(out, "\\x{b:02x}");
            }
        } else {
            out.push(ch);
        }
    }
    out
}
