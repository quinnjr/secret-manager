//! Bounded property tests for the text sanitisers and parsers that sit on
//! attacker-controlled strings.
//!
//! These mirror, case for case, the invariants asserted by the fuzz targets in
//! `fuzz/fuzz_targets/{display_label,escape_control_sanitize,pinentry_escape,
//! dbus_paths,askpass_prompt,config_toml}.rs`. Those need nightly and run for
//! as long as you give them; this file runs on stable in a plain `cargo test`,
//! so every commit is checked against the same properties even when nobody
//! has fuzzed anything. When one of these changes, change the other.
//!
//! The generators are deliberately biased towards the characters that matter —
//! the quotes and parens the consent dialog is built from, control characters,
//! bidi overrides and invisible formatters — because a uniform `String`
//! strategy produces none of them and would prove nothing.

use proptest::prelude::*;
use secret_manager::config::Config;
use secret_manager::dbus::paths::{self, Target};
use secret_manager::fuzz_api::{
    AskpassKind, classify_prompt, display_label, escape_control, is_invisible_format,
    passphrase_path, sanitize,
};
use secret_manager::prompt::pinentry::{escape, unescape};
use secret_manager::vault::crypto::KdfParams;

/// The truncation marker `display_label` appends. Spelled as a constant
/// because `prop_assert!` stringifies its expression into a format string,
/// where a `\u{...}` escape would be read as a positional argument.
const ELLIPSIS: char = '\u{2026}';

/// `MAX_LOGGED_ERROR` in `src/pam/mod.rs`.
const MAX_LOGGED: usize = 200;

/// The characters an attacker actually reaches for: the punctuation the
/// dialog's authoritative clause is built from, the terminal controls, and
/// the invisible formatters that hide or reorder text.
const INTERESTING: &[char] = &[
    '"', '(', ')', '\'', '\\', '\n', '\r', '\t', '\0', '\u{7}', '\u{1b}', '\u{7f}', '\u{00ad}',
    '\u{061c}', '\u{200b}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}', '\u{202b}',
    '\u{202c}', '\u{202d}', '\u{202e}', '\u{2060}', '\u{2066}', '\u{2069}', '\u{feff}', '\u{fffd}',
    'é', '中', '🔐', '/', ':', '=', ' ', '%',
];

/// Half interesting characters, half arbitrary ones: the same mix
/// `smfuzz::hostile_string` produces.
fn hostile_char() -> impl Strategy<Value = char> {
    prop_oneof![
        1 => proptest::sample::select(INTERESTING),
        1 => any::<char>(),
    ]
}

fn hostile_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(hostile_char(), 0..80).prop_map(|v| v.into_iter().collect())
}

/// Long enough to cross `display_label`'s 64-character bound and
/// `sanitize`'s 200-character one from either side.
fn long_hostile_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(hostile_char(), 0..260).prop_map(|v| v.into_iter().collect())
}

/// `is_bidi_format` in `src/pam/mod.rs`. `sanitize` strips exactly this range
/// and not the wider `is_invisible_format` set that the dialogs use; see
/// `sanitize_strips_the_bidi_range`.
fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn check_shown(shown: &str, from: &str) {
    for c in shown.chars() {
        assert!(!c.is_control(), "control U+{:04X} from {from:?}", c as u32);
        assert!(
            !is_invisible_format(c),
            "invisible U+{:04X} from {from:?}",
            c as u32
        );
        assert!(
            !matches!(c, '"' | '(' | ')'),
            "the dialog's own punctuation survived from {from:?}: {shown:?}"
        );
    }
    assert!(!shown.contains('\n') && !shown.contains('\r'), "{shown:?}");
    let n = shown.chars().count();
    assert!(n <= 65, "{n} characters from {from:?}");
    if n == 65 {
        assert!(shown.ends_with('\u{2026}'), "{shown:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    /// The verified forgery (third audit, HIGH) reproduced the `"` and `()`
    /// the delete dialog's authoritative clause is built from. Nothing a
    /// client can put in a label may come out able to do that again.
    #[test]
    fn display_label_neutralises_the_dialogs_punctuation(label in long_hostile_string()) {
        let shown = display_label(&label);
        check_shown(&shown, &label);
    }

    /// The label is rendered by more than one dialog, so the filter has to be
    /// a fixed point: a form that is safe once but unsafe when passed through
    /// again is not a sanitiser. The truncating branch is the interesting one
    /// — it appends a character of its own, and can leave a space in front of
    /// it for the second pass's whitespace collapse to find.
    #[test]
    fn display_label_is_idempotent(label in long_hostile_string()) {
        let once = display_label(&label);
        let twice = display_label(&once);
        prop_assert_eq!(&once, &twice);
        check_shown(&twice, &once);
    }

    /// A rendering may drop or blank a character, never invent one: only the
    /// replacement space and the truncation ellipsis are the filter's own.
    #[test]
    fn display_label_invents_nothing(label in hostile_string()) {
        let shown = display_label(&label);
        for c in shown.chars() {
            prop_assert!(label.contains(c) || c == ' ' || c == '\u{2026}',
                "U+{:04X} appeared from nowhere in {shown:?}", c as u32);
        }
    }

    /// `sm ssh list` writes attribute values, which any bus client can set,
    /// straight to a terminal. An unescaped `\x1b[2K` erases the row above.
    #[test]
    fn escape_control_leaves_nothing_executable(text in hostile_string()) {
        let escaped = escape_control(&text);
        for c in escaped.chars() {
            prop_assert!(!c.is_control(), "control U+{:04X} from {text:?}", c as u32);
            prop_assert!(!is_invisible_format(c), "invisible U+{:04X} from {text:?}", c as u32);
        }
        prop_assert_eq!(escape_control(&escaped), escaped, "not a fixed point");
    }

    /// Everything the PAM module logs runs as root inside a hostile user's
    /// login, so a newline in it is a forged authpriv line.
    #[test]
    fn sanitize_strips_the_bidi_range(text in long_hostile_string()) {
        let clean = sanitize(&text);
        for c in clean.chars() {
            prop_assert!(!c.is_control(), "control U+{:04X} from {text:?}", c as u32);
            prop_assert!(!is_bidi_format(c), "bidi U+{:04X} from {text:?}", c as u32);
        }
        prop_assert!(!clean.contains('\n') && !clean.contains('\r'));
        // The bound is on characters, so a multi-byte scalar is never split.
        prop_assert!(clean.chars().count() <= MAX_LOGGED);
        prop_assert_eq!(sanitize(&clean), clean.clone(), "not a fixed point");
        // Appending can only add: what survives from a prefix is a prefix of
        // what survives from the whole.
        let doubled = sanitize(&format!("{text}{text}"));
        prop_assert!(doubled.starts_with(&clean), "{doubled:?} does not extend {clean:?}");
    }

    /// A sanitiser that mangles benign input is its own kind of failure: it
    /// hides the real content of the row or the log line just as effectively.
    #[test]
    fn printable_ascii_passes_through_untouched(
        plain in proptest::collection::vec(0x20u8..=0x7e, 0..MAX_LOGGED)
            .prop_map(|v| v.into_iter().map(char::from).collect::<String>())
    ) {
        prop_assert_eq!(escape_control(&plain), plain.clone());
        prop_assert_eq!(sanitize(&plain), plain.clone());
        // A label of printable ASCII keeps everything but the three
        // characters the dialog reserves and its own whitespace collapse.
        let shown = display_label(&plain);
        for c in shown.chars() {
            prop_assert!(plain.contains(c) || c == ' ' || c == ELLIPSIS, "{shown:?}");
        }
    }

    /// Assuan is line-oriented, so a raw newline in a description is an extra
    /// command; and the escaping has to be lossless or a PIN comes back
    /// altered and unlocks nothing.
    #[test]
    fn pinentry_escaping_round_trips(text in hostile_string()) {
        let escaped = escape(&text);
        for b in escaped.bytes() {
            prop_assert!(b >= 0x20 && b != 0x7f, "byte {b:#04x} from {text:?}");
        }
        prop_assert!(!escaped.contains('\n') && !escaped.contains('\r'));
        let back = unescape(&escaped).expect("our own escaping must decode");
        prop_assert_eq!(&*back, &text);
    }

    /// `unescape` parses a hostile pinentry server's reply: malformed
    /// escapes, truncated ones, invalid hex and a lone `%` at end of input
    /// are all reachable, and none of them may panic.
    #[test]
    fn unescape_survives_a_hostile_reply(text in hostile_string()) {
        for suffix in ["", "%", "%2", "%zz", "%%", "%ff", "%c3"] {
            if let Ok(pin) = unescape(&format!("{text}{suffix}")) {
                // `%XX` is three characters in and one byte out, so decoding
                // can only ever shorten.
                prop_assert!(pin.len() <= text.len() + suffix.len());
            }
        }
    }

    /// Collection and item ids are client-supplied and become path segments:
    /// no parsed component may carry a separator, whatever went in.
    #[test]
    fn object_paths_never_escape_their_segment(a in hostile_string(), b in hostile_string()) {
        for candidate in [
            format!("{}{a}", paths::COLLECTIONS_PREFIX),
            format!("{}{a}/{b}", paths::COLLECTIONS_PREFIX),
            format!("{}{a}/{b}/{a}", paths::COLLECTIONS_PREFIX),
            format!("{}{a}", paths::ALIASES_PREFIX),
            format!("{}{a}/{b}", paths::ALIASES_PREFIX),
            format!("{}{a}", paths::SESSIONS_PREFIX),
            format!("{}{a}", paths::PROMPTS_PREFIX),
            a.clone(),
        ] {
            if let Some(t) = paths::parse(&candidate) {
                let parts: Vec<&String> = match &t {
                    Target::Collection(c) | Target::Alias(c) => vec![c],
                    Target::Item { collection: x, item: y }
                    | Target::AliasItem { alias: x, item: y } => vec![x, y],
                };
                for p in parts {
                    prop_assert!(!p.contains('/'), "{p:?} from {candidate:?}");
                    prop_assert!(paths::is_segment(p), "{p:?} from {candidate:?}");
                }
            }
        }
        // A session or prompt object is owned by one client and must never be
        // reachable through the collection or alias lookup.
        let session = format!("{}{a}", paths::SESSIONS_PREFIX);
        let prompt = format!("{}{a}", paths::PROMPTS_PREFIX);
        prop_assert!(paths::parse(&session).is_none(), "{session:?}");
        prop_assert!(paths::parse(&prompt).is_none(), "{prompt:?}");
    }

    /// `alias` is the constructor that takes untrusted input directly, so its
    /// refusal is part of the contract; `collection` and `item` are only ever
    /// called on ids already validated by `is_segment`, and round-trip there.
    #[test]
    fn validated_ids_round_trip(a in "[A-Za-z0-9_]{0,12}", b in "[A-Za-z0-9_]{0,12}") {
        match paths::alias(&a) {
            Some(p) => {
                prop_assert!(paths::is_segment(&a));
                prop_assert!(p.as_str().starts_with(paths::ALIASES_PREFIX));
                prop_assert_eq!(paths::parse(p.as_str()), Some(Target::Alias(a.clone())));
            }
            None => prop_assert!(!paths::is_segment(&a)),
        }
        if paths::is_segment(&a) {
            let c = paths::collection(&a);
            prop_assert!(c.as_str().starts_with(paths::COLLECTIONS_PREFIX));
            prop_assert_eq!(paths::parse(c.as_str()), Some(Target::Collection(a.clone())));
            if paths::is_segment(&b) {
                let i = paths::item(&a, &b);
                prop_assert!(i.as_str().starts_with(paths::COLLECTIONS_PREFIX));
                prop_assert_eq!(
                    paths::parse(i.as_str()),
                    Some(Target::Item { collection: a.clone(), item: b.clone() })
                );
            }
        }
    }

    /// The prompt OpenSSH hands to `SSH_ASKPASS` carries an attacker-chosen
    /// destination string. Whatever path comes back is what `askpass` will
    /// look up and name in the consent dialog, so it must be a single-line,
    /// non-empty path — and the unquoted form, which has no delimiters, must
    /// be absolute.
    #[test]
    fn an_askpass_path_is_single_line_and_non_empty(tail in hostile_string()) {
        let prompts = [
            tail.clone(),
            format!("Enter passphrase for key '{tail}': "),
            format!("Enter passphrase for \"{tail}\": "),
            format!("Enter passphrase for {tail}: "),
            format!("Enter passphrase for {tail} (will confirm each use): "),
            format!("The authenticity of host '{tail}' can't be established.\n\
                     Are you sure you want to continue connecting (yes/no)? "),
            format!("Allow use of key {tail}?"),
        ];
        for prompt in &prompts {
            let mut paths = vec![passphrase_path(prompt)];
            for env in [None, Some("confirm"), Some("none"), Some(tail.as_str())] {
                match classify_prompt(prompt, env) {
                    AskpassKind::Passphrase(p) => {
                        // The tag `ssh` sets is authoritative and can never be
                        // overridden by the prompt text.
                        prop_assert_ne!(env, Some("confirm"), "{:?}", prompt);
                        paths.push(Some(p));
                    }
                    AskpassKind::Confirm | AskpassKind::Other => {}
                }
            }
            for p in paths.into_iter().flatten() {
                let s = p.to_string_lossy();
                prop_assert!(!s.is_empty(), "empty path from {prompt:?}");
                prop_assert!(!s.contains('\n') && !s.contains('\r'),
                    "a line terminator reached the key path from {prompt:?}: {s:?}");
                prop_assert!(!escape_control(&s).chars().any(char::is_control));
                if !prompt.contains('\'') && !prompt.contains('"') {
                    prop_assert!(p.is_absolute(), "relative unquoted path from {prompt:?}");
                }
            }
            prop_assert_eq!(classify_prompt(prompt, Some("confirm")), AskpassKind::Confirm);
            if prompt.contains('\n') {
                prop_assert!(!matches!(classify_prompt(prompt, None), AskpassKind::Passphrase(_)),
                    "a multi-line dialog was read as a passphrase request: {prompt:?}");
            }
        }
    }

    /// A config that parses has KDF parameters the vault can actually use:
    /// the same ceilings an unauthenticated vault header is held to, because
    /// a vault created from this config is stuck with what it says.
    #[test]
    fn an_accepted_config_has_usable_kdf_parameters(
        m in any::<u32>(), t in any::<u32>(), p in any::<u32>(), dir in hostile_string(),
    ) {
        let text = format!(
            "[vault]\ndir = {dir:?}\n[kdf]\nm_cost_kib = {m}\nt_cost = {t}\np_cost = {p}\n"
        );
        if let Ok(c) = Config::from_str(&text) {
            let params: KdfParams = c.kdf.into();
            prop_assert!(params.validate().is_ok(), "{params:?} from {text:?}");
            prop_assert!(params.p_cost >= 1 && params.p_cost <= KdfParams::MAX_P_COST);
            prop_assert!(params.t_cost >= 1 && params.t_cost <= KdfParams::MAX_T_COST);
            prop_assert!(params.m_cost_kib <= KdfParams::MAX_M_COST_KIB);
            prop_assert!(params.m_cost_kib >= 8 * params.p_cost);
            prop_assert!(!c.vault.dir.starts_with("~"), "unexpanded tilde: {:?}", c.vault.dir);
        }
    }

    /// Arbitrary text as a config file: a truncated write or the wrong file
    /// is an error, never a panic on a startup path.
    #[test]
    fn arbitrary_text_is_never_a_panic(text in long_hostile_string()) {
        if let Ok(c) = Config::from_str(&text) {
            prop_assert!(KdfParams::from(c.kdf).validate().is_ok());
        }
    }
}
