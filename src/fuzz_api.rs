//! Thin wrappers over internal helpers, for the fuzz targets in `fuzz/`.
//!
//! The items below sit directly on attacker-fed input — a hostile collection
//! label, a pinentry server's reply, an askpass prompt string — and are
//! exactly where a panic or a sanitisation gap would matter, which is why the
//! fuzzers need to reach them.
//!
//! Most are `pub(crate)` or private, because nothing outside this crate should
//! call them, and a `pub use` cannot widen a `pub(crate)` item's visibility:
//! hence wrappers. Three of them are not: `display_label` and
//! `classify_prompt` are already `pub` in a `pub` module, and `AskpassKind` is
//! a plain `pub use` of a `pub` type. They are restated here anyway so the
//! fuzz targets have one import path and do not have to track which side of
//! that line each helper is on. Every wrapper forwards and does nothing else,
//! so a fuzz target exercises the same code the daemon runs.
//!
//! Gated behind the `fuzzing` feature, so enabling it is a deliberate act and
//! the default build's public surface is unchanged. `cargo fuzz` turns it on
//! for its own build of the library only; nothing we ship sets it.

#[cfg(feature = "daemon")]
pub use crate::cli::ssh::AskpassKind;

/// See [`crate::cli::secrets::escape_control`].
#[cfg(feature = "daemon")]
pub fn escape_control(s: &str) -> String {
    crate::cli::secrets::escape_control(s)
}

/// See [`crate::cli::ssh::classify_prompt`].
#[cfg(feature = "daemon")]
pub fn classify_prompt(prompt: &str, askpass_prompt_env: Option<&str>) -> AskpassKind {
    crate::cli::ssh::classify_prompt(prompt, askpass_prompt_env)
}

/// See [`crate::cli::ssh::passphrase_path`].
#[cfg(feature = "daemon")]
pub fn passphrase_path(prompt: &str) -> Option<std::path::PathBuf> {
    crate::cli::ssh::passphrase_path(prompt)
}

/// See [`crate::dbus::prompt::display_label`].
#[cfg(feature = "daemon")]
pub fn display_label(label: &str) -> String {
    crate::dbus::prompt::display_label(label)
}

/// See [`crate::dbus::prompt::is_invisible_format`].
#[cfg(feature = "daemon")]
pub fn is_invisible_format(c: char) -> bool {
    crate::dbus::prompt::is_invisible_format(c)
}

/// See [`crate::pam::sanitize`].
pub fn sanitize(text: &str) -> String {
    crate::pam::sanitize(text)
}
