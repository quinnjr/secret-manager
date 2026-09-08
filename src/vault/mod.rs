//! Encrypted collection storage.
pub mod crypto;
pub mod format;
pub mod store;
pub use store::{Vault, VaultError};

/// Current unix time in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Longest collection id [`collection_id_from_label`] will produce.
///
/// The id is used as the `<id>.vault` filename, so it is bounded by `NAME_MAX`
/// (255 bytes on every filesystem Linux ships), not by `format::MAX_LABEL` -
/// which allows 4 KiB. 200 bytes leaves room for the `.vault` suffix and for
/// the `_<n>` uniquifier `dbus::state::unique_collection_id_in` appends.
pub const MAX_ID_LEN: usize = 200;

/// Derive an object-path-safe collection id from a label: lowercase `[a-z0-9_]+`,
/// at most [`MAX_ID_LEN`] bytes.
///
/// The bound is not cosmetic: without it a label near `format::MAX_LABEL` -
/// which `check_label` accepts - yields a filename the kernel refuses, and a
/// `CreateCollection` prompt fails with a raw `VaultError::Io` carrying
/// `ENAMETOOLONG` rather than a clean refusal. Every character kept is ASCII,
/// so truncating by bytes cannot split one.
pub fn collection_id_from_label(label: &str) -> String {
    let mut id = String::new();
    let mut last_underscore = false;
    for ch in label.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            id.push(c);
            last_underscore = false;
        } else if !last_underscore && !id.is_empty() {
            id.push('_');
            last_underscore = true;
        }
    }
    // Truncate before the trailing-separator trim, so a cut that lands on a
    // `_` does not leave one at the end.
    let id = id[..id.len().min(MAX_ID_LEN)]
        .trim_end_matches('_')
        .to_string();
    if id.is_empty() {
        "collection".to_string()
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id becomes the `<id>.vault` filename, and `MAX_LABEL` allows a
    /// 4 KiB label, so without a bound a legal label produces a name no
    /// filesystem accepts and `CreateCollection` fails with a raw
    /// `ENAMETOOLONG` instead of a clean refusal.
    #[test]
    fn collection_ids_are_bounded_for_use_as_a_filename() {
        let long = "a".repeat(4 << 10);
        let id = collection_id_from_label(&long);
        assert_eq!(id.len(), MAX_ID_LEN);
        // Room for `.vault` and a `_<n>` dedup suffix inside the usual
        // 255-byte NAME_MAX.
        assert!(id.len() + "_1234.vault".len() <= 255);

        // Truncation must not leave a trailing separator, and must still be
        // path-safe.
        let id = collection_id_from_label(&format!("{} tail", "b c ".repeat(200)));
        assert!(id.len() <= MAX_ID_LEN, "{}", id.len());
        assert!(!id.ends_with('_'), "{id}");
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));

        // A label that only becomes empty after truncation still gets a name.
        assert!(!collection_id_from_label(&"x ".repeat(4096)).is_empty());
    }

    #[test]
    fn collection_ids_are_path_safe() {
        assert_eq!(collection_id_from_label("Default"), "default");
        assert_eq!(collection_id_from_label("My Work Keys!"), "my_work_keys");
        assert_eq!(collection_id_from_label("   "), "collection");
        assert_eq!(collection_id_from_label("Ünïcode"), "n_code");
    }
}
