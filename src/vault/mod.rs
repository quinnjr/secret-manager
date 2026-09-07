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

/// Derive an object-path-safe collection id from a label: lowercase `[a-z0-9_]+`.
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
    let id = id.trim_end_matches('_').to_string();
    if id.is_empty() {
        "collection".to_string()
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_ids_are_path_safe() {
        assert_eq!(collection_id_from_label("Default"), "default");
        assert_eq!(collection_id_from_label("My Work Keys!"), "my_work_keys");
        assert_eq!(collection_id_from_label("   "), "collection");
        assert_eq!(collection_id_from_label("Ünïcode"), "n_code");
    }
}
