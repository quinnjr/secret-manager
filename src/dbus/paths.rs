//! Object path layout of the service.

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

pub const BUS_NAME: &str = "org.freedesktop.secrets";
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const COLLECTIONS_PREFIX: &str = "/org/freedesktop/secrets/collection/";
pub const ALIASES_PREFIX: &str = "/org/freedesktop/secrets/aliases/";
pub const SESSIONS_PREFIX: &str = "/org/freedesktop/secrets/session/";
pub const PROMPTS_PREFIX: &str = "/org/freedesktop/secrets/prompt/";

/// D-Bus object path segment: `[A-Za-z0-9_]+`.
pub fn is_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn owned(s: String) -> OwnedObjectPath {
    ObjectPath::try_from(s)
        .expect("path built from validated segments")
        .into()
}

pub fn root() -> OwnedObjectPath {
    ObjectPath::from_static_str_unchecked("/").into()
}

pub fn service() -> OwnedObjectPath {
    ObjectPath::from_static_str_unchecked(SERVICE_PATH).into()
}

pub fn collection(id: &str) -> OwnedObjectPath {
    owned(format!("{COLLECTIONS_PREFIX}{id}"))
}

pub fn item(collection_id: &str, item_id: &str) -> OwnedObjectPath {
    owned(format!("{COLLECTIONS_PREFIX}{collection_id}/{item_id}"))
}

pub fn alias(name: &str) -> Option<OwnedObjectPath> {
    is_segment(name).then(|| owned(format!("{ALIASES_PREFIX}{name}")))
}

pub fn session(n: u64) -> OwnedObjectPath {
    owned(format!("{SESSIONS_PREFIX}s{n}"))
}

pub fn prompt(n: u64) -> OwnedObjectPath {
    owned(format!("{PROMPTS_PREFIX}p{n}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Collection(String),
    Alias(String),
    Item { collection: String, item: String },
    AliasItem { alias: String, item: String },
}

pub fn parse(path: &str) -> Option<Target> {
    let split = |rest: &str| -> Option<(String, Option<String>)> {
        let mut parts = rest.split('/');
        let first = parts.next().filter(|s| is_segment(s))?.to_string();
        let second = match parts.next() {
            None => None,
            Some(s) if is_segment(s) => Some(s.to_string()),
            Some(_) => return None,
        };
        if parts.next().is_some() {
            return None;
        }
        Some((first, second))
    };
    if let Some(rest) = path.strip_prefix(COLLECTIONS_PREFIX) {
        return match split(rest)? {
            (collection, None) => Some(Target::Collection(collection)),
            (collection, Some(item)) => Some(Target::Item { collection, item }),
        };
    }
    if let Some(rest) = path.strip_prefix(ALIASES_PREFIX) {
        return match split(rest)? {
            (alias, None) => Some(Target::Alias(alias)),
            (alias, Some(item)) => Some(Target::AliasItem { alias, item }),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_paths() {
        assert_eq!(
            collection("default").as_str(),
            "/org/freedesktop/secrets/collection/default"
        );
        assert_eq!(
            item("default", "abc").as_str(),
            "/org/freedesktop/secrets/collection/default/abc"
        );
        assert_eq!(
            alias("default").unwrap().as_str(),
            "/org/freedesktop/secrets/aliases/default"
        );
        assert!(alias("bad-name").is_none());
        assert_eq!(session(3).as_str(), "/org/freedesktop/secrets/session/s3");
        assert_eq!(prompt(7).as_str(), "/org/freedesktop/secrets/prompt/p7");
        assert_eq!(
            parse("/org/freedesktop/secrets/collection/default"),
            Some(Target::Collection("default".into()))
        );
        assert_eq!(
            parse("/org/freedesktop/secrets/collection/default/abc"),
            Some(Target::Item {
                collection: "default".into(),
                item: "abc".into()
            })
        );
        assert_eq!(
            parse("/org/freedesktop/secrets/aliases/default"),
            Some(Target::Alias("default".into()))
        );
        assert_eq!(
            parse("/org/freedesktop/secrets/aliases/default/abc"),
            Some(Target::AliasItem {
                alias: "default".into(),
                item: "abc".into()
            })
        );
        assert_eq!(parse("/org/freedesktop/secrets/collection/a/b/c"), None);
        assert_eq!(parse("/org/freedesktop/secrets"), None);
        assert_eq!(parse("/"), None);
    }
}
