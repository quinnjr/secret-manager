//! `org.freedesktop.Secret.*` interfaces.

pub mod collection;
pub mod errors;
pub mod item;
pub mod paths;
pub mod prompt;
pub mod proxies;
pub mod registry;
pub mod service;
pub mod session;
pub mod state;

use std::collections::{BTreeMap, HashMap};
use zbus::message::Header;
use zbus::zvariant::OwnedValue;

/// Unique bus name of the caller, if the message carries one.
///
/// Deliberately not defaulted to `""`: every ownership check in this crate
/// compares caller identities, and an empty-string fallback would make two
/// senderless callers compare equal to each other.
pub fn sender(header: &Header<'_>) -> Option<String> {
    header.sender().map(|s| s.to_string())
}

/// Caller identity, or `NoSession` when the message has no sender (a bus
/// always supplies one; anything else fails closed).
pub fn require_sender(header: &Header<'_>) -> errors::Result<String> {
    sender(header).ok_or(errors::Error::NoSession)
}

pub(crate) fn prop_string(
    props: &HashMap<String, OwnedValue>,
    key: &str,
) -> errors::Result<Option<String>> {
    match props.get(key) {
        None => Ok(None),
        Some(v) => String::try_from(v.clone())
            .map(Some)
            .map_err(|_| errors::Error::invalid_args(format!("{key} must be a string"))),
    }
}

pub(crate) fn prop_attributes(
    props: &HashMap<String, OwnedValue>,
    key: &str,
) -> errors::Result<BTreeMap<String, String>> {
    match props.get(key) {
        None => Ok(BTreeMap::new()),
        Some(v) => {
            let m = HashMap::<String, String>::try_from(v.clone())
                .map_err(|_| errors::Error::invalid_args(format!("{key} must be a{{ss}}")))?;
            // Attributes are stored in the encrypted item blob and hashed into
            // the vault header's search index, so an unbounded set is a way to
            // push a collection past the vault size limit exactly as an
            // unbounded secret was. `MAX_SEARCH_ATTRIBUTES` bounds queries,
            // not what gets written.
            collection::check_attributes(m.len(), m.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
            Ok(m.into_iter().collect())
        }
    }
}
