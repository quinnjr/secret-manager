//! `org.freedesktop.Secret.*` interfaces.

pub mod collection;
pub mod errors;
pub mod item;
pub mod paths;
pub mod proxies;
pub mod registry;
pub mod service;
pub mod session;
pub mod state;

use std::collections::{BTreeMap, HashMap};
use zbus::message::Header;
use zbus::zvariant::OwnedValue;

/// Unique bus name of the caller, or empty.
pub fn sender(header: &Header<'_>) -> String {
    header.sender().map(|s| s.to_string()).unwrap_or_default()
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
        Some(v) => HashMap::<String, String>::try_from(v.clone())
            .map(|m| m.into_iter().collect())
            .map_err(|_| errors::Error::invalid_args(format!("{key} must be a{{ss}}"))),
    }
}
