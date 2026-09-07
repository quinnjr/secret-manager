//! Client-side proxies, shared by the CLI and the integration tests.

use super::session::SecretStruct;
use std::collections::HashMap;
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

#[proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
pub trait Service {
    fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;
    fn create_collection(
        &self,
        properties: HashMap<&str, Value<'_>>,
        alias: &str,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
    fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>;
    fn unlock(
        &self,
        objects: &[OwnedObjectPath],
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
    fn lock(
        &self,
        objects: &[OwnedObjectPath],
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
    fn get_secrets(
        &self,
        items: &[OwnedObjectPath],
        session: &OwnedObjectPath,
    ) -> zbus::Result<HashMap<OwnedObjectPath, SecretStruct>>;
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn set_alias(&self, name: &str, collection: &OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(property)]
    fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(signal)]
    fn collection_created(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn collection_deleted(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn collection_changed(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets"
)]
pub trait Collection {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn create_item(
        &self,
        properties: HashMap<&str, Value<'_>>,
        secret: &SecretStruct,
        replace: bool,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
    #[zbus(property)]
    fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_label(&self, label: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn created(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn modified(&self) -> zbus::Result<u64>;
    #[zbus(signal)]
    fn item_created(&self, item: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn item_deleted(&self, item: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn item_changed(&self, item: OwnedObjectPath) -> zbus::Result<()>;
}

/// The private, non-spec batch interface exported alongside
/// `org.freedesktop.Secret.Collection` on the same object path (see
/// `collection::CollectionAdmin`). Only this project's own CLI uses it; the
/// spec interface above is unchanged, so libsecret sees exactly the spec.
#[proxy(
    interface = "org.secret_manager.Collection1",
    default_service = "org.freedesktop.secrets"
)]
pub trait CollectionAdmin {
    fn delete_items(&self, items: &[OwnedObjectPath]) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets"
)]
pub trait Item {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn get_secret(&self, session: &OwnedObjectPath) -> zbus::Result<SecretStruct>;
    fn set_secret(&self, secret: &SecretStruct) -> zbus::Result<()>;
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<HashMap<String, String>>;
    #[zbus(property)]
    fn set_attributes(&self, attributes: HashMap<&str, &str>) -> zbus::Result<()>;
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_label(&self, label: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn created(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn modified(&self) -> zbus::Result<u64>;
}

#[proxy(
    interface = "org.freedesktop.Secret.Session",
    default_service = "org.freedesktop.secrets"
)]
pub trait Session {
    fn close(&self) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.Secret.Prompt",
    default_service = "org.freedesktop.secrets"
)]
pub trait Prompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;
    fn dismiss(&self) -> zbus::Result<()>;
    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}
