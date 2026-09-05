//! `org.freedesktop.Secret.Collection`, served at `/collection/<id>` and `/aliases/<name>`.

use super::errors::{Error, Result};
use super::registry;
use super::service::ServiceSignals;
use super::session::SecretStruct;
use super::state::{ServiceState, Shared};
use super::{paths, prop_attributes, prop_string};
use std::collections::{BTreeMap, HashMap};
use zbus::Connection;
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

pub enum CollectionRef {
    Id(String),
    Alias(String),
}

pub struct Collection {
    state: Shared,
    target: CollectionRef,
}

impl Collection {
    pub fn new(state: Shared, target: CollectionRef) -> Self {
        Self { state, target }
    }

    fn id(&self, st: &ServiceState) -> Result<String> {
        match &self.target {
            CollectionRef::Id(id) => st
                .collections
                .contains_key(id)
                .then(|| id.clone())
                .ok_or(Error::NoSuchObject),
            CollectionRef::Alias(name) => st
                .aliases
                .get(name)
                .filter(|id| st.collections.contains_key(*id))
                .cloned()
                .ok_or(Error::NoSuchObject),
        }
    }

    fn unknown() -> zbus::fdo::Error {
        zbus::fdo::Error::UnknownObject("no such collection".into())
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    /// Deletes immediately (no prompt). Requires the collection to be unlocked.
    #[zbus(out_args("prompt"))]
    async fn delete(&self, #[zbus(connection)] conn: &Connection) -> Result<OwnedObjectPath> {
        let (id, vault) = {
            let mut st = self.state.lock().await;
            let id = self.id(&st)?;
            if st.collections[&id].is_locked() {
                return Err(Error::IsLocked);
            }
            let vault = st.collections.remove(&id).ok_or(Error::NoSuchObject)?;
            st.aliases.retain(|_, target| target != &id);
            if let Err(e) = st.save_aliases() {
                tracing::warn!("cannot save aliases: {e}");
            }
            (id, vault)
        };
        let item_ids = vault.item_ids();
        vault.delete_file()?;
        let conn2 = conn.clone();
        let id2 = id.clone();
        tokio::spawn(async move {
            registry::unregister_collection(&conn2, &id2, &item_ids).await;
            registry::notify_collections_changed(&conn2).await;
        });
        SignalEmitter::new(conn, paths::SERVICE_PATH)?
            .collection_deleted(paths::collection(&id))
            .await?;
        Ok(paths::root())
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>> {
        let st = self.state.lock().await;
        let id = self.id(&st)?;
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(st.collections[&id]
            .search_ids(&query)
            .into_iter()
            .map(|iid| paths::item(&id, &iid))
            .collect())
    }

    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label =
            prop_string(&properties, "org.freedesktop.Secret.Item.Label")?.unwrap_or_default();
        let attributes = prop_attributes(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (id, iid, replaced) = {
            let mut st = self.state.lock().await;
            let id = self.id(&st)?;
            let plaintext = st
                .cipher(secret.session.as_str())?
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            let vault = st.collections.get_mut(&id).ok_or(Error::NoSuchObject)?;
            let (iid, replaced) = vault.insert_item(
                &label,
                attributes,
                plaintext.to_vec(),
                &secret.content_type,
                replace,
            )?;
            st.touch();
            (id, iid, replaced)
        };
        let item_path = paths::item(&id, &iid);
        if !replaced {
            registry::register_item(conn, &self.state, &id, &iid).await?;
        }
        let emitter = SignalEmitter::new(conn, paths::collection(&id))?;
        if replaced {
            emitter.item_changed(item_path.clone()).await?;
        } else {
            emitter.item_created(item_path.clone()).await?;
        }
        Ok((item_path, paths::root()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let st = self.state.lock().await;
        match self.id(&st) {
            Ok(id) => st.collections[&id]
                .item_ids()
                .into_iter()
                .map(|iid| paths::item(&id, &iid))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        let st = self.state.lock().await;
        self.id(&st)
            .map(|id| st.collections[&id].label().to_string())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&self, label: &str) -> zbus::fdo::Result<()> {
        let mut st = self.state.lock().await;
        let id = self.id(&st).map_err(|_| Self::unknown())?;
        st.collections
            .get_mut(&id)
            .ok_or_else(Self::unknown)?
            .set_label(label)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        let st = self.state.lock().await;
        self.id(&st)
            .map(|id| st.collections[&id].is_locked())
            .unwrap_or(true)
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let st = self.state.lock().await;
        self.id(&st)
            .map(|id| st.collections[&id].created())
            .unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let st = self.state.lock().await;
        self.id(&st)
            .map(|id| st.collections[&id].modified())
            .unwrap_or(0)
    }

    #[zbus(signal)]
    pub async fn item_created(
        emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn item_deleted(
        emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn item_changed(
        emitter: &SignalEmitter<'_>,
        item: OwnedObjectPath,
    ) -> zbus::Result<()>;
}
