//! `org.freedesktop.Secret.Collection`, served at `/collection/<id>` and `/aliases/<name>`.

use super::errors::{Error, Result};
use super::prompt::{Prompt, PromptAction};
use super::registry;
use super::require_sender;
use super::session::SecretStruct;
use super::state::{ServiceState, Shared};
use super::{paths, prop_attributes, prop_string};
use std::collections::{BTreeMap, HashMap};
use zbus::Connection;
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::{ObjectServer, SignalEmitter};
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

    /// Shared daemon state, for `registry::notify_collection_changed` to
    /// look up aliases without needing its own `&Shared` parameter.
    pub(crate) fn state(&self) -> &Shared {
        &self.state
    }

    /// The loaded vault behind this object, or `None` when the target is a
    /// broken collection (see `state::ServiceState::broken`), which behaves
    /// as a permanently locked, empty one.
    fn vault<'a>(&self, st: &'a ServiceState) -> Option<&'a crate::vault::Vault> {
        self.id(st).ok().and_then(|id| st.collections.get(&id))
    }

    fn id(&self, st: &ServiceState) -> Result<String> {
        match &self.target {
            // A broken collection (see `state::ServiceState::broken`) is a
            // valid target too, so callers see a locked, empty collection
            // instead of `NoSuchObject`.
            CollectionRef::Id(id) => (st.collections.contains_key(id)
                || st.broken.contains_key(id))
            .then(|| id.clone())
            .ok_or(Error::NoSuchObject),
            CollectionRef::Alias(name) => st.alias_target(name).ok_or(Error::NoSuchObject),
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    /// Returns a prompt that asks for confirmation through pinentry before
    /// deleting; the collection is only removed once the prompt is run and
    /// confirmed (see `prompt::delete_collection`). `Item.Delete` stays
    /// immediate.
    #[zbus(out_args("prompt"))]
    async fn delete(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<OwnedObjectPath> {
        let mut st = self.state.lock().await;
        let id = self.id(&st)?;
        // A broken collection has no vault to index; treat it as locked.
        if self.vault(&st).map(|v| v.is_locked()).unwrap_or(true) {
            return Err(Error::IsLocked);
        }
        let prompt_path = st.new_prompt_path();
        st.prompt_owners
            .insert(prompt_path.to_string(), require_sender(&header)?);
        drop(st);
        let prompt = Prompt::new(
            self.state.clone(),
            prompt_path.clone(),
            PromptAction::DeleteCollection { id },
        );
        server.at(prompt_path.clone(), prompt).await?;
        Ok(prompt_path)
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>> {
        let st = self.state.lock().await;
        let id = self.id(&st)?;
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(st
            .collections
            .get(&id)
            .map(|v| {
                super::state::search_collection(v, &query)
                    .into_iter()
                    .map(|iid| paths::item(&id, &iid))
                    .collect()
            })
            .unwrap_or_default())
    }

    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label =
            prop_string(&properties, "org.freedesktop.Secret.Item.Label")?.unwrap_or_default();
        let attributes = prop_attributes(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (id, iid, replaced) = {
            let mut st = self.state.lock().await;
            let id = self.id(&st)?;
            let plaintext = st
                .cipher(secret.session.as_str(), &require_sender(&header)?)?
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            // `id` was already validated by `self.id(&st)` above; missing
            // from `collections` here means it's a broken collection.
            let vault = st.collections.get_mut(&id).ok_or(Error::IsLocked)?;
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
        let Ok(id) = self.id(&st) else {
            return Vec::new();
        };
        self.vault(&st)
            .map(|v| {
                v.item_ids()
                    .into_iter()
                    .map(|iid| paths::item(&id, &iid))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        let st = self.state.lock().await;
        // A broken collection has no vault to ask; its label is the file
        // stem, which is exactly the id it was loaded under.
        match self.id(&st) {
            Ok(id) => st
                .collections
                .get(&id)
                .map(|v| v.label().to_string())
                .unwrap_or(id),
            Err(_) => String::new(),
        }
    }

    #[zbus(property)]
    async fn set_label(&self, label: &str) -> zbus::fdo::Result<()> {
        let mut st = self.state.lock().await;
        let id = self
            .id(&st)
            .map_err(|_| zbus::fdo::Error::UnknownObject("no such collection".into()))?;
        st.collections
            .get_mut(&id)
            // Not in `collections` despite `id()` having validated it: it's a
            // broken collection (see `state::ServiceState::broken`), which is
            // always reported locked.
            .ok_or_else(|| super::errors::vault_error_to_fdo(crate::vault::VaultError::Locked))?
            .set_label(label)
            .map_err(super::errors::vault_error_to_fdo)
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        let st = self.state.lock().await;
        self.vault(&st).map(|v| v.is_locked()).unwrap_or(true)
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let st = self.state.lock().await;
        self.vault(&st).map(|v| v.created()).unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let st = self.state.lock().await;
        self.vault(&st).map(|v| v.modified()).unwrap_or(0)
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
