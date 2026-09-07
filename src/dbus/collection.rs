//! `org.freedesktop.Secret.Collection`, served at `/collection/<id>` and `/aliases/<name>`.

use super::errors::{Error, Result};
use super::item::Item;
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

/// Upper bound on one item's decrypted secret, matching the control
/// protocol's frame cap. Without it a single client could push a collection
/// past the vault-level size limit — at which point the whole collection
/// stops saving — with one `CreateItem` call.
pub const MAX_ITEM_SECRET: usize = 1024 * 1024;

/// Upper bound on one `DeleteItems` batch, for the same reason as
/// [`super::service::MAX_GET_SECRETS_ITEMS`]: every element costs a path
/// resolution and a linear item lookup under the global state mutex.
pub const MAX_DELETE_ITEMS: usize = 1024;

/// Wire name of the private batch interface. Deliberately *not* under
/// `org.freedesktop.Secret.*`: the freedesktop spec has no batch delete, and a
/// libsecret client must keep seeing exactly the spec's methods on
/// `org.freedesktop.Secret.Collection`. This is a separate interface on the
/// same object, for this project's own CLI.
pub const ADMIN_INTERFACE: &str = "org.secret_manager.Collection1";

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
        let owner = require_sender(&header)?;
        st.check_prompt_quota(&owner)?;
        let prompt_path = st.new_prompt_path();
        st.prompt_owners.insert(prompt_path.to_string(), owner);
        drop(st);
        let prompt = Prompt::new(
            self.state.clone(),
            prompt_path.clone(),
            PromptAction::DeleteCollection { id },
        );
        // A failed export must not leave an owner entry counting against this
        // client's prompt quota for a prompt that does not exist (LOW 3).
        if let Err(e) = server.at(prompt_path.clone(), prompt).await {
            self.state
                .lock()
                .await
                .prompt_owners
                .remove(prompt_path.as_str());
            return Err(e.into());
        }
        Ok(prompt_path)
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>> {
        if attributes.len() > super::service::MAX_SEARCH_ATTRIBUTES {
            return Err(Error::invalid_args(format!(
                "too many attributes; at most {} per call",
                super::service::MAX_SEARCH_ATTRIBUTES
            )));
        }
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
            if plaintext.len() > MAX_ITEM_SECRET {
                return Err(Error::invalid_args(format!(
                    "secret is too large; at most {MAX_ITEM_SECRET} bytes per item"
                )));
            }
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

/// A private, non-spec interface exported alongside
/// `org.freedesktop.Secret.Collection` on the same object path.
///
/// It exists for one operation the freedesktop spec does not have: deleting a
/// set of items atomically. The CLI's `sm delete` / `sm ssh remove` used to
/// issue N separate `Item.Delete` calls, each of which rewrites the vault
/// file; if the collection locked or the daemon died part-way through, the
/// user was left with a half-deleted set and a secret that still existed.
pub struct CollectionAdmin {
    state: Shared,
    target: CollectionRef,
}

impl CollectionAdmin {
    pub fn new(state: Shared, target: CollectionRef) -> Self {
        Self { state, target }
    }

    fn id(&self, st: &ServiceState) -> Result<String> {
        match &self.target {
            CollectionRef::Id(id) => (st.collections.contains_key(id)
                || st.broken.contains_key(id))
            .then(|| id.clone())
            .ok_or(Error::NoSuchObject),
            CollectionRef::Alias(name) => st.alias_target(name).ok_or(Error::NoSuchObject),
        }
    }
}

#[interface(name = "org.secret_manager.Collection1")]
impl CollectionAdmin {
    /// Delete every item in `items`, or none of them.
    ///
    /// Every path is resolved and checked to belong to *this* collection
    /// before anything is removed, so one bogus or foreign path refuses the
    /// whole call with the vault untouched and its file unwritten. The removal
    /// itself is a single `Vault::delete_items`, which is one `retain` plus one
    /// save with in-memory rollback on write failure.
    ///
    /// The critical section is one short acquisition of the state mutex with
    /// no `.await` inside it and no key derivation — the vault is already
    /// unlocked, so a delete needs none — as `CLAUDE.md` requires. The
    /// `ItemDeleted` signals and the object unexports happen after the save
    /// has succeeded, for the whole batch at once; a failed save emits
    /// nothing.
    async fn delete_items(
        &self,
        items: Vec<OwnedObjectPath>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        if items.len() > MAX_DELETE_ITEMS {
            return Err(Error::invalid_args(format!(
                "too many items; at most {MAX_DELETE_ITEMS} per call"
            )));
        }
        let (id, item_ids) = {
            let mut st = self.state.lock().await;
            let id = self.id(&st)?;
            // Validate the whole batch first, against an immutable borrow.
            let mut item_ids: Vec<String> = Vec::with_capacity(items.len());
            for path in &items {
                let (cid, iid) = st.resolve_item(path.as_str()).ok_or(Error::NoSuchObject)?;
                if cid != id {
                    return Err(Error::invalid_args(
                        "every item must belong to this collection",
                    ));
                }
                if !item_ids.contains(&iid) {
                    item_ids.push(iid);
                }
            }
            if item_ids.is_empty() {
                return Ok(());
            }
            // Not in `collections` despite `id()` having validated it: a
            // broken collection, which is always reported locked.
            let vault = st.collections.get_mut(&id).ok_or(Error::IsLocked)?;
            vault.delete_items(&item_ids)?;
            st.touch();
            (id, item_ids)
        };
        // Past this point the file on disk no longer has any of them.
        let conn2 = conn.clone();
        let (id2, ids2) = (id.clone(), item_ids.clone());
        tokio::spawn(async move {
            let server = conn2.object_server();
            for iid in &ids2 {
                let _ = server.remove::<Item, _>(paths::item(&id2, iid)).await;
            }
        });
        let emitter = SignalEmitter::new(conn, paths::collection(&id))?;
        for iid in &item_ids {
            emitter.item_deleted(paths::item(&id, iid)).await?;
        }
        Ok(())
    }
}
