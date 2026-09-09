//! `org.freedesktop.Secret.Collection`, served at `/collection/<id>` and `/aliases/<name>`.

use super::errors::{Error, Result};
use super::item::Item;
use super::prompt::{Prompt, PromptAction};
use super::registry;
use super::require_sender;
use super::session::SecretStruct;
use super::state::{PathTarget, ServiceState, Shared, VaultRef, block_in_place};
use super::{paths, prop_attributes, prop_string};
use crate::session::SessionCipher;
use std::collections::{BTreeMap, HashMap};
use zbus::Connection;
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// The per-item caps live in [`crate::vault::format`], not here, because
/// they are re-applied by `Vault::import_items` on the offline import path,
/// which is compiled without the `daemon` feature. Re-exported so this
/// module's public surface is unchanged.
pub use crate::vault::format::{
    MAX_ATTRIBUTE_KEY, MAX_ATTRIBUTE_VALUE, MAX_ITEM_ATTRIBUTES, MAX_ITEM_CONTENT_TYPE,
    MAX_ITEM_LABEL, MAX_ITEM_SECRET,
};

/// The *predicate* moved with the constants, for the same reason and one step
/// later: three layers each measured the same six caps in their own order
/// with their own error type - here, in `Vault::import_items`, and in
/// `import`'s pre-flight check - and when three hand-maintained copies of an
/// ordering drift, the symptom is a pre-check that passes an item the vault
/// then refuses halfway through a migration. [`Cap`] decides what is too
/// large; everything below only decides what to say about it.
use crate::vault::format::{Cap, CapViolation};

/// Render one cap violation as the `InvalidArgs` this layer has always
/// returned. The wording is per-cap and unchanged, so no client-visible
/// message moves.
pub(crate) fn cap_message(v: CapViolation) -> String {
    let limit = v.limit;
    match v.cap {
        Cap::Secret => format!("secret is too large; at most {limit} bytes per item"),
        Cap::Label => format!("label is too large; at most {limit} bytes per item"),
        Cap::ContentType => format!("content type is too large; at most {limit} bytes per item"),
        Cap::AttributeCount => format!("too many attributes; at most {limit} per item"),
        Cap::AttributeKey => {
            format!("attribute name is too large; at most {limit} bytes per attribute")
        }
        Cap::AttributeValue => {
            format!("attribute value is too large; at most {limit} bytes per attribute")
        }
    }
}

/// [`cap_message`] as the `InvalidArgs` the property setters must return; see
/// [`check_label`] for why they cannot return [`Error`].
fn invalid_args(v: CapViolation) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(cap_message(v))
}

/// Upper bound on the *ciphertext* of one item's secret, checked before the
/// decrypt rather than after it.
///
/// [`MAX_ITEM_SECRET`] is the exact cap and stays exactly where it was, on the
/// plaintext. This one exists because the decrypt itself was the attack:
/// `secret.value` arrives bounded only by the D-Bus message size limit
/// (128 MiB) and is decrypted while the single global state mutex is held, so
/// a client could stall every other client for the length of a 128 MiB
/// decrypt and only then be told its secret was over the cap.
///
/// It must never refuse something the plaintext check would have accepted, so
/// it bounds the plaintext from above rather than claiming to equal it. The
/// AES session cipher is CBC with PKCS#7, which appends 1..=16 bytes, so
/// `plaintext == ciphertext - pad >= ciphertext - 16`; a `plain` session's
/// ciphertext is the plaintext itself, so the same bound holds with room to
/// spare. Anything longer than `MAX_ITEM_SECRET + 16` therefore cannot
/// possibly decrypt to something within the cap. Everything shorter is still
/// measured exactly, after the decrypt, against `MAX_ITEM_SECRET`.
pub const MAX_ITEM_CIPHERTEXT: usize = MAX_ITEM_SECRET + 16;

/// Refuse an over-long content type. See [`check_label`] for the error type.
pub(crate) fn check_content_type(content_type: &str) -> std::result::Result<(), zbus::fdo::Error> {
    match Cap::ContentType.check(content_type.len()) {
        Some(v) => Err(invalid_args(v)),
        None => Ok(()),
    }
}

/// Refuse an over-long item label.
///
/// Returns `zbus::fdo::Error::InvalidArgs` — what [`Error::invalid_args`]
/// wraps — rather than [`Error`], because the `#[zbus(property)]` setters in
/// [`super::item`] cannot return a custom `DBusError` (see
/// [`super::errors::vault_error_to_fdo`]) and must share this check. `?`
/// converts it to [`Error`] on the method paths.
pub(crate) fn check_label(label: &str) -> std::result::Result<(), zbus::fdo::Error> {
    match Cap::Label.check(label.len()) {
        Some(v) => Err(invalid_args(v)),
        None => Ok(()),
    }
}

/// Refuse an over-large attribute set: too many pairs, or a pair whose name
/// or value is over its cap. See [`check_label`] for the error type.
pub(crate) fn check_attributes<'a>(
    count: usize,
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> std::result::Result<(), zbus::fdo::Error> {
    if let Some(over) = Cap::AttributeCount.check(count) {
        return Err(invalid_args(over));
    }
    for (k, v) in pairs {
        if let Some(over) = Cap::AttributeKey
            .check(k.len())
            .or_else(|| Cap::AttributeValue.check(v.len()))
        {
            return Err(invalid_args(over));
        }
    }
    Ok(())
}

/// Upper bound on one `DeleteItems` batch, for the same reason as
/// [`super::service::MAX_GET_SECRETS_ITEMS`] and with the same number: every
/// element costs a path resolution and a linear scan of the collection's item
/// index to confirm it exists. Neither happens under the global state mutex
/// any more — the batch is resolved under one acquisition of it and checked
/// with it released, under this collection's own lock — so the cap bounds the
/// work one message can ask for, not the time the mutex is held.
pub const MAX_DELETE_ITEMS: usize = 1024;

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

    /// `(id, vault)` under one brief state-lock acquisition, for every method
    /// that needs the vault behind this object. `Ok(_, None)` is a broken
    /// collection (see `state::ServiceState::broken`), which behaves as a
    /// permanently locked, empty one.
    ///
    /// Returns the vault's `Arc`, not a borrow: it is locked *after* the
    /// state guard is dropped, never while it is held (see
    /// `state::VaultRef`).
    async fn target(&self) -> Result<(String, Option<VaultRef>)> {
        let st = self.state.lock().await;
        let id = self.id(&st)?;
        let vault = st.vault(&id);
        Ok((id, vault))
    }

    /// Whether this collection is locked, or `true` when it is broken or
    /// gone. One state-lock acquisition, then the vault's own lock.
    async fn is_locked(&self) -> bool {
        match self.target().await {
            Ok((_, Some(v))) => v.lock().await.is_locked(),
            _ => true,
        }
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
            // An unreadable alias table is not "no such collection": saying
            // so would tell a client the name is free. It carries the reason
            // instead, which is the whole difference between unusable and
            // silently empty.
            CollectionRef::Alias(name) => match st.alias_target(name) {
                Ok(Some(id)) => Ok(id),
                Ok(None) => Err(Error::NoSuchObject),
                Err(e) => Err(Error::failed(format!("alias table is unreadable: {e}"))),
            },
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
        let (id, vault) = self.target().await?;
        // A broken collection has no vault to index; treat it as locked.
        let locked = match &vault {
            Some(v) => v.lock().await.is_locked(),
            None => true,
        };
        if locked {
            return Err(Error::IsLocked);
        }
        let mut st = self.state.lock().await;
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
        let (id, vault) = self.target().await?;
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        let Some(vault) = vault else {
            return Ok(Vec::new());
        };
        let vault = vault.lock().await;
        Ok(super::state::search_collection(&vault, &query)
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
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label =
            prop_string(&properties, "org.freedesktop.Secret.Item.Label")?.unwrap_or_default();
        // The label, the content type and the attributes all land in the same
        // encrypted item blob as the secret, so they need the same kind of
        // cap; `prop_attributes` bounds the attributes as it reads them.
        check_label(&label)?;
        check_content_type(&secret.content_type)?;
        let attributes = prop_attributes(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        // The state lock is held only for the map lookups and the session
        // lookup; the decrypt, the insert and the save that follows it all
        // happen under this collection's own lock with the global one free
        // (see `state::VaultRef`).
        let (id, vault, cipher) = {
            let st = self.state.lock().await;
            let id = self.id(&st)?;
            let cipher = SessionCipher::clone(
                st.cipher(secret.session.as_str(), &require_sender(&header)?)?,
            );
            // Everything cheap first: the decrypt below is caller-sized, so
            // it must not happen for a secret that is over the cap anyway,
            // nor for a collection that is locked and would refuse the write
            // regardless.
            if secret.value.len() > MAX_ITEM_CIPHERTEXT {
                return Err(Error::invalid_args(format!(
                    "secret is too large; at most {MAX_ITEM_SECRET} bytes per item"
                )));
            }
            // `id` was already validated by `self.id(&st)` above; missing
            // from `collections` here means it's a broken collection, which
            // is always locked.
            let vault = st.vault(&id).ok_or(Error::IsLocked)?;
            (id, vault, cipher)
        };
        let (iid, replaced) = {
            let mut vault = vault.lock().await;
            if vault.is_locked() {
                return Err(Error::IsLocked);
            }
            let plaintext = cipher
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            // The exact check: `MAX_ITEM_CIPHERTEXT` only bounds the plaintext
            // from above, it does not measure it.
            if let Some(over) = Cap::Secret.check(plaintext.len()) {
                return Err(Error::invalid_args(cap_message(over)));
            }
            block_in_place(|| {
                vault.insert_item(
                    &label,
                    attributes,
                    plaintext.to_vec(),
                    &secret.content_type,
                    replace,
                )
            })?
        };
        self.state.lock().await.touch();
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
        let Ok((id, Some(vault))) = self.target().await else {
            return Vec::new();
        };
        let item_ids = vault.lock().await.item_ids();
        item_ids
            .into_iter()
            .map(|iid| paths::item(&id, &iid))
            .collect()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        // A broken collection has no vault to ask; its label is the file
        // stem, which is exactly the id it was loaded under.
        match self.target().await {
            Ok((_, Some(v))) => v.lock().await.label().to_string(),
            Ok((id, None)) => id,
            Err(_) => String::new(),
        }
    }

    #[zbus(property)]
    async fn set_label(&self, label: &str) -> zbus::fdo::Result<()> {
        let vault = {
            let st = self.state.lock().await;
            let id = self
                .id(&st)
                .map_err(|_| zbus::fdo::Error::UnknownObject("no such collection".into()))?;
            st.vault(&id)
                // Not in `collections` despite `id()` having validated it:
                // it's a broken collection (see `state::ServiceState::broken`),
                // which is always reported locked.
                .ok_or_else(|| {
                    super::errors::vault_error_to_fdo(crate::vault::VaultError::Locked)
                })?
        };
        // The rename rewrites and re-fsyncs the whole vault, so it runs on
        // this collection's lock only, and off the async worker.
        let mut vault = vault.lock().await;
        block_in_place(|| vault.set_label(label)).map_err(super::errors::vault_error_to_fdo)
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        Collection::is_locked(self).await
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        match self.target().await {
            Ok((_, Some(v))) => v.lock().await.created(),
            _ => 0,
        }
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        match self.target().await {
            Ok((_, Some(v))) => v.lock().await.modified(),
            _ => 0,
        }
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
            // An unreadable alias table is not "no such collection": saying
            // so would tell a client the name is free. It carries the reason
            // instead, which is the whole difference between unusable and
            // silently empty.
            CollectionRef::Alias(name) => match st.alias_target(name) {
                Ok(Some(id)) => Ok(id),
                Ok(None) => Err(Error::NoSuchObject),
                Err(e) => Err(Error::failed(format!("alias table is unreadable: {e}"))),
            },
        }
    }
}

/// The private batch interface. Its wire name is deliberately *not* under
/// `org.freedesktop.Secret.*`: the freedesktop spec has no batch delete, and a
/// libsecret client must keep seeing exactly the spec's methods on
/// `org.freedesktop.Secret.Collection`. This is a separate interface on the
/// same object, for this project's own CLI.
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
    /// The state mutex is taken **once** for the whole batch — the alias
    /// lookup and every path resolution together — and released before any
    /// item is looked up; the validation and the single save then run under
    /// this collection's own lock, which is where a whole-vault re-encrypt
    /// and its two `fsync`s belong (see `state::VaultRef`). The `ItemDeleted`
    /// signals and the object unexports happen after the save has succeeded,
    /// for the whole batch at once; a failed save emits nothing.
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
        // Resolve every path under ONE state acquisition, then confirm each
        // names a real item with that lock released — the shape
        // `Service::get_secrets` uses. It used to re-take the state lock
        // *and* this collection's lock once per element, up to 1024 of each
        // per call, and de-duplicate with a linear `Vec::contains` inside the
        // loop (about half a million comparisons at the cap).
        //
        // `ServiceState::resolve_path` stops before the item index — that
        // lives behind the collection's own lock — so the existence check is
        // done here. Every semantic of the per-element version is kept: a
        // path that names no item is `NoSuchObject` whichever collection it
        // points at, exactly as the single `resolve_item` under the state
        // lock used to report it, and the *first* such path in the batch's
        // own order is the one reported; only then does a foreign but real
        // item become `InvalidArgs`; an empty batch is a no-op.
        let (id, resolved) = {
            let st = self.state.lock().await;
            let id = self.id(&st)?;
            let mut resolved = Vec::with_capacity(items.len());
            for path in &items {
                match st.resolve_path(path.as_str()) {
                    Some(PathTarget::Item { id, vault, item }) => resolved.push((id, item, vault)),
                    _ => return Err(Error::NoSuchObject),
                }
            }
            (id, resolved)
        };
        // One vault-lock acquisition per *run* of paths naming the same
        // collection, not one per path. Checking in the batch's own order is
        // what keeps the reporting rule above exact, and it costs nothing:
        // the first path naming another collection refuses the whole call, so
        // any batch that is not refused on its second element is a single
        // run — one acquisition, whatever its length.
        let mut item_ids: Vec<String> = Vec::with_capacity(resolved.len());
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut i = 0;
        while i < resolved.len() {
            let cid = resolved[i].0.clone();
            let vault = resolved[i].2.clone();
            let vault = vault.lock().await;
            while i < resolved.len() && resolved[i].0 == cid {
                let iid = &resolved[i].1;
                if !vault.has_item(iid) {
                    return Err(Error::NoSuchObject);
                }
                if cid != id {
                    return Err(Error::invalid_args(
                        "every item must belong to this collection",
                    ));
                }
                if seen.insert(iid.clone()) {
                    item_ids.push(iid.clone());
                }
                i += 1;
            }
        }
        {
            // Not in `collections`: a broken collection, which is always
            // reported locked.
            let vault = {
                let st = self.state.lock().await;
                st.vault(&id).ok_or(Error::IsLocked)?
            };
            let mut vault = vault.lock().await;
            // The lock is answered before the empty-batch shortcut, so
            // `DeleteItems([])` cannot report success on a collection where
            // `Item.Delete` — and a one-item batch — say `IsLocked`.
            if vault.is_locked() {
                return Err(Error::IsLocked);
            }
            if item_ids.is_empty() {
                return Ok(());
            }
            // `delete_items` re-checks every id against the items it is
            // about to remove, so an item that vanished since the loop above
            // still refuses the whole batch rather than deleting part of it.
            block_in_place(|| vault.delete_items(&item_ids))?;
        }
        self.state.lock().await.touch();
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
