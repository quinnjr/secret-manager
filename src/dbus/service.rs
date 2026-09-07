//! `org.freedesktop.Secret.Service`.

use super::errors::{Error, Result};
use super::paths;
use super::prompt::{Prompt, PromptAction};
use super::prop_string;
use super::registry;
use super::require_sender;
use super::session::{SecretStruct, Session};
use super::state::{SessionEntry, Shared};
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::{BTreeMap, HashMap};
use zbus::Connection;
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

pub struct Service {
    state: Shared,
}

impl Service {
    pub fn new(state: Shared) -> Self {
        Self { state }
    }
}

/// Upper bound on the `items` array of one `GetSecrets` call. Every element
/// costs a linear path resolution, a linear item lookup, and an AES
/// encryption; without a cap a single ~128 MiB D-Bus message could occupy the
/// global state mutex for a very long time. libsecret never sends more than a
/// few hundred.
pub const MAX_GET_SECRETS_ITEMS: usize = 1024;

/// Upper bound on the attribute count of one search, for the same reason.
pub const MAX_SEARCH_ATTRIBUTES: usize = 1024;

/// A `SessionCipher` is not `Clone`; this copies one so the per-item
/// encryption in `get_secrets` can run after the state lock is released.
/// Append `id` unless it's already present.
fn push_unique(ids: &mut Vec<String>, id: String) {
    if !ids.contains(&id) {
        ids.push(id);
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    async fn open_session(
        &self,
        algorithm: &str,
        input: Value<'_>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        // The identity check and the quota check come FIRST, before any
        // key material is generated: `dh` costs two 1024-bit modexps
        // (`KeyPair::generate` and `SessionCipher::from_dh`), and running
        // them ahead of the cap meant the cap did not bound the work it
        // exists to bound — a client at its limit could still spend the
        // daemon's CPU on every refused call (HIGH 4).
        let owner = require_sender(&header)?;
        self.state.lock().await.check_session_quota(&owner)?;
        let (cipher, output) = match algorithm {
            ALGORITHM_PLAIN => (SessionCipher::plain(), Value::from("")),
            ALGORITHM_DH => {
                let peer = Vec::<u8>::try_from(input)
                    .map_err(|_| Error::invalid_args("input must be a byte array"))?;
                let pair = KeyPair::generate();
                let cipher = SessionCipher::from_dh(&pair, &peer).map_err(Error::invalid_args)?;
                (cipher, Value::from(pair.public_bytes().to_vec()))
            }
            other => {
                return Err(Error::not_supported(format!(
                    "unsupported algorithm '{other}'"
                )));
            }
        };
        let path = {
            let mut st = self.state.lock().await;
            // Re-checked: the lock was released across the key generation
            // above, so concurrent calls from the same client could otherwise
            // all pass the first check and land together.
            st.check_session_quota(&owner)?;
            let path = st.new_session_path();
            st.sessions
                .insert(path.to_string(), SessionEntry { owner, cipher });
            path
        };
        if let Err(e) = server
            .at(path.clone(), Session::new(self.state.clone(), path.clone()))
            .await
        {
            // Otherwise the session entry counts against this client's quota
            // for the life of the connection, for an object that was never
            // exported.
            self.state.lock().await.sessions.remove(path.as_str());
            return Err(e.into());
        }
        let output = OwnedValue::try_from(output).map_err(Error::failed)?;
        Ok((output, path))
    }

    #[zbus(out_args("unlocked", "locked"))]
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        if attributes.len() > MAX_SEARCH_ATTRIBUTES {
            return Err(Error::invalid_args(format!(
                "too many attributes; at most {MAX_SEARCH_ATTRIBUTES} per call"
            )));
        }
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(self.state.lock().await.search_all(&query))
    }

    async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath> {
        let st = self.state.lock().await;
        Ok(st
            .alias_target(name)
            .map(|id| paths::collection(&id))
            .unwrap_or_else(paths::root))
    }

    /// Secrets of `items`, encrypted for `session`.
    ///
    /// `items` is caller-supplied and otherwise bounded only by the D-Bus
    /// message size limit, so it is capped at [`MAX_GET_SECRETS_ITEMS`]; the
    /// per-item encryption also runs after the state lock is released, so
    /// only the (cheap) lookups happen under it.
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>> {
        if items.len() > MAX_GET_SECRETS_ITEMS {
            return Err(Error::invalid_args(format!(
                "too many items; at most {MAX_GET_SECRETS_ITEMS} per call"
            )));
        }
        let sender = require_sender(&header)?;
        type Plan = Vec<(OwnedObjectPath, Zeroizing<Vec<u8>>, String)>;
        let (cipher, plan): (SessionCipher, Plan) = {
            let mut st = self.state.lock().await;
            st.touch();
            let cipher = SessionCipher::clone(st.cipher(session.as_str(), &sender)?);
            let mut plan = Vec::with_capacity(items.len());
            for path in items {
                let Some((cid, iid)) = st.resolve_item(path.as_str()) else {
                    continue;
                };
                let Some(vault) = st.collections.get(&cid) else {
                    continue;
                };
                // Locked items are omitted, as the spec allows.
                let Ok(item) = vault.item(&iid) else {
                    continue;
                };
                plan.push((path, item.secret.clone(), item.content_type.clone()));
            }
            (cipher, plan)
        };
        let mut out = HashMap::new();
        for (path, secret, content_type) in plan {
            let (parameters, value) = cipher.encrypt(&secret);
            out.insert(
                path,
                SecretStruct {
                    session: session.clone(),
                    parameters,
                    value,
                    content_type,
                },
            );
        }
        Ok(out)
    }

    /// Point `name` at `collection`, or clear it when `collection` is `"/"`.
    ///
    /// As the freedesktop spec specifies (and every other implementation
    /// does), an existing alias is overwritten silently. **Any client on the
    /// session bus can repoint any alias, `default` included.** That is
    /// inherent to the same-uid Secret Service model — the bus offers no
    /// caller distinction to authorize against, and a client that could not
    /// repoint an alias could simply clear it and set it again — so this
    /// method is not, and cannot be, an integrity boundary.
    async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        if !paths::is_segment(name) {
            return Err(Error::invalid_args("alias names must match [A-Za-z0-9_]+"));
        }
        {
            let mut st = self.state.lock().await;
            if collection.as_str() == "/" {
                st.aliases.remove(name);
            } else {
                let id = st
                    .resolve_collection(collection.as_str())
                    .ok_or(Error::NoSuchObject)?;
                st.aliases.insert(name.to_string(), id);
            }
            st.save_aliases().map_err(Error::failed)?;
        }
        if collection.as_str() != "/" {
            registry::register_alias(conn, &self.state, name).await?;
        }
        Ok(())
    }

    #[zbus(out_args("unlocked", "prompt"))]
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut st = self.state.lock().await;
        let mut unlocked = Vec::new();
        let mut collections: Vec<String> = Vec::new();
        let mut requested = Vec::new();
        for path in objects {
            let Some(cid) = st.collection_id_of_path(path.as_str()) else {
                continue;
            };
            // A broken collection (no entry in `collections`; see
            // `state::ServiceState::broken`) is always locked.
            let is_locked = st
                .collections
                .get(&cid)
                .map(|v| v.is_locked())
                .unwrap_or(true);
            if !is_locked {
                unlocked.push(path);
                continue;
            }
            push_unique(&mut collections, cid);
            requested.push(path);
        }
        if collections.is_empty() {
            return Ok((unlocked, paths::root()));
        }
        let owner = require_sender(&header)?;
        st.check_prompt_quota(&owner)?;
        let prompt_path = st.new_prompt_path();
        st.prompt_owners.insert(prompt_path.to_string(), owner);
        drop(st);
        let prompt = Prompt::new(
            self.state.clone(),
            prompt_path.clone(),
            PromptAction::Unlock {
                collections,
                requested,
            },
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
        Ok((unlocked, prompt_path))
    }

    #[zbus(out_args("locked", "prompt"))]
    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let (locked, changed) = {
            let mut st = self.state.lock().await;
            let mut locked = Vec::new();
            let mut changed: Vec<String> = Vec::new();
            for path in objects {
                let Some(cid) = st.collection_id_of_path(path.as_str()) else {
                    continue;
                };
                if let Some(vault) = st.collections.get_mut(&cid) {
                    if !vault.is_locked() {
                        vault.lock();
                        push_unique(&mut changed, cid);
                    }
                    locked.push(path);
                }
            }
            (locked, changed)
        };
        for cid in changed {
            registry::notify_collection_changed(conn, &cid).await;
        }
        Ok((locked, paths::root()))
    }

    #[zbus(out_args("collection", "prompt"))]
    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = prop_string(&properties, "org.freedesktop.Secret.Collection.Label")?
            .unwrap_or_else(|| "Unnamed".to_string());
        let alias = if alias.is_empty() {
            None
        } else if paths::is_segment(alias) {
            Some(alias.to_string())
        } else {
            return Err(Error::invalid_args("alias names must match [A-Za-z0-9_]+"));
        };
        let mut st = self.state.lock().await;
        if let Some(existing) = alias.as_ref().and_then(|a| st.alias_target(a)) {
            return Ok((paths::collection(&existing), paths::root()));
        }
        let owner = require_sender(&header)?;
        st.check_prompt_quota(&owner)?;
        let prompt_path = st.new_prompt_path();
        st.prompt_owners.insert(prompt_path.to_string(), owner);
        drop(st);
        let prompt = Prompt::new(
            self.state.clone(),
            prompt_path.clone(),
            PromptAction::CreateCollection { label, alias },
        );
        // See `unlock` (LOW 3).
        if let Err(e) = server.at(prompt_path.clone(), prompt).await {
            self.state
                .lock()
                .await
                .prompt_owners
                .remove(prompt_path.as_str());
            return Err(e.into());
        }
        Ok((paths::root(), prompt_path))
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        let st = self.state.lock().await;
        st.collections
            .keys()
            .chain(st.broken.keys())
            .map(|id| paths::collection(id))
            .collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;
}
