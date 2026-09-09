//! `org.freedesktop.Secret.Service`.

use super::errors::{Error, Result};
use super::paths;
use super::prompt::{Prompt, PromptAction};
use super::prop_string;
use super::registry;
use super::require_sender;
use super::session::{SecretStruct, Session};
use super::state::{self, PathTarget, SessionEntry, Shared, VaultRef};
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
/// daemon for a very long time. libsecret never sends more than a few
/// hundred.
///
/// The per-element cost is no longer paid *under the global state mutex*:
/// only the path resolutions are, and the lookups and the encryption happen
/// with it released, one collection lock per collection named. The cap is
/// still the right one — a resolution each, plus a lock acquisition each, is
/// unbounded work driven by one message either way — but it bounds the
/// daemon's time, not the mutex's.
pub const MAX_GET_SECRETS_ITEMS: usize = 1024;

/// Upper bound on the attribute count of one search, for the same reason.
pub const MAX_SEARCH_ATTRIBUTES: usize = 1024;

/// Upper bound on the `objects` array of one `Lock` or `Unlock` call, for the
/// same reason as [`MAX_GET_SECRETS_ITEMS`] and with the same number (HIGH 2).
/// Every element costs a `paths::parse` (two `String` allocations), one state
/// lock acquisition to resolve it, and one acquisition of the named
/// collection's lock plus a scan of its whole item index to confirm the item
/// exists — the existence half of what `resolve_item` used to answer in one
/// step under the state lock, which is now the caller's to do with that lock
/// released. A single legal D-Bus message can carry over a million minimal
/// item paths, and an attacker maximises the scan by naming a real collection
/// and an item id that does not exist, so nothing short-circuits. The cap is
/// checked before any of it, and before any lock is taken. libsecret never
/// sends more than a few.
pub const MAX_LOCK_OBJECTS: usize = 1024;

/// Upper bound on an alias name (HIGH 3). `paths::is_segment` constrains the
/// alphabet but not the length, and every alias is written to `aliases.toml`
/// on every `SetAlias` and re-read at every daemon start, so an unbounded
/// name is unbounded disk and unbounded startup work that survives a restart.
/// Comfortably longer than any real alias (`default`, `login`, `session`).
pub const MAX_ALIAS_NAME: usize = 128;

/// Upper bound on how many aliases may exist at once (HIGH 3). Each one costs
/// a map entry, a line in `aliases.toml` — rewritten in full on every
/// `SetAlias`, so N aliases make the sequence quadratic — and two exported
/// D-Bus objects registered at startup. The spec defines a handful of aliases;
/// this leaves room for orders of magnitude more.
pub const MAX_ALIASES: usize = 256;

/// Refuse an oversized `Lock`/`Unlock` array. Deliberately a free function
/// called before the state lock is taken, so a refused call does no
/// per-element work and never contends for the mutex.
fn check_object_count(n: usize) -> Result<()> {
    if n > MAX_LOCK_OBJECTS {
        return Err(Error::invalid_args(format!(
            "too many objects; at most {MAX_LOCK_OBJECTS} per call"
        )));
    }
    Ok(())
}

/// Validate a client-supplied alias name: the path alphabet, plus the length
/// cap [`MAX_ALIAS_NAME`]. Shared by `SetAlias` and `CreateCollection`, which
/// both take one.
fn check_alias_name(name: &str) -> Result<()> {
    if !paths::is_segment(name) {
        return Err(Error::invalid_args("alias names must match [A-Za-z0-9_]+"));
    }
    if name.len() > MAX_ALIAS_NAME {
        return Err(Error::invalid_args(format!(
            "alias name too long; at most {MAX_ALIAS_NAME} characters"
        )));
    }
    Ok(())
}

/// Refuse a *new* alias once the table is at [`MAX_ALIASES`]. Repointing an
/// existing one is always allowed; only a new entry can grow the table.
///
/// Shared by `SetAlias` and the `CreateCollection` prompt: the cap used to be
/// enforced in `SetAlias` alone, so a client could pass it by creating
/// collections with an alias instead — and [`state::MAX_ALIAS_BYTES`] sizes
/// itself on this cap holding.
pub(crate) fn check_alias_room(table: &BTreeMap<String, String>, name: &str) -> Result<()> {
    if !table.contains_key(name) && table.len() >= MAX_ALIASES {
        return Err(Error::failed(format!(
            "too many aliases; at most {MAX_ALIASES}"
        )));
    }
    Ok(())
}

/// Append `id` unless it's already present.
fn push_unique(ids: &mut Vec<String>, id: String) {
    if !ids.contains(&id) {
        ids.push(id);
    }
}

/// Bucket `elements` by collection id, keeping each element's index.
///
/// The point is one vault-lock acquisition per *distinct collection* in a
/// batch instead of one per element: `Unlock` and `Lock` accept up to
/// [`MAX_LOCK_OBJECTS`] paths, which at the cap is 1024 acquisitions of a
/// lock there may be one of. Buckets come back in first-appearance order and
/// each holds its indices in the request's own order, so a caller can
/// reassemble a reply that is indistinguishable from the per-element walk.
///
/// The grouping itself is a hashed index rather than a linear scan per
/// element — the `contains`-in-a-loop shape `CollectionAdmin::delete_items`
/// replaced with a set.
fn group_by_collection<T>(
    elements: &[T],
    key: impl Fn(&T) -> &String,
) -> Vec<(String, Vec<usize>)> {
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    let mut at: HashMap<&String, usize> = HashMap::new();
    for (i, e) in elements.iter().enumerate() {
        let cid = key(e);
        match at.get(cid) {
            Some(&slot) => groups[slot].1.push(i),
            None => {
                at.insert(cid, groups.len());
                groups.push((cid.clone(), vec![i]));
            }
        }
    }
    groups
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
        Ok(super::state::search_all(&self.state, &query).await)
    }

    /// `/` means "no such alias", which would invite a client to claim a
    /// name the user may already own, so it is only ever answered from a
    /// table the daemon has actually read. A name the daemon still knows from
    /// an earlier successful read is answered normally — losing every alias
    /// because the file was truncated under a running daemon helps nobody —
    /// and anything else is an error. See `state::AliasTable`.
    async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath> {
        let st = self.state.lock().await;
        match st.alias_target(name) {
            Ok(Some(id)) => Ok(paths::collection(&id)),
            Ok(None) => Ok(paths::root()),
            Err(e) => Err(Error::failed(format!("alias table is unreadable: {e}"))),
        }
    }

    /// Secrets of `items`, encrypted for `session`.
    ///
    /// `items` is caller-supplied and otherwise bounded only by the D-Bus
    /// message size limit, so it is capped at [`MAX_GET_SECRETS_ITEMS`]; the
    /// per-item encryption also runs after the state lock is released, so
    /// only the (cheap) lookups happen under it.
    ///
    /// `touch()` runs only *after* the session check has passed (HIGH 1).
    /// Touching first meant any bus client could keep `last_activity` fresh
    /// with `GetSecrets([], "/bogus")` — a call that needs no session, no
    /// unlocked collection and no knowledge of any path, and that then fails
    /// with `NoSession`. `daemon::idle_lock` never fired, so `auto_lock_after`
    /// never locked anything and the keys stayed in daemon memory forever.
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
        // Resolve the paths under the state lock, then read the items with it
        // released — one vault lock at a time, and the requests for the same
        // collection grouped so a batch costs one acquisition per collection
        // rather than one per item (see `state::VaultRef`).
        type Wanted = Vec<(
            String,
            Vec<(OwnedObjectPath, String)>,
            super::state::VaultRef,
        )>;
        let (cipher, wanted): (SessionCipher, Wanted) = {
            let mut st = self.state.lock().await;
            let cipher = SessionCipher::clone(st.cipher(session.as_str(), &sender)?);
            st.touch();
            let mut wanted: Wanted = Vec::new();
            // Grouping is a hashed index, not a linear scan of `wanted` per
            // item: at `MAX_GET_SECRETS_ITEMS` items in as many distinct
            // collections the `find` was quadratic, the same
            // `contains`-in-a-loop shape `CollectionAdmin::delete_items`
            // replaced with a set. The index maps a collection id to its slot
            // in `wanted`, so the reply still groups in first-appearance
            // order.
            let mut group: HashMap<String, usize> = HashMap::new();
            for path in items {
                let Some(PathTarget::Item { id, vault, item }) = st.resolve_path(path.as_str())
                else {
                    continue;
                };
                match group.get(&id) {
                    Some(&at) => wanted[at].1.push((path, item)),
                    None => {
                        group.insert(id.clone(), wanted.len());
                        wanted.push((id, vec![(path, item)], vault));
                    }
                }
            }
            (cipher, wanted)
        };
        let mut plan: Plan = Vec::new();
        for (_, paths, vault) in wanted {
            let vault = vault.lock().await;
            for (path, iid) in paths {
                // An item that does not exist, and a locked collection, are
                // both omitted, as the spec allows.
                let Ok(item) = vault.item(&iid) else {
                    continue;
                };
                plan.push((path, item.secret.clone(), item.content_type.clone()));
            }
        }
        let mut out = HashMap::new();
        for (path, secret, content_type) in plan {
            let (parameters, value) = cipher.encrypt(&secret);
            out.insert(
                path,
                SecretStruct {
                    session: session.clone(),
                    parameters,
                    value: Zeroizing::new(value),
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
    ///
    /// It is, however, a resource boundary: the name is capped at
    /// [`MAX_ALIAS_NAME`] and the alias table at [`MAX_ALIASES`], and clearing
    /// an alias unexports its D-Bus objects again (HIGH 3). Without those, a
    /// client could loop `SetAlias(<megabyte name>, <real collection>)` and
    /// grow `aliases.toml`, the daemon's memory, and the object server without
    /// bound — and it survived a restart, because the file is reloaded and
    /// re-registered every time the daemon starts.
    async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        check_alias_name(name)?;
        let clearing = collection.as_str() == "/";
        // The edit runs under the state guard; the write that follows it does
        // not. `state::update_aliases` keeps the deliberate write-first,
        // commit-second order, re-checks `writable()` after re-acquiring the
        // lock — the table can degrade while the guard is dropped — and
        // redoes the edit if another writer committed underneath it.
        //
        // Clearing is handled above the split, not inside the repointing
        // branch. It used to mutate the table first and rely on the save
        // refusing, which returns *after* the removal and *before*
        // `unregister_alias` — so a refused clear left the table changed in
        // memory and both exported objects behind, which is exactly what
        // clearing exists to reclaim.
        let outcome =
            state::update_aliases(&self.state, state::OnWriteError::Refuse, |st, next| {
                if clearing {
                    next.remove(name);
                    return Ok(());
                }
                let id = st
                    .resolve_collection(collection.as_str())
                    .ok_or(Error::NoSuchObject)?;
                check_alias_room(next, name)?;
                next.insert(name.to_string(), id);
                Ok(())
            })
            .await;
        match outcome {
            state::AliasUpdate::Committed => {}
            state::AliasUpdate::Rejected(e) => return Err(e),
            state::AliasUpdate::Unusable(e) => {
                return Err(Error::failed(format!(
                    "alias table is unreadable ({e}); refusing to replace it"
                )));
            }
            // Nothing is committed in memory: the daemon must not disagree
            // with its own file when the write failed for any reason — a
            // full disk, a read-only directory — because the next reload
            // would silently undo what the client was told happened.
            state::AliasUpdate::NotWritten(e) => return Err(Error::failed(e)),
        }
        if clearing {
            // The alias object resolves its target at call time, so a
            // *repointed* alias keeps the objects it already has; a *cleared*
            // one has nothing left to resolve, and leaving its two exported
            // objects behind made every name a client ever used a permanent
            // cost.
            registry::unregister_alias(conn, name).await;
        } else {
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
        check_object_count(objects.len())?;
        // Answered before the resolution loop, not after it: a caller with no
        // sender, or one already at [`MAX_PROMPTS_PER_OWNER`], is refused
        // without first paying up to `MAX_LOCK_OBJECTS` lock acquisitions for
        // a prompt it can never be given. That is the shape HIGH 4 corrected
        // on `open_session`. The check is repeated under the guard that
        // inserts the owner entry below, because only there is it atomic with
        // the insert.
        let owner = require_sender(&header)?;
        self.state.lock().await.check_prompt_quota(&owner)?;
        // Resolve every path under ONE state acquisition and answer the lock
        // state with that guard released, one vault acquisition per *distinct
        // collection* rather than one of each per element — the shape
        // `CollectionAdmin::delete_items` documents. The two locks are never
        // held together: the `Arc`s are cloned out and the guard dropped
        // before any vault is touched (see `state::VaultRef`).
        struct Pending {
            path: OwnedObjectPath,
            cid: String,
            vault: Option<VaultRef>,
            item: Option<String>,
        }
        let pending: Vec<Pending> = {
            let st = self.state.lock().await;
            objects
                .into_iter()
                .filter_map(|path| match st.resolve_path(path.as_str()) {
                    // A broken collection (no entry in `collections`; see
                    // `state::ServiceState::broken`) has no vault and is
                    // always locked.
                    Some(PathTarget::Broken { id }) => Some(Pending {
                        path,
                        cid: id,
                        vault: None,
                        item: None,
                    }),
                    Some(PathTarget::Collection { id, vault }) => Some(Pending {
                        path,
                        cid: id,
                        vault: Some(vault),
                        item: None,
                    }),
                    Some(PathTarget::Item { id, vault, item }) => Some(Pending {
                        path,
                        cid: id,
                        vault: Some(vault),
                        item: Some(item),
                    }),
                    None => None,
                })
                .collect()
        };
        // `None` drops the element from the reply entirely; `Some(locked)` is
        // its answer. Verdicts are per element, so grouping cannot reorder
        // the reply: it is reassembled in the request's own order below.
        let mut verdict: Vec<Option<bool>> = vec![None; pending.len()];
        for (_, idxs) in group_by_collection(&pending, |p| &p.cid) {
            let Some(vault) = pending[idxs[0]].vault.clone() else {
                for i in idxs {
                    verdict[i] = Some(true);
                }
                continue;
            };
            let vault = vault.lock().await;
            let is_locked = vault.is_locked();
            for i in idxs {
                // An item path that names no item resolves to nothing, as it
                // did when the item index was reachable from the state lock
                // itself.
                if let Some(iid) = &pending[i].item
                    && !vault.has_item(iid)
                {
                    continue;
                }
                verdict[i] = Some(is_locked);
            }
        }
        let mut unlocked = Vec::new();
        let mut collections: Vec<String> = Vec::new();
        let mut requested = Vec::new();
        for (p, verdict) in pending.into_iter().zip(verdict) {
            let Some(is_locked) = verdict else { continue };
            if !is_locked {
                unlocked.push(p.path);
                continue;
            }
            push_unique(&mut collections, p.cid);
            requested.push(p.path);
        }
        if collections.is_empty() {
            return Ok((unlocked, paths::root()));
        }
        let mut st = self.state.lock().await;
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
        check_object_count(objects.len())?;
        // The same shape `unlock` uses: resolve every path under ONE state
        // acquisition, then take each *distinct collection's* lock once
        // instead of once per element — up to `MAX_LOCK_OBJECTS` of each per
        // message before. The state guard is dropped before any vault is
        // locked; the two are never held together (see `state::VaultRef`).
        struct Pending {
            path: OwnedObjectPath,
            cid: String,
            vault: VaultRef,
            item: Option<String>,
        }
        let pending: Vec<Pending> = {
            let st = self.state.lock().await;
            objects
                .into_iter()
                .filter_map(|path| match st.resolve_path(path.as_str()) {
                    // A broken collection has no vault to lock and is left
                    // out of the reply, exactly as when `collections.get_mut`
                    // missed it.
                    Some(PathTarget::Collection { id, vault }) => Some(Pending {
                        path,
                        cid: id,
                        vault,
                        item: None,
                    }),
                    Some(PathTarget::Item { id, vault, item }) => Some(Pending {
                        path,
                        cid: id,
                        vault,
                        item: Some(item),
                    }),
                    Some(PathTarget::Broken { .. }) | None => None,
                })
                .collect()
        };
        let (locked, changed) = {
            let mut answered: Vec<bool> = vec![false; pending.len()];
            let mut changed: Vec<String> = Vec::new();
            for (cid, idxs) in group_by_collection(&pending, |p| &p.cid) {
                let vault = pending[idxs[0]].vault.clone();
                let mut vault = vault.lock().await;
                let mut any = false;
                for i in idxs {
                    if let Some(iid) = &pending[i].item
                        && !vault.has_item(iid)
                    {
                        continue;
                    }
                    answered[i] = true;
                    any = true;
                }
                // A collection named only by paths that resolve to nothing is
                // not locked, exactly as before: the per-element walk reached
                // `vault.lock()` only past the existence check.
                if any && !vault.is_locked() {
                    vault.lock();
                    push_unique(&mut changed, cid);
                }
            }
            let locked: Vec<OwnedObjectPath> = pending
                .into_iter()
                .zip(answered)
                .filter_map(|(p, keep)| keep.then_some(p.path))
                .collect();
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
        // Beside `check_alias_name`, and before the prompt object exists.
        // `Vault::build` refuses an oversized label too, but only after a
        // pinentry dialog has been raised and answered — and the client is
        // then told its prompt was *dismissed*, which is neither true nor
        // actionable.
        if label.len() > crate::vault::format::MAX_LABEL {
            return Err(Error::invalid_args(format!(
                "label is too large; at most {} bytes",
                crate::vault::format::MAX_LABEL
            )));
        }
        let alias = if alias.is_empty() {
            None
        } else {
            check_alias_name(alias)?;
            Some(alias.to_string())
        };
        let mut st = self.state.lock().await;
        if let Some(a) = alias.as_ref() {
            // Refuse rather than fall through: without an answer here the
            // call would create a *second* collection where a healthy daemon
            // would have returned the existing one, and it could not record
            // the alias afterwards either.
            match st.alias_target(a) {
                Ok(Some(existing)) => return Ok((paths::collection(&existing), paths::root())),
                Ok(None) => {}
                Err(e) => {
                    return Err(Error::failed(format!(
                        "alias table is unreadable ({e}); cannot tell whether \
                         that alias is already taken"
                    )));
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The alias cap is a property of the *table*, not of `SetAlias`: the
    /// `CreateCollection` prompt takes an alias too and used to insert
    /// unconditionally, so a client could grow the table past `MAX_ALIASES`
    /// by creating collections instead of setting aliases — and
    /// `state::MAX_ALIAS_BYTES` derives its own sizing from this cap holding.
    /// Repointing an existing name never grows the table and is always
    /// allowed, at the cap included.
    #[test]
    fn the_alias_cap_counts_only_new_names() {
        let mut table: BTreeMap<String, String> = (0..MAX_ALIASES - 1)
            .map(|n| (format!("a{n}"), "default".to_string()))
            .collect();
        assert!(
            check_alias_room(&table, "fresh").is_ok(),
            "room for one more"
        );
        table.insert("fresh".into(), "default".into());
        assert_eq!(table.len(), MAX_ALIASES);
        assert!(
            check_alias_room(&table, "fresh").is_ok(),
            "repointing an existing alias at the cap is always allowed"
        );
        let err = check_alias_room(&table, "one_too_many").unwrap_err();
        assert!(err.to_string().contains(&MAX_ALIASES.to_string()), "{err}");
    }
}
