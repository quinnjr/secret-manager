//! `org.freedesktop.Secret.Prompt`: pinentry-driven unlock and collection creation.

use super::errors::{Error, Result};
use super::paths;
use super::registry;
use super::require_sender;
use super::service::ServiceSignals;
use super::state::Shared;
use crate::prompt::{PinOutcome, PinRequest};
use crate::vault::{Vault, VaultError};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub enum PromptAction {
    Unlock {
        collections: Vec<String>,
        requested: Vec<OwnedObjectPath>,
    },
    CreateCollection {
        label: String,
        alias: Option<String>,
    },
    DeleteCollection {
        id: String,
    },
}

/// Which `Completed` result variant a prompt owes: `ao` for unlock, `o` for
/// collection creation and deletion. Fixed at construction so `dismiss` can
/// pick the right one even after `prompt()` has consumed the `PromptAction`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    Unlock,
    CreateCollection,
    DeleteCollection,
}

impl PromptAction {
    fn kind(&self) -> PromptKind {
        match self {
            PromptAction::Unlock { .. } => PromptKind::Unlock,
            PromptAction::CreateCollection { .. } => PromptKind::CreateCollection,
            PromptAction::DeleteCollection { .. } => PromptKind::DeleteCollection,
        }
    }
}

pub struct Prompt {
    state: Shared,
    path: OwnedObjectPath,
    kind: PromptKind,
    action: Mutex<Option<PromptAction>>,
    task: Mutex<Option<JoinHandle<()>>>,
    /// Guards the single moment past which aborting the running task could
    /// leave inconsistent state (a password obtained, about to mutate
    /// `ServiceState` or the filesystem). Whoever locks this and flips it from
    /// `false` to `true` first "wins": the task proceeds to completion on its
    /// own (a too-late `dismiss` becomes a no-op), or `dismiss` proceeds to
    /// abort the task and finish the prompt itself (the task, if it later
    /// reaches the same check, finds it already set and abandons its work
    /// before mutating anything).
    committed: Arc<Mutex<bool>>,
}

impl Prompt {
    pub fn new(state: Shared, path: OwnedObjectPath, action: PromptAction) -> Self {
        let kind = action.kind();
        Self {
            state,
            path,
            kind,
            action: Mutex::new(Some(action)),
            task: Mutex::new(None),
            committed: Arc::new(Mutex::new(false)),
        }
    }

    /// Reject `Prompt` and `Dismiss` calls from anyone but the client that
    /// obtained this prompt (`Service.Unlock`/`CreateCollection`/`Delete`),
    /// so one client cannot dismiss or drive another's confirmation. A
    /// missing `prompt_owners` entry (already finished, or somehow never
    /// recorded) is not an ownership mismatch: `prompt()`'s own "already
    /// performed" check, or `dismiss()`'s idempotent no-op, handles that.
    async fn check_owner(&self, header: &Header<'_>) -> Result<()> {
        let who = require_sender(header)?;
        let st = self.state.lock().await;
        match st.prompt_owners.get(self.path.as_str()) {
            Some(owner) if owner != &who => Err(Error::NoSuchObject),
            _ => Ok(()),
        }
    }
}

fn owned(v: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(v).expect("no file descriptors in prompt results")
}

fn no_paths() -> OwnedValue {
    owned(Value::from(Vec::<OwnedObjectPath>::new()))
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        _window_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        self.check_owner(&header).await?;
        let action = self
            .action
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::failed("prompt already performed"))?;
        let conn = conn.clone();
        let state = self.state.clone();
        let path = self.path.clone();
        let committed = self.committed.clone();
        // The handle is registered before the task can reach `finish` (which
        // removes it): take the lock first, so a prompt that completes
        // immediately cannot leave a stale entry behind. `watch_clients` uses
        // it to abort the task, and its pinentry, if the owner disconnects.
        let mut st = self.state.lock().await;
        let handle = tokio::spawn(async move {
            let (dismissed, result) = run(&conn, &state, &path, action, &committed).await;
            finish(&conn, &state, &path, dismissed, result).await;
        });
        st.prompt_tasks
            .insert(self.path.to_string(), handle.abort_handle());
        drop(st);
        *self.task.lock().await = Some(handle);
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        self.check_owner(&header).await?;
        let already_committed = {
            let mut committed = self.committed.lock().await;
            let was = *committed;
            *committed = true;
            was
        };
        if already_committed {
            // The running task has already passed (or fully completed) the
            // point of no return; its own `finish` call completes the
            // prompt exactly once, whatever the real outcome turned out to
            // be. Nothing to do here.
            return Ok(());
        }
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
        let dismissed_result = match self.kind {
            PromptKind::Unlock => no_paths(),
            PromptKind::CreateCollection | PromptKind::DeleteCollection => {
                owned(Value::from(paths::root()))
            }
        };
        finish(conn, &self.state, &self.path, true, dismissed_result).await;
        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

/// Emit `Completed`, forget the prompt, and remove the object.
///
/// Idempotent: claims the prompt by removing its `prompt_owners` entry, and
/// does nothing if some other caller already claimed it first. This is what
/// guarantees exactly one `Completed` per prompt even when the running task's
/// own completion races against a `Dismiss` call (both may end up calling
/// `finish`).
async fn finish(
    conn: &Connection,
    state: &Shared,
    path: &OwnedObjectPath,
    dismissed: bool,
    result: OwnedValue,
) {
    let already_done = {
        let mut st = state.lock().await;
        st.prompt_tasks.remove(path.as_str());
        st.prompt_owners.remove(path.as_str()).is_none()
    };
    if already_done {
        return;
    }
    if let Ok(emitter) = SignalEmitter::new(conn, path.clone()) {
        let _ = emitter.completed(dismissed, Value::from(result)).await;
    }
    let conn = conn.clone();
    let path = path.clone();
    tokio::spawn(async move {
        let _ = conn
            .object_server()
            .remove::<Prompt, _>(path.as_str())
            .await;
    });
}

async fn run(
    conn: &Connection,
    state: &Shared,
    path: &OwnedObjectPath,
    action: PromptAction,
    committed: &Mutex<bool>,
) -> (bool, OwnedValue) {
    match action {
        PromptAction::Unlock {
            collections,
            requested,
        } => {
            let mut any_unlocked = false;
            let mut unlocked_now: Vec<String> = Vec::new();
            // The gate is claimed by whichever collection first gets a real
            // answer from pinentry, not necessarily the first in the list.
            let mut gate = Some(committed);
            for id in collections.iter() {
                match unlock_collection_inner(conn, state, id, &mut gate).await {
                    Outcome::Unlocked => {
                        any_unlocked = true;
                        unlocked_now.push(id.clone());
                    }
                    Outcome::Failed => {}
                    // Cancel means cancel: do not raise a dialog for the next
                    // collection in the same prompt.
                    Outcome::Cancelled => break,
                }
            }
            // An abort can only take effect at an await point, so a client
            // that vanished mid-prompt may have had its task aborted after a
            // vault was already opened. Re-lock anything this prompt opened
            // for an owner that is no longer there.
            if !state.lock().await.prompt_owners.contains_key(path.as_str()) {
                let mut st = state.lock().await;
                for id in &unlocked_now {
                    if let Some(vault) = st.collections.get_mut(id) {
                        vault.lock();
                    }
                }
                drop(st);
                for id in &unlocked_now {
                    registry::notify_collection_changed(conn, id).await;
                }
                return (true, no_paths());
            }
            if !any_unlocked {
                return (true, no_paths());
            }
            let unlocked: Vec<OwnedObjectPath> = {
                let st = state.lock().await;
                requested
                    .into_iter()
                    .filter(|p| st.is_unlocked_path(p.as_str()))
                    .collect()
            };
            (false, owned(Value::from(unlocked)))
        }
        PromptAction::CreateCollection { label, alias } => {
            match create_collection(conn, state, &label, alias.as_deref(), committed).await {
                Some(path) => (false, owned(Value::from(path))),
                None => (true, owned(Value::from(paths::root()))),
            }
        }
        PromptAction::DeleteCollection { id } => {
            match delete_collection(conn, state, &id, committed).await {
                Some(path) => (false, owned(Value::from(path))),
                None => (true, owned(Value::from(paths::root()))),
            }
        }
    }
}

/// How one collection's unlock attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Unlocked,
    /// Could not be unlocked, but the user did not ask to stop.
    Failed,
    /// The user cancelled, or a racing `Dismiss` claimed the prompt.
    Cancelled,
}

/// Ask for the collection's password up to three times. True when unlocked.
pub async fn unlock_collection(conn: &Connection, state: &Shared, id: &str) -> bool {
    let mut gate = None;
    unlock_collection_inner(conn, state, id, &mut gate).await == Outcome::Unlocked
}

async fn unlock_collection_inner(
    conn: &Connection,
    state: &Shared,
    id: &str,
    commit_gate: &mut Option<&Mutex<bool>>,
) -> Outcome {
    let (pinentry, label) = {
        let st = state.lock().await;
        if let Some(err) = st.broken_error(id) {
            // Never worked; no password can fix this. Skip pinentry
            // entirely and report the stored error rather than prompting.
            tracing::warn!("cannot unlock '{id}': vault is broken: {err}");
            return Outcome::Failed;
        }
        let Some(vault) = st.collections.get(id) else {
            return Outcome::Failed;
        };
        if !vault.is_locked() {
            return Outcome::Unlocked;
        }
        (st.pinentry.clone(), vault.label().to_string())
    };
    let mut error = None;
    for _ in 0..3 {
        let req = PinRequest {
            title: "secret-manager".into(),
            description: format!(
                "An application wants access to the keyring '{label}', but it is locked."
            ),
            prompt: "Password:".into(),
            error: error.take(),
            repeat: false,
        };
        let pin = match pinentry.ask(&req).await {
            Ok(PinOutcome::Pin(pin)) => pin,
            Ok(PinOutcome::Cancelled) => return Outcome::Cancelled,
            Err(e) => {
                tracing::warn!("pinentry failed: {e}");
                return Outcome::Failed;
            }
        };
        // Claim the commit point exactly once, on the first real (uncancelled)
        // answer from pinentry. If `dismiss` claimed it first, back off before
        // touching any state.
        if let Some(gate) = commit_gate.take()
            && !claim(gate).await
        {
            return Outcome::Cancelled;
        }
        // Argon2 runs off the state lock and under the daemon-wide derivation
        // cap; only the cheap AEAD open takes the lock.
        let params = {
            let st = state.lock().await;
            match st.collections.get(id) {
                Some(vault) => (*vault.salt(), vault.kdf()),
                None => return Outcome::Failed,
            }
        };
        let derived = crate::kdf::derive(
            zeroize::Zeroizing::new(pin.as_bytes().to_vec()),
            params.0,
            params.1,
        )
        .await;
        let result = match derived {
            Ok(key) => {
                let mut st = state.lock().await;
                match st.collections.get_mut(id) {
                    Some(vault) => vault.unlock_with_key(&key),
                    None => return Outcome::Failed,
                }
            }
            Err(e) => Err(VaultError::Crypto(e)),
        };
        match result {
            Ok(()) => {
                state.lock().await.touch();
                registry::notify_collection_changed(conn, id).await;
                return Outcome::Unlocked;
            }
            Err(VaultError::WrongPassword) => {
                error = Some("Wrong password, please try again.".into())
            }
            Err(e) => {
                tracing::warn!("cannot unlock '{id}': {e}");
                return Outcome::Failed;
            }
        }
    }
    Outcome::Failed
}

async fn create_collection(
    conn: &Connection,
    state: &Shared,
    label: &str,
    alias: Option<&str>,
    committed: &Mutex<bool>,
) -> Option<OwnedObjectPath> {
    let pinentry = state.lock().await.pinentry.clone();
    let req = PinRequest {
        title: "secret-manager".into(),
        description: format!("Choose a password for the new keyring '{label}'."),
        prompt: "Password:".into(),
        error: None,
        repeat: true,
    };
    let pin = match pinentry.ask(&req).await {
        Ok(PinOutcome::Pin(pin)) if !pin.is_empty() => pin,
        Ok(_) => return None,
        Err(e) => {
            tracing::warn!("pinentry failed: {e}");
            return None;
        }
    };
    if !claim(committed).await {
        return None;
    }
    let id = {
        let mut st = state.lock().await;
        let id = st.unique_collection_id(label);
        let path = st.vault_dir.join(format!("{id}.vault"));
        match Vault::create(&path, label, pin.as_bytes(), st.kdf) {
            Ok(mut vault) => {
                vault.set_index_attributes(st.index_attributes);
                st.collections.insert(id.clone(), vault);
                if let Some(a) = alias {
                    st.aliases.insert(a.to_string(), id.clone());
                    if let Err(e) = st.save_aliases() {
                        tracing::warn!("cannot save aliases: {e}");
                    }
                }
                id
            }
            Err(e) => {
                tracing::warn!("cannot create collection '{label}': {e}");
                return None;
            }
        }
    };
    if let Err(e) = registry::register_collection(conn, state, &id).await {
        tracing::warn!("cannot register collection '{id}': {e}");
    }
    if let Some(a) = alias {
        let _ = registry::register_alias(conn, state, a).await;
    }
    registry::notify_collections_changed(conn).await;
    if let Ok(emitter) = SignalEmitter::new(conn, paths::SERVICE_PATH) {
        let _ = emitter.collection_created(paths::collection(&id)).await;
    }
    Some(paths::collection(&id))
}

/// Confirm through pinentry, then perform exactly what `Collection::delete`
/// used to do directly: remove the collection from state, purge its
/// aliases, delete its vault file, unregister its D-Bus objects, and emit
/// `CollectionDeleted` / `Service.Collections` change notifications. The
/// unlink itself happens only after `claim(committed)` succeeds, so a
/// racing `Dismiss` cannot land between "confirmed" and "deleted".
async fn delete_collection(
    conn: &Connection,
    state: &Shared,
    id: &str,
    committed: &Mutex<bool>,
) -> Option<OwnedObjectPath> {
    let (pinentry, label, item_count) = {
        let st = state.lock().await;
        let vault = st.collections.get(id)?;
        (
            st.pinentry.clone(),
            vault.label().to_string(),
            vault.item_ids().len(),
        )
    };
    let req = PinRequest {
        title: "secret-manager".into(),
        description: format!(
            "Permanently delete the keyring '{label}' and all {item_count} secrets?"
        ),
        prompt: "Delete".into(),
        error: None,
        repeat: false,
    };
    let confirmed = match pinentry.confirm(&req).await {
        Ok(ok) => ok,
        Err(e) => {
            tracing::warn!("pinentry failed: {e}");
            false
        }
    };
    if !confirmed {
        return None;
    }
    if !claim(committed).await {
        return None;
    }
    // Unlink the vault file first, while it is still held in `collections`.
    // Only once that succeeds do we remove the collection from state and
    // purge its aliases, so a failing unlink leaves state untouched instead
    // of orphaning a collection whose file could not actually be deleted.
    let vault_path = {
        let st = state.lock().await;
        let vault = st.collections.get(id)?;
        if vault.is_locked() {
            tracing::warn!(
                "cannot delete '{id}': it is locked; treating the confirmed delete as dismissed"
            );
            return None;
        }
        vault.path().to_path_buf()
    };
    if let Err(e) = std::fs::remove_file(&vault_path) {
        tracing::warn!("cannot delete vault file for '{id}': {e}");
        return None;
    }
    let item_ids = {
        let mut st = state.lock().await;
        let vault = st.collections.remove(id)?;
        st.aliases.retain(|_, target| target != id);
        if let Err(e) = st.save_aliases() {
            tracing::warn!("cannot save aliases: {e}");
        }
        vault.item_ids()
    };
    let conn2 = conn.clone();
    let id2 = id.to_string();
    tokio::spawn(async move {
        registry::unregister_collection(&conn2, &id2, &item_ids).await;
        registry::notify_collections_changed(&conn2).await;
    });
    if let Ok(emitter) = SignalEmitter::new(conn, paths::SERVICE_PATH) {
        let _ = emitter.collection_deleted(paths::collection(id)).await;
    }
    Some(paths::collection(id))
}

/// Try to claim the commit point: true if this call won the race (safe to
/// proceed with irreversible work), false if `dismiss` claimed it first.
async fn claim(committed: &Mutex<bool>) -> bool {
    let mut c = committed.lock().await;
    if *c {
        return false;
    }
    *c = true;
    true
}
