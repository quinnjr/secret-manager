//! `org.freedesktop.Secret.Prompt`: pinentry-driven unlock and collection creation.

use super::errors::{Error, Result};
use super::paths;
use super::registry;
use super::service::ServiceSignals;
use super::state::Shared;
use crate::prompt::{PinOutcome, PinRequest};
use crate::vault::{Vault, VaultError};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::interface;
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
}

/// Which `Completed` result variant a prompt owes: `ao` for unlock, `o` for
/// collection creation. Fixed at construction so `dismiss` can pick the right
/// one even after `prompt()` has consumed the `PromptAction`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    Unlock,
    CreateCollection,
}

impl PromptAction {
    fn kind(&self) -> PromptKind {
        match self {
            PromptAction::Unlock { .. } => PromptKind::Unlock,
            PromptAction::CreateCollection { .. } => PromptKind::CreateCollection,
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
}

fn owned(v: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(v).expect("no file descriptors in prompt results")
}

fn no_paths() -> OwnedValue {
    owned(Value::from(Vec::<OwnedObjectPath>::new()))
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(&self, _window_id: &str, #[zbus(connection)] conn: &Connection) -> Result<()> {
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
        let handle = tokio::spawn(async move {
            let (dismissed, result) = run(&conn, &state, action, &committed).await;
            finish(&conn, &state, &path, dismissed, result).await;
        });
        *self.task.lock().await = Some(handle);
        Ok(())
    }

    async fn dismiss(&self, #[zbus(connection)] conn: &Connection) -> Result<()> {
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
            PromptKind::CreateCollection => owned(Value::from(paths::root())),
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
    let already_done = state
        .lock()
        .await
        .prompt_owners
        .remove(path.as_str())
        .is_none();
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
    action: PromptAction,
    committed: &Mutex<bool>,
) -> (bool, OwnedValue) {
    match action {
        PromptAction::Unlock {
            collections,
            requested,
        } => {
            for (i, id) in collections.iter().enumerate() {
                // Only the first collection's password exchange is guarded:
                // once we're committed, later collections in the same prompt
                // proceed unconditionally (their own mutations are no more
                // abortable than the first's, and re-checking an already-true
                // flag would wrongly look like a `dismiss`).
                let gate = if i == 0 { Some(committed) } else { None };
                if !unlock_collection_inner(conn, state, id, gate).await {
                    return (true, no_paths());
                }
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
    }
}

/// Ask for the collection's password up to three times. True when unlocked.
pub async fn unlock_collection(conn: &Connection, state: &Shared, id: &str) -> bool {
    unlock_collection_inner(conn, state, id, None).await
}

async fn unlock_collection_inner(
    conn: &Connection,
    state: &Shared,
    id: &str,
    mut commit_gate: Option<&Mutex<bool>>,
) -> bool {
    let (pinentry, label) = {
        let st = state.lock().await;
        let Some(vault) = st.collections.get(id) else {
            return false;
        };
        if !vault.is_locked() {
            return true;
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
            Ok(PinOutcome::Cancelled) => return false,
            Err(e) => {
                tracing::warn!("pinentry failed: {e}");
                return false;
            }
        };
        // Claim the commit point exactly once, on the first real (uncancelled)
        // answer from pinentry. If `dismiss` claimed it first, back off before
        // touching any state.
        if let Some(gate) = commit_gate.take()
            && !claim(gate).await
        {
            return false;
        }
        let result = {
            let mut st = state.lock().await;
            match st.collections.get_mut(id) {
                Some(vault) => vault.unlock(pin.as_bytes()),
                None => return false,
            }
        };
        match result {
            Ok(()) => {
                state.lock().await.touch();
                registry::notify_collection_changed(conn, id).await;
                return true;
            }
            Err(VaultError::WrongPassword) => {
                error = Some("Wrong password, please try again.".into())
            }
            Err(e) => {
                tracing::warn!("cannot unlock '{id}': {e}");
                return false;
            }
        }
    }
    false
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
            Ok(vault) => {
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
