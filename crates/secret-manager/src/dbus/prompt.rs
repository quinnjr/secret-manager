//! `org.freedesktop.Secret.Prompt`: pinentry-driven unlock and collection creation.

use super::errors::{Error, Result};
use super::paths;
use super::registry;
use super::service::ServiceSignals;
use super::state::Shared;
use crate::prompt::{PinOutcome, PinRequest};
use crate::vault::{Vault, VaultError};
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

pub struct Prompt {
    state: Shared,
    path: OwnedObjectPath,
    action: Mutex<Option<PromptAction>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Prompt {
    pub fn new(state: Shared, path: OwnedObjectPath, action: PromptAction) -> Self {
        Self {
            state,
            path,
            action: Mutex::new(Some(action)),
            task: Mutex::new(None),
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
        let handle = tokio::spawn(async move {
            let (dismissed, result) = run(&conn, &state, action).await;
            finish(&conn, &state, &path, dismissed, result).await;
        });
        *self.task.lock().await = Some(handle);
        Ok(())
    }

    async fn dismiss(&self, #[zbus(connection)] conn: &Connection) -> Result<()> {
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
        let dismissed_result = match self.action.lock().await.take() {
            Some(PromptAction::CreateCollection { .. }) | None => owned(Value::from(paths::root())),
            Some(PromptAction::Unlock { .. }) => no_paths(),
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

/// Emit `Completed`, forget the prompt, and remove the object (deferred: may run inside `dismiss`).
async fn finish(
    conn: &Connection,
    state: &Shared,
    path: &OwnedObjectPath,
    dismissed: bool,
    result: OwnedValue,
) {
    state.lock().await.prompt_owners.remove(path.as_str());
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

async fn run(conn: &Connection, state: &Shared, action: PromptAction) -> (bool, OwnedValue) {
    match action {
        PromptAction::Unlock {
            collections,
            requested,
        } => {
            for id in &collections {
                if !unlock_collection(conn, state, id).await {
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
            match create_collection(conn, state, &label, alias.as_deref()).await {
                Some(path) => (false, owned(Value::from(path))),
                None => (true, owned(Value::from(paths::root()))),
            }
        }
    }
}

/// Ask for the collection's password up to three times. True when unlocked.
pub async fn unlock_collection(conn: &Connection, state: &Shared, id: &str) -> bool {
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
