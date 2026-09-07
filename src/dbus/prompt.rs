//! `org.freedesktop.Secret.Prompt`: pinentry-driven unlock and collection creation.

use super::errors::{Error, Result};
use super::paths;
use super::registry;
use super::require_sender;
use super::service::ServiceSignals;
use super::state::{PromptCommit, Shared};
use crate::prompt::{PinOutcome, PinRequest};
use crate::vault::{Vault, VaultError};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
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
    /// Guards the single moment past which aborting the running task could
    /// leave inconsistent state (a password obtained, about to mutate
    /// `ServiceState` or the filesystem). Whoever flips it from `false` to
    /// `true` first "wins": the task proceeds to completion on its own (a
    /// too-late `dismiss` becomes a no-op), or `dismiss` proceeds to abort the
    /// task and finish the prompt itself (the task, if it later reaches the
    /// same check, finds it already set and abandons its work before mutating
    /// anything).
    ///
    /// The gate is a *veto on aborting*, so it may only ever cover an
    /// irreversible step. An `Unlock` is reversible (the collection can simply
    /// be locked again), so its arm resets the gate at the top of every
    /// collection: the veto lasts one collection, never the whole prompt.
    committed: PromptCommit,
    /// Set by every `dismiss()`, including one that arrives *after* the
    /// commit gate was claimed. A multi-collection `Unlock` checks it before
    /// each remaining collection, so a dismissal stops the loop instead of
    /// raising a dialog for every collection left in the request.
    cancelled: Arc<AtomicBool>,
}

impl Prompt {
    pub fn new(state: Shared, path: OwnedObjectPath, action: PromptAction) -> Self {
        let kind = action.kind();
        Self {
            state,
            path,
            kind,
            action: Mutex::new(Some(action)),
            committed: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Reject `Prompt` and `Dismiss` calls from anyone but the client that
    /// obtained this prompt (`Service.Unlock`/`CreateCollection`/`Delete`),
    /// so one client cannot dismiss or drive another's confirmation.
    ///
    /// Fails closed: only a `prompt_owners` entry naming the caller is
    /// authorized. A *missing* entry means the prompt has been completed (or
    /// its owner disconnected) while the object is still briefly exported —
    /// treating that as authorized let any client take over a dismissed
    /// prompt's action and drive it to completion, a delete confirmation
    /// included.
    async fn check_owner(&self, header: &Header<'_>) -> Result<()> {
        let who = require_sender(header)?;
        let st = self.state.lock().await;
        match st.prompt_owners.get(self.path.as_str()) {
            Some(owner) if owner == &who => Ok(()),
            _ => Err(Error::NoSuchObject),
        }
    }
}

/// True for a codepoint in general category `Cf` (format), `Co` (private use)
/// or `Cn` (unassigned-but-reserved-for-formatting) that a toolkit may act on
/// rather than draw. (`Cs`, the surrogates, cannot occur in a Rust `str` at
/// all, so there is nothing to filter for them.)
///
/// `char::is_control()` covers only `Cc`, which leaves the whole invisible
/// half of the problem intact: `U+00AD` (soft hyphen), `U+061C` (Arabic letter
/// mark), `U+200B..U+200F` (zero-width space/joiners and the LTR/RTL marks),
/// `U+2060` (word joiner) and `U+FEFF` (zero-width no-break space) all survive
/// it. The marks among them still reorder neutral text in a GTK/Qt dialog, and
/// the zero-width ones let a label split a word an operator is scanning for
/// ("de\u{200B}lete"). Enumerated explicitly rather than pulled from a unicode
/// crate; the list is the set of `Cf`/`Cs`/`Co` ranges plus the `Cn`
/// codepoints reserved for formatting use (MEDIUM 1).
pub(crate) fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{08E2}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{E000}'..='\u{F8FF}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}'
        | '\u{110CD}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}'
        | '\u{F0000}'..='\u{FFFFD}'
        | '\u{100000}'..='\u{10FFFD}'
    )
}

/// Render a client-supplied label for a pinentry dialog.
///
/// Any bus client can set `Collection.Label` (no authorization is required for
/// it), and the label is interpolated into the text of a destructive-consent
/// dialog. Three separate forgeries have to be shut out:
///
/// * `escape()` turns a newline into `%0A`, which pinentry decodes back into a
///   real line break, so an unfiltered label can forge extra *lines* of dialog
///   text ("safe to remove, no secrets"). Every control character therefore
///   becomes an ordinary space (a space, not nothing, so words are not
///   silently glued together).
/// * A label can forge the daemon's own punctuation and so fake a complete
///   authoritative clause — `x" (id: default) and all 0 secrets? Nothing to
///   worry about` renders as a whole plausible first sentence naming a
///   *different* collection. `"`, `(` and `)` are the only characters the
///   daemon's own dialog text uses structurally, so all three are replaced by
///   a space and the label is left unable to imitate it (HIGH 1). The dialogs
///   additionally put the authoritative clause first and the label on a line
///   of its own, so a label cannot get in front of it at all.
/// * Bidi and other invisible format characters reorder or hide what the user
///   reads; see [`is_invisible_format`].
///
/// Whitespace runs then collapse to single spaces, and the result is truncated
/// to 64 characters plus a trailing ellipsis (so at most 65 characters).
pub fn display_label(label: &str) -> String {
    const MAX: usize = 64;
    let cleaned: String = label
        .chars()
        .filter(|c| !is_invisible_format(*c))
        .map(|c| {
            if c.is_control() || matches!(c, '"' | '(' | ')') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > MAX {
        let mut out: String = collapsed.chars().take(MAX).collect();
        out.push('\u{2026}');
        out
    } else {
        collapsed
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
        let cancelled = self.cancelled.clone();
        // The handle is registered before the task can reach `finish` (which
        // removes it): take the lock first, so a prompt that completes
        // immediately cannot leave a stale entry behind. `watch_clients` uses
        // it to abort the task, and its pinentry, if the owner disconnects,
        // and so does `dismiss` — the abort handle lives in `prompt_tasks` and
        // nowhere else, so a `Dismiss` that wakes on the state lock the moment
        // this one drops it can never find "no task" for a task that is in
        // fact running (MEDIUM 2).
        let mut st = self.state.lock().await;
        let handle = tokio::spawn(async move {
            let (dismissed, result) =
                run(&conn, &state, &path, action, &committed, &cancelled).await;
            finish(&conn, &state, &path, dismissed, result).await;
        });
        st.prompt_tasks
            .insert(self.path.to_string(), handle.abort_handle());
        // Published alongside the abort handle so an aborting caller can see
        // that this prompt has already committed (see
        // `ServiceState::prompt_commits`).
        st.prompt_commits
            .insert(self.path.to_string(), self.committed.clone());
        drop(st);
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        self.check_owner(&header).await?;
        // A completed prompt must never be re-armed: consume the action so a
        // later `Prompt` call finds nothing to run, even if it somehow passes
        // the owner check.
        self.action.lock().await.take();
        // Always recorded, even past the commit gate, so a multi-collection
        // unlock stops asking about the collections it has not reached yet.
        self.cancelled.store(true, Ordering::Release);
        // Claiming the gate and taking the abort handle happen under one
        // acquisition of the state lock, which is also the lock `prompt()`
        // holds while it registers the handle. That is what makes "gate not
        // yet claimed" and "no handle to abort" impossible to observe
        // together for a task that is actually running (MEDIUM 2).
        let handle = {
            let mut st = self.state.lock().await;
            if !claim(&self.committed) {
                // The running task has already passed (or fully completed)
                // the point of no return; its own `finish` call completes
                // the prompt exactly once, whatever the real outcome turned
                // out to be. Nothing to do here.
                return Ok(());
            }
            st.prompt_tasks.remove(self.path.as_str())
        };
        if let Some(handle) = handle {
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
        st.prompt_commits.remove(path.as_str());
        // The prompt finished with its owner still present, so what it
        // unlocked stays unlocked: forget the record rather than re-locking.
        st.prompt_unlocked.remove(path.as_str());
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
    committed: &AtomicBool,
    cancelled: &AtomicBool,
) -> (bool, OwnedValue) {
    match action {
        PromptAction::Unlock {
            collections,
            requested,
        } => {
            let mut any_unlocked = false;
            let mut unlocked_now: Vec<String> = Vec::new();
            for id in collections.iter() {
                // Unlocking is reversible, so the commit gate — which is a
                // veto on aborting this task — must not cover the whole
                // prompt. It is reset here, at the top of every collection, so
                // the veto lasts exactly one collection's dialog: a client
                // that disconnects, or dismisses, part-way through a
                // multi-collection unlock can always be obeyed (HIGH 2).
                //
                // Reset *before* reading `cancelled`, so a `Dismiss` racing
                // this point is caught by one side or the other: either it
                // claims the freshly-reset gate (and aborts this task), or it
                // claimed the old one first — in which case it set `cancelled`
                // before that, and the read below sees it.
                committed.store(false, Ordering::Release);
                // The gate is claimed by this collection's first real
                // (uncancelled) answer from pinentry.
                let mut gate = Some(committed);
                // A `Dismiss` that arrived after the commit gate was claimed
                // still stops the remaining collections here.
                if cancelled.load(Ordering::Acquire) {
                    break;
                }
                // And an owner that vanished stops them too, whatever the gate
                // says: `daemon::watch_clients` skips the abort for a prompt
                // that has claimed its gate, so without this check a
                // disconnect landing inside one dialog left the task walking
                // the rest of the list, raising a dialog for each with nobody
                // left to receive the result (HIGH 2).
                if !state.lock().await.prompt_owners.contains_key(path.as_str()) {
                    break;
                }
                match unlock_collection_inner(conn, state, id, &mut gate).await {
                    Outcome::Unlocked => {
                        any_unlocked = true;
                        unlocked_now.push(id.clone());
                        // Also record it where an abort cannot destroy it:
                        // this task may be aborted before the next
                        // collection's gate is claimed.
                        state
                            .lock()
                            .await
                            .prompt_unlocked
                            .entry(path.to_string())
                            .or_default()
                            .push(id.clone());
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
                st.prompt_unlocked.remove(path.as_str());
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
            match create_collection(conn, state, &label, alias.as_deref(), committed, cancelled)
                .await
            {
                Some(path) => (false, owned(Value::from(path))),
                None => (true, owned(Value::from(paths::root()))),
            }
        }
        PromptAction::DeleteCollection { id } => {
            match delete_collection(conn, state, &id, committed, cancelled).await {
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

async fn unlock_collection_inner(
    conn: &Connection,
    state: &Shared,
    id: &str,
    commit_gate: &mut Option<&AtomicBool>,
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
        (st.pinentry.clone(), display_label(vault.label()))
    };
    let mut error = None;
    for _ in 0..3 {
        let req = PinRequest {
            title: "secret-manager".into(),
            // The immutable id comes FIRST, and the client-controlled
            // label sits on a line of its own after it, so a label cannot
            // render text in front of the authoritative clause (HIGH 1).
            description: format!(
                "An application wants access to the locked keyring with id \"{id}\".\nIts label is: {label}"
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
            && !claim(gate)
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
    committed: &AtomicBool,
    cancelled: &AtomicBool,
) -> Option<OwnedObjectPath> {
    let pinentry = state.lock().await.pinentry.clone();
    let req = PinRequest {
        title: "secret-manager".into(),
        description: format!(
            "Choose a password for the new keyring \"{}\".",
            display_label(label)
        ),
        prompt: "Password:".into(),
        error: None,
        repeat: true,
    };
    // `dismiss()` records the dismissal unconditionally, including when it
    // arrives too late to abort this task. Checking it on both sides of the
    // dialog means a dismissal that failed to abort still cannot raise one, or
    // act on one already answered (MEDIUM 3).
    if cancelled.load(Ordering::Acquire) {
        return None;
    }
    let pin = match pinentry.ask(&req).await {
        Ok(PinOutcome::Pin(pin)) if !pin.is_empty() => pin,
        Ok(_) => return None,
        Err(e) => {
            tracing::warn!("pinentry failed: {e}");
            return None;
        }
    };
    if cancelled.load(Ordering::Acquire) {
        return None;
    }
    if !claim(committed) {
        return None;
    }
    // Only the cheap bookkeeping happens under the state lock: `Vault::create`
    // runs Argon2 (64 MiB by default), which would otherwise block every other
    // D-Bus and control-socket request and bypass the daemon-wide derivation
    // cap. Same split as the unlock path above.
    // `unique_collection_id` picks a free name, but `Vault::create` reserves
    // it exclusively, so a concurrent create can legitimately take the name
    // between the two. That is a lost race, not a failure: pick the next free
    // id and try again rather than failing a create the user confirmed.
    // Every attempt costs a full Argon2 derivation, and a same-uid attacker
    // who races file creation on the (predictable) candidate names can force
    // every one of them. Three is enough for a genuine lost race (MEDIUM 4).
    const NAME_ATTEMPTS: usize = 3;
    let mut attempt = 0;
    let (id, mut vault) = loop {
        attempt += 1;
        let (id, path, kdf) = {
            let st = state.lock().await;
            let id = st.unique_collection_id(label);
            let path = st.vault_dir.join(format!("{id}.vault"));
            (id, path, st.kdf)
        };
        let created = {
            let (path, label) = (path.clone(), label.to_string());
            let pin = zeroize::Zeroizing::new(pin.as_bytes().to_vec());
            crate::kdf::run_bounded(move || Vault::create(&path, &label, &pin, kdf)).await
        };
        match created {
            Ok(vault) => break (id, vault),
            Err(VaultError::AlreadyExists(_)) if attempt < NAME_ATTEMPTS => {
                tracing::debug!("collection id '{id}' was taken while creating it; retrying");
            }
            Err(e) => {
                tracing::warn!("cannot create collection '{label}': {e}");
                return None;
            }
        }
    };
    {
        // One acquisition, not three: the loop used to read `index_attributes`
        // only to discard it, then re-read it here under a second lock, then
        // take a third for the insert (MEDIUM 4).
        let mut st = state.lock().await;
        vault.set_index_attributes(st.index_attributes);
        st.collections.insert(id.clone(), vault);
        if let Some(a) = alias {
            st.aliases.insert(a.to_string(), id.clone());
            if let Err(e) = st.save_aliases() {
                tracing::warn!("cannot save aliases: {e}");
            }
        }
    }
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
    committed: &AtomicBool,
    cancelled: &AtomicBool,
) -> Option<OwnedObjectPath> {
    let (pinentry, label, item_count) = {
        let st = state.lock().await;
        let vault = st.collections.get(id)?;
        (
            st.pinentry.clone(),
            display_label(vault.label()),
            vault.item_ids().len(),
        )
    };
    let req = PinRequest {
        title: "secret-manager".into(),
        // The whole question — the immutable id and the secret count — is
        // stated before any client-controlled text, and the label follows on a
        // line of its own. A hostile label used to be interpolated *before*
        // the id in the same sentence, so it could close the daemon's quote,
        // forge its own `(id: ...)` clause and describe a different, empty
        // collection; the real clause then trailed after it and read as noise
        // (HIGH 1).
        description: format!(
            "Permanently delete the keyring with id \"{id}\" and all {item_count} secrets?\nIts label is: {label}"
        ),
        prompt: "Delete".into(),
        error: None,
        repeat: false,
    };
    // See `create_collection`: a dismissal that arrived too late to abort
    // this task must still stop it, before and after the dialog (MEDIUM 3).
    if cancelled.load(Ordering::Acquire) {
        return None;
    }
    let confirmed = match pinentry.confirm(&req).await {
        Ok(ok) => ok,
        Err(e) => {
            tracing::warn!("pinentry failed: {e}");
            false
        }
    };
    if !confirmed || cancelled.load(Ordering::Acquire) {
        return None;
    }
    if !claim(committed) {
        return None;
    }
    // Removing the collection from state and unlinking its file happen under
    // ONE guard, with no await between them. Two guards would let a
    // concurrent `CreateItem`/`SetSecret` re-create the file (via
    // `Vault::save`) in the gap, so the delete would silently do nothing and
    // leave an orphaned vault on disk; it would also let an abort land
    // between the two halves. A failing unlink puts the collection straight
    // back, so state and disk never disagree.
    let item_ids = {
        let mut st = state.lock().await;
        let vault = st.collections.remove(id)?;
        if vault.is_locked() {
            tracing::warn!(
                "cannot delete '{id}': it is locked; treating the confirmed delete as dismissed"
            );
            st.collections.insert(id.to_string(), vault);
            return None;
        }
        if let Err(e) = std::fs::remove_file(vault.path()) {
            tracing::warn!("cannot delete vault file for '{id}': {e}");
            st.collections.insert(id.to_string(), vault);
            return None;
        }
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
fn claim(committed: &AtomicBool) -> bool {
    committed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::display_label;

    /// A client-set label is the whole text of a consent dialog, so it must
    /// not be able to forge extra lines, reorder what is shown, or push the
    /// real question off screen (HIGH 3).
    #[test]
    fn display_label_strips_control_characters_and_newlines() {
        let hostile = "Scratch keyring\n(no secrets)";
        let shown = display_label(hostile);
        assert!(!shown.contains('\n'), "{shown}");
        assert!(!shown.contains('\r'));
        // The parentheses the label tried to use are neutralised too; see
        // `display_label_cannot_forge_the_daemons_own_punctuation`.
        assert_eq!(shown, "Scratch keyring no secrets");
        // A longer forged dialog is both flattened and truncated.
        let long_hostile =
            "Scratch keyring \u{2014} safe to remove\n(created by the installer, no secrets)";
        let shown = display_label(long_hostile);
        assert!(!shown.contains('\n'), "{shown}");
        assert!(shown.ends_with('\u{2026}'), "{shown}");
        assert_eq!(display_label("a\tb\r\nc"), "a b c");
        assert_eq!(display_label("a \u{0}\u{7} b"), "a b");
        // Whitespace runs collapse to a single space, and the ends are trimmed.
        assert_eq!(display_label("  lots   of \n\n space  "), "lots of space");
        assert_eq!(display_label(""), "");
    }

    /// The delete dialog's own text uses `"` and `(`/`)` structurally. A label
    /// that can reproduce them can forge a complete, plausible authoritative
    /// clause naming a *different* collection, so all three must be
    /// neutralised wherever the label ends up (HIGH 1).
    ///
    /// The payload is the verified attack: against the old filter, which
    /// stripped only control characters and bidi overrides, it rendered as
    /// `Permanently delete the keyring "x" (id: default) and all 0 secrets?
    /// Nothing to worry about" (id: work) and all 47 secrets?` — a first
    /// sentence a user reads and acts on, describing the wrong keyring.
    #[test]
    fn display_label_cannot_forge_the_daemons_own_punctuation() {
        let payload = "x\" (id: default) and all 0 secrets? Nothing to worry about";
        let shown = display_label(payload);
        assert!(!shown.contains('"'), "a quote survived: {shown}");
        assert!(!shown.contains('('), "an open paren survived: {shown}");
        assert!(!shown.contains(')'), "a close paren survived: {shown}");
        assert!(
            !shown.contains("(id:"),
            "the label forged an id clause: {shown}"
        );
        // Neutralised as spaces, not deleted, so words are never glued
        // together into something new.
        assert_eq!(
            shown,
            "x id: default and all 0 secrets? Nothing to worry about"
        );
        assert_eq!(display_label("a(b)c"), "a b c");
        assert_eq!(display_label("say \"hi\""), "say hi");
    }

    /// `char::is_control()` is general category `Cc` only, which leaves every
    /// invisible formatting codepoint intact: the marks among them reorder
    /// neutral text in a GTK/Qt dialog and the zero-width ones split a word an
    /// operator is scanning for. The filter is a category-based whitelist, so
    /// this covers `Cf`, `Cs`, `Co` and the formatting `Cn` alike — not just
    /// the bidi overrides the old test enumerated back at the filter (MEDIUM 1).
    #[test]
    fn display_label_drops_invisible_format_characters() {
        for c in [
            // Bidi controls (these the old filter already handled).
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            // All of these survived the old filter.
            '\u{00AD}',
            '\u{0600}',
            '\u{0605}',
            '\u{061C}',
            '\u{06DD}',
            '\u{070F}',
            '\u{180E}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{2064}',
            '\u{206F}',
            '\u{FEFF}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{1D173}',
            '\u{1D17A}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
            // Private use: a font can render these as anything at all.
            '\u{E000}',
            '\u{F8FF}',
        ] {
            let shown = display_label(&format!("safe{c}delete"));
            assert_eq!(shown, "safedelete", "U+{:04X} survived", c as u32);
        }
        // Ordinary text, including non-ASCII, is untouched.
        assert_eq!(
            display_label("caf\u{e9} \u{4e2d}\u{6587}"),
            "caf\u{e9} \u{4e2d}\u{6587}"
        );
    }

    #[test]
    fn display_label_truncates_an_over_long_label() {
        let long = "A".repeat(500);
        let shown = display_label(&long);
        assert_eq!(shown.chars().count(), 65);
        assert!(shown.ends_with('\u{2026}'), "{shown}");
        assert_eq!(&shown[..64], &long[..64]);
        // Exactly at the limit: no ellipsis.
        let at_limit = "B".repeat(64);
        assert_eq!(display_label(&at_limit), at_limit);
        // Truncation counts characters, not bytes, and never splits one.
        let wide = "\u{4e2d}".repeat(100);
        let shown = display_label(&wide);
        assert_eq!(shown.chars().count(), 65);
    }
}
