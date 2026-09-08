//! Shared daemon state behind one async mutex.

use super::errors::{Error, Result};
use super::paths::{self, Target};
use crate::prompt::Pinentry;
use crate::session::SessionCipher;
use crate::vault::crypto::KdfParams;
use crate::vault::{Vault, collection_id_from_label};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::task::AbortHandle;
use zbus::zvariant::OwnedObjectPath;

pub type Shared = Arc<tokio::sync::Mutex<ServiceState>>;

/// One collection's vault, behind its own lock.
///
/// **Lock order (see `CLAUDE.md`): the global [`Shared`] lock is taken first,
/// the `Arc`s needed are cloned out of it, the global guard is dropped, and
/// only then is a vault locked.** Nothing ever holds both, so there is no
/// cycle to deadlock on, and the whole-vault re-encrypt and the two `fsync`s
/// a save performs happen with the global state lock free.
pub type VaultRef = Arc<tokio::sync::Mutex<Vault>>;

/// Wrap a freshly opened or created [`Vault`] in its own lock.
pub fn vault_ref(vault: Vault) -> VaultRef {
    Arc::new(tokio::sync::Mutex::new(vault))
}

/// Run a blocking closure without parking the async worker it is called on.
///
/// A vault save clones every item, encodes and seals the whole plaintext, and
/// then does two `fsync`s; at a large collection that is on the order of a
/// second of CPU and synchronous I/O. Left as a plain call it holds the
/// worker thread for the whole time, so a bounded pool of workers is a
/// bounded number of concurrent saves before *every* task on the runtime
/// stalls behind them. [`tokio::task::block_in_place`] hands the worker's
/// remaining queue to another thread first.
///
/// `block_in_place` panics on a current-thread runtime and is meaningless
/// with no runtime at all (the CLI drives the same `Vault` code
/// synchronously), so the flavour is checked and the closure is otherwise
/// simply run in place. The daemon and every integration test use a
/// multi-threaded runtime, so the fast path is the real one.
pub fn block_in_place<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// A prompt's commit gate; see `ServiceState::prompt_commits`.
///
/// An atomic rather than a mutex: `daemon::watch_clients` has to read it
/// while holding the state lock, and a `try_lock` there could not distinguish
/// "committed" from "momentarily contended", so it had to guess — and guessed
/// in the direction that leaves an orphaned prompt running.
pub type PromptCommit = Arc<std::sync::atomic::AtomicBool>;

/// Sessions one bus client may hold open at once. Each costs an exported
/// object (and, for `dh`, a 1024-bit modexp), and is only reclaimed on
/// `Close` or disconnect, so an unbounded number is a memory/CPU DoS.
pub const MAX_SESSIONS_PER_SENDER: usize = 32;

/// Prompts one bus client may have outstanding at once. Each costs an
/// exported object plus a `prompt_owners` entry until it completes.
pub const MAX_PROMPTS_PER_OWNER: usize = 8;

pub struct SessionEntry {
    /// Unique bus name of the client that opened the session.
    pub owner: String,
    pub cipher: SessionCipher,
}

pub struct ServiceState {
    pub vault_dir: PathBuf,
    pub kdf: KdfParams,
    /// `[vault] locked_search`: whether vault headers carry attribute
    /// hashes. Applied to every vault as it is loaded or created.
    pub index_attributes: bool,
    pub pinentry: Pinentry,
    /// Loaded collections, each behind its own lock. See [`VaultRef`] for the
    /// ordering rule that makes this safe.
    pub collections: BTreeMap<String, VaultRef>,
    /// `<id>.vault` files that failed to open (corrupt or unreadable),
    /// keyed by the same id a healthy vault would have used: its file
    /// stem. Reported as a permanently-locked collection with that id as
    /// its label; `(path, error message)` for `Reload` retries and for
    /// `broken_error`.
    pub broken: BTreeMap<String, (PathBuf, String)>,
    /// The alias table, and whether it can be trusted. See [`AliasTable`]:
    /// the "unusable" state is a *variant*, not a flag beside the map, so
    /// every lookup has to answer the question rather than remember a rule.
    pub aliases: AliasTable,
    /// session object path -> entry
    pub sessions: BTreeMap<String, SessionEntry>,
    /// prompt object path -> owner unique bus name
    pub prompt_owners: BTreeMap<String, String>,
    /// prompt object path -> the running pinentry task, so a prompt whose
    /// owner disconnects can be aborted (which also kills its pinentry).
    pub prompt_tasks: BTreeMap<String, AbortHandle>,
    /// prompt object path -> that prompt's commit gate, alongside its entry
    /// in `prompt_tasks`. `true` means the task has passed the point of no
    /// return and is finishing irreversible work, so aborting it (as
    /// `daemon::watch_clients` does when the owner disconnects) would drop a
    /// change that has already been committed. Exposed so an abort can be
    /// skipped for such a prompt.
    pub prompt_commits: BTreeMap<String, PromptCommit>,
    /// prompt object path -> collections that prompt has unlocked so far.
    ///
    /// The task keeps its own list, but an abort destroys it, and the abort
    /// is exactly when the list is needed: the commit gate is reset at the
    /// top of every collection, so a client that disconnects while a *later*
    /// dialog is on screen has its task aborted, and anything unlocked in an
    /// earlier iteration would otherwise stay decrypted in memory with no
    /// owner. `daemon::watch_clients` re-locks these before it drops the
    /// prompt.
    pub prompt_unlocked: BTreeMap<String, Vec<String>>,
    pub started: Instant,
    pub last_activity: Instant,
    next_session: u64,
    next_prompt: u64,
}

/// Why the alias table cannot be trusted, in a form that is safe to log, to
/// put in a D-Bus error, and to carry in a `Status` reply.
///
/// `toml`'s error `Display` echoes the offending source line verbatim, so the
/// text is attacker-shaped in both length and content. A 500 KB single-line
/// `aliases.toml` yields a half-megabyte message: on its own that is larger
/// than [`crate::protocol::MAX_FRAME`], so it destroys the whole `Status`
/// reply and takes the collection table down along with the diagnostic. And
/// the bytes come back raw, so a file the daemon only ever *reads* can forge
/// journal lines the way a client-supplied label can — which is why
/// `prompt::display_label` exists. Both are dealt with here, at the single
/// point of construction, rather than at each of the places the reason is
/// shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasError(String);

/// Longest recorded alias-failure reason, in characters.
///
/// Sized the way [`crate::vault::format::MAX_LABEL`] is: large enough for the
/// first line or two of a real TOML error ("expected `.`, `=`" and where),
/// small enough that it can never crowd a `Status` frame even with one per
/// reply.
pub const MAX_ALIAS_ERROR: usize = 200;
const _: () = assert!(MAX_ALIAS_ERROR <= crate::protocol::MAX_FRAME / 256);

impl AliasError {
    /// Name the file, then the bounded, sanitized reason.
    fn new(e: &std::io::Error) -> Self {
        let raw = format!("{ALIAS_FILE}: {e}");
        let cleaned: String = raw
            .chars()
            .filter(|c| !super::prompt::is_invisible_format(*c))
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.chars().count() > MAX_ALIAS_ERROR {
            let mut out: String = collapsed.chars().take(MAX_ALIAS_ERROR).collect();
            out.push('\u{2026}');
            Self(out)
        } else {
            Self(collapsed)
        }
    }
}

impl std::fmt::Display for AliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The alias table, in the two states it can actually be in.
///
/// A corrupt vault file has always been tolerated — it becomes a permanently
/// locked collection carrying its error — while a corrupt `aliases.toml`
/// refused to start the daemon at all, so the least valuable file in the
/// directory was the one that could brick the service. The two are now
/// symmetric: the daemon starts, and the alias table is **unusable rather
/// than silently empty**, because "no such alias" is exactly the answer that
/// invites a client to claim a name the user already owns.
///
/// That distinction was first written as a `bool` beside the map, and it held
/// only by accident: every lookup that forgot to consult the flag got `None`
/// out of the empty fallback, which is the wrong answer spelled correctly.
/// It is a sum type now so that "unusable but non-empty" is unrepresentable
/// and every caller is made by the compiler to say what it does about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasTable {
    /// `aliases.toml` parsed. This is what is on disk.
    Usable(BTreeMap<String, String>),
    /// It could not be read, and `known` is the last table that *was* read
    /// successfully — empty when it has never parsed, which is the state a
    /// daemon starts in over a corrupt file.
    ///
    /// Nothing may be written back. A name in `known` still resolves, because
    /// dropping a table we already hold would break every alias in a running
    /// process over a file whose contents we have; a name that is not in it
    /// is refused rather than reported free, because what is in the file
    /// *now* is exactly what the daemon does not know. A daemon that started
    /// over a corrupt file knows nothing at all, and its empty `known`
    /// collapses onto the second of those on its own.
    Degraded {
        reason: AliasError,
        known: BTreeMap<String, String>,
    },
}

impl Default for AliasTable {
    fn default() -> Self {
        AliasTable::Usable(BTreeMap::new())
    }
}

impl AliasTable {
    /// Why the table cannot be written, when it cannot. `None` means healthy.
    pub fn unusable(&self) -> Option<&AliasError> {
        match self {
            AliasTable::Usable(_) => None,
            AliasTable::Degraded { reason, .. } => Some(reason),
        }
    }

    /// The mappings the daemon knows about: the file's contents when healthy,
    /// the last ones read when stale, and none at all when it has never
    /// parsed.
    ///
    /// For enumeration only — registering D-Bus objects, listing the aliases
    /// that point at a collection. A *lookup* must go through [`resolve`] or
    /// [`ServiceState::alias_target`], which distinguish "not in the table"
    /// from "the table cannot answer".
    ///
    /// [`resolve`]: AliasTable::resolve
    pub fn known(&self) -> &BTreeMap<String, String> {
        match self {
            AliasTable::Usable(table) | AliasTable::Degraded { known: table, .. } => table,
        }
    }

    /// The table, only when it is what is actually on disk. `Err` means it
    /// must not be modified or written back: replacing a file the operator
    /// may still be able to repair with one built from what we guessed turns
    /// a recoverable parse error into silent data loss.
    pub fn writable(&self) -> std::result::Result<&BTreeMap<String, String>, &AliasError> {
        match self {
            AliasTable::Usable(table) => Ok(table),
            AliasTable::Degraded { reason, .. } => Err(reason),
        }
    }

    /// Look one name up.
    ///
    /// `Ok(None)` is the only "no such alias" this type ever produces, and it
    /// is produced only from a table we have actually read. While degraded, a
    /// name we know still resolves (availability), and a name we do not is an
    /// `Err` — never a `/`, which would invite a claim on a name the file may
    /// well already hold.
    pub fn resolve(&self, name: &str) -> std::result::Result<Option<&str>, &AliasError> {
        match self {
            AliasTable::Usable(table) => Ok(table.get(name).map(String::as_str)),
            AliasTable::Degraded { reason, known } => {
                known.get(name).map(String::as_str).ok_or(reason).map(Some)
            }
        }
    }

    /// Record that the file could not be read, keeping whatever was last read
    /// successfully.
    ///
    /// Overwriting the table with the empty fallback here is what made a
    /// single bad `Reload` permanent: every alias stopped resolving *and* the
    /// table could never be written back, so nothing could put it right
    /// except repairing the file by hand.
    pub fn degrade(&mut self, reason: AliasError) {
        let known = match std::mem::take(self) {
            AliasTable::Usable(table) | AliasTable::Degraded { known: table, .. } => table,
        };
        *self = AliasTable::Degraded { reason, known };
    }
}

#[derive(Default, Serialize, Deserialize)]
struct AliasFile {
    aliases: BTreeMap<String, String>,
}

const ALIAS_FILE: &str = "aliases.toml";

/// Largest `aliases.toml` that will be read into memory.
///
/// A vault file is bounded by [`crate::vault::format::MAX_VAULT_BYTES`] from
/// its `stat` size before a byte of it is read; the alias file had no bound
/// at all, so a multi-gigabyte one was slurped whole at startup — and, since
/// `Reload` is reachable from any same-uid peer, again on demand. 1 MiB is
/// four orders of magnitude more than [`super::service::MAX_ALIASES`] entries
/// at [`super::service::MAX_ALIAS_NAME`] each could ever need.
pub const MAX_ALIAS_BYTES: u64 = 1 << 20;

/// Read `aliases.toml`.
///
/// `InvalidData` — and only `InvalidData` — means "the file is there and the
/// daemon cannot make sense of it", which is the condition the caller may
/// degrade over. Every other error (`EACCES`, `EIO`, `EISDIR`) is a fault
/// with the *directory*, and "repair or delete aliases.toml" is meaningless
/// advice for it.
pub fn load_aliases(dir: &Path) -> std::io::Result<BTreeMap<String, String>> {
    let path = dir.join(ALIAS_FILE);
    // Bound the read before making it, exactly as `Vault::open` does.
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > MAX_ALIAS_BYTES => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("too large: {} bytes, at most {MAX_ALIAS_BYTES}", meta.len()),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e),
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str::<AliasFile>(&text)
            .map(|f| f.aliases)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        // The file can be unlinked between the `stat` and the read.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e),
    }
}

/// Write the alias file atomically: a fresh `O_EXCL` temp file beside it,
/// fsync, rename over the target, fsync the directory (HIGH 3).
///
/// The old implementation was `std::fs::write`, which truncates and then
/// writes: a crash, a full disk, or a kill between the two left a truncated
/// `aliases.toml` on disk, and `load_aliases` turns a truncated file into
/// `InvalidData`, which refuses daemon startup. Vault saves have always used
/// `vault::store::write_atomic` for exactly this reason; that helper is a
/// private item of `vault::store` and returns `VaultError`, so it is not
/// reachable from here — this is the same shape written against
/// `std::io::Error`, not a copy of it.
pub fn save_aliases_to(dir: &Path, aliases: &BTreeMap<String, String>) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let text = toml::to_string(&AliasFile {
        aliases: aliases.clone(),
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let path = dir.join(ALIAS_FILE);
    let suffix: String = crate::vault::crypto::random_bytes::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let tmp = dir.join(format!("{ALIAS_FILE}.{suffix}.tmp"));
    let write = || -> std::io::Result<()> {
        // No explicit mode: `std::fs::write` created the file with the
        // process umask applied to 0o666, and this must not change that.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    };
    match write() {
        Ok(()) => {
            // Best effort, as in `vault::store`: the rename is already durable
            // enough that a reader never sees a partial file.
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// What a directory scan found, before any of it is applied to the daemon's
/// state. Produced by [`scan_vault_dir`] and consumed by
/// [`ServiceState::merge_scan`].
pub struct VaultScan {
    pub opened: Vec<(String, Vault)>,
    pub broken: Vec<(String, PathBuf, String)>,
    /// The alias file's contents, or why they could not be had. A `Result`
    /// rather than a map plus a flag, so [`ServiceState::merge_scan`] cannot
    /// apply the one without deciding about the other.
    pub aliases: std::result::Result<BTreeMap<String, String>, AliasError>,
    pub seen: std::collections::BTreeSet<String>,
}

/// Read every `<id>.vault` in `dir` that is not already loaded.
///
/// Deliberately a free function taking no state: opening a vault reads the
/// whole file, and doing that while holding the daemon's state mutex lets any
/// peer stall every other request. The caller scans here, then applies the
/// result with [`ServiceState::merge_scan`] under a brief lock.
pub fn scan_vault_dir(
    dir: &Path,
    index_attributes: bool,
    already_loaded: &std::collections::BTreeSet<String>,
) -> std::io::Result<VaultScan> {
    std::fs::create_dir_all(dir)?;
    let mut scan = VaultScan {
        opened: Vec::new(),
        broken: Vec::new(),
        aliases: Ok(BTreeMap::new()),
        seen: std::collections::BTreeSet::new(),
    };
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("vault") {
            continue;
        }
        let Some(id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        scan.seen.insert(id.clone());
        if !paths::is_segment(&id) || already_loaded.contains(&id) {
            continue;
        }
        match Vault::open(&path) {
            Ok(mut v) => {
                v.set_index_attributes(index_attributes);
                scan.opened.push((id, v));
            }
            Err(e) => {
                tracing::warn!("skipping {}: {e}", path.display());
                scan.broken.push((id, path, e.to_string()));
            }
        }
    }
    // Tolerated exactly as a corrupt vault file is, and for the same reason:
    // refusing to start leaves the user with no daemon at all over a file that
    // holds nothing but convenience mappings, and anything that truncates it —
    // a backup tool, a full disk, a hand edit — would take the service down.
    match load_aliases(dir) {
        Ok(aliases) => scan.aliases = Ok(aliases),
        // A file that is present and unparseable is the tolerated case.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            let reason = AliasError::new(&e);
            // Sanitized and bounded: the text is the `toml` crate's echo of a
            // line of an attacker-writable file (F2).
            tracing::error!(
                "{}: {reason}; alias lookups will refuse for names not already \
                 known, and nothing will overwrite the file, until it is \
                 repaired or removed",
                dir.display()
            );
            scan.aliases = Err(reason);
        }
        // Anything else is a fault with the directory, not with the TOML in
        // it, and is reported the same way `read_dir` above is: a permission
        // error is not something the operator fixes by editing the file, and
        // degrading over it would start a daemon whose `SetAlias` can never
        // recreate it.
        Err(e) => return Err(e),
    }
    Ok(scan)
}

/// What a client-supplied object path resolves to, as far as
/// [`ServiceState::resolve_path`] can take it without touching a vault.
pub enum PathTarget {
    /// A collection or alias path naming a loaded collection.
    Collection { id: String, vault: VaultRef },
    /// A collection or alias path naming a collection whose file would not
    /// open (see [`ServiceState::broken`]): permanently locked, no vault.
    Broken { id: String },
    /// An item path under a loaded collection. **The item is not yet known to
    /// exist**: the caller must confirm it with `Vault::has_item` (or by the
    /// lookup it was going to do anyway) under `vault`'s lock, and treat a
    /// miss exactly as it would have treated an unresolvable path.
    Item {
        id: String,
        vault: VaultRef,
        item: String,
    },
}

impl PathTarget {
    /// The collection id, whichever kind of target this is.
    pub fn id(&self) -> &str {
        match self {
            PathTarget::Collection { id, .. }
            | PathTarget::Broken { id }
            | PathTarget::Item { id, .. } => id,
        }
    }
}

/// Whether the collection behind `path` is currently unlocked.
///
/// A free async function, not a method: it has to lock the collection, which
/// may only happen once the state guard is released.
pub async fn is_unlocked_path(state: &Shared, path: &str) -> bool {
    let Some(target) = state.lock().await.resolve_path(path) else {
        return false;
    };
    match target {
        PathTarget::Broken { .. } => false,
        PathTarget::Collection { vault, .. } => !vault.lock().await.is_locked(),
        PathTarget::Item { vault, item, .. } => {
            let v = vault.lock().await;
            v.has_item(&item) && !v.is_locked()
        }
    }
}

/// Search every collection. Returns `(unlocked item paths, locked item paths)`.
///
/// The collections are snapshotted under the state lock and searched with it
/// released, one vault lock at a time.
pub async fn search_all(
    state: &Shared,
    query: &BTreeMap<String, String>,
) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
    let vaults = state.lock().await.all_vaults();
    let mut unlocked = Vec::new();
    let mut locked = Vec::new();
    for (cid, vault) in vaults {
        let vault = vault.lock().await;
        let target = if vault.is_locked() {
            &mut locked
        } else {
            &mut unlocked
        };
        target.extend(
            search_collection(&vault, query)
                .into_iter()
                .map(|iid| paths::item(&cid, &iid)),
        );
    }
    (unlocked, locked)
}

/// Test helper: whether collection `id` is locked. A collection that is not
/// loaded counts as locked, matching what every bus and socket caller sees.
///
/// Tests used to read `state.lock().await.collections[id]` directly. They
/// cannot any more, and should not: the vault is behind its own lock, and
/// reaching it means the same global-then-collection ordering the daemon
/// itself obeys (see [`VaultRef`]).
#[cfg(any(test, feature = "test-util"))]
pub async fn collection_is_locked(state: &Shared, id: &str) -> bool {
    match state.lock().await.vault(id) {
        Some(v) => v.lock().await.is_locked(),
        None => true,
    }
}

/// Test helper: run `f` against collection `id`'s vault, under the daemon's
/// own lock ordering. Panics if `id` names no loaded collection.
#[cfg(any(test, feature = "test-util"))]
pub async fn with_vault<R>(state: &Shared, id: &str, f: impl FnOnce(&mut Vault) -> R) -> R {
    let vault = state
        .lock()
        .await
        .vault(id)
        .unwrap_or_else(|| panic!("no collection '{id}'"));
    let mut vault = vault.lock().await;
    f(&mut vault)
}

/// Item ids matching `query`: from the plaintext items when unlocked, from
/// the hashed header index otherwise (which is empty under
/// `locked_search = false`).
pub fn search_collection(vault: &Vault, query: &BTreeMap<String, String>) -> Vec<String> {
    match vault.search(query) {
        Ok(items) => items.into_iter().map(|i| i.id.clone()).collect(),
        Err(_) => vault.search_ids(query),
    }
}

impl ServiceState {
    pub fn new(vault_dir: PathBuf, kdf: KdfParams, pinentry: Pinentry) -> Self {
        let now = Instant::now();
        Self {
            vault_dir,
            kdf,
            index_attributes: true,
            pinentry,
            collections: BTreeMap::new(),
            broken: BTreeMap::new(),
            aliases: AliasTable::default(),
            sessions: BTreeMap::new(),
            prompt_owners: BTreeMap::new(),
            prompt_tasks: BTreeMap::new(),
            prompt_commits: BTreeMap::new(),
            prompt_unlocked: BTreeMap::new(),
            started: now,
            last_activity: now,
            next_session: 0,
            next_prompt: 0,
        }
    }

    /// Open every `<id>.vault` in the vault directory that is not loaded yet, and
    /// reload aliases. A file that fails to open is recorded in `broken`
    /// instead of being skipped, so it still shows up as a (permanently
    /// locked) collection; a previously-broken file that now opens cleanly
    /// moves into `collections`. Returns the ids seen for the first time
    /// this call (freshly opened, or freshly found broken) — the set a
    /// caller should register D-Bus objects for and announce.
    pub fn load_vaults(&mut self) -> std::io::Result<Vec<String>> {
        let scan = scan_vault_dir(
            &self.vault_dir,
            self.index_attributes,
            &self.collections.keys().cloned().collect(),
        )?;
        Ok(self.merge_scan(scan))
    }

    /// The ids already loaded, so a scan can skip re-reading them.
    pub fn loaded_ids(&self) -> std::collections::BTreeSet<String> {
        self.collections.keys().cloned().collect()
    }

    /// Apply a [`VaultScan`] taken outside the lock. Fast and allocation-only:
    /// no file is opened here.
    pub fn merge_scan(&mut self, scan: VaultScan) -> Vec<String> {
        let mut new_ids = Vec::new();
        for (id, vault) in scan.opened {
            let previously_broken = self.broken.remove(&id).is_some();
            if self
                .collections
                .insert(id.clone(), vault_ref(vault))
                .is_none()
                && !previously_broken
            {
                new_ids.push(id);
            }
        }
        for (id, path, err) in scan.broken {
            let previously_known = self.broken.insert(id.clone(), (path, err)).is_some()
                || self.collections.contains_key(&id);
            if !previously_known {
                new_ids.push(id);
            }
        }
        // A `broken` entry whose file has since been deleted or repaired stops
        // being advertised as a locked collection.
        self.broken.retain(|id, _| scan.seen.contains(id));
        match scan.aliases {
            Ok(aliases) => self.aliases = AliasTable::Usable(aliases),
            // A failed scan must not discard what is already loaded — the
            // rule `tests/daemon.rs` pins for collections. Assigning the
            // empty fallback here broke every alias in the running daemon
            // *and* forbade writing the table back, so one bad `Reload` was
            // permanent.
            Err(reason) => self.aliases.degrade(reason),
        }
        new_ids
    }

    /// The stored error for a broken collection (see `broken`), if `id`
    /// names one — for the control-socket `Unlock` handler to report back
    /// verbatim instead of trying to unlock a vault that never loaded.
    pub fn broken_error(&self, id: &str) -> Option<&str> {
        self.broken.get(id).map(|(_, e)| e.as_str())
    }

    /// Why the alias table cannot be used, when it cannot.
    pub fn aliases_unusable(&self) -> Option<&AliasError> {
        self.aliases.unusable()
    }

    /// Write the table back. Refuses unless it is the file's own contents;
    /// see [`AliasTable::writable`]. The callers refuse first, with a better
    /// message; this is the backstop.
    pub fn save_aliases(&self) -> std::io::Result<()> {
        let table = self.aliases.writable().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("refusing to overwrite an unreadable alias table: {e}"),
            )
        })?;
        save_aliases_to(&self.vault_dir, table)
    }

    /// Collection id an alias currently resolves to.
    ///
    /// `Ok(None)` is "no such alias": either unset, or set to a collection
    /// that no longer exists. `Err` is "this table cannot answer", which is a
    /// different thing and which every caller has to handle — the single
    /// funnel for alias resolution returns a `Result` precisely so that the
    /// compiler, not a future reader's memory, enumerates the places that
    /// have to decide (`Collection::id`, `CollectionAdmin::id`,
    /// `resolve_collection`, `resolve_path`, `Service::read_alias`,
    /// `Service::create_collection`).
    pub(crate) fn alias_target(
        &self,
        name: &str,
    ) -> std::result::Result<Option<String>, &AliasError> {
        Ok(self
            .aliases
            .resolve(name)?
            .filter(|id| self.collections.contains_key(*id))
            .map(str::to_string))
    }

    /// Collection id for a collection or alias path. Recognises a broken
    /// collection's id too (see `broken`), so it still resolves as a
    /// (locked) collection rather than `NoSuchObject`.
    pub fn resolve_collection(&self, path: &str) -> Option<String> {
        match paths::parse(path)? {
            Target::Collection(id)
                if self.collections.contains_key(&id) || self.broken.contains_key(&id) =>
            {
                Some(id)
            }
            // An object path that cannot be resolved is refused as
            // `NoSuchObject`, which is the safe answer: it reaches no vault
            // and touches no secret. It is also the *only* answer available
            // here — the D-Bus surface this feeds turns `None` into an error
            // and has nowhere to put a reason — so the reason is dropped
            // deliberately, and `Collection::id` carries it instead for the
            // paths that have a `Result` to put it in.
            Target::Alias(name) => self.alias_target(&name).unwrap_or(None),
            _ => None,
        }
    }

    /// The vault behind a loaded collection id.
    pub fn vault(&self, id: &str) -> Option<VaultRef> {
        self.collections.get(id).cloned()
    }

    /// What a client-supplied object path names, resolved as far as the
    /// global state alone can take it.
    ///
    /// It deliberately stops short of touching a vault: confirming that an
    /// item path names an item that exists needs that collection's own lock,
    /// which must never be awaited while this one is held. The caller locks
    /// the returned [`VaultRef`] after dropping the state guard and finishes
    /// the resolution there — see [`PathTarget::Item`].
    pub fn resolve_path(&self, path: &str) -> Option<PathTarget> {
        let (cid, iid) = match paths::parse(path)? {
            Target::Collection(id) => (id, None),
            // As in `resolve_collection`: an unusable table resolves to
            // nothing at all, so no path silently reaches a different
            // collection than the caller meant. This is the arm that carries
            // `GetSecrets`, `CreateItem`, `SetSecret` and `Delete` under an
            // alias path, so "resolves to nothing" is a refusal, not a
            // fallback.
            Target::Alias(name) => (self.alias_target(&name).unwrap_or(None)?, None),
            Target::Item { collection, item } => (collection, Some(item)),
            Target::AliasItem { alias, item } => {
                (self.alias_target(&alias).unwrap_or(None)?, Some(item))
            }
        };
        match (self.collections.get(&cid), iid) {
            (Some(v), None) => Some(PathTarget::Collection {
                id: cid,
                vault: v.clone(),
            }),
            (Some(v), Some(item)) => Some(PathTarget::Item {
                id: cid,
                vault: v.clone(),
                item,
            }),
            // A broken collection (see `broken`) has no vault; it resolves as
            // a permanently locked, empty collection. An *item* path under
            // one names nothing, exactly as before: it has no item index to
            // match against.
            (None, None) if self.broken.contains_key(&cid) => Some(PathTarget::Broken { id: cid }),
            _ => None,
        }
    }

    /// Refuse a new session once this client already holds
    /// [`MAX_SESSIONS_PER_SENDER`] of them.
    pub fn check_session_quota(&self, owner: &str) -> Result<()> {
        if self.sessions.values().filter(|e| e.owner == owner).count() >= MAX_SESSIONS_PER_SENDER {
            return Err(Error::failed("too many open sessions"));
        }
        Ok(())
    }

    /// Refuse a new prompt once this client already has
    /// [`MAX_PROMPTS_PER_OWNER`] outstanding.
    pub fn check_prompt_quota(&self, owner: &str) -> Result<()> {
        if self.prompt_owners.values().filter(|o| *o == owner).count() >= MAX_PROMPTS_PER_OWNER {
            return Err(Error::failed("too many outstanding prompts"));
        }
        Ok(())
    }

    pub fn new_session_path(&mut self) -> OwnedObjectPath {
        self.next_session += 1;
        paths::session(self.next_session)
    }

    pub fn new_prompt_path(&mut self) -> OwnedObjectPath {
        self.next_prompt += 1;
        paths::prompt(self.next_prompt)
    }

    /// Cipher of `session_path`, but only for the client that opened it.
    /// Any other caller gets `NoSession`, exactly as for a path that never
    /// existed, so sessions cannot be enumerated or borrowed across clients.
    pub fn cipher(&self, session_path: &str, sender: &str) -> Result<&SessionCipher> {
        match self.sessions.get(session_path) {
            Some(e) if e.owner == sender => Ok(&e.cipher),
            _ => Err(Error::NoSession),
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Every loaded collection and its vault, in id order, for a caller that
    /// has to walk all of them. Snapshotting the `Arc`s under this lock and
    /// working through them after it is released is the only permitted shape:
    /// see [`VaultRef`].
    pub fn all_vaults(&self) -> Vec<(String, VaultRef)> {
        self.collections
            .iter()
            .map(|(id, v)| (id.clone(), v.clone()))
            .collect()
    }

    /// Path-safe id derived from a label, made unique against loaded collections and files.
    pub fn unique_collection_id(&self, label: &str) -> String {
        let base = collection_id_from_label(label);
        let taken = |id: &str| {
            // `symlink_metadata`, not `exists`: `exists` follows the link, so a
            // dangling symlink at `<id>.vault` looks free here and then makes
            // `Vault::create`'s RENAME_NOREPLACE publish fail EEXIST, retrying
            // the same free-looking name until the attempts run out. Same-uid
            // is only semi-trusted, so treat any entry at the name — link,
            // directory, or file — as taken.
            self.collections.contains_key(id)
                || std::fs::symlink_metadata(self.vault_dir.join(format!("{id}.vault"))).is_ok()
        };
        if !taken(&base) {
            return base;
        }
        (2..)
            .map(|n| format!("{base}_{n}"))
            .find(|id| !taken(id))
            .expect("unbounded")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(dir: &Path) -> ServiceState {
        ServiceState::new(
            dir.to_path_buf(),
            KdfParams::FAST_FOR_TESTS,
            Pinentry::new("pinentry"),
        )
    }

    /// `resolve_path` stops at the item *index*, which lives behind the
    /// collection's own lock: it reports what a path names, and the caller
    /// confirms an item exists after the state guard is dropped. The
    /// existence half of what `resolve_item` used to answer in one step is
    /// asserted here through `has_item`, on the same paths.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loads_vaults_and_aliases_and_resolves_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(
            &dir.path().join("default.vault"),
            "Default",
            b"pw",
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        let (iid, _) = v
            .insert_item("x", BTreeMap::new(), b"s".to_vec(), "text/plain", false)
            .unwrap();
        save_aliases_to(
            dir.path(),
            &BTreeMap::from([("default".to_string(), "default".to_string())]),
        )
        .unwrap();
        std::fs::write(dir.path().join("junk.txt"), b"").unwrap();

        let mut st = state(dir.path());
        assert_eq!(st.load_vaults().unwrap(), vec!["default"]);
        assert!(
            st.load_vaults().unwrap().is_empty(),
            "second load adds nothing"
        );
        assert_eq!(
            st.resolve_collection("/org/freedesktop/secrets/collection/default"),
            Some("default".into())
        );
        assert_eq!(
            st.resolve_collection("/org/freedesktop/secrets/aliases/default"),
            Some("default".into())
        );
        assert_eq!(
            st.resolve_collection("/org/freedesktop/secrets/aliases/nope"),
            None
        );
        let item_path = paths::item("default", &iid);
        let alias_item = format!("/org/freedesktop/secrets/aliases/default/{iid}");
        for path in [item_path.as_str(), alias_item.as_str()] {
            match st.resolve_path(path) {
                Some(PathTarget::Item { id, item, vault }) => {
                    assert_eq!((id.as_str(), item.as_str()), ("default", iid.as_str()));
                    assert!(vault.try_lock().unwrap().has_item(&iid), "{path}");
                }
                _ => panic!("{path} must resolve to an item"),
            }
        }
        // A path under a real collection naming an item that does not exist
        // still resolves *to that collection* — the miss is the caller's to
        // notice, under the vault's lock, and every caller does.
        match st.resolve_path("/org/freedesktop/secrets/collection/default/missing") {
            Some(PathTarget::Item { id, item, vault }) => {
                assert_eq!(id, "default");
                assert!(!vault.try_lock().unwrap().has_item(&item));
            }
            _ => panic!("an item path under a loaded collection resolves to it"),
        }
        assert_eq!(
            st.resolve_path(item_path.as_str())
                .map(|t| t.id().to_string()),
            Some("default".into())
        );

        let shared: Shared = Arc::new(tokio::sync::Mutex::new(st));
        assert!(!is_unlocked_path(&shared, item_path.as_str()).await);
        assert!(
            !is_unlocked_path(
                &shared,
                "/org/freedesktop/secrets/collection/default/missing"
            )
            .await,
            "a path naming no item is not an unlocked one"
        );
        with_vault(&shared, "default", |v| v.unlock(b"pw"))
            .await
            .unwrap();
        assert!(is_unlocked_path(&shared, item_path.as_str()).await);
        let (u, l) = search_all(&shared, &BTreeMap::new()).await;
        assert_eq!(u, vec![item_path]);
        assert!(l.is_empty());
    }

    #[test]
    fn unique_ids_and_counters() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = state(dir.path());
        assert_eq!(st.unique_collection_id("Work"), "work");
        std::fs::write(dir.path().join("work.vault"), b"").unwrap();
        assert_eq!(st.unique_collection_id("Work"), "work_2");
        let first = st.new_session_path().to_string();
        let second = st.new_session_path().to_string();
        assert!(
            first.starts_with("/org/freedesktop/secrets/session/s1_"),
            "{first}"
        );
        assert!(
            second.starts_with("/org/freedesktop/secrets/session/s2_"),
            "{second}"
        );
        assert!(
            st.new_prompt_path()
                .as_str()
                .starts_with("/org/freedesktop/secrets/prompt/p1_")
        );
        assert!(matches!(
            st.cipher("/org/freedesktop/secrets/session/s9", ":1.1"),
            Err(Error::NoSession)
        ));
        st.sessions.insert(
            first.clone(),
            SessionEntry {
                owner: ":1.1".into(),
                cipher: SessionCipher::plain(),
            },
        );
        assert!(st.cipher(&first, ":1.1").is_ok());
        assert!(matches!(st.cipher(&first, ":1.2"), Err(Error::NoSession)));
    }

    /// Per-client caps on sessions and outstanding prompts (MEDIUM 4): the
    /// cap is per sender, so another client is unaffected.
    #[test]
    fn per_client_session_and_prompt_quotas() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = state(dir.path());
        for i in 0..MAX_SESSIONS_PER_SENDER {
            assert!(st.check_session_quota(":1.1").is_ok(), "at {i}");
            let path = st.new_session_path().to_string();
            st.sessions.insert(
                path,
                SessionEntry {
                    owner: ":1.1".into(),
                    cipher: SessionCipher::plain(),
                },
            );
        }
        let err = st.check_session_quota(":1.1").unwrap_err();
        assert!(err.to_string().contains("too many open sessions"), "{err}");
        assert!(st.check_session_quota(":1.2").is_ok());

        for i in 0..MAX_PROMPTS_PER_OWNER {
            assert!(st.check_prompt_quota(":1.1").is_ok(), "at {i}");
            let path = st.new_prompt_path().to_string();
            st.prompt_owners.insert(path, ":1.1".into());
        }
        let err = st.check_prompt_quota(":1.1").unwrap_err();
        assert!(
            err.to_string().contains("too many outstanding prompts"),
            "{err}"
        );
        assert!(st.check_prompt_quota(":1.2").is_ok());
    }

    /// `resolve_path` takes any path a bus client can send. A collection or
    /// alias path is not an item path, and must not be mistaken for one -
    /// `GetSecrets` and the batch delete both feed it caller-supplied paths
    /// and act only on the `Item` variant.
    #[test]
    fn resolve_path_never_calls_a_collection_path_an_item() {
        let dir = tempfile::tempdir().unwrap();
        let st = state(dir.path());
        for path in [
            "/org/freedesktop/secrets/collection/default",
            "/org/freedesktop/secrets/aliases/default",
            "/org/freedesktop/secrets",
            "/",
        ] {
            assert!(
                !matches!(st.resolve_path(path), Some(PathTarget::Item { .. })),
                "{path}"
            );
        }
    }

    /// An unreadable alias file is not a missing one: only `NotFound` means
    /// "no aliases yet". Anything else has to surface, or a `Reload` would
    /// silently replace every alias with an empty map.
    #[test]
    fn an_unreadable_alias_file_is_an_error_not_an_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_aliases(dir.path()).unwrap().is_empty(), "no file yet");
        // A directory where the file belongs: readable metadata, unreadable
        // contents, and not `NotFound`.
        std::fs::create_dir(dir.path().join(ALIAS_FILE)).unwrap();
        let err = load_aliases(dir.path()).unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    }

    /// A corrupt alias file must not stop the daemon, and must not be
    /// silently treated as "no aliases" either.
    ///
    /// It used to propagate out of `scan_vault_dir` and refuse startup, while
    /// a corrupt *vault* was tolerated as a permanently locked collection —
    /// so the file holding nothing but convenience mappings was the one that
    /// could brick the service, and anything that truncated it (a backup
    /// tool, a full disk, a hand edit) took the daemon down with it.
    #[test]
    fn a_corrupt_alias_file_degrades_instead_of_refusing_to_start() {
        let dir = tempfile::tempdir().unwrap();
        Vault::create(
            &dir.path().join("default.vault"),
            "Default",
            b"pw",
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        std::fs::write(dir.path().join(ALIAS_FILE), b"this is = = not toml").unwrap();

        let scan = scan_vault_dir(dir.path(), true, &Default::default())
            .expect("a corrupt alias file must not fail the scan");
        assert_eq!(scan.opened.len(), 1, "the vault still loads");
        let reason = scan.aliases.clone().expect_err("the reason is recorded");
        assert!(!reason.to_string().is_empty());

        let mut st = state(dir.path());
        st.load_vaults().expect("the daemon still starts");
        assert!(st.collections.contains_key("default"));
        assert_eq!(st.aliases_unusable(), Some(&reason));

        // Unusable, not empty. The assertion that used to stand here was
        // `alias_target("default") == None`, which passed with or without any
        // guard at all — the fixture cannot parse, so the map was empty
        // either way, and the property it claimed to pin held by accident.
        // Nothing has ever been read here, so the answer is an *error*: "no
        // such alias" is what would invite a client to claim the name.
        assert!(
            st.aliases.known().is_empty(),
            "a file that has never parsed leaves nothing known"
        );
        assert_eq!(st.alias_target("default").unwrap_err(), &reason);
        // And that refusal reaches the paths that carry secrets, not just
        // the read-only introspection: an alias object path resolves to
        // nothing rather than to some other collection.
        assert!(
            st.resolve_path("/org/freedesktop/secrets/aliases/default/item")
                .is_none()
        );
        assert!(
            st.resolve_collection("/org/freedesktop/secrets/aliases/default")
                .is_none()
        );
    }

    /// The file the operator still needs must not be replaced by one built
    /// from the empty table we fell back to.
    #[test]
    fn a_degraded_alias_table_is_never_written_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ALIAS_FILE);
        let corrupt = b"aliases = \"not a table\"";
        std::fs::write(&path, corrupt).unwrap();

        let mut st = state(dir.path());
        st.load_vaults().unwrap();
        assert!(st.aliases_unusable().is_some());

        let err = st.save_aliases().expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            corrupt,
            "the unreadable file was overwritten"
        );
    }

    /// Repairing the file and reloading clears the condition.
    #[test]
    fn repairing_the_alias_file_restores_it_on_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ALIAS_FILE), b"not toml at all =").unwrap();
        let mut st = state(dir.path());
        st.load_vaults().unwrap();
        assert!(st.aliases_unusable().is_some());

        Vault::create(
            &dir.path().join("work.vault"),
            "Work",
            b"pw",
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        save_aliases_to(
            dir.path(),
            &BTreeMap::from([("default".to_string(), "work".to_string())]),
        )
        .unwrap();

        st.load_vaults().unwrap();
        assert_eq!(st.aliases_unusable(), None, "the condition must clear");
        assert_eq!(st.alias_target("default"), Ok(Some("work".to_string())));
    }

    /// A vault directory that cannot be scanned must fail `load_vaults`
    /// rather than reporting an empty daemon.
    #[test]
    fn load_vaults_propagates_a_scan_failure() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"").unwrap();
        let mut st = state(&not_a_dir);
        assert!(st.load_vaults().is_err());
        assert!(st.collections.is_empty());
    }

    /// Vault file names come from the filesystem, so they are arbitrary
    /// bytes. One that is not UTF-8 has no id to load it under and is
    /// skipped, without failing the scan for every other vault beside it.
    #[test]
    fn a_vault_file_with_a_non_utf8_name_is_skipped() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        Vault::create(
            &dir.path().join("good.vault"),
            "Good",
            b"pw",
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        let bad = dir
            .path()
            .join(std::ffi::OsStr::from_bytes(b"\xff\xfe.vault"));
        std::fs::write(&bad, b"whatever").unwrap();

        let scan = scan_vault_dir(dir.path(), true, &Default::default()).unwrap();
        assert_eq!(
            scan.opened
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["good"]
        );
        assert!(
            scan.broken.is_empty(),
            "an unnameable file must be skipped, not advertised as a broken collection"
        );
        assert_eq!(
            scan.seen.len(),
            1,
            "only the nameable file is accounted for"
        );
    }

    /// A failed scan must not discard the alias table already loaded.
    ///
    /// `tests/daemon.rs` pins the equivalent contract for collections; this
    /// is the same rule for aliases, and it was broken by the fallback: a
    /// `Reload` after the file went corrupt replaced a good in-memory table
    /// with the empty fallback *and* forbade writing it back, so every alias
    /// stopped resolving, permanently.
    #[test]
    fn a_corrupt_alias_file_does_not_discard_the_table_already_loaded() {
        let dir = tempfile::tempdir().unwrap();
        Vault::create(
            &dir.path().join("work.vault"),
            "Work",
            b"pw",
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        save_aliases_to(
            dir.path(),
            &BTreeMap::from([("default".to_string(), "work".to_string())]),
        )
        .unwrap();
        let mut st = state(dir.path());
        st.load_vaults().unwrap();
        assert_eq!(
            st.resolve_collection("/org/freedesktop/secrets/aliases/default"),
            Some("work".to_string())
        );

        std::fs::write(dir.path().join(ALIAS_FILE), b"aliases = 5\n").unwrap();
        st.load_vaults().unwrap();
        assert_eq!(
            st.resolve_collection("/org/freedesktop/secrets/aliases/default"),
            Some("work".to_string()),
            "a failed reload must not discard the aliases already loaded"
        );
        assert_eq!(st.alias_target("default"), Ok(Some("work".to_string())));
        // A name we have never read is still refused: what is in the file now
        // is the thing we do not know, so "no such alias" is not ours to say.
        assert!(st.alias_target("login").is_err());
        // And the table stays unwritable while it is in that state.
        assert!(st.save_aliases().is_err());
        assert_eq!(
            std::fs::read(dir.path().join(ALIAS_FILE)).unwrap(),
            b"aliases = 5\n",
            "the unreadable file was overwritten"
        );
    }

    /// The recorded reason is bounded and carries no control characters.
    ///
    /// `toml`'s `Display` echoes the offending source line, so a large
    /// single-line file produced an error larger than `MAX_FRAME` — which
    /// destroys the whole `Status` reply, losing the collection table as well
    /// as the diagnostic — and reproduced raw control bytes, which forge
    /// journal lines from a file the daemon only ever reads.
    #[test]
    fn the_alias_error_is_bounded_and_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        // One long line, so `toml`'s echo of it is the whole 500 KB, with
        // control and bidi characters in it.
        let mut text = String::from("k = \"\x1b[2K\u{202e}");
        text.push_str(&"A".repeat(500 * 1024));
        std::fs::write(dir.path().join(ALIAS_FILE), text.as_bytes()).unwrap();
        let scan = scan_vault_dir(dir.path(), true, &Default::default()).unwrap();
        let reason = scan.aliases.expect_err("recorded").to_string();
        assert!(
            reason.len() <= 4 * MAX_ALIAS_ERROR,
            "the reason is {} bytes, which alone can overflow a Status frame",
            reason.len()
        );
        assert!(
            !reason.chars().any(|c| c.is_control()),
            "raw control characters forge log lines: {reason:?}"
        );
        assert!(
            reason.contains(ALIAS_FILE),
            "the reason must name the file to repair: {reason:?}"
        );
    }

    /// An oversized alias file is refused from its `stat` size, before it is
    /// read, exactly as a vault file is: `Reload` is reachable from any
    /// same-uid peer, so a multi-gigabyte file would otherwise be slurped
    /// whole on demand.
    #[test]
    fn an_oversized_alias_file_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut text = String::from("k = \"");
        text.push_str(&"a".repeat(MAX_ALIAS_BYTES as usize));
        text.push('"');
        std::fs::write(dir.path().join(ALIAS_FILE), text.as_bytes()).unwrap();
        let err = load_aliases(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("too large"), "{err}");
    }

    /// Only a *parse* failure degrades. An `EACCES`/`EIO`/`EISDIR` file is
    /// not a file the operator can repair by editing TOML, and starting into
    /// a permanently degraded state where `SetAlias` can never recreate the
    /// file is worse than saying so.
    #[test]
    fn an_unreadable_alias_file_fails_the_scan_rather_than_degrading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(ALIAS_FILE)).unwrap();
        let Err(err) = scan_vault_dir(dir.path(), true, &Default::default()) else {
            panic!("a file that cannot be read is not a parse failure");
        };
        assert_ne!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    }
}
