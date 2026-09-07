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
    pub collections: BTreeMap<String, Vault>,
    /// `<id>.vault` files that failed to open (corrupt or unreadable),
    /// keyed by the same id a healthy vault would have used: its file
    /// stem. Reported as a permanently-locked collection with that id as
    /// its label; `(path, error message)` for `Reload` retries and for
    /// `broken_error`.
    pub broken: BTreeMap<String, (PathBuf, String)>,
    pub aliases: BTreeMap<String, String>,
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

#[derive(Default, Serialize, Deserialize)]
struct AliasFile {
    aliases: BTreeMap<String, String>,
}

const ALIAS_FILE: &str = "aliases.toml";

pub fn load_aliases(dir: &Path) -> std::io::Result<BTreeMap<String, String>> {
    match std::fs::read_to_string(dir.join(ALIAS_FILE)) {
        Ok(text) => toml::from_str::<AliasFile>(&text)
            .map(|f| f.aliases)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
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
    pub aliases: BTreeMap<String, String>,
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
        aliases: BTreeMap::new(),
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
    scan.aliases = load_aliases(dir)?;
    Ok(scan)
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
            aliases: BTreeMap::new(),
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
            if self.collections.insert(id.clone(), vault).is_none() && !previously_broken {
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
        self.aliases = scan.aliases;
        new_ids
    }

    /// The stored error for a broken collection (see `broken`), if `id`
    /// names one — for the control-socket `Unlock` handler to report back
    /// verbatim instead of trying to unlock a vault that never loaded.
    pub fn broken_error(&self, id: &str) -> Option<&str> {
        self.broken.get(id).map(|(_, e)| e.as_str())
    }

    pub fn save_aliases(&self) -> std::io::Result<()> {
        save_aliases_to(&self.vault_dir, &self.aliases)
    }

    /// Collection id an alias currently resolves to, or `None` if it names
    /// no collection (unset, or targeting one that no longer exists).
    /// Shared by `Collection::id`, `Service::read_alias`, and
    /// `Service::create_collection` so alias resolution lives in one place.
    pub(crate) fn alias_target(&self, name: &str) -> Option<String> {
        self.aliases
            .get(name)
            .filter(|id| self.collections.contains_key(*id))
            .cloned()
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
            Target::Alias(name) => self.alias_target(&name),
            _ => None,
        }
    }

    /// `(collection id, item id)` for an item path under a collection or alias.
    pub fn resolve_item(&self, path: &str) -> Option<(String, String)> {
        let (cid, iid) = match paths::parse(path)? {
            Target::Item { collection, item } => (collection, item),
            Target::AliasItem { alias, item } => (self.alias_target(&alias)?, item),
            _ => return None,
        };
        self.collections
            .get(&cid)
            .filter(|v| v.has_item(&iid))
            .map(|_| (cid, iid))
    }

    /// Collection id behind any collection, alias, or item path.
    pub fn collection_id_of_path(&self, path: &str) -> Option<String> {
        self.resolve_collection(path)
            .or_else(|| self.resolve_item(path).map(|(c, _)| c))
    }

    pub fn is_unlocked_path(&self, path: &str) -> bool {
        self.collection_id_of_path(path)
            .and_then(|id| self.collections.get(&id))
            .map(|v| !v.is_locked())
            .unwrap_or(false)
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

    /// Search every collection. Returns `(unlocked item paths, locked item paths)`.
    pub fn search_all(
        &self,
        query: &BTreeMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for (cid, vault) in &self.collections {
            let target = if vault.is_locked() {
                &mut locked
            } else {
                &mut unlocked
            };
            target.extend(
                search_collection(vault, query)
                    .into_iter()
                    .map(|iid| paths::item(cid, &iid)),
            );
        }
        (unlocked, locked)
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

    #[test]
    fn loads_vaults_and_aliases_and_resolves_paths() {
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
        assert_eq!(
            st.resolve_item(item_path.as_str()),
            Some(("default".into(), iid.clone()))
        );
        assert_eq!(
            st.resolve_item(&format!("/org/freedesktop/secrets/aliases/default/{iid}")),
            Some(("default".into(), iid.clone()))
        );
        assert_eq!(
            st.resolve_item("/org/freedesktop/secrets/collection/default/missing"),
            None
        );
        assert_eq!(
            st.collection_id_of_path(item_path.as_str()),
            Some("default".into())
        );
        assert!(!st.is_unlocked_path(item_path.as_str()));
        st.collections
            .get_mut("default")
            .unwrap()
            .unlock(b"pw")
            .unwrap();
        assert!(st.is_unlocked_path(item_path.as_str()));
        let (u, l) = st.search_all(&BTreeMap::new());
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

    /// `resolve_item` takes any path a bus client can send. A collection or
    /// alias path is not an item path, and must not be mistaken for one -
    /// `GetSecrets` and the batch delete both feed it caller-supplied paths.
    #[test]
    fn resolve_item_refuses_a_path_that_names_no_item() {
        let dir = tempfile::tempdir().unwrap();
        let st = state(dir.path());
        for path in [
            "/org/freedesktop/secrets/collection/default",
            "/org/freedesktop/secrets/aliases/default",
            "/org/freedesktop/secrets",
            "/",
        ] {
            assert_eq!(st.resolve_item(path), None, "{path}");
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
}
