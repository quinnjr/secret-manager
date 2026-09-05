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
use zbus::zvariant::OwnedObjectPath;

pub type Shared = Arc<tokio::sync::Mutex<ServiceState>>;

pub struct SessionEntry {
    /// Unique bus name of the client that opened the session.
    pub owner: String,
    pub cipher: SessionCipher,
}

pub struct ServiceState {
    pub vault_dir: PathBuf,
    pub kdf: KdfParams,
    pub pinentry: Pinentry,
    pub collections: BTreeMap<String, Vault>,
    pub aliases: BTreeMap<String, String>,
    /// session object path -> entry
    pub sessions: BTreeMap<String, SessionEntry>,
    /// prompt object path -> owner unique bus name
    pub prompt_owners: BTreeMap<String, String>,
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

pub fn save_aliases_to(dir: &Path, aliases: &BTreeMap<String, String>) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let text = toml::to_string(&AliasFile {
        aliases: aliases.clone(),
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(dir.join(ALIAS_FILE), text)
}

impl ServiceState {
    pub fn new(vault_dir: PathBuf, kdf: KdfParams, pinentry: Pinentry) -> Self {
        let now = Instant::now();
        Self {
            vault_dir,
            kdf,
            pinentry,
            collections: BTreeMap::new(),
            aliases: BTreeMap::new(),
            sessions: BTreeMap::new(),
            prompt_owners: BTreeMap::new(),
            started: now,
            last_activity: now,
            next_session: 0,
            next_prompt: 0,
        }
    }

    /// Open every `<id>.vault` in the vault directory that is not loaded yet, and
    /// reload aliases. Returns the ids that were newly loaded.
    pub fn load_vaults(&mut self) -> std::io::Result<Vec<String>> {
        std::fs::create_dir_all(&self.vault_dir)?;
        let mut new_ids = Vec::new();
        for entry in std::fs::read_dir(&self.vault_dir)? {
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
            if !paths::is_segment(&id) || self.collections.contains_key(&id) {
                continue;
            }
            match Vault::open(&path) {
                Ok(v) => {
                    self.collections.insert(id.clone(), v);
                    new_ids.push(id);
                }
                Err(e) => tracing::warn!("skipping {}: {e}", path.display()),
            }
        }
        self.aliases = load_aliases(&self.vault_dir)?;
        Ok(new_ids)
    }

    pub fn save_aliases(&self) -> std::io::Result<()> {
        save_aliases_to(&self.vault_dir, &self.aliases)
    }

    fn alias_target(&self, name: &str) -> Option<String> {
        self.aliases
            .get(name)
            .filter(|id| self.collections.contains_key(*id))
            .cloned()
    }

    /// Collection id for a collection or alias path.
    pub fn resolve_collection(&self, path: &str) -> Option<String> {
        match paths::parse(path)? {
            Target::Collection(id) if self.collections.contains_key(&id) => Some(id),
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

    pub fn new_session_path(&mut self) -> OwnedObjectPath {
        self.next_session += 1;
        paths::session(self.next_session)
    }

    pub fn new_prompt_path(&mut self) -> OwnedObjectPath {
        self.next_prompt += 1;
        paths::prompt(self.next_prompt)
    }

    pub fn cipher(&self, session_path: &str) -> Result<&SessionCipher> {
        self.sessions
            .get(session_path)
            .map(|e| &e.cipher)
            .ok_or(Error::NoSession)
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
                vault
                    .search_ids(query)
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
            self.collections.contains_key(id) || self.vault_dir.join(format!("{id}.vault")).exists()
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
        assert_eq!(
            st.new_session_path().as_str(),
            "/org/freedesktop/secrets/session/s1"
        );
        assert_eq!(
            st.new_session_path().as_str(),
            "/org/freedesktop/secrets/session/s2"
        );
        assert_eq!(
            st.new_prompt_path().as_str(),
            "/org/freedesktop/secrets/prompt/p1"
        );
        assert!(matches!(
            st.cipher("/org/freedesktop/secrets/session/s9"),
            Err(Error::NoSession)
        ));
    }
}
