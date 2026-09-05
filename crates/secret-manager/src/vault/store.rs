//! A collection on disk: load, unlock, edit, save atomically.

use super::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};
use super::format::{self, FormatError, Header, Item, VERSION, VaultFile};
use super::now;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("collection is locked")]
    Locked,
    #[error("wrong password")]
    WrongPassword,
    #[error("no such item: {0}")]
    NoSuchItem(String),
    #[error("vault already exists: {0}")]
    AlreadyExists(PathBuf),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> VaultError {
    VaultError::Io {
        path: path.to_path_buf(),
        source,
    }
}

enum State {
    Locked,
    Unlocked { key: Key, items: Vec<Item> },
}

pub struct Vault {
    path: PathBuf,
    header: Header,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    state: State,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("label", &self.header.label)
            .field("locked", &self.is_locked())
            .field("items", &self.header.index.len())
            .finish()
    }
}

impl Vault {
    pub fn create(
        path: &Path,
        label: &str,
        password: &[u8],
        kdf: KdfParams,
    ) -> Result<Vault, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_key(password, &salt, kdf)?;
        let t = now();
        let header = Header {
            version: VERSION,
            label: label.to_string(),
            created: t,
            modified: t,
            kdf,
            salt,
            nonce: [0u8; NONCE_LEN],
            index: Vec::new(),
        };
        let mut vault = Vault {
            path: path.to_path_buf(),
            header,
            aad: Vec::new(),
            ciphertext: Vec::new(),
            state: State::Unlocked {
                key,
                items: Vec::new(),
            },
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        let bytes = std::fs::read(path).map_err(|e| io_err(path, e))?;
        let file = VaultFile::decode(&bytes)?;
        Ok(Vault {
            path: path.to_path_buf(),
            header: file.header,
            aad: file.aad,
            ciphertext: file.ciphertext,
            state: State::Locked,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn label(&self) -> &str {
        &self.header.label
    }
    pub fn created(&self) -> u64 {
        self.header.created
    }
    pub fn modified(&self) -> u64 {
        self.header.modified
    }
    pub fn kdf(&self) -> KdfParams {
        self.header.kdf
    }
    pub fn is_locked(&self) -> bool {
        matches!(self.state, State::Locked)
    }

    pub fn item_ids(&self) -> Vec<String> {
        self.header.index.iter().map(|e| e.id.clone()).collect()
    }

    pub fn has_item(&self, id: &str) -> bool {
        self.header.index.iter().any(|e| e.id == id)
    }

    /// Search by hashed attributes. Works while locked.
    pub fn search_ids(&self, query: &BTreeMap<String, String>) -> Vec<String> {
        self.header
            .index
            .iter()
            .filter(|e| e.matches(&self.header.salt, query))
            .map(|e| e.id.clone())
            .collect()
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<(), VaultError> {
        if !self.is_locked() {
            return Ok(());
        }
        let key = crypto::derive_key(password, &self.header.salt, self.header.kdf)?;
        let plain = crypto::open(&key, &self.header.nonce, &self.aad, &self.ciphertext)
            .map_err(|_| VaultError::WrongPassword)?;
        let items = format::decode_items(&plain)?;
        self.state = State::Unlocked { key, items };
        Ok(())
    }

    /// Check a password without changing lock state.
    pub fn verify_password(&self, password: &[u8]) -> Result<bool, VaultError> {
        let key = crypto::derive_key(password, &self.header.salt, self.header.kdf)?;
        match &self.state {
            State::Unlocked { key: current, .. } => {
                Ok(current.as_bytes()[..].ct_eq(&key.as_bytes()[..]).into())
            }
            State::Locked => {
                Ok(crypto::open(&key, &self.header.nonce, &self.aad, &self.ciphertext).is_ok())
            }
        }
    }

    pub fn lock(&mut self) {
        self.state = State::Locked;
    }

    pub fn items(&self) -> Result<&[Item], VaultError> {
        match &self.state {
            State::Unlocked { items, .. } => Ok(items),
            State::Locked => Err(VaultError::Locked),
        }
    }

    pub fn item(&self, id: &str) -> Result<&Item, VaultError> {
        self.items()?
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| VaultError::NoSuchItem(id.to_string()))
    }

    pub fn search(&self, query: &BTreeMap<String, String>) -> Result<Vec<&Item>, VaultError> {
        Ok(self
            .items()?
            .iter()
            .filter(|i| query.iter().all(|(k, v)| i.attributes.get(k) == Some(v)))
            .collect())
    }

    fn items_mut(&mut self) -> Result<&mut Vec<Item>, VaultError> {
        match &mut self.state {
            State::Unlocked { items, .. } => Ok(items),
            State::Locked => Err(VaultError::Locked),
        }
    }

    /// Insert an item. With `replace`, an item whose attributes are exactly
    /// equal is overwritten instead. Returns `(id, replaced)`.
    pub fn insert_item(
        &mut self,
        label: &str,
        attributes: BTreeMap<String, String>,
        secret: Vec<u8>,
        content_type: &str,
        replace: bool,
    ) -> Result<(String, bool), VaultError> {
        let t = now();
        let result = {
            let items = self.items_mut()?;
            let pos = if replace {
                items.iter().position(|i| i.attributes == attributes)
            } else {
                None
            };
            if let Some(p) = pos {
                let existing = &mut items[p];
                existing.label = label.to_string();
                existing.secret = Zeroizing::new(secret);
                existing.content_type = content_type.to_string();
                existing.modified = t;
                (existing.id.clone(), true)
            } else {
                let id = uuid::Uuid::new_v4().simple().to_string();
                items.push(Item {
                    id: id.clone(),
                    label: label.to_string(),
                    attributes,
                    secret: Zeroizing::new(secret),
                    content_type: content_type.to_string(),
                    created: t,
                    modified: t,
                });
                (id, false)
            }
        };
        self.save()?;
        Ok(result)
    }

    pub fn update_item(&mut self, id: &str, f: impl FnOnce(&mut Item)) -> Result<(), VaultError> {
        {
            let items = self.items_mut()?;
            let item = items
                .iter_mut()
                .find(|i| i.id == id)
                .ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            f(item);
            item.modified = now();
        }
        self.save()
    }

    pub fn delete_item(&mut self, id: &str) -> Result<(), VaultError> {
        {
            let items = self.items_mut()?;
            let pos = items
                .iter()
                .position(|i| i.id == id)
                .ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            items.remove(pos);
        }
        self.save()
    }

    pub fn set_label(&mut self, label: &str) -> Result<(), VaultError> {
        self.items_mut()?;
        self.header.label = label.to_string();
        self.save()
    }

    /// Re-encrypt under a new password with a fresh salt. Unlocks with `old` if locked.
    pub fn change_password(
        &mut self,
        old: &[u8],
        new: &[u8],
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        if self.is_locked() {
            self.unlock(old)?;
        } else if !self.verify_password(old)? {
            return Err(VaultError::WrongPassword);
        }
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_key(new, &salt, kdf)?;
        self.header.salt = salt;
        self.header.kdf = kdf;
        if let State::Unlocked { key: k, .. } = &mut self.state {
            *k = key;
        }
        self.save()
    }

    pub fn delete_file(self) -> Result<(), VaultError> {
        std::fs::remove_file(&self.path).map_err(|e| io_err(&self.path, e))?;
        let _ = std::fs::remove_file(self.path.with_extension("vault.tmp"));
        Ok(())
    }

    fn save(&mut self) -> Result<(), VaultError> {
        let State::Unlocked { key, items } = &self.state else {
            return Err(VaultError::Locked);
        };
        self.header.modified = now();
        self.header.nonce = crypto::random_bytes::<NONCE_LEN>();
        self.header.index = format::build_index(&self.header.salt, items);
        let aad = VaultFile::header_bytes(&self.header)?;
        let plain = format::encode_items(items)?;
        let ciphertext = crypto::seal(key, &self.header.nonce, &aad, &plain)?;
        let mut bytes = aad.clone();
        bytes.extend_from_slice(&ciphertext);
        write_atomic(&self.path, &bytes)?;
        self.aad = aad;
        self.ciphertext = ciphertext;
        Ok(())
    }
}

/// Write to `<path>.tmp`, fsync, rename over `path`, fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let tmp = path.with_extension("vault.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_err(&tmp, e))?;
    f.write_all(bytes).map_err(|e| io_err(&tmp, e))?;
    f.sync_all().map_err(|e| io_err(&tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::KdfParams;
    use std::os::unix::fs::PermissionsExt;

    const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.vault");
        (dir, path)
    }

    #[test]
    fn create_writes_private_file_and_is_unlocked() {
        let (_d, path) = tmp();
        let v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        assert!(!v.is_locked());
        assert_eq!(v.label(), "Default");
        assert!(v.items().unwrap().is_empty());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!path.with_extension("vault.tmp").exists());
        assert!(matches!(
            Vault::create(&path, "x", b"pw", FAST),
            Err(VaultError::AlreadyExists(_))
        ));
    }

    #[test]
    fn open_is_locked_until_correct_password() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        assert!(v.is_locked());
        assert!(matches!(v.items(), Err(VaultError::Locked)));
        assert!(matches!(v.unlock(b"nope"), Err(VaultError::WrongPassword)));
        v.unlock(b"pw").unwrap();
        assert!(!v.is_locked());
        assert!(v.verify_password(b"pw").unwrap());
        assert!(!v.verify_password(b"nope").unwrap());
        v.lock();
        assert!(v.is_locked());
    }

    #[test]
    fn items_persist_and_index_search_works_locked() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let (id_a, replaced) = v
            .insert_item(
                "git",
                attrs(&[("app", "git"), ("user", "joe")]),
                b"tok".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        assert!(!replaced);
        let (id_b, _) = v
            .insert_item(
                "other",
                attrs(&[("app", "git")]),
                b"x".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        assert_ne!(id_a, id_b);
        assert!(id_a.chars().all(|c| c.is_ascii_alphanumeric()));

        let mut v = Vault::open(&path).unwrap();
        assert_eq!(v.item_ids().len(), 2);
        assert_eq!(v.search_ids(&attrs(&[("user", "joe")])), vec![id_a.clone()]);
        assert_eq!(v.search_ids(&attrs(&[("app", "git")])).len(), 2);
        v.unlock(b"pw").unwrap();
        assert_eq!(v.item(&id_a).unwrap().secret.as_slice(), b"tok");
        assert_eq!(v.search(&attrs(&[("app", "git")])).unwrap().len(), 2);
    }

    #[test]
    fn replace_update_delete() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let (id, _) = v
            .insert_item(
                "git",
                attrs(&[("app", "git")]),
                b"one".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        let (id2, replaced) = v
            .insert_item(
                "git2",
                attrs(&[("app", "git")]),
                b"two".to_vec(),
                "text/plain",
                true,
            )
            .unwrap();
        assert!(replaced);
        assert_eq!(id, id2);
        assert_eq!(v.items().unwrap().len(), 1);
        assert_eq!(v.item(&id).unwrap().secret.as_slice(), b"two");
        assert_eq!(v.item(&id).unwrap().label, "git2");

        v.update_item(&id, |i| i.label = "renamed".into()).unwrap();
        assert_eq!(Vault::open(&path).unwrap().item_ids(), vec![id.clone()]);
        v.delete_item(&id).unwrap();
        assert!(matches!(v.delete_item(&id), Err(VaultError::NoSuchItem(_))));
        assert!(Vault::open(&path).unwrap().item_ids().is_empty());
    }

    #[test]
    fn change_password_rotates_salt() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();
        v.insert_item(
            "x",
            attrs(&[("a", "b")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let salt_before = v.header.salt;
        v.change_password(b"old", b"new", FAST).unwrap();
        assert_ne!(v.header.salt, salt_before);
        let mut v = Vault::open(&path).unwrap();
        assert!(matches!(v.unlock(b"old"), Err(VaultError::WrongPassword)));
        v.unlock(b"new").unwrap();
        assert_eq!(v.items().unwrap()[0].secret.as_slice(), b"s");
        assert!(matches!(
            v.change_password(b"wrong", b"x", FAST),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn tampered_header_fails_to_unlock() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let file = crate::vault::format::VaultFile::decode(&bytes).unwrap();
        let mut header = file.header.clone();
        header.label = "evil".into();
        let forged = crate::vault::format::VaultFile::new(header, file.ciphertext).unwrap();
        std::fs::write(&path, forged.encode()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        assert_eq!(v.label(), "evil");
        assert!(matches!(v.unlock(b"pw"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn set_label_and_delete_file() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.set_label("Renamed").unwrap();
        assert_eq!(Vault::open(&path).unwrap().label(), "Renamed");
        v.delete_file().unwrap();
        assert!(!path.exists());
    }
}
