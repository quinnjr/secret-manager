//! A collection on disk: load, unlock, edit, save atomically.

pub use super::crypto::KEY_LEN;
use super::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};
use super::format::{self, FormatError, Header, Item, VERSION, VaultFile};
use super::now;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
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
    #[error("the new salt must differ from the current one")]
    SaltReused,
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
    /// Whether saves hash attributes into the header index (searchable while
    /// locked) or store item ids only. See `format::build_index`.
    index_attributes: bool,
    /// Set when the on-disk index could not be brought in line with
    /// `index_attributes`, so the condition is reportable rather than only
    /// logged once. Cleared by a successful rescrub.
    index_warning: Option<String>,
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
        // Reserve the name *before* deriving the key. A plain `exists()`
        // check is separated from the rename that publishes the file by
        // 100-500 ms of Argon2, so two concurrent `sm init work` runs both
        // pass it, both derive, and the loser's collection is silently
        // replaced by the winner's empty one. `O_EXCL` makes the first
        // publish exclusive; `write_atomic`'s rename then legitimately
        // replaces our own reservation.
        ensure_vault_dir(path.parent().unwrap_or_else(|| Path::new(".")))?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(VaultError::AlreadyExists(path.to_path_buf()));
            }
            Err(e) => return Err(io_err(path, e)),
        }
        let created = Self::fill_reservation(path, label, password, kdf);
        if created.is_err() {
            // Never leave an empty reservation standing in for a vault:
            // it would fail to decode and block every later create.
            let _ = std::fs::remove_file(path);
        }
        created
    }

    /// The body of [`Vault::create`], run with `path` already reserved.
    fn fill_reservation(
        path: &Path,
        label: &str,
        password: &[u8],
        kdf: KdfParams,
    ) -> Result<Vault, VaultError> {
        let salt = crypto::try_random_bytes::<SALT_LEN>()?;
        let index_salt = crypto::try_random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key(password, &salt, kdf)?;
        let t = now();
        let header = Header {
            version: VERSION,
            label: label.to_string(),
            created: t,
            modified: t,
            kdf,
            salt,
            index_salt,
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
            index_attributes: true,
            index_warning: None,
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        // Bound the read before making it: `MAX_HEADER` caps the header but
        // not the ciphertext, so an oversized file in the vault directory
        // would otherwise be slurped whole and take the daemon down during
        // `load_vaults`.
        let meta = std::fs::metadata(path).map_err(|e| io_err(path, e))?;
        format::check_vault_size(meta.len())?;
        let bytes = std::fs::read(path).map_err(|e| io_err(path, e))?;
        let file = VaultFile::decode(&bytes)?;
        Ok(Vault {
            path: path.to_path_buf(),
            header: file.header,
            aad: file.aad,
            ciphertext: file.ciphertext,
            state: State::Locked,
            index_attributes: true,
            index_warning: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.header.salt
    }
    pub fn index_salt(&self) -> &[u8; SALT_LEN] {
        &self.header.index_salt
    }
    /// Choose whether future saves hash attributes into the header index.
    /// Takes effect on the next save; call `resave` to apply immediately.
    pub fn set_index_attributes(&mut self, enabled: bool) {
        self.index_attributes = enabled;
    }
    /// True when the on-disk index carries attribute hashes for any item.
    pub fn index_has_attributes(&self) -> bool {
        self.header.index.iter().any(|e| !e.attr_hashes.is_empty())
    }

    /// Why the header index does not match `index_attributes`, if it does
    /// not. Reported through `sm status` so a failed rescrub is visible.
    pub fn index_warning(&self) -> Option<&str> {
        self.index_warning.as_deref()
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
            .filter(|e| e.matches(&self.header.index_salt, query))
            .map(|e| e.id.clone())
            .collect()
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<(), VaultError> {
        let key = crypto::derive_key(password, &self.header.salt, self.header.kdf)?;
        self.unlock_with_key(&key)
    }

    /// Unlock with an already-derived key (`derive_key(password, salt(), kdf())`),
    /// so callers can run Argon2 outside any lock, or on another host of the
    /// password entirely (the PAM module). Verifies the key even when the vault
    /// is already unlocked.
    pub fn unlock_with_key(&mut self, key: &Key) -> Result<(), VaultError> {
        if !self.is_locked() {
            return if self.verify_key(key)? {
                Ok(())
            } else {
                Err(VaultError::WrongPassword)
            };
        }
        let plain = match crypto::open(key, &self.header.nonce, &self.aad, &self.ciphertext) {
            Ok(plain) => plain,
            Err(_) => {
                self.warn_aead_failure("unlock");
                return Err(VaultError::WrongPassword);
            }
        };
        let items = format::decode_items(&plain)?;
        self.state = State::Unlocked {
            key: key.clone(),
            items,
        };
        // First chance to bring the on-disk index in line with the current
        // `index_attributes` policy (a header written under the other setting
        // keeps its old shape until it is re-sealed here). Compare against
        // what the policy would actually produce: items with no attributes
        // hash to nothing under either setting, so a collection of those must
        // not be re-sealed on every unlock.
        let wants_attributes = self.index_attributes
            && self
                .items()
                .map(|items| items.iter().any(|i| !i.attributes.is_empty()))
                .unwrap_or(false);
        if self.index_has_attributes() != wants_attributes {
            match self.save() {
                Ok(()) => self.index_warning = None,
                Err(e) => {
                    let msg = format!("cannot rewrite the attribute index: {e}");
                    tracing::error!("{}: {msg}", self.path.display());
                    self.index_warning = Some(msg);
                }
            }
        } else {
            self.index_warning = None;
        }
        Ok(())
    }

    /// Check a password without changing lock state.
    pub fn verify_password(&self, password: &[u8]) -> Result<bool, VaultError> {
        let key = crypto::derive_key(password, &self.header.salt, self.header.kdf)?;
        self.verify_key(&key)
    }

    /// Check a derived key without changing lock state.
    pub fn verify_key(&self, key: &Key) -> Result<bool, VaultError> {
        match &self.state {
            State::Unlocked { key: current, .. } => {
                Ok(current.as_bytes()[..].ct_eq(&key.as_bytes()[..]).into())
            }
            State::Locked => {
                let ok = crypto::open(key, &self.header.nonce, &self.aad, &self.ciphertext).is_ok();
                if !ok {
                    self.warn_aead_failure("verify");
                }
                Ok(ok)
            }
        }
    }

    /// Record an AEAD failure with enough detail to tell the two causes
    /// apart by hand.
    ///
    /// A wrong password and a flipped ciphertext byte are cryptographically
    /// indistinguishable, and the returned error stays `WrongPassword` so no
    /// oracle is added; but a caller that keeps failing on a file whose size
    /// or mtime is not what the operator expects is looking at damage, not a
    /// forgotten password, and PAM in particular reports nothing at all.
    fn warn_aead_failure(&self, op: &str) {
        let (size, modified) = match std::fs::metadata(&self.path) {
            Ok(m) => (
                Some(m.len()),
                m.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            ),
            Err(_) => (None, None),
        };
        tracing::warn!(
            path = %self.path.display(),
            size = ?size,
            modified = ?modified,
            "{op}: vault authentication failed - wrong password, or the file is damaged"
        );
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

    /// Persist, restoring `before` through `restore` if the write fails, so
    /// a failed save never leaves memory describing something the disk does
    /// not. Every item-mutating method funnels through here.
    fn save_or_restore<T>(
        &mut self,
        before: T,
        restore: impl FnOnce(&mut Self, T),
    ) -> Result<(), VaultError> {
        match self.save() {
            Ok(()) => Ok(()),
            Err(e) => {
                restore(self, before);
                Err(e)
            }
        }
    }

    fn restore_items(&mut self, items: Vec<Item>) {
        if let State::Unlocked { items: cur, .. } = &mut self.state {
            *cur = items;
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
        let items_before = self.items()?.to_vec();
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
        self.save_or_restore(items_before, Self::restore_items)?;
        Ok(result)
    }

    pub fn update_item(&mut self, id: &str, f: impl FnOnce(&mut Item)) -> Result<(), VaultError> {
        let items_before = self.items()?.to_vec();
        {
            let items = self.items_mut()?;
            let item = items
                .iter_mut()
                .find(|i| i.id == id)
                .ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            f(item);
            item.modified = now();
        }
        self.save_or_restore(items_before, Self::restore_items)
    }

    /// Test-only hook: force an item's `modified` timestamp to an exact
    /// value and persist it, without the `now()` overwrite that
    /// `update_item` applies. Used to make ordering-sensitive tests
    /// (e.g. "most recent item wins") deterministic without sleeping
    /// across the timestamp's clock granularity.
    #[cfg(feature = "test-util")]
    pub fn set_modified_for_tests(&mut self, id: &str, ts: u64) -> Result<(), VaultError> {
        let items_before = self.items()?.to_vec();
        {
            let items = self.items_mut()?;
            let item = items
                .iter_mut()
                .find(|i| i.id == id)
                .ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            item.modified = ts;
        }
        self.save_or_restore(items_before, Self::restore_items)
    }

    pub fn delete_item(&mut self, id: &str) -> Result<(), VaultError> {
        let items_before = self.items()?.to_vec();
        {
            let items = self.items_mut()?;
            let pos = items
                .iter()
                .position(|i| i.id == id)
                .ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            items.remove(pos);
        }
        self.save_or_restore(items_before, Self::restore_items)
    }

    pub fn set_label(&mut self, label: &str) -> Result<(), VaultError> {
        self.items_mut()?;
        let old_label = self.header.label.clone();
        self.header.label = label.to_string();
        self.save_or_restore(old_label, |v, old| v.header.label = old)
    }

    /// Re-encrypt under a new password with a fresh salt. A vault that was
    /// locked on entry is locked again afterwards.
    pub fn change_password(
        &mut self,
        old: &[u8],
        new: &[u8],
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        let old_key = crypto::derive_key(old, &self.header.salt, self.header.kdf)?;
        let new_salt = crypto::try_random_bytes::<SALT_LEN>()?;
        let new_key = crypto::derive_key(new, &new_salt, kdf)?;
        self.change_key(&old_key, &new_salt, kdf, &new_key)
    }

    /// Key-level rotation: `old_key` must open the vault; the items are then
    /// re-sealed under `new_key`, whose salt and parameters are recorded in
    /// the header. Lock state on exit equals lock state on entry.
    ///
    /// `new_key` **must** be `derive_key(new_password, new_salt, new_kdf)`.
    /// Nothing here can check that - the key is opaque and the salt is only
    /// an input to a KDF this function never runs - and a mismatch writes a
    /// header whose recorded salt derives some other key, producing a vault
    /// that no password opens. `new_salt` must also differ from the salt
    /// currently in the header, so a rotation always moves the KDF's input.
    pub fn change_key(
        &mut self,
        old_key: &Key,
        new_salt: &[u8; SALT_LEN],
        new_kdf: KdfParams,
        new_key: &Key,
    ) -> Result<(), VaultError> {
        new_kdf.validate()?;
        // The salt is public (it sits unauthenticated in the header), so
        // rejecting a reused one leaks nothing and catches a caller that
        // rotated the password but not the salt.
        if new_salt == &self.header.salt {
            return Err(VaultError::SaltReused);
        }
        // The attribute index is keyed by its own salt, so leaving it in
        // place would keep every index hash byte-identical across a password
        // change: dictionary work done against a pre-rotation copy of the
        // file would still apply to the new one. Drawn before anything is
        // mutated so an unavailable RNG needs no rollback.
        let new_index_salt = crypto::try_random_bytes::<SALT_LEN>()?;
        let was_locked = self.is_locked();
        if was_locked {
            self.unlock_with_key(old_key)?;
        } else if !self.verify_key(old_key)? {
            return Err(VaultError::WrongPassword);
        }
        let old_salt = self.header.salt;
        let old_kdf = self.header.kdf;
        let old_index_salt = self.header.index_salt;
        self.header.salt = *new_salt;
        self.header.kdf = new_kdf;
        // `save` rebuilds the index from `header.index_salt`, so the rehash
        // happens as part of the write below.
        self.header.index_salt = new_index_salt;
        if let State::Unlocked { key: k, .. } = &mut self.state {
            *k = new_key.clone();
        }
        let result = self.save();
        if result.is_err() {
            self.header.salt = old_salt;
            self.header.kdf = old_kdf;
            self.header.index_salt = old_index_salt;
            if let State::Unlocked { key: k, .. } = &mut self.state {
                *k = old_key.clone();
            }
        }
        if was_locked {
            self.lock();
        }
        result
    }

    pub fn delete_file(self) -> Result<(), VaultError> {
        std::fs::remove_file(&self.path).map_err(|e| io_err(&self.path, e))?;
        if let Some(dir) = self.path.parent() {
            sweep_stale_temp_files(dir);
        }
        Ok(())
    }

    fn save(&mut self) -> Result<(), VaultError> {
        let State::Unlocked { key, items } = &self.state else {
            return Err(VaultError::Locked);
        };
        // Snapshot so that any failure below leaves `header` consistent with
        // the still-valid `aad`/`ciphertext` pair; otherwise a failed write
        // would carry a fresh nonce/index while the on-disk ciphertext (and
        // our cached `aad`/`ciphertext`) still describe the old one, and a
        // later lock()+unlock() would fail decryption permanently.
        // Fallibly, and before any mutation: `save` runs while the daemon
        // holds its state mutex, where a panic on an unavailable RNG would
        // poison it for every other caller.
        let nonce = crypto::try_random_bytes::<NONCE_LEN>()?;
        let saved_header = self.header.clone();
        self.header.modified = now();
        self.header.nonce = nonce;
        self.header.index =
            format::build_index(&self.header.index_salt, items, self.index_attributes);
        let aad = match VaultFile::header_bytes(&self.header) {
            Ok(aad) => aad,
            Err(e) => {
                self.header = saved_header;
                return Err(e.into());
            }
        };
        let plain = match format::encode_items(items) {
            Ok(plain) => plain,
            Err(e) => {
                self.header = saved_header;
                return Err(e.into());
            }
        };
        let ciphertext = match crypto::seal(key, &self.header.nonce, &aad, &plain) {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                self.header = saved_header;
                return Err(e.into());
            }
        };
        let mut bytes = aad.clone();
        bytes.extend_from_slice(&ciphertext);
        if let Err(e) = write_atomic(&self.path, &bytes) {
            self.header = saved_header;
            return Err(e);
        }
        self.aad = aad;
        self.ciphertext = ciphertext;
        Ok(())
    }
}

/// How long a temp file must have gone untouched before the sweep treats it
/// as abandoned. Long enough that no live `write_atomic` can be caught by
/// it: the whole write is a `write_all`, an `fsync` and a `rename`.
pub const STALE_TEMP_AGE: Duration = Duration::from_secs(5 * 60);

/// True for a name `write_atomic` could actually have produced:
/// `<file name>.<16 lowercase hex digits>.tmp`.
///
/// The shape check is the whole point. Matching on "contains `.vault.` and
/// ends with `.tmp`" also matches a user's own `backup.vault.2026-09.tmp`,
/// and the sweep deletes unconditionally.
fn is_write_atomic_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_suffix(".tmp") else {
        return false;
    };
    let Some((stem, hex)) = rest.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty() && hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Remove `<name>.<16 hex>.tmp` files left behind by a save that was
/// interrupted between `create_new` and `rename` (a crash or power loss).
/// The names are random, so nothing would otherwise reuse or clean them and
/// each interrupted save would leave another encrypted copy behind forever.
/// Returns how many were removed.
///
/// Only entries matching the exact temp-name shape and untouched for
/// [`STALE_TEMP_AGE`] are removed: this runs at daemon start and on every
/// `delete_file`, concurrently with saves in other processes, and unlinking
/// a live temp file mid-write makes that save's rename fail with ENOENT.
pub fn sweep_stale_temp_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_write_atomic_temp_name(name) {
            continue;
        }
        // `metadata` on the DirEntry does not follow symlinks, so a planted
        // link is skipped by the `is_file` check rather than chased.
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        // A future mtime yields Err here and is treated as "not yet stale".
        let stale = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= STALE_TEMP_AGE);
        if stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Create the vault directory private from the start.
///
/// `create_dir_all` uses 0777 & ~umask (typically 0755) and only then gets
/// chmodded, so another uid winning that window can open a descriptor and go
/// on listing collection names afterwards. The `set_permissions` below stays
/// as the repair path for a directory that already existed with looser bits.
fn ensure_vault_dir(dir: &Path) -> Result<(), VaultError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| io_err(dir, e))?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

/// Write to a fresh `<path>.<random>.tmp` (`O_CREAT|O_EXCL`, so a planted
/// file or symlink at a guessable name is never followed), fsync, rename over
/// `path`, fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_vault_dir(dir)?;
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".into());
    let suffix: [u8; 8] = crypto::try_random_bytes()?;
    let tmp = dir.join(format!(
        "{stem}.{}.tmp",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_err(&tmp, e))?;
    let written = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| io_err(&tmp, e));
    drop(f);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(path, e));
    }
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

    /// Make the next save fail deterministically: replace the vault file
    /// with a directory so the final `rename` cannot succeed. `write_atomic`
    /// chmods the directory and picks a random temp name, so neither
    /// permissions nor a planted temp path can force the failure.
    struct WriteBlock {
        path: PathBuf,
        saved: Vec<u8>,
    }

    fn block_writes(path: &Path) -> WriteBlock {
        let saved = std::fs::read(path).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::create_dir(path).unwrap();
        WriteBlock {
            path: path.to_path_buf(),
            saved,
        }
    }

    fn unblock(b: WriteBlock) {
        std::fs::remove_dir(&b.path).unwrap();
        std::fs::write(&b.path, b.saved).unwrap();
    }

    /// Move a file's mtime into the past so the age check in
    /// `sweep_stale_temp_files` sees it as abandoned.
    fn backdate(path: &Path, ago: Duration) {
        let f = File::options().write(true).open(path).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() - ago))
            .unwrap();
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

    /// A failed write must not leave the header describing a nonce/index
    /// that doesn't match the still-on-disk (and still-cached) ciphertext.
    /// Otherwise the vault becomes permanently un-unlockable: lock() then
    /// unlock(correct password) would fail crypto::open and report
    /// WrongPassword until the process restarts and re-reads the file.
    #[test]
    fn failed_save_does_not_corrupt_header() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item(
            "first",
            attrs(&[("a", "1")]),
            b"secret-1".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let items_before: Vec<_> = v
            .items()
            .unwrap()
            .iter()
            .map(|i| (i.id.clone(), i.secret.to_vec()))
            .collect();

        let block = block_writes(&path);

        let result = v.insert_item(
            "second",
            attrs(&[("a", "2")]),
            b"secret-2".to_vec(),
            "text/plain",
            false,
        );
        assert!(result.is_err(), "expected write_atomic to fail");

        unblock(block);

        v.lock();
        v.unlock(b"pw").unwrap();
        let items_after: Vec<_> = v
            .items()
            .unwrap()
            .iter()
            .map(|i| (i.id.clone(), i.secret.to_vec()))
            .collect();
        assert_eq!(items_after, items_before);
    }

    /// A failed `change_password` must leave the header salt/kdf *and* the
    /// in-memory key consistent with each other and with the old password;
    /// otherwise `verify_password` disagrees with both passwords and the
    /// next successful save seals with the new key under the old salt,
    /// producing a file no password can open.
    #[test]
    fn failed_change_password_keeps_old_password_working() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();

        let block = block_writes(&path);

        let result = v.change_password(b"old", b"new", FAST);
        assert!(result.is_err(), "expected write_atomic to fail");

        assert!(v.verify_password(b"old").unwrap());
        assert!(!v.verify_password(b"new").unwrap());

        unblock(block);

        v.insert_item(
            "x",
            attrs(&[("a", "b")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        v.lock();
        v.unlock(b"old").unwrap();

        let mut v2 = Vault::open(&path).unwrap();
        assert!(matches!(v2.unlock(b"new"), Err(VaultError::WrongPassword)));
    }

    /// A `change_password` that fails on a vault that was locked at entry
    /// (unlocked internally via `old` to perform the rotation) must leave
    /// the vault locked again, not unlocked with the rolled-back key.
    #[test]
    fn failed_change_password_on_locked_vault_stays_locked() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();
        v.lock();
        assert!(v.is_locked());

        let block = block_writes(&path);

        let result = v.change_password(b"old", b"new", FAST);
        assert!(result.is_err(), "expected write_atomic to fail");
        assert!(
            v.is_locked(),
            "vault should be re-locked after failed change_password"
        );

        unblock(block);
        v.unlock(b"old").unwrap();
    }

    /// A failed `insert_item` must not leave the in-memory item list
    /// mutated relative to what was actually persisted.
    #[test]
    fn failed_save_restores_items() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let (id, _) = v
            .insert_item(
                "first",
                attrs(&[("a", "1")]),
                b"secret-1".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        let items_before = v.items().unwrap().to_vec();
        let ids_before = v.item_ids();

        let block = block_writes(&path);

        let result = v.insert_item(
            "second",
            attrs(&[("a", "2")]),
            b"secret-2".to_vec(),
            "text/plain",
            false,
        );
        assert!(result.is_err(), "expected write_atomic to fail");

        let items_after: Vec<_> = v
            .items()
            .unwrap()
            .iter()
            .map(|i| (i.id.clone(), i.secret.to_vec()))
            .collect();
        let items_before_cmp: Vec<_> = items_before
            .iter()
            .map(|i| (i.id.clone(), i.secret.to_vec()))
            .collect();
        assert_eq!(items_after, items_before_cmp);
        assert_eq!(v.item_ids(), ids_before);

        unblock(block);

        let (id2, _) = v
            .insert_item(
                "second",
                attrs(&[("a", "2")]),
                b"secret-2".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        assert_ne!(id, id2);
        assert_eq!(v.items().unwrap().len(), 2);
    }

    /// The attribute index is hashed with its own random salt, not the
    /// Argon2 salt, so one value never serves two purposes.
    #[test]
    fn create_uses_an_index_salt_independent_of_the_kdf_salt() {
        let (_d, path) = tmp();
        let v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        assert_ne!(v.salt(), v.index_salt());
        let (_d2, path2) = tmp();
        let v2 = Vault::create(&path2, "Default", b"pw", FAST).unwrap();
        assert_ne!(v.index_salt(), v2.index_salt());
    }

    /// With attribute indexing off the header carries item ids only, so a
    /// file holder cannot dictionary-attack attributes and a locked search
    /// matches nothing.
    #[test]
    fn disabling_attribute_index_hides_attributes_from_the_header() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.set_index_attributes(false);
        let (id, _) = v
            .insert_item(
                "git",
                attrs(&[("app", "git")]),
                b"tok".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        let locked = Vault::open(&path).unwrap();
        assert_eq!(locked.item_ids(), vec![id.clone()]);
        assert!(locked.search_ids(&attrs(&[("app", "git")])).is_empty());
        assert!(!locked.index_has_attributes());
        let bytes = std::fs::read(&path).unwrap();
        let file = crate::vault::format::VaultFile::decode(&bytes).unwrap();
        assert!(file.header.index.iter().all(|e| e.attr_hashes.is_empty()));
        // Unlocked search still works from the plaintext items.
        let mut v = Vault::open(&path).unwrap();
        v.unlock(b"pw").unwrap();
        assert_eq!(v.search(&attrs(&[("app", "git")])).unwrap().len(), 1);
    }

    /// A collection whose items carry no attributes produces an index with
    /// no hashes under either policy, so it must not be re-sealed on every
    /// single unlock (an unbounded write amplification on the hot path).
    #[test]
    fn unlock_does_not_rewrite_an_index_that_already_matches_policy() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item("x", BTreeMap::new(), b"s".to_vec(), "text/plain", false)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        for _ in 0..3 {
            let mut v = Vault::open(&path).unwrap();
            v.unlock(b"pw").unwrap();
            assert!(v.index_warning().is_none());
        }
        assert_eq!(std::fs::read(&path).unwrap(), before, "vault re-sealed");
    }

    /// A rescrub that cannot be written must be visible, not just logged:
    /// otherwise `locked_search = false` can silently never take effect.
    #[test]
    fn failed_index_rescrub_is_reported_as_a_warning() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item(
            "x",
            attrs(&[("a", "b")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();

        let mut v = Vault::open(&path).unwrap();
        v.set_index_attributes(false);
        let block = block_writes(&path);
        v.unlock(b"pw").unwrap();
        let warning = v.index_warning().expect("a failed rescrub must warn");
        assert!(warning.contains("attribute index"), "{warning}");
        unblock(block);

        // Once writable again, the next unlock completes the rescrub and
        // clears the warning.
        let mut v = Vault::open(&path).unwrap();
        v.set_index_attributes(false);
        v.unlock(b"pw").unwrap();
        assert!(v.index_warning().is_none());
        assert!(!Vault::open(&path).unwrap().index_has_attributes());
    }

    /// A crash between `create_new` and `rename` leaves a temp file behind.
    /// Because the name is random, nothing would ever reuse or remove it, so
    /// stale encrypted copies would accumulate for the life of the vault.
    #[test]
    fn stale_temp_files_are_swept() {
        let (d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let stale = d.path().join("default.vault.0011223344556677.tmp");
        std::fs::write(&stale, b"leftover").unwrap();
        backdate(&stale, STALE_TEMP_AGE * 2);
        let unrelated = d.path().join("notes.txt");
        std::fs::write(&unrelated, b"keep").unwrap();
        let removed = sweep_stale_temp_files(d.path());
        assert_eq!(removed, 1);
        assert!(!stale.exists());
        assert!(unrelated.exists());
        assert!(path.exists());
    }

    /// A vault written with attribute hashes, later loaded under
    /// `locked_search = false`, scrubs the hashes from disk on its first
    /// unlock (the earliest moment it has the key to re-seal).
    #[test]
    fn unlock_rescrubs_the_index_when_policy_changed() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item(
            "x",
            attrs(&[("a", "b")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        assert!(Vault::open(&path).unwrap().index_has_attributes());
        let mut v = Vault::open(&path).unwrap();
        v.set_index_attributes(false);
        v.unlock(b"pw").unwrap();
        assert!(!v.index_has_attributes());
        assert!(!Vault::open(&path).unwrap().index_has_attributes());
        // And back again.
        let mut v = Vault::open(&path).unwrap();
        v.set_index_attributes(true);
        v.unlock(b"pw").unwrap();
        assert!(Vault::open(&path).unwrap().index_has_attributes());
    }

    /// `change_password` on a locked vault must not leave it unlocked.
    #[test]
    fn change_password_relocks_a_vault_that_was_locked() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();
        v.lock();
        v.change_password(b"old", b"new", FAST).unwrap();
        assert!(v.is_locked());
        v.unlock(b"new").unwrap();
    }

    /// The temp file must never be a pre-existing path (symlink or not).
    #[test]
    fn save_never_writes_through_a_planted_tmp_symlink() {
        let (d, path) = tmp();
        let victim = d.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("vault.tmp")).unwrap();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item(
            "x",
            attrs(&[("a", "b")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(path.exists());
        let leftovers: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp") && n != "default.vault.tmp")
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }

    /// Key-based unlock: a caller that already derived the key (the PAM
    /// module) never needs to send the password.
    #[test]
    fn unlock_and_verify_with_a_derived_key() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        let key = crypto::derive_key(b"pw", v.salt(), v.kdf()).unwrap();
        let wrong = crypto::derive_key(b"nope", v.salt(), v.kdf()).unwrap();
        assert!(matches!(
            v.unlock_with_key(&wrong),
            Err(VaultError::WrongPassword)
        ));
        assert!(v.is_locked());
        v.unlock_with_key(&key).unwrap();
        assert!(!v.is_locked());
        assert!(v.verify_key(&key).unwrap());
        assert!(!v.verify_key(&wrong).unwrap());
    }

    #[test]
    fn change_key_rotates_salt_and_relocks() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"old", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        let old_key = crypto::derive_key(b"old", v.salt(), v.kdf()).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>();
        let new_key = crypto::derive_key(b"new", &new_salt, FAST).unwrap();
        let wrong = crypto::derive_key(b"wrong", v.salt(), v.kdf()).unwrap();
        assert!(matches!(
            v.change_key(&wrong, &new_salt, FAST, &new_key),
            Err(VaultError::WrongPassword)
        ));
        v.change_key(&old_key, &new_salt, FAST, &new_key).unwrap();
        assert!(v.is_locked(), "was locked on entry, must stay locked");
        assert_eq!(v.salt(), &new_salt);
        let mut again = Vault::open(&path).unwrap();
        assert!(matches!(
            again.unlock(b"old"),
            Err(VaultError::WrongPassword)
        ));
        again.unlock(b"new").unwrap();
    }

    /// `unlock` on an already-unlocked vault must still verify the
    /// password, rather than unconditionally returning `Ok`.
    #[test]
    fn unlock_when_already_unlocked_still_checks_password() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        assert!(!v.is_locked());
        assert!(matches!(v.unlock(b"nope"), Err(VaultError::WrongPassword)));
        assert!(!v.is_locked());
        v.unlock(b"pw").unwrap();
        assert!(!v.is_locked());
    }

    /// `create` must reserve its name before the 100-500 ms key derivation.
    /// A second create racing the first sees the reservation - an existing
    /// but not yet written file - and must lose there, rather than deriving
    /// its own key and having `write_atomic` rename over the winner.
    #[test]
    fn create_loses_against_a_reserved_but_unwritten_path() {
        let (_d, path) = tmp();
        // Exactly what the losing racer sees: the winner's empty O_EXCL
        // reservation, before its `save` has published anything.
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(
            Vault::create(&path, "x", b"pw", FAST),
            Err(VaultError::AlreadyExists(_))
        ));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"",
            "reservation overwritten"
        );
    }

    /// The defect this guards against is not the existence check itself but
    /// the 100-500 ms of Argon2 between it and the rename that publishes the
    /// file. Two `sm init work` runs both pass the check, both derive, and
    /// `write_atomic` renames unconditionally, so the loser's collection is
    /// replaced by an empty one with no error on either side.
    ///
    /// Both racers are released from a barrier and use a KDF slow enough
    /// that neither can finish deriving before the other has checked, so an
    /// existence check placed before the derivation lets both through.
    /// Exactly one must win.
    #[test]
    fn concurrent_creates_produce_exactly_one_winner() {
        let (_d, path) = tmp();
        // ~30-60 ms per derivation: far longer than the gap between the two
        // threads reaching the check, and short enough for a unit test.
        const SLOW: KdfParams = KdfParams {
            m_cost_kib: 16 * 1024,
            t_cost: 3,
            p_cost: 1,
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let results: Vec<_> = ["one", "two"]
            .into_iter()
            .map(|label| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    Vault::create(&path, label, b"pw", SLOW).map(|v| v.label().to_string())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        let winners: Vec<&String> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(
            winners.len(),
            1,
            "both creates succeeded; one collection was silently destroyed: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| matches!(r, Err(VaultError::AlreadyExists(_)))),
            "{results:?}"
        );
        // The file on disk is the winner's, not an empty overwrite.
        let mut v = Vault::open(&path).unwrap();
        assert_eq!(&v.label(), winners[0]);
        v.unlock(b"pw").unwrap();
    }

    /// A create that fails after reserving must not leave the empty
    /// reservation behind: it decodes as nothing and would block every
    /// later create of that collection forever.
    #[test]
    fn failed_create_removes_its_reservation() {
        let (_d, path) = tmp();
        let bad = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(Vault::create(&path, "x", b"pw", bad).is_err());
        assert!(!path.exists(), "failed create left its reservation behind");
        // And the name is usable again.
        Vault::create(&path, "x", b"pw", FAST).unwrap();
        assert_eq!(Vault::open(&path).unwrap().label(), "x");
    }

    /// A header past `MAX_HEADER` is refused on the way out, not written and
    /// then found unreadable: `decode` would reject it, and the rename has
    /// already replaced the last good file by then.
    #[test]
    fn save_refuses_an_oversized_header_and_keeps_the_old_file() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = v
            .set_label(&"x".repeat(format::MAX_HEADER + 1))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::Format(FormatError::HeaderTooLarge(_))),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "old file replaced");
        assert_eq!(v.label(), "Default", "label not rolled back");
        // The rollback left header, aad and ciphertext consistent, so the
        // vault still opens.
        v.lock();
        v.unlock(b"pw").unwrap();
        assert_eq!(Vault::open(&path).unwrap().label(), "Default");
    }

    /// The ciphertext is unbounded on disk, so `open` must bound the read
    /// from the file's size rather than slurping whatever is there.
    #[test]
    fn open_refuses_a_file_over_the_size_limit() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        // Sparse: no data is written, only the size is set.
        let f = File::options().write(true).open(&path).unwrap();
        f.set_len(format::MAX_VAULT_BYTES + 1).unwrap();
        drop(f);
        let err = Vault::open(&path).unwrap_err();
        assert!(
            matches!(err, VaultError::Format(FormatError::VaultTooLarge(_))),
            "{err:?}"
        );
        // At the limit it is still read (and then rejected as truncated
        // garbage, not refused for size).
        let f = File::options().write(true).open(&path).unwrap();
        f.set_len(format::MAX_VAULT_BYTES).unwrap();
        drop(f);
        assert!(!matches!(
            Vault::open(&path),
            Err(VaultError::Format(FormatError::VaultTooLarge(_)))
        ));
    }

    /// Reusing the current salt is a caller bug (the password moved but the
    /// KDF input did not); reject it rather than writing the rotation.
    #[test]
    fn change_key_rejects_reusing_the_current_salt() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"old", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        let same_salt = *v.salt();
        let old_key = crypto::derive_key(b"old", &same_salt, FAST).unwrap();
        let new_key = crypto::derive_key(b"new", &same_salt, FAST).unwrap();
        assert!(matches!(
            v.change_key(&old_key, &same_salt, FAST, &new_key),
            Err(VaultError::SaltReused)
        ));
        // Nothing moved: the old password still opens the file.
        assert!(v.is_locked());
        let mut again = Vault::open(&path).unwrap();
        again.unlock(b"old").unwrap();
    }

    /// A password change must also rotate the index salt. Otherwise every
    /// attribute hash in the header is byte-identical afterwards, and any
    /// dictionary work done against a copy taken before the change still
    /// applies to the file after it.
    #[test]
    fn change_key_rotates_the_index_salt_and_rehashes_the_index() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();
        v.insert_item(
            "x",
            attrs(&[("app", "git")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let index_salt_before = *v.index_salt();
        let hashes_before = v.header.index[0].attr_hashes.clone();
        assert!(!hashes_before.is_empty());

        let old_key = crypto::derive_key(b"old", v.salt(), v.kdf()).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>();
        let new_key = crypto::derive_key(b"new", &new_salt, FAST).unwrap();
        v.change_key(&old_key, &new_salt, FAST, &new_key).unwrap();

        assert_ne!(*v.index_salt(), index_salt_before, "index salt reused");
        let on_disk = Vault::open(&path).unwrap();
        assert_ne!(
            on_disk.header.index[0].attr_hashes, hashes_before,
            "index hashes unchanged across a password change"
        );
        assert_ne!(*on_disk.index_salt(), index_salt_before);
        // The index is still usable under the new salt, locked and unlocked.
        assert_eq!(on_disk.search_ids(&attrs(&[("app", "git")])).len(), 1);
        let mut again = Vault::open(&path).unwrap();
        again.unlock(b"new").unwrap();
        assert_eq!(again.item_ids().len(), 1);
    }

    /// The sweep runs concurrently with saves in other processes and at
    /// daemon start in a directory that may hold the user's own files, so it
    /// must match the real temp-name shape and wait out an age threshold.
    #[test]
    fn sweep_spares_live_and_unrelated_temp_files() {
        let (d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();

        // A save in flight in another process, right now.
        let live = d.path().join("default.vault.aabbccdd00112233.tmp");
        std::fs::write(&live, b"in flight").unwrap();
        // A user's own file that the substring match used to eat.
        let unrelated = d.path().join("backup.vault.2026-09.tmp");
        std::fs::write(&unrelated, b"mine").unwrap();
        backdate(&unrelated, STALE_TEMP_AGE * 2);
        // Right shape, wrong length of hex.
        let short_hex = d.path().join("default.vault.00112233.tmp");
        std::fs::write(&short_hex, b"mine too").unwrap();
        backdate(&short_hex, STALE_TEMP_AGE * 2);
        // A genuine leftover from an interrupted save.
        let stale = d.path().join("default.vault.0123456789abcdef.tmp");
        std::fs::write(&stale, b"leftover").unwrap();
        backdate(&stale, STALE_TEMP_AGE * 2);

        assert_eq!(sweep_stale_temp_files(d.path()), 1);
        assert!(!stale.exists(), "genuine stale temp file kept");
        assert!(live.exists(), "live temp file unlinked mid-write");
        assert!(unrelated.exists(), "unrelated user file deleted");
        assert!(short_hex.exists(), "wrong-shaped name deleted");
        assert!(path.exists());
    }

    /// A damaged file and a wrong password are indistinguishable, and must
    /// stay that way in the returned error: corruption is reported through
    /// the logs, never through a different error the caller could use as an
    /// oracle.
    #[test]
    fn corrupted_ciphertext_still_reports_wrong_password() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item("x", BTreeMap::new(), b"s".to_vec(), "text/plain", false)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let mut v = Vault::open(&path).unwrap();
        assert!(matches!(v.unlock(b"pw"), Err(VaultError::WrongPassword)));
        assert!(!v.verify_password(b"pw").unwrap());
        assert!(v.is_locked());
    }

    /// The vault directory must never exist world-readable, not even for the
    /// instant between `create_dir_all` and a follow-up chmod.
    #[test]
    fn the_vault_directory_is_created_private() {
        let d = tempfile::tempdir().unwrap();
        let nested = d.path().join("outer").join("inner");
        let path = nested.join("default.vault");
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        for dir in [nested.as_path(), nested.parent().unwrap()] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
    }
}
