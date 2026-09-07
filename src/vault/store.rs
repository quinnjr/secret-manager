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
    /// Largest file this vault may write, normally
    /// [`format::MAX_VAULT_BYTES`]. Overridable only in tests, so the
    /// refusal can be exercised without building a quarter-gigabyte vault.
    size_limit: u64,
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
    /// Create a new collection at `path`, failing with
    /// [`VaultError::AlreadyExists`] if one is already there.
    ///
    /// The whole vault is built in a temp file and published with
    /// `RENAME_NOREPLACE`, which both resolves the race between two concurrent
    /// `sm init work` runs (exactly one rename can win) and leaves `path` with
    /// no observable intermediate state.
    ///
    /// The previous design reserved `path` with an empty `O_EXCL` file and
    /// held that reservation across the 100-500 ms Argon2 derivation and the
    /// save. That window is not survivable: a SIGINT, SIGTERM, OOM kill or
    /// power loss inside it runs no cleanup code and strands a zero-length
    /// `<id>.vault`, which `open` reports as `Truncated`, `load_vaults` files
    /// under `broken`, and this function then refuses as `AlreadyExists` -
    /// permanently, since no command removes it. Nothing reserves anything
    /// now, and a zero-length file left by an older build is treated as
    /// absent rather than as a collection.
    pub fn create(
        path: &Path,
        label: &str,
        password: &[u8],
        kdf: KdfParams,
    ) -> Result<Vault, VaultError> {
        ensure_vault_dir(path.parent().unwrap_or_else(|| Path::new(".")))?;
        let mut vault = Self::build(path, label, password, kdf)?;
        vault.save_with(publish_new)?;
        Ok(vault)
    }

    /// A new, unlocked, empty vault in memory. Touches no file, so a failure
    /// here (an unavailable RNG, an out-of-range KDF) leaves nothing behind.
    fn build(
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
        let vault = Vault {
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
            size_limit: format::MAX_VAULT_BYTES,
        };
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
            size_limit: format::MAX_VAULT_BYTES,
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
    ///
    /// Takes effect on the next save, so an existing vault keeps the index it
    /// was written with until something writes it again. There is no method
    /// that rewrites it on demand: the daemon applies a config change by
    /// reloading, which re-reads each vault from disk.
    pub fn set_index_attributes(&mut self, enabled: bool) {
        self.index_attributes = enabled;
    }
    /// Shrink the size ceiling so the refusal path can be tested cheaply.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_size_limit_for_tests(&mut self, limit: u64) {
        self.size_limit = limit;
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

    /// Delete several items in a single save: either every id in `ids` is gone
    /// from the file, or none of them is.
    ///
    /// Every id is checked *before* anything is removed, so an unknown one is
    /// refused with the vault untouched and unwritten. The removal itself is
    /// one `retain` followed by one `save_or_restore`, so a failed write rolls
    /// the whole batch back in memory exactly as `delete_item` rolls back one.
    /// Duplicate ids are harmless.
    ///
    /// An empty batch is a no-op and does not rewrite the file.
    pub fn delete_items(&mut self, ids: &[String]) -> Result<(), VaultError> {
        let items_before = self.items()?.to_vec();
        for id in ids {
            if !items_before.iter().any(|i| &i.id == id) {
                return Err(VaultError::NoSuchItem(id.clone()));
            }
        }
        if ids.is_empty() {
            return Ok(());
        }
        {
            let items = self.items_mut()?;
            items.retain(|i| !ids.contains(&i.id));
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
        // A temp file left by an interrupted save is a complete copy of this
        // vault under the *old* key, and rotating the master password is
        // exactly the operation that is supposed to revoke the old key.
        // Waiting for `STALE_TEMP_AGE` here would leave a working copy of the
        // pre-rotation vault sitting next to the rotated one, so the sweep
        // runs with no age threshold - shape matching only. It runs twice:
        // once before the rotation is written, and once after it succeeds, to
        // catch anything that appeared in between.
        //
        // The zero threshold can unlink a temp belonging to a save running
        // *right now* in another process, which makes that save's rename fail
        // with ENOENT. That save then rolls back and reports an error, which
        // is the acceptable side of the trade: the alternative is a silently
        // un-revoked copy of the old vault.
        self.sweep_dir_now();
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
        } else {
            // The rotation is on disk; nothing shaped like a temp file next to
            // it may still open under the old key.
            self.sweep_dir_now();
        }
        if was_locked {
            self.lock();
        }
        result
    }

    /// Remove every `write_atomic`-shaped temp file beside this vault, with no
    /// age threshold. See the call sites in [`Vault::change_key`].
    fn sweep_dir_now(&self) {
        if let Some(dir) = self.path.parent() {
            sweep_temp_files(dir, Duration::ZERO);
        }
    }

    pub fn delete_file(self) -> Result<(), VaultError> {
        std::fs::remove_file(&self.path).map_err(|e| io_err(&self.path, e))?;
        if let Some(dir) = self.path.parent() {
            sweep_stale_temp_files(dir);
        }
        Ok(())
    }

    fn save(&mut self) -> Result<(), VaultError> {
        self.save_with(write_atomic)
    }

    /// [`Vault::save`], with the step that publishes the finished bytes at
    /// `self.path` left to the caller: an ordinary save renames over whatever
    /// is there, while [`Vault::create`] must refuse to replace an existing
    /// file (see [`publish_new`]).
    fn save_with(
        &mut self,
        publish: impl FnOnce(&Path, &[u8]) -> Result<(), VaultError>,
    ) -> Result<(), VaultError> {
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
        let mut bytes = Vec::with_capacity(aad.len() + ciphertext.len());
        bytes.extend_from_slice(&aad);
        bytes.extend_from_slice(&ciphertext);
        // Bound the whole file, not just the header. `open` refuses anything
        // over `MAX_VAULT_BYTES`, so without this a collection can be grown
        // past the limit one item at a time: every save succeeds, the daemon
        // keeps serving from memory, and at the next restart `load_vaults`
        // files the collection under `broken` with every secret in it
        // unreachable - and the rename has already replaced the last good
        // copy by then. Refusing here routes through the same header rollback
        // as the other failure arms.
        if let Err(e) = format::check_vault_size_against(bytes.len() as u64, self.size_limit) {
            self.header = saved_header;
            return Err(e.into());
        }
        if let Err(e) = publish(&self.path, &bytes) {
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
/// `<something>.vault.<16 lowercase hex digits>.tmp`.
///
/// The shape check is the whole point. Matching on "contains `.vault.` and
/// ends with `.tmp`" also matches a user's own `backup.vault.2026-09.tmp`,
/// and the sweep deletes unconditionally. Two narrower traps mattered just as
/// much: `is_ascii_hexdigit` accepts uppercase, which `{b:02x}` never emits,
/// so `notes.0123456789ABCDEF.tmp` was eaten; and leaving the stem
/// unconstrained let `receipts.2024.deadbeefdeadbeef.tmp` through. The stem a
/// real temp file carries is a vault file name, so require that.
fn is_write_atomic_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_suffix(".tmp") else {
        return false;
    };
    let Some((stem, hex)) = rest.rsplit_once('.') else {
        return false;
    };
    let vault_stem = stem
        .strip_suffix(".vault")
        .is_some_and(|base| !base.is_empty());
    let lower_hex = hex.len() == 16
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    vault_stem && lower_hex
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
    sweep_temp_files(dir, STALE_TEMP_AGE)
}

/// [`sweep_stale_temp_files`] with the age threshold chosen by the caller.
/// `Duration::ZERO` removes every temp-shaped file regardless of age, which
/// [`Vault::change_key`] needs: a leftover is a copy of the vault under the
/// key being revoked, so it cannot be left for five minutes.
fn sweep_temp_files(dir: &Path, min_age: Duration) -> usize {
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
        // A timestamp in the future makes `duration_since` fail. Reading that
        // as "not yet stale" is a permanent evasion: one `touch -d` in the
        // future and the file survives every sweep for good. Treat an
        // unreadable or nonsensical timestamp as stale instead - the shape
        // match has already established that only `write_atomic` produces
        // this name.
        let stale = match meta.modified() {
            Ok(m) => match now.duration_since(m) {
                Ok(age) => age >= min_age,
                Err(_) => true,
            },
            Err(_) => true,
        };
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
/// file or symlink at a guessable name is never followed), fsync, and return
/// the temp path for the caller to publish.
fn write_temp(path: &Path, bytes: &[u8]) -> Result<PathBuf, VaultError> {
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
    Ok(tmp)
}

fn sync_dir(path: &Path) {
    if let Ok(d) = File::open(path.parent().unwrap_or_else(|| Path::new("."))) {
        let _ = d.sync_all();
    }
}

/// [`write_temp`], then rename over `path` and fsync the directory. Replaces
/// whatever is at `path`, which is what an update of an existing vault wants.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = write_temp(path, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io_err(path, e));
    }
    sync_dir(path);
    Ok(())
}

/// `renameat2(AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE)`: rename that
/// fails with `EEXIST` rather than replacing `to`.
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `from_c` and `to_c` are NUL-terminated C strings that outlive
    // the call; `renameat2` reads them and retains neither. `AT_FDCWD` is a
    // valid dirfd value for both path arguments, and `RENAME_NOREPLACE` is a
    // valid flag. The raw `syscall` is used rather than the glibc wrapper,
    // which only exists from glibc 2.28 and is absent on some libcs; an
    // unsupported kernel or filesystem reports `ENOSYS`/`EINVAL` and is
    // handled by the caller.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE as libc::c_uint,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// True for a path that is present but zero bytes long.
///
/// A zero-length file is never a valid vault - `decode` needs eight bytes of
/// magic - so it is a dead reservation from an interrupted create by an older
/// build, not a collection. Treating it as one blocks the name forever.
fn is_empty_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() == 0)
}

/// Publish `bytes` at `path` as a *new* file: exactly one concurrent caller
/// can win, and an existing collection is never renamed over.
///
/// `RENAME_NOREPLACE` is the whole mechanism. Unlike an `O_EXCL` reservation
/// held across the key derivation, it makes the name appear already complete,
/// so a signal or power loss at any point leaves either nothing or a finished
/// vault - never a zero-length file that blocks the name.
fn publish_new(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = write_temp(path, bytes)?;
    let finish = |r: Result<(), VaultError>| {
        if r.is_ok() {
            sync_dir(path);
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
        r
    };
    let exists = || VaultError::AlreadyExists(path.to_path_buf());

    match rename_noreplace(&tmp, path) {
        Ok(()) => finish(Ok(())),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Reclaim a dead zero-length reservation left by an older build,
            // then try once more. The unlink and the retry are not one atomic
            // step, so two creates racing over a *pre-existing* empty file can
            // still both win; nothing produces such a file any more, and the
            // alternative is a collection name that is blocked for good.
            if is_empty_file(path) && std::fs::remove_file(path).is_ok() {
                return finish(rename_noreplace(&tmp, path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        exists()
                    } else {
                        io_err(path, e)
                    }
                }));
            }
            finish(Err(exists()))
        }
        // No `renameat2` (pre-3.15 kernel) or a filesystem that rejects the
        // flag. Fall back to claiming the name with an `O_EXCL` create and
        // renaming our finished file over that reservation. The window in
        // which `path` is zero bytes is now microseconds rather than a whole
        // Argon2 derivation, and the reclaim above covers what it can still
        // leave behind.
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::ENOSYS)
                    | Some(libc::EINVAL)
                    | Some(libc::EOPNOTSUPP)
                    | Some(libc::EPERM)
            ) =>
        {
            finish(publish_new_via_reservation(&tmp, path))
        }
        Err(e) => finish(Err(io_err(path, e))),
    }
}

/// The `publish_new` fallback for kernels and filesystems without
/// `RENAME_NOREPLACE`.
fn publish_new_via_reservation(tmp: &Path, path: &Path) -> Result<(), VaultError> {
    let reserve = || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    match reserve() {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if !(is_empty_file(path) && std::fs::remove_file(path).is_ok() && reserve().is_ok()) {
                return Err(VaultError::AlreadyExists(path.to_path_buf()));
            }
        }
        Err(e) => return Err(io_err(path, e)),
    }
    match std::fs::rename(tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Never leave the empty reservation standing in for a vault.
            let _ = std::fs::remove_file(path);
            Err(io_err(path, e))
        }
    }
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

    /// Move a file's mtime into the future. `duration_since` then fails, which
    /// must not be read as "not yet stale".
    fn postdate(path: &Path, ahead: Duration) {
        let f = File::options().write(true).open(path).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now() + ahead))
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

    /// `delete_items` is all-or-nothing: an unknown id refuses the batch with
    /// nothing removed and nothing written, and a batch whose save fails rolls
    /// the whole in-memory set back, exactly as `delete_item` does for one.
    #[test]
    fn delete_items_is_atomic() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let ids: Vec<String> = ["a", "b", "c"]
            .iter()
            .map(|n| {
                v.insert_item(n, BTreeMap::new(), b"s".to_vec(), "text/plain", false)
                    .unwrap()
                    .0
            })
            .collect();
        let before = std::fs::read(&path).unwrap();

        // One unknown id refuses the whole batch, untouched and unwritten.
        let err = v
            .delete_items(&[ids[0].clone(), "nope".into(), ids[2].clone()])
            .unwrap_err();
        assert!(matches!(err, VaultError::NoSuchItem(_)), "{err}");
        assert_eq!(v.item_ids(), ids);
        assert_eq!(std::fs::read(&path).unwrap(), before, "vault was rewritten");

        // An empty batch is a no-op and does not rewrite the file either.
        v.delete_items(&[]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);

        // A save that cannot be written rolls the whole batch back in memory.
        let block = block_writes(&path);
        assert!(v.delete_items(&[ids[0].clone(), ids[1].clone()]).is_err());
        assert_eq!(v.item_ids(), ids, "a failed save must roll the batch back");
        unblock(block);

        // The happy path: one save, all of them gone, duplicates harmless.
        v.delete_items(&[ids[0].clone(), ids[1].clone(), ids[0].clone()])
            .unwrap();
        assert_eq!(v.item_ids(), vec![ids[2].clone()]);
        let mut reopened = Vault::open(&path).unwrap();
        reopened.unlock(b"pw").unwrap();
        assert_eq!(reopened.item_ids(), vec![ids[2].clone()]);
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

    /// `create` publishes with `RENAME_NOREPLACE`, so an existing collection
    /// is never renamed over: the second create must lose at the publish and
    /// leave the first one's bytes exactly as they were.
    #[test]
    fn create_loses_against_an_existing_vault() {
        let (_d, path) = tmp();
        Vault::create(&path, "first", b"pw", FAST).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            Vault::create(&path, "second", b"pw", FAST),
            Err(VaultError::AlreadyExists(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before, "existing vault lost");
        assert_eq!(Vault::open(&path).unwrap().label(), "first");
    }

    /// An interrupted `create` used to leave a zero-length reservation, which
    /// `open` reports as `Truncated`, `load_vaults` files under `broken`, and
    /// `create` refuses as `AlreadyExists` - permanently, with no command that
    /// removes it. A zero-length file is never a valid vault, so `create`
    /// claims the name instead of being blocked by it.
    #[test]
    fn a_zero_length_vault_file_does_not_block_a_later_create() {
        let (_d, path) = tmp();
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(
            Vault::open(&path),
            Err(VaultError::Format(FormatError::Truncated))
        ));
        let v = Vault::create(&path, "recovered", b"pw", FAST).unwrap();
        assert_eq!(v.label(), "recovered");
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
        let mut again = Vault::open(&path).unwrap();
        again.unlock(b"pw").unwrap();
        assert_eq!(again.label(), "recovered");
    }

    /// `save` must bound the whole file, not just the header. `open` refuses a
    /// file over `MAX_VAULT_BYTES`, so a save that produces one writes a
    /// collection that works until the next restart and is then unreachable
    /// for good - over the top of the last good copy.
    #[test]
    fn save_refuses_an_oversized_file_and_keeps_the_old_one() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item(
            "small",
            attrs(&[("a", "1")]),
            b"keep".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();

        // Exercise the ceiling rather than materialise it: building a real
        // 256 MiB vault cost 42 s of every test run and proved nothing the
        // injected limit does not.
        v.set_size_limit_for_tests(before.len() as u64 + 64);
        let err = v
            .insert_item(
                "over",
                attrs(&[("a", "2")]),
                vec![0u8; 4096],
                "application/octet-stream",
                false,
            )
            .unwrap_err();
        assert!(
            matches!(err, VaultError::Format(FormatError::VaultTooLarge(_))),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "old file replaced");
        assert_eq!(v.items().unwrap().len(), 1, "item list not rolled back");

        // The rollback left header, aad and ciphertext consistent, so the
        // vault still works in memory and from disk.
        assert_eq!(v.item_ids().len(), 1);
        v.lock();
        v.unlock(b"pw").unwrap();
        assert_eq!(v.items().unwrap()[0].secret.as_slice(), b"keep");
        let mut reopened = Vault::open(&path).unwrap();
        reopened.unlock(b"pw").unwrap();
        assert_eq!(reopened.items().unwrap().len(), 1);

        // With the real ceiling restored the same insert succeeds, so the
        // refusal was the limit and nothing else.
        v.set_size_limit_for_tests(format::MAX_VAULT_BYTES);
        v.insert_item(
            "over",
            attrs(&[("a", "2")]),
            vec![0u8; 4096],
            "application/octet-stream",
            false,
        )
        .unwrap();
        assert_eq!(v.items().unwrap().len(), 2);
    }

    #[test]
    fn change_key_removes_leftover_copies_under_the_old_key() {
        let (d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();
        v.insert_item(
            "x",
            attrs(&[("a", "b")]),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let leftover = d.path().join("default.vault.00112233445566aa.tmp");
        std::fs::copy(&path, &leftover).unwrap();
        assert!(
            Vault::open(&leftover)
                .unwrap()
                .verify_password(b"old")
                .unwrap(),
            "fixture is not a working copy under the old password"
        );

        let old_key = crypto::derive_key(b"old", v.salt(), v.kdf()).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>();
        let new_key = crypto::derive_key(b"new", &new_salt, FAST).unwrap();
        v.change_key(&old_key, &new_salt, FAST, &new_key).unwrap();

        assert!(
            !leftover.exists(),
            "a leftover temp still decrypts under the old password after a rotation"
        );
        assert!(path.exists());
        let mut again = Vault::open(&path).unwrap();
        again.unlock(b"new").unwrap();
        assert_eq!(again.items().unwrap()[0].secret.as_slice(), b"s");
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

    /// A create that fails must leave nothing behind at `path`: a partial or
    /// empty file there decodes as nothing and would block every later create
    /// of that collection.
    ///
    /// This covers the *graceful* failure path only - an `Err` returned from
    /// inside `create`. The path that actually stranded files was a SIGINT,
    /// SIGTERM, OOM kill or power loss mid-create, where no Rust cleanup code
    /// runs at all; that one is addressed structurally (the vault is built in
    /// a temp file and published with `RENAME_NOREPLACE`, so `path` has no
    /// observable intermediate state) and is covered by
    /// `a_zero_length_vault_file_does_not_block_a_later_create`.
    #[test]
    fn failed_create_leaves_nothing_at_the_path() {
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
        // `write_atomic` formats with `{b:02x}`, so it never produces an
        // uppercase name; a user's own file may well be uppercase.
        let upper_hex = d.path().join("notes.0123456789ABCDEF.tmp");
        std::fs::write(&upper_hex, b"mine three").unwrap();
        backdate(&upper_hex, STALE_TEMP_AGE * 2);
        // Right hex shape, but the stem is not a vault file name.
        let not_a_vault = d.path().join("receipts.2024.deadbeefdeadbeef.tmp");
        std::fs::write(&not_a_vault, b"mine four").unwrap();
        backdate(&not_a_vault, STALE_TEMP_AGE * 2);
        // A genuine leftover from an interrupted save.
        let stale = d.path().join("default.vault.0123456789abcdef.tmp");
        std::fs::write(&stale, b"leftover").unwrap();
        backdate(&stale, STALE_TEMP_AGE * 2);
        // A leftover whose mtime is in the future: `duration_since` fails, and
        // reading that as "not yet stale" lets it evade every future sweep.
        let future = d.path().join("default.vault.ffffffffffffffff.tmp");
        std::fs::write(&future, b"leftover too").unwrap();
        postdate(&future, STALE_TEMP_AGE * 100);

        assert_eq!(sweep_stale_temp_files(d.path()), 2);
        assert!(!stale.exists(), "genuine stale temp file kept");
        assert!(!future.exists(), "a future mtime evades the sweep forever");
        assert!(live.exists(), "live temp file unlinked mid-write");
        assert!(unrelated.exists(), "unrelated user file deleted");
        assert!(short_hex.exists(), "wrong-shaped name deleted");
        assert!(upper_hex.exists(), "uppercase-hex user file deleted");
        assert!(not_a_vault.exists(), "non-vault stem deleted");
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

    /// `change_key` is the only place the KDF ceilings are enforced on the
    /// write path: `Request::ChangeKey` carries a peer-chosen `new_kdf`
    /// straight through `handle_control` and `daemon::change_key` with no
    /// intermediate validation. A vault sealed under `m_cost_kib = u32::MAX`
    /// would need that much memory to open again, so the rotation must be
    /// refused before anything is written.
    #[test]
    fn change_key_refuses_kdf_parameters_over_the_ceiling() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"old", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let old_key = crypto::derive_key(b"old", v.salt(), v.kdf()).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>();
        let bad = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            p_cost: 1,
        };
        // The key is never used - validation refuses on the first line - so
        // deriving it under FAST keeps the test cheap.
        let new_key = crypto::derive_key(b"new", &new_salt, FAST).unwrap();

        let err = v
            .change_key(&old_key, &new_salt, bad, &new_key)
            .unwrap_err();
        assert!(
            matches!(err, VaultError::Crypto(CryptoError::UnsafeKdf(_))),
            "{err:?}"
        );

        // Nothing was written and nothing rotated: the old password still
        // opens the file exactly as it was.
        assert_eq!(std::fs::read(&path).unwrap(), before, "vault was rewritten");
        assert_eq!(v.kdf(), FAST, "header kdf moved");
        let mut again = Vault::open(&path).unwrap();
        again.unlock(b"old").unwrap();
        assert_eq!(again.label(), "Default");
    }

    /// A ciphertext that authenticates but does not decode as an item list is
    /// damage, not a wrong password, and the two must not be conflated: the
    /// AEAD has already proved the caller holds the key, so reporting
    /// `WrongPassword` would send the operator hunting for a password that
    /// was right all along.
    #[test]
    fn unlock_reports_a_decode_failure_rather_than_a_wrong_password() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let file = format::VaultFile::decode(&bytes).unwrap();
        let key = crypto::derive_key(b"pw", &file.header.salt, file.header.kdf).unwrap();
        // Re-seal the *existing* header over garbage, so the AEAD verifies
        // (same key, same nonce, same associated data) and only
        // `decode_items` can fail.
        let forged =
            crypto::seal(&key, &file.header.nonce, &file.aad, b"not postcard items").unwrap();
        let mut out = file.aad.clone();
        out.extend_from_slice(&forged);
        std::fs::write(&path, &out).unwrap();

        let mut v = Vault::open(&path).unwrap();
        let err = v.unlock(b"pw").unwrap_err();
        assert!(
            matches!(err, VaultError::Format(FormatError::Encoding(_))),
            "{err:?}"
        );
        assert!(
            !matches!(err, VaultError::WrongPassword),
            "a decode failure must not masquerade as a wrong password"
        );
        assert!(v.is_locked(), "a failed unlock must leave the vault locked");
    }

    /// Every accessor and mutator refuses a locked vault, not just `items`.
    /// A gap here would serve or edit plaintext the daemon believes it has
    /// dropped, so the refusal is checked at each entry point rather than at
    /// the one they happen to share today.
    #[test]
    fn every_item_entry_point_refuses_a_locked_vault() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let (id, _) = v
            .insert_item(
                "x",
                attrs(&[("a", "b")]),
                b"s".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        v.lock();

        let err = v.item(&id).unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        let err = v.search(&attrs(&[("a", "b")])).unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        let err = v
            .insert_item("y", BTreeMap::new(), b"t".to_vec(), "text/plain", false)
            .unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        let err = v.update_item(&id, |i| i.label = "no".into()).unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        let err = v.delete_item(&id).unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        let err = v.delete_items(std::slice::from_ref(&id)).unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        let err = v.set_label("no").unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");

        assert!(v.is_locked());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "a refused call rewrote the vault"
        );
    }

    /// `item` and `update_item` must name the id they could not find, and
    /// `update_item` must refuse before `save_or_restore` runs: an unknown id
    /// is a client mistake, not a reason to rewrite the file.
    #[test]
    fn item_and_update_item_reject_an_unknown_id() {
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
        let before = std::fs::read(&path).unwrap();

        let err = v.item("nope").unwrap_err();
        assert!(
            matches!(&err, VaultError::NoSuchItem(id) if id == "nope"),
            "{err:?}"
        );

        let err = v
            .update_item("nope", |i| i.label = "touched".into())
            .unwrap_err();
        assert!(
            matches!(&err, VaultError::NoSuchItem(id) if id == "nope"),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "vault was rewritten");
        assert_eq!(v.items().unwrap().len(), 1);
        assert_eq!(v.items().unwrap()[0].label, "x");
    }

    /// A missing collection must be an `Io` error carrying `NotFound`, not a
    /// format error: `load_vaults` and the CLI use exactly that distinction to
    /// tell a collection that was never created from one that is damaged.
    #[test]
    fn open_reports_a_missing_file_as_not_found() {
        let (_d, path) = tmp();
        let err = Vault::open(&path).unwrap_err();
        let VaultError::Io { path: p, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &path, "the path must survive into the error");
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound, "{source:?}");
    }

    /// The `publish_new` fallback runs only when `renameat2` reports
    /// `ENOSYS`/`EINVAL`/`EOPNOTSUPP`/`EPERM`, which no modern Linux does, so
    /// it is called directly here. It has to make the same three promises the
    /// `RENAME_NOREPLACE` path makes.
    #[test]
    fn publish_via_reservation_claims_a_free_name_and_never_replaces_a_vault() {
        // A free name: the reservation is claimed and the finished bytes
        // land on it.
        let (d, path) = tmp();
        let tmp_file = write_temp(&path, b"finished vault").unwrap();
        publish_new_via_reservation(&tmp_file, &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"finished vault");
        assert!(!tmp_file.exists(), "the temp file was not consumed");
        drop(d);

        // An existing, non-empty collection is refused and left alone.
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "first", b"pw", FAST).unwrap();
        v.insert_item("x", BTreeMap::new(), b"s".to_vec(), "text/plain", false)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let tmp_file = write_temp(&path, b"replacement").unwrap();
        let err = publish_new_via_reservation(&tmp_file, &path).unwrap_err();
        assert!(
            matches!(err, VaultError::AlreadyExists(ref p) if p == &path),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "existing vault lost");
        let mut again = Vault::open(&path).unwrap();
        again.unlock(b"pw").unwrap();
        assert_eq!(again.items().unwrap().len(), 1);
        let _ = std::fs::remove_file(&tmp_file);

        // A zero-length reservation left by an interrupted older build is
        // never a vault, so it is reclaimed rather than blocking the name.
        let (_d, path) = tmp();
        std::fs::write(&path, b"").unwrap();
        let tmp_file = write_temp(&path, b"recovered").unwrap();
        publish_new_via_reservation(&tmp_file, &path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"recovered");
    }

    /// The earliest failure in `create`, before any Argon2 work: if the vault
    /// directory cannot be made, the error names the directory and nothing is
    /// left on disk.
    #[test]
    fn create_reports_a_vault_directory_that_cannot_be_made() {
        let d = tempfile::tempdir().unwrap();
        // A regular file where the directory should be, so `DirBuilder` fails.
        let blocked = d.path().join("collections");
        std::fs::write(&blocked, b"not a directory").unwrap();
        let path = blocked.join("default.vault");

        let err = Vault::create(&path, "Default", b"pw", FAST).unwrap_err();
        let VaultError::Io { path: p, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &blocked, "the error must name the directory");
        assert_eq!(
            std::fs::read(&blocked).unwrap(),
            b"not a directory",
            "the blocking file was touched"
        );
        assert!(!path.exists());
    }

    /// A vault file that vanished under the handle is an error, not a silent
    /// success: `delete_file` reporting `Ok` for a file it did not remove
    /// would let the caller drop a collection it never actually deleted.
    #[test]
    fn delete_file_reports_a_vault_that_is_already_gone() {
        let (_d, path) = tmp();
        let v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        std::fs::remove_file(&path).unwrap();

        let err = v.delete_file().unwrap_err();
        let VaultError::Io { path: p, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &path);
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound, "{source:?}");
    }

    /// `Vault` carries the master key and every plaintext secret, so its
    /// hand-written `Debug` must show only the four things an operator needs
    /// (which file, which label, locked or not, how many items) and nothing
    /// that a log line or a `{:?}` in an error could leak.
    #[test]
    fn the_debug_impl_reports_state_without_any_secret() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Work", b"correct horse", FAST).unwrap();
        v.insert_item(
            "github",
            attrs(&[("service", "github")]),
            b"hunter2".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();

        let shown = format!("{v:?}");
        assert!(shown.contains(&path.display().to_string()), "{shown}");
        assert!(shown.contains("Work"), "{shown}");
        assert!(shown.contains("locked: false"), "{shown}");
        assert!(shown.contains("items: 1"), "{shown}");
        for leaked in ["hunter2", "correct horse", "github"] {
            assert!(!shown.contains(leaked), "{leaked} leaked into {shown}");
        }

        v.lock();
        assert!(format!("{v:?}").contains("locked: true"));
    }

    /// The AEAD-failure diagnostic reads the file to report its size and
    /// mtime. A vault whose file has been removed since it was opened still
    /// has to answer `WrongPassword` - the missing metadata is the one thing
    /// the diagnostic is allowed to be silent about, not a reason to fail
    /// differently or to panic.
    #[test]
    fn a_failed_unlock_still_reports_wrong_password_when_the_file_is_gone() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let err = v.unlock(b"wrong").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword), "{err:?}");
        assert!(v.is_locked());
    }

    /// Every public mutator checks the lock state before it touches anything,
    /// so this is the backstop underneath them: the writer itself refuses a
    /// locked vault rather than sealing an empty item list under a key it
    /// does not have, and the file on disk is left exactly as it was.
    #[test]
    fn saving_a_locked_vault_is_refused_and_writes_nothing() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.insert_item("x", BTreeMap::new(), b"s".to_vec(), "text/plain", false)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        v.lock();

        let err = v.save().unwrap_err();
        assert!(matches!(err, VaultError::Locked), "{err:?}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the file was rewritten"
        );
    }

    /// The sweep deletes unconditionally, so the name shape is the only
    /// guard. A name with no random component at all - the shape a user's own
    /// `something.tmp` has - must not match.
    #[test]
    fn a_temp_name_without_a_random_component_is_not_swept() {
        assert!(!is_write_atomic_temp_name("default.tmp"));
        assert!(!is_write_atomic_temp_name(".tmp"));
        assert!(!is_write_atomic_temp_name("default.vault"));
        // The shape that does match, for contrast.
        assert!(is_write_atomic_temp_name(
            "default.vault.0123456789abcdef.tmp"
        ));
    }

    /// The sweep runs at daemon start and from `delete_file`, both of which
    /// can happen before the vault directory exists. An unreadable directory
    /// is nothing to clean, not a failure.
    #[test]
    fn sweeping_a_directory_that_is_not_there_removes_nothing() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(sweep_stale_temp_files(&d.path().join("never-created")), 0);
    }

    /// `remove_file` on a directory fails anyway, but the `is_file` check has
    /// to come first: the sweep must skip anything that is not a regular
    /// file, however temp-shaped its name, and report it as not removed.
    #[test]
    fn the_sweep_skips_a_directory_wearing_a_temp_files_name() {
        let d = tempfile::tempdir().unwrap();
        let decoy = d.path().join("default.vault.0123456789abcdef.tmp");
        std::fs::create_dir(&decoy).unwrap();
        let real = d.path().join("default.vault.fedcba9876543210.tmp");
        std::fs::write(&real, b"leftover").unwrap();

        // Zero threshold: the age check cannot be what saves the directory.
        assert_eq!(sweep_temp_files(d.path(), Duration::ZERO), 1);
        assert!(decoy.is_dir(), "the directory was removed");
        assert!(!real.exists(), "the real leftover survived");
    }

    /// The reservation fallback claims the name with `O_EXCL` before it
    /// renames. If that create fails for a reason other than the name being
    /// taken, the error has to be reported as-is, naming the path - reporting
    /// `AlreadyExists` for a directory that is not there would send the
    /// caller looking for a collection that does not exist.
    #[test]
    fn publish_via_reservation_reports_a_reservation_it_could_not_make() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("missing-dir").join("default.vault");
        let tmp_file = write_temp(&d.path().join("default.vault"), b"finished").unwrap();

        let err = publish_new_via_reservation(&tmp_file, &path).unwrap_err();
        let VaultError::Io { path: p, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &path, "the error must name the vault path");
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound, "{source:?}");
        assert!(!path.exists());
    }

    /// The window this fallback exists to shrink is the one where `path` is a
    /// zero-length reservation. If the rename that closes it fails, the
    /// reservation must be removed again: leaving it would stand in for a
    /// collection, which `open` reports as truncated and `create` then
    /// refuses as already existing - the exact trap the whole design is
    /// there to avoid.
    #[test]
    fn publish_via_reservation_removes_its_reservation_when_the_rename_fails() {
        let (_d, path) = tmp();
        // A temp file that is not there, so the rename cannot succeed.
        let vanished = path.with_file_name("default.vault.0123456789abcdef.tmp");

        let err = publish_new_via_reservation(&vanished, &path).unwrap_err();
        let VaultError::Io { path: p, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &path);
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound, "{source:?}");
        assert!(
            !path.exists(),
            "the empty reservation was left standing in for a vault"
        );
    }

    /// `publish_new` recognises two rename failures - the name being taken,
    /// and a kernel without `RENAME_NOREPLACE` - and everything else has to
    /// come back as an `Io` error carrying the real errno, with the finished
    /// temp file cleaned up. No errno outside those two classes is reachable
    /// on a working filesystem, so one is manufactured here with a trailing
    /// slash on the destination, which makes the kernel insist the name be a
    /// directory (`ENOTDIR`).
    #[test]
    fn an_unexpected_rename_failure_is_reported_and_leaves_no_temp_file() {
        let d = tempfile::tempdir().unwrap();
        let path = PathBuf::from(format!("{}/default.vault/", d.path().display()));

        let err = publish_new(&path, b"finished vault").unwrap_err();
        let VaultError::Io { path: p, source } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(p, &path);
        assert_eq!(source.raw_os_error(), Some(libc::ENOTDIR), "{source:?}");
        let leftovers: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {leftovers:?}");
    }
}
