//! Cleartext header parsers for both source formats.
//!
//! Both gnome-keyring and KWallet store an **unencrypted index** ahead of the
//! ciphertext, so that the daemon can answer a `SearchItems` on a *locked*
//! keyring. That index is the whole of what this module reads. It gives an
//! inventory with no password and no daemon — what `sm import --inventory`
//! prints — and it gives verification an independent item count to check the
//! extraction against: if the file says 28 items and the D-Bus walk yielded
//! 27, something was skipped and the assistant must say so.
//!
//! # Why the ciphertext is never touched
//!
//! Both formats are easy to parse and hard to decrypt safely. gnome-keyring's
//! format 0 needs iterated-MD5 key derivation and AES-128-CBC; KWallet's
//! needs PBKDF2-SHA512 and Blowfish-CBC. None of those primitives exists in
//! this codebase, whose entire cryptographic surface is Argon2id and
//! XChaCha20-Poly1305, and the failure mode decides it: a subtly wrong key
//! derivation produces garbage indistinguishable from a wrong password, so
//! the user is told "wrong password" when the truth is "our KDF is broken" —
//! precisely the bug that testing against our own output cannot catch. The
//! secret bytes come from each source's own daemon, whose KDF is by
//! definition correct.
//!
//! So these parsers stop at `ciphertext_offset`, and every structure they
//! return holds counts, names and opaque hashes.
//!
//! # These are attacker-controlled files
//!
//! A `.keyring` or a `.kwl` is a file on disk that a hostile party may have
//! written, and `--inventory` reads it with no authentication of any kind —
//! there is nothing to authenticate it *with*, since the integrity check
//! lives inside the encrypted half. Every length and count is therefore
//! checked against the bytes actually remaining before it is used to size
//! anything, all reads go through [`Cursor`], and the parsers allocate
//! `O(file length)` and never `O(declared length)`. `src/vault/format.rs` is
//! the model and `docs/fuzzing.md` explains why.

use super::{AttributeKeys, Source};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `GnomeKeyring\n\r\0\n`.
pub const KEYRING_MAGIC: [u8; 16] = *b"GnomeKeyring\n\r\0\n";
/// `KWALLET\n\r\0\r\n`.
pub const KWALLET_MAGIC: [u8; 12] = *b"KWALLET\n\r\0\r\n";

/// The only gnome-keyring file version this reads. Format 0.0 is the legacy
/// binary keyring; anything else is refused rather than guessed at.
pub const KEYRING_MAJOR: u8 = 0;
pub const KEYRING_MINOR: u8 = 0;

/// KWallet 5/6's format. Minor 0 is the KWallet4 format, which is a different
/// layout and is refused.
pub const KWALLET_MAJOR: u8 = 0;
pub const KWALLET_MINOR: u8 = 1;

/// Largest source file read into memory for an inventory. The header is a
/// small fraction of a keyring, and the largest measured here is 74 KiB; the
/// cap exists so a hostile 40 GiB file in `~/.local/share/keyrings/` cannot
/// be `read_to_end`ed before the parser ever sees a byte.
pub const MAX_SOURCE_BYTES: u64 = 64 << 20;

/// gnome-keyring item types. Only the two that must be refused are named:
/// everything else flattens to a generic item, and the report says which
/// items lost a type.
pub const ITEM_TYPE_GENERIC_SECRET: u32 = 0;
pub const ITEM_TYPE_NETWORK_PASSWORD: u32 = 1;
pub const ITEM_TYPE_NOTE: u32 = 2;
/// A secret whose purpose is to unlock *another* keyring.
pub const ITEM_TYPE_CHAINED_KEYRING_PASSWORD: u32 = 3;
/// A secret whose purpose is to unlock an encryption key.
pub const ITEM_TYPE_ENCRYPTION_KEY_PASSWORD: u32 = 4;

/// True for the item types that are refused, listed, and never written:
/// importing one would copy an unlock credential into a different trust
/// domain.
pub const fn is_unlock_credential(item_type: u32) -> bool {
    matches!(
        item_type,
        ITEM_TYPE_CHAINED_KEYRING_PASSWORD | ITEM_TYPE_ENCRYPTION_KEY_PASSWORD
    )
}

/// Attribute value kinds in the cleartext index. A string attribute's value
/// is stored as the 32-character lowercase hex of its unsalted MD5; a uint32
/// attribute's as a 32-bit hash. Neither is retained: an inventory yields
/// attribute *names*.
const ATTR_TYPE_STRING: u32 = 0;
const ATTR_TYPE_UINT32: u32 = 1;

/// An MD5 digest from a KWallet index, kept as opaque bytes. Nothing here
/// computes MD5 — the index is only ever compared against, and adding a hash
/// this project does not otherwise use, for a one-shot tool, is not a trade
/// worth making until verification actually needs it.
pub type Md5Hash = [u8; 16];

/// Smallest possible encoding of one gnome-keyring index item: id, type and
/// an attribute count.
const MIN_ITEM_BYTES: usize = 12;
/// Smallest possible encoding of one index attribute: a name length, a type,
/// and a value that is at least a `u32`.
const MIN_ATTRIBUTE_BYTES: usize = 12;
/// Smallest possible encoding of one KWallet folder: its name hash and an
/// entry count.
const MIN_FOLDER_BYTES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("not a {0} file (bad magic)")]
    BadMagic(Source),
    #[error(
        "unsupported {format} format version {major}.{minor}; this build reads only \
         {expected_major}.{expected_minor}"
    )]
    UnsupportedVersion {
        /// Named `format` rather than `source`: `thiserror` reads a field
        /// called `source` as the error's cause and demands `std::error::Error`
        /// of it.
        format: Source,
        major: u8,
        minor: u8,
        expected_major: u8,
        expected_minor: u8,
    },
    #[error("truncated file: it ends inside the {field}")]
    Truncated { field: &'static str },
    /// A length or count field claiming more than the file holds. Reported
    /// separately from [`HeaderError::Truncated`] because it is the shape of
    /// a deliberately malformed file rather than of an interrupted write, and
    /// it is the field a caller would otherwise have sized an allocation by.
    #[error("{field} claims {declared} entries, more than the file can hold")]
    ImpossibleLength { field: &'static str, declared: u64 },
    #[error("{field} is not valid UTF-8")]
    NonUtf8 { field: &'static str },
    /// A length-prefixed string encoded as the format's NULL (`0xffffffff`)
    /// in a position that requires a name. Reported separately from
    /// [`HeaderError::NonUtf8`] because nothing failed to decode: there were
    /// no bytes to decode, and saying "not valid UTF-8" of a field that was
    /// never present sends a reader looking for an encoding bug that is not
    /// there.
    #[error("{field} is NULL, and this format requires a name here")]
    NullName { field: &'static str },
    #[error("item {item_id} has an attribute of unknown type {attribute_type}")]
    UnknownAttributeType { item_id: u32, attribute_type: u32 },
    #[error("the `default` file does not name a keyring")]
    InvalidDefaultName,
    #[error("source file is too large to read ({0} bytes; limit is {MAX_SOURCE_BYTES})")]
    FileTooLarge(u64),
}

/// Refuse a file too large to load, from its `stat` size, before any read.
pub fn check_source_size(len: u64) -> Result<(), HeaderError> {
    if len > MAX_SOURCE_BYTES {
        return Err(HeaderError::FileTooLarge(len));
    }
    Ok(())
}

/// A bounds-checked reader over a byte slice.
///
/// The invariant is `pos <= buf.len()`, established at construction and
/// preserved by [`Cursor::take`] being the only thing that advances `pos`:
/// it refuses `n > remaining()` before adding, so the addition cannot
/// overflow and the slice index cannot panic. Every other method is written
/// in terms of `take`.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        // `pos <= buf.len()` by the type's invariant.
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], HeaderError> {
        if n > self.remaining() {
            return Err(HeaderError::Truncated { field });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, HeaderError> {
        Ok(self.take(1, field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, HeaderError> {
        let b = self.take(4, field)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, HeaderError> {
        let b = self.take(8, field)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn array16(&mut self, field: &'static str) -> Result<Md5Hash, HeaderError> {
        let mut out = [0u8; 16];
        out.copy_from_slice(self.take(16, field)?);
        Ok(out)
    }

    /// A declared count, refused unless the file could actually hold that
    /// many elements of `min_each` bytes.
    ///
    /// This is the check that keeps work proportional to the input rather
    /// than to a number an attacker wrote: a `num_items` of `0xffffffff` in a
    /// 900-byte file is rejected here, before any loop is entered. It bounds
    /// the *count*, not the allocation — `min_each` is the smallest encoded
    /// size and the parsed element is wider — so callers grow their `Vec`
    /// from the elements they actually read rather than reserving on the
    /// declared count.
    fn count(
        &self,
        declared: u32,
        min_each: usize,
        field: &'static str,
    ) -> Result<usize, HeaderError> {
        let need = u64::from(declared).saturating_mul(min_each as u64);
        if need > self.remaining() as u64 {
            return Err(HeaderError::ImpossibleLength {
                field,
                declared: u64::from(declared),
            });
        }
        Ok(declared as usize)
    }

    /// gnome-keyring's length-prefixed string. `0xffffffff` is its NULL.
    fn opt_string(&mut self, field: &'static str) -> Result<Option<String>, HeaderError> {
        let len = self.u32(field)?;
        if len == u32::MAX {
            return Ok(None);
        }
        let len = self.count(len, 1, field)?;
        let bytes = self.take(len, field)?;
        let s = std::str::from_utf8(bytes).map_err(|_| HeaderError::NonUtf8 { field })?;
        Ok(Some(s.to_string()))
    }
}

// --------------------------------------------------------------------------
// gnome-keyring
// --------------------------------------------------------------------------

/// One item's entry in a keyring's cleartext index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringItemIndex {
    /// Per-keyring item id. Unique within the file and stable, which makes it
    /// the provenance handle for an item whose label we cannot yet read.
    pub id: u32,
    /// A gnome-keyring item type. Our daemon exposes no `Type` property, so
    /// anything but [`ITEM_TYPE_GENERIC_SECRET`] flattens on import.
    pub item_type: u32,
    /// The attribute **names**. Values in this index are unsalted MD5 and are
    /// not retained: they identify nothing an inventory needs, and carrying
    /// them would put a guess-confirming oracle in a report.
    pub attribute_keys: AttributeKeys,
}

impl KeyringItemIndex {
    /// True for the item types that are refused rather than imported.
    pub fn is_unlock_credential(&self) -> bool {
        is_unlock_credential(self.item_type)
    }
}

/// Everything a `.keyring` file yields without its password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringInventory {
    pub display_name: String,
    /// Unix seconds. The two files measured here both carry `modified == 0`,
    /// so a keyring's own mtime is not meaningful and must not be used as a
    /// timestamp for anything. Per-*item* timestamps live in the encrypted
    /// half and come from the daemon.
    pub created: u64,
    pub modified: u64,
    pub flags: u32,
    /// Seconds of idle time before the keyring re-locks; `0` for never.
    /// gnome-keyring declares it `guint32` and writes it as one, so it is
    /// read as one: an earlier version read it signed on the strength of an
    /// unverified claim that negative values occur in the wild, which turned
    /// a large timeout into a negative number in an inventory nobody could
    /// then explain. Recorded, never acted on.
    pub lock_timeout: u32,
    /// Iterations of the file's iterated-MD5 key derivation, calibrated per
    /// file at creation (3457 and 1166 in the two measured here). Recorded
    /// because it is the honest measure of how weak the source is, not
    /// because anything here derives a key.
    pub hash_iterations: u32,
    /// The file's 8-byte KDF salt. Opaque; nothing here derives from it.
    pub salt: [u8; 8],
    pub items: Vec<KeyringItemIndex>,
    /// Where the encrypted half begins. Nothing beyond this offset is read.
    pub ciphertext_offset: usize,
    pub ciphertext_len: usize,
}

impl KeyringInventory {
    /// The independent count. If the D-Bus walk yields a different number,
    /// the import failed regardless of what the fingerprints agree on.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// How many items carry each attribute name, across the whole keyring.
    /// This is what makes `--inventory` worth reading: it shows at a glance
    /// how many items have an `xdg:schema` and are therefore fully portable.
    pub fn attribute_key_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for item in &self.items {
            for key in item.attribute_keys.iter() {
                *counts.entry(key.to_string()).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Items that will be refused rather than imported.
    pub fn unlock_credential_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.is_unlock_credential())
            .count()
    }
}

/// Parses the cleartext half of a gnome-keyring `.keyring` file.
///
/// Refuses: a wrong magic; any version other than
/// [`KEYRING_MAJOR`].[`KEYRING_MINOR`]; a truncation at any structural
/// boundary; a count or length field claiming more than the file holds; a
/// non-UTF-8 keyring name or attribute name; an attribute of a type the
/// format does not define.
///
/// All integers are big-endian.
pub fn parse_keyring_header(bytes: &[u8]) -> Result<KeyringInventory, HeaderError> {
    let mut c = Cursor::new(bytes);
    if c.take(KEYRING_MAGIC.len(), "magic")? != KEYRING_MAGIC {
        return Err(HeaderError::BadMagic(Source::GnomeKeyring));
    }
    let major = c.u8("version")?;
    let minor = c.u8("version")?;
    // The crypto and hash ids identify the algorithms of the encrypted half,
    // which is never touched, so they are read past rather than validated.
    let _crypto = c.u8("version")?;
    let _hash = c.u8("version")?;
    if (major, minor) != (KEYRING_MAJOR, KEYRING_MINOR) {
        return Err(HeaderError::UnsupportedVersion {
            format: Source::GnomeKeyring,
            major,
            minor,
            expected_major: KEYRING_MAJOR,
            expected_minor: KEYRING_MINOR,
        });
    }

    let display_name = c.opt_string("keyring name")?.unwrap_or_default();
    let created = c.u64("created time")?;
    let modified = c.u64("modified time")?;
    let flags = c.u32("flags")?;
    let lock_timeout = c.u32("lock timeout")?;
    let hash_iterations = c.u32("hash iterations")?;
    let mut salt = [0u8; 8];
    salt.copy_from_slice(c.take(8, "salt")?);
    for _ in 0..4 {
        let _reserved = c.u32("reserved words")?;
    }

    let declared = c.u32("item count")?;
    let num_items = c.count(declared, MIN_ITEM_BYTES, "item count")?;
    // `Vec::new`, not `with_capacity(num_items)`. `count` bounds the declared
    // number by the *encoded* minimum against a wider in-memory type, so
    // reserving up front still admits roughly 2x amplification over the file
    // length — bounded by `MAX_SOURCE_BYTES`, so not a denial of service, but
    // it contradicts this module's `O(file length)` claim for no gain: the
    // push loop is bounded by the same reads that produce the elements.
    let mut items = Vec::new();
    for _ in 0..num_items {
        items.push(parse_keyring_item(&mut c)?);
    }

    // The encrypted half is length-prefixed. Its length is read so that a
    // file claiming more ciphertext than it holds is refused here rather than
    // by whatever reads it next; the bytes themselves are never touched.
    let declared_len = c.u32("ciphertext length")?;
    let ciphertext_len = c.count(declared_len, 1, "ciphertext length")?;
    let ciphertext_offset = c.pos;

    Ok(KeyringInventory {
        display_name,
        created,
        modified,
        flags,
        lock_timeout,
        hash_iterations,
        salt,
        items,
        ciphertext_offset,
        ciphertext_len,
    })
}

fn parse_keyring_item(c: &mut Cursor<'_>) -> Result<KeyringItemIndex, HeaderError> {
    let id = c.u32("item id")?;
    let item_type = c.u32("item type")?;
    let declared = c.u32("attribute count")?;
    let count = c.count(declared, MIN_ATTRIBUTE_BYTES, "attribute count")?;
    let mut names = Vec::new();
    for _ in 0..count {
        let name = c
            .opt_string("attribute name")?
            .ok_or(HeaderError::NullName {
                field: "attribute name",
            })?;
        let attribute_type = c.u32("attribute type")?;
        match attribute_type {
            // A hashed string value: the 32-character hex of its unsalted
            // MD5, length-prefixed. Skipped, not kept.
            ATTR_TYPE_STRING => {
                let len = c.u32("attribute value")?;
                let len = c.count(len, 1, "attribute value")?;
                let _hashed = c.take(len, "attribute value")?;
            }
            ATTR_TYPE_UINT32 => {
                let _hashed = c.u32("attribute value")?;
            }
            other => {
                return Err(HeaderError::UnknownAttributeType {
                    item_id: id,
                    attribute_type: other,
                });
            }
        }
        names.push(name);
    }
    Ok(KeyringItemIndex {
        id,
        item_type,
        attribute_keys: AttributeKeys::from_names(names),
    })
}

/// The keyring named by `$XDG_DATA_HOME/keyrings/default`: a one-line
/// basename with no `.keyring` suffix.
///
/// The name becomes a *filename*, so it is validated as one. A `default`
/// containing `../../etc/passwd` is refused rather than resolved.
pub fn parse_default_file(contents: &str) -> Result<String, HeaderError> {
    let name = contents.lines().next().unwrap_or("").trim();
    // Trimmed again after the suffix is stripped, not only before it. A
    // `default` reading `Login  .keyring` otherwise yielded `Login  ` — an
    // accepted name that is not what feeding it back through this function
    // produces, so `<name>.keyring` and the name in a report disagreed about
    // the same keyring. The `import_keyring_header` fuzz target found this by
    // asserting the idempotence the caller relies on.
    let name = name.strip_suffix(".keyring").unwrap_or(name).trim_end();
    let rejected = name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0');
    if rejected {
        return Err(HeaderError::InvalidDefaultName);
    }
    Ok(name.to_string())
}

// --------------------------------------------------------------------------
// KWallet
// --------------------------------------------------------------------------

/// One folder's entry in a wallet's cleartext index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletFolderIndex {
    /// `MD5(folderName)`, opaque.
    pub folder_hash: Md5Hash,
    /// `MD5(entryName)` for each entry, in file order.
    pub entry_hashes: Vec<Md5Hash>,
}

impl WalletFolderIndex {
    pub fn entry_count(&self) -> usize {
        self.entry_hashes.len()
    }

    /// A folder a collection-of-items model has nowhere to put. Four of the
    /// 25 measured here; the report says how many were lost.
    pub fn is_empty(&self) -> bool {
        self.entry_hashes.is_empty()
    }
}

/// Everything a `.kwl` file yields without its password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletInventory {
    /// Cipher id from the header (`3` observed). Recorded, never acted on.
    pub cipher: u8,
    /// Hash id from the header (`2` observed).
    pub hash: u8,
    pub folders: Vec<WalletFolderIndex>,
    /// Where the encrypted half begins. Nothing beyond this offset is read.
    pub ciphertext_offset: usize,
}

impl WalletInventory {
    pub fn folder_count(&self) -> usize {
        self.folders.len()
    }

    /// The independent count, as for a keyring.
    pub fn entry_count(&self) -> usize {
        self.folders
            .iter()
            .map(WalletFolderIndex::entry_count)
            .sum()
    }

    pub fn empty_folder_count(&self) -> usize {
        self.folders.iter().filter(|f| f.is_empty()).count()
    }

    /// Whether the index holds this `(MD5(folder), MD5(entry))` pair.
    ///
    /// This is the stronger verification the spec asks for: recompute both
    /// hashes for every imported item and assert membership, proving no name
    /// was mangled using only hashes. Computing MD5 is a later agent's
    /// problem; comparing it is this type's.
    pub fn contains_entry(&self, folder_hash: &Md5Hash, entry_hash: &Md5Hash) -> bool {
        self.folders
            .iter()
            .filter(|f| &f.folder_hash == folder_hash)
            .any(|f| f.entry_hashes.contains(entry_hash))
    }
}

/// Parses the cleartext half of a KWallet `.kwl` file.
///
/// Refuses: a wrong magic; any version other than
/// [`KWALLET_MAJOR`].[`KWALLET_MINOR`] (minor 0 is the KWallet4 layout); a
/// truncation at any structural boundary; a folder or entry count claiming
/// more than the file holds.
///
/// All integers are big-endian.
pub fn parse_wallet_header(bytes: &[u8]) -> Result<WalletInventory, HeaderError> {
    let mut c = Cursor::new(bytes);
    if c.take(KWALLET_MAGIC.len(), "magic")? != KWALLET_MAGIC {
        return Err(HeaderError::BadMagic(Source::KWallet));
    }
    let major = c.u8("version")?;
    let minor = c.u8("version")?;
    let cipher = c.u8("version")?;
    let hash = c.u8("version")?;
    if (major, minor) != (KWALLET_MAJOR, KWALLET_MINOR) {
        return Err(HeaderError::UnsupportedVersion {
            format: Source::KWallet,
            major,
            minor,
            expected_major: KWALLET_MAJOR,
            expected_minor: KWALLET_MINOR,
        });
    }

    let declared = c.u32("folder count")?;
    let folder_count = c.count(declared, MIN_FOLDER_BYTES, "folder count")?;
    // See `parse_keyring_header`: reserving on a declared count is allocation
    // proportional to a number the attacker wrote, not to the file.
    let mut folders = Vec::new();
    for _ in 0..folder_count {
        let folder_hash = c.array16("folder name hash")?;
        let declared = c.u32("entry count")?;
        let entry_count = c.count(declared, 16, "entry count")?;
        let mut entry_hashes = Vec::new();
        for _ in 0..entry_count {
            entry_hashes.push(c.array16("entry name hash")?);
        }
        folders.push(WalletFolderIndex {
            folder_hash,
            entry_hashes,
        });
    }

    Ok(WalletInventory {
        cipher,
        hash,
        folders,
        ciphertext_offset: c.pos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // Byte-level builders, writing the layout this parser was written to.
    //
    // What these prove is limited, and the limit is worth stating: the
    // builders and the parser encode the *same* understanding of the
    // format, by the same author, so a wrong understanding makes both
    // wrong together and every test below still passes. They pin the
    // parser against change — a regression suite — and they do not
    // validate the format. Only bytes from a file this project did not
    // write could do that, and there are none here: a real keyring is
    // personal data and does not belong in a repository. Anyone with a
    // real `.keyring` or `.kwl` to hand should check an annotated
    // hexdump of its cleartext prefix against `keyring_prologue` and
    // `wallet_index` before trusting the layout.
    // ----------------------------------------------------------------

    #[derive(Default)]
    struct Bytes(Vec<u8>);

    impl Bytes {
        fn raw(mut self, b: &[u8]) -> Self {
            self.0.extend_from_slice(b);
            self
        }
        fn u8(self, v: u8) -> Self {
            self.raw(&[v])
        }
        fn u32(self, v: u32) -> Self {
            self.raw(&v.to_be_bytes())
        }
        fn u64(self, v: u64) -> Self {
            self.raw(&v.to_be_bytes())
        }
        fn str(self, s: &str) -> Self {
            self.u32(s.len() as u32).raw(s.as_bytes())
        }
        fn done(self) -> Vec<u8> {
            self.0
        }
    }

    /// A keyring header up to and including `num_items`.
    fn keyring_prologue(name: &str, iterations: u32, num_items: u32) -> Bytes {
        Bytes::default()
            .raw(&KEYRING_MAGIC)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .str(name)
            .u64(1_699_383_593)
            .u64(0)
            .u32(0)
            .u32(0)
            .u32(iterations)
            .raw(&[1, 2, 3, 4, 5, 6, 7, 8])
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(num_items)
    }

    fn hashed(name: &str) -> Bytes {
        // A string attribute: the name, type 0, then the 32-character hex of
        // an unsalted MD5. `d41d8cd9…` is MD5 of the empty string and really
        // does appear in the file measured here.
        Bytes::default()
            .str(name)
            .u32(ATTR_TYPE_STRING)
            .str("d41d8cd98f00b204e9800998ecf8427e")
    }

    /// The two-item keyring used by most cases below.
    fn keyring() -> Vec<u8> {
        let ciphertext = vec![0xAB; 32];
        keyring_prologue("Sample keyring", 3457, 2)
            // item 2: two string attributes, one of them the schema
            .u32(2)
            .u32(ITEM_TYPE_GENERIC_SECRET)
            .u32(2)
            .raw(&hashed("xdg:schema").done())
            .raw(&hashed("account").done())
            // item 5: a network password with a uint32 attribute
            .u32(5)
            .u32(ITEM_TYPE_NETWORK_PASSWORD)
            .u32(2)
            .raw(&hashed("server").done())
            .raw(
                &Bytes::default()
                    .str("port")
                    .u32(ATTR_TYPE_UINT32)
                    .u32(443)
                    .done(),
            )
            .u32(ciphertext.len() as u32)
            .raw(&ciphertext)
            .done()
    }

    fn wallet_index(folders: &[usize]) -> Vec<u8> {
        let mut b = Bytes::default()
            .raw(&KWALLET_MAGIC)
            .u8(0)
            .u8(1)
            .u8(3)
            .u8(2)
            .u32(folders.len() as u32);
        for (f, entries) in folders.iter().enumerate() {
            b = b.raw(&[f as u8; 16]).u32(*entries as u32);
            for e in 0..*entries {
                b = b.raw(&[(f * 16 + e) as u8; 16]);
            }
        }
        b.done()
    }

    // ----------------------------------------------------------------
    // Golden files
    // ----------------------------------------------------------------

    /// Committed fixtures. They are synthetic, built from the same layout
    /// knowledge as the parser, so they pin regressions and do not confirm
    /// the format; see the note on the builders above.
    #[test]
    fn the_golden_keyring_parses_to_exact_values() {
        let inv =
            parse_keyring_header(include_bytes!("../../tests/fixtures/import/sample.keyring"))
                .unwrap();
        assert_eq!(inv.display_name, "Sample keyring");
        assert_eq!(inv.created, 1_699_383_593);
        assert_eq!(inv.modified, 0);
        assert_eq!(inv.hash_iterations, 3457);
        assert_eq!(inv.lock_timeout, 0);
        assert_eq!(inv.item_count(), 3);
        assert_eq!(inv.items[0].id, 2);
        assert_eq!(inv.items[0].item_type, ITEM_TYPE_GENERIC_SECRET);
        assert_eq!(
            inv.items[0].attribute_keys,
            AttributeKeys::from_names(["account", "xdg:schema"])
        );
        assert_eq!(inv.items[1].item_type, ITEM_TYPE_NETWORK_PASSWORD);
        assert_eq!(
            inv.items[1].attribute_keys,
            AttributeKeys::from_names(["port", "server"])
        );
        assert!(inv.items[2].is_unlock_credential());
        assert_eq!(inv.unlock_credential_count(), 1);
        assert_eq!(
            inv.attribute_key_counts(),
            BTreeMap::from([
                ("account".to_string(), 1),
                ("keyring".to_string(), 1),
                ("port".to_string(), 1),
                ("server".to_string(), 1),
                ("xdg:schema".to_string(), 1),
            ])
        );
        // Nothing past here is ever read.
        assert_eq!(
            inv.ciphertext_offset + inv.ciphertext_len,
            include_bytes!("../../tests/fixtures/import/sample.keyring").len()
        );
    }

    #[test]
    fn the_golden_wallet_parses_to_exact_values() {
        let bytes = include_bytes!("../../tests/fixtures/import/sample.kwl");
        let inv = parse_wallet_header(bytes).unwrap();
        assert_eq!((inv.cipher, inv.hash), (3, 2));
        assert_eq!(inv.folder_count(), 3);
        assert_eq!(inv.entry_count(), 4);
        assert_eq!(inv.empty_folder_count(), 1);
        assert_eq!(
            inv.folders
                .iter()
                .map(|f| f.entry_count())
                .collect::<Vec<_>>(),
            [2, 0, 2]
        );
        // The arithmetic the real 75352-byte wallet satisfies: 16 bytes of
        // header, 4 of folder count, 20 per folder, 16 per entry.
        assert_eq!(inv.ciphertext_offset, 16 + 4 + 3 * 20 + 4 * 16);
        let f = &inv.folders[0];
        assert!(inv.contains_entry(&f.folder_hash, &f.entry_hashes[0]));
        assert!(!inv.contains_entry(&f.folder_hash, &[0xFF; 16]));
        // A hash present under a different folder is not a match.
        assert!(!inv.contains_entry(&inv.folders[2].folder_hash, &f.entry_hashes[0]));
    }

    // ----------------------------------------------------------------
    // gnome-keyring
    // ----------------------------------------------------------------

    #[test]
    fn a_well_formed_keyring_parses() {
        let inv = parse_keyring_header(&keyring()).unwrap();
        assert_eq!(inv.display_name, "Sample keyring");
        assert_eq!(inv.hash_iterations, 3457);
        assert_eq!(inv.salt, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(inv.item_count(), 2);
        assert_eq!(inv.ciphertext_len, 32);
        assert_eq!(inv.ciphertext_offset, keyring().len() - 32);
        assert_eq!(inv.unlock_credential_count(), 0);
    }

    #[test]
    fn a_zero_item_keyring_is_valid() {
        let bytes = keyring_prologue("Empty", 1166, 0).u32(0).done();
        let inv = parse_keyring_header(&bytes).unwrap();
        assert_eq!(inv.item_count(), 0);
        assert_eq!(inv.ciphertext_len, 0);
        assert_eq!(inv.ciphertext_offset, bytes.len());
        assert!(inv.attribute_key_counts().is_empty());
    }

    #[test]
    fn a_keyring_name_may_be_null() {
        let bytes = Bytes::default()
            .raw(&KEYRING_MAGIC)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .u32(u32::MAX)
            .u64(0)
            .u64(0)
            .u32(0)
            .u32(0)
            .u32(1)
            .raw(&[0; 8])
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .done();
        assert_eq!(parse_keyring_header(&bytes).unwrap().display_name, "");
    }

    /// The top-bit-set case, which is where reading this field signed used
    /// to turn a large timeout into `-1`.
    #[test]
    fn a_top_bit_set_lock_timeout_round_trips_unsigned() {
        let mut bytes = keyring_prologue("x", 1, 0).done();
        // `lock_timeout` sits 12 bytes before `hash_iterations`.
        let at = KEYRING_MAGIC.len() + 4 + 4 + 1 + 8 + 8 + 4;
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(parse_keyring_header(&bytes).unwrap().lock_timeout, u32::MAX);
    }

    #[test]
    fn a_wrong_magic_is_refused() {
        let mut bytes = keyring();
        bytes[0] = b'X';
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::BadMagic(Source::GnomeKeyring))
        );
        // And a file too short to hold a magic at all.
        assert!(matches!(
            parse_keyring_header(b"Gnome"),
            Err(HeaderError::Truncated { .. })
        ));
        assert!(matches!(
            parse_keyring_header(&[]),
            Err(HeaderError::Truncated { .. })
        ));
    }

    /// Format 0.0 is the only one whose layout was verified. Anything else is
    /// refused rather than parsed on the assumption that it is similar.
    #[test]
    fn any_version_but_zero_zero_is_refused() {
        for (major, minor) in [(0u8, 1u8), (1, 0), (1, 1), (255, 255)] {
            let mut bytes = keyring();
            bytes[16] = major;
            bytes[17] = minor;
            assert_eq!(
                parse_keyring_header(&bytes),
                Err(HeaderError::UnsupportedVersion {
                    format: Source::GnomeKeyring,
                    major,
                    minor,
                    expected_major: 0,
                    expected_minor: 0,
                })
            );
        }
        // The crypto and hash ids are read past, not validated: they describe
        // the encrypted half, which is never touched.
        let mut bytes = keyring();
        bytes[18] = 9;
        bytes[19] = 9;
        assert!(parse_keyring_header(&bytes).is_ok());
    }

    /// Every structural boundary, not just the interesting ones: a parser
    /// that survives 900 truncations survives the one that happens.
    #[test]
    fn a_keyring_truncated_anywhere_is_an_error_and_never_a_panic() {
        let full = keyring();
        for n in 0..full.len() {
            match parse_keyring_header(&full[..n]) {
                Err(HeaderError::Truncated { .. }) | Err(HeaderError::ImpossibleLength { .. }) => {}
                other => panic!("truncating to {n} bytes gave {other:?}"),
            }
        }
        assert!(parse_keyring_header(&full).is_ok());
    }

    /// The check that keeps allocation proportional to the file and not to a
    /// number an attacker wrote.
    #[test]
    fn an_item_count_larger_than_the_file_is_refused_before_allocating() {
        let bytes = keyring_prologue("x", 1, u32::MAX).done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "item count",
                declared: u64::from(u32::MAX),
            })
        );
        // One item needs 12 bytes; a file with 11 spare cannot hold one.
        let bytes = keyring_prologue("x", 1, 1).raw(&[0; 11]).done();
        assert!(matches!(
            parse_keyring_header(&bytes),
            Err(HeaderError::ImpossibleLength { .. })
        ));
    }

    #[test]
    fn an_attribute_count_larger_than_the_file_is_refused() {
        let bytes = keyring_prologue("x", 1, 1)
            .u32(1)
            .u32(0)
            .u32(0x0F00_0000)
            .done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "attribute count",
                declared: 0x0F00_0000,
            })
        );
    }

    #[test]
    fn a_string_length_larger_than_the_file_is_refused() {
        // The keyring name claims 4 GiB.
        let bytes = Bytes::default()
            .raw(&KEYRING_MAGIC)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .u32(u32::MAX - 1)
            .done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "keyring name",
                declared: u64::from(u32::MAX - 1),
            })
        );
        // And an attribute name doing the same.
        let bytes = keyring_prologue("x", 1, 1)
            .u32(1)
            .u32(0)
            .u32(1)
            .u32(1 << 30)
            // Enough spare bytes that the attribute *count* check passes and
            // the name length is what fails.
            .raw(&[0; 12])
            .done();
        assert!(matches!(
            parse_keyring_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "attribute name",
                ..
            })
        ));
    }

    #[test]
    fn a_ciphertext_length_larger_than_the_file_is_refused() {
        let bytes = keyring_prologue("x", 1, 0).u32(1 << 20).done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "ciphertext length",
                declared: 1 << 20,
            })
        );
    }

    #[test]
    fn a_non_utf8_name_is_an_error_rather_than_a_lossy_conversion() {
        let bytes = Bytes::default()
            .raw(&KEYRING_MAGIC)
            .u8(0)
            .u8(0)
            .u8(0)
            .u8(0)
            .u32(2)
            .raw(&[0xFF, 0xFE])
            .done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::NonUtf8 {
                field: "keyring name"
            })
        );
        let bytes = keyring_prologue("x", 1, 1)
            .u32(1)
            .u32(0)
            .u32(1)
            .u32(2)
            .raw(&[0xFF, 0xFE])
            .u32(ATTR_TYPE_UINT32)
            .u32(0)
            .u32(0)
            .done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::NonUtf8 {
                field: "attribute name"
            })
        );
    }

    #[test]
    fn an_unknown_attribute_type_is_refused() {
        let bytes = keyring_prologue("x", 1, 1)
            .u32(7)
            .u32(0)
            .u32(1)
            .raw(&Bytes::default().str("k").u32(2).u32(0).done())
            .u32(0)
            .done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::UnknownAttributeType {
                item_id: 7,
                attribute_type: 2,
            })
        );
    }

    /// A NULL name is not a decoding failure: the bytes decoded fine, there
    /// were none. Reporting it as `NonUtf8` sends the reader hunting an
    /// encoding bug that does not exist.
    #[test]
    fn a_null_attribute_name_is_refused_as_null_and_not_as_bad_utf8() {
        let bytes = keyring_prologue("x", 1, 1)
            .u32(7)
            .u32(0)
            .u32(1)
            .u32(u32::MAX)
            .u32(ATTR_TYPE_UINT32)
            .u32(0)
            .u32(0)
            .done();
        assert_eq!(
            parse_keyring_header(&bytes),
            Err(HeaderError::NullName {
                field: "attribute name"
            })
        );
    }

    #[test]
    fn duplicate_attribute_names_collapse_into_a_set() {
        let bytes = keyring_prologue("x", 1, 1)
            .u32(1)
            .u32(0)
            .u32(2)
            .raw(&hashed("service").done())
            .raw(&hashed("service").done())
            .u32(0)
            .done();
        let inv = parse_keyring_header(&bytes).unwrap();
        assert_eq!(inv.items[0].attribute_keys.len(), 1);
    }

    // ----------------------------------------------------------------
    // The `default` file
    // ----------------------------------------------------------------

    #[test]
    fn the_default_file_names_a_basename() {
        assert_eq!(
            parse_default_file("Default_keyring\n").unwrap(),
            "Default_keyring"
        );
        assert_eq!(parse_default_file("login.keyring").unwrap(), "login");
        assert_eq!(
            parse_default_file("  spaced  \nignored\n").unwrap(),
            "spaced"
        );
    }

    /// Stripping `.keyring` can uncover whitespace the first trim could not
    /// see. Returning `login  ` there would be a name that does not survive
    /// being read back — the same keyring under two spellings.
    #[test]
    fn whitespace_uncovered_by_the_suffix_is_trimmed_too() {
        assert_eq!(parse_default_file("login  .keyring").unwrap(), "login");
        assert_eq!(
            parse_default_file("  login  .keyring  \n").unwrap(),
            "login"
        );
        assert_eq!(
            parse_default_file(" .keyring"),
            Err(HeaderError::InvalidDefaultName)
        );
        for text in ["login  .keyring", "  login \t.keyring", "login"] {
            let once = parse_default_file(text).unwrap();
            assert_eq!(parse_default_file(&once).unwrap(), once, "{text:?}");
        }
    }

    /// The name becomes a filename, so a traversal is refused rather than
    /// resolved.
    #[test]
    fn a_default_file_naming_a_path_is_refused() {
        for bad in [
            "",
            "\n",
            "   ",
            ".",
            "..",
            "../../etc/passwd",
            "/etc/passwd",
            "a\\b",
            "a\0b",
            ".keyring",
        ] {
            assert_eq!(
                parse_default_file(bad),
                Err(HeaderError::InvalidDefaultName),
                "{bad:?}"
            );
        }
    }

    // ----------------------------------------------------------------
    // KWallet
    // ----------------------------------------------------------------

    #[test]
    fn a_well_formed_wallet_parses() {
        let bytes = wallet_index(&[2, 0, 1]);
        let inv = parse_wallet_header(&bytes).unwrap();
        assert_eq!(inv.folder_count(), 3);
        assert_eq!(inv.entry_count(), 3);
        assert_eq!(inv.empty_folder_count(), 1);
        assert_eq!(inv.ciphertext_offset, bytes.len());
    }

    /// The arithmetic of the real file: 75352 bytes, 25 folders, 66 entries,
    /// 4 of them empty, ciphertext at 1576. `16 + 4 + 25*20 + 66*16 == 1576`.
    #[test]
    fn the_measured_wallet_geometry_holds() {
        let mut folders = vec![3usize; 21];
        folders.extend([0, 0, 0, 0]);
        assert_eq!(folders.len(), 25);
        assert_eq!(folders.iter().sum::<usize>(), 63);
        folders[0] += 3;
        let bytes = wallet_index(&folders);
        let inv = parse_wallet_header(&bytes).unwrap();
        assert_eq!(inv.folder_count(), 25);
        assert_eq!(inv.entry_count(), 66);
        assert_eq!(inv.empty_folder_count(), 4);
        assert_eq!(inv.ciphertext_offset, 1576);
    }

    #[test]
    fn a_zero_folder_wallet_is_valid() {
        let inv = parse_wallet_header(&wallet_index(&[])).unwrap();
        assert_eq!(inv.folder_count(), 0);
        assert_eq!(inv.entry_count(), 0);
        assert_eq!(inv.ciphertext_offset, 20);
    }

    #[test]
    fn a_wrong_wallet_magic_is_refused() {
        let mut bytes = wallet_index(&[1]);
        bytes[3] = b'X';
        assert_eq!(
            parse_wallet_header(&bytes),
            Err(HeaderError::BadMagic(Source::KWallet))
        );
        assert!(matches!(
            parse_wallet_header(b"KWAL"),
            Err(HeaderError::Truncated { .. })
        ));
    }

    /// Minor 0 is the KWallet4 layout, which is a different file entirely.
    #[test]
    fn any_wallet_version_but_zero_one_is_refused() {
        for (major, minor) in [(0u8, 0u8), (0, 2), (1, 1), (255, 255)] {
            let mut bytes = wallet_index(&[1]);
            bytes[12] = major;
            bytes[13] = minor;
            assert_eq!(
                parse_wallet_header(&bytes),
                Err(HeaderError::UnsupportedVersion {
                    format: Source::KWallet,
                    major,
                    minor,
                    expected_major: 0,
                    expected_minor: 1,
                })
            );
        }
    }

    #[test]
    fn a_wallet_truncated_anywhere_is_an_error_and_never_a_panic() {
        let full = wallet_index(&[2, 0, 3]);
        for n in 0..full.len() {
            match parse_wallet_header(&full[..n]) {
                Err(HeaderError::Truncated { .. }) | Err(HeaderError::ImpossibleLength { .. }) => {}
                other => panic!("truncating to {n} bytes gave {other:?}"),
            }
        }
        assert!(parse_wallet_header(&full).is_ok());
    }

    /// `folderCount` is the one field that could overflow an allocation: 20
    /// bytes each times `u32::MAX` is 85 GB.
    #[test]
    fn a_folder_count_that_would_overflow_is_refused() {
        let bytes = Bytes::default()
            .raw(&KWALLET_MAGIC)
            .u8(0)
            .u8(1)
            .u8(3)
            .u8(2)
            .u32(u32::MAX)
            .done();
        assert_eq!(
            parse_wallet_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "folder count",
                declared: u64::from(u32::MAX),
            })
        );
        // And the same one element over the edge: 20 bytes of body is one
        // folder's worth, so two is impossible.
        let bytes = Bytes::default()
            .raw(&KWALLET_MAGIC)
            .u8(0)
            .u8(1)
            .u8(3)
            .u8(2)
            .u32(2)
            .raw(&[0; 20])
            .done();
        assert!(matches!(
            parse_wallet_header(&bytes),
            Err(HeaderError::ImpossibleLength { .. })
        ));
    }

    #[test]
    fn an_entry_count_larger_than_the_file_is_refused() {
        let bytes = Bytes::default()
            .raw(&KWALLET_MAGIC)
            .u8(0)
            .u8(1)
            .u8(3)
            .u8(2)
            .u32(1)
            .raw(&[7; 16])
            .u32(u32::MAX)
            .done();
        assert_eq!(
            parse_wallet_header(&bytes),
            Err(HeaderError::ImpossibleLength {
                field: "entry count",
                declared: u64::from(u32::MAX),
            })
        );
    }

    // ----------------------------------------------------------------

    #[test]
    fn a_file_over_the_size_cap_is_refused_from_its_stat_size() {
        assert_eq!(check_source_size(MAX_SOURCE_BYTES), Ok(()));
        assert_eq!(
            check_source_size(MAX_SOURCE_BYTES + 1),
            Err(HeaderError::FileTooLarge(MAX_SOURCE_BYTES + 1))
        );
    }

    #[test]
    fn unlock_credentials_are_the_two_chained_types() {
        assert!(is_unlock_credential(ITEM_TYPE_CHAINED_KEYRING_PASSWORD));
        assert!(is_unlock_credential(ITEM_TYPE_ENCRYPTION_KEY_PASSWORD));
        for t in [
            ITEM_TYPE_GENERIC_SECRET,
            ITEM_TYPE_NETWORK_PASSWORD,
            ITEM_TYPE_NOTE,
            5,
            u32::MAX,
        ] {
            assert!(!is_unlock_credential(t));
        }
    }

    #[test]
    fn errors_name_the_source_and_the_field() {
        assert_eq!(
            HeaderError::BadMagic(Source::KWallet).to_string(),
            "not a kwallet file (bad magic)"
        );
        let text = HeaderError::UnsupportedVersion {
            format: Source::GnomeKeyring,
            major: 1,
            minor: 2,
            expected_major: 0,
            expected_minor: 0,
        }
        .to_string();
        assert!(text.contains("gnome-keyring format version 1.2"), "{text}");
        assert!(
            HeaderError::Truncated { field: "salt" }
                .to_string()
                .contains("ends inside the salt")
        );
        assert!(
            HeaderError::ImpossibleLength {
                field: "item count",
                declared: 9,
            }
            .to_string()
            .contains("claims 9 entries")
        );
    }
}
