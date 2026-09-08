//! Live extraction from KWallet, over `org.kde.kwalletd6`.
//!
//! KWallet's own service is a different bus name from
//! `org.freedesktop.secrets`, so this path needs no private bus and no
//! ordering against our daemon. This module owns the blind, total walk —
//! `wallets()`, `openAsync(name, 0, "secret-manager-import", false)`,
//! `walletAsyncOpened`, `folderList`, `entryList`, `entryType`,
//! `readPassword`/`readMap`/`readEntry` — and the `kdewallet_attributes.json`
//! sidecar that carries every attribute, content type and timestamp in clear.
//!
//! The `.kwl` cleartext index parser lives in [`super::formats`]; nothing
//! here decrypts a wallet.
//!
//! # Only the secret bytes need the wallet open
//!
//! `~/.local/share/kwalletd/<wallet>_attributes.json` is written by
//! `ksecretd`, KWallet's Secret Service bridge, because the wallet format has
//! nowhere to put an attribute map and the Secret Service API requires
//! attribute lookup on a *locked* collection. It is unencrypted, mode `0600`,
//! and keyed by `"<folder>/<entry>"`. It is therefore the source of `created`,
//! `modified` and `content_type` — none of which the `org.kde.KWallet` D-Bus
//! API exposes at all — and of the attribute map itself. The wallet is opened
//! for one reason only: the secret bytes.
//!
//! # The sidecar key is built, never parsed
//!
//! Both folder names and entry names may contain `/` — this author's own
//! wallet holds `ksshaskpass//home/joseph/.ssh/aur` and
//! `Registry credentials for https://index.docker.io/v1/`. Splitting a
//! sidecar key on `/` therefore cannot recover `(folder, entry)`. The walk
//! goes the other way: it has the folder and the entry from `folderList` and
//! `entryList`, and *composes* the lookup key with [`sidecar_key`]. Rows the
//! walk never composes a key for are reported by
//! [`Extraction::unresolved_sidecar_rows`] rather than dropped.
//!
//! # Nothing here logs a secret, and nothing logs an attribute value
//!
//! Secret bytes live in [`Zeroizing`] from the moment they leave zbus.
//! [`SidecarEntry`]'s `Debug` prints attribute *names* only, for the same
//! reason [`super::SourceItem`]'s does: `server=`, `user=` and `url=` have no
//! business in a log line. Everything this module reads — a wallet file, a
//! JSON sidecar, a D-Bus reply — is attacker-influenced, so every length is
//! bounded before it is allocated and every parse returns a typed error
//! instead of panicking.

use super::{Provenance, Refusal, SourceItem, XDG_SCHEMA, check_caps};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The bus name KWallet 6 owns. Deliberately *not* `org.kde.kwalletd5`: the
/// same process owns both here, but the 5 name is a compatibility alias and
/// may be answered by an older daemon on a mixed system.
pub const SERVICE: &str = "org.kde.kwalletd6";

/// The one object that exports `org.kde.KWallet`.
pub const OBJECT_PATH: &str = "/modules/kwalletd6";

/// The application id every call carries.
///
/// This becomes **persistent state** in the wallet's per-application access
/// list — it survives the import and the user will see it in KWallet's
/// configuration afterwards — so it is stable and honest rather than
/// randomised or borrowed from another application.
pub const APP_ID: &str = "secret-manager-import";

/// `wId` for a process with no window. KWallet uses it only to parent the
/// unlock dialog.
pub const NO_WINDOW: i64 = 0;

/// How long [`open_wallet`] waits for `walletAsyncOpened` before giving up.
///
/// The bound exists because the failure it guards is a *hang*, not an error:
/// `openAsync` returns a transaction id immediately whether or not anything
/// can ever answer the unlock dialog, and a blocked import with no output is
/// the worst outcome available. Two minutes is long enough for a user to find
/// the dialog and type a password.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest sidecar this module will read into memory. The measured file
/// is 21 KiB for 66 entries; 16 MiB is four orders of magnitude of headroom
/// and still a bound.
pub const MAX_SIDECAR_BYTES: u64 = 16 << 20;

/// The largest number of rows a sidecar may declare.
pub const MAX_SIDECAR_ROWS: usize = 100_000;

/// The largest number of entries a serialised `QMap` may declare, checked
/// before anything is allocated for it.
pub const MAX_MAP_ENTRIES: usize = 4096;

/// The largest number of entries one walk will produce, across all folders.
/// A wallet larger than this is not a wallet, it is a denial of service.
pub const MAX_ENTRIES: usize = 200_000;

/// Attribute recording the KWallet folder. See
/// [`the `kwallet:` prefix`](self#the-kwallet-prefix-is-added-only-where-it-is-free).
pub const ATTR_FOLDER: &str = "kwallet:folder";
/// Attribute recording the KWallet entry name.
pub const ATTR_KEY: &str = "kwallet:key";
/// Attribute recording the KWallet entry type.
pub const ATTR_TYPE: &str = "kwallet:type";

/// Sidecar field holding the creation time, as a decimal string of Unix
/// seconds.
pub const FDO_CREATED: &str = "$fdo_created";
/// Sidecar field holding the modification time.
pub const FDO_MODIFIED: &str = "$fdo_modified";
/// Sidecar field holding the content type.
pub const FDO_MIME_TYPE: &str = "$fdo_mime_type";
/// Sidecar field holding the libsecret attribute map.
pub const FDO_ATTRIBUTES: &str = "attributes";

const CT_PASSWORD: &str = "text/plain";
const CT_STREAM: &str = "application/octet-stream";
const CT_MAP: &str = "application/json";

// ---------------------------------------------------------------------------
// Entry types
// ---------------------------------------------------------------------------

/// KWallet's entry type, as `entryType` returns it.
///
/// The numbering is **not inferred**: it is `KWallet::Wallet::EntryType` from
/// `/usr/include/KF6/KWallet/kwallet.h`, which reads
/// `Unknown = 0, Password, Stream, Map, Unused = 0xffff`. Anything else is
/// kept as [`EntryType::Other`] rather than collapsed, so an entry from a
/// future KWallet is still copied — as opaque bytes, which is the honest
/// reading of a type we do not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryType {
    Unknown,
    Password,
    Stream,
    Map,
    Other(i32),
}

impl EntryType {
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => EntryType::Unknown,
            1 => EntryType::Password,
            2 => EntryType::Stream,
            3 => EntryType::Map,
            other => EntryType::Other(other),
        }
    }

    pub const fn code(self) -> i32 {
        match self {
            EntryType::Unknown => 0,
            EntryType::Password => 1,
            EntryType::Stream => 2,
            EntryType::Map => 3,
            EntryType::Other(n) => n,
        }
    }

    /// The value of the `kwallet:type` attribute. `Other` renders as its
    /// number so nothing is silently flattened into `unknown`.
    pub fn attribute_value(self) -> String {
        match self {
            EntryType::Unknown => "unknown".into(),
            EntryType::Password => "password".into(),
            EntryType::Stream => "stream".into(),
            EntryType::Map => "map".into(),
            EntryType::Other(n) => n.to_string(),
        }
    }

    /// The content type implied by the entry type alone, before the sidecar
    /// is consulted. An entry whose type KWallet itself does not know is
    /// bytes.
    pub const fn default_content_type(self) -> &'static str {
        match self {
            EntryType::Password => CT_PASSWORD,
            EntryType::Map => CT_MAP,
            EntryType::Stream | EntryType::Unknown | EntryType::Other(_) => CT_STREAM,
        }
    }
}

impl fmt::Display for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.attribute_value())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a sidecar could not be read at all. A *row* that is malformed is not
/// an error — see [`Sidecar::skipped_rows`] — because one bad row must not
/// cost the user 65 good ones.
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("cannot read the KWallet attribute sidecar {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the KWallet attribute sidecar {path} is {len} bytes, over the {limit} byte limit")]
    TooLarge { path: PathBuf, len: u64, limit: u64 },
    #[error("the KWallet attribute sidecar {path} is not valid JSON: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("the KWallet attribute sidecar {path} is not a JSON object")]
    NotAnObject { path: PathBuf },
    #[error("the KWallet attribute sidecar {path} declares {rows} rows, over the {limit} limit")]
    TooManyRows {
        path: PathBuf,
        rows: usize,
        limit: usize,
    },
}

/// Why a serialised `QMap<QString, QString>` could not be decoded.
///
/// Every variant is a refusal to guess. A wrong decode writes corrupted data
/// into the vault and reports success, which is strictly worse than not
/// importing the entry at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapDecodeError {
    #[error("the serialised map ends inside the {field}")]
    Truncated { field: &'static str },
    #[error("the serialised map declares {declared} pairs, more than the {} bytes can hold", .available)]
    ImpossibleCount { declared: u32, available: usize },
    #[error("the serialised map declares {declared} pairs, over the {limit} limit")]
    TooManyPairs { declared: usize, limit: usize },
    #[error("a string in the serialised map has an odd byte length ({len}) and cannot be UTF-16")]
    OddStringLength { len: usize },
    #[error("a string in the serialised map is not valid UTF-16")]
    BadUtf16,
    #[error("a key appears twice in the serialised map, which a QMap cannot produce")]
    DuplicateKey,
    #[error("{trailing} bytes remain after the serialised map, so this is not a QMap")]
    TrailingBytes { trailing: usize },
    #[error("the serialised map could not be re-encoded as JSON: {0}")]
    Json(String),
}

/// Everything that can stop the KWallet walk.
#[derive(Debug, thiserror::Error)]
pub enum KWalletError {
    #[error(
        "kwalletd6 does not own {SERVICE} on the session bus; KWallet is not running, so there \
         is nothing to import from"
    )]
    ServiceUnavailable,
    #[error("KWallet has no wallet named {wallet}")]
    NoSuchWallet { wallet: String },
    #[error(
        "the wallet {wallet} is closed and there is no display for KWallet's unlock dialog \
         (neither DISPLAY nor WAYLAND_DISPLAY is set). The dialog is a Qt widget and cannot \
         appear over a bare SSH session: open the wallet in a graphical session first, or run \
         the import there"
    )]
    NoDisplay { wallet: String },
    #[error("KWallet refused to open the wallet {wallet} (returned {code})")]
    OpenRefused { wallet: String, code: i32 },
    #[error(
        "KWallet did not open the wallet {wallet} within {timeout:?}: the unlock dialog is \
         probably waiting for an answer nobody can give"
    )]
    OpenTimedOut { wallet: String, timeout: Duration },
    #[error("the walk produced more than {limit} entries, which is not a wallet")]
    TooManyEntries { limit: usize },
    #[error(transparent)]
    Sidecar(#[from] SidecarError),
    #[error("KWallet D-Bus call failed: {0}")]
    Dbus(#[from] zbus::Error),
    /// A `org.freedesktop.DBus` call — only the name-owner check — failed.
    #[error("the session bus refused a request: {0}")]
    Bus(#[from] zbus::fdo::Error),
}

// ---------------------------------------------------------------------------
// The sidecar
// ---------------------------------------------------------------------------

/// One row of `<wallet>_attributes.json`.
///
/// Every field is optional because every field is optional *in practice*: of
/// the 66 rows measured here, 10 have no `$fdo_mime_type`. A missing
/// timestamp becomes `0` rather than `now()` — see [`super::SourceItem`] for
/// why an import must never stamp its own clock onto the user's items.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SidecarEntry {
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub content_type: Option<String>,
    /// The libsecret attribute map, verbatim. Values are carried but never
    /// printed.
    pub attributes: BTreeMap<String, String>,
    /// Fields this row declared that could not be used: a `$fdo_created` that
    /// is not a number, an `attributes` that is not an object, an attribute
    /// whose value is not a string. Counted rather than guessed at.
    pub malformed_fields: usize,
}

// Hand-written for the same reason `SourceItem`'s is: an attribute *value* is
// `server=`/`user=`/`url=` and must not reach a log line.
impl fmt::Debug for SidecarEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SidecarEntry")
            .field("created", &self.created)
            .field("modified", &self.modified)
            .field("content_type", &self.content_type)
            .field(
                "attribute_keys",
                &self.attributes.keys().collect::<Vec<_>>(),
            )
            .field("malformed_fields", &self.malformed_fields)
            .finish()
    }
}

/// A parsed `<wallet>_attributes.json`.
#[derive(Debug, Clone, Default)]
pub struct Sidecar {
    entries: BTreeMap<String, SidecarEntry>,
    skipped_rows: usize,
}

impl Sidecar {
    /// An empty sidecar: what a wallet that was never touched by `ksecretd`
    /// has. Not an error — such a wallet's entries simply have no attributes,
    /// which is exactly [`super::Outcome::PreservedOnly`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Reads and parses `path`, or yields [`Sidecar::empty`] if it does not
    /// exist.
    pub fn load(path: &Path) -> Result<Self, SidecarError> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(source) => {
                return Err(SidecarError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        // Bound before reading, not after: the point of the limit is to not
        // allocate the file.
        if meta.len() > MAX_SIDECAR_BYTES {
            return Err(SidecarError::TooLarge {
                path: path.to_path_buf(),
                len: meta.len(),
                limit: MAX_SIDECAR_BYTES,
            });
        }
        let text = std::fs::read_to_string(path).map_err(|source| SidecarError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text, path)
    }

    /// Parses sidecar JSON. `path` is used only for error messages.
    ///
    /// The root object is **not** uniformly `"<folder>/<entry>" -> object`:
    /// the real file also carries wallet-level `$fdo_created` and
    /// `$fdo_modified` as bare strings at the root. Those are not entries and
    /// are not an error; they are counted in [`Sidecar::skipped_rows`].
    pub fn parse(text: &str, path: &Path) -> Result<Self, SidecarError> {
        let root: serde_json::Value =
            serde_json::from_str(text).map_err(|source| SidecarError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        let serde_json::Value::Object(rows) = root else {
            return Err(SidecarError::NotAnObject {
                path: path.to_path_buf(),
            });
        };
        if rows.len() > MAX_SIDECAR_ROWS {
            return Err(SidecarError::TooManyRows {
                path: path.to_path_buf(),
                rows: rows.len(),
                limit: MAX_SIDECAR_ROWS,
            });
        }

        let mut entries = BTreeMap::new();
        let mut skipped_rows = 0usize;
        for (key, value) in rows {
            let serde_json::Value::Object(row) = value else {
                skipped_rows += 1;
                continue;
            };
            entries.insert(key, parse_row(&row));
        }
        Ok(Self {
            entries,
            skipped_rows,
        })
    }

    /// The row for `"<folder>/<entry>"`, composed by [`sidecar_key`].
    pub fn get(&self, key: &str) -> Option<&SidecarEntry> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Root values that were not objects, so cannot be entries. The wallet's
    /// own `$fdo_created`/`$fdo_modified` are two of these in every real
    /// file.
    pub fn skipped_rows(&self) -> usize {
        self.skipped_rows
    }

    /// The row keys, so a caller can diff them against what the walk resolved.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

fn parse_row(row: &serde_json::Map<String, serde_json::Value>) -> SidecarEntry {
    let mut malformed_fields = 0usize;

    let mut timestamp = |field: &str| match row.get(field) {
        None => None,
        // The real file writes these as decimal *strings*. A number is
        // accepted too rather than refused: it costs nothing and a future
        // ksecretd may write one.
        Some(serde_json::Value::String(s)) => match s.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => {
                malformed_fields += 1;
                None
            }
        },
        Some(serde_json::Value::Number(n)) => match n.as_u64() {
            Some(n) => Some(n),
            None => {
                malformed_fields += 1;
                None
            }
        },
        Some(_) => {
            malformed_fields += 1;
            None
        }
    };
    let created = timestamp(FDO_CREATED);
    let modified = timestamp(FDO_MODIFIED);

    let content_type = match row.get(FDO_MIME_TYPE) {
        None => None,
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        // An empty string is a present-but-useless value, not a malformed
        // one: it says nothing, so the entry type decides instead.
        Some(serde_json::Value::String(_)) => None,
        Some(_) => {
            malformed_fields += 1;
            None
        }
    };

    let mut attributes = BTreeMap::new();
    match row.get(FDO_ATTRIBUTES) {
        None => {}
        Some(serde_json::Value::Object(map)) => {
            for (k, v) in map {
                match v {
                    serde_json::Value::String(s) => {
                        attributes.insert(k.clone(), s.clone());
                    }
                    // A non-string attribute value cannot be copied verbatim,
                    // and stringifying it would invent an attribute. Dropped
                    // and counted.
                    _ => malformed_fields += 1,
                }
            }
        }
        Some(_) => malformed_fields += 1,
    }

    SidecarEntry {
        created,
        modified,
        content_type,
        attributes,
        malformed_fields,
    }
}

/// The sidecar path for a wallet: `$XDG_DATA_HOME/kwalletd/<wallet>_attributes.json`.
pub fn sidecar_path(wallet: &str) -> PathBuf {
    kwalletd_dir().join(format!("{wallet}_attributes.json"))
}

/// `$XDG_DATA_HOME/kwalletd`, with the XDG fallback.
pub fn kwalletd_dir() -> PathBuf {
    match std::env::var_os("XDG_DATA_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => crate::config::home_dir().join(".local/share"),
    }
    .join("kwalletd")
}

/// The sidecar lookup key for an entry.
///
/// Composed, never parsed back: see the module docs for why splitting on `/`
/// cannot work.
pub fn sidecar_key(folder: &str, entry: &str) -> String {
    format!("{folder}/{entry}")
}

// ---------------------------------------------------------------------------
// QDataStream QMap<QString, QString>
// ---------------------------------------------------------------------------

/// Decodes the `QDataStream`-serialised `QMap<QString, QString>` that
/// `readMap` returns, into the wire-order pairs.
///
/// # Why this can be decoded rather than guessed at
///
/// `KWallet::Wallet::writeMap` does `QDataStream ds(&a, QIODevice::WriteOnly);
/// ds << value;` on a default-constructed stream and hands the bytes to
/// `writeEntry`. A default `QDataStream` is **big-endian** and writes no
/// header of its own, and the two operators involved have been
/// wire-compatible since Qt 4.0:
///
/// * `QMap` → `quint32 size`, then `size` (key, value) pairs. Qt writes them
///   in *reverse* key order so that replaying them into a map reproduces it;
///   that only affects the order pairs arrive in, which is why this function
///   returns them in wire order and lets the caller sort.
/// * `QString` → `quint32 byteLen`, then `byteLen` bytes of UTF-16 in the
///   stream's byte order. `0xFFFFFFFF` is the null string, distinct from the
///   empty string's `0`.
///
/// So the format is established, not inferred. What makes the decode *safe*
/// is that every one of those facts is then checked against the bytes: the
/// declared pair count must fit in the remaining bytes, each string length
/// must be even and in range, every code unit sequence must be valid UTF-16,
/// no key may repeat (a `QMap` cannot produce that), and the buffer must be
/// consumed **exactly**. A stream that is not this format fails at least one
/// of those, and a failure refuses the entry rather than writing a guess.
pub fn decode_qmap(bytes: &[u8]) -> Result<Vec<(String, String)>, MapDecodeError> {
    let mut r = Reader::new(bytes);
    let declared = r.u32("pair count")?;
    // Every pair is two strings, each at least a 4-byte length. Reject an
    // impossible count before reserving anything for it.
    let min_bytes = (declared as u64).saturating_mul(8);
    if min_bytes > r.remaining() as u64 {
        return Err(MapDecodeError::ImpossibleCount {
            declared,
            available: r.remaining(),
        });
    }
    let count = declared as usize;
    if count > MAX_MAP_ENTRIES {
        return Err(MapDecodeError::TooManyPairs {
            declared: count,
            limit: MAX_MAP_ENTRIES,
        });
    }

    let mut pairs = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let key = r.qstring("map key")?;
        let value = r.qstring("map value")?;
        if !seen.insert(key.clone()) {
            return Err(MapDecodeError::DuplicateKey);
        }
        pairs.push((key, value));
    }
    if r.remaining() != 0 {
        return Err(MapDecodeError::TrailingBytes {
            trailing: r.remaining(),
        });
    }
    Ok(pairs)
}

/// Canonical JSON for a decoded map: an object with keys in sorted order and
/// no insignificant whitespace, so re-importing the same wallet produces the
/// same bytes.
///
/// The pairs are borrowed rather than moved so the caller keeps ownership of
/// the plaintext and can zeroize it; see [`read_map_secret`].
pub fn qmap_to_canonical_json(
    pairs: &[(String, String)],
) -> Result<Zeroizing<Vec<u8>>, MapDecodeError> {
    let canonical: BTreeMap<&str, &str> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    serde_json::to_vec(&canonical)
        .map(Zeroizing::new)
        .map_err(|e| MapDecodeError::Json(e.to_string()))
}

/// [`decode_qmap`] then [`qmap_to_canonical_json`], zeroizing the decoded
/// plaintext on the way out.
///
/// The intermediate `String`s hold the map's values, which are secret. They
/// are wiped here rather than left to the allocator, which is the whole
/// reason this wrapper exists instead of the caller chaining the two.
pub fn read_map_secret(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, MapDecodeError> {
    let mut pairs = decode_qmap(bytes)?;
    let json = qmap_to_canonical_json(&pairs);
    for (k, v) in &mut pairs {
        k.zeroize();
        v.zeroize();
    }
    json
}

/// A bounds-checked cursor. Every read names the field it was reading so a
/// truncation says where.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], MapDecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.bytes.len())
            .ok_or(MapDecodeError::Truncated { field })?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, MapDecodeError> {
        let b = self.take(4, field)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn qstring(&mut self, field: &'static str) -> Result<String, MapDecodeError> {
        let len = self.u32(field)?;
        // Qt's null QString. Not the same as an empty one on the wire; both
        // become an empty Rust `String`, which is the only representation we
        // have and which round-trips through JSON identically.
        if len == u32::MAX {
            return Ok(String::new());
        }
        let len = len as usize;
        if !len.is_multiple_of(2) {
            return Err(MapDecodeError::OddStringLength { len });
        }
        let raw = self.take(len, field)?;
        let units = raw
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]));
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| MapDecodeError::BadUtf16)
    }
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/// Builds the [`SourceItem`] for one entry.
///
/// This is the whole of the spec's mapping table, in one pure function so the
/// decision it encodes can be tested without a wallet:
///
/// | KWallet | secret-manager |
/// |---|---|
/// | wallet | collection (the caller's, recorded in [`Provenance`]) |
/// | folder | attribute `kwallet:folder` |
/// | entry name | `label`, plus attribute `kwallet:key` |
/// | entry type | attribute `kwallet:type` |
/// | `$fdo_created` / `$fdo_modified` | `created` / `modified` |
/// | `$fdo_mime_type` | `content_type` |
/// | sidecar `attributes` | merged verbatim |
///
/// # The `kwallet:` prefix is added only where it is free
///
/// Adding `kwallet:folder` to an item's attribute map **changes its
/// identity**: our `replace` semantics compare whole maps for equality, so an
/// item libsecret wrote and would recognise becomes one it does not. The rule
/// is therefore that an item carrying `xdg:schema` is copied with its
/// attribute map *untouched*, exactly as libsecret wrote it, and its KWallet
/// provenance is recorded in the report instead. A working lookup is worth
/// more than a recorded folder name.
///
/// The test is the **presence** of the key, not a non-empty value. An
/// `xdg:schema=""` still means libsecret wrote this map, and the identity
/// argument applies to it unchanged — even though
/// [`super::Outcome::classify`] rightly refuses to call it portable, because
/// that is a question about whether a *search* will match and this is a
/// question about whether we may edit the map.
///
/// # Content type
///
/// The sidecar wins for `Password`, `Stream` and unknown types, because those
/// bytes are copied through unaltered and `$fdo_mime_type` is what libsecret
/// recorded about them — including oddities the real file contains, like
/// `text/plain; charset=utf8` and `application/binary`. A `Map` is the
/// exception: its bytes are *transformed* into canonical JSON here, so the
/// content type must describe what we stored, not what KWallet held. Saying
/// `text/plain` about a JSON object would be a lie the sidecar merely
/// inherited.
pub fn map_entry(
    wallet: &str,
    folder: &str,
    entry: &str,
    entry_type: EntryType,
    secret: Zeroizing<Vec<u8>>,
    sidecar: Option<&SidecarEntry>,
) -> SourceItem {
    let mut attributes = sidecar.map(|s| s.attributes.clone()).unwrap_or_default();

    if !attributes.contains_key(XDG_SCHEMA) {
        attributes.insert(ATTR_FOLDER.to_string(), folder.to_string());
        attributes.insert(ATTR_KEY.to_string(), entry.to_string());
        attributes.insert(ATTR_TYPE.to_string(), entry_type.attribute_value());
    }

    let content_type = match entry_type {
        EntryType::Map => CT_MAP.to_string(),
        _ => sidecar
            .and_then(|s| s.content_type.clone())
            .unwrap_or_else(|| entry_type.default_content_type().to_string()),
    };

    SourceItem {
        label: entry.to_string(),
        attributes,
        secret,
        content_type,
        // Never `now()`. An entry with no sidecar row has no timestamp we
        // know, and 0 says so; inventing one destroys the newest-wins
        // ordering `sm get` uses to break an attribute-set collision.
        created: sidecar.and_then(|s| s.created).unwrap_or(0),
        modified: sidecar.and_then(|s| s.modified).unwrap_or(0),
        provenance: Provenance::kwallet(wallet, folder, entry),
    }
}

// ---------------------------------------------------------------------------
// The D-Bus surface
// ---------------------------------------------------------------------------

/// `org.kde.KWallet` on `org.kde.kwalletd6`, as introspected.
///
/// Every member carries an explicit `name`: KWallet is a Qt service and its
/// members are `camelCase`, which is not what the proxy macro derives from a
/// Rust `snake_case` method. Signatures are `i` = handle, `x` = window id,
/// `s` = string, `b` = bool, `ay` = bytes.
///
/// Only the members the walk needs are declared. `writeEntry`, `removeEntry`,
/// `deleteWallet` and the rest of the mutating half are deliberately absent:
/// an importer that cannot express a write cannot perform one by accident.
#[zbus::proxy(
    interface = "org.kde.KWallet",
    default_service = "org.kde.kwalletd6",
    default_path = "/modules/kwalletd6"
)]
pub trait KWallet {
    /// Every wallet's name.
    #[zbus(name = "wallets")]
    fn wallets(&self) -> zbus::Result<Vec<String>>;

    /// Whether the named wallet is already open, by anyone.
    ///
    /// `isOpen` is overloaded on the wire (`i` and `s`); Qt dispatches on the
    /// signature, so declaring only the `s` form is correct.
    #[zbus(name = "isOpen")]
    fn is_open(&self, wallet: &str) -> zbus::Result<bool>;

    /// Begins opening a wallet and returns a **transaction id**, not a
    /// handle. The handle arrives on [`KWalletProxy::receive_wallet_async_opened`].
    ///
    /// `open` is not declared here on purpose: it blocks the caller for as
    /// long as the unlock dialog is up, which is exactly the hang this module
    /// exists to avoid.
    #[zbus(name = "openAsync")]
    fn open_async(
        &self,
        wallet: &str,
        w_id: i64,
        appid: &str,
        handle_session: bool,
    ) -> zbus::Result<i32>;

    #[zbus(name = "folderList")]
    fn folder_list(&self, handle: i32, appid: &str) -> zbus::Result<Vec<String>>;

    #[zbus(name = "entryList")]
    fn entry_list(&self, handle: i32, folder: &str, appid: &str) -> zbus::Result<Vec<String>>;

    /// `KWallet::Wallet::EntryType` as an integer. See [`EntryType`].
    #[zbus(name = "entryType")]
    fn entry_type(&self, handle: i32, folder: &str, key: &str, appid: &str) -> zbus::Result<i32>;

    /// A `Password` entry's value. Errors if the entry is not a password.
    #[zbus(name = "readPassword")]
    fn read_password(
        &self,
        handle: i32,
        folder: &str,
        key: &str,
        appid: &str,
    ) -> zbus::Result<String>;

    /// A `Map` entry's value, still `QDataStream`-serialised. See
    /// [`decode_qmap`].
    #[zbus(name = "readMap")]
    fn read_map(&self, handle: i32, folder: &str, key: &str, appid: &str) -> zbus::Result<Vec<u8>>;

    /// Any entry's raw bytes, whatever its type. The fallback for everything.
    #[zbus(name = "readEntry")]
    fn read_entry(
        &self,
        handle: i32,
        folder: &str,
        key: &str,
        appid: &str,
    ) -> zbus::Result<Vec<u8>>;

    /// Releases this `appid`'s hold on the wallet. `force` is never `true`
    /// here: closing a wallet out from under the user's own session would be
    /// a destructive side effect of a read-only operation.
    #[zbus(name = "close")]
    fn close(&self, handle: i32, force: bool, appid: &str) -> zbus::Result<i32>;

    /// `(transaction id, handle)`. The handle is negative on failure.
    #[zbus(signal, name = "walletAsyncOpened")]
    fn wallet_async_opened(&self, tid: i32, handle: i32) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// Whether anything could display KWallet's Qt unlock dialog.
pub fn has_display() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()))
}

/// True if `org.kde.kwalletd6` has an owner on this bus.
pub async fn service_is_running(conn: &zbus::Connection) -> Result<bool, KWalletError> {
    let dbus = zbus::fdo::DBusProxy::new(conn).await?;
    let name = zbus::names::BusName::try_from(SERVICE).map_err(zbus::Error::from)?;
    Ok(dbus.name_has_owner(name).await?)
}

/// A wallet held open by [`APP_ID`].
///
/// Deliberately not `Drop`-closing: closing is an `async` D-Bus round trip
/// and a `Drop` that cannot `await` would either block or silently skip. The
/// close is explicit and every path in [`extract`] takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletHandle(pub i32);

/// Opens a wallet, without ever blocking on the unlock dialog.
///
/// The signal stream is subscribed **before** `openAsync` is called. The
/// other order loses the race against an already-unlocked wallet, whose
/// `walletAsyncOpened` can be emitted before the method reply is even
/// delivered — and a missed signal is an import that waits out the whole
/// timeout for an event that already happened.
pub async fn open_wallet(
    proxy: &KWalletProxy<'_>,
    wallet: &str,
    timeout: Duration,
) -> Result<WalletHandle, KWalletError> {
    use futures_util::StreamExt;

    // If it is already open there is no dialog to worry about. If it is not,
    // and nothing can draw one, say so now rather than after two minutes of
    // silence: this is the SSH case, and a clear refusal is the entire point.
    let already_open = proxy.is_open(wallet).await.unwrap_or(false);
    if !already_open && !has_display() {
        return Err(KWalletError::NoDisplay {
            wallet: wallet.to_string(),
        });
    }

    let mut opened = proxy.receive_wallet_async_opened().await?;

    let tid = proxy.open_async(wallet, NO_WINDOW, APP_ID, false).await?;
    // A negative return is the error; non-negative is the transaction id.
    if tid < 0 {
        return Err(KWalletError::OpenRefused {
            wallet: wallet.to_string(),
            code: tid,
        });
    }

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let signal = tokio::time::timeout_at(deadline, opened.next())
            .await
            .map_err(|_| KWalletError::OpenTimedOut {
                wallet: wallet.to_string(),
                timeout,
            })?;
        let Some(signal) = signal else {
            // The stream ended: the connection went away.
            return Err(KWalletError::OpenTimedOut {
                wallet: wallet.to_string(),
                timeout,
            });
        };
        let args = signal.args()?;
        // Another application's open is none of our business.
        if *args.tid() != tid {
            continue;
        }
        let handle = *args.handle();
        if handle < 0 {
            return Err(KWalletError::OpenRefused {
                wallet: wallet.to_string(),
                code: handle,
            });
        }
        return Ok(WalletHandle(handle));
    }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// An entry the walk saw but did not turn into a [`SourceItem`], with the
/// reason.
///
/// This is separate from [`Refusal`] because `Refusal` names the three
/// conditions the *spec* enumerates, and a map that will not decode or an
/// entry the wallet will not hand over is neither. Both are real, both are
/// per-entry, and both must be counted rather than swallowed — so they get
/// their own type instead of a fourth `Refusal` variant this module has no
/// business inventing.
#[derive(Debug, Clone)]
pub struct SkippedEntry {
    pub provenance: Provenance,
    pub label: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SkipReason {
    /// `readMap` returned bytes that are not a `QDataStream`
    /// `QMap<QString, QString>`. Refused rather than guessed at: a wrong
    /// decode writes corrupted data and reports success.
    #[error("the map value could not be decoded: {0}")]
    MapUndecodable(#[from] MapDecodeError),
    /// Every read this module knows how to try failed.
    #[error("KWallet would not hand over the entry: {0}")]
    Unreadable(String),
}

/// An item the walk produced but will not write, with the spec's reason.
#[derive(Debug, Clone)]
pub struct RefusedEntry {
    pub provenance: Provenance,
    pub label: String,
    pub refusal: Refusal,
}

/// Everything one wallet's walk produced.
///
/// The counts are the point. The spec's rule is that a sidecar row that does
/// not resolve and an entry with no sidecar row are *both real conditions*,
/// so each has a field here and neither is silently dropped.
#[derive(Debug, Default)]
pub struct Extraction {
    pub items: Vec<SourceItem>,
    /// Items refused for a reason [`Refusal`] names — in practice always a
    /// cap violation, since a JSON sidecar cannot produce a non-UTF-8
    /// attribute and KWallet has no chained-keyring item.
    pub refused: Vec<RefusedEntry>,
    /// Entries that could not be read or decoded. See [`SkippedEntry`].
    pub skipped: Vec<SkippedEntry>,
    /// Folders with no entries at all. A collection-of-items model has
    /// nowhere to put them, so they are lost and the count says how many.
    pub empty_folders: usize,
    /// Entries the walk found for which the sidecar has no row. They have no
    /// attributes and no timestamps, which makes them
    /// [`super::Outcome::PreservedOnly`] — not an error, but a fact the
    /// report must carry.
    pub entries_without_sidecar: usize,
    /// Sidecar rows whose key no entry in the wallet composed. Stale rows
    /// `ksecretd` left behind, or rows for a folder the walk could not read.
    pub unresolved_sidecar_rows: Vec<String>,
    /// Root values in the sidecar that were not objects — the wallet's own
    /// `$fdo_created` and `$fdo_modified` are two of these in every real file.
    pub skipped_sidecar_rows: usize,
    /// Sidecar fields that were present but unusable, summed over all rows.
    pub malformed_sidecar_fields: usize,
    /// Entries whose declared type was `Password` but whose `readPassword`
    /// failed, and which `readEntry` recovered. The count exists because the
    /// type numbering is a claim about another project's enum, and a nonzero
    /// value here is the evidence that it is wrong.
    pub password_read_fallbacks: usize,
    /// Folders `entryList` refused. Their entries are unreachable and their
    /// sidecar rows will show up in `unresolved_sidecar_rows`.
    pub unreadable_folders: Vec<String>,
}

impl Extraction {
    /// Every entry the walk accounted for, written or not.
    pub fn seen(&self) -> usize {
        self.items.len() + self.refused.len() + self.skipped.len()
    }
}

/// Walks one wallet and produces its items.
///
/// The wallet is opened, walked and **always closed**, including on every
/// error path: the close is not conditional on the walk succeeding, because a
/// wallet left held open by `secret-manager-import` is a lasting side effect
/// of a tool that promised to only read.
pub async fn extract(
    conn: &zbus::Connection,
    wallet: &str,
    sidecar: &Sidecar,
    open_timeout: Duration,
) -> Result<Extraction, KWalletError> {
    if !service_is_running(conn).await? {
        return Err(KWalletError::ServiceUnavailable);
    }
    let proxy = KWalletProxy::new(conn).await?;
    if !proxy.wallets().await?.iter().any(|w| w == wallet) {
        return Err(KWalletError::NoSuchWallet {
            wallet: wallet.to_string(),
        });
    }

    let handle = open_wallet(&proxy, wallet, open_timeout).await?;
    let walked = walk(&proxy, wallet, handle, sidecar).await;
    // Deliberately not `?`: a failed close must not mask the walk's result,
    // and there is nothing a caller could do about it.
    let _ = proxy.close(handle.0, false, APP_ID).await;
    walked
}

/// The walk itself, with the wallet already open.
async fn walk(
    proxy: &KWalletProxy<'_>,
    wallet: &str,
    handle: WalletHandle,
    sidecar: &Sidecar,
) -> Result<Extraction, KWalletError> {
    let h = handle.0;
    let mut out = Extraction {
        skipped_sidecar_rows: sidecar.skipped_rows(),
        ..Default::default()
    };
    let mut resolved: BTreeSet<String> = BTreeSet::new();

    for folder in proxy.folder_list(h, APP_ID).await? {
        let entries = match proxy.entry_list(h, &folder, APP_ID).await {
            Ok(e) => e,
            Err(_) => {
                out.unreadable_folders.push(folder);
                continue;
            }
        };
        if entries.is_empty() {
            out.empty_folders += 1;
            continue;
        }
        if out.seen() + entries.len() > MAX_ENTRIES {
            return Err(KWalletError::TooManyEntries { limit: MAX_ENTRIES });
        }

        for entry in entries {
            let key = sidecar_key(&folder, &entry);
            let row = sidecar.get(&key);
            if row.is_some() {
                resolved.insert(key);
            } else {
                out.entries_without_sidecar += 1;
            }
            out.malformed_sidecar_fields += row.map_or(0, |r| r.malformed_fields);

            let provenance = Provenance::kwallet(wallet, &folder, &entry);
            let entry_type = EntryType::from_code(
                proxy
                    .entry_type(h, &folder, &entry, APP_ID)
                    .await
                    .unwrap_or(EntryType::Unknown.code()),
            );

            let secret = match read_secret(proxy, h, &folder, &entry, entry_type, &mut out).await {
                Ok(s) => s,
                Err(reason) => {
                    out.skipped.push(SkippedEntry {
                        provenance,
                        label: entry,
                        reason,
                    });
                    continue;
                }
            };

            let item = map_entry(wallet, &folder, &entry, entry_type, secret, row);
            // Checked before anything is written: an import that fails halfway
            // leaves the user worse off than one that refuses at the start.
            if let Some(refusal) = check_caps(
                &item.label,
                &item.attributes,
                item.secret.len(),
                &item.content_type,
            ) {
                out.refused.push(RefusedEntry {
                    provenance: item.provenance.clone(),
                    label: item.label.clone(),
                    refusal,
                });
                continue;
            }
            out.items.push(item);
        }
    }

    out.unresolved_sidecar_rows = sidecar
        .keys()
        .filter(|k| !resolved.contains(*k))
        .map(str::to_string)
        .collect();
    Ok(out)
}

/// Reads one entry's bytes, dispatching on its declared type.
///
/// The dispatch is defensive on purpose. `entryType`'s numbering is
/// `KWallet::Wallet::EntryType` from KWallet's own public header, but it is
/// still another project's enum reached over a wire that reports it as a bare
/// integer. So a `Password` whose `readPassword` fails falls back to
/// `readEntry` — the raw bytes are the same bytes — and the fallback is
/// *counted*, so a wrong assumption shows up as a number in the report rather
/// than as a pile of missing items.
///
/// A `Map` gets no such fallback. Its bytes are not the secret; the decoded
/// map is, and an undecodable map is refused with a reason rather than
/// written as an opaque blob that no one will ever recognise.
async fn read_secret(
    proxy: &KWalletProxy<'_>,
    handle: i32,
    folder: &str,
    entry: &str,
    entry_type: EntryType,
    out: &mut Extraction,
) -> Result<Zeroizing<Vec<u8>>, SkipReason> {
    match entry_type {
        EntryType::Password => {
            match proxy.read_password(handle, folder, entry, APP_ID).await {
                // `into_bytes` moves the buffer, so no un-zeroized copy of the
                // password is left behind by the conversion.
                Ok(s) => Ok(Zeroizing::new(s.into_bytes())),
                Err(first) => {
                    out.password_read_fallbacks += 1;
                    proxy
                        .read_entry(handle, folder, entry, APP_ID)
                        .await
                        .map(Zeroizing::new)
                        .map_err(|second| {
                            SkipReason::Unreadable(format!(
                                "readPassword failed ({first}) and readEntry failed ({second})"
                            ))
                        })
                }
            }
        }
        EntryType::Map => {
            let raw = match proxy.read_map(handle, folder, entry, APP_ID).await {
                Ok(v) => Zeroizing::new(v),
                Err(e) => {
                    // `readEntry` returns the identical bytes for a map entry,
                    // so it is a legitimate retry for a refused `readMap` —
                    // and the decode below is what actually decides.
                    proxy
                        .read_entry(handle, folder, entry, APP_ID)
                        .await
                        .map(Zeroizing::new)
                        .map_err(|second| {
                            SkipReason::Unreadable(format!(
                                "readMap failed ({e}) and readEntry failed ({second})"
                            ))
                        })?
                }
            };
            Ok(read_map_secret(&raw)?)
        }
        EntryType::Stream | EntryType::Unknown | EntryType::Other(_) => proxy
            .read_entry(handle, folder, entry, APP_ID)
            .await
            .map(Zeroizing::new)
            .map_err(|e| SkipReason::Unreadable(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::Outcome;

    // -- helpers -----------------------------------------------------------

    fn sidecar_entry(attrs: &[(&str, &str)]) -> SidecarEntry {
        SidecarEntry {
            created: Some(1_699_383_593),
            modified: Some(1_699_387_319),
            content_type: Some("text/plain".into()),
            attributes: attrs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            malformed_fields: 0,
        }
    }

    fn secret() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b"hunter2".to_vec())
    }

    /// Serialises `pairs` exactly as `QDataStream << QMap<QString, QString>`
    /// does: big-endian `quint32` count, then per pair a `quint32` byte length
    /// and UTF-16BE bytes for the key and then the value.
    fn qmap_bytes(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (k, v) in pairs {
            for s in [k, v] {
                let units: Vec<u16> = s.encode_utf16().collect();
                out.extend_from_slice(&((units.len() * 2) as u32).to_be_bytes());
                for u in units {
                    out.extend_from_slice(&u.to_be_bytes());
                }
            }
        }
        out
    }

    // -- mapping -----------------------------------------------------------

    /// The one rule that is easy to get wrong. An item that already carries
    /// an `xdg:schema` must reach the vault with the attribute map libsecret
    /// wrote, byte for byte: our `replace` semantics compare maps for
    /// equality, so one added key breaks the very lookup the import exists to
    /// preserve.
    #[test]
    fn an_item_with_a_schema_keeps_its_attribute_map_untouched() {
        let row = sidecar_entry(&[
            ("xdg:schema", "org.freedesktop.Secret.Generic"),
            ("server", "example.com"),
            ("user", "joseph"),
        ]);
        let item = map_entry(
            "kdewallet",
            "Secret Service",
            "credential",
            EntryType::Password,
            secret(),
            Some(&row),
        );
        assert_eq!(item.attributes, row.attributes);
        for added in [ATTR_FOLDER, ATTR_KEY, ATTR_TYPE] {
            assert!(!item.attributes.contains_key(added), "{added} was added");
        }
        assert_eq!(item.outcome(), Outcome::FullyPortable);
        // The provenance is still recorded — in the report, not in the vault.
        assert_eq!(item.provenance.folder.as_deref(), Some("Secret Service"));
        assert_eq!(item.provenance.entry.as_deref(), Some("credential"));
    }

    /// The presence of the key is the test, not the value. An empty schema is
    /// still a map libsecret wrote, and editing it carries the same identity
    /// risk — even though `Outcome::classify` rightly declines to call it
    /// portable, which is a question about matching, not about editing.
    #[test]
    fn an_empty_schema_value_still_freezes_the_attribute_map() {
        let row = sidecar_entry(&[("xdg:schema", ""), ("server", "example.com")]);
        let item = map_entry(
            "kdewallet",
            "Secret Service",
            "credential",
            EntryType::Password,
            secret(),
            Some(&row),
        );
        assert_eq!(item.attributes, row.attributes);
        assert_eq!(item.outcome(), Outcome::AttributesPreserved);
    }

    /// A schema-absent item gains exactly the three `kwallet:` keys and
    /// nothing else, and everything the sidecar held is still verbatim.
    #[test]
    fn a_schema_absent_item_gains_exactly_the_kwallet_keys() {
        let row = sidecar_entry(&[("server", "example.com"), ("user", "joseph")]);
        let item = map_entry(
            "kdewallet",
            "Passwords",
            "my router",
            EntryType::Password,
            secret(),
            Some(&row),
        );
        let added: BTreeSet<&str> = item
            .attributes
            .keys()
            .map(String::as_str)
            .filter(|k| !row.attributes.contains_key(*k))
            .collect();
        assert_eq!(
            added,
            BTreeSet::from([ATTR_FOLDER, ATTR_KEY, ATTR_TYPE]),
            "exactly the kwallet: keys, no more and no fewer"
        );
        for (k, v) in &row.attributes {
            assert_eq!(item.attributes.get(k), Some(v), "{k} was not verbatim");
        }
        assert_eq!(item.attributes[ATTR_FOLDER], "Passwords");
        assert_eq!(item.attributes[ATTR_KEY], "my router");
        assert_eq!(item.attributes[ATTR_TYPE], "password");
        assert_eq!(item.outcome(), Outcome::AttributesPreserved);
    }

    /// A native KWallet entry: no sidecar row at all. It gets the three
    /// `kwallet:` keys, no timestamps, and the content type its entry type
    /// implies.
    #[test]
    fn an_entry_with_no_sidecar_row_is_still_imported() {
        let item = map_entry(
            "kdewallet",
            "ksshaskpass",
            "/home/joseph/.ssh/id_ed25519",
            EntryType::Password,
            secret(),
            None,
        );
        assert_eq!(item.attributes.len(), 3);
        assert_eq!(item.attributes[ATTR_KEY], "/home/joseph/.ssh/id_ed25519");
        assert_eq!(item.label, "/home/joseph/.ssh/id_ed25519");
        assert_eq!(item.content_type, "text/plain");
        // Never `now()`.
        assert_eq!((item.created, item.modified), (0, 0));
        // Three `kwallet:` attributes are still attributes, so this is
        // "attributes preserved" rather than "preserved only" — the honest
        // reading, since `sm get kwallet:folder=... kwallet:key=...` works.
        assert_eq!(item.outcome(), Outcome::AttributesPreserved);
    }

    /// The label is the entry name and the timestamps are the sidecar's.
    #[test]
    fn the_label_and_the_timestamps_come_from_where_the_spec_says() {
        let row = sidecar_entry(&[]);
        let item = map_entry(
            "kdewallet",
            "Passwords",
            "my router",
            EntryType::Password,
            secret(),
            Some(&row),
        );
        assert_eq!(item.label, "my router");
        assert_eq!(item.created, 1_699_383_593);
        assert_eq!(item.modified, 1_699_387_319);
        assert_eq!(item.provenance.container, "kdewallet");
    }

    /// Each entry type maps to the right content type, and the sidecar
    /// overrides all of them except `Map` — whose bytes we transformed, so
    /// the sidecar's claim about the old bytes no longer describes them.
    #[test]
    fn each_entry_type_maps_to_the_right_content_type() {
        let cases = [
            (EntryType::Password, "text/plain"),
            (EntryType::Stream, "application/octet-stream"),
            (EntryType::Map, "application/json"),
            (EntryType::Unknown, "application/octet-stream"),
            (EntryType::Other(9), "application/octet-stream"),
        ];
        for (ty, expected) in cases {
            let item = map_entry("w", "f", "e", ty, secret(), None);
            assert_eq!(item.content_type, expected, "{ty} with no sidecar");
            assert_eq!(item.attributes[ATTR_TYPE], ty.attribute_value());

            let mut row = sidecar_entry(&[]);
            row.content_type = Some("text/plain; charset=utf8".into());
            let item = map_entry("w", "f", "e", ty, secret(), Some(&row));
            let with_sidecar = if ty == EntryType::Map {
                "application/json"
            } else {
                "text/plain; charset=utf8"
            };
            assert_eq!(item.content_type, with_sidecar, "{ty} with a sidecar");
        }
    }

    /// An entry type KWallet itself calls unknown, and one from a future
    /// KWallet, both keep their number rather than being flattened.
    #[test]
    fn entry_type_codes_round_trip() {
        for code in [0i32, 1, 2, 3, 4, 0xffff, -1] {
            assert_eq!(EntryType::from_code(code).code(), code);
        }
        assert_eq!(EntryType::from_code(0), EntryType::Unknown);
        assert_eq!(EntryType::from_code(1), EntryType::Password);
        assert_eq!(EntryType::from_code(2), EntryType::Stream);
        assert_eq!(EntryType::from_code(3), EntryType::Map);
        assert_eq!(EntryType::from_code(0xffff).attribute_value(), "65535");
    }

    // -- sidecar parsing ---------------------------------------------------

    fn parse(text: &str) -> Sidecar {
        Sidecar::parse(text, Path::new("kdewallet_attributes.json")).unwrap()
    }

    #[test]
    fn a_complete_row_parses() {
        let s = parse(
            r#"{"Passwords/my router": {
                 "$fdo_created": "1699383593",
                 "$fdo_modified": "1699387319",
                 "$fdo_mime_type": "text/plain",
                 "attributes": {"server": "example.com", "user": "joseph"}
               }}"#,
        );
        let row = s.get("Passwords/my router").unwrap();
        assert_eq!(row.created, Some(1_699_383_593));
        assert_eq!(row.modified, Some(1_699_387_319));
        assert_eq!(row.content_type.as_deref(), Some("text/plain"));
        assert_eq!(row.attributes.len(), 2);
        assert_eq!(row.malformed_fields, 0);
        assert_eq!(s.skipped_rows(), 0);
    }

    /// The real file carries wallet-level `$fdo_created` and `$fdo_modified`
    /// as bare strings at the *root*, beside the entry rows. They are not
    /// entries and they are not an error.
    #[test]
    fn root_scalars_are_skipped_rather_than_failing_the_parse() {
        let s = parse(
            r#"{"$fdo_created": "1767901014",
                "$fdo_modified": "1788889806",
                "Passwords/x": {"attributes": {}}}"#,
        );
        assert_eq!(s.len(), 1);
        assert_eq!(s.skipped_rows(), 2);
        assert!(s.get("Passwords/x").is_some());
        assert!(s.get("$fdo_created").is_none());
    }

    /// Ten of the 66 rows measured here have no `$fdo_mime_type`, and a row
    /// may have no `attributes` at all. Both are normal.
    #[test]
    fn missing_fdo_fields_and_absent_attributes_are_not_errors() {
        let s = parse(r#"{"xdg-desktop-portal/claude": {"attributes": {"a": "b"}}}"#);
        let row = s.get("xdg-desktop-portal/claude").unwrap();
        assert_eq!(row.created, None);
        assert_eq!(row.modified, None);
        assert_eq!(row.content_type, None);
        assert_eq!(row.malformed_fields, 0);

        let s = parse(r#"{"f/e": {"$fdo_created": "1", "$fdo_mime_type": "text/plain"}}"#);
        let row = s.get("f/e").unwrap();
        assert!(row.attributes.is_empty());
        assert_eq!(row.created, Some(1));
        assert_eq!(row.malformed_fields, 0);
    }

    /// An empty mime string says nothing, so the entry type decides. It is
    /// not counted as malformed, because it is not.
    #[test]
    fn an_empty_mime_type_falls_through_to_the_entry_type() {
        let s = parse(r#"{"f/e": {"$fdo_mime_type": ""}}"#);
        let row = s.get("f/e").unwrap();
        assert_eq!(row.content_type, None);
        assert_eq!(row.malformed_fields, 0);
        let item = map_entry("w", "f", "e", EntryType::Stream, secret(), Some(row));
        assert_eq!(item.content_type, "application/octet-stream");
    }

    /// Non-string values are dropped and counted, never stringified: a
    /// synthesised attribute is a broken lookup with extra steps.
    #[test]
    fn non_string_values_are_counted_not_coerced() {
        let s = parse(
            r#"{"f/e": {
                 "$fdo_created": "not a number",
                 "$fdo_modified": true,
                 "$fdo_mime_type": 7,
                 "attributes": {"good": "yes", "bad": 12, "worse": null}
               }}"#,
        );
        let row = s.get("f/e").unwrap();
        assert_eq!(row.created, None);
        assert_eq!(row.modified, None);
        assert_eq!(row.content_type, None);
        assert_eq!(row.attributes.len(), 1);
        assert_eq!(row.attributes["good"], "yes");
        // created, modified, mime, and two attribute values.
        assert_eq!(row.malformed_fields, 5);
    }

    /// A numeric timestamp is accepted, because it costs nothing and a future
    /// ksecretd may write one; a negative or fractional one is not a Unix
    /// second count we can use.
    #[test]
    fn numeric_timestamps_are_accepted_and_bad_ones_are_not() {
        let s = parse(r#"{"f/e": {"$fdo_created": 1699383593, "$fdo_modified": -5}}"#);
        let row = s.get("f/e").unwrap();
        assert_eq!(row.created, Some(1_699_383_593));
        assert_eq!(row.modified, None);
        assert_eq!(row.malformed_fields, 1);
    }

    /// `attributes` that is not an object is one malformed field, not a
    /// failed parse.
    #[test]
    fn attributes_that_is_not_an_object_is_counted() {
        let s = parse(r#"{"f/e": {"attributes": ["server", "example.com"]}}"#);
        let row = s.get("f/e").unwrap();
        assert!(row.attributes.is_empty());
        assert_eq!(row.malformed_fields, 1);
    }

    /// Keys are composed, never split: both halves may contain `/`, and the
    /// real file proves it.
    #[test]
    fn keys_with_slashes_on_both_sides_resolve() {
        let s = parse(
            r#"{"ksshaskpass//home/joseph/.ssh/aur": {"attributes": {}},
                "accounts/3/1": {"attributes": {}}}"#,
        );
        assert!(
            s.get(&sidecar_key("ksshaskpass", "/home/joseph/.ssh/aur"))
                .is_some()
        );
        assert!(s.get(&sidecar_key("accounts", "3/1")).is_some());
        // Two different `(folder, entry)` pairs compose the *same* key, so
        // the reverse — splitting a key back into a pair — has no unique
        // answer. That is exactly why the walk composes rather than parses:
        // it already knows which pair is real, and never has to guess.
        assert_eq!(
            sidecar_key("accounts/3", "1"),
            sidecar_key("accounts", "3/1")
        );
    }

    /// A key no entry composes is a real condition — a stale row `ksecretd`
    /// left behind — and is reported, not dropped.
    #[test]
    fn unresolvable_keys_are_visible_to_the_caller() {
        let s = parse(r#"{"Gone/away": {"attributes": {}}, "Here/now": {"attributes": {}}}"#);
        let resolved = BTreeSet::from([sidecar_key("Here", "now")]);
        let unresolved: Vec<&str> = s.keys().filter(|k| !resolved.contains(*k)).collect();
        assert_eq!(unresolved, ["Gone/away"]);
    }

    #[test]
    fn a_sidecar_that_is_not_an_object_is_refused() {
        let e = Sidecar::parse("[1, 2, 3]", Path::new("x.json")).unwrap_err();
        assert!(matches!(e, SidecarError::NotAnObject { .. }));
        let e = Sidecar::parse("{oops", Path::new("x.json")).unwrap_err();
        assert!(matches!(e, SidecarError::Json { .. }));
    }

    /// A file with more rows than the limit is refused before the rows are
    /// turned into entries. Everything read here is attacker-influenced.
    #[test]
    fn a_huge_sidecar_is_refused_by_row_count() {
        let mut text = String::from("{");
        for n in 0..=MAX_SIDECAR_ROWS {
            if n > 0 {
                text.push(',');
            }
            text.push_str(&format!("\"f/{n}\":{{}}"));
        }
        text.push('}');
        let e = Sidecar::parse(&text, Path::new("x.json")).unwrap_err();
        match e {
            SidecarError::TooManyRows { rows, limit, .. } => {
                assert_eq!(rows, MAX_SIDECAR_ROWS + 1);
                assert_eq!(limit, MAX_SIDECAR_ROWS);
            }
            other => panic!("expected TooManyRows, got {other:?}"),
        }
    }

    /// A sidecar larger than the byte limit is refused without being read.
    #[test]
    fn an_oversized_sidecar_file_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big_attributes.json");
        std::fs::write(&path, vec![b'x'; (MAX_SIDECAR_BYTES + 1) as usize]).unwrap();
        match Sidecar::load(&path).unwrap_err() {
            SidecarError::TooLarge { len, limit, .. } => {
                assert_eq!(len, MAX_SIDECAR_BYTES + 1);
                assert_eq!(limit, MAX_SIDECAR_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// A wallet `ksecretd` never touched has no sidecar. Its entries have no
    /// attributes, which is a state the mapping already handles; it is not an
    /// error.
    #[test]
    fn a_missing_sidecar_is_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let s = Sidecar::load(&dir.path().join("nope_attributes.json")).unwrap();
        assert!(s.is_empty());
        assert_eq!(s.skipped_rows(), 0);
    }

    #[test]
    fn the_sidecar_path_follows_xdg() {
        let p = sidecar_path("kdewallet");
        assert!(p.ends_with("kwalletd/kdewallet_attributes.json"), "{p:?}");
    }

    /// The `Debug` that goes into a log line carries attribute names and no
    /// attribute values, for the same reason `SourceItem`'s does.
    #[test]
    fn sidecar_debug_redacts_attribute_values() {
        let row = sidecar_entry(&[("server", "secret-host.example.com")]);
        let text = format!("{row:?}");
        assert!(text.contains("server"));
        assert!(!text.contains("secret-host.example.com"), "{text}");
    }

    // -- QMap decoding -----------------------------------------------------

    #[test]
    fn a_serialised_qmap_round_trips_through_canonical_json() {
        let bytes = qmap_bytes(&[("zeta", "last"), ("alpha", "first"), ("mid", "")]);
        let pairs = decode_qmap(&bytes).unwrap();
        assert_eq!(pairs.len(), 3);
        let json = read_map_secret(&bytes).unwrap();
        // Canonical: sorted keys, no whitespace.
        assert_eq!(
            std::str::from_utf8(&json).unwrap(),
            r#"{"alpha":"first","mid":"","zeta":"last"}"#
        );
    }

    #[test]
    fn an_empty_qmap_is_an_empty_object() {
        let json = read_map_secret(&qmap_bytes(&[])).unwrap();
        assert_eq!(std::str::from_utf8(&json).unwrap(), "{}");
    }

    /// Qt writes a *null* QString as `0xFFFFFFFF`, distinct from the empty
    /// string's `0`. Both become an empty Rust string, which is the only
    /// representation JSON has.
    #[test]
    fn a_null_qstring_decodes_as_empty() {
        let mut bytes = 1u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&[0x00, b'k', 0x00, b'v']); // "kv", UTF-16BE
        bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // null value
        let pairs = decode_qmap(&bytes).unwrap();
        assert_eq!(pairs, [("kv".to_string(), String::new())]);
    }

    /// Non-ASCII and astral-plane characters are the case a naive latin-1
    /// decode would corrupt silently.
    #[test]
    fn utf16_surrogate_pairs_survive() {
        let bytes = qmap_bytes(&[("kéy", "🔑 välue")]);
        let pairs = decode_qmap(&bytes).unwrap();
        assert_eq!(pairs, [("kéy".to_string(), "🔑 välue".to_string())]);
    }

    /// Every way the bytes can fail to be a `QMap` is a refusal, never a
    /// guess: a wrong decode writes corrupted data and reports success.
    #[test]
    fn malformed_streams_are_refused_rather_than_guessed_at() {
        let good = qmap_bytes(&[("k", "v")]);

        // Truncated count.
        assert!(matches!(
            decode_qmap(&good[..2]),
            Err(MapDecodeError::Truncated { .. })
        ));
        // A count larger than the bytes can hold.
        let mut lying = good.clone();
        lying[..4].copy_from_slice(&1000u32.to_be_bytes());
        assert!(matches!(
            decode_qmap(&lying),
            Err(MapDecodeError::ImpossibleCount { .. })
        ));
        // Truncated in the middle of a string.
        assert!(matches!(
            decode_qmap(&good[..good.len() - 1]),
            Err(MapDecodeError::Truncated { .. })
        ));
        // Trailing bytes: the buffer must be consumed exactly, which is what
        // makes "this is not a QMap" detectable at all.
        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(
            decode_qmap(&extra),
            Err(MapDecodeError::TrailingBytes { trailing: 1 })
        ));
        // An odd string length cannot be UTF-16.
        let mut odd = 1u32.to_be_bytes().to_vec();
        odd.extend_from_slice(&3u32.to_be_bytes());
        odd.extend_from_slice(&[0, b'k', 0]);
        odd.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            decode_qmap(&odd),
            Err(MapDecodeError::OddStringLength { len: 3 })
        ));
        // An unpaired surrogate.
        let mut bad = 1u32.to_be_bytes().to_vec();
        bad.extend_from_slice(&2u32.to_be_bytes());
        bad.extend_from_slice(&0xD800u16.to_be_bytes());
        bad.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(decode_qmap(&bad), Err(MapDecodeError::BadUtf16)));
        // A QMap cannot hold a key twice, so a stream that does is not one.
        let dup = qmap_bytes(&[("k", "1"), ("k", "2")]);
        assert!(matches!(
            decode_qmap(&dup),
            Err(MapDecodeError::DuplicateKey)
        ));
        // An absurd count is bounded before anything is reserved for it.
        let mut huge = (MAX_MAP_ENTRIES as u32 + 1).to_be_bytes().to_vec();
        huge.resize(4 + (MAX_MAP_ENTRIES + 1) * 8, 0);
        assert!(matches!(
            decode_qmap(&huge),
            Err(MapDecodeError::TooManyPairs { .. })
        ));
    }

    /// Text that happens to be a password is not a `QMap`, and must not be
    /// mistaken for one. This is the whole safety argument for the decoder.
    #[test]
    fn arbitrary_bytes_are_not_mistaken_for_a_qmap() {
        for junk in [
            &b"hunter2"[..],
            b"{\"json\": \"not qdatastream\"}",
            b"\x00\x00\x00\x00extra",
            &[0xffu8; 64],
        ] {
            assert!(decode_qmap(junk).is_err(), "{junk:?} decoded");
        }
    }

    // -- live service ------------------------------------------------------

    /// A read-only sanity check against a real `kwalletd6`, when there is
    /// one. It never opens a closed wallet: that would raise a password
    /// dialog in the middle of `cargo test`. Like `tests/pam_stack.rs`, it
    /// prints why it skipped rather than passing vacuously.
    #[tokio::test]
    async fn live_kwalletd_agrees_with_this_modules_assumptions() {
        let Ok(conn) = zbus::Connection::session().await else {
            println!("SKIPPED: no session bus");
            return;
        };
        match service_is_running(&conn).await {
            Ok(true) => {}
            _ => {
                println!("SKIPPED: {SERVICE} has no owner on the session bus");
                return;
            }
        }
        let proxy = KWalletProxy::new(&conn).await.unwrap();
        let wallets = proxy.wallets().await.unwrap();
        println!("live kwalletd6: {} wallet(s)", wallets.len());
        for wallet in &wallets {
            let open = proxy.is_open(wallet).await.unwrap_or(false);
            // Names and counts only. Never a value, never a secret.
            println!("  wallet {wallet:?} open={open}");
            let path = sidecar_path(wallet);
            match Sidecar::load(&path) {
                Ok(s) => println!(
                    "  sidecar {} row(s), {} non-object root value(s)",
                    s.len(),
                    s.skipped_rows()
                ),
                Err(e) => println!("  sidecar unreadable: {e}"),
            }
            if !open {
                println!("  SKIPPED the walk: the wallet is closed and opening it would prompt");
            }
        }
    }
}
