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
//! `entryList`, and *composes* the lookup key with `sidecar_key`. Rows the
//! walk never composes a key for are reported by
//! [`Extraction::unresolved_sidecar_rows`] rather than dropped.
//!
//! # Nothing here logs a secret, and nothing logs an attribute value
//!
//! Secret bytes live in [`Zeroizing`] from the moment they leave zbus.
//! `SidecarEntry`'s `Debug` prints attribute *names* only, for the same
//! reason [`super::SourceItem`]'s does: `server=`, `user=` and `url=` have no
//! business in a log line. Everything this module reads — a wallet file, a
//! JSON sidecar, a D-Bus reply — is attacker-influenced, so every length is
//! bounded before it is allocated and every parse returns a typed error
//! instead of panicking.

use super::{Provenance, Refusal, SourceItem, XDG_SCHEMA, check_caps};
use crate::vault::format::{Cap, MAX_ITEM_SECRET};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The bus name KWallet 6 owns. Deliberately *not* `org.kde.kwalletd5`: the
/// same process owns both here, but the 5 name is a compatibility alias and
/// may be answered by an older daemon on a mixed system.
pub(crate) const SERVICE: &str = "org.kde.kwalletd6";

/// The application id every call carries.
///
/// This becomes **persistent state** in the wallet's per-application access
/// list — it survives the import and the user will see it in KWallet's
/// configuration afterwards — so it is stable and honest rather than
/// randomised or borrowed from another application.
pub(crate) const APP_ID: &str = "secret-manager-import";

/// `wId` for a process with no window. KWallet uses it only to parent the
/// unlock dialog.
pub(crate) const NO_WINDOW: i64 = 0;

/// How long `open_wallet` waits for `walletAsyncOpened` before giving up.
///
/// The bound exists because the failure it guards is a *hang*, not an error:
/// `openAsync` returns a transaction id immediately whether or not anything
/// can ever answer the unlock dialog, and a blocked import with no output is
/// the worst outcome available. Two minutes is long enough for a user to find
/// the dialog and type a password.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(120);

/// How long any *other* D-Bus call to kwalletd may take.
///
/// [`DEFAULT_OPEN_TIMEOUT`] bounds only the wait for `walletAsyncOpened`, and
/// that is not the only place a dialog can appear: KWallet's *per-application*
/// access prompt ("allow secret-manager-import to read this wallet?") is
/// raised inside a `readPassword`/`readEntry`, not at open. An unbounded read
/// therefore reproduces exactly the hang [`open_wallet`] exists to prevent.
/// Every call is bounded — including the proxy constructors and the `AddMatch`
/// behind `receive_wallet_async_opened`, which are bus round trips too — and a
/// read that expires costs one entry, not the import.
///
/// This is also why the live test at the bottom of this file walks only a
/// wallet that is *already open*: being open rules out the unlock dialog,
/// which a test may not raise. It does not rule out this one.
pub(crate) const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the `close` at the end of [`extract`] may take. Shorter than
/// [`DEFAULT_CALL_TIMEOUT`] because nothing is waiting on its answer and its
/// failure is already ignored: the only thing a long wait buys is a longer
/// hang.
pub(crate) const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`open_wallet`] keeps listening for a wallet that timed out.
///
/// A [`KWalletError::OpenTimedOut`] does not cancel anything: the transaction
/// is still live inside kwalletd, and a user who finds the dialog ten minutes
/// later opens the wallet against [`APP_ID`] — producing a handle nobody is
/// listening for and nobody will ever close. The grace task exists so that
/// handle is closed rather than held for the life of the session.
pub(crate) const OPEN_GRACE: Duration = Duration::from_secs(600);

/// The largest sidecar this module will read into memory. The measured file
/// is 21 KiB for 66 entries; 16 MiB is four orders of magnitude of headroom
/// and still a bound.
pub(crate) const MAX_SIDECAR_BYTES: u64 = 16 << 20;

/// The largest number of rows a sidecar may declare.
pub(crate) const MAX_SIDECAR_ROWS: usize = 100_000;

/// The largest number of entries a serialised `QMap` may declare, checked
/// before anything is allocated for it.
pub(crate) const MAX_MAP_ENTRIES: usize = 4096;

/// The largest number of entries one walk will produce, across all folders.
/// A wallet larger than this is not a wallet, it is a denial of service.
pub(crate) const MAX_ENTRIES: usize = 200_000;

/// The largest total of secret bytes one walk will hold, across all entries.
///
/// [`MAX_ENTRIES`] alone bounds nothing that matters here: an entry's secret
/// may be up to `vault::format::MAX_ITEM_SECRET` (1 MiB), so 200,000 of them
/// is ~200 GiB resident and the walk dies to the OOM killer with the wallet
/// still held open by [`APP_ID`] — the one lasting side effect this module
/// promises not to leave. A count limits how many things are read; only a
/// byte budget limits how much memory reading them takes.
///
/// 256 MiB is four orders of magnitude above the measured wallet (66 entries,
/// a few KiB each) and still a bound. Exceeding it aborts the walk, so the
/// close in [`extract`] still runs.
pub(crate) const MAX_SECRET_BYTES: usize = 256 << 20;

/// Attribute recording the KWallet folder. See
/// [`the `kwallet:` prefix`](self#the-kwallet-prefix-is-added-only-where-it-is-free).
pub(crate) const ATTR_FOLDER: &str = "kwallet:folder";
/// Attribute recording the KWallet entry name.
pub(crate) const ATTR_KEY: &str = "kwallet:key";
/// Attribute recording the KWallet entry type.
pub(crate) const ATTR_TYPE: &str = "kwallet:type";

/// Sidecar field holding the creation time, as a decimal string of Unix
/// seconds.
pub(crate) const FDO_CREATED: &str = "$fdo_created";
/// Sidecar field holding the modification time.
pub(crate) const FDO_MODIFIED: &str = "$fdo_modified";
/// Sidecar field holding the content type.
pub(crate) const FDO_MIME_TYPE: &str = "$fdo_mime_type";
/// Sidecar field holding the libsecret attribute map.
pub(crate) const FDO_ATTRIBUTES: &str = "attributes";

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
/// an error — see `Sidecar::skipped_rows` — because one bad row must not
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
    /// The bytes *are* a legal `QString` — Qt permits an unpaired surrogate,
    /// and a null `QString` is distinct from an empty one — but Rust's
    /// `String` has no way to say so.
    ///
    /// This replaces what used to be reported as "not valid UTF-16" and as
    /// "a key appears twice, which a QMap cannot produce". Both were refusals
    /// — and both should stay refusals, since a lossy import is worse than
    /// none — but neither message named what happened: the wallet is fine,
    /// and it is our representation that is narrower than Qt's.
    #[error("the serialised map cannot be represented faithfully: {what}")]
    Unrepresentable { what: &'static str },
    #[error("a key appears twice in the serialised map, which a QMap cannot produce")]
    DuplicateKey,
    #[error("{trailing} bytes remain after the serialised map, so this is not a QMap")]
    TrailingBytes { trailing: usize },
    /// The decoded pairs already hold more secret than the Secret Service API
    /// allows, so re-encoding them would only produce a secret `check_caps`
    /// refuses. Refused before sizing the output buffer: the capacity is six
    /// bytes per decoded byte, so sizing first turns an over-cap entry into a
    /// multi-megabyte pre-allocation for a secret that is never written.
    #[error("the decoded map holds {len} bytes, over the {limit} byte secret limit")]
    TooLarge { len: usize, limit: usize },
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
    /// The name would not address a wallet, and — because it is interpolated
    /// into the sidecar's filename — could address a file outside
    /// `kwalletd/`. Refused before either the bus or the filesystem sees it.
    #[error(
        "{wallet:?} is not a usable KWallet wallet name: a name may not be empty, be \".\" or \
         \"..\", or contain \"/\" or a NUL byte"
    )]
    InvalidWalletName { wallet: String },
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
         probably waiting for an answer nobody can give. The request was not cancelled — \
         kwalletd may still open the wallet if the dialog is answered, in which case it will be \
         held by \"{APP_ID}\"; check KWallet's own configuration and close it there if so"
    )]
    OpenTimedOut { wallet: String, timeout: Duration },
    /// A wallet-level call did not answer inside `DEFAULT_CALL_TIMEOUT`.
    /// A *per-entry* call that expires costs one entry — see
    /// [`SkipReason::Unreadable`] — but there is no wallet without its folder
    /// list.
    #[error(
        "KWallet did not answer {call} within {timeout:?}; kwalletd may be waiting on a prompt \
         nobody can see"
    )]
    CallTimedOut {
        call: &'static str,
        timeout: Duration,
    },
    #[error("the walk produced more than {limit} entries, which is not a wallet")]
    TooManyEntries { limit: usize },
    /// The walk's secrets exceeded [`MAX_SECRET_BYTES`] in total. Separate
    /// from [`KWalletError::TooManyEntries`] because the two bound different
    /// things: a wallet of ten entries can still be larger than memory.
    #[error(
        "the walk's entries hold more than {limit} bytes of secrets in total, which is not a wallet"
    )]
    TooManySecretBytes { limit: usize },
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
pub(crate) struct SidecarEntry {
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
    duplicate_keys: Vec<String>,
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
    /// One open, one bounded read: the `stat` and the read are the *same*
    /// file, so the size the limit was checked against is the size that is
    /// allocated. Bounding a separate `stat` and then re-opening the path
    /// bounds nothing — the file can grow, or become another file, in
    /// between — so the [`std::io::Read::take`] is the guarantee and the
    /// `metadata` call is only an early refusal.
    pub fn load(path: &Path) -> Result<Self, SidecarError> {
        Self::load_with_limit(path, MAX_SIDECAR_BYTES)
    }

    /// [`Sidecar::load`] with the limit as a parameter.
    ///
    /// The parameter exists so the `take` re-check below is *reachable in a
    /// test*. With the limit fixed, every file a test can write has an honest
    /// `metadata` and the `metadata` refusal fires first — so deleting the
    /// re-check left the suite green, and the guarantee this function claims
    /// had no coverage at all. With a limit the caller chooses, a file whose
    /// `metadata` under-reports its length (every file in `/proc`) exercises
    /// the second check and nothing else.
    fn load_with_limit(path: &Path, limit: u64) -> Result<Self, SidecarError> {
        let io = |source| SidecarError::Io {
            path: path.to_path_buf(),
            source,
        };
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(source) => return Err(io(source)),
        };
        let len = file.metadata().map_err(io)?.len();
        if len > limit {
            return Err(SidecarError::TooLarge {
                path: path.to_path_buf(),
                len,
                limit,
            });
        }
        // One byte past the limit, so a file that grew between the `stat` and
        // the read is caught rather than silently truncated into a parse
        // error that blames the JSON.
        let mut text = String::with_capacity(len as usize);
        file.take(limit + 1).read_to_string(&mut text).map_err(io)?;
        if text.len() as u64 > limit {
            return Err(SidecarError::TooLarge {
                path: path.to_path_buf(),
                len: text.len() as u64,
                limit,
            });
        }
        Self::parse(&text, path)
    }

    /// Parses sidecar JSON. `path` is used only for error messages.
    ///
    /// The root object is **not** uniformly `"<folder>/<entry>" -> object`:
    /// the real file also carries wallet-level `$fdo_created` and
    /// `$fdo_modified` as bare strings at the root. Those are not entries and
    /// are not an error; they are counted in [`Sidecar::skipped_rows`].
    /// A repeated key is **counted**, not silently resolved. JSON has no rule
    /// against one, `serde_json` keeps the last and says nothing, and the
    /// dropped row is an entry's whole attribute map — so a file with one
    /// imports an item under attributes that came from the row that happened
    /// to be second. Last-wins is kept, because that is what every other
    /// reader of this file does and changing it would invent a different
    /// answer; what changes is that the file no longer lies about it. See
    /// [`Sidecar::duplicate_keys`].
    pub(crate) fn parse(text: &str, path: &Path) -> Result<Self, SidecarError> {
        let root: SidecarRoot =
            serde_json::from_str(text).map_err(|source| SidecarError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        let SidecarRoot::Object {
            rows,
            duplicate_keys,
        } = root
        else {
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
            duplicate_keys,
        })
    }

    /// The row for `"<folder>/<entry>"`, composed by [`sidecar_key`].
    pub(crate) fn get(&self, key: &str) -> Option<&SidecarEntry> {
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
    pub(crate) fn skipped_rows(&self) -> usize {
        self.skipped_rows
    }

    /// The row keys, so a caller can diff them against what the walk resolved.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Keys the file declared **more than once**. Each one is a row whose
    /// attribute map was discarded in favour of a later row with the same key,
    /// which the walk cannot detect afterwards because only the survivor is
    /// there to see. Carried through to
    /// [`Extraction::duplicate_sidecar_keys`].
    pub(crate) fn duplicate_keys(&self) -> &[String] {
        &self.duplicate_keys
    }
}

/// The sidecar's root value, parsed in one pass so a repeated key is visible.
///
/// `serde_json::Value` cannot express this: its object is a map, so by the
/// time the root is a `Value` the earlier of two identical keys is already
/// gone. A non-object root is a variant here rather than an error so
/// [`SidecarError::NotAnObject`] stays the message the user sees for it.
enum SidecarRoot {
    Object {
        rows: serde_json::Map<String, serde_json::Value>,
        duplicate_keys: Vec<String>,
    },
    NotAnObject,
}

impl<'de> serde::Deserialize<'de> for SidecarRoot {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::{MapAccess, SeqAccess, Visitor};

        struct RootVisitor;

        impl<'de> Visitor<'de> for RootVisitor {
            type Value = SidecarRoot;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a KWallet attribute sidecar object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                // No row cap here: `Sidecar::parse` applies `MAX_SIDECAR_ROWS`
                // and its error names the limit, which a `de::Error::custom`
                // from inside the visitor would flatten into a JSON syntax
                // error blaming the file's shape. The bound that keeps this
                // finite in the meantime is `MAX_SIDECAR_BYTES` on the read.
                let mut rows = serde_json::Map::new();
                let mut duplicate_keys = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if rows.insert(key.clone(), value).is_some() {
                        duplicate_keys.push(key);
                    }
                }
                Ok(SidecarRoot::Object {
                    rows,
                    duplicate_keys,
                })
            }

            // Every other shape is "not an object". A sequence's elements are
            // drained rather than left, so the error is about the root and not
            // about trailing input.
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(SidecarRoot::NotAnObject)
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(SidecarRoot::NotAnObject)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(SidecarRoot::NotAnObject)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(SidecarRoot::NotAnObject)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(SidecarRoot::NotAnObject)
            }
            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(SidecarRoot::NotAnObject)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(SidecarRoot::NotAnObject)
            }
        }

        de.deserialize_any(RootVisitor)
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

/// Whether `wallet` may be interpolated into a filename and sent to KWallet.
///
/// The name reaches this module from the command line, and it is interpolated
/// into `<wallet>_attributes.json` — so `../../.ssh/id` would compose a path
/// outside `kwalletd/` entirely. None of the rejected forms names a wallet
/// KWallet could have created, so nothing is lost by refusing them.
pub(crate) fn wallet_name_is_usable(wallet: &str) -> bool {
    !wallet.is_empty()
        && wallet != "."
        && wallet != ".."
        && !wallet.contains('/')
        && !wallet.contains('\0')
}

/// The sidecar path for a wallet: `$XDG_DATA_HOME/kwalletd/<wallet>_attributes.json`.
///
/// A name `wallet_name_is_usable` rejects yields the empty path, which
/// [`Sidecar::load`] reports as "no sidecar" — it never composes a path that
/// could leave `kwalletd/`. The name itself is refused with
/// [`KWalletError::InvalidWalletName`] by [`extract`], which is where the
/// user sees a message; this function has no error channel and does not need
/// one, because refusing to *name* a file is the whole of its job.
pub fn sidecar_path(wallet: &str) -> PathBuf {
    if !wallet_name_is_usable(wallet) {
        return PathBuf::new();
    }
    kwalletd_dir().join(format!("{wallet}_attributes.json"))
}

/// `$XDG_DATA_HOME/kwalletd`, with the XDG fallback.
pub(crate) fn kwalletd_dir() -> PathBuf {
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
pub(crate) fn sidecar_key(folder: &str, entry: &str) -> String {
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
pub(crate) fn decode_qmap(bytes: &[u8]) -> Result<MapPairs, MapDecodeError> {
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

    // `pairs` wipes itself on drop, so every `?` below — not only the happy
    // path — wipes the plaintext decoded so far. Malformed input is exactly
    // when that matters: it is the one case where the values are abandoned
    // mid-map. That only holds for plaintext `pairs` actually *owns*, which
    // is why the loop below pushes each string before it can fail rather than
    // holding it in a local across a `?`.
    let mut pairs = MapPairs(Vec::with_capacity(count));
    // Digests, never the keys themselves: a `BTreeSet<String>` of map keys is
    // a second, un-zeroized copy of half the plaintext, dropped to the
    // allocator on every path. A 32-byte digest answers "have I seen this?"
    // without ever holding the answer's preimage.
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    // A null `QString` and an empty one are different on the wire and the
    // same in Rust. If both appear as keys the collision is ours, not the
    // wallet's, and saying "a QMap cannot produce that" would be false.
    let mut saw_null_key = false;
    let mut saw_empty_key = false;
    for _ in 0..count {
        let (key, key_was_null) = r.qstring("map key")?;
        // Pushed before the value is read, not after both are. A `String`
        // local is wiped by nobody: an early return between the two reads —
        // a malformed value, a duplicate key — drops decoded plaintext to the
        // allocator un-wiped, which is the one thing `MapPairs` exists to make
        // impossible. Inside `pairs` it is owned by the `Drop` that wipes.
        pairs.0.push((key, String::new()));
        let (value, _) = r.qstring("map value")?;
        let (key, slot) = pairs.0.last_mut().expect("just pushed");
        *slot = value;
        if key.is_empty() {
            if key_was_null {
                saw_null_key = true;
            } else {
                saw_empty_key = true;
            }
        }
        if !seen.insert(digest(key)) {
            if saw_null_key && saw_empty_key {
                return Err(MapDecodeError::Unrepresentable {
                    what: "the map has both a null and an empty string as keys, and Rust's \
                           String cannot tell them apart",
                });
            }
            return Err(MapDecodeError::DuplicateKey);
        }
    }
    if r.remaining() != 0 {
        return Err(MapDecodeError::TrailingBytes {
            trailing: r.remaining(),
        });
    }
    Ok(pairs)
}

/// The decoded pairs of a `QMap`, wiped on drop.
///
/// The keys and the values are the map entry's *plaintext*. A bare
/// `Vec<(String, String)>` is wiped only where a caller remembers to, which
/// on an error path is nowhere; making the wipe a `Drop` makes it
/// unconditional and makes forgetting it impossible.
pub(crate) struct MapPairs(Vec<(String, String)>);

impl Drop for MapPairs {
    fn drop(&mut self) {
        for (k, v) in &mut self.0 {
            k.zeroize();
            v.zeroize();
        }
    }
}

impl Deref for MapPairs {
    type Target = [(String, String)];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Keys and values alike are secret; only the count may be printed.
impl fmt::Debug for MapPairs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MapPairs({} pairs, redacted)", self.0.len())
    }
}

/// A digest of a map key, so duplicate detection never keeps a second copy of
/// the plaintext.
fn digest(key: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(key.as_bytes()).into()
}

/// Canonical JSON for a decoded map: an object with keys in sorted order and
/// no insignificant whitespace, so re-importing the same wallet produces the
/// same bytes.
///
/// The pairs are borrowed rather than moved so the caller keeps ownership of
/// the plaintext and can zeroize it; see [`read_map_secret`].
///
/// # The buffer is sized before it is written, not grown while it is
///
/// `serde_json::to_vec` starts small and *doubles*. Each abandoned
/// intermediate is a prefix of the serialised map — that is, of the secret —
/// handed back to the allocator un-wiped, and wrapping only the final
/// allocation in [`Zeroizing`] does nothing about them. So the capacity is
/// computed up front from the worst case JSON string escaping can produce
/// (`\uXXXX`, six bytes per input byte) and the value is written into that
/// buffer, which therefore never reallocates and never leaves a copy behind.
///
/// This takes [`MapPairs`] rather than a bare slice because the duplicate-key
/// rule is [`decode_qmap`]'s: a `BTreeMap` silently keeps the *last* of any
/// repeated key, so handing this function pairs that did not come through the
/// decoder would lose data under a name that promises canonical output.
pub(crate) fn qmap_to_canonical_json(
    pairs: &MapPairs,
) -> Result<Zeroizing<Vec<u8>>, MapDecodeError> {
    let canonical: BTreeMap<&str, &str> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    // The decoded length is bounded before it sizes anything: the capacity
    // below is six bytes per decoded byte, so an over-cap map would turn
    // into a multi-megabyte `with_capacity` for a secret `check_caps`
    // refuses anyway. Canonical JSON only expands (quotes, colons, `\uXXXX`
    // escapes), so anything over the secret cap here is over it after
    // encoding too, and refusing now keeps the refusal while skipping the
    // allocation. Anything at or under the cap flows through to the normal
    // `check_caps` measurement on the encoded bytes.
    let decoded_len: usize = pairs
        .iter()
        .map(|(k, v)| k.len().saturating_add(v.len()))
        .fold(0usize, |a, b| a.saturating_add(b));
    if decoded_len > MAX_ITEM_SECRET {
        return Err(MapDecodeError::TooLarge {
            len: decoded_len,
            limit: MAX_ITEM_SECRET,
        });
    }
    // `{}` plus, per pair, two quoted strings at six bytes per byte, a colon
    // and a comma.
    let mut capacity = 2usize;
    for (k, v) in pairs.iter() {
        capacity = capacity.saturating_add(
            k.len()
                .saturating_add(v.len())
                .saturating_mul(6)
                .saturating_add(6),
        );
    }
    let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(capacity));
    serde_json::to_writer(&mut *buf, &canonical)
        .map_err(|e| MapDecodeError::Json(e.to_string()))?;
    debug_assert!(
        buf.len() <= capacity,
        "the canonical-JSON buffer reallocated, so a plaintext prefix was leaked"
    );
    Ok(buf)
}

/// [`decode_qmap`] then [`qmap_to_canonical_json`], zeroizing the decoded
/// plaintext on the way out.
///
/// The intermediate `String`s hold the map's values, which are secret. They
/// are wiped by [`MapPairs`]'s `Drop` — unconditionally, on the error path as
/// much as the happy one — which is the whole reason this wrapper exists
/// instead of the caller chaining the two.
pub(crate) fn read_map_secret(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, MapDecodeError> {
    let pairs = decode_qmap(bytes)?;
    qmap_to_canonical_json(&pairs)
}

/// Decodes the bytes `readEntry` returns for a `Password` entry: a
/// `QDataStream`-serialised `QString`.
///
/// # `readPassword` and `readEntry` do not return the same bytes
///
/// This is the whole reason this function exists. `readPassword` is declared
/// `s` on the wire and `readEntry` is declared `ay`, and the difference is not
/// a wrapper: `KWallet::Wallet::writePassword` does
/// `QDataStream ds(&a, QIODevice::WriteOnly); ds << value;` and stores *that*,
/// so what is in the wallet is a `quint32` byte length followed by big-endian
/// UTF-16 — and `readPassword` is kwalletd deserialising it for us, while
/// `readEntry` hands back the stored blob.
///
/// So the fallback used to store `00 00 00 0E 00 68 00 75 …` where the user
/// had written `hunter2`, label it `text/plain`, count it as a *recovery*, and
/// leave the user believing their wallet was safe to decommission. Deleting
/// the fallback would have been correct too — refusing one entry beats
/// corrupting it — but the bytes are a format this module already decodes, so
/// decoding them recovers the entry honestly, and anything that is not that
/// format is refused exactly the way an undecodable map is.
///
/// The buffer must be consumed **exactly**: a `QString` is the whole of what
/// `writePassword` writes, so trailing bytes mean these are not a serialised
/// password and a prefix of them is not the secret.
pub(crate) fn decode_qstring_password(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, MapDecodeError> {
    let mut r = Reader::new(bytes);
    let (mut decoded, _was_null) = r.qstring("password")?;
    if r.remaining() != 0 {
        let trailing = r.remaining();
        // The password is plaintext and this path abandons it, so it is wiped
        // here rather than dropped to the allocator: the same rule
        // `MapPairs`'s `Drop` enforces for a map.
        decoded.zeroize();
        return Err(MapDecodeError::TrailingBytes { trailing });
    }
    // `into_bytes` reuses the `String`'s allocation, so the conversion leaves
    // no second, un-wiped copy behind.
    Ok(Zeroizing::new(std::mem::take(&mut decoded).into_bytes()))
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

    /// Returns the decoded string and whether it was Qt's *null* string,
    /// which the caller needs because a null and an empty `QString` are
    /// distinct on the wire and identical here.
    ///
    /// The string is built by hand rather than with
    /// `collect::<Result<String, _>>()` because that discards a partially
    /// decoded `String` — a prefix of the plaintext — straight to the
    /// allocator when a code unit does not decode. Here the partial value is
    /// wiped before the error leaves.
    fn qstring(&mut self, field: &'static str) -> Result<(String, bool), MapDecodeError> {
        let len = self.u32(field)?;
        // Qt's null QString. Not the same as an empty one on the wire; both
        // become an empty Rust `String`, which is the only representation we
        // have and which round-trips through JSON identically.
        if len == u32::MAX {
            return Ok((String::new(), true));
        }
        let len = len as usize;
        if !len.is_multiple_of(2) {
            return Err(MapDecodeError::OddStringLength { len });
        }
        let raw = self.take(len, field)?;
        let units = raw
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]));
        // `len` is the UTF-16 *byte* length, so the string holds `len / 2`
        // code units. A code unit becomes at most three UTF-8 bytes — a
        // surrogate pair is two units and four bytes, so the per-unit
        // worst case is the 3-byte BMP scalar above U+07FF. Sizing at the
        // code-unit count instead lets `push` grow and relocate the buffer,
        // handing an un-wiped prefix of a decrypted key or value back to the
        // allocator; `out.zeroize()` below and `MapPairs`'s `Drop` only ever
        // reach the current allocation. This is the same reasoning
        // `qmap_to_canonical_json` documents for its own buffer.
        let capacity = len.saturating_mul(3) / 2;
        let mut out = String::with_capacity(capacity);
        for unit in char::decode_utf16(units) {
            match unit {
                Ok(c) => out.push(c),
                Err(_) => {
                    out.zeroize();
                    return Err(MapDecodeError::Unrepresentable {
                        what: "a string contains an unpaired UTF-16 surrogate, which QString \
                               allows and Rust's String cannot hold",
                    });
                }
            }
        }
        debug_assert!(
            out.len() <= capacity,
            "the QString buffer reallocated, so a plaintext prefix was leaked"
        );
        Ok((out, false))
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
///
/// # A `kwallet:` attribute the sidecar already carries is left alone
///
/// Nothing stops a libsecret client from having written an attribute literally
/// named `kwallet:folder`. Overwriting it would change the lookup for an
/// attribute we did not write — the same identity argument as above, one key
/// at a time — so the insert is `or_insert` and the collision is counted
/// through `conflicts` rather than resolved silently.
///
/// `conflicts` counts **entries**, not names: an entry whose row carries all
/// three `kwallet:*` names increments it once, because the CLI reports it as a
/// number of sidecar rows and one row that collides three times is still one
/// row. Every colliding name in that row is left alone all the same — the
/// counter is what is aggregated, never what is decided on.
pub(crate) fn map_entry(
    wallet: &str,
    folder: &str,
    entry: &str,
    entry_type: EntryType,
    secret: Zeroizing<Vec<u8>>,
    sidecar: Option<&SidecarEntry>,
    conflicts: &mut usize,
) -> SourceItem {
    let mut attributes = sidecar.map(|s| s.attributes.clone()).unwrap_or_default();

    // The names this call inserted, as opposed to the ones the sidecar
    // already carried. A hand-written `kwallet:key` collides below and is
    // kept as user data; it must reach `Outcome::classify` as searchable
    // rather than synthesised, so only the `Vacant` arm records.
    let mut inserted_keys = BTreeSet::new();
    if !attributes.contains_key(XDG_SCHEMA) {
        let mut collided = false;
        for (name, value) in [
            (ATTR_FOLDER, folder.to_string()),
            (ATTR_KEY, entry.to_string()),
            (ATTR_TYPE, entry_type.attribute_value()),
        ] {
            match attributes.entry(name.to_string()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(value);
                    inserted_keys.insert(name.to_string());
                }
                std::collections::btree_map::Entry::Occupied(_) => collided = true,
            }
        }
        // One entry, one count. Three collisions in one sidecar row are one
        // row that collided, and the row is what the report names.
        if collided {
            *conflicts += 1;
        }
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
        inserted_keys,
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
pub(crate) trait KWallet {
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

/// Bounds one D-Bus call at the wallet level.
///
/// `zbus` has no default reply timeout: a method call on a wedged peer waits
/// for the lifetime of the process. Every call this module makes goes through
/// this or through [`DbusReader`]'s per-entry equivalent.
async fn bounded<T>(
    call: &'static str,
    timeout: Duration,
    fut: impl std::future::Future<Output = zbus::Result<T>>,
) -> Result<T, KWalletError> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(KWalletError::CallTimedOut { call, timeout }),
    }
}

/// Whether anything could display KWallet's Qt unlock dialog.
pub(crate) fn has_display() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()))
}

/// True if `org.kde.kwalletd6` has an owner on this bus.
pub(crate) async fn service_is_running(conn: &zbus::Connection) -> Result<bool, KWalletError> {
    // Constructing a proxy is not free of the bus: zbus may introspect and
    // will register match rules, so "every call is bounded" has to include the
    // constructors or it is a claim about most of them.
    let dbus = bounded(
        "DBusProxy::new",
        DEFAULT_CALL_TIMEOUT,
        zbus::fdo::DBusProxy::new(conn),
    )
    .await?;
    let name = zbus::names::BusName::try_from(SERVICE).map_err(zbus::Error::from)?;
    match tokio::time::timeout(DEFAULT_CALL_TIMEOUT, dbus.name_has_owner(name)).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(KWalletError::CallTimedOut {
            call: "NameHasOwner",
            timeout: DEFAULT_CALL_TIMEOUT,
        }),
    }
}

/// A wallet held open by [`APP_ID`].
///
/// Deliberately not `Drop`-closing: closing is an `async` D-Bus round trip
/// and a `Drop` that cannot `await` would either block or silently skip. The
/// close is explicit and every path in [`extract`] takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalletHandle(i32);

impl WalletHandle {
    /// The wire handle. Private field, public reader: a `WalletHandle` names
    /// a wallet this process holds open, and a value anyone can construct
    /// from any `i32` is not that.
    pub(crate) const fn raw(self) -> i32 {
        self.0
    }
}

/// Opens a wallet, without ever blocking on the unlock dialog.
///
/// The signal stream is subscribed **before** `openAsync` is called. The
/// other order loses the race against an already-unlocked wallet, whose
/// `walletAsyncOpened` can be emitted before the method reply is even
/// delivered — and a missed signal is an import that waits out the whole
/// timeout for an event that already happened.
///
/// # A timeout does not cancel the open
///
/// `openAsync` has no cancel. When the wait expires the transaction is still
/// live inside kwalletd, and if the user answers the dialog afterwards the
/// wallet opens against [`APP_ID`] and emits a handle — one nobody is
/// listening for and nobody will ever `close`, which is exactly the lasting
/// side effect this module promises not to leave. So the stream is not
/// dropped on expiry: it is handed to a bounded grace task
/// ([`OPEN_GRACE`]) that closes a late handle if one arrives. The error is
/// still returned immediately; the grace task never affects the caller.
///
/// The connection is taken rather than a proxy because the grace task
/// outlives this call and needs a proxy it owns.
pub(crate) async fn open_wallet(
    conn: &zbus::Connection,
    wallet: &str,
    timeout: Duration,
) -> Result<WalletHandle, KWalletError> {
    use futures_util::StreamExt;

    let proxy = bounded(
        "KWalletProxy::new",
        DEFAULT_CALL_TIMEOUT,
        KWalletProxy::new(conn),
    )
    .await?;

    // If it is already open there is no dialog to worry about. If it is not,
    // and nothing can draw one, say so now rather than after two minutes of
    // silence: this is the SSH case, and a clear refusal is the entire point.
    // Deliberately not `unwrap_or(false)`: a failed `isOpen` says nothing
    // about the wallet, and treating it as "closed" makes the *next* line
    // report `NoDisplay` — a diagnosis about the user's session — for what is
    // really a broken call to kwalletd. A call that failed is an error.
    let already_open = bounded("isOpen", DEFAULT_CALL_TIMEOUT, proxy.is_open(wallet)).await?;
    if !already_open && !has_display() {
        return Err(KWalletError::NoDisplay {
            wallet: wallet.to_string(),
        });
    }

    // `receive_*` sends `AddMatch` to the bus daemon, so it is a call like any
    // other and is bounded like one.
    let mut opened = bounded(
        "AddMatch(walletAsyncOpened)",
        DEFAULT_CALL_TIMEOUT,
        proxy.receive_wallet_async_opened(),
    )
    .await?;

    let tid = bounded(
        "openAsync",
        DEFAULT_CALL_TIMEOUT,
        proxy.open_async(wallet, NO_WINDOW, APP_ID, false),
    )
    .await?;
    // A negative return is the error; non-negative is the transaction id.
    if tid < 0 {
        return Err(KWalletError::OpenRefused {
            wallet: wallet.to_string(),
            code: tid,
        });
    }

    let timed_out = || KWalletError::OpenTimedOut {
        wallet: wallet.to_string(),
        timeout,
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let signal = match tokio::time::timeout_at(deadline, opened.next()).await {
            Ok(s) => s,
            Err(_) => {
                spawn_open_grace(proxy, opened, tid);
                return Err(timed_out());
            }
        };
        let Some(signal) = signal else {
            // The stream ended: the connection went away, so there is nothing
            // left to hear a late handle on and no way to close one.
            return Err(timed_out());
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

/// Keeps listening for `tid` after [`open_wallet`] has given up, and closes
/// the wallet if it opens.
///
/// Bounded by [`OPEN_GRACE`] rather than unbounded: an import that has
/// already reported failure must not leave a task alive for the life of the
/// process either. If the wallet opens after the grace expires the handle is
/// genuinely lost, which is what [`KWalletError::OpenTimedOut`]'s message
/// tells the user to check for.
fn spawn_open_grace(proxy: KWalletProxy<'static>, mut opened: walletAsyncOpenedStream, tid: i32) {
    use futures_util::StreamExt;

    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + OPEN_GRACE;
        loop {
            let Ok(Some(signal)) = tokio::time::timeout_at(deadline, opened.next()).await else {
                return;
            };
            let Ok(args) = signal.args() else { continue };
            if *args.tid() != tid {
                continue;
            }
            let handle = *args.handle();
            if handle >= 0 {
                let _ =
                    tokio::time::timeout(DEFAULT_CLOSE_TIMEOUT, proxy.close(handle, false, APP_ID))
                        .await;
            }
            return;
        }
    });
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
    /// `readEntry` recovered bytes for a `Password` entry that are not a
    /// `QDataStream`-serialised `QString`, so they are not the password.
    ///
    /// Separate from [`SkipReason::MapUndecodable`] because it names a
    /// different format and a different branch, and the branch is the point:
    /// this is the fallback that used to skip the decoder entirely and store
    /// a serialised `QString` as if it were the secret. See
    /// [`decode_qstring_password`].
    #[error("the password value could not be decoded: {0}")]
    PasswordUndecodable(MapDecodeError),
    /// A read answered successfully with no bytes at all.
    ///
    /// Refused rather than imported as a zero-length secret. No KWallet
    /// writer stores an entry with nothing in it that this module can tell
    /// apart from a failed read, and a migration that silently writes an
    /// empty secret and reports success is the one direction that cannot be
    /// undone. Whether kwalletd *also* uses an empty reply as its per-entry
    /// error channel — rather than raising a D-Bus error — is recollection
    /// and was not verifiable here; the refusal is correct either way, which
    /// is why it does not rest on the answer.
    #[error("KWallet answered {call} with no bytes, so nothing was established about the entry")]
    EmptyRead { call: &'static str },
    /// `entryType` failed, or reported a type no KWallet writer produces, so
    /// the entry's type is not known.
    ///
    /// This is a refusal and not a default. Falling back to
    /// [`EntryType::Unknown`] routes the entry to `readEntry`, whose bytes for
    /// a `Map` are the *undecoded* QDataStream — which would then be written
    /// as the secret, labelled with the sidecar's `application/json`, and
    /// counted as imported. That is the exact outcome `decode_qmap` refuses,
    /// reached by a path the decoder never sees, and a false success on a
    /// secret cannot be undone later.
    ///
    /// A reported type of `0` ([`EntryType::Unknown`]) lands here too, for the
    /// same reason and not because the call failed: `writePassword`,
    /// `writeEntry` and `writeMap` produce 1, 2 and 3, so nothing that can
    /// write a wallet produces a `0` entry. (kwalletd is additionally
    /// remembered to return `0` for every failed lookup — unknown handle,
    /// missing folder, unauthorised application — rather than raising a D-Bus
    /// error, which would make the in-band `0` the *common* case; only the
    /// client library is installed here, so that half is unverified. The
    /// refusal does not depend on it.)
    #[error("KWallet would not report the entry's type, so it cannot be read safely: {0}")]
    TypeUnavailable(String),
}

/// An item the walk produced but will not write, with the spec's reason.
#[derive(Debug, Clone)]
pub struct RefusedEntry {
    pub provenance: Provenance,
    pub label: String,
    pub refusal: Refusal,
}

/// The number of non-object root values a real `<wallet>_attributes.json`
/// always has: the wallet's own `$fdo_created` and `$fdo_modified`, which are
/// bare strings at the root and are not entries.
///
/// Anything beyond these two is a sidecar in a shape this module does not
/// understand, and every entry it should have described will import with no
/// attributes at all — see [`Extraction::unexpected_sidecar_rows`].
pub const EXPECTED_NON_ENTRY_ROWS: usize = 2;

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
    /// Sidecar rows the walk did not apply to any entry.
    ///
    /// Three conditions land here and they are not the same condition:
    ///
    /// - a **stale** row, whose key no entry in the wallet composes at all —
    ///   `ksecretd` left it behind when the entry was deleted;
    /// - a row for a folder `entryList` refused, which is not stale and would
    ///   have resolved had the folder been readable (see
    ///   [`Extraction::unreadable_folders`]);
    /// - an **ambiguous** row, whose key *two* entries compose and which was
    ///   therefore deliberately used by neither — see
    ///   [`Extraction::ambiguous_sidecar_keys`], where the same key is also
    ///   listed, and which is the field that says why.
    ///
    /// So this list means "unapplied", not "orphaned": a reader who takes
    /// every entry in it as a row pointing at an entry that does not exist
    /// will go looking for a deleted entry that is in fact still there. The
    /// two lists are meant to be read together, and a key in both is the
    /// ambiguous case, not two problems.
    pub unresolved_sidecar_rows: Vec<String>,
    /// Sidecar keys that **more than one** `(folder, entry)` pair composes,
    /// and which were therefore used by none of them.
    ///
    /// `sidecar_key("accounts/3", "1")` and `sidecar_key("accounts", "3/1")`
    /// are the same string, so a wallet holding both an `accounts` and an
    /// `accounts/3` folder can have two distinct entries pointing at one row.
    /// Applying it to either would attach another item's `xdg:schema`,
    /// `server=` and `user=` — under `replace` semantics, a secret written
    /// under a different item's identity. Both entries are therefore treated
    /// as having no sidecar row, and the key is listed here.
    pub ambiguous_sidecar_keys: Vec<String>,
    /// Root values in the sidecar that were not objects — the wallet's own
    /// `$fdo_created` and `$fdo_modified` are two of these in every real file.
    /// See [`Extraction::unexpected_sidecar_rows`], which is the number worth
    /// showing a user.
    pub skipped_sidecar_rows: usize,
    /// Keys the sidecar file declared **more than once**.
    ///
    /// Each is a row that was discarded in favour of a later row with the same
    /// key — an entry's whole attribute map, dropped. Nothing downstream can
    /// notice, because only the surviving row reaches the walk, so this is the
    /// only place the condition is visible at all. Nonzero means the file is
    /// not the shape `ksecretd` writes.
    pub duplicate_sidecar_keys: Vec<String>,
    /// Sidecar fields that were present but unusable, summed over the rows
    /// that were **applied to an entry**.
    ///
    /// Not over every row in the file. A row the walk did not apply — stale,
    /// or ambiguous between two entries — contributed nothing to any item, so
    /// its malformed fields cost the migration nothing and counting them here
    /// would inflate a number whose whole meaning is "this many fields of
    /// items you imported were dropped". Those rows are reported as themselves
    /// by [`Extraction::unresolved_sidecar_rows`] and
    /// [`Extraction::ambiguous_sidecar_keys`]; the parser does measure their
    /// malformed fields, and this sum deliberately discards that.
    pub malformed_sidecar_fields: usize,
    /// Entries whose declared type was `Password`, whose `readPassword`
    /// failed, and whose `readEntry` bytes then **decoded** to the password.
    /// Counted on success only: an entry both reads failed for, or whose
    /// fallback bytes were not a serialised `QString`, is in `skipped`, and
    /// counting it here as well would make this number, and the sentence the
    /// CLI prints about it, false. Before [`decode_qstring_password`] existed
    /// this counted entries whose *serialised* `QString` had just been stored
    /// as the secret — so the number said "recovered" about the entries it had
    /// corrupted.
    ///
    /// The count exists because the type numbering is a claim about another
    /// project's enum, and a nonzero value here is the evidence that it is
    /// wrong.
    pub password_read_fallbacks: usize,
    /// The same, for a `Map` whose `readMap` failed and whose `readEntry`
    /// returned the identical bytes. The *decode* has no fallback; the read
    /// does, and it is counted for the same reason.
    pub map_read_fallbacks: usize,
    /// Entries whose sidecar row already carried an attribute named
    /// `kwallet:folder`, `kwallet:key` or `kwallet:type`. The sidecar's value
    /// was kept — overwriting an attribute we did not write changes a lookup
    /// — and the collision is counted rather than resolved silently.
    ///
    /// One **entry** per unit, however many of the three names collided in it.
    /// The CLI prints this as a number of sidecar rows, and a row carrying all
    /// three names is one row, not three.
    pub attribute_conflicts: usize,
    /// Folders `entryList` refused. Their entries are unreachable and their
    /// sidecar rows will show up in `unresolved_sidecar_rows`.
    pub unreadable_folders: Vec<String>,
    /// Folder listings skipped because the folder was already listed.
    ///
    /// A live kwalletd6 repeats every folder in `folderList` once per
    /// `open()`, so without this the same entries are imported once per
    /// copy and the header/walk count check fails the run. Folder names
    /// are unique keys — `createFolder` refuses a duplicate — so a repeat
    /// is the daemon misspeaking, never a second folder.
    pub duplicate_folders: usize,
    /// Entry listings skipped because the entry was already listed in the
    /// same folder. A folder is a map, so a repeat is the same class of
    /// daemon misspeaking as [`Extraction::duplicate_folders`].
    pub duplicate_entries: usize,
    /// Anything the run must not be silent about that is not an entry: a
    /// `close` that failed after the walk succeeded, for example. The walk's
    /// result is returned unchanged beside these; a note never masks it.
    pub notes: Vec<String>,
}

impl Extraction {
    /// Every entry the walk accounted for, written or not.
    pub fn seen(&self) -> usize {
        self.items.len() + self.refused.len() + self.skipped.len()
    }

    /// Non-object sidecar rows beyond the two every real file has.
    ///
    /// Zero is the normal case and says nothing. A nonzero value says the
    /// sidecar is not the shape this module parses — the whole file may have
    /// parsed "successfully" with no entries at all, in which case every item
    /// imports attribute-less and *nothing else in this struct says so*.
    /// `entries_without_sidecar` will be high, but that is also what a wallet
    /// of native KWallet entries looks like, so it cannot distinguish the two.
    /// This can, and a caller that does not surface it turns a silently
    /// degraded import into a reported success.
    pub fn unexpected_sidecar_rows(&self) -> usize {
        self.skipped_sidecar_rows
            .saturating_sub(EXPECTED_NON_ENTRY_ROWS)
    }
}

// ---------------------------------------------------------------------------
// Reading, and the seam that makes the walk testable
// ---------------------------------------------------------------------------

/// Why one read failed. Separate from [`KWalletError`] because these are
/// per-entry: a wedged read costs one entry, not the import.
#[derive(Debug, Clone)]
pub(crate) enum ReadError {
    /// KWallet answered with an error.
    Failed(String),
    /// KWallet did not answer at all inside the bound.
    TimedOut { call: &'static str },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Failed(e) => f.write_str(e),
            ReadError::TimedOut { call } => {
                write!(f, "{call} did not answer within {DEFAULT_CALL_TIMEOUT:?}")
            }
        }
    }
}

/// The reads [`walk`] performs, and nothing else.
///
/// This exists so the walk can be driven by something other than a live
/// kwalletd. `walk` used to take a concrete `&KWalletProxy`, which meant its
/// decisions — what a failed `entryType` does, which sidecar row an entry
/// gets, when a fallback is counted — could only be asserted by reimplementing
/// them in a test, and a test that reimplements the thing it checks passes
/// after the real code stops doing it.
///
/// It is deliberately read-only and deliberately handle-free: the handle is
/// the implementation's business, so nothing that drives a walk can address a
/// wallet it was not given.
pub(crate) trait WalletReader {
    async fn folder_list(&self) -> Result<Vec<String>, ReadError>;
    async fn entry_list(&self, folder: &str) -> Result<Vec<String>, ReadError>;
    async fn entry_type(&self, folder: &str, entry: &str) -> Result<i32, ReadError>;
    /// `Zeroizing` because a password is a password even before we decide
    /// what to do with it.
    async fn read_password(
        &self,
        folder: &str,
        entry: &str,
    ) -> Result<Zeroizing<String>, ReadError>;
    async fn read_map(&self, folder: &str, entry: &str) -> Result<Zeroizing<Vec<u8>>, ReadError>;
    async fn read_entry(&self, folder: &str, entry: &str) -> Result<Zeroizing<Vec<u8>>, ReadError>;
}

/// The live implementation: one open wallet, over D-Bus, with every call
/// bounded.
pub(crate) struct DbusReader<'a> {
    proxy: &'a KWalletProxy<'a>,
    handle: WalletHandle,
    timeout: Duration,
}

impl<'a> DbusReader<'a> {
    pub(crate) fn new(proxy: &'a KWalletProxy<'a>, handle: WalletHandle) -> Self {
        Self {
            proxy,
            handle,
            timeout: DEFAULT_CALL_TIMEOUT,
        }
    }

    async fn call<T>(
        &self,
        call: &'static str,
        fut: impl std::future::Future<Output = zbus::Result<T>>,
    ) -> Result<T, ReadError> {
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(ReadError::Failed(e.to_string())),
            Err(_) => Err(ReadError::TimedOut { call }),
        }
    }
}

impl WalletReader for DbusReader<'_> {
    async fn folder_list(&self) -> Result<Vec<String>, ReadError> {
        self.call(
            "folderList",
            self.proxy.folder_list(self.handle.raw(), APP_ID),
        )
        .await
    }

    async fn entry_list(&self, folder: &str) -> Result<Vec<String>, ReadError> {
        self.call(
            "entryList",
            self.proxy.entry_list(self.handle.raw(), folder, APP_ID),
        )
        .await
    }

    async fn entry_type(&self, folder: &str, entry: &str) -> Result<i32, ReadError> {
        self.call(
            "entryType",
            self.proxy
                .entry_type(self.handle.raw(), folder, entry, APP_ID),
        )
        .await
    }

    async fn read_password(
        &self,
        folder: &str,
        entry: &str,
    ) -> Result<Zeroizing<String>, ReadError> {
        self.call(
            "readPassword",
            self.proxy
                .read_password(self.handle.raw(), folder, entry, APP_ID),
        )
        .await
        .map(Zeroizing::new)
    }

    async fn read_map(&self, folder: &str, entry: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        self.call(
            "readMap",
            self.proxy
                .read_map(self.handle.raw(), folder, entry, APP_ID),
        )
        .await
        .map(Zeroizing::new)
    }

    async fn read_entry(&self, folder: &str, entry: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        self.call(
            "readEntry",
            self.proxy
                .read_entry(self.handle.raw(), folder, entry, APP_ID),
        )
        .await
        .map(Zeroizing::new)
    }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

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
    // Before the bus and before the filesystem: a name that cannot be a
    // wallet name is refused where the user can see why.
    if !wallet_name_is_usable(wallet) {
        return Err(KWalletError::InvalidWalletName {
            wallet: wallet.to_string(),
        });
    }
    if !service_is_running(conn).await? {
        return Err(KWalletError::ServiceUnavailable);
    }
    let proxy = bounded(
        "KWalletProxy::new",
        DEFAULT_CALL_TIMEOUT,
        KWalletProxy::new(conn),
    )
    .await?;
    let wallets = bounded("wallets", DEFAULT_CALL_TIMEOUT, proxy.wallets()).await?;
    if !wallets.iter().any(|w| w == wallet) {
        return Err(KWalletError::NoSuchWallet {
            wallet: wallet.to_string(),
        });
    }

    let handle = open_wallet(conn, wallet, open_timeout).await?;
    let mut walked = walk(&DbusReader::new(&proxy, handle), wallet, sidecar).await;
    // Deliberately not `?`: a failed close must not mask the walk's result,
    // and there is nothing a caller could do about it. Bounded on a shorter
    // leash than a read, because nothing is waiting on its answer. A failure
    // is said out loud — naming the wallet and the handle, so the user can
    // check what was left open — and recorded on the extraction beside the
    // walk's result rather than in place of it.
    let raw = handle.raw();
    match tokio::time::timeout(DEFAULT_CLOSE_TIMEOUT, proxy.close(raw, false, APP_ID)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let note = format!(
                "the wallet '{wallet}' (handle {raw}) could not be closed ({e}); \
                 it may still be held open by secret-manager-import"
            );
            eprintln!("warning: {note}");
            if let Ok(extraction) = walked.as_mut() {
                extraction.notes.push(note);
            }
        }
        Err(_) => {
            let note = format!(
                "closing the wallet '{wallet}' (handle {raw}) timed out after \
                 {DEFAULT_CLOSE_TIMEOUT:?}; it may still be held open by \
                 secret-manager-import"
            );
            eprintln!("warning: {note}");
            if let Ok(extraction) = walked.as_mut() {
                extraction.notes.push(note);
            }
        }
    }
    walked
}

/// One folder and the entries in it, as the listing pass found them.
struct Listing {
    folder: String,
    entries: Vec<String>,
}

/// The walk itself, with the wallet already open.
///
/// # Why the listing is a separate pass
///
/// A sidecar key is *composed* from `(folder, entry)`, which removes the
/// ambiguity of parsing one back — but not the ambiguity of the composition
/// itself. Two different pairs can compose the same key, and applying that one
/// row to both would give one entry the other's attribute map. The only way to
/// know a key is unique is to have composed every key first, so the listing
/// happens up front and the reads happen after.
async fn walk<R: WalletReader>(
    reader: &R,
    wallet: &str,
    sidecar: &Sidecar,
) -> Result<Extraction, KWalletError> {
    let mut out = Extraction {
        skipped_sidecar_rows: sidecar.skipped_rows(),
        duplicate_sidecar_keys: sidecar.duplicate_keys().to_vec(),
        ..Default::default()
    };

    // -- pass one: list, and count how many pairs claim each sidecar key ----
    let folders = reader.folder_list().await.map_err(|e| match e {
        ReadError::TimedOut { call } => KWalletError::CallTimedOut {
            call,
            timeout: DEFAULT_CALL_TIMEOUT,
        },
        ReadError::Failed(e) => KWalletError::Dbus(zbus::Error::Failure(e)),
    })?;

    let mut listings: Vec<Listing> = Vec::new();
    let mut claims: BTreeMap<String, usize> = BTreeMap::new();
    let mut listed = 0usize;
    let mut seen_folders: BTreeSet<String> = BTreeSet::new();
    for folder in folders {
        // A repeated folder is the daemon misspeaking (see
        // `duplicate_folders`): re-reading it would import every entry
        // twice and charge the secret budget twice for the same bytes.
        if !seen_folders.insert(folder.clone()) {
            out.duplicate_folders += 1;
            continue;
        }
        let entries = match reader.entry_list(&folder).await {
            Ok(e) => e,
            Err(_) => {
                out.unreadable_folders.push(folder);
                continue;
            }
        };
        // Same class of misspeaking one level down: a folder is a map, so
        // a repeated entry name is never a second entry.
        let mut seen_entries: BTreeSet<String> = BTreeSet::new();
        let entries: Vec<String> = entries
            .into_iter()
            .filter(|entry| {
                if seen_entries.insert(entry.clone()) {
                    true
                } else {
                    out.duplicate_entries += 1;
                    false
                }
            })
            .collect();
        if entries.is_empty() {
            out.empty_folders += 1;
            continue;
        }
        listed = listed.saturating_add(entries.len());
        if listed > MAX_ENTRIES {
            return Err(KWalletError::TooManyEntries { limit: MAX_ENTRIES });
        }
        for entry in &entries {
            *claims.entry(sidecar_key(&folder, entry)).or_insert(0) += 1;
        }
        listings.push(Listing { folder, entries });
    }
    out.ambiguous_sidecar_keys = claims
        .iter()
        .filter(|(key, n)| **n > 1 && sidecar.get(key).is_some())
        .map(|(key, _)| key.clone())
        .collect();

    // -- pass two: read ----------------------------------------------------
    let mut resolved: BTreeSet<String> = BTreeSet::new();
    // Beside `MAX_ENTRIES`, not instead of it: the count bounds how many
    // secrets are read and this bounds how large they may be together. See
    // `MAX_SECRET_BYTES`.
    let mut secret_bytes = 0usize;
    for Listing { folder, entries } in listings {
        for entry in entries {
            let key = sidecar_key(&folder, &entry);
            // A key more than one pair composes belongs to none of them. The
            // entry is treated exactly as one with no sidecar row, which is a
            // real and already-handled state, rather than being given a row
            // that may describe a different item.
            let unique = claims.get(&key).copied().unwrap_or(0) == 1;
            let row = if unique { sidecar.get(&key) } else { None };
            if row.is_some() {
                resolved.insert(key);
            } else {
                out.entries_without_sidecar += 1;
            }
            let provenance = Provenance::kwallet(wallet, &folder, &entry);

            // A failed `entryType` is a refusal, not a default. Treating it as
            // `Unknown` routes the entry to `readEntry`, whose bytes for a
            // `Map` are the undecoded QDataStream — which would then be stored
            // as the secret, labelled `application/json` by the sidecar, and
            // counted as imported. A false success on a secret is permanent,
            // and this is the one path the decoder's refusal never sees.
            let entry_type = match reader.entry_type(&folder, &entry).await {
                // `0` is `EntryType::Unknown`, which no KWallet writer
                // produces: `writePassword`, `writeEntry` and `writeMap` store
                // 1, 2 and 3. So a `0` here is not a type, and routing it to
                // `readEntry` stores an undecoded blob under whatever the
                // sidecar's content type claims — the same false success a
                // failed `entryType` would cause, reached in band. (kwalletd is
                // additionally remembered to answer `0` for every failed lookup
                // rather than raising a D-Bus error, which would make this the
                // common path and not the odd one; only the client library is
                // installed here, so that half is unverified. The refusal is
                // right under either reading, which is why it does not wait on
                // the answer.)
                Ok(code) if EntryType::from_code(code) == EntryType::Unknown => {
                    out.skipped.push(SkippedEntry {
                        provenance,
                        label: entry,
                        reason: SkipReason::TypeUnavailable(
                            "entryType reported 0 (Unknown), which no KWallet writer stores"
                                .to_string(),
                        ),
                    });
                    continue;
                }
                Ok(code) => EntryType::from_code(code),
                Err(e) => {
                    out.skipped.push(SkippedEntry {
                        provenance,
                        label: entry,
                        reason: SkipReason::TypeUnavailable(e.to_string()),
                    });
                    continue;
                }
            };

            let secret = match read_secret(reader, &folder, &entry, entry_type, &mut out).await {
                Ok(s) => s,
                // An over-cap map is refused, not skipped: the bytes decoded
                // fine and the only thing wrong with them is their size, which
                // is exactly what `check_caps` refuses two steps down. Routing
                // it through `skipped` would report a cap violation as an
                // undecodable entry.
                Err(SkipReason::MapUndecodable(MapDecodeError::TooLarge { len, limit })) => {
                    out.refused.push(RefusedEntry {
                        provenance,
                        label: entry,
                        refusal: Refusal::CapViolation {
                            cap: Cap::Secret,
                            actual: len,
                            limit,
                        },
                    });
                    continue;
                }
                Err(reason) => {
                    out.skipped.push(SkippedEntry {
                        provenance,
                        label: entry,
                        reason,
                    });
                    continue;
                }
            };
            // Checked as soon as the bytes exist, so the walk cannot be made
            // to hold more than the budget even by one enormous entry.
            secret_bytes = secret_bytes.saturating_add(secret.len());
            if secret_bytes > MAX_SECRET_BYTES {
                return Err(KWalletError::TooManySecretBytes {
                    limit: MAX_SECRET_BYTES,
                });
            }

            // Counted only now: a row whose entry the guards above skipped was
            // applied to nothing, so its malformed fields cost the migration
            // nothing, and adding them here would inflate a number that means
            // "this many fields of items you imported were dropped".
            out.malformed_sidecar_fields += row.map_or(0, |r| r.malformed_fields);

            let item = map_entry(
                wallet,
                &folder,
                &entry,
                entry_type,
                secret,
                row,
                &mut out.attribute_conflicts,
            );
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
/// `readEntry`, and the fallback is *counted* when it works, so a wrong
/// assumption shows up as a number in the report rather than as a pile of
/// missing items. An entry both reads failed for is not a fallback: it is a
/// skip, and counting it as both would make the number mean nothing.
///
/// # The fallback bytes are decoded, not copied
///
/// This doc used to say the two reads return "the same bytes". They do not:
/// `readPassword` is `s` and `readEntry` is `ay`, because kwalletd
/// deserialises the stored `QDataStream` `QString` for the first and hands
/// back the stored blob for the second. Copying the blob through stored
/// `00 00 00 0E 00 68 00 75 …` for `hunter2`, labelled `text/plain`, counted
/// as a *recovery*, and reported to the user as safe to decommission — the
/// exact failure [`SkipReason::MapUndecodable`] exists to prevent, on the one
/// branch that skipped the decoder. The fallback now goes through
/// [`decode_qstring_password`] and refuses anything that is not a serialised
/// `QString`.
///
/// A `Map`'s *read* falls back the same way and is counted the same way; its
/// **decode** is what gets no fallback. Its bytes are not the secret, the
/// decoded map is, and an undecodable map is refused with a reason rather than
/// written as an opaque blob that no one will ever recognise.
///
/// # An empty reply is not a secret
///
/// Every branch refuses a read that succeeded with no bytes. No supported
/// KWallet writer produces an entry this module could tell apart from a failed
/// read, so importing a zero-length secret and counting it as a success is the
/// one outcome here that cannot be undone. (kwalletd is additionally
/// remembered to signal a per-entry failure with an empty `QString`/
/// `QByteArray` rather than a D-Bus error; only the client library is
/// installed here, so that half is unverified and the refusal does not rest on
/// it.) The `Map` branch was previously protected only by accident —
/// `decode_qmap(b"")` is `Truncated` — which is why the gap was invisible.
async fn read_secret<R: WalletReader>(
    reader: &R,
    folder: &str,
    entry: &str,
    entry_type: EntryType,
    out: &mut Extraction,
) -> Result<Zeroizing<Vec<u8>>, SkipReason> {
    match entry_type {
        EntryType::Password => {
            let first = match reader.read_password(folder, entry).await {
                // The `String` is moved out of the `Zeroizing` wrapper and its
                // buffer reused, so the conversion leaves no un-zeroized copy.
                Ok(mut s) if !s.is_empty() => {
                    return Ok(Zeroizing::new(std::mem::take(&mut *s).into_bytes()));
                }
                // An empty answer establishes nothing, so it is treated as a
                // failed read and the fallback decides — not as a password
                // that happens to be "".
                Ok(_) => "readPassword answered with an empty string".to_string(),
                Err(e) => e.to_string(),
            };
            let raw = reader.read_entry(folder, entry).await.map_err(|second| {
                SkipReason::Unreadable(format!(
                    "readPassword failed ({first}) and readEntry failed ({second})"
                ))
            })?;
            if raw.is_empty() {
                return Err(SkipReason::EmptyRead { call: "readEntry" });
            }
            // `readEntry` hands back the *stored* blob, which for a password
            // is a serialised `QString` and not the password. Decoded, or
            // refused: storing the blob is the corruption this branch used to
            // commit.
            let recovered =
                decode_qstring_password(&raw).map_err(SkipReason::PasswordUndecodable)?;
            // Counted here and not before the attempt: a fallback that did not
            // recover the password is a skip, not a recovery.
            out.password_read_fallbacks += 1;
            Ok(recovered)
        }
        EntryType::Map => {
            let raw = match reader.read_map(folder, entry).await {
                Ok(v) if !v.is_empty() => v,
                first => {
                    let first = match first {
                        Ok(_) => "readMap answered with no bytes".to_string(),
                        Err(e) => e.to_string(),
                    };
                    // `readEntry` returns the identical bytes for a map entry
                    // — both are `ay` and both are the stored blob — so it is
                    // a legitimate retry for a refused `readMap`, and the
                    // decode below is what actually decides.
                    let recovered = reader.read_entry(folder, entry).await.map_err(|second| {
                        SkipReason::Unreadable(format!(
                            "readMap failed ({first}) and readEntry failed ({second})"
                        ))
                    })?;
                    if recovered.is_empty() {
                        return Err(SkipReason::EmptyRead { call: "readEntry" });
                    }
                    out.map_read_fallbacks += 1;
                    recovered
                }
            };
            Ok(read_map_secret(&raw)?)
        }
        EntryType::Stream | EntryType::Unknown | EntryType::Other(_) => {
            let raw = reader
                .read_entry(folder, entry)
                .await
                .map_err(|e| SkipReason::Unreadable(e.to_string()))?;
            if raw.is_empty() {
                return Err(SkipReason::EmptyRead { call: "readEntry" });
            }
            Ok(raw)
        }
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

    /// Serialises `s` exactly as `QDataStream << QString` does, which is what
    /// `KWallet::Wallet::writePassword` stores and therefore what `readEntry`
    /// hands back for a `Password` entry: a big-endian `quint32` **byte**
    /// length, then UTF-16BE.
    fn qstring_bytes(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = ((units.len() * 2) as u32).to_be_bytes().to_vec();
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
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
            &mut 0,
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
            &mut 0,
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
            &mut 0,
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
            &mut 0,
        );
        assert_eq!(item.attributes.len(), 3);
        assert_eq!(item.attributes[ATTR_KEY], "/home/joseph/.ssh/id_ed25519");
        assert_eq!(item.label, "/home/joseph/.ssh/id_ed25519");
        assert_eq!(item.content_type, "text/plain");
        // Never `now()`.
        assert_eq!((item.created, item.modified), (0, 0));
        // The three `kwallet:` keys are ones *we* synthesised, so
        // `Outcome::classify` does not count them: nothing that existed
        // before the import was preserved, and an item findable only by a
        // name this import invented is "preserved only".
        assert_eq!(item.outcome(), Outcome::PreservedOnly);
    }

    /// A sidecar row that already carries a `kwallet:` name collides rather
    /// than being overwritten — and the collision is what keeps the item
    /// searchable. The name was written by hand, so it is absent from
    /// `inserted_keys` and the exact classifier counts it; a by-name test
    /// reports this item `PreservedOnly` although a client could search on
    /// the very attribute the sidecar recorded.
    #[test]
    fn a_hand_written_kwallet_key_is_kept_and_counts_as_searchable() {
        let row = sidecar_entry(&[(ATTR_KEY, "their key")]);
        let mut conflicts = 0;
        let item = map_entry(
            "kdewallet",
            "Passwords",
            "router",
            EntryType::Password,
            secret(),
            Some(&row),
            &mut conflicts,
        );
        assert_eq!(conflicts, 1);
        // The sidecar's value survived; nothing this call wrote sits under
        // that name.
        assert_eq!(item.attributes[ATTR_KEY], "their key");
        assert!(
            !item.inserted_keys.contains(ATTR_KEY),
            "a collided name was recorded as inserted: {:?}",
            item.inserted_keys
        );
        assert!(item.inserted_keys.contains(ATTR_FOLDER));
        assert!(item.inserted_keys.contains(ATTR_TYPE));
        // And because the surviving name is user data, the item is
        // searchable rather than preserved-only.
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
            &mut 0,
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
            let item = map_entry("w", "f", "e", ty, secret(), None, &mut 0);
            assert_eq!(item.content_type, expected, "{ty} with no sidecar");
            assert_eq!(item.attributes[ATTR_TYPE], ty.attribute_value());

            let mut row = sidecar_entry(&[]);
            row.content_type = Some("text/plain; charset=utf8".into());
            let item = map_entry("w", "f", "e", ty, secret(), Some(&row), &mut 0);
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
        let item = map_entry(
            "w",
            "f",
            "e",
            EntryType::Stream,
            secret(),
            Some(row),
            &mut 0,
        );
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
    }

    /// Composing removes the ambiguity of *parsing* a key. It does not remove
    /// the ambiguity of the composition, and this collision is a bug, not a
    /// safety argument: two different `(folder, entry)` pairs name one row, so
    /// a wallet holding both would give two entries the same attribute map —
    /// including the other item's `xdg:schema`, `server=` and `user=`.
    /// `walk` therefore refuses such a key for every claimant; see
    /// `a_sidecar_key_two_entries_claim_is_used_by_neither`.
    #[test]
    fn one_sidecar_key_can_name_two_different_entries() {
        assert_eq!(
            sidecar_key("accounts/3", "1"),
            sidecar_key("accounts", "3/1")
        );
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

    /// The `take` is the guarantee and the `metadata` check is only an early
    /// refusal — so the `take` needs a case where `metadata` does not fire.
    /// Every file a test can *write* has an honest length, which is why
    /// deleting this re-check left the suite green; a `/proc` file reports a
    /// length of zero and has content, which is exactly the shape the
    /// re-check exists for.
    #[test]
    fn a_file_whose_metadata_understates_its_length_is_still_bounded() {
        let path = Path::new("/proc/self/maps");
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            0,
            "this test needs a file whose metadata understates its length"
        );
        match Sidecar::load_with_limit(path, 64).unwrap_err() {
            SidecarError::TooLarge { len, limit, .. } => {
                assert_eq!(len, 65, "the read was not stopped one byte past the limit");
                assert_eq!(limit, 64);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// A repeated key silently loses a whole row — an entry's entire attribute
    /// map — because `serde_json` keeps the last and says nothing. Last-wins
    /// is kept, since every other reader of the file does the same; what is
    /// not kept is the silence.
    #[test]
    fn a_duplicate_sidecar_key_is_reported_rather_than_silently_resolved() {
        let s = parse(
            r#"{"f/e": {"attributes": {"server": "first"}},
                "f/e": {"attributes": {"server": "second"}}}"#,
        );
        assert_eq!(s.duplicate_keys(), ["f/e"]);
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("f/e").unwrap().attributes["server"], "second");
    }

    /// And the walk carries it out to the caller, which is the only place the
    /// condition is visible at all: only the surviving row ever reaches it.
    #[tokio::test]
    async fn duplicate_sidecar_keys_reach_the_extraction() {
        let fake = FakeWallet::default()
            .folder("f", &["e"])
            .password("f", "e", "v");
        let sidecar = parse(r#"{"f/e": {"attributes": {}}, "f/e": {"attributes": {}}}"#);

        let out = walked(&fake, &sidecar).await;

        assert_eq!(out.duplicate_sidecar_keys, ["f/e"]);
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

    /// The capacity is six bytes per decoded byte, so an over-cap map must
    /// be refused *before* it sizes the buffer: sizing first turns one entry
    /// into a ~6 MiB pre-allocation for a secret that is never written. The
    /// refusal names the secret cap, so the walk reports it as refused
    /// rather than skipped.
    #[test]
    fn an_over_cap_map_is_refused_before_sizing_its_buffer() {
        let big = "v".repeat(MAX_ITEM_SECRET + 1);
        let bytes = qmap_bytes(&[("k", big.as_str())]);
        match read_map_secret(&bytes) {
            Err(MapDecodeError::TooLarge { len, limit }) => {
                assert_eq!(limit, MAX_ITEM_SECRET);
                assert!(len > MAX_ITEM_SECRET, "{len}");
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
        // At the cap is fine: the comparison is `>`, matching `check_caps`.
        let at_cap = "v".repeat(MAX_ITEM_SECRET - 1);
        assert!(read_map_secret(&qmap_bytes(&[("k", at_cap.as_str())])).is_ok());
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
        assert_eq!(*pairs, [("kv".to_string(), String::new())]);
    }

    /// Non-ASCII and astral-plane characters are the case a naive latin-1
    /// decode would corrupt silently.
    #[test]
    fn utf16_surrogate_pairs_survive() {
        let bytes = qmap_bytes(&[("kéy", "🔑 välue")]);
        let pairs = decode_qmap(&bytes).unwrap();
        assert_eq!(*pairs, [("kéy".to_string(), "🔑 välue".to_string())]);
    }

    /// The decoded string must never outgrow the buffer it was allocated
    /// with. A `String` that reallocates copies the plaintext decoded so far
    /// into a new allocation and frees the old one *unwiped* — neither
    /// `zeroize` on the error path nor `MapPairs`'s `Drop` can reach a freed
    /// allocation. A correctness assertion cannot see this, so what is
    /// asserted here is the capacity: it must still be the one the decoder
    /// asked for, because a grown buffer is a moved buffer.
    #[test]
    fn qstring_never_reallocates_and_so_never_leaks_a_plaintext_prefix() {
        for value in [
            "\u{7ff}".repeat(400), // two UTF-8 bytes, one code unit
            "康".repeat(400),      // three UTF-8 bytes, one code unit — the worst case
            "🔑".repeat(400),      // four UTF-8 bytes, two code units
            "a康🔑\u{7ff}".repeat(100),
        ] {
            let bytes = qmap_bytes(&[("k", value.as_str())]);
            let mut r = Reader::new(&bytes);
            assert_eq!(r.u32("count").unwrap(), 1);
            let (_key, _) = r.qstring("key").unwrap();
            let (decoded, _) = r.qstring("value").unwrap();
            assert_eq!(decoded, value, "the decode must still be correct");

            // What `qstring` asks for: three bytes per UTF-16 code unit.
            // Ask the allocator the same question rather than assuming
            // `with_capacity` is exact.
            let units = value.encode_utf16().count();
            let want = String::with_capacity(units * 3).capacity();
            assert_eq!(
                decoded.capacity(),
                want,
                "the QString buffer reallocated while decoding {units} code units \
                 into {} bytes, leaking an un-wiped plaintext prefix",
                decoded.len(),
            );
        }
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
        // An unpaired surrogate is a *legal* QString that Rust's String
        // cannot hold, so the message must say so rather than blame the
        // wallet for corruption that is not there.
        let mut bad = 1u32.to_be_bytes().to_vec();
        bad.extend_from_slice(&2u32.to_be_bytes());
        bad.extend_from_slice(&0xD800u16.to_be_bytes());
        bad.extend_from_slice(&0u32.to_be_bytes());
        match decode_qmap(&bad) {
            Err(MapDecodeError::Unrepresentable { what }) => {
                assert!(what.contains("surrogate"), "{what}");
            }
            other => panic!("expected Unrepresentable, got {other:?}"),
        }
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

    // -- the walk, driven by a fake wallet ---------------------------------

    /// An in-memory [`WalletReader`].
    ///
    /// The point of the seam. Every decision the walk makes — what a failed
    /// `entryType` costs, which sidecar row an entry is given, when a
    /// fallback counts as a recovery — is a decision about a *reply*, and
    /// until there was something other than kwalletd that could produce a
    /// reply, none of them could be asserted except by writing the same
    /// filter twice and calling the agreement a test.
    #[derive(Default)]
    struct FakeWallet {
        folders: Vec<(String, Vec<String>)>,
        unreadable: BTreeSet<String>,
        types: BTreeMap<(String, String), Result<i32, String>>,
        passwords: BTreeMap<(String, String), Result<String, String>>,
        maps: BTreeMap<(String, String), Result<Vec<u8>, String>>,
        raw: BTreeMap<(String, String), Result<Vec<u8>, String>>,
    }

    impl FakeWallet {
        fn folder(mut self, folder: &str, entries: &[&str]) -> Self {
            self.folders.push((
                folder.to_string(),
                entries.iter().map(|e| (*e).to_string()).collect(),
            ));
            self
        }

        /// A plain password entry: the type resolves and `readPassword` works.
        fn password(mut self, folder: &str, entry: &str, value: &str) -> Self {
            let k = (folder.to_string(), entry.to_string());
            self.types.insert(k.clone(), Ok(EntryType::Password.code()));
            self.passwords.insert(k, Ok(value.to_string()));
            self
        }

        fn entry_type(mut self, folder: &str, entry: &str, ty: Result<i32, &str>) -> Self {
            self.types.insert(
                (folder.to_string(), entry.to_string()),
                ty.map_err(str::to_string),
            );
            self
        }

        fn read_password(mut self, folder: &str, entry: &str, v: Result<&str, &str>) -> Self {
            self.passwords.insert(
                (folder.to_string(), entry.to_string()),
                v.map(str::to_string).map_err(str::to_string),
            );
            self
        }

        fn read_map(mut self, folder: &str, entry: &str, v: Result<Vec<u8>, &str>) -> Self {
            self.maps.insert(
                (folder.to_string(), entry.to_string()),
                v.map_err(str::to_string),
            );
            self
        }

        fn read_entry(mut self, folder: &str, entry: &str, v: Result<Vec<u8>, &str>) -> Self {
            self.raw.insert(
                (folder.to_string(), entry.to_string()),
                v.map_err(str::to_string),
            );
            self
        }
    }

    fn looked_up<T: Clone>(
        table: &BTreeMap<(String, String), Result<T, String>>,
        folder: &str,
        entry: &str,
    ) -> Result<T, ReadError> {
        match table.get(&(folder.to_string(), entry.to_string())) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(e)) => Err(ReadError::Failed(e.clone())),
            None => Err(ReadError::Failed("no such entry".into())),
        }
    }

    impl WalletReader for FakeWallet {
        async fn folder_list(&self) -> Result<Vec<String>, ReadError> {
            Ok(self.folders.iter().map(|(f, _)| f.clone()).collect())
        }

        async fn entry_list(&self, folder: &str) -> Result<Vec<String>, ReadError> {
            if self.unreadable.contains(folder) {
                return Err(ReadError::Failed("refused".into()));
            }
            Ok(self
                .folders
                .iter()
                .find(|(f, _)| f == folder)
                .map(|(_, e)| e.clone())
                .unwrap_or_default())
        }

        async fn entry_type(&self, folder: &str, entry: &str) -> Result<i32, ReadError> {
            looked_up(&self.types, folder, entry)
        }

        async fn read_password(
            &self,
            folder: &str,
            entry: &str,
        ) -> Result<Zeroizing<String>, ReadError> {
            looked_up(&self.passwords, folder, entry).map(Zeroizing::new)
        }

        async fn read_map(
            &self,
            folder: &str,
            entry: &str,
        ) -> Result<Zeroizing<Vec<u8>>, ReadError> {
            looked_up(&self.maps, folder, entry).map(Zeroizing::new)
        }

        async fn read_entry(
            &self,
            folder: &str,
            entry: &str,
        ) -> Result<Zeroizing<Vec<u8>>, ReadError> {
            looked_up(&self.raw, folder, entry).map(Zeroizing::new)
        }
    }

    async fn walked(reader: &FakeWallet, sidecar: &Sidecar) -> Extraction {
        walk(reader, "kdewallet", sidecar).await.unwrap()
    }

    /// **The one that must never regress.** `entryType` failing used to
    /// default to `Unknown`, which dispatches to `readEntry` — and for a `Map`
    /// those bytes are the *undecoded* QDataStream. The blob was written as
    /// the secret, given the sidecar's `application/json` content type, and
    /// counted as imported: a false success on a secret, reached by the one
    /// path the decoder's refusal never sees.
    ///
    /// Both shapes of failure are driven, and the second is the one that
    /// matters. This test used to drive only `Err(…)` — a *transport* error,
    /// which an `i`-returning method cannot produce for a missing entry — so
    /// the refusal was real here and unreachable in production: a live daemon
    /// reports the failure in band as `0`, which is `EntryType::Unknown`,
    /// which dispatched straight to `readEntry`.
    #[tokio::test]
    async fn a_refused_entry_type_is_skipped_rather_than_read_as_raw_bytes() {
        let blob = qmap_bytes(&[("user", "joseph"), ("password", "hunter2")]);
        for reported in [Err("no such entry"), Ok(EntryType::Unknown.code())] {
            let fake = FakeWallet::default()
                .folder("Secret Service", &["credential"])
                .entry_type("Secret Service", "credential", reported)
                .read_entry("Secret Service", "credential", Ok(blob.clone()));
            let sidecar =
                parse(r#"{"Secret Service/credential": {"$fdo_mime_type": "application/json"}}"#);

            let out = walked(&fake, &sidecar).await;

            assert!(
                out.items.is_empty(),
                "the entry was imported ({reported:?}): {:?}",
                out.items
            );
            assert_eq!(out.skipped.len(), 1, "{reported:?}");
            assert!(
                matches!(out.skipped[0].reason, SkipReason::TypeUnavailable(_)),
                "{:?}",
                out.skipped[0].reason
            );
            // And in particular the raw stream never became a secret.
            assert!(!out.items.iter().any(|i| *i.secret == blob));
        }
    }

    /// A sidecar key two `(folder, entry)` pairs compose belongs to neither.
    /// Applying it to either would give one entry the other's `xdg:schema`,
    /// `server=` and `user=` — under `replace` semantics, a secret written
    /// under a different item's identity.
    #[tokio::test]
    async fn a_sidecar_key_two_entries_claim_is_used_by_neither() {
        let fake = FakeWallet::default()
            .folder("accounts/3", &["1"])
            .password("accounts/3", "1", "one")
            .folder("accounts", &["3/1"])
            .password("accounts", "3/1", "two");
        let sidecar = parse(
            r#"{"accounts/3/1": {"attributes": {"xdg:schema": "org.freedesktop.Secret.Generic",
                                                "server": "example.com"}}}"#,
        );

        let out = walked(&fake, &sidecar).await;

        assert_eq!(out.items.len(), 2);
        for item in &out.items {
            assert!(
                !item.attributes.contains_key("xdg:schema"),
                "an ambiguous row was applied: {:?}",
                item.attributes.keys().collect::<Vec<_>>()
            );
            assert!(!item.attributes.contains_key("server"));
            // Treated exactly as an entry with no row: the `kwallet:` keys.
            assert!(item.attributes.contains_key(ATTR_FOLDER));
        }
        assert_eq!(out.ambiguous_sidecar_keys, ["accounts/3/1"]);
        assert_eq!(out.entries_without_sidecar, 2);
        // Nothing claimed the row, so it is also reported as unresolved
        // rather than quietly counting as used.
        assert_eq!(out.unresolved_sidecar_rows, ["accounts/3/1"]);
    }

    /// A row exactly one pair composes is still applied. The refusal above
    /// must not cost the ordinary case.
    #[tokio::test]
    async fn an_unambiguous_sidecar_key_is_still_applied() {
        let fake = FakeWallet::default()
            .folder("accounts", &["3/1"])
            .password("accounts", "3/1", "two");
        let sidecar = parse(r#"{"accounts/3/1": {"attributes": {"server": "example.com"}}}"#);

        let out = walked(&fake, &sidecar).await;

        assert_eq!(out.items.len(), 1);
        assert_eq!(out.items[0].attributes["server"], "example.com");
        assert!(out.ambiguous_sidecar_keys.is_empty());
        assert_eq!(out.entries_without_sidecar, 0);
        assert!(out.unresolved_sidecar_rows.is_empty());
    }

    /// A key no entry composes is a real condition — a stale row `ksecretd`
    /// left behind — and is reported, not dropped. Asserted through `walk`,
    /// because a test that reimplements `walk`'s filter still passes after
    /// `walk` stops applying it.
    #[tokio::test]
    async fn unresolvable_keys_are_visible_to_the_caller() {
        let fake = FakeWallet::default()
            .folder("Here", &["now"])
            .password("Here", "now", "v");
        let sidecar = parse(r#"{"Gone/away": {"attributes": {}}, "Here/now": {"attributes": {}}}"#);

        let out = walked(&fake, &sidecar).await;

        assert_eq!(out.unresolved_sidecar_rows, ["Gone/away"]);
        assert_eq!(out.items.len(), 1);
    }

    /// The fallback counter names what `readEntry` *recovered*, and what it
    /// recovered has to be the password.
    ///
    /// `read_entry` is fed the **wire form** — `readEntry` is `ay` and returns
    /// the stored `QDataStream` `QString`, not the plain UTF-8 bytes an
    /// earlier version of this test invented — and the recovered secret's
    /// bytes are asserted. With plain `b"hunter2"` and no assertion on the
    /// stored bytes, this test passed while the fallback wrote
    /// `00 00 00 0E 00 68 00 75 …` into the vault, labelled it `text/plain`,
    /// and counted it as a recovery. The sibling
    /// `a_map_read_falls_back_and_is_counted` did assert its bytes; the
    /// asymmetry was the whole of the defect.
    #[tokio::test]
    async fn a_password_fallback_recovers_the_password_and_is_counted() {
        let fake = FakeWallet::default()
            .folder("f", &["recovered", "lost"])
            .entry_type("f", "recovered", Ok(EntryType::Password.code()))
            .read_password("f", "recovered", Err("not a password"))
            .read_entry("f", "recovered", Ok(qstring_bytes("hunter2")))
            .entry_type("f", "lost", Ok(EntryType::Password.code()))
            .read_password("f", "lost", Err("not a password"))
            .read_entry("f", "lost", Err("denied"));

        let out = walked(&fake, &Sidecar::empty()).await;

        assert_eq!(out.items.len(), 1);
        assert_eq!(
            &*out.items[0].secret, b"hunter2",
            "the fallback stored something that is not the password"
        );
        assert_eq!(out.skipped.len(), 1);
        assert_eq!(
            out.password_read_fallbacks, 1,
            "an entry that was skipped was counted as a recovery"
        );
    }

    /// A live kwalletd6 repeats every folder in `folderList` once per
    /// `open()` — 2x, then 3x, then 4x observed against one real daemon —
    /// so the walk must treat a repeated folder as the same folder, not a
    /// second one. Without the dedupe each entry is imported once per copy
    /// and the header/walk count check fails the whole run.
    #[tokio::test]
    async fn a_folder_list_that_repeats_a_folder_imports_its_entries_once() {
        let fake = FakeWallet::default()
            .folder("Passwords", &["a"])
            .folder("Passwords", &["a"])
            .password("Passwords", "a", "hunter2");

        let out = walked(&fake, &Sidecar::empty()).await;

        assert_eq!(
            out.items.len(),
            1,
            "the folder was walked twice: {:?}",
            out.items.iter().map(|i| &i.label).collect::<Vec<_>>()
        );
        assert_eq!(out.duplicate_folders, 1);
        assert_eq!(out.duplicate_entries, 0);
    }

    /// The same misspeaking one level down: a folder is a map, so a
    /// repeated entry name is never a second entry.
    #[tokio::test]
    async fn an_entry_list_that_repeats_an_entry_imports_it_once() {
        let fake = FakeWallet::default()
            .folder("Passwords", &["a", "a"])
            .password("Passwords", "a", "hunter2");

        let out = walked(&fake, &Sidecar::empty()).await;

        assert_eq!(out.items.len(), 1);
        assert_eq!(out.duplicate_entries, 1);
        assert_eq!(out.duplicate_folders, 0);
    }

    /// Fallback bytes that are not a serialised `QString` are refused, not
    /// stored. There is no shape of `readEntry` reply that becomes a secret
    /// without going through the decoder.
    #[tokio::test]
    async fn a_password_fallback_refuses_bytes_that_are_not_a_qstring() {
        // Plain UTF-8, which is what the old test fed and what the old code
        // would have stored verbatim: as a `QString` it declares 0x68756e74
        // bytes and truncates immediately.
        for blob in [
            b"hunter2".to_vec(),
            // A well-formed `QString` with one byte glued on the end: a prefix
            // of a password is not a password.
            {
                let mut b = qstring_bytes("hunter2");
                b.push(0);
                b
            },
        ] {
            let fake = FakeWallet::default()
                .folder("f", &["p"])
                .entry_type("f", "p", Ok(EntryType::Password.code()))
                .read_password("f", "p", Err("not a password"))
                .read_entry("f", "p", Ok(blob.clone()));

            let out = walked(&fake, &Sidecar::empty()).await;

            assert!(out.items.is_empty(), "stored {blob:?}");
            assert_eq!(out.password_read_fallbacks, 0, "counted as a recovery");
            assert!(
                matches!(out.skipped[0].reason, SkipReason::PasswordUndecodable(_)),
                "{:?}",
                out.skipped[0].reason
            );
        }
    }

    /// A `readPassword` that works is not touched by any of this: its reply is
    /// already the deserialised string.
    #[tokio::test]
    async fn a_successful_read_password_is_the_secret_verbatim() {
        let fake = FakeWallet::default()
            .folder("f", &["p"])
            .password("f", "p", "hunter2");

        let out = walked(&fake, &Sidecar::empty()).await;

        assert_eq!(&*out.items[0].secret, b"hunter2");
        assert_eq!(out.password_read_fallbacks, 0);
    }

    /// An empty reply is not a zero-length secret.
    ///
    /// No supported KWallet writer produces an entry this module could tell
    /// apart from a failed read, and kwalletd is remembered to report a
    /// per-entry failure this way rather than by raising a D-Bus error.
    /// Importing it and reporting success is the direction that cannot be
    /// undone. The `Map` branch was protected only by accident —
    /// `decode_qmap(b"")` is `Truncated` — so only the other two were live.
    #[tokio::test]
    async fn an_empty_reply_is_refused_rather_than_imported_as_an_empty_secret() {
        let fake = FakeWallet::default()
            .folder("f", &["password", "stream", "map"])
            .entry_type("f", "password", Ok(EntryType::Password.code()))
            .read_password("f", "password", Ok(""))
            .read_entry("f", "password", Ok(Vec::new()))
            .entry_type("f", "stream", Ok(EntryType::Stream.code()))
            .read_entry("f", "stream", Ok(Vec::new()))
            .entry_type("f", "map", Ok(EntryType::Map.code()))
            .read_map("f", "map", Ok(Vec::new()))
            .read_entry("f", "map", Ok(Vec::new()));

        let out = walked(&fake, &Sidecar::empty()).await;

        assert!(out.items.is_empty(), "{:?}", out.items);
        assert_eq!(out.skipped.len(), 3);
        assert_eq!(
            out.password_read_fallbacks, 0,
            "an empty reply was counted as a recovery"
        );
        assert_eq!(out.map_read_fallbacks, 0);
        for skipped in &out.skipped {
            assert!(
                matches!(
                    skipped.reason,
                    SkipReason::EmptyRead { .. } | SkipReason::Unreadable(_)
                ),
                "{:?}",
                skipped.reason
            );
        }
    }

    /// A walk is bounded by bytes as well as by entries. `MAX_ENTRIES` alone
    /// permits ~200 GiB resident, at which point the process dies with the
    /// wallet still held open by `APP_ID`.
    #[tokio::test]
    async fn the_walk_refuses_to_hold_more_than_the_byte_budget() {
        let big = vec![b'x'; 8 << 20];
        let names: Vec<String> = (0..40).map(|n| format!("e{n}")).collect();
        let mut fake = FakeWallet::default()
            .folder("f", &names.iter().map(String::as_str).collect::<Vec<_>>());
        for name in &names {
            fake = fake
                .entry_type("f", name, Ok(EntryType::Stream.code()))
                .read_entry("f", name, Ok(big.clone()));
        }

        let e = walk(&fake, "kdewallet", &Sidecar::empty())
            .await
            .expect_err("the walk held 320 MiB of secrets and said nothing");
        assert!(
            matches!(e, KWalletError::TooManySecretBytes { limit } if limit == MAX_SECRET_BYTES),
            "{e:?}"
        );
    }

    /// A row whose entry never became an item contributed nothing to any item,
    /// so its malformed fields are not counted against the import. The doc
    /// said this before the code did.
    #[tokio::test]
    async fn malformed_fields_of_a_skipped_entrys_row_are_not_counted() {
        let fake = FakeWallet::default().folder("f", &["gone"]).entry_type(
            "f",
            "gone",
            Err("no such entry"),
        );
        let sidecar = parse(r#"{"f/gone": {"$fdo_created": "not a number"}}"#);

        let out = walked(&fake, &sidecar).await;

        assert_eq!(out.skipped.len(), 1);
        assert_eq!(
            out.malformed_sidecar_fields, 0,
            "a row for an entry that was skipped was counted against the import"
        );
    }

    /// A `Map`'s *read* does fall back, and is counted. Only the **decode**
    /// has no fallback — the module docs used to say otherwise, and nothing
    /// counted the map fallbacks at all.
    #[tokio::test]
    async fn a_map_read_falls_back_and_is_counted() {
        let good = qmap_bytes(&[("user", "joseph")]);
        let fake = FakeWallet::default()
            .folder("f", &["m"])
            .entry_type("f", "m", Ok(EntryType::Map.code()))
            .read_map("f", "m", Err("refused"))
            .read_entry("f", "m", Ok(good));

        let out = walked(&fake, &Sidecar::empty()).await;

        assert_eq!(out.map_read_fallbacks, 1);
        assert_eq!(out.items.len(), 1);
        assert_eq!(
            std::str::from_utf8(&out.items[0].secret).unwrap(),
            r#"{"user":"joseph"}"#
        );
    }

    /// An undecodable map is refused however its bytes were obtained. The
    /// decode is the thing with no fallback.
    #[tokio::test]
    async fn an_undecodable_map_is_skipped_not_stored_as_a_blob() {
        let fake = FakeWallet::default()
            .folder("f", &["m"])
            .entry_type("f", "m", Ok(EntryType::Map.code()))
            .read_map("f", "m", Ok(b"hunter2".to_vec()));

        let out = walked(&fake, &Sidecar::empty()).await;

        assert!(out.items.is_empty());
        assert!(matches!(
            out.skipped[0].reason,
            SkipReason::MapUndecodable(_)
        ));
    }

    /// A sidecar attribute already named `kwallet:folder` is ours to read,
    /// not to overwrite: an attribute we did not write and then changed is a
    /// changed lookup. Kept, and counted.
    #[tokio::test]
    async fn an_existing_kwallet_attribute_is_kept_and_counted() {
        let fake = FakeWallet::default()
            .folder("Passwords", &["router"])
            .password("Passwords", "router", "v");
        let sidecar =
            parse(r#"{"Passwords/router": {"attributes": {"kwallet:folder": "theirs"}}}"#);

        let out = walked(&fake, &sidecar).await;

        assert_eq!(out.items[0].attributes[ATTR_FOLDER], "theirs");
        assert_eq!(out.attribute_conflicts, 1);
    }

    /// The counter counts **entries**, not colliding names.
    ///
    /// The CLI renders it as "N sidecar rows already carried an attribute
    /// named kwallet:folder, kwallet:key or kwallet:type". One row carrying
    /// all three is one row; counting each name multiplied a single row into
    /// three and the user went looking for two rows that do not exist. Every
    /// colliding name is still left alone — that is asserted here too, so the
    /// counting change cannot be mistaken for permission to overwrite one.
    #[tokio::test]
    async fn one_row_that_collides_three_times_is_one_conflict() {
        let fake = FakeWallet::default()
            .folder("Passwords", &["router"])
            .password("Passwords", "router", "v");
        let sidecar = parse(
            r#"{"Passwords/router": {"attributes": {"kwallet:folder": "theirs",
                                                    "kwallet:key": "their key",
                                                    "kwallet:type": "their type"}}}"#,
        );

        let out = walked(&fake, &sidecar).await;

        let attributes = &out.items[0].attributes;
        assert_eq!(attributes[ATTR_FOLDER], "theirs");
        assert_eq!(attributes[ATTR_KEY], "their key");
        assert_eq!(attributes[ATTR_TYPE], "their type");
        assert_eq!(
            out.attribute_conflicts, 1,
            "three colliding names in one sidecar row are one row that collided"
        );
    }

    /// A sidecar in an unexpected shape parses "successfully" with no entries
    /// at all, and every entry then imports attribute-less. The only signal
    /// is this number, so it has to be reachable.
    #[test]
    fn extra_non_entry_sidecar_rows_are_surfaced() {
        let ordinary = Extraction {
            skipped_sidecar_rows: EXPECTED_NON_ENTRY_ROWS,
            ..Default::default()
        };
        assert_eq!(ordinary.unexpected_sidecar_rows(), 0);
        let odd = Extraction {
            skipped_sidecar_rows: 68,
            ..Default::default()
        };
        assert_eq!(odd.unexpected_sidecar_rows(), 66);
    }

    /// A name that is not a wallet name never reaches the bus, and never
    /// composes a sidecar path that could leave `kwalletd/`.
    #[test]
    fn a_wallet_name_that_could_escape_the_directory_is_refused() {
        for bad in ["", ".", "..", "../../.ssh/id", "a/b", "a\0b"] {
            assert!(!wallet_name_is_usable(bad), "{bad:?} accepted");
            assert_eq!(sidecar_path(bad), PathBuf::new(), "{bad:?} composed a path");
        }
        assert!(wallet_name_is_usable("kdewallet"));
    }

    // -- properties --------------------------------------------------------

    /// `decode_qmap` is the one parser in this module fed by a live foreign
    /// daemon, over a wire that carries a bare byte array. Two properties: it
    /// never panics on anything, and it is exact on everything it accepts.
    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Arbitrary bytes either decode or produce a typed error. Never
            /// a panic, never an unbounded allocation.
            #[test]
            fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
                let _ = decode_qmap(&bytes);
            }

            /// Bytes that begin with a plausible count are the interesting
            /// shape: random input bounces off the length check and never
            /// reaches the string decoder.
            #[test]
            fn plausible_streams_never_panic(
                count in 0u32..8,
                rest in proptest::collection::vec(any::<u8>(), 0..256),
            ) {
                let mut bytes = count.to_be_bytes().to_vec();
                bytes.extend_from_slice(&rest);
                let _ = decode_qmap(&bytes);
            }

            /// Every map Qt could have written round-trips exactly: same
            /// pairs out, and canonical JSON that re-reads as the same map.
            #[test]
            fn well_formed_maps_round_trip(
                pairs in proptest::collection::btree_map(".{0,24}", ".{0,24}", 0..12),
            ) {
                let wire: Vec<(&str, &str)> =
                    pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                let bytes = qmap_bytes(&wire);
                let decoded = decode_qmap(&bytes).expect("a well-formed map was refused");
                let back: BTreeMap<String, String> = decoded.iter().cloned().collect();
                prop_assert_eq!(&back, &pairs);

                let json = read_map_secret(&bytes).expect("a well-formed map was refused");
                let parsed: BTreeMap<String, String> =
                    serde_json::from_slice(&json).expect("canonical JSON did not re-read");
                prop_assert_eq!(parsed, pairs);
            }

            /// One byte removed from a well-formed stream is never accepted:
            /// the buffer must be consumed exactly, which is what makes "this
            /// is not a QMap" detectable at all.
            #[test]
            fn a_truncated_map_is_always_refused(
                pairs in proptest::collection::btree_map("[a-z]{1,8}", "[a-z]{0,8}", 1..6),
                cut in 1usize..8,
            ) {
                let wire: Vec<(&str, &str)> =
                    pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                let bytes = qmap_bytes(&wire);
                let cut = cut.min(bytes.len());
                prop_assert!(decode_qmap(&bytes[..bytes.len() - cut]).is_err());
            }

            /// A hand-written `kwallet:key` stays searchable whatever value it
            /// carries. The name is in the synthesised denylist, but the
            /// sidecar wrote it — `map_entry` collides rather than
            /// overwriting — so it is absent from `inserted_keys` and the
            /// exact classifier counts it. A by-name test reports every one
            /// of these `PreservedOnly`.
            #[test]
            fn hand_written_kwallet_keys_stay_attributes_preserved(
                value in ".{0,128}",
            ) {
                let row = sidecar_entry(&[(ATTR_KEY, value.as_str())]);
                let mut conflicts = 0;
                let item = map_entry(
                    "kdewallet",
                    "Passwords",
                    "router",
                    EntryType::Password,
                    secret(),
                    Some(&row),
                    &mut conflicts,
                );
                prop_assert_eq!(conflicts, 1);
                prop_assert_eq!(&item.attributes[ATTR_KEY], &value);
                prop_assert!(!item.inserted_keys.contains(ATTR_KEY));
                prop_assert_eq!(item.outcome(), Outcome::AttributesPreserved);
            }
        }
    }

    // -- live service ------------------------------------------------------

    /// A read-only sanity check against a real `kwalletd6`, opted into with
    /// `SM_KWALLET_LIVE=1`.
    ///
    /// The gate is the whole design. `cargo test` captures `println!`, so a
    /// version that printed "SKIPPED" and returned reported PASS identically
    /// whether kwalletd was there or not — which is the one thing a live test
    /// must not do, because the only reason to have it is to find out that
    /// the assumptions are wrong. Unset, it says on stderr that it skipped.
    /// Set, every step is required: the service, the wallet list, and a real
    /// walk of an open wallet.
    ///
    /// It never opens a *closed* wallet even when opted in: that raises the
    /// unlock dialog, and a test may not do that. A wallet that is already
    /// open can still prompt for *this application's* access on the first
    /// read — see [`DEFAULT_CALL_TIMEOUT`] — which is bounded rather than
    /// avoided, so a run against a wallet that has never seen [`APP_ID`] may
    /// wait on one.
    #[tokio::test]
    async fn live_kwalletd_agrees_with_this_modules_assumptions() {
        // `eprintln!` and not `println!`: a skip has to be visible.
        if std::env::var_os("SM_KWALLET_LIVE").is_none() {
            eprintln!(
                "SKIPPED live_kwalletd_agrees_with_this_modules_assumptions: set \
                 SM_KWALLET_LIVE=1, with a kwalletd6 running and a wallet already open, to run it"
            );
            return;
        }
        let conn = zbus::Connection::session()
            .await
            .expect("SM_KWALLET_LIVE is set but there is no session bus");
        assert!(
            service_is_running(&conn)
                .await
                .expect("NameHasOwner failed"),
            "SM_KWALLET_LIVE is set but {SERVICE} has no owner on the session bus"
        );
        let proxy = KWalletProxy::new(&conn).await.unwrap();
        // Not `unwrap()`: a denied `wallets()` is a result about KWallet's
        // policy, and "the call was refused" is what the run has to say.
        let wallets = bounded("wallets", DEFAULT_CALL_TIMEOUT, proxy.wallets())
            .await
            .expect("kwalletd refused the wallets() call");
        assert!(!wallets.is_empty(), "kwalletd reports no wallets");
        println!("live kwalletd6: {} wallet(s)", wallets.len());

        let mut walked_any = false;
        for wallet in &wallets {
            let open = bounded("isOpen", DEFAULT_CALL_TIMEOUT, proxy.is_open(wallet))
                .await
                .unwrap_or(false);
            // Names and counts only. Never a value, never a secret.
            println!("  wallet {wallet:?} open={open}");
            let sidecar = Sidecar::load(&sidecar_path(wallet)).expect("the sidecar is unreadable");
            println!(
                "  sidecar {} row(s), {} non-object root value(s)",
                sidecar.len(),
                sidecar.skipped_rows()
            );
            if !open {
                println!("  not walked: the wallet is closed and opening it would prompt");
                continue;
            }
            // Already open, so this cannot raise the *unlock* dialog — which
            // is the one a test may not raise, because nobody is there to type
            // into it. It can still raise KWallet's per-application access
            // prompt, which `DEFAULT_CALL_TIMEOUT` documents as appearing
            // inside a read; the ten-second open timeout below does not bound
            // that, and the per-call bound is what does. The two docs used to
            // contradict each other, with this one claiming no dialog was
            // possible at all.
            let out = extract(&conn, wallet, &sidecar, Duration::from_secs(10))
                .await
                .expect("the walk failed");
            println!(
                "  walked: {} item(s), {} skipped, {} refused, {} ambiguous key(s)",
                out.items.len(),
                out.skipped.len(),
                out.refused.len(),
                out.ambiguous_sidecar_keys.len()
            );
            walked_any = true;
        }
        assert!(
            walked_any,
            "SM_KWALLET_LIVE is set but no wallet was open, so nothing was walked; open one first"
        );
    }
}
