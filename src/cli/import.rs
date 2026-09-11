//! `sm import`: moving a user off gnome-keyring or KWallet.
//!
//! The command is the spec's four phases in order — inventory, extract,
//! pre-check, write, verify — and the report is the deliverable, not a log.
//! Three rules shape everything here:
//!
//! **A new collection, always.** Never a merge. `Reload` does not re-read a
//! collection the daemon already holds, so an offline write into a live one
//! is invisible until restart and the daemon's next save serialises straight
//! over it: the import would appear to succeed and then vanish. A new
//! collection is safe beside a running daemon because [`Vault::create`]
//! publishes with `RENAME_NOREPLACE`, and it is reversible — the user deletes
//! one file and has lost nothing.
//!
//! **Classify before writing anything.** Every item is measured against the
//! six caps during extraction, before the first byte is written — a migration
//! that discovers the twenty-eighth item is oversized after writing
//! twenty-seven leaves the user with a half-populated vault and no way to tell
//! which half. The policy `import::check_caps` states is that a cap violation
//! refuses *one item*, never the run: the extractor drops it into `refusals`
//! and the walk continues. This command therefore never re-checks the caps —
//! by the time it sees `extraction.items` every violating item has already
//! been removed from that list — and its whole obligation is to report them.
//! `print_report`'s "Refused, and why" section and the `refused` tally are the
//! only place a user learns an item was too large, so neither may be
//! conditional.
//!
//! **Refuse rather than convert.** A non-UTF-8 attribute cannot be
//! represented, and a lossily converted attribute is a silently broken
//! lookup — the failure this feature exists to prevent. Such items are
//! refused and listed.
//!
//! Nothing here prints a secret or an attribute value: the report is built
//! from [`ItemReport`], whose attribute type is [`AttributeKeys`], and the
//! only place attribute values exist is inside a [`verify::ProbeQuery`],
//! which is consumed by a D-Bus call and never rendered.
//!
//! **The independent count and the walk have one scope: the container the
//! user named.** `ExtractOptions::only_container` tells the gnome walk which
//! keyring to enumerate, so the walk covers exactly the one [`locate`] chose,
//! and the header total is that one file's `item_count()`. The two halves have
//! to agree about *what* they are counting or the check fails a faithful
//! import: summing every `.keyring` in the directory against a walk of one is
//! a guaranteed mismatch for anyone with a second keyring, raised after the
//! collection has already been written. Widening the walk is not the
//! alternative — a collection labelled after one keyring must not hold the
//! items of another.
//!
//! **A dry run writes nothing, and neither does a real one, at the source.**
//! The gnome route spawns a `gnome-keyring-daemon --unlock`, and that child
//! reads *and writes* whatever `XDG_DATA_HOME` points it at: it rewrites
//! keyring files it opens and creates a `login.keyring` where there is none.
//! So the child is never pointed at the user's own directory. It is given a
//! private snapshot — a copy of the source directory in a 0700 temp dir,
//! removed when the extraction ends — which is what makes "the source was not
//! modified" a fact about the filesystem rather than a sentence in the report.
//!
//! **The surface below the command itself is test-only.** [`Extraction`],
//! [`Imported`], [`Extractor`], [`ImportEnv`], [`DaemonTarget`] and
//! [`run_with`] exist so the pipeline can be driven with no gnome-keyring and
//! no kwalletd anywhere — and, with [`DaemonTarget::At`], against a real
//! daemon on a bus nothing else can see, which is what the lookup probe needs
//! to be exercised at all; they
//! are `pub` under the `test-util` feature and `pub(crate)` otherwise, because
//! `CLAUDE.md` is explicit that test scaffolding must not widen the shipped
//! API, and they are `#[non_exhaustive]` so a field added to one of them is
//! not a breaking change.

use super::secrets::escape_control;
use super::{CliError, load_config, read_new_password};
use crate::config::Config;
use crate::dbus::paths;
use crate::dbus::state::{load_aliases, save_aliases_to};
use crate::import::formats::{
    self, HeaderError, KeyringInventory, WalletInventory, parse_default_file, parse_keyring_header,
    parse_wallet_header,
};
use crate::import::verify::{self, FingerprintEntry, Histogram, ProbeResult, Verification};
use crate::import::{AttributeKeys, ImportReport, ItemReport, Source, SourceItem, Tally};
use crate::import::{gnome, kwallet};
use crate::protocol::{ProtocolError, Request, Response, call, socket_path};
use crate::vault::store::ImportItem;
use crate::vault::{Vault, collection_id_from_label};
use serde::Serialize;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use zeroize::Zeroizing;

/// `--from`, as a value clap can parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SourceArg {
    #[value(name = "gnome-keyring")]
    GnomeKeyring,
    #[value(name = "kwallet")]
    KWallet,
}

impl From<SourceArg> for Source {
    fn from(a: SourceArg) -> Source {
        match a {
            SourceArg::GnomeKeyring => Source::GnomeKeyring,
            SourceArg::KWallet => Source::KWallet,
        }
    }
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// Which provider to migrate from
    #[arg(long = "from", value_name = "SOURCE")]
    pub from: SourceArg,
    /// Read the source's cleartext headers only; print and exit. Needs no
    /// password and no daemon.
    #[arg(long, conflicts_with_all = ["dry_run", "set_default", "collection", "report"])]
    pub inventory: bool,
    /// Extract and check everything, then write nothing. The intended first
    /// run.
    #[arg(long = "dry-run", conflicts_with = "set_default")]
    pub dry_run: bool,
    /// Label for the new collection. Defaults to the source's own name.
    #[arg(long, value_name = "LABEL")]
    pub collection: Option<String>,
    /// Point the `default` alias at the imported collection.
    #[arg(long = "set-default")]
    pub set_default: bool,
    /// Write the per-item report as JSON. Holds no secret and no attribute
    /// value.
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
}

// --------------------------------------------------------------------------
// The interface this command needs from the two extraction transports
// --------------------------------------------------------------------------

// `pub` for the integration tests that drive the pipeline, `pub(crate)`
// otherwise: see this module's header.
#[cfg(any(test, feature = "test-util"))]
pub use self::pipeline::{DaemonTarget, ImportEnv, run_with};
#[cfg(not(any(test, feature = "test-util")))]
pub(crate) use self::pipeline::{DaemonTarget, ImportEnv, run_with};
#[cfg(any(test, feature = "test-util"))]
pub use self::transport::{Extraction, Extractor, Imported, NotMigrated};
#[cfg(not(any(test, feature = "test-util")))]
pub(crate) use self::transport::{Extraction, Extractor, Imported, NotMigrated};

mod transport {
    use super::*;

    /// One item that will be written, with the report row that describes it.
    ///
    /// The row comes from the extractor rather than from
    /// `ItemReport::imported` here, because only the extractor knows the two
    /// things the row carries that the item itself does not: the source item
    /// type that has no target, and the per-application access list the Secret
    /// Service has no equivalent for.
    #[non_exhaustive]
    pub struct Imported {
        pub item: SourceItem,
        pub report: ItemReport,
    }

    /// Constructors for the tests that build these; production code uses the
    /// struct literals, which `#[non_exhaustive]` still allows inside this
    /// crate.
    #[cfg(any(test, feature = "test-util"))]
    impl Imported {
        pub fn new(item: SourceItem, report: ItemReport) -> Self {
            Self { item, report }
        }
    }

    /// An entry the walk found and did not write for a reason
    /// [`Refusal`](crate::import::Refusal) does
    /// not name — a KWallet map that would not decode, an entry the wallet
    /// would not hand over. Named in the report rather than counted, because
    /// "something did not come across" is the one thing a migration report may
    /// not round off.
    #[derive(Debug, Clone, serde::Serialize)]
    #[non_exhaustive]
    pub struct NotMigrated {
        pub label: String,
        pub reason: String,
    }

    #[cfg(any(test, feature = "test-util"))]
    impl NotMigrated {
        pub fn new(label: impl Into<String>, reason: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                reason: reason.into(),
            }
        }
    }

    /// What one source's extractor produces.
    ///
    /// `src/import/gnome.rs` and `src/import/kwallet.rs` own the transports —
    /// a private session bus and a `gnome-keyring-daemon` child for one, the
    /// `org.kde.kwalletd6` service for the other. This is the shape the rest of
    /// the command is written against, so the pipeline below (pre-check, write,
    /// verify, report) is exercised by tests with no source daemon anywhere.
    #[non_exhaustive]
    pub struct Extraction {
        /// The source's own name for the container: a keyring's display name,
        /// or a wallet's name. It is the default destination label.
        pub container: String,
        /// Items in walk order, attributes carried verbatim.
        pub items: Vec<Imported>,
        /// Items the extractor would not represent — a chained keyring item, a
        /// non-UTF-8 attribute, a cap violation it caught first.
        pub refusals: Vec<ItemReport>,
        /// Entries lost for a reason with no `Refusal` variant. See
        /// [`NotMigrated`].
        pub skipped: Vec<NotMigrated>,
        /// KWallet folders with no entries. A collection-of-items model has
        /// nowhere to put them; the report says how many were lost.
        pub empty_folders: usize,
        /// Anything else the run must not be silent about: a plaintext session
        /// because the source refused DH, a collection whose unlock prompt
        /// nobody could answer, sidecar rows that resolved to no entry.
        pub notes: Vec<String>,
    }

    #[cfg(any(test, feature = "test-util"))]
    impl Extraction {
        /// An empty extraction of `container`. The fields are public and set
        /// afterwards; this exists because the struct is `#[non_exhaustive]`,
        /// so a field added later is not a breaking change for the tests that
        /// build one.
        pub fn new(container: impl Into<String>) -> Self {
            Self {
                container: container.into(),
                items: Vec::new(),
                refusals: Vec::new(),
                skipped: Vec::new(),
                empty_folders: 0,
                notes: Vec::new(),
            }
        }
    }

    /// A boxed future, because the two transports are async and this trait is
    /// used through `dyn`.
    pub type Extracting<'a> = Pin<Box<dyn Future<Output = Result<Extraction, CliError>> + 'a>>;

    /// How the command obtains an [`Extraction`]. One implementation per source
    /// plus, in tests, one that returns a fixed set.
    pub trait Extractor {
        fn extract<'a>(&'a self, source: Source, container_hint: &'a str) -> Extracting<'a>;
    }
}

/// The live transports.
///
/// `source_dir` is here because the gnome route must not point its private
/// `gnome-keyring-daemon` at the user's own `$XDG_DATA_HOME`: it snapshots
/// this directory and reads the copy. See [`snapshot_source_dir`].
struct LiveExtractor {
    source_dir: PathBuf,
}

impl Extractor for LiveExtractor {
    fn extract<'a>(&'a self, source: Source, container_hint: &'a str) -> transport::Extracting<'a> {
        Box::pin(async move {
            match source {
                Source::GnomeKeyring => extract_gnome(&self.source_dir, container_hint).await,
                Source::KWallet => extract_kwallet(container_hint).await,
            }
        })
    }
}

/// gnome-keyring, over a private bus with a private daemon: the real session
/// bus is never displaced, and the password goes to the child's stdin.
///
/// **The session bus's owner is a warning here, never a refusal.** This route
/// does not use the session bus at all: it stands up its own `dbus-daemon` and
/// its own `gnome-keyring-daemon` and reads `keyrings/` off disk, so nothing
/// about who owns `org.freedesktop.secrets` can make it read the wrong
/// provider, and the honest precondition — is there a keyring directory with a
/// keyring in it — is [`locate`]'s, made before this function is reached.
///
/// What the owner *does* say is worth saying: a name held by `ksecretd` means
/// the files below are not where this user's secrets have been going, and the
/// import will faithfully copy a stale keyring. That is a fact about the
/// source, so it is printed and the run continues.
///
/// Refusing on it was worse than useless. The install guides *mask*
/// gnome-keyring, so the name is either unowned or held by us on every machine
/// this command exists for — and both were refused, which made `sm import
/// --from gnome-keyring` impossible in exactly the state it is run from.
///
/// The warning is printed *before* the password prompt: a user who learns
/// their source is stale should learn it before typing a password for it.
async fn extract_gnome(source_dir: &Path, container: &str) -> Result<Extraction, CliError> {
    let mut notes = Vec::new();
    // A `busctl`/`ps` that will not answer is not a reason to stop: it costs
    // the user a sentence, not the migration.
    match gnome::secrets_bus_owner().await {
        Ok(owner) => {
            if let Some(warning) = owner.foreign_provider_warning() {
                eprintln!("warning: {}", escape_control(&warning));
                notes.push(warning);
            }
        }
        Err(e) => eprintln!(
            "warning: could not tell who owns org.freedesktop.secrets ({}), so this run \
             cannot say whether the keyrings it is about to read are the ones your session \
             has been using.",
            escape_control(&e.to_string())
        ),
    }
    // Before the password prompt, and before the child that would write to it:
    // the private gnome-keyring gets a copy of the source directory and the
    // user's own is never opened for writing. See `gnome::KeyringSnapshot`.
    let snapshot = gnome::KeyringSnapshot::create(source_dir).map_err(gnome_error)?;
    let password = super::read_password(
        "gnome-keyring login password (it is sent to a private gnome-keyring-daemon, \
         never stored)",
    )?;
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let walked = gnome::extract_over_private_bus(&password, &snapshot, &gnome_options(container))
        .await
        .map_err(gnome_error)?;

    if let Some(reason) = &walked.plain_fallback_reason {
        notes.push(format!(
            "the session with the source daemon was plaintext, not DH-encrypted: {reason}"
        ));
    }
    if walked.item_type_unavailable {
        notes.push(
            "no item exposed Item.Type, so the chained-keyring refusal could not be \
             evaluated on this source: check by hand that no imported item is an unlock \
             credential for another keyring"
                .to_string(),
        );
    }
    for collection in walked.unanswerable_collections() {
        notes.push(format!(
            "the collection '{}' holds {} and its unlock prompt could not be \
             answered, so none of them were read",
            escape_control(&collection.label),
            // A collection nobody could unlock may also not say how many items
            // it holds; "an unknown number" is the honest phrasing, and `0`
            // would read as "nothing was lost".
            match collection.item_count {
                Some(n) => format!("{n} items"),
                None => "an unknown number of items".to_string(),
            }
        ));
    }
    Ok(Extraction {
        container: container.to_string(),
        items: walked
            .items
            .iter()
            .map(|e| Imported {
                item: e.item.clone(),
                report: e.report(),
            })
            .collect(),
        refusals: walked.refused,
        // Items the source daemon would not hand over, or would not hand over
        // intelligibly. Each one is a per-item failure the walk continued
        // past, and each is named here rather than counted: `NotMigrated` is
        // exactly the shape for a loss no `Refusal` variant covers.
        skipped: walked
            .skipped
            .into_iter()
            .map(|s| NotMigrated {
                label: s.label,
                reason: s.reason,
            })
            .collect(),
        empty_folders: 0,
        notes,
    })
}

/// Sentences for listings the walk skipped as repeats of an already-listed
/// folder or entry (see `kwallet::Extraction::{duplicate_folders,
/// duplicate_entries}`). Kept beside the rest of the KWallet notes so the
/// report says the daemon was not taken at its word.
fn kwallet_notes(walked: &kwallet::Extraction) -> Vec<String> {
    let mut notes = Vec::new();
    if walked.duplicate_folders > 0 {
        notes.push(format!(
            "{} folder listings repeated a folder that was already listed, so the repeats were \
             not read again: kwalletd repeats every folder in folderList once per open, and \
             reading them again would import every entry once per copy",
            walked.duplicate_folders
        ));
    }
    if walked.duplicate_entries > 0 {
        notes.push(format!(
            "{} entry listings repeated an entry that was already listed in the same folder, \
             so the repeats were not read again: a folder is a map, so a repeat is never a \
             second entry",
            walked.duplicate_entries
        ));
    }
    notes
}

/// KWallet, over `org.kde.kwalletd6` on the session bus: a different bus name
/// from ours, so this path needs no private bus and no ordering against our
/// own daemon.
async fn extract_kwallet(wallet: &str) -> Result<Extraction, CliError> {
    let conn = zbus::Connection::session()
        .await
        .map_err(|e| CliError::Unreachable(format!("cannot connect to the session bus: {e}")))?;
    let sidecar_path = kwallet::sidecar_path(wallet);
    let mut notes = Vec::new();
    let sidecar = match kwallet::Sidecar::load(&sidecar_path) {
        Ok(s) => s,
        Err(e) => {
            // A wallet with no sidecar is a wallet of native KWallet entries,
            // which is a real case and not an error: those items are
            // `PreservedOnly` and the report says so — in the notes it
            // carries, in the same words as the warning, so a pasted report
            // still says why every entry lost its attributes.
            let note = format!(
                "{} could not be read ({}), so no attributes, content types or \
                 timestamps are available and every entry will be preserved-only.",
                escape_control(&sidecar_path.display().to_string()),
                escape_control(&e.to_string())
            );
            eprintln!("warning: {note}");
            notes.push(note);
            kwallet::Sidecar::empty()
        }
    };
    let walked = kwallet::extract(&conn, wallet, &sidecar, kwallet::DEFAULT_OPEN_TIMEOUT)
        .await
        .map_err(|e| match e {
            kwallet::KWalletError::ServiceUnavailable => {
                CliError::Unreachable(escape_control(&e.to_string()))
            }
            kwallet::KWalletError::NoSuchWallet { .. } => {
                CliError::NotFound(escape_control(&e.to_string()))
            }
            other => CliError::Failed(escape_control(&other.to_string())),
        })?;

    // First, because it is the one that changes how every other line should be
    // read: a sidecar in a shape this build does not parse imports the whole
    // wallet attribute-less, and `entries_without_sidecar` cannot tell that
    // apart from a wallet of genuinely native entries.
    if walked.unexpected_sidecar_rows() > 0 {
        notes.push(format!(
            "the attributes sidecar held {} root values that are not entries, which is {} \
             more than the two every real file has: it is not the shape this build parses, \
             so treat every 'no sidecar row' line below as a parse failure rather than as a \
             native KWallet entry",
            walked.unexpected_sidecar_rows() + kwallet::EXPECTED_NON_ENTRY_ROWS,
            walked.unexpected_sidecar_rows()
        ));
    }
    if walked.entries_without_sidecar > 0 {
        notes.push(format!(
            "{} entries had no sidecar row, so they carry no attributes and no timestamps",
            walked.entries_without_sidecar
        ));
    }
    if !walked.ambiguous_sidecar_keys.is_empty() {
        notes.push(format!(
            "{} sidecar rows were composed by more than one entry, so their attributes were \
             dropped from every one of them rather than guessed at: attaching another item's \
             xdg:schema would have written a secret under a different item's identity",
            walked.ambiguous_sidecar_keys.len()
        ));
    }
    if !walked.duplicate_sidecar_keys.is_empty() {
        notes.push(format!(
            "{} sidecar keys were declared more than once, and only the last of each \
             reached the walk: an entry's whole attribute map was replaced by another \
             row's, so its attributes may belong to a different entry. This is the same \
             harm the ambiguous keys above are refused for, arriving by a different door, \
             and it means the file is not the shape ksecretd writes",
            walked.duplicate_sidecar_keys.len()
        ));
    }
    if !walked.unresolved_sidecar_rows.is_empty() {
        notes.push(format!(
            "{} sidecar rows were not applied to any entry. That is not the same as \
             stale: a row also lands here when its folder's entryList was refused, and \
             when its key is ambiguous — those are the keys listed above, and the entry \
             they name does exist",
            walked.unresolved_sidecar_rows.len()
        ));
    }
    if walked.malformed_sidecar_fields > 0 {
        notes.push(format!(
            "{} sidecar fields were present but unusable",
            walked.malformed_sidecar_fields
        ));
    }
    if walked.password_read_fallbacks > 0 {
        notes.push(format!(
            "{} entries typed Password were read through readEntry instead",
            walked.password_read_fallbacks
        ));
    }
    if walked.map_read_fallbacks > 0 {
        notes.push(format!(
            "{} entries typed Map were read through readEntry instead",
            walked.map_read_fallbacks
        ));
    }
    if walked.attribute_conflicts > 0 {
        notes.push(format!(
            "{} sidecar rows already carried an attribute named kwallet:folder, kwallet:key \
             or kwallet:type; the sidecar's own value was kept, because overwriting an \
             attribute we did not write changes a lookup",
            walked.attribute_conflicts
        ));
    }
    for folder in &walked.unreadable_folders {
        notes.push(format!(
            "the folder '{}' could not be listed, so none of its entries were read",
            escape_control(folder)
        ));
    }
    notes.extend(kwallet_notes(&walked));
    Ok(Extraction {
        container: wallet.to_string(),
        items: walked
            .items
            .into_iter()
            .map(|item| Imported {
                report: ItemReport::imported(&item),
                item,
            })
            .collect(),
        refusals: walked
            .refused
            .into_iter()
            .map(|r| ItemReport::refused(r.provenance, r.label, r.refusal))
            .collect(),
        skipped: walked
            .skipped
            .into_iter()
            .map(|s| NotMigrated {
                label: s.label,
                reason: s.reason.to_string(),
            })
            .collect(),
        empty_folders: walked.empty_folders,
        notes,
    })
}

/// The options the gnome walk is given.
///
/// A function rather than a literal inside the `await` above, because the one
/// decision it encodes is the one this module's header calls load-bearing and
/// it needs to be assertable: **only the keyring the user named**. Without
/// `only_container` the walk covers every collection the private daemon
/// exposes, so items from keyrings they did not ask for land in a collection
/// labelled after the one they did — and the label then misdescribes its own
/// contents. It is also the scope the independent count is taken over; the two
/// must not disagree. A literal there was reachable only through a real
/// `gnome-keyring-daemon`, so nothing in the suite could tell `Some(container)`
/// from `None`.
fn gnome_options(container: &str) -> gnome::ExtractOptions {
    gnome::ExtractOptions {
        only_container: Some(container.to_string()),
        ..Default::default()
    }
}

fn gnome_error(e: gnome::GnomeError) -> CliError {
    let text = escape_control(&e.to_string());
    match e {
        gnome::GnomeError::BusNeverReady { .. } | gnome::GnomeError::KeyringNeverReady { .. } => {
            CliError::Unreachable(text)
        }
        _ => CliError::Failed(text),
    }
}

// --------------------------------------------------------------------------
// Locating the source files
// --------------------------------------------------------------------------

/// A source's cleartext inventory, and the file it came from.
enum Inventory {
    Keyring(Box<KeyringInventory>),
    Wallet(Box<WalletInventory>),
}

struct SourceFile {
    path: PathBuf,
    inventory: Inventory,
    /// The independent item count the walk is measured against, from the
    /// cleartext header of **this** file: the keyring the walk is restricted
    /// to, or the wallet that is opened. `None` when it could not be taken,
    /// which is reported as *not made* rather than as a failure.
    header_item_count: Option<usize>,
}

impl SourceFile {
    /// The source's own name for the container.
    fn container(&self) -> String {
        match &self.inventory {
            Inventory::Keyring(k) if !k.display_name.is_empty() => k.display_name.clone(),
            // A wallet's name is not in the file; the file name is the name,
            // which is how `kwalletd` itself resolves it.
            _ => self
                .path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "imported".to_string()),
        }
    }
}

/// `$XDG_DATA_HOME`, or `$HOME/.local/share`.
fn data_home() -> Result<PathBuf, CliError> {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| CliError::Usage("neither XDG_DATA_HOME nor HOME is set".into()))?;
    Ok(PathBuf::from(home).join(".local/share"))
}

fn source_dir(source: Source) -> Result<PathBuf, CliError> {
    let home = data_home()?;
    Ok(match source {
        Source::GnomeKeyring => home.join("keyrings"),
        // KWallet 5 and 6 both keep their wallets here.
        Source::KWallet => home.join("kwalletd"),
    })
}

/// Files with `extension` in `dir`, sorted, so a listing is deterministic.
fn files_with_extension(dir: &Path, extension: &str) -> Result<Vec<PathBuf>, CliError> {
    let entries = std::fs::read_dir(dir).map_err(|e| match e.kind() {
        // The directory is what is missing, not a directory *of* the
        // extension: `keyrings/` is not "a keyring directory", and a user told
        // "no keyring directory at ~/.local/share/kwalletd" reads it as a
        // statement about the files inside a directory that does exist.
        std::io::ErrorKind::NotFound => CliError::NotFound(format!(
            "there is no directory at {}",
            escape_control(&dir.display().to_string())
        )),
        _ => CliError::Failed(format!(
            "{}: {e}",
            escape_control(&dir.display().to_string())
        )),
    })?;
    // A failed entry is not "no such file": a directory that cannot be read
    // through is a directory whose listing is incomplete, and an incomplete
    // listing is how `one_of` picks a keyring the user did not mean.
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            CliError::Failed(format!(
                "{}: {e}",
                escape_control(&dir.display().to_string())
            ))
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == extension) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Read a source file, bounding the read *as* it is made: these are foreign
/// files and their length fields are attacker-controlled.
///
/// One open, one bounded read, exactly as `kwallet::Sidecar::load` does.
/// Sizing a `metadata(path)` and then re-opening the path bounds nothing —
/// the file can grow, or become a different file, between the two syscalls,
/// and the second open resolves the path again. So the `stat` is taken on the
/// open handle and is only an early refusal; the [`std::io::Read::take`] is
/// the guarantee.
fn read_source(path: &Path) -> Result<Vec<u8>, CliError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| header_io(path, e))?;
    let len = file.metadata().map_err(|e| header_io(path, e))?.len();
    formats::check_source_size(len).map_err(|e| header_error(path, &e))?;
    // One byte past the limit, so a file that grew after the `stat` is
    // refused rather than silently truncated into a parse error that blames
    // the format.
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(formats::MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| header_io(path, e))?;
    formats::check_source_size(bytes.len() as u64).map_err(|e| header_error(path, &e))?;
    Ok(bytes)
}

fn header_io(path: &Path, e: std::io::Error) -> CliError {
    let path = escape_control(&path.display().to_string());
    match e.kind() {
        std::io::ErrorKind::NotFound => CliError::NotFound(format!("{path}: {e}")),
        _ => CliError::Failed(format!("{path}: {e}")),
    }
}

fn header_error(path: &Path, e: &HeaderError) -> CliError {
    CliError::Failed(format!(
        "{}: {}",
        escape_control(&path.display().to_string()),
        escape_control(&e.to_string())
    ))
}

/// The file `--from` names.
///
/// gnome-keyring: the keyring named by the `default` file, else the only
/// `.keyring` there. KWallet: the only `.kwl`. Where the choice is genuinely
/// ambiguous the command refuses and lists the candidates rather than
/// guessing which of a user's keyrings they meant.
fn locate(source: Source, dir: &Path) -> Result<SourceFile, CliError> {
    match source {
        Source::GnomeKeyring => {
            let candidates = files_with_extension(dir, "keyring")?;
            let default_file = dir.join("default");
            let chosen = match std::fs::read_to_string(&default_file) {
                Ok(text) => {
                    let name =
                        parse_default_file(&text).map_err(|e| header_error(&default_file, &e))?;
                    let path = dir.join(format!("{name}.keyring"));
                    if !path.exists() {
                        return Err(CliError::NotFound(format!(
                            "the default keyring is '{}', but {} does not exist",
                            escape_control(&name),
                            escape_control(&path.display().to_string())
                        )));
                    }
                    path
                }
                // Only an absent `default` file means "there is no default".
                // A `default` that exists and cannot be read would otherwise
                // be treated as absent, and this command would silently pick a
                // different keyring than the one the user's session uses.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    one_of(&candidates, dir, "keyring")?
                }
                Err(e) => return Err(header_io(&default_file, e)),
            };

            // One keyring is walked — `ExtractOptions::only_container` names
            // it — so one keyring's header is the independent total. Summing
            // the siblings here is what made the check fail every user with a
            // second `.keyring`: six declared against three walked, raised
            // after the collection had already been written. The two halves
            // count the same thing or they compare nothing.
            let bytes = read_source(&chosen)?;
            let inventory = parse_keyring_header(&bytes).map_err(|e| header_error(&chosen, &e))?;
            Ok(SourceFile {
                path: chosen,
                header_item_count: Some(inventory.item_count()),
                inventory: Inventory::Keyring(Box::new(inventory)),
            })
        }
        Source::KWallet => {
            let candidates = files_with_extension(dir, "kwl")?;
            let chosen = one_of(&candidates, dir, "kwl")?;
            let bytes = read_source(&chosen)?;
            let inventory = parse_wallet_header(&bytes).map_err(|e| header_error(&chosen, &e))?;
            Ok(SourceFile {
                path: chosen,
                // One wallet is opened and one wallet is walked, so its own
                // header is the whole independent total.
                header_item_count: Some(inventory.entry_count()),
                inventory: Inventory::Wallet(Box::new(inventory)),
            })
        }
    }
}

fn one_of(candidates: &[PathBuf], dir: &Path, extension: &str) -> Result<PathBuf, CliError> {
    match candidates {
        [only] => Ok(only.clone()),
        [] => Err(CliError::NotFound(format!(
            "no .{extension} file in {}",
            escape_control(&dir.display().to_string())
        ))),
        many => {
            let names: Vec<String> = many
                .iter()
                .map(|p| escape_control(&p.file_name().unwrap_or_default().to_string_lossy()))
                .collect();
            // Exit 1, not the exit 2 that means "a different invocation is the
            // remedy". There is no flag naming the source container — `sm
            // import` has `--collection` for the *destination* and nothing for
            // the source — so no rerun of `sm` fixes this: the user has to
            // change the directory, or write a `default` file. Contrast the
            // "collection already exists" refusal, which is exit 2 because
            // `--collection` is the remedy.
            Err(CliError::Failed(format!(
                "{} holds {} .{extension} files ({}); this command imports one container, \
                 so move the ones you do not want aside and run it again",
                escape_control(&dir.display().to_string()),
                many.len(),
                names.join(", ")
            )))
        }
    }
}

// --------------------------------------------------------------------------
// --inventory
// --------------------------------------------------------------------------

fn print_inventory(source: Source, file: &SourceFile) {
    println!("{source} inventory");
    println!(
        "  file                 {}",
        escape_control(&file.path.display().to_string())
    );
    println!(
        "  container            {}",
        escape_control(&file.container())
    );
    match &file.inventory {
        Inventory::Keyring(k) => {
            println!("  items                {}", k.item_count());
            let refused = k.unlock_credential_count();
            if refused > 0 {
                println!("  of those, refused    {refused} (they unlock another keyring)");
            }
            println!("  kdf iterations       {}", k.hash_iterations);
            let counts = k.attribute_key_counts();
            if counts.is_empty() {
                println!("  attribute keys       none");
            } else {
                println!("  attribute keys       (name, items carrying it)");
                for (key, n) in &counts {
                    println!("      {:<28} {n}", escape_control(key));
                }
                let portable = counts.get(crate::import::XDG_SCHEMA).copied().unwrap_or(0);
                println!(
                    "  {portable} of {} items carry an xdg:schema and are fully portable",
                    k.item_count()
                );
            }
        }
        Inventory::Wallet(w) => {
            println!("  folders              {}", w.folder_count());
            println!("  of those, empty      {}", w.empty_folder_count());
            println!("  entries              {}", w.entry_count());
        }
    }
    println!();
    println!(
        "No password was asked for and none was needed: only the cleartext header was read, \
         and no secret was decrypted."
    );
}

// --------------------------------------------------------------------------
// The report file
// --------------------------------------------------------------------------

/// What `--report PATH` writes: the per-item report, plus what verification
/// concluded. Both hold keys, counts and outcomes only.
///
/// The report's own fields are named here rather than flattened in, for one
/// reason: there are two tallies, and the one a consumer reaches by the
/// obvious name has to be the one the command itself prints. `tally` is the
/// tally *after* the probe has had its say; the pre-probe classification is
/// `tally_before_probe`, which is the number the command deliberately does not
/// print because the probe may have downgraded it.
#[derive(Serialize)]
struct ReportFile<'a> {
    source: Source,
    /// Destination collection label.
    collection: &'a str,
    /// The tally after the lookup probe has had its say. The probe downgrades
    /// an item whose attributes arrived but which the daemon does not return.
    tally: &'a Tally,
    /// The classification before the probe, kept because the difference
    /// between the two is itself a finding.
    tally_before_probe: &'a Tally,
    items: &'a [ItemReport],
    empty_folders: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_item_count: Option<usize>,
    verification: &'a Verification,
    /// Entries lost for a reason no `Refusal` variant names.
    not_migrated: &'a [NotMigrated],
    /// Anything the run must not be silent about.
    notes: &'a [String],
    /// `true` for `--dry-run`: the report describes what *would* happen, and
    /// nothing on this machine was changed by the run that wrote it.
    dry_run: bool,
    /// Whether the collection this report describes is **on disk** now.
    ///
    /// Two fields and not one, because the two questions have different
    /// answers on the path that matters most. A failed offline verification
    /// is not a dry run — a vault really was created — and the vault is then
    /// unlinked three lines below the report, so a single flag meaning both
    /// had to lie about one of them: it said `written: true` for a collection
    /// the error text beside it correctly described as "removed again". The
    /// artifact a user pastes into a bug report now agrees with the message
    /// printed above it.
    written: bool,
    /// Whether the `default` alias now points at this collection. `false`
    /// both when `--set-default` was never passed and when it was passed and
    /// the alias file could not be saved — the `notes` say which, and the
    /// terminal says it too, so an unmoved alias is never a silent exit 0.
    default_alias_moved: bool,
}

/// What became of the collection a report describes.
///
/// Three states and not two booleans, because one of the four pairs is
/// impossible — a dry run cannot have left a vault on disk — and the pair that
/// was collapsed into a single flag is the one that made the report lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// `--dry-run`: nothing was created, so nothing was removed either.
    DryRun,
    /// A real run whose collection is on disk and stays there — including the
    /// failed-probe path, which deliberately leaves it.
    Kept,
    /// A real run that created a collection and unlinked it again, which is
    /// what a failed offline verification does three lines after writing the
    /// report.
    RemovedAgain,
}

impl Disposition {
    fn of(dry_run: bool) -> Self {
        if dry_run {
            Disposition::DryRun
        } else {
            Disposition::Kept
        }
    }

    fn dry_run(self) -> bool {
        matches!(self, Disposition::DryRun)
    }

    fn written(self) -> bool {
        matches!(self, Disposition::Kept)
    }
}

impl<'a> ReportFile<'a> {
    /// `probed_tally` and `items` are passed together, and they are *the same
    /// pair*: the tally the probe produced and the items the probe downgraded.
    ///
    /// They used to be the post-probe tally beside the pre-probe items, which
    /// made the file one its own reader rejects — `ImportReport`'s
    /// `Deserialize` recomputes the tally from the items and errors on a
    /// disagreement — and the file is written before the failure return, so it
    /// was produced in exactly the case a user pastes into a bug report. See
    /// [`downgrade_items`].
    #[allow(clippy::too_many_arguments)]
    fn new(
        report: &'a ImportReport,
        probed_tally: &'a Tally,
        items: &'a [ItemReport],
        verification: &'a Verification,
        not_migrated: &'a [NotMigrated],
        notes: &'a [String],
        disposition: Disposition,
        default_alias_moved: bool,
    ) -> Self {
        Self {
            source: report.source,
            collection: &report.collection,
            tally: probed_tally,
            tally_before_probe: &report.tally,
            items,
            empty_folders: report.empty_folders,
            header_item_count: report.header_item_count,
            verification,
            not_migrated,
            notes,
            dry_run: disposition.dry_run(),
            written: disposition.written(),
            default_alias_moved,
        }
    }
}

/// The items, with the probe's verdict applied to each one's outcome.
///
/// The rule lives in `verify::{downgraded_keys, downgrade_outcome}` and is
/// shared with `verify::tally_with_probes`, so the report's `tally` and its
/// `items` add up to each other. Matching is by key set because an
/// [`ItemReport`] holds no attribute values.
fn downgrade_items(items: &[ItemReport], failed: &[ProbeResult]) -> Vec<ItemReport> {
    let failed = verify::downgraded_keys(failed);
    items
        .iter()
        .map(|item| {
            let mut item = item.clone();
            item.outcome =
                verify::downgrade_outcome(item.outcome, failed.contains(&item.attribute_keys));
            item
        })
        .collect()
}

/// Write `--report`, and treat a failure as a warning rather than an abort.
///
/// The report is a diagnostic artifact; it is never the thing the command is
/// for. Both call sites sit between the last check and the effects that
/// finish — or unwind — the import, so propagating an unwritable directory,
/// a full disk or a temp-name collision from here would leave the run half
/// done: on the failure path the freshly created vault would stay on disk,
/// contradicting the error's own promise that it "has been removed again"
/// and blocking the next run with the "collection already exists" refusal
/// against a file this run made; on the success path it would exit 1 with
/// the collection loaded by the daemon and `--set-default` silently skipped.
/// A report nobody could write is worth a line on stderr, not either of
/// those.
fn write_report_or_warn(path: &Path, file: &ReportFile<'_>) {
    let shown = escape_control(&path.display().to_string());
    match write_report(path, file) {
        Ok(()) => println!("\nReport written to {shown}"),
        Err(e) => eprintln!("\nwarning: the report could not be written to {shown}: {e}"),
    }
}

fn write_report(path: &Path, file: &ReportFile<'_>) -> Result<(), CliError> {
    let mut json = serde_json::to_string_pretty(file)
        .map_err(|e| CliError::Failed(format!("could not render the report: {e}")))?;
    json.push('\n');
    write_report_file(path, json.as_bytes())
}

/// Write the report via [`crate::atomic::write_atomic`].
///
/// Two things this fixes, and neither is theoretical. `OpenOptions::mode`
/// applies **only when the file is created**, so an existing `report.json` at
/// 0644 was truncated and rewritten with its old permissions — publishing
/// labels, attribute key names and KWallet folder and entry names to every
/// local user, while the comment beside it claimed 0600. And a truncate
/// followed by two writes leaves a truncated JSON document behind a crash,
/// where a complete report used to be. A rename is atomic: the reader sees the
/// old report or the new one.
///
/// The report names labels and attribute keys, which is not secret but is
/// nobody else's business either — hence 0600.
fn write_report_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    crate::atomic::write_atomic(path, bytes, 0o600).map_err(|e| header_io(path, e))
}

// --------------------------------------------------------------------------
// The command
// --------------------------------------------------------------------------

pub async fn run(args: ImportArgs) -> Result<(), CliError> {
    let source: Source = args.from.into();
    let env = ImportEnv::new(load_config()?, source_dir(source)?);
    let extractor = LiveExtractor {
        source_dir: env.source_dir.clone(),
    };
    run_with(args, &extractor, &env).await
}

mod pipeline {
    use super::*;

    /// How the new collection's password is obtained. `read_new_password` in
    /// production; a fixed value in a test, which is the only way an
    /// in-process test can exercise the write path at all — the real reader
    /// reads process stdin, and a test has none to feed.
    pub type PasswordReader = Box<dyn Fn(&str) -> Result<Zeroizing<String>, CliError>>;

    /// Where the command reads from and writes to.
    ///
    /// A parameter rather than two calls into the environment, so the pipeline
    /// can be driven against a fixture directory and a scratch vault directory
    /// with no process-global state - which is what makes "a dry run writes
    /// nothing" and "the pre-check refuses before any write" testable as
    /// assertions about a directory rather than as a reading of the code.
    #[non_exhaustive]
    pub struct ImportEnv {
        pub config: Config,
        /// The directory holding the source's files: `keyrings/` or
        /// `kwalletd/`.
        pub source_dir: PathBuf,
        /// See [`PasswordReader`]. Defaults to [`read_new_password`].
        pub new_password: PasswordReader,
        /// Which daemon this run reloads and probes. See [`DaemonTarget`].
        pub daemon: DaemonTarget,
    }

    /// The running daemon this import publishes to, and then questions.
    ///
    /// This replaces a `reach_the_daemon: bool` that every one of the nine
    /// tests set to `false`, so the whole probe path — the one this module
    /// calls "the check that matters" — shipped with the suite *pinning that
    /// it had not run. The boolean could not be anything else: it named no
    /// daemon, so the only alternative to "the developer's own" was "none".
    ///
    /// An address can be a third thing. [`DaemonTarget::At`] is a real daemon on a
    /// private bus, which is what `tests/common`'s fixture already stands up
    /// for eleven other integration binaries, so the probe is now exercised
    /// against a daemon that answers rather than against a `false`.
    // Production constructs `FromEnvironment` and nothing else — the other two
    // exist for the tests, like `Extraction` and `PasswordReader` above, and
    // like them they are `pub` only under `test-util`. The allow is for the
    // shipped build, where they are the unused half of a test seam rather than
    // dead code anyone could reach.
    #[cfg_attr(not(any(test, feature = "test-util")), allow(dead_code))]
    pub enum DaemonTarget {
        /// The user's own: `DBUS_SESSION_BUS_ADDRESS` and
        /// `$XDG_RUNTIME_DIR/secret-manager/control.sock`. Production, and
        /// nothing else.
        FromEnvironment,
        /// A specific one. The two addresses travel together because the
        /// probe's whole validity rests on them being the *same process*; see
        /// [`probe_target`].
        At {
            bus_address: String,
            control_socket: PathBuf,
        },
        /// There is none. Every probe comes back *not issued*, which
        /// `Verification::unproved` reports as a check that was not made —
        /// exactly what it is on a machine with no daemon.
        None,
    }

    impl ImportEnv {
        pub fn new(config: Config, source_dir: PathBuf) -> Self {
            Self {
                config,
                source_dir,
                new_password: Box::new(read_new_password),
                daemon: DaemonTarget::FromEnvironment,
            }
        }
    }

    /// The whole pipeline, over any [`Extractor`]. Tests drive this with a
    /// fake source so every rule below — the cap pre-check, the "new
    /// collection, always" refusal, what a dry run does not write — is
    /// exercised without a gnome-keyring or a kwalletd anywhere.
    pub async fn run_with(
        args: ImportArgs,
        extractor: &dyn Extractor,
        env: &ImportEnv,
    ) -> Result<(), CliError> {
        let source: Source = args.from.into();
        let file = locate(source, &env.source_dir)?;

        if args.inventory {
            print_inventory(source, &file);
            return Ok(());
        }

        let config = &env.config;
        let container = file.container();
        let mut extraction = extractor.extract(source, &container).await?;

        let label = args
            .collection
            .clone()
            .unwrap_or_else(|| extraction.container.clone());
        let id = collection_id_from_label(&label);
        let vault_path = config.vault.dir.join(format!("{id}.vault"));

        // A new collection, always. Refused here, before a password is asked
        // for and before anything is extracted further, because the
        // alternative is merging into a live collection whose next daemon save
        // writes straight over the import.
        //
        // Checked on a dry run too, and warned about rather than refused: the
        // point of a dry run is to find out whether the real one would work,
        // and a dry run that skipped this check ended by advising the user to
        // run a command that will refuse.
        let destination_exists = vault_path.exists();
        if destination_exists {
            let message = format!(
                "collection '{id}' already exists at {}. `sm import` never merges into an \
                 existing collection - a write into one the daemon already holds is invisible \
                 until it restarts and is then overwritten by its next save. Pass \
                 --collection with a name that is not in use.",
                escape_control(&vault_path.display().to_string())
            );
            if args.dry_run {
                eprintln!("warning: {message}");
            } else {
                // A different invocation is the remedy, so this is exit 2 and
                // not the exit 1 that means "something went wrong".
                return Err(CliError::Usage(message));
            }
        }

        // ---------------------------------------------------------------
        // The classification, before a single byte is written
        // ---------------------------------------------------------------
        //
        // The caps are not re-checked here. Both extractors measure every item
        // against them during the walk and put the violations in `refusals`,
        // which is the policy `import::check_caps` documents: refuse the item,
        // not the run. What this command owes those items is the report — they
        // are counted in the `refused` tally and named, with their limit, by
        // `print_report`.
        let mut report = ImportReport::new(source, &label);
        report.header_item_count = file.header_item_count;
        report.empty_folders = extraction.empty_folders;

        for refusal in extraction.refusals {
            report.push(refusal);
        }
        for imported in &extraction.items {
            report.push(imported.report.clone());
        }
        let items: Vec<SourceItem> = extraction.items.iter().map(|i| i.item.clone()).collect();

        // ---------------------------------------------------------------
        // Write, or discard
        // ---------------------------------------------------------------
        let mut destination: Option<Destination> = None;
        if !args.dry_run {
            let password = (env.new_password)(&format!(
                "Choose a password for the new collection '{}'",
                escape_control(&label)
            ))?;
            // From here to `reopen` the file is already published, so every
            // failure has to take it away again: `RENAME_NOREPLACE` proved the
            // name was ours, and leaving it behind would make the refusal
            // above fire on the next attempt, against a file this run created.
            let written: Result<Destination, CliError> = (|| {
                let mut vault =
                    Vault::create(&vault_path, &label, password.as_bytes(), config.kdf.into())?;
                vault
                    .import_items(
                        items
                            .iter()
                            .map(|i| ImportItem {
                                // Verbatim, every field. Nothing here normalises,
                                // synthesises or drops an attribute pair: that is
                                // the one thing an import may never do.
                                label: i.label.clone(),
                                attributes: i.attributes.clone(),
                                secret: i.secret.clone(),
                                content_type: i.content_type.clone(),
                                created: i.created,
                                modified: i.modified,
                            })
                            .collect(),
                    )
                    .map_err(CliError::from)?;
                drop(vault);
                // Read the destination back off *disk*, decrypting it again, so
                // the fingerprints compare what was written rather than the list
                // we intended to write. An import that verified against its own
                // in-memory copy would prove nothing about the file.
                reopen(&vault_path, password.as_bytes(), &id)
            })();
            match written {
                Ok(dest) => destination = Some(dest),
                Err(e) => {
                    // A failed write still gets its report: the offline checks
                    // run against no destination, every probe is not issued,
                    // and the file this run may have published is unlinked
                    // after the report, mirroring the offline-failure branch.
                    let plan = verify::probe_plan(&items);
                    let walked = report.tally.seen() + extraction.skipped.len();
                    let verification = verify_import(
                        &file,
                        &items,
                        walked,
                        None,
                        plan.iter().map(ProbeResult::not_issued).collect(),
                    );
                    let report_file = ReportFile::new(
                        &report,
                        &report.tally,
                        &report.items,
                        &verification,
                        &extraction.skipped,
                        &extraction.notes,
                        // This branch only runs on a real run (`destination`
                        // is only written above), so a published file is
                        // about to be unlinked by `unlink_partial` below.
                        Disposition::RemovedAgain,
                        false,
                    );
                    print_report(&file, &id, &report_file, destination_exists);
                    if let Some(path) = &args.report {
                        write_report_or_warn(path, &report_file);
                    }
                    return Err(unlink_partial(&vault_path, e));
                }
            }
        }

        // ---------------------------------------------------------------
        // Verify
        // ---------------------------------------------------------------
        //
        // In two stages, and the order is the whole point. Everything except
        // the lookup probe is offline — the count against the cleartext
        // header, the fingerprints against the decrypted file, the length
        // histogram — and none of it needs the daemon. So it is taken *first*,
        // while the only thing this run has done is create a file nobody has
        // been told about. A failure there is reversible: unlink and nothing
        // remains, because the alias has not moved and the daemon has not been
        // asked to load anything.
        //
        // Both of those used to happen fifty-one lines before the gate, so a
        // failed verification left `default` pointing at the new collection,
        // the daemon holding it, and the retry blocked by the "already exists"
        // refusal — against a file that run had created.
        let plan = verify::probe_plan(&items);
        let walked =
            // Skipped entries were in the file too, so they count towards the
            // independent total; leaving them out would hide the shortfall the
            // count check exists to expose.
            report.tally.seen() + extraction.skipped.len();
        let mut verification = verify_import(
            &file,
            &items,
            walked,
            destination.as_ref(),
            plan.iter().map(ProbeResult::not_issued).collect(),
        );
        if !verification.passed() {
            // Nothing was published, so the file goes and the error says so
            // rather than the reverse.
            let report_file = ReportFile::new(
                &report,
                // The probe was never issued, so it downgraded nothing and the
                // two tallies are the same one.
                &report.tally,
                &report.items,
                &verification,
                &extraction.skipped,
                &extraction.notes,
                // Nothing is on disk after this branch, whichever run it was:
                // a dry run created nothing, and a real one is about to have
                // the collection it created unlinked by `unlink_partial`
                // below — which is what the error text printed beside this
                // report already says. It said `written: true`.
                if args.dry_run {
                    Disposition::DryRun
                } else {
                    Disposition::RemovedAgain
                },
                // The alias moves only after every check has passed, so on
                // this branch it never moved.
                false,
            );
            print_report(&file, &id, &report_file, destination_exists);
            if let Some(path) = &args.report {
                write_report_or_warn(path, &report_file);
            }
            let e = CliError::Failed(format!(
                "verification did not pass; the lines above name every check that failed. \
                 Nothing was published: the `default` alias was not moved, no daemon was \
                 told to load anything, {} and the source files were not touched.",
                if args.dry_run {
                    "no vault was written,"
                } else {
                    "the collection this run created has been removed again,"
                }
            ));
            return Err(if args.dry_run {
                e
            } else {
                unlink_partial(&vault_path, e)
            });
        }

        // Only now is the collection published: the daemon is told to rescan,
        // which is what gives the probe something to find.
        //
        // **One guard, because these are one ordered pair.** Reload, then
        // question what was reloaded: a probe before the rescan asks a daemon
        // that has never heard of this collection and comes back empty for
        // every attribute set, which is a failure report on a correct import.
        // They sat in two adjacent `if !args.dry_run` blocks with identical
        // conditions — two independently editable halves of one sequence,
        // which is the mechanical shape of the regression this file already
        // records — so they are one block and the order is stated here.
        if !args.dry_run {
            let reloaded = notify_daemon(&env.daemon).await;
            // Whether a *locked* collection can answer an attribute search is
            // a property of the file that was just written, not of this CLI's
            // config: `reopen` read the header back off disk and
            // `Destination::indexed` is what it found there. Gating on
            // `[vault] locked_search` asked the wrong process — the daemon
            // holds the collection and has its own copy of that setting — so
            // a byte-perfect import could exit 1 saying a libsecret client
            // could not find its items, or skip the probe on a header that
            // carries every hash.
            let indexed = destination.as_ref().is_some_and(|d| d.indexed);
            // A daemon that refused the reload was never given the collection,
            // so a probe would come back empty for every attribute set and
            // fail a correct import. Unproved, never failed.
            let probes = if reloaded {
                run_probes(&plan, &id, indexed, &env.daemon).await
            } else {
                eprintln!(
                    "warning: the running daemon did not reload, so the lookup probe was not \
                     issued and discoverability is unproved. Unlock the collection with `sm \
                     unlock --collection {}` and check it by hand with `sm list`.",
                    escape_control(&id)
                );
                plan.iter().map(ProbeResult::not_issued).collect()
            };
            verification.probes = verify::ProbeSummary::of(&probes);
            verification.failed_probes = probes
                .into_iter()
                .filter(|p| p.found.is_some() && !p.passed())
                .collect();
        }

        // The probe's verdict is applied to the items *and* to the tally, so
        // the two agree: `ImportReport`'s own deserializer recomputes the
        // tally from the items and refuses a file where they disagree, which
        // is what `--report` used to write in exactly the case a user would
        // paste into a bug report.
        let probed_items = downgrade_items(&report.items, &verification.failed_probes);
        let probed_tally = verify::tally_with_probes(&probed_items, &verification.failed_probes);

        if !verification.passed() {
            // The bytes are right — every offline check passed above — and the
            // daemon has been told to load the collection, so unlinking now
            // would take a good file away from a daemon that still holds it in
            // memory. The file stays, the alias does not move, and the error
            // names both.
            let report_file = ReportFile::new(
                &report,
                &probed_tally,
                &probed_items,
                &verification,
                &extraction.skipped,
                &extraction.notes,
                // A real run's collection is on disk and stays there, which
                // is what `written` says; the alias below never moves on this
                // branch, which is what `default_alias_moved` says.
                Disposition::of(args.dry_run),
                false,
            );
            print_report(&file, &id, &report_file, destination_exists);
            if let Some(path) = &args.report {
                write_report_or_warn(path, &report_file);
            }
            return Err(CliError::Failed(format!(
                "the collection was written correctly but a libsecret client could not find \
                 every item in it; the lines above name each attribute set that did not come \
                 back. {} is on disk and a running daemon has loaded it, the `default` alias \
                 was not moved, and the source files were not touched. Either unlock it with \
                 `sm unlock --collection {}` and check it by hand with `sm list`, or remove \
                 that file and restart the daemon before importing again.",
                escape_control(&vault_path.display().to_string()),
                escape_control(&id)
            )));
        }
        // Last, and only once every check that could be made has passed: the
        // alias is the one destination effect a user notices, and moving it
        // over a failed migration points `default` at a collection this run is
        // about to call broken.
        let default_alias_moved = if args.set_default && !args.dry_run {
            set_default_alias(config, &id)
        } else {
            false
        };
        if args.set_default && !args.dry_run && !default_alias_moved {
            extraction.notes.push(
                "the `default` alias was requested with --set-default but was left alone; \
                 the warning above says why"
                    .to_string(),
            );
        }
        let report_file = ReportFile::new(
            &report,
            &probed_tally,
            &probed_items,
            &verification,
            &extraction.skipped,
            &extraction.notes,
            Disposition::of(args.dry_run),
            default_alias_moved,
        );

        print_report(&file, &id, &report_file, destination_exists);

        if let Some(path) = &args.report {
            write_report_or_warn(path, &report_file);
        }

        // The alias is a silent exit 0's opposite: when it was requested the
        // run says, on its own line, whether it moved.
        if args.set_default && !args.dry_run {
            if default_alias_moved {
                println!(
                    "The `default` alias now points at '{}'.",
                    escape_control(&id)
                );
            } else {
                println!("The `default` alias was not moved; the warning above says why.");
            }
        }
        Ok(())
    }
}

/// Remove a collection this run published and then failed to finish.
///
/// If the unlink fails too the leftover is named in the error, because it is
/// what the next run will refuse against.
fn unlink_partial(path: &Path, e: CliError) -> CliError {
    match std::fs::remove_file(path) {
        Ok(()) => e,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => e,
        Err(err) => CliError::Failed(format!(
            "{e}. The collection this run had already created could not be removed \
             ({}); {} is still there, and `sm import` will refuse to write that name \
             again until it is gone.",
            escape_control(&err.to_string()),
            escape_control(&path.display().to_string())
        )),
    }
}

/// Point the `default` alias at the imported collection. Returns whether the
/// alias now points at `id`: a `false` is loud, never a silent exit 0 — the
/// caller records it in the report, the notes, and a final terminal line.
///
/// As in `sm init`: the vault is already on disk, so nothing about the
/// alias file may fail the command from here on.
fn set_default_alias(config: &Config, id: &str) -> bool {
    match load_aliases(&config.vault.dir) {
        Ok(mut aliases) => {
            aliases.insert("default".to_string(), id.to_string());
            if let Err(e) = save_aliases_to(&config.vault.dir, &aliases) {
                eprintln!(
                    "warning: the import was written, but the `default` alias could not be \
                     saved: {}",
                    escape_control(&e.to_string())
                );
                false
            } else {
                true
            }
        }
        Err(e) => {
            eprintln!(
                "warning: the import was written, but {} could not be read ({}), so the \
                 `default` alias was left alone.",
                escape_control(&config.vault.dir.join("aliases.toml").display().to_string()),
                escape_control(&e.to_string())
            );
            false
        }
    }
}

/// Tell a running daemon to rescan, so the probe below has something to find.
///
/// Returns whether the probe may run. `true` when the reload answered `Ok`,
/// when there is no daemon to tell (the probe then reports itself not
/// issued), and when nothing is listening at all — a `Connect` failure means
/// no daemon holds a stale view, so the probe's own "no daemon" verdict
/// stands. `false` when a daemon answered with an error or the call failed
/// past connecting: it may not hold this collection, so issuing `SearchItems`
/// would come back empty for every attribute set and fail a correct import.
/// The caller leaves those probes not issued instead.
///
/// `protocol::call` is a blocking connect/write/read on a unix socket against
/// a daemon that may be busy loading the collection this run just wrote, so it
/// goes to the blocking pool rather than onto the async worker this `async fn`
/// is running on. Blocking here parked the runtime thread, which is why three
/// tests carried `worker_threads = 4` and a comment naming the reason.
async fn notify_daemon(target: &DaemonTarget) -> bool {
    let path = match target {
        DaemonTarget::None => return true,
        DaemonTarget::At { control_socket, .. } => control_socket.clone(),
        DaemonTarget::FromEnvironment => {
            let Ok(path) = socket_path() else { return true };
            path
        }
    };
    let reloaded = tokio::task::spawn_blocking(move || call(&path, &Request::Reload))
        .await
        .unwrap_or_else(|e| Err(ProtocolError::Io(std::io::Error::other(e.to_string()))));
    match reloaded {
        Ok(Response::Error(e)) => {
            eprintln!(
                "warning: running daemon did not reload: {}",
                escape_control(&e)
            );
            false
        }
        Err(ProtocolError::Connect(_)) | Ok(_) => true,
        Err(e) => {
            eprintln!(
                "warning: could not tell the running daemon to reload: {}",
                escape_control(&e.to_string())
            );
            false
        }
    }
}

/// The pid of whatever answers the control socket, via
/// [`crate::protocol::peer_pid`]. Nothing is sent: the connection is opened
/// for the kernel's answer about who is on the other end and then dropped.
fn control_socket_peer_pid(socket: &Path) -> std::io::Result<i32> {
    let stream = std::os::unix::net::UnixStream::connect(socket)?;
    crate::protocol::peer_pid(&stream).map_err(|e| match e {
        crate::protocol::ProtocolError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    })
}

/// A session-bus connection and the proof that the service on it is *our*
/// daemon, or a sentence saying why the probe cannot be issued.
///
/// This is the correction the probe needed most. `SearchItems` was issued to
/// whoever owns `org.freedesktop.secrets` on the session bus, and the run that
/// reached this point had just been required to prove that owner was
/// `gnome-keyring-daemon` — the *source*. For a keyring named `login` the
/// destination id is `login` too, so the object-path prefix filter matched
/// gnome-keyring's own item paths and the probe counted source items and
/// reported PASS while proving nothing at all; for a keyring named anything
/// else it matched nothing and failed a byte-perfect import.
///
/// So the probe has to establish who it is talking to, and the only thing that
/// establishes it is identity with the process on the other end of *our*
/// control socket — the socket under `$XDG_RUNTIME_DIR` whose peer we compare
/// by pid. A name matched by process *name* would be a guess (an in-process
/// daemon runs under the test binary's name, and a same-uid impostor may pick
/// any name it likes); a pid from `SO_PEERCRED` against a pid from
/// `GetConnectionUnixProcessID` is the same kernel telling us twice.
///
/// Anything it cannot establish is *unproved*, never a pass and never a
/// failure: no daemon, no answer, two different processes. Each returns the
/// sentence the user is shown.
async fn probe_target(target: &DaemonTarget) -> Result<zbus::Connection, String> {
    let (bus, socket) = match target {
        DaemonTarget::None => {
            return Err("this run was given no daemon to probe".to_string());
        }
        DaemonTarget::At {
            bus_address,
            control_socket,
        } => (Some(bus_address.clone()), control_socket.clone()),
        DaemonTarget::FromEnvironment => (
            None,
            socket_path().map_err(|e| format!("no control socket: {e}"))?,
        ),
    };

    // Ours by construction: the socket lives under `$XDG_RUNTIME_DIR`, and
    // whoever answers it is the daemon this CLI already trusts with vault
    // keys.
    // `connect(2)` on a unix socket blocks, so it goes to the blocking pool
    // rather than onto this async worker: the daemon on the other end may be
    // mid-rescan of the collection this run just wrote, and it answers on the
    // same runtime in an in-process test.
    let ours = {
        let socket = socket.clone();
        tokio::task::spawn_blocking(move || control_socket_peer_pid(&socket))
            .await
            .map_err(|e| format!("the control socket could not be questioned: {e}"))?
    }
    .map_err(|e| {
        format!(
            "the daemon's control socket at {} did not answer ({e})",
            escape_control(&socket.display().to_string())
        )
    })?;

    let conn = match &bus {
        Some(address) => zbus::connection::Builder::address(address.as_str())
            .map_err(|e| format!("bad bus address: {e}"))?
            .build()
            .await
            .map_err(|e| format!("cannot connect to the session bus: {e}"))?,
        None => zbus::Connection::session()
            .await
            .map_err(|e| format!("cannot connect to the session bus: {e}"))?,
    };
    let dbus = zbus::fdo::DBusProxy::new(&conn)
        .await
        .map_err(|e| format!("cannot reach the bus daemon: {e}"))?;
    let name = zbus::names::BusName::try_from(gnome::SECRETS_BUS_NAME)
        .map_err(|e| format!("bad bus name: {e}"))?;
    let owner = dbus
        .get_connection_unix_process_id(name)
        .await
        .map_err(|e| {
            format!(
                "nothing owns {} on the session bus ({e})",
                gnome::SECRETS_BUS_NAME
            )
        })?;
    if i64::from(owner) != i64::from(ours) {
        return Err(format!(
            "{} on the session bus is owned by pid {owner}, which is not the pid {ours} that \
             answers this machine's secret-manager control socket. The probe would have \
             questioned a different provider about our collection",
            gnome::SECRETS_BUS_NAME
        ));
    }
    Ok(conn)
}

/// The lookup probe: one `SearchItems` per distinct source attribute set.
///
/// This is the check that matters. The fingerprints prove the bytes copied;
/// this proves a libsecret client can still find them, which is the actual
/// promise. A daemon that cannot be reached, or that cannot be shown to be
/// ours, makes every probe *not issued* — unproved, never passed.
async fn run_probes(
    plan: &[verify::ProbeQuery],
    id: &str,
    header_is_indexed: bool,
    target: &DaemonTarget,
) -> Vec<ProbeResult> {
    if plan.is_empty() {
        return Vec::new();
    }
    if !header_is_indexed {
        // The new collection is locked the moment the daemon reloads it, and a
        // locked collection is searchable only through the header's hashed
        // attribute index. When that index holds ids alone, every probe
        // returns nothing whatever the import did. Reporting that as a failed
        // probe would fail a correct import; it is an unproved check, which is
        // what it is.
        //
        // The question is asked of the **file** — `Destination::indexed`, read
        // back off disk by `reopen` — and not of `[vault] locked_search`. The
        // config this CLI loaded is not the config the daemon is running, and
        // it is not what shaped the header either: the header is what a locked
        // search reads.
        eprintln!(
            "warning: the new collection's header carries item ids only, so a locked \
             collection answers no attribute search. Every probe would find nothing however \
             faithful the import was, so discoverability is left unproved rather than \
             reported as failed. Unlock the collection with `sm unlock --collection {}` and \
             check with `sm list`.",
            escape_control(id)
        );
        return plan.iter().map(ProbeResult::not_issued).collect();
    }
    let conn = match probe_target(target).await {
        Ok(c) => c,
        Err(why) => {
            eprintln!(
                "warning: the lookup probe could not run ({}), so discoverability is \
                 unproved. Start the daemon and run `sm list` to check by hand.",
                escape_control(&why)
            );
            return plan.iter().map(ProbeResult::not_issued).collect();
        }
    };
    // No session is opened: `SearchItems` returns object paths and no secret,
    // so the probe never asks the daemon to hand one back.
    let service = match crate::dbus::proxies::ServiceProxy::builder(&conn)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "warning: the lookup probe could not run ({}), so discoverability is \
                 unproved. Start the daemon and run `sm list` to check by hand.",
                escape_control(&e.to_string())
            );
            return plan.iter().map(ProbeResult::not_issued).collect();
        }
    };
    // `SearchItems` is service-wide, so the answer includes every collection
    // the daemon holds. Scoped to the one just written, or an item that never
    // arrived still probes green because another collection carries the same
    // attributes, and a pre-existing duplicate makes `found` exceed `expected`
    // - a spurious failure that fails the whole run after a good write.
    let prefix = format!("{}/", paths::collection(id).as_str());
    let mut out = Vec::with_capacity(plan.len());
    for query in plan {
        let map: std::collections::HashMap<&str, &str> = query
            .attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        match service.search_items(map).await {
            // Both halves count: `SearchItems` returns unlocked and locked
            // matches separately, and a locked match is still findable - the
            // hashed attribute index is what makes search work on a locked
            // collection.
            Ok((unlocked, locked)) => {
                let found = unlocked
                    .iter()
                    .chain(locked.iter())
                    .filter(|path| path.as_str().starts_with(&prefix))
                    .count();
                out.push(ProbeResult::new(query, found));
            }
            // Keys, never values: this is the one place in the command that
            // holds attribute values, and an error message naming the probe
            // has to name it the way a report does.
            Err(e) => {
                eprintln!(
                    "warning: the lookup probe for [{}] was refused ({}), so it is unproved \
                     rather than failed.",
                    keys_line(&query.keys()),
                    escape_control(&e.to_string())
                );
                out.push(ProbeResult::not_issued(query));
            }
        }
    }
    out
}

/// What the new vault holds, read back off disk: one fingerprint per item and
/// the distribution of their lengths.
struct Destination {
    fingerprints: Vec<FingerprintEntry>,
    lengths: Histogram,
    /// Whether the header this run wrote carries attribute hashes, so a
    /// *locked* collection can answer an attribute search at all. Read from
    /// the file, which is the only thing that decides it — see [`run_probes`].
    indexed: bool,
}

/// Reopen the collection that was just written and decrypt it again.
fn reopen(path: &Path, password: &[u8], id: &str) -> Result<Destination, CliError> {
    let mut vault = Vault::open(path)?;
    vault.unlock(password)?;
    let items = vault.items()?;
    Ok(Destination {
        fingerprints: items
            .iter()
            .map(|item| {
                FingerprintEntry::destination(
                    &item.attributes,
                    &item.label,
                    &item.content_type,
                    &item.secret,
                    paths::item(id, &item.id).as_str().to_string(),
                )
            })
            .collect(),
        lengths: Histogram::of_lengths(items.iter().map(|i| i.secret.len())),
        indexed: vault.index_has_attributes(),
    })
}

fn verify_import(
    file: &SourceFile,
    items: &[SourceItem],
    walked: usize,
    destination: Option<&Destination>,
    probes: Vec<ProbeResult>,
) -> Verification {
    let source_entries: Vec<FingerprintEntry> =
        items.iter().map(FingerprintEntry::source).collect();
    let (mismatches, compared) = match destination {
        Some(dest) => (
            verify::compare_fingerprints(&source_entries, &dest.fingerprints),
            Some(dest.fingerprints.len()),
        ),
        None => (Vec::new(), None),
    };

    // The KWallet hash-table check: recompute MD5(folder) and MD5(key) per
    // imported item and assert membership, proving no name was mangled using
    // only hashes.
    let (hash_table_misses, hash_table_checked) = match &file.inventory {
        Inventory::Wallet(w) => (
            verify::check_wallet_hash_table(w, items),
            Some(
                items
                    .iter()
                    .filter(|i| i.provenance.folder.is_some() && i.provenance.entry.is_some())
                    .count(),
            ),
        ),
        Inventory::Keyring(_) => (Vec::new(), None),
    };

    // Source lengths from the source items, destination lengths from the
    // decrypted file: a histogram built from one side twice would agree with
    // itself and catch nothing.
    let source_lengths = Histogram::of_lengths(items.iter().map(|i| i.secret.len()));
    let destination_lengths = destination.map(|d| d.lengths.clone());
    let length_differences = match &destination_lengths {
        Some(dest) => verify::compare_histograms(&source_lengths, dest),
        None => Vec::new(),
    };

    Verification {
        // `walked` counts every item the walk produced, refused ones
        // included: a refused item was still in the file, so leaving it out
        // would report a count mismatch for an item we deliberately declined.
        count: verify::CountCheck::new(file.header_item_count, walked),
        fingerprint_mismatches: mismatches,
        fingerprints_compared: compared,
        hash_table_misses,
        hash_table_checked,
        probes: verify::ProbeSummary::of(&probes),
        // Only the failures are kept: a report lists what went wrong, and a
        // line per passing probe would bury it. The counts above already say
        // how many passed.
        failed_probes: probes
            .into_iter()
            .filter(|p| p.found.is_some() && !p.passed())
            .collect(),
        source_lengths,
        destination_lengths,
        length_differences,
    }
}

/// Print what the report file says, from the report file itself.
///
/// One argument rather than ten: six of the ten were `&str` and slices, where
/// swapping two of them type-checks by luck, and every one of them was a field
/// of the [`ReportFile`] this function is printing.
/// The two item-type paragraphs of the printed report, rendered rather than
/// printed so a test can assert on them without capturing stdout.
///
/// They are two paragraphs and not one on purpose. `lost_item_type` is a
/// number from the on-disk format's own numbering, and there is no number for
/// a type string this build cannot place; folding the unrecognised case into
/// it would set `lost_item_type: None`, which is the value that means
/// *nothing was lost* — a flattened type reported as no type at all.
fn item_type_paragraphs(items: &[ItemReport]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let lost: Vec<&ItemReport> = items
        .iter()
        .filter(|i| i.lost_item_type.is_some())
        .collect();
    if !lost.is_empty() {
        let _ = write!(
            out,
            "\n{} items had a source item type with no target here; it was dropped:\n",
            lost.len()
        );
        for item in lost {
            let _ = writeln!(
                out,
                "  {} (type {})",
                escape_control(&item.label),
                item.lost_item_type.unwrap_or_default()
            );
        }
    }
    let unknown: Vec<&ItemReport> = items
        .iter()
        .filter(|i| i.unknown_item_type.is_some())
        .collect();
    if !unknown.is_empty() {
        let _ = write!(
            out,
            "\n{} items carried a source item type this build does not recognise; it has no \
             target here either, and was dropped:\n",
            unknown.len()
        );
        for item in unknown {
            let _ = writeln!(
                out,
                "  {} (type {})",
                escape_control(&item.label),
                escape_control(item.unknown_item_type.as_deref().unwrap_or_default())
            );
        }
    }
    out
}

fn print_report(file: &SourceFile, id: &str, r: &ReportFile<'_>, destination_exists: bool) {
    let source = r.source;
    let label = r.collection;
    let probed = r.tally;
    let verification = r.verification;
    let not_migrated = r.not_migrated;
    let notes = r.notes;
    // `r.dry_run`, never `!r.written`: a run whose offline verification failed
    // wrote a collection and then removed it again, so it is a real run with
    // `written: false`, and printing it as a dry run would tell the user no
    // vault was ever created.
    let dry_run = r.dry_run;
    println!(
        "{} import from {source}",
        if dry_run { "Dry run:" } else { "Completed" }
    );
    println!(
        "  source file          {}",
        escape_control(&file.path.display().to_string())
    );
    println!(
        "  destination          '{}' (id {})",
        escape_control(label),
        escape_control(id)
    );
    if dry_run {
        println!("  no vault was written");
    }

    println!("\nOutcome, per the three-way split:");
    println!(
        "  fully portable                                {}",
        probed.fully_portable()
    );
    println!(
        "  attributes preserved, discoverability uncertain  {}",
        probed.attributes_preserved()
    );
    println!(
        "  preserved only                                {}",
        probed.preserved_only()
    );
    println!(
        "  refused                                       {}",
        probed.refused()
    );

    let refused: Vec<&ItemReport> = r.items.iter().filter(|i| i.is_refused()).collect();
    if !refused.is_empty() {
        println!("\nRefused, and why:");
        for item in refused {
            for refusal in &item.refusals {
                println!(
                    "  {}: {}",
                    escape_control(&item.label),
                    escape_control(&refusal.to_string())
                );
            }
        }
    }

    if !not_migrated.is_empty() {
        println!("\nNot migrated, and why ({} entries):", not_migrated.len());
        for entry in not_migrated {
            println!(
                "  {}: {}",
                escape_control(&entry.label),
                escape_control(&entry.reason)
            );
        }
    }
    if !notes.is_empty() {
        println!("\nAlso worth knowing:");
        for note in notes {
            println!("  {}", escape_control(note));
        }
    }

    let downgraded: Vec<&ItemReport> = r.items.iter().filter(|i| i.acl_downgrade).collect();
    if !downgraded.is_empty() {
        println!(
            "\n{} items carried a per-application access list, which the Secret Service has no \
             equivalent for. \"Only one program may read this\" has become \"anything on the \
             session bus may read this\":",
            downgraded.len()
        );
        for item in downgraded {
            println!("  {}", escape_control(&item.label));
        }
    }

    print!("{}", item_type_paragraphs(r.items));
    if r.empty_folders > 0 {
        println!(
            "\n{} source folders held no entries. A collection of items has nowhere to put \
             them, so they were not migrated.",
            r.empty_folders
        );
    }

    println!("\nVerification:");
    println!("  item count           {}", verification.count);
    match verification.fingerprints_compared {
        Some(n) if verification.fingerprint_mismatches.is_empty() => {
            println!("  fingerprints         {n} compared, all matched");
        }
        Some(n) => {
            println!(
                "  fingerprints         {n} compared, {} did not match:",
                verification.fingerprint_mismatches.len()
            );
            for m in &verification.fingerprint_mismatches {
                println!(
                    "      {} [{}] {} {}",
                    m.fingerprint,
                    keys_line(&m.attribute_keys),
                    m.side,
                    m.object_path
                        .as_deref()
                        .map(escape_control)
                        .unwrap_or_default()
                );
            }
        }
        None => println!("  fingerprints         not compared: no vault was written"),
    }
    if let Some(n) = verification.hash_table_checked {
        if verification.hash_table_misses.is_empty() {
            println!("  wallet hash table    {n} names matched by hash");
        } else {
            println!(
                "  wallet hash table    {} of {n} names are not in the index:",
                verification.hash_table_misses.len()
            );
            for miss in &verification.hash_table_misses {
                println!(
                    "      folder {} entry {}",
                    miss.folder_hash, miss.entry_hash
                );
            }
        }
    }
    let p = &verification.probes;
    println!(
        "  lookup probe         {} of {} attribute sets found exactly what was expected{}",
        p.passed,
        p.total(),
        if p.not_issued > 0 {
            format!(" ({} not issued)", p.not_issued)
        } else {
            String::new()
        }
    );
    for probe in verification
        .failed_probes
        .iter()
        .filter(|r| r.found.is_some() && !r.passed())
    {
        println!(
            "      [{}] expected {}, found {}",
            keys_line(&probe.attribute_keys),
            probe.expected,
            probe.found.unwrap_or_default()
        );
    }
    println!(
        "  secret lengths       {}",
        histogram_line(&verification.source_lengths)
    );
    if let Some(dest) = &verification.destination_lengths {
        println!("                       {}", histogram_line(dest));
        for diff in &verification.length_differences {
            println!(
                "      bucket {} holds {} items at the source and {} here",
                diff.bucket, diff.source, diff.destination
            );
        }
    }
    for line in verification.unproved() {
        println!("  unproved             {line}");
    }

    // Nothing is ever deleted or modified at the source; the path is printed
    // and the decision is the user's.
    println!(
        "\nThe source was not modified. It is still at {}.",
        escape_control(&file.path.display().to_string())
    );
    if dry_run {
        if destination_exists {
            println!(
                "A collection with this id already exists, so running the same command \
                 without --dry-run would refuse. Pass --collection with a name that is not \
                 in use."
            );
        } else {
            println!("Run the same command without --dry-run to write the collection.");
        }
        return;
    }
    // `passed()` is every check that was *made*; the right to suggest that the
    // old provider be removed belongs to a run with nothing left unproved. A
    // probe that was never issued proves nothing about discoverability, and
    // "decommission the thing that still works" is not advice to give on the
    // strength of a check that did not run.
    if verification.passed() && verification.unproved().is_empty() {
        println!(
            "\nNext: decommission the old provider. docs/install-arch.md and \
             docs/install-debian.md cover that for each distribution - the autostart entry, \
             the PAM stack, and the other bus names the old provider owns.\n\
             One thing is specific to having migrated: ksecretd holds the bus name for the \
             life of the session, so log out and back in before checking. Anything short of \
             that leaves the old provider in place and looks like a failed migration."
        );
    }
}

fn keys_line(keys: &AttributeKeys) -> String {
    keys.iter()
        .map(escape_control)
        .collect::<Vec<_>>()
        .join(", ")
}

fn histogram_line(h: &Histogram) -> String {
    h.rows()
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(bucket, n)| format!("{bucket}:{n}"))
        .collect::<Vec<_>>()
        .join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{Provenance, Refusal};
    use std::collections::BTreeMap;

    // Distinctive enough that a substring search for them is a real search:
    // none of these is a word the report could produce by other means.
    const SECRET: &str = "correct-horse-battery-staple-7f1c";
    const SERVER_VALUE: &str = "vault-host.internal.example";
    const USER_VALUE: &str = "joseph-the-distinctive-account";
    const SCHEMA_VALUE: &str = "org.example.DistinctiveSchema";

    fn hostile_item() -> SourceItem {
        let attributes: BTreeMap<String, String> = [
            ("xdg:schema", SCHEMA_VALUE),
            ("server", SERVER_VALUE),
            ("user", USER_VALUE),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        SourceItem {
            label: "A migrated login".to_string(),
            attributes,
            secret: Zeroizing::new(SECRET.as_bytes().to_vec()),
            content_type: "text/plain".to_string(),
            created: 1_699_383_593,
            modified: 1_699_387_319,
            provenance: Provenance::kwallet("kdewallet", "Passwords", "an entry name"),
            inserted_keys: std::collections::BTreeSet::new(),
        }
    }

    /// The gnome walk is restricted to the keyring [`locate`] chose.
    ///
    /// This is the one decision on that path a test can reach: the call itself
    /// needs a `gnome-keyring-daemon` and a private bus, so with the option
    /// built as a literal inside it, `only_container: None` — the bug this
    /// branch introduced, where a walk of every keyring the private daemon
    /// exposes was written into a collection named after one of them — passed
    /// the whole suite. The independent count is taken over the same one
    /// keyring, so the two halves disagreeing is a failed verification on a
    /// faithful import.
    #[test]
    fn the_gnome_walk_is_restricted_to_the_keyring_that_was_located() {
        let options = gnome_options("Work keyring");
        assert_eq!(
            options.only_container.as_deref(),
            Some("Work keyring"),
            "the walk covers every keyring the private daemon holds"
        );
    }

    /// An item type this build does not recognise gets its own paragraph.
    ///
    /// The case used to be invisible: an unrecognised `Item.Type` produced
    /// `lost_item_type: None`, which is the value that means nothing was
    /// lost, and the printed report said nothing at all. This asserts the
    /// paragraph, and that it is separate from the numbered one — a report
    /// that merged them would name the type twice or not at all.
    #[test]
    fn an_unrecognised_item_type_gets_its_own_paragraph() {
        let mut numbered = ItemReport::imported(&hostile_item());
        numbered.label = "A network password".to_string();
        numbered.lost_item_type = Some(1);
        let mut unknown = ItemReport::imported(&hostile_item());
        unknown.label = "A future thing".to_string();
        unknown.unknown_item_type = Some("org.gnome.keyring.NewType".to_string());
        let plain = ItemReport::imported(&hostile_item());

        let out = item_type_paragraphs(&[numbered, unknown, plain]);
        assert!(
            out.contains("1 items had a source item type with no target"),
            "{out}"
        );
        assert!(out.contains("A network password (type 1)"), "{out}");
        assert!(
            out.contains("1 items carried a source item type this build does not recognise"),
            "{out}"
        );
        assert!(
            out.contains("A future thing (type org.gnome.keyring.NewType)"),
            "{out}"
        );
        // The item with neither is in neither paragraph.
        assert!(!out.contains("A migrated login"), "{out}");
    }

    /// A daemon that repeats listings must be audible in the report. Without
    /// these sentences a wallet whose daemon tripled every folder imports
    /// cleanly and nothing says the counts were ever in doubt.
    #[test]
    fn repeated_listings_get_their_own_notes() {
        let walked = kwallet::Extraction {
            duplicate_folders: 3,
            duplicate_entries: 5,
            ..Default::default()
        };

        let out = kwallet_notes(&walked).join("\n");

        assert!(
            out.contains("3 folder listings repeated a folder"),
            "no folder sentence: {out}"
        );
        assert!(
            out.contains("5 entry listings repeated an entry"),
            "no entry sentence: {out}"
        );
    }

    /// And silence when there is nothing to say: the common case adds no
    /// paragraphs.
    #[test]
    fn no_repeats_means_no_repeat_notes() {
        let walked = kwallet::Extraction {
            ..Default::default()
        };

        assert!(kwallet_notes(&walked).is_empty());
    }

    fn wallet_source_file() -> SourceFile {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import/sample.kwl");
        let inventory = parse_wallet_header(&std::fs::read(&path).unwrap()).unwrap();
        SourceFile {
            path,
            inventory: Inventory::Wallet(Box::new(inventory)),
            header_item_count: Some(1),
        }
    }

    /// The report `--report` writes must be a report its own parser accepts.
    ///
    /// `ImportReport`'s `Deserialize` recomputes the tally from the items and
    /// refuses a file where the two disagree — which is exactly what this
    /// command used to write, because it paired the post-probe `tally` with
    /// the un-downgraded `items`. And it is written *before* the failure
    /// return, so the unreadable file was produced in precisely the case a
    /// user pastes into a bug report.
    #[test]
    fn the_written_report_parses_back_as_the_report_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");

        let item = hostile_item();
        let mut report = ImportReport::new(Source::GnomeKeyring, "Sample keyring");
        report.push(ItemReport::imported(&item));
        assert_eq!(report.tally.fully_portable(), 1);

        // One probe, for this item's own attribute set, that came back empty:
        // the attributes are on disk and the daemon does not return the item.
        let plan = verify::probe_plan(std::slice::from_ref(&item));
        let failed: Vec<ProbeResult> = plan.iter().map(|q| ProbeResult::new(q, 0)).collect();
        assert!(!failed[0].passed());

        let verification = Verification {
            count: verify::CountCheck::new(Some(1), 1),
            fingerprint_mismatches: Vec::new(),
            fingerprints_compared: Some(1),
            hash_table_misses: Vec::new(),
            hash_table_checked: None,
            probes: verify::ProbeSummary::of(&failed),
            failed_probes: failed,
            source_lengths: Histogram::of_lengths(std::iter::once(item.secret.len())),
            destination_lengths: None,
            length_differences: Vec::new(),
        };

        let probed_items = downgrade_items(&report.items, &verification.failed_probes);
        let probed_tally = verify::tally_with_probes(&probed_items, &verification.failed_probes);
        // The probe downgraded it, so the tally the file carries is not the
        // one the items would have added up to a moment ago.
        assert_eq!(probed_tally.fully_portable(), 0);
        assert_eq!(probed_tally.attributes_preserved(), 1);
        let report_file = ReportFile::new(
            &report,
            &probed_tally,
            &probed_items,
            &verification,
            &[],
            &[],
            Disposition::Kept,
            false,
        );
        write_report(&path, &report_file).unwrap();

        let json = std::fs::read_to_string(&path).unwrap();
        let parsed: ImportReport = serde_json::from_str(&json).unwrap_or_else(|e| {
            panic!("the report this command writes does not parse: {e}\n{json}")
        });
        assert_eq!(parsed.tally, probed_tally);
        // And the pre-probe tally is still in the file, because the difference
        // between the two is itself a finding.
        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            raw["tally_before_probe"]["fully_portable"],
            serde_json::json!(1)
        );
    }

    /// The module's central claim, asserted against the bytes the product
    /// actually writes.
    ///
    /// `ImportReport` is no longer what `--report` emits: [`ReportFile`] wraps
    /// it and adds `verification`, `not_migrated` and `notes`, and
    /// [`write_report`] is what renders the whole thing to disk. Screening
    /// `ImportReport` alone therefore screened a value the product never
    /// produces, and left three report fields — [`verify::HashMiss`], the
    /// [`FingerprintEntry`]-derived mismatch rows, and [`NotMigrated`] — with
    /// nothing asserting they are hashes, counts and names rather than the
    /// values they are computed from.
    ///
    /// So every one of the three is *made non-empty here*, from an item whose
    /// secret and whose three attribute values are strings nothing else can
    /// produce, and the file is read back off disk and searched.
    #[test]
    fn the_written_report_holds_no_secret_and_no_attribute_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");

        let item = hostile_item();
        let items = vec![item.clone()];
        let file = wallet_source_file();

        // A destination that holds nothing, so every source fingerprint is a
        // mismatch and the `FingerprintEntry`-derived rows are in the report.
        // The mismatch rows are the ones built from a digest over the secret.
        let destination = Destination {
            fingerprints: Vec::new(),
            lengths: Histogram::of_lengths(std::iter::empty()),
            indexed: true,
        };
        let verification = verify_import(&file, &items, 1, Some(&destination), Vec::new());
        assert!(
            !verification.fingerprint_mismatches.is_empty(),
            "the fingerprint rows this test exists to screen were never produced"
        );
        assert!(
            !verification.hash_table_misses.is_empty(),
            "the hash-table rows this test exists to screen were never produced"
        );

        let mut report = ImportReport::new(Source::KWallet, "kdewallet (imported)");
        report.push(ItemReport::imported(&item));
        report.push(ItemReport::refused(
            item.provenance.clone(),
            "An oversized login",
            Refusal::CapViolation {
                cap: crate::vault::format::Cap::Secret,
                actual: 1_000_000,
                limit: crate::vault::format::MAX_ITEM_SECRET,
            },
        ));
        let probed_tally = verify::tally_with_probes(&report.items, &verification.failed_probes);
        let not_migrated = vec![NotMigrated {
            label: "An entry that would not decode".to_string(),
            reason: "the map would not decode".to_string(),
        }];
        let notes = vec!["the session with the source daemon was plaintext".to_string()];
        let probed_items = downgrade_items(&report.items, &verification.failed_probes);
        let report_file = ReportFile::new(
            &report,
            &probed_tally,
            &probed_items,
            &verification,
            &not_migrated,
            &notes,
            Disposition::Kept,
            false,
        );
        write_report(&path, &report_file).unwrap();

        let json = std::fs::read_to_string(&path).unwrap();
        for leaked in [SECRET, SERVER_VALUE, USER_VALUE, SCHEMA_VALUE] {
            assert!(!json.contains(leaked), "{leaked:?} leaked into {json}");
        }
        // And the report is still readable by the person it is for: the keys,
        // the outcome, and each of the three sections above are present, so
        // the screen above cannot be passing because the file is empty.
        for kept in [
            "xdg:schema",
            "server",
            "user",
            "fully-portable",
            "cap-violation",
            "fingerprint_mismatches",
            "hash_table_misses",
            "not_migrated",
            "An entry that would not decode",
        ] {
            assert!(json.contains(kept), "{kept:?} missing from {json}");
        }
    }
}
