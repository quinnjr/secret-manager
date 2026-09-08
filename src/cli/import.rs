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
//! **The independent count is taken over everything the walk can reach.** For
//! gnome-keyring that is *every* keyring the private daemon holds, not the one
//! [`locate`] named: the walk enumerates collections over the bus and has no
//! way to be told "only this file". So the header total is summed across every
//! `.keyring` in the source directory, which is the side of the disagreement
//! that can be fixed here — restricting the walk is a change to the transport
//! in `src/import/gnome.rs`. If any sibling header cannot be read the total is
//! not taken at all: a check that is *not made* is reported as unproved, and a
//! wrong total would fail a good import.
//!
//! **The surface below the command itself is test-only.** [`Extraction`],
//! [`Imported`], [`Extractor`], [`ImportEnv`] and [`run_with`] exist so the
//! pipeline can be driven with no gnome-keyring and no kwalletd anywhere; they
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
pub use self::pipeline::{ImportEnv, run_with};
#[cfg(not(any(test, feature = "test-util")))]
pub(crate) use self::pipeline::{ImportEnv, run_with};
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
struct LiveExtractor;

impl Extractor for LiveExtractor {
    fn extract<'a>(&'a self, source: Source, container_hint: &'a str) -> transport::Extracting<'a> {
        Box::pin(async move {
            match source {
                Source::GnomeKeyring => extract_gnome(container_hint).await,
                Source::KWallet => extract_kwallet(container_hint).await,
            }
        })
    }
}

/// gnome-keyring, over a private bus with a private daemon: the real session
/// bus is never displaced, and the password goes to the child's stdin.
///
/// The bus-owner precondition runs first, and it is a hard refusal with no
/// override. The private bus means the session bus's owner cannot *technically*
/// block the extraction — the daemon read below is one this process started.
/// That is not the reason the check exists. `org.freedesktop.secrets` owned by
/// something that is not `gnome-keyring-daemon` — `ksecretd`, in the case this
/// was written for — means gnome-keyring is not the provider the user has been
/// using, and "migrate gnome-keyring" would faithfully migrate a set of
/// keyrings nobody has written to since the other provider took over. Every
/// check in this command would agree, because both halves read the same wrong
/// source. The user's belief about what is being migrated is the thing being
/// verified, and nothing downstream can verify it.
///
/// It runs *before* the password prompt: there is no point asking for a
/// password to read the wrong source, and a refusal after the prompt reads as
/// "your password was wrong".
async fn extract_gnome(container: &str) -> Result<Extraction, CliError> {
    gnome::require_gnome_keyring_owner()
        .await
        .map_err(|e| match e {
            // The variant's own text names the owner and the two remedies —
            // migrate that provider instead, or stop it and log back in. What
            // it cannot say, because it does not know which route asked, is why
            // a private-bus extraction refuses on the strength of the *session*
            // bus, so that is added here.
            e @ gnome::GnomeError::WrongBusOwner { .. } => CliError::Unreachable(format!(
                "{} This command would have read gnome-keyring's own keyrings over a private \
                 bus and reported success, so the refusal is not about reachability: it is \
                 that the keyrings on disk are not where your secrets have been going.",
                escape_control(&e.to_string())
            )),
            other => gnome_error(other),
        })?;
    let password = super::read_password(
        "gnome-keyring login password (it is sent to a private gnome-keyring-daemon, \
         never stored)",
    )?;
    let password = Zeroizing::new(password.as_bytes().to_vec());
    // Only the keyring the user named. Without this the walk covers every
    // collection the private daemon exposes, so items from keyrings they did
    // not ask for land in a collection labelled after the one they did — and
    // the label then misdescribes its own contents.
    let walked = gnome::extract_over_private_bus(
        &password,
        &gnome::ExtractOptions {
            only_container: Some(container.to_string()),
            ..Default::default()
        },
    )
    .await
    .map_err(gnome_error)?;

    let mut notes = Vec::new();
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
            "the collection '{}' holds {} items and its unlock prompt could not be \
             answered, so none of them were read",
            escape_control(&collection.label),
            collection.item_count
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
        skipped: Vec::new(),
        empty_folders: 0,
        notes,
    })
}

/// KWallet, over `org.kde.kwalletd6` on the session bus: a different bus name
/// from ours, so this path needs no private bus and no ordering against our
/// own daemon.
async fn extract_kwallet(wallet: &str) -> Result<Extraction, CliError> {
    let conn = zbus::Connection::session()
        .await
        .map_err(|e| CliError::Unreachable(format!("cannot connect to the session bus: {e}")))?;
    let sidecar_path = kwallet::sidecar_path(wallet);
    let sidecar = match kwallet::Sidecar::load(&sidecar_path) {
        Ok(s) => s,
        Err(e) => {
            // A wallet with no sidecar is a wallet of native KWallet entries,
            // which is a real case and not an error: those items are
            // `PreservedOnly` and the report says so.
            eprintln!(
                "warning: {} could not be read ({}), so no attributes, content types or \
                 timestamps are available and every entry will be preserved-only.",
                escape_control(&sidecar_path.display().to_string()),
                escape_control(&e.to_string())
            );
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

    let mut notes = Vec::new();
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
    if !walked.unresolved_sidecar_rows.is_empty() {
        notes.push(format!(
            "{} sidecar rows named an entry the walk never found",
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

fn gnome_error(e: gnome::GnomeError) -> CliError {
    let text = escape_control(&e.to_string());
    match e {
        gnome::GnomeError::WrongBusOwner { .. }
        | gnome::GnomeError::BusNeverReady { .. }
        | gnome::GnomeError::KeyringNeverReady { .. } => CliError::Unreachable(text),
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
    /// cleartext header(s) — summed over every keyring the gnome walk reaches,
    /// and the single wallet's entry count for KWallet. `None` when it could
    /// not be taken, which is reported as *not made* rather than as a failure.
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
        std::io::ErrorKind::NotFound => CliError::NotFound(format!(
            "no {} directory at {}",
            extension,
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

/// Read a source file, bounding the read before making it: these are foreign
/// files and their length fields are attacker-controlled.
fn read_source(path: &Path) -> Result<Vec<u8>, CliError> {
    let meta = std::fs::metadata(path).map_err(|e| header_io(path, e))?;
    formats::check_source_size(meta.len()).map_err(|e| header_error(path, &e))?;
    std::fs::read(path).map_err(|e| header_io(path, e))
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

            // The walk covers every keyring the private daemon holds, so the
            // independent total has to as well; see this module's header.
            let mut total = Some(0usize);
            let mut chosen_inventory = None;
            for path in &candidates {
                let parsed = read_source(path).and_then(|bytes| {
                    parse_keyring_header(&bytes).map_err(|e| header_error(path, &e))
                });
                match parsed {
                    Ok(inventory) => {
                        if let Some(sum) = total.as_mut() {
                            *sum += inventory.item_count();
                        }
                        if *path == chosen {
                            chosen_inventory = Some(inventory);
                        }
                    }
                    Err(e) if *path == chosen => return Err(e),
                    Err(e) => {
                        eprintln!(
                            "warning: {} could not be read ({}), so the item count cannot be \
                             taken over every keyring the walk reaches and the count check is \
                             not made.",
                            escape_control(&path.display().to_string()),
                            escape_control(&e.to_string())
                        );
                        total = None;
                    }
                }
            }
            let inventory = match chosen_inventory {
                Some(inventory) => inventory,
                // The `default` file named a keyring the listing did not
                // produce; read it on its own and take no total.
                None => {
                    total = None;
                    let bytes = read_source(&chosen)?;
                    parse_keyring_header(&bytes).map_err(|e| header_error(&chosen, &e))?
                }
            };
            Ok(SourceFile {
                path: chosen,
                inventory: Inventory::Keyring(Box::new(inventory)),
                header_item_count: total,
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
            Err(CliError::Usage(format!(
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
    /// `false` for `--dry-run`: the report describes what *would* happen.
    written: bool,
}

impl<'a> ReportFile<'a> {
    fn new(
        report: &'a ImportReport,
        probed_tally: &'a Tally,
        verification: &'a Verification,
        not_migrated: &'a [NotMigrated],
        notes: &'a [String],
        written: bool,
    ) -> Self {
        Self {
            source: report.source,
            collection: &report.collection,
            tally: probed_tally,
            tally_before_probe: &report.tally,
            items: &report.items,
            empty_folders: report.empty_folders,
            header_item_count: report.header_item_count,
            verification,
            not_migrated,
            notes,
            written,
        }
    }
}

fn write_report(path: &Path, file: &ReportFile<'_>) -> Result<(), CliError> {
    let mut json = serde_json::to_string_pretty(file)
        .map_err(|e| CliError::Failed(format!("could not render the report: {e}")))?;
    json.push('\n');
    write_report_file(path, json.as_bytes())
}

/// Write the report to a sibling temp file created 0600, fsync it, and rename
/// it into place.
///
/// Two things this fixes, and neither is theoretical. `OpenOptions::mode`
/// applies **only when the file is created**, so an existing `report.json` at
/// 0644 was truncated and rewritten with its old permissions — publishing
/// labels, attribute key names and KWallet folder and entry names to every
/// local user, while the comment beside it claimed 0600. And a truncate
/// followed by two writes leaves a truncated JSON document behind a crash,
/// where a complete report used to be. A rename is atomic: the reader sees the
/// old report or the new one.
fn write_report_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "report.json".to_string());
    let suffix: String = crate::vault::crypto::random_bytes::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let temp = dir.join(format!(".{name}.{suffix}.tmp"));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The report names labels and attribute keys, which is not secret but
        // is nobody else's business either.
        options.mode(0o600);
    }
    let mut f = options.open(&temp).map_err(|e| header_io(&temp, e))?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| std::fs::rename(&temp, path)) {
        let _ = std::fs::remove_file(&temp);
        return Err(header_io(path, e));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// The command
// --------------------------------------------------------------------------

pub async fn run(args: ImportArgs) -> Result<(), CliError> {
    let source: Source = args.from.into();
    let env = ImportEnv::new(load_config()?, source_dir(source)?);
    run_with(args, &LiveExtractor, &env).await
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
        /// Whether this run may reach the running daemon at all: the `Reload`
        /// over the control socket and the lookup probe over the session bus.
        ///
        /// `true` everywhere in production. It is a field rather than a
        /// question answered from the environment because the only other way
        /// to keep an in-process test off the developer's own daemon is to
        /// point `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` at nothing
        /// with `std::env::set_var` — which, in edition 2024, is `unsafe`
        /// precisely because it races every other thread in the same test
        /// binary, and `cargo test` runs tests in parallel. The addresses
        /// themselves cannot be carried here: `protocol::socket_path` and
        /// `cli::client::Client::connect` read the environment inside
        /// themselves, and neither is this module's to change.
        ///
        /// Turning it off does not fake a pass. The probes come back *not
        /// issued*, which `Verification::unproved` reports as a check that was
        /// not made — exactly what they are on a machine with no daemon.
        pub reach_the_daemon: bool,
    }

    impl ImportEnv {
        pub fn new(config: Config, source_dir: PathBuf) -> Self {
            Self {
                config,
                source_dir,
                new_password: Box::new(read_new_password),
                reach_the_daemon: true,
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
        let extraction = extractor.extract(source, &container).await?;

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
            let mut vault =
                Vault::create(&vault_path, &label, password.as_bytes(), config.kdf.into())?;
            let imported = vault
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
                .map_err(CliError::from);
            drop(vault);
            // Read the destination back off *disk*, decrypting it again, so
            // the fingerprints compare what was written rather than the list
            // we intended to write. An import that verified against its own
            // in-memory copy would prove nothing about the file.
            match imported.and_then(|()| reopen(&vault_path, password.as_bytes(), &id)) {
                Ok(dest) => destination = Some(dest),
                Err(e) => return Err(unlink_partial(&vault_path, e)),
            }
            if args.set_default {
                set_default_alias(config, &id);
            }
            if env.reach_the_daemon {
                notify_daemon();
            }
        }

        // ---------------------------------------------------------------
        // Verify
        // ---------------------------------------------------------------
        let probes = if args.dry_run || !env.reach_the_daemon {
            verify::probe_plan(&items)
                .iter()
                .map(ProbeResult::not_issued)
                .collect()
        } else {
            run_probes(&items, &id, config.vault.locked_search).await
        };
        let verification = verify_import(
            &file,
            &items,
            // Skipped entries were in the file too, so they count towards the
            // independent total; leaving them out would hide the shortfall the
            // count check exists to expose.
            report.tally.seen() + extraction.skipped.len(),
            destination.as_ref(),
            probes,
        );
        let probed_tally = verify::tally_with_probes(&report.items, &verification.failed_probes);
        let report_file = ReportFile::new(
            &report,
            &probed_tally,
            &verification,
            &extraction.skipped,
            &extraction.notes,
            !args.dry_run,
        );

        print_report(&file, &id, &report_file, destination_exists);

        if let Some(path) = &args.report {
            write_report(path, &report_file)?;
            println!(
                "\nReport written to {}",
                escape_control(&path.display().to_string())
            );
        }

        if !verification.passed() {
            return Err(CliError::Failed(
                "verification did not pass; the lines above name every check that failed. \
                 The source files were not touched."
                    .into(),
            ));
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

fn set_default_alias(config: &Config, id: &str) {
    // As in `sm init`: the vault is already on disk, so nothing about the
    // alias file may fail the command from here on.
    match load_aliases(&config.vault.dir) {
        Ok(mut aliases) => {
            aliases.insert("default".to_string(), id.to_string());
            if let Err(e) = save_aliases_to(&config.vault.dir, &aliases) {
                eprintln!(
                    "warning: the import was written, but the `default` alias could not be \
                     saved: {}",
                    escape_control(&e.to_string())
                );
            }
        }
        Err(e) => eprintln!(
            "warning: the import was written, but {} could not be read ({}), so the \
             `default` alias was left alone.",
            escape_control(&config.vault.dir.join("aliases.toml").display().to_string()),
            escape_control(&e.to_string())
        ),
    }
}

/// Tell a running daemon to rescan, so the probe below has something to find.
fn notify_daemon() {
    let Ok(path) = socket_path() else { return };
    match call(&path, &Request::Reload) {
        Ok(Response::Error(e)) => {
            eprintln!(
                "warning: running daemon did not reload: {}",
                escape_control(&e)
            );
        }
        Err(ProtocolError::Connect(_)) | Ok(_) => {}
        Err(e) => eprintln!(
            "warning: could not tell the running daemon to reload: {}",
            escape_control(&e.to_string())
        ),
    }
}

/// The lookup probe: one `SearchItems` per distinct source attribute set.
///
/// This is the check that matters. The fingerprints prove the bytes copied;
/// this proves a libsecret client can still find them, which is the actual
/// promise. A daemon that cannot be reached makes every probe *not issued* —
/// unproved, never passed.
async fn run_probes(items: &[SourceItem], id: &str, locked_search: bool) -> Vec<ProbeResult> {
    let plan = verify::probe_plan(items);
    if plan.is_empty() {
        return Vec::new();
    }
    if !locked_search {
        // The new collection is locked the moment the daemon reloads it, and a
        // locked collection is searchable only through the header's hashed
        // attribute index. With `[vault] locked_search = false` that index
        // holds ids alone, so every probe returns nothing whatever the import
        // did. Reporting that as a failed probe would fail a correct import;
        // it is an unproved check, which is what it is.
        eprintln!(
            "warning: [vault] locked_search = false, so the new collection's header carries \
             item ids only and a locked collection answers no attribute search. Every probe \
             would find nothing however faithful the import was, so discoverability is left \
             unproved rather than reported as failed. Unlock the collection with `sm unlock \
             --collection {}` and check with `sm list`.",
            escape_control(id)
        );
        return plan.iter().map(ProbeResult::not_issued).collect();
    }
    let client = match super::client::Client::connect().await {
        Ok(c) => c,
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
    for query in &plan {
        match client.search(&query.attributes).await {
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
fn print_report(file: &SourceFile, id: &str, r: &ReportFile<'_>, destination_exists: bool) {
    let source = r.source;
    let label = r.collection;
    let probed = r.tally;
    let verification = r.verification;
    let not_migrated = r.not_migrated;
    let notes = r.notes;
    let dry_run = !r.written;
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
        println!("  nothing was written");
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

    let lost_types: Vec<&ItemReport> = r
        .items
        .iter()
        .filter(|i| i.lost_item_type.is_some())
        .collect();
    if !lost_types.is_empty() {
        println!(
            "\n{} items had a source item type with no target here; it was dropped:",
            lost_types.len()
        );
        for item in lost_types {
            println!(
                "  {} (type {})",
                escape_control(&item.label),
                item.lost_item_type.unwrap_or_default()
            );
        }
    }
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
        None => println!("  fingerprints         not compared: nothing was written"),
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
        }
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
        let report_file = ReportFile::new(
            &report,
            &probed_tally,
            &verification,
            &not_migrated,
            &notes,
            true,
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
