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
//! **Pre-check before writing anything.** Every item is measured against the
//! six caps before the first byte is written. A migration that fails halfway
//! leaves the user worse off than one that refuses at the start, so a cap
//! violation aborts the whole import and names the items.
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
use crate::import::{AttributeKeys, ImportReport, ItemReport, Refusal, Source, SourceItem, Tally};
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

/// One item that will be written, with the report row that describes it.
///
/// The row comes from the extractor rather than from `ItemReport::imported`
/// here, because only the extractor knows the two things the row carries that
/// the item itself does not: the source item type that has no target, and the
/// per-application access list the Secret Service has no equivalent for.
pub struct Imported {
    pub item: SourceItem,
    pub report: ItemReport,
}

/// An entry the walk found and did not write for a reason [`Refusal`] does
/// not name — a KWallet map that would not decode, an entry the wallet would
/// not hand over. Named in the report rather than counted, because "something
/// did not come across" is the one thing a migration report may not round off.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NotMigrated {
    pub label: String,
    pub reason: String,
}

/// What one source's extractor produces.
///
/// `src/import/gnome.rs` and `src/import/kwallet.rs` own the transports —
/// a private session bus and a `gnome-keyring-daemon` child for one, the
/// `org.kde.kwalletd6` service for the other. This is the shape the rest of
/// the command is written against, so the pipeline below (pre-check, write,
/// verify, report) is exercised by tests with no source daemon anywhere.
pub struct Extraction {
    /// The source's own name for the container: a keyring's display name, or
    /// a wallet's name. It is the default destination label.
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
    /// because the source refused DH, a collection whose unlock prompt nobody
    /// could answer, sidecar rows that resolved to no entry.
    pub notes: Vec<String>,
}

/// A boxed future, because the two transports are async and this trait is
/// used through `dyn`.
type Extracting<'a> = Pin<Box<dyn Future<Output = Result<Extraction, CliError>> + 'a>>;

/// How the command obtains an [`Extraction`]. One implementation per source
/// plus, in tests, one that returns a fixed set.
pub trait Extractor {
    fn extract<'a>(&'a self, source: Source, container_hint: &'a str) -> Extracting<'a>;
}

/// The live transports.
struct LiveExtractor;

impl Extractor for LiveExtractor {
    fn extract<'a>(&'a self, source: Source, container_hint: &'a str) -> Extracting<'a> {
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
async fn extract_gnome(container: &str) -> Result<Extraction, CliError> {
    let password = super::read_password(
        "gnome-keyring login password (it is sent to a private gnome-keyring-daemon, \
         never stored)",
    )?;
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let walked = gnome::extract_over_private_bus(&password, &gnome::ExtractOptions::default())
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
    if walked.entries_without_sidecar > 0 {
        notes.push(format!(
            "{} entries had no sidecar row, so they carry no attributes and no timestamps",
            walked.entries_without_sidecar
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

    /// The independent item count, from the cleartext header.
    fn header_item_count(&self) -> usize {
        match &self.inventory {
            Inventory::Keyring(k) => k.item_count(),
            Inventory::Wallet(w) => w.entry_count(),
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
    let mut out: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == extension))
        .collect();
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
            let chosen = match std::fs::read_to_string(dir.join("default")) {
                Ok(text) => {
                    let name = parse_default_file(&text)
                        .map_err(|e| header_error(&dir.join("default"), &e))?;
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
                Err(_) => one_of(&candidates, dir, "keyring")?,
            };
            let bytes = read_source(&chosen)?;
            let inventory = parse_keyring_header(&bytes).map_err(|e| header_error(&chosen, &e))?;
            Ok(SourceFile {
                path: chosen,
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
#[derive(Serialize)]
struct ReportFile<'a> {
    #[serde(flatten)]
    report: &'a ImportReport,
    /// The tally after the lookup probe has had its say, which may differ
    /// from `report.tally` — the probe downgrades an item whose attributes
    /// arrived but which the daemon does not return.
    probed_tally: &'a Tally,
    verification: &'a Verification,
    /// Entries lost for a reason no `Refusal` variant names.
    not_migrated: &'a [NotMigrated],
    /// Anything the run must not be silent about.
    notes: &'a [String],
    /// `false` for `--dry-run`: the report describes what *would* happen.
    written: bool,
}

fn write_report(path: &Path, file: &ReportFile<'_>) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(file)
        .map_err(|e| CliError::Failed(format!("could not render the report: {e}")))?;
    // 0600: the report names labels and attribute keys, which is not secret
    // but is nobody else's business either.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| header_io(path, e))?;
        f.write_all(json.as_bytes())
            .map_err(|e| header_io(path, e))?;
        f.write_all(b"\n").map_err(|e| header_io(path, e))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, json).map_err(|e| header_io(path, e))?;
    Ok(())
}

// --------------------------------------------------------------------------
// The command
// --------------------------------------------------------------------------

pub async fn run(args: ImportArgs) -> Result<(), CliError> {
    let source: Source = args.from.into();
    let env = ImportEnv {
        config: load_config()?,
        source_dir: source_dir(source)?,
    };
    run_with(args, &LiveExtractor, &env).await
}

/// Where the command reads from and writes to.
///
/// A parameter rather than two calls into the environment, so the pipeline
/// can be driven against a fixture directory and a scratch vault directory
/// with no process-global state - which is what makes "a dry run writes
/// nothing" and "the pre-check refuses before any write" testable as
/// assertions about a directory rather than as a reading of the code.
pub struct ImportEnv {
    pub config: Config,
    /// The directory holding the source's files: `keyrings/` or `kwalletd/`.
    pub source_dir: PathBuf,
}

/// The whole pipeline, over any [`Extractor`]. Tests drive this with a fake
/// source so every rule below — the cap pre-check, the "new collection,
/// always" refusal, what a dry run does not write — is exercised without a
/// gnome-keyring or a kwalletd anywhere.
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

    // A new collection, always. Refused here, before a password is asked for
    // and before anything is extracted further, because the alternative is
    // merging into a live collection whose next daemon save writes straight
    // over the import.
    if !args.dry_run && vault_path.exists() {
        return Err(CliError::Failed(format!(
            "collection '{id}' already exists at {}. `sm import` never merges into an \
             existing collection - a write into one the daemon already holds is invisible \
             until it restarts and is then overwritten by its next save. Pass \
             --collection with a name that is not in use.",
            escape_control(&vault_path.display().to_string())
        )));
    }

    // ---------------------------------------------------------------
    // The pre-check, before a single byte is written
    // ---------------------------------------------------------------
    let mut report = ImportReport::new(source, &label);
    report.header_item_count = Some(file.header_item_count());
    report.empty_folders = extraction.empty_folders;

    let mut blocked: Vec<(String, Refusal)> = Vec::new();
    for imported in &extraction.items {
        if let Some(refusal) = imported.item.cap_violation() {
            blocked.push((imported.item.label.clone(), refusal));
        }
    }
    if !blocked.is_empty() {
        // Every one of them, not the first: a user fixing these needs the
        // whole list, and a migration that refuses at the start has cost
        // nothing.
        let mut message = format!(
            "{} of {} items exceed a limit the Secret Service API enforces, so nothing was \
             written:",
            blocked.len(),
            extraction.items.len()
        );
        for (item_label, refusal) in &blocked {
            message.push_str(&format!(
                "\n  {}: {}",
                escape_control(item_label),
                escape_control(&refusal.to_string())
            ));
        }
        return Err(CliError::Failed(message));
    }

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
        let password = read_new_password(&format!(
            "Choose a password for the new collection '{}'",
            escape_control(&label)
        ))?;
        let mut vault = Vault::create(&vault_path, &label, password.as_bytes(), config.kdf.into())?;
        vault.import_items(
            items
                .iter()
                .map(|i| ImportItem {
                    // Verbatim, every field. Nothing here normalises,
                    // synthesises or drops an attribute pair: that is the one
                    // thing an import may never do.
                    label: i.label.clone(),
                    attributes: i.attributes.clone(),
                    secret: i.secret.clone(),
                    content_type: i.content_type.clone(),
                    created: i.created,
                    modified: i.modified,
                })
                .collect(),
        )?;
        drop(vault);
        // Read the destination back off *disk*, decrypting it again, so the
        // fingerprints compare what was written rather than the list we
        // intended to write. An import that verified against its own
        // in-memory copy would prove nothing about the file.
        destination = Some(reopen(&vault_path, password.as_bytes(), &id)?);
        if args.set_default {
            set_default_alias(config, &id);
        }
        notify_daemon();
    }

    // ---------------------------------------------------------------
    // Verify
    // ---------------------------------------------------------------
    let probes = if args.dry_run {
        verify::probe_plan(&items)
            .iter()
            .map(ProbeResult::not_issued)
            .collect()
    } else {
        run_probes(&items).await
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

    print_report(
        source,
        &file,
        &label,
        &id,
        &report,
        &probed_tally,
        &verification,
        &extraction.skipped,
        &extraction.notes,
        args.dry_run,
    );

    if let Some(path) = &args.report {
        write_report(
            path,
            &ReportFile {
                report: &report,
                probed_tally: &probed_tally,
                verification: &verification,
                not_migrated: &extraction.skipped,
                notes: &extraction.notes,
                written: !args.dry_run,
            },
        )?;
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
async fn run_probes(items: &[SourceItem]) -> Vec<ProbeResult> {
    let plan = verify::probe_plan(items);
    if plan.is_empty() {
        return Vec::new();
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
    let mut out = Vec::with_capacity(plan.len());
    for query in &plan {
        match client.search(&query.attributes).await {
            // Both halves count: `SearchItems` returns unlocked and locked
            // matches separately, and a locked match is still findable - the
            // hashed attribute index is what makes search work on a locked
            // collection.
            Ok((unlocked, locked)) => {
                out.push(ProbeResult::new(query, unlocked.len() + locked.len()));
            }
            Err(_) => out.push(ProbeResult::not_issued(query)),
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
        count: verify::CountCheck::new(Some(file.header_item_count()), walked),
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

#[allow(clippy::too_many_arguments)]
fn print_report(
    source: Source,
    file: &SourceFile,
    label: &str,
    id: &str,
    report: &ImportReport,
    probed: &Tally,
    verification: &Verification,
    not_migrated: &[NotMigrated],
    notes: &[String],
    dry_run: bool,
) {
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
        probed.fully_portable
    );
    println!(
        "  attributes preserved, discoverability uncertain  {}",
        probed.attributes_preserved
    );
    println!(
        "  preserved only                                {}",
        probed.preserved_only
    );
    println!(
        "  refused                                       {}",
        probed.refused
    );

    let refused: Vec<&ItemReport> = report.items.iter().filter(|i| i.is_refused()).collect();
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

    let downgraded: Vec<&ItemReport> = report.items.iter().filter(|i| i.acl_downgrade).collect();
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

    let lost_types: Vec<&ItemReport> = report
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
    if report.empty_folders > 0 {
        println!(
            "\n{} source folders held no entries. A collection of items has nowhere to put \
             them, so they were not migrated.",
            report.empty_folders
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
        println!("Run the same command without --dry-run to write the collection.");
        return;
    }
    if verification.passed() {
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
