//! `sm import`: argument parsing, the inventory that needs nothing running,
//! and the two rules that are properties of a *directory* rather than of a
//! code path — the cap pre-check refuses before anything is written, and a
//! dry run writes nothing.
//!
//! The extraction transports (`src/import/gnome.rs`, `src/import/kwallet.rs`)
//! drive a foreign daemon and are tested against one. Everything downstream
//! of them is driven here through `cli::import::Extractor`, so the pipeline's
//! rules are asserted with no gnome-keyring and no kwalletd anywhere.

use secret_manager::cli::import::{
    Extraction, Extractor, ImportArgs, ImportEnv, Imported, NotMigrated, SourceArg,
};
use secret_manager::cli::{Cli, CliError, Command};
use secret_manager::config::Config;
use secret_manager::import::{ItemReport, Provenance, Refusal, Source, SourceItem};
use secret_manager::vault::format::MAX_ITEM_LABEL;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

/// The committed golden keyring, in a directory shaped like a real
/// `$XDG_DATA_HOME/keyrings`. It declares three items, one of them an unlock
/// credential, which is what the fake extraction below reproduces.
fn keyring_dir(root: &Path) -> PathBuf {
    let dir = root.join("keyrings");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import/sample.keyring"),
        dir.join("Sample keyring.keyring"),
    )
    .unwrap();
    dir
}

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn item(id: u32, label: &str, pairs: &[(&str, &str)], secret: &[u8]) -> SourceItem {
    SourceItem {
        label: label.to_string(),
        attributes: attrs(pairs),
        secret: Zeroizing::new(secret.to_vec()),
        content_type: "text/plain".into(),
        created: 1_699_383_593,
        modified: 1_699_387_319,
        provenance: Provenance::gnome("Sample keyring", id),
    }
}

/// Two importable items and the refused unlock credential — the golden
/// keyring's own three, so the independent count check has something true to
/// agree with.
fn sample_items() -> Vec<SourceItem> {
    vec![
        item(
            2,
            "GitHub token",
            &[
                ("xdg:schema", "org.freedesktop.Secret.Generic"),
                ("account", "joseph"),
            ],
            b"ghp_topsecretvalue",
        ),
        item(
            5,
            "router",
            &[("server", "router.example.com"), ("port", "443")],
            b"correct horse battery staple\n",
        ),
    ]
}

fn sample_refusal() -> ItemReport {
    ItemReport::refused(
        Provenance::gnome("Sample keyring", 9),
        "Unlock password for Other keyring",
        Refusal::ChainedKeyringItem { item_type: 3 },
    )
}

struct Fake {
    items: Vec<SourceItem>,
    refusals: Vec<ItemReport>,
    skipped: Vec<NotMigrated>,
}

impl Fake {
    fn sample() -> Self {
        Self {
            items: sample_items(),
            refusals: vec![sample_refusal()],
            skipped: Vec::new(),
        }
    }
}

impl Extractor for Fake {
    fn extract<'a>(
        &'a self,
        _source: Source,
        container: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Extraction, CliError>> + 'a>>
    {
        Box::pin(async move {
            Ok(Extraction {
                container: container.to_string(),
                items: self
                    .items
                    .iter()
                    .map(|item| Imported {
                        report: ItemReport::imported(item),
                        item: item.clone(),
                    })
                    .collect(),
                refusals: self.refusals.clone(),
                skipped: self.skipped.clone(),
                empty_folders: 0,
                notes: Vec::new(),
            })
        })
    }
}

fn env_for(root: &Path, vault_dir: &Path) -> ImportEnv {
    let mut config = Config::default();
    config.vault.dir = vault_dir.to_path_buf();
    ImportEnv {
        config,
        source_dir: keyring_dir(root),
    }
}

fn args(dry_run: bool) -> ImportArgs {
    ImportArgs {
        from: SourceArg::GnomeKeyring,
        inventory: false,
        dry_run,
        collection: None,
        set_default: false,
        report: None,
    }
}

/// Every file in a directory, or an empty list when it does not exist. The
/// "nothing was written" assertions are made against this rather than against
/// one expected filename, so a write under any other name still fails them.
fn files_in(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// --------------------------------------------------------------------------
// Argument parsing
// --------------------------------------------------------------------------

fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    use clap::Parser;
    let mut full = vec!["sm"];
    full.extend_from_slice(argv);
    Cli::try_parse_from(full)
}

#[test]
fn import_parses_the_documented_surface() {
    let cli = parse(&[
        "import",
        "--from",
        "kwallet",
        "--dry-run",
        "--collection",
        "Imported wallet",
        "--report",
        "/tmp/r.json",
    ])
    .unwrap();
    let Command::Import(args) = cli.command else {
        panic!("not an import command");
    };
    assert_eq!(args.from, SourceArg::KWallet);
    assert!(args.dry_run);
    assert!(!args.inventory);
    assert!(!args.set_default);
    assert_eq!(args.collection.as_deref(), Some("Imported wallet"));
    assert_eq!(args.report, Some(PathBuf::from("/tmp/r.json")));

    let cli = parse(&["import", "--from", "gnome-keyring", "--set-default"]).unwrap();
    let Command::Import(args) = cli.command else {
        panic!("not an import command");
    };
    assert_eq!(args.from, SourceArg::GnomeKeyring);
    assert!(args.set_default);
}

#[test]
fn import_requires_a_source_and_rejects_an_unknown_one() {
    assert!(parse(&["import"]).is_err());
    assert!(parse(&["import", "--from", "seahorse"]).is_err());
    // The spelling is the provider's own, not a shortened one.
    assert!(parse(&["import", "--from", "gnome"]).is_err());
}

/// `--inventory` reads headers and exits; combining it with a flag about
/// *writing* is a contradiction, not a preference, so it is a usage error
/// rather than a silently ignored argument.
#[test]
fn inventory_conflicts_with_every_flag_about_writing() {
    for other in [
        vec!["--dry-run"],
        vec!["--set-default"],
        vec!["--collection", "X"],
        vec!["--report", "/tmp/r.json"],
    ] {
        let mut argv = vec!["import", "--from", "kwallet", "--inventory"];
        argv.extend(other.iter().copied());
        assert!(parse(&argv).is_err(), "{argv:?} should conflict");
    }
    // And `--dry-run --set-default` is the same contradiction: a dry run has
    // no collection for the alias to point at.
    assert!(parse(&["import", "--from", "kwallet", "--dry-run", "--set-default"]).is_err());
}

// --------------------------------------------------------------------------
// --inventory, with nothing running
// --------------------------------------------------------------------------

/// No daemon, no bus, no password on stdin: the cleartext header is all it
/// reads.
#[test]
fn inventory_works_with_no_daemon_and_no_password() {
    let root = tempfile::tempdir().unwrap();
    keyring_dir(root.path());
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    let assert = cmd
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root.path())
        .env("XDG_DATA_HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_RUNTIME_DIR", root.path().join("run"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .args(["import", "--from", "gnome-keyring", "--inventory"])
        // Nothing on stdin: a password prompt would hang or fail, and the
        // point of this command is that it asks for neither.
        .write_stdin("")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("Sample keyring"), "{out}");
    assert!(out.contains("items                3"), "{out}");
    assert!(out.contains("xdg:schema"), "{out}");
    assert!(out.contains("unlock another keyring"), "{out}");
    assert!(out.contains("No password was asked for"), "{out}");
    // The inventory reads names, never values: the hashed attribute values in
    // the file are not printed, and neither is any ciphertext.
    assert!(!out.contains("d41d8cd9"), "{out}");
}

#[test]
fn inventory_names_the_directory_it_could_not_find() {
    let root = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root.path())
        .env("XDG_DATA_HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_RUNTIME_DIR", root.path().join("run"))
        .args(["import", "--from", "kwallet", "--inventory"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("kwalletd"));
}

// --------------------------------------------------------------------------
// The pre-check, and what a dry run does not do
// --------------------------------------------------------------------------

/// One oversized item stops the whole import, before the first byte. A
/// migration that fails halfway leaves the user worse off than one that
/// refuses at the start, so this asserts on the *directory*: no vault file,
/// under any name, exists afterwards.
#[tokio::test]
async fn the_cap_pre_check_refuses_before_anything_is_written() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());

    let mut fake = Fake::sample();
    fake.items[1].label = "x".repeat(MAX_ITEM_LABEL + 1);

    let err = secret_manager::cli::import::run_with(args(false), &fake, &env)
        .await
        .expect_err("an item over a cap must stop the import");
    let message = err.to_string();
    assert!(message.contains("nothing was written"), "{message}");
    assert!(message.contains("label is"), "{message}");
    assert_eq!(err.exit_code(), 1);
    assert!(
        files_in(vaults.path()).is_empty(),
        "the vault directory is not empty: {:?}",
        files_in(vaults.path())
    );
}

/// `--dry-run` runs the extraction and every pre-flight check and then
/// discards. Nothing is created, no alias moves, and the report it writes is
/// a real one.
#[tokio::test]
async fn a_dry_run_writes_no_vault_and_its_report_holds_no_secret() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    let report_path = root.path().join("import-report.json");

    let mut a = args(true);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("a dry run over a consistent source passes");

    assert!(
        files_in(vaults.path()).is_empty(),
        "a dry run wrote {:?}",
        files_in(vaults.path())
    );

    // The report is real output, generated by the run above, and it is what
    // a user may paste into a bug report.
    let json = std::fs::read_to_string(&report_path).unwrap();
    for leaked in [
        "ghp_topsecretvalue",
        "correct horse battery staple",
        "router.example.com",
        "joseph",
        "org.freedesktop.Secret.Generic",
    ] {
        assert!(!json.contains(leaked), "{leaked:?} leaked into the report");
    }
    // Keys, labels, counts and outcomes are all there - the report has to be
    // readable by the person it is for.
    for kept in [
        "xdg:schema",
        "account",
        "server",
        "port",
        "GitHub token",
        "fully-portable",
        "chained-keyring-item",
    ] {
        assert!(json.contains(kept), "{kept:?} missing from the report");
    }
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["written"], serde_json::json!(false));
    assert_eq!(parsed["tally"]["fully_portable"], serde_json::json!(1));
    assert_eq!(parsed["tally"]["refused"], serde_json::json!(1));
    // 3 in the header, 3 walked: two imported and one refused.
    assert_eq!(parsed["header_item_count"], serde_json::json!(3));
    assert_eq!(
        parsed["verification"]["count"]["walked"],
        serde_json::json!(3)
    );
    // No probe was issued, so discoverability is unproved rather than proved.
    assert_eq!(
        parsed["verification"]["probes"]["not_issued"],
        serde_json::json!(2)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&report_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the report is not the world's business"
        );
    }
}

/// The independent count is not decoration: a walk that produced fewer items
/// than the cleartext header declares is a failed import even when every
/// fingerprint it does have agrees.
#[tokio::test]
async fn a_walk_that_missed_an_item_fails_the_run() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    let fake = Fake {
        items: sample_items(),
        // The golden keyring declares three items; without the refusal only
        // two are accounted for.
        refusals: Vec::new(),
        skipped: Vec::new(),
    };
    let err = secret_manager::cli::import::run_with(args(true), &fake, &env)
        .await
        .expect_err("2 walked against 3 in the header is a failure");
    assert!(err.to_string().contains("verification"), "{err}");
}

/// A new collection, always. An id already in use is refused before a
/// password is asked for, because merging into a collection the daemon holds
/// is invisible until it restarts and is then overwritten by its next save.
#[tokio::test]
async fn import_never_merges_into_an_existing_collection() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    // `Sample keyring` is the golden file's display name and so the default
    // destination label.
    let existing = vaults.path().join("sample_keyring.vault");
    std::fs::write(&existing, b"not touched").unwrap();

    let err = secret_manager::cli::import::run_with(args(false), &Fake::sample(), &env)
        .await
        .expect_err("an existing collection must not be merged into");
    let message = err.to_string();
    assert!(message.contains("never merges"), "{message}");
    assert!(message.contains("--collection"), "{message}");
    assert_eq!(std::fs::read(&existing).unwrap(), b"not touched");
    assert_eq!(files_in(vaults.path()), ["sample_keyring.vault"]);
}
