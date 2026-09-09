//! `sm import`: argument parsing, the inventory that needs nothing running,
//! and the two rules that are properties of a *directory* rather than of a
//! code path — a dry run writes nothing, and an item no cap allows leaves no
//! half-written collection behind.
//!
//! The extraction transports (`src/import/gnome.rs`, `src/import/kwallet.rs`)
//! drive a foreign daemon and are tested against one. Everything downstream
//! of them is driven here through `cli::import::Extractor`, so the pipeline's
//! rules are asserted with no gnome-keyring and no kwalletd anywhere.

mod common;

use common::Fixture;
use secret_manager::cli::import::{
    DaemonTarget, Extraction, Extractor, ImportArgs, ImportEnv, Imported, NotMigrated, SourceArg,
};
use secret_manager::cli::{Cli, CliError, Command};
use secret_manager::config::Config;
use secret_manager::import::{Cap, ItemReport, Provenance, Refusal, Source, SourceItem};
use secret_manager::vault::format::{MAX_ITEM_LABEL, MAX_ITEM_SECRET};
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
            let mut extraction = Extraction::new(container);
            extraction.items = self
                .items
                .iter()
                .map(|item| Imported::new(item.clone(), ItemReport::imported(item)))
                .collect();
            extraction.refusals = self.refusals.clone();
            extraction.skipped = self.skipped.clone();
            Ok(extraction)
        })
    }
}

/// The password for every write-path test below. `ImportEnv::new` reads one
/// from the process's stdin, which an in-process test has none of; the
/// override is the seam that makes the successful write testable at all.
const PASSWORD: &str = "an import test password";

fn env_for(root: &Path, vault_dir: &Path) -> ImportEnv {
    let mut config = Config::default();
    config.vault.dir = vault_dir.to_path_buf();
    // Argon2 at the real cost three times over (create, reopen, and the test's
    // own open) is most of a second for nothing this test is about.
    config.kdf.m_cost_kib = 8;
    config.kdf.t_cost = 1;
    config.kdf.p_cost = 1;
    let mut env = ImportEnv::new(config, keyring_dir(root));
    env.new_password = Box::new(|_| Ok(Zeroizing::new(PASSWORD.to_string())));
    // Keep every run in this binary away from whatever is running on this
    // machine. After a write the command tells a running daemon to reload and
    // issues the lookup probe over the session bus; both would otherwise reach
    // the developer's own daemon, so the probe would search their real
    // collections and the reload would be a side effect of running the test
    // suite.
    //
    // This is the seam, not `std::env::set_var` on `DBUS_SESSION_BUS_ADDRESS`
    // and `XDG_RUNTIME_DIR`. That is `unsafe` in edition 2024 because it races
    // every other thread in the same binary, and `cargo test` runs these tests
    // in parallel with two that read the environment to build a child
    // process's.
    //
    // `None` is honest about what it means: there is no daemon, so the probes
    // come back *not issued* — unproved, and not a pass. The tests that have
    // to exercise the probe say so by naming one instead, with
    // `env_against(&fixture)` below.
    env.daemon = DaemonTarget::None;
    env
}

/// The same environment, pointed at the fixture's private bus and control
/// socket: a real daemon, on a bus nothing else can see.
///
/// This is what the probe path never had. `reach_the_daemon = false` in every
/// call site meant the suite asserted the check had *not* been made — two
/// tests pinned `not_issued == 2` — while the code that issues it went
/// unexecuted, which is how it came to search the wrong daemon and to expect
/// the wrong number.
fn env_against(fixture: &Fixture, root: &Path) -> ImportEnv {
    let mut config = Config::default();
    config.vault.dir = fixture.data_dir.path().join("secret-manager");
    config.vault.locked_search = true;
    config.kdf.m_cost_kib = 8;
    config.kdf.t_cost = 1;
    config.kdf.p_cost = 1;
    let mut env = ImportEnv::new(config, keyring_dir(root));
    env.new_password = Box::new(|_| Ok(Zeroizing::new(PASSWORD.to_string())));
    env.daemon = DaemonTarget::At {
        bus_address: fixture.bus.address.clone(),
        control_socket: fixture.control_socket(),
    };
    env
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

/// The policy `import::check_caps` states: a cap violation refuses **one
/// item**, never the run.
///
/// Both extractors measure the caps during the walk and put a violating item
/// in `refusals`, so this is the shape the command actually sees. The import
/// goes ahead with everything else, and the only place the user learns the
/// item was too large is the report — so the report is what this asserts, by
/// name and by count.
#[tokio::test]
async fn a_cap_violation_refuses_one_item_and_not_the_run() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());

    let fake = Fake {
        items: sample_items(),
        // The golden keyring declares three items; this is the third, and the
        // extractor has already declined it.
        refusals: vec![ItemReport::refused(
            Provenance::gnome("Sample keyring", 9),
            "An enormous note",
            Refusal::CapViolation {
                cap: Cap::Secret,
                actual: MAX_ITEM_SECRET + 1,
                limit: MAX_ITEM_SECRET,
            },
        )],
        skipped: Vec::new(),
    };

    let report_path = root.path().join("cap.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect("one oversized item must not refuse the whole import");

    // The other two were written.
    assert!(files_in(vaults.path()).contains(&"sample_keyring.vault".to_string()));
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(parsed["tally"]["fully_portable"], serde_json::json!(1));
    assert_eq!(parsed["tally"]["refused"], serde_json::json!(1));
    // Counted *and* named, with the limit it exceeded: a number alone does not
    // tell the user which item to shorten.
    let refused = parsed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == serde_json::json!("An enormous note"))
        .expect("the refused item is not in the report");
    let refusal = &refused["refusals"][0];
    assert_eq!(refusal["reason"], serde_json::json!("cap-violation"));
    assert_eq!(refusal["limit"], serde_json::json!(MAX_ITEM_SECRET));
}

/// The command does not second-guess the extractor, and does not have to: if
/// a violating item ever did reach the write, the vault layer re-applies every
/// cap to the whole batch and refuses it atomically.
///
/// So the assertion is about the *directory* — a half-populated collection is
/// the outcome the caps exist to prevent, and it is worse than a refusal — and
/// about the exit code, which is 1 and not the 2 the deleted pre-check
/// returned: nothing here is a different invocation away from working.
#[tokio::test]
async fn an_item_over_a_cap_leaves_no_half_written_collection() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());

    let mut fake = Fake::sample();
    fake.items[1].label = "x".repeat(MAX_ITEM_LABEL + 1);

    let err = secret_manager::cli::import::run_with(args(false), &fake, &env)
        .await
        .expect_err("an item over a cap cannot be written");
    let message = err.to_string();
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
    let report_path = root.path().join("count.json");
    let mut a = args(true);
    a.report = Some(report_path.clone());
    let err = secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect_err("2 walked against 3 in the header is a failure");
    assert!(err.to_string().contains("verification"), "{err}");
    // Not just "a verification failed": the count check is the one that has to
    // fail, and with these numbers. Asserting on the word alone passes for a
    // fingerprint mismatch, a probe or a histogram difference just as well.
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        parsed["verification"]["count"],
        serde_json::json!({ "header_item_count": 3, "walked": 2 })
    );
}

/// The walk and the independent count have one scope, and it is the keyring
/// `default` names.
///
/// `ExtractOptions::only_container` restricts the walk to that one keyring, so
/// the header total is that one file's. Summing every `.keyring` in the
/// directory against a walk of one is a guaranteed mismatch — 6 declared, 3
/// walked — for the ordinary login-plus-one setup, raised after the collection
/// has already been written.
#[tokio::test]
async fn the_independent_count_is_scoped_to_the_keyring_that_is_walked() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    // A second keyring beside the first, and a `default` naming which of them
    // the destination is labelled after. The walk never enters it.
    std::fs::copy(
        env.source_dir.join("Sample keyring.keyring"),
        env.source_dir.join("Other keyring.keyring"),
    )
    .unwrap();
    std::fs::write(env.source_dir.join("default"), "Sample keyring\n").unwrap();

    let report_path = root.path().join("two-keyrings.json");
    let mut a = args(true);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("3 walked against the walked keyring's own 3 is not a shortfall");
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        parsed["verification"]["count"],
        serde_json::json!({ "header_item_count": 3, "walked": 3 })
    );
    // And the destination is still labelled after the keyring `default` names.
    assert_eq!(parsed["collection"], serde_json::json!("Sample keyring"));
}

// --------------------------------------------------------------------------
// The write path
// --------------------------------------------------------------------------

/// The successful write, end to end: the collection is created, reopened off
/// disk, and every item is there with its bytes intact. Everything this
/// asserts was unverified while the password could only come from process
/// stdin.
#[tokio::test]
async fn a_real_import_writes_a_collection_that_reopens_and_verifies() {
    use secret_manager::vault::Vault;
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    let source_path = env.source_dir.join("Sample keyring.keyring");
    let source_before = std::fs::read(&source_path).unwrap();

    // The report already exists, world-readable. `OpenOptions::mode` applies
    // only on creation, so this is the case where the "0600" comment was a
    // claim and not a fact.
    let report_path = root.path().join("import-report.json");
    std::fs::write(&report_path, b"{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&report_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let mut a = args(false);
    a.report = Some(report_path.clone());
    a.set_default = true;
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("a consistent source writes and verifies");

    // The collection is on disk under the id derived from the source's own
    // display name, and the `default` alias points at it.
    let vault_path = vaults.path().join("sample_keyring.vault");
    assert!(files_in(vaults.path()).contains(&"sample_keyring.vault".to_string()));
    let aliases = std::fs::read_to_string(vaults.path().join("aliases.toml")).unwrap();
    assert!(aliases.contains("sample_keyring"), "{aliases}");

    // Reopened from the file, with the password the seam supplied: every item
    // is there, verbatim, and in walk order.
    let mut vault = Vault::open(&vault_path).unwrap();
    vault.unlock(PASSWORD.as_bytes()).unwrap();
    let written = vault.items().unwrap();
    assert_eq!(written.len(), 2);
    for (source, dest) in sample_items().iter().zip(written) {
        assert_eq!(dest.label, source.label);
        assert_eq!(dest.attributes, source.attributes);
        assert_eq!(dest.secret.as_slice(), source.secret.as_slice());
        assert_eq!(dest.content_type, source.content_type);
    }

    let json = std::fs::read_to_string(&report_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["written"], serde_json::json!(true));
    // The run's own fingerprint check ran against the decrypted file and found
    // both items, with nothing on either side unaccounted for.
    assert_eq!(
        parsed["verification"]["fingerprints_compared"],
        serde_json::json!(2)
    );
    assert!(parsed["verification"]["fingerprint_mismatches"].is_null());
    assert_eq!(
        parsed["verification"]["count"],
        serde_json::json!({ "header_item_count": 3, "walked": 3 })
    );
    // No daemon to probe, so discoverability is unproved rather than proved -
    // and unproved is not a failure.
    assert_eq!(
        parsed["verification"]["probes"]["not_issued"],
        serde_json::json!(2)
    );
    for leaked in [
        "ghp_topsecretvalue",
        "correct horse battery staple",
        "joseph",
    ] {
        assert!(!json.contains(leaked), "{leaked:?} leaked into the report");
    }

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
            "an existing report was rewritten with its old permissions"
        );
    }

    // Nothing was touched at the source, and a second run refuses against the
    // file the first one wrote rather than merging into it.
    assert_eq!(std::fs::read(&source_path).unwrap(), source_before);
    let err = secret_manager::cli::import::run_with(args(false), &Fake::sample(), &env)
        .await
        .expect_err("the collection this run wrote is still a collection that exists");
    assert!(err.to_string().contains("never merges"), "{err}");
    assert_eq!(err.exit_code(), 2);
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
    // The remedy is a different invocation, which is exit 2 and not the exit 1
    // that means the command tried and something broke.
    assert_eq!(err.exit_code(), 2);
    assert_eq!(std::fs::read(&existing).unwrap(), b"not touched");
    assert_eq!(files_in(vaults.path()), ["sample_keyring.vault"]);

    // A dry run makes the same check - it is the run whose whole purpose is to
    // say whether the real one would work - and warns instead of refusing, so
    // it still reports on the extraction it just did.
    secret_manager::cli::import::run_with(args(true), &Fake::sample(), &env)
        .await
        .expect("a dry run reports rather than refuses");
    assert_eq!(std::fs::read(&existing).unwrap(), b"not touched");
    assert_eq!(files_in(vaults.path()), ["sample_keyring.vault"]);
}

// --------------------------------------------------------------------------
// The lookup probe, against a daemon that answers
// --------------------------------------------------------------------------

/// The check this module calls "the one that matters", exercised for the first
/// time.
///
/// Every call site of the old `reach_the_daemon` seam set it to `false`, and
/// two tests positively asserted `not_issued == 2` — so the suite pinned that
/// the probe had *not* run, and the code that issues it went unexecuted. What
/// shipped behind that: the probe queried whoever owned `org.freedesktop.secrets`
/// on the session bus, which the command had just required to be
/// gnome-keyring — the source — so for a keyring named `login` it counted
/// *source* items through a matching object-path prefix and reported PASS.
///
/// Here it runs against a real `secret-manager` on the fixture's private bus,
/// and every probe has to come back found.
// A real daemon on the fixture's bus answers on other threads; the control
// socket call the import makes is blocking, so this needs more than one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_lookup_probe_runs_against_our_own_daemon_and_finds_every_item() {
    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let env = env_against(&fixture, root.path());

    let report_path = root.path().join("probe.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("a faithful import must pass its own lookup probe");

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        parsed["verification"]["probes"],
        serde_json::json!({ "passed": 2, "failed": 0, "not_issued": 0 }),
        "the probe did not run against the daemon: {parsed}"
    );
    // Nothing is left unproved, so the run is entitled to recommend
    // decommissioning the old provider.
    assert!(
        parsed["verification"]["failed_probes"]
            .as_array()
            .is_none_or(|a| a.is_empty())
    );
}

/// `SearchItems` is **subset** matching, so a probe for `{server, user}`
/// returns the item that also carries an `xdg:schema`.
///
/// The plan counted items whose attribute map was *equal* to the query, so on
/// the ordinary source that holds both an item and a more-specific sibling the
/// smaller probe expected 1 and found 2 — and a byte-perfect import failed
/// verification, with every item sharing that key set downgraded on the way
/// out.
// A real daemon on the fixture's bus answers on other threads; the control
// socket call the import makes is blocking, so this needs more than one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_probe_expects_what_subset_matching_actually_returns() {
    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let env = env_against(&fixture, root.path());

    let fake = Fake {
        items: vec![
            item(
                2,
                "router",
                &[("server", "r.example"), ("user", "joseph")],
                b"a",
            ),
            // The same two attributes, plus the schema every libsecret client
            // writes. A probe for the pair returns both of these.
            item(
                5,
                "router, from libsecret",
                &[
                    ("server", "r.example"),
                    ("user", "joseph"),
                    ("xdg:schema", "org.freedesktop.Secret.Generic"),
                ],
                b"b",
            ),
        ],
        refusals: vec![sample_refusal()],
        skipped: Vec::new(),
    };

    let report_path = root.path().join("subset.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect("an item and its more-specific sibling are both a faithful import");

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        parsed["verification"]["probes"],
        serde_json::json!({ "passed": 2, "failed": 0, "not_issued": 0 }),
        "{parsed}"
    );
    // And nothing was downgraded: the probe changed no item's classification.
    assert_eq!(parsed["tally"], parsed["tally_before_probe"], "{parsed}");
}

/// A failed verification publishes **nothing**.
///
/// `set_default_alias` and the daemon `Reload` used to run unconditionally,
/// fifty-one lines before the gate, so a run that ended "verification did not
/// pass" left `default` pointing at the new collection, the daemon holding it,
/// and the file on disk — which then made the retry fail on the "already
/// exists" refusal, naming a file that same run had created.
// A real daemon on the fixture's bus answers on other threads; the control
// socket call the import makes is blocking, so this needs more than one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_verification_moves_no_alias_and_leaves_no_collection() {
    use secret_manager::protocol::{Request, Response, call};

    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let env = env_against(&fixture, root.path());
    let vault_dir = fixture.data_dir.path().join("secret-manager");

    // Two items walked against the golden keyring's declared three: the count
    // check fails, after a perfectly good write.
    let fake = Fake {
        items: sample_items(),
        refusals: Vec::new(),
        skipped: Vec::new(),
    };
    let mut a = args(false);
    a.set_default = true;
    let err = secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect_err("2 walked against 3 in the header is a failure");
    let message = err.to_string();
    assert!(message.contains("Nothing was published"), "{message}");

    // The collection this run created is gone, so the next attempt is not
    // refused against it.
    assert!(
        !vault_dir.join("sample_keyring.vault").exists(),
        "the collection outlived the failure: {:?}",
        files_in(&vault_dir)
    );
    // `default` still points where it did.
    let aliases = std::fs::read_to_string(vault_dir.join("aliases.toml")).unwrap();
    assert!(
        !aliases.contains("sample_keyring"),
        "the alias moved anyway: {aliases}"
    );
    // And the daemon was never told to load it.
    let socket = fixture.control_socket();
    let status = tokio::task::spawn_blocking(move || call(&socket, &Request::Status))
        .await
        .unwrap();
    let Ok(Response::Status { collections, .. }) = status else {
        panic!("the fixture daemon did not answer Status: {status:?}");
    };
    assert!(
        !collections.iter().any(|c| c.id == "sample_keyring"),
        "the daemon was told to load a collection that failed verification"
    );

    // The remedy actually works: the same command again, over a source that
    // adds up, is not refused by a leftover.
    secret_manager::cli::import::run_with(args(false), &Fake::sample(), &env)
        .await
        .expect("the retry must not be blocked by the failed run's own file");
}
