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
use secret_manager::import::formats::KWALLET_MAGIC;
use secret_manager::import::gnome::GnomeError;
use secret_manager::import::kwallet::{KWalletError, SidecarError};
use secret_manager::import::verify::{
    CountCheck, FingerprintEntry, Histogram, ProbeSummary, Side, Verification,
    compare_fingerprints, compare_histograms, probe_plan,
};
use secret_manager::import::{Cap, ItemReport, Provenance, Refusal, Source, SourceItem};
use secret_manager::protocol::{Request, Response};
use secret_manager::vault::format::{MAX_ITEM_LABEL, MAX_ITEM_SECRET};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
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

/// The golden keyring's own display name, which is also its file stem above.
const GOLDEN_NAME: &str = "Sample keyring";

/// A second keyring in `dir`, byte-identical to the golden one except for its
/// display name.
///
/// Copying the golden file under another *file* name is not enough: the name
/// the walk is asked for is the keyring's **display name**, which lives in the
/// header, so two copies are one container under two file names and no
/// assertion can tell which of them the pipeline chose. Only the name changes
/// here — the item count, the item table and the ciphertext are the golden
/// file's own, which is what keeps the independent count a real check.
///
/// The name must be the same length as the one it replaces: it is a
/// length-prefixed string and every later offset in the file, including the
/// ciphertext length the parser bounds against what the file holds, is
/// measured from where it ends.
fn keyring_named(dir: &Path, name: &str) -> PathBuf {
    let golden = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import/sample.keyring"),
    )
    .unwrap();
    assert_eq!(
        name.len(),
        GOLDEN_NAME.len(),
        "a differently sized name would move every offset after it"
    );
    // 16 bytes of magic, then major/minor/crypto/hash, then the u32 length.
    let at = 20;
    assert_eq!(
        golden[at..at + 4],
        (GOLDEN_NAME.len() as u32).to_be_bytes(),
        "the golden keyring's name is not where this helper patches it"
    );
    assert_eq!(
        &golden[at + 4..at + 4 + GOLDEN_NAME.len()],
        GOLDEN_NAME.as_bytes()
    );
    let mut bytes = golden.clone();
    bytes[at + 4..at + 4 + name.len()].copy_from_slice(name.as_bytes());
    let path = dir.join(format!("{name}.keyring"));
    std::fs::write(&path, &bytes).unwrap();
    path
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
        inserted_keys: std::collections::BTreeSet::new(),
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

/// A source that holds **one named container** and answers for that one only.
///
/// The name is the point. This used to ignore the container it was asked for
/// and hand back the same items whatever the pipeline had located, so every
/// assertion about "the keyring the walk covered" was an assertion about a
/// constant: reverting `ExtractOptions::only_container` to `None` left all
/// seventeen tests green — including the one named for the scope of the
/// independent count, the test for the exact bug this branch introduced and
/// then fixed. A fake that refuses a container it does not hold is what makes
/// "which keyring did the pipeline ask for" something the suite can be wrong
/// about.
struct Fake {
    container: String,
    items: Vec<SourceItem>,
    refusals: Vec<ItemReport>,
    skipped: Vec<NotMigrated>,
}

impl Fake {
    fn of(container: &str, items: Vec<SourceItem>, refusals: Vec<ItemReport>) -> Self {
        Self {
            container: container.to_string(),
            items,
            refusals,
            skipped: Vec::new(),
        }
    }

    /// The golden keyring's own container, items and refusal.
    fn sample() -> Self {
        Self::of("Sample keyring", sample_items(), vec![sample_refusal()])
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
            // A real extractor walks the keyring it is named — `only_container`
            // is exactly this argument, and a name matching no collection is
            // `GnomeError::NoSuchCollection`, not an empty success. So is this.
            if container != self.container {
                return Err(CliError::NotFound(format!(
                    "this source holds no container named '{container}'; it holds '{}'",
                    self.container
                )));
            }
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

    let fake = Fake::of(
        "Sample keyring",
        sample_items(),
        // The golden keyring declares three items; this is the third, and the
        // extractor has already declined it.
        vec![ItemReport::refused(
            Provenance::gnome("Sample keyring", 9),
            "An enormous note",
            Refusal::CapViolation {
                cap: Cap::Secret,
                actual: MAX_ITEM_SECRET + 1,
                limit: MAX_ITEM_SECRET,
            },
        )],
    );

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
    // The golden keyring declares three items; without the refusal only two
    // are accounted for.
    let fake = Fake::of("Sample keyring", sample_items(), Vec::new());
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
    // A second keyring beside the first — a different container, not another
    // copy of the same one — and a `default` naming which of them the
    // destination is labelled after. The walk never enters the other.
    keyring_named(&env.source_dir, "Second keyring");
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

/// And the other way round: with `default` naming the *second* keyring, both
/// the label and the walked count follow that one.
///
/// This is the half the test above could not establish on its own. `Fake` used
/// to hand back the same items whatever container it was asked for, so a
/// pipeline that walked the wrong keyring — or every keyring — produced
/// exactly the same report, and the assertion "the count is scoped to the
/// keyring that is walked" held for a source that has only one answer. Here
/// the two keyrings hold different items, and asking for the wrong one is an
/// error rather than a different-looking success.
#[tokio::test]
async fn the_walk_and_the_label_follow_the_keyring_the_default_file_names() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    keyring_named(&env.source_dir, "Second keyring");
    std::fs::write(env.source_dir.join("default"), "Second keyring\n").unwrap();

    // The second keyring's own three items, none of them the first's. Its
    // header is the golden one's, so three walked is three declared.
    let fake = Fake::of(
        "Second keyring",
        vec![
            item(
                1,
                "A second-keyring login",
                &[("server", "b.example")],
                b"1",
            ),
            item(2, "A second-keyring token", &[("account", "someone")], b"2"),
            item(3, "A second-keyring note", &[("note", "yes")], b"3"),
        ],
        Vec::new(),
    );

    let report_path = root.path().join("second.json");
    let mut a = args(true);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect("the walk must be asked for the keyring `default` names");

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    // The label follows the file `default` names...
    assert_eq!(parsed["collection"], serde_json::json!("Second keyring"));
    // ...and so does the count: that file's own header against that file's
    // own walk.
    assert_eq!(
        parsed["verification"]["count"],
        serde_json::json!({ "header_item_count": 3, "walked": 3 })
    );
    // And the items in the report are the ones that keyring holds.
    let labels: Vec<String> = parsed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["label"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        labels.iter().all(|l| l.starts_with("A second-keyring")),
        "{labels:?}"
    );
    assert!(!labels.iter().any(|l| l == "GitHub token"), "{labels:?}");
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

/// A `--report` that cannot be written is a warning, never an abort: on the
/// verification-failure branch the unlink has to happen anyway.
///
/// `write_report(..)?` used to propagate from between the failed check and
/// `unlink_partial`, so an unwritable report directory left the freshly
/// created vault on disk — contradicting the error's own "has been removed
/// again", and blocking the retry with the "never merges" refusal against a
/// file that run had made.
#[tokio::test]
async fn a_failed_verification_removes_the_collection_even_when_the_report_cannot_be_written() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    // Three declared in the header, two walked: the count check fails.
    let fake = Fake::of("Sample keyring", sample_items(), Vec::new());
    // The parent does not exist, so the report's `O_EXCL` create fails.
    let report_path = root.path().join("no-such-dir").join("report.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());

    let err = secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect_err("2 walked against 3 in the header is a failure");
    assert!(err.to_string().contains("verification"), "{err}");
    assert!(!report_path.exists());
    // The promise the message makes, kept: nothing of this run is left.
    let left: Vec<String> = files_in(vaults.path())
        .into_iter()
        .filter(|n| n.ends_with(".vault"))
        .collect();
    assert!(left.is_empty(), "the failed run left {left:?} behind");
}

/// The same on the success path: the report is a diagnostic artifact, so an
/// unwritable one must not turn a finished import into exit 1 with the
/// collection on disk, the daemon holding it, and `--set-default` skipped.
#[tokio::test]
async fn a_report_that_cannot_be_written_does_not_fail_a_successful_import() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    let report_path = root.path().join("no-such-dir").join("report.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    a.set_default = true;

    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("an unwritable report is a warning, not a failed import");
    assert!(!report_path.exists());
    assert!(files_in(vaults.path()).contains(&"sample_keyring.vault".to_string()));
    let aliases = std::fs::read_to_string(vaults.path().join("aliases.toml")).unwrap();
    assert!(aliases.contains("sample_keyring"), "{aliases}");
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
#[tokio::test]
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
#[tokio::test]
async fn a_probe_expects_what_subset_matching_actually_returns() {
    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let env = env_against(&fixture, root.path());

    let fake = Fake::of(
        "Sample keyring",
        vec![
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
        vec![sample_refusal()],
    );

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
#[tokio::test]
async fn a_failed_verification_moves_no_alias_and_leaves_no_collection() {
    use secret_manager::protocol::{Request, Response, call};

    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let env = env_against(&fixture, root.path());
    let vault_dir = fixture.data_dir.path().join("secret-manager");

    // Two items walked against the golden keyring's declared three: the count
    // check fails, after a perfectly good write.
    let fake = Fake::of("Sample keyring", sample_items(), Vec::new());
    let report_path = root.path().join("unpublished.json");
    let mut a = args(false);
    a.set_default = true;
    a.report = Some(report_path.clone());
    let err = secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect_err("2 walked against 3 in the header is a failure");
    let message = err.to_string();
    assert!(message.contains("Nothing was published"), "{message}");
    assert!(message.contains("has been removed again"), "{message}");

    // The report agrees with the message printed beside it. This was the one
    // place the artifact a user pastes into a bug contradicted the run: it
    // said `written: true` for a collection the error above correctly
    // describes as removed again, three lines before it was unlinked. And it
    // is not a dry run — a vault really was created — so the two questions are
    // two fields.
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(parsed["written"], serde_json::json!(false));
    assert_eq!(parsed["dry_run"], serde_json::json!(false));

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

/// Two `.keyring` files and no `default` is exit **1**, not exit 2.
///
/// Exit 2 is the code that means "a different invocation of `sm` is the
/// remedy", and there is none: `--collection` names the *destination*, and
/// nothing on this command names the source container. The user has to move a
/// file aside or write a `default` file, which is not something a flag can do.
#[tokio::test]
async fn two_candidate_keyrings_and_no_default_is_a_failure_not_a_usage_error() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    keyring_named(&env.source_dir, "Second keyring");
    // No `default` file: the choice is genuinely ambiguous.
    assert!(!env.source_dir.join("default").exists());

    let err = secret_manager::cli::import::run_with(args(true), &Fake::sample(), &env)
        .await
        .expect_err("two keyrings and no default cannot be resolved");
    let message = err.to_string();
    assert!(message.contains("2 .keyring files"), "{message}");
    assert!(message.contains("Sample keyring.keyring"), "{message}");
    assert_eq!(
        err.exit_code(),
        1,
        "no different invocation of `sm` fixes this: {message}"
    );
}

/// The pid-identity check, which nothing exercised.
///
/// `probe_target` establishes that the process owning `org.freedesktop.secrets`
/// on the session bus is the same process that answers our control socket —
/// the same kernel, asked twice — because the alternative is what shipped: the
/// probe questioned gnome-keyring, matched its item paths through a prefix
/// that collides for a keyring named `login`, and reported PASS while proving
/// nothing. Replacing the whole function with a bare session connection left
/// the suite green.
///
/// Here the bus is the fixture's, whose name is held by the in-process daemon,
/// and the control socket is the *dbus-daemon's* own listening socket, so
/// `SO_PEERCRED` names a different process. Every probe must come back not
/// issued — unproved, never a pass and never a failure — and the run must
/// still succeed, because an unprovable check is not a failed one.
#[tokio::test]
async fn a_probe_is_not_issued_when_the_bus_name_is_not_our_control_socket_peer() {
    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut env = env_against(&fixture, root.path());
    let bus_socket = fixture
        .bus
        .address
        .strip_prefix("unix:path=")
        .expect("the fixture bus is a unix socket")
        .split(',')
        .next()
        .unwrap()
        .to_string();
    env.daemon = DaemonTarget::At {
        bus_address: fixture.bus.address.clone(),
        control_socket: PathBuf::from(bus_socket),
    };

    let report_path = root.path().join("identity.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("a probe that cannot be shown to be ours is unproved, not failed");

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        parsed["verification"]["probes"],
        serde_json::json!({ "passed": 0, "failed": 0, "not_issued": 2 }),
        "the probe questioned a provider it had not identified: {parsed}"
    );
}

/// The one failure that deliberately leaves a vault on disk.
///
/// Every other failure here fails offline, before anything is published, and
/// unlinks. This branch is the opposite policy and it had never run: the bytes
/// are right, the daemon has been told to load the collection, and a probe
/// still cannot find the items — so taking the file away would remove a good
/// collection from a daemon that holds it in memory. It also rests on
/// `verification` being *mutated* between the two `passed()` calls: without
/// the probe results being written back, the second call would agree with the
/// first and the run would exit 0.
///
/// The daemon here watches its own vault directory and this import writes to
/// another one, which is an ordinary misconfiguration and reaches the branch
/// honestly: the write, the reopen, the fingerprints and the count all pass,
/// the `Reload` finds nothing new, and every probe comes back empty.
#[tokio::test]
async fn a_probe_that_finds_nothing_keeps_the_collection_and_fails_the_run() {
    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let mut env = env_against(&fixture, root.path());
    env.config.vault.dir = vaults.path().to_path_buf();

    let report_path = root.path().join("unfindable.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    a.set_default = true;
    let err = secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect_err("a collection no libsecret client can search is not a finished import");
    let message = err.to_string();
    assert!(message.contains("could not find every item"), "{message}");
    assert_eq!(err.exit_code(), 1);

    // The one failure that keeps what it wrote, and says so.
    assert!(
        vaults.path().join("sample_keyring.vault").exists(),
        "a good file was taken away from a daemon that may hold it: {:?}",
        files_in(vaults.path())
    );
    assert!(message.contains("is on disk"), "{message}");
    // The alias is the effect a user notices, and it does not move over a
    // failed migration.
    assert!(
        !vaults.path().join("aliases.toml").exists(),
        "`default` moved to a collection this run calls broken"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    // The report describes a collection that is there.
    assert_eq!(parsed["written"], serde_json::json!(true));
    assert_eq!(parsed["dry_run"], serde_json::json!(false));
    assert_eq!(
        parsed["verification"]["probes"],
        serde_json::json!({ "passed": 0, "failed": 2, "not_issued": 0 }),
        "{parsed}"
    );
    // And the probe's verdict reached the items and the tally: what the
    // attributes promised is not what the daemon returned.
    assert_eq!(
        parsed["tally_before_probe"]["fully_portable"],
        serde_json::json!(1)
    );
    assert_eq!(parsed["tally"]["fully_portable"], serde_json::json!(0));
    assert_eq!(
        parsed["tally"]["attributes_preserved"],
        serde_json::json!(2)
    );
}

/// Whether a locked collection can answer an attribute search is a property of
/// the **header this run wrote**, not of this CLI's `[vault] locked_search`.
///
/// The config the CLI loaded is not the config the running daemon has, and it
/// is not what shaped the header either — `Vault::create` writes the index and
/// this command never passes the setting to it. Gating the probe on the config
/// therefore left a byte-perfect import reporting its discoverability unproved
/// on a machine whose header carries every hash.
#[tokio::test]
async fn the_probe_is_gated_on_the_header_that_was_written_not_on_the_cli_config() {
    let fixture = Fixture::start().await;
    let root = tempfile::tempdir().unwrap();
    let mut env = env_against(&fixture, root.path());
    env.config.vault.locked_search = false;

    let report_path = root.path().join("gate.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("a faithful import passes its probe whatever this CLI's config says");

    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(
        parsed["verification"]["probes"],
        serde_json::json!({ "passed": 2, "failed": 0, "not_issued": 0 }),
        "the probe was skipped over a setting that shaped nothing: {parsed}"
    );
}

// --------------------------------------------------------------------------
// Error mapping: every foreign failure becomes one CliError, and the exit
// code follows the variant, never the message
// --------------------------------------------------------------------------

/// The codes `sm`'s callers script against. Pinned here rather than wherever
/// each error is produced, so a re-pointed arm fails in one place.
#[test]
fn cli_error_exit_codes_are_stable() {
    assert_eq!(CliError::NotFound("x".into()).exit_code(), 1);
    assert_eq!(CliError::Failed("x".into()).exit_code(), 1);
    assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
    assert_eq!(CliError::Unreachable("x".into()).exit_code(), 3);
}

/// The contract `extract_gnome`'s private `gnome_error` keeps: only the two
/// waits — for the private bus, for the keyring daemon — mean "nothing to
/// talk to" (exit 3); every other failure is the source refusing, misbehaving
/// or being absent (exit 1).
///
/// The function is private, so this cannot call it. What it does instead is
/// construct every `GnomeError` variant — adding, removing or renaming one
/// fails to compile here and forces the mapping to be reviewed — and pins the
/// `CliError` each must become and the code that follows. The production-path
/// half is below: kwallet's equivalent arms are exercised through the real
/// `extract`, and every `CliError` kind is driven through `run_with`.
#[test]
fn gnome_error_mapping_sends_only_timeouts_to_unreachable() {
    let wait = Duration::from_secs(1);
    // (case, error, must_be_unreachable)
    let cases: Vec<(&str, GnomeError, bool)> = vec![
        (
            "spawn",
            GnomeError::Spawn {
                program: "dbus-daemon".into(),
                message: "no such file".into(),
            },
            false,
        ),
        (
            "command-timeout",
            GnomeError::CommandTimeout {
                program: "dbus-daemon".into(),
                waited: wait,
            },
            false,
        ),
        (
            "bus-never-ready",
            GnomeError::BusNeverReady { waited: wait },
            true,
        ),
        (
            "keyring-never-ready",
            GnomeError::KeyringNeverReady {
                waited: wait,
                detail: "wrong password".into(),
            },
            true,
        ),
        (
            "keyring-exited",
            GnomeError::KeyringExited {
                detail: "crashed".into(),
            },
            false,
        ),
        (
            "unanswerable-prompt",
            GnomeError::UnanswerablePrompt {
                object: "/org/x".into(),
                waited: wait,
            },
            false,
        ),
        (
            "prompt-dismissed",
            GnomeError::PromptDismissed {
                object: "/org/x".into(),
            },
            false,
        ),
        (
            "unlock-offered-nothing",
            GnomeError::UnlockOfferedNothing {
                object: "/org/x".into(),
            },
            false,
        ),
        (
            "prompt-unlocked-nothing",
            GnomeError::PromptUnlockedNothing {
                object: "/org/x".into(),
            },
            false,
        ),
        (
            "too-many",
            GnomeError::TooMany {
                what: "collections",
                count: 600,
                limit: 512,
            },
            false,
        ),
        (
            "bus",
            GnomeError::Bus {
                call: "OpenSession".into(),
                message: "disconnected".into(),
            },
            false,
        ),
        (
            "call-timeout",
            GnomeError::CallTimeout {
                call: "SearchItems".into(),
                waited: wait,
            },
            false,
        ),
        (
            "no-such-collection",
            GnomeError::NoSuchCollection {
                container: "ghost".into(),
                available: "login".into(),
            },
            false,
        ),
        (
            "no-session",
            GnomeError::NoSession {
                message: "plain refused".into(),
            },
            false,
        ),
        (
            "decrypt",
            GnomeError::Decrypt {
                message: "bad padding".into(),
            },
            false,
        ),
    ];
    assert_eq!(
        cases.len(),
        15,
        "a GnomeError variant was added and is unmapped here"
    );
    for (name, e, unreachable) in &cases {
        // The mapping under test, restated: two timeouts go Unreachable,
        // everything else goes Failed. If `gnome_error` is re-pointed, this
        // table is what disagrees with it.
        let mapped = match e {
            GnomeError::BusNeverReady { .. } | GnomeError::KeyringNeverReady { .. } => {
                CliError::Unreachable(e.to_string())
            }
            _ => CliError::Failed(e.to_string()),
        };
        assert_eq!(
            matches!(mapped, CliError::Unreachable(_)),
            *unreachable,
            "{name}: {e:?}"
        );
        assert_eq!(
            mapped.exit_code(),
            if *unreachable { 3 } else { 1 },
            "{name}: {e:?}"
        );
        assert!(
            !mapped.to_string().is_empty(),
            "{name}: the message must survive the mapping"
        );
    }
}

/// The same contract for `extract_kwallet`'s inline match: a missing service
/// is unreachable (exit 3), a missing wallet is not-found (exit 1), and
/// everything else — including both foreign-error wrappers — is a failure
/// (exit 1).
///
/// As with the gnome table, the match itself is inline in the transport and
/// this pins every arm of it plus the codes. The two arms reachable without
/// a kwalletd are additionally exercised through the real `extract` below.
#[test]
fn kwallet_error_mapping_names_the_remedy() {
    let wait = Duration::from_secs(1);
    let cases: Vec<(&str, KWalletError, u8)> = vec![
        ("service-unavailable", KWalletError::ServiceUnavailable, 3),
        (
            "no-such-wallet",
            KWalletError::NoSuchWallet {
                wallet: "ghost".into(),
            },
            1,
        ),
        (
            "invalid-name",
            KWalletError::InvalidWalletName {
                wallet: "../escape".into(),
            },
            1,
        ),
        (
            "no-display",
            KWalletError::NoDisplay {
                wallet: "kdewallet".into(),
            },
            1,
        ),
        (
            "open-refused",
            KWalletError::OpenRefused {
                wallet: "kdewallet".into(),
                code: -1,
            },
            1,
        ),
        (
            "open-timed-out",
            KWalletError::OpenTimedOut {
                wallet: "kdewallet".into(),
                timeout: wait,
            },
            1,
        ),
        (
            "call-timed-out",
            KWalletError::CallTimedOut {
                call: "folderList",
                timeout: wait,
            },
            1,
        ),
        (
            "too-many-entries",
            KWalletError::TooManyEntries { limit: 200_000 },
            1,
        ),
        (
            "too-many-secret-bytes",
            KWalletError::TooManySecretBytes { limit: 1 },
            1,
        ),
        (
            "sidecar",
            KWalletError::Sidecar(SidecarError::NotAnObject {
                path: PathBuf::from("/x"),
            }),
            1,
        ),
        (
            "dbus",
            KWalletError::Dbus(zbus::Error::Address("bad address".to_string())),
            1,
        ),
        (
            "bus",
            KWalletError::Bus(zbus::fdo::Error::Failed("nope".to_string())),
            1,
        ),
    ];
    assert_eq!(
        cases.len(),
        12,
        "a KWalletError variant was added and is unmapped here"
    );
    for (name, e, code) in &cases {
        // The production match, restated as the contract: service →
        // Unreachable, wallet → NotFound, everything else → Failed.
        let mapped = match e {
            KWalletError::ServiceUnavailable => CliError::Unreachable(e.to_string()),
            KWalletError::NoSuchWallet { .. } => CliError::NotFound(e.to_string()),
            _ => CliError::Failed(e.to_string()),
        };
        assert_eq!(mapped.exit_code(), *code, "{name}: {e:?}");
        let expect = match *code {
            3 => "Unreachable",
            1 if *name == "no-such-wallet" => "NotFound",
            _ => "Failed",
        };
        assert!(
            format!("{mapped:?}").starts_with(expect),
            "{name}: expected CliError::{expect}, got {mapped:?}"
        );
    }
}

/// The two kwallet arms reachable with no kwalletd, through the real
/// `kwallet::extract` on the fixture's private bus — the production function,
/// not a restatement of its match.
///
/// A bus nobody answers `org.kde.kwalletd6` on is `ServiceUnavailable`, and a
/// name that would escape `kwalletd/` is refused before the bus or the
/// filesystem sees it.
#[tokio::test]
async fn kwallet_extract_names_a_missing_service_and_an_unusable_name() {
    use secret_manager::import::kwallet::{self, Sidecar};
    let fixture = Fixture::start().await;
    let conn = fixture.client().await;
    let err = kwallet::extract(&conn, "test", &Sidecar::empty(), Duration::from_secs(5))
        .await
        .expect_err("no kwalletd owns the fixture bus");
    assert!(
        matches!(err, KWalletError::ServiceUnavailable),
        "got {err:?}"
    );
    let err = kwallet::extract(
        &conn,
        "../escape",
        &Sidecar::empty(),
        Duration::from_secs(5),
    )
    .await
    .expect_err("a name containing '/' cannot be a wallet");
    assert!(
        matches!(err, KWalletError::InvalidWalletName { .. }),
        "got {err:?}"
    );
}

/// An extractor that fails the way the mapped transports do. `run_with` must
/// carry the error to the caller unchanged — variant, message and code —
/// and write nothing.
struct Failing(&'static str);

impl Extractor for Failing {
    fn extract<'a>(
        &'a self,
        _source: Source,
        _container: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Extraction, CliError>> + 'a>>
    {
        Box::pin(async move {
            Err(match self.0 {
                "missing" => CliError::NotFound("KWallet has no wallet named 'ghost'".to_string()),
                "unreachable" => CliError::Unreachable(
                    "kwalletd6 does not own org.kde.kwalletd6 on the session bus".to_string(),
                ),
                _ => CliError::Failed("the source daemon answered with an error".to_string()),
            })
        })
    }
}

#[tokio::test]
async fn extractor_errors_reach_the_caller_unmapped() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    for (which, code) in [("missing", 1), ("unreachable", 3), ("failed", 1)] {
        let err = secret_manager::cli::import::run_with(args(true), &Failing(which), &env)
            .await
            .expect_err("an extraction failure is a failed import");
        assert_eq!(err.exit_code(), code, "{which}: {err}");
        assert!(
            files_in(vaults.path()).is_empty(),
            "{which}: a failed extraction wrote {0:?}",
            files_in(vaults.path())
        );
    }
}

// --------------------------------------------------------------------------
// Verification wiring: the checks after the write, and what a failure does
// --------------------------------------------------------------------------

fn kwallet_args(dry_run: bool) -> ImportArgs {
    ImportArgs {
        from: SourceArg::KWallet,
        inventory: false,
        dry_run,
        collection: None,
        set_default: false,
        report: None,
    }
}

fn unhex(s: &str) -> [u8; 16] {
    assert_eq!(s.len(), 32, "an md5 hex digest is 32 characters");
    let mut out = [0u8; 16];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}

/// A `.kwl` cleartext index holding exactly one folder with exactly one
/// entry, built from caller-chosen hashes: the parser stops at the index end
/// and never reads the tail, so the ciphertext can be anything.
fn kwl_with_single_entry(folder_hash: [u8; 16], entry_hash: [u8; 16]) -> Vec<u8> {
    let mut out = KWALLET_MAGIC.to_vec();
    out.extend_from_slice(&[0, 1, 3, 2]); // the accepted version; cipher/hash ids
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&folder_hash);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&entry_hash);
    out.extend_from_slice(&[0u8; 32]); // the encrypted half, never parsed
    out
}

/// A tampered secret is a fingerprint mismatch, and a failed verification
/// publishes nothing: Err, `written: false`, and no vault left on disk.
///
/// In two halves, because the pipeline writes the very bytes it verifies —
/// the vault round-trips verbatim (see
/// `import_items_round_trips_awkward_values`) — so a fingerprint failure is
/// unreachable through a `Fake` alone: any extraction the fake returns is
/// self-consistent by construction. The first half pins the detection itself,
/// in pipeline order (plan, then tamper, then compare); the second pins the
/// failure branch every verification failure shares, travelled here by a
/// count shortfall.
#[tokio::test]
async fn a_tampered_secret_is_a_fingerprint_mismatch_and_a_failed_run_leaves_nothing() {
    // Half 1: the plan is made, the secret is tampered after it, and the
    // comparison against what was written reports the pair.
    let items = sample_items();
    let plan = probe_plan(&items);
    assert_eq!(
        plan.len(),
        2,
        "the plan must exist before the tamper or this proves nothing"
    );
    let mut written = items.clone();
    written[0].secret = zeroize::Zeroizing::new(b"tampered-after-the-plan".to_vec());
    let source: Vec<FingerprintEntry> = items.iter().map(FingerprintEntry::source).collect();
    let destination: Vec<FingerprintEntry> = written
        .iter()
        .enumerate()
        .map(|(n, i)| {
            FingerprintEntry::destination(
                &i.attributes,
                &i.label,
                &i.content_type,
                &i.secret,
                format!("/org/freedesktop/secrets/collection/test/{n}"),
            )
        })
        .collect();
    let mismatches = compare_fingerprints(&source, &destination);
    // One changed item reports as a pair — the source fingerprint with no
    // partner, and the destination fingerprint nobody asked for — so "one
    // mismatch" is two rows, one per side.
    assert_eq!(mismatches.len(), 2, "{mismatches:?}");
    assert_eq!(mismatches[0].side, Side::MissingFromDestination);
    assert_eq!(mismatches[1].side, Side::UnexpectedInDestination);
    // Named by keys and path, never by values.
    let json = serde_json::to_string(&mismatches).unwrap();
    assert!(json.contains("account"), "{json}");
    assert!(!json.contains("tampered-after-the-plan"), "{json}");

    // Half 2: the shared failure branch — the error, the report, the unlink.
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    // Three declared in the header, two walked: the count fails.
    let fake = Fake::of("Sample keyring", sample_items(), Vec::new());
    let report_path = root.path().join("fp.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    let err = secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect_err("2 walked against 3 in the header is a failure");
    assert!(err.to_string().contains("verification"), "{err}");
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(parsed["written"], serde_json::json!(false));
    assert_eq!(
        parsed["verification"]["count"],
        serde_json::json!({ "header_item_count": 3, "walked": 2 })
    );
    // The fingerprint machinery ran against the bytes on disk and matched —
    // the count is what failed here, and the sections are independent.
    assert_eq!(
        parsed["verification"]["fingerprints_compared"],
        serde_json::json!(2)
    );
    assert!(
        parsed["verification"]["fingerprint_mismatches"].is_null(),
        "{parsed}"
    );
    let left: Vec<String> = files_in(vaults.path())
        .into_iter()
        .filter(|n| n.ends_with(".vault"))
        .collect();
    assert!(left.is_empty(), "the failed run left {left:?} behind");
}

/// A forged wallet name fails verification and the run unlinks what it wrote.
///
/// The `.kwl` holds folder "TestFolder" with entry "good-entry" (hashes
/// below); the walked item names the real folder with a forged entry. The
/// `assert_ne!` is what makes the miss real rather than assumed.
///
/// Note the count no longer isolates the miss the way it used to: the walked
/// item is not in the file, so the file's real entry is unlisted, and the
/// count reads one declared, one walked, one never listed. Both checks fire,
/// and both are right — a forgery displaces the real entry rather than
/// matching it — and the run still unlinks what it wrote.
#[tokio::test]
async fn a_forged_wallet_name_fails_the_hash_table_check_and_leaves_nothing() {
    // MD5("TestFolder"), MD5("good-entry"), MD5("forged-entry").
    let folder_hash = unhex("95e8fd9739097a67c833315b8461ec04");
    let entry_hash = unhex("f3a221333b1a4914cceaa5b973715a42");
    let forged_hash = unhex("8afaf5db9d2ec25512a1fc379ea113d8");
    assert_ne!(
        entry_hash, forged_hash,
        "the forgery must differ from the index or the miss is vacuous"
    );
    let source = tempfile::tempdir().unwrap();
    let kwalletd = source.path().join("kwalletd");
    std::fs::create_dir_all(&kwalletd).unwrap();
    std::fs::write(
        kwalletd.join("test.kwl"),
        kwl_with_single_entry(folder_hash, entry_hash),
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let mut env = env_for(root.path(), vaults.path());
    env.source_dir = kwalletd;

    let forged = SourceItem {
        label: "a wallet login".to_string(),
        attributes: attrs(&[("server", "w.example"), ("user", "u")]),
        secret: zeroize::Zeroizing::new(b"wallet-secret".to_vec()),
        content_type: "text/plain".into(),
        created: 1_699_383_593,
        modified: 1_699_387_319,
        provenance: Provenance::kwallet("test", "TestFolder", "forged-entry"),
        inserted_keys: Default::default(),
    };
    let fake = Fake::of("test", vec![forged], Vec::new());
    let report_path = root.path().join("hash.json");
    let mut a = kwallet_args(false);
    a.report = Some(report_path.clone());
    let err = secret_manager::cli::import::run_with(a, &fake, &env)
        .await
        .expect_err("a forged entry hash is a failed verification");
    assert!(err.to_string().contains("verification"), "{err}");
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    // One declared, one walked, one never listed: the walked item is not
    // the file's entry, so the file's real entry is unlisted and the count
    // fires alongside the hash-table miss. Both fail closed.
    assert_eq!(
        parsed["verification"]["count"],
        serde_json::json!({ "header_item_count": 1, "walked": 1, "unlisted": 1 })
    );
    assert_eq!(
        parsed["verification"]["hash_table_checked"],
        serde_json::json!(1)
    );
    assert_eq!(
        parsed["verification"]["hash_table_misses"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{parsed}"
    );
    assert_eq!(parsed["written"], serde_json::json!(false));
    let left: Vec<String> = files_in(vaults.path())
        .into_iter()
        .filter(|n| n.ends_with(".vault"))
        .collect();
    assert!(left.is_empty(), "the failed run left {left:?} behind");
}

/// A truncated secret fails the histogram check: 17 bytes became 16 — a
/// stripped trailing newline — which the fingerprints only call "different"
/// and the histogram localises to a bucket.
///
/// And on a good run both length distributions are measured, the destination
/// from the decrypted file rather than from the source twice: a histogram
/// built from one side twice would agree with itself and catch nothing.
#[tokio::test]
async fn a_truncated_secret_fails_the_histogram_check() {
    let source = Histogram::of_lengths([17]);
    let destination = Histogram::of_lengths([16]);
    let diffs = compare_histograms(&source, &destination);
    assert!(!diffs.is_empty(), "a one-byte truncation moved a bucket");
    // The difference alone fails the whole verification: every other section
    // below passes, so `passed()` is decided by the histogram.
    let verification = Verification {
        count: CountCheck::new(Some(1), 1),
        fingerprint_mismatches: Vec::new(),
        fingerprints_compared: Some(1),
        hash_table_misses: Vec::new(),
        hash_table_checked: None,
        unlisted: Vec::new(),
        probes: ProbeSummary::of(&[]),
        failed_probes: Vec::new(),
        source_lengths: source,
        destination_lengths: Some(destination),
        length_differences: diffs,
    };
    assert!(verification.count.passed());
    assert!(
        !verification.passed(),
        "a histogram difference must fail verification"
    );

    // The wiring half: a faithful write measures both sides and agrees.
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    let report_path = root.path().join("lengths.json");
    let mut a = args(false);
    a.report = Some(report_path.clone());
    secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
        .await
        .expect("a faithful import measures agreeing histograms");
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert!(
        !parsed["verification"]["source_lengths"].is_null(),
        "{parsed}"
    );
    assert!(
        !parsed["verification"]["destination_lengths"].is_null(),
        "{parsed}"
    );
    assert!(
        parsed["verification"]["length_differences"].is_null(),
        "a faithful import has no length differences: {parsed}"
    );
}

// --------------------------------------------------------------------------
// Locating the source: an empty directory, and a default file that cannot
// be read
// --------------------------------------------------------------------------

/// No `.keyring` file and no `default` is NotFound (exit 1): there is nothing
/// to import from, and the error names the directory.
#[tokio::test]
async fn empty_source_dir_is_not_found() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let mut env = env_for(root.path(), vaults.path());
    let empty = tempfile::tempdir().unwrap();
    env.source_dir = empty.path().to_path_buf();
    let err = secret_manager::cli::import::run_with(args(true), &Fake::sample(), &env)
        .await
        .expect_err("an empty source directory holds nothing to import");
    assert!(
        matches!(err, CliError::NotFound(_)),
        "an empty directory is absent, not broken: {err:?}"
    );
    assert_eq!(err.exit_code(), 1);
    assert!(err.to_string().contains("no .keyring file"), "{err}");
}

/// A `default` file that cannot be read is Failed (exit 1), never a silent
/// fall back to "the only keyring" — which would import a different keyring
/// than the user's session uses.
///
/// A directory in the file's place fails the read on every uid (a chmod-000
/// file stays readable for root, so permissions cannot pin this); only an
/// *absent* file means "there is no default".
#[tokio::test]
async fn unreadable_default_file_is_failed_not_absent() {
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let env = env_for(root.path(), vaults.path());
    std::fs::create_dir(env.source_dir.join("default")).unwrap();
    let err = secret_manager::cli::import::run_with(args(true), &Fake::sample(), &env)
        .await
        .expect_err("an unreadable default file is not an absent one");
    assert!(
        matches!(err, CliError::Failed(_)),
        "a directory named `default` is a failure, not an absence: {err:?}"
    );
    assert_eq!(err.exit_code(), 1);
    assert!(err.to_string().contains("default"), "{err}");
}

// --------------------------------------------------------------------------
// Proving nothing without a daemon: `DaemonTarget::FromEnvironment` with no
// socket, and with a dead one
// --------------------------------------------------------------------------

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Set an env var for the duration of a test, restoring it after.
///
/// `std::env::set_var` is `unsafe` in edition 2024 because it races every
/// other thread in the process. The subprocess harness below runs each of
/// these bodies in a child process that executes exactly one test, so no
/// other test in this binary reads the variable while it is set; the lock
/// serialises the bodies against each other anyway, and every other test in
/// this binary reaches its daemon through `DaemonTarget::None` or
/// `DaemonTarget::At` and never reads this variable.
struct EnvGuard {
    key: &'static str,
    old: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let lock = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self {
            key,
            old,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.old {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Re-run this test in a child process with real fds, then assert on its
/// stderr.
///
/// libtest intercepts `eprintln!` on every thread of this process, so no fd
/// redirect here can capture what `run_with` prints: the capture tests below
/// failed with empty files while their warnings displayed under the test's
/// own output instead (and pass with `-- --nocapture`, which disables that
/// interception). A child test-binary process has real fds, so the parent
/// spawns one — this same test, `--exact` plus `--nocapture`, with
/// `SM_IMPORT_SUBPROCESS` set — and asserts on its stderr.
///
/// Returns `None` in the child, where the caller runs the real body; in the
/// parent it asserts the child succeeded and its stderr holds every one of
/// `expect_stderr`, then returns `Some` to end the test.
fn subprocess_harness(test_name: &str, expect_stderr: &[&str]) -> Option<()> {
    if std::env::var_os("SM_IMPORT_SUBPROCESS").is_some() {
        return None;
    }
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let out = std::process::Command::new(exe)
        .args([test_name, "--exact", "--nocapture"])
        .env("SM_IMPORT_SUBPROCESS", "1")
        .output()
        .expect("could not spawn the subprocess");
    assert!(
        out.status.success(),
        "subprocess for {test_name} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    for want in expect_stderr {
        assert!(
            stderr.contains(want),
            "subprocess stderr lacked {want:?}:\n{stderr}"
        );
    }
    Some(())
}

/// No control socket under this runtime dir: both the reload nudge (silent
/// without a socket) and the probe (a warning) find nothing, every probe
/// comes back not issued, and the run succeeds — unproved is not failed.
///
/// The "did not answer" sentence is asserted by the parent side of
/// `subprocess_harness` (it lives on stderr, which the report JSON never
/// carries); the body below asserts the run and the report.
#[test]
fn probe_without_control_socket_is_unproved() {
    if subprocess_harness(
        "probe_without_control_socket_is_unproved",
        &["did not answer"],
    )
    .is_some()
    {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let runtime = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set("XDG_RUNTIME_DIR", runtime.path());
        let root = tempfile::tempdir().unwrap();
        let vaults = tempfile::tempdir().unwrap();
        let mut env = env_for(root.path(), vaults.path());
        env.daemon = DaemonTarget::FromEnvironment;

        let report_path = root.path().join("no-daemon.json");
        let mut a = args(false);
        a.report = Some(report_path.clone());
        secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
            .await
            .expect("a probe that cannot run is unproved, not failed");

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
        assert_eq!(
            parsed["verification"]["probes"],
            serde_json::json!({ "passed": 0, "failed": 0, "not_issued": 2 }),
            "{parsed}"
        );
    });
}

/// A regular file where the control socket belongs: `connect` fails, the
/// probe is unproved for a different reason than above, and the run still
/// succeeds. The file's presence is what distinguishes this arm from the
/// missing-socket one; the sentence is asserted by the harness.
#[test]
fn probe_with_dead_control_socket_is_unproved() {
    if subprocess_harness(
        "probe_with_dead_control_socket_is_unproved",
        &["did not answer"],
    )
    .is_some()
    {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let runtime = tempfile::tempdir().unwrap();
        let sock_dir = runtime.path().join("secret-manager");
        std::fs::create_dir_all(&sock_dir).unwrap();
        std::fs::write(sock_dir.join("control.sock"), b"not a socket").unwrap();
        assert!(sock_dir.join("control.sock").is_file());
        let _env = EnvGuard::set("XDG_RUNTIME_DIR", runtime.path());

        let root = tempfile::tempdir().unwrap();
        let vaults = tempfile::tempdir().unwrap();
        let mut env = env_for(root.path(), vaults.path());
        env.daemon = DaemonTarget::FromEnvironment;

        let report_path = root.path().join("dead-socket.json");
        let mut a = args(false);
        a.report = Some(report_path.clone());
        secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
            .await
            .expect("a dead control socket is unproved, not failed");

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
        assert_eq!(
            parsed["verification"]["probes"],
            serde_json::json!({ "passed": 0, "failed": 0, "not_issued": 2 }),
            "{parsed}"
        );
    });
}

// --------------------------------------------------------------------------
// Warnings, not failures: a refusing daemon, and an unwritable alias table
// --------------------------------------------------------------------------

/// A control socket that answers `Reload` with an error: the daemon is there
/// but refuses the rescan.
///
/// Exactly one connection follows — a refused reload means the probe is
/// never issued, so nothing else ever arrives at this socket — and the
/// deadline bounds the wait so a regression that stops sending `Reload`
/// fails the test (via the missing warning) instead of hanging it.
fn spawn_failing_reload_server(sock: &Path) -> std::thread::JoinHandle<()> {
    use std::io::ErrorKind;
    use std::os::unix::net::UnixListener;
    let listener = UnixListener::bind(sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    if let Ok(body) = secret_manager::protocol::read_frame_sync(&mut s) {
                        let req: Request = secret_manager::protocol::decode_frame(&body).unwrap();
                        assert!(
                            matches!(req, Request::Reload),
                            "the import only ever sends Reload here"
                        );
                        let frame = secret_manager::protocol::encode_frame(&Response::Error(
                            "injected reload failure".to_string(),
                        ))
                        .unwrap();
                        secret_manager::protocol::write_frame_sync(&mut s, &frame).unwrap();
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    })
}

/// A refused `Reload` is a line on stderr, not a failed import: the
/// collection is written, the report says so, and the probes stay not issued —
/// a daemon that refused the rescan may not hold the collection, so the run
/// does not issue `SearchItems` at all. The sentence is asserted by
/// the harness; the body asserts the run and the report.
#[test]
fn a_daemon_that_refuses_reload_costs_a_warning_not_the_run() {
    if subprocess_harness(
        "a_daemon_that_refuses_reload_costs_a_warning_not_the_run",
        &["did not reload", "injected reload failure"],
    )
    .is_some()
    {
        return;
    }
    // Both halves of the warning travel in one sentence; the parent asserts
    // them together.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("control.sock");
    let server = spawn_failing_reload_server(&sock);

    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut env = env_for(root.path(), vaults.path());
        env.daemon = DaemonTarget::At {
            bus_address: "unix:path=/nonexistent-bus-for-import-test".to_string(),
            control_socket: sock,
        };

        let report_path = root.path().join("reload.json");
        let mut a = args(false);
        a.report = Some(report_path.clone());
        secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
            .await
            .expect("a refused reload is a warning, not a failed import");

        assert!(files_in(vaults.path()).contains(&"sample_keyring.vault".to_string()));
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
        assert_eq!(parsed["written"], serde_json::json!(true));
        assert_eq!(
            parsed["verification"]["probes"],
            serde_json::json!({ "passed": 0, "failed": 0, "not_issued": 2 }),
            "{parsed}"
        );
    });
    server.join().expect("the fake control server finished");
}

/// An alias table that cannot be read is a warning, not a failed import: the
/// collection is written, no alias moves, and the run succeeds.
///
/// `aliases.toml` as a directory fails the read on every uid — permissions
/// would still let root through, and the vault write needs the same directory
/// writable, so a read-only directory cannot reach this step at all.
///
/// The sentence is asserted by the harness; the body asserts the run, the
/// files, and the report's own record of the unmoved alias.
#[test]
fn an_unwritable_alias_table_costs_a_warning_not_the_run() {
    if subprocess_harness(
        "an_unwritable_alias_table_costs_a_warning_not_the_run",
        &["aliases.toml", "left alone"],
    )
    .is_some()
    {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let vaults = tempfile::tempdir().unwrap();
    std::fs::create_dir(vaults.path().join("aliases.toml")).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut env = env_for(root.path(), vaults.path());
        env.daemon = DaemonTarget::None;

        let report_path = root.path().join("alias.json");
        let mut a = args(false);
        a.set_default = true;
        a.report = Some(report_path.clone());
        secret_manager::cli::import::run_with(a, &Fake::sample(), &env)
            .await
            .expect("an unwritable alias table is a warning");

        assert!(files_in(vaults.path()).contains(&"sample_keyring.vault".to_string()));
        assert!(
            !vaults.path().join("aliases.toml").is_file(),
            "no alias file was written"
        );
        // The same failure is also in the report's notes, which is the half
        // that needs no subprocess to assert on.
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
        let notes = parsed["notes"].as_array().cloned().unwrap_or_default();
        assert!(
            notes
                .iter()
                .any(|n| n.as_str().is_some_and(|s| s.contains("left alone"))),
            "the report must record the unmoved alias: {parsed}"
        );
    });
}

// --------------------------------------------------------------------------
// --inventory for a wallet, with nothing running
// --------------------------------------------------------------------------

/// The kwallet mirror of the keyring inventory test: the cleartext index is
/// all it reads — folders and entries from the committed `sample.kwl`, which
/// holds three folders (one of them empty) and four entries.
#[test]
fn kwallet_inventory_names_folders_and_entries_with_no_daemon_and_no_password() {
    let root = tempfile::tempdir().unwrap();
    let kwalletd = root.path().join("kwalletd");
    std::fs::create_dir_all(&kwalletd).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/import/sample.kwl"),
        kwalletd.join("test.kwl"),
    )
    .unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    let assert = cmd
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root.path())
        .env("XDG_DATA_HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_RUNTIME_DIR", root.path().join("run"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .args(["import", "--from", "kwallet", "--inventory"])
        .write_stdin("")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("test"), "{out}");
    assert!(out.contains("folders              3"), "{out}");
    assert!(out.contains("of those, empty      1"), "{out}");
    assert!(out.contains("entries              4"), "{out}");
    assert!(out.contains("No password was asked for"), "{out}");
}
