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
