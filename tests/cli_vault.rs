mod common;

use common::Fixture;
use predicates::prelude::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_unlock_lock_change_password() {
    let fx = Fixture::start().await;
    fx.sm()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("default").and(predicate::str::contains("locked")));
    fx.sm()
        .arg("unlock")
        .write_stdin("wrong\n")
        .assert()
        .code(1)
        // The daemon deliberately does not say *why* it refused: a wrong key,
        // a damaged file and an absent collection are one message, so the
        // socket is not an existence oracle for collection names.
        .stderr(predicate::str::contains("cannot unlock that collection"));
    fx.sm().arg("unlock").write_stdin("pw\n").assert().success();
    fx.sm()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked"));
    assert!(!secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);
    fx.sm().arg("lock").assert().success();
    assert!(secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);
    fx.sm()
        .args(["unlock", "--collection", "nope"])
        .write_stdin("pw\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no collection"));

    fx.sm()
        .arg("change-password")
        .write_stdin("pw\nnewpw\n")
        .assert()
        .success();
    fx.sm().arg("lock").assert().success();
    fx.sm().arg("unlock").write_stdin("pw\n").assert().code(1);
    fx.sm()
        .arg("unlock")
        .write_stdin("newpw\n")
        .assert()
        .success();
    fx.sm()
        .arg("change-password")
        .write_stdin("newpw\n\n")
        .assert()
        .code(2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_daemon_exits_3() {
    let fx = Fixture::start().await;
    let empty = tempfile::tempdir().unwrap();
    fx.sm()
        .arg("status")
        .env("XDG_RUNTIME_DIR", empty.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "systemctl --user start secret-manager",
        ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_xdg_runtime_dir_exits_3_but_init_still_succeeds() {
    let fx = Fixture::start().await;
    fx.sm()
        .arg("status")
        .env_remove("XDG_RUNTIME_DIR")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("XDG_RUNTIME_DIR is not set"));
    fx.sm()
        .args(["init", "--collection", "tmpx"])
        .env_remove("XDG_RUNTIME_DIR")
        .write_stdin("hunter2\n")
        .assert()
        .success();
}

#[test]
fn completions_render() {
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sm"));
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}

/// HIGH 3: `--collection` is pasted into a filesystem path, so only a value
/// that is already a normalized collection id may be accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collection_argument_is_validated() {
    let fx = Fixture::start().await;

    // A planted vault file outside the vault directory must be unreachable.
    let outside = tempfile::tempdir().unwrap();
    let planted = outside.path().join("planted.vault");
    secret_manager::vault::Vault::create(
        &planted,
        "Planted",
        b"attacker",
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let traversal = format!("{}/planted", outside.path().display());
    for arg in [
        "../x".to_string(),
        "..".to_string(),
        traversal,
        "My Work".to_string(),
        "UPPER".to_string(),
    ] {
        fx.sm()
            .args(["unlock", "--collection", &arg])
            .write_stdin("pw\n")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("[a-z0-9_]"));
        fx.sm()
            .args(["change-password", "--collection", &arg])
            .write_stdin("pw\nnew\n")
            .assert()
            .code(2)
            .stderr(predicate::str::contains("[a-z0-9_]"));
    }
    // A valid id that simply does not exist is still a "not found", not usage.
    fx.sm()
        .args(["unlock", "--collection", "nope"])
        .write_stdin("pw\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no collection"));
}

/// HIGH 3: `sm init` still accepts a human label, but names the derived id so
/// the same string is not later passed to `sm unlock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_reports_the_derived_collection_id() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["init", "--collection", "My Work"])
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("my_work"));
    fx.sm()
        .args(["unlock", "--collection", "my_work"])
        .write_stdin("hunter2\n")
        .assert()
        .success();
}

/// WARNING: `header_params` maps only `NotFound` to "no collection"; anything
/// else must stay a plain failure naming the file. A vault whose header will
/// not decode is the dangerous case: telling the user there is no collection
/// invites `sm init` over a file that already holds their secrets, and `init`
/// would overwrite it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_with_an_undecodable_header_is_not_reported_as_missing() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");

    // Not a vault at all: the magic is wrong, so `header_prefix_len` rejects
    // the 12-byte prefix.
    let garbage = dir.join("broken.vault");
    std::fs::write(&garbage, b"NOTAVAULT and then some").unwrap();

    // A real vault cut short: the prefix itself cannot be read, which is an
    // `UnexpectedEof`, not a `NotFound`.
    let truncated = dir.join("cut.vault");
    secret_manager::vault::Vault::create(
        &truncated,
        "Cut",
        b"pw",
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&truncated)
        .unwrap()
        .set_len(8)
        .unwrap();

    for (id, path) in [("broken", &garbage), ("cut", &truncated)] {
        for cmd in ["unlock", "change-password"] {
            fx.sm()
                .args([cmd, "--collection", id])
                .write_stdin("pw\npw\n")
                .assert()
                .code(1)
                .stderr(
                    predicate::str::contains(path.display().to_string())
                        .and(predicate::str::contains("no collection").not()),
                );
        }
    }
}

/// A control socket the CLI did not start, answering with a `Response` of our
/// choosing. The CLI finds it purely from `XDG_RUNTIME_DIR`, and
/// `protocol::call` checks only that the listening peer shares our uid — which
/// a listener in the test process does — so this is the whole of what a
/// same-uid process could do to `sm`.
///
/// Serves exactly one connection and hands back the request it saw.
fn serve_one_control_reply(
    runtime_dir: &std::path::Path,
    reply: secret_manager::protocol::Response,
) -> std::thread::JoinHandle<secret_manager::protocol::Request> {
    use secret_manager::protocol::{
        decode_frame, encode_frame, read_frame_sync, socket_path_for_runtime_dir, write_frame_sync,
    };
    let sock = socket_path_for_runtime_dir(runtime_dir);
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let body = read_frame_sync(&mut stream).unwrap();
        let req = decode_frame(&body).unwrap();
        write_frame_sync(&mut stream, &encode_frame(&reply).unwrap()).unwrap();
        req
    })
}

/// `sm status` accepts exactly one reply variant. A peer that answers
/// `Response::Ok` — well-formed, right protocol version, right uid, wrong
/// variant — must be a plain failure, not a panic and not a silent success.
#[test]
fn status_rejects_a_wrong_reply_variant() {
    use secret_manager::protocol::{Request, Response};

    let runtime = tempfile::tempdir().unwrap();
    let server = serve_one_control_reply(runtime.path(), Response::Ok);

    let out = assert_cmd::Command::cargo_bin("secret-manager")
        .unwrap()
        .env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .arg("status")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unexpected reply"))
        .get_output()
        .clone();

    let seen = server.join().unwrap();
    assert!(matches!(seen, Request::Status), "{seen:?}");
    // Nothing was printed as if it were state.
    assert!(
        out.stdout.is_empty(),
        "a rejected reply still produced output: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The `unexpected reply {other:?}` arm is the one place a peer-supplied
/// `Response` is `Debug`-formatted into a message that reaches the terminal,
/// rather than going through `escape_control` the way `sm list` does.
///
/// Two things keep that safe, and both are asserted here:
///
/// * By construction the arm can only ever see `Response::Ok`.
///   `Response::Status` is handled above it and `Response::Error` never gets
///   that far — `vault_cmds::control` turns it into `CliError::Failed`
///   first — so no peer-controlled *text* reaches the `{:?}`.
/// * Even if it did, `Debug` for `String` escapes: a `\r`, an ESC and a
///   U+202E bidi override all come out as `\u{...}` / `\r` sequences.
///
/// The second is checked directly rather than through the CLI, because the
/// first makes it unreachable from the CLI — and it is the property that
/// would have to hold if a later variant ever carried peer text into this
/// arm.
#[test]
fn a_debug_formatted_response_cannot_carry_terminal_control_bytes() {
    use secret_manager::protocol::Response;

    const HOSTILE: &str = "boom\r\u{1b}[2K\u{202e}dessimsid\u{7f}";
    let rendered = format!("{:?}", Response::Error(HOSTILE.to_string()));
    for bad in ['\r', '\n', '\u{1b}', '\u{7f}', '\u{202e}'] {
        assert!(
            !rendered.contains(bad),
            "Debug leaked {bad:?} verbatim: {rendered}"
        );
    }
    assert!(
        rendered.contains("\\u{202e}") && rendered.contains("\\u{1b}"),
        "the bidi override and the escape must be visible as escapes: {rendered}"
    );
}

/// The other half of the same question, and the one that is actually
/// reachable: `vault_cmds::control` turns a `Response::Error` into the
/// message the CLI prints, and that string is chosen by whatever answers the
/// control socket. It must reach the terminal escaped — a `\r` or an
/// `ESC [ 2 K` in it would otherwise erase lines the user has already read,
/// and a bidi override would let a "locked" line be shown reversed.
#[test]
fn a_daemon_error_cannot_write_escape_sequences_to_the_terminal() {
    use secret_manager::protocol::Response;

    const HOSTILE: &str = "boom\r\u{1b}[2K\u{202e}dessimsid\u{7f}";
    let runtime = tempfile::tempdir().unwrap();
    let server = serve_one_control_reply(runtime.path(), Response::Error(HOSTILE.to_string()));

    let out = assert_cmd::Command::cargo_bin("secret-manager")
        .unwrap()
        .env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .arg("status")
        .assert()
        .code(1)
        .get_output()
        .clone();
    let _ = server.join();

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    for bad in ['\r', '\u{1b}', '\u{7f}', '\u{202e}'] {
        assert!(
            !stderr.contains(bad),
            "raw {bad:?} reached the terminal: {stderr:?}"
        );
    }
    // The text is still readable, and the hidden parts are visible as bytes.
    assert!(stderr.contains("boom"), "{stderr:?}");
    assert!(stderr.contains("\\x0d"), "{stderr:?}");
    assert!(stderr.contains("\\x1b"), "{stderr:?}");
    assert!(stderr.contains("\\xe2\\x80\\xae"), "{stderr:?}");
}

/// A CLI child with its own HOME, config and runtime directory and no bus.
///
/// `env_clear` is deliberate — the CLI must not inherit the test runner's
/// environment — but it also drops the variable the coverage profiler needs,
/// so that one is put back explicitly (see `Fixture::sm`).
fn bare_sm(home: &std::path::Path, runtime: &std::path::Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_RUNTIME_DIR", runtime)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent");
    for key in ["LLVM_PROFILE_FILE", "LLVM_PROFILE_DIR"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd
}

/// A config with a test-cheap KDF, so `sm init` in these tests costs
/// milliseconds rather than the shipped Argon2 cost.
fn write_fast_config(home: &std::path::Path) -> std::path::PathBuf {
    let vault_dir = home.join("vaults");
    let config_dir = home.join("config").join("secret-manager");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "[vault]\ndir = \"{}\"\n[kdf]\nm_cost_kib = 8\nt_cost = 1\np_cost = 1\n",
            vault_dir.display()
        ),
    )
    .unwrap();
    vault_dir
}

/// A control socket that accepts one connection and hangs up without
/// answering: a daemon that died between `connect` and its reply. This is not
/// `ProtocolError::Connect` — something *was* listening — so it must not be
/// mistaken for "no daemon running".
fn serve_one_hangup(runtime_dir: &std::path::Path) -> std::thread::JoinHandle<()> {
    let sock = secret_manager::protocol::socket_path_for_runtime_dir(runtime_dir);
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        drop(stream);
    })
}

/// `sm init` claims the `default` alias only when there is not one already.
/// The alias is what every later `sm set` resolves, so the first collection on
/// a fresh machine has to become it — and the running daemon has to see it,
/// which is the reload the same function sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_claims_the_default_alias_when_there_is_none() {
    use secret_manager::dbus::proxies::ServiceProxy;

    let fx = Fixture::start_without_default_alias().await;
    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    assert_eq!(
        service.read_alias("default").await.unwrap().as_str(),
        "/",
        "the fixture must start with no default alias"
    );

    fx.sm()
        .args(["init", "--collection", "Work"])
        .write_stdin("hunter2\n")
        .assert()
        .success();

    let aliases =
        std::fs::read_to_string(fx.data_dir.path().join("secret-manager/aliases.toml")).unwrap();
    assert!(
        aliases.contains("default = \"work\""),
        "the first collection did not claim the default alias: {aliases}"
    );
    assert!(
        common::wait_for(std::time::Duration::from_secs(3), || async {
            service.read_alias("default").await.unwrap()
                == secret_manager::dbus::paths::collection("work")
        })
        .await,
        "the running daemon never picked the new alias up"
    );
}

/// A daemon that answers the reload with an error must not fail the `init`:
/// the vault is on disk and correct, only the running daemon is behind. The
/// user is warned, on stderr, and the command still succeeds.
#[test]
fn init_warns_when_the_running_daemon_refuses_to_reload() {
    use secret_manager::protocol::{Request, Response};

    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let vault_dir = write_fast_config(home.path());
    let server = serve_one_control_reply(runtime.path(), Response::Error("no".into()));

    bare_sm(home.path(), runtime.path())
        .arg("init")
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("did not reload"));

    assert!(matches!(server.join().unwrap(), Request::Reload));
    assert!(
        vault_dir.join("default.vault").exists(),
        "the vault must exist however the daemon answered"
    );
}

/// The same rule for a daemon that hangs up mid-call: warn, and keep the
/// vault. `ProtocolError::Connect` is the "no daemon" case and is silent; this
/// one is not, because a daemon that is there but unreachable may keep the new
/// collection invisible until it restarts.
#[test]
fn init_warns_when_the_control_socket_hangs_up() {
    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let vault_dir = write_fast_config(home.path());
    let server = serve_one_hangup(runtime.path());

    bare_sm(home.path(), runtime.path())
        .arg("init")
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "could not tell the running daemon",
        ));

    server.join().unwrap();
    assert!(vault_dir.join("default.vault").exists());
}

/// A hang-up on a command whose whole job is the control call is a failure,
/// not a "daemon not running" (exit 3): something answered, so telling the
/// user to start the daemon would send them the wrong way.
#[test]
fn status_reports_a_control_socket_that_hangs_up_as_a_failure() {
    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    write_fast_config(home.path());
    let server = serve_one_hangup(runtime.path());

    bare_sm(home.path(), runtime.path())
        .arg("status")
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("control socket")
                .and(predicate::str::contains("systemctl --user start").not()),
        );
    server.join().unwrap();
}

/// Every string in a `Status` reply — the id, the label and the operator
/// warning — is chosen by whatever answers the control socket, and all three
/// reach a terminal. A `\r` or an `ESC [ 2 K` in any of them would erase rows
/// the user has already read; the warning is the one that goes to stderr,
/// through its own printer.
#[test]
fn a_collection_warning_from_the_control_socket_is_escaped() {
    use secret_manager::protocol::{CollectionStatus, Response};

    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    write_fast_config(home.path());
    let server = serve_one_control_reply(
        runtime.path(),
        Response::Status {
            aliases_error: None,
            collections: vec![CollectionStatus {
                id: "ev\ril".into(),
                label: "lab\u{1b}[2Kel".into(),
                locked: false,
                items: 7,
                warning: Some("index\rrewrite \u{1b}[2Kfailed".into()),
            }],
            uptime_secs: 12,
        },
    );

    let out = bare_sm(home.path(), runtime.path())
        .arg("status")
        .assert()
        .success()
        .get_output()
        .clone();
    let _ = server.join();

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stdout.contains("daemon up 12s"), "{stdout:?}");
    assert!(stdout.contains("ev\\x0dil"), "{stdout:?}");
    assert!(stdout.contains("lab\\x1b[2Kel"), "{stdout:?}");
    assert!(stdout.contains("unlocked"), "{stdout:?}");
    // The warning is a separate line on stderr, and escaped there too.
    assert!(stderr.contains("warning: ev\\x0dil"), "{stderr:?}");
    assert!(stderr.contains("rewrite \\x1b[2Kfailed"), "{stderr:?}");
    for bad in ['\r', '\u{1b}'] {
        assert!(!stdout.contains(bad), "raw {bad:?} on stdout: {stdout:?}");
        assert!(!stderr.contains(bad), "raw {bad:?} on stderr: {stderr:?}");
    }
}

/// `sm daemon` that cannot start for a *local* reason — here a vault
/// directory it cannot read, refused by the scan that runs before the bus is
/// ever touched — is exit 1, and says what failed.
///
/// This used to induce the failure with an unreachable bus address and assert
/// 1 for it, on the belief that only the name clash is 3. That contradicted
/// the README, which lists exit 3 as "daemon or bus unreachable, or
/// `XDG_RUNTIME_DIR` unset", and made `sm daemon` the one command that
/// disagreed with `vault_cmds::control` and `client::method_error_to_cli`
/// about an unreachable bus. Those two cases are exit 3 and are asserted in
/// `tests/daemon.rs`; what is left for 1 is everything that is not a
/// transport failure.
#[test]
#[cfg(unix)]
fn daemon_reports_a_local_start_failure_as_exit_1() {
    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let vault_dir = write_fast_config(home.path());
    // A regular file where the vault directory belongs, so the startup scan
    // fails with `DaemonError::Io` before the connection and the bus address
    // plays no part in the verdict.
    //
    // A mode-000 directory does *not* work here, and the reason is worth
    // keeping: `scan_vault_dir` goes through `ensure_vault_dir`, which repairs
    // a directory's mode as well as setting it at creation, so it chmods 000
    // back to 0700, the scan succeeds, and the daemon reaches the bus — which
    // is exit 3, the very code this test exists to distinguish from.
    if let Some(parent) = vault_dir.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&vault_dir, b"not a directory").unwrap();

    bare_sm(home.path(), runtime.path())
        .arg("daemon")
        .arg("--foreground")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("secret-manager:"));
}

/// The `daemon` subcommand run end to end: it starts, serves, and returns 0
/// when it is asked to stop. A daemon that exited non-zero on SIGTERM would
/// make systemd report every ordinary `systemctl --user stop` as a failure.
#[test]
fn the_daemon_subcommand_exits_cleanly_on_sigterm() {
    let bus = common::TestBus::start();
    let home = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let vault_dir = write_fast_config(home.path());
    std::fs::create_dir_all(&vault_dir).unwrap();

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_secret-manager"));
    cmd.env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address);
    for key in ["LLVM_PROFILE_FILE", "LLVM_PROFILE_DIR"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    let mut child = cmd.args(["daemon", "--foreground"]).spawn().unwrap();

    // The control socket is the last thing `Daemon::start` creates, so its
    // existence means the daemon is fully up.
    let sock = secret_manager::protocol::socket_path_for_runtime_dir(runtime.path());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !sock.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon never bound its control socket"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "the daemon exited before it was up"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // SAFETY: `kill` takes a pid and a signal number and touches no memory.
    assert_eq!(
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) },
        0,
        "could not signal the daemon: {}",
        std::io::Error::last_os_error()
    );
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "a daemon stopped with SIGTERM exited {status:?}"
    );
}

/// `sm reload` exists, and reaches the daemon.
///
/// The recovery instruction printed for a corrupt alias table names it, and
/// used to name a subcommand that did not exist — the only `Reload` sender in
/// the CLI was inside `sm init`, which is itself the command a half-broken
/// vault directory breaks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_tells_a_running_daemon_to_rescan() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    secret_manager::vault::Vault::create(
        &dir.join("work.vault"),
        "Work",
        b"pw",
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();

    fx.sm().arg("reload").assert().success();

    let out = fx.sm().arg("status").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("work"), "{stdout}");
}

/// `sm status` is the only place an operator is told the alias table is
/// unusable, since the daemon no longer announces it by refusing to start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_reports_an_unreadable_alias_table() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    std::fs::write(dir.join("aliases.toml"), b"aliases = 5\n").unwrap();
    fx.sm().arg("reload").assert().success();

    let out = fx.sm().arg("status").output().unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("aliases.toml"), "{stderr}");
    // The instruction has to name something that exists.
    assert!(stderr.contains("sm reload"), "{stderr}");
}
