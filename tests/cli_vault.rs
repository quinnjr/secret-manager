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
    assert!(!fx.daemon.state.lock().await.collections["default"].is_locked());
    fx.sm().arg("lock").assert().success();
    assert!(fx.daemon.state.lock().await.collections["default"].is_locked());
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
