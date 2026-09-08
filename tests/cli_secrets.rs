mod common;

use common::Fixture;
use predicates::prelude::*;
use std::collections::BTreeMap;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_get_list_delete_round_trip() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=git", "user=joe", "--label", "git token"])
        .write_stdin("s3cret\n")
        .assert()
        .success();
    fx.sm()
        .args(["get", "app=git", "user=joe"])
        .assert()
        .success()
        .stdout("s3cret");
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .success()
        .stdout("s3cret");
    fx.sm()
        .args(["get", "app=git", "--label", "git token"])
        .assert()
        .success()
        .stdout("s3cret");
    fx.sm()
        .args(["get", "app=git", "--label", "other"])
        .assert()
        .code(1);
    fx.sm()
        .args(["get", "user=nobody"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no matching secret"));

    // replace keeps a single item
    fx.sm()
        .args(["set", "app=git", "user=joe", "--label", "git token 2"])
        .write_stdin("newer")
        .assert()
        .success();
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .success()
        .stdout("newer");
    fx.sm()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("git token 2").and(predicate::str::contains("app=git")));
    fx.sm()
        .args(["list", "app=git"])
        .assert()
        .success()
        .stdout(predicate::str::contains("user=joe"));
    fx.sm()
        .args(["list", "app=nope"])
        .assert()
        .success()
        .stdout("");
    let json = fx
        .sm()
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed[0]["label"], "git token 2");
    assert_eq!(parsed[0]["attributes"]["user"], "joe");
    assert_eq!(parsed[0]["locked"], false);
    assert!(
        !fx.sm()
            .args(["list"])
            .assert()
            .get_output()
            .stdout
            .windows(5)
            .any(|w| w == b"newer"),
        "list never prints secrets"
    );

    fx.sm().args(["delete", "app=git"]).assert().success();
    fx.sm().args(["get", "app=git"]).assert().code(1);
    fx.sm().args(["delete", "app=git"]).assert().code(1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn most_recent_item_wins() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "k=v", "n=1", "--label", "one"])
        .write_stdin("first")
        .assert()
        .success();
    // Force the first item's `modified` timestamp back deterministically
    // instead of sleeping past the second-granularity clock, so this test
    // doesn't depend on a >1s wall-clock sleep.
    secret_manager::dbus::state::with_vault(&fx.daemon.state, "default", |v| {
        let first_id = v
            .search_ids(&BTreeMap::from([("k".to_string(), "v".to_string())]))
            .into_iter()
            .next()
            .unwrap();
        v.set_modified_for_tests(&first_id, 1).unwrap();
    })
    .await;
    fx.sm()
        .args(["set", "k=v", "n=2", "--label", "two"])
        .write_stdin("second")
        .assert()
        .success();
    fx.sm()
        .args(["get", "k=v"])
        .assert()
        .success()
        .stdout("second");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_secrets_survive() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let bytes: Vec<u8> = vec![0, 1, 2, 255, 10, 13, 10];
    fx.sm()
        .args(["set", "bin=1", "--label", "bin"])
        .write_stdin(bytes.clone())
        .assert()
        .success();
    let out = fx
        .sm()
        .args(["get", "bin=1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        out,
        &bytes[..bytes.len() - 1],
        "exactly one trailing newline is stripped on set"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_errors_and_unreachable() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["get", "noequals"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ATTR=VALUE"));
    fx.sm().args(["set", "a=b"]).assert().code(2); // clap: --label required
    fx.sm().args(["get"]).assert().code(2);
    fx.sm()
        .args(["get", "a=b"])
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
        .assert()
        .code(3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_prompts_to_unlock() {
    let fx = Fixture::start().await; // locked, pinentry answers pw
    fx.sm()
        .args(["set", "a=b", "--label", "x"])
        .write_stdin("v")
        .assert()
        .success();
    assert!(
        fx.pinentry_log().contains("GETPIN"),
        "set unlocked through the prompt"
    );
    fx.lock_default().await;
    fx.sm().args(["get", "a=b"]).assert().success().stdout("v");
    fx.sm()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("x"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dismissed_prompt_exits_1() {
    let fx = Fixture::start_with_pin(None).await;
    fx.sm()
        .args(["set", "a=b", "--label", "x"])
        .write_stdin("v")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("dismissed"));
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "a=b", "--label", "x"])
        .write_stdin("v")
        .assert()
        .success();
    fx.lock_default().await;
    fx.sm()
        .args(["get", "a=b"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("dismissed"));
    fx.sm()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[locked]"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interop_with_secret_tool() {
    if std::process::Command::new("secret-tool")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=interop", "--label", "from sm"])
        .write_stdin("shared")
        .assert()
        .success();
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "app", "interop"])
        .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "shared");
}

/// CRITICAL: `sm delete` must delete nothing unless every locked match could
/// be unlocked. Two collections hold a matching item; only one of them can be
/// opened with the password the prompt answers, so the daemon reports
/// `dismissed = false` while listing only the paths it actually unlocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_refuses_a_partial_unlock() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=dup", "--label", "copy in default"])
        .write_stdin("a")
        .assert()
        .success();

    // A second collection whose password is *not* the one the fake pinentry
    // answers, holding an item with the same attributes.
    let dir = fx.data_dir.path().join("secret-manager");
    let mut extra = secret_manager::vault::Vault::create(
        &dir.join("extra.vault"),
        "Extra",
        b"other-password",
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    extra
        .insert_item(
            "copy in extra",
            BTreeMap::from([("app".to_string(), "dup".to_string())]),
            b"a".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
    drop(extra);
    secret_manager::protocol::call(
        &fx.control_socket(),
        &secret_manager::protocol::Request::Reload,
    )
    .unwrap();
    fx.lock_default().await;

    fx.sm()
        .args(["delete", "app=dup"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("nothing was deleted"));

    // Both copies survive: the default one is now unlocked (its prompt was
    // answered), the other is still locked.
    fx.sm().args(["list", "app=dup"]).assert().success().stdout(
        predicate::str::contains("copy in default").and(predicate::str::contains("[locked]")),
    );
}

/// MEDIUM 1: a second matching item (which any bus client can create by
/// adding attributes to the user's own) must be announced on stderr.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_warns_when_more_than_one_item_matches() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "app=git", "--label", "github token"])
        .write_stdin("mine")
        .assert()
        .success();
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .success()
        .stdout("mine")
        .stderr("");

    // A shadowing item: same attributes plus one more, so it still matches.
    fx.sm()
        .args(["set", "app=git", "evil=1", "--label", "shadow"])
        .write_stdin("theirs")
        .assert()
        .success();
    fx.sm().args(["get", "app=git"]).assert().success().stderr(
        predicate::str::contains("warning: 2 items match").and(predicate::str::contains("--label")),
    );
    // A --label filter that narrows to one item is silent again.
    fx.sm()
        .args(["get", "app=git", "--label", "github token"])
        .assert()
        .success()
        .stdout("mine")
        .stderr("");
}

/// MEDIUM 2: stdin is capped, so `sm set < /dev/zero` cannot exhaust memory.
///
/// Every size and the expected message are derived from `MAX_SECRET`, which is
/// itself derived from the control protocol's `MAX_FRAME`. They used to be the
/// literals `1 << 20` and `"exceeds 1 MiB"`, which pinned a number the code no
/// longer had to agree with: moving `MAX_FRAME` would have made the message
/// wrong and left this test asserting the stale string. The assertions are the
/// same ones -- one byte over is refused with exit 2 and a message naming the
/// cap, exactly the cap is accepted -- just no longer spelled out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_rejects_an_oversized_secret() {
    use secret_manager::cli::MAX_SECRET;
    let too_big = predicate::str::contains(format!("exceeds {MAX_SECRET} bytes"));

    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args(["set", "big=1", "--label", "big"])
        .write_stdin(vec![b'x'; MAX_SECRET + 1])
        .assert()
        .code(2)
        .stderr(too_big.clone());
    // Exactly at the limit still works.
    fx.sm()
        .args(["set", "big=1", "--label", "big"])
        .write_stdin(vec![b'x'; MAX_SECRET])
        .assert()
        .success();
    // LOW: the trailing newline is a delimiter, not part of the secret, so it
    // must be dropped *before* the size check. `printf '%s\n'` of a 1 MiB
    // secret is a 1 MiB secret.
    let mut with_newline = vec![b'x'; MAX_SECRET];
    with_newline.push(b'\n');
    fx.sm()
        .args(["set", "big=2", "--label", "big2"])
        .write_stdin(with_newline)
        .assert()
        .success();
    fx.sm()
        .args(["get", "big=2"])
        .assert()
        .success()
        .stdout(predicate::function(|o: &[u8]| {
            o.len() == MAX_SECRET && o.iter().all(|b| *b == b'x')
        }));
    // One byte past the limit *plus* a newline is still too big.
    let mut oversized = vec![b'x'; MAX_SECRET + 1];
    oversized.push(b'\n');
    fx.sm()
        .args(["set", "big=3", "--label", "big3"])
        .write_stdin(oversized)
        .assert()
        .code(2)
        .stderr(too_big);
}

/// LOW 1: control characters in a label or an attribute value must not reach
/// the terminal, or a hostile item could erase or forge `sm list` rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_escapes_control_characters() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm()
        .args([
            "set",
            "app=x\u{1b}[31mred",
            "--label",
            "sneaky\rHIDDEN\u{1b}[2K",
        ])
        .write_stdin("v")
        .assert()
        .success();
    let out = fx
        .sm()
        .args(["list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        !text.contains('\r') && !text.contains('\u{1b}'),
        "raw control characters reached stdout: {text:?}"
    );
    assert!(
        text.contains("\\x0d"),
        "carriage return is rendered: {text:?}"
    );
    assert!(text.contains("\\x1b"), "escape is rendered: {text:?}");
    // The --json path is unchanged and still carries the real bytes.
    let json = fx
        .sm()
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed[0]["label"], "sneaky\rHIDDEN\u{1b}[2K");
}

/// `Client::connect` bounds `Connection::session()` with a timeout, and the
/// case that timeout exists for is a bus that *accepts* the connection and
/// then says nothing: an address that refuses fails immediately and never
/// reaches the guard. Asserting it at the shipped 10 s would cost 10 s of
/// wall clock, so the deadline is shortened through the `test-util` feature
/// (`SM_CONNECT_TIMEOUT_MS`), the same mechanism `KdfParams::FAST_FOR_TESTS`
/// uses. Nothing we ship enables that feature, so the shipped deadline stays
/// 10 s.
///
/// The message names the deadline it actually waited, so the expectation is
/// derived from the same override rather than spelled out: it used to assert
/// the literal "within 10 s" against a run that waited 500 ms, which is the
/// mismatch that made the message worth interpolating in the first place.
#[test]
fn a_session_bus_that_accepts_and_never_answers_is_unreachable() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    /// The deadline this run actually waits, and so the one the message must
    /// name.
    const SHORT_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("silent-bus");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();

    // The accepted stream must be *held*, not dropped: a closed connection is
    // an EOF, which is an ordinary transport error, not the hang this guards.
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        let mut held = Vec::new();
        while !worker_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        held.len()
    });

    let started = Instant::now();
    assert_cmd::Command::cargo_bin("secret-manager")
        .unwrap()
        .env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.path())
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", sock.display()),
        )
        .env(
            "SM_CONNECT_TIMEOUT_MS",
            SHORT_CONNECT_TIMEOUT.as_millis().to_string(),
        )
        .args(["get", "a=b"])
        .assert()
        // Exit 3, not 1: a script must be able to tell "the bus is not
        // answering" from "no such secret".
        .code(3)
        .stderr(predicate::str::contains(format!(
            "session bus did not answer within {SHORT_CONNECT_TIMEOUT:?}"
        )));
    let elapsed = started.elapsed();

    stop.store(true, Ordering::Relaxed);
    let accepted = worker.join().unwrap();
    assert!(accepted > 0, "the CLI never reached the listener");
    // Proof the run ended on the timeout and not on some faster transport
    // error: with the override honoured the whole command is sub-second, and
    // without it this arm would take the full ten.
    assert!(
        elapsed < Duration::from_secs(5),
        "connect did not honour the shortened deadline: {elapsed:?}"
    );
}

/// Every `sm set` resolves the `default` alias first, so a daemon that has a
/// collection but no `default` alias is the store path with nowhere to store.
/// The other fixtures all install the alias before the daemon starts, which
/// makes this arm unreachable from them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_without_a_default_alias_says_to_run_init() {
    let fx = Fixture::start_without_default_alias().await;
    // The collection itself is there and the daemon is healthy — the alias is
    // the only thing missing, so this is not a "daemon is broken" message.
    fx.sm()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("default"));

    fx.sm()
        .args(["set", "app=git", "--label", "git token"])
        .write_stdin("s3cret")
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("no default collection")
                .and(predicate::str::contains("sm init")),
        );
}

/// A stand-in for the daemon: a bus name and just enough of
/// `org.freedesktop.Secret.Service` to drive the CLI's client down paths the
/// real daemon never takes — a service that refuses DH sessions, one that
/// answers with the wrong type, one without the private batch-delete
/// interface, one whose batch delete fails.
///
/// These are not hypothetical: the CLI is `secret-tool`-compatible, so it can
/// be pointed at any implementation of the spec, and every one of these
/// behaviours is something a different (or hostile) implementation may do.
mod fake_service {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    /// A private bus with **no service activation**: the stock `--session`
    /// configuration includes the system's service directories, so a bus
    /// started that way starts the machine's *real* secret service the moment
    /// something asks for `org.freedesktop.secrets` — and these tests would
    /// then be driving the developer's own keyring. This config file lists no
    /// service directory, so an unowned name stays unowned.
    pub struct Bus {
        pub address: String,
        child: std::process::Child,
        _dir: tempfile::TempDir,
    }

    impl Bus {
        pub fn start() -> Bus {
            use std::io::BufRead;
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("bus");
            let conf = dir.path().join("bus.conf");
            std::fs::write(
                &conf,
                format!(
                    "<busconfig>\n\
                     <type>session</type>\n\
                     <listen>unix:path={}</listen>\n\
                     <auth>EXTERNAL</auth>\n\
                     <policy context=\"default\">\n\
                     <allow own=\"*\"/>\n\
                     <allow send_destination=\"*\"/>\n\
                     <allow receive_sender=\"*\"/>\n\
                     </policy>\n\
                     </busconfig>\n",
                    sock.display()
                ),
            )
            .unwrap();
            let mut child = std::process::Command::new("dbus-daemon")
                .args(["--nofork", "--nopidfile", "--print-address"])
                .arg(format!("--config-file={}", conf.display()))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("dbus-daemon must be installed");
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            Bus {
                address: line.trim().to_string(),
                child,
                _dir: dir,
            }
        }
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
    pub const BUS_NAME: &str = "org.freedesktop.secrets";

    /// What every fake object recorded, so a test can assert on what the CLI
    /// actually did rather than only on what it printed.
    #[derive(Default, Debug)]
    pub struct Log {
        /// Algorithm of every `OpenSession` call, in order.
        pub sessions: Vec<String>,
        /// Item paths passed to `Item.Delete`.
        pub deleted: Vec<String>,
        /// Item paths passed to the batch `DeleteItems`.
        pub batched: Vec<String>,
        /// Object paths passed to `Unlock`.
        pub unlocked: Vec<String>,
    }

    pub type Shared = Arc<Mutex<Log>>;

    #[derive(Clone, Copy, PartialEq)]
    pub enum Sessions {
        /// Refuse `dh` with `NotSupported`, accept `plain`: the fallback the
        /// spec requires a client to make.
        PlainOnly,
        /// Refuse every algorithm with an error that is *not* `NotSupported`.
        AllRefused,
    }

    pub struct Service {
        pub sessions: Sessions,
        /// What `SearchItems` reports as unlocked matches.
        pub found: Vec<OwnedObjectPath>,
        /// What `SearchItems` reports as *locked* matches. This fake unlocks
        /// them without a prompt, the way a service whose store was already
        /// opened (by PAM at login, say) answers.
        pub locked: Vec<OwnedObjectPath>,
        pub log: Shared,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl Service {
        async fn open_session(
            &self,
            algorithm: String,
            _input: Value<'_>,
        ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
            self.log.lock().unwrap().sessions.push(algorithm.clone());
            match self.sessions {
                Sessions::AllRefused => Err(zbus::fdo::Error::Failed("no sessions here".into())),
                Sessions::PlainOnly if algorithm != "plain" => {
                    Err(zbus::fdo::Error::NotSupported("dh refused".into()))
                }
                _ => Ok((
                    OwnedValue::try_from(Value::from("")).unwrap(),
                    OwnedObjectPath::try_from("/org/freedesktop/secrets/session/1").unwrap(),
                )),
            }
        }

        async fn search_items(
            &self,
            _attributes: HashMap<String, String>,
        ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
            (self.found.clone(), self.locked.clone())
        }

        /// Unlocks everything asked for, with no prompt: `/` is the spec's
        /// "no prompt needed" path.
        async fn unlock(
            &self,
            objects: Vec<OwnedObjectPath>,
        ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
            self.log
                .lock()
                .unwrap()
                .unlocked
                .extend(objects.iter().map(|o| o.to_string()));
            (objects, OwnedObjectPath::try_from("/").unwrap())
        }
    }

    /// A service whose `SearchItems` answers with one array where the spec
    /// says two: a well-formed D-Bus reply of the wrong type.
    pub struct WrongTypeService {
        pub log: Shared,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl WrongTypeService {
        async fn open_session(
            &self,
            algorithm: String,
            _input: Value<'_>,
        ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
            self.log.lock().unwrap().sessions.push(algorithm.clone());
            if algorithm != "plain" {
                return Err(zbus::fdo::Error::NotSupported("dh refused".into()));
            }
            Ok((
                OwnedValue::try_from(Value::from("")).unwrap(),
                OwnedObjectPath::try_from("/org/freedesktop/secrets/session/1").unwrap(),
            ))
        }

        async fn search_items(&self, _attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
            Vec::new()
        }
    }

    pub struct Item {
        pub path: String,
        pub log: Shared,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Item")]
    impl Item {
        async fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
            self.log.lock().unwrap().deleted.push(self.path.clone());
            Ok(OwnedObjectPath::try_from("/").unwrap())
        }
    }

    /// The private batch interface, on the collection object.
    pub struct Admin {
        pub fail: bool,
        pub log: Shared,
    }

    #[zbus::interface(name = "org.secret_manager.Collection1")]
    impl Admin {
        async fn delete_items(&self, items: Vec<OwnedObjectPath>) -> zbus::fdo::Result<()> {
            let mut log = self.log.lock().unwrap();
            for i in &items {
                log.batched.push(i.to_string());
            }
            if self.fail {
                return Err(zbus::fdo::Error::Failed("the vault is read-only".into()));
            }
            Ok(())
        }
    }
}

/// A CLI child pointed at `address` with its own HOME and no daemon of its
/// own. `env_clear` is deliberate — the CLI must not inherit the test
/// runner's environment — but it also drops the variable the coverage
/// profiler needs, so that one is put back explicitly (see `Fixture::sm`).
fn sm_on_bus(home: &std::path::Path, address: &str) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.env_clear()
        .envs(common::profiling_env())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env("DBUS_SESSION_BUS_ADDRESS", address);
    for key in ["LLVM_PROFILE_FILE", "LLVM_PROFILE_DIR"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd
}

/// A bus with nobody owning `org.freedesktop.secrets`: the message goes
/// through and comes back as `ServiceUnknown`, which is a different failure
/// from "there is no bus" and must still be exit 3 — a script has to be able
/// to tell "the service is not running" from "no such secret" (exit 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bus_without_the_secret_service_exits_3() {
    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();

    sm_on_bus(home.path(), &bus.address)
        .args(["get", "a=b"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "systemctl --user start secret-manager",
        ));
}

/// The spec lets a service refuse `dh`; a client that cannot fall back to
/// `plain` simply stops working against it. The fallback must be tried once,
/// with `plain`, and the command must then succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_that_refuses_dh_gets_a_plain_session() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use secret_manager::session::{ALGORITHM_DH, ALGORITHM_PLAIN};

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::PlainOnly,
                locked: Vec::new(),
                found: Vec::new(),
                log: log.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    sm_on_bus(home.path(), &bus.address)
        // A query, so this goes through `SearchItems` and not the
        // `Collections` property, which this fake does not export.
        .args(["list", "a=b"])
        .assert()
        .success()
        .stdout("");

    assert_eq!(
        log.lock().unwrap().sessions,
        [ALGORITHM_DH, ALGORITHM_PLAIN],
        "the CLI must try DH first and fall back to plain exactly once"
    );
}

/// Only `NotSupported` means "this service does not do DH". Any other error
/// from `OpenSession` is a failure of the call itself, and retrying it as
/// `plain` would silently drop the session encryption on a service that never
/// asked for that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_session_error_is_not_retried_as_plain() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use secret_manager::session::ALGORITHM_DH;

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::AllRefused,
                locked: Vec::new(),
                found: Vec::new(),
                log: log.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    sm_on_bus(home.path(), &bus.address)
        .args(["list", "a=b"])
        .assert()
        // Exit 1, not 3: the service is there and answering, so telling the
        // user to start it would send them the wrong way.
        .code(1)
        .stderr(predicate::str::contains("no sessions here"));

    assert_eq!(
        log.lock().unwrap().sessions,
        [ALGORITHM_DH],
        "a refused session must not be retried in the clear"
    );
}

/// A reply that is well-formed D-Bus but the wrong type is neither a method
/// error nor a transport failure. It must come out as a plain failure naming
/// what went wrong, not as a panic and not as exit 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reply_of_the_wrong_type_is_a_plain_failure() {
    use fake_service::{BUS_NAME, SERVICE_PATH};

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::WrongTypeService { log: log.clone() },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let out = sm_on_bus(home.path(), &bus.address)
        .args(["get", "a=b"])
        .assert()
        .code(1)
        .get_output()
        .clone();
    assert!(
        !String::from_utf8_lossy(&out.stderr).is_empty(),
        "the failure must say something"
    );
    assert!(out.stdout.is_empty(), "nothing may be printed as a secret");
}

/// A search result the CLI cannot attribute to a collection cannot be
/// batched, so it goes through `Item.Delete` one at a time — and when that
/// fails, `sm delete` must say the secret is still there rather than report a
/// deletion it did not make.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_item_outside_any_collection_is_deleted_one_at_a_time() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use zbus::zvariant::OwnedObjectPath;

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    // Not `<service>/collection/<id>/<item>`, so it belongs to no collection.
    let stray = OwnedObjectPath::try_from("/org/freedesktop/secrets/stray").unwrap();
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::PlainOnly,
                locked: Vec::new(),
                found: vec![stray.clone()],
                log: log.clone(),
            },
        )
        .unwrap()
        // Nothing is served at `stray`, so `Item.Delete` on it fails.
        .build()
        .await
        .unwrap();

    sm_on_bus(home.path(), &bus.address)
        .args(["delete", "a=b"])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("could not be deleted")
                .and(predicate::str::contains("the secret still exists")),
        );
    assert!(
        log.lock().unwrap().batched.is_empty(),
        "an unattributable path must not have been batched"
    );
}

/// A service without the private batch interface is an older build of this
/// daemon, or another implementation of the spec entirely. The CLI must fall
/// back to `Item.Delete` per item and succeed, not report the missing
/// interface as a failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_without_the_batch_interface_deletes_item_by_item() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use zbus::zvariant::OwnedObjectPath;

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    let item = "/org/freedesktop/secrets/collection/default/1";
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::PlainOnly,
                locked: Vec::new(),
                found: vec![OwnedObjectPath::try_from(item).unwrap()],
                log: log.clone(),
            },
        )
        .unwrap()
        // The item exists; the collection object it names does not, so the
        // batch call comes back as an unknown object.
        .serve_at(
            item,
            fake_service::Item {
                path: item.to_string(),
                log: log.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    sm_on_bus(home.path(), &bus.address)
        .args(["delete", "a=b"])
        .assert()
        .success();

    let log = log.lock().unwrap();
    assert_eq!(log.deleted, [item], "the fallback did not delete the item");
    assert!(log.batched.is_empty());
}

/// The batch delete is atomic: when it fails, nothing in that collection was
/// deleted. The CLI must say exactly that — and must *not* then try the items
/// one at a time, which would turn an all-or-nothing failure into a
/// half-deleted set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_batch_delete_leaves_the_set_untouched() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use zbus::zvariant::OwnedObjectPath;

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    let collection = "/org/freedesktop/secrets/collection/default";
    let item = "/org/freedesktop/secrets/collection/default/1";
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::PlainOnly,
                locked: Vec::new(),
                found: vec![OwnedObjectPath::try_from(item).unwrap()],
                log: log.clone(),
            },
        )
        .unwrap()
        .serve_at(
            collection,
            fake_service::Admin {
                fail: true,
                log: log.clone(),
            },
        )
        .unwrap()
        .serve_at(
            item,
            fake_service::Item {
                path: item.to_string(),
                log: log.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    sm_on_bus(home.path(), &bus.address)
        .args(["delete", "a=b"])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("left untouched")
                .and(predicate::str::contains("the vault is read-only")),
        );

    let log = log.lock().unwrap();
    assert_eq!(log.batched, [item], "the batch call was not made");
    assert!(
        log.deleted.is_empty(),
        "a failed atomic batch must not fall back to deleting items one by one"
    );
}

/// `sm delete` is strict: it must open every locked match before it deletes
/// anything. The refusal half of that rule is
/// `delete_refuses_a_partial_unlock`; this is the half where the unlock
/// succeeds — the collection is locked, the prompt is answered, every match is
/// accounted for, and the delete goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_unlocks_every_locked_match_before_deleting() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["set", "app=git", "--label", "git token"])
        .write_stdin("s3cret")
        .assert()
        .success();
    fx.lock_default().await;

    fx.sm().args(["delete", "app=git"]).assert().success();
    assert!(
        !secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "the delete unlocked the collection through the prompt"
    );
    fx.sm()
        .args(["get", "app=git"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no matching secret"));
}

/// A delete that both loses items and leaves a batch untouched has to report
/// both, distinguishably: the first set may still exist and is worth hunting
/// for, the second was never touched at all. The two halves are separate
/// sentences, so neither is read as the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_reports_lost_items_and_untouched_batches_separately() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use zbus::zvariant::OwnedObjectPath;

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    // One match belongs to no collection (so it is deleted one at a time, and
    // fails), one belongs to a collection whose batch delete refuses.
    let stray = "/org/freedesktop/secrets/stray";
    let collection = "/org/freedesktop/secrets/collection/default";
    let item = "/org/freedesktop/secrets/collection/default/1";
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::PlainOnly,
                locked: Vec::new(),
                found: vec![
                    OwnedObjectPath::try_from(stray).unwrap(),
                    OwnedObjectPath::try_from(item).unwrap(),
                ],
                log: log.clone(),
            },
        )
        .unwrap()
        .serve_at(
            collection,
            fake_service::Admin {
                fail: true,
                log: log.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    let out = sm_on_bus(home.path(), &bus.address)
        .args(["delete", "a=b"])
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("could not be deleted"), "{stderr:?}");
    assert!(stderr.contains("left untouched"), "{stderr:?}");
    assert!(
        stderr.contains(stray) && stderr.contains(collection),
        "the report must name both, so the user knows where to look: {stderr:?}"
    );
    // The two halves are on separate lines rather than run together.
    assert!(
        stderr.lines().count() > 2,
        "the report ran the two outcomes together: {stderr:?}"
    );
}

/// A locked match that the service opens *without* a prompt — a collection
/// already unlocked out of band, which is what PAM does at login. The CLI
/// must treat the returned paths as unlocked and carry on, not wait for a
/// prompt that is never coming.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_match_unlocked_without_a_prompt_is_still_deleted() {
    use fake_service::{BUS_NAME, SERVICE_PATH, Sessions};
    use zbus::zvariant::OwnedObjectPath;

    let bus = fake_service::Bus::start();
    let home = tempfile::tempdir().unwrap();
    let log = fake_service::Shared::default();
    let item = "/org/freedesktop/secrets/collection/default/1";
    let _conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name(BUS_NAME)
        .unwrap()
        .serve_at(
            SERVICE_PATH,
            fake_service::Service {
                sessions: Sessions::PlainOnly,
                // Reported as locked, and unlocked with no prompt object.
                locked: vec![OwnedObjectPath::try_from(item).unwrap()],
                found: Vec::new(),
                log: log.clone(),
            },
        )
        .unwrap()
        .serve_at(
            item,
            fake_service::Item {
                path: item.to_string(),
                log: log.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    sm_on_bus(home.path(), &bus.address)
        .args(["delete", "a=b"])
        .assert()
        .success();

    let log = log.lock().unwrap();
    assert_eq!(log.unlocked, [item], "the locked match was never unlocked");
    assert_eq!(log.deleted, [item], "the unlocked match was not deleted");
}
