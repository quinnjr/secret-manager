//! The lock-ordering invariant `CLAUDE.md` states, tested two ways.
//!
//! A vault save clones every item, re-encrypts the whole collection and
//! `fsync`s twice. That used to happen with the single global `ServiceState`
//! mutex held, so one `CreateItem` against a large collection stopped every
//! other bus call, every control request and the housekeeping tasks for the
//! length of the write. The fix puts each vault behind its own lock and holds
//! the state lock only for map lookups — with the rule that the two are never
//! held at once, state lock first.
//!
//! [`a_write_stuck_on_one_collection_blocks_nothing_else`] proves the
//! property at runtime without depending on any duration, and
//! [`no_source_file_acquires_a_lock_while_holding_one`] proves the rule that
//! makes it safe, by reading the source.

mod common;

use common::Fixture;
use secret_manager::dbus::proxies::{CollectionProxy, ServiceProxy};
use secret_manager::dbus::session::SecretStruct;
use secret_manager::dbus::{paths, state};
use secret_manager::session::ALGORITHM_PLAIN;
use std::collections::HashMap;
use std::time::Duration;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, Value};

/// Generous on purpose. Every `timeout` below is an "immediately, or never"
/// question: the thing it waits on is either free of the held lock or blocked
/// behind it forever. A long budget therefore costs a passing run nothing and
/// keeps a loaded machine from looking like a regression.
const NEVER: Duration = Duration::from_secs(30);

async fn collection(conn: &zbus::Connection, path: OwnedObjectPath) -> CollectionProxy<'static> {
    CollectionProxy::builder(conn)
        .path(path)
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .unwrap()
}

fn props(label: &str) -> HashMap<&'static str, Value<'static>> {
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label",
            Value::from(label.to_string()),
        ),
        (
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(HashMap::from([("k".to_string(), label.to_string())])),
        ),
    ])
}

fn plain_secret(session: &OwnedObjectPath, bytes: &[u8]) -> SecretStruct {
    SecretStruct {
        session: session.clone(),
        parameters: vec![],
        value: bytes.to_vec(),
        content_type: "text/plain".into(),
    }
}

/// A write that is stuck inside one collection must not stop anything else:
/// not a write to another collection, and not a call that needs only the
/// global state.
///
/// The stall is produced by *holding that collection's lock*, not by making a
/// save slow, so there is no duration to guess and nothing to race. A save in
/// flight holds exactly this lock and nothing else; if the daemon took the
/// state lock and then awaited a collection's — the ordering that would both
/// deadlock and reintroduce the DoS — the state lock would be held for as
/// long as this test holds the vault, and every assertion below would hang
/// instead of failing on a millisecond.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_stuck_on_one_collection_blocks_nothing_else() {
    let fx = Fixture::start().await;

    // A second collection, registered on the bus the way a real one is.
    let dir = fx.data_dir.path().join("secret-manager");
    secret_manager::vault::Vault::create(
        &dir.join("second.vault"),
        "Second",
        common::PASSWORD.as_bytes(),
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();
    fx.unlock_default().await;
    state::with_vault(&fx.daemon.state, "second", |v| {
        v.unlock(common::PASSWORD.as_bytes())
    })
    .await
    .unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap()
        .1;

    // Stand in for a save in flight on `default`.
    let default_vault = fx.daemon.state.lock().await.vault("default").unwrap();
    let held = default_vault.lock().await;

    // A write to `default` now waits for that lock, in a task of its own.
    let write = {
        let conn = conn.clone();
        let path = fx.default_collection();
        let secret = plain_secret(&session, b"blocked");
        tokio::spawn(async move {
            collection(&conn, path)
                .await
                .create_item(props("blocked"), &secret, false)
                .await
        })
    };

    // The timing assumption, asserted rather than assumed: the write really
    // is still in flight, so the checks below are being made *during* it.
    // Only ever false in the safe direction — a write that had already
    // finished would make the rest of the test prove nothing — so it cannot
    // report a regression that is not there.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !write.is_finished(),
        "timing assumption: the write on 'default' should still be waiting for \
         that collection's lock"
    );

    // A property that needs only the state lock.
    let collections = tokio::time::timeout(NEVER, service.collections())
        .await
        .expect(
            "Service.Collections needs only the state lock, which a stalled write must not hold",
        )
        .unwrap();
    assert!(collections.contains(&paths::collection("second")));

    // And a write to the *other* collection, which needs the state lock for
    // its lookup and then a different vault's lock for the save.
    let second = collection(&conn, paths::collection("second")).await;
    let (created, _) = tokio::time::timeout(
        NEVER,
        second.create_item(props("free"), &plain_secret(&session, b"free"), false),
    )
    .await
    .expect("a write to another collection must not queue behind one stalled on 'default'")
    .unwrap();
    assert!(
        created
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/second/"),
        "{created}"
    );

    // Reads on the stalled collection do queue behind it — that is the point
    // of a per-collection lock — and the write completes, durably, as soon as
    // the lock is free.
    assert!(
        !write.is_finished(),
        "timing assumption: nothing above should have released 'default'"
    );
    drop(held);
    let (item, prompt) = tokio::time::timeout(NEVER, write)
        .await
        .expect("the blocked write completes once the collection's lock is free")
        .unwrap()
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    assert!(
        item.as_str()
            .starts_with("/org/freedesktop/secrets/collection/default/"),
        "{item}"
    );
    // Answered means written: the item is in the vault, not merely queued.
    let ids = state::with_vault(&fx.daemon.state, "default", |v| v.item_ids()).await;
    assert_eq!(ids.len(), 1, "the answered write left nothing on disk");
}

/// Nothing in the daemon holds one lock while acquiring another.
///
/// This is the invariant behind the ordering rule, and it is stronger: with
/// no site ever holding two locks there is no cycle for two tasks to deadlock
/// on, whatever order they would have taken them in. It is also the one thing
/// a timing test cannot establish — a green run proves the sites the test
/// exercised were fine on that machine, not that the next edit will be — so
/// it is checked against the source instead, where it cannot flake.
///
/// The check is deliberately blunt: inside `src/dbus/` and `src/daemon.rs`, a
/// statement that binds a guard (`let g = <expr>.lock().await;`) opens a
/// region that ends at `drop(g)` or at the end of its block, and no
/// `.lock().await` may appear inside one. Temporaries — `state.lock().await
/// .touch()` — are not guards and open no region; `try_lock` is not an await
/// and cannot block on anything.
///
/// It reads *formatted* source, so it sees a method chain that `cargo fmt`
/// split across lines as one logical line. Run `cargo fmt` before trusting a
/// failure.
#[test]
fn no_source_file_acquires_a_lock_while_holding_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(root.join("src/dbus"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    files.push(root.join("src/daemon.rs"));
    files.sort();
    assert!(files.len() > 5, "the scan found almost nothing: {files:?}");

    let mut offences: Vec<String> = Vec::new();
    let mut guards_seen = 0usize;
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let name = file.strip_prefix(root).unwrap().display().to_string();
        // Held guards, as (binding name, brace depth of the block they live
        // in). Depth is what ends a region; `drop(name)` ends one early.
        let mut held: Vec<(String, usize)> = Vec::new();
        let mut depth = 0usize;
        for (logical, first_line) in logical_lines(&text) {
            let code = strip_strings_and_comments(&logical);
            // The region a guard opens starts *after* its own statement, so a
            // violation is any later `.lock().await` while `held` is not empty.
            if code.contains(".lock().await")
                && let Some((holder, _)) = held.last()
            {
                offences.push(format!(
                    "{name}:{first_line}: takes a lock while `{holder}` is still held\n    {}",
                    logical.trim()
                ));
            }
            held.retain(|(n, _)| !code.contains(&format!("drop({n})")));
            // Braces in order, so `} else {` nets out correctly and a guard
            // is released exactly where its block closes.
            for ch in code.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth = depth.saturating_sub(1);
                        held.retain(|(_, d)| *d <= depth);
                    }
                    _ => {}
                }
            }
            if is_guard_binding(&code)
                && let Some(n) = binding_name(&code)
            {
                guards_seen += 1;
                held.push((n, depth));
            }
        }
    }
    assert!(
        guards_seen >= 20,
        "the scan recognised only {guards_seen} guard bindings, so it is not \
         looking at what it thinks it is"
    );
    assert!(
        offences.is_empty(),
        "a lock is taken while another is held; see `CLAUDE.md`, \
         \"Lock order is global-then-collection, and nothing ever holds both\":\n{}",
        offences.join("\n")
    );
}

/// Physical lines joined into logical ones: a line whose first non-space
/// character is `.` or `?` continues the chain above it, which is how
/// `cargo fmt` writes `self.state.lock().await.foo()` when it does not fit.
/// Yields `(text, first physical line number)`.
fn logical_lines(text: &str) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim_start();
        if (t.starts_with('.') || t.starts_with('?'))
            && !t.starts_with("..")
            && let Some(last) = out.last_mut()
        {
            last.0.push_str(t);
            continue;
        }
        out.push((raw.to_string(), i + 1));
    }
    out
}

/// Drop `//` comments and the contents of string literals, so a brace inside
/// `format!("{id}")` or a `.lock().await` named in a doc comment is not read
/// as code. Crude but sufficient: none of these files contains a raw string
/// or an escaped quote inside a literal that would fool it.
fn strip_strings_and_comments(line: &str) -> String {
    let line = match line.find("//") {
        Some(i) if !in_string(line, i) => &line[..i],
        _ => line,
    };
    let mut out = String::with_capacity(line.len());
    let mut in_str = false;
    let mut escaped = false;
    for ch in line.chars() {
        match (in_str, ch) {
            (true, _) if escaped => escaped = false,
            (true, '\\') => escaped = true,
            (true, '"') => {
                in_str = false;
                out.push('"');
            }
            (true, _) => {}
            (false, '"') => {
                in_str = true;
                out.push('"');
            }
            (false, _) => out.push(ch),
        }
    }
    out
}

/// Whether byte offset `i` falls inside a string literal on this line.
fn in_string(line: &str, i: usize) -> bool {
    let mut in_str = false;
    let mut escaped = false;
    for (b, ch) in line.char_indices() {
        if b >= i {
            break;
        }
        match (in_str, ch) {
            (true, _) if escaped => escaped = false,
            (true, '\\') => escaped = true,
            (true, '"') => in_str = false,
            (false, '"') => in_str = true,
            _ => {}
        }
    }
    in_str
}

/// A statement that binds a lock guard: `let [mut] <name> = ....lock().await;`
/// — the `.lock().await` has to be the *end* of the statement, or what is
/// bound is whatever the chain returned next, and the guard was a temporary.
fn is_guard_binding(code: &str) -> bool {
    let t = code.trim();
    t.starts_with("let ") && t.ends_with(".lock().await;")
}

fn binding_name(code: &str) -> Option<String> {
    let t = code.trim().strip_prefix("let ")?;
    let t = t.strip_prefix("mut ").unwrap_or(t);
    let name = t.split(['=', ':', ' ']).next()?.trim();
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| name.to_string())
}
