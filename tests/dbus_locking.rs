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
    // `ServiceProxy::new` would take zbus's default `CacheProperties::Lazily`,
    // unlike every collection proxy in this file. The state-only assertion
    // below calls `collections()`; served from a property cache it would
    // answer without the daemon taking the state lock at all, and would prove
    // nothing. Not vacuous today — the first call populates the cache — but a
    // second `collections()` call, or a change in zbus's caching, would make
    // it so silently. Build it the same way as the collection proxies.
    let service = ServiceProxy::builder(&conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .unwrap();
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

/// Nothing in the daemon holds one lock while acquiring another, and nothing
/// blocks under one.
///
/// This is the invariant behind the ordering rule, and it is stronger: with
/// no site ever holding two locks there is no cycle for two tasks to deadlock
/// on, whatever order they would have taken them in. It is also the one thing
/// a timing test cannot establish — a green run proves the sites the test
/// exercised were fine on that machine, not that the next edit will be — so
/// it is checked against the source instead, where it cannot flake.
///
/// The check is deliberately blunt. Inside `src/dbus/` and `src/daemon.rs`, a
/// statement that binds a guard opens a region that ends at `drop(g)` or at
/// the end of its block, and inside a region nothing may take another lock or
/// do blocking I/O. Three things it used to miss, each of which had a live
/// site in this tree:
///
/// * **A `match` or `while let` scrutinee that locks.** A scrutinee is not a
///   terminating scope, so the guard outlives every arm. It is refused
///   outright rather than treated as a region: there is no shape of it in
///   this daemon that is not better written as a `let`, a clone and a `drop`.
/// * **Guards that are not `.lock()`.** `let coll = iface.get().await;` is a
///   zbus read guard and `let g = x.read().await;` is an async `RwLock` one;
///   both are as blocking as a mutex and neither contains the word `lock`.
/// * **Blocking I/O under a guard.** `CLAUDE.md` is explicit that phrasing
///   this rule for `.await` alone is what let the original bug through — a
///   whole-vault re-encrypt and two `fsync`s ran under the global mutex and
///   no `.await` appeared anywhere. A synchronous `sync_all` is exactly as
///   fatal as an awaited lock and must be seen as one.
/// * **A helper that is handed the state.** Regions were tracked by brace
///   depth *within one function*, and the scan does not follow calls. A
///   helper with a `st: &ServiceState` or `st: &mut ServiceState` parameter
///   can only ever be called with the guard held — that reference cannot be
///   produced any other way — yet its body sat at depth zero with an empty
///   held set, so a `vault.lock().await` or an `fsync` moved into one passed
///   silently. Such a function is now a guard region for its whole body,
///   exactly as if a guard were bound on its first line. `MutexGuard<'_,
///   ServiceState>` taken by value counts too; it is the same object.
/// * **A `&self` method on `ServiceState`.** The same rule one position
///   further in, and the position the one above structurally cannot reach: a
///   receiver has no `name: ty` form to split on. `&self` here *is*
///   `&ServiceState`, so such a method is only reachable through the guard.
///   This was a live blind spot, not a theoretical one —
///   `ServiceState::unique_collection_id` did an unbounded loop of blocking
///   `symlink_metadata` behind `&self`, wrapping a free function whose own
///   doc comment said it must run with the guard dropped. It has been
///   deleted; this rule is what stops the next one. `self` by value is not
///   included: it consumes the state and so cannot be behind a guard.
///
/// A `&Shared` parameter is deliberately *not* treated this way. [`Shared`]
/// is `Arc<Mutex<ServiceState>>` — the lock, not a guard — so a function
/// handed one is called with nothing held and locking inside it is the
/// intended pattern (`state::with_vault`, `is_unlocked_path`, `update_aliases`
/// all do it). Treating it as a region would flag the correct code and say
/// nothing about the hazard. The distinction is exactly whether the callee
/// receives the lock or the thing behind it.
///
/// It reads *formatted* source, so it sees a method chain that `cargo fmt`
/// split across lines as one logical line, and a signature `cargo fmt` split
/// over several as one signature. Run `cargo fmt` before trusting a failure.
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
    let mut state_params_seen = 0usize;
    let mut self_methods_seen = 0usize;
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let name = file.strip_prefix(root).unwrap().display().to_string();
        let found = scan(&name, &text);
        guards_seen += found.guards;
        state_params_seen += found.state_params;
        self_methods_seen += found.self_methods;
        offences.extend(found.offences);
    }
    assert!(
        guards_seen >= 20,
        "the scan recognised only {guards_seen} guard bindings, so it is not \
         looking at what it thinks it is"
    );
    // `CollectionAdmin::id` and `Collection::id` in `src/dbus/collection.rs`
    // are the live examples, joined by `daemon::reclaim_prompt` — an
    // extraction that was refused until this rule existed to watch it. If this
    // ever reads zero the helper rule has stopped matching and is proving
    // nothing.
    assert!(
        state_params_seen >= 3,
        "the scan recognised only {state_params_seen} functions taking the \
         state by reference, so that rule is no longer matching the tree"
    );
    // `ServiceState`'s own accessors — `vault`, `all_vaults`, `resolve_path`
    // and the rest. There are many; a low reading means the `impl` detection
    // has stopped matching, not that the methods went away.
    assert!(
        self_methods_seen >= 10,
        "the scan recognised only {self_methods_seen} `&self` methods on \
         `ServiceState`, so that rule is no longer matching the tree"
    );
    assert!(
        offences.is_empty(),
        "a lock is taken, or blocking work is done, while another lock is held; \
         see `CLAUDE.md`, \"Lock order is global-then-collection, and nothing \
         ever holds both\" and \"Nothing slow or blocking may happen under the \
         state mutex\":\n{}",
        offences.join("\n")
    );
}

/// The scanner, checked against source it is *supposed* to reject.
///
/// This is the most important test in the file. The scan above has already
/// been narrower than the sentence in `CLAUDE.md` that cites it: for a long
/// time it recognised only `let … = ….lock().await;`, so a `match`
/// scrutinee, a zbus `iface.get().await` guard and an `fsync` under a guard
/// all passed it silently. A matcher that quietly stops matching is worse
/// than no matcher, because the green run is read as proof. Every class the
/// scan claims to catch therefore has a synthetic offender here, and a
/// near-miss that must *not* be reported so the matcher cannot pass by
/// flagging everything.
#[test]
fn the_scan_reports_the_source_it_claims_to_reject() {
    let offending: &[(&str, &str)] = &[
        (
            "a second lock while a guard is bound",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             let v = vault.lock().await;\n    g.touch(v);\n}\n",
        ),
        (
            "a match scrutinee that locks",
            "async fn f() {\n    match self.state.lock().await.vault(id) {\n        \
             Some(v) => v.lock().await.save(),\n        None => {}\n    }\n}\n",
        ),
        (
            "a while-let scrutinee that locks",
            "async fn f() {\n    while let Some(v) = self.state.lock().await.pop() {\n        \
             v.save();\n    }\n}\n",
        ),
        (
            "an if-let scrutinee that locks",
            "async fn f() {\n    if let Some(v) = self.state.lock().await.vault(id) {\n        \
             v.save();\n    }\n}\n",
        ),
        (
            "a zbus interface guard held across a lock",
            "async fn f() {\n    let coll = iface.get().await;\n    \
             let st = coll.state().lock().await;\n    st.touch();\n}\n",
        ),
        (
            "an async RwLock read guard held across a lock",
            "async fn f() {\n    let g = self.inner.read().await;\n    \
             let st = state.lock().await;\n    st.touch();\n}\n",
        ),
        (
            "an fsync under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             file.sync_all()?;\n    drop(g);\n}\n",
        ),
        (
            "a write under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             file.write_all(&bytes)?;\n}\n",
        ),
        (
            "a std::fs call under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             std::fs::rename(&tmp, &path)?;\n}\n",
        ),
        (
            "a directory create under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             create_dir_all(&dir)?;\n}\n",
        ),
        (
            "an unlink under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             remove_file(&path)?;\n}\n",
        ),
        (
            "blocking work under a guard bound in an outer block",
            "async fn f() {\n    let g = self.state.lock().await;\n    if x {\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
        (
            "a lock taken in a helper handed `&mut ServiceState`",
            "async fn reclaim(st: &mut ServiceState, id: &str) {\n    \
             let v = st.vault(id).unwrap().lock().await;\n    v.save();\n}\n",
        ),
        (
            "blocking I/O in a helper handed `&mut ServiceState`",
            "fn reclaim(st: &mut ServiceState, path: &Path) {\n    \
             st.prompts.remove(path);\n    std::fs::remove_file(path).ok();\n}\n",
        ),
        (
            "a lock taken in a helper handed a shared `&ServiceState`",
            "async fn id(&self, st: &ServiceState) -> Result<String> {\n    \
             let v = st.vault(\"default\")?.lock().await;\n    Ok(v.label())\n}\n",
        ),
        (
            "a helper whose `&mut ServiceState` parameter `cargo fmt` wrapped",
            "async fn reclaim(\n    st: &mut ServiceState,\n    id: &str,\n) -> Result<()> {\n    \
             let v = vault.lock().await;\n    Ok(())\n}\n",
        ),
        (
            "a helper handed the guard itself, by value",
            "async fn reclaim(mut st: MutexGuard<'_, ServiceState>) {\n    \
             let v = vault.lock().await;\n}\n",
        ),
        (
            "a nested block inside a helper handed `&mut ServiceState`",
            "fn reclaim(st: &mut ServiceState) {\n    if st.dirty {\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
        // The shape `ServiceState::unique_collection_id` actually had before
        // it was deleted: an unbounded loop of blocking `symlink_metadata`,
        // reachable only through the guard, in the one position the
        // `&ServiceState`-parameter rule structurally cannot see.
        (
            "blocking I/O in a `&self` method on `ServiceState`",
            "impl ServiceState {\n    fn unique(&self, label: &str) -> String {\n        \
             for n in 1.. {\n            if self.dir.join(n).symlink_metadata().is_err() {\n \
             break;\n            }\n        }\n    }\n}\n",
        ),
        (
            "a lock taken in a `&mut self` method on `ServiceState`",
            "impl ServiceState {\n    async fn f(&mut self) {\n        \
             let v = vault.lock().await;\n    }\n}\n",
        ),
        (
            "a `&self` method on `ServiceState` reached through a trait impl",
            "impl fmt::Debug for ServiceState {\n    fn fmt(&self, f: &mut Formatter) {\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
    ];
    for (what, src) in offending {
        let found = scan("synthetic.rs", src);
        assert!(
            !found.offences.is_empty(),
            "the scan did not report {what}; it has been narrowed and no longer \
             checks what its doc comment and `CLAUDE.md` say it checks:\n{src}"
        );
    }

    // The other half: the matcher must still be a matcher. Each of these is a
    // near-miss for one of the offenders above.
    let clean: &[(&str, &str)] = &[
        (
            "a guard dropped before the next lock",
            "async fn f() {\n    let g = self.state.lock().await;\n    let a = g.arc();\n    \
             drop(g);\n    let v = a.lock().await;\n}\n",
        ),
        (
            "a guard whose block has closed",
            "async fn f() {\n    let a = {\n        let g = self.state.lock().await;\n        \
             g.arc()\n    };\n    let v = a.lock().await;\n}\n",
        ),
        (
            "a temporary, which is not a guard",
            "async fn f() {\n    self.state.lock().await.touch();\n    \
             let v = vault.lock().await;\n}\n",
        ),
        (
            "blocking I/O with no lock held at all",
            "async fn f() {\n    std::fs::rename(&tmp, &path)?;\n    file.sync_all()?;\n}\n",
        ),
        (
            "a match whose scrutinee takes no lock",
            "async fn f() {\n    match self.lookup(id) {\n        Some(v) => v.save(),\n        \
             None => {}\n    }\n}\n",
        ),
        (
            "an fsync inside the sanctioned block_in_place, under a guard",
            "async fn f() {\n    let v = vault.lock().await;\n    \
             block_in_place(|| v.save())?;\n}\n",
        ),
        (
            "a multi-line block_in_place closure under a guard",
            "async fn f() {\n    let v = vault.lock().await;\n    \
             block_in_place(|| {\n        std::fs::rename(&tmp, &path)?;\n        \
             file.sync_all()\n    })?;\n}\n",
        ),
        (
            "blocking work after the block_in_place closure has closed, with no guard",
            "async fn f() {\n    {\n        let v = vault.lock().await;\n        \
             block_in_place(|| v.save())?;\n    }\n    std::fs::rename(&a, &b)?;\n}\n",
        ),
        (
            "a try_lock, which cannot block",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             let v = vault.try_lock();\n}\n",
        ),
        (
            "a `&self` method on some other type, which is not the state",
            "impl Vault {\n    fn save(&self) {\n        file.sync_all()?;\n    }\n}\n",
        ),
        (
            "an associated function on `ServiceState` with no receiver",
            "impl ServiceState {\n    fn load(dir: &Path) -> Self {\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
        (
            "a `self`-by-value method, which cannot be behind a guard",
            "impl ServiceState {\n    fn into_parts(self) -> Parts {\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
        (
            "a free function after the `impl ServiceState` block has closed",
            "impl ServiceState {\n    fn id(&self) -> u32 {\n        0\n    }\n}\n\
             fn helper(p: &Path) {\n    file.sync_all()?;\n}\n",
        ),
        (
            "`block_in_place` inside a `&self` method on `ServiceState`",
            "impl ServiceState {\n    fn save(&self) {\n        \
             block_in_place(|| file.sync_all())?;\n    }\n}\n",
        ),
        (
            // Exactly the shape of the declined `reclaim_prompt` extraction
            // from `src/daemon.rs`: map surgery on state already held. This
            // must stay clean or the rule above forbids the extraction rather
            // than watching it.
            "a helper handed `&mut ServiceState` that only touches maps",
            "fn reclaim_prompt(st: &mut ServiceState, path: &str, id: &str) {\n    \
             st.prompts.remove(path);\n    if let Some(o) = st.owners.remove(id) {\n        \
             st.free.push(o);\n    }\n}\n",
        ),
        (
            "a helper handed `&mut ServiceState` whose blocking save is in a block_in_place",
            "fn persist(st: &mut ServiceState, f: &File) -> Result<()> {\n    \
             block_in_place(|| f.sync_all())?;\n    Ok(())\n}\n",
        ),
        (
            // `Shared` is `Arc<Mutex<ServiceState>>`: the lock, not a guard.
            // A callee handed one holds nothing, and locking is what it is for.
            "a function handed `&Shared`, which is the lock and not a guard",
            "async fn with_vault(state: &Shared, id: &str) -> Arc<Mutex<Vault>> {\n    \
             let st = state.lock().await;\n    st.vault(id).unwrap()\n}\n",
        ),
        (
            "a callback type that mentions the state, on a function handed `&Shared`",
            "pub async fn update_aliases<E>(\n    state: &Shared,\n    \
             mut edit: impl FnMut(&ServiceState, &mut BTreeMap<String, String>) -> Result<(), E>,\n\
             ) -> AliasUpdate<E> {\n    let st = state.lock().await;\n}\n",
        ),
        (
            "a lock taken after a helper's body has closed",
            "fn reclaim(st: &mut ServiceState) {\n    st.prompts.clear();\n}\n\
             async fn g() {\n    let v = vault.lock().await;\n}\n",
        ),
        (
            "the words in a comment and a string",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             // never .lock().await or sync_all() here\n    \
             log(\"x.lock().await and sync_all\");\n}\n",
        ),
    ];
    for (what, src) in clean {
        let found = scan("synthetic.rs", src);
        assert!(
            found.offences.is_empty(),
            "the scan reported {what}, which is allowed:\n{:?}",
            found.offences
        );
    }
}

struct Scan {
    offences: Vec<String>,
    guards: usize,
    /// Functions treated as a guard region because they are handed the state
    /// itself. Counted separately so the real-tree test can assert the rule is
    /// live and not matching nothing.
    state_params: usize,
    /// `&self` methods in an `impl ServiceState`, treated as a guard region
    /// for the same reason and counted for the same reason.
    self_methods: usize,
}

/// Anything that yields a guard whose lifetime is the binding's. `.lock()` is
/// the async mutex; `.read()`/`.write()` an async `RwLock`; `.get()` and
/// `.get_mut()` are zbus's `InterfaceRef`, which is an `RwLock` by another
/// name and is the one that reads as harmless.
const ACQUIRE: &[&str] = &[
    ".lock().await",
    ".read().await",
    ".write().await",
    ".get().await",
    ".get_mut().await",
];

/// Blocking calls that must never run under a guard. The rule is not about
/// `.await`: a synchronous `fsync` stops the same tasks for the same time,
/// and phrasing it for awaits alone is what let the original bug through.
const BLOCKING: &[&str] = &[
    "sync_all",
    "sync_data",
    "write_all",
    "remove_file",
    "create_dir_all",
    "std::fs::",
    "fs::rename",
    // A `stat`. One is cheap; `unique_collection_id_in` does an unbounded
    // number of them in a loop, which is the shape the rule above exists for.
    "symlink_metadata",
];

/// The sanctioned escape hatch. `CLAUDE.md` requires a vault mutation and the
/// save it triggers to run under the collection's lock, wrapped in
/// `state::block_in_place` so the `fsync`s release the async worker instead of
/// parking it. Blocking work inside one of those closures is the documented
/// pattern; blocking work under a guard *without* one is the bug this catches.
const EXEMPT: &str = "block_in_place";

fn takes_a_lock(code: &str) -> bool {
    ACQUIRE.iter().any(|a| code.contains(a))
}

/// A scrutinee holds its temporaries for the whole construct, so a lock taken
/// in one outlives every arm. Refused outright.
fn is_locking_scrutinee(code: &str) -> bool {
    let t = code.trim();
    if !takes_a_lock(t) || !t.ends_with('{') {
        return false;
    }
    t.starts_with("match ")
        || t.starts_with("while let ")
        || t.starts_with("if let ")
        || t.contains(" = match ")
        || t.contains(" = while let ")
}

fn scan(name: &str, text: &str) -> Scan {
    let mut offences: Vec<String> = Vec::new();
    let mut guards = 0usize;
    let mut state_params = 0usize;
    let mut self_methods = 0usize;
    // Brace depths at which an `impl ServiceState` block is currently open.
    let mut state_impl: Vec<usize> = Vec::new();
    // Held guards, as (binding name, brace depth of the block they live in).
    // Depth is what ends a region; `drop(name)` ends one early.
    let mut held: Vec<(String, usize)> = Vec::new();
    // Brace depths at which a `block_in_place` closure is currently open.
    let mut blocking_ok: Vec<usize> = Vec::new();
    let mut depth = 0usize;
    for (logical, first_line) in join_signatures(logical_lines(text)) {
        let code = strip_strings_and_comments(&logical);
        let mut report = |why: &str| {
            offences.push(format!(
                "{name}:{first_line}: {why}\n    {}",
                logical.trim()
            ));
        };

        if is_locking_scrutinee(&code) {
            report(
                "takes a lock in a `match`/`while let`/`if let` scrutinee, which \
                 holds the guard across every arm",
            );
        }
        // The region a guard opens starts *after* its own statement, so a
        // violation is any later acquisition while `held` is not empty.
        let exempt = !blocking_ok.is_empty() || code.contains(EXEMPT);
        if let Some((holder, _)) = held.last() {
            if takes_a_lock(&code) {
                report(&format!("takes a lock while `{holder}` is still held"));
            }
            if !exempt && let Some(op) = BLOCKING.iter().find(|b| code.contains(**b)) {
                report(&format!(
                    "does blocking work (`{op}`) while `{holder}` is still held, \
                     and not inside a `{EXEMPT}`"
                ));
            }
        }
        held.retain(|(n, _)| !code.contains(&format!("drop({n})")));
        // Braces in order, so `} else {` nets out correctly and a guard is
        // released exactly where its block closes. A `block_in_place` closure
        // that opens a block exempts everything inside it, for as long as it
        // is open.
        let opens_exemption = code.contains(EXEMPT);
        let opens_state_impl = opens_state_impl(&code);
        let entry_depth = depth;
        for ch in code.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    if opens_exemption && depth == entry_depth + 1 {
                        blocking_ok.push(entry_depth);
                    }
                    if opens_state_impl && depth == entry_depth + 1 {
                        state_impl.push(entry_depth);
                    }
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    held.retain(|(_, d)| *d <= depth);
                    blocking_ok.retain(|d| *d < depth);
                    state_impl.retain(|d| *d < depth);
                }
                _ => {}
            }
        }
        if is_guard_binding(&code)
            && let Some(n) = binding_name(&code)
        {
            guards += 1;
            held.push((n, depth));
        }
        // A function handed `&ServiceState` was called with the state guard
        // held; its whole body is inside that region. Pushed at the body's
        // depth, so it is released exactly where the body closes — the same
        // bookkeeping as a guard bound on the first line of it.
        if let Some(p) = state_param(&code) {
            state_params += 1;
            held.push((p, depth));
        }
        // The same rule one position further in. A `&self` method on
        // `ServiceState` can only be reached through the guard, because
        // `&ServiceState` cannot be produced any other way — but a receiver
        // has no `name: ty` form, so `state_param` structurally cannot see it.
        if !state_impl.is_empty() && has_self_receiver(&code) {
            self_methods += 1;
            held.push(("self".to_string(), depth));
        }
    }
    Scan {
        offences,
        guards,
        state_params,
        self_methods,
    }
}

/// Whether a line opens an inherent `impl ServiceState` block. A trait impl
/// (`impl Debug for ServiceState`) is deliberately included: its methods reach
/// the state through the same `&self`, so they are under the guard too.
fn opens_state_impl(code: &str) -> bool {
    let Some(rest) = code.trim_start().strip_prefix("impl") else {
        return false;
    };
    if !rest.starts_with(|c: char| c.is_whitespace() || c == '<') {
        return false;
    }
    // The implementing type is what follows `for` in a trait impl, and the
    // whole tail otherwise.
    let target = rest.rsplit_once(" for ").map(|(_, t)| t).unwrap_or(rest);
    let target = target.split('{').next().unwrap_or(target).trim();
    let target = target.rsplit("::").next().unwrap_or(target);
    let head = target.trim_end_matches(|c: char| c.is_whitespace());
    let head = head.split(['<', ' ']).next().unwrap_or(head);
    head == "ServiceState"
}

/// Whether a signature's first parameter is a `self` receiver taken by
/// reference. `self` by value consumes the state and cannot happen behind a
/// guard, so it is not one.
fn has_self_receiver(code: &str) -> bool {
    let Some(open) = code
        .find("fn ")
        .and_then(|i| code[i..].find('(').map(|j| i + j))
    else {
        return false;
    };
    let rest = code[open + 1..].trim_start();
    let rest = match rest.strip_prefix('&') {
        Some(r) => r.trim_start(),
        None => return false,
    };
    // `&'a self` / `&'a mut self`.
    let rest = match rest.strip_prefix('\'') {
        Some(r) => r
            .trim_start_matches(|c: char| c.is_alphanumeric() || c == '_')
            .trim_start(),
        None => rest,
    };
    let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
    let Some(tail) = rest.strip_prefix("self") else {
        return false;
    };
    !tail.starts_with(|c: char| c.is_alphanumeric() || c == '_')
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

/// A statement that binds a guard: `let [mut] <name> = ….lock().await;`, or
/// any of the other guard-producing calls in [`ACQUIRE`]. The acquisition has
/// to be the *end* of the statement, or what is bound is whatever the chain
/// returned next and the guard was a temporary.
fn is_guard_binding(code: &str) -> bool {
    let t = code.trim();
    t.starts_with("let ") && ACQUIRE.iter().any(|a| t.ends_with(&format!("{a};")))
}

fn binding_name(code: &str) -> Option<String> {
    let t = code.trim().strip_prefix("let ")?;
    let t = t.strip_prefix("mut ").unwrap_or(t);
    let name = t.split(['=', ':', ' ']).next()?.trim();
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| name.to_string())
}

/// Whether a line begins a `fn` item: an optional visibility, then any of the
/// modifier keywords, then `fn`. Deliberately anchored at the start of the
/// line so `impl FnMut(…)` in a parameter type, or `fn` inside a chain, is
/// not mistaken for one.
fn starts_fn(code: &str) -> bool {
    let mut t = code.trim();
    if let Some(rest) = t.strip_prefix("pub") {
        let rest = rest.trim_start();
        t = match rest.strip_prefix('(') {
            Some(r) => match r.find(')') {
                Some(i) => r[i + 1..].trim_start(),
                None => return false,
            },
            None => rest,
        };
    }
    loop {
        let before = t;
        for kw in ["default ", "const ", "async ", "unsafe ", "extern "] {
            if let Some(rest) = t.strip_prefix(kw) {
                t = rest.trim_start();
                // `extern "C" fn` — step over the ABI string, which the
                // stripper has already emptied to `""`.
                if kw == "extern "
                    && let Some(rest) = t.strip_prefix("\"\"")
                {
                    t = rest.trim_start();
                }
            }
        }
        if t == before {
            break;
        }
    }
    t.starts_with("fn ")
}

/// A signature is finished at the first `{` (its body) or `;` (a declaration
/// with none) that is outside the parameter list, so a `where` clause or a
/// return type on a line of its own is still part of it.
fn signature_complete(sig: &str) -> bool {
    let mut parens = 0i32;
    for ch in sig.chars() {
        match ch {
            '(' => parens += 1,
            ')' => parens -= 1,
            '{' | ';' if parens <= 0 => return true,
            _ => {}
        }
    }
    false
}

/// Join a `fn` signature that `cargo fmt` wrapped over several lines into one
/// entry, so [`state_param`] sees the whole parameter list at once. The
/// joined text is stripped of comments and string bodies first: a `//` inside
/// a wrapped parameter list would otherwise swallow the rest of the
/// signature. Character order is preserved, so brace accounting is unaffected.
fn join_signatures(lines: Vec<(String, usize)>) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    let mut pending: Option<(String, usize)> = None;
    for (text, line) in lines {
        let code = strip_strings_and_comments(&text);
        match pending.take() {
            Some((mut buf, start)) => {
                buf.push(' ');
                buf.push_str(code.trim());
                if signature_complete(&buf) {
                    out.push((buf, start));
                } else {
                    pending = Some((buf, start));
                }
            }
            None if starts_fn(&code) && !signature_complete(&code) => {
                pending = Some((code.trim_end().to_string(), line));
            }
            None => out.push((text, line)),
        }
    }
    // An unterminated signature means the file did not parse the way this
    // thinks it does; keep it rather than dropping a line silently.
    out.extend(pending);
    out
}

/// The name of the parameter through which a `fn` is handed the daemon state
/// itself — `&ServiceState`, `&mut ServiceState`, `&'a ServiceState`, or a
/// `MutexGuard<'_, ServiceState>` by value. Such a function can only be called
/// with the state guard held, so its body is a guard region.
///
/// The parameter is looked for at the top level of the parameter list only.
/// `update_aliases` takes `edit: impl FnMut(&ServiceState, …)` — a *callback*
/// type mentioning the state, on a function that is handed `&Shared` and does
/// the locking itself. Nesting is what tells the two apart, so a plain
/// substring match over the signature would be wrong.
fn state_param(code: &str) -> Option<String> {
    let t = code.trim();
    // No body, no region: a trait declaration ends at `;`.
    if !starts_fn(t) || !t.ends_with('{') {
        return None;
    }
    // The parameter list's `(`, which is the first one outside the generic
    // parameters: `fn f<F: Fn(&ServiceState)>(state: &Shared)` has two.
    let mut angles = 0i32;
    let mut prev = ' ';
    let open = t
        .char_indices()
        .find(|&(_, ch)| {
            let hit = ch == '(' && angles == 0;
            match ch {
                '<' => angles += 1,
                '>' if prev != '-' => angles -= 1,
                _ => {}
            }
            prev = ch;
            hit
        })?
        .0;

    let mut parens = 0i32;
    let mut brackets = 0i32;
    let mut arg = String::new();
    let mut args: Vec<String> = Vec::new();
    angles = 0;
    prev = ' ';
    for ch in t[open..].chars() {
        let top = parens == 1 && angles == 0 && brackets == 0;
        match ch {
            '(' => {
                parens += 1;
                if parens > 1 {
                    arg.push(ch);
                }
            }
            ')' => {
                parens -= 1;
                if parens == 0 {
                    args.push(std::mem::take(&mut arg));
                    break;
                }
                arg.push(ch);
            }
            ',' if top => args.push(std::mem::take(&mut arg)),
            _ => {
                match ch {
                    '<' => angles += 1,
                    // `->` is not a closing angle bracket.
                    '>' if prev != '-' => angles -= 1,
                    '[' => brackets += 1,
                    ']' => brackets -= 1,
                    _ => {}
                }
                arg.push(ch);
            }
        }
        prev = ch;
    }
    args.into_iter().find_map(|a| {
        let (name, ty) = a.split_once(':')?;
        let name = name.trim();
        let ty = ty.trim();
        is_state_ref(ty).then(|| format!("{name}: {ty}"))
    })
}

/// Whether a parameter type is a borrow of, or a guard over, `ServiceState`.
/// A `&Shared` is neither: it is `Arc<Mutex<ServiceState>>`, the lock itself,
/// so a callee holding one holds nothing.
fn is_state_ref(ty: &str) -> bool {
    if ty.contains("MutexGuard") {
        return ty.contains("ServiceState");
    }
    let Some(rest) = ty.strip_prefix('&') else {
        return false;
    };
    let rest = rest.trim_start();
    // An explicit lifetime, `&'a ServiceState`.
    let rest = match rest.strip_prefix('\'') {
        Some(r) => r.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_'),
        None => rest,
    };
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
    let rest = rest.strip_prefix("state::").unwrap_or(rest);
    let Some(tail) = rest.strip_prefix("ServiceState") else {
        return false;
    };
    !tail.starts_with(|c: char| c.is_alphanumeric() || c == '_')
}
