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
        value: bytes.to_vec().into(),
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

    // The gate is the hand-held collection lock above, not the clock: a write
    // that needs `default` cannot finish while `held` lives, so there is no
    // duration to wait out and nothing to race. The only way `is_finished`
    // is true here is a write that failed fast — a broken setup — or a daemon
    // that never took the lock at all, and either must fail loudly rather
    // than let every assertion below pass vacuously. The calls below, each
    // with a thirty-second budget, give a live write every chance to reach
    // the lock on a loaded machine.
    assert!(
        !write.is_finished(),
        "the write on 'default' finished while its collection's lock was held: \
         either the setup is broken or the daemon no longer takes the lock"
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

/// The source the scan reads: every `.rs` under `src/dbus/` and `src/vault/`,
/// plus `src/daemon.rs` and `src/kdf.rs`.
///
/// `src/vault/` is in the set not because the lock rules are about it, but
/// because the blocking work is: every `Vault` mutator ends in `save`'s
/// `write_all`/`sync_all`/`rename`, and `change_password`, `unlock`,
/// `verify_password` and `create` run Argon2 as well. Parsed, those are call
/// edges the graph follows toward the real blocking call. `src/kdf.rs` comes
/// along so the derivation path is whole. See
/// `the_scan_reaches_the_vaults_own_blocking_work`.
///
/// Parsing them did not make [`BLOCKING_METHODS`] redundant, which is what
/// deleting the mutators from it assumed. The graph reaches
/// `Vault::update_item` and stops one call short of the `fsync`, because
/// `Vault::save` is `self.save_with(write_atomic)` and `save_with` publishes
/// through `publish(&path, &bytes)` — a parameter, not a path, and a
/// higher-order edge a signature-only view cannot draw. The list is back, as a
/// backstop rather than as the coverage: the graph is what reaches whatever a
/// future edit writes, and the list is what makes a rename unable to drop
/// coverage silently. `the_scan_catches_a_vault_write_at_a_real_call_site`
/// fails if either half goes.
fn production_files() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths: Vec<std::path::PathBuf> = ["src/dbus", "src/vault"]
        .iter()
        .flat_map(|dir| std::fs::read_dir(root.join(dir)).unwrap())
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    paths.push(root.join("src/daemon.rs"));
    paths.push(root.join("src/kdf.rs"));
    paths.sort();
    assert!(paths.len() > 5, "the scan found almost nothing: {paths:?}");
    paths
        .iter()
        .map(|p| {
            (
                p.strip_prefix(root).unwrap().display().to_string(),
                std::fs::read_to_string(p).unwrap(),
            )
        })
        .collect()
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
/// The check parses `src/dbus/` and `src/daemon.rs` with `syn` and answers
/// one question by **reachability**: can this statement run while a lock is
/// held? Guard regions are seeded from what genuinely holds the state —
///
/// * a `let`-bound `….lock().await` (or `.read()`, `.write()`, zbus's
///   `.get()`/`.get_mut()`, which are `RwLock`s by another name and are the
///   ones that read as harmless), for as long as its binding lives — and the
///   binding is *typed*, from what the acquisition is a lock over, which is
///   what makes `let mut vault = vault.lock().await; vault.update_item(…)`
///   resolve into `src/vault/` at all;
/// * a parameter of type `&ServiceState`, `&mut ServiceState` or
///   `MutexGuard<'_, ServiceState>`, which cannot be produced any other way,
///   so the whole body is inside the caller's region;
/// * the body of a closure passed to a callee that invokes it under a guard.
///   `state::update_aliases` runs its `edit` argument with the state guard
///   held, so the closure written at the *call site* is as much under the
///   guard as `update_aliases`'s own body.
///
/// — and then **propagated along call edges** to a fixed point. That last
/// part is what makes the rules hold. Every rule here used to be defeated by
/// moving the offending line one call deeper, and that was not hypothetical:
/// the method whose deletion motivated this rule, `unique_collection_id`, had
/// the one-line body `unique_collection_id_in(&self.vault_dir, …)`. Nothing
/// in it blocked; everything it called did.
///
/// A `&self`/`&mut self` receiver in an `impl ServiceState` is `&ServiceState`
/// one position further in, and is a seed on the same terms: holding `&self`
/// on the state *is* holding the guard, so the whole body is a region and it
/// is entered whether or not this scan can see a caller. There was for a
/// while one method in the tree that made the premise false —
/// `ServiceState::load_vaults`, which fused the blocking directory scan to
/// the pure merge and which `src/daemon.rs` called on the owned value one
/// line before the `Mutex` existed — and the seed was softened to a
/// reachability question to accommodate it. That method is gone: startup
/// calls the free `scan_vault_dir` and then `merge_scan`, exactly as
/// `Request::Reload` does. So the seed is unconditional again, which is the
/// stronger rule: a blocking receiver method is reported the moment it is
/// written, rather than when someone first gives it a guarded caller. See
/// [`entry_points`], and [`dead_and_dangerous`] for the rule that still
/// covers a method with no caller at all — the shape both methods this scan
/// was written from were in.
///
/// A `match`/`while let`/`if let`/`for` scrutinee that locks is refused
/// outright rather than modelled: a scrutinee is not a terminating scope, so
/// the guard outlives every arm, and there is no shape of it in this daemon
/// that is not better written as a `let`, a clone and a `drop`. That includes
/// a **let-chain** — `if let Some(x) = a.lock().await.f() && cond`, which
/// parses as an `Expr::Binary` and used to walk straight past a rule that
/// matched only a bare `Expr::Let`. See [`let_chain_locks`].
///
/// Under the **state** guard the rule about blocking work covers `.await` as
/// well as a synchronous call, which is what `CLAUDE.md` has always said and
/// what only half of was ever checked: a pinentry Assuan round trip, a
/// `SignalEmitter` await, an `object_server().at(…)`, a `JoinHandle`, a
/// control-socket read. Under a *collection's* lock an `.await` is ordinary
/// and is not reported.
///
/// Which of the two locks an acquisition takes is answered by the receiver's
/// **type** where the scan has one, and only otherwise by its name. Naming
/// alone was a hole with a direction: a state lock reached through a binding
/// not called `state`/`st`/`shared` classified as a collection lock, which
/// then *permits* `block_in_place` — the one construct that is itself an
/// offence under the state guard. See [`Walk::guard_of`].
///
/// A `&Shared` parameter is deliberately *not* a region. [`Shared`] is
/// `Arc<Mutex<ServiceState>>` — the lock, not a guard — so a function handed
/// one is called with nothing held and locking inside it is the intended
/// pattern (`state::with_vault`, `update_aliases`). The distinction is
/// exactly whether the callee receives the lock or the thing behind it, and
/// `syn` sees it structurally: `edit: impl FnMut(&ServiceState, …)` is a
/// callback *type* mentioning the state, not a borrow of it.
///
/// Calls are resolved by name, because `syn` has no type inference. That is
/// the conservative direction — every definition with a matching name is
/// followed — and an offence reached through an ambiguous name says so in its
/// call path instead of quietly picking one.
#[test]
fn no_source_file_acquires_a_lock_while_holding_one() {
    let files = production_files();
    let found = scan_files(&files);

    // Canaries. Each is a floor with room above it, and none pins the
    // existence of one particular function: the predecessor's canary was
    // `state_params >= 3` against exactly three call sites, so re-inlining
    // any one of them would have failed with a message blaming the matcher
    // for something the matcher had got right.
    //
    // Every one of them counts **production** definitions only. They used to
    // filter `reg.defs` without `!d.in_test` while `entry_points` correctly
    // skipped test roots, so a refactor that moved production code out from
    // under the scan could have left every floor satisfied by
    // `src/dbus/state.rs`'s own `#[cfg(test)]` fixtures — which build states
    // and lock vaults by hand — with the assertion message asserting the
    // opposite of what it had measured. Filtering them cost 156 of 418
    // "functions" and 3 of 68 guard bindings; the seeds were production-only
    // already, which is luck rather than design. Current readings, from which
    // these floors are derived: 262 functions, 65 guard bindings, 18 seeds,
    // 15 receiver seeds, 68 guarded functions, 792 guarded call sites.
    assert!(
        found.functions >= 200,
        "the scan parsed only {} functions out of {} files, so it is not looking \
         at what it thinks it is",
        found.functions,
        files.len()
    );
    assert!(
        found.guard_bindings >= 45,
        "the scan recognised only {} `let`-bound guards, so the acquisition \
         rule has stopped matching the tree",
        found.guard_bindings
    );
    assert!(
        found.seeds >= 14,
        "the scan recognised only {} functions whose signature puts their whole \
         body under the state guard — a `&ServiceState`/`MutexGuard` parameter \
         or a `&self` receiver on `ServiceState` — so that rule is no longer \
         matching the tree",
        found.seeds
    );
    // Receiver seeds specifically. These are the population the
    // dead-and-dangerous rule ranges over: a `&self` method on the state that
    // no production caller reaches is checked *because* it has no caller. If
    // this reads zero the rule has nothing to range over and both deletions it
    // encodes could happen again unnoticed.
    assert!(
        found.receiver_seeds >= 12,
        "the scan recognised only {} `&self`/`&mut self` methods on \
         `ServiceState`, so neither the receiver seeding nor the \
         dead-and-dangerous rule is looking at this tree",
        found.receiver_seeds
    );
    // The call graph specifically. If this reads zero the propagation is dead
    // and every rule above is back to being defeatable by one `fn` boundary,
    // which is the failure mode that motivated the rewrite.
    assert!(
        found.guarded_fns >= 45 && found.guarded_calls >= 500,
        "the scan reached only {} functions and {} call sites with a lock held, \
         so the call graph is not being walked and every rule here is one \
         delegation away from proving nothing",
        found.guarded_fns,
        found.guarded_calls
    );

    assert!(
        found.offences.is_empty(),
        "a lock is taken, or blocking work is done, while another lock is held; \
         see `CLAUDE.md`, \"Lock order is global-then-collection, and nothing \
         ever holds both\" and \"Nothing slow or blocking may happen under the \
         state mutex\":\n{}",
        found.offences.join("\n")
    );
}

/// The scan reaches the vault's own blocking work, through the call graph and
/// not through a list of names.
///
/// This is the verification the widened path set needs, and the synthetic
/// cases in [`the_scan_reports_the_source_it_claims_to_reject`] cannot give
/// it: each of those is scanned in isolation and carries the definition it
/// delegates to, so it proves the graph walk and says nothing about which
/// files are read. Here the offender is one function appended to the *real*
/// tree, calling a real `Vault` method that is defined in a file the scan
/// used to skip.
///
/// `change_password` is the case the old name list missed. It was not on it
/// — `import_items`, `insert_item`, `delete_items`, `set_label` and the
/// unreachable `save` were — so the same guard region that reported
/// `vault.import_items(batch)` reported *nothing* for a call that derives two
/// Argon2 keys, re-encrypts the whole collection and `fsync`s twice under the
/// global mutex. Revert either half of the fix — drop `src/vault` from
/// [`production_files`], or drop `derive_key` from [`BLOCKING_FNS`] — and the
/// corresponding case here goes green with the source unchanged.
#[test]
fn the_scan_reaches_the_vaults_own_blocking_work() {
    // `Vault::from_a_fixture` does not exist, and that is the point: the
    // scan types the local from the path in its initialiser, so `v` is a
    // `Vault` and `v.change_password(…)` resolves into `src/vault/store.rs`,
    // while the initialiser itself draws no edge and cannot be what the
    // offence is reported for.
    let cases: &[(&str, &str, &str)] = &[
        (
            "a whole-vault re-encrypt under the state guard",
            "async fn offender(state: &Shared) {\n    let st = state.lock().await;\n    \
             let mut v = Vault::from_a_fixture();\n    \
             v.change_password(old, new, kdf).unwrap();\n}\n",
            "Vault::change_password",
        ),
        (
            "an unlock under the state guard",
            "async fn offender(state: &Shared) {\n    let st = state.lock().await;\n    \
             let mut v = Vault::from_a_fixture();\n    v.unlock(password).unwrap();\n}\n",
            "Vault::unlock",
        ),
        (
            "a direct Argon2 derivation under the state guard",
            "async fn offender(state: &Shared) {\n    let st = state.lock().await;\n    \
             let key = crypto::derive_key(&password, &salt, kdf).unwrap();\n}\n",
            "offender",
        ),
    ];
    for (what, src, expect_in_path) in cases {
        let mut files = production_files();
        files.push(("synthetic.rs".to_string(), (*src).to_string()));
        let found = scan_files(&files);
        let reported: Vec<&String> = found
            .offences
            .iter()
            .filter(|o| o.contains(expect_in_path))
            .collect();
        assert!(
            !reported.is_empty(),
            "the scan did not report {what}: no offence names `{expect_in_path}`, so \
             the blocking work it does is outside what the scan can see:\n{}",
            found.offences.join("\n")
        );
    }
}

/// A vault write at a **real call site, in the shape the daemon actually
/// writes it**, is reported.
///
/// This is the test the hole was hiding behind. `src/dbus/item.rs` writes
///
/// ```ignore
/// let mut vault = vault.lock().await;
/// block_in_place(|| vault.update_item(&self.id, f))
/// ```
///
/// — a receiver that is a *guard*, not a local typed by its initialiser.
/// `visit_local` refused to type a binding whose initialiser was an
/// acquisition, so `vault` had no type, `Registry::resolve` dropped every
/// method call on it, and nothing was ever followed into `src/vault/`. Delete
/// the `block_in_place` from that line — a whole-vault re-encrypt and two
/// `fsync`s, on the async worker — and the whole file passed, four of four.
/// The three synthetic offenders that stood in for this passed because they
/// were written `let mut owned = Vault::open(p)?;`, a shape that appears
/// nowhere in `src/dbus/`.
///
/// Both halves of the repair are pinned here, and they are separate
/// instruments:
///
/// * `sweep_dir_now` is not on any list. It is reported only because the
///   guard binding is typed from its acquisition's receiver, so
///   `Vault::sweep_dir_now` resolves and the graph walks on to
///   `sweep_temp_files`'s `std::fs::read_dir`. Revert the guard-binding
///   typing in [`Walk::visit_local`] and this case goes green.
/// * `update_item` is on [`BLOCKING_METHODS`]. It is reported by name because
///   the graph *cannot* reach its `fsync`: `Vault::save` is
///   `self.save_with(write_atomic)` and `save_with` publishes through
///   `publish(&path, &bytes)`, a parameter rather than a path, which a
///   signature-only view cannot follow. Empty the mutator half of
///   `BLOCKING_METHODS` and this case goes green.
///
/// Neither instrument covers the other. That is why both are here.
#[test]
fn the_scan_catches_a_vault_write_at_a_real_call_site() {
    // `Item::vault` is the real `src/dbus/item.rs` helper returning
    // `Option<VaultRef>`; the binding names are the real ones, shadowing
    // included, because the shadowing is part of the shape that broke.
    let cases: &[(&str, &str, &str)] = &[
        (
            "a graph-only blocking `Vault` method under a guard receiver",
            "async fn offender(item: &Item) {\n    \
             let vault = item.vault().await.unwrap();\n    \
             let mut vault = vault.lock().await;\n    \
             vault.sweep_dir_now();\n}\n",
            "Vault::sweep_dir_now",
        ),
        (
            "a named `Vault` mutator under a guard receiver",
            "async fn offender(item: &Item) {\n    \
             let vault = item.vault().await.unwrap();\n    \
             let mut vault = vault.lock().await;\n    \
             vault.update_item(id, f).ok();\n}\n",
            "update_item",
        ),
    ];
    for (what, src, expect_in_offence) in cases {
        let mut files = production_files();
        files.push(("synthetic.rs".to_string(), (*src).to_string()));
        let found = scan_files(&files);
        assert!(
            found.offences.iter().any(|o| o.contains(expect_in_offence)),
            "the scan did not report {what}: no offence names `{expect_in_offence}`, so a \
             vault write through the receiver every `src/dbus/` write actually uses is \
             still invisible:\n{}",
            found.offences.join("\n")
        );
    }

    // And the near-miss, at the same real call site: wrapped in the sanctioned
    // `block_in_place` under the collection's lock, which is how
    // `src/dbus/item.rs` is written today. The rule must watch that shape,
    // not forbid it.
    let mut files = production_files();
    files.push((
        "synthetic.rs".to_string(),
        "async fn allowed(item: &Item) {\n    \
         let vault = item.vault().await.unwrap();\n    \
         let mut vault = vault.lock().await;\n    \
         block_in_place(|| vault.update_item(id, f)).ok();\n}\n"
            .to_string(),
    ));
    let found = scan_files(&files);
    assert!(
        !found.offences.iter().any(|o| o.contains("synthetic.rs")),
        "the scan reported the sanctioned shape — a vault mutator inside \
         `block_in_place` under a collection's lock — which `CLAUDE.md` requires:\n{}",
        found.offences.join("\n")
    );
}

/// The scanner, checked against source it is *supposed* to reject.
///
/// This is the most important test in the file. The scan above has repeatedly
/// been narrower than the sentence in `CLAUDE.md` that cites it, and a
/// matcher that quietly stops matching is worse than no matcher, because the
/// green run is read as proof. Every class the scan claims to catch therefore
/// has a synthetic offender here, and a near-miss that must *not* be reported
/// so the matcher cannot pass by flagging everything.
///
/// The cases marked "regression" below are the ones the hand-rolled lexer
/// this replaced got wrong. Each of them was green against source that
/// violates the rule.
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
            "a for-loop iterator that locks",
            "async fn f() {\n    for v in self.state.lock().await.all_vaults() {\n        \
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
        // ---- The vault mutators, through the call graph. -----------------
        // These used to be caught by name, from a hand-maintained list, because
        // `src/vault/` was outside the parsed set. It is inside it now, so each
        // of these carries the definition it delegates to and is reported for
        // the reason the real tree reports it: the edge reaches the `fsync`.
        (
            "a vault batch import under the state guard",
            "async fn f(state: &Shared, p: &Path) {\n    let st = state.lock().await;\n    \
             let mut v = Vault::open(p)?;\n    v.import_items(batch)?;\n}\n\
             impl Vault {\n    fn import_items(&mut self, items: Vec<ImportItem>) -> Result<()> {\n        \
             self.save()\n    }\n    fn save(&mut self) -> Result<()> {\n        \
             file.write_all(&bytes)?;\n        file.sync_all()\n    }\n}\n",
        ),
        (
            "a vault save under the state guard",
            "async fn f(state: &Shared, p: &Path) {\n    let st = state.lock().await;\n    \
             let mut v = Vault::open(p)?;\n    v.save()?;\n}\n\
             impl Vault {\n    fn save(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        (
            "a vault mutator under a collection lock, outside a block_in_place",
            "async fn f(p: &Path) {\n    let mut v = vault.lock().await;\n    \
             let mut owned = Vault::open(p)?;\n    \
             owned.insert_item(label, attrs, secret, ct, false)?;\n}\n\
             impl Vault {\n    fn insert_item(&mut self, l: &str, a: Attrs, s: Vec<u8>, c: &str, r: bool) -> Result<()> {\n        \
             self.save()\n    }\n    fn save(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        // ---- Argon2. -----------------------------------------------------
        // `CLAUDE.md`: "Never run Argon2 under the state mutex". The rule had
        // no case here at all, and the name list it relied on omitted every
        // method that derives — swap `import_items` for `change_password` in
        // the case above and the scan reported *zero* offences while two
        // arenas, a whole-vault re-encrypt and two `fsync`s ran under the
        // global mutex.
        (
            "a whole-vault re-encrypt under the state guard",
            "async fn f(state: &Shared, p: &Path) {\n    let st = state.lock().await;\n    \
             let mut v = Vault::open(p)?;\n    v.change_password(old, new, kdf)?;\n}\n\
             impl Vault {\n    fn change_password(&mut self, old: &[u8], new: &[u8], kdf: KdfParams) -> Result<()> {\n        \
             let key = crypto::derive_key(old, &self.salt, kdf)?;\n        \
             self.save()\n    }\n    fn save(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        (
            "a direct Argon2 derivation under the state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let key = crypto::derive_key(&password, &salt, kdf)?;\n}\n",
        ),
        (
            "an Argon2 derivation one `fn` deeper, under the state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let key = unlock_key(&password, &salt)?;\n}\n\
             fn unlock_key(password: &[u8], salt: &[u8; 16]) -> Result<Key> {\n    \
             crypto::derive_key(password, salt, KdfParams::default())\n}\n",
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
            "a lock taken in a method handed a shared `&ServiceState`",
            "impl CollectionAdmin {\n    async fn id(&self, st: &ServiceState) -> Result<String> {\n        \
             let v = st.vault(\"default\")?.lock().await;\n        Ok(v.label())\n    }\n}\n",
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
        // ---- The semantic correction. ------------------------------------
        // `block_in_place` releases the async worker; it never releases a
        // mutex. `CLAUDE.md` sanctions it for the save a *collection's* lock
        // protects and forbids blocking work under the *state* mutex outright,
        // and `src/dbus/state.rs`'s own sibling scanner lists `block_in_place(`
        // among the blocking calls. The previous version of this file blessed
        // it inside a `&self` method on `ServiceState`, which is exactly
        // backwards.
        (
            "`block_in_place` inside a `&self` method on `ServiceState`",
            "impl ServiceState {\n    fn save(&self) {\n        \
             block_in_place(|| file.sync_all())?;\n    }\n}\n",
        ),
        (
            "a helper handed `&mut ServiceState` whose blocking save is in a block_in_place",
            "fn persist(st: &mut ServiceState, f: &File) -> Result<()> {\n    \
             block_in_place(|| f.sync_all())?;\n    Ok(())\n}\n",
        ),
        (
            "`block_in_place` under a `let`-bound state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             block_in_place(|| save_it(&st))?;\n}\n",
        ),
        // ---- Regressions: each of these was green under the hand-rolled
        // ---- lexer this replaced.
        (
            // The `//` stripper spliced a `.`-continuation onto the comment
            // line above it and then threw the whole joined line away. Live at
            // `src/daemon.rs:187` (a five-call builder chain) and at
            // `src/dbus/collection.rs:394`, where it also swallowed the `{`
            // the chain opened and desynchronised the brace counter.
            "regression: blocking work in a chain continued below a comment",
            "async fn f() {\n    let g = self.state.lock().await;\n    file\n        \
             .try_clone()?\n        // a comment inside the chain\n        \
             .sync_all()?;\n}\n",
        ),
        (
            // The same splice, one step worse: at `src/dbus/collection.rs:394`
            // the discarded continuation was `.ok_or_else(|| {`, so its `{`
            // went with it and every brace count after that point was one
            // short — which released guards early for the rest of the file.
            "regression: a guard released early by a `{` lost to a spliced comment",
            "async fn f() {\n    let g = self.state.lock().await;\n    let v = g\n        \
             .vault(id)\n        // a comment inside the chain\n        \
             .ok_or_else(|| {\n            Error::NoSuchObject\n        })?;\n    \
             file.sync_all()?;\n}\n",
        ),
        (
            // No char-literal handling: `'\"'` opened a phantom string and
            // `'}'` was counted as a real brace, so the guard was released
            // early and everything after it read as unlocked. Live at
            // `src/dbus/prompt.rs:187` and `src/dbus/state.rs:1536`.
            "regression: blocking work after a char literal holding a brace or a quote",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             let quote = '\"';\n    let close = '}';\n    file.sync_all()?;\n}\n",
        ),
        (
            // Only the *first* `//` was inspected, and angle brackets were not
            // tracked when looking for a receiver, so a generic parameter list
            // hid the `&self`.
            "regression: blocking I/O in a `&self` method whose generics contain a `(`",
            "impl ServiceState {\n    fn each<F: FnMut(&Vault)>(&self, f: F) {\n        \
             file.sync_all().ok();\n    }\n}\n",
        ),
        (
            // `opens_state_impl` only ever looked at a line that also carried
            // the `{`, so a wrapped `impl` header disabled the rule for the
            // whole block.
            "regression: blocking I/O in a `&self` method under a wrapped `impl` header",
            "impl ServiceState\nwhere\n    Self: Sized,\n{\n    fn f(&self) {\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
        (
            // The region was pushed at post-brace depth, so a body `cargo fmt`
            // wrote on one line never saw its own contents.
            "regression: blocking I/O in a one-line `&self` method body",
            "impl ServiceState {\n    fn touch(&mut self) { file.sync_all().ok(); }\n}\n",
        ),
        (
            // The region was pushed under the literal name `self`, so
            // `drop(self)` — a legal no-op on a `&self` receiver — ended it.
            "regression: blocking I/O after `drop(self)` in a `&self` method",
            "impl ServiceState {\n    fn f(&self) {\n        drop(self);\n        \
             file.sync_all().ok();\n    }\n}\n",
        ),
        (
            // The one that matters. `ServiceState::unique_collection_id` was
            // `unique_collection_id_in(&self.vault_dir, &self.loaded_ids(),
            // label)` — one line, no blocking token — and the rule written to
            // catch it reported nothing. This is that exact shape, not an
            // inlined loop.
            "regression: a one-line `&self` method delegating to a blocking free function",
            "impl ServiceState {\n    fn unique_collection_id(&self, label: &str) -> String {\n        \
             unique_collection_id_in(&self.vault_dir, &self.loaded_ids(), label)\n    }\n}\n\
             fn unique_collection_id_in(dir: &Path, ids: &Ids, label: &str) -> String {\n    \
             for n in 1.. {\n        if dir.join(n).symlink_metadata().is_err() {\n            \
             break;\n        }\n    }\n    String::new()\n}\n",
        ),
        (
            "regression: a helper handed `&mut ServiceState` delegating to a blocking free function",
            "fn reload(st: &mut ServiceState) {\n    let scan = rescan(&st.vault_dir);\n    \
             st.merge(scan);\n}\n\
             fn rescan(dir: &Path) -> Scan {\n    std::fs::create_dir_all(dir).ok();\n    \
             Scan::default()\n}\n",
        ),
        (
            // Closures passed *into* a guard region were unwatched: the callee
            // invokes them with the state held, but the body is written at the
            // call site, which the scan read with nothing held.
            "regression: a closure invoked by the callee under the state guard",
            "async fn update_aliases<E>(\n    state: &Shared,\n    \
             mut edit: impl FnMut(&ServiceState) -> Result<(), E>,\n) {\n    \
             let st = state.lock().await;\n    edit(&st).ok();\n}\n\
             async fn caller(state: &Shared) {\n    \
             update_aliases(state, |st| {\n        \
             std::fs::remove_file(st.path())?;\n        Ok(())\n    })\n    .await;\n}\n",
        ),
        // ---- Receiver regions reached through the call graph. -------------
        // The seed catches these on its own now, but the call graph must keep
        // carrying the guard into them too: these are the paths by which a
        // *non*-receiver region reaches a receiver one, and they are what a
        // method-resolution regression would break first.
        (
            "a `&self` method on `ServiceState` reached from a `let`-bound state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             st.persist();\n}\n\
             impl ServiceState {\n    fn persist(&self) {\n        \
             std::fs::create_dir_all(&self.dir).ok();\n    }\n}\n",
        ),
        (
            "a `&self` method on `ServiceState` reached from a helper handed `&ServiceState`",
            "fn helper(st: &ServiceState) {\n    st.persist();\n}\n\
             impl ServiceState {\n    fn persist(&self) {\n        \
             std::fs::create_dir_all(&self.dir).ok();\n    }\n}\n",
        ),
        // Dead and dangerous: the shape of both deletions. The seed reports
        // the body either way; what this rule adds is the diagnosis, because
        // "nothing calls it" reads as a defence and is not one for a method
        // whose only possible caller holds the guard.
        (
            "a blocking `&self` method on `ServiceState` that nothing calls",
            "impl ServiceState {\n    fn save_aliases(&self) -> Result<()> {\n        \
             save_aliases_to(&self.vault_dir, self.table())\n    }\n}\n\
             fn save_aliases_to(dir: &Path, t: &Table) -> Result<()> {\n    \
             std::fs::create_dir_all(dir)?;\n    f.sync_all()\n}\n",
        ),
        (
            "a blocking `&self` method on `ServiceState` kept alive only by its own tests",
            "impl ServiceState {\n    fn save_aliases(&self) -> Result<()> {\n        \
             std::fs::create_dir_all(&self.dir)\n    }\n}\n\
             #[cfg(test)]\nmod tests {\n    #[test]\n    fn it_refuses() {\n        \
             assert!(st.save_aliases().is_err());\n    }\n}\n",
        ),
        (
            // What pins the local type inference. `syn` infers nothing, so a
            // call on a local receiver resolves only where the initialiser
            // names the type. Without it `v.persist()` is a call on an
            // unknown receiver, is not followed, and the blocking body one
            // `fn` deeper goes unreported — the delegation hole again, in the
            // one place a type annotation is the only thing that closes it.
            "a method on a local typed by its initialiser, called under a guard",
            "async fn f(state: &Shared, path: &Path) -> Result<()> {\n    \
             let st = state.lock().await;\n    let v = Vault::open(path)?;\n    \
             v.persist();\n    Ok(())\n}\n\
             impl Vault {\n    fn persist(&self) {\n        \
             std::fs::create_dir_all(&self.dir).ok();\n    }\n}\n",
        ),
        (
            // What pins the closure-parameter typing on its own, now that a
            // receiver on `ServiceState` is a seeded region again and would
            // catch the case above by itself. Nothing here is on the state:
            // `Vault::persist` is reached only because the callee's signature
            // says the closure's parameter is a `&Vault`, and it is guarded
            // only because the callee invokes `edit` with the state held.
            // Drop either half and this goes unreported.
            "a method on a typed closure parameter, invoked by the callee under the guard",
            "async fn with_vault<E>(\n    state: &Shared,\n    \
             mut edit: impl FnMut(&Vault) -> Result<(), E>,\n) {\n    \
             let st = state.lock().await;\n    edit(&st.vault).ok();\n}\n\
             async fn caller(state: &Shared) {\n    \
             with_vault(state, |v| {\n        v.persist();\n        \
             Ok(())\n    })\n    .await;\n}\n\
             impl Vault {\n    fn persist(&self) {\n        \
             std::fs::create_dir_all(&self.dir).ok();\n    }\n}\n",
        ),
        (
            // The closure-region rule and the receiver rule have to meet:
            // `Service::set_alias` calls `st.resolve_collection(…)` inside the
            // closure it hands `update_aliases`, and `st` there is a closure
            // parameter, typed nowhere but in the callee's own signature.
            // Without that typing the call resolves to nothing and the edge
            // into `dir` — and through it into the blocking helper — is never
            // drawn. The blocking work is deliberately *not* in the method: a
            // receiver on `ServiceState` is a seeded region on its own now, so
            // putting it there would prove the seed and not the closure.
            "a `&self` method on `ServiceState` called inside a closure the callee runs guarded",
            "async fn update_aliases<E>(\n    state: &Shared,\n    \
             mut edit: impl FnMut(&ServiceState) -> Result<(), E>,\n) {\n    \
             let st = state.lock().await;\n    edit(&st).ok();\n}\n\
             async fn caller(state: &Shared) {\n    \
             update_aliases(state, |st| {\n        persist(st.dir());\n        \
             Ok(())\n    })\n    .await;\n}\n\
             impl ServiceState {\n    fn dir(&self) -> &Path {\n        \
             &self.vault_dir\n    }\n}\n\
             fn persist(dir: &Path) {\n    std::fs::create_dir_all(dir).ok();\n}\n",
        ),
        // ---- The exception that used to be carved out here. -------------
        // `ServiceState::load_vaults` was a `&mut self` method fusing the
        // blocking directory scan to the pure merge, and `src/daemon.rs`
        // called it on the owned value one line before the `Mutex` existed.
        // That one call site was the whole reason the receiver seed had been
        // softened from "a receiver on `ServiceState` is a guard region" to
        // "…only where a caller carries a guard into it" — a weaker rule that
        // waits for a guarded caller before it says anything. The method is
        // gone: startup now calls the free `scan_vault_dir` and then
        // `merge_scan`, so nothing in the tree needs the exception and the
        // shape it protected is an offence again, reported the moment it is
        // written rather than when someone first calls it under the guard.
        (
            "a blocking `&mut self` method on `ServiceState` called only before the mutex exists",
            "impl ServiceState {\n    fn load_vaults(&mut self) -> Result<()> {\n        \
             std::fs::create_dir_all(&self.vault_dir)\n    }\n}\n\
             async fn run(dir: &Path) -> Result<()> {\n    \
             let mut state = ServiceState::new(dir);\n    state.load_vaults()?;\n    \
             let state: Shared = Arc::new(Mutex::new(state));\n    Ok(())\n}\n",
        ),
        (
            // Its delegating twin: the blocking half one `fn` deeper, which is
            // how `unique_collection_id` hid. The seed puts the body under the
            // guard and the call graph carries it into `scan_vault_dir`.
            "a `&mut self` method delegating to a blocking helper, called only before the mutex",
            "impl ServiceState {\n    fn load_vaults(&mut self) -> Result<()> {\n        \
             let scan = scan_vault_dir(&self.vault_dir)?;\n    Ok(self.merge_scan(scan))\n    }\n}\n\
             fn scan_vault_dir(dir: &Path) -> Result<Scan> {\n    \
             std::fs::create_dir_all(dir)?;\n    Ok(Scan::default())\n}\n\
             async fn run(dir: &Path) -> Result<()> {\n    \
             let mut state = ServiceState::new(dir);\n    state.load_vaults()?;\n    Ok(())\n}\n",
        ),
        // ---- The guard receiver: the shape production actually uses. -----
        //
        // Every vault offender above is written `let mut owned =
        // Vault::open(p)?;` — a local typed by its initialiser. Nothing in
        // `src/dbus/` is written that way. Every write there goes
        //
        //     let vault = self.vault().await.ok_or_else(…)?;
        //     let mut vault = vault.lock().await;
        //     block_in_place(|| vault.update_item(&self.id, f))
        //
        // and `visit_local` used to refuse to type a binding whose initialiser
        // was an acquisition, so `vault` had no type, the method call resolved
        // to nothing, and removing that `block_in_place` from the real
        // `src/dbus/item.rs` left all four tests in this file green.
        //
        // `rewrite` is deliberately a name no list mentions: this case is
        // reported only if the guard binding is typed from its acquisition's
        // receiver. The binding before the lock is named `cell` rather than
        // `vault` on purpose too — with both named `vault`, the ordinary local
        // typing would answer for the shadowed one and the case would prove
        // nothing about the guard.
        (
            "a blocking method on a guard receiver, under a collection's lock",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Item {\n    coll: VaultRef,\n}\n\
             impl Item {\n    async fn update(&self) -> Result<()> {\n        \
             let cell = self.coll.clone();\n        let mut vault = cell.lock().await;\n        \
             vault.rewrite()\n    }\n}\n\
             impl Vault {\n    fn rewrite(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        (
            "a blocking method on a guard receiver, under the state guard",
            "type Shared = Arc<Mutex<ServiceState>>;\nstruct Service {\n    inner: Shared,\n}\n\
             impl Service {\n    async fn touch(&self) -> Result<()> {\n        \
             let cell = self.inner.clone();\n        let mut held = cell.lock().await;\n        \
             held.rewrite()\n    }\n}\n\
             impl ServiceState {\n    fn rewrite(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        // ---- The name backstop, where the call graph structurally cannot
        // ---- reach. `Vault::save` publishes through a *parameter*
        // ---- (`save_with(write_atomic)` calling `publish(&path, &bytes)`),
        // ---- which a signature-only view cannot follow, so the graph stops
        // ---- one call short of the `fsync`. No definition is given here
        // ---- either: this is exactly the case a list answers and a graph
        // ---- does not.
        (
            "a `Vault` mutator whose definition the scan cannot see, under a guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let mut v = elsewhere();\n    v.change_password(old, new, kdf)?;\n}\n",
        ),
        (
            "a `Vault` mutator on a guard receiver, outside a `block_in_place`",
            "async fn f() {\n    let mut vault = vault.lock().await;\n    \
             vault.import_items(batch)?;\n}\n",
        ),
        // ---- The guard nobody binds. -------------------------------------
        //
        // A guard pushed onto `held` came only from `visit_local` or a
        // signature seed, so an acquisition consumed as a **temporary**
        // opened no region at all: `innermost()` was `None`, and both the
        // blocking check in `visit_expr_method_call` and `note_call`
        // early-return on that. The name list and the call graph went blind
        // together, and `src/dbus/` writes this shape about twenty-five times
        // — `collection.rs:173,380,427`, `prompt.rs:450`, `registry.rs:31`,
        // `state.rs:681`. Every callee there is cheap today, so there was no
        // live bug; there was also no protection.
        (
            "a `Vault` mutator on a temporary collection guard",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Item {\n    coll: VaultRef,\n}\n\
             impl Item {\n    async fn update(&self, id: &str) -> Result<()> {\n        \
             self.coll.lock().await.update_item(id, f)\n    }\n}\n",
        ),
        (
            // The graph half of the same hole, with nothing on any list:
            // reported only because the temporary opens a region *and* the
            // receiver is typed through it, so the edge into `Vault::rewrite`
            // is drawn and walked with the lock held.
            "a graph-only blocking `Vault` method on a temporary collection guard",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Item {\n    coll: VaultRef,\n}\n\
             impl Item {\n    async fn update(&self) -> Result<()> {\n        \
             self.coll.lock().await.rewrite()\n    }\n}\n\
             impl Vault {\n    fn rewrite(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        (
            // Rule two, defeated by the same hole. Both guards here are
            // temporaries and both are live at once — the state guard lives to
            // the end of the statement, and the collection lock is taken
            // inside it. The state half of this shape was covered only by
            // accident, because `vault` resolves to a `&self` method on
            // `ServiceState` and those are seeded; the collection half — the
            // one place `block_in_place` is mandatory — was invisible.
            "two locks in one statement, both taken as temporaries",
            "async fn f(id: &str) {\n    \
             state.lock().await.vault(id).unwrap().lock().await.is_locked();\n}\n",
        ),
        // ---- `Vault::lock`, which was permanently unfollowable. ----------
        // Its name collides with `ACQUIRE`, so `note_call` was skipped for
        // every method called `lock` and no edge was ever drawn into it from
        // anywhere. It is cheap today and on no list. The `.await` is what
        // tells the two apart: an acquisition is always `recv.lock().await`.
        (
            "a blocking `Vault::lock` called bare, under the state guard",
            "async fn f(state: &Shared, p: &Path) {\n    let st = state.lock().await;\n    \
             let mut v = Vault::open(p)?;\n    v.lock();\n}\n\
             impl Vault {\n    fn lock(&mut self) {\n        \
             std::fs::create_dir_all(&self.dir).ok();\n    }\n}\n",
        ),
        // ---- The `.await` half of rule one. ------------------------------
        // `CLAUDE.md`: "Not an `.await` that can block, and not a synchronous
        // blocking call either." Only the synchronous half was ever checked,
        // so every one of these was invisible under the global mutex.
        (
            "a pinentry round trip under the state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let pin = ask_passphrase(&st.pinentry, &label).await?;\n}\n",
        ),
        (
            "a signal emission under the state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             emitter.collection_created(&path).await.ok();\n}\n",
        ),
        (
            "an object-server registration under the state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             conn.object_server().at(&path, iface).await?;\n}\n",
        ),
        (
            // The case the clean list used to bless. Detaching work is fine;
            // waiting for it under the guard holds the mutex for exactly as
            // long as the blocking work runs, which is the whole offence.
            "a `JoinHandle` awaited under the state guard",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let dir = st.vault_dir.clone();\n    \
             tokio::task::spawn_blocking(move || std::fs::create_dir_all(&dir)).await.ok();\n}\n",
        ),
        (
            "an `.await` in a helper handed `&ServiceState`",
            "async fn reply(st: &ServiceState, sock: &mut UnixStream) -> Result<()> {\n    \
             sock.read_exact(&mut buf).await?;\n    Ok(())\n}\n",
        ),
        // ---- The state lock reached through a name the heuristic did not
        // ---- know. `receiver_kind` decided `Guard::State` from the binding
        // ---- name alone, so a state lock under any other name classified as
        // ---- a collection lock — and a collection lock is the one that
        // ---- *permits* `block_in_place`, which is itself an offence under
        // ---- the state guard. The asymmetry is safe when it over-flags and
        // ---- unsafe when it exempts, and this is the exempting direction.
        (
            "`block_in_place` under a state lock reached through an unfamiliar name",
            "type Shared = Arc<Mutex<ServiceState>>;\nstruct Housekeeping {\n    registry: Shared,\n}\n\
             impl Housekeeping {\n    async fn sweep(&self) {\n        \
             let mut inner = self.registry.lock().await;\n        \
             block_in_place(|| inner.persist()).ok();\n    }\n}\n",
        ),
        (
            "an fsync under a state lock reached through an unfamiliar name",
            "type Shared = Arc<Mutex<ServiceState>>;\nstruct Housekeeping {\n    registry: Shared,\n}\n\
             impl Housekeeping {\n    async fn sweep(&self) {\n        \
             let inner = self.registry.lock().await;\n        \
             file.sync_all()?;\n    }\n}\n",
        ),
        // ---- Let-chain scrutinees. `visit_expr_if`/`visit_expr_while`
        // ---- matched a bare `Expr::Let` and nothing else, so a let-chain —
        // ---- which parses as an `Expr::Binary` — walked past the scrutinee
        // ---- rule entirely. The tree uses let-chains freely, so this is the
        // ---- shape a future edit is most likely to take, and there was a
        // ---- live one in `src/dbus/registry.rs` when this was written.
        (
            "a lock in an `if let` chain's first scrutinee",
            "async fn f() {\n    if let Some(v) = self.state.lock().await.vault(id)\n        \
             && v.is_ready()\n    {\n        v.save();\n    }\n}\n",
        ),
        (
            "a lock in an `if let` chain's second scrutinee",
            "async fn f() {\n    if let Ok(iface) = server.interface(path).await\n        \
             && let Err(e) = iface.get().await.emit(sig).await\n    {\n        warn(e);\n    }\n}\n",
        ),
        (
            "a lock in the plain operand beside a `let` in an `if` chain",
            "async fn f() {\n    if let Some(v) = self.lookup(id)\n        \
             && self.state.lock().await.is_ready()\n    {\n        v.save();\n    }\n}\n",
        ),
        (
            "a lock in a `while let` chain's scrutinee",
            "async fn f() {\n    while let Some(v) = self.state.lock().await.pop()\n        \
             && !done\n    {\n        v.save();\n    }\n}\n",
        ),
        (
            "regression: a lock taken inside a macro invocation under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             assert!(vault.lock().await.is_locked());\n}\n",
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
            // A temporary guard *is* a region now, but Rust ends it with the
            // statement that produced it, so the lock on the next line is
            // taken with nothing held. This case used to be named "a
            // temporary, which is not a guard" and passed because temporaries
            // were modelled as nothing at all; it passes now because the
            // region is modelled and has ended.
            "a second lock after a temporary guard's statement has ended",
            "async fn f() {\n    self.state.lock().await.touch();\n    \
             let v = vault.lock().await;\n}\n",
        ),
        (
            // The near-miss that decides whether any of this is usable. This
            // is what `src/dbus/` writes about twenty-five times —
            // `collection.rs:380`, `registry.rs:31`, `state.rs:681` — and
            // every callee is a map read. Flagging it would make the scan
            // useless, so the temporary must open a region the graph walks
            // *through* rather than one it reports on sight.
            "a cheap read on a temporary collection guard",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Item {\n    coll: VaultRef,\n}\n\
             impl Item {\n    async fn ids(&self) -> Vec<String> {\n        \
             self.coll.lock().await.item_ids()\n    }\n}\n\
             impl Vault {\n    fn item_ids(&self) -> Vec<String> {\n        \
             self.index.iter().map(|e| e.id.clone()).collect()\n    }\n}\n",
        ),
        (
            // The near-miss for `Vault::lock`: the acquisition is not a call
            // to a method named `lock`, even where the receiver is typed and a
            // `Vault::lock` definition is right there to resolve to.
            //
            // Honest about what it pins: reverting the fix does **not** make
            // this case fail, and it cannot, because an acquisition is only
            // ever reached with nothing held — anywhere a guard *is* held, a
            // second acquisition is already reported as one. So the edge, if
            // it were drawn, would be drawn unguarded and cost nothing. This
            // case is the shape a future edit would break first; the real
            // check on the over-flagging direction is
            // `no_source_file_acquires_a_lock_while_holding_one`, where 65
            // acquisitions meet the real `Vault::lock`.
            "the acquisition `.lock().await`, beside a real `Vault::lock`",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Item {\n    coll: VaultRef,\n}\n\
             impl Item {\n    async fn ids(&self) -> Vec<String> {\n        \
             let v = self.coll.lock().await;\n        v.item_ids()\n    }\n}\n\
             impl Vault {\n    fn lock(&mut self) {\n        \
             std::fs::create_dir_all(&self.dir).ok();\n    }\n    \
             fn item_ids(&self) -> Vec<String> {\n        Vec::new()\n    }\n}\n",
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
            "an fsync inside the sanctioned block_in_place, under a collection's lock",
            "async fn f() {\n    let v = vault.lock().await;\n    \
             block_in_place(|| v.save())?;\n}\n",
        ),
        (
            "a multi-line block_in_place closure under a collection's lock",
            "async fn f() {\n    let v = vault.lock().await;\n    \
             block_in_place(|| {\n        std::fs::rename(&tmp, &path)?;\n        \
             file.sync_all()\n    })?;\n}\n",
        ),
        (
            "a blocking helper called from inside a block_in_place under a collection's lock",
            "async fn f() {\n    let v = vault.lock().await;\n    \
             block_in_place(|| persist(&v))?;\n}\n\
             fn persist(v: &Vault) -> Result<()> {\n    std::fs::rename(&tmp, &path)?;\n    \
             Ok(())\n}\n",
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
        (
            // Regression, the other way: only the first `//` on a line was
            // inspected, so a `//` inside a string literal made the real
            // trailing comment read as code and produced a finding against
            // source that does not exist.
            "regression: a URL in a string literal, with a real trailing comment",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             log(\"see https://example.invalid/x\"); // vault.lock().await, sync_all()\n}\n",
        ),
        (
            // Regression: `state_impl` recorded depths but only ever tested
            // `is_empty()`, so an `impl` of another type *inside* an
            // `impl ServiceState` inherited the region.
            "regression: an inner `impl` of another type inside `impl ServiceState`",
            "impl ServiceState {\n    fn f(&self) -> u32 {\n        struct Inner;\n        \
             impl Inner {\n            fn go(&self) {\n                \
             std::fs::remove_file(\"/x\").ok();\n            }\n        }\n        0\n    }\n}\n",
        ),
        (
            // The premise the receiver rule cannot have: `src/daemon.rs`
            // builds a `ServiceState`, calls a method on the owned value and
            // only then wraps it in the mutex. Reachability is what tells this
            // apart from a call made under the guard.
            "a blocking helper reached only from lock-free startup code",
            "fn start(dir: &Path) -> Result<()> {\n    let mut state = ServiceState::new(dir);\n    \
             sweep(dir)?;\n    Ok(())\n}\n\
             fn sweep(dir: &Path) -> Result<()> {\n    std::fs::create_dir_all(dir)\n}\n",
        ),
        (
            "a `&self` method on `ServiceState` delegating to a helper that does not block",
            "impl ServiceState {\n    fn ids(&self) -> Vec<String> {\n        \
             collect_ids(&self.collections)\n    }\n}\n\
             fn collect_ids(m: &Map) -> Vec<String> {\n    m.keys().cloned().collect()\n}\n",
        ),
        (
            "a closure passed to a callee that does not invoke it under a guard",
            "async fn apply(state: &Shared, mut edit: impl FnMut() -> Result<()>) {\n    \
             {\n        let st = state.lock().await;\n        st.touch();\n    }\n    \
             edit().ok();\n}\n\
             async fn caller(state: &Shared) {\n    \
             apply(state, || {\n        std::fs::remove_file(\"/x\")?;\n        \
             Ok(())\n    })\n    .await;\n}\n",
        ),
        (
            // The other half of the dead-and-dangerous rule: uncalled is only
            // an offence when the body would cost something under the guard.
            // Most of `ServiceState` is uncalled map accessors.
            "an uncalled `&self` method on `ServiceState` that does no blocking work",
            "impl ServiceState {\n    fn broken_error(&self, id: &str) -> Option<&str> {\n        \
             self.broken.get(id).map(|(_, e)| e.as_str())\n    }\n}\n",
        ),
        (
            // The near-miss for the guarded-closure offender above, written to
            // the same shape so the two differ in exactly one thing: whether
            // the callee invokes `edit` with the guard held. Here it drops the
            // guard first, so the blocking helper the closure reaches through
            // the typed `&ServiceState` parameter runs with nothing held.
            "a `&self` method on `ServiceState` called in a closure the callee runs unguarded",
            "async fn apply(state: &Shared, mut edit: impl FnMut(&ServiceState) -> Result<()>) {\n    \
             {\n        let st = state.lock().await;\n        st.touch();\n    }\n    \
             edit(&owned).ok();\n}\n\
             async fn caller(state: &Shared) {\n    \
             apply(state, |st| {\n        persist(st.dir());\n        Ok(())\n    })\n    \
             .await;\n}\n\
             impl ServiceState {\n    fn dir(&self) -> &Path {\n        \
             &self.vault_dir\n    }\n}\n\
             fn persist(dir: &Path) {\n    std::fs::create_dir_all(dir).ok();\n}\n",
        ),
        (
            // The near-miss for the three offenders above: the same mutators,
            // under a *collection's* lock and inside the sanctioned wrapper,
            // which is exactly how `CreateItem`, `SetLabel` and `DeleteItems`
            // are written today. Naming the mutators must not forbid the one
            // shape `CLAUDE.md` sanctions.
            "vault mutators inside a block_in_place under a collection's lock",
            "async fn f() {\n    let mut v = vault.lock().await;\n    \
             block_in_place(|| v.import_items(batch))?;\n    \
             block_in_place(|| v.set_label(label))?;\n    \
             block_in_place(|| v.delete_items(&ids))?;\n}\n",
        ),
        (
            // The mutator names are not reserved words: a call with nothing
            // held is not an offence, wherever it is written.
            "a vault mutator with no lock held at all",
            "async fn f(path: &Path) {\n    let mut v = Vault::open(path)?;\n    \
             v.import_items(batch)?;\n}\n",
        ),
        (
            // The near-miss for the guard-receiver offenders: the same
            // receiver, the same method, inside the sanctioned wrapper under a
            // collection's lock — which is exactly how `src/dbus/item.rs`
            // writes it. Typing the guard binding must make this shape
            // *visible*, not forbidden.
            "a blocking method on a guard receiver, inside a `block_in_place`",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Item {\n    coll: VaultRef,\n}\n\
             impl Item {\n    async fn update(&self) -> Result<()> {\n        \
             let cell = self.coll.clone();\n        let mut vault = cell.lock().await;\n        \
             block_in_place(|| vault.rewrite())\n    }\n}\n\
             impl Vault {\n    fn rewrite(&mut self) -> Result<()> {\n        \
             file.sync_all()\n    }\n}\n",
        ),
        (
            // The near-miss for the misclassification offenders, differing in
            // exactly one thing: what the field is a lock *over*. A `VaultRef`
            // is a collection's lock however it is named, and
            // `block_in_place` is what `CLAUDE.md` requires there.
            "`block_in_place` under a collection lock reached through an unfamiliar name",
            "type VaultRef = Arc<Mutex<Vault>>;\nstruct Housekeeping {\n    registry: VaultRef,\n}\n\
             impl Housekeeping {\n    async fn sweep(&self) {\n        \
             let mut inner = self.registry.lock().await;\n        \
             block_in_place(|| inner.persist()).ok();\n    }\n}\n",
        ),
        (
            // `CLAUDE.md` scopes the `.await` rule to the state mutex. Under a
            // collection's lock an `.await` is ordinary: that lock is one
            // collection's, and the sanctioned save is held across it.
            "an `.await` under a collection's lock",
            "async fn f() {\n    let mut vault = vault.lock().await;\n    \
             emitter.item_created(&path).await.ok();\n}\n",
        ),
        (
            "an `.await` after the state guard is dropped",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let dir = st.vault_dir.clone();\n    drop(st);\n    \
             emitter.collection_created(&dir).await.ok();\n}\n",
        ),
        (
            // The acquisition that opens a region is not an offence against
            // itself, and neither is one taken with nothing held.
            "the `.await` that takes the state lock in the first place",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             st.touch();\n}\n",
        ),
        (
            // A plain `if` condition is not a let-chain: its temporaries are
            // dropped before the body runs, so the guard does not outlive the
            // scrutinee and the rule does not apply.
            "an `if` condition with no `let` in it, which locks",
            "async fn f(state: &Shared) {\n    if state.lock().await.is_ready() {\n        \
             log(\"ready\");\n    }\n}\n",
        ),
        (
            "an `if let` chain whose scrutinees take no lock",
            "async fn f() {\n    if let Some(v) = self.lookup(id)\n        \
             && v.is_ready()\n    {\n        v.save();\n    }\n}\n",
        ),
        // ---- The macro rule's near-misses, which it had none of. ---------
        // `visit_macro` matched its patterns against the whole token text,
        // string literals included, and the whitespace stripping made it
        // worse. There was an offender for the rule and the nearest clean case
        // deliberately used a *function call* rather than a macro, so the
        // coverage was illusory: nothing in this file would have failed if the
        // rule had started reporting every log line that mentions a syscall.
        (
            "a blocking name inside a string literal in a macro under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             tracing::debug!(\"about to sync_all() the vault\");\n}\n",
        ),
        (
            "an acquisition inside a string literal in a macro under a guard",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             tracing::warn!(\"callers must take vault.lock().await first\");\n}\n",
        ),
        (
            // The other half, and the reason the whitespace stripping made the
            // rule worse rather than merely imprecise: it joined words that
            // are not adjacent in the source, so a literal that does not
            // contain `sync_all(` at all matched once the spaces were gone.
            "words in a macro's string literal that only touch once whitespace is stripped",
            "async fn f() {\n    let g = self.state.lock().await;\n    \
             tracing::debug!(\"about to sync _all() the vault\");\n}\n",
        ),
        (
            // The point of this case is that the closure's blocking body runs
            // somewhere else and carries no guard with it. It used to `.await`
            // the handle, which is a different thing entirely — awaiting a
            // `JoinHandle` under the state guard holds the mutex for exactly
            // as long as the blocking work takes — and it is now the offender
            // "a `JoinHandle` awaited under the state guard" above. Detaching
            // is allowed; waiting for the detached work under the guard is not.
            "work handed to a blocking pool under a guard, which takes nothing with it",
            "async fn f(state: &Shared) {\n    let st = state.lock().await;\n    \
             let dir = st.vault_dir.clone();\n    \
             tokio::task::spawn_blocking(move || std::fs::create_dir_all(&dir));\n}\n",
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

// ===========================================================================
// The source scan.
//
// Everything below parses the daemon with `syn` — the real Rust grammar —
// and answers one question by *reachability*: can this statement run while
// the state guard, or a collection's lock, is held? The predecessor matched
// text, and text is where it went wrong; the doc comment on
// `no_source_file_acquires_a_lock_while_holding_one` states the rules, and
// `the_scan_reports_the_source_it_claims_to_reject` holds a synthetic
// offender and a near-miss for every one of them.
// ===========================================================================

use proc_macro2::Span;
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

/// Which lock is held. The two are *not* interchangeable, and conflating them
/// is a semantic error this scan used to contain.
///
/// `CLAUDE.md` sanctions `state::block_in_place` for the mutation and the save
/// that a **collection's** lock protects: the `fsync`s release the async
/// worker instead of parking it, and no other task wants that vault. It says
/// the opposite about the **state** mutex — "nothing slow or blocking may
/// happen under the state mutex", and `block_in_place` does not release a
/// mutex, it releases a worker thread. So under the state guard blocking work
/// is an offence whether or not it is wrapped, and the wrapper is itself an
/// offence: it is the marker of blocking work in the one place blocking work
/// may not go.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
enum Guard {
    // Ordered so that `max` prefers the state guard: it is the stronger
    // claim, and where the two meet its rules are the ones that apply.
    Collection,
    State,
}

impl Guard {
    fn what(self) -> &'static str {
        match self {
            Guard::State => "the state guard",
            Guard::Collection => "a collection lock",
        }
    }
}

/// What a function is entered holding. The analysis is run once per
/// `(function, entry)` pair and propagated along call edges to a fixed point,
/// so a rule can no longer be defeated by moving the offending line one call
/// deeper.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
struct Entry {
    guard: Option<Guard>,
    /// Inside a `block_in_place` closure. Only ever meaningful together with
    /// [`Guard::Collection`]; see [`Guard`].
    exempt: bool,
}

impl Entry {
    const NONE: Entry = Entry {
        guard: None,
        exempt: false,
    };
    fn held(g: Guard, exempt: bool) -> Entry {
        Entry {
            guard: Some(g),
            exempt,
        }
    }
}

/// Guard-producing calls. `.lock()` is the async mutex; `.read()`/`.write()`
/// an async `RwLock`; `.get()`/`.get_mut()` are zbus's `InterfaceRef`, which
/// is an `RwLock` by another name and is the one that reads as harmless. All
/// are recognised only as `recv.m().await` with no arguments, so `try_lock()`
/// — which cannot block — and `file.write(buf).await` are not mistaken for
/// one.
const ACQUIRE: &[&str] = &["lock", "read", "write", "get", "get_mut"];

/// Blocking calls that must never run under a guard, as method names. The
/// rule is not about `.await`: a synchronous `fsync` stops the same tasks for
/// the same time, and phrasing it for awaits alone is what let the original
/// bug through.
const BLOCKING_METHODS: &[&str] = &[
    "sync_all",
    "sync_data",
    "write_all",
    // A `stat`. One is cheap; `unique_collection_id_in` does an unbounded
    // number of them in a loop, which is the shape the delegation rule below
    // exists for.
    "symlink_metadata",
    // ---- The `Vault` mutators, as a backstop to the call graph. ----------
    //
    // Every one of these ends in `Vault::save` — build the hashed index over
    // the whole collection, postcard-encode every item, seal the blob, write a
    // temp file, `fsync` it, rename, `fsync` the directory — and the four that
    // derive (`unlock`, `unlock_with_key`, `verify_password`, `change_key`)
    // allocate an Argon2 arena as well. That is exactly the work `CLAUDE.md`
    // forbids under the state mutex and sanctions under a collection's lock
    // only inside `block_in_place`.
    //
    // This list was deleted in favour of "coverage is the call graph's now,
    // not a list's". The graph is the better instrument and it does not reach
    // this: `Vault::save` is `self.save_with(write_atomic)`, and `save_with`
    // publishes through `publish(&path, &bytes)` — a *parameter*, not a path,
    // so the edge to `write_atomic`'s `write_all`/`sync_all`/`rename` is a
    // higher-order one that a signature-only view cannot draw. The graph
    // reaches `Vault::update_item` and stops one call short of the `fsync`.
    //
    // So the two instruments are kept, and they are not the same instrument
    // twice. The graph is primary — it is what reaches `change_password`'s
    // second Argon2 arena and anything a future edit writes. The list is a
    // backstop with one job: a rename cannot silently drop coverage, because a
    // renamed mutator that is no longer on it still has to reach the `fsync`
    // through the graph, and one that the graph cannot reach still has to be
    // on it. `the_scan_catches_a_vault_write_at_a_real_call_site` is the case
    // that fails if either half goes.
    //
    // `save` itself is kept even though it is private to `vault::store` — the
    // reason the old list's `save` was dead was that `src/vault/` was outside
    // the parsed set, and it no longer is. `self.save()` inside a `Vault`
    // method now fires whenever the graph enters that method holding a lock,
    // which is precisely the higher-order gap above.
    "insert_item",
    "update_item",
    "delete_item",
    "delete_items",
    "import_items",
    "set_label",
    "change_password",
    "change_key",
    "unlock",
    "unlock_with_key",
    "verify_password",
    "verify_key",
    "delete_file",
    "save",
];
/// The same, as the last segment of a called path: `remove_file(p)`,
/// `std::fs::rename(a, b)`, `fs::create_dir_all(d)`.
const BLOCKING_FNS: &[&str] = &[
    "sync_all",
    "sync_data",
    "write_all",
    "symlink_metadata",
    "remove_file",
    "create_dir_all",
    "rename",
    // Argon2id. `CLAUDE.md`: "Never run Argon2 under the state mutex" — a
    // derivation is hundreds of milliseconds and a whole memory arena, which
    // is blocking work by any reading of the rule, and until now the rule
    // had nothing in this scan enforcing it. `crypto::derive_key` is where
    // the arena is allocated and every derivation in the tree goes through
    // it, `src/kdf.rs`'s bounded wrapper included, so naming it covers the
    // direct call and, through the call graph, every `Vault` method that
    // derives: `unlock`, `verify_password`, `change_password`, `create`,
    // `open`.
    "derive_key",
];

/// Method calls that yield the same payload they are called on, so a type
/// travels through them: `Option`/`Result` unwrapping, cloning, borrowing.
/// Peeling these is not following a call edge — [`TypeMap::payload`] has
/// already collapsed `Option<Arc<Mutex<Vault>>>` to `Vault`, and these are the
/// expressions that do the collapsing at runtime.
const PASSTHROUGH: &[&str] = &[
    "clone",
    "cloned",
    "to_owned",
    "unwrap",
    "expect",
    "ok_or",
    "ok_or_else",
    "unwrap_or_else",
    "unwrap_or_default",
    "as_ref",
    "as_mut",
    "borrow",
    "borrow_mut",
];

/// The sanctioned escape hatch — for a collection's lock only.
const EXEMPT: &str = "block_in_place";

/// Calls whose closure or `async` argument runs somewhere else entirely, so
/// nothing this function holds is held inside it.
const DETACHED: &[&str] = &["spawn", "spawn_blocking", "spawn_local", "spawn_local_obj"];

// ---------------------------------------------------------------------------
// The registry: every function in the scanned files, and which of them are
// seeds — entered with the state guard already held.
// ---------------------------------------------------------------------------

struct FnDef {
    /// `ServiceState::load_vaults`, or `save_aliases_to` for a free function.
    display: String,
    name: String,
    file: String,
    line: usize,
    /// Whether the first parameter is a `self` receiver.
    has_receiver: bool,
    /// The type of the `impl` block this came from, if any.
    self_ty: Option<String>,
    /// Parameter binding names, index-aligned with the call's arguments
    /// (`self` occupies index 0 when there is a receiver).
    params: Vec<String>,
    /// The declared type of each parameter, as its outermost named type
    /// (`st: &mut ServiceState` -> `ServiceState`, `state: &Shared` ->
    /// `Shared`). This is the only type information available — `syn` does no
    /// inference — and it is what keeps method-call resolution honest: a call
    /// is followed when the receiver's type is *known*, not merely when some
    /// function somewhere shares the method's name.
    param_types: Vec<Option<String>>,
    /// For a parameter that is a callback — `edit: impl FnMut(&ServiceState,
    /// …)` — the outermost type name of each of *its* arguments. The callee's
    /// signature is the only place a closure literal's parameter types are
    /// written down, and without them a call on one (`st.resolve_collection(…)`
    /// inside the closure `Service::set_alias` hands to `update_aliases`)
    /// resolves to nothing at all.
    callback_params: Vec<Option<Vec<Option<String>>>>,
    /// The payload type this function returns, when it names one:
    /// `ServiceState::vault(&self, …) -> Option<VaultRef>` yields `Vault`.
    /// This is what carries a type across a call, and it is how the local in
    /// `let vault = self.vault().await.ok_or_else(…)?` — the shape every
    /// `src/dbus/` write actually uses — comes to be a `Vault` at all.
    ret_ty: Option<String>,
    /// Why this function's whole body is a guard region, if it is.
    seed: Option<(Guard, String)>,
    /// Whether that region comes from a `&self`/`&mut self` receiver rather
    /// than from a parameter. Both are seeded, and identically; the
    /// distinction is what [`dead_and_dangerous`] ranges over.
    receiver_seed: bool,
    /// Declared inside a `#[cfg(test)]` module, so a call written here is not
    /// a production caller.
    in_test: bool,
    block: syn::Block,
}

/// Wrappers a value is *behind* rather than *is*. Peeling them is what turns
/// `Option<VaultRef>` — and `VaultRef` is itself `Arc<Mutex<Vault>>` — into
/// `Vault`, which is the whole reason the guard binding in
/// `let mut vault = vault.lock().await` can be typed at all.
const WRAPPERS: &[&str] = &[
    "Option",
    "Result",
    "Arc",
    "Rc",
    "Box",
    "Pin",
    "Mutex",
    "RwLock",
    "RefCell",
    "Cell",
    "MutexGuard",
    "OwnedMutexGuard",
    "RwLockReadGuard",
    "RwLockWriteGuard",
    "Zeroizing",
];

/// The type names the scan knows: `type` aliases and struct fields, from the
/// scanned files themselves.
///
/// `syn` does no inference, so this is the whole of the scan's type knowledge
/// — and it is enough for the shape that matters, because the daemon writes
/// every one of these down. `Shared` and `VaultRef` are aliases in
/// `src/dbus/state.rs`; `Item { state: Shared, … }` is a struct there; and
/// `ServiceState::vault(&self, …) -> Option<VaultRef>` is a signature. Follow
/// those three and `let mut vault = vault.lock().await` types as `Vault` and
/// `let st = self.state.lock().await` as `ServiceState`, which is what the
/// guard-binding rule and the state/collection classification both need.
#[derive(Default)]
struct TypeMap {
    aliases: HashMap<String, syn::Type>,
    /// `(struct name, field name) -> declared type`.
    fields: HashMap<(String, String), syn::Type>,
}

impl TypeMap {
    /// The named type a value of this type ultimately *is*, after peeling
    /// references and [`WRAPPERS`] and resolving aliases.
    fn payload(&self, ty: &syn::Type) -> Option<String> {
        self.payload_at(ty, 0)
    }

    fn payload_at(&self, ty: &syn::Type, depth: usize) -> Option<String> {
        if depth > 12 {
            return None;
        }
        match ty {
            syn::Type::Reference(r) => self.payload_at(&r.elem, depth + 1),
            syn::Type::Paren(p) => self.payload_at(&p.elem, depth + 1),
            syn::Type::Group(g) => self.payload_at(&g.elem, depth + 1),
            syn::Type::Path(p) => {
                let seg = p.path.segments.last()?;
                let name = seg.ident.to_string();
                if WRAPPERS.contains(&name.as_str())
                    && let syn::PathArguments::AngleBracketed(a) = &seg.arguments
                    && let Some(inner) = a.args.iter().find_map(|g| match g {
                        syn::GenericArgument::Type(t) => Some(t),
                        _ => None,
                    })
                {
                    return self.payload_at(inner, depth + 1);
                }
                if let Some(aliased) = self.aliases.get(&name) {
                    return self.payload_at(&aliased.clone(), depth + 1);
                }
                Some(name)
            }
            _ => None,
        }
    }

    fn field(&self, on: &str, field: &str) -> Option<String> {
        let ty = self.fields.get(&(on.to_string(), field.to_string()))?;
        self.payload(&ty.clone())
    }
}

fn collect_types(items: &[syn::Item], out: &mut TypeMap) {
    for item in items {
        match item {
            syn::Item::Type(t) => {
                out.aliases.insert(t.ident.to_string(), (*t.ty).clone());
            }
            syn::Item::Struct(s) => {
                for f in &s.fields {
                    if let Some(id) = &f.ident {
                        out.fields
                            .insert((s.ident.to_string(), id.to_string()), f.ty.clone());
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_types(inner, out);
                }
            }
            _ => {}
        }
    }
}

struct Registry {
    defs: Vec<FnDef>,
    by_name: HashMap<String, Vec<usize>>,
    types: TypeMap,
}

impl Registry {
    fn build(files: &[(String, String)]) -> Registry {
        let parsed: Vec<(&String, syn::File)> = files
            .iter()
            .map(|(name, text)| {
                let f = syn::parse_file(text).unwrap_or_else(|e| {
                    panic!(
                        "{name} did not parse as Rust, so the scan below would be reading \
                         something other than this daemon: {e}"
                    )
                });
                (name, f)
            })
            .collect();
        // Types first: a signature in the first file may name an alias
        // declared in the last one.
        let mut types = TypeMap::default();
        for (_, f) in &parsed {
            collect_types(&f.items, &mut types);
        }
        let mut defs = Vec::new();
        for (name, f) in &parsed {
            collect_items(name, &f.items, false, &types, &mut defs);
        }
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, d) in defs.iter().enumerate() {
            by_name.entry(d.name.clone()).or_default().push(i);
        }
        Registry {
            defs,
            by_name,
            types,
        }
    }

    /// Candidate definitions for a call.
    ///
    /// A **method** call is followed only when the receiver's type is known
    /// from a signature — `self` inside an `impl`, a parameter with a declared
    /// type, a binding holding the state guard, a local initialised from an
    /// associated function (`let mut state = ServiceState::new(…)`), or a
    /// closure parameter typed from the callee's callback signature. Following one by
    /// bare name instead would make `vault.set_label(…)` reach
    /// `Collection::set_label`, and the resulting "offence" would name source
    /// that is never executed. A false positive is preferred to a false
    /// negative, but an invented call edge is neither: it is noise that
    /// hides both.
    ///
    /// A **free function** call is resolved by name, ignoring a lowercase
    /// module qualifier (`state::save_aliases_to`) and requiring an uppercase
    /// one to be the implementing type (`ServiceState::new`). That is where
    /// the delegation this rule exists for actually lives.
    fn resolve(&self, call: &Call) -> Vec<usize> {
        let Some(all) = self.by_name.get(&call.name) else {
            return Vec::new();
        };
        all.iter()
            .copied()
            .filter(|&i| {
                let d = &self.defs[i];
                if d.has_receiver != call.method {
                    return false;
                }
                match (&call.on, call.method) {
                    (Some(ty), _) => d.self_ty.as_deref() == Some(ty.as_str()),
                    // An unqualified free function: any definition of that
                    // name, since a module path says nothing about which.
                    (None, false) => true,
                    // A method on a receiver of unknown type: not followed.
                    (None, true) => false,
                }
            })
            .collect()
    }
}

/// Whether an item is behind `#[cfg(test)]`.
fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.meta
                .to_token_stream()
                .to_string()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|w| w == "test")
    })
}

fn collect_items(
    file: &str,
    items: &[syn::Item],
    in_test: bool,
    types: &TypeMap,
    out: &mut Vec<FnDef>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => push_fn(
                file,
                None,
                &f.sig,
                &f.block,
                in_test || is_cfg_test(&f.attrs),
                types,
                out,
            ),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_items(file, inner, in_test || is_cfg_test(&m.attrs), types, out);
                }
            }
            syn::Item::Impl(i) => {
                let ty = type_name(&i.self_ty);
                let t = in_test || is_cfg_test(&i.attrs);
                for ii in &i.items {
                    if let syn::ImplItem::Fn(m) = ii {
                        push_fn(file, ty.as_deref(), &m.sig, &m.block, t, types, out);
                    }
                }
            }
            syn::Item::Trait(t) => {
                let tt = in_test || is_cfg_test(&t.attrs);
                for ti in &t.items {
                    if let syn::TraitItem::Fn(m) = ti
                        && let Some(body) = &m.default
                    {
                        push_fn(file, None, &m.sig, body, tt, types, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn push_fn(
    file: &str,
    self_ty: Option<&str>,
    sig: &syn::Signature,
    block: &syn::Block,
    in_test: bool,
    types: &TypeMap,
    out: &mut Vec<FnDef>,
) {
    let name = sig.ident.to_string();
    let mut params = Vec::new();
    let mut param_types = Vec::new();
    let mut callback_params: Vec<Option<Vec<Option<String>>>> = Vec::new();
    let mut has_receiver = false;
    let mut seed: Option<(Guard, String)> = None;
    let mut receiver_seed = false;
    for arg in &sig.inputs {
        match arg {
            syn::FnArg::Receiver(r) => {
                has_receiver = true;
                params.push("self".to_string());
                param_types.push(self_ty.map(str::to_string));
                callback_params.push(None);
                // A `&self` method on `ServiceState` is the guard one position
                // further in: holding `&ServiceState` *is* holding the state,
                // and a receiver has no `name: ty` form for the parameter rule
                // to split on. `self` by value consumes the state and so
                // cannot be behind a guard.
                if r.reference.is_some() && self_ty == Some("ServiceState") && seed.is_none() {
                    let m = if r.mutability.is_some() { "mut " } else { "" };
                    seed = Some((Guard::State, format!("`&{m}self` on `ServiceState`")));
                    receiver_seed = true;
                }
            }
            syn::FnArg::Typed(pt) => {
                params.push(pat_name(&pt.pat).unwrap_or_else(|| "_".to_string()));
                // A guard over the state answers method calls as the state.
                // The *payload* type, not the outermost one: a `&VaultRef`
                // is a `Vault` behind an `Arc<Mutex<…>>`, and typing it as
                // `Arc` would resolve nothing. `&Shared` becomes
                // `ServiceState` for the same reason — which says what the
                // lock is *over*, and is not the same claim as holding it;
                // `is_state_ref` below is still what decides the seed.
                param_types.push(if is_state_ref(&pt.ty) {
                    Some("ServiceState".to_string())
                } else {
                    types.payload(&pt.ty).or_else(|| type_name(&pt.ty))
                });
                callback_params.push(callback_arg_types(&pt.ty));
                if seed.is_none() && is_state_ref(&pt.ty) {
                    seed = Some((
                        Guard::State,
                        format!(
                            "`{}: {}`",
                            pat_name(&pt.pat).unwrap_or_else(|| "_".into()),
                            tidy(&pt.ty.to_token_stream().to_string())
                        ),
                    ));
                }
            }
        }
    }
    let display = match self_ty {
        Some(t) => format!("{t}::{name}"),
        None => name.clone(),
    };
    let ret_ty = match &sig.output {
        syn::ReturnType::Type(_, ty) => types.payload(ty).map(|t| match t.as_str() {
            "Self" => self_ty.unwrap_or("Self").to_string(),
            _ => t,
        }),
        syn::ReturnType::Default => None,
    };
    out.push(FnDef {
        display,
        name,
        file: file.to_string(),
        line: sig.ident.span().start().line,
        has_receiver,
        self_ty: self_ty.map(str::to_string),
        params,
        param_types,
        callback_params,
        ret_ty,
        seed,
        receiver_seed,
        in_test,
        block: block.clone(),
    });
}

fn tidy(s: &str) -> String {
    s.replace(" :: ", "::")
        .replace(" < ", "<")
        .replace(" > ", ">")
}

fn type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
        syn::Type::Reference(r) => type_name(&r.elem),
        syn::Type::Paren(p) => type_name(&p.elem),
        syn::Type::Group(g) => type_name(&g.elem),
        _ => None,
    }
}

/// Whether a parameter type is a borrow of, or a guard over, `ServiceState`.
/// A `&Shared` is neither: it is `Arc<Mutex<ServiceState>>`, the lock itself,
/// so a callee holding one holds nothing and locking inside it is the
/// intended pattern. `edit: impl FnMut(&ServiceState, …)` is not one either —
/// that is a callback *type* mentioning the state, and `syn` tells the two
/// apart structurally where a substring match could not.
fn is_state_ref(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(r) => type_name(&r.elem).as_deref() == Some("ServiceState"),
        syn::Type::Path(p) => {
            let Some(seg) = p.path.segments.last() else {
                return false;
            };
            seg.ident == "MutexGuard"
                && seg
                    .arguments
                    .to_token_stream()
                    .to_string()
                    .contains("ServiceState")
        }
        syn::Type::Paren(p) => is_state_ref(&p.elem),
        syn::Type::Group(g) => is_state_ref(&g.elem),
        _ => false,
    }
}

/// The argument types of a callback parameter, if it is one: `impl
/// FnMut(&ServiceState, &mut BTreeMap<…>) -> Result<(), E>` yields
/// `[Some("ServiceState"), Some("BTreeMap")]`. Only the parenthesised `Fn`
/// sugar is recognised, which is the only form this daemon writes.
fn callback_arg_types(ty: &syn::Type) -> Option<Vec<Option<String>>> {
    fn from_bounds<'a>(
        bounds: impl IntoIterator<Item = &'a syn::TypeParamBound>,
    ) -> Option<Vec<Option<String>>> {
        for b in bounds {
            let syn::TypeParamBound::Trait(t) = b else {
                continue;
            };
            let seg = t.path.segments.last()?;
            if !matches!(seg.ident.to_string().as_str(), "Fn" | "FnMut" | "FnOnce") {
                continue;
            }
            let syn::PathArguments::Parenthesized(args) = &seg.arguments else {
                continue;
            };
            return Some(
                args.inputs
                    .iter()
                    .map(|a| {
                        if is_state_ref(a) {
                            Some("ServiceState".to_string())
                        } else {
                            type_name(a)
                        }
                    })
                    .collect(),
            );
        }
        None
    }
    match ty {
        syn::Type::ImplTrait(i) => from_bounds(&i.bounds),
        syn::Type::TraitObject(o) => from_bounds(&o.bounds),
        syn::Type::Reference(r) => callback_arg_types(&r.elem),
        syn::Type::Paren(p) => callback_arg_types(&p.elem),
        syn::Type::Group(g) => callback_arg_types(&g.elem),
        _ => None,
    }
}

fn pat_name(p: &syn::Pat) -> Option<String> {
    match p {
        syn::Pat::Ident(i) => Some(i.ident.to_string()),
        syn::Pat::Type(t) => pat_name(&t.pat),
        syn::Pat::Reference(r) => pat_name(&r.pat),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Recognising an acquisition.
// ---------------------------------------------------------------------------

fn strip_try(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Try(t) => strip_try(&t.expr),
        syn::Expr::Paren(p) => strip_try(&p.expr),
        syn::Expr::Group(g) => strip_try(&g.expr),
        _ => e,
    }
}

/// The receiver of `recv.lock().await` and friends, if this expression is an
/// acquisition. The receiver is what says *which* lock it is, and — once it
/// has a type — what the binding the guard is bound to holds.
fn acquisition_recv(e: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::Await(a) = strip_try(e) else {
        return None;
    };
    await_acquisition(a)
}

fn await_acquisition(a: &syn::ExprAwait) -> Option<&syn::Expr> {
    await_acquisition_call(a).map(|m| &*m.receiver)
}

/// The `.lock()`/`.read()`/… call an acquisition is made of, not merely its
/// receiver.
///
/// The distinction is what makes `Vault::lock` followable. Its name collides
/// with [`ACQUIRE`], and while the acquisition was recognised only by name the
/// scan skipped `note_call` for *every* method called `lock`, so no edge was
/// ever drawn into that method from anywhere — it was permanently invisible,
/// cheap today and on no list. An acquisition is always `recv.lock().await`;
/// a bare `v.lock()` is an ordinary call. Knowing which node is the
/// acquisition's own lets [`Walk::visit_expr_await`] skip that one node and
/// treat every other `lock` as the call it is.
fn await_acquisition_call(a: &syn::ExprAwait) -> Option<&syn::ExprMethodCall> {
    let syn::Expr::MethodCall(m) = strip_try(&a.base) else {
        return None;
    };
    (ACQUIRE.contains(&m.method.to_string().as_str()) && m.args.is_empty()).then_some(m)
}

/// Which lock an acquisition takes, with no type information: used where
/// there is no walk to ask — [`count_guard_bindings`] and [`scrutinee_locks`],
/// neither of which cares which lock it is.
fn acquisition(e: &syn::Expr) -> Option<Guard> {
    acquisition_recv(e).map(receiver_kind)
}

/// Which mutex a receiver names, by *name* — the fallback for a receiver whose
/// type the scan cannot see. This used to be the only answer, and it was a
/// hole: `receiver_kind` decided `Guard::State` from the binding name, so a
/// state lock reached under any other name classified as a collection lock and
/// was thereby *permitted* `block_in_place`, which is itself an offence under
/// the state guard. Naming is now the last resort; [`Walk::guard_of`] asks the
/// type first. The asymmetry is still deliberate in this direction: mistaking
/// a vault's lock for the state's would flag `block_in_place(|| v.save())`,
/// which `CLAUDE.md` *requires*, at every save site in the tree.
fn receiver_kind(e: &syn::Expr) -> Guard {
    fn tail(e: &syn::Expr) -> Option<String> {
        match e {
            syn::Expr::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
            syn::Expr::Field(f) => match &f.member {
                syn::Member::Named(i) => Some(i.to_string()),
                syn::Member::Unnamed(_) => None,
            },
            syn::Expr::MethodCall(m) => Some(m.method.to_string()),
            syn::Expr::Call(c) => tail(&c.func),
            syn::Expr::Reference(r) => tail(&r.expr),
            syn::Expr::Unary(u) => tail(&u.expr),
            syn::Expr::Paren(p) => tail(&p.expr),
            syn::Expr::Group(g) => tail(&g.expr),
            _ => None,
        }
    }
    match tail(e).as_deref() {
        Some("state") | Some("st") | Some("shared") => Guard::State,
        _ => Guard::Collection,
    }
}

/// Whether any acquisition appears anywhere in an expression — used on a
/// `match`/`while let`/`if let`/`for` scrutinee, which is not a terminating
/// scope, so a guard taken there outlives every arm.
fn scrutinee_locks(e: &syn::Expr) -> bool {
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_await(&mut self, a: &'ast syn::ExprAwait) {
            if await_acquisition(a).is_some() {
                self.0 = true;
            }
            visit::visit_expr_await(self, a);
        }
        // A closure in a scrutinee runs there too, but a nested `async` block
        // is polled elsewhere; neither changes the answer often enough to
        // model, and following both is the conservative side.
    }
    let mut f = Find(false);
    f.visit_expr(e);
    f.0
}

/// Whether an `if`/`while` condition is a `let` **chain** whose temporaries a
/// lock outlives.
///
/// `visit_expr_if` and `visit_expr_while` used to match a bare `Expr::Let` and
/// nothing else, so `if let Some(x) = a.lock().await.f() && cond` — which
/// parses as an `Expr::Binary` with the `let` on one side — walked straight
/// past the scrutinee rule. The tree uses let-chains freely, so that is the
/// shape a future edit is most likely to take.
///
/// A `let` anywhere in the condition is what makes the whole condition's
/// temporaries live to the end of the construct, so once one is present the
/// *whole* condition is the scrutinee — both `let` initialisers and the plain
/// operands beside them. A condition with no `let` in it is not one of these:
/// its temporaries are dropped before the body runs, which is why a plain
/// `if guard.lock().await.is_locked() {}` is not reported here.
fn let_chain_locks(cond: &syn::Expr) -> bool {
    struct HasLet(bool);
    impl<'ast> Visit<'ast> for HasLet {
        fn visit_expr_let(&mut self, l: &'ast syn::ExprLet) {
            self.0 = true;
            visit::visit_expr_let(self, l);
        }
        // A closure body in the condition is its own scope.
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut has = HasLet(false);
    has.visit_expr(cond);
    has.0 && scrutinee_locks(cond)
}

fn call_path(f: &syn::Expr) -> Option<Vec<String>> {
    match f {
        syn::Expr::Path(p) => Some(
            p.path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
        ),
        syn::Expr::Paren(p) => call_path(&p.expr),
        syn::Expr::Group(g) => call_path(&g.expr),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The walk over one function body, entered holding what `Entry` says.
// ---------------------------------------------------------------------------

struct Held {
    /// `None` for a region the *caller* opened, which no `drop(…)` in this
    /// body can end — including `drop(self)`, a legal no-op on a `&self`
    /// receiver that used to silence the whole rule.
    name: Option<String>,
    kind: Guard,
    label: String,
    depth: usize,
    /// A guard produced as a **temporary**, by an acquisition nobody binds:
    /// `vault.lock().await.update_item(id, f)`. Rust keeps such a temporary
    /// alive to the end of the enclosing statement, so that is the region,
    /// and [`Walk::drop_temporaries`] is what ends it. Modelling it is the
    /// difference between watching the shape `src/dbus/` actually writes and
    /// watching nothing at all: a temporary was pushed onto `held` by nothing,
    /// so `innermost()` was `None` and both the blocking check and `note_call`
    /// early-returned — the name list and the call graph blind together.
    temporary: bool,
}

/// A call site, as far as a signature-only view can describe it.
#[derive(Clone, Debug)]
struct Call {
    name: String,
    method: bool,
    /// The implementing type, when it is known: the receiver's declared type
    /// for a method, or an uppercase path qualifier for an associated
    /// function.
    on: Option<String>,
}

#[derive(Default)]
struct RunOut {
    /// `(file, line, why) -> the call path that reaches it`.
    offences: BTreeMap<(String, usize, String), String>,
    /// Calls made while a guard was held, and what the callee is entered
    /// holding.
    calls: Vec<(Call, Entry, usize)>,
    /// Every call this body makes, guard or no guard. This is the caller side
    /// of the call graph, and it is what answers "does anything call this?"
    /// for the dead-and-dangerous rule below.
    every_call: Vec<Call>,
    /// `(parameter index, guard)` for a parameter this function *invokes*
    /// while holding a guard — which makes a closure passed to it at any call
    /// site a guard region.
    invoked_params: Vec<(usize, Guard)>,
    guarded_calls: BTreeSet<(String, usize)>,
}

struct Walk<'a> {
    reg: &'a Registry,
    facts: &'a BTreeMap<(usize, usize), Guard>,
    me: usize,
    path: String,
    held: Vec<Held>,
    /// `(binding, type, depth)` for a local whose type is legible from its
    /// initialiser — `let mut state = ServiceState::new(…)`. `syn` does no
    /// inference, so this is the only way a call on a local receiver resolves,
    /// and it is the shape `src/daemon.rs` builds its state with: without it
    /// the daemon's own `state.loaded_ids()` and `state.merge_scan(scan)` are
    /// invisible and both methods read as uncalled.
    locals: Vec<(String, String, usize)>,
    depth: usize,
    exempt: usize,
    out: RunOut,
}

impl<'a> Walk<'a> {
    fn innermost(&self) -> Option<&Held> {
        // A `State` region outranks a collection lock nested inside it: the
        // rules that matter (no exemption, no `block_in_place`) are the
        // state's, and a site holding both is already an offence.
        self.held
            .iter()
            .find(|h| h.kind == Guard::State)
            .or_else(|| self.held.last())
    }

    /// End every temporary guard region opened above `base`.
    ///
    /// A temporary guard lives to the end of the statement that produced it —
    /// that is Rust's rule, not an approximation of one — so a statement is
    /// where its region ends. The `base` index is what keeps a temporary
    /// opened by an *enclosing* expression alive across a nested statement:
    /// `foo(v.lock().await.id(), { … })` holds the guard inside the block too.
    fn drop_temporaries(&mut self, base: usize) {
        let mut i = 0;
        self.held.retain(|h| {
            let keep = i < base || !h.temporary;
            i += 1;
            keep
        });
    }

    /// Visit an expression whose temporaries are dropped before anything that
    /// follows it runs — an `if`/`while` condition with no `let` in it.
    fn visit_temp_scoped(&mut self, e: &syn::Expr) {
        let base = self.held.len();
        Visit::visit_expr(self, e);
        self.drop_temporaries(base);
    }

    fn report(&mut self, span: Span, why: String) {
        let key = (self.reg.defs[self.me].file.clone(), span.start().line, why);
        let path = self.path.clone();
        self.out.offences.entry(key).or_insert(path);
    }

    fn blocking(&mut self, span: Span, what: &str) {
        let Some(h) = self.innermost() else { return };
        let (kind, label) = (h.kind, h.label.clone());
        match kind {
            Guard::State => self.report(
                span,
                format!(
                    "does blocking work (`{what}`) while {label} is held. \
                     `CLAUDE.md`: nothing slow or blocking may happen under the state \
                     mutex, and `{EXEMPT}` does not exempt it there — it releases the \
                     async worker, never the mutex"
                ),
            ),
            Guard::Collection => {
                if self.exempt == 0 {
                    self.report(
                        span,
                        format!(
                            "does blocking work (`{what}`) while {label} is held, and not \
                             inside a `{EXEMPT}`"
                        ),
                    );
                }
            }
        }
    }

    fn note_call(&mut self, call: Call, line: usize) {
        self.out.every_call.push(call.clone());
        let Some(h) = self.innermost() else { return };
        let entry = Entry::held(h.kind, h.kind == Guard::Collection && self.exempt > 0);
        self.out.guarded_calls.insert((call.name.clone(), line));
        self.out.calls.push((call, entry, line));
    }

    /// The type of an expression, as far as signatures, struct fields and
    /// `type` aliases can say — which is the whole of what `syn` offers,
    /// since it infers nothing.
    ///
    /// This is what resolves a method call on a receiver, and it is the piece
    /// the scan was missing. It used to type only `self`, a parameter, a
    /// state-guard binding, and a local whose initialiser was literally
    /// `Type::assoc(…)`. Production writes none of those at a vault write
    /// site: `let vault = self.vault().await.ok_or_else(…)?;` then
    /// `let mut vault = vault.lock().await;`. Following the *return* type of
    /// `Item::vault` (`Option<VaultRef>`, so `Vault`) and then the
    /// acquisition's receiver is what makes that second binding a `Vault` and
    /// the edge into `src/vault/store.rs` exist at all.
    fn expr_ty(&self, e: &syn::Expr) -> Option<String> {
        let me = &self.reg.defs[self.me];
        match e {
            syn::Expr::Path(p) if p.path.is_ident("self") => me.self_ty.clone(),
            syn::Expr::Path(p) => {
                let id = p.path.get_ident()?.to_string();
                if self
                    .held
                    .iter()
                    .any(|h| h.kind == Guard::State && h.name.as_deref() == Some(&id))
                {
                    return Some("ServiceState".to_string());
                }
                if let Some((_, ty, _)) = self.locals.iter().rev().find(|(n, _, _)| *n == id) {
                    return Some(ty.clone());
                }
                let i = me.params.iter().position(|n| *n == id)?;
                me.param_types.get(i).cloned().flatten()
            }
            syn::Expr::Field(f) => {
                let base = self.expr_ty(&f.base)?;
                let syn::Member::Named(n) = &f.member else {
                    return None;
                };
                self.reg.types.field(&base, &n.to_string())
            }
            syn::Expr::MethodCall(m) => {
                let name = m.method.to_string();
                // A wrapper peeled, not a call followed: `Option`/`Result`
                // unwrapping and the guard-producing calls all yield the
                // payload, which [`TypeMap::payload`] has already collapsed
                // the receiver's type to.
                if PASSTHROUGH.contains(&name.as_str())
                    || (ACQUIRE.contains(&name.as_str()) && m.args.is_empty())
                {
                    return self.expr_ty(&m.receiver);
                }
                let call = Call {
                    name,
                    method: true,
                    on: self.expr_ty(&m.receiver),
                };
                self.reg
                    .resolve(&call)
                    .iter()
                    .find_map(|&j| self.reg.defs[j].ret_ty.clone())
            }
            syn::Expr::Call(c) => {
                let segs = call_path(&c.func)?;
                let on = segs
                    .get(segs.len().wrapping_sub(2))
                    .filter(|s| s.starts_with(char::is_uppercase))
                    .cloned();
                let call = Call {
                    name: segs.last()?.clone(),
                    method: false,
                    on: on.clone(),
                };
                self.reg
                    .resolve(&call)
                    .iter()
                    .find_map(|&j| self.reg.defs[j].ret_ty.clone())
                    .or(on)
            }
            syn::Expr::Await(a) => self.expr_ty(&a.base),
            syn::Expr::Try(t) => self.expr_ty(&t.expr),
            syn::Expr::Reference(r) => self.expr_ty(&r.expr),
            syn::Expr::Unary(u) => self.expr_ty(&u.expr),
            syn::Expr::Paren(p) => self.expr_ty(&p.expr),
            syn::Expr::Group(g) => self.expr_ty(&g.expr),
            _ => None,
        }
    }

    /// Which lock an acquisition takes: the receiver's *type* where the scan
    /// has one, and only otherwise its name.
    ///
    /// The name-only answer was a hole with a direction: a state lock reached
    /// through a binding not called `state`/`st`/`shared` classified as a
    /// collection lock, and a collection lock is the one that *permits*
    /// `block_in_place` and blocking work inside it. Over-flagging is safe
    /// here and exempting is not, so the two answers are unioned rather than
    /// ranked: either the type or the name saying "state" makes it the state
    /// guard. The name alone still has to answer where the type is invisible
    /// — a synthetic case carries no `type Shared = …` for the alias table to
    /// resolve, and neither does a file that names its lock through something
    /// the scan cannot follow.
    fn guard_of(&self, recv: &syn::Expr) -> Guard {
        let by_type = self.expr_ty(recv).as_deref() == Some("ServiceState");
        if by_type || receiver_kind(recv) == Guard::State {
            Guard::State
        } else {
            Guard::Collection
        }
    }

    /// Visit the arguments of a call, giving a closure literal that the callee
    /// invokes under a guard its own region. This is what makes a closure
    /// passed *into* a guarded callee visible: `update_aliases` runs its
    /// `edit` argument with the state guard held, so the closure written at
    /// the call site is as much under the guard as the callee's own body.
    fn visit_args(&mut self, call: &Call, offset: usize, args: &[&syn::Expr]) {
        let callee = &call.name;
        let candidates = self.reg.resolve(call);
        for (i, arg) in args.iter().enumerate() {
            let idx = i + offset;
            let guard = candidates
                .iter()
                .filter_map(|&j| self.facts.get(&(j, idx)).copied())
                .max();
            match (guard, strip_try(arg)) {
                (Some(kind), syn::Expr::Closure(cl)) => {
                    let label = format!(
                        "{} — `{callee}` invokes this closure with it held",
                        kind.what()
                    );
                    self.held.push(Held {
                        name: None,
                        kind,
                        label: label.clone(),
                        depth: self.depth,
                        temporary: false,
                    });
                    // The closure's parameters, typed from the callee's
                    // declared callback signature — `syn` infers nothing, and
                    // an untyped receiver resolves no method call at all.
                    let types = candidates
                        .iter()
                        .find_map(|&j| self.reg.defs[j].callback_params.get(idx).cloned().flatten())
                        .unwrap_or_default();
                    let mut bound = Vec::new();
                    for (n, input) in cl.inputs.iter().enumerate() {
                        if let Some(name) = pat_name(input)
                            && let Some(Some(ty)) = types.get(n)
                        {
                            bound.push(name.clone());
                            let depth = self.depth;
                            self.locals.push((name, ty.clone(), depth));
                        }
                    }
                    Visit::visit_expr(self, arg);
                    self.locals.retain(|(n, _, _)| !bound.contains(n));
                    self.held.retain(|h| h.label != label);
                }
                _ => Visit::visit_expr(self, arg),
            }
        }
    }
}

impl<'ast> Visit<'ast> for Walk<'_> {
    fn visit_block(&mut self, b: &'ast syn::Block) {
        self.depth += 1;
        for s in &b.stmts {
            // A nested item is a separate function with its own callers; it is
            // registered in its own right and is not part of this region.
            if !matches!(s, syn::Stmt::Item(_)) {
                self.visit_stmt(s);
            }
        }
        let d = self.depth;
        self.held.retain(|h| h.depth < d);
        self.locals.retain(|(_, _, ld)| *ld < d);
        self.depth -= 1;
    }

    /// A statement is where a temporary guard's region ends. See
    /// [`Held::temporary`].
    fn visit_stmt(&mut self, s: &'ast syn::Stmt) {
        let base = self.held.len();
        visit::visit_stmt(self, s);
        self.drop_temporaries(base);
    }

    /// So is a `match` arm. `state::is_unlocked_path` writes one arm
    /// `!vault.lock().await.is_locked()` and the next `let v = vault.lock()
    /// .await;`, and the two arms are alternatives — treating the first arm's
    /// temporary as live in the second reported a second acquisition that
    /// cannot happen.
    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        let base = self.held.len();
        if let Some((_, cond)) = &a.guard {
            self.visit_expr(cond);
        }
        self.visit_expr(&a.body);
        self.drop_temporaries(base);
    }

    /// And so is a closure body written as a bare expression, for the same
    /// reason: it is not a statement, so nothing else would end the region.
    fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
        self.visit_temp_scoped(&c.body);
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        let Some(init) = &l.init else { return };
        self.visit_expr(&init.expr);
        if let Some((_, diverge)) = &init.diverge {
            self.visit_expr(diverge);
        }
        let acquired = acquisition_recv(&init.expr).map(|recv| (self.guard_of(recv), recv));
        // Every local the scan can type is typed, acquisition or not. A guard
        // binding is typed from what it is a guard *over* — that is the whole
        // fix: `visit_local` used to type a local only when the initialiser
        // was `Type::assoc(…)`, and deliberately typed nothing when the
        // initialiser was an acquisition, so `let mut vault = vault.lock()
        // .await` — the receiver every write in `src/dbus/` goes through —
        // left `vault` untyped, `Registry::resolve` dropped the edge, and
        // nothing was ever followed into `src/vault/`. The three synthetic
        // offenders that stood in for the real thing passed only because they
        // were written `let mut owned = Vault::open(p)?;`, a shape that
        // appears nowhere in `src/dbus/`.
        if let Some(name) = pat_name(&l.pat) {
            let ty = match acquired {
                Some((Guard::State, _)) => Some("ServiceState".to_string()),
                Some((Guard::Collection, recv)) => self.expr_ty(recv),
                None => self.expr_ty(&init.expr),
            };
            if let Some(ty) = ty {
                let depth = self.depth;
                self.locals.push((name, ty, depth));
            }
        }
        if let Some((kind, _)) = acquired {
            let name = pat_name(&l.pat);
            let label = match &name {
                Some(n) => format!("`{n}` ({})", kind.what()),
                None => kind.what().to_string(),
            };
            let depth = self.depth;
            self.held.push(Held {
                name,
                kind,
                label,
                depth,
                temporary: false,
            });
        }
    }

    fn visit_expr_await(&mut self, a: &'ast syn::ExprAwait) {
        let acq = await_acquisition_call(a);
        // Descend *first*. Two acquisitions can live in one expression —
        // `state.lock().await.vault(id).unwrap().lock().await.is_locked()`
        // holds both locks at once — and the inner one is the deeper node, so
        // a check made before descending saw nothing held and reported
        // nothing. Only the state half of that shape was ever covered, and
        // only by accident, because `vault` resolves to a `&self` method on
        // `ServiceState` and those are seeded; the *collection* half — the one
        // place `block_in_place` is mandatory — was invisible.
        match acq {
            // The acquisition's own `.lock()` is not a call into this crate:
            // it is this node. Visiting only its receiver leaves every other
            // `lock` a call, which is what makes `Vault::lock` followable at
            // all — see [`await_acquisition_call`].
            Some(m) => self.visit_expr(&m.receiver),
            None => visit::visit_expr_await(self, a),
        }
        let held = self.innermost().map(|h| (h.kind, h.label.clone()));
        match (acq.is_some(), held) {
            (true, Some((_, label))) => self.report(
                a.await_token.span(),
                format!("takes a lock while {label} is still held"),
            ),
            // The `.await` half of the first rule, which had no check at all.
            // `CLAUDE.md`: "Not an `.await` that can block, and not a
            // synchronous blocking call either" — only the synchronous half
            // was enforced, so a pinentry Assuan round trip, a
            // `SignalEmitter::…().await`, an `object_server().at(…).await`, a
            // `JoinHandle` await and a control-socket read were all invisible
            // under the state guard. None of them is bounded by a constant and
            // every one of them parks the global mutex for its duration.
            //
            // Scoped to the state guard on purpose: under a *collection's*
            // lock an `.await` is ordinary — that lock is one collection's,
            // nothing else wants it, and `CLAUDE.md` sanctions holding it
            // across the save. The acquisition that opens a region is not an
            // offence against itself; it is reported, if at all, by the arm
            // above.
            (false, Some((Guard::State, label))) => self.report(
                a.await_token.span(),
                format!(
                    "`.await`s while {label} is held. `CLAUDE.md`: nothing slow or \
                     blocking may happen under the state mutex, and that is not an \
                     `.await` that can block either — the guard is held across the \
                     suspension, so every other bus call, control request and \
                     housekeeping task waits on whatever this is waiting for. Clone \
                     what is needed out of the state, drop the guard, and await after"
                ),
            ),
            _ => {}
        }
        // The guard this acquisition produces. A `let` binding gets its own,
        // named, region from `visit_local`; this one is the *temporary*, and
        // it is the whole point — `vault.lock().await.update_item(id, f)` is
        // how `src/dbus/` writes a vault call about twenty-five times, and
        // until now it opened no region at all.
        if let Some(m) = acq {
            let kind = self.guard_of(&m.receiver);
            let depth = self.depth;
            self.held.push(Held {
                name: None,
                kind,
                label: format!("{} taken as a temporary", kind.what()),
                depth,
                temporary: true,
            });
        }
    }

    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        if scrutinee_locks(&m.expr) {
            self.report(
                m.match_token.span(),
                "takes a lock in a `match` scrutinee, which holds the guard across every arm"
                    .to_string(),
            );
        }
        visit::visit_expr_match(self, m);
    }

    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        if let_chain_locks(&e.cond) {
            self.report(
                e.if_token.span(),
                "takes a lock in an `if let` scrutinee, which holds the guard across the \
                 whole construct"
                    .to_string(),
            );
        }
        // A condition with no `let` in it drops its temporaries before the
        // body runs, so a guard taken there is not held across the branches.
        // (A let-chain does hold it — and is refused outright, just above.)
        self.visit_temp_scoped(&e.cond);
        self.visit_block(&e.then_branch);
        if let Some((_, alt)) = &e.else_branch {
            self.visit_expr(alt);
        }
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        if let_chain_locks(&e.cond) {
            self.report(
                e.while_token.span(),
                "takes a lock in a `while let` scrutinee, which holds the guard across \
                 every iteration"
                    .to_string(),
            );
        }
        self.visit_temp_scoped(&e.cond);
        self.visit_block(&e.body);
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        if scrutinee_locks(&e.expr) {
            self.report(
                e.for_token.span(),
                "takes a lock in a `for` iterator expression, which holds the guard \
                 across every iteration"
                    .to_string(),
            );
        }
        visit::visit_expr_for_loop(self, e);
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        let segs = call_path(&c.func).unwrap_or_default();
        let last = segs.last().cloned().unwrap_or_default();
        let args: Vec<&syn::Expr> = c.args.iter().collect();
        let line = c.func.span().start().line;

        // `drop(g)` ends the region `g` opened. Only a *named* region: a
        // caller's guard has no binding here, so `drop(self)` — a no-op on a
        // `&self` receiver — cannot end one.
        if last == "drop" && args.len() == 1 {
            if segs.len() == 1
                && let Some(n) = call_path(args[0]).and_then(|p| p.first().cloned())
            {
                self.held.retain(|h| h.name.as_deref() != Some(n.as_str()));
            }
            visit::visit_expr_call(self, c);
            return;
        }

        // Work handed to another thread or task takes nothing with it.
        if DETACHED.contains(&last.as_str()) {
            let saved = std::mem::take(&mut self.held);
            visit::visit_expr_call(self, c);
            self.held = saved;
            return;
        }

        if last == EXEMPT {
            let statey = self.held.iter().any(|h| h.kind == Guard::State);
            if statey {
                let label = self
                    .innermost()
                    .map(|h| h.label.clone())
                    .unwrap_or_default();
                self.report(
                    c.func.span(),
                    format!(
                        "wraps blocking work in `{EXEMPT}` while {label} is held. \
                         `{EXEMPT}` releases the async worker, not the mutex, so the \
                         work still stops every other task; `CLAUDE.md` sanctions it \
                         for a collection's lock only"
                    ),
                );
            }
            let bump = !statey && !self.held.is_empty();
            if bump {
                self.exempt += 1;
            }
            self.visit_expr(&c.func);
            let call = Call {
                name: last.clone(),
                method: false,
                on: None,
            };
            self.visit_args(&call, 0, &args);
            if bump {
                self.exempt -= 1;
            }
            return;
        }

        // A parameter of *this* function, called while a guard is held: any
        // closure a caller passes for it runs under that guard.
        if segs.len() == 1
            && let Some(idx) = self.reg.defs[self.me]
                .params
                .iter()
                .position(|p| *p == last)
            && let Some(h) = self.innermost()
        {
            let kind = h.kind;
            self.out.invoked_params.push((idx, kind));
        }

        let blocking = BLOCKING_FNS.contains(&last.as_str())
            || segs.iter().any(|s| s == "fs")
            || segs.first().map(|s| s == "File").unwrap_or(false);
        if blocking && !last.is_empty() {
            self.blocking(c.func.span(), &tidy(&segs.join("::")));
        }
        // `ServiceState::new(…)` names its type; `state::save_aliases_to(…)`
        // names a module, which says nothing about which definition it is.
        let on = segs
            .get(segs.len().wrapping_sub(2))
            .filter(|s| s.starts_with(char::is_uppercase))
            .cloned();
        let call = Call {
            name: last.clone(),
            method: false,
            on,
        };
        self.note_call(call.clone(), line);
        self.visit_expr(&c.func);
        self.visit_args(&call, 0, &args);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let name = m.method.to_string();
        let line = m.method.span().start().line;
        let args: Vec<&syn::Expr> = m.args.iter().collect();

        if DETACHED.contains(&name.as_str()) {
            let saved = std::mem::take(&mut self.held);
            visit::visit_expr_method_call(self, m);
            self.held = saved;
            return;
        }
        // The **receiver first**, and this order is the fix. An acquisition
        // consumed as a temporary — `vault.lock().await.update_item(id, f)` —
        // opens its region while the receiver is visited, so by the time the
        // call on it is examined the guard is held. Checking the call before
        // descending was the hole: `innermost()` answered `None`, and both
        // `blocking` and `note_call` early-return on that, so the shape
        // `src/dbus/` actually writes was invisible to the name list and to
        // the call graph at once. Visiting the receiver first is also what
        // keeps the acquisition's own `.await` from reading as a *second*
        // lock: the region opens after that check, not before it.
        self.visit_expr(&m.receiver);
        if BLOCKING_METHODS.contains(&name.as_str()) {
            self.blocking(m.method.span(), &name);
        }
        let call = Call {
            name: name.clone(),
            method: true,
            on: self.expr_ty(&m.receiver),
        };
        // Every method call is an edge, `lock` included. The acquisition's own
        // `.lock()` never reaches here — `visit_expr_await` visits just its
        // receiver — so excluding [`ACQUIRE`] by name is no longer needed, and
        // it used to make `Vault::lock` permanently unreachable.
        self.note_call(call.clone(), line);
        self.visit_args(&call, 1, &args);
    }

    /// `syn` does not parse the inside of a macro invocation, so a lock or an
    /// `fsync` written inside one would be invisible. Fall back to matching
    /// the token text there — the one place this scan still reads characters,
    /// and it can only add findings, never remove them.
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if self.held.is_empty() {
            return;
        }
        let text = macro_code(&m.tokens);
        for a in ACQUIRE {
            if text.contains(&format!(".{a}().await")) {
                self.report(
                    m.span(),
                    format!("takes a lock inside a macro invocation (`.{a}().await`) while a guard is held"),
                );
            }
        }
        for b in BLOCKING_FNS {
            if text.contains(&format!("{b}(")) {
                self.blocking(m.span(), b);
            }
        }
    }
}

/// A macro invocation's tokens as text, **with literals dropped**.
///
/// The macro rule is the one place this scan still matches characters, and it
/// used to match them against the whole token text — string literals included,
/// with whitespace stripped, so `tracing::debug!("about to sync_all() the
/// vault")` under a guard read as an `fsync` and a literal mentioning
/// `.lock().await` read as an acquisition. Findings against source that does
/// not exist are the failure mode this file exists to avoid, and there was an
/// offender for the macro rule but no near-miss, so nothing said so.
///
/// Delimiters are kept, because the patterns matched against this are written
/// with them — `.lock().await`, `sync_all(` — and groups are recursed into,
/// because a literal nested inside one is still a literal. A `char` literal is
/// one too, which is incidentally how `'}'` stops being a brace.
fn macro_code(tokens: &proc_macro2::TokenStream) -> String {
    fn go(ts: proc_macro2::TokenStream, out: &mut String) {
        for t in ts {
            match t {
                proc_macro2::TokenTree::Literal(_) => {}
                proc_macro2::TokenTree::Group(g) => {
                    let (open, close) = match g.delimiter() {
                        proc_macro2::Delimiter::Parenthesis => ("(", ")"),
                        proc_macro2::Delimiter::Brace => ("{", "}"),
                        proc_macro2::Delimiter::Bracket => ("[", "]"),
                        proc_macro2::Delimiter::None => ("", ""),
                    };
                    out.push_str(open);
                    go(g.stream(), out);
                    out.push_str(close);
                }
                other => out.push_str(&other.to_string()),
            }
        }
    }
    let mut s = String::new();
    go(tokens.clone(), &mut s);
    s.retain(|c| !c.is_whitespace());
    s
}

// ---------------------------------------------------------------------------
// The fixed point.
// ---------------------------------------------------------------------------

struct Scan {
    offences: Vec<String>,
    /// `let`-bound guard acquisitions across the scanned files.
    guard_bindings: usize,
    /// Functions whose whole body is a state-guard region because of their
    /// signature — a `&ServiceState`/`&mut ServiceState`/`MutexGuard`
    /// parameter, or a `&self` receiver in an `impl ServiceState`.
    seeds: usize,
    /// Of those, the ones seeded from a receiver — the population
    /// [`dead_and_dangerous`] ranges over.
    receiver_seeds: usize,
    /// Functions reached, through the call graph, while a guard is held.
    /// Zero would mean the graph is not being walked.
    guarded_fns: usize,
    /// Distinct call sites that run with a guard held.
    guarded_calls: usize,
    functions: usize,
}

/// One walk of the whole call graph from a given set of roots.
struct Pass {
    offences: BTreeMap<(String, usize, String), String>,
    guarded_calls: BTreeSet<(String, usize)>,
    /// `(function, parameter index) -> the guard the function invokes that
    /// parameter under`, which makes a closure passed there a guard region.
    facts: BTreeMap<(usize, usize), Guard>,
    guarded: BTreeSet<usize>,
    /// Every function some *production* (non-`#[cfg(test)]`) body calls.
    called_from_production: BTreeSet<usize>,
}

fn run_pass(
    reg: &Registry,
    facts: &BTreeMap<(usize, usize), Guard>,
    mut work: Vec<(usize, Entry, String)>,
) -> Pass {
    let mut out = Pass {
        offences: BTreeMap::new(),
        guarded_calls: BTreeSet::new(),
        facts: facts.clone(),
        guarded: BTreeSet::new(),
        called_from_production: BTreeSet::new(),
    };
    let mut seen: BTreeSet<(usize, Entry)> = BTreeSet::new();
    while let Some((i, entry, path)) = work.pop() {
        if !seen.insert((i, entry)) {
            continue;
        }
        if entry.guard.is_some() {
            out.guarded.insert(i);
        }
        let mut walk = Walk {
            reg,
            facts,
            me: i,
            path: path.clone(),
            held: match entry.guard {
                Some(kind) => vec![Held {
                    name: None,
                    kind,
                    label: format!("{} (held by the caller)", kind.what()),
                    depth: 0,
                    temporary: false,
                }],
                None => Vec::new(),
            },
            locals: Vec::new(),
            depth: 0,
            exempt: usize::from(entry.exempt),
            out: RunOut::default(),
        };
        let block = reg.defs[i].block.clone();
        walk.visit_block(&block);
        let run = walk.out;

        for (k, v) in run.offences {
            out.offences.entry(k).or_insert(v);
        }
        out.guarded_calls.extend(run.guarded_calls);
        for (idx, kind) in run.invoked_params {
            let slot = out.facts.entry((i, idx)).or_insert(kind);
            *slot = (*slot).max(kind);
        }
        if !reg.defs[i].in_test {
            for call in &run.every_call {
                out.called_from_production.extend(reg.resolve(call));
            }
        }
        for (call, ce, _line) in run.calls {
            let cands = reg.resolve(&call);
            let n = cands.len();
            for j in cands {
                let ambiguous = if n > 1 {
                    format!(" [1 of {n} definitions named `{}`]", call.name)
                } else {
                    String::new()
                };
                work.push((
                    j,
                    ce,
                    format!("{path} → {}{ambiguous}", reg.defs[j].display),
                ));
            }
        }
    }
    out
}

/// Where a walk starts.
///
/// Every function is walked once holding nothing. On top of that, a function
/// whose signature puts its whole body under the state guard is walked again
/// with the guard held — a **parameter** of type `&ServiceState`,
/// `&mut ServiceState` or `MutexGuard<'_, ServiceState>`, which cannot be
/// produced any other way, and equally a `&self`/`&mut self` **receiver** in
/// an `impl ServiceState`, which is the same borrow one position further in.
///
/// The receiver seed is unconditional, and that is stronger than seeding it
/// only where the call graph carries a guard in. Reachability waits: a
/// blocking method added today says nothing until someone gives it a guarded
/// caller, and by then the call is written. Seeding says it at the moment the
/// method appears.
///
/// It was not always unconditional. `ServiceState::load_vaults` fused the
/// blocking vault-directory scan to the pure merge, and `src/daemon.rs`
/// called it on the owned value one line before wrapping it in the `Mutex` —
/// a call that provably held no lock, because the lock did not yet exist. One
/// method made the premise false for all of them, and the seed was weakened
/// to a reachability question to accommodate it. The method is gone: startup
/// takes the two steps explicitly, the free `scan_vault_dir` and then
/// `merge_scan`, which is what `Request::Reload` had always done. Nothing in
/// the tree is now called on a `ServiceState` that no mutex owns.
///
/// The hole the seed does not reach is a method with **no caller at all**:
/// it is walked, but so is every other function, and nothing distinguishes
/// it. That is exactly what `unique_collection_id` and `save_aliases` were,
/// and [`dead_and_dangerous`] is what names it.
fn entry_points(reg: &Registry) -> Vec<(usize, Entry, String)> {
    let mut work = Vec::new();
    for (i, d) in reg.defs.iter().enumerate() {
        // A `#[cfg(test)]` body is not a root. The rules are about what the
        // daemon does with a lock held, and a unit test that locks a vault by
        // hand and calls `Vault::unlock` on it — `src/dbus/state.rs`'s own
        // fixtures do exactly that — is not the daemon doing anything. The
        // production callers of the same methods are walked from their own
        // roots, and `called_from_production` already refuses to count a test
        // as a caller, so nothing this rule reports is lost. Before
        // `src/vault/` was parsed these bodies resolved to no definition and
        // the question never arose.
        if d.in_test {
            continue;
        }
        work.push((i, Entry::NONE, d.display.clone()));
        if let Some((g, why)) = &d.seed {
            work.push((
                i,
                Entry::held(*g, false),
                format!(
                    "{} ({}:{}) — entered holding {} via {why}",
                    d.display,
                    d.file,
                    d.line,
                    g.what()
                ),
            ));
        }
    }
    work
}

/// The companion to the seeding rule above: a `&self`/`&mut self` method on
/// `ServiceState` that offends when walked under the guard, and that
/// **nothing in production calls at all**.
///
/// The seed above already walks such a method with the guard held, so a body
/// that blocks is reported either way. What this adds is the *diagnosis*, and
/// it is a different one: "nothing calls it" reads as a defence, and it is
/// not. Holding `&self` on `ServiceState` *is* holding the guard, so the only
/// caller such a method can ever acquire is one that already has it; a
/// blocking body sitting there is a deadlock-shaped hole with a doc comment
/// inviting someone to fill it, and the fix is deletion rather than a
/// carefully placed call. Both methods this rule was written from —
/// `unique_collection_id` and `save_aliases` — were precisely that: no
/// production caller, kept alive by their own unit tests, each a delegation
/// away from a `fsync` under the global mutex.
///
/// Tests are not production callers — a `#[cfg(test)]` module keeping a
/// method alive is the symptom, not the excuse.
fn dead_and_dangerous(
    reg: &Registry,
    facts: &BTreeMap<(usize, usize), Guard>,
    called: &BTreeSet<usize>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (i, d) in reg.defs.iter().enumerate() {
        if !d.receiver_seed || d.in_test || called.contains(&i) {
            continue;
        }
        let probe = run_pass(
            reg,
            facts,
            vec![(
                i,
                Entry::held(Guard::State, false),
                format!("{} — probed as if a caller held the state guard", d.display),
            )],
        );
        if probe.offences.is_empty() {
            continue;
        }
        let would: Vec<String> = probe
            .offences
            .into_iter()
            .map(|((file, line, why), path)| {
                format!("        {file}:{line}: {why}\n            reached as: {path}")
            })
            .collect();
        out.push(format!(
            "{}:{}: `{}` is dead and dangerous: a `{}` method on `ServiceState` that \
             blocks or takes a second lock, and that nothing outside `#[cfg(test)]` \
             calls. Holding `&self` on the state *is* holding the guard, so the only \
             caller it can ever gain is one that already has it. Delete it, and give \
             its tests the helper underneath. Were it called under the guard it would \
             report:\n{}",
            d.file,
            d.line,
            d.display,
            if d.seed.as_ref().is_some_and(|(_, w)| w.contains("mut")) {
                "&mut self"
            } else {
                "&self"
            },
            would.join("\n"),
        ));
    }
    out
}

fn scan_files(files: &[(String, String)]) -> Scan {
    let reg = Registry::build(files);
    let mut facts: BTreeMap<(usize, usize), Guard> = BTreeMap::new();

    let guard_bindings = count_guard_bindings(&reg);

    loop {
        let pass = run_pass(&reg, &facts, entry_points(&reg));
        if pass.facts == facts {
            let mut list: Vec<String> = pass
                .offences
                .into_iter()
                .map(|((file, line, why), path)| {
                    format!("{file}:{line}: {why}\n    reached as: {path}")
                })
                .collect();
            list.extend(dead_and_dangerous(
                &reg,
                &facts,
                &pass.called_from_production,
            ));
            list.sort();
            return Scan {
                offences: list,
                guard_bindings,
                // Production only. `entry_points` already refuses to root a
                // walk in a `#[cfg(test)]` body, and a floor these counted
                // could be satisfied entirely by `src/dbus/state.rs`'s test
                // fixtures — which lock vaults by hand and call `Vault::unlock`
                // on them — while the production code the floor is about had
                // moved out from under the scan. The assertion message would
                // then be asserting the opposite of what it checked.
                seeds: reg
                    .defs
                    .iter()
                    .filter(|d| !d.in_test && d.seed.is_some())
                    .count(),
                receiver_seeds: reg
                    .defs
                    .iter()
                    .filter(|d| !d.in_test && d.receiver_seed)
                    .count(),
                guarded_fns: pass.guarded.len(),
                guarded_calls: pass.guarded_calls.len(),
                functions: reg.defs.iter().filter(|d| !d.in_test).count(),
            };
        }
        facts = pass.facts;
    }
}

fn count_guard_bindings(reg: &Registry) -> usize {
    struct Count(usize);
    impl<'ast> Visit<'ast> for Count {
        fn visit_local(&mut self, l: &'ast syn::Local) {
            if let Some(init) = &l.init
                && acquisition(&init.expr).is_some()
            {
                self.0 += 1;
            }
            visit::visit_local(self, l);
        }
    }
    let mut c = Count(0);
    for d in &reg.defs {
        // Production only, for the reason the other canaries are: a guard a
        // test fixture binds is not the daemon binding one.
        if d.in_test {
            continue;
        }
        c.visit_block(&d.block);
    }
    c.0
}

/// One synthetic file, for the self-test below.
fn scan(name: &str, text: &str) -> Scan {
    scan_files(&[(name.to_string(), text.to_string())])
}
