mod common;

use common::{Fixture, PASSWORD, wait_for};
use futures_util::StreamExt;
use secret_manager::dbus::paths;
use secret_manager::dbus::proxies::{CollectionProxy, PromptProxy, ServiceProxy, SessionProxy};
use secret_manager::protocol::{KEY_LEN, KdfParams, Request, Response, SALT_LEN, Zeroizing, call};
use secret_manager::session::ALGORITHM_PLAIN;
use secret_manager::vault::Vault;
use secret_manager::vault::crypto;
use std::time::Duration;
use zbus::zvariant::Value;

async fn control(fx: &Fixture, req: Request) -> Response {
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || call(&sock, &req))
        .await
        .unwrap()
        .unwrap()
}

/// Salt and Argon2 parameters straight from the collection's vault file —
/// the same source the CLI and the PAM module use, so no answer from the
/// socket can influence what a password is hashed with.
fn header_params(fx: &Fixture, collection: &str) -> ([u8; SALT_LEN], KdfParams) {
    let path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join(format!("{collection}.vault"));
    let bytes = std::fs::read(&path).unwrap();
    let header = secret_manager::vault::format::decode_header(&bytes).unwrap();
    (header.salt, header.kdf)
}

/// The wire form of a key derived from `password` under `collection`'s header.
fn key_for(fx: &Fixture, collection: &str, password: &str) -> Zeroizing<[u8; KEY_LEN]> {
    let (salt, kdf) = header_params(fx, collection);
    let key = crypto::derive_key(password.as_bytes(), &salt, kdf).unwrap();
    Zeroizing::new(*key.as_bytes())
}

/// Rotate `collection` from `old` to `new`, deriving both keys locally.
fn change_key_req(fx: &Fixture, collection: &str, old: &str, new: &str) -> Request {
    let (_, kdf) = header_params(fx, collection);
    let new_salt = crypto::random_bytes::<SALT_LEN>();
    let new_key = crypto::derive_key(new.as_bytes(), &new_salt, kdf).unwrap();
    Request::ChangeKey {
        collection: collection.to_string(),
        old_key: key_for(fx, collection, old),
        new_salt,
        new_kdf: kdf,
        new_key: Zeroizing::new(*new_key.as_bytes()),
    }
}

fn unlock_with(fx: &Fixture, collection: &str, password: &str) -> Request {
    Request::UnlockWithKey {
        collection: collection.to_string(),
        key: key_for(fx, collection, password),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_socket_status_unlock_lock_change_password() {
    let fx = Fixture::start().await;
    match control(&fx, Request::Status).await {
        Response::Status { collections, .. } => {
            assert_eq!(collections.len(), 1);
            assert_eq!(collections[0].id, "default");
            assert_eq!(collections[0].label, "Default");
            assert!(collections[0].locked);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        control(&fx, unlock_with(&fx, "default", "nope")).await,
        Response::Error(_)
    ));
    assert!(matches!(
        control(
            &fx,
            Request::UnlockWithKey {
                collection: "missing".into(),
                key: key_for(&fx, "default", PASSWORD),
            }
        )
        .await,
        Response::Error(_)
    ));

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut changed = service.receive_collection_changed().await.unwrap();
    assert_eq!(
        control(&fx, unlock_with(&fx, "default", PASSWORD)).await,
        Response::Ok
    );
    assert_eq!(
        changed.next().await.unwrap().args().unwrap().collection,
        fx.default_collection()
    );
    match control(&fx, Request::Status).await {
        Response::Status { collections, .. } => assert!(!collections[0].locked),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        control(&fx, Request::Lock { collection: None }).await,
        Response::Ok
    );
    assert!(secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);

    assert!(matches!(
        control(&fx, change_key_req(&fx, "default", "bad", "x")).await,
        Response::Error(_)
    ));
    assert_eq!(
        control(&fx, change_key_req(&fx, "default", PASSWORD, "new")).await,
        Response::Ok
    );
    assert_eq!(
        control(
            &fx,
            Request::Lock {
                collection: Some("default".into())
            }
        )
        .await,
        Response::Ok
    );
    assert!(matches!(
        control(&fx, unlock_with(&fx, "default", PASSWORD)).await,
        Response::Error(_)
    ));
    assert_eq!(
        control(&fx, unlock_with(&fx, "default", "new")).await,
        Response::Ok
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_picks_up_new_vault_files() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut created = service.receive_collection_created().await.unwrap();
    let dir = fx.data_dir.path().join("secret-manager");
    Vault::create(
        &dir.join("extra.vault"),
        "Extra",
        b"x",
        KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    let extra = paths::collection("extra");
    assert_eq!(
        created.next().await.unwrap().args().unwrap().collection,
        extra
    );
    assert!(service.collections().await.unwrap().contains(&extra));
    let coll = CollectionProxy::builder(&conn)
        .path(extra)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_eq!(coll.label().await.unwrap(), "Extra");
    assert_eq!(
        control(&fx, Request::Reload).await,
        Response::Ok,
        "reload is idempotent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_and_prompts_die_with_their_client() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, session) = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert_eq!(fx.daemon.state.lock().await.sessions.len(), 1);
    assert_eq!(fx.daemon.state.lock().await.prompt_owners.len(), 1);
    drop(service);
    drop(conn);
    assert!(
        wait_for(Duration::from_secs(3), || async {
            let st = fx.daemon.state.lock().await;
            st.sessions.is_empty() && st.prompt_owners.is_empty()
        })
        .await
    );
    let conn2 = fx.client().await;
    let s = SessionProxy::builder(&conn2)
        .path(session)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(s.close().await.is_err(), "session object removed");
    let p = PromptProxy::builder(&conn2)
        .path(prompt)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(p.dismiss().await.is_err(), "prompt object removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_lock_locks_after_inactivity() {
    let fx = Fixture::start_with_idle(Duration::from_millis(500)).await;
    fx.unlock_default().await;
    fx.daemon.state.lock().await.touch();
    assert!(!secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);
    assert!(
        wait_for(Duration::from_secs(5), || async {
            secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await
        })
        .await
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_daemon_exits_with_code_3() {
    let fx = Fixture::start().await;
    let mut cmd = fx.sm();
    cmd.arg("daemon");
    let out = cmd.timeout(Duration::from_secs(20)).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("already owns"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_socket_removed_on_shutdown() {
    let fx = Fixture::start().await;
    let sock = fx.control_socket();
    assert!(sock.exists());
    let Fixture { daemon, .. } = fx;
    drop(daemon);
    assert!(wait_for(Duration::from_secs(2), || async { !sock.exists() }).await);
}

/// A `<id>.vault` file that fails to parse should still show up (locked) in
/// `Service.Collections`/`Status`, and `Unlock` on it should report the
/// format error rather than "no collection".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_vault_file_appears_locked_with_format_error() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    std::fs::write(dir.join("broken.vault"), b"not a real vault file").unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    match control(&fx, Request::Status).await {
        Response::Status { collections, .. } => {
            let broken = collections
                .iter()
                .find(|c| c.id == "broken")
                .expect("corrupt vault should still be listed, locked");
            assert!(broken.locked);
        }
        other => panic!("{other:?}"),
    }
    match control(
        &fx,
        Request::UnlockWithKey {
            collection: "broken".into(),
            key: key_for(&fx, "default", "whatever"),
        },
    )
    .await
    {
        Response::Error(msg) => assert!(
            msg.to_lowercase().contains("magic")
                || msg.to_lowercase().contains("format")
                || msg.to_lowercase().contains("invalid"),
            "expected a format error, got: {msg}"
        ),
        other => panic!("{other:?}"),
    }
}

/// Once the daemon is up, the process must be non-dumpable so same-uid
/// processes cannot ptrace it or read `/proc/<pid>/mem`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_start_makes_the_process_non_dumpable() {
    let _fx = Fixture::start().await;
    // SAFETY: PR_GET_DUMPABLE takes no pointers and cannot fail.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(dumpable, 0);
}

/// The PAM and CLI path: read salt and parameters from the vault file,
/// derive locally, unlock and rotate by key. No password, and no
/// salt/parameter choice, ever crosses the socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_socket_key_based_unlock_and_rotation() {
    let fx = Fixture::start().await;
    let (salt, kdf) = header_params(&fx, "default");
    assert_eq!(kdf, KdfParams::FAST_FOR_TESTS);
    let key = crypto::derive_key(PASSWORD.as_bytes(), &salt, kdf).unwrap();
    let wrong = crypto::derive_key(b"nope", &salt, kdf).unwrap();
    let as_wire = |k: &crypto::Key| Zeroizing::new(*k.as_bytes());

    assert!(matches!(
        control(
            &fx,
            Request::UnlockWithKey {
                collection: "default".into(),
                key: as_wire(&wrong),
            }
        )
        .await,
        Response::Error(_)
    ));
    assert_eq!(
        control(
            &fx,
            Request::UnlockWithKey {
                collection: "default".into(),
                key: as_wire(&key),
            }
        )
        .await,
        Response::Ok
    );
    assert!(!secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);

    let new_salt = crypto::random_bytes::<SALT_LEN>();
    let new_key = crypto::derive_key(b"rotated", &new_salt, kdf).unwrap();
    assert_eq!(
        control(
            &fx,
            Request::ChangeKey {
                collection: "default".into(),
                old_key: as_wire(&key),
                new_salt,
                new_kdf: kdf,
                new_key: as_wire(&new_key),
            }
        )
        .await,
        Response::Ok
    );
    assert!(
        !secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "was unlocked on entry, stays unlocked"
    );
    assert_eq!(
        control(&fx, Request::Lock { collection: None }).await,
        Response::Ok
    );
    // The rotation is visible in the file the next caller will read.
    assert_eq!(header_params(&fx, "default").0, new_salt);
    assert!(matches!(
        control(
            &fx,
            Request::UnlockWithKey {
                collection: "default".into(),
                key: as_wire(&key),
            }
        )
        .await,
        Response::Error(_)
    ));
    assert_eq!(
        control(
            &fx,
            Request::UnlockWithKey {
                collection: "default".into(),
                key: as_wire(&new_key),
            }
        )
        .await,
        Response::Ok
    );
    // Rotation on a locked vault leaves it locked.
    assert_eq!(
        control(&fx, Request::Lock { collection: None }).await,
        Response::Ok
    );
    let third_salt = crypto::random_bytes::<SALT_LEN>();
    let third_key = crypto::derive_key(b"third", &third_salt, kdf).unwrap();
    assert_eq!(
        control(
            &fx,
            Request::ChangeKey {
                collection: "default".into(),
                old_key: as_wire(&new_key),
                new_salt: third_salt,
                new_kdf: kdf,
                new_key: as_wire(&third_key),
            }
        )
        .await,
        Response::Ok
    );
    assert!(secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);
    // An unsafe KDF in a rotation request is refused outright.
    assert!(matches!(
        control(
            &fx,
            Request::ChangeKey {
                collection: "default".into(),
                old_key: as_wire(&third_key),
                new_salt: third_salt,
                new_kdf: KdfParams {
                    m_cost_kib: u32::MAX,
                    t_cost: 1,
                    p_cost: 1
                },
                new_key: as_wire(&third_key),
            }
        )
        .await,
        Response::Error(_)
    ));
}

/// With `locked_search = false` a locked collection matches nothing, and a
/// vault that already carried attribute hashes is scrubbed on first unlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_search_off_hides_attributes_until_unlock() {
    let fx = Fixture::start_with_config(|c| c.vault.locked_search = false).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    fx.unlock_default().await;
    let session = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap()
        .1;
    let coll = CollectionProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();
    let attrs: std::collections::HashMap<String, String> =
        [("app".to_string(), "git".to_string())].into();
    let props = std::collections::HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label",
            Value::from("x".to_string()),
        ),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
    ]);
    let secret = secret_manager::dbus::session::SecretStruct {
        session,
        parameters: vec![],
        value: b"s".to_vec(),
        content_type: "text/plain".into(),
    };
    let (item, _) = coll.create_item(props, &secret, false).await.unwrap();
    let query = std::collections::HashMap::from([("app", "git")]);
    let (unlocked, locked) = service.search_items(query.clone()).await.unwrap();
    assert_eq!(unlocked, vec![item.clone()]);
    assert!(locked.is_empty());
    fx.lock_default().await;
    let (unlocked, locked) = service.search_items(query).await.unwrap();
    assert!(unlocked.is_empty());
    assert!(
        locked.is_empty(),
        "locked search must not use attribute hashes"
    );
    let vault_path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");
    assert!(!Vault::open(&vault_path).unwrap().index_has_attributes());
}

/// A `broken` entry must disappear once its file does, instead of being
/// advertised as a locked collection until the daemon restarts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_forgets_a_broken_vault_whose_file_was_removed() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    let bad = dir.join("broken.vault");
    std::fs::write(&bad, b"not a real vault file").unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    let listed = |r: Response| match r {
        Response::Status { collections, .. } => collections.iter().any(|c| c.id == "broken"),
        other => panic!("{other:?}"),
    };
    assert!(listed(control(&fx, Request::Status).await));

    std::fs::remove_file(&bad).unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    assert!(
        !listed(control(&fx, Request::Status).await),
        "a removed vault file must not stay listed as a broken collection"
    );
}

/// A failed index rescrub is reported through `Status`, not just logged:
/// otherwise `locked_search = false` could silently never take effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_reports_an_index_that_could_not_be_rewritten() {
    let fx = Fixture::start().await;
    let path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");

    // Give the collection an item with attributes, so its header carries
    // hashes and switching the policy owes a rewrite.
    secret_manager::dbus::state::with_vault(&fx.daemon.state, "default", |vault| {
        vault.unlock(PASSWORD.as_bytes()).unwrap();
        vault
            .insert_item(
                "x",
                [("a".to_string(), "b".to_string())].into(),
                b"s".to_vec(),
                "text/plain",
                false,
            )
            .unwrap();
        assert!(vault.index_has_attributes());
        vault.lock();
        vault.set_index_attributes(false);
    })
    .await;

    // Make the rewrite fail: a directory where the vault file belongs means
    // the final rename cannot succeed, whatever the permissions.
    let saved = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    secret_manager::dbus::state::with_vault(&fx.daemon.state, "default", |vault| {
        vault.unlock(PASSWORD.as_bytes()).unwrap();
        assert!(vault.index_warning().is_some());
    })
    .await;
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, saved).unwrap();

    match control(&fx, Request::Status).await {
        Response::Status { collections, .. } => {
            let d = collections.iter().find(|c| c.id == "default").unwrap();
            let w = d.warning.as_deref().unwrap_or_default();
            assert!(w.contains("attribute index"), "got {w:?}");
        }
        other => panic!("{other:?}"),
    }
}

/// The CLI's own "no collection" message comes from reading the header off
/// disk, so this daemon-side branch is not reached by any CLI test. A
/// regression returning `Ok` here would let `sm lock --collection typo`
/// report success while nothing was sealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lock_reports_an_unknown_collection() {
    let fx = Fixture::start().await;
    assert_eq!(
        control(&fx, unlock_with(&fx, "default", PASSWORD)).await,
        Response::Ok
    );
    match control(
        &fx,
        Request::Lock {
            collection: Some("nope".into()),
        },
    )
    .await
    {
        Response::Error(msg) => assert!(msg.contains("no collection 'nope'"), "got {msg:?}"),
        other => panic!("{other:?}"),
    }
    assert!(
        !secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "a lock for an unknown collection must not seal anything else"
    );
}

/// `unlock_with_key` deliberately gives one uniform message for a wrong key
/// and an absent collection; `change_key` is a distinct branch that names the
/// collection. Pin the difference so neither message drifts into the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn change_key_names_a_collection_that_does_not_exist() {
    let fx = Fixture::start().await;
    let (_, kdf) = header_params(&fx, "default");
    let new_salt = crypto::random_bytes::<SALT_LEN>();
    let new_key = crypto::derive_key(b"new", &new_salt, kdf).unwrap();
    let req = Request::ChangeKey {
        collection: "missing".into(),
        old_key: key_for(&fx, "default", PASSWORD),
        new_salt,
        new_kdf: kdf,
        new_key: Zeroizing::new(*new_key.as_bytes()),
    };
    match control(&fx, req).await {
        Response::Error(msg) => assert!(msg.contains("no collection 'missing'"), "got {msg:?}"),
        other => panic!("{other:?}"),
    }

    match control(
        &fx,
        Request::UnlockWithKey {
            collection: "missing".into(),
            key: key_for(&fx, "default", PASSWORD),
        },
    )
    .await
    {
        Response::Error(msg) => assert!(
            !msg.contains("missing"),
            "an unlock must not say which of the two failed: {msg:?}"
        ),
        other => panic!("{other:?}"),
    }
}

/// A single unreadable vault file is recorded as `broken` and the scan still
/// succeeds; a scan that fails outright is a different arm, and the
/// collections already in memory must survive it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_reports_a_vault_directory_it_cannot_scan() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    let saved = std::fs::read(dir.join("default.vault")).unwrap();

    // A regular file where the vault directory belongs: the scan cannot even
    // list it.
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::write(&dir, b"not a directory").unwrap();
    assert!(matches!(
        control(&fx, Request::Reload).await,
        Response::Error(_)
    ));
    let still_loaded = |r: Response| match r {
        Response::Status { collections, .. } => collections.iter().any(|c| c.id == "default"),
        other => panic!("{other:?}"),
    };
    assert!(
        still_loaded(control(&fx, Request::Status).await),
        "a failed scan must not discard the collections already loaded"
    );

    // An unparseable alias file, by contrast, must *not* fail the scan.
    //
    // This half of the test used to assert the opposite, and that was the
    // asymmetry: a corrupt vault became a permanently locked collection and
    // the daemon carried on, while a corrupt `aliases.toml` — a file holding
    // nothing but convenience mappings — refused the reload and, at startup,
    // refused to run at all. Anything that truncated it took the service
    // down. It is now reported instead, and the table is unusable rather than
    // silently empty.
    std::fs::remove_file(&dir).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("default.vault"), &saved).unwrap();
    std::fs::write(dir.join("aliases.toml"), b"aliases = 5\n").unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    match control(&fx, Request::Status).await {
        Response::Status {
            collections,
            aliases_error,
            ..
        } => {
            assert!(collections.iter().any(|c| c.id == "default"));
            assert!(
                aliases_error.is_some(),
                "a corrupt alias table must be reported, not passed off as empty"
            );
        }
        other => panic!("{other:?}"),
    }

    // Repairing it clears the condition.
    std::fs::remove_file(dir.join("aliases.toml")).unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    match control(&fx, Request::Status).await {
        Response::Status { aliases_error, .. } => assert!(aliases_error.is_none()),
        other => panic!("{other:?}"),
    }
}

/// SIGTERM must end `run_until_shutdown` and take the daemon's resources with
/// it: the control socket file is unlinked and the bus name released, so a
/// replacement daemon can start immediately. The terminate stream is
/// installed here first, before the signal is raised, so the test process
/// never sees an unhandled SIGTERM.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_ends_run_until_shutdown_and_frees_the_name() {
    let fx = Fixture::start().await;
    let sock = fx.control_socket();
    let conn = fx.client().await;
    let dbus = zbus::fdo::DBusProxy::new(&conn).await.unwrap();
    let name = zbus::names::BusName::try_from(paths::BUS_NAME).unwrap();
    assert!(dbus.name_has_owner(name.clone()).await.unwrap());

    // The bus, the vault directory and the runtime directory outlive the
    // daemon, so what disappears below is the daemon's own doing and not a
    // temporary directory being cleaned up.
    let Fixture {
        daemon,
        bus: _bus,
        data_dir: _data_dir,
        runtime_dir: _runtime_dir,
        ..
    } = fx;
    let mut _term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let stopped = tokio::spawn(daemon.run_until_shutdown());

    // `run_until_shutdown` registers its own handler; repeat the signal until
    // it has, so the test cannot lose the race and hang.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !stopped.is_finished() && std::time::Instant::now() < deadline {
        // SAFETY: `raise` takes a signal number and nothing else. SIGTERM is
        // already handled process-wide by `_term` above.
        unsafe { libc::raise(libc::SIGTERM) };
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stopped
        .await
        .expect("run_until_shutdown returned on SIGTERM");

    assert!(
        wait_for(Duration::from_secs(5), || async { !sock.exists() }).await,
        "the control socket file must be removed with the daemon"
    );
    assert!(
        wait_for(Duration::from_secs(5), || async {
            !dbus.name_has_owner(name.clone()).await.unwrap_or(true)
        })
        .await,
        "the bus name must be released with the daemon"
    );
}
