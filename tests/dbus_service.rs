mod common;

use common::Fixture;
use secret_manager::dbus::proxies::{CollectionProxy, PromptProxy, ServiceProxy, SessionProxy};
use secret_manager::protocol::{Request, Response, call};
use secret_manager::session::dh::KeyPair;
use secret_manager::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::HashMap;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, Value};

async fn control(fx: &Fixture, req: Request) -> Response {
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || call(&sock, &req))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn plain_and_dh_sessions() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();

    let (output, path) = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap();
    assert_eq!(String::try_from(output).unwrap(), "");
    assert!(
        path.as_str()
            .starts_with("/org/freedesktop/secrets/session/")
    );

    let pair = KeyPair::generate();
    let (output, path2) = service
        .open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec()))
        .await
        .unwrap();
    let peer = Vec::<u8>::try_from(output).unwrap();
    assert!(!peer.is_empty() && peer.len() <= 128);
    assert!(SessionCipher::from_dh(&pair, &peer).is_ok());
    assert_ne!(path, path2);
    assert_eq!(fx.daemon.state.lock().await.sessions.len(), 2);

    let session = SessionProxy::builder(&conn)
        .path(path.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    session.close().await.unwrap();
    assert!(
        common::wait_for(std::time::Duration::from_secs(2), || async {
            fx.daemon.state.lock().await.sessions.len() == 1
        })
        .await
    );
}

/// A session belongs to the client that opened it: another client calling
/// `Close` on it must be refused, and the session must remain open
/// (finding 6).
#[tokio::test]
async fn session_close_is_refused_to_a_non_owner() {
    let fx = Fixture::start().await;
    let owner_conn = fx.client().await;
    let intruder_conn = fx.client().await;
    let service = ServiceProxy::new(&owner_conn).await.unwrap();
    let (_, path) = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap();

    let intruder = SessionProxy::builder(&intruder_conn)
        .path(path.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let err = intruder.close().await.unwrap_err();
    assert!(
        matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.Secret.Error.NoSession")
    );
    assert_eq!(fx.daemon.state.lock().await.sessions.len(), 1);

    let owner = SessionProxy::builder(&owner_conn)
        .path(path)
        .unwrap()
        .build()
        .await
        .unwrap();
    owner.close().await.unwrap();
    assert!(
        common::wait_for(std::time::Duration::from_secs(2), || async {
            fx.daemon.state.lock().await.sessions.is_empty()
        })
        .await
    );
}

/// Sessions are only reclaimed on `Close` or disconnect, and each costs an
/// exported object (plus a 1024-bit modexp for `dh`), so one client may hold
/// only so many at once (MEDIUM 4). The cap is per sender: another client is
/// unaffected.
///
/// The cap must also actually *bound the work it was added to bound* (HIGH 4).
/// `KeyPair::generate()` and `SessionCipher::from_dh` — two 1024-bit modexps —
/// used to run before `require_sender` and the quota check, so a client at its
/// limit still spent the daemon's CPU on every refused call. That ordering is
/// asserted here without relying on wall-clock timing: a `dh` request whose
/// peer key `from_dh` rejects would answer `InvalidArgs` if the key exchange
/// ran first, and answers the quota error only if the quota check ran first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_session_is_capped_per_client() {
    use secret_manager::dbus::state::MAX_SESSIONS_PER_SENDER;
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    for i in 0..MAX_SESSIONS_PER_SENDER {
        service
            .open_session(ALGORITHM_PLAIN, &Value::from(""))
            .await
            .unwrap_or_else(|e| panic!("session {i} must be allowed: {e}"));
    }
    let err = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap_err();
    match &err {
        zbus::Error::MethodError(name, desc, _) => {
            assert_eq!(name.as_str(), "org.freedesktop.DBus.Error.Failed");
            assert!(
                desc.as_deref()
                    .unwrap_or_default()
                    .contains("too many open sessions"),
                "{desc:?}"
            );
        }
        other => panic!("expected MethodError, got {other:?}"),
    }
    assert_eq!(
        fx.daemon.state.lock().await.sessions.len(),
        MAX_SESSIONS_PER_SENDER
    );

    // Ordering proof (HIGH 4): `vec![1u8]` is a peer key `from_dh` rejects —
    // `unsupported_algorithm_and_bad_input` shows it yields `InvalidArgs` when
    // the quota is free. With the quota exhausted it must be refused *before*
    // the key exchange is attempted, so the quota error is what comes back.
    let err = service
        .open_session(ALGORITHM_DH, &Value::from(vec![1u8]))
        .await
        .unwrap_err();
    match &err {
        zbus::Error::MethodError(name, desc, _) => {
            assert_eq!(
                name.as_str(),
                "org.freedesktop.DBus.Error.Failed",
                "the modexps ran before the quota check: {desc:?}"
            );
            assert!(
                desc.as_deref()
                    .unwrap_or_default()
                    .contains("too many open sessions"),
                "{desc:?}"
            );
        }
        other => panic!("expected MethodError, got {other:?}"),
    }
    assert_eq!(
        fx.daemon.state.lock().await.sessions.len(),
        MAX_SESSIONS_PER_SENDER,
        "a refused call must not have created a session"
    );

    // A different client is unaffected by the first one's exhausted quota.
    let other_conn = fx.client().await;
    ServiceProxy::new(&other_conn)
        .await
        .unwrap()
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap();
    assert_eq!(
        fx.daemon.state.lock().await.sessions.len(),
        MAX_SESSIONS_PER_SENDER + 1
    );
}

#[tokio::test]
async fn unsupported_algorithm_and_bad_input() {
    let fx = Fixture::start().await;
    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    let err = service
        .open_session("rot13", &Value::from(""))
        .await
        .unwrap_err();
    assert!(
        matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.NotSupported")
    );
    let err = service
        .open_session(ALGORITHM_DH, &Value::from("not bytes"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs")
    );
    let err = service
        .open_session(ALGORITHM_DH, &Value::from(vec![1u8]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs")
    );
}

/// A vault file that fails to open (corrupt or unreadable) must still show
/// up as a collection — permanently locked, never silently dropped
/// (finding 7). `Reload` (triggered here over the control socket, since that
/// is how a running daemon is told to rescan the vault directory) picks it
/// up the same way startup does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broken_vault_appears_as_a_locked_collection() {
    let fx = Fixture::start().await;
    std::fs::write(
        fx.data_dir.path().join("secret-manager").join("bad.vault"),
        b"not a real vault file",
    )
    .unwrap();

    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let bad_path = secret_manager::dbus::paths::collection("bad");
    assert!(service.collections().await.unwrap().contains(&bad_path));

    let bad = CollectionProxy::builder(&conn)
        .path(bad_path.clone())
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .unwrap();
    assert!(bad.locked().await.unwrap());
    assert_eq!(bad.label().await.unwrap(), "bad");
    assert!(bad.items().await.unwrap().is_empty());

    // Unlock still returns a prompt (a broken collection isn't rejected
    // outright), but it completes dismissed without ever touching pinentry.
    let (unlocked, prompt) = service
        .unlock(std::slice::from_ref(&bad_path))
        .await
        .unwrap();
    assert!(unlocked.is_empty());
    assert_ne!(prompt.as_str(), "/");
    let proxy = PromptProxy::builder(&conn)
        .path(prompt)
        .unwrap()
        .build()
        .await
        .unwrap();
    use futures_util::StreamExt;
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    let sig = tokio::time::timeout(std::time::Duration::from_secs(5), completed.next())
        .await
        .unwrap()
        .unwrap();
    assert!(sig.args().unwrap().dismissed);
    assert!(
        !fx.pinentry_log().contains("GETPIN"),
        "a broken vault must never reach pinentry"
    );
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(sig.args().unwrap().result.try_to_owned().unwrap())
            .unwrap(),
        Vec::<OwnedObjectPath>::new()
    );
}

#[tokio::test]
async fn collections_alias_and_empty_search() {
    let fx = Fixture::start().await;
    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    assert_eq!(
        service.collections().await.unwrap(),
        vec![fx.default_collection()]
    );
    assert_eq!(
        service.read_alias("default").await.unwrap(),
        fx.default_collection()
    );
    assert_eq!(service.read_alias("nope").await.unwrap().as_str(), "/");
    let (unlocked, locked) = service
        .search_items(HashMap::from([("a", "b")]))
        .await
        .unwrap();
    assert!(unlocked.is_empty() && locked.is_empty());
}

fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => panic!("expected MethodError, got {other:?}"),
    }
}

/// `Lock` and `Unlock` take arrays of caller-supplied object paths. A path
/// that names nothing is skipped, not an error and not a prompt: libsecret
/// routinely passes paths it cached before a collection went away, and a
/// prompt raised for one would put a password dialog on screen for a keyring
/// that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lock_and_unlock_skip_paths_that_name_nothing() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let nowhere: Vec<OwnedObjectPath> = [
        // A collection id that was never loaded.
        "/org/freedesktop/secrets/collection/nope",
        // An item under one.
        "/org/freedesktop/secrets/collection/nope/abc",
        // An alias that resolves to nothing.
        "/org/freedesktop/secrets/aliases/nope",
        // Paths outside the collection tree altogether.
        "/org/freedesktop/secrets",
        "/",
    ]
    .iter()
    .map(|p| OwnedObjectPath::try_from(*p).unwrap())
    .collect();

    let (unlocked, prompt) = service.unlock(&nowhere).await.unwrap();
    assert!(unlocked.is_empty());
    assert_eq!(
        prompt.as_str(),
        "/",
        "paths that name nothing must not raise a prompt"
    );
    assert!(
        fx.daemon.state.lock().await.prompt_owners.is_empty(),
        "a prompt object was exported for a collection that does not exist"
    );

    let (locked, prompt) = service.lock(&nowhere).await.unwrap();
    assert!(locked.is_empty());
    assert_eq!(prompt.as_str(), "/");
    assert!(
        !fx.daemon.state.lock().await.collections["default"].is_locked(),
        "a Lock of unrelated paths locked the real collection"
    );
    assert!(
        !fx.pinentry_log().contains("GETPIN"),
        "nothing here may reach pinentry:\n{}",
        fx.pinentry_log()
    );
}

/// A vault file that will not open is advertised as a permanently locked
/// collection with no vault behind it, which is the one case where a path
/// resolves but `collections` has no entry. `Lock` must leave it out of its
/// reply (there is nothing to lock), and the private batch-delete interface,
/// which is exported on it like on any other collection, must refuse rather
/// than panic on the missing entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_collection_cannot_be_locked_or_batch_deleted() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    std::fs::write(
        fx.data_dir.path().join("secret-manager").join("bad.vault"),
        b"not a real vault file",
    )
    .unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let bad_path = secret_manager::dbus::paths::collection("bad");
    assert!(service.collections().await.unwrap().contains(&bad_path));

    let (locked, prompt) = service.lock(std::slice::from_ref(&bad_path)).await.unwrap();
    assert!(
        locked.is_empty(),
        "a broken collection has no vault to lock, so it cannot be reported locked"
    );
    assert_eq!(prompt.as_str(), "/");

    let admin = CollectionAdminProxy::builder(&conn)
        .path(bad_path.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    // An empty batch is a no-op on any collection, broken or not.
    admin.delete_items(&[]).await.unwrap();
    let err = admin
        .delete_items(&[
            OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/bad/abc").unwrap(),
        ])
        .await
        .unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.Secret.Error.NoSuchObject",
        "a broken collection holds no items, so none of them can be named"
    );
    assert!(service.collections().await.unwrap().contains(&bad_path));
}
