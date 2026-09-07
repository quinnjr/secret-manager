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
