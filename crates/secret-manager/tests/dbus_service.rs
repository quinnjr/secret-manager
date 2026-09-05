mod common;

use common::Fixture;
use secret_manager::dbus::proxies::{ServiceProxy, SessionProxy};
use secret_manager::session::dh::KeyPair;
use secret_manager::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::HashMap;
use zbus::zvariant::Value;

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
