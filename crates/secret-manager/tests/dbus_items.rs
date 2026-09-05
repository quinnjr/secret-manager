mod common;

use common::Fixture;
use futures_util::StreamExt;
use secret_manager::dbus::proxies::{CollectionProxy, ItemProxy, ServiceProxy};
use secret_manager::dbus::session::SecretStruct;
use secret_manager::session::dh::KeyPair;
use secret_manager::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::HashMap;
use std::time::Duration;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, Value};

async fn plain_session(service: &ServiceProxy<'_>) -> OwnedObjectPath {
    service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap()
        .1
}

fn props(label: &str, attrs: &[(&str, &str)]) -> HashMap<&'static str, Value<'static>> {
    let attrs: HashMap<String, String> = attrs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label",
            Value::from(label.to_string()),
        ),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
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

async fn collection(conn: &zbus::Connection, path: OwnedObjectPath) -> CollectionProxy<'static> {
    CollectionProxy::builder(conn)
        .path(path)
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .unwrap()
}

async fn item(conn: &zbus::Connection, path: OwnedObjectPath) -> ItemProxy<'static> {
    ItemProxy::builder(conn)
        .path(path)
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .unwrap()
}

fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_search_get_set_delete_with_signals() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    assert_eq!(coll.label().await.unwrap(), "Default");
    assert!(!coll.locked().await.unwrap());

    let mut created = coll.receive_item_created().await.unwrap();
    let (item_path, prompt) = coll
        .create_item(
            props("git token", &[("app", "git"), ("user", "joe")]),
            &plain_secret(&session, b"tok"),
            false,
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    assert!(
        item_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/default/")
    );
    assert_eq!(
        created.next().await.unwrap().args().unwrap().item,
        item_path
    );
    assert_eq!(coll.items().await.unwrap(), vec![item_path.clone()]);

    let (u, l) = service
        .search_items(HashMap::from([("app", "git")]))
        .await
        .unwrap();
    assert_eq!(u, vec![item_path.clone()]);
    assert!(l.is_empty());
    assert_eq!(
        coll.search_items(HashMap::from([("user", "joe")]))
            .await
            .unwrap(),
        vec![item_path.clone()]
    );
    assert!(
        coll.search_items(HashMap::from([("user", "bob")]))
            .await
            .unwrap()
            .is_empty()
    );

    let it = item(&conn, item_path.clone()).await;
    assert_eq!(it.label().await.unwrap(), "git token");
    assert_eq!(it.attributes().await.unwrap()["app"], "git");
    assert!(!it.locked().await.unwrap());
    assert!(it.created().await.unwrap() > 0);
    let s = it.get_secret(&session).await.unwrap();
    assert_eq!(s.value, b"tok");
    assert_eq!(s.content_type, "text/plain");
    let all = service
        .get_secrets(std::slice::from_ref(&item_path), &session)
        .await
        .unwrap();
    assert_eq!(all[&item_path].value, b"tok");

    let mut changed = coll.receive_item_changed().await.unwrap();
    it.set_secret(&plain_secret(&session, b"tok2"))
        .await
        .unwrap();
    assert_eq!(
        changed.next().await.unwrap().args().unwrap().item,
        item_path
    );
    assert_eq!(it.get_secret(&session).await.unwrap().value, b"tok2");
    it.set_label("renamed").await.unwrap();
    assert_eq!(it.label().await.unwrap(), "renamed");
    it.set_attributes(HashMap::from([("app", "git"), ("user", "jane")]))
        .await
        .unwrap();
    assert!(
        coll.search_items(HashMap::from([("user", "joe")]))
            .await
            .unwrap()
            .is_empty()
    );

    let (again, _) = coll
        .create_item(
            props("replaced", &[("app", "git"), ("user", "jane")]),
            &plain_secret(&session, b"tok3"),
            true,
        )
        .await
        .unwrap();
    assert_eq!(again, item_path);
    assert_eq!(coll.items().await.unwrap().len(), 1);
    assert_eq!(it.label().await.unwrap(), "replaced");

    let mut deleted = coll.receive_item_deleted().await.unwrap();
    assert_eq!(it.delete().await.unwrap().as_str(), "/");
    assert_eq!(
        deleted.next().await.unwrap().args().unwrap().item,
        item_path
    );
    assert!(coll.items().await.unwrap().is_empty());
    assert!(
        common::wait_for(Duration::from_secs(2), || async {
            it.label().await.is_err()
        })
        .await,
        "item object removed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dh_session_end_to_end() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let pair = KeyPair::generate();
    let (output, session) = service
        .open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec()))
        .await
        .unwrap();
    let cipher = SessionCipher::from_dh(&pair, &Vec::<u8>::try_from(output).unwrap()).unwrap();
    let (parameters, value) = cipher.encrypt(b"encrypted on the wire");
    let secret = SecretStruct {
        session: session.clone(),
        parameters,
        value,
        content_type: "text/plain".into(),
    };
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(props("dh", &[("k", "v")]), &secret, false)
        .await
        .unwrap();
    let got = service
        .get_secrets(std::slice::from_ref(&item_path), &session)
        .await
        .unwrap();
    let s = &got[&item_path];
    assert_ne!(s.value, b"encrypted on the wire");
    assert_eq!(
        cipher.decrypt(&s.parameters, &s.value).unwrap().as_slice(),
        b"encrypted on the wire"
    );
    assert_eq!(
        fx.daemon.state.lock().await.collections["default"]
            .items()
            .unwrap()[0]
            .secret
            .as_slice(),
        b"encrypted on the wire"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_collection_behaviour() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("x", &[("app", "git")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    fx.lock_default().await;

    assert!(coll.locked().await.unwrap());
    assert_eq!(coll.items().await.unwrap(), vec![item_path.clone()]);
    let (u, l) = service
        .search_items(HashMap::from([("app", "git")]))
        .await
        .unwrap();
    assert!(u.is_empty());
    assert_eq!(l, vec![item_path.clone()]);
    let it = item(&conn, item_path.clone()).await;
    assert!(it.locked().await.unwrap());
    assert_eq!(it.label().await.unwrap(), "");
    assert!(it.attributes().await.unwrap().is_empty());
    assert_eq!(
        error_name(&it.get_secret(&session).await.unwrap_err()),
        "org.freedesktop.Secret.Error.IsLocked"
    );
    assert_eq!(
        error_name(&it.delete().await.unwrap_err()),
        "org.freedesktop.Secret.Error.IsLocked"
    );
    let err = coll
        .create_item(props("y", &[]), &plain_secret(&session, b"s"), false)
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.IsLocked");
    assert!(
        service
            .get_secrets(std::slice::from_ref(&item_path), &session)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        error_name(
            &it.get_secret(&secret_manager::dbus::paths::session(99))
                .await
                .unwrap_err()
        ),
        "org.freedesktop.Secret.Error.NoSession"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alias_path_and_set_alias() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let alias = collection(
        &conn,
        secret_manager::dbus::paths::alias("default").unwrap(),
    )
    .await;
    assert_eq!(alias.label().await.unwrap(), "Default");
    let (item_path, _) = alias
        .create_item(
            props("via alias", &[("a", "b")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    assert!(
        item_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/default/")
    );
    let real = collection(&conn, fx.default_collection()).await;
    assert_eq!(real.items().await.unwrap(), alias.items().await.unwrap());

    service
        .set_alias("work", &fx.default_collection())
        .await
        .unwrap();
    assert_eq!(
        service.read_alias("work").await.unwrap(),
        fx.default_collection()
    );
    let work = collection(&conn, secret_manager::dbus::paths::alias("work").unwrap()).await;
    assert_eq!(work.label().await.unwrap(), "Default");
    let text = std::fs::read_to_string(
        fx.data_dir
            .path()
            .join("secret-manager")
            .join("aliases.toml"),
    )
    .unwrap();
    assert!(text.contains("work = \"default\""));
    service
        .set_alias("work", &secret_manager::dbus::paths::root())
        .await
        .unwrap();
    assert_eq!(service.read_alias("work").await.unwrap().as_str(), "/");
    assert_eq!(
        error_name(
            &service
                .set_alias("bad name", &fx.default_collection())
                .await
                .unwrap_err()
        ),
        "org.freedesktop.DBus.Error.InvalidArgs"
    );
    assert_eq!(
        error_name(
            &service
                .set_alias("x", &secret_manager::dbus::paths::collection("nope"))
                .await
                .unwrap_err()
        ),
        "org.freedesktop.Secret.Error.NoSuchObject"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_tool_interop() {
    if std::process::Command::new("secret-tool")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("secret-tool not installed; skipping");
        return;
    }
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let run = |args: &[&str], stdin: &str| {
        let mut cmd = std::process::Command::new("secret-tool");
        cmd.args(args)
            .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    run(
        &["store", "--label=Interop", "app", "interop", "user", "joe"],
        "s3cret\n",
    );
    // `secret-tool lookup` prints the secret followed by a trailing newline
    // (see secret-tool(1)); trim it before comparing.
    assert_eq!(run(&["lookup", "app", "interop"], "").trim_end(), "s3cret");
    assert!(run(&["search", "app", "interop"], "").contains("label = Interop"));
}
