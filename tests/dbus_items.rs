mod common;

use common::Fixture;
use futures_util::{FutureExt, StreamExt};
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
        value: bytes.to_vec().into(),
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

/// `Item.GetSecret` must answer one `(oayays)` struct, not four loose
/// values. Introspection advertises the struct, libsecret tolerates the
/// flattening, and every strict client (Python secretstorage among them)
/// reads the header signature and chokes: `secret, = call(...)` fails with
/// "too many values to unpack (expected 1, got 4)".
///
/// Asserted through `busctl monitor`, not through the reply object: zbus's
/// client side reports the promised signature whatever the bytes carry, and
/// decoding is structurally lenient both ways, so neither can pin the
/// framing — only an independent bus observer sees the header as sent.
/// (Skipped where `busctl` is absent; it ships with the same dbus package
/// the fixture's `dbus-daemon` comes from.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_secret_reply_is_a_single_struct_on_the_wire() {
    if tokio::process::Command::new("busctl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_err()
    {
        eprintln!("skipped: busctl not found");
        return;
    }
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("framing probe", &[("app", "framing")]),
            &plain_secret(&session, b"tok"),
            false,
        )
        .await
        .unwrap();

    let mut mon = tokio::process::Command::new("busctl")
        .args([
            "--address",
            &fx.bus.address,
            "monitor",
            "org.freedesktop.secrets",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Give the monitor a moment to attach before the only call it must see.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    conn.call_method(
        Some("org.freedesktop.secrets"),
        item_path.as_str(),
        Some("org.freedesktop.Secret.Item"),
        "GetSecret",
        &(session.clone(),),
    )
    .await
    .unwrap();
    // The call already returned, so the reply is on the bus; the wait is
    // only for the monitor's pipe to deliver it.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let _ = mon.kill().await;
    let out = mon.wait_with_output().await.unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    let mut lines = log.lines();
    let reply_message = loop {
        let line = lines
            .by_ref()
            .find(|l| l.contains("Member=GetSecret"))
            .expect("monitor saw the call");
        let _ = lines
            .by_ref()
            .find(|l| l.contains("Type=method_return"))
            .expect("monitor saw the reply");
        let message = lines
            .by_ref()
            .find(|l| l.trim_start().starts_with("MESSAGE "))
            .expect("reply has a body signature");
        if line.contains("Interface=org.freedesktop.Secret.Item") {
            break message.trim().to_string();
        }
    };
    assert_eq!(
        reply_message, "MESSAGE \"(oayays)\" {",
        "GetSecret reply framing on the wire"
    );
}

fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => panic!("unexpected error {other:?}"),
    }
}

/// zbus 5's `#[zbus(property)]` setters cannot return a custom `DBusError`
/// (see `dbus::errors::vault_error_to_fdo`), so a locked-vault failure from
/// one arrives as `org.freedesktop.DBus.Error.Failed` with the intended name
/// only in the description text; this checks that text instead of the wire
/// name.
fn error_message(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(_, desc, _) => desc.clone().unwrap_or_default(),
        // A `#[zbus(property)]` setter's error apparently doesn't always
        // make the round trip through the wire as a `MethodError`; zbus can
        // also report it locally as `FDO`.
        zbus::Error::FDO(inner) => inner.to_string(),
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
    assert_eq!(s.value.as_slice(), b"tok");
    assert_eq!(s.content_type, "text/plain");
    let all = service
        .get_secrets(std::slice::from_ref(&item_path), &session)
        .await
        .unwrap();
    assert_eq!(all[&item_path].value.as_slice(), b"tok");

    let mut changed = coll.receive_item_changed().await.unwrap();
    it.set_secret(&plain_secret(&session, b"tok2"))
        .await
        .unwrap();
    assert_eq!(
        changed.next().await.unwrap().args().unwrap().item,
        item_path
    );
    assert_eq!(
        it.get_secret(&session).await.unwrap().value.as_slice(),
        b"tok2"
    );
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

    // A `replace = true` create that hits an existing item is a *change*, not
    // a creation: `ItemChanged` names the item, and no `ItemCreated` follows
    // it. Both streams are live across the call, and the `ItemCreated` one is
    // read after `ItemChanged` has arrived — the two signals are emitted on
    // the same connection in order, so had the wrong one been sent it would
    // already be queued.
    let mut created_again = coll.receive_item_created().await.unwrap();
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
    let replace_signal = tokio::time::timeout(Duration::from_secs(5), changed.next())
        .await
        .expect("a replace emits ItemChanged")
        .unwrap();
    assert_eq!(replace_signal.args().unwrap().item, item_path);
    // No timeout: the ordering argument above is the whole proof. `ItemChanged`
    // has been received, both signals travel the same connection in emission
    // order, so an `ItemCreated` for this call would already be queued and
    // ready. Polling once answers that exactly, where half a second of waiting
    // answered it only probabilistically — and charged every run for it.
    assert!(
        created_again.next().now_or_never().is_none(),
        "a replace must not emit ItemCreated"
    );

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

/// `replace = true` matches on the *exact* attribute set, as
/// `Collection::create_item` documents. The spec's "an item with the same
/// attributes" also reads as `SearchItems`' superset rule, under which a
/// create carrying one attribute would overwrite every item that has it — so
/// this pins which reading is implemented, in both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replace_matches_exact_attributes_only() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let (original, _) = coll
        .create_item(
            props("original", &[("app", "git"), ("user", "joe")]),
            &plain_secret(&session, b"tok"),
            false,
        )
        .await
        .unwrap();

    // A strict subset: every attribute given is on the existing item, and
    // `SearchItems` finds it, but the sets are not equal.
    assert_eq!(
        coll.search_items(HashMap::from([("app", "git")]))
            .await
            .unwrap(),
        vec![original.clone()],
        "the subset does match the existing item for search"
    );
    let (subset, _) = coll
        .create_item(
            props("subset", &[("app", "git")]),
            &plain_secret(&session, b"other"),
            true,
        )
        .await
        .unwrap();
    assert_ne!(subset, original, "a subset creates a new item");

    // A superset, for the same reason from the other side.
    let (superset, _) = coll
        .create_item(
            props("superset", &[("app", "git"), ("user", "joe"), ("h", "x")]),
            &plain_secret(&session, b"third"),
            true,
        )
        .await
        .unwrap();
    assert_ne!(superset, original);
    assert_ne!(superset, subset);
    assert_eq!(coll.items().await.unwrap().len(), 3);

    // The original is untouched by either.
    let it = item(&conn, original.clone()).await;
    assert_eq!(it.label().await.unwrap(), "original");
    assert_eq!(
        it.get_secret(&session).await.unwrap().value.as_slice(),
        b"tok"
    );

    // The exact set does replace, in place.
    let (same, _) = coll
        .create_item(
            props("replaced", &[("app", "git"), ("user", "joe")]),
            &plain_secret(&session, b"tok2"),
            true,
        )
        .await
        .unwrap();
    assert_eq!(same, original);
    assert_eq!(coll.items().await.unwrap().len(), 3);
    assert_eq!(it.label().await.unwrap(), "replaced");
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
        value: value.into(),
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
    assert_ne!(s.value.as_slice(), b"encrypted on the wire");
    assert_eq!(
        cipher.decrypt(&s.parameters, &s.value).unwrap().as_slice(),
        b"encrypted on the wire"
    );
    assert_eq!(
        secret_manager::dbus::state::with_vault(&fx.daemon.state, "default", |v| v
            .items()
            .unwrap()[0]
            .secret
            .to_vec())
        .await
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

    // Property setters on a locked item/collection also refuse (finding 3).
    // zbus can't carry a custom wire name out of a property setter (see
    // `error_message`), so only the description is checked here.
    assert!(
        error_message(&it.set_label("nope").await.unwrap_err()).contains("IsLocked"),
        "set_label on a locked item must mention IsLocked"
    );
    assert!(
        error_message(
            &it.set_attributes(HashMap::from([("a", "b")]))
                .await
                .unwrap_err()
        )
        .contains("IsLocked"),
        "set_attributes on a locked item must mention IsLocked"
    );
    assert!(
        error_message(&coll.set_label("nope").await.unwrap_err()).contains("IsLocked"),
        "Collection.set_label on a locked collection must mention IsLocked"
    );
}

/// `GetSecrets` and `SearchItems` do per-element work; a caller-supplied
/// array bounded only by the D-Bus message size limit would hold the global
/// state mutex for arbitrarily long, so both are capped (MEDIUM 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_secrets_and_search_are_capped() {
    use secret_manager::dbus::service::{MAX_GET_SECRETS_ITEMS, MAX_SEARCH_ATTRIBUTES};
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("one", &[("a", "b")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();

    // At the cap: still answered (the real item repeated to fill the array).
    let at_cap = vec![item_path.clone(); MAX_GET_SECRETS_ITEMS];
    let got = service.get_secrets(&at_cap, &session).await.unwrap();
    assert_eq!(got[&item_path].value.as_slice(), b"s");

    let over = vec![item_path.clone(); MAX_GET_SECRETS_ITEMS + 1];
    let err = service.get_secrets(&over, &session).await.unwrap_err();
    assert!(
        matches!(&err, zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs"),
        "{err:?}"
    );

    let keys: Vec<String> = (0..=MAX_SEARCH_ATTRIBUTES)
        .map(|i| format!("k{i}"))
        .collect();
    let too_many: HashMap<&str, &str> = keys.iter().map(|k| (k.as_str(), "v")).collect();
    let err = service.search_items(too_many.clone()).await.unwrap_err();
    assert!(
        matches!(&err, zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs"),
        "{err:?}"
    );
    let err = coll.search_items(too_many).await.unwrap_err();
    assert!(
        matches!(&err, zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs"),
        "{err:?}"
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

    // First assignment is always allowed.
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

    // Repointing an alias to the same target it already has is a no-op, not
    // a conflict.
    service
        .set_alias("work", &fx.default_collection())
        .await
        .unwrap();
    assert_eq!(
        service.read_alias("work").await.unwrap(),
        fx.default_collection()
    );

    // Repointing an alias that already targets another collection is a
    // silent overwrite, exactly as the freedesktop spec says (HIGH 2). The
    // old refusal was no boundary at all: `SetAlias(name, "/")` followed by
    // `SetAlias(name, other)` achieved the same thing unauthenticated.
    {
        let mut st = fx.daemon.state.lock().await;
        let vault = secret_manager::vault::Vault::create(
            &fx.data_dir
                .path()
                .join("secret-manager")
                .join("second.vault"),
            "Second",
            b"pw2",
            secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        st.collections.insert(
            "second".to_string(),
            secret_manager::dbus::state::vault_ref(vault),
        );
    }
    let second = secret_manager::dbus::paths::collection("second");
    service.set_alias("work", &second).await.unwrap();
    assert_eq!(service.read_alias("work").await.unwrap(), second);
    // And back again.
    service
        .set_alias("work", &fx.default_collection())
        .await
        .unwrap();
    assert_eq!(
        service.read_alias("work").await.unwrap(),
        fx.default_collection()
    );

    // Removal via "/" stays allowed, and clears the way for a fresh assignment.
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
        "s3cret",
    );
    assert_eq!(run(&["lookup", "app", "interop"], ""), "s3cret");
    assert!(run(&["search", "app", "interop"], "").contains("label = Interop"));
}

/// A session belongs to the connection that opened it: another client may
/// not read or write secrets through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_calls_reject_a_foreign_session() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let owner = fx.client().await;
    let owner_service = ServiceProxy::new(&owner).await.unwrap();
    let session = plain_session(&owner_service).await;
    let coll = collection(&owner, fx.default_collection()).await;
    let (path, _) = coll
        .create_item(
            props("x", &[("k", "v")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();

    let other = fx.client().await;
    let other_service = ServiceProxy::new(&other).await.unwrap();
    let it = item(&other, path.clone()).await;
    let err = it.get_secret(&session).await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.NoSession");
    let err = it
        .set_secret(&plain_secret(&session, b"t"))
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.NoSession");
    let err = other_service
        .get_secrets(std::slice::from_ref(&path), &session)
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.NoSession");
    let other_coll = collection(&other, fx.default_collection()).await;
    let err = other_coll
        .create_item(
            props("y", &[("k", "w")]),
            &plain_secret(&session, b"u"),
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.NoSession");
    // The owner is unaffected.
    let got = item(&owner, path).await.get_secret(&session).await.unwrap();
    assert_eq!(got.value.as_slice(), b"s");
}

/// A `Close` naming a session the daemon does not know must answer exactly
/// as one owned by another client (`NoSession`), rather than `Ok`, so a
/// caller cannot probe which session paths are live.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_an_unknown_session_is_refused_like_a_foreign_one() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let path = plain_session(&service).await;
    let proxy = secret_manager::dbus::proxies::SessionProxy::builder(&conn)
        .path(path.clone())
        .unwrap()
        .build()
        .await
        .unwrap();

    // Drop the daemon's record while the object stays registered, so the
    // call reaches `Session::close` with nothing to find.
    fx.daemon
        .state
        .lock()
        .await
        .sessions
        .remove(path.as_str())
        .expect("session was registered");

    let err = proxy.close().await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.NoSession");
}

/// One item's decrypted secret is bounded (MEDIUM 6).
///
/// `CreateItem` used to accept a secret of any size, which is how a collection
/// reaches the vault-level size limit — past which the whole collection stops
/// saving — from a single call. The cap matches the control protocol's frame
/// cap; anything over it is `InvalidArgs`, and the item is not created.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_item_rejects_an_oversized_secret() {
    use secret_manager::dbus::collection::MAX_ITEM_SECRET;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let too_big = vec![b'x'; MAX_ITEM_SECRET + 1];
    let err = coll
        .create_item(
            props("huge", &[("k", "huge")]),
            &plain_secret(&session, &too_big),
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(
        coll.items().await.unwrap().is_empty(),
        "a refused CreateItem must not create the item"
    );

    // Exactly at the limit is still accepted: the cap is a bound, not a
    // tightening of the normal case.
    let at_limit = vec![b'y'; MAX_ITEM_SECRET];
    let (item_path, _) = coll
        .create_item(
            props("big", &[("k", "big")]),
            &plain_secret(&session, &at_limit),
            false,
        )
        .await
        .unwrap();
    assert_eq!(coll.items().await.unwrap(), vec![item_path.clone()]);
    let got = service
        .get_secrets(std::slice::from_ref(&item_path), &session)
        .await
        .unwrap();
    assert_eq!(got[&item_path].value.len(), MAX_ITEM_SECRET);
}

/// The private batch delete is atomic: one bad path refuses the whole call,
/// leaving every real item in place and the vault file byte-identical.
///
/// The CLI's `sm delete` / `sm ssh remove` used to issue N separate
/// `Item.Delete` calls, each rewriting the vault file; a collection that locked
/// (or a daemon that died) part-way through left a half-deleted set and a
/// secret that still existed. This is the daemon-side "all or none".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_delete_is_all_or_nothing() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let mut created = Vec::new();
    for n in ["a", "b", "c"] {
        let (path, _) = coll
            .create_item(
                props(n, &[("k", n)]),
                &plain_secret(&session, n.as_bytes()),
                false,
            )
            .await
            .unwrap();
        created.push(path);
    }

    let admin = CollectionAdminProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();

    let vault_file = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");
    let before = std::fs::read(&vault_file).unwrap();

    // One bogus path among three real ones: the whole batch is refused.
    let bogus = OwnedObjectPath::try_from(
        "/org/freedesktop/secrets/collection/default/nosuchitem".to_string(),
    )
    .unwrap();
    let batch = vec![created[0].clone(), bogus, created[2].clone()];
    let err = admin.delete_items(&batch).await.unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.Secret.Error.NoSuchObject"
    );
    assert_eq!(
        coll.items().await.unwrap().len(),
        3,
        "a refused batch must delete nothing"
    );
    assert_eq!(
        std::fs::read(&vault_file).unwrap(),
        before,
        "a refused batch must not rewrite the vault file"
    );
    // Every item is still readable, not just present in the index.
    for path in &created {
        let got = service
            .get_secrets(std::slice::from_ref(path), &session)
            .await
            .unwrap();
        assert!(got.contains_key(path), "{path} lost its secret");
    }

    // An item of another collection cannot be smuggled into the batch either.
    let dir = fx.data_dir.path().join("secret-manager");
    secret_manager::vault::Vault::create(
        &dir.join("other.vault"),
        "Other",
        common::PASSWORD.as_bytes(),
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let foreign =
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/other/whatever".to_string())
            .unwrap();
    assert!(
        admin
            .delete_items(&[created[0].clone(), foreign])
            .await
            .is_err()
    );
    assert_eq!(coll.items().await.unwrap().len(), 3);

    // The successful batch: three items gone, three `ItemDeleted` signals.
    let mut deleted = coll.receive_item_deleted().await.unwrap();
    admin.delete_items(&created).await.unwrap();
    let mut signalled = Vec::new();
    for _ in 0..3 {
        let sig = tokio::time::timeout(Duration::from_secs(5), deleted.next())
            .await
            .expect("an ItemDeleted signal")
            .unwrap();
        signalled.push(sig.args().unwrap().item.clone());
    }
    let mut signalled: Vec<String> = signalled.iter().map(|p| p.to_string()).collect();
    signalled.sort();
    let mut expected: Vec<String> = created.iter().map(|p| p.to_string()).collect();
    expected.sort();
    assert_eq!(signalled, expected);
    assert!(coll.items().await.unwrap().is_empty());
    assert_ne!(
        std::fs::read(&vault_file).unwrap(),
        before,
        "the successful batch must have been written"
    );

    // The spec's own per-item Delete is untouched.
    let (path, _) = coll
        .create_item(
            props("d", &[("k", "d")]),
            &plain_secret(&session, b"d"),
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        item(&conn, path.clone())
            .await
            .delete()
            .await
            .unwrap()
            .as_str(),
        "/"
    );
    assert!(coll.items().await.unwrap().is_empty());

    // And the batch interface is a *separate* interface: the spec interface
    // must not have grown a DeleteItems method.
    let introspect = zbus::fdo::IntrospectableProxy::builder(&conn)
        .destination(secret_manager::dbus::paths::BUS_NAME)
        .unwrap()
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap()
        .introspect()
        .await
        .unwrap();
    let spec_iface = introspect
        .split("<interface name=\"org.freedesktop.Secret.Collection\">")
        .nth(1)
        .and_then(|rest| rest.split("</interface>").next())
        .expect("the spec interface is exported");
    assert!(
        !spec_iface.contains("DeleteItems"),
        "the batch method leaked onto the freedesktop interface:\n{spec_iface}"
    );
    assert!(
        introspect.contains("org.secret_manager.Collection1"),
        "the private interface is exported alongside it:\n{introspect}"
    );
}

/// An empty batch is a no-op: no save, no signals, no error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_batch_delete_does_nothing() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let admin = CollectionAdminProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();
    let vault_file = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");
    let before = std::fs::read(&vault_file).unwrap();
    admin.delete_items(&[]).await.unwrap();
    assert_eq!(std::fs::read(&vault_file).unwrap(), before);
}

/// Properties with one entry whose value the caller controls, so a test can
/// hand a create path a badly typed `a{sv}`. `props` above always builds a
/// well-typed pair, which is exactly why the type guards were never reached.
fn prop(key: &'static str, value: Value<'static>) -> HashMap<&'static str, Value<'static>> {
    HashMap::from([(key, value)])
}

/// A DH session plus the cipher its client half needs, for the tests that
/// feed attacker-shaped bytes to the server's decrypt.
async fn dh_session(service: &ServiceProxy<'_>) -> (SessionCipher, OwnedObjectPath) {
    let pair = KeyPair::generate();
    let (output, session) = service
        .open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec()))
        .await
        .unwrap();
    let cipher = SessionCipher::from_dh(&pair, &Vec::<u8>::try_from(output).unwrap()).unwrap();
    (cipher, session)
}

fn vault_path(fx: &Fixture) -> std::path::PathBuf {
    fx.data_dir
        .path()
        .join("secret-manager")
        .join("default.vault")
}

/// The `a{sv}` properties dict is the only free-form, client-typed structure
/// the create paths accept, and `dbus::prop_string` / `dbus::prop_attributes`
/// are the two guards on it. A wrongly typed value must be `InvalidArgs` and
/// must not half-create anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_paths_reject_wrongly_typed_properties() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let err = coll
        .create_item(
            prop("org.freedesktop.Secret.Item.Label", Value::from(42u32)),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(
        coll.items().await.unwrap().is_empty(),
        "a refused CreateItem must not create the item"
    );

    let err = coll
        .create_item(
            prop(
                "org.freedesktop.Secret.Item.Attributes",
                Value::from("not a dict"),
            ),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(coll.items().await.unwrap().is_empty());

    // The same guard on the service's own create path, which is checked
    // before any prompt object is exported.
    let err = service
        .create_collection(
            prop(
                "org.freedesktop.Secret.Collection.Label",
                Value::from(42u32),
            ),
            "",
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");

    // A well-typed dict still works, so the guard is a type check and not a
    // blanket refusal.
    coll.create_item(
        props("fine", &[("k", "v")]),
        &plain_secret(&session, b"s"),
        false,
    )
    .await
    .unwrap();
    assert_eq!(coll.items().await.unwrap().len(), 1);
}

/// `DeleteItems` is capped for the same reason as `GetSecrets` and
/// `SearchItems`: every element costs a path resolution and a linear lookup
/// under the global state mutex.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_delete_is_capped() {
    use secret_manager::dbus::collection::MAX_DELETE_ITEMS;
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("one", &[("k", "v")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    let admin = CollectionAdminProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();

    let vault_file = vault_path(&fx);
    let before = std::fs::read(&vault_file).unwrap();

    // Over the cap is refused on length alone, before any path is resolved.
    let over = vec![item_path.clone(); MAX_DELETE_ITEMS + 1];
    let err = admin.delete_items(&over).await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert_eq!(
        coll.items().await.unwrap(),
        vec![item_path.clone()],
        "a refused batch must delete nothing"
    );
    assert_eq!(
        std::fs::read(&vault_file).unwrap(),
        before,
        "a refused batch must not rewrite the vault file"
    );

    // Exactly at the cap still works: the duplicates collapse to the one id.
    let at_cap = vec![item_path.clone(); MAX_DELETE_ITEMS];
    admin.delete_items(&at_cap).await.unwrap();
    assert!(coll.items().await.unwrap().is_empty());
}

/// A locked collection still lists its item ids (the index lives in the
/// cleartext header), so `resolve_item` succeeds and the refusal has to come
/// from the vault itself. That makes this the all-or-nothing case for a
/// *save* failure rather than for path validation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_delete_on_a_locked_collection_changes_nothing() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("locked", &[("k", "v")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    let admin = CollectionAdminProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();

    fx.lock_default().await;
    let vault_file = vault_path(&fx);
    let before = std::fs::read(&vault_file).unwrap();

    let err = admin
        .delete_items(std::slice::from_ref(&item_path))
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.IsLocked");
    assert_eq!(
        coll.items().await.unwrap(),
        vec![item_path.clone()],
        "a locked batch delete must leave the index intact"
    );
    assert_eq!(
        std::fs::read(&vault_file).unwrap(),
        before,
        "a locked batch delete must not rewrite the vault file"
    );

    // And the item is genuinely still there once the collection reopens.
    fx.unlock_default().await;
    let got = service
        .get_secrets(std::slice::from_ref(&item_path), &session)
        .await
        .unwrap();
    assert_eq!(got[&item_path].value.as_slice(), b"s");
}

/// `CreateItem` is the one mutation path where caller-supplied bytes reach a
/// cipher: the session decrypt runs on `parameters`/`value` straight off the
/// wire. Both failure shapes must be `Failed`, with no item created.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_item_rejects_an_undecryptable_secret() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (cipher, session) = dh_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (_, good) = cipher.encrypt(b"plaintext");

    // An IV that is not 16 bytes.
    let err = coll
        .create_item(
            props("bad iv", &[("k", "v")]),
            &SecretStruct {
                session: session.clone(),
                parameters: vec![0u8; 8],
                value: good.clone().into(),
                content_type: "text/plain".into(),
            },
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.Failed");
    assert!(coll.items().await.unwrap().is_empty());

    // A ciphertext that is not a whole number of AES blocks.
    let (iv, mut ragged) = cipher.encrypt(b"plaintext");
    ragged.push(0);
    let err = coll
        .create_item(
            props("ragged", &[("k", "v")]),
            &SecretStruct {
                session: session.clone(),
                parameters: iv,
                value: ragged.into(),
                content_type: "text/plain".into(),
            },
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.Failed");
    assert!(
        coll.items().await.unwrap().is_empty(),
        "a refused CreateItem must not create the item"
    );
}

/// `SetSecret` decrypts on its own path, and unlike `CreateItem` it has an
/// existing secret to lose: a regression that wrote garbage — or an empty
/// vector — before checking the decrypt result would silently destroy it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_secret_leaves_the_old_secret_when_the_decrypt_fails() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (cipher, session) = dh_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (parameters, value) = cipher.encrypt(b"the original");
    let (item_path, _) = coll
        .create_item(
            props("dh set", &[("k", "v")]),
            &SecretStruct {
                session: session.clone(),
                parameters,
                value: value.into(),
                content_type: "text/plain".into(),
            },
            false,
        )
        .await
        .unwrap();
    let it = item(&conn, item_path.clone()).await;

    let (_, replacement) = cipher.encrypt(b"the replacement");
    let err = it
        .set_secret(&SecretStruct {
            session: session.clone(),
            parameters: vec![0u8; 8],
            value: replacement.into(),
            content_type: "text/plain".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.Failed");

    let got = it.get_secret(&session).await.unwrap();
    assert_eq!(
        cipher
            .decrypt(&got.parameters, &got.value)
            .unwrap()
            .as_slice(),
        b"the original",
        "a failed SetSecret must not touch the stored secret"
    );
}

/// The per-item secret cap was bypassable: `CreateItem` enforced
/// `MAX_ITEM_SECRET` but `SetSecret` did not, so a one-byte item could have
/// its secret replaced with something far larger and push the collection past
/// the vault size limit — at which point the whole collection stops saving.
/// This pins the check on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_secret_rejects_an_oversized_secret() {
    use secret_manager::dbus::collection::MAX_ITEM_SECRET;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("small", &[("k", "v")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    let it = item(&conn, item_path.clone()).await;

    let too_big = vec![b'x'; MAX_ITEM_SECRET + 1];
    let err = it
        .set_secret(&plain_secret(&session, &too_big))
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(
        error_message(&err).contains(&MAX_ITEM_SECRET.to_string()),
        "the refusal should name the cap: {}",
        error_message(&err)
    );
    assert_eq!(
        it.get_secret(&session).await.unwrap().value.as_slice(),
        b"s",
        "a refused SetSecret must not touch the stored secret"
    );

    // Exactly at the limit is still accepted, as it is on `CreateItem`.
    let at_limit = vec![b'y'; MAX_ITEM_SECRET];
    it.set_secret(&plain_secret(&session, &at_limit))
        .await
        .unwrap();
    assert_eq!(
        it.get_secret(&session).await.unwrap().value.len(),
        MAX_ITEM_SECRET
    );
}

/// `GetSecrets` takes an arbitrary array of caller-supplied paths. Anything
/// that does not name an item it can read is simply left out of the reply, as
/// the spec allows — the call must not fail, and must still answer for the
/// paths that *are* good, or one stale path from a client's cache would cost
/// it every secret in the batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_secrets_omits_paths_that_name_no_readable_item() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("real", &[("k", "v")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();

    let asked = [
        // An item id that never existed, under a real collection.
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/default/nosuchitem")
            .unwrap(),
        // A collection path, which names no item at all.
        fx.default_collection(),
        // An item under a collection that does not exist.
        OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/nope/abc").unwrap(),
        item_path.clone(),
    ];
    let out = service.get_secrets(&asked, &session).await.unwrap();
    assert_eq!(
        out.keys().cloned().collect::<Vec<_>>(),
        vec![item_path],
        "only the one readable item may appear in the reply"
    );
    assert_eq!(out.values().next().unwrap().value.as_slice(), b"s");
}

/// The `Attributes` property is optional in the spec, and `secret-tool`-style
/// callers do send an item with a label and nothing else. The missing-key arm
/// of `dbus::prop_attributes` is what makes that an empty attribute set
/// instead of an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_item_without_an_attributes_property_gets_an_empty_set() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let (item_path, prompt) = coll
        .create_item(
            prop(
                "org.freedesktop.Secret.Item.Label",
                Value::from("no attributes"),
            ),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    let it = item(&conn, item_path.clone()).await;
    assert_eq!(it.label().await.unwrap(), "no attributes");
    assert!(
        it.attributes().await.unwrap().is_empty(),
        "an absent Attributes property must mean no attributes, not a failure"
    );
    // And the item is a normal item: an empty query still finds it.
    assert_eq!(
        coll.search_items(HashMap::new()).await.unwrap(),
        vec![item_path]
    );
}

/// The batch delete is all-or-nothing *and* single-collection: a path that
/// resolves to a real item of a **different** collection must refuse the whole
/// call, with both collections untouched. Without the check, one call could
/// delete across a collection boundary the caller never named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_delete_refuses_an_item_of_another_collection() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
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
    secret_manager::dbus::state::with_vault(&fx.daemon.state, "second", |v| {
        v.unlock(common::PASSWORD.as_bytes())
    })
    .await
    .unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let first = collection(&conn, fx.default_collection()).await;
    let second_path = secret_manager::dbus::paths::collection("second");
    let second = collection(&conn, second_path.clone()).await;
    let (mine, _) = first
        .create_item(
            props("mine", &[("k", "v")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    let (theirs, _) = second
        .create_item(
            props("theirs", &[("k", "v")]),
            &plain_secret(&session, b"t"),
            false,
        )
        .await
        .unwrap();

    let admin = CollectionAdminProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();
    let err = admin
        .delete_items(&[mine.clone(), theirs.clone()])
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(
        error_message(&err).contains("belong to this collection"),
        "{}",
        error_message(&err)
    );
    assert_eq!(
        first.items().await.unwrap(),
        vec![mine],
        "the refused batch deleted an item of the collection it was sent to"
    );
    assert_eq!(
        second.items().await.unwrap(),
        vec![theirs],
        "the refused batch deleted an item of the other collection"
    );
}

/// The batch interface is exported on the alias object as well as the
/// collection's own path, and the CLI reaches a collection through
/// `/aliases/default`. An alias target that resolves must behave exactly like
/// the real path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_delete_works_through_the_alias_object() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (a, _) = coll
        .create_item(
            props("a", &[("k", "1")]),
            &plain_secret(&session, b"1"),
            false,
        )
        .await
        .unwrap();
    let (b, _) = coll
        .create_item(
            props("b", &[("k", "2")]),
            &plain_secret(&session, b"2"),
            false,
        )
        .await
        .unwrap();

    let alias_path = secret_manager::dbus::paths::alias("default").unwrap();
    let admin = CollectionAdminProxy::builder(&conn)
        .path(alias_path)
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut deleted = coll.receive_item_deleted().await.unwrap();
    admin.delete_items(std::slice::from_ref(&a)).await.unwrap();
    assert_eq!(deleted.next().await.unwrap().args().unwrap().item, a);
    assert_eq!(
        coll.items().await.unwrap(),
        vec![b],
        "the alias object deleted the wrong item, or none"
    );
}

/// Properties dict with an arbitrary label and attribute set, for the cap
/// tests: `props` above only takes `&'static`-ish borrowed pairs, and these
/// need owned, generated ones.
fn props_owned(label: &str, attrs: Vec<(String, String)>) -> HashMap<&'static str, Value<'static>> {
    let attrs: HashMap<String, String> = attrs.into_iter().collect();
    HashMap::from([
        (
            "org.freedesktop.Secret.Item.Label",
            Value::from(label.to_string()),
        ),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
    ])
}

/// `MAX_ITEM_SECRET` bounded the secret and nothing else, so the same DoS it
/// exists to stop was reachable through the two other client-supplied fields
/// that land in the very same encrypted item blob: the label and the
/// attributes. A label is one `CreateItem` argument, so it took *two* calls to
/// push a collection past the vault size limit where a capped secret takes
/// 256; an attribute set is unbounded in pair count, name length and value
/// length at once.
///
/// Every path that writes either field is capped: `CreateItem` (both), and the
/// `Item.Label` / `Item.Attributes` property setters, which otherwise make the
/// create-path cap a speed bump — create a one-byte item, then grow it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn label_and_attributes_are_capped_on_every_write_path() {
    use secret_manager::dbus::collection::{
        MAX_ATTRIBUTE_KEY, MAX_ATTRIBUTE_VALUE, MAX_ITEM_ATTRIBUTES, MAX_ITEM_LABEL,
    };
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let huge_label = "L".repeat(MAX_ITEM_LABEL + 1);
    let too_many: Vec<(String, String)> = (0..=MAX_ITEM_ATTRIBUTES)
        .map(|n| (format!("k{n}"), "v".to_string()))
        .collect();
    let huge_key = vec![("K".repeat(MAX_ATTRIBUTE_KEY + 1), "v".to_string())];
    let huge_value = vec![("k".to_string(), "V".repeat(MAX_ATTRIBUTE_VALUE + 1))];

    // --- CreateItem, label path ---
    let err = coll
        .create_item(
            props_owned(&huge_label, vec![]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(
        error_message(&err).contains(&MAX_ITEM_LABEL.to_string()),
        "the refusal must name the limit: {}",
        error_message(&err)
    );

    // --- CreateItem, attributes path: count, name length, value length ---
    for (attrs, limit) in [
        (too_many.clone(), MAX_ITEM_ATTRIBUTES),
        (huge_key.clone(), MAX_ATTRIBUTE_KEY),
        (huge_value.clone(), MAX_ATTRIBUTE_VALUE),
    ] {
        let err = coll
            .create_item(
                props_owned("ok", attrs),
                &plain_secret(&session, b"s"),
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
        assert!(
            error_message(&err).contains(&limit.to_string()),
            "the refusal must name the limit {limit}: {}",
            error_message(&err)
        );
    }
    assert!(
        coll.items().await.unwrap().is_empty(),
        "a refused CreateItem must not create the item"
    );

    // --- the setters, on an item created within the caps ---
    let (item_path, _) = coll
        .create_item(
            props_owned("fine", vec![("k".into(), "v".into())]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    let it = item(&conn, item_path.clone()).await;

    let err = it.set_label(&huge_label).await.unwrap_err();
    assert!(
        error_message(&err).contains(&MAX_ITEM_LABEL.to_string()),
        "set_label must refuse an over-long label naming the limit: {}",
        error_message(&err)
    );
    assert_eq!(
        it.label().await.unwrap(),
        "fine",
        "a refused set_label must not have changed the label"
    );

    for (attrs, limit) in [
        (too_many, MAX_ITEM_ATTRIBUTES),
        (huge_key, MAX_ATTRIBUTE_KEY),
        (huge_value, MAX_ATTRIBUTE_VALUE),
    ] {
        let map: HashMap<&str, &str> = attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let err = it.set_attributes(map).await.unwrap_err();
        assert!(
            error_message(&err).contains(&limit.to_string()),
            "set_attributes must refuse and name the limit {limit}: {}",
            error_message(&err)
        );
        assert_eq!(
            it.attributes().await.unwrap(),
            HashMap::from([("k".to_string(), "v".to_string())]),
            "a refused set_attributes must not have changed the attributes"
        );
    }

    // Exactly at each limit is still accepted: these are bounds, not a
    // tightening of the normal case.
    let at_limit_label = "L".repeat(MAX_ITEM_LABEL);
    it.set_label(&at_limit_label).await.unwrap();
    assert_eq!(it.label().await.unwrap(), at_limit_label);
    let at_limit_key = "K".repeat(MAX_ATTRIBUTE_KEY);
    let at_limit_value = "V".repeat(MAX_ATTRIBUTE_VALUE);
    it.set_attributes(HashMap::from([(
        at_limit_key.as_str(),
        at_limit_value.as_str(),
    )]))
    .await
    .unwrap();
    assert_eq!(
        it.attributes().await.unwrap(),
        HashMap::from([(at_limit_key, at_limit_value)])
    );
}

/// The caller-sized decrypt used to run *before* the size cap and the locked
/// check, with the global state mutex held: `secret.value` is bounded only by
/// the bus message size (128 MiB), so a client could make the daemon decrypt
/// 128 MiB — stalling every other client — before being told the secret was
/// over the cap and the collection locked anyway.
///
/// Both refusals are observable because they now beat the decrypt: a
/// deliberately undecryptable ciphertext gets `InvalidArgs` (too big) or
/// `IsLocked` (locked) instead of the `Failed` that a performed decrypt
/// produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_and_locked_are_refused_before_the_decrypt() {
    use secret_manager::dbus::collection::{MAX_ITEM_CIPHERTEXT, MAX_ITEM_SECRET};
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (cipher, session) = dh_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    // Garbage that no key can decrypt, and one byte past the ciphertext cap.
    let undecryptable = |len: usize| SecretStruct {
        session: session.clone(),
        parameters: vec![7u8; 16],
        value: vec![0xab; len].into(),
        content_type: "text/plain".into(),
    };

    let err = coll
        .create_item(
            props("huge", &[("k", "1")]),
            &undecryptable(MAX_ITEM_CIPHERTEXT + 1),
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.DBus.Error.InvalidArgs",
        "an over-cap ciphertext must be refused before it is decrypted"
    );
    assert!(error_message(&err).contains(&MAX_ITEM_SECRET.to_string()));
    assert!(coll.items().await.unwrap().is_empty());

    // A real item, to exercise Item.SetSecret's copy of the same ordering.
    let (params, value) = cipher.encrypt(b"small");
    let (item_path, _) = coll
        .create_item(
            props("real", &[("k", "2")]),
            &SecretStruct {
                session: session.clone(),
                parameters: params,
                value: value.into(),
                content_type: "text/plain".into(),
            },
            false,
        )
        .await
        .unwrap();
    let it = item(&conn, item_path.clone()).await;
    let err = it
        .set_secret(&undecryptable(MAX_ITEM_CIPHERTEXT + 1))
        .await
        .unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.DBus.Error.InvalidArgs",
        "SetSecret must refuse an over-cap ciphertext before decrypting it"
    );

    // The bound is an upper bound on the plaintext, not a tightening of it: a
    // plaintext of exactly `MAX_ITEM_SECRET` pads to `MAX_ITEM_CIPHERTEXT`
    // and must still be accepted, through the real cipher.
    let big = vec![b'y'; MAX_ITEM_SECRET];
    let (params, value) = cipher.encrypt(&big);
    assert_eq!(value.len(), MAX_ITEM_CIPHERTEXT);
    it.set_secret(&SecretStruct {
        session: session.clone(),
        parameters: params,
        value: value.into(),
        content_type: "text/plain".into(),
    })
    .await
    .unwrap();

    // Locked: the lock is answered before the decrypt too, so an
    // undecryptable but legally sized secret reports `IsLocked`, not the
    // `Failed` of a decrypt that should never have run.
    fx.lock_default().await;
    let err = coll
        .create_item(props("x", &[]), &undecryptable(64), false)
        .await
        .unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.Secret.Error.IsLocked",
        "a locked collection must refuse before decrypting"
    );
    let err = it.set_secret(&undecryptable(64)).await.unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.Secret.Error.IsLocked",
        "SetSecret on a locked collection must refuse before decrypting"
    );
}

/// `DeleteItems([])` returned `Ok` on a locked collection because the
/// empty-batch shortcut sat in front of the lock check, so an empty batch
/// answered success exactly where `Item.Delete` — and a one-item batch —
/// answer `IsLocked`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_batch_delete_still_answers_the_lock() {
    use secret_manager::dbus::proxies::CollectionAdminProxy;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("a", &[("k", "1")]),
            &plain_secret(&session, b"1"),
            false,
        )
        .await
        .unwrap();
    let admin = CollectionAdminProxy::builder(&conn)
        .path(fx.default_collection())
        .unwrap()
        .build()
        .await
        .unwrap();
    fx.lock_default().await;

    assert_eq!(
        error_name(&admin.delete_items(&[]).await.unwrap_err()),
        "org.freedesktop.Secret.Error.IsLocked",
        "an empty batch must answer the lock like every other delete"
    );
    // The one-item batch and Item.Delete are what it has to agree with.
    assert_eq!(
        error_name(
            &admin
                .delete_items(std::slice::from_ref(&item_path))
                .await
                .unwrap_err()
        ),
        "org.freedesktop.Secret.Error.IsLocked"
    );
    assert_eq!(
        error_name(&item(&conn, item_path).await.delete().await.unwrap_err()),
        "org.freedesktop.Secret.Error.IsLocked"
    );
}

/// The content type is the fourth caller-supplied field stored in the
/// encrypted item blob, alongside the secret, the label and the attributes,
/// so an uncapped one is the same vault-size DoS with a different field name:
/// two `CreateItem` calls with a multi-megabyte "MIME type" push a collection
/// past the size limit, past which it stops saving at all. Both paths that
/// write it are capped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn content_type_is_capped_on_every_write_path() {
    use secret_manager::dbus::collection::MAX_ITEM_CONTENT_TYPE;
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;

    let huge = "t".repeat(MAX_ITEM_CONTENT_TYPE + 1);
    let typed = |content_type: &str| SecretStruct {
        session: session.clone(),
        parameters: vec![],
        value: b"s".to_vec().into(),
        content_type: content_type.to_string(),
    };

    let err = coll
        .create_item(props("ct", &[("k", "1")]), &typed(&huge), false)
        .await
        .unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(
        error_message(&err).contains(&MAX_ITEM_CONTENT_TYPE.to_string()),
        "the refusal must name the limit: {}",
        error_message(&err)
    );
    assert!(
        coll.items().await.unwrap().is_empty(),
        "a refused CreateItem must not create the item"
    );

    // The setter is the other half: a short content type on create, then a
    // huge one on SetSecret, would make the create-path cap a speed bump.
    let (item_path, _) = coll
        .create_item(props("ct", &[("k", "1")]), &typed("text/plain"), false)
        .await
        .unwrap();
    let it = item(&conn, item_path.clone()).await;
    let err = it.set_secret(&typed(&huge)).await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(error_message(&err).contains(&MAX_ITEM_CONTENT_TYPE.to_string()));
    assert_eq!(
        service
            .get_secrets(std::slice::from_ref(&item_path), &session)
            .await
            .unwrap()[&item_path]
            .content_type,
        "text/plain",
        "a refused SetSecret must not have changed the content type"
    );

    // Exactly at the limit is still accepted: a bound, not a tightening.
    let at_limit = "t".repeat(MAX_ITEM_CONTENT_TYPE);
    it.set_secret(&typed(&at_limit)).await.unwrap();
    assert_eq!(
        service
            .get_secrets(std::slice::from_ref(&item_path), &session)
            .await
            .unwrap()[&item_path]
            .content_type,
        at_limit
    );
}

/// `Item.GetSecret` refreshed the idle timer before it checked the session,
/// the twin of the bug fixed in `Service.GetSecrets`: any bus client could
/// call it with a bogus (or another client's) session path, be refused, and
/// still keep `last_activity` moving — so `idle_lock` never fired,
/// `auto_lock_after` never locked the vault, and the keys stayed in daemon
/// memory indefinitely. It needs no session, no unlocked collection and no
/// knowledge of a real item path.
///
/// The assertion is on `last_activity` itself, not on a timeout: a refused
/// call must leave it *identical*, and an authorised one must advance it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_get_secret_does_not_refresh_the_idle_timer() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll
        .create_item(
            props("t", &[("k", "1")]),
            &plain_secret(&session, b"s"),
            false,
        )
        .await
        .unwrap();
    let it = item(&conn, item_path.clone()).await;
    let last_activity = || async { fx.daemon.state.lock().await.last_activity };

    // A session path that names nothing: refused, and must not count.
    let before = last_activity().await;
    assert_eq!(
        error_name(
            &it.get_secret(&secret_manager::dbus::paths::session(99))
                .await
                .unwrap_err()
        ),
        "org.freedesktop.Secret.Error.NoSession"
    );
    assert_eq!(
        last_activity().await,
        before,
        "a refused GetSecret refreshed the idle timer"
    );

    // Another client's session is refused the same way, and must not count
    // either — that one needs no session of the caller's own at all.
    let other = fx.client().await;
    let other_session = plain_session(&ServiceProxy::new(&other).await.unwrap()).await;
    assert_eq!(
        error_name(&it.get_secret(&other_session).await.unwrap_err()),
        "org.freedesktop.Secret.Error.NoSession"
    );
    assert_eq!(
        last_activity().await,
        before,
        "a GetSecret on a foreign session refreshed the idle timer"
    );

    // The authorised call still counts, in the same lock acquisition.
    assert_eq!(
        it.get_secret(&session).await.unwrap().value.as_slice(),
        b"s"
    );
    assert!(
        last_activity().await > before,
        "an authorised GetSecret must still refresh the idle timer"
    );
}

/// Reload a daemon whose vault directory has changed under it.
async fn reload(fx: &Fixture) {
    let sock = fx.control_socket();
    let reply = tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply, secret_manager::protocol::Response::Ok);
}

/// An `aliases.toml` that stops parsing under a running daemon.
///
/// The table is then **unusable, not empty**, and the difference is the whole
/// point: "no such alias" is the answer that invites a client to claim a name
/// the user already owns. A name the daemon has already read still resolves,
/// because losing every alias in a running process over a file we already
/// hold the contents of helps nobody; a name it has never read is refused.
///
/// Nothing here was covered before, which is why the guard could sit inside
/// `SetAlias`'s repointing branch — leaving the clearing path to mutate the
/// table first and bounce off the `update_aliases` backstop afterwards, with
/// the entry gone from memory and the two exported objects it exists to
/// reclaim still on the bus.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alias_operations_while_the_table_is_unreadable() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    service
        .set_alias("work", &fx.default_collection())
        .await
        .unwrap();

    let path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("aliases.toml");
    let corrupt = b"aliases = 5\n";
    std::fs::write(&path, corrupt).unwrap();
    reload(&fx).await;

    // Known names keep working, on the read-only introspection...
    assert_eq!(
        service.read_alias("work").await.unwrap(),
        fx.default_collection(),
        "a name already read must survive the file going bad"
    );
    // ...and on the object path that actually carries secrets.
    let alias = collection(&conn, secret_manager::dbus::paths::alias("work").unwrap()).await;
    assert_eq!(alias.label().await.unwrap(), "Default");
    let (item_path, _) = alias
        .create_item(
            props("still works", &[("a", "b")]),
            &plain_secret(&session, b"s"),
            true,
        )
        .await
        .unwrap();
    assert!(
        item_path
            .as_str()
            .starts_with("/org/freedesktop/secrets/collection/default/")
    );

    // A name the daemon has never read is refused, not answered `/`.
    let err = service.read_alias("login").await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.Failed");
    assert!(format!("{err:?}").contains("unreadable"), "{err:?}");
    let unknown = collection(&conn, secret_manager::dbus::paths::alias("login").unwrap()).await;
    assert!(unknown.label().await.is_err());

    // Clearing refuses *before* it changes anything.
    assert_eq!(
        error_name(
            &service
                .set_alias("work", &secret_manager::dbus::paths::root())
                .await
                .unwrap_err()
        ),
        "org.freedesktop.DBus.Error.Failed"
    );
    assert_eq!(
        service.read_alias("work").await.unwrap(),
        fx.default_collection(),
        "a refused clear must not have removed the entry anyway"
    );
    assert_eq!(
        alias.label().await.unwrap(),
        "Default",
        "a refused clear must not leave the alias half-removed"
    );

    // So does setting one.
    assert_eq!(
        error_name(
            &service
                .set_alias("login", &fx.default_collection())
                .await
                .unwrap_err()
        ),
        "org.freedesktop.DBus.Error.Failed"
    );

    // And through all of it the file the operator has to repair is untouched.
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);

    // Repairing it restores everything.
    std::fs::remove_file(&path).unwrap();
    reload(&fx).await;
    assert_eq!(service.read_alias("login").await.unwrap().as_str(), "/");
    service
        .set_alias("login", &fx.default_collection())
        .await
        .unwrap();
}
