mod common;

use common::Fixture;
use futures_util::StreamExt;
use secret_manager::dbus::paths;
use secret_manager::dbus::proxies::{CollectionProxy, PromptProxy, ServiceProxy};
use secret_manager::dbus::session::SecretStruct;
use secret_manager::session::ALGORITHM_PLAIN;
use std::collections::HashMap;
use std::time::Duration;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

async fn collection(conn: &zbus::Connection, path: OwnedObjectPath) -> CollectionProxy<'static> {
    CollectionProxy::builder(conn)
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
        other => panic!("expected MethodError, got {other:?}"),
    }
}

/// Subscribe, trigger, and wait for `Completed`. Returns `(dismissed, result)`.
async fn perform(conn: &zbus::Connection, prompt: &OwnedObjectPath) -> (bool, OwnedValue) {
    let proxy = PromptProxy::builder(conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(10), completed.next())
        .await
        .unwrap()
        .unwrap();
    let args = sig.args().unwrap();
    (args.dismissed, args.result.try_to_owned().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlock_with_correct_password() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let coll = collection(&conn, fx.default_collection()).await;
    assert!(coll.locked().await.unwrap());
    let mut changed = service.receive_collection_changed().await.unwrap();

    let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert!(unlocked.is_empty());
    assert!(
        prompt
            .as_str()
            .starts_with("/org/freedesktop/secrets/prompt/")
    );
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(result).unwrap(),
        vec![fx.default_collection()]
    );
    assert!(!coll.locked().await.unwrap());
    assert_eq!(
        changed.next().await.unwrap().args().unwrap().collection,
        fx.default_collection()
    );
    assert!(fx.pinentry_log().contains("GETPIN"));

    // Already unlocked: no prompt.
    let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert_eq!(unlocked, vec![fx.default_collection()]);
    assert_eq!(prompt.as_str(), "/");
    // Prompt object is gone.
    assert!(
        common::wait_for(Duration::from_secs(2), || async {
            PromptProxy::builder(&conn)
                .path(prompt.clone())
                .unwrap()
                .build()
                .await
                .unwrap()
                .dismiss()
                .await
                .is_err()
        })
        .await
    );
    assert!(fx.daemon.state.lock().await.prompt_owners.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_password_three_times_then_dismissed() {
    let fx = Fixture::start_with_pin(Some("wrong")).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(dismissed);
    assert!(Vec::<OwnedObjectPath>::try_from(result).unwrap().is_empty());
    let log = fx.pinentry_log();
    assert_eq!(log.matches("GETPIN").count(), 3);
    assert_eq!(log.matches("SETERROR").count(), 2);
    assert!(
        collection(&conn, fx.default_collection())
            .await
            .locked()
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_and_dismiss() {
    let fx = Fixture::start_with_pin(None).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    let (dismissed, _) = perform(&conn, &prompt).await;
    assert!(dismissed);

    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.dismiss().await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(5), completed.next())
        .await
        .unwrap()
        .unwrap();
    assert!(sig.args().unwrap().dismissed);
}

/// `Dismiss` arriving while the prompt's task is still stuck waiting on
/// pinentry (never having obtained an answer) must abort it cleanly, emit
/// exactly one `Completed(true, [])` with an `ao` result (unlock prompts
/// always resolve to `ao`, on success and on dismissal alike), and never a
/// second `Completed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dismiss_after_prompt_on_unlock_yields_one_completed_with_ao_result() {
    let fx = Fixture::start_with_pin_and_env(
        None,
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    proxy.dismiss().await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(5), completed.next())
        .await
        .unwrap()
        .unwrap();
    let args = sig.args().unwrap();
    assert!(args.dismissed);
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(args.result.try_to_owned().unwrap()).unwrap(),
        Vec::<OwnedObjectPath>::new()
    );
    // No second `Completed` ever arrives (the fake pinentry would otherwise
    // still answer, cancelled, after its `FAKE_DELAY`).
    assert!(
        tokio::time::timeout(Duration::from_millis(300), completed.next())
            .await
            .is_err()
    );
}

/// The success path must still emit exactly one `Completed`, including when a
/// (too-late) `Dismiss` arrives after the prompt has already finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlock_success_emits_exactly_one_completed() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(10), completed.next())
        .await
        .unwrap()
        .unwrap();
    assert!(!sig.args().unwrap().dismissed);
    // The prompt object is already gone; a late `Dismiss` cannot resurrect it
    // or emit a second `Completed`.
    let _ = proxy.dismiss().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), completed.next())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlock_by_item_path_and_lock() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap()
        .1;
    let coll = collection(&conn, fx.default_collection()).await;
    let attrs: HashMap<String, String> = HashMap::from([("k".to_string(), "v".to_string())]);
    let props = HashMap::from([
        ("org.freedesktop.Secret.Item.Label", Value::from("x")),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
    ]);
    let secret = SecretStruct {
        session: session.clone(),
        parameters: vec![],
        value: b"s".to_vec(),
        content_type: "text/plain".into(),
    };
    let (item_path, _) = coll.create_item(props, &secret, false).await.unwrap();

    let mut changed = service.receive_collection_changed().await.unwrap();
    let (locked, prompt) = service
        .lock(std::slice::from_ref(&item_path))
        .await
        .unwrap();
    assert_eq!(locked, vec![item_path.clone()]);
    assert_eq!(prompt.as_str(), "/");
    assert!(coll.locked().await.unwrap());
    assert_eq!(
        changed.next().await.unwrap().args().unwrap().collection,
        fx.default_collection()
    );

    let (_, prompt) = service
        .unlock(std::slice::from_ref(&item_path))
        .await
        .unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(result).unwrap(),
        vec![item_path.clone()]
    );
    assert!(!coll.locked().await.unwrap());
    let got = service
        .get_secrets(std::slice::from_ref(&item_path), &session)
        .await
        .unwrap();
    assert_eq!(got[&item_path].value, b"s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_with_alias_and_delete() {
    let fx = Fixture::start_with_pin_and_env(
        Some("newpw"),
        vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
        Duration::ZERO,
    )
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut created = service.receive_collection_created().await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (path, prompt) = service
        .create_collection(props.clone(), "work")
        .await
        .unwrap();
    assert_eq!(path.as_str(), "/");
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    let new_path = OwnedObjectPath::try_from(result).unwrap();
    assert_eq!(new_path, paths::collection("work_keys"));
    assert_eq!(
        created.next().await.unwrap().args().unwrap().collection,
        new_path
    );
    assert!(fx.pinentry_log().contains("SETREPEAT"));
    assert!(
        fx.data_dir
            .path()
            .join("secret-manager")
            .join("work_keys.vault")
            .exists()
    );
    assert_eq!(service.read_alias("work").await.unwrap(), new_path);
    let work = collection(&conn, new_path.clone()).await;
    assert_eq!(work.label().await.unwrap(), "Work Keys");
    assert!(
        !work.locked().await.unwrap(),
        "freshly created collections start unlocked"
    );
    assert!(service.collections().await.unwrap().contains(&new_path));

    // Existing alias short-circuits without a prompt.
    let (path, prompt) = service.create_collection(props, "work").await.unwrap();
    assert_eq!(path, new_path);
    assert_eq!(prompt.as_str(), "/");

    let mut deleted = service.receive_collection_deleted().await.unwrap();
    let delete_prompt = work.delete().await.unwrap();
    assert!(
        delete_prompt
            .as_str()
            .starts_with("/org/freedesktop/secrets/prompt/"),
        "Delete must return a confirmation prompt, not delete immediately"
    );
    let (dismissed, result) = perform(&conn, &delete_prompt).await;
    assert!(!dismissed);
    assert_eq!(OwnedObjectPath::try_from(result).unwrap(), new_path);
    assert!(fx.pinentry_log().contains("CONFIRM"));
    assert_eq!(
        deleted.next().await.unwrap().args().unwrap().collection,
        new_path
    );
    assert!(
        !fx.data_dir
            .path()
            .join("secret-manager")
            .join("work_keys.vault")
            .exists()
    );
    assert_eq!(service.read_alias("work").await.unwrap().as_str(), "/");
    assert!(!service.collections().await.unwrap().contains(&new_path));
}

/// Refusing (or cancelling) the confirmation prompt leaves the collection,
/// its vault file, and its alias untouched, and completes the prompt with
/// `Completed(true, "/")`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_collection_refused_leaves_it_intact() {
    // No FAKE_CONFIRM set => the fake pinentry answers CONFIRM with cancel.
    let fx = Fixture::start_with_pin(Some("newpw")).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service.create_collection(props, "work").await.unwrap();
    let (_, result) = perform(&conn, &prompt).await;
    let new_path = OwnedObjectPath::try_from(result).unwrap();
    let work = collection(&conn, new_path.clone()).await;

    let delete_prompt = work.delete().await.unwrap();
    assert!(
        delete_prompt
            .as_str()
            .starts_with("/org/freedesktop/secrets/prompt/")
    );
    let (dismissed, result) = perform(&conn, &delete_prompt).await;
    assert!(dismissed);
    assert_eq!(OwnedObjectPath::try_from(result).unwrap().as_str(), "/");

    assert!(
        fx.data_dir
            .path()
            .join("secret-manager")
            .join("work_keys.vault")
            .exists(),
        "refused delete must not remove the vault file"
    );
    assert_eq!(service.read_alias("work").await.unwrap(), new_path);
    assert!(service.collections().await.unwrap().contains(&new_path));
    assert!(!work.locked().await.unwrap());
}

/// `Collection.Delete` on a locked collection must fail immediately with
/// `IsLocked` and must not allocate a confirmation prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_on_locked_collection_returns_is_locked_without_prompt() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let coll_path = fx.default_collection();
    let coll = collection(&conn, coll_path.clone()).await;

    let (locked, prompt) = service
        .lock(std::slice::from_ref(&coll_path))
        .await
        .unwrap();
    assert_eq!(locked, vec![coll_path.clone()]);
    assert_eq!(prompt.as_str(), "/");
    assert!(coll.locked().await.unwrap());

    let owners_before = fx.daemon.state.lock().await.prompt_owners.clone();
    let err = coll.delete().await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.IsLocked");
    assert_eq!(
        fx.daemon.state.lock().await.prompt_owners,
        owners_before,
        "a rejected Delete must not create a prompt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_cancelled() {
    let fx = Fixture::start_with_pin(None).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Nope"),
    )]);
    let (_, prompt) = service.create_collection(props, "").await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(dismissed);
    assert_eq!(OwnedObjectPath::try_from(result).unwrap().as_str(), "/");
    assert_eq!(
        service.collections().await.unwrap(),
        vec![fx.default_collection()]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_tool_unlocks_through_prompt() {
    if std::process::Command::new("secret-tool")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let fx = Fixture::start().await; // locked, pinentry answers "pw"
    let mut cmd = tokio::process::Command::new("secret-tool");
    cmd.args(["store", "--label=Prompted", "app", "prompted"])
        .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    use tokio::io::AsyncWriteExt;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"s3cret")
        .await
        .unwrap();
    let out = child.wait_with_output().await.unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fx.pinentry_log().contains("GETPIN"));

    let out = tokio::process::Command::new("secret-tool")
        .args(["lookup", "app", "prompted"])
        .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address)
        .output()
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "s3cret");
}
