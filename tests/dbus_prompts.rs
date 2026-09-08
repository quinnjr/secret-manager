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

/// Locking a collection must also emit `Collection.Locked`'s
/// `PropertiesChanged` on every alias object that targets it, not just on
/// the collection's own path (finding 4): an alias is served by its own
/// `Collection` instance with its own cached property, so it needs its own
/// signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lock_emits_properties_changed_on_alias_too() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();

    let alias_props = zbus::fdo::PropertiesProxy::builder(&conn)
        .destination(secret_manager::dbus::paths::BUS_NAME)
        .unwrap()
        .path(secret_manager::dbus::paths::alias("default").unwrap())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut changed = alias_props.receive_properties_changed().await.unwrap();

    let (locked, prompt) = service.lock(&[fx.default_collection()]).await.unwrap();
    assert_eq!(locked, vec![fx.default_collection()]);
    assert_eq!(prompt.as_str(), "/");

    let sig = tokio::time::timeout(Duration::from_secs(5), changed.next())
        .await
        .expect("PropertiesChanged on the alias object")
        .unwrap();
    let args = sig.args().unwrap();
    assert_eq!(
        args.interface_name.as_str(),
        "org.freedesktop.Secret.Collection"
    );
    assert!(args.changed_properties.contains_key("Locked"));
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
        value: b"s".to_vec().into(),
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
    assert_eq!(got[&item_path].value.as_slice(), b"s");
}

/// A prompt belongs to the client that obtained it (`Service.Unlock` etc.):
/// another client calling `Prompt`/`Dismiss` on it must be refused, and the
/// prompt must still complete normally for its actual owner afterwards
/// (finding 5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_is_refused_to_a_non_owner() {
    let fx = Fixture::start().await;
    let owner_conn = fx.client().await;
    let intruder_conn = fx.client().await;
    let service = ServiceProxy::new(&owner_conn).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();

    let intruder = PromptProxy::builder(&intruder_conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let err = intruder.dismiss().await.unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.Secret.Error.NoSuchObject"
    );
    let err = intruder.prompt("").await.unwrap_err();
    assert_eq!(
        error_name(&err),
        "org.freedesktop.Secret.Error.NoSuchObject"
    );

    // The prompt is otherwise untouched: its owner still completes it normally.
    let (dismissed, result) = perform(&owner_conn, &prompt).await;
    assert!(!dismissed);
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(result).unwrap(),
        vec![fx.default_collection()]
    );
}

/// A dismissed prompt must be dead: its action is consumed and its owner
/// entry gone, so no other client can take it over in the window before the
/// object is unexported and drive it to completion (HIGH 1). Historically
/// `check_owner` treated a *missing* owner entry as authorized and `dismiss`
/// left `action` intact, so a second client could call `Prompt` on the
/// just-dismissed path and raise the dialog for itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dismissed_prompt_cannot_be_driven_by_another_client() {
    let fx = Fixture::start().await; // pinentry would answer the correct password
    let owner_conn = fx.client().await;
    let intruder_conn = fx.client().await;
    let service = ServiceProxy::new(&owner_conn).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();

    let owner = PromptProxy::builder(&owner_conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = owner.receive_completed().await.unwrap();
    owner.dismiss().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), completed.next())
            .await
            .unwrap()
            .unwrap()
            .args()
            .unwrap()
            .dismissed
    );

    // Racing straight into the window between `Dismiss` and the object being
    // unexported: every call must be refused, whichever side of it lands.
    let intruder = PromptProxy::builder(&intruder_conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    for _ in 0..20 {
        assert!(
            intruder.prompt("").await.is_err(),
            "a non-owner drove a dismissed prompt"
        );
        assert!(intruder.dismiss().await.is_err());
    }
    // The owner cannot re-arm it either.
    assert!(owner.prompt("").await.is_err());

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !fx.pinentry_log().contains("GETPIN"),
        "a dialog was raised for a dismissed prompt:\n{}",
        fx.pinentry_log()
    );
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "the collection was unlocked by a taken-over prompt"
    );
    assert!(fx.daemon.state.lock().await.prompt_owners.is_empty());
}

/// The same takeover, raced against the dismissal and aimed at a *delete*
/// confirmation — the destructive case the missing-owner hole exposed. A
/// second client hammers `Prompt` while the owner dismisses, so calls land
/// inside the window where the owner entry is already gone but the object is
/// still exported. None of them may raise a confirmation dialog, and the
/// collection must survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dismissed_delete_prompt_cannot_be_taken_over() {
    for _ in 0..8 {
        // The fake pinentry would confirm the deletion if it were ever asked.
        let fx = Fixture::start_with_pin_and_env(
            Some(common::PASSWORD),
            vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
            Duration::ZERO,
        )
        .await;
        fx.unlock_default().await;
        let owner_conn = fx.client().await;
        let intruder_conn = fx.client().await;
        let coll = collection(&owner_conn, fx.default_collection()).await;
        let prompt = coll.delete().await.unwrap();
        let owner = PromptProxy::builder(&owner_conn)
            .path(prompt.clone())
            .unwrap()
            .build()
            .await
            .unwrap();
        let intruder = PromptProxy::builder(&intruder_conn)
            .path(prompt.clone())
            .unwrap()
            .build()
            .await
            .unwrap();
        let hammer = tokio::spawn(async move {
            for _ in 0..200 {
                let _ = intruder.prompt("").await;
            }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _ = owner.dismiss().await;
        let _ = hammer.await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let log = fx.pinentry_log();
        assert!(
            !log.contains("CONFIRM"),
            "a non-owner raised the delete confirmation of a dismissed prompt:\n{log}"
        );
        assert!(
            fx.data_dir
                .path()
                .join("secret-manager")
                .join("default.vault")
                .exists(),
            "a taken-over prompt deleted the collection"
        );
        assert!(
            fx.daemon
                .state
                .lock()
                .await
                .collections
                .contains_key("default"),
            "a taken-over prompt removed the collection from state"
        );
    }
}

/// `Dismiss` arriving *after* the commit gate was claimed (so it cannot abort
/// the task) must still stop a multi-collection unlock from raising dialogs
/// for the collections it has not reached yet (MEDIUM 2).
///
/// Three locked collections, so the dismissal can land inside the second
/// dialog — past the commit gate, which the first collection's answer
/// claimed — and be observed to suppress the third.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dismiss_after_the_commit_gate_stops_the_remaining_collections() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
    let dir = fx.data_dir.path().join("secret-manager");
    for id in ["second", "third"] {
        secret_manager::vault::Vault::create(
            &dir.join(format!("{id}.vault")),
            id,
            common::PASSWORD.as_bytes(),
            secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
    }
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    let (_, prompt) = service
        .unlock(&[
            fx.default_collection(),
            paths::collection("second"),
            paths::collection("third"),
        ])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    // The first dialog answers at ~2s and claims the gate; dismiss inside the
    // second one, which is therefore already past the point of no return.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        2,
        "timing assumption: two dialogs raised by now:\n{}",
        fx.pinentry_log()
    );
    proxy.dismiss().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), completed.next())
        .await
        .expect("the prompt still completes")
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = fx.pinentry_log();
    assert_eq!(
        log.matches("GETPIN").count(),
        2,
        "a dialog was raised after the dismissal:\n{log}"
    );
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "third").await,
        "the third collection was unlocked despite the dismissal"
    );
}

/// A collection label is attacker-controlled — any client can call `SetLabel`,
/// no authorization required — and it is shown in the delete-confirmation
/// dialog. It must not be able to forge extra lines of dialog text, and it must
/// not be able to forge the daemon's *own* authoritative clause (HIGH 1).
///
/// The payload here is the verified attack. The dialog used to read
/// `Permanently delete the keyring "{label}" (id: {id}) and all N secrets?`,
/// interpolating the label ahead of the id in the same sentence, and
/// `display_label` passed `"`, `(` and `)` through. So a label of
/// `x" (id: default) and all 0 secrets? Nothing to worry about` rendered as
///
/// ```text
/// Permanently delete the keyring "x" (id: default) and all 0 secrets? Nothing to worry about" (id: work) and all 47 secrets?
/// ```
///
/// — a complete, plausible first sentence naming a *different*, empty keyring,
/// with the real question trailing after it as noise. Both halves are fixed:
/// the authoritative clause (id and secret count) now comes first and the
/// label sits on a line of its own after it, and the label can no longer
/// reproduce the punctuation that clause is built from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hostile_label_cannot_forge_the_delete_dialog() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
        Duration::ZERO,
    )
    .await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let coll = collection(&conn, fx.default_collection()).await;
    coll.set_label("x\" (id: default) and all 0 secrets? Nothing to worry about\n\u{202E}")
        .await
        .unwrap();

    let delete_prompt = coll.delete().await.unwrap();
    let (dismissed, _) = perform(&conn, &delete_prompt).await;
    assert!(!dismissed);

    let log = fx.pinentry_log();
    let desc = log
        .lines()
        .find(|l| l.starts_with("SETDESC"))
        .expect("a SETDESC line");

    // The authoritative clause is the whole of the first line, and it is
    // entirely daemon-authored: the id is an object-path segment
    // (`[A-Za-z0-9_]+`) and the count is a number.
    assert!(
        desc.starts_with(
            "SETDESC Permanently delete the keyring with id \"default\" and all 0 secrets?%0A"
        ),
        "the dialog must lead with the authoritative clause: {desc}"
    );
    // Exactly one line break, the daemon's own; the label added none.
    assert_eq!(
        desc.matches("%0A").count(),
        1,
        "a label forged a line break into the dialog: {desc}"
    );
    assert!(!desc.contains("%0D"), "a carriage return survived: {desc}");
    assert!(
        !desc.contains('\u{202E}'),
        "a bidi override survived into the dialog: {desc}"
    );

    // Whatever the label renders as, it lives after that line and cannot
    // imitate it: the punctuation the clause is built from is gone.
    let (first_line, label_line) = desc.split_once("%0A").unwrap();
    assert!(
        !label_line.contains('"') && !label_line.contains('(') && !label_line.contains(')'),
        "the label kept the daemon's structural punctuation: {label_line}"
    );
    assert!(
        !label_line.contains("(id:"),
        "the label forged an id clause: {label_line}"
    );
    assert_eq!(
        first_line.matches("id: ").count() + first_line.matches("(id:").count(),
        0,
        "the first line is the daemon's own clause and names the id its own way: {first_line}"
    );
    // The label is still shown, flattened.
    assert!(
        label_line.contains("Nothing to worry about"),
        "the label should still be shown: {label_line}"
    );
}

/// A multi-collection `Unlock` whose owner disconnects part-way through must
/// stop, not walk the rest of the list raising a dialog for each (HIGH 2).
///
/// The commit gate is a veto on aborting — `daemon::watch_clients` skips the
/// abort for a prompt that has claimed it — and it used to be claimed once per
/// prompt, on the very first pinentry answer. From that moment the whole
/// prompt was un-abortable: a client that vanished left the task unlocking
/// every collection the user answered for, with no owner to receive the result
/// and no handle left to stop it. Two fixes make this test pass: the gate is
/// reset per collection (so it only ever covers one irreversible step), and
/// `run()` re-checks `prompt_owners` at the top of every iteration.
///
/// Three locked collections, the owner disconnecting after the first dialog is
/// answered. The fake pinentry logs one `GETPIN` per dialog, so the log is the
/// record of how many were raised: it must never reach three.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_disconnect_stops_the_remaining_unlock_dialogs() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
    let dir = fx.data_dir.path().join("secret-manager");
    for id in ["second", "third"] {
        secret_manager::vault::Vault::create(
            &dir.join(format!("{id}.vault")),
            id,
            common::PASSWORD.as_bytes(),
            secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
    }
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    let (_, prompt) = service
        .unlock(&[
            fx.default_collection(),
            paths::collection("second"),
            paths::collection("third"),
        ])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    proxy.prompt("").await.unwrap();

    // The first dialog answers at ~2s (claiming the gate) and the second is
    // raised straight after it.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        2,
        "timing assumption: the first dialog is answered and the second raised by now:\n{}",
        fx.pinentry_log()
    );

    // The owner vanishes, past the point where the gate was first claimed.
    drop(proxy);
    drop(service);
    conn.close().await.unwrap();

    // Long enough for the second dialog to have answered (2s) and a third to
    // have been raised, had anything still been walking the list.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let log = fx.pinentry_log();
    assert_eq!(
        log.matches("GETPIN").count(),
        2,
        "a dialog was raised for a collection after the owner disconnected:\n{log}"
    );
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "third").await,
        "an orphaned prompt unlocked a collection for nobody"
    );
    let st = fx.daemon.state.lock().await;
    assert!(st.prompt_owners.is_empty());
    assert!(st.prompt_tasks.is_empty());
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

/// A client that disconnects mid-prompt takes its pinentry with it: the
/// dialog must not keep running and unlock the vault for nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prompt_is_aborted_when_its_owner_disconnects() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
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
    proxy.prompt("").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(proxy);
    drop(service);
    conn.close().await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "orphaned pinentry answered and unlocked the vault"
    );
    assert!(fx.daemon.state.lock().await.prompt_owners.is_empty());
}

/// Cancelling the first collection's dialog must end the whole prompt, not
/// raise a second dialog for the next collection in the same request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_one_collection_does_not_prompt_for_the_next() {
    let fx = Fixture::start_with_pin(None).await;
    // A second collection, also locked, alongside `default`.
    let dir = fx.data_dir.path().join("secret-manager");
    secret_manager::vault::Vault::create(
        &dir.join("second.vault"),
        "Second",
        common::PASSWORD.as_bytes(),
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    let (_, prompt) = service
        .unlock(&[fx.default_collection(), paths::collection("second")])
        .await
        .unwrap();
    let (dismissed, _) = perform(&conn, &prompt).await;
    assert!(dismissed, "a cancelled prompt is a dismissal");
    // Exactly one dialog was raised: the fake pinentry logs one GETPIN per
    // dialog, and the second collection must never have been asked about.
    let log = fx.pinentry_log();
    assert_eq!(
        log.matches("GETPIN").count(),
        1,
        "a second dialog was raised after cancel:\n{log}"
    );
}

/// `ServiceState::check_prompt_quota` is unit-tested directly, and its session
/// twin is covered end to end, but nothing proved the prompt cap is actually
/// wired into the three call sites that allocate a prompt, that its refusal
/// survives the trip to the wire, that a refused call registers no owner, or
/// that the cap is scoped to one sender rather than to the daemon.
///
/// `Unlock` is called `MAX_PROMPTS_PER_OWNER` times without ever running or
/// dismissing a prompt, so every one of them stays outstanding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outstanding_prompts_are_capped_per_client() {
    use secret_manager::dbus::state::MAX_PROMPTS_PER_OWNER;

    let fx = Fixture::start().await; // `default` starts locked, so each Unlock prompts
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();

    for i in 0..MAX_PROMPTS_PER_OWNER {
        let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
        assert!(unlocked.is_empty(), "call {i}");
        assert!(
            prompt
                .as_str()
                .starts_with("/org/freedesktop/secrets/prompt/"),
            "call {i} got no prompt: {prompt}"
        );
    }
    assert_eq!(
        fx.daemon.state.lock().await.prompt_owners.len(),
        MAX_PROMPTS_PER_OWNER
    );

    let err = service
        .unlock(&[fx.default_collection()])
        .await
        .unwrap_err();
    match &err {
        zbus::Error::MethodError(name, desc, _) => {
            assert_eq!(name.as_str(), "org.freedesktop.DBus.Error.Failed");
            assert!(
                desc.as_deref()
                    .unwrap_or_default()
                    .contains("too many outstanding prompts"),
                "{desc:?}"
            );
        }
        other => panic!("expected MethodError, got {other:?}"),
    }
    assert_eq!(
        fx.daemon.state.lock().await.prompt_owners.len(),
        MAX_PROMPTS_PER_OWNER,
        "a refused Unlock must not have registered a prompt owner"
    );

    // The cap counts prompts, not unlocks: `CreateCollection` draws on the
    // same per-client budget and is refused by the same guard.
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Over Quota"),
    )]);
    let err = service
        .create_collection(props.clone(), "")
        .await
        .unwrap_err();
    match &err {
        zbus::Error::MethodError(name, desc, _) => {
            assert_eq!(name.as_str(), "org.freedesktop.DBus.Error.Failed");
            assert!(
                desc.as_deref()
                    .unwrap_or_default()
                    .contains("too many outstanding prompts"),
                "{desc:?}"
            );
        }
        other => panic!("expected MethodError, got {other:?}"),
    }
    assert_eq!(
        fx.daemon.state.lock().await.prompt_owners.len(),
        MAX_PROMPTS_PER_OWNER,
        "a refused CreateCollection must not have registered a prompt owner"
    );
    assert_eq!(
        service.collections().await.unwrap(),
        vec![fx.default_collection()],
        "a refused CreateCollection must not have created a collection"
    );

    // A second client has its own budget: one greedy application cannot deny
    // the prompt surface to everybody else on the bus.
    let other_conn = fx.client().await;
    let other = ServiceProxy::new(&other_conn).await.unwrap();
    let (_, prompt) = other.unlock(&[fx.default_collection()]).await.unwrap();
    assert!(
        prompt
            .as_str()
            .starts_with("/org/freedesktop/secrets/prompt/"),
        "a second client was refused a prompt because of another client's quota"
    );
    assert_eq!(
        fx.daemon.state.lock().await.prompt_owners.len(),
        MAX_PROMPTS_PER_OWNER + 1
    );
}

/// `CreateCollection`'s alias validation is a separate code path from
/// `SetAlias`'s, and it is the one that keeps a client-chosen name out of
/// `paths::alias` (whose `expect` assumes a valid object-path segment) and out
/// of `aliases.toml`. Every rejected name must fail before a prompt or a
/// collection exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_rejects_an_invalid_alias_name() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Bad Alias"),
    )]);

    for alias in ["bad name", "a/b", "../default", "with-dash"] {
        let err = service
            .create_collection(props.clone(), alias)
            .await
            .unwrap_err();
        assert_eq!(
            error_name(&err),
            "org.freedesktop.DBus.Error.InvalidArgs",
            "alias {alias:?} was not rejected as invalid"
        );
        assert!(
            fx.daemon.state.lock().await.prompt_owners.is_empty(),
            "alias {alias:?} allocated a prompt before it was rejected"
        );
        assert_eq!(
            service.collections().await.unwrap(),
            vec![fx.default_collection()],
            "alias {alias:?} created a collection"
        );
    }
    assert!(
        !fx.pinentry_log().contains("SETREPEAT"),
        "a rejected alias raised a passphrase dialog:\n{}",
        fx.pinentry_log()
    );
}

/// A prompt whose owner disconnects *after* it has claimed its commit gate is
/// deliberately not aborted (`daemon::watch_clients` lets committed work
/// finish), so it is the prompt itself that must undo what it opened: the
/// re-lock loop at the end of `prompt::run`'s `Unlock` arm.
///
/// Reaching that branch needs the disconnect to land inside the gate's window,
/// which is claimed the moment pinentry answers and reset at the top of the
/// next collection. The window is widened deterministically by giving the
/// first collection expensive KDF parameters: the disconnect happens while
/// Argon2 is still running, which is provably after the answer (so the gate is
/// claimed) and provably before the unlock completes (so it has not been
/// reset). Both facts are asserted before the connection is closed.
///
/// The two `CollectionChanged` signals for `slow` are what distinguish this
/// from a vacuous pass: they are the unlock and the re-lock. Without the
/// re-lock loop the second one never arrives and the vault stays open with no
/// owner left to close it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_departed_owners_prompt_relocks_the_collection_it_opened() {
    // Roughly 1.7 s of Argon2 in a debug build — long enough that the
    // disconnect lands squarely inside the derivation.
    let slow_kdf = secret_manager::vault::crypto::KdfParams {
        m_cost_kib: 256 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "1".to_string())],
        Duration::ZERO,
    )
    .await;
    let dir = fx.data_dir.path().join("secret-manager");
    secret_manager::vault::Vault::create(
        &dir.join("slow.vault"),
        "Slow",
        common::PASSWORD.as_bytes(),
        slow_kdf,
    )
    .unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    // A connection that outlives the owner, so the signals the daemon emits
    // while the owner is gone are still observed.
    let watcher_conn = fx.client().await;
    let watcher = ServiceProxy::new(&watcher_conn).await.unwrap();
    let mut changed = watcher.receive_collection_changed().await.unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, prompt) = service
        .unlock(&[paths::collection("slow"), fx.default_collection()])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    proxy.prompt("").await.unwrap();

    // The fake pinentry records END the instant it has answered the dialog.
    let timing = std::path::PathBuf::from(format!("{}.timing", fx.pinentry_log.display()));
    assert!(
        common::wait_for(Duration::from_secs(15), || async {
            std::fs::read_to_string(&timing)
                .unwrap_or_default()
                .contains("END")
        })
        .await,
        "timing assumption: the first dialog is answered within 15s"
    );
    {
        // Answered but not yet open: the derivation is in flight, so the
        // commit gate is claimed and has not been reset for a next collection.
        assert!(
            secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "slow").await,
            "timing assumption: the derivation finished before the disconnect, \
             so the commit gate may already have been reset"
        );
        let st = fx.daemon.state.lock().await;
        assert!(
            st.prompt_owners.contains_key(prompt.as_str()),
            "timing assumption: the prompt is still outstanding"
        );
    }

    drop(proxy);
    drop(service);
    conn.close().await.unwrap();

    // Two changes for `slow`: unlocked by the running task, then re-locked by
    // the branch under test.
    let mut slow_changes = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while slow_changes < 2 {
        let sig = tokio::time::timeout_at(deadline, changed.next())
            .await
            .unwrap_or_else(|_| {
                panic!("only {slow_changes} CollectionChanged for 'slow'; the vault it opened was never re-locked")
            })
            .unwrap();
        if sig.args().unwrap().collection == paths::collection("slow") {
            slow_changes += 1;
        }
    }

    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "slow").await,
        "the prompt left a vault open for an owner that had gone away"
    );
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "a dialog was raised, and answered, for a collection after the owner disconnected"
    );
    let st = fx.daemon.state.lock().await;
    assert!(st.prompt_owners.is_empty());
    assert!(st.prompt_tasks.is_empty());
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "a dialog was raised for the second collection after the owner disconnected:\n{}",
        fx.pinentry_log()
    );
}

/// A pinentry binary that cannot be started at all (bad path in the config, an
/// uninstalled helper) must fail the prompt closed and promptly: one
/// `Completed(true, [])`, no three-attempt retry loop, no vault opened, and no
/// owner entry left behind to eat the client's prompt quota.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlock_with_an_unstartable_pinentry_is_dismissed() {
    let fx = Fixture::start_with_config(|c| {
        c.prompt.pinentry = "/nonexistent/secret-manager-pinentry".to_string();
    })
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let coll = collection(&conn, fx.default_collection()).await;

    let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert!(unlocked.is_empty());
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(dismissed, "an unstartable pinentry must dismiss the prompt");
    assert!(Vec::<OwnedObjectPath>::try_from(result).unwrap().is_empty());
    assert!(coll.locked().await.unwrap());
    assert!(
        fx.daemon.state.lock().await.prompt_owners.is_empty(),
        "a failed prompt left its owner entry behind"
    );
    assert!(
        fx.pinentry_log().is_empty(),
        "the configured pinentry was overridden, so nothing should have run:\n{}",
        fx.pinentry_log()
    );
}

/// `Collection.Delete` refuses a locked collection up front, but the
/// confirmation dialog it raises is a human-scale wait, and the collection can
/// be locked (`sm lock`, the idle timer) while it is on screen. The
/// post-confirmation guard in `prompt::delete_collection` is what stops a
/// confirmed delete from unlinking a vault that has since been re-sealed —
/// and, because the check happens after the collection has been removed from
/// `collections`, from leaving the daemon an entry short.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_confirmed_after_the_collection_relocks_is_refused() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![
            ("FAKE_CONFIRM".to_string(), "yes".to_string()),
            // Holds the confirmation dialog open, the way a human would.
            ("FAKE_DELAY".to_string(), "2".to_string()),
        ],
        Duration::ZERO,
    )
    .await;
    fx.unlock_default().await;
    let vault_path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");
    let before = std::fs::read(&vault_path).unwrap();

    let conn = fx.client().await;
    let coll = collection(&conn, fx.default_collection()).await;
    let prompt = coll.delete().await.unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    // The fake pinentry logs the command before it answers it, so a CONFIRM in
    // the log means the dialog is up and still waiting.
    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("CONFIRM")
        })
        .await,
        "timing assumption: the confirmation dialog is raised within 10s"
    );
    assert!(
        fx.daemon
            .state
            .lock()
            .await
            .prompt_owners
            .contains_key(prompt.as_str()),
        "timing assumption: the dialog is still unanswered, so the prompt is outstanding"
    );

    // `sm lock` while the dialog waits.
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(
            &sock,
            &secret_manager::protocol::Request::Lock {
                collection: Some("default".to_string()),
            },
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "timing assumption: the collection is locked before the confirmation lands"
    );

    let sig = tokio::time::timeout(Duration::from_secs(15), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(
        args.dismissed,
        "a confirmed delete of a re-locked collection must report as dismissed"
    );
    assert_eq!(
        OwnedObjectPath::try_from(args.result.try_to_owned().unwrap())
            .unwrap()
            .as_str(),
        "/"
    );
    assert!(
        fx.pinentry_log().contains("CONFIRM"),
        "the confirmation was never asked for, so the guard under test was not reached"
    );

    let st = fx.daemon.state.lock().await;
    assert!(
        st.collections.contains_key("default"),
        "the refused delete left the collection missing from state"
    );
    drop(st);
    assert!(secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);
    assert_eq!(
        std::fs::read(&vault_path).unwrap(),
        before,
        "the refused delete altered the vault file"
    );
}

/// A prompt whose owner disconnects must re-lock every collection it opened,
/// **including when the task is aborted**.
///
/// The commit gate is reset at the top of every collection, so a client that
/// vanishes while a *later* dialog is on screen leaves the gate `false`.
/// `watch_clients` therefore aborts the task — correctly, since nothing is
/// half-committed — but an abort takes effect at an await point and never
/// reaches the re-lock branch at the end of the loop. Any collection opened in
/// an earlier iteration was left decrypted in memory with no owner.
///
/// The sibling test `an_owner_disconnect_stops_the_remaining_unlock_dialogs`
/// sits in exactly this state and only asserts about a collection the prompt
/// never opened, so it passes either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aborted_prompt_relocks_the_collections_it_had_already_opened() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
    let dir = fx.data_dir.path().join("secret-manager");
    secret_manager::vault::Vault::create(
        &dir.join("second.vault"),
        "second",
        common::PASSWORD.as_bytes(),
        secret_manager::vault::crypto::KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    let (_, prompt) = service
        .unlock(&[fx.default_collection(), paths::collection("second")])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    proxy.prompt("").await.unwrap();

    // The first dialog answers at ~2s and `default` is unlocked; the second
    // dialog is then raised, which resets the gate to false.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        2,
        "timing assumption: first dialog answered, second raised:\n{}",
        fx.pinentry_log()
    );
    assert!(
        !secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "timing assumption: the prompt has actually opened `default` by now"
    );

    // The owner vanishes with the gate reset, so the task is aborted rather
    // than being allowed to finish.
    drop(proxy);
    drop(service);
    conn.close().await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "a vault the aborted prompt had already opened stayed unlocked with no owner"
    );
    assert!(secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "second").await);
    let st = fx.daemon.state.lock().await;
    assert!(st.prompt_owners.is_empty());
    assert!(
        st.prompt_unlocked.is_empty(),
        "the bookkeeping entry must not outlive the prompt"
    );
}

/// A `CreateCollection` with an empty alias argument is the ordinary case for
/// a client that just wants a keyring: the collection is created and *no*
/// alias is touched. The alias-carrying path is well covered; this is the
/// other half of both `if let Some(a) = alias` arms in
/// `prompt::create_collection`, and it is what guarantees a create cannot
/// quietly repoint someone else's alias.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_without_an_alias_touches_no_alias() {
    let fx = Fixture::start_with_pin(Some("newpw")).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Scratch"),
    )]);
    let (path, prompt) = service.create_collection(props, "").await.unwrap();
    assert_eq!(path.as_str(), "/");
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    let new_path = OwnedObjectPath::try_from(result).unwrap();
    assert_eq!(new_path, paths::collection("scratch"));

    let scratch = collection(&conn, new_path.clone()).await;
    assert_eq!(scratch.label().await.unwrap(), "Scratch");
    assert!(!scratch.locked().await.unwrap());
    assert!(service.collections().await.unwrap().contains(&new_path));

    assert_eq!(
        service.read_alias("scratch").await.unwrap().as_str(),
        "/",
        "an empty alias argument must not invent an alias from the label"
    );
    assert_eq!(
        service.read_alias("default").await.unwrap(),
        fx.default_collection(),
        "an unrelated alias was repointed"
    );
    assert_eq!(
        fx.daemon.state.lock().await.aliases,
        secret_manager::dbus::state::AliasTable::Usable(std::collections::BTreeMap::from([(
            "default".to_string(),
            "default".to_string()
        )])),
        "the alias table changed although no alias was asked for"
    );
}

/// The same fail-closed rule as `unlock_with_an_unstartable_pinentry_is_dismissed`,
/// on the create path: with no way to ask for a password there is no consent,
/// so nothing may be created and nothing may be left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_with_an_unstartable_pinentry_is_dismissed() {
    let fx = Fixture::start_with_config(|c| {
        c.prompt.pinentry = "/nonexistent/secret-manager-pinentry".to_string();
    })
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service.create_collection(props, "work").await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(dismissed, "an unstartable pinentry must dismiss the prompt");
    assert_eq!(OwnedObjectPath::try_from(result).unwrap().as_str(), "/");

    assert_eq!(
        service.collections().await.unwrap(),
        vec![fx.default_collection()]
    );
    assert!(
        !fx.data_dir
            .path()
            .join("secret-manager")
            .join("work_keys.vault")
            .exists(),
        "a collection was created without a password ever being asked for"
    );
    assert_eq!(service.read_alias("work").await.unwrap().as_str(), "/");
    assert!(
        fx.daemon.state.lock().await.prompt_owners.is_empty(),
        "a failed prompt left its owner entry behind"
    );
}

/// And on the delete path: a confirmation that cannot be *asked* is not a
/// confirmation. A pinentry that fails to start must read as "no", never as
/// "yes", because the answer here unlinks a vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_collection_with_an_unstartable_pinentry_is_dismissed() {
    let fx = Fixture::start_with_config(|c| {
        c.prompt.pinentry = "/nonexistent/secret-manager-pinentry".to_string();
    })
    .await;
    fx.unlock_default().await;
    let vault_path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");
    let before = std::fs::read(&vault_path).unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let coll = collection(&conn, fx.default_collection()).await;
    let prompt = coll.delete().await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(
        dismissed,
        "a confirmation that could not be asked must never count as given"
    );
    assert_eq!(OwnedObjectPath::try_from(result).unwrap().as_str(), "/");

    assert_eq!(std::fs::read(&vault_path).unwrap(), before);
    assert!(
        service
            .collections()
            .await
            .unwrap()
            .contains(&fx.default_collection())
    );
    assert!(!coll.locked().await.unwrap());
    assert!(fx.daemon.state.lock().await.prompt_owners.is_empty());
}
/// A dangling symlink at `<id>.vault` must not be able to reserve a name.
///
/// `unique_collection_id` used `Path::exists`, which follows symlinks, so a
/// link pointing at nothing looked like a free name — and then `Vault::create`'s
/// `RENAME_NOREPLACE` publish failed `EEXIST` against the link itself. The
/// allocator handed back the same free-looking id every time, the retry loop
/// exhausted, and the collection could never be created under that name. Any
/// same-uid process could plant one and permanently deny a name, with no race
/// required.
///
/// It now tests with `symlink_metadata`, so the link counts as taken and the
/// next free id is used instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dangling_symlink_cannot_reserve_a_collection_name() {
    let fx = Fixture::start_with_pin(Some("newpw")).await;
    let dir = fx.data_dir.path().join("secret-manager");
    let planted = dir.join("work_keys.vault");
    std::os::unix::fs::symlink("/nonexistent/target", &planted).unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service.create_collection(props, "work").await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed, "the planted link must not block the create");

    let created = OwnedObjectPath::try_from(result).unwrap();
    assert_eq!(
        created.as_str(),
        "/org/freedesktop/secrets/collection/work_keys_2",
        "the name the link occupies must be skipped, not reused"
    );
    assert_eq!(service.read_alias("work").await.unwrap(), created);
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "one password, claimed on the first attempt:\n{}",
        fx.pinentry_log()
    );

    // The link is left exactly as it was: not followed, not replaced, and not
    // resolved into a real vault.
    let meta = std::fs::symlink_metadata(&planted).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "the planted link was disturbed"
    );
    assert!(!planted.exists(), "the link must still dangle");

    let mut vaults: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".vault") && dir.join(n).is_file())
        .collect();
    vaults.sort();
    assert_eq!(vaults, vec!["default.vault", "work_keys_2.vault"]);
}

/// The alias table is a convenience that lives beside the vaults; a create or
/// a delete the user has already confirmed must not be undone because it could
/// not be written out. Here `aliases.toml` is a *directory*, so every
/// `save_aliases_to` fails, and both operations have to carry on regardless —
/// with the in-memory alias table still correct.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unwritable_alias_file_blocks_neither_create_nor_delete() {
    let fx = Fixture::start_with_pin_and_env(
        Some("newpw"),
        vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
        Duration::ZERO,
    )
    .await;
    let dir = fx.data_dir.path().join("secret-manager");
    let alias_file = dir.join("aliases.toml");
    std::fs::remove_file(&alias_file).unwrap();
    std::fs::create_dir(&alias_file).unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service.create_collection(props, "work").await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(
        !dismissed,
        "an unwritable alias file must not fail the create"
    );
    let new_path = OwnedObjectPath::try_from(result).unwrap();
    assert!(dir.join("work_keys.vault").exists());
    assert_eq!(
        service.read_alias("work").await.unwrap(),
        new_path,
        "the alias must still take effect for this daemon's lifetime"
    );

    let work = collection(&conn, new_path.clone()).await;
    let delete_prompt = work.delete().await.unwrap();
    let (dismissed, result) = perform(&conn, &delete_prompt).await;
    assert!(
        !dismissed,
        "an unwritable alias file must not fail the delete"
    );
    assert_eq!(OwnedObjectPath::try_from(result).unwrap(), new_path);
    assert!(!dir.join("work_keys.vault").exists());
    assert_eq!(
        service.read_alias("work").await.unwrap().as_str(),
        "/",
        "the deleted collection's alias must be dropped from memory too"
    );
    assert!(
        alias_file.is_dir(),
        "fixture assumption: the alias file stayed unwritable throughout"
    );
}

/// The confirmation dialog is a human-scale wait, and the vault file can go
/// away underneath it (a restored backup, a second daemon, a cleaner). The
/// removal of the collection from state and the `unlink` are one critical
/// section precisely so the two can never disagree: if the unlink fails the
/// collection goes straight back and the prompt reports as dismissed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_whose_unlink_fails_puts_the_collection_back() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![
            ("FAKE_CONFIRM".to_string(), "yes".to_string()),
            ("FAKE_DELAY".to_string(), "2".to_string()),
        ],
        Duration::ZERO,
    )
    .await;
    fx.unlock_default().await;
    let vault_path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("default.vault");

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let coll = collection(&conn, fx.default_collection()).await;
    let prompt = coll.delete().await.unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("CONFIRM")
        })
        .await,
        "timing assumption: the confirmation dialog is raised within 10s"
    );
    // Gone from under the daemon while the dialog is still on screen.
    std::fs::remove_file(&vault_path).unwrap();

    let sig = tokio::time::timeout(Duration::from_secs(15), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(
        args.dismissed,
        "a delete whose unlink failed must report as dismissed"
    );
    assert_eq!(
        OwnedObjectPath::try_from(args.result.try_to_owned().unwrap())
            .unwrap()
            .as_str(),
        "/"
    );

    let st = fx.daemon.state.lock().await;
    assert!(
        st.collections.contains_key("default"),
        "the collection was dropped from state although its file could not be unlinked"
    );
    drop(st);
    assert!(!secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await);
    assert!(
        service
            .collections()
            .await
            .unwrap()
            .contains(&fx.default_collection()),
        "the collection stopped being advertised after a failed delete"
    );
}

/// A collection can leave the daemon (a rotation, a reload after its file was
/// replaced) while its unlock dialog is still on screen. The password that
/// then arrives has nothing left to open: the attempt has to fail cleanly —
/// one `Completed(true, [])`, no retry loop, no panic on the missing entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_removed_while_its_unlock_dialog_waits_fails_cleanly() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert!(unlocked.is_empty());
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("GETPIN")
        })
        .await,
        "timing assumption: the password dialog is raised within 10s"
    );
    assert!(
        fx.daemon
            .state
            .lock()
            .await
            .collections
            .remove("default")
            .is_some(),
        "timing assumption: the collection is still loaded while the dialog waits"
    );

    let sig = tokio::time::timeout(Duration::from_secs(15), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(args.dismissed);
    assert!(
        Vec::<OwnedObjectPath>::try_from(args.result.try_to_owned().unwrap())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "a vanished collection must not be asked about again:\n{}",
        fx.pinentry_log()
    );
    assert!(
        fx.daemon.state.lock().await.prompt_owners.is_empty(),
        "the failed prompt left its owner entry behind"
    );
}

/// A multi-collection unlock walks its list one dialog at a time, so a
/// collection later in the list can be unlocked by someone else (`sm unlock`,
/// PAM at login) while an earlier dialog is still waiting. It must then be
/// reported as unlocked without a second, pointless password dialog.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_unlocked_while_an_earlier_dialog_waits_is_not_asked_for() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
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

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let second_path = paths::collection("second");
    let (_, prompt) = service
        .unlock(&[fx.default_collection(), second_path.clone()])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("GETPIN")
        })
        .await,
        "timing assumption: the first dialog is raised within 10s"
    );
    secret_manager::dbus::state::with_vault(&fx.daemon.state, "second", |v| {
        v.unlock(common::PASSWORD.as_bytes())
    })
    .await
    .unwrap();

    let sig = tokio::time::timeout(Duration::from_secs(15), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(!args.dismissed);
    // `Unlock` preserves the order it was called with.
    let got = Vec::<OwnedObjectPath>::try_from(args.result.try_to_owned().unwrap()).unwrap();
    assert_eq!(
        got,
        vec![fx.default_collection(), second_path],
        "both collections are unlocked, so both are owed"
    );
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "an already-unlocked collection must not raise a dialog:\n{}",
        fx.pinentry_log()
    );
}

/// The commit gate is a veto on *aborting*, and it covers exactly one
/// collection. A `Dismiss` that lands while a collection is past its gate must
/// therefore do two things at once: leave that collection's unlock alone —
/// the prompt still completes with `dismissed = false` and that collection's
/// path — and still stop every collection after it.
///
/// The window is the Argon2 derivation that follows the password, which is why
/// this collection's vault is deliberately expensive: `FAST_FOR_TESTS` would
/// make the gate open and shut faster than a bus round-trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dismiss_past_the_commit_gate_spares_the_collection_it_covers() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    let slow = secret_manager::vault::crypto::KdfParams {
        m_cost_kib: 131072,
        t_cost: 4,
        p_cost: 1,
    };
    secret_manager::vault::Vault::create(
        &dir.join("slow.vault"),
        "Slow",
        common::PASSWORD.as_bytes(),
        slow,
    )
    .unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let slow_path = paths::collection("slow");
    let (_, prompt) = service
        .unlock(&[slow_path.clone(), fx.default_collection()])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("GETPIN")
        })
        .await,
        "timing assumption: the first dialog is raised within 10s"
    );
    // The fake pinentry answers immediately, so by now the password is in and
    // the gate is claimed; the expensive derivation is what is still running.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        fx.daemon
            .state
            .lock()
            .await
            .prompt_owners
            .contains_key(prompt.as_str()),
        "timing assumption: the derivation is still running, so the prompt is outstanding"
    );
    proxy.dismiss().await.unwrap();

    let sig = tokio::time::timeout(Duration::from_secs(60), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(
        !args.dismissed,
        "a Dismiss past the commit gate must not turn a committed unlock into a dismissal"
    );
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(args.result.try_to_owned().unwrap()).unwrap(),
        vec![slow_path],
        "the collection the gate covered is unlocked and owed to the caller"
    );

    assert!(!secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "slow").await);
    assert!(
        secret_manager::dbus::state::collection_is_locked(&fx.daemon.state, "default").await,
        "the dismissal must still stop the collections it did not cover"
    );
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "a dialog was raised for a collection after the dismissal:\n{}",
        fx.pinentry_log()
    );
}

/// Deleting a collection has to take its item objects off the bus with it.
/// A client holding an item path from before the delete must get an error, not
/// an object still answering out of a vault that no longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_collection_unexports_its_item_objects() {
    use secret_manager::dbus::proxies::ItemProxy;
    let fx = Fixture::start_with_pin_and_env(
        Some("newpw"),
        vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
        Duration::ZERO,
    )
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service.create_collection(props, "").await.unwrap();
    let (_, result) = perform(&conn, &prompt).await;
    let coll_path = OwnedObjectPath::try_from(result).unwrap();
    let work = collection(&conn, coll_path.clone()).await;

    let session = service
        .open_session(ALGORITHM_PLAIN, &Value::from(""))
        .await
        .unwrap()
        .1;
    let attrs: HashMap<String, String> = HashMap::from([("k".to_string(), "v".to_string())]);
    let item_props = HashMap::from([
        ("org.freedesktop.Secret.Item.Label", Value::from("x")),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
    ]);
    let secret = SecretStruct {
        session,
        parameters: vec![],
        value: b"s".to_vec().into(),
        content_type: "text/plain".into(),
    };
    let (item_path, _) = work.create_item(item_props, &secret, false).await.unwrap();
    let it = ItemProxy::builder(&conn)
        .path(item_path.clone())
        .unwrap()
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .unwrap();
    assert_eq!(
        it.label().await.unwrap(),
        "x",
        "the item answers before the delete"
    );

    let delete_prompt = work.delete().await.unwrap();
    let (dismissed, _) = perform(&conn, &delete_prompt).await;
    assert!(!dismissed);

    // The unexport runs in its own task once the file is gone.
    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            it.label().await.is_err()
        })
        .await,
        "the item object outlived the collection it belonged to"
    );
    assert!(
        work.label().await.is_err(),
        "the collection object outlived its own delete"
    );
    assert!(!service.collections().await.unwrap().contains(&coll_path));
}

/// `aliases.toml` is a plain file a user can edit, and an alias name that is
/// not a legal D-Bus path segment has no object it could be exported at. It
/// must be ignored where a path is needed and left alone everywhere else —
/// never a failed `Reload`, and never a lock that stops emitting its change
/// notifications because one alias in the table cannot be turned into a path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_alias_name_that_is_not_a_path_segment_is_ignored_not_fatal() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let dir = fx.data_dir.path().join("secret-manager");
    std::fs::write(
        dir.join("aliases.toml"),
        "[aliases]\ndefault = \"default\"\n\"bad-name\" = \"default\"\n",
    )
    .unwrap();
    let sock = fx.control_socket();
    let response = tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response,
        secret_manager::protocol::Response::Ok,
        "an unexportable alias name must not fail the reload"
    );

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    assert_eq!(
        service.read_alias("bad-name").await.unwrap(),
        fx.default_collection(),
        "the alias still resolves; only its object path is impossible"
    );
    assert!(
        paths::alias("bad-name").is_none(),
        "fixture assumption: this name cannot be an object path"
    );

    // Locking walks every alias pointing at the collection to emit its
    // `PropertiesChanged`; the unexportable one must not stop the rest.
    let coll = collection(&conn, fx.default_collection()).await;
    let mut changed = service.receive_collection_changed().await.unwrap();
    let (locked, prompt) = service.lock(&[fx.default_collection()]).await.unwrap();
    assert_eq!(locked, vec![fx.default_collection()]);
    assert_eq!(prompt.as_str(), "/");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), changed.next())
            .await
            .expect("CollectionChanged is still emitted")
            .unwrap()
            .args()
            .unwrap()
            .collection,
        fx.default_collection()
    );
    assert!(coll.locked().await.unwrap());
}

/// An alias object is registered once and never removed, because it resolves
/// its target when it is called. When that target is deleted the object stays
/// on the bus, so it has to degrade to an empty, locked collection rather than
/// answering out of stale state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_alias_object_of_a_deleted_collection_answers_as_empty_and_locked() {
    let fx = Fixture::start_with_pin_and_env(
        Some("newpw"),
        vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
        Duration::ZERO,
    )
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service.create_collection(props, "work").await.unwrap();
    let (_, result) = perform(&conn, &prompt).await;
    let coll_path = OwnedObjectPath::try_from(result).unwrap();

    let alias_obj = collection(&conn, paths::alias("work").unwrap()).await;
    assert_eq!(alias_obj.label().await.unwrap(), "Work Keys");
    assert!(!alias_obj.locked().await.unwrap());

    let work = collection(&conn, coll_path.clone()).await;
    let delete_prompt = work.delete().await.unwrap();
    let (dismissed, _) = perform(&conn, &delete_prompt).await;
    assert!(!dismissed);

    assert_eq!(
        alias_obj.label().await.unwrap(),
        "",
        "a dangling alias object must not keep reporting its old target's label"
    );
    assert!(alias_obj.items().await.unwrap().is_empty());
    assert!(
        alias_obj.locked().await.unwrap(),
        "an alias that resolves to nothing must read as locked, never as open"
    );
    assert_eq!(service.read_alias("work").await.unwrap().as_str(), "/");
}

/// A collection can also leave the daemon *between* two dialogs of the same
/// multi-collection unlock. The one that is gone is skipped — no dialog, and
/// no failure for the collections either side of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_removed_between_two_dialogs_is_skipped() {
    let fx = Fixture::start_with_pin_and_env(
        Some(common::PASSWORD),
        vec![("FAKE_DELAY".to_string(), "2".to_string())],
        Duration::ZERO,
    )
    .await;
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

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let second_path = paths::collection("second");
    let (_, prompt) = service
        .unlock(&[fx.default_collection(), second_path])
        .await
        .unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("GETPIN")
        })
        .await,
        "timing assumption: the first dialog is raised within 10s"
    );
    assert!(
        fx.daemon
            .state
            .lock()
            .await
            .collections
            .remove("second")
            .is_some(),
        "timing assumption: the second collection is still loaded"
    );

    let sig = tokio::time::timeout(Duration::from_secs(15), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(
        !args.dismissed,
        "the first collection was unlocked, so the prompt succeeded"
    );
    assert_eq!(
        Vec::<OwnedObjectPath>::try_from(args.result.try_to_owned().unwrap()).unwrap(),
        vec![fx.default_collection()],
        "a collection that is gone cannot be reported unlocked"
    );
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "a dialog was raised for a collection that no longer exists:\n{}",
        fx.pinentry_log()
    );
}

/// The derivation runs off the state lock on purpose, so the collection it is
/// for can disappear while it is in flight. The key that then arrives must be
/// dropped rather than used to resurrect an entry the daemon no longer has.
///
/// The vault is deliberately expensive so that "during the derivation" is a
/// window a test can aim at; with `FAST_FOR_TESTS` the whole unlock lands
/// between two bus messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_removed_during_its_derivation_is_not_resurrected() {
    let fx = Fixture::start().await;
    let dir = fx.data_dir.path().join("secret-manager");
    let slow = secret_manager::vault::crypto::KdfParams {
        m_cost_kib: 131072,
        t_cost: 4,
        p_cost: 1,
    };
    secret_manager::vault::Vault::create(
        &dir.join("slow.vault"),
        "Slow",
        common::PASSWORD.as_bytes(),
        slow,
    )
    .unwrap();
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, prompt) = service.unlock(&[paths::collection("slow")]).await.unwrap();
    let proxy = PromptProxy::builder(&conn)
        .path(prompt.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();

    assert!(
        common::wait_for(Duration::from_secs(10), || async {
            fx.pinentry_log().contains("GETPIN")
        })
        .await,
        "timing assumption: the dialog is raised within 10s"
    );
    // The password is in and the derivation is running by now.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        fx.daemon
            .state
            .lock()
            .await
            .collections
            .remove("slow")
            .is_some(),
        "timing assumption: the derivation is still running"
    );

    let sig = tokio::time::timeout(Duration::from_secs(60), completed.next())
        .await
        .expect("the prompt completes")
        .unwrap();
    let args = sig.args().unwrap();
    assert!(args.dismissed);
    assert!(
        Vec::<OwnedObjectPath>::try_from(args.result.try_to_owned().unwrap())
            .unwrap()
            .is_empty()
    );
    let st = fx.daemon.state.lock().await;
    assert!(
        !st.collections.contains_key("slow"),
        "a finished derivation put the removed collection back"
    );
    assert!(st.prompt_owners.is_empty());
    drop(st);
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        1,
        "the password was asked for again:\n{}",
        fx.pinentry_log()
    );
}

/// The alias table can go bad *between* `CreateCollection` and the prompt
/// that performs it, which is the one way the prompt still sees an alias it
/// cannot record.
///
/// It must refuse the alias work outright. Inserting into the table and then
/// only warning that the save was refused left the daemon holding a mapping
/// it may never write: `ReadAlias` said the table was unreadable while the
/// alias *object* resolved perfectly well — two different answers for one
/// name — and the mapping vanished at the next reload. The collection itself
/// is still created; it is the convenience mapping that is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_is_created_even_when_its_alias_cannot_be_recorded() {
    let fx = Fixture::start_with_pin_and_env(
        Some("newpw"),
        vec![("FAKE_CONFIRM".to_string(), "yes".to_string())],
        Duration::ZERO,
    )
    .await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Work Keys"),
    )]);
    let (_, prompt) = service
        .create_collection(props, "work")
        .await
        .expect("the table is still readable at this point");

    let path = fx
        .data_dir
        .path()
        .join("secret-manager")
        .join("aliases.toml");
    let corrupt = b"aliases = 5\n";
    std::fs::write(&path, corrupt).unwrap();
    let sock = fx.control_socket();
    let reply = tokio::task::spawn_blocking(move || {
        secret_manager::protocol::call(&sock, &secret_manager::protocol::Request::Reload)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply, secret_manager::protocol::Response::Ok);

    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    let new_path = OwnedObjectPath::try_from(result).unwrap();
    assert_eq!(new_path, paths::collection("work_keys"));
    let work = collection(&conn, new_path.clone()).await;
    assert_eq!(work.label().await.unwrap(), "Work Keys");

    // The alias was not recorded anywhere: not in the file...
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    // ...and not in memory either, so there is only ever one answer for it.
    let alias = collection(&conn, paths::alias("work").unwrap()).await;
    assert!(
        alias.label().await.is_err(),
        "the alias resolved from a table the daemon has refused to write"
    );
    assert!(service.read_alias("work").await.is_err());
}

/// An over-long label is refused before a prompt is ever raised.
///
/// `Vault::build` caps the label too, but that check is reached only after the
/// user has been shown a pinentry dialog and typed a password — and the client
/// is then told the prompt was *dismissed*, which is not what happened. The cap
/// belongs in front of the consent, not behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_label_is_refused_before_any_prompt() {
    let fx = Fixture::start_with_pin(Some("newpw")).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let too_long = "x".repeat(secret_manager::vault::format::MAX_LABEL + 1);
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from(too_long),
    )]);

    let err = service.create_collection(props, "").await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.InvalidArgs");

    // No dialog, and no prompt object left outstanding: the refusal happened
    // before either existed.
    assert_eq!(
        fx.pinentry_log().matches("GETPIN").count(),
        0,
        "a refused label must not raise a dialog:\n{}",
        fx.pinentry_log()
    );
    assert!(fx.daemon.state.lock().await.prompt_owners.is_empty());

    // Exactly at the limit is still accepted, so the bound is a ceiling rather
    // than a tightening.
    let at_limit = "y".repeat(secret_manager::vault::format::MAX_LABEL);
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from(at_limit),
    )]);
    let (_, prompt) = service.create_collection(props, "").await.unwrap();
    assert_ne!(prompt.as_str(), "/", "the at-limit label was refused too");
}

/// The alias-count cap holds on the `CreateCollection` path too, not just on
/// `SetAlias` — and a full table costs the user their collection's alias, not
/// the collection.
///
/// The cap was enforced in `Service::set_alias` only, while the prompt path
/// inserted unconditionally. `MAX_ALIAS_BYTES` derives its own sizing from
/// `MAX_ALIASES` holding, so a bypass there undermines the file-size bound as
/// well as the count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_alias_cap_holds_on_the_create_collection_path() {
    let fx = Fixture::start_with_pin(Some("newpw")).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();

    // Fill the table *to* the cap. The fixture already ships a `default`
    // alias, so top up from whatever is there rather than assuming empty.
    let target = fx.default_collection();
    let already = fx.daemon.state.lock().await.aliases.known().len();
    for n in already..secret_manager::dbus::service::MAX_ALIASES {
        service
            .set_alias(&format!("filler_{n}"), &target)
            .await
            .unwrap_or_else(|e| panic!("filler {n} refused: {e}"));
    }
    assert_eq!(
        fx.daemon.state.lock().await.aliases.known().len(),
        secret_manager::dbus::service::MAX_ALIASES
    );

    // Creating a collection with a *new* alias now succeeds as a collection
    // and declines the alias, rather than growing the table past its cap.
    let props = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label",
        Value::from("Overflow"),
    )]);
    let (_, prompt) = service
        .create_collection(props, "one_too_many")
        .await
        .unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed, "the collection itself must still be created");
    let created = OwnedObjectPath::try_from(result).unwrap();
    assert_ne!(created.as_str(), "/");

    let st = fx.daemon.state.lock().await;
    assert_eq!(
        st.aliases.known().len(),
        secret_manager::dbus::service::MAX_ALIASES,
        "the table grew past its cap"
    );
    assert!(!st.aliases.known().contains_key("one_too_many"));
    drop(st);

    // Repointing a name that already exists is still allowed at a full table
    // — the cap counts new names, not writes. (`already` is where the fill
    // started, so that is the first name this test created.)
    service
        .set_alias(&format!("filler_{already}"), &created)
        .await
        .unwrap();
}
