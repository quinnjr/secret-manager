mod common;

use common::{Fixture, PASSWORD, wait_for};
use control_protocol::{Request, Response, Zeroizing, call};
use futures_util::StreamExt;
use secret_manager::dbus::paths;
use secret_manager::dbus::proxies::{CollectionProxy, PromptProxy, ServiceProxy, SessionProxy};
use secret_manager::session::ALGORITHM_PLAIN;
use secret_manager::vault::Vault;
use secret_manager::vault::crypto::KdfParams;
use std::time::Duration;
use zbus::zvariant::Value;

async fn control(fx: &Fixture, req: Request) -> Response {
    let sock = fx.control_socket();
    tokio::task::spawn_blocking(move || call(&sock, &req))
        .await
        .unwrap()
        .unwrap()
}

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
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
        control(
            &fx,
            Request::Unlock {
                collection: "default".into(),
                password: pw("nope")
            }
        )
        .await,
        Response::Error(_)
    ));
    assert!(matches!(
        control(
            &fx,
            Request::Unlock {
                collection: "missing".into(),
                password: pw(PASSWORD)
            }
        )
        .await,
        Response::Error(_)
    ));

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut changed = service.receive_collection_changed().await.unwrap();
    assert_eq!(
        control(
            &fx,
            Request::Unlock {
                collection: "default".into(),
                password: pw(PASSWORD)
            }
        )
        .await,
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
    assert!(fx.daemon.state.lock().await.collections["default"].is_locked());

    assert!(matches!(
        control(
            &fx,
            Request::ChangePassword {
                collection: "default".into(),
                old: pw("bad"),
                new: pw("x")
            }
        )
        .await,
        Response::Error(_)
    ));
    assert_eq!(
        control(
            &fx,
            Request::ChangePassword {
                collection: "default".into(),
                old: pw(PASSWORD),
                new: pw("new")
            }
        )
        .await,
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
        control(
            &fx,
            Request::Unlock {
                collection: "default".into(),
                password: pw(PASSWORD)
            }
        )
        .await,
        Response::Error(_)
    ));
    assert_eq!(
        control(
            &fx,
            Request::Unlock {
                collection: "default".into(),
                password: pw("new")
            }
        )
        .await,
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
    assert!(!fx.daemon.state.lock().await.collections["default"].is_locked());
    assert!(
        wait_for(Duration::from_secs(5), || async {
            fx.daemon.state.lock().await.collections["default"].is_locked()
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
    daemon.shutdown();
    assert!(wait_for(Duration::from_secs(2), || async { !sock.exists() }).await);
}
