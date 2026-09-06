//! Drives the module through libpam, isolated with pam_wrapper (cwrap).
//! Skips itself when pam_wrapper is not installed:
//!   Arch:   pacman -S pam_wrapper
//!   Debian: apt install libpam-wrapper
//! The outer test process starts a fake control socket and re-executes itself
//! with LD_PRELOAD so libpam reads the temporary service directory.

use control_protocol::{Request, Response, decode_frame, encode_frame, read_frame_sync};
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

fn pam_wrapper() -> Option<PathBuf> {
    first_existing(&[
        "/usr/lib/libpam_wrapper.so",
        "/usr/lib64/libpam_wrapper.so",
        "/usr/lib/x86_64-linux-gnu/libpam_wrapper.so",
    ])
}

fn pam_matrix() -> Option<PathBuf> {
    first_existing(&[
        "/usr/lib/pam_wrapper/pam_matrix.so",
        "/usr/lib64/pam_wrapper/pam_matrix.so",
        "/usr/lib/x86_64-linux-gnu/pam_wrapper/pam_matrix.so",
    ])
}

/// target/debug/deps/<test> -> target/debug/libpam_secret_manager.so
fn module_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("libpam_secret_manager.so")
}

#[test]
fn pam_stack_unlocks_vault() {
    if std::env::var_os("PAM_WRAPPER").is_some() {
        return inner();
    }
    let (Some(wrapper), Some(matrix)) = (pam_wrapper(), pam_matrix()) else {
        eprintln!("skipping: pam_wrapper is not installed");
        return;
    };
    assert!(
        module_path().exists(),
        "{} missing; run cargo build -p pam_secret_manager",
        module_path().display()
    );
    let dir = tempfile::tempdir().unwrap();
    let user = std::env::var("USER").expect("USER");
    let sock = dir.path().join("control.sock");
    let passdb = dir.path().join("passdb");
    std::fs::write(&passdb, format!("{user}:hunter2:secret-manager-test\n")).unwrap();
    std::fs::write(
        dir.path().join("secret-manager-test"),
        format!(
            "auth required {matrix} passdb={passdb} verbose\n\
             auth optional {module} socket={sock}\n\
             account required pam_permit.so\n\
             session optional {module} socket={sock} auto_start=no\n",
            matrix = matrix.display(),
            passdb = passdb.display(),
            module = module_path().display(),
            sock = sock.display()
        ),
    )
    .unwrap();

    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let body = read_frame_sync(&mut stream).unwrap();
        let req: Request = decode_frame(&body).unwrap();
        stream
            .write_all(&encode_frame(&Response::Ok).unwrap())
            .unwrap();
        req
    });

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "pam_stack_unlocks_vault", "--nocapture"])
        .env("LD_PRELOAD", &wrapper)
        .env("PAM_WRAPPER", "1")
        .env("PAM_WRAPPER_SERVICE_DIR", dir.path())
        .env("SM_TEST_USER", &user)
        .status()
        .unwrap();
    assert!(status.success(), "inner PAM run failed");

    match server.join().unwrap() {
        Request::Unlock {
            collection,
            password,
        } => {
            assert_eq!(collection, "default");
            assert_eq!(password.as_str(), "hunter2");
        }
        other => panic!("unexpected request {other:?}"),
    }
}

fn inner() {
    use pam_client::conv_mock::Conversation;
    use pam_client::{Context, Flag};
    let user = std::env::var("SM_TEST_USER").unwrap();
    let mut ctx = Context::new(
        "secret-manager-test",
        Some(&user),
        Conversation::with_credentials(&user, "hunter2"),
    )
    .unwrap();
    ctx.authenticate(Flag::NONE).expect("authenticate");
    let _session = ctx.open_session(Flag::NONE).expect("open_session");
}
