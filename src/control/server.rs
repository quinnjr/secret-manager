use crate::protocol::{MAX_FRAME, Request, Response, Zeroizing, decode_frame, encode_frame};
use std::fs::Permissions;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// Longest a peer may take to send its request, or to read the response.
/// Deliberately does not cover the handler: a key rotation re-seals the vault
/// and can outlast this, and cutting the socket then would report failure for
/// an operation that already succeeded on disk.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served at once; the rest wait in the listen backlog.
pub const MAX_CONNECTIONS: usize = 16;

/// Ceiling on one request's processing, separate from (and much larger than)
/// [`CONNECTION_TIMEOUT`]. A key rotation re-seals and fsyncs a whole vault,
/// so the handler must not share the I/O deadline — but without any bound a
/// peer could pin all [`MAX_CONNECTIONS`] slots indefinitely and deny the
/// PAM module its login unlock.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(120);

/// First wait after an `accept(2)` failure, and the base the doubling in
/// [`next_accept_backoff`] starts from.
const ACCEPT_BACKOFF_START: Duration = Duration::from_millis(100);
/// Ceiling on that wait: long enough that a persistent EMFILE costs nothing,
/// short enough that the daemon starts serving again promptly once the
/// condition clears.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
    timeout: Duration,
    /// Ceiling on one request's processing. Always [`HANDLER_TIMEOUT`] for a
    /// server built by [`bind`](Self::bind); overridable so a test can drive
    /// the timeout arm without waiting two minutes for it.
    handler_timeout: Duration,
    /// The peer check the accept loop applies. Always [`peer_allowed`] for a
    /// server built by [`bind`](Self::bind); the indirection exists so a test
    /// can drive the refusal path of the accept loop without needing a second
    /// uid on the machine.
    policy: fn(&UnixStream) -> bool,
}

impl ControlServer {
    /// Create the parent directory (0700), replace any stale socket, bind, chmod 0600.
    pub async fn bind(path: &Path) -> std::io::Result<ControlServer> {
        Self::bind_with_timeouts(path, CONNECTION_TIMEOUT, HANDLER_TIMEOUT).await
    }

    /// [`bind`](Self::bind) with both deadlines given explicitly. They are
    /// deliberately separate — see [`CONNECTION_TIMEOUT`] and
    /// [`HANDLER_TIMEOUT`] — so a test can shorten the handler's without
    /// shortening the peer's, or the other way round.
    pub async fn bind_with_timeouts(
        path: &Path,
        timeout: Duration,
        handler_timeout: Duration,
    ) -> std::io::Result<ControlServer> {
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("socket path has no parent"))?;
        tokio::fs::create_dir_all(dir).await?;
        tokio::fs::set_permissions(dir, Permissions::from_mode(0o700)).await?;
        // Whoever is listening here, it is not another daemon.
        //
        // `Daemon::start` acquires the bus name before it calls us, with
        // replacement refused in both directions, and D-Bus guarantees that
        // name is held by exactly one connection. So a second legitimate
        // daemon cannot exist at this point: it would already have failed
        // with `NameTaken` and never reached this line.
        //
        // This used to refuse to bind when anything answered on the path, to
        // avoid unlinking a live daemon's socket. Against the only party that
        // can actually be there — a same-uid impostor squatting the name —
        // that refusal was a permanent denial of service rather than a
        // defence: the unit fails, `Restart=on-failure` retries into
        // `StartLimitBurst`, and it stays failed after the squatter exits
        // until someone runs `systemctl --user reset-failed`.
        //
        // So we take the name. The impostor keeps its own listening socket
        // and any client already connected to it, which is the accepted
        // residue of gap I3 and unchanged by this; what it loses is the
        // ability to keep the real daemon from starting.
        let squatter = tokio::net::UnixStream::connect(path).await.is_ok();

        // Bind a private name and rename it over the target, rather than
        // unlink-then-bind. `rename(2)` is atomic, so there is no instant in
        // which the path is missing or unbound, and a squatter cannot win by
        // re-binding in a gap — there is no gap. Unlink-then-bind would give
        // it one, and losing that race is what makes a squat stick.
        let staging = dir.join(format!(
            ".control.{}.sock",
            crate::vault::crypto::random_bytes::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = tokio::fs::remove_file(&staging).await;
        let listener = UnixListener::bind(&staging)?;
        tokio::fs::set_permissions(&staging, Permissions::from_mode(0o600)).await?;
        if let Err(e) = tokio::fs::rename(&staging, path).await {
            let _ = tokio::fs::remove_file(&staging).await;
            return Err(e);
        }
        if squatter {
            tracing::warn!(
                "something was already listening on {}; it is not a daemon, because                  this process holds the bus name. Took the socket over.",
                path.display()
            );
        }
        Ok(ControlServer {
            listener,
            path: path.to_path_buf(),
            timeout,
            handler_timeout,
            policy: peer_allowed,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop. One request/response per connection, at most
    /// [`MAX_CONNECTIONS`] in flight, each bounded by the connection timeout.
    pub async fn run(self, handler: Handler) {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        let mut backoff = Duration::from_millis(0);
        loop {
            let permit = match slots.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let (stream, _) = match self.listener.accept().await {
                Ok(pair) => {
                    backoff = Duration::from_millis(0);
                    pair
                }
                Err(e) => {
                    // A persistent condition such as EMFILE/ENFILE would
                    // otherwise spin this loop at 100% CPU, one log line per
                    // iteration. Back off, and keep the log quiet after the
                    // first report of a run.
                    if backoff.is_zero() {
                        tracing::warn!("control socket accept failed: {e}");
                    }
                    backoff = next_accept_backoff(backoff);
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            };
            if !(self.policy)(&stream) {
                tracing::warn!("rejected control connection from another uid");
                continue;
            }
            let handler = handler.clone();
            let timeout = self.timeout;
            let handler_timeout = self.handler_timeout;
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(stream, handler, timeout, handler_timeout).await {
                    tracing::debug!("control connection ended: {e}");
                }
            });
        }
    }
}

/// The next wait after an `accept(2)` failure: the first failure of a run
/// waits [`ACCEPT_BACKOFF_START`], each consecutive one doubles up to
/// [`ACCEPT_BACKOFF_MAX`], and a zero argument — what the accept loop stores
/// after every successful accept — starts the sequence over.
///
/// Split out from the loop because the condition that drives it (an `accept`
/// that keeps failing, i.e. EMFILE/ENFILE) cannot be provoked in-process
/// without exhausting the whole test binary's file descriptors, so this
/// arithmetic is only testable on its own.
fn next_accept_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        ACCEPT_BACKOFF_START
    } else {
        (current * 2).min(ACCEPT_BACKOFF_MAX)
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Same uid as the daemon, or root (the PAM module runs as root at login).
fn peer_allowed(stream: &UnixStream) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail. The effective uid
    // is the one the client side checks for, so both ends compare the same
    // identity.
    let me = unsafe { libc::geteuid() };
    peer_allowed_from(stream.peer_cred(), me)
}

/// The credential decision, split out from the two syscalls so every arm —
/// including the one where the kernel refuses to name the peer — is reachable
/// from a test. A peer whose credentials cannot be read is refused: there is
/// no identity to compare, so the only safe answer is no.
fn peer_allowed_from(cred: std::io::Result<tokio::net::unix::UCred>, me: u32) -> bool {
    match cred {
        Ok(cred) => uid_allowed(me, cred.uid()),
        Err(_) => false,
    }
}

fn uid_allowed(me: u32, peer: u32) -> bool {
    peer == me || peer == 0
}

/// Reads one frame body into a [`Zeroizing`] buffer: a request may carry a
/// password or key, and the raw bytes must not outlive the decode.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!(
            "frame of {len} bytes exceeds limit"
        )));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body[..]).await?;
    Ok(body)
}

async fn handle_connection(
    mut stream: UnixStream,
    handler: Handler,
    timeout: Duration,
    handler_timeout: Duration,
) -> std::io::Result<()> {
    let body = tokio::time::timeout(timeout, read_frame(&mut stream))
        .await
        .map_err(|_| std::io::Error::other("peer sent no request in time"))??;
    let response = match decode_frame::<Request>(&body) {
        Ok(req) => match tokio::time::timeout(handler_timeout, handler(req)).await {
            Ok(response) => response,
            Err(_) => Response::Error("the daemon took too long to answer".into()),
        },
        Err(e) => Response::Error(format!("malformed request: {e}")),
    };
    // A response too large to frame must still be diagnosable: send an error
    // the peer can read rather than dropping the connection, which would
    // surface as an unexplained EOF.
    let frame = match encode_frame(&response) {
        Ok(frame) => frame,
        Err(e) => {
            tracing::warn!("cannot encode a control response: {e}");
            encode_frame(&Response::Error("response too large".into()))
                .map_err(std::io::Error::other)?
        }
    };
    tokio::time::timeout(timeout, stream.write_all(&frame))
        .await
        .map_err(|_| std::io::Error::other("peer stopped reading"))??;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CollectionStatus, call};
    use std::os::unix::fs::PermissionsExt;

    fn handler() -> Handler {
        Arc::new(|req: Request| {
            Box::pin(async move {
                match req {
                    Request::Status => Response::Status {
                        aliases_error: None,
                        collections: vec![CollectionStatus {
                            id: "default".into(),
                            label: "Default".into(),
                            locked: true,
                            items: 0,
                            warning: None,
                        }],
                        uptime_secs: 1,
                    },
                    Request::Lock { .. } => Response::Ok,
                    _ => Response::Error("unsupported in test".into()),
                }
            })
        })
    }

    #[tokio::test]
    async fn serves_requests_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("secret-manager").join("control.sock");
        let server = ControlServer::bind(&sock).await.unwrap();
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(sock.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let task = tokio::spawn(server.run(handler()));

        let s = sock.clone();
        let resp = tokio::task::spawn_blocking(move || call(&s, &Request::Status))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(resp, Response::Status { uptime_secs: 1, .. }));
        let s = sock.clone();
        let resp =
            tokio::task::spawn_blocking(move || call(&s, &Request::Lock { collection: None }))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(resp, Response::Ok);

        task.abort();
        let _ = task.await;
        assert!(!sock.exists(), "socket removed when server dropped");
    }

    /// A client that connects and never sends a frame must not hold a task
    /// (or one of the bounded connection slots) forever.
    #[tokio::test]
    async fn idle_connections_are_closed_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server =
            ControlServer::bind_with_timeouts(&sock, Duration::from_millis(200), HANDLER_TIMEOUT)
                .await
                .unwrap();
        let task = tokio::spawn(server.run(handler()));
        let mut idle = Vec::new();
        for _ in 0..(MAX_CONNECTIONS + 4) {
            idle.push(tokio::net::UnixStream::connect(&sock).await.unwrap());
        }
        // Every idle connection is dropped by the server within the timeout.
        let mut buf = [0u8; 1];
        let started = std::time::Instant::now();
        for s in idle.iter_mut() {
            let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
                .await
                .expect("server should close the idle connection")
                .unwrap_or(0);
            assert_eq!(n, 0, "expected EOF from the server");
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        // ...and the slots are free again for a real request.
        let s = sock.clone();
        let resp = tokio::task::spawn_blocking(move || call(&s, &Request::Status))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(resp, Response::Status { .. }));
        task.abort();
    }

    #[test]
    fn uid_allowed_same_uid_or_root() {
        assert!(uid_allowed(1000, 1000));
        assert!(uid_allowed(1000, 0));
        assert!(!uid_allowed(1000, 1001));
        assert!(!uid_allowed(0, 1001));
    }

    #[tokio::test]
    async fn malformed_request_gets_error_response() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = ControlServer::bind(&sock).await.unwrap();
        let task = tokio::spawn(server.run(handler()));
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff])
            .await
            .unwrap();
        let body = read_frame(&mut stream).await.unwrap();
        let resp: Response = crate::protocol::decode_frame(&body).unwrap();
        assert!(matches!(resp, Response::Error(msg) if msg.contains("malformed")));
        task.abort();
    }

    #[tokio::test]
    async fn rebinding_replaces_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        std::fs::write(&sock, b"stale").unwrap();
        let server = ControlServer::bind(&sock).await.unwrap();
        assert_eq!(server.path(), sock.as_path());
    }

    /// This reader is the daemon's own, separate from `protocol::read_frame_sync`:
    /// it is what every inbound control connection goes through, so the length
    /// ceiling has to be proven here too. Without it a peer announcing 4 GiB
    /// would have that much allocated per connection, `MAX_CONNECTIONS` at a
    /// time.
    #[tokio::test]
    async fn read_frame_rejects_an_oversized_length_prefix() {
        let mut oversized = u32::MAX.to_be_bytes().to_vec();
        oversized.extend_from_slice(b"body");
        let err = read_frame(&mut &oversized[..]).await.unwrap_err();
        assert!(err.to_string().contains("exceeds limit"), "got {err}",);

        // The bound is a ceiling, not a tightening: a frame of exactly
        // MAX_FRAME is still a legal frame.
        let mut exact = (MAX_FRAME as u32).to_be_bytes().to_vec();
        exact.resize(4 + MAX_FRAME, 0u8);
        let body = read_frame(&mut &exact[..]).await.unwrap();
        assert_eq!(body.len(), MAX_FRAME);
    }

    /// A squatter cannot keep the daemon from starting.
    ///
    /// This test previously asserted the opposite — that a bind over anything
    /// still answering was refused — on the grounds that unlinking a live
    /// daemon's socket would strand its clients. That reasoning does not
    /// survive the startup order: `Daemon::start` takes the bus name before
    /// it binds, refusing replacement in both directions, and D-Bus makes
    /// that name unique. A second *legitimate* daemon therefore cannot reach
    /// the bind at all, so the only party the refusal ever met was a same-uid
    /// impostor — for whom it was a permanent denial of service, because the
    /// unit then fails, retries into `StartLimitBurst`, and stays failed
    /// after the impostor exits.
    #[tokio::test]
    async fn a_squatted_socket_is_taken_over_rather_than_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");

        // Stand in for the squatter: something listening on the path that is
        // not a daemon and never answers a request.
        let squatter = UnixListener::bind(&sock).unwrap();
        assert!(
            tokio::net::UnixStream::connect(&sock).await.is_ok(),
            "precondition: the squatter is accepting"
        );

        let server = ControlServer::bind(&sock)
            .await
            .expect("a squatter must not be able to keep the daemon from starting");
        let task = tokio::spawn(server.run(handler()));

        // The path now names the daemon's socket, and it answers.
        let s = sock.clone();
        let resp = tokio::task::spawn_blocking(move || call(&s, &Request::Status))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(resp, Response::Status { .. }), "got {resp:?}");

        // The squatter still holds its own listening socket — it was renamed
        // out from under it, not closed — so taking the name over does not
        // reach into another process. It simply no longer owns the path.
        drop(squatter);

        task.abort();
        let _ = task.await;
    }

    /// The rename is what makes the takeover safe: there is no instant in
    /// which the path is absent or unbound, so a squatter cannot win by
    /// re-binding in a gap. Unlink-then-bind would leave exactly such a gap.
    #[tokio::test]
    async fn the_socket_is_never_absent_during_a_takeover() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let _squatter = UnixListener::bind(&sock).unwrap();

        // Watch the path while the bind runs. `symlink_metadata` so a missing
        // entry is distinguishable from anything else.
        let watch = sock.clone();
        let observer = tokio::spawn(async move {
            let mut vanished = false;
            for _ in 0..2000 {
                if std::fs::symlink_metadata(&watch).is_err() {
                    vanished = true;
                    break;
                }
                tokio::time::sleep(Duration::from_micros(50)).await;
            }
            vanished
        });

        let server = ControlServer::bind(&sock).await.unwrap();
        let vanished = {
            observer.abort();
            observer.await.unwrap_or(false)
        };
        assert!(!vanished, "the socket path vanished during the takeover");
        assert!(sock.exists());
        drop(server);
    }

    /// A response too large to frame is substituted rather than dropped: the
    /// peer gets a readable error instead of an unexplained EOF.
    #[tokio::test]
    async fn oversized_response_is_replaced_with_a_readable_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = ControlServer::bind(&sock).await.unwrap();
        let huge: Handler = Arc::new(|_req: Request| {
            Box::pin(async move { Response::Error("x".repeat(MAX_FRAME + 1)) })
        });
        let task = tokio::spawn(server.run(huge));

        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let frame = encode_frame(&Request::Status).unwrap();
        stream.write_all(&frame).await.unwrap();
        let body = read_frame(&mut stream).await.unwrap();
        let resp: Response = crate::protocol::decode_frame(&body).unwrap();
        assert_eq!(resp, Response::Error("response too large".into()));

        task.abort();
        let _ = task.await;
    }

    /// `uid_allowed` is arithmetic; this is the arm that actually decides.
    /// The `Err` case is the one that had no coverage at all: a peer whose
    /// credentials the kernel will not report must be refused, not admitted.
    #[tokio::test]
    async fn peer_allowed_from_fails_closed_on_an_unreadable_credential() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };

        // A real UCred, from a real socket: the same uid is allowed.
        assert_eq!(a.peer_cred().unwrap().uid(), me);
        assert!(peer_allowed_from(a.peer_cred(), me));

        // A foreign uid is refused. Skipped when the suite runs as root,
        // where every uid it could name is either `me` or 0.
        if me != 0 {
            let foreign = me.wrapping_add(1);
            assert!(
                !peer_allowed_from(a.peer_cred(), foreign),
                "a daemon running as {foreign} must refuse a peer at {me}"
            );
        }

        // Root is allowed: the PAM module connects as root at login.
        assert!(uid_allowed(me, 0));

        // No credential, no decision to make: refuse.
        assert!(!peer_allowed_from(
            Err(std::io::Error::other("peer_cred failed")),
            me
        ));
        assert!(!peer_allowed_from(
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            me
        ));
        assert!(!peer_allowed_from(
            Err(std::io::Error::other("peer_cred failed")),
            0
        ));
    }

    static REFUSALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// Refuse the first `REFUSE_FIRST` connections, then defer to the real
    /// check. More than `MAX_CONNECTIONS` refusals, so a permit leaked on the
    /// refusal path would wedge the loop before the last one.
    const REFUSE_FIRST: usize = MAX_CONNECTIONS + 4;
    fn refuse_first_then_real(stream: &UnixStream) -> bool {
        if REFUSALS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < REFUSE_FIRST {
            false
        } else {
            peer_allowed(stream)
        }
    }

    /// A refused peer is dropped *unserved* — it gets EOF, never a response
    /// frame — and the accept loop carries on: its `continue` has to release
    /// the concurrency permit, or the twentieth refusal would never be
    /// reached and the legitimate connection after it would never be
    /// answered.
    #[tokio::test]
    async fn a_refused_peer_is_closed_unserved_and_the_loop_keeps_accepting() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let mut server = ControlServer::bind(&sock).await.unwrap();
        server.policy = refuse_first_then_real;
        let task = tokio::spawn(server.run(handler()));

        let frame = encode_frame(&Request::Status).unwrap();
        for i in 0..REFUSE_FIRST {
            let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
            // The write may or may not fail depending on when the server
            // closes; what matters is that nothing comes back.
            let _ = stream.write_all(&frame).await;
            let mut buf = [0u8; 64];
            // EOF or ECONNRESET: both mean the connection was dropped before
            // anything was written back. A byte count above zero would be a
            // response frame, which is the thing that must never happen.
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("refused connection {i} was neither served nor closed"))
            {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => 0,
                Err(e) => panic!("refused connection {i} failed unexpectedly: {e}"),
            };
            assert_eq!(n, 0, "a refused peer must not get a response frame");
        }

        // ...and the loop is still accepting, with all its slots back.
        for _ in 0..3 {
            let s = sock.clone();
            let resp = tokio::task::spawn_blocking(move || call(&s, &Request::Status))
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(resp, Response::Status { .. }),
                "the loop must keep serving after a refusal"
            );
        }

        task.abort();
        let _ = task.await;
    }

    // --- the foreign-uid test, and its plumbing ---------------------------

    /// `SO_PEERCRED` on a raw fd. `std`'s accessor is still unstable, and the
    /// test needs the uid the *kernel* reports, not one Rust hands back.
    fn peer_uid_of(fd: std::os::fd::RawFd) -> u32 {
        let mut cred = libc::ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `fd` is an open connected socket owned by the caller, and
        // `cred`/`len` are a correctly sized out-parameter pair.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt(SO_PEERCRED) failed");
        cred.uid
    }

    /// Write every byte, retrying short writes. Called on both sides of a
    /// `fork`, so it is `libc` only: no allocation, no locks.
    ///
    /// # Safety
    /// `fd` must be an open, writable file descriptor.
    unsafe fn write_all_fd(fd: libc::c_int, buf: &[u8]) {
        let mut off = 0usize;
        while off < buf.len() {
            // SAFETY: the caller guarantees `fd`; the pointer/length pair is
            // an in-bounds slice of `buf`.
            let n = unsafe { libc::write(fd, buf[off..].as_ptr().cast(), buf.len() - off) };
            if n <= 0 {
                // SAFETY: async-signal-safe, and the only correct move in a
                // forked child that cannot report.
                unsafe { libc::_exit(70) };
            }
            off += n as usize;
        }
    }

    /// The sub-uid ranges delegated to this user, newest first. Empty when
    /// `/etc/subuid` has no entry for us, which is the usual reason this
    /// machine cannot host the foreign-uid test.
    fn delegated_subuids(uid: u32) -> Vec<u32> {
        // SAFETY: getpwuid has no preconditions; the returned pointer is
        // owned by libc and only read here, before any other libc call that
        // could reuse the static buffer.
        let name = unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                None
            } else {
                std::ffi::CStr::from_ptr((*pw).pw_name)
                    .to_str()
                    .ok()
                    .map(str::to_owned)
            }
        };
        let text = match std::fs::read_to_string("/etc/subuid") {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        text.lines()
            .filter_map(|line| {
                let mut f = line.split(':');
                let who = f.next()?;
                let start: u32 = f.next()?.trim().parse().ok()?;
                let count: u32 = f.next()?.trim().parse().ok()?;
                let mine = who == uid.to_string() || name.as_deref() == Some(who);
                (mine && count >= 2).then_some(start)
            })
            .collect()
    }

    /// The real thing: a connection from a process whose kernel uid is
    /// genuinely not ours and not root, refused by the accept loop.
    ///
    /// Getting a second uid without being root takes a user namespace *plus*
    /// a delegated sub-uid range. A namespace alone is not enough, and the
    /// obvious recipe is a trap: `unshare(CLONE_NEWUSER)` with the usual
    /// `0 <uid> 1` map makes the connecting parent appear as uid **0** to the
    /// namespaced listener, which `uid_allowed` allows — the test would pass
    /// while proving nothing. With no map at all, listener and peer both read
    /// back as the overflow uid, which `uid_allowed` also allows. So the
    /// namespace here is only the vehicle for `newuidmap`, which maps a
    /// second uid from `/etc/subuid` that the child can then `setresuid` to:
    /// a real, different `kuid`, seen as such by an ordinary listener in the
    /// host namespace.
    ///
    /// Plain `#[test]`: the `fork` happens before any tokio runtime exists,
    /// and the child touches nothing but `libc` before `_exit`.
    #[test]
    fn a_connection_from_a_genuinely_foreign_uid_is_refused() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if me == 0 {
            eprintln!(
                "SKIP a_connection_from_a_genuinely_foreign_uid_is_refused: running as root, where every uid is allowed by design"
            );
            return;
        }
        let subuids = delegated_subuids(me);
        if subuids.is_empty() {
            eprintln!(
                "SKIP a_connection_from_a_genuinely_foreign_uid_is_refused: no /etc/subuid range delegated to uid {me}, so no second uid is reachable unprivileged"
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let probe_path = dir.path().join("probe.sock");
        // sockaddr_un is 108 bytes including the NUL.
        assert!(
            sock.as_os_str().len() < 100,
            "temp path too long for AF_UNIX"
        );

        // Everything the forked child touches is built now: after `fork` it
        // may only call async-signal-safe functions.
        let probe = std::os::unix::net::UnixListener::bind(&probe_path).unwrap();
        let control_addr = sockaddr_un(&sock);
        let probe_addr = sockaddr_un(&probe_path);
        let request = encode_frame(&Request::Status).unwrap();

        let mut ready = [0 as libc::c_int; 2];
        let mut go = [0 as libc::c_int; 2];
        // SAFETY: both arrays are two-element c_int buffers, as pipe(2) wants.
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::pipe(go.as_mut_ptr()) }, 0);

        // SAFETY: the child below calls only async-signal-safe libc functions
        // and ends in `_exit`, so no Rust destructor, allocator lock, or
        // atexit handler inherited from this multi-threaded process runs.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // ---- forked child: libc only, no allocation, no destructors ----
            unsafe {
                libc::close(ready[0]);
                libc::close(go[1]);
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    write_all_fd(ready[1], b"U");
                    libc::_exit(0);
                }
                write_all_fd(ready[1], b"R");
                let mut sig = [0u8; 1];
                if libc::read(go[0], sig.as_mut_ptr().cast(), 1) != 1 || sig[0] != b'G' {
                    libc::_exit(71);
                }
                // The parent has just mapped a delegated sub-uid to namespace
                // uid 1; becoming it changes this process's real kernel uid.
                if libc::setresuid(1, 1, 1) != 0 {
                    write_all_fd(ready[1], b"S");
                    libc::_exit(0);
                }
                // Let the parent observe the credentials the kernel now
                // reports for us on an ordinary socket.
                let p = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if p < 0
                    || libc::connect(
                        p,
                        (&raw const probe_addr).cast(),
                        std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                    ) != 0
                {
                    write_all_fd(ready[1], b"P");
                    libc::_exit(0);
                }
                // Now the real target.
                let c = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if c < 0
                    || libc::connect(
                        c,
                        (&raw const control_addr).cast(),
                        std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                    ) != 0
                {
                    write_all_fd(ready[1], b"C");
                    libc::_exit(0);
                }
                libc::write(c, request.as_ptr().cast(), request.len());
                let mut buf = [0u8; 64];
                let n = libc::read(c, buf.as_mut_ptr().cast(), buf.len());
                let err = if n < 0 { *libc::__errno_location() } else { 0 };
                write_all_fd(ready[1], b"K");
                write_all_fd(ready[1], &(n as i64).to_ne_bytes());
                write_all_fd(ready[1], &err.to_ne_bytes());
                libc::_exit(0);
            }
        }

        // ---- parent ----
        // SAFETY: these are our own pipe ends, still open.
        unsafe {
            libc::close(ready[1]);
            libc::close(go[0]);
        }
        let reap = |pid: libc::pid_t| {
            let mut status = 0;
            // SAFETY: `pid` is our child; `status` is a valid out-parameter.
            unsafe { libc::waitpid(pid, &raw mut status, 0) };
        };
        let read_exactly = |fd: libc::c_int, buf: &mut [u8]| -> bool {
            let mut off = 0usize;
            while off < buf.len() {
                // SAFETY: `fd` is our open pipe read end; the pointer/length
                // pair is an in-bounds slice of `buf`.
                let n = unsafe { libc::read(fd, buf[off..].as_mut_ptr().cast(), buf.len() - off) };
                if n <= 0 {
                    return false;
                }
                off += n as usize;
            }
            true
        };

        let mut tag = [0u8; 1];
        if !read_exactly(ready[0], &mut tag) || tag[0] == b'U' {
            reap(child);
            eprintln!(
                "SKIP a_connection_from_a_genuinely_foreign_uid_is_refused: unshare(CLONE_NEWUSER) was refused by the kernel (hardened kernel, seccomp, or a container runtime)"
            );
            return;
        }
        assert_eq!(tag[0], b'R', "unexpected report from the forked child");

        // Map namespace uid 0 -> our uid, and namespace uid 1 -> the first
        // delegated sub-uid. newuidmap holds cap_setuid; without it (or
        // without a delegated range) the mapping is impossible unprivileged.
        let foreign = subuids[0];
        let mapped = subuids.iter().any(|start| {
            std::process::Command::new("newuidmap")
                .args([
                    child.to_string(),
                    "0".into(),
                    me.to_string(),
                    "1".into(),
                    "1".into(),
                    start.to_string(),
                    "1".into(),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        });
        if !mapped {
            // SAFETY: `child` is our own child process.
            unsafe { libc::kill(child, libc::SIGKILL) };
            reap(child);
            eprintln!(
                "SKIP a_connection_from_a_genuinely_foreign_uid_is_refused: newuidmap could not map a delegated sub-uid (missing binary, missing cap_setuid, or an /etc/subuid range this user does not own)"
            );
            return;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(ControlServer::bind(&sock)).unwrap();
        let task = rt.spawn(server.run(handler()));

        // The daemon's own 0700/0600 modes would refuse the foreign uid at
        // `connect` — that is defence in depth, and it is exactly what has to
        // be stood down here so the *credential check* is what does the
        // refusing.
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o711)).unwrap();
        std::fs::set_permissions(&sock, Permissions::from_mode(0o666)).unwrap();
        std::fs::set_permissions(&probe_path, Permissions::from_mode(0o666)).unwrap();

        // SAFETY: `go[1]` is our open pipe write end.
        unsafe { write_all_fd(go[1], b"G") };

        let observed = {
            use std::os::fd::AsRawFd;
            let (conn, _) = probe
                .accept()
                .expect("child never reached the probe socket");
            peer_uid_of(conn.as_raw_fd())
        };

        let mut report = [0u8; 13];
        let got = read_exactly(ready[0], &mut report[..1])
            && (report[0] != b'K' || read_exactly(ready[0], &mut report[1..]));
        reap(child);
        assert!(got, "the forked child died without reporting");

        match report[0] {
            b'K' => {}
            b'S' => panic!("setresuid into the mapped sub-uid failed after newuidmap succeeded"),
            b'C' => panic!(
                "connect to the control socket failed; the credential check was never reached"
            ),
            other => panic!("unexpected report byte {other:#x} from the forked child"),
        }
        let n = i64::from_ne_bytes(report[1..9].try_into().unwrap());
        let err = i32::from_ne_bytes(report[9..13].try_into().unwrap());

        // The uid the kernel reported for the peer really is foreign.
        assert_eq!(
            observed, foreign,
            "expected the delegated sub-uid {foreign} on the wire"
        );
        assert_ne!(observed, me, "the peer must not share the daemon's uid");
        assert_ne!(observed, 0, "the peer must not be root");
        assert!(
            !uid_allowed(me, observed),
            "uid_allowed({me}, {observed}) must refuse"
        );

        // ...and the server refused it: not one byte of a response frame.
        // A clean EOF and an ECONNRESET both mean unserved — the reset is
        // just the kernel's answer to a socket closed with the peer's unread
        // request still queued on it. Anything else would be a served peer.
        assert!(
            n == 0 || (n < 0 && err == libc::ECONNRESET),
            "a peer at uid {observed} was served {n} bytes (errno {err}) by a daemon at uid {me}"
        );

        // The loop survived the refusal and still answers a legitimate peer.
        // A plain blocking call: the server is running on `rt`'s threads,
        // not this one.
        let resp = call(&sock, &Request::Status).unwrap();
        assert!(
            matches!(resp, Response::Status { .. }),
            "the loop must keep serving after refusing a foreign uid"
        );

        eprintln!(
            "a_connection_from_a_genuinely_foreign_uid_is_refused: daemon uid {me}, peer uid {observed} (delegated sub-uid), refused unserved"
        );

        task.abort();
        drop(rt);
    }

    /// A `sockaddr_un` for a path short enough to fit one, built before any
    /// `fork` so the child never has to.
    fn sockaddr_un(path: &Path) -> libc::sockaddr_un {
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: sockaddr_un is a plain C struct of integers and a byte
        // array; an all-zero value is a valid (empty-path) one.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        assert!(
            bytes.len() < addr.sun_path.len(),
            "path too long for AF_UNIX"
        );
        for (slot, b) in addr.sun_path.iter_mut().zip(bytes) {
            *slot = *b as libc::c_char;
        }
        addr
    }

    /// The stale-socket cleanup must not swallow every failure to unlink. A
    /// path occupied by something that is not a socket file — a directory,
    /// say — has to be reported, not stepped over on the way to a `bind` that
    /// would fail with a less informative error.
    #[tokio::test]
    async fn a_socket_path_occupied_by_a_directory_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        std::fs::create_dir(&sock).unwrap();
        let err = match ControlServer::bind(&sock).await {
            Ok(_) => panic!("bind must not claim a path occupied by a directory"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EISDIR), "got {err}");
        assert!(sock.is_dir(), "the directory must survive the failed bind");
    }

    /// The doubling, the ceiling, and the restart after a good run. A failing
    /// `accept(2)` is what this protects against — an unbacked-off loop would
    /// spin at 100% CPU and fill the log — and the failure itself cannot be
    /// staged in-process, so the arithmetic is checked directly.
    #[test]
    fn the_accept_backoff_starts_small_doubles_and_stops_at_its_ceiling() {
        // A zero backoff is what the loop holds after a successful accept, so
        // the first failure of a run always starts from the bottom.
        assert_eq!(next_accept_backoff(Duration::ZERO), ACCEPT_BACKOFF_START);

        let mut seen = vec![next_accept_backoff(Duration::ZERO)];
        for _ in 0..8 {
            seen.push(next_accept_backoff(*seen.last().unwrap()));
        }
        assert_eq!(
            &seen[..4],
            &[
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(800),
            ]
        );
        assert!(
            seen.iter().all(|d| *d <= ACCEPT_BACKOFF_MAX),
            "the backoff must never exceed its ceiling: {seen:?}"
        );
        assert_eq!(*seen.last().unwrap(), ACCEPT_BACKOFF_MAX);
        // The ceiling is a fixed point: however long the condition persists,
        // the wait neither grows nor overflows.
        assert_eq!(
            next_accept_backoff(ACCEPT_BACKOFF_MAX),
            ACCEPT_BACKOFF_MAX,
            "the ceiling must hold"
        );
    }

    /// The handler has its own, much larger deadline than the connection —
    /// a key rotation re-seals a whole vault — but it is still a deadline. A
    /// handler that never returns must not hold its connection slot forever:
    /// the peer gets a readable answer and the slot comes back.
    #[tokio::test]
    async fn a_handler_that_never_returns_is_abandoned_with_an_error_response() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = ControlServer::bind_with_timeouts(
            &sock,
            CONNECTION_TIMEOUT,
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let stuck: Handler = Arc::new(|_req: Request| {
            Box::pin(async move { std::future::pending::<Response>().await })
        });
        let task = tokio::spawn(server.run(stuck));

        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(&encode_frame(&Request::Status).unwrap())
            .await
            .unwrap();
        let body = read_frame(&mut stream).await.unwrap();
        let resp: Response = crate::protocol::decode_frame(&body).unwrap();
        assert!(
            matches!(&resp, Response::Error(msg) if msg.contains("too long")),
            "got {resp:?}"
        );

        // And the loop is still accepting: the slot the abandoned handler
        // held was released rather than leaked, so a second peer is served
        // (with the same verdict) instead of waiting on a permit forever.
        let mut second = tokio::net::UnixStream::connect(&sock).await.unwrap();
        second
            .write_all(&encode_frame(&Request::Status).unwrap())
            .await
            .unwrap();
        let body = read_frame(&mut second).await.unwrap();
        let resp: Response = crate::protocol::decode_frame(&body).unwrap();
        assert!(
            matches!(&resp, Response::Error(msg) if msg.contains("too long")),
            "got {resp:?}"
        );

        task.abort();
        let _ = task.await;
    }
}
