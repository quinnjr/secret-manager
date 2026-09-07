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

pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
    timeout: Duration,
}

impl ControlServer {
    /// Create the parent directory (0700), replace any stale socket, bind, chmod 0600.
    pub async fn bind(path: &Path) -> std::io::Result<ControlServer> {
        Self::bind_with_timeout(path, CONNECTION_TIMEOUT).await
    }

    /// [`bind`](Self::bind) with a custom per-connection deadline (tests).
    pub async fn bind_with_timeout(
        path: &Path,
        timeout: Duration,
    ) -> std::io::Result<ControlServer> {
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("socket path has no parent"))?;
        tokio::fs::create_dir_all(dir).await?;
        tokio::fs::set_permissions(dir, Permissions::from_mode(0o700)).await?;
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(path)?;
        tokio::fs::set_permissions(path, Permissions::from_mode(0o600)).await?;
        Ok(ControlServer {
            listener,
            path: path.to_path_buf(),
            timeout,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop. One request/response per connection, at most
    /// [`MAX_CONNECTIONS`] in flight, each bounded by the connection timeout.
    pub async fn run(self, handler: Handler) {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        loop {
            let permit = match slots.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let (stream, _) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("control socket accept failed: {e}");
                    continue;
                }
            };
            if !peer_allowed(&stream) {
                tracing::warn!("rejected control connection from another uid");
                continue;
            }
            let handler = handler.clone();
            let timeout = self.timeout;
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(stream, handler, timeout).await {
                    tracing::debug!("control connection ended: {e}");
                }
            });
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Same uid as the daemon, or root (the PAM module runs as root at login).
fn peer_allowed(stream: &UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(cred) => {
            // SAFETY: getuid has no preconditions and cannot fail.
            let me = unsafe { libc::getuid() };
            uid_allowed(me, cred.uid())
        }
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
) -> std::io::Result<()> {
    let body = tokio::time::timeout(timeout, read_frame(&mut stream))
        .await
        .map_err(|_| std::io::Error::other("peer sent no request in time"))??;
    let response = match decode_frame::<Request>(&body) {
        Ok(req) => handler(req).await,
        Err(e) => Response::Error(format!("malformed request: {e}")),
    };
    let frame = encode_frame(&response).map_err(std::io::Error::other)?;
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
        let server = ControlServer::bind_with_timeout(&sock, Duration::from_millis(200))
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
}
