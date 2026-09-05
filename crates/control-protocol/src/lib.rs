//! Control socket protocol shared by the daemon, CLI, and PAM module.
//!
//! Framing: 4-byte big-endian length, then a postcard-encoded body.
//! This crate is std-only so the PAM module can link it without tokio.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
pub use zeroize::Zeroizing;

pub const MAX_FRAME: usize = 1 << 20;
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Unlock {
        collection: String,
        password: Zeroizing<String>,
    },
    Lock {
        collection: Option<String>,
    },
    ChangePassword {
        collection: String,
        old: Zeroizing<String>,
        new: Zeroizing<String>,
    },
    Status,
    Reload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionStatus {
    pub id: String,
    pub label: String,
    pub locked: bool,
    pub items: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Status {
        collections: Vec<CollectionStatus>,
        uptime_secs: u64,
    },
    Error(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("cannot connect to control socket: {0}")]
    Connect(std::io::Error),
    #[error("control socket i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds limit")]
    FrameTooLarge(usize),
    #[error("malformed message: {0}")]
    Encoding(#[from] postcard::Error),
}

pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let body = postcard::to_allocvec(msg)?;
    if body.len() > MAX_FRAME {
        return Err(ProtocolError::FrameTooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_frame<T: DeserializeOwned>(body: &[u8]) -> Result<T, ProtocolError> {
    Ok(postcard::from_bytes(body)?)
}

pub fn read_frame_sync<R: Read>(r: &mut R) -> Result<Vec<u8>, ProtocolError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

pub fn write_frame_sync<W: Write>(w: &mut W, frame: &[u8]) -> std::io::Result<()> {
    w.write_all(frame)?;
    w.flush()
}

/// `<runtime_dir>/secret-manager/control.sock`
pub fn socket_path_for_runtime_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("secret-manager").join("control.sock")
}

/// Socket for the current user: `$XDG_RUNTIME_DIR/secret-manager/control.sock`,
/// falling back to `/tmp/secret-manager-<uid>/control.sock`.
pub fn socket_path() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() => socket_path_for_runtime_dir(Path::new(&v)),
        _ => {
            // SAFETY: getuid has no preconditions and cannot fail.
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/secret-manager-{uid}")).join("control.sock")
        }
    }
}

/// Blocking request/response over the control socket.
pub fn call(path: &Path, req: &Request) -> Result<Response, ProtocolError> {
    let mut stream = UnixStream::connect(path).map_err(ProtocolError::Connect)?;
    stream.set_read_timeout(Some(CALL_TIMEOUT))?;
    stream.set_write_timeout(Some(CALL_TIMEOUT))?;
    write_frame_sync(&mut stream, &encode_frame(req)?)?;
    let body = read_frame_sync(&mut stream)?;
    decode_frame(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::net::UnixListener;

    #[test]
    fn frame_round_trip() {
        let req = Request::Unlock {
            collection: "default".into(),
            password: Zeroizing::new("hunter2".into()),
        };
        let bytes = encode_frame(&req).unwrap();
        assert_eq!(&bytes[..4], &((bytes.len() - 4) as u32).to_be_bytes());
        let mut cur = Cursor::new(bytes);
        let body = read_frame_sync(&mut cur).unwrap();
        let back: Request = decode_frame(&body).unwrap();
        match back {
            Request::Unlock {
                collection,
                password,
            } => {
                assert_eq!(collection, "default");
                assert_eq!(password.as_str(), "hunter2");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut bytes = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let err = read_frame_sync(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge(_)));
    }

    #[test]
    fn socket_path_shape() {
        let p = socket_path_for_runtime_dir(std::path::Path::new("/run/user/1000"));
        assert_eq!(
            p,
            std::path::PathBuf::from("/run/user/1000/secret-manager/control.sock")
        );
    }

    #[test]
    fn blocking_call_round_trip() {
        let dir = std::env::temp_dir().join(format!("cp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_frame_sync(&mut stream).unwrap();
            let req: Request = decode_frame(&body).unwrap();
            assert!(matches!(req, Request::Status));
            let resp = Response::Status {
                collections: vec![],
                uptime_secs: 7,
            };
            stream.write_all(&encode_frame(&resp).unwrap()).unwrap();
        });
        let resp = call(&sock, &Request::Status).unwrap();
        assert_eq!(
            resp,
            Response::Status {
                collections: vec![],
                uptime_secs: 7
            }
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreachable_socket_is_reported() {
        let err = call(
            std::path::Path::new("/nonexistent/control.sock"),
            &Request::Status,
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::Connect(_)));
    }
}
