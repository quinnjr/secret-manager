//! Control socket protocol shared by the daemon, the CLI, and the PAM module.
//!
//! Deliberately free of async and of every daemon-only dependency: the PAM
//! module links this code into a library that `sshd` loads as root.
//!
//! Framing: 4-byte big-endian length, then the frame body. The body is
//! `[version: u8][postcard-encoded message]`, so a peer speaking a different
//! protocol revision is rejected before its bytes are handed to postcard.
//! This crate is std-only so the PAM module can link it without tokio.

pub use crate::vault::crypto::{KEY_LEN, KdfParams, SALT_LEN};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
pub use zeroize::Zeroizing;

pub const MAX_FRAME: usize = 1 << 20;
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Wire revision of the frame body. Bump on any change to the shape or the
/// declaration order of [`Request`] or [`Response`].
///
/// v3 removed every password-carrying request. Both the CLI and the PAM
/// module read the collection's header from disk, derive the vault key
/// themselves, and send only the key, so nothing that answers this socket
/// can choose a salt or KDF parameters, and no password ever crosses it.
///
/// v4 added the `aliases_error` field to [`Response::Status`], so a corrupt
/// `aliases.toml` is reported to `sm status` instead of keeping the daemon
/// from starting. The request set is unchanged from v3 - v4 is a response
/// shape change only - but a `Response` field is as wire-significant as a
/// request variant under postcard, so the version moved with it.
pub const PROTOCOL_VERSION: u8 = 4;

/// Variant names of [`Request`] in wire order, for tests and diagnostics.
pub const REQUEST_VARIANTS: [&str; 5] = ["Lock", "Status", "Reload", "UnlockWithKey", "ChangeKey"];

/// A control-socket request.
///
/// The declaration order of these variants is wire-significant: postcard
/// encodes the variant as its zero-based index, so reordering, inserting, or
/// removing a variant silently changes the meaning of existing frames. Any
/// such change must bump [`PROTOCOL_VERSION`].
#[derive(Serialize, Deserialize)]
pub enum Request {
    Lock {
        collection: Option<String>,
    },
    Status,
    Reload,
    /// Unlock with a key the caller derived from the collection's own header
    /// (`derive_key(password, salt, kdf)`). Whoever answers this socket
    /// learns the vault key, never the password it came from.
    UnlockWithKey {
        collection: String,
        key: Zeroizing<[u8; KEY_LEN]>,
    },
    /// Rotate the vault key. `old_key` must open the collection; the items
    /// are re-sealed under `new_key`, and `new_salt`/`new_kdf` are written to
    /// the header so later derivations use them.
    ChangeKey {
        collection: String,
        old_key: Zeroizing<[u8; KEY_LEN]>,
        new_salt: [u8; SALT_LEN],
        new_kdf: KdfParams,
        new_key: Zeroizing<[u8; KEY_LEN]>,
    },
}

impl Request {
    /// Variant name only; always safe to log.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Request::Lock { .. } => REQUEST_VARIANTS[0],
            Request::Status => REQUEST_VARIANTS[1],
            Request::Reload => REQUEST_VARIANTS[2],
            Request::UnlockWithKey { .. } => REQUEST_VARIANTS[3],
            Request::ChangeKey { .. } => REQUEST_VARIANTS[4],
        }
    }
}

/// Hand-written so keys never reach a log, a panic message, or a `{:?}` in
/// an error path.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "<redacted>";
        match self {
            Request::Lock { collection } => f
                .debug_struct("Lock")
                .field("collection", collection)
                .finish(),
            Request::Status => f.write_str("Status"),
            Request::Reload => f.write_str("Reload"),
            Request::UnlockWithKey { collection, .. } => f
                .debug_struct("UnlockWithKey")
                .field("collection", collection)
                .field("key", &REDACTED)
                .finish(),
            Request::ChangeKey {
                collection,
                new_kdf,
                ..
            } => f
                .debug_struct("ChangeKey")
                .field("collection", collection)
                .field("old_key", &REDACTED)
                .field("new_salt", &REDACTED)
                .field("new_kdf", new_kdf)
                .field("new_key", &REDACTED)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionStatus {
    pub id: String,
    pub label: String,
    pub locked: bool,
    pub items: usize,
    /// A condition the operator should know about, such as an attribute
    /// index that could not be rewritten to match `locked_search`.
    pub warning: Option<String>,
}

/// A control-socket response.
///
/// As with [`Request`], the declaration order of these variants is
/// wire-significant and any change to it must bump [`PROTOCOL_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Status {
        collections: Vec<CollectionStatus>,
        uptime_secs: u64,
        /// Why the alias table is unusable, when it is. A corrupt
        /// `aliases.toml` no longer stops the daemon starting, so this is the
        /// only way an operator finds out that alias lookups are refusing and
        /// that the file is waiting to be repaired.
        aliases_error: Option<String>,
    },
    Error(String),
}

impl Response {
    /// Variant name only; safe to log even when the peer is untrusted.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Response::Ok => "Ok",
            Response::Status { .. } => "Status",
            Response::Error(_) => "Error",
        }
    }
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
    #[error("XDG_RUNTIME_DIR is not set; cannot locate the control socket")]
    NoRuntimeDir,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("{0} unexpected bytes after the message")]
    TrailingBytes(usize),
    #[error("control socket is owned by uid {actual}, expected {expected}")]
    UntrustedPeer { expected: u32, actual: u32 },
}

/// Encodes `msg` into a complete frame: `[len u32 BE][version u8][postcard]`.
///
/// The intermediate postcard buffer and the returned frame are both
/// [`Zeroizing`], so a serialized password is wiped rather than left in a
/// freed allocation.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    // Serialise into a buffer that is Zeroizing from the start and never
    // grows, so postcard's reallocations cannot leave an unwiped copy of a
    // key in freed memory. Start small — every real message is a few dozen
    // bytes — and grow once to the cap only if that is genuinely too small,
    // rather than allocating and wiping a megabyte per request.
    const SCRATCH: usize = 8 * 1024;
    let mut scratch = Zeroizing::new(vec![0u8; SCRATCH]);
    let body_len = match postcard::to_slice(msg, &mut scratch) {
        Ok(slice) => slice.len(),
        Err(postcard::Error::SerializeBufferFull) => {
            scratch = Zeroizing::new(vec![0u8; MAX_FRAME + 1]);
            match postcard::to_slice(msg, &mut scratch) {
                Ok(slice) => slice.len(),
                Err(postcard::Error::SerializeBufferFull) => {
                    return Err(ProtocolError::FrameTooLarge(MAX_FRAME + 1));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };
    // Readers check the on-wire length, which includes the version byte;
    // measure exactly that quantity here so both ends agree at the boundary.
    let framed_len = body_len + 1;
    if framed_len > MAX_FRAME {
        return Err(ProtocolError::FrameTooLarge(framed_len));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + framed_len));
    out.extend_from_slice(&(framed_len as u32).to_be_bytes());
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(&scratch[..body_len]);
    Ok(out)
}

/// Decodes a frame body produced by [`encode_frame`] (the bytes after the
/// length prefix, i.e. the version byte followed by the postcard payload).
pub fn decode_frame<T: DeserializeOwned>(body: &[u8]) -> Result<T, ProtocolError> {
    let (&version, rest) = body.split_first().ok_or(ProtocolError::Encoding(
        postcard::Error::DeserializeUnexpectedEnd,
    ))?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    // `from_bytes` stops at the end of the first complete message and ignores
    // whatever follows, so a peer could append arbitrary bytes to a valid
    // request and have it accepted. Nothing downstream is harmed by that
    // today — the length prefix is what delimits a frame, one message is read
    // per frame, and no frame is ever hashed, signed or compared — but a
    // frame that decodes must have been fully consumed, or "the frame that
    // was received" and "the message that was acted on" are different
    // objects. Found by the `protocol_frame` fuzz target.
    let (value, rest) = postcard::take_from_bytes(rest)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes(rest.len()));
    }
    Ok(value)
}

/// Reads one frame body. The buffer is [`Zeroizing`] because a request body
/// may carry a password or key.
pub fn read_frame_sync<R: Read>(r: &mut R) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
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

/// Socket for the current user: `$XDG_RUNTIME_DIR/secret-manager/control.sock`.
///
/// There is deliberately no `/tmp` fallback: a world-writable directory is not
/// a safe place to look for (or create) a socket that carries passwords.
pub fn socket_path() -> Result<PathBuf, ProtocolError> {
    let value = std::env::var_os("XDG_RUNTIME_DIR");
    socket_path_from(value.as_deref())
}

/// [`socket_path`] for an explicit `XDG_RUNTIME_DIR` value, so the rule can
/// be tested without mutating the process environment.
pub fn socket_path_from(runtime_dir: Option<&std::ffi::OsStr>) -> Result<PathBuf, ProtocolError> {
    match runtime_dir {
        Some(v) if !v.is_empty() => Ok(socket_path_for_runtime_dir(Path::new(v))),
        _ => Err(ProtocolError::NoRuntimeDir),
    }
}

/// Effective uid of the calling process.
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Reads the connected peer's credentials via `SO_PEERCRED`.
fn peer_uid(stream: &UnixStream) -> Result<u32, ProtocolError> {
    // SAFETY: ucred is plain data; all-zero is a valid initial value.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` owns a valid socket fd for the duration of the call, and
    // `cred`/`len` are live, correctly sized out-parameters for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(ProtocolError::Io(std::io::Error::last_os_error()));
    }
    Ok(cred.uid)
}

/// A blocking-socket timeout surfaces as `WouldBlock` on Linux; normalise it
/// so callers see one error kind for "the deadline ran out".
fn normalize_timeout(e: ProtocolError) -> ProtocolError {
    match e {
        ProtocolError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control socket call exceeded its deadline",
            ))
        }
        other => other,
    }
}

/// Blocking request/response over the control socket, verifying that the
/// listening peer runs as the current effective uid.
pub fn call(path: &Path, req: &Request) -> Result<Response, ProtocolError> {
    call_inner(path, req, effective_uid(), CALL_TIMEOUT)
}

/// [`call`] with an explicit overall deadline, for tests.
pub fn call_with_timeout(
    path: &Path,
    req: &Request,
    timeout: Duration,
) -> Result<Response, ProtocolError> {
    call_inner(path, req, effective_uid(), timeout)
}

/// Blocking request/response over the control socket, verifying that the
/// listening peer runs as `uid`.
///
/// The PAM module runs as root but must talk to the target user's daemon, so
/// it passes that user's uid explicitly rather than its own.
///
/// The whole exchange — connect, peer check, write, and read — is bounded by
/// [`CALL_TIMEOUT`]. A listener whose backlog is full and that never accepts
/// stalls `connect(2)` itself, so bounding only the read and write would
/// still let one hang a login.
pub fn call_expecting_uid(path: &Path, req: &Request, uid: u32) -> Result<Response, ProtocolError> {
    call_inner(path, req, uid, CALL_TIMEOUT)
}

/// [`call_expecting_uid`] with an explicit deadline, for a caller that is
/// already working to an overall budget — the PAM module bounds a whole login
/// hook, and a fixed per-call timeout would let a few calls overrun it.
pub fn call_expecting_uid_with_timeout(
    path: &Path,
    req: &Request,
    uid: u32,
    timeout: Duration,
) -> Result<Response, ProtocolError> {
    call_inner(path, req, uid, timeout)
}

fn call_inner(
    path: &Path,
    req: &Request,
    uid: u32,
    timeout: Duration,
) -> Result<Response, ProtocolError> {
    let deadline = Deadline::new(timeout);
    let mut stream = connect_with_deadline(path, deadline.remaining()?)?;

    let actual = peer_uid(&stream)?;
    if actual != uid {
        return Err(ProtocolError::UntrustedPeer {
            expected: uid,
            actual,
        });
    }

    let frame = encode_frame(req)?;
    let mut timed = TimedStream {
        inner: &mut stream,
        deadline: &deadline,
    };
    write_frame_sync(&mut timed, &frame).map_err(|e| normalize_timeout(e.into()))?;
    let body = read_frame_sync(&mut timed).map_err(normalize_timeout)?;
    decode_frame(&body)
}

/// A wall-clock budget for one call.
///
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` bound a single `read(2)`/`write(2)`, but
/// `read_exact` and `write_all` loop, so a peer that trickles one byte per
/// tick keeps every individual syscall inside its window while the operation
/// runs forever. Re-arming the socket timeout from the *remaining* budget
/// before each syscall makes the deadline mean what it says.
struct Deadline {
    start: Instant,
    budget: Duration,
}

impl Deadline {
    fn new(budget: Duration) -> Self {
        Self {
            start: Instant::now(),
            budget,
        }
    }

    fn remaining(&self) -> Result<Duration, ProtocolError> {
        self.budget
            .checked_sub(self.start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(deadline_error)
    }

    fn remaining_io(&self) -> std::io::Result<Duration> {
        self.budget
            .checked_sub(self.start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "control socket call exceeded its deadline",
                )
            })
    }
}

/// Wraps a stream so every read and write is re-armed from the remaining
/// budget, giving the whole transfer a single wall-clock deadline.
struct TimedStream<'a> {
    inner: &'a mut UnixStream,
    deadline: &'a Deadline,
}

impl Read for TimedStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner
            .set_read_timeout(Some(self.deadline.remaining_io()?))?;
        self.inner.read(buf)
    }
}

impl Write for TimedStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner
            .set_write_timeout(Some(self.deadline.remaining_io()?))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // A no-op for unix sockets today, but the deadline is re-armed anyway
        // so this method cannot become the one unbounded path if `inner` is
        // ever generalised.
        self.inner
            .set_write_timeout(Some(self.deadline.remaining_io()?))?;
        self.inner.flush()
    }
}

fn deadline_error() -> ProtocolError {
    ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "control socket call exceeded its deadline",
    ))
}

/// Fills a `sockaddr_un` for `path`.
fn unix_addr(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t), ProtocolError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is plain data; all-zero is a valid initial value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if bytes.is_empty() {
        return Err(ProtocolError::Connect(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty control socket path",
        )));
    }
    if bytes.len() >= addr.sun_path.len() {
        return Err(ProtocolError::Connect(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control socket path is too long for sockaddr_un",
        )));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Ok((addr, len))
}

/// `connect(2)` on a unix stream socket blocks for as long as the listener's
/// backlog stays full, with no timeout of its own — so a same-uid process
/// that binds the socket, never accepts, and lets the queue fill would
/// otherwise hang the caller (the PAM module, inside a login) forever.
/// Connect on a non-blocking socket instead, retrying while the kernel
/// reports a full queue and waiting for writability if the connect is merely
/// in progress, all inside `deadline`.
fn connect_with_deadline(path: &Path, deadline: Duration) -> Result<UnixStream, ProtocolError> {
    use std::os::fd::FromRawFd;
    let (addr, addr_len) = unix_addr(path)?;
    let start = Instant::now();
    loop {
        // SAFETY: plain syscall with constant flags and no pointer arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(ProtocolError::Connect(std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` is a fresh socket we own; wrapping it here means every
        // path below closes it exactly once, when `stream` drops.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        // SAFETY: `addr` is an initialised sockaddr_un of `addr_len` bytes and
        // `fd` is a valid socket for the duration of the call.
        let rc = unsafe { libc::connect(fd, (&raw const addr).cast::<libc::sockaddr>(), addr_len) };
        if rc == 0 {
            stream.set_nonblocking(false)?;
            return Ok(stream);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // PORTABILITY ARMOUR — DEAD ON LINUX AF_UNIX. Do not read this
            // arm as a path the daemon takes: it does not execute here, and
            // it is not covered by any test. Linux's `unix_stream_connect`
            // answers a non-blocking connect to a listener whose backlog is
            // full with EAGAIN (the arm below), and every other outcome is
            // either success or a terminal error. EINPROGRESS is what a
            // non-blocking connect on a *connection-oriented network* socket
            // returns, so the arm is kept for the day this path is reused for
            // one, and because a kernel that did report it would otherwise
            // fall into the catch-all and turn a connect in progress into a
            // hard failure. `wait_writable` is unit-tested directly for the
            // same reason: if this ever does execute, its logic is proven.
            Some(libc::EINPROGRESS) => {
                wait_writable(fd, remaining_or_timeout(start, deadline)?)?;
                let mut so_error: libc::c_int = 0;
                let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                // SAFETY: valid fd with correctly sized out-parameters.
                let rc = unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&raw mut so_error).cast::<libc::c_void>(),
                        &mut len,
                    )
                };
                if rc != 0 {
                    return Err(ProtocolError::Connect(std::io::Error::last_os_error()));
                }
                if so_error != 0 {
                    return Err(ProtocolError::Connect(std::io::Error::from_raw_os_error(
                        so_error,
                    )));
                }
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            // The listener's backlog is full (this is what a blocking connect
            // would wait out); retry with a fresh socket until the deadline.
            Some(libc::EAGAIN) | Some(libc::EINTR) => {
                drop(stream);
                let left = remaining_or_timeout(start, deadline)?;
                std::thread::sleep(left.min(Duration::from_millis(20)));
            }
            _ => return Err(ProtocolError::Connect(err)),
        }
    }
}

/// Time left before `deadline`, or a connect timeout once it is spent.
fn remaining_or_timeout(start: Instant, deadline: Duration) -> Result<Duration, ProtocolError> {
    deadline
        .checked_sub(start.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            ProtocolError::Connect(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connecting to the control socket exceeded its deadline",
            ))
        })
}

/// Waits for `fd` to become writable, giving up once `deadline` is spent.
fn wait_writable(fd: std::os::fd::RawFd, budget: Duration) -> Result<(), ProtocolError> {
    let start = Instant::now();
    loop {
        let left = remaining_or_timeout(start, budget)?;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = left.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: one valid, live pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, millis.max(1)) };
        if rc > 0 {
            // Deliberately `Ok` for any ready event, not only POLLOUT: a
            // failed connect reports POLLERR (or POLLNVAL for a closed fd),
            // and this returns "no longer waiting", not "connected". The one
            // caller must therefore read SO_ERROR before treating the socket
            // as usable — reusing this function without that check would turn
            // a failed connect into a silently broken stream.
            return Ok(());
        }
        if rc == 0 {
            continue; // the deadline is re-checked at the top of the loop
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(ProtocolError::Connect(err));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::net::UnixListener;

    #[test]
    fn frame_round_trip() {
        let req = Request::UnlockWithKey {
            collection: "default".into(),
            key: Zeroizing::new([7u8; KEY_LEN]),
        };
        let bytes = encode_frame(&req).unwrap();
        assert_eq!(&bytes[..4], &((bytes.len() - 4) as u32).to_be_bytes());
        assert_eq!(bytes[4], PROTOCOL_VERSION);
        let mut cur = Cursor::new(bytes.to_vec());
        let body = read_frame_sync(&mut cur).unwrap();
        let back: Request = decode_frame(&body).unwrap();
        match back {
            Request::UnlockWithKey { collection, key } => {
                assert_eq!(collection, "default");
                assert_eq!(*key, [7u8; KEY_LEN]);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// The protocol carries no password anywhere: the wire request set is
    /// exactly `Lock`, `Status`, `Reload`, `UnlockWithKey`, `ChangeKey`.
    ///
    /// The version is pinned alongside it deliberately. It is not what this
    /// test is about — the request set is — but the wire format and the
    /// version have to move together, so changing one without the other
    /// should fail here and make it a decision rather than an accident.
    /// v3 → v4 added `Response::Status::aliases_error`, so that a corrupt
    /// `aliases.toml` can be reported instead of refusing to start the daemon.
    #[test]
    fn the_protocol_has_no_password_requests() {
        assert_eq!(PROTOCOL_VERSION, 4);
        let names: Vec<&str> = REQUEST_VARIANTS.to_vec();
        assert_eq!(
            names,
            ["Lock", "Status", "Reload", "UnlockWithKey", "ChangeKey"]
        );
        let status = Response::Status {
            aliases_error: None,
            collections: vec![CollectionStatus {
                id: "d".into(),
                label: "D".into(),
                locked: true,
                items: 0,
                warning: Some("index rewrite failed".into()),
            }],
            uptime_secs: 1,
        };
        let body =
            read_frame_sync(&mut Cursor::new(encode_frame(&status).unwrap().to_vec())).unwrap();
        assert_eq!(decode_frame::<Response>(&body).unwrap(), status);
    }

    /// A body of exactly MAX_FRAME bytes must be accepted by the reader if
    /// the encoder accepted it; the two checks measure the same quantity.
    #[test]
    fn frame_size_limit_agrees_between_encoder_and_reader() {
        let payload = "a".repeat(MAX_FRAME);
        let req = Request::Lock {
            collection: Some(payload),
        };
        match encode_frame(&req) {
            Ok(frame) => {
                read_frame_sync(&mut Cursor::new(frame.to_vec()))
                    .expect("reader must accept what the encoder produced");
            }
            Err(ProtocolError::FrameTooLarge(n)) => assert!(n > MAX_FRAME),
            Err(e) => panic!("{e}"),
        }
        // And a frame the encoder emits at the very edge round-trips.
        let n = MAX_FRAME - 16;
        let req = Request::Lock {
            collection: Some("b".repeat(n)),
        };
        let frame = encode_frame(&req).unwrap();
        read_frame_sync(&mut Cursor::new(frame.to_vec())).unwrap();
    }

    /// `SO_RCVTIMEO` bounds one `read(2)`, not the whole transfer, so a peer
    /// that answers with one byte per tick would keep `read_exact` alive
    /// indefinitely while never exceeding the per-syscall window. The call
    /// must be bounded by wall-clock time, not by syscall inactivity.
    #[test]
    fn call_deadline_bounds_a_drip_feeding_listener() {
        let dir = test_dir("drip");
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut len = [0u8; 4];
            if s.read_exact(&mut len).is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            let mut body = vec![0u8; n];
            if s.read_exact(&mut body).is_err() {
                return;
            }
            // Announce a large frame, then dribble a byte at a time, always
            // well inside the per-read window.
            if s.write_all(&600u32.to_be_bytes()).is_err() {
                return;
            }
            let _ = s.flush();
            while stop_rx.try_recv().is_err() {
                if s.write_all(&[0u8]).is_err() || s.flush().is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        let start = Instant::now();
        let err = call_with_timeout(&sock, &Request::Status, Duration::from_millis(500))
            .expect_err("a drip-feeding peer must not satisfy the call");
        let elapsed = start.elapsed();
        let _ = stop_tx.send(());
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
        match err {
            ProtocolError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}"),
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(3),
            "the deadline did not bound the read: {elapsed:?}"
        );
    }

    /// A listener that never accepts, with a full backlog, stalls `connect(2)`
    /// itself — the case a read/write timeout cannot cover. The filler
    /// connections run on detached threads precisely because a blocking
    /// connect to such a listener is what never returns.
    #[test]
    fn call_gives_up_when_the_listener_never_accepts() {
        let dir = test_dir("no-accept");
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        // SAFETY: shrinking the backlog of a listening socket we own.
        unsafe { libc::listen(listener.as_raw_fd(), 0) };
        for _ in 0..8 {
            let s = sock.clone();
            std::thread::spawn(move || {
                let _ = UnixStream::connect(&s);
                std::thread::sleep(Duration::from_secs(60));
            });
        }
        std::thread::sleep(Duration::from_millis(300));

        let start = Instant::now();
        let err =
            call_with_timeout(&sock, &Request::Status, Duration::from_millis(500)).unwrap_err();
        let elapsed = start.elapsed();
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
        match err {
            ProtocolError::Io(e) | ProtocolError::Connect(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}")
            }
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
    }

    #[test]
    fn foreign_protocol_version_is_rejected() {
        let mut body = encode_frame(&Request::Status).unwrap().to_vec();
        body[4] = PROTOCOL_VERSION + 1;
        let err = decode_frame::<Request>(&body[4..]).unwrap_err();
        assert!(
            matches!(err, ProtocolError::UnsupportedVersion(v) if v == PROTOCOL_VERSION + 1),
            "expected UnsupportedVersion, got {err:?}"
        );
    }

    #[test]
    fn empty_frame_body_is_rejected() {
        let err = decode_frame::<Request>(&[]).unwrap_err();
        assert!(matches!(err, ProtocolError::Encoding(_)), "got {err:?}");
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut bytes = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let err = read_frame_sync(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge(_)));
    }

    #[test]
    fn encoding_an_oversized_message_is_rejected() {
        let req = Request::Lock {
            collection: Some("a".repeat(MAX_FRAME + 1)),
        };
        let err = encode_frame(&req).unwrap_err();
        assert!(
            matches!(err, ProtocolError::FrameTooLarge(n) if n > MAX_FRAME),
            "got {err:?}"
        );
    }

    #[test]
    fn request_debug_redacts_secrets() {
        let unlock = Request::UnlockWithKey {
            collection: "default".into(),
            key: Zeroizing::new([0xab; KEY_LEN]),
        };
        let rendered = format!("{unlock:?}");
        assert!(!rendered.contains("171"), "leaked: {rendered}");
        assert!(rendered.contains("key: \"<redacted>\""), "got {rendered}");
        assert!(rendered.contains("default"));

        let change = Request::ChangeKey {
            collection: "default".into(),
            old_key: Zeroizing::new([0xab; KEY_LEN]),
            new_salt: [0xcd; SALT_LEN],
            new_kdf: KdfParams::default(),
            new_key: Zeroizing::new([0xef; KEY_LEN]),
        };
        let rendered = format!("{change:?}");
        assert!(
            !rendered.contains("171") && !rendered.contains("205") && !rendered.contains("239"),
            "leaked: {rendered}"
        );
        assert!(
            rendered.contains("old_key: \"<redacted>\""),
            "got {rendered}"
        );
        assert!(
            rendered.contains("new_key: \"<redacted>\""),
            "got {rendered}"
        );
        assert!(
            rendered.contains("new_salt: \"<redacted>\""),
            "got {rendered}"
        );
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
    fn socket_path_from_env_value() {
        assert_eq!(
            socket_path_from(Some(std::ffi::OsStr::new("/run/user/4242"))).unwrap(),
            PathBuf::from("/run/user/4242/secret-manager/control.sock")
        );
        assert!(matches!(
            socket_path_from(None),
            Err(ProtocolError::NoRuntimeDir)
        ));
        assert!(matches!(
            socket_path_from(Some(std::ffi::OsStr::new(""))),
            Err(ProtocolError::NoRuntimeDir)
        ));
        assert_eq!(
            ProtocolError::NoRuntimeDir.to_string(),
            "XDG_RUNTIME_DIR is not set; cannot locate the control socket"
        );
    }

    /// A private directory per test. `std::env::temp_dir()` with a
    /// predictable name would let another user on a shared `/tmp` pre-create
    /// it and watch the sockets these tests bind.
    fn test_dir(tag: &str) -> PathBuf {
        let dir = tempfile::Builder::new()
            .prefix(&format!("cp-test-{tag}-"))
            .tempdir()
            .unwrap()
            .keep();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn blocking_call_round_trip() {
        let dir = test_dir("round-trip");
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_frame_sync(&mut stream).unwrap();
            let req: Request = decode_frame(&body).unwrap();
            assert!(matches!(req, Request::Status));
            let resp = Response::Status {
                aliases_error: None,
                collections: vec![],
                uptime_secs: 7,
            };
            stream.write_all(&encode_frame(&resp).unwrap()).unwrap();
        });
        let resp = call(&sock, &Request::Status).unwrap();
        assert_eq!(
            resp,
            Response::Status {
                aliases_error: None,
                collections: vec![],
                uptime_secs: 7
            }
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn call_rejects_a_peer_with_the_wrong_uid() {
        let dir = test_dir("peer-uid");
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        // The listener runs as us, so demanding a different uid must fail.
        let err = call_expecting_uid(&sock, &Request::Status, effective_uid() ^ 1).unwrap_err();
        match err {
            ProtocolError::UntrustedPeer { expected, actual } => {
                assert_eq!(expected, effective_uid() ^ 1);
                assert_eq!(actual, effective_uid());
            }
            other => panic!("expected UntrustedPeer, got {other:?}"),
        }
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn call_gives_up_when_the_daemon_never_replies() {
        let dir = test_dir("deadline");
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let accepted = listener.accept();
            // Hold the connection open, reply to nothing.
            let _ = done_rx.recv_timeout(CALL_TIMEOUT * 4);
            drop(accepted);
        });
        let start = Instant::now();
        let err = call(&sock, &Request::Status).unwrap_err();
        let elapsed = start.elapsed();
        drop(done_tx);
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&dir);
        match err {
            ProtocolError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}"),
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(
            elapsed < CALL_TIMEOUT + Duration::from_secs(1),
            "call took {elapsed:?}, expected roughly {CALL_TIMEOUT:?}"
        );
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

    /// The path comes from `XDG_RUNTIME_DIR`, which the PAM module treats as
    /// hostile. Both shapes must be refused in `unix_addr`: the copy loop
    /// below the guards writes no terminator of its own, so an over-long
    /// path would leave `sun_path` unterminated and an empty one would name
    /// the abstract namespace rather than the file we mean.
    #[test]
    fn a_socket_path_that_cannot_fit_sockaddr_un_is_refused() {
        let invalid = |path: &Path| match call(path, &Request::Status).unwrap_err() {
            ProtocolError::Connect(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}")
            }
            other => panic!("expected Connect, got {other:?}"),
        };
        invalid(Path::new(""));
        // 256 bytes: over the 108-byte `sun_path`, and never truncated into
        // some shorter path that happens to exist.
        let long = PathBuf::from(format!("/{}", "a".repeat(255)));
        assert_eq!(long.as_os_str().len(), 256);
        invalid(&long);
    }

    /// The PAM module passes the remaining slice of a whole-login budget, so
    /// a call can be entered with nothing left. It must fail before
    /// connecting rather than connect and then arm a zero — that is,
    /// unbounded — socket timeout, even against a listener that would answer.
    #[test]
    fn a_call_entered_with_a_spent_budget_fails_before_connecting() {
        let dir = test_dir("spent-budget");
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let start = Instant::now();
        let err = call_with_timeout(&sock, &Request::Status, Duration::ZERO).unwrap_err();
        let elapsed = start.elapsed();
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
        match err {
            ProtocolError::Io(e) | ProtocolError::Connect(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}")
            }
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_millis(200),
            "a spent budget must fail immediately, took {elapsed:?}"
        );
    }
    /// postcard stops at the end of the first complete message, so before
    /// this was fixed a peer could append anything it liked to a valid
    /// request and have it accepted. Not exploitable as the protocol stands,
    /// but a frame that decodes should have been consumed in full. Found by
    /// the `protocol_frame` fuzz target.
    #[test]
    fn trailing_bytes_after_a_complete_message_are_refused() {
        let frame = encode_frame(&Response::Ok).unwrap();
        let body = &frame[4..];
        assert!(matches!(decode_frame::<Response>(body), Ok(Response::Ok)));

        let mut with_junk = body.to_vec();
        with_junk.extend_from_slice(&[0xff, 0xff, 0xff]);
        match decode_frame::<Response>(&with_junk) {
            Err(ProtocolError::TrailingBytes(3)) => {}
            other => panic!("expected TrailingBytes(3), got {other:?}"),
        }

        // A single stray byte counts too.
        let mut one = body.to_vec();
        one.push(0);
        assert!(matches!(
            decode_frame::<Response>(&one),
            Err(ProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn response_variant_name_names_every_variant() {
        assert_eq!(Response::Ok.variant_name(), "Ok");
        assert_eq!(
            Response::Status {
                aliases_error: None,
                collections: vec![],
                uptime_secs: 0,
            }
            .variant_name(),
            "Status"
        );
        assert_eq!(Response::Error("boom".into()).variant_name(), "Error");
        // The point of the name is that it can be logged when the payload
        // cannot: it must never carry any of it.
        assert_eq!(
            Response::Error("s3cret".into()).variant_name(),
            Response::Error(String::new()).variant_name()
        );
    }

    /// The encoder's own limit is on the *framed* length — the postcard body
    /// plus the version byte — so a body of exactly `MAX_FRAME` is one byte
    /// too long. Without that check the frame would go out with a length
    /// prefix a byte short of its own body.
    #[test]
    fn a_body_of_exactly_max_frame_is_one_byte_too_long_to_frame() {
        // Lock: 1 variant byte + 1 `Some` tag + 3 varint length bytes + payload.
        let req = Request::Lock {
            collection: Some("a".repeat(MAX_FRAME - 5)),
        };
        let mut scratch = vec![0u8; MAX_FRAME + 64];
        let body = postcard::to_slice(&req, &mut scratch).unwrap();
        assert_eq!(
            body.len(),
            MAX_FRAME,
            "this test needs a body of exactly MAX_FRAME"
        );
        let err = encode_frame(&req).unwrap_err();
        assert!(
            matches!(err, ProtocolError::FrameTooLarge(n) if n == MAX_FRAME + 1),
            "got {err:?}"
        );
    }

    /// Serializes `self.0` filler bytes and then fails with an error that is
    /// *not* `SerializeBufferFull`, so both scratch buffers in `encode_frame`
    /// — the 8 KiB first attempt and the grown retry — can be driven into a
    /// serializer failure that is not about size.
    struct FailsAfter(usize);

    impl Serialize for FailsAfter {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            use serde::ser::{Error, SerializeSeq};
            let mut seq = s.serialize_seq(Some(self.0))?;
            for _ in 0..self.0 {
                seq.serialize_element(&0u8)?;
            }
            Err(S::Error::custom("this type never finishes serializing"))
        }
    }

    /// A serializer failure must be reported as what it is. `encode_frame`
    /// retries in a larger buffer when the first attempt runs out of room, and
    /// a failure in that retry must not be laundered into a size error — the
    /// caller would go looking for an oversized message that does not exist.
    #[test]
    fn a_serializer_failure_is_reported_as_an_encoding_error_in_both_buffers() {
        // Fails inside the first, 8 KiB buffer.
        let err = encode_frame(&FailsAfter(0)).unwrap_err();
        assert!(matches!(err, ProtocolError::Encoding(_)), "got {err:?}");

        // Overruns the first buffer, then fails inside the grown one.
        let big = FailsAfter(9000);
        let mut small = [0u8; 8 * 1024];
        assert!(
            matches!(
                postcard::to_slice(&big, &mut small),
                Err(postcard::Error::SerializeBufferFull)
            ),
            "this test needs a value that overruns the first scratch buffer"
        );
        let err = encode_frame(&big).unwrap_err();
        assert!(matches!(err, ProtocolError::Encoding(_)), "got {err:?}");
    }

    /// A blocking-socket deadline surfaces as `WouldBlock`, which reads like a
    /// spurious failure; it is rewritten to `TimedOut`. Nothing else is: a
    /// caller must still be able to tell a broken pipe from a slow daemon.
    #[test]
    fn normalize_timeout_rewrites_only_a_spent_deadline() {
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            match normalize_timeout(ProtocolError::Io(std::io::Error::new(kind, "x"))) {
                ProtocolError::Io(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
                    assert!(e.to_string().contains("deadline"), "{e}");
                }
                other => panic!("expected Io, got {other:?}"),
            }
        }
        match normalize_timeout(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "the daemon exited",
        ))) {
            ProtocolError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
                assert!(e.to_string().contains("the daemon exited"), "{e}");
            }
            other => panic!("expected Io, got {other:?}"),
        }
        let err = normalize_timeout(ProtocolError::UnsupportedVersion(9));
        assert!(
            matches!(err, ProtocolError::UnsupportedVersion(9)),
            "got {err:?}"
        );
    }

    /// `wait_writable` is only reached from the `EINPROGRESS` arm of
    /// `connect_with_deadline`, which Linux never takes for `AF_UNIX` (a full
    /// backlog is reported as `EAGAIN`), so it is exercised directly here.
    #[test]
    fn wait_writable_returns_at_once_for_a_writable_socket() {
        let (a, _b) = UnixStream::pair().unwrap();
        let start = Instant::now();
        wait_writable(a.as_raw_fd(), Duration::from_secs(5))
            .expect("a fresh socketpair must be writable");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// The poll loop re-checks its own budget, so a socket that never becomes
    /// writable fails on the deadline instead of waiting forever — this is the
    /// case that would otherwise hang a login.
    #[test]
    fn wait_writable_gives_up_once_its_budget_is_spent() {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        // Fill the send buffer: with no reader on `b`, the fd stops being
        // writable and stays that way.
        let chunk = [0u8; 64 * 1024];
        loop {
            match (&a).write(&chunk) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("unexpected write error: {e}"),
            }
        }
        let start = Instant::now();
        let err = wait_writable(a.as_raw_fd(), Duration::from_millis(50)).unwrap_err();
        let elapsed = start.elapsed();
        drop(b);
        match err {
            ProtocolError::Connect(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
                assert!(e.to_string().contains("deadline"), "{e}");
            }
            other => panic!("expected Connect, got {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "the budget did not bound the wait: {elapsed:?}"
        );
    }
}
