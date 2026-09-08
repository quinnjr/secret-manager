//! Minimal Assuan client that drives a `pinentry` binary.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

/// How long one dialog may stay on screen while holding the process-wide
/// pinentry lock. A client that raises a dialog and never answers would
/// otherwise block every unlock in the daemon forever; on expiry the child is
/// dropped (`kill_on_drop`) and the request reports a cancellation.
///
/// This is the *hold* budget. The *wait* budget is [`DEFAULT_QUEUE_TIMEOUT`],
/// and the two must not be equal — see there.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// How much longer a queued request waits for the dialog lock than a single
/// dialog may hold it: `queue budget = dialog budget * QUEUE_TIMEOUT_FACTOR`.
///
/// It must be **greater than 1**, and that is the whole point of the
/// constant. When the two budgets were equal, a client that raised a dialog
/// nobody answered held the lock for the full hold budget while the user's own
/// prompt — queued behind it, `tokio::sync::Mutex` being FIFO — ran out its
/// identical budget at the same instant, and was reported as *dismissed by the
/// user* without a dialog ever being drawn. A waiter can only win if its
/// budget outlasts the holder's.
///
/// 5 is chosen against the worst case a *single* holder can construct:
/// [`Pinentry::session`] keeps the lock across an unlock's three password
/// attempts, so one occupancy is worth up to three hold budgets (6 min).
/// Five hold budgets (10 min) clears that with room for the derivation
/// between attempts, and stays finite so a waiter still cannot wedge forever.
/// No finite budget can beat an unbounded *queue* of hostile waiters — FIFO
/// puts the victim behind all of them — so the guarantee is one full hostile
/// occupancy survived, not starvation-freedom.
const QUEUE_TIMEOUT_FACTOR: u32 = 5;

/// How long a request waits for the process-wide dialog lock before giving up
/// with [`PinentryError::Busy`]. Deliberately several times
/// [`DEFAULT_TIMEOUT`]; see [`QUEUE_TIMEOUT_FACTOR`].
pub const DEFAULT_QUEUE_TIMEOUT: Duration =
    Duration::from_secs(DEFAULT_TIMEOUT.as_secs() * QUEUE_TIMEOUT_FACTOR as u64);

#[derive(Debug, Clone, Default)]
pub struct PinRequest {
    pub title: String,
    pub description: String,
    pub prompt: String,
    pub error: Option<String>,
    /// Ask twice and require both entries to match (new passwords).
    pub repeat: bool,
}

pub enum PinOutcome {
    Pin(Zeroizing<String>),
    Cancelled,
}

impl std::fmt::Debug for PinOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinOutcome::Pin(_) => write!(f, "PinOutcome::Pin(..)"),
            PinOutcome::Cancelled => write!(f, "PinOutcome::Cancelled"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PinentryError {
    #[error("cannot start {program}: {source}")]
    Spawn {
        program: PathBuf,
        source: std::io::Error,
    },
    #[error("pinentry i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("pinentry protocol error: {0}")]
    Protocol(String),
    #[error("pinentry error {code}: {message}")]
    Assuan { code: u32, message: String },
    /// Gave up waiting for the process-wide dialog lock: another dialog was on
    /// screen for longer than this request's queue budget, so **no dialog was
    /// ever shown to the user**.
    ///
    /// A separate variant on purpose. Reporting this as
    /// [`PinOutcome::Cancelled`] told the user they had dismissed a prompt
    /// they were never offered, which is exactly what a client that parks an
    /// unanswered dialog wants the daemon to say.
    #[error("no dialog could be shown: another pinentry dialog is still open")]
    Busy,
}

#[derive(Debug, Clone)]
pub struct Pinentry {
    program: PathBuf,
    env: Vec<(OsString, OsString)>,
    /// One dialog at a time: clones share the lock, so every prompt raised
    /// through the daemon's `Pinentry` queues behind the one on screen.
    dialog: Arc<tokio::sync::Mutex<()>>,
    /// Upper bound on a single dialog, so the shared `dialog` lock is always
    /// released again (see [`DEFAULT_TIMEOUT`]).
    timeout: Duration,
    /// Upper bound on *waiting* for that lock. Strictly larger than `timeout`
    /// (see [`QUEUE_TIMEOUT_FACTOR`]) so a queued request outlasts the holder
    /// it is queued behind.
    queue_timeout: Duration,
}

/// An acquired dialog slot: while this is alive no other dialog can be raised
/// through the same [`Pinentry`] (or any clone of it).
///
/// Exists so a retry loop — "wrong password, try again" — keeps the slot it
/// already won instead of releasing it between attempts and re-queueing
/// behind everyone who arrived while the user was typing.
pub struct DialogSession {
    pinentry: Pinentry,
    _slot: tokio::sync::OwnedMutexGuard<()>,
}

impl DialogSession {
    /// Like [`Pinentry::ask`], but on the slot this session already holds.
    pub async fn ask(&self, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
        self.pinentry.ask_held(req).await
    }

    /// Like [`Pinentry::confirm`], but on the slot this session already holds.
    pub async fn confirm(&self, req: &PinRequest) -> Result<bool, PinentryError> {
        self.pinentry.confirm_held(req).await
    }
}

/// GPG_ERR_CANCELED is 99 in the low 16 bits of an Assuan error code.
pub fn is_cancel(code: u32) -> bool {
    code & 0xFFFF == 99
}

/// Assuan-escape a string for use as a command argument.
///
/// `%` must be escaped because it introduces an escape, and every byte below
/// `0x20` plus `0x7f` because they are not representable on an Assuan line —
/// a raw newline ends the line and injects a further command, and the rest
/// reach the dialog as terminal control sequences. `askpass` puts a fully
/// attacker-controlled string into a description, so the whole C0 range is
/// escaped rather than just `\n` and `\r` (LOW 1).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("%{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Decodes Assuan `%XX` escapes. The result (and the working buffer) are
/// [`Zeroizing`], since this is how a PIN arrives.
pub fn unescape(s: &str) -> Result<Zeroizing<String>, PinentryError> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or_else(|| PinentryError::Protocol("truncated escape".into()))?;
            let hex = std::str::from_utf8(hex)
                .map_err(|_| PinentryError::Protocol("bad escape".into()))?;
            let v = u8::from_str_radix(hex, 16)
                .map_err(|_| PinentryError::Protocol(format!("bad escape %{hex}")))?;
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    std::str::from_utf8(&out)
        .map(|s| Zeroizing::new(s.to_string()))
        .map_err(|_| PinentryError::Protocol("pin is not utf-8".into()))
}

impl Pinentry {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            env: Vec::new(),
            dialog: Arc::new(tokio::sync::Mutex::new(())),
            timeout: DEFAULT_TIMEOUT,
            queue_timeout: DEFAULT_QUEUE_TIMEOUT,
        }
    }

    /// Override [`DEFAULT_TIMEOUT`] for this handle (and its clones).
    ///
    /// The queue budget moves with it, keeping the [`QUEUE_TIMEOUT_FACTOR`]
    /// ratio: the two budgets exist in relation to each other, and setting one
    /// down to a test-sized value while the other stayed at ten minutes would
    /// be a trap. [`Pinentry::with_queue_timeout`] overrides it explicitly.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.queue_timeout = timeout.saturating_mul(QUEUE_TIMEOUT_FACTOR);
        self
    }

    /// Override the wait-for-the-dialog-lock budget alone. Call it *after*
    /// [`Pinentry::with_timeout`], which resets it.
    pub fn with_queue_timeout(mut self, queue_timeout: Duration) -> Self {
        self.queue_timeout = queue_timeout;
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Take the process-wide dialog slot, so a caller that raises several
    /// dialogs in a row (an unlock retrying a mistyped password) keeps it
    /// across all of them.
    ///
    /// Bounded by the queue budget like [`Pinentry::ask`], and fails with
    /// [`PinentryError::Busy`] rather than pretending the user answered.
    pub async fn session(&self) -> Result<DialogSession, PinentryError> {
        Ok(DialogSession {
            pinentry: self.clone(),
            _slot: self.acquire().await?,
        })
    }

    /// Wait for the shared dialog slot, bounded by the *queue* budget.
    ///
    /// Waiting must be bounded — a client that raised a dialog and never
    /// answered would otherwise block every other unlock in the daemon
    /// forever (HIGH 3) — but the bound must not be the dialog's own budget:
    /// the waiter then expires no later than the holder is killed and never
    /// gets its turn. See [`QUEUE_TIMEOUT_FACTOR`].
    async fn acquire(&self) -> Result<tokio::sync::OwnedMutexGuard<()>, PinentryError> {
        match tokio::time::timeout(self.queue_timeout, self.dialog.clone().lock_owned()).await {
            Ok(slot) => Ok(slot),
            Err(_) => {
                tracing::warn!(
                    "another pinentry dialog held the screen for longer than {:?}; \
                     giving up without showing one",
                    self.queue_timeout
                );
                Err(PinentryError::Busy)
            }
        }
    }

    /// Ask for a password. A dialog that outlives [`Pinentry::with_timeout`]
    /// is abandoned — the child is dropped, which kills it — and reported as
    /// a cancellation, so one unanswered dialog cannot wedge the daemon.
    ///
    /// Failing to get a slot at all is [`PinentryError::Busy`], never a
    /// cancellation: no dialog was shown, so the user cancelled nothing.
    pub async fn ask(&self, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
        let _one_at_a_time = self.acquire().await?;
        self.ask_held(req).await
    }

    /// [`Pinentry::ask`] with the dialog slot already held by the caller.
    async fn ask_held(&self, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
        let work = async {
            let mut conn = self.connect().await?;
            conn.setup(req).await?;
            if req.repeat {
                conn.command_lenient("SETREPEAT Repeat:").await?;
            }
            let outcome = match conn.getpin().await {
                Ok(pin) => PinOutcome::Pin(pin),
                Err(PinentryError::Assuan { code, .. }) if is_cancel(code) => PinOutcome::Cancelled,
                Err(e) => return Err(e),
            };
            conn.bye().await;
            Ok(outcome)
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("pinentry dialog timed out; treating it as cancelled");
                Ok(PinOutcome::Cancelled)
            }
        }
    }

    /// Yes/no question. Cancel or a timeout on the dialog itself means "no";
    /// never getting a dialog at all is [`PinentryError::Busy`], which every
    /// caller must still treat as "not confirmed" — the difference is what the
    /// user is told, not whether the destructive thing happens.
    pub async fn confirm(&self, req: &PinRequest) -> Result<bool, PinentryError> {
        let _one_at_a_time = self.acquire().await?;
        self.confirm_held(req).await
    }

    /// [`Pinentry::confirm`] with the dialog slot already held by the caller.
    async fn confirm_held(&self, req: &PinRequest) -> Result<bool, PinentryError> {
        let work = async {
            let mut conn = self.connect().await?;
            conn.setup(req).await?;
            let ok = match conn.command("CONFIRM").await {
                Ok(()) => true,
                Err(PinentryError::Assuan { .. }) => false,
                Err(e) => return Err(e),
            };
            conn.bye().await;
            Ok(ok)
        };
        match tokio::time::timeout(self.timeout, work).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("pinentry confirmation timed out; treating it as refused");
                Ok(false)
            }
        }
    }

    async fn connect(&self) -> Result<Assuan, PinentryError> {
        let mut cmd = Command::new(&self.program);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|source| PinentryError::Spawn {
            program: self.program.clone(),
            source,
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PinentryError::Protocol("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PinentryError::Protocol("no stdout".into()))?;
        let mut conn = Assuan {
            _child: child,
            stdin,
            stdout: BufReader::new(stdout),
        };
        conn.expect_ok().await?; // greeting
        for opt in tty_options() {
            conn.command_lenient(&opt).await?;
        }
        Ok(conn)
    }
}

/// Options that let pinentry-curses/tty find the terminal and locale.
fn tty_options() -> Vec<String> {
    tty_options_from(|name| std::env::var(name).ok())
}

/// `tty_options` over an arbitrary environment lookup, so it is testable
/// without mutating the process environment.
///
/// Every value is Assuan-escaped like any other argument, and a value holding
/// a control character is dropped entirely rather than escaped: these come
/// from the daemon's environment, and an unescaped newline would end the
/// `OPTION` line and inject a further Assuan command.
fn tty_options_from(var: impl Fn(&str) -> Option<String>) -> Vec<String> {
    fn usable(v: &str) -> bool {
        !v.is_empty() && !v.chars().any(char::is_control)
    }
    let mut opts = Vec::new();
    if let Some(tty) = var("GPG_TTY").filter(|v| usable(v)) {
        opts.push(format!("OPTION ttyname={}", escape(&tty)));
    }
    if let Some(term) = var("TERM").filter(|v| usable(v)) {
        opts.push(format!("OPTION ttytype={}", escape(&term)));
    }
    let ctype = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|v| var(v).filter(|s| usable(s)));
    if let Some(c) = ctype {
        opts.push(format!("OPTION lc-ctype={}", escape(&c)));
    }
    opts
}

enum Reply {
    Ok,
    /// Still Assuan-escaped; wiped on drop because `GETPIN` answers here.
    Data(Zeroizing<String>),
    Err {
        code: u32,
        message: String,
    },
}

struct Assuan {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Assuan {
    async fn setup(&mut self, req: &PinRequest) -> Result<(), PinentryError> {
        if !req.title.is_empty() {
            self.command_lenient(&format!("SETTITLE {}", escape(&req.title)))
                .await?;
        }
        self.command(&format!("SETDESC {}", escape(&req.description)))
            .await?;
        self.command(&format!("SETPROMPT {}", escape(&req.prompt)))
            .await?;
        if let Some(e) = &req.error {
            self.command_lenient(&format!("SETERROR {}", escape(e)))
                .await?;
        }
        Ok(())
    }

    async fn send(&mut self, line: &str) -> Result<(), PinentryError> {
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_reply(&mut self) -> Result<Reply, PinentryError> {
        loop {
            // Pre-allocate so a reply that spans multiple reallocations
            // doesn't leave unwiped prefix copies of a PIN behind in freed
            // heap memory.
            let mut line = Zeroizing::new(String::with_capacity(1024));
            let n = self.stdout.read_line(&mut line).await?;
            if n == 0 {
                return Err(PinentryError::Protocol(
                    "pinentry closed the connection".into(),
                ));
            }
            let line = line.trim_end_matches(['\n', '\r']);
            if line == "OK" || line.starts_with("OK ") {
                return Ok(Reply::Ok);
            }
            if let Some(rest) = line.strip_prefix("D ") {
                return Ok(Reply::Data(Zeroizing::new(rest.to_string())));
            }
            if let Some(rest) = line.strip_prefix("ERR ") {
                let (code, message) = rest.split_once(' ').unwrap_or((rest, ""));
                let code = code
                    .parse::<u32>()
                    .map_err(|_| PinentryError::Protocol(format!("bad error line: {line}")))?;
                return Ok(Reply::Err {
                    code,
                    message: message.to_string(),
                });
            }
            // "S ..." status lines and "# ..." comments are informational.
        }
    }

    async fn expect_ok(&mut self) -> Result<(), PinentryError> {
        match self.read_reply().await? {
            Reply::Ok => Ok(()),
            Reply::Err { code, message } => Err(PinentryError::Assuan { code, message }),
            Reply::Data(_) => Err(PinentryError::Protocol("unexpected data line".into())),
        }
    }

    async fn command(&mut self, line: &str) -> Result<(), PinentryError> {
        self.send(line).await?;
        self.expect_ok().await
    }

    /// Like `command` but an Assuan ERR is ignored (unsupported options).
    async fn command_lenient(&mut self, line: &str) -> Result<(), PinentryError> {
        match self.command(line).await {
            Err(PinentryError::Assuan { .. }) => Ok(()),
            other => other,
        }
    }

    async fn getpin(&mut self) -> Result<Zeroizing<String>, PinentryError> {
        self.send("GETPIN").await?;
        // Pre-allocated for the same reason as `read_reply`'s buffer: a
        // pinentry that splits its answer over several `D` lines would
        // otherwise grow this `String`, leaving unwiped prefix copies of the
        // PIN behind in freed heap (MEDIUM 5).
        let mut pin = Zeroizing::new(String::with_capacity(1024));
        loop {
            match self.read_reply().await? {
                Reply::Data(d) => pin.push_str(&unescape(&d)?),
                Reply::Ok => return Ok(pin),
                Reply::Err { code, message } => {
                    return Err(PinentryError::Assuan { code, message });
                }
            }
        }
    }

    async fn bye(&mut self) {
        let _ = self.send("BYE").await;
        let _ = self.read_reply().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn fake() -> Pinentry {
        Pinentry::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/fake-pinentry.sh"
        ))
    }

    fn req() -> PinRequest {
        PinRequest {
            title: "secret-manager".into(),
            description: "Unlock 'default'\nline two".into(),
            prompt: "Password:".into(),
            error: None,
            repeat: false,
        }
    }

    #[test]
    fn pin_outcome_debug_does_not_print_the_pin() {
        let outcome = PinOutcome::Pin(Zeroizing::new("hunter2".to_string()));
        assert!(!format!("{outcome:?}").contains("hunter2"));
    }

    #[test]
    fn escaping_round_trips() {
        assert_eq!(escape("a%b\nc\rd"), "a%25b%0Ac%0Dd");
        assert_eq!(unescape("a%25b%0Ac%0Dd").unwrap().as_str(), "a%b\nc\rd");
        // Every C0 byte and DEL, not just CR/LF: `askpass` puts a fully
        // attacker-controlled string into a description, and the rest of the
        // range reaches the dialog as terminal control sequences (LOW 1).
        assert_eq!(escape("a\u{0}b\u{1b}c\u{7f}d\u{9}e"), "a%00b%1Bc%7Fd%09e");
        assert_eq!(
            unescape("a%00b%1Bc%7Fd%09e").unwrap().as_str(),
            "a\u{0}b\u{1b}c\u{7f}d\u{9}e"
        );
        // Printable text, including non-ASCII, is passed through untouched.
        assert_eq!(escape("caf\u{e9} ~!"), "caf\u{e9} ~!");
        assert!(unescape("bad%zz").is_err());
        assert!(is_cancel(83886179));
        assert!(!is_cancel(83886180));
    }

    #[tokio::test]
    async fn returns_pin() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let p = fake()
            .env("FAKE_PIN", "hun%25ter2")
            .env("FAKE_LOG", log.path());
        match p.ask(&req()).await.unwrap() {
            PinOutcome::Pin(pin) => assert_eq!(pin.as_str(), "hun%ter2"),
            PinOutcome::Cancelled => panic!("cancelled"),
        }
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("SETDESC Unlock 'default'%0Aline two"));
        assert!(text.contains("SETPROMPT Password:"));
        assert!(text.contains("SETTITLE secret-manager"));
        assert!(!text.contains("SETERROR"));
        assert!(!text.contains("SETREPEAT"));
        assert!(text.trim_end().ends_with("BYE"));
    }

    #[tokio::test]
    async fn cancel_error_and_repeat() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let p = fake().env("FAKE_LOG", log.path());
        let mut r = req();
        r.error = Some("Wrong password".into());
        r.repeat = true;
        assert!(matches!(p.ask(&r).await.unwrap(), PinOutcome::Cancelled));
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("SETERROR Wrong password"));
        assert!(text.contains("SETREPEAT"));
    }

    /// Two prompts issued at once must show one dialog at a time. Proven
    /// deterministically: each fake-pinentry invocation logs a START/END
    /// timestamp pair around GETPIN, and the two dialogs' intervals must not
    /// overlap (the first's END must precede the second's START).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_asks_are_serialized() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let timing_path = format!("{}.timing", log.path().display());
        let p = fake()
            .env("FAKE_PIN", "x")
            .env("FAKE_DELAY", "1")
            .env("FAKE_LOG", log.path());
        let r = req();
        let (a, b) = tokio::join!(p.ask(&r), p.ask(&r));
        assert!(matches!(a.unwrap(), PinOutcome::Pin(_)));
        assert!(matches!(b.unwrap(), PinOutcome::Pin(_)));

        let text = std::fs::read_to_string(&timing_path).unwrap();
        let mut intervals: Vec<(u128, u128)> = Vec::new();
        let mut pending_start: Option<u128> = None;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let kind = parts.next().unwrap();
            let _pid = parts.next().unwrap();
            let ts: u128 = parts.next().unwrap().parse().unwrap();
            match kind {
                "START" => pending_start = Some(ts),
                "END" => {
                    let start = pending_start.take().expect("END without START");
                    intervals.push((start, ts));
                }
                other => panic!("unexpected timing line kind: {other}"),
            }
        }
        assert_eq!(intervals.len(), 2, "expected two GETPIN intervals: {text}");
        let (first, second) = if intervals[0].0 <= intervals[1].0 {
            (intervals[0], intervals[1])
        } else {
            (intervals[1], intervals[0])
        };
        assert!(
            first.1 <= second.0,
            "dialogs overlapped: {first:?} vs {second:?}"
        );
    }

    #[tokio::test]
    async fn confirm_yes_and_no() {
        assert!(
            fake()
                .env("FAKE_CONFIRM", "yes")
                .confirm(&req())
                .await
                .unwrap()
        );
        assert!(
            !fake()
                .env("FAKE_CONFIRM", "no")
                .confirm(&req())
                .await
                .unwrap()
        );
    }

    /// A dialog that never answers must not hold the process-wide pinentry
    /// lock forever: it is abandoned at the timeout and reported as a
    /// cancellation (MEDIUM 5).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hanging_dialog_times_out_as_cancelled() {
        let p = fake()
            .env("FAKE_PIN", "x")
            .env("FAKE_DELAY", "30")
            .with_timeout(Duration::from_millis(300));
        let started = std::time::Instant::now();
        assert!(matches!(
            p.ask(&req()).await.unwrap(),
            PinOutcome::Cancelled
        ));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "did not time out"
        );
        // The lock is free again, so the next dialog runs normally.
        let ok = fake()
            .env("FAKE_PIN", "y")
            .with_timeout(Duration::from_secs(5));
        assert!(matches!(ok.ask(&req()).await.unwrap(), PinOutcome::Pin(_)));
    }

    /// The wait for the process-wide dialog lock is bounded (HIGH 3).
    ///
    /// The lock used to be taken *outside* any timeout, so a client that
    /// raised a dialog and never answered held it for the full timeout while
    /// every other unlock in the daemon queued behind it with no deadline of
    /// its own — repeat that and no unlock ever completes again. Here the
    /// holder hangs far past both budgets; the queued caller has a 100 ms
    /// queue budget of its own and must give up on that, not on the holder's.
    ///
    /// It gives up with [`PinentryError::Busy`], **not** a cancellation: it
    /// was never shown a dialog, so the user cancelled nothing (F1). The
    /// queue budget is set explicitly here because that is the budget under
    /// test; `a_queued_dialog_outlasts_a_holder_that_never_answers` covers
    /// the default relationship between the two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_queued_dialog_gives_up_rather_than_waiting_for_the_lock() {
        let p = fake()
            .env("FAKE_DELAY", "30")
            .with_timeout(Duration::from_secs(5));
        // A clone shares the `dialog` lock, exactly as the daemon's single
        // `Pinentry` does across concurrent prompts.
        let queued = p
            .clone()
            .with_timeout(Duration::from_secs(5))
            .with_queue_timeout(Duration::from_millis(100));
        let holder = tokio::spawn(async move { p.ask(&req()).await });
        // Let the holder take the lock before the second caller queues.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = std::time::Instant::now();
        assert!(matches!(
            queued.ask(&req()).await.unwrap_err(),
            PinentryError::Busy
        ));
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(2),
            "queued ask waited {waited:?} for the lock instead of its own 100ms queue budget"
        );

        // `confirm` bounds its wait the same way, and is likewise not a "no
        // from the user".
        let started = std::time::Instant::now();
        assert!(matches!(
            queued.confirm(&req()).await.unwrap_err(),
            PinentryError::Busy
        ));
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(2),
            "queued confirm waited {waited:?} for the lock"
        );

        assert!(matches!(
            holder.await.unwrap().unwrap(),
            PinOutcome::Cancelled
        ));
    }

    /// The timeout wrapper must not change the normal `confirm` outcome (the
    /// fake pinentry answers CONFIRM immediately, so only the wrapper is
    /// under test here).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn confirm_still_answers_under_a_timeout() {
        let p = fake()
            .env("FAKE_CONFIRM", "yes")
            .with_timeout(Duration::from_secs(5));
        assert!(p.confirm(&req()).await.unwrap());
    }

    /// `GPG_TTY`/`TERM`/`LC_*` reach Assuan as escaped arguments, and a value
    /// carrying a control character is dropped rather than injected as an
    /// extra command line (LOW 2).
    #[test]
    fn tty_options_are_escaped_and_control_characters_dropped() {
        let opts = tty_options_from(|name| match name {
            "GPG_TTY" => Some("/dev/pts/%1".to_string()),
            "TERM" => Some("xterm\nOPTION ttyname=/dev/evil".to_string()),
            "LC_ALL" => Some("en_US.UTF-8".to_string()),
            _ => None,
        });
        assert_eq!(
            opts,
            vec![
                "OPTION ttyname=/dev/pts/%251".to_string(),
                "OPTION lc-ctype=en_US.UTF-8".to_string(),
            ]
        );
        assert!(
            !opts
                .iter()
                .any(|o| o.contains('\n') || o.contains("ttytype")),
            "a control character must drop the value, not escape into a line: {opts:?}"
        );
        assert!(tty_options_from(|_| None).is_empty());
        assert!(tty_options_from(|_| Some(String::new())).is_empty());
    }

    #[tokio::test]
    async fn missing_program_is_spawn_error() {
        let err = Pinentry::new("/nonexistent/pinentry")
            .ask(&req())
            .await
            .unwrap_err();
        assert!(matches!(err, PinentryError::Spawn { .. }));
    }

    /// A pinentry stand-in whose whole conversation is scripted, so the
    /// unhappy Assuan paths — a reply that is not `OK`, an `ERR` line that
    /// does not parse, a dialog that exits mid-conversation — can be driven
    /// deterministically. `OPTION` lines (which vary with the environment)
    /// are always answered `OK` and never consume a script entry; every other
    /// command takes the next entry, where `CLOSE` exits and `HANG` sleeps.
    fn scripted(replies: &[&str]) -> (tempfile::TempDir, Pinentry) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scripted-pinentry.sh");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             printf 'OK Pleased to meet you\\n'\n\
             n=0\n\
             while IFS= read -r line; do\n\
               case \"$line\" in\n\
                 OPTION*) printf 'OK\\n'; continue ;;\n\
               esac\n\
               n=$((n + 1))\n\
               reply=$(printf '%s\\n' \"$SCRIPT\" | sed -n \"${n}p\")\n\
               case \"$reply\" in\n\
                 '') exit 0 ;;\n\
                 CLOSE) exit 0 ;;\n\
                 HANG) sleep 30; exit 0 ;;\n\
                 *) printf '%b\\n' \"$reply\" ;;\n\
               esac\n\
             done\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = Pinentry::new(&path)
            .env("SCRIPT", replies.join("\n"))
            .with_timeout(Duration::from_secs(10));
        (dir, p)
    }

    /// Runs a scripted dialog, retrying a spawn that lost the `ETXTBSY` race.
    ///
    /// The scripted binary is written by the test and executed immediately.
    /// Any other thread in this process that forks between the `write` and
    /// the `exec` inherits the still-open write descriptor, and the kernel
    /// then refuses to execute the file. Nothing about the code under test is
    /// involved, so the spawn is simply retried.
    async fn retrying<T>(
        mut dialog: impl AsyncFnMut() -> Result<T, PinentryError>,
    ) -> Result<T, PinentryError> {
        for _ in 0..50 {
            match dialog().await {
                Err(PinentryError::Spawn { source, .. })
                    if source.raw_os_error() == Some(libc::ETXTBSY) =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                other => return other,
            }
        }
        dialog().await
    }

    #[test]
    fn cancelled_debug_names_the_variant() {
        assert_eq!(
            format!("{:?}", PinOutcome::Cancelled),
            "PinOutcome::Cancelled"
        );
    }

    /// A dialog that exits in the middle of the conversation is not a
    /// cancellation: only an Assuan cancel is. The caller must see the error
    /// so an unlock is not recorded as "the user said no".
    #[tokio::test]
    async fn a_dialog_that_exits_mid_conversation_is_a_protocol_error() {
        // SETTITLE, SETDESC, SETPROMPT, then GETPIN with the child gone.
        let (_dir, p) = scripted(&["OK", "OK", "OK", "CLOSE"]);
        let err = retrying(async || p.ask(&req()).await).await.unwrap_err();
        assert!(
            matches!(&err, PinentryError::Protocol(m) if m.contains("closed the connection")),
            "{err:?}"
        );
    }

    /// An option the dialog does not implement answers `ERR`, and that is not
    /// fatal — pinentry-tty rejects `SETTITLE`, and a password prompt that
    /// refused to run because of it would be a regression.
    #[tokio::test]
    async fn an_option_the_dialog_rejects_is_not_fatal() {
        let (_dir, p) = scripted(&[
            "ERR 83886254 Not implemented",
            "OK",
            "OK",
            "D hunter2\\nOK",
            "OK",
        ]);
        match retrying(async || p.ask(&req()).await).await.unwrap() {
            PinOutcome::Pin(pin) => assert_eq!(pin.as_str(), "hunter2"),
            PinOutcome::Cancelled => panic!("cancelled"),
        }
    }

    /// A `D` line where an `OK` belongs is a protocol violation, not a PIN:
    /// treating it as one would let a rogue pinentry answer a `SETDESC` with
    /// data and have it read as an answer to a later command.
    #[tokio::test]
    async fn a_data_line_where_ok_belongs_is_a_protocol_error() {
        let (_dir, p) = scripted(&["D nope"]);
        let err = retrying(async || p.ask(&req()).await).await.unwrap_err();
        assert!(
            matches!(&err, PinentryError::Protocol(m) if m.contains("unexpected data line")),
            "{err:?}"
        );
    }

    /// An `ERR` line whose code is not a number cannot be classified — in
    /// particular `is_cancel` cannot be consulted — so it is reported rather
    /// than guessed at.
    #[tokio::test]
    async fn an_error_line_with_no_numeric_code_is_a_protocol_error() {
        let (_dir, p) = scripted(&["OK", "ERR oops the sky is falling"]);
        let err = retrying(async || p.ask(&req()).await).await.unwrap_err();
        assert!(
            matches!(&err, PinentryError::Protocol(m) if m.contains("bad error line")),
            "{err:?}"
        );
    }

    /// `confirm` answers "no" for a cancel or an Assuan error, but a broken
    /// dialog is a different thing and reaches the caller as an error.
    #[tokio::test]
    async fn confirm_reports_a_broken_dialog_rather_than_answering_no() {
        // SETTITLE, SETDESC, SETPROMPT, then CONFIRM with the child gone.
        let (_dir, p) = scripted(&["OK", "OK", "OK", "CLOSE"]);
        let err = retrying(async || p.confirm(&req()).await)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, PinentryError::Protocol(m) if m.contains("closed the connection")),
            "{err:?}"
        );
    }

    /// A confirmation nobody answers must not hold the process-wide dialog
    /// lock forever; it is abandoned at the timeout and read as a refusal,
    /// which is the fail-closed direction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hanging_confirmation_times_out_as_refused() {
        let (_dir, p) = scripted(&["OK", "OK", "OK", "HANG"]);
        let p = p.with_timeout(Duration::from_millis(300));
        let started = std::time::Instant::now();
        assert!(!retrying(async || p.confirm(&req()).await).await.unwrap());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "did not time out"
        );
    }

    /// An empty title means no `SETTITLE` at all, rather than one with an
    /// empty argument: pinentry-gtk draws an empty title bar for the latter.
    #[tokio::test]
    async fn an_empty_title_sends_no_settitle() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let p = fake().env("FAKE_PIN", "x").env("FAKE_LOG", log.path());
        let mut r = req();
        r.title = String::new();
        assert!(matches!(p.ask(&r).await.unwrap(), PinOutcome::Pin(_)));
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(!text.contains("SETTITLE"), "{text}");
        assert!(text.contains("SETDESC"), "the rest of the setup still runs");
    }

    /// Assuan status (`S`) and comment (`#`) lines can arrive before any
    /// reply. They are informational: the reader must skip them and keep
    /// waiting, not mistake one for an answer or an error.
    #[tokio::test]
    async fn status_and_comment_lines_are_skipped() {
        let (_dir, p) = scripted(&[
            "S SETTITLE_DONE\\nOK",
            "# a comment\\nOK",
            "OK",
            "S PINENTRY_LAUNCHED 1234\\nD hunter2\\nOK",
            "OK",
        ]);
        match retrying(async || p.ask(&req()).await).await.unwrap() {
            PinOutcome::Pin(pin) => assert_eq!(pin.as_str(), "hunter2"),
            PinOutcome::Cancelled => panic!("cancelled"),
        }
    }

    /// F1: a queued request must be able to outlast a dialog that nobody
    /// answers, and get its own dialog rather than being reported as
    /// dismissed.
    ///
    /// The budgets used to be one and the same constant, so a queued caller's
    /// deadline expired no later than the holder's — and with a second
    /// unanswered dialog ahead of it (`tokio::sync::Mutex` is FIFO, so a
    /// hostile client can always put one there) it expired *while that second
    /// dialog was still up*, and completed as "the user dismissed it" without
    /// ever having drawn one.
    ///
    /// Two holders that never answer, then the victim. Every handle shares
    /// one `dialog` lock and one 500 ms dialog budget, exactly as the daemon's
    /// single `Pinentry` does; the victim's queue budget is the default
    /// multiple of that, so it must survive both holds (~1 s) and get a PIN.
    /// Timing is decided by the two 500 ms dialog budgets, not by scheduling:
    /// the victim's own deadline is 2.5 s, more than a second clear.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_queued_dialog_outlasts_a_holder_that_never_answers() {
        let dialog = Duration::from_millis(500);
        let base = fake().env("FAKE_PIN", "x").with_timeout(dialog);
        // Clones share the lock; the extra env var only affects the clone.
        let stuck_a = base.clone().env("FAKE_DELAY", "30");
        let stuck_b = base.clone().env("FAKE_DELAY", "30");
        let victim = base.clone();

        let a = tokio::spawn(async move { stuck_a.ask(&req()).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let b = tokio::spawn(async move { stuck_b.ask(&req()).await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        let outcome = victim.ask(&req()).await;
        match outcome {
            Ok(PinOutcome::Pin(pin)) => assert_eq!(pin.as_str(), "x"),
            other => panic!(
                "the queued request was never shown a dialog after {:?}: {other:?}",
                started.elapsed()
            ),
        }
        // It really did wait behind both of them rather than racing ahead.
        assert!(
            started.elapsed() >= dialog,
            "the victim did not queue behind the stuck dialogs"
        );
        // Both holders were abandoned at their own budget, as before.
        assert!(matches!(a.await.unwrap().unwrap(), PinOutcome::Cancelled));
        assert!(matches!(b.await.unwrap().unwrap(), PinOutcome::Cancelled));
    }

    /// F1: giving up on the wait is not a cancellation, and must not read
    /// like one anywhere it reaches a user.
    #[test]
    fn busy_does_not_claim_the_user_cancelled() {
        let text = PinentryError::Busy.to_string();
        assert!(!text.to_lowercase().contains("cancel"), "{text}");
        assert!(!text.to_lowercase().contains("dismiss"), "{text}");
        assert!(text.contains("no dialog"), "{text}");
    }

    /// The queue budget is a multiple of the dialog budget, not equal to it —
    /// the whole of F1. Pinned as a property of the defaults so the two
    /// cannot silently drift back together.
    #[test]
    fn the_queue_budget_outlasts_the_dialog_budget() {
        const { assert!(QUEUE_TIMEOUT_FACTOR > 1) };
        assert!(DEFAULT_QUEUE_TIMEOUT > DEFAULT_TIMEOUT);
        // `with_timeout` keeps the relationship rather than leaving the queue
        // budget at ten minutes next to a 10 ms dialog.
        let p = Pinentry::new("/nonexistent").with_timeout(Duration::from_millis(10));
        assert_eq!(p.queue_timeout, Duration::from_millis(50));
        assert_eq!(
            p.with_queue_timeout(Duration::from_secs(1)).queue_timeout,
            Duration::from_secs(1)
        );
    }

    /// A retry loop keeps the dialog slot it already won: `session()` holds it
    /// across every dialog raised through it, so a user who mistypes a
    /// password is not sent to the back of the queue between attempts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_holds_the_slot_across_several_dialogs() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let p = fake()
            .env("FAKE_PIN", "x")
            .env("FAKE_LOG", log.path())
            .with_timeout(Duration::from_secs(5));
        let session = p.session().await.unwrap();

        // Someone else cannot get in while the session is open, whatever it is
        // doing between its dialogs.
        let other = p.clone().with_queue_timeout(Duration::from_millis(100));
        assert!(matches!(
            other.ask(&req()).await.unwrap_err(),
            PinentryError::Busy
        ));

        // The session itself raises dialog after dialog without re-queueing.
        for _ in 0..3 {
            assert!(matches!(
                session.ask(&req()).await.unwrap(),
                PinOutcome::Pin(_)
            ));
        }
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(text.matches("GETPIN").count(), 3, "{text}");

        // And the slot is free again once it is dropped.
        drop(session);
        assert!(matches!(
            other.ask(&req()).await.unwrap(),
            PinOutcome::Pin(_)
        ));
    }
}
