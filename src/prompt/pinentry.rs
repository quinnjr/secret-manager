//! Minimal Assuan client that drives a `pinentry` binary.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

/// How long one dialog may hold the process-wide pinentry lock. A client that
/// raises a dialog and never answers would otherwise block every unlock in the
/// daemon forever; on expiry the child is dropped (`kill_on_drop`) and the
/// request reports a cancellation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

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
        }
    }

    /// Override [`DEFAULT_TIMEOUT`] for this handle (and its clones).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Ask for a password. A dialog that outlives [`Pinentry::with_timeout`]
    /// is abandoned — the child is dropped, which kills it — and reported as
    /// a cancellation, so one unanswered dialog cannot wedge the daemon.
    pub async fn ask(&self, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
        // The wait for the shared dialog lock is bounded by the same timeout
        // as the dialog itself. Acquiring it outside the timeout meant a
        // client that raised a dialog and never answered blocked every other
        // unlock in the daemon for the full timeout with no deadline of their
        // own, and repeating that indefinitely blocked them forever (HIGH 3).
        let Ok(_one_at_a_time) = tokio::time::timeout(self.timeout, self.dialog.lock()).await
        else {
            tracing::warn!("timed out waiting for the pinentry dialog lock; giving up");
            return Ok(PinOutcome::Cancelled);
        };
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

    /// Yes/no question. Cancel, a timeout, or any pinentry error means "no".
    pub async fn confirm(&self, req: &PinRequest) -> Result<bool, PinentryError> {
        // Bounded like `ask`'s (HIGH 3).
        let Ok(_one_at_a_time) = tokio::time::timeout(self.timeout, self.dialog.lock()).await
        else {
            tracing::warn!("timed out waiting for the pinentry dialog lock; refusing");
            return Ok(false);
        };
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

    /// The wait for the process-wide dialog lock is bounded by the same
    /// timeout as the dialog itself (HIGH 3).
    ///
    /// The lock used to be taken *outside* the timeout, so a client that
    /// raised a dialog and never answered held it for the full timeout while
    /// every other unlock in the daemon queued behind it with no deadline of
    /// its own — repeat that and no unlock ever completes again. Here the
    /// holder hangs for 5 s; the queued caller has a 300 ms timeout of its
    /// own and must give up on that, not on the holder's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_queued_dialog_gives_up_rather_than_waiting_for_the_lock() {
        let p = fake()
            .env("FAKE_DELAY", "30")
            .with_timeout(Duration::from_secs(5));
        // A clone shares the `dialog` lock, exactly as the daemon's single
        // `Pinentry` does across concurrent prompts.
        let queued = p.clone().with_timeout(Duration::from_millis(300));
        let holder = tokio::spawn(async move { p.ask(&req()).await });
        // Let the holder take the lock before the second caller queues.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = std::time::Instant::now();
        assert!(matches!(
            queued.ask(&req()).await.unwrap(),
            PinOutcome::Cancelled
        ));
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(2),
            "queued ask waited {waited:?} for the lock instead of its own 300ms timeout"
        );

        // `confirm` bounds its wait the same way.
        let started = std::time::Instant::now();
        assert!(!queued.confirm(&req()).await.unwrap());
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
}
