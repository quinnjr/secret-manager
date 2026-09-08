# secret-manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust freedesktop Secret Service daemon with encrypted vault files, a `secret-tool` compatible CLI, SSH passphrase storage with an askpass helper, and a PAM module that unlocks the vault at login.

**Architecture:** One `secret-manager` binary hosts both the daemon (`zbus` Secret Service + control socket, one tokio runtime) and every CLI subcommand (D-Bus and control-socket clients). A std-only `control-protocol` crate carries the socket message types so the `pam_secret_manager` cdylib stays small. Vaults are one Argon2id + XChaCha20-Poly1305 file per collection with a plaintext hashed-attribute index so search works while locked.

**Tech Stack:** Rust 2024 edition (rustc 1.97), `zbus 5`, `tokio 1`, `clap 4`, `argon2 0.5`, `chacha20poly1305 0.10`, `hkdf 0.12`, `sha2 0.10`, `aes 0.8`, `cbc 0.1`, `num-bigint 0.4`, `postcard 1`, `zeroize 1`, `pamsm 0.5`, `rpassword 7`, `assert_cmd 2`.

**Spec:** `docs/superpowers/specs/2026-09-05-secret-manager-design.md`

## Global Constraints

- Edition `2024`, `resolver = "3"`, rustc 1.97 available locally.
- All work happens in a git worktree, never in the primary checkout (user rule).
- Every task ends with `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` green before commit.
- No `unsafe` outside `crates/pam_secret_manager`, the `SO_PEERCRED`/`getuid` check in `control/server.rs`, and the `libc::getuid()` fallbacks in `config.rs` (`runtime_dir`) and `control-protocol` (`socket_path`).
- Secrets in memory live in `zeroize::Zeroizing` wrappers; never `println!`/`tracing` a secret.
- Bus name `org.freedesktop.secrets`; object root `/org/freedesktop/secrets`; error prefix `org.freedesktop.Secret.Error`.
- Session algorithms: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`. Both required.
- Vault: Argon2id defaults `m_cost_kib = 65536`, `t_cost = 3`, `p_cost = 1`; salt 16 bytes; nonce 24 bytes; key 32 bytes. Tests use `m_cost_kib = 8, t_cost = 1, p_cost = 1`.
- Object path segments allow only `[A-Za-z0-9_]`. Item ids are `Uuid::new_v4().simple()`; collection ids are derived from labels as `[a-z0-9_]+`.
- Exit codes: 0 ok, 1 not found / dismissed / other failure, 2 usage error, 3 daemon unreachable or bus name taken.
- Commit messages end with the two attribution trailers used in this repo (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01J13d2kZEesjVfQ7RNGdupq`).
- Local tools available for tests: `dbus-daemon`, `secret-tool`, `pinentry`, `ssh-keygen`. `pamtester`/`pam_wrapper` are not installed; the PAM integration test skips itself when `libpam_wrapper.so` is absent.

---

## File map

| Path | Responsibility |
|------|----------------|
| `Cargo.toml` | workspace: three members, shared package metadata |
| `crates/control-protocol/src/lib.rs` | `Request`, `Response`, `CollectionStatus`, frame encode/decode, `socket_path()`, blocking `call()` |
| `crates/secret-manager/src/lib.rs` | module tree, re-exports for tests |
| `crates/secret-manager/src/main.rs` | argv0 dispatch, tracing init, tokio runtime, exit code mapping |
| `crates/secret-manager/src/config.rs` | `Config` + XDG path helpers |
| `crates/secret-manager/src/vault/crypto.rs` | Argon2id KDF, XChaCha20-Poly1305 seal/open, random bytes |
| `crates/secret-manager/src/vault/format.rs` | `Header`, `IndexEntry`, `Item`, attribute hashing, file encode/decode |
| `crates/secret-manager/src/vault/store.rs` | `Vault`: create/open/unlock/lock, item CRUD, atomic save, change password |
| `crates/secret-manager/src/vault/mod.rs` | re-exports, `now()` |
| `crates/secret-manager/src/session/dh.rs` | RFC 2409 group 2 DH, HKDF key derivation |
| `crates/secret-manager/src/session/mod.rs` | `SessionCipher` (plain / AES-128-CBC) |
| `crates/secret-manager/src/prompt/pinentry.rs` | Assuan pinentry client |
| `crates/secret-manager/src/control/server.rs` | tokio control socket server with peer-cred check |
| `crates/secret-manager/src/dbus/paths.rs` | object path constants and builders/parsers |
| `crates/secret-manager/src/dbus/errors.rs` | `org.freedesktop.Secret.Error.*` DBusError enum |
| `crates/secret-manager/src/dbus/state.rs` | `ServiceState`, `Shared`, alias persistence |
| `crates/secret-manager/src/dbus/session.rs` | `Session` interface + `SecretStruct` |
| `crates/secret-manager/src/dbus/service.rs` | `Service` interface |
| `crates/secret-manager/src/dbus/collection.rs` | `Collection` interface (real path and alias path) |
| `crates/secret-manager/src/dbus/item.rs` | `Item` interface |
| `crates/secret-manager/src/dbus/prompt.rs` | `Prompt` interface, pinentry-driven unlock/create flows |
| `crates/secret-manager/src/dbus/registry.rs` | register/unregister collection + item objects on the ObjectServer |
| `crates/secret-manager/src/daemon.rs` | `Daemon::start`: load vaults, bus, control server, cleanup, idle lock |
| `crates/secret-manager/src/cli/mod.rs` | clap tree, `run()`, `CliError` → exit code |
| `crates/secret-manager/src/cli/client.rs` | zbus proxies and `Client` helper (session, prompt wait) |
| `crates/secret-manager/src/cli/secrets.rs` | get / set / delete / list |
| `crates/secret-manager/src/cli/vault_cmds.rs` | init / lock / unlock / status / change-password |
| `crates/secret-manager/src/cli/ssh.rs` | ssh add / list / remove / askpass |
| `crates/secret-manager/tests/common/mod.rs` | private `dbus-daemon`, in-process daemon fixture, fake pinentry env |
| `crates/secret-manager/tests/fixtures/fake-pinentry.sh` | scripted Assuan pinentry |
| `crates/secret-manager/tests/*.rs` | integration tests per task |
| `crates/pam_secret_manager/src/lib.rs` | PAM hooks |
| `crates/pam_secret_manager/tests/pam_stack.rs` | pam_wrapper based test, self-skipping |
| `dist/` | systemd unit, D-Bus activation file, environment.d, pam.d snippet |
| `docs/install-arch.md`, `docs/install-debian.md`, `README.md` | install and usage |

---

### Task 1: Workspace scaffold and config module

**Files:**
- Modify: `Cargo.toml` (becomes the workspace manifest)
- Move: `src/main.rs` → `crates/secret-manager/src/main.rs`
- Create: `crates/secret-manager/Cargo.toml`, `crates/secret-manager/src/lib.rs`, `crates/secret-manager/src/config.rs`
- Create: `crates/control-protocol/Cargo.toml`, `crates/control-protocol/src/lib.rs` (empty shell, filled in Task 2)
- Create: `crates/pam_secret_manager/Cargo.toml`, `crates/pam_secret_manager/src/lib.rs` (empty shell, filled in Task 16)
- Create: `rustfmt.toml` (empty, default style), `.gitignore` add `/target`

**Interfaces:**
- Produces: `secret_manager::config::{Config, VaultConfig, PromptConfig, KdfConfig, Config::load, Config::default, data_dir, config_file, runtime_dir}`

- [ ] **Step 1: Write the workspace manifest**

```toml
# Cargo.toml
[workspace]
resolver = "3"
members = [
    "crates/control-protocol",
    "crates/secret-manager",
    "crates/pam_secret_manager",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/quinnjr/secret-manager"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["use-std"] }
zeroize = { version = "1", features = ["serde", "derive"] }
thiserror = "2"
anyhow = "1"
libc = "0.2"
```

- [ ] **Step 2: Create the three crate manifests**

`crates/control-protocol/Cargo.toml`:
```toml
[package]
name = "control-protocol"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
postcard.workspace = true
zeroize.workspace = true
thiserror.workspace = true
```

`crates/secret-manager/Cargo.toml`:
```toml
[package]
name = "secret-manager"
version.workspace = true
edition.workspace = true
license.workspace = true
default-run = "secret-manager"

[lib]
name = "secret_manager"
path = "src/lib.rs"

[[bin]]
name = "secret-manager"
path = "src/main.rs"

[dependencies]
control-protocol = { path = "../control-protocol" }
anyhow.workspace = true
thiserror.workspace = true
serde.workspace = true
postcard.workspace = true
zeroize.workspace = true
libc.workspace = true
toml = "0.8"
humantime-serde = "1"
argon2 = "0.5"
chacha20poly1305 = "0.10"
rand_core = { version = "0.6", features = ["getrandom"] }
sha2 = "0.10"
hkdf = "0.12"
aes = "0.8"
cbc = { version = "0.1", features = ["alloc", "block-padding"] }
num-bigint = "0.4"
num-traits = "0.2"
uuid = { version = "1", features = ["v4"] }
zbus = { version = "5", default-features = false, features = ["tokio"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "process", "sync", "time", "fs", "signal"] }
futures-util = "0.3"
clap = { version = "4", features = ["derive"] }
clap_complete = "4"
rpassword = "7"
regex = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

`crates/pam_secret_manager/Cargo.toml`:
```toml
[package]
name = "pam_secret_manager"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib"]

[dependencies]
control-protocol = { path = "../control-protocol" }
pamsm = { version = "0.5", features = ["libpam"] }
zeroize.workspace = true
libc.workspace = true
```

Shell files so the workspace builds:

```rust
// crates/control-protocol/src/lib.rs
//! Control socket protocol shared by the daemon, CLI, and PAM module.
```

```rust
// crates/pam_secret_manager/src/lib.rs
//! PAM module that unlocks the secret-manager vault at login.
```

- [ ] **Step 3: Move main.rs and add lib.rs**

```bash
mkdir -p crates/secret-manager/src && git mv src/main.rs crates/secret-manager/src/main.rs
```

`crates/secret-manager/src/lib.rs`:
```rust
//! secret-manager: a freedesktop Secret Service daemon and CLI.
pub mod config;
```

`crates/secret-manager/src/main.rs` (temporary, replaced in Task 12):
```rust
fn main() {
    println!("secret-manager {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 4: Write the failing config tests**

`crates/secret-manager/src/config.rs` starts with only the tests module so the failing run is meaningful:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();
        assert_eq!(c.kdf.m_cost_kib, 65536);
        assert_eq!(c.kdf.t_cost, 3);
        assert_eq!(c.kdf.p_cost, 1);
        assert_eq!(c.prompt.pinentry, "pinentry");
        assert_eq!(c.vault.auto_lock_after, Duration::ZERO);
        assert!(c.vault.dir.ends_with("secret-manager"));
    }

    #[test]
    fn parses_partial_file() {
        let text = r#"
[vault]
auto_lock_after = "15m"
[prompt]
pinentry = "/usr/bin/pinentry-tty"
"#;
        let c = Config::from_str(text).unwrap();
        assert_eq!(c.vault.auto_lock_after, Duration::from_secs(900));
        assert_eq!(c.prompt.pinentry, "/usr/bin/pinentry-tty");
        assert_eq!(c.kdf.t_cost, 3);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::from_str("[vault]\nbogus = 1\n").is_err());
    }

    #[test]
    fn expands_tilde_in_vault_dir() {
        let c = Config::from_str("[vault]\ndir = \"~/vaults\"\n").unwrap();
        assert!(!c.vault.dir.to_string_lossy().starts_with('~'));
        assert!(c.vault.dir.ends_with("vaults"));
    }

    #[test]
    fn xdg_env_overrides() {
        // Tests run in parallel; use unique env keys is not possible, so only assert the shape.
        assert!(runtime_dir().ends_with("secret-manager"));
        assert!(config_file().ends_with("secret-manager/config.toml"));
    }
}
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `cargo test -p secret-manager config`
Expected: compile error, `Config` not found.

- [ ] **Step 6: Implement config.rs**

Prepend to `crates/secret-manager/src/config.rs`:

```rust
//! Configuration file and XDG path helpers.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub vault: VaultConfig,
    pub prompt: PromptConfig,
    pub kdf: KdfConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    pub dir: PathBuf,
    #[serde(with = "humantime_serde")]
    pub auto_lock_after: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PromptConfig {
    pub pinentry: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KdfConfig {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self { vault: VaultConfig::default(), prompt: PromptConfig::default(), kdf: KdfConfig::default() }
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self { dir: data_dir(), auto_lock_after: Duration::ZERO }
    }
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self { pinentry: std::env::var("PINENTRY").unwrap_or_else(|_| "pinentry".to_string()) }
    }
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self { m_cost_kib: 65536, t_cost: 3, p_cost: 1 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
}

impl Config {
    /// Load `$SECRET_MANAGER_CONFIG` or `$XDG_CONFIG_HOME/secret-manager/config.toml`.
    /// A missing file yields defaults.
    pub fn load() -> Result<Config, ConfigError> {
        let path = std::env::var_os("SECRET_MANAGER_CONFIG").map(PathBuf::from).unwrap_or_else(config_file);
        match std::fs::read_to_string(&path) {
            Ok(text) => Config::from_str(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(source) => Err(ConfigError::Read { path, source }),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(text: &str) -> Result<Config, ConfigError> {
        let mut c: Config = toml::from_str(text)?;
        c.vault.dir = expand_tilde(&c.vault.dir);
        Ok(c)
    }
}

fn expand_tilde(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("~") {
        home_dir().join(rest)
    } else {
        p.to_path_buf()
    }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir().join(fallback),
    }
}

/// `$XDG_DATA_HOME/secret-manager`
pub fn data_dir() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share").join("secret-manager")
}

/// `$XDG_CONFIG_HOME/secret-manager/config.toml`
pub fn config_file() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join("secret-manager").join("config.toml")
}

/// `$XDG_RUNTIME_DIR/secret-manager`, falling back to `/tmp/secret-manager-<uid>`.
pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() => PathBuf::from(v).join("secret-manager"),
        // SAFETY: getuid has no preconditions and cannot fail.
        _ => PathBuf::from(format!("/tmp/secret-manager-{}", unsafe { libc::getuid() })),
    }
}
```

- [ ] **Step 7: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager config && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 5 tests pass, no warnings.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "Scaffold workspace with config module"
```

---

### Task 2: control-protocol crate

**Files:**
- Create: `crates/control-protocol/src/lib.rs` (replace shell)

**Interfaces:**
- Produces:
  - `control_protocol::{Request, Response, CollectionStatus}`
  - `control_protocol::encode_frame(&impl Serialize) -> Result<Vec<u8>, ProtocolError>` (4-byte big-endian length + postcard body)
  - `control_protocol::decode_frame<T: DeserializeOwned>(&[u8]) -> Result<T, ProtocolError>` (body only, no prefix)
  - `control_protocol::MAX_FRAME: usize = 1 << 20`
  - `control_protocol::socket_path() -> PathBuf` and `socket_path_for_runtime_dir(&Path) -> PathBuf`
  - `control_protocol::call(path: &Path, req: &Request) -> Result<Response, ProtocolError>` (blocking, std `UnixStream`, 5 s timeout)
  - `control_protocol::read_frame_sync<R: Read>(&mut R) -> Result<Vec<u8>, ProtocolError>` / `write_frame_sync<W: Write>(&mut W, &[u8]) -> io::Result<()>`

- [ ] **Step 1: Write the failing tests**

Append to `crates/control-protocol/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::net::UnixListener;

    #[test]
    fn frame_round_trip() {
        let req = Request::Unlock { collection: "default".into(), password: Zeroizing::new("hunter2".into()) };
        let bytes = encode_frame(&req).unwrap();
        assert_eq!(&bytes[..4], &((bytes.len() - 4) as u32).to_be_bytes());
        let mut cur = Cursor::new(bytes);
        let body = read_frame_sync(&mut cur).unwrap();
        let back: Request = decode_frame(&body).unwrap();
        match back {
            Request::Unlock { collection, password } => {
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
        assert_eq!(p, std::path::PathBuf::from("/run/user/1000/secret-manager/control.sock"));
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
            let resp = Response::Status { collections: vec![], uptime_secs: 7 };
            stream.write_all(&encode_frame(&resp).unwrap()).unwrap();
        });
        let resp = call(&sock, &Request::Status).unwrap();
        assert_eq!(resp, Response::Status { collections: vec![], uptime_secs: 7 });
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreachable_socket_is_reported() {
        let err = call(std::path::Path::new("/nonexistent/control.sock"), &Request::Status).unwrap_err();
        assert!(matches!(err, ProtocolError::Connect(_)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p control-protocol`
Expected: compile errors for missing items.

- [ ] **Step 3: Implement the crate**

Replace the top of `crates/control-protocol/src/lib.rs` (keep the tests module at the bottom):

```rust
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
    Unlock { collection: String, password: Zeroizing<String> },
    Lock { collection: Option<String> },
    ChangePassword { collection: String, old: Zeroizing<String>, new: Zeroizing<String> },
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
    Status { collections: Vec<CollectionStatus>, uptime_secs: u64 },
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
```

Add `libc.workspace = true` to `crates/control-protocol/Cargo.toml` dependencies.

- [ ] **Step 4: Run tests, fmt, clippy**

Run: `cargo test -p control-protocol && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add control-protocol crate with framing and blocking client"
```

---

### Task 3: Vault crypto (Argon2id + XChaCha20-Poly1305)

**Files:**
- Create: `crates/secret-manager/src/vault/mod.rs`, `crates/secret-manager/src/vault/crypto.rs`
- Modify: `crates/secret-manager/src/lib.rs` (add `pub mod vault;`)

**Interfaces:**
- Produces:
  - `vault::crypto::{KEY_LEN=32, SALT_LEN=16, NONCE_LEN=24}`
  - `vault::crypto::KdfParams { m_cost_kib: u32, t_cost: u32, p_cost: u32 }` with `Default` (65536/3/1), `KdfParams::FAST_FOR_TESTS` (8/1/1), `From<config::KdfConfig>`
  - `vault::crypto::Key` (Clone, redacted Debug) with `as_bytes(&self) -> &[u8; 32]`
  - `vault::crypto::derive_key(password: &[u8], salt: &[u8; 16], params: KdfParams) -> Result<Key, CryptoError>`
  - `vault::crypto::seal(key: &Key, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>`
  - `vault::crypto::open(key: &Key, nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>`
  - `vault::crypto::random_bytes<const N: usize>() -> [u8; N]`
  - `vault::crypto::CryptoError::{Kdf(String), Auth}`
  - `vault::now() -> u64` (unix seconds)
  - `vault::collection_id_from_label(&str) -> String`

- [ ] **Step 1: Write the failing tests**

`crates/secret-manager/src/vault/mod.rs`:
```rust
//! Encrypted collection storage.
pub mod crypto;

/// Current unix time in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Derive an object-path-safe collection id from a label: lowercase `[a-z0-9_]+`.
pub fn collection_id_from_label(label: &str) -> String {
    let mut id = String::new();
    let mut last_underscore = false;
    for ch in label.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            id.push(c);
            last_underscore = false;
        } else if !last_underscore && !id.is_empty() {
            id.push('_');
            last_underscore = true;
        }
    }
    let id = id.trim_end_matches('_').to_string();
    if id.is_empty() { "collection".to_string() } else { id }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_ids_are_path_safe() {
        assert_eq!(collection_id_from_label("Default"), "default");
        assert_eq!(collection_id_from_label("My Work Keys!"), "my_work_keys");
        assert_eq!(collection_id_from_label("   "), "collection");
        assert_eq!(collection_id_from_label("Ünïcode"), "n_code");
    }
}
```

`crates/secret-manager/src/vault/crypto.rs` tests module:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [9u8; NONCE_LEN];

    #[test]
    fn derive_is_deterministic_and_password_sensitive() {
        let a = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let b = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let c = derive_key(b"other", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn seal_open_round_trip() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let ct = seal(&key, &NONCE, b"aad", b"hello").unwrap();
        assert_ne!(&ct[..5], b"hello");
        let pt = open(&key, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn tampered_ciphertext_aad_or_key_fails() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let other = derive_key(b"pw2", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        let mut ct = seal(&key, &NONCE, b"aad", b"hello").unwrap();
        assert!(matches!(open(&key, &NONCE, b"AAD", &ct), Err(CryptoError::Auth)));
        assert!(matches!(open(&other, &NONCE, b"aad", &ct), Err(CryptoError::Auth)));
        ct[0] ^= 1;
        assert!(matches!(open(&key, &NONCE, b"aad", &ct), Err(CryptoError::Auth)));
    }

    #[test]
    fn random_bytes_differ() {
        let a: [u8; 24] = random_bytes();
        let b: [u8; 24] = random_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = derive_key(b"pw", &SALT, KdfParams::FAST_FOR_TESTS).unwrap();
        assert_eq!(format!("{key:?}"), "Key(..)");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager vault`
Expected: compile errors for missing items.

- [ ] **Step 3: Implement crypto.rs**

Prepend to `crates/secret-manager/src/vault/crypto.rs`:
```rust
//! Key derivation and authenticated encryption for vault files.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Fast parameters for unit tests only.
    pub const FAST_FOR_TESTS: KdfParams = KdfParams { m_cost_kib: 8, t_cost: 1, p_cost: 1 };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_cost_kib: 65536, t_cost: 3, p_cost: 1 }
    }
}

impl From<crate::config::KdfConfig> for KdfParams {
    fn from(c: crate::config::KdfConfig) -> Self {
        Self { m_cost_kib: c.m_cost_kib, t_cost: c.t_cost, p_cost: c.p_cost }
    }
}

/// A derived vault key. Zeroized on drop, never printed.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("authentication failed")]
    Auth,
}

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key, CryptoError> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut out[..])
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(Key(out))
}

pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Auth)
}

pub fn open(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Auth)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}
```

Add `pub mod vault;` to `lib.rs`.

- [ ] **Step 4: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager vault && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add vault key derivation and AEAD primitives"
```

---

### Task 4: Vault file format and hashed index

**Files:**
- Create: `crates/secret-manager/src/vault/format.rs`
- Modify: `crates/secret-manager/src/vault/mod.rs` (add `pub mod format;`)

**Interfaces:**
- Produces:
  - `vault::format::{MAGIC, VERSION=1}`
  - `vault::format::IndexEntry { id: String, attr_hashes: Vec<[u8; 32]> }` with `matches(&self, salt: &[u8;16], query: &BTreeMap<String,String>) -> bool`
  - `vault::format::Header { version: u16, label: String, created: u64, modified: u64, kdf: KdfParams, salt: [u8;16], nonce: [u8;24], index: Vec<IndexEntry> }`
  - `vault::format::Item { id, label, attributes: BTreeMap<String,String>, secret: Zeroizing<Vec<u8>>, content_type: String, created: u64, modified: u64 }` (manual `Debug` redacts secret, manual `PartialEq`)
  - `vault::format::attribute_hash(salt, key, value) -> [u8; 32]`, `build_index(salt, &[Item]) -> Vec<IndexEntry>`
  - `vault::format::VaultFile { header: Header, aad: Vec<u8>, ciphertext: Vec<u8> }` with `VaultFile::new(header, ciphertext) -> Result<Self, FormatError>`, `header_bytes(&Header) -> Result<Vec<u8>, FormatError>`, `encode(&self) -> Vec<u8>`, `decode(&[u8]) -> Result<VaultFile, FormatError>`
  - `vault::format::{encode_items(&[Item]) -> Result<Zeroizing<Vec<u8>>, FormatError>, decode_items(&[u8]) -> Result<Vec<Item>, FormatError>}`
  - `vault::format::FormatError::{BadMagic, UnsupportedVersion(u16), Truncated, Encoding(postcard::Error)}`

- [ ] **Step 1: Write the failing tests**

Tests module for `crates/secret-manager/src/vault/format.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::KdfParams;

    fn item(id: &str, attrs: &[(&str, &str)]) -> Item {
        Item {
            id: id.into(),
            label: format!("label {id}"),
            attributes: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            secret: Zeroizing::new(b"s3cret".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
        }
    }

    fn header(index: Vec<IndexEntry>) -> Header {
        Header {
            version: VERSION,
            label: "default".into(),
            created: 1,
            modified: 2,
            kdf: KdfParams::FAST_FOR_TESTS,
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            index,
        }
    }

    #[test]
    fn items_round_trip() {
        let items = vec![item("a", &[("k", "v")]), item("b", &[])];
        let bytes = encode_items(&items).unwrap();
        assert_eq!(decode_items(&bytes).unwrap(), items);
    }

    #[test]
    fn item_debug_hides_secret() {
        let s = format!("{:?}", item("a", &[]));
        assert!(!s.contains("s3cret"));
        assert!(s.contains("label a"));
    }

    #[test]
    fn file_round_trip_and_aad() {
        let file = VaultFile::new(header(vec![]), vec![9, 9, 9]).unwrap();
        let bytes = file.encode();
        assert_eq!(&bytes[..8], &MAGIC);
        let back = VaultFile::decode(&bytes).unwrap();
        assert_eq!(back.header, file.header);
        assert_eq!(back.ciphertext, vec![9, 9, 9]);
        assert_eq!(back.aad, file.aad);
        assert_eq!(&bytes[..back.aad.len()], back.aad.as_slice());
    }

    #[test]
    fn bad_magic_truncated_and_version() {
        assert!(matches!(VaultFile::decode(b"NOTAVAULT000"), Err(FormatError::BadMagic)));
        assert!(matches!(VaultFile::decode(&MAGIC[..]), Err(FormatError::Truncated)));
        let mut h = header(vec![]);
        h.version = 42;
        let bytes = VaultFile::new(h, vec![]).unwrap().encode();
        assert!(matches!(VaultFile::decode(&bytes), Err(FormatError::UnsupportedVersion(42))));
    }

    #[test]
    fn attribute_hash_is_pair_sensitive() {
        let salt = [3u8; SALT_LEN];
        assert_ne!(attribute_hash(&salt, "a", "bc"), attribute_hash(&salt, "ab", "c"));
        assert_ne!(attribute_hash(&salt, "a", "b"), attribute_hash(&[4u8; SALT_LEN], "a", "b"));
        assert_eq!(attribute_hash(&salt, "a", "b"), attribute_hash(&salt, "a", "b"));
    }

    #[test]
    fn index_matches_exact_subset_queries() {
        let salt = [3u8; SALT_LEN];
        let items = vec![item("a", &[("app", "git"), ("user", "joe")]), item("b", &[("app", "git")])];
        let index = build_index(&salt, &items);
        let q = |pairs: &[(&str, &str)]| -> Vec<String> {
            let query: BTreeMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            index.iter().filter(|e| e.matches(&salt, &query)).map(|e| e.id.clone()).collect()
        };
        assert_eq!(q(&[("app", "git")]), vec!["a", "b"]);
        assert_eq!(q(&[("app", "git"), ("user", "joe")]), vec!["a"]);
        assert!(q(&[("user", "bob")]).is_empty());
        assert_eq!(q(&[]), vec!["a", "b"]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager vault::format`
Expected: compile errors.

- [ ] **Step 3: Implement format.rs**

```rust
//! On-disk vault layout: `magic(8) | header_len u32 LE | header (postcard) | ciphertext`.
//! Everything before the ciphertext is the AEAD associated data.

use super::crypto::{KdfParams, NONCE_LEN, SALT_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 8] = *b"SMVAULT\0";
pub const VERSION: u16 = 1;
const MAX_HEADER: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: String,
    /// Sorted `attribute_hash` values, one per attribute pair.
    pub attr_hashes: Vec<[u8; 32]>,
}

impl IndexEntry {
    /// True when every query pair hashes to a value present in this entry.
    pub fn matches(&self, salt: &[u8; SALT_LEN], query: &BTreeMap<String, String>) -> bool {
        query.iter().all(|(k, v)| self.attr_hashes.binary_search(&attribute_hash(salt, k, v)).is_ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub version: u16,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub index: Vec<IndexEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("attributes", &self.attributes)
            .field("secret", &"..")
            .field("content_type", &self.content_type)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .finish()
    }
}

impl PartialEq for Item {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
            && self.label == o.label
            && self.attributes == o.attributes
            && *self.secret == *o.secret
            && self.content_type == o.content_type
            && self.created == o.created
            && self.modified == o.modified
    }
}
impl Eq for Item {}

/// `SHA-256(salt || len(key) LE u32 || key || value)`
pub fn attribute_hash(salt: &[u8; SALT_LEN], key: &str, value: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update((key.len() as u32).to_le_bytes());
    h.update(key.as_bytes());
    h.update(value.as_bytes());
    h.finalize().into()
}

pub fn build_index(salt: &[u8; SALT_LEN], items: &[Item]) -> Vec<IndexEntry> {
    items
        .iter()
        .map(|item| {
            let mut attr_hashes: Vec<[u8; 32]> =
                item.attributes.iter().map(|(k, v)| attribute_hash(salt, k, v)).collect();
            attr_hashes.sort_unstable();
            IndexEntry { id: item.id.clone(), attr_hashes }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("not a secret-manager vault (bad magic)")]
    BadMagic,
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u16),
    #[error("truncated vault file")]
    Truncated,
    #[error("corrupt vault: {0}")]
    Encoding(#[from] postcard::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    pub header: Header,
    /// Exact bytes preceding the ciphertext: magic, length, header.
    pub aad: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn new(header: Header, ciphertext: Vec<u8>) -> Result<Self, FormatError> {
        let aad = Self::header_bytes(&header)?;
        Ok(Self { header, aad, ciphertext })
    }

    pub fn header_bytes(header: &Header) -> Result<Vec<u8>, FormatError> {
        let body = postcard::to_allocvec(header)?;
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.aad.clone();
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<VaultFile, FormatError> {
        if bytes.len() < 8 {
            return Err(FormatError::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(FormatError::BadMagic);
        }
        if bytes.len() < 12 {
            return Err(FormatError::Truncated);
        }
        let len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        if len > MAX_HEADER || bytes.len() < 12 + len {
            return Err(FormatError::Truncated);
        }
        let header: Header = postcard::from_bytes(&bytes[12..12 + len])?;
        if header.version != VERSION {
            return Err(FormatError::UnsupportedVersion(header.version));
        }
        Ok(VaultFile { header, aad: bytes[..12 + len].to_vec(), ciphertext: bytes[12 + len..].to_vec() })
    }
}

pub fn encode_items(items: &[Item]) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    Ok(Zeroizing::new(postcard::to_allocvec(items)?))
}

pub fn decode_items(bytes: &[u8]) -> Result<Vec<Item>, FormatError> {
    Ok(postcard::from_bytes(bytes)?)
}
```

Note for `bad_magic_truncated_and_version`: the first assertion passes 12 bytes that are not the magic, so `BadMagic` wins over `Truncated`; the second passes exactly the 8 magic bytes, so `Truncated` is returned. Keep the check order as written.

- [ ] **Step 4: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager vault && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all vault tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add vault file format with hashed attribute index"
```

---

### Task 5: Vault store (create, unlock, CRUD, atomic save)

**Files:**
- Create: `crates/secret-manager/src/vault/store.rs`
- Modify: `crates/secret-manager/src/vault/mod.rs` (add `pub mod store; pub use store::{Vault, VaultError};`)
- Modify: `crates/secret-manager/Cargo.toml` (add `subtle = "2"`)

**Interfaces:**
- Produces `vault::store::Vault` with:
  - `Vault::create(path: &Path, label: &str, password: &[u8], kdf: KdfParams) -> Result<Vault, VaultError>` (writes file, returns unlocked)
  - `Vault::open(path: &Path) -> Result<Vault, VaultError>` (locked)
  - `path() -> &Path`, `label() -> &str`, `created() -> u64`, `modified() -> u64`, `is_locked() -> bool`, `kdf() -> KdfParams`
  - `item_ids() -> Vec<String>`, `has_item(&str) -> bool`, `search_ids(&BTreeMap<String,String>) -> Vec<String>` (work while locked)
  - `unlock(&mut self, password: &[u8]) -> Result<(), VaultError>`, `verify_password(&self, &[u8]) -> Result<bool, VaultError>`, `lock(&mut self)`
  - `items() -> Result<&[Item], VaultError>`, `item(&str) -> Result<&Item, VaultError>`, `search(&BTreeMap<String,String>) -> Result<Vec<&Item>, VaultError>`
  - `insert_item(&mut self, label: &str, attributes: BTreeMap<String,String>, secret: Vec<u8>, content_type: &str, replace: bool) -> Result<(String, bool), VaultError>`
  - `update_item(&mut self, id: &str, f: impl FnOnce(&mut Item)) -> Result<(), VaultError>`
  - `delete_item(&mut self, id: &str) -> Result<(), VaultError>`
  - `set_label(&mut self, &str) -> Result<(), VaultError>`
  - `change_password(&mut self, old: &[u8], new: &[u8], kdf: KdfParams) -> Result<(), VaultError>`
  - `delete_file(self) -> Result<(), VaultError>`
  - `VaultError::{Locked, WrongPassword, NoSuchItem(String), AlreadyExists(PathBuf), Format, Crypto, Io{path, source}}`

- [ ] **Step 1: Write the failing tests**

Tests module for `store.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::KdfParams;
    use std::os::unix::fs::PermissionsExt;

    const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.vault");
        (dir, path)
    }

    #[test]
    fn create_writes_private_file_and_is_unlocked() {
        let (_d, path) = tmp();
        let v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        assert!(!v.is_locked());
        assert_eq!(v.label(), "Default");
        assert!(v.items().unwrap().is_empty());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!path.with_extension("vault.tmp").exists());
        assert!(matches!(Vault::create(&path, "x", b"pw", FAST), Err(VaultError::AlreadyExists(_))));
    }

    #[test]
    fn open_is_locked_until_correct_password() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let mut v = Vault::open(&path).unwrap();
        assert!(v.is_locked());
        assert!(matches!(v.items(), Err(VaultError::Locked)));
        assert!(matches!(v.unlock(b"nope"), Err(VaultError::WrongPassword)));
        v.unlock(b"pw").unwrap();
        assert!(!v.is_locked());
        assert!(v.verify_password(b"pw").unwrap());
        assert!(!v.verify_password(b"nope").unwrap());
        v.lock();
        assert!(v.is_locked());
    }

    #[test]
    fn items_persist_and_index_search_works_locked() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let (id_a, replaced) = v.insert_item("git", attrs(&[("app", "git"), ("user", "joe")]), b"tok".to_vec(), "text/plain", false).unwrap();
        assert!(!replaced);
        let (id_b, _) = v.insert_item("other", attrs(&[("app", "git")]), b"x".to_vec(), "text/plain", false).unwrap();
        assert_ne!(id_a, id_b);
        assert!(id_a.chars().all(|c| c.is_ascii_alphanumeric()));

        let mut v = Vault::open(&path).unwrap();
        assert_eq!(v.item_ids().len(), 2);
        assert_eq!(v.search_ids(&attrs(&[("user", "joe")])), vec![id_a.clone()]);
        assert_eq!(v.search_ids(&attrs(&[("app", "git")])).len(), 2);
        v.unlock(b"pw").unwrap();
        assert_eq!(v.item(&id_a).unwrap().secret.as_slice(), b"tok");
        assert_eq!(v.search(&attrs(&[("app", "git")])).unwrap().len(), 2);
    }

    #[test]
    fn replace_update_delete() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let (id, _) = v.insert_item("git", attrs(&[("app", "git")]), b"one".to_vec(), "text/plain", false).unwrap();
        let (id2, replaced) = v.insert_item("git2", attrs(&[("app", "git")]), b"two".to_vec(), "text/plain", true).unwrap();
        assert!(replaced);
        assert_eq!(id, id2);
        assert_eq!(v.items().unwrap().len(), 1);
        assert_eq!(v.item(&id).unwrap().secret.as_slice(), b"two");
        assert_eq!(v.item(&id).unwrap().label, "git2");

        v.update_item(&id, |i| i.label = "renamed".into()).unwrap();
        assert_eq!(Vault::open(&path).unwrap().item_ids(), vec![id.clone()]);
        v.delete_item(&id).unwrap();
        assert!(matches!(v.delete_item(&id), Err(VaultError::NoSuchItem(_))));
        assert!(Vault::open(&path).unwrap().item_ids().is_empty());
    }

    #[test]
    fn change_password_rotates_salt() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"old", FAST).unwrap();
        v.insert_item("x", attrs(&[("a", "b")]), b"s".to_vec(), "text/plain", false).unwrap();
        let salt_before = v.header.salt;
        v.change_password(b"old", b"new", FAST).unwrap();
        assert_ne!(v.header.salt, salt_before);
        let mut v = Vault::open(&path).unwrap();
        assert!(matches!(v.unlock(b"old"), Err(VaultError::WrongPassword)));
        v.unlock(b"new").unwrap();
        assert_eq!(v.items().unwrap()[0].secret.as_slice(), b"s");
        assert!(matches!(v.change_password(b"wrong", b"x", FAST), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn tampered_header_fails_to_unlock() {
        let (_d, path) = tmp();
        Vault::create(&path, "Default", b"pw", FAST).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let file = crate::vault::format::VaultFile::decode(&bytes).unwrap();
        let mut header = file.header.clone();
        header.label = "evil".into();
        let forged = crate::vault::format::VaultFile::new(header, file.ciphertext).unwrap();
        std::fs::write(&path, forged.encode()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        assert_eq!(v.label(), "evil");
        assert!(matches!(v.unlock(b"pw"), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn set_label_and_delete_file() {
        let (_d, path) = tmp();
        let mut v = Vault::create(&path, "Default", b"pw", FAST).unwrap();
        v.set_label("Renamed").unwrap();
        assert_eq!(Vault::open(&path).unwrap().label(), "Renamed");
        v.delete_file().unwrap();
        assert!(!path.exists());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager vault::store`
Expected: compile errors.

- [ ] **Step 3: Implement store.rs**

```rust
//! A collection on disk: load, unlock, edit, save atomically.

use super::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};
use super::format::{self, FormatError, Header, Item, VERSION, VaultFile};
use super::now;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("collection is locked")]
    Locked,
    #[error("wrong password")]
    WrongPassword,
    #[error("no such item: {0}")]
    NoSuchItem(String),
    #[error("vault already exists: {0}")]
    AlreadyExists(PathBuf),
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
}

fn io_err(path: &Path, source: std::io::Error) -> VaultError {
    VaultError::Io { path: path.to_path_buf(), source }
}

enum State {
    Locked,
    Unlocked { key: Key, items: Vec<Item> },
}

pub struct Vault {
    path: PathBuf,
    header: Header,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    state: State,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("label", &self.header.label)
            .field("locked", &self.is_locked())
            .field("items", &self.header.index.len())
            .finish()
    }
}

impl Vault {
    pub fn create(path: &Path, label: &str, password: &[u8], kdf: KdfParams) -> Result<Vault, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_key(password, &salt, kdf)?;
        let t = now();
        let header = Header {
            version: VERSION,
            label: label.to_string(),
            created: t,
            modified: t,
            kdf,
            salt,
            nonce: [0u8; NONCE_LEN],
            index: Vec::new(),
        };
        let mut vault = Vault {
            path: path.to_path_buf(),
            header,
            aad: Vec::new(),
            ciphertext: Vec::new(),
            state: State::Unlocked { key, items: Vec::new() },
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        let bytes = std::fs::read(path).map_err(|e| io_err(path, e))?;
        let file = VaultFile::decode(&bytes)?;
        Ok(Vault {
            path: path.to_path_buf(),
            header: file.header,
            aad: file.aad,
            ciphertext: file.ciphertext,
            state: State::Locked,
        })
    }

    pub fn path(&self) -> &Path { &self.path }
    pub fn label(&self) -> &str { &self.header.label }
    pub fn created(&self) -> u64 { self.header.created }
    pub fn modified(&self) -> u64 { self.header.modified }
    pub fn kdf(&self) -> KdfParams { self.header.kdf }
    pub fn is_locked(&self) -> bool { matches!(self.state, State::Locked) }

    pub fn item_ids(&self) -> Vec<String> {
        self.header.index.iter().map(|e| e.id.clone()).collect()
    }

    pub fn has_item(&self, id: &str) -> bool {
        self.header.index.iter().any(|e| e.id == id)
    }

    /// Search by hashed attributes. Works while locked.
    pub fn search_ids(&self, query: &BTreeMap<String, String>) -> Vec<String> {
        self.header
            .index
            .iter()
            .filter(|e| e.matches(&self.header.salt, query))
            .map(|e| e.id.clone())
            .collect()
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<(), VaultError> {
        if !self.is_locked() {
            return Ok(());
        }
        let key = crypto::derive_key(password, &self.header.salt, self.header.kdf)?;
        let plain = crypto::open(&key, &self.header.nonce, &self.aad, &self.ciphertext)
            .map_err(|_| VaultError::WrongPassword)?;
        let items = format::decode_items(&plain)?;
        self.state = State::Unlocked { key, items };
        Ok(())
    }

    /// Check a password without changing lock state.
    pub fn verify_password(&self, password: &[u8]) -> Result<bool, VaultError> {
        let key = crypto::derive_key(password, &self.header.salt, self.header.kdf)?;
        match &self.state {
            State::Unlocked { key: current, .. } => Ok(current.as_bytes()[..].ct_eq(&key.as_bytes()[..]).into()),
            State::Locked => Ok(crypto::open(&key, &self.header.nonce, &self.aad, &self.ciphertext).is_ok()),
        }
    }

    pub fn lock(&mut self) {
        self.state = State::Locked;
    }

    pub fn items(&self) -> Result<&[Item], VaultError> {
        match &self.state {
            State::Unlocked { items, .. } => Ok(items),
            State::Locked => Err(VaultError::Locked),
        }
    }

    pub fn item(&self, id: &str) -> Result<&Item, VaultError> {
        self.items()?.iter().find(|i| i.id == id).ok_or_else(|| VaultError::NoSuchItem(id.to_string()))
    }

    pub fn search(&self, query: &BTreeMap<String, String>) -> Result<Vec<&Item>, VaultError> {
        Ok(self
            .items()?
            .iter()
            .filter(|i| query.iter().all(|(k, v)| i.attributes.get(k) == Some(v)))
            .collect())
    }

    fn items_mut(&mut self) -> Result<&mut Vec<Item>, VaultError> {
        match &mut self.state {
            State::Unlocked { items, .. } => Ok(items),
            State::Locked => Err(VaultError::Locked),
        }
    }

    /// Insert an item. With `replace`, an item whose attributes are exactly
    /// equal is overwritten instead. Returns `(id, replaced)`.
    pub fn insert_item(
        &mut self,
        label: &str,
        attributes: BTreeMap<String, String>,
        secret: Vec<u8>,
        content_type: &str,
        replace: bool,
    ) -> Result<(String, bool), VaultError> {
        let t = now();
        let result = {
            let items = self.items_mut()?;
            let pos = if replace { items.iter().position(|i| i.attributes == attributes) } else { None };
            if let Some(p) = pos {
                let existing = &mut items[p];
                existing.label = label.to_string();
                existing.secret = Zeroizing::new(secret);
                existing.content_type = content_type.to_string();
                existing.modified = t;
                (existing.id.clone(), true)
            } else {
                let id = uuid::Uuid::new_v4().simple().to_string();
                items.push(Item {
                    id: id.clone(),
                    label: label.to_string(),
                    attributes,
                    secret: Zeroizing::new(secret),
                    content_type: content_type.to_string(),
                    created: t,
                    modified: t,
                });
                (id, false)
            }
        };
        self.save()?;
        Ok(result)
    }

    pub fn update_item(&mut self, id: &str, f: impl FnOnce(&mut Item)) -> Result<(), VaultError> {
        {
            let items = self.items_mut()?;
            let item = items.iter_mut().find(|i| i.id == id).ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            f(item);
            item.modified = now();
        }
        self.save()
    }

    pub fn delete_item(&mut self, id: &str) -> Result<(), VaultError> {
        {
            let items = self.items_mut()?;
            let pos = items.iter().position(|i| i.id == id).ok_or_else(|| VaultError::NoSuchItem(id.to_string()))?;
            items.remove(pos);
        }
        self.save()
    }

    pub fn set_label(&mut self, label: &str) -> Result<(), VaultError> {
        self.items_mut()?;
        self.header.label = label.to_string();
        self.save()
    }

    /// Re-encrypt under a new password with a fresh salt. Unlocks with `old` if locked.
    pub fn change_password(&mut self, old: &[u8], new: &[u8], kdf: KdfParams) -> Result<(), VaultError> {
        if self.is_locked() {
            self.unlock(old)?;
        } else if !self.verify_password(old)? {
            return Err(VaultError::WrongPassword);
        }
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_key(new, &salt, kdf)?;
        self.header.salt = salt;
        self.header.kdf = kdf;
        if let State::Unlocked { key: k, .. } = &mut self.state {
            *k = key;
        }
        self.save()
    }

    pub fn delete_file(self) -> Result<(), VaultError> {
        std::fs::remove_file(&self.path).map_err(|e| io_err(&self.path, e))?;
        let _ = std::fs::remove_file(self.path.with_extension("vault.tmp"));
        Ok(())
    }

    fn save(&mut self) -> Result<(), VaultError> {
        let State::Unlocked { key, items } = &self.state else {
            return Err(VaultError::Locked);
        };
        self.header.modified = now();
        self.header.nonce = crypto::random_bytes::<NONCE_LEN>();
        self.header.index = format::build_index(&self.header.salt, items);
        let aad = VaultFile::header_bytes(&self.header)?;
        let plain = format::encode_items(items)?;
        let ciphertext = crypto::seal(key, &self.header.nonce, &aad, &plain)?;
        let mut bytes = aad.clone();
        bytes.extend_from_slice(&ciphertext);
        write_atomic(&self.path, &bytes)?;
        self.aad = aad;
        self.ciphertext = ciphertext;
        Ok(())
    }
}

/// Write to `<path>.tmp`, fsync, rename over `path`, fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let tmp = path.with_extension("vault.tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_err(&tmp, e))?;
    f.write_all(bytes).map_err(|e| io_err(&tmp, e))?;
    f.sync_all().map_err(|e| io_err(&tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| io_err(path, e))?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
```

Add `use std::os::unix::fs::PermissionsExt;` at the top (needed by `from_mode`). Add `subtle = "2"` under `[dependencies]` in the crate manifest.

- [ ] **Step 4: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager vault && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all vault tests pass, including 7 store tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add vault store with atomic writes and password rotation"
```

---

### Task 6: Session transport (plain and DH + AES-128-CBC)

**Files:**
- Create: `crates/secret-manager/src/session/mod.rs`, `crates/secret-manager/src/session/dh.rs`
- Modify: `crates/secret-manager/src/lib.rs` (add `pub mod session;`)

**Interfaces:**
- Produces:
  - `session::{ALGORITHM_PLAIN = "plain", ALGORITHM_DH = "dh-ietf1024-sha256-aes128-cbc-pkcs7"}`
  - `session::dh::KeyPair::generate() -> KeyPair`, `public_bytes(&self) -> &[u8]`, `derive_aes_key(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8;16]>, DhError>`
  - `session::dh::DhError::{InvalidPeerKey, Hkdf}`
  - `session::SessionCipher::{Plain, Aes{key}}` with `plain()`, `from_dh(&KeyPair, peer_public: &[u8]) -> Result<Self, SessionError>`, `algorithm(&self) -> &'static str`, `encrypt(&self, &[u8]) -> (Vec<u8> /*parameters*/, Vec<u8> /*value*/)`, `decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>, SessionError>`
  - `session::SessionError::{BadIv(usize), Decrypt, Dh(DhError)}`

- [ ] **Step 1: Write the failing tests**

Tests module in `session/dh.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_key() {
        let client = KeyPair::generate();
        let server = KeyPair::generate();
        let k1 = client.derive_aes_key(server.public_bytes()).unwrap();
        let k2 = server.derive_aes_key(client.public_bytes()).unwrap();
        assert_eq!(*k1, *k2);
        assert!(client.public_bytes().len() <= PRIME_BYTES);
        let other = KeyPair::generate();
        assert_ne!(*k1, *client.derive_aes_key(other.public_bytes()).unwrap());
    }

    #[test]
    fn degenerate_peer_keys_are_rejected() {
        let me = KeyPair::generate();
        let p = prime();
        for bad in [BigUint::from(0u32), BigUint::from(1u32), &p - BigUint::from(1u32), p.clone()] {
            assert!(matches!(me.derive_aes_key(&bad.to_bytes_be()), Err(DhError::InvalidPeerKey)));
        }
    }

    #[test]
    fn prime_is_1024_bits() {
        assert_eq!(prime().bits(), 1024);
    }
}
```

Tests module in `session/mod.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_passes_through() {
        let c = SessionCipher::plain();
        let (params, value) = c.encrypt(b"pw");
        assert!(params.is_empty());
        assert_eq!(value, b"pw");
        assert_eq!(c.decrypt(&params, &value).unwrap().as_slice(), b"pw");
        assert_eq!(c.algorithm(), ALGORITHM_PLAIN);
    }

    #[test]
    fn aes_round_trip_between_peers() {
        let client = dh::KeyPair::generate();
        let server = dh::KeyPair::generate();
        let c = SessionCipher::from_dh(&client, server.public_bytes()).unwrap();
        let s = SessionCipher::from_dh(&server, client.public_bytes()).unwrap();
        let (iv, ct) = c.encrypt(b"correct horse battery staple");
        assert_eq!(iv.len(), 16);
        assert_eq!(ct.len() % 16, 0);
        assert_ne!(&ct[..], b"correct horse battery staple");
        assert_eq!(s.decrypt(&iv, &ct).unwrap().as_slice(), b"correct horse battery staple");
        assert_eq!(c.algorithm(), ALGORITHM_DH);
        let (iv2, _) = c.encrypt(b"x");
        assert_ne!(iv, iv2);
    }

    #[test]
    fn aes_rejects_bad_iv_and_truncated_ciphertext() {
        let a = dh::KeyPair::generate();
        let b = dh::KeyPair::generate();
        let c = SessionCipher::from_dh(&a, b.public_bytes()).unwrap();
        let (iv, ct) = c.encrypt(b"hello");
        assert!(matches!(c.decrypt(&iv[..8], &ct), Err(SessionError::BadIv(8))));
        assert!(matches!(c.decrypt(&iv, &ct[..ct.len() - 1]), Err(SessionError::Decrypt)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager session`
Expected: compile errors.

- [ ] **Step 3: Implement dh.rs**

```rust
//! Diffie-Hellman over the RFC 2409 second Oakley group (1024-bit MODP, g = 2),
//! with HKDF-SHA256 to a 128-bit AES key. Matches libsecret and gnome-keyring:
//! the shared secret is left-padded to 128 bytes before HKDF, salt and info are empty.

use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::One;
use sha2::Sha256;
use zeroize::Zeroizing;

const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
pub const PRIME_BYTES: usize = 128;

pub fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid constant")
}

#[derive(Debug, thiserror::Error)]
pub enum DhError {
    #[error("invalid peer public key")]
    InvalidPeerKey,
    #[error("hkdf expansion failed")]
    Hkdf,
}

/// Ephemeral DH key pair. The private exponent is not zeroized on drop
/// (`BigUint` has no zeroize support); keys live only for one session.
pub struct KeyPair {
    private: BigUint,
    public: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let p = prime();
        let two = BigUint::from(2u32);
        let raw = crate::vault::crypto::random_bytes::<PRIME_BYTES>();
        // x in [2, p-2]
        let private = BigUint::from_bytes_be(&raw) % (&p - BigUint::from(3u32)) + &two;
        let public = two.modpow(&private, &p).to_bytes_be();
        KeyPair { private, public }
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    pub fn derive_aes_key(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 16]>, DhError> {
        let p = prime();
        let peer = BigUint::from_bytes_be(peer_public);
        if peer <= BigUint::one() || peer >= &p - BigUint::one() {
            return Err(DhError::InvalidPeerKey);
        }
        let shared = peer.modpow(&self.private, &p).to_bytes_be();
        if shared.len() > PRIME_BYTES {
            return Err(DhError::InvalidPeerKey);
        }
        let mut ikm = Zeroizing::new([0u8; PRIME_BYTES]);
        ikm[PRIME_BYTES - shared.len()..].copy_from_slice(&shared);
        let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
        let mut okm = Zeroizing::new([0u8; 16]);
        hk.expand(&[], &mut okm[..]).map_err(|_| DhError::Hkdf)?;
        Ok(okm)
    }
}
```

- [ ] **Step 4: Implement session/mod.rs**

```rust
//! Transport encryption for secrets crossing the bus.

pub mod dh;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use zeroize::Zeroizing;

pub const ALGORITHM_PLAIN: &str = "plain";
pub const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("bad IV length {0}, expected 16")]
    BadIv(usize),
    #[error("secret decryption failed")]
    Decrypt,
    #[error(transparent)]
    Dh(#[from] dh::DhError),
}

pub enum SessionCipher {
    Plain,
    Aes { key: Zeroizing<[u8; 16]> },
}

impl SessionCipher {
    pub fn plain() -> Self {
        SessionCipher::Plain
    }

    pub fn from_dh(pair: &dh::KeyPair, peer_public: &[u8]) -> Result<Self, SessionError> {
        Ok(SessionCipher::Aes { key: pair.derive_aes_key(peer_public)? })
    }

    pub fn algorithm(&self) -> &'static str {
        match self {
            SessionCipher::Plain => ALGORITHM_PLAIN,
            SessionCipher::Aes { .. } => ALGORITHM_DH,
        }
    }

    /// Returns `(parameters, value)` for the `(oayays)` secret struct.
    pub fn encrypt(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            SessionCipher::Plain => (Vec::new(), plaintext.to_vec()),
            SessionCipher::Aes { key } => {
                let iv = crate::vault::crypto::random_bytes::<16>();
                let enc = Aes128CbcEnc::new(GenericArray::from_slice(&key[..]), GenericArray::from_slice(&iv));
                (iv.to_vec(), enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
            }
        }
    }

    pub fn decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        match self {
            SessionCipher::Plain => Ok(Zeroizing::new(value.to_vec())),
            SessionCipher::Aes { key } => {
                if parameters.len() != 16 {
                    return Err(SessionError::BadIv(parameters.len()));
                }
                let dec = Aes128CbcDec::new(GenericArray::from_slice(&key[..]), GenericArray::from_slice(parameters));
                dec.decrypt_padded_vec_mut::<Pkcs7>(value).map(Zeroizing::new).map_err(|_| SessionError::Decrypt)
            }
        }
    }
}
```

Add `pub mod session;` to `lib.rs`.

- [ ] **Step 5: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager session && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 6 tests pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Add plain and DH-AES session transport"
```

---

### Task 7: Pinentry (Assuan) client

**Files:**
- Create: `crates/secret-manager/src/prompt/mod.rs`, `crates/secret-manager/src/prompt/pinentry.rs`
- Create: `crates/secret-manager/tests/fixtures/fake-pinentry.sh` (executable)
- Modify: `crates/secret-manager/src/lib.rs` (add `pub mod prompt;`)

**Interfaces:**
- Produces:
  - `prompt::pinentry::PinRequest { title: String, description: String, prompt: String, error: Option<String>, repeat: bool }` (Default)
  - `prompt::pinentry::PinOutcome::{Pin(Zeroizing<String>), Cancelled}`
  - `prompt::pinentry::Pinentry::new(program) -> Self`, `.env(key, value) -> Self` (builder), `async fn ask(&self, &PinRequest) -> Result<PinOutcome, PinentryError>`, `async fn confirm(&self, &PinRequest) -> Result<bool, PinentryError>`
  - `prompt::pinentry::{escape(&str) -> String, unescape(&str) -> Result<String, PinentryError>, is_cancel(u32) -> bool}`
  - `prompt::pinentry::PinentryError::{Spawn{program, source}, Io, Protocol(String), Assuan{code, message}}`
  - Test fixture env contract: `FAKE_PIN` (pin, unset = cancel), `FAKE_CONFIRM` (`yes` = confirmed), `FAKE_LOG` (path appended with every command line)

- [ ] **Step 1: Create the fake pinentry fixture**

`crates/secret-manager/tests/fixtures/fake-pinentry.sh`:
```sh
#!/bin/sh
# Scripted Assuan pinentry for tests.
#   FAKE_PIN      value answered to GETPIN (Assuan-escaped); unset => cancel
#   FAKE_CONFIRM  "yes" => CONFIRM succeeds; anything else => cancel
#   FAKE_LOG      file that receives every command line
echo "OK Pleased to meet you"
while IFS= read -r line; do
  if [ -n "$FAKE_LOG" ]; then printf '%s\n' "$line" >> "$FAKE_LOG"; fi
  case "$line" in
    GETPIN*)
      if [ -n "$FAKE_PIN" ]; then
        printf 'D %s\n' "$FAKE_PIN"
        echo "OK"
      else
        echo "ERR 83886179 Operation cancelled <Pinentry>"
      fi
      ;;
    CONFIRM*)
      if [ "$FAKE_CONFIRM" = "yes" ]; then echo "OK"; else echo "ERR 83886179 Operation cancelled <Pinentry>"; fi
      ;;
    BYE*)
      echo "OK closing connection"
      exit 0
      ;;
    *)
      echo "OK"
      ;;
  esac
done
```

Run: `chmod +x crates/secret-manager/tests/fixtures/fake-pinentry.sh`

- [ ] **Step 2: Write the failing tests**

Tests module in `prompt/pinentry.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> Pinentry {
        Pinentry::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-pinentry.sh"))
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
    fn escaping_round_trips() {
        assert_eq!(escape("a%b\nc\rd"), "a%25b%0Ac%0Dd");
        assert_eq!(unescape("a%25b%0Ac%0Dd").unwrap(), "a%b\nc\rd");
        assert!(unescape("bad%zz").is_err());
        assert!(is_cancel(83886179));
        assert!(!is_cancel(83886180));
    }

    #[tokio::test]
    async fn returns_pin() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let p = fake().env("FAKE_PIN", "hun%25ter2").env("FAKE_LOG", log.path());
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

    #[tokio::test]
    async fn confirm_yes_and_no() {
        assert!(fake().env("FAKE_CONFIRM", "yes").confirm(&req()).await.unwrap());
        assert!(!fake().env("FAKE_CONFIRM", "no").confirm(&req()).await.unwrap());
    }

    #[tokio::test]
    async fn missing_program_is_spawn_error() {
        let err = Pinentry::new("/nonexistent/pinentry").ask(&req()).await.unwrap_err();
        assert!(matches!(err, PinentryError::Spawn { .. }));
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p secret-manager prompt`
Expected: compile errors.

- [ ] **Step 4: Implement pinentry.rs**

`prompt/mod.rs`:
```rust
//! Password prompting through pinentry.
pub mod pinentry;
pub use pinentry::{PinOutcome, PinRequest, Pinentry, PinentryError};
```

`prompt/pinentry.rs`:
```rust
//! Minimal Assuan client that drives a `pinentry` binary.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

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

#[derive(Debug, thiserror::Error)]
pub enum PinentryError {
    #[error("cannot start {program}: {source}")]
    Spawn { program: PathBuf, source: std::io::Error },
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
}

/// GPG_ERR_CANCELED is 99 in the low 16 bits of an Assuan error code.
pub fn is_cancel(code: u32) -> bool {
    code & 0xFFFF == 99
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            c => out.push(c),
        }
    }
    out
}

pub fn unescape(s: &str) -> Result<String, PinentryError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(|| PinentryError::Protocol("truncated escape".into()))?;
            let hex = std::str::from_utf8(hex).map_err(|_| PinentryError::Protocol("bad escape".into()))?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| PinentryError::Protocol(format!("bad escape %{hex}")))?;
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PinentryError::Protocol("pin is not utf-8".into()))
}

impl Pinentry {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self { program: program.into(), env: Vec::new() }
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub async fn ask(&self, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
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
    }

    /// Yes/no question. Cancel or any pinentry error means "no".
    pub async fn confirm(&self, req: &PinRequest) -> Result<bool, PinentryError> {
        let mut conn = self.connect().await?;
        conn.setup(req).await?;
        let ok = match conn.command("CONFIRM").await {
            Ok(()) => true,
            Err(PinentryError::Assuan { .. }) => false,
            Err(e) => return Err(e),
        };
        conn.bye().await;
        Ok(ok)
    }

    async fn connect(&self) -> Result<Assuan, PinentryError> {
        let mut cmd = Command::new(&self.program);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|source| PinentryError::Spawn { program: self.program.clone(), source })?;
        let stdin = child.stdin.take().ok_or_else(|| PinentryError::Protocol("no stdin".into()))?;
        let stdout = child.stdout.take().ok_or_else(|| PinentryError::Protocol("no stdout".into()))?;
        let mut conn = Assuan { _child: child, stdin, stdout: BufReader::new(stdout) };
        conn.expect_ok().await?; // greeting
        for opt in tty_options() {
            conn.command_lenient(&opt).await?;
        }
        Ok(conn)
    }
}

/// Options that let pinentry-curses/tty find the terminal and locale.
fn tty_options() -> Vec<String> {
    let mut opts = Vec::new();
    if let Ok(tty) = std::env::var("GPG_TTY") {
        opts.push(format!("OPTION ttyname={tty}"));
    }
    if let Ok(term) = std::env::var("TERM") {
        opts.push(format!("OPTION ttytype={term}"));
    }
    let ctype = ["LC_ALL", "LC_CTYPE", "LANG"].iter().find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()));
    if let Some(c) = ctype {
        opts.push(format!("OPTION lc-ctype={c}"));
    }
    opts
}

enum Reply {
    Ok,
    Data(String),
    Err { code: u32, message: String },
}

struct Assuan {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Assuan {
    async fn setup(&mut self, req: &PinRequest) -> Result<(), PinentryError> {
        if !req.title.is_empty() {
            self.command_lenient(&format!("SETTITLE {}", escape(&req.title))).await?;
        }
        self.command(&format!("SETDESC {}", escape(&req.description))).await?;
        self.command(&format!("SETPROMPT {}", escape(&req.prompt))).await?;
        if let Some(e) = &req.error {
            self.command_lenient(&format!("SETERROR {}", escape(e))).await?;
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
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).await?;
            if n == 0 {
                return Err(PinentryError::Protocol("pinentry closed the connection".into()));
            }
            let line = line.trim_end_matches(['\n', '\r']);
            if line == "OK" || line.starts_with("OK ") {
                return Ok(Reply::Ok);
            }
            if let Some(rest) = line.strip_prefix("D ") {
                return Ok(Reply::Data(rest.to_string()));
            }
            if let Some(rest) = line.strip_prefix("ERR ") {
                let (code, message) = rest.split_once(' ').unwrap_or((rest, ""));
                let code = code.parse::<u32>().map_err(|_| PinentryError::Protocol(format!("bad error line: {line}")))?;
                return Ok(Reply::Err { code, message: message.to_string() });
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
        let mut pin = Zeroizing::new(String::new());
        loop {
            match self.read_reply().await? {
                Reply::Data(d) => pin.push_str(&unescape(&d)?),
                Reply::Ok => return Ok(pin),
                Reply::Err { code, message } => return Err(PinentryError::Assuan { code, message }),
            }
        }
    }

    async fn bye(&mut self) {
        let _ = self.send("BYE").await;
        let _ = self.read_reply().await;
    }
}
```

Add `pub mod prompt;` to `lib.rs`.

- [ ] **Step 5: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager prompt && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Add Assuan pinentry client with scripted test fixture"
```

---

### Task 8: Async control socket server

**Files:**
- Create: `crates/secret-manager/src/control/mod.rs`, `crates/secret-manager/src/control/server.rs`
- Modify: `crates/secret-manager/src/lib.rs` (add `pub mod control;`)

**Interfaces:**
- Consumes: `control_protocol::{Request, Response, encode_frame, decode_frame, MAX_FRAME, call}`
- Produces:
  - `control::Handler = Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>`
  - `control::ControlServer::bind(path: &Path) -> io::Result<ControlServer>`, `path(&self) -> &Path`, `async fn run(self, handler: Handler)` (never returns; dropping the future removes the socket)
  - `control::read_frame<R: AsyncRead + Unpin>(&mut R) -> io::Result<Vec<u8>>`

- [ ] **Step 1: Write the failing tests**

Tests module in `control/server.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use control_protocol::{CollectionStatus, call};
    use std::os::unix::fs::PermissionsExt;

    fn handler() -> Handler {
        Arc::new(|req: Request| {
            Box::pin(async move {
                match req {
                    Request::Status => Response::Status {
                        collections: vec![CollectionStatus { id: "default".into(), label: "Default".into(), locked: true, items: 0 }],
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
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(sock.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        let task = tokio::spawn(server.run(handler()));

        let s = sock.clone();
        let resp = tokio::task::spawn_blocking(move || call(&s, &Request::Status)).await.unwrap().unwrap();
        assert!(matches!(resp, Response::Status { uptime_secs: 1, .. }));
        let s = sock.clone();
        let resp = tokio::task::spawn_blocking(move || call(&s, &Request::Lock { collection: None })).await.unwrap().unwrap();
        assert_eq!(resp, Response::Ok);

        task.abort();
        let _ = task.await;
        assert!(!sock.exists(), "socket removed when server dropped");
    }

    #[tokio::test]
    async fn malformed_request_gets_error_response() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        let server = ControlServer::bind(&sock).await.unwrap();
        let task = tokio::spawn(server.run(handler()));
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream.write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff]).await.unwrap();
        let body = read_frame(&mut stream).await.unwrap();
        let resp: Response = control_protocol::decode_frame(&body).unwrap();
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager control`
Expected: compile errors.

- [ ] **Step 3: Implement the server**

`control/mod.rs`:
```rust
//! Unix control socket used by the CLI and the PAM module.
pub mod server;
pub use server::{ControlServer, Handler, read_frame};
```

`control/server.rs`:
```rust
use control_protocol::{MAX_FRAME, Request, Response, decode_frame, encode_frame};
use std::fs::Permissions;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub type Handler = Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlServer {
    /// Create the parent directory (0700), replace any stale socket, bind, chmod 0600.
    pub async fn bind(path: &Path) -> std::io::Result<ControlServer> {
        let dir = path.parent().ok_or_else(|| std::io::Error::other("socket path has no parent"))?;
        tokio::fs::create_dir_all(dir).await?;
        tokio::fs::set_permissions(dir, Permissions::from_mode(0o700)).await?;
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(path)?;
        tokio::fs::set_permissions(path, Permissions::from_mode(0o600)).await?;
        Ok(ControlServer { listener, path: path.to_path_buf() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop. One request/response per connection.
    pub async fn run(self, handler: Handler) {
        loop {
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
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, handler).await {
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
            cred.uid() == me || cred.uid() == 0
        }
        Err(_) => false,
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!("frame of {len} bytes exceeds limit")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

async fn handle_connection(mut stream: UnixStream, handler: Handler) -> std::io::Result<()> {
    let body = read_frame(&mut stream).await?;
    let response = match decode_frame::<Request>(&body) {
        Ok(req) => handler(req).await,
        Err(e) => Response::Error(format!("malformed request: {e}")),
    };
    let frame = encode_frame(&response).map_err(std::io::Error::other)?;
    stream.write_all(&frame).await?;
    stream.shutdown().await
}
```

Add `pub mod control;` to `lib.rs`.

- [ ] **Step 4: Run tests, fmt, clippy**

Run: `cargo test -p secret-manager control && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add async control socket server with peer credential check"
```

---

### Task 9: D-Bus foundation: paths, errors, state, Session, Service.OpenSession, daemon skeleton, test fixture

**Files:**
- Create: `crates/secret-manager/src/dbus/mod.rs`, `paths.rs`, `errors.rs`, `state.rs`, `session.rs`, `service.rs`, `proxies.rs`
- Create: `crates/secret-manager/src/daemon.rs`
- Create: `crates/secret-manager/tests/common/mod.rs`, `crates/secret-manager/tests/dbus_service.rs`
- Modify: `crates/secret-manager/src/lib.rs` (add `pub mod dbus; pub mod daemon;`)

**Interfaces:**
- Consumes: `vault::{Vault, VaultError, collection_id_from_label, crypto::KdfParams}`, `session::{SessionCipher, dh::KeyPair, ALGORITHM_*}`, `prompt::Pinentry`, `config::Config`
- Produces:
  - `dbus::paths::{BUS_NAME, SERVICE_PATH, root(), service(), collection(id), item(cid, iid), session(n), prompt(n), alias(name) -> Option<OwnedObjectPath>, is_segment(&str) -> bool, parse(&str) -> Option<Target>}` and `Target::{Collection(String), Alias(String), Item{collection, item}, AliasItem{alias, item}}`
  - `dbus::errors::{Error::{ZBus, IsLocked, NoSession, NoSuchObject}, Result<T>}` with `Error::failed(msg)`, `Error::invalid_args(msg)`, `Error::not_supported(msg)`, `From<VaultError>`, `From<zbus::fdo::Error>`
  - `dbus::state::{ServiceState, Shared = Arc<tokio::sync::Mutex<ServiceState>>, SessionEntry{owner, cipher}}` with `ServiceState::new(vault_dir, kdf, pinentry)`, `load_vaults() -> io::Result<Vec<String>>`, `save_aliases() -> io::Result<()>`, `resolve_collection(&str) -> Option<String>`, `resolve_item(&str) -> Option<(String, String)>`, `collection_id_of_path(&str) -> Option<String>`, `is_unlocked_path(&str) -> bool`, `new_session_path()`, `new_prompt_path()`, `cipher(&str) -> Result<&SessionCipher>`, `touch()`, `search_all(&BTreeMap) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)`, `unique_collection_id(&str) -> String`, pub fields `vault_dir, kdf, pinentry, collections, aliases, sessions, prompt_owners, started, last_activity`
  - `dbus::state::{load_aliases(dir) -> io::Result<BTreeMap<String,String>>, save_aliases_to(dir, &BTreeMap) -> io::Result<()>}`
  - `dbus::session::{SecretStruct{session, parameters, value, content_type}, Session::new(state, path)}`
  - `dbus::service::Service::new(state)` implementing `OpenSession`, `SearchItems`, `ReadAlias`, `Collections`, and the three collection signals (`ServiceSignals` trait)
  - `dbus::proxies::{ServiceProxy, CollectionProxy, ItemProxy, SessionProxy, PromptProxy}`
  - `dbus::sender(&Header) -> String`
  - `daemon::{Daemon{connection, state}, DaemonOptions{config, bus, control_socket, pinentry_env, idle_check_interval}, BusAddress::{Session, Address(String)}, DaemonError::{NameTaken, ZBus, Io, Control}}` with `Daemon::start(opts)`, `Daemon::shutdown(self)`
  - Test fixture `common::Fixture::start().await`, `Fixture::start_with_pin(Option<&str>).await`, fields `bus_address, data_dir, runtime_dir, daemon, pinentry_log`, methods `client().await -> Connection`, `sm() -> assert_cmd::Command`, `envs() -> Vec<(String, String)>`, `default_collection() -> OwnedObjectPath`; `common::PASSWORD = "pw"`

- [ ] **Step 1: Write paths.rs with its unit tests**

```rust
//! Object path layout of the service.

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

pub const BUS_NAME: &str = "org.freedesktop.secrets";
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const COLLECTIONS_PREFIX: &str = "/org/freedesktop/secrets/collection/";
pub const ALIASES_PREFIX: &str = "/org/freedesktop/secrets/aliases/";
pub const SESSIONS_PREFIX: &str = "/org/freedesktop/secrets/session/";
pub const PROMPTS_PREFIX: &str = "/org/freedesktop/secrets/prompt/";

/// D-Bus object path segment: `[A-Za-z0-9_]+`.
pub fn is_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn owned(s: String) -> OwnedObjectPath {
    ObjectPath::try_from(s).expect("path built from validated segments").into()
}

pub fn root() -> OwnedObjectPath {
    ObjectPath::from_static_str_unchecked("/").into()
}

pub fn service() -> OwnedObjectPath {
    ObjectPath::from_static_str_unchecked(SERVICE_PATH).into()
}

pub fn collection(id: &str) -> OwnedObjectPath {
    owned(format!("{COLLECTIONS_PREFIX}{id}"))
}

pub fn item(collection_id: &str, item_id: &str) -> OwnedObjectPath {
    owned(format!("{COLLECTIONS_PREFIX}{collection_id}/{item_id}"))
}

pub fn alias(name: &str) -> Option<OwnedObjectPath> {
    is_segment(name).then(|| owned(format!("{ALIASES_PREFIX}{name}")))
}

pub fn session(n: u64) -> OwnedObjectPath {
    owned(format!("{SESSIONS_PREFIX}s{n}"))
}

pub fn prompt(n: u64) -> OwnedObjectPath {
    owned(format!("{PROMPTS_PREFIX}p{n}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Collection(String),
    Alias(String),
    Item { collection: String, item: String },
    AliasItem { alias: String, item: String },
}

pub fn parse(path: &str) -> Option<Target> {
    let split = |rest: &str| -> Option<(String, Option<String>)> {
        let mut parts = rest.split('/');
        let first = parts.next().filter(|s| is_segment(s))?.to_string();
        let second = match parts.next() {
            None => None,
            Some(s) if is_segment(s) => Some(s.to_string()),
            Some(_) => return None,
        };
        if parts.next().is_some() {
            return None;
        }
        Some((first, second))
    };
    if let Some(rest) = path.strip_prefix(COLLECTIONS_PREFIX) {
        return match split(rest)? {
            (collection, None) => Some(Target::Collection(collection)),
            (collection, Some(item)) => Some(Target::Item { collection, item }),
        };
    }
    if let Some(rest) = path.strip_prefix(ALIASES_PREFIX) {
        return match split(rest)? {
            (alias, None) => Some(Target::Alias(alias)),
            (alias, Some(item)) => Some(Target::AliasItem { alias, item }),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_paths() {
        assert_eq!(collection("default").as_str(), "/org/freedesktop/secrets/collection/default");
        assert_eq!(item("default", "abc").as_str(), "/org/freedesktop/secrets/collection/default/abc");
        assert_eq!(alias("default").unwrap().as_str(), "/org/freedesktop/secrets/aliases/default");
        assert!(alias("bad-name").is_none());
        assert_eq!(session(3).as_str(), "/org/freedesktop/secrets/session/s3");
        assert_eq!(prompt(7).as_str(), "/org/freedesktop/secrets/prompt/p7");
        assert_eq!(parse("/org/freedesktop/secrets/collection/default"), Some(Target::Collection("default".into())));
        assert_eq!(
            parse("/org/freedesktop/secrets/collection/default/abc"),
            Some(Target::Item { collection: "default".into(), item: "abc".into() })
        );
        assert_eq!(parse("/org/freedesktop/secrets/aliases/default"), Some(Target::Alias("default".into())));
        assert_eq!(
            parse("/org/freedesktop/secrets/aliases/default/abc"),
            Some(Target::AliasItem { alias: "default".into(), item: "abc".into() })
        );
        assert_eq!(parse("/org/freedesktop/secrets/collection/a/b/c"), None);
        assert_eq!(parse("/org/freedesktop/secrets"), None);
        assert_eq!(parse("/"), None);
    }
}
```

- [ ] **Step 2: Write errors.rs**

```rust
//! Errors in the `org.freedesktop.Secret.Error` namespace.

use crate::vault::VaultError;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked,
    NoSession,
    NoSuchObject,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn failed(msg: impl std::fmt::Display) -> Self {
        Error::ZBus(zbus::fdo::Error::Failed(msg.to_string()).into())
    }

    pub fn invalid_args(msg: impl std::fmt::Display) -> Self {
        Error::ZBus(zbus::fdo::Error::InvalidArgs(msg.to_string()).into())
    }

    pub fn not_supported(msg: impl std::fmt::Display) -> Self {
        Error::ZBus(zbus::fdo::Error::NotSupported(msg.to_string()).into())
    }
}

impl From<VaultError> for Error {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => Error::IsLocked,
            VaultError::NoSuchItem(_) => Error::NoSuchObject,
            other => Error::failed(other),
        }
    }
}

impl From<zbus::fdo::Error> for Error {
    fn from(e: zbus::fdo::Error) -> Self {
        Error::ZBus(e.into())
    }
}
```

- [ ] **Step 3: Write state.rs with unit tests**

```rust
//! Shared daemon state behind one async mutex.

use super::errors::{Error, Result};
use super::paths::{self, Target};
use crate::prompt::Pinentry;
use crate::session::SessionCipher;
use crate::vault::crypto::KdfParams;
use crate::vault::{Vault, collection_id_from_label};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zbus::zvariant::OwnedObjectPath;

pub type Shared = Arc<tokio::sync::Mutex<ServiceState>>;

pub struct SessionEntry {
    /// Unique bus name of the client that opened the session.
    pub owner: String,
    pub cipher: SessionCipher,
}

pub struct ServiceState {
    pub vault_dir: PathBuf,
    pub kdf: KdfParams,
    pub pinentry: Pinentry,
    pub collections: BTreeMap<String, Vault>,
    pub aliases: BTreeMap<String, String>,
    /// session object path -> entry
    pub sessions: BTreeMap<String, SessionEntry>,
    /// prompt object path -> owner unique bus name
    pub prompt_owners: BTreeMap<String, String>,
    pub started: Instant,
    pub last_activity: Instant,
    next_session: u64,
    next_prompt: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct AliasFile {
    aliases: BTreeMap<String, String>,
}

const ALIAS_FILE: &str = "aliases.toml";

pub fn load_aliases(dir: &Path) -> std::io::Result<BTreeMap<String, String>> {
    match std::fs::read_to_string(dir.join(ALIAS_FILE)) {
        Ok(text) => toml::from_str::<AliasFile>(&text)
            .map(|f| f.aliases)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e),
    }
}

pub fn save_aliases_to(dir: &Path, aliases: &BTreeMap<String, String>) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let text = toml::to_string(&AliasFile { aliases: aliases.clone() })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(dir.join(ALIAS_FILE), text)
}

impl ServiceState {
    pub fn new(vault_dir: PathBuf, kdf: KdfParams, pinentry: Pinentry) -> Self {
        let now = Instant::now();
        Self {
            vault_dir,
            kdf,
            pinentry,
            collections: BTreeMap::new(),
            aliases: BTreeMap::new(),
            sessions: BTreeMap::new(),
            prompt_owners: BTreeMap::new(),
            started: now,
            last_activity: now,
            next_session: 0,
            next_prompt: 0,
        }
    }

    /// Open every `<id>.vault` in the vault directory that is not loaded yet, and
    /// reload aliases. Returns the ids that were newly loaded.
    pub fn load_vaults(&mut self) -> std::io::Result<Vec<String>> {
        std::fs::create_dir_all(&self.vault_dir)?;
        let mut new_ids = Vec::new();
        for entry in std::fs::read_dir(&self.vault_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("vault") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
            if !paths::is_segment(&id) || self.collections.contains_key(&id) {
                continue;
            }
            match Vault::open(&path) {
                Ok(v) => {
                    self.collections.insert(id.clone(), v);
                    new_ids.push(id);
                }
                Err(e) => tracing::warn!("skipping {}: {e}", path.display()),
            }
        }
        self.aliases = load_aliases(&self.vault_dir)?;
        Ok(new_ids)
    }

    pub fn save_aliases(&self) -> std::io::Result<()> {
        save_aliases_to(&self.vault_dir, &self.aliases)
    }

    fn alias_target(&self, name: &str) -> Option<String> {
        self.aliases.get(name).filter(|id| self.collections.contains_key(*id)).cloned()
    }

    /// Collection id for a collection or alias path.
    pub fn resolve_collection(&self, path: &str) -> Option<String> {
        match paths::parse(path)? {
            Target::Collection(id) if self.collections.contains_key(&id) => Some(id),
            Target::Alias(name) => self.alias_target(&name),
            _ => None,
        }
    }

    /// `(collection id, item id)` for an item path under a collection or alias.
    pub fn resolve_item(&self, path: &str) -> Option<(String, String)> {
        let (cid, iid) = match paths::parse(path)? {
            Target::Item { collection, item } => (collection, item),
            Target::AliasItem { alias, item } => (self.alias_target(&alias)?, item),
            _ => return None,
        };
        self.collections.get(&cid).filter(|v| v.has_item(&iid)).map(|_| (cid, iid))
    }

    /// Collection id behind any collection, alias, or item path.
    pub fn collection_id_of_path(&self, path: &str) -> Option<String> {
        self.resolve_collection(path).or_else(|| self.resolve_item(path).map(|(c, _)| c))
    }

    pub fn is_unlocked_path(&self, path: &str) -> bool {
        self.collection_id_of_path(path)
            .and_then(|id| self.collections.get(&id))
            .map(|v| !v.is_locked())
            .unwrap_or(false)
    }

    pub fn new_session_path(&mut self) -> OwnedObjectPath {
        self.next_session += 1;
        paths::session(self.next_session)
    }

    pub fn new_prompt_path(&mut self) -> OwnedObjectPath {
        self.next_prompt += 1;
        paths::prompt(self.next_prompt)
    }

    pub fn cipher(&self, session_path: &str) -> Result<&SessionCipher> {
        self.sessions.get(session_path).map(|e| &e.cipher).ok_or(Error::NoSession)
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Search every collection. Returns `(unlocked item paths, locked item paths)`.
    pub fn search_all(&self, query: &BTreeMap<String, String>) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for (cid, vault) in &self.collections {
            let target = if vault.is_locked() { &mut locked } else { &mut unlocked };
            target.extend(vault.search_ids(query).into_iter().map(|iid| paths::item(cid, &iid)));
        }
        (unlocked, locked)
    }

    /// Path-safe id derived from a label, made unique against loaded collections and files.
    pub fn unique_collection_id(&self, label: &str) -> String {
        let base = collection_id_from_label(label);
        let taken = |id: &str| self.collections.contains_key(id) || self.vault_dir.join(format!("{id}.vault")).exists();
        if !taken(&base) {
            return base;
        }
        (2..).map(|n| format!("{base}_{n}")).find(|id| !taken(id)).expect("unbounded")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(dir: &Path) -> ServiceState {
        ServiceState::new(dir.to_path_buf(), KdfParams::FAST_FOR_TESTS, Pinentry::new("pinentry"))
    }

    #[test]
    fn loads_vaults_and_aliases_and_resolves_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(&dir.path().join("default.vault"), "Default", b"pw", KdfParams::FAST_FOR_TESTS).unwrap();
        let (iid, _) = v.insert_item("x", BTreeMap::new(), b"s".to_vec(), "text/plain", false).unwrap();
        save_aliases_to(dir.path(), &BTreeMap::from([("default".to_string(), "default".to_string())])).unwrap();
        std::fs::write(dir.path().join("junk.txt"), b"").unwrap();

        let mut st = state(dir.path());
        assert_eq!(st.load_vaults().unwrap(), vec!["default"]);
        assert!(st.load_vaults().unwrap().is_empty(), "second load adds nothing");
        assert_eq!(st.resolve_collection("/org/freedesktop/secrets/collection/default"), Some("default".into()));
        assert_eq!(st.resolve_collection("/org/freedesktop/secrets/aliases/default"), Some("default".into()));
        assert_eq!(st.resolve_collection("/org/freedesktop/secrets/aliases/nope"), None);
        let item_path = paths::item("default", &iid);
        assert_eq!(st.resolve_item(item_path.as_str()), Some(("default".into(), iid.clone())));
        assert_eq!(st.resolve_item(&format!("/org/freedesktop/secrets/aliases/default/{iid}")), Some(("default".into(), iid.clone())));
        assert_eq!(st.resolve_item("/org/freedesktop/secrets/collection/default/missing"), None);
        assert_eq!(st.collection_id_of_path(item_path.as_str()), Some("default".into()));
        assert!(!st.is_unlocked_path(item_path.as_str()));
        st.collections.get_mut("default").unwrap().unlock(b"pw").unwrap();
        assert!(st.is_unlocked_path(item_path.as_str()));
        let (u, l) = st.search_all(&BTreeMap::new());
        assert_eq!(u, vec![item_path]);
        assert!(l.is_empty());
    }

    #[test]
    fn unique_ids_and_counters() {
        let dir = tempfile::tempdir().unwrap();
        let mut st = state(dir.path());
        assert_eq!(st.unique_collection_id("Work"), "work");
        std::fs::write(dir.path().join("work.vault"), b"").unwrap();
        assert_eq!(st.unique_collection_id("Work"), "work_2");
        assert_eq!(st.new_session_path().as_str(), "/org/freedesktop/secrets/session/s1");
        assert_eq!(st.new_session_path().as_str(), "/org/freedesktop/secrets/session/s2");
        assert_eq!(st.new_prompt_path().as_str(), "/org/freedesktop/secrets/prompt/p1");
        assert!(matches!(st.cipher("/org/freedesktop/secrets/session/s9"), Err(Error::NoSession)));
    }
}
```

- [ ] **Step 4: Write session.rs, service.rs, proxies.rs, dbus/mod.rs**

`dbus/mod.rs`:
```rust
//! `org.freedesktop.Secret.*` interfaces.

pub mod collection;   // added in Task 10
pub mod errors;
pub mod item;         // added in Task 10
pub mod paths;
pub mod prompt;       // added in Task 11
pub mod proxies;
pub mod registry;     // added in Task 10
pub mod service;
pub mod session;
pub mod state;

use std::collections::{BTreeMap, HashMap};
use zbus::message::Header;
use zbus::zvariant::OwnedValue;

/// Unique bus name of the caller, or empty.
pub fn sender(header: &Header<'_>) -> String {
    header.sender().map(|s| s.to_string()).unwrap_or_default()
}

pub(crate) fn prop_string(props: &HashMap<String, OwnedValue>, key: &str) -> errors::Result<Option<String>> {
    match props.get(key) {
        None => Ok(None),
        Some(v) => String::try_from(v.clone())
            .map(Some)
            .map_err(|_| errors::Error::invalid_args(format!("{key} must be a string"))),
    }
}

pub(crate) fn prop_attributes(props: &HashMap<String, OwnedValue>, key: &str) -> errors::Result<BTreeMap<String, String>> {
    match props.get(key) {
        None => Ok(BTreeMap::new()),
        Some(v) => HashMap::<String, String>::try_from(v.clone())
            .map(|m| m.into_iter().collect())
            .map_err(|_| errors::Error::invalid_args(format!("{key} must be a{{ss}}"))),
    }
}
```
For this task, leave out the `collection`, `item`, `prompt`, `registry` lines; Tasks 10 and 11 add them.

`dbus/session.rs`:
```rust
//! `org.freedesktop.Secret.Session` and the `(oayays)` secret struct.

use super::errors::Result;
use super::state::Shared;
use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::zvariant::{OwnedObjectPath, Type};

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

pub struct Session {
    state: Shared,
    path: OwnedObjectPath,
}

impl Session {
    pub fn new(state: Shared, path: OwnedObjectPath) -> Self {
        Self { state, path }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(&self, #[zbus(connection)] conn: &zbus::Connection) -> Result<()> {
        self.state.lock().await.sessions.remove(self.path.as_str());
        let conn = conn.clone();
        let path = self.path.clone();
        // Removing the object from inside its own method call deadlocks; defer it.
        tokio::spawn(async move {
            let _ = conn.object_server().remove::<Session, _>(path.as_str()).await;
        });
        Ok(())
    }
}
```

`dbus/service.rs` (this task's subset; Tasks 10 and 11 add methods):
```rust
//! `org.freedesktop.Secret.Service`.

use super::errors::{Error, Result};
use super::paths;
use super::sender;
use super::session::Session;
use super::state::{SessionEntry, Shared};
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::{BTreeMap, HashMap};
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub struct Service {
    state: Shared,
}

impl Service {
    pub fn new(state: Shared) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    async fn open_session(
        &self,
        algorithm: &str,
        input: Value<'_>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        let (cipher, output) = match algorithm {
            ALGORITHM_PLAIN => (SessionCipher::plain(), Value::from("")),
            ALGORITHM_DH => {
                let peer = Vec::<u8>::try_from(input).map_err(|_| Error::invalid_args("input must be a byte array"))?;
                let pair = KeyPair::generate();
                let cipher = SessionCipher::from_dh(&pair, &peer).map_err(|e| Error::invalid_args(e))?;
                (cipher, Value::from(pair.public_bytes().to_vec()))
            }
            other => return Err(Error::not_supported(format!("unsupported algorithm '{other}'"))),
        };
        let owner = sender(&header);
        let path = {
            let mut st = self.state.lock().await;
            let path = st.new_session_path();
            st.sessions.insert(path.to_string(), SessionEntry { owner, cipher });
            path
        };
        server.at(path.clone(), Session::new(self.state.clone(), path.clone())).await?;
        let output = OwnedValue::try_from(output).map_err(Error::failed)?;
        Ok((output, path))
    }

    #[zbus(out_args("unlocked", "locked"))]
    async fn search_items(&self, attributes: HashMap<String, String>) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(self.state.lock().await.search_all(&query))
    }

    async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath> {
        let st = self.state.lock().await;
        Ok(st
            .aliases
            .get(name)
            .filter(|id| st.collections.contains_key(*id))
            .map(|id| paths::collection(id))
            .unwrap_or_else(paths::root))
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.state.lock().await.collections.keys().map(|id| paths::collection(id)).collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_deleted(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_changed(emitter: &SignalEmitter<'_>, collection: OwnedObjectPath) -> zbus::Result<()>;
}
```

`dbus/proxies.rs`:
```rust
//! Client-side proxies, shared by the CLI and the integration tests.

use super::session::SecretStruct;
use std::collections::HashMap;
use zbus::proxy;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

#[proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
pub trait Service {
    fn open_session(&self, algorithm: &str, input: &Value<'_>) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;
    fn create_collection(&self, properties: HashMap<&str, Value<'_>>, alias: &str) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>;
    fn unlock(&self, objects: &[OwnedObjectPath]) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
    fn lock(&self, objects: &[OwnedObjectPath]) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
    fn get_secrets(&self, items: &[OwnedObjectPath], session: &OwnedObjectPath) -> zbus::Result<HashMap<OwnedObjectPath, SecretStruct>>;
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn set_alias(&self, name: &str, collection: &OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(property)]
    fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(signal)]
    fn collection_created(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn collection_deleted(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn collection_changed(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
}

#[proxy(interface = "org.freedesktop.Secret.Collection", default_service = "org.freedesktop.secrets")]
pub trait Collection {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn create_item(&self, properties: HashMap<&str, Value<'_>>, secret: &SecretStruct, replace: bool) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
    #[zbus(property)]
    fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_label(&self, label: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn created(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn modified(&self) -> zbus::Result<u64>;
    #[zbus(signal)]
    fn item_created(&self, item: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn item_deleted(&self, item: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn item_changed(&self, item: OwnedObjectPath) -> zbus::Result<()>;
}

#[proxy(interface = "org.freedesktop.Secret.Item", default_service = "org.freedesktop.secrets")]
pub trait Item {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn get_secret(&self, session: &OwnedObjectPath) -> zbus::Result<SecretStruct>;
    fn set_secret(&self, secret: &SecretStruct) -> zbus::Result<()>;
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<HashMap<String, String>>;
    #[zbus(property)]
    fn set_attributes(&self, attributes: HashMap<&str, &str>) -> zbus::Result<()>;
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn set_label(&self, label: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn created(&self) -> zbus::Result<u64>;
    #[zbus(property)]
    fn modified(&self) -> zbus::Result<u64>;
}

#[proxy(interface = "org.freedesktop.Secret.Session", default_service = "org.freedesktop.secrets")]
pub trait Session {
    fn close(&self) -> zbus::Result<()>;
}

#[proxy(interface = "org.freedesktop.Secret.Prompt", default_service = "org.freedesktop.secrets")]
pub trait Prompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;
    fn dismiss(&self) -> zbus::Result<()>;
    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}
```

- [ ] **Step 5: Write daemon.rs (skeleton, extended in Tasks 10 and 12)**

```rust
//! Daemon assembly: vaults, bus connection, control socket, housekeeping tasks.

use crate::config::Config;
use crate::dbus::paths::{BUS_NAME, SERVICE_PATH};
use crate::dbus::service::Service;
use crate::dbus::state::{ServiceState, Shared};
use crate::prompt::Pinentry;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::connection::Builder;

#[derive(Debug, Clone)]
pub enum BusAddress {
    Session,
    Address(String),
}

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config: Config,
    pub bus: BusAddress,
    /// Override for `control_protocol::socket_path()` (tests).
    pub control_socket: Option<PathBuf>,
    /// Extra environment for the pinentry child (tests).
    pub pinentry_env: Vec<(String, String)>,
    /// How often the idle-lock timer checks. Production: 30 s.
    pub idle_check_interval: Duration,
}

impl DaemonOptions {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            bus: BusAddress::Session,
            control_socket: None,
            pinentry_env: Vec::new(),
            idle_check_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("another secret service already owns {BUS_NAME}")]
    NameTaken,
    #[error("bus error: {0}")]
    ZBus(zbus::Error),
    #[error("cannot load vaults: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot bind control socket: {0}")]
    Control(std::io::Error),
}

impl From<zbus::Error> for DaemonError {
    fn from(e: zbus::Error) -> Self {
        match e {
            zbus::Error::NameTaken => DaemonError::NameTaken,
            other => DaemonError::ZBus(other),
        }
    }
}

pub struct Daemon {
    pub connection: Connection,
    pub state: Shared,
    tasks: Vec<JoinHandle<()>>,
}

impl Daemon {
    pub async fn start(opts: DaemonOptions) -> Result<Daemon, DaemonError> {
        let mut pinentry = Pinentry::new(&opts.config.prompt.pinentry);
        for (k, v) in &opts.pinentry_env {
            pinentry = pinentry.env(k, v);
        }
        let mut state = ServiceState::new(opts.config.vault.dir.clone(), opts.config.kdf.into(), pinentry);
        state.load_vaults()?;
        let state: Shared = Arc::new(tokio::sync::Mutex::new(state));

        let builder = match &opts.bus {
            BusAddress::Session => Builder::session()?,
            BusAddress::Address(a) => Builder::address(a.as_str())?,
        };
        let connection = builder
            .name(BUS_NAME)?
            .serve_at(SERVICE_PATH, Service::new(state.clone()))?
            .build()
            .await?;

        // Task 10: crate::dbus::registry::register_all(&connection, &state).await?;
        // Task 12: control server, client watcher, idle lock.
        let tasks = Vec::new();
        tracing::info!("serving {BUS_NAME}");
        Ok(Daemon { connection, state, tasks })
    }

    /// Stop background tasks. The bus name is released when the connection drops.
    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
```

Add `pub mod dbus; pub mod daemon;` to `lib.rs`.

- [ ] **Step 6: Write the test fixture**

`crates/secret-manager/tests/common/mod.rs`:
```rust
#![allow(dead_code)]
//! Private bus + in-process daemon for integration tests.

use secret_manager::config::{Config, KdfConfig, PromptConfig, VaultConfig};
use secret_manager::daemon::{BusAddress, Daemon, DaemonOptions};
use secret_manager::vault::Vault;
use secret_manager::vault::crypto::KdfParams;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

pub const PASSWORD: &str = "pw";

pub struct TestBus {
    pub address: String,
    child: Child,
    _dir: TempDir,
}

impl TestBus {
    pub fn start() -> TestBus {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("bus");
        let mut child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address"])
            .arg(format!("--address=unix:path={}", sock.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon must be installed");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        TestBus { address: line.trim().to_string(), child, _dir: dir }
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn fake_pinentry() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-pinentry.sh"))
}

pub struct Fixture {
    pub bus: TestBus,
    pub data_dir: TempDir,
    pub runtime_dir: TempDir,
    pub daemon: Daemon,
    pub pinentry_log: PathBuf,
    pub pin: Option<String>,
}

impl Fixture {
    /// Daemon with a `default` collection (password `pw`), pinentry answering `pw`.
    pub async fn start() -> Fixture {
        Self::start_with_pin(Some(PASSWORD)).await
    }

    /// `pin = None` makes every prompt cancel.
    pub async fn start_with_pin(pin: Option<&str>) -> Fixture {
        let bus = TestBus::start();
        let data_dir = tempfile::tempdir().unwrap();
        let runtime_dir = tempfile::tempdir().unwrap();
        let vault_dir = data_dir.path().join("secret-manager");
        std::fs::create_dir_all(&vault_dir).unwrap();
        Vault::create(&vault_dir.join("default.vault"), "Default", PASSWORD.as_bytes(), KdfParams::FAST_FOR_TESTS).unwrap();
        secret_manager::dbus::state::save_aliases_to(
            &vault_dir,
            &BTreeMap::from([("default".to_string(), "default".to_string())]),
        )
        .unwrap();
        let pinentry_log = runtime_dir.path().join("pinentry.log");
        let config = Config {
            vault: VaultConfig { dir: vault_dir, auto_lock_after: Duration::ZERO },
            prompt: PromptConfig { pinentry: fake_pinentry().to_string_lossy().into_owned() },
            kdf: KdfConfig { m_cost_kib: 8, t_cost: 1, p_cost: 1 },
        };
        let mut pinentry_env = vec![("FAKE_LOG".to_string(), pinentry_log.to_string_lossy().into_owned())];
        if let Some(p) = pin {
            pinentry_env.push(("FAKE_PIN".to_string(), p.to_string()));
        }
        let opts = DaemonOptions {
            config,
            bus: BusAddress::Address(bus.address.clone()),
            control_socket: Some(runtime_dir.path().join("secret-manager").join("control.sock")),
            pinentry_env,
            idle_check_interval: Duration::from_millis(200),
        };
        let daemon = Daemon::start(opts).await.expect("daemon starts");
        Fixture { bus, data_dir, runtime_dir, daemon, pinentry_log, pin: pin.map(str::to_string) }
    }

    pub async fn client(&self) -> Connection {
        zbus::connection::Builder::address(self.bus.address.as_str()).unwrap().build().await.unwrap()
    }

    pub fn control_socket(&self) -> PathBuf {
        self.runtime_dir.path().join("secret-manager").join("control.sock")
    }

    pub fn default_collection(&self) -> OwnedObjectPath {
        secret_manager::dbus::paths::collection("default")
    }

    /// Environment for spawning the CLI against this fixture.
    pub fn envs(&self) -> Vec<(String, String)> {
        let mut v = vec![
            ("DBUS_SESSION_BUS_ADDRESS".to_string(), self.bus.address.clone()),
            ("XDG_DATA_HOME".to_string(), self.data_dir.path().to_string_lossy().into_owned()),
            ("XDG_RUNTIME_DIR".to_string(), self.runtime_dir.path().to_string_lossy().into_owned()),
            ("XDG_CONFIG_HOME".to_string(), self.data_dir.path().join("config").to_string_lossy().into_owned()),
            ("PINENTRY".to_string(), fake_pinentry().to_string_lossy().into_owned()),
            ("FAKE_LOG".to_string(), self.pinentry_log.to_string_lossy().into_owned()),
        ];
        if let Some(p) = &self.pin {
            v.push(("FAKE_PIN".to_string(), p.clone()));
        }
        v
    }

    pub fn sm(&self) -> assert_cmd::Command {
        let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
        cmd.env_clear();
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
        cmd.env("HOME", self.data_dir.path());
        for (k, v) in self.envs() {
            cmd.env(k, v);
        }
        cmd
    }

    pub fn pinentry_log(&self) -> String {
        std::fs::read_to_string(&self.pinentry_log).unwrap_or_default()
    }
}

/// Poll until `f` returns true or `timeout` elapses.
pub async fn wait_for<F, Fut>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}
```

- [ ] **Step 7: Write the failing integration test**

`crates/secret-manager/tests/dbus_service.rs`:
```rust
mod common;

use common::Fixture;
use secret_manager::dbus::proxies::{ServiceProxy, SessionProxy};
use secret_manager::session::dh::KeyPair;
use secret_manager::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::HashMap;
use zbus::zvariant::Value;

#[tokio::test]
async fn plain_and_dh_sessions() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();

    let (output, path) = service.open_session(ALGORITHM_PLAIN, &Value::from("")).await.unwrap();
    assert_eq!(String::try_from(output).unwrap(), "");
    assert!(path.as_str().starts_with("/org/freedesktop/secrets/session/"));

    let pair = KeyPair::generate();
    let (output, path2) = service.open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec())).await.unwrap();
    let peer = Vec::<u8>::try_from(output).unwrap();
    assert!(!peer.is_empty() && peer.len() <= 128);
    assert!(SessionCipher::from_dh(&pair, &peer).is_ok());
    assert_ne!(path, path2);
    assert_eq!(fx.daemon.state.lock().await.sessions.len(), 2);

    let session = SessionProxy::builder(&conn).path(path.clone()).unwrap().build().await.unwrap();
    session.close().await.unwrap();
    assert!(common::wait_for(std::time::Duration::from_secs(2), || async {
        fx.daemon.state.lock().await.sessions.len() == 1
    })
    .await);
}

#[tokio::test]
async fn unsupported_algorithm_and_bad_input() {
    let fx = Fixture::start().await;
    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    let err = service.open_session("rot13", &Value::from("")).await.unwrap_err();
    assert!(matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.NotSupported"));
    let err = service.open_session(ALGORITHM_DH, &Value::from("not bytes")).await.unwrap_err();
    assert!(matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs"));
    let err = service.open_session(ALGORITHM_DH, &Value::from(vec![1u8])).await.unwrap_err();
    assert!(matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.DBus.Error.InvalidArgs"));
}

#[tokio::test]
async fn collections_alias_and_empty_search() {
    let fx = Fixture::start().await;
    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    assert_eq!(service.collections().await.unwrap(), vec![fx.default_collection()]);
    assert_eq!(service.read_alias("default").await.unwrap(), fx.default_collection());
    assert_eq!(service.read_alias("nope").await.unwrap().as_str(), "/");
    let (unlocked, locked) = service.search_items(HashMap::from([("a", "b")])).await.unwrap();
    assert!(unlocked.is_empty() && locked.is_empty());
}
```

- [ ] **Step 8: Run tests to verify they fail, then build until green**

Run: `cargo test -p secret-manager --test dbus_service`
Expected first: compile errors. After implementing Steps 1–6: 3 tests pass. Also run `cargo test -p secret-manager dbus` for the unit tests in `paths.rs` and `state.rs`.

- [ ] **Step 9: fmt, clippy, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add -A
git commit -m "Add Secret Service skeleton with sessions and test fixture"
```

---

### Task 10: Collection and Item interfaces, object registry, GetSecrets, SetAlias

**Files:**
- Create: `crates/secret-manager/src/dbus/registry.rs`, `collection.rs`, `item.rs`
- Modify: `crates/secret-manager/src/dbus/mod.rs` (add `pub mod collection; pub mod item; pub mod registry;`), `service.rs` (add `get_secrets`, `set_alias`), `daemon.rs` (call `register_all`)
- Modify: `crates/secret-manager/tests/common/mod.rs` (add `unlock_default`, `lock_default`)
- Create: `crates/secret-manager/tests/dbus_items.rs`

**Interfaces:**
- Consumes: Task 9 state/paths/errors/session types, `vault::Vault` item API
- Produces:
  - `dbus::collection::{Collection::new(state, CollectionRef), CollectionRef::{Id(String), Alias(String)}, CollectionSignals}`
  - `dbus::item::Item::new(state, collection_id, item_id)`
  - `dbus::registry::{register_collection(conn, state, id), unregister_collection(conn, id, item_ids: &[String]), register_alias(conn, state, name), register_item(conn, state, cid, iid), register_all(conn, state), notify_collection_changed(conn, id)}`
  - `Service` gains `GetSecrets(items, session) -> a{o(oayays)}` and `SetAlias(name, collection)`
  - Fixture gains `async fn unlock_default(&self)`, `async fn lock_default(&self)`

- [ ] **Step 1: Extend the fixture**

Add to `impl Fixture` in `tests/common/mod.rs`:
```rust
    pub async fn unlock_default(&self) {
        self.daemon.state.lock().await.collections.get_mut("default").unwrap().unlock(PASSWORD.as_bytes()).unwrap();
    }

    pub async fn lock_default(&self) {
        self.daemon.state.lock().await.collections.get_mut("default").unwrap().lock();
    }
```

- [ ] **Step 2: Write the failing integration tests**

`crates/secret-manager/tests/dbus_items.rs`:
```rust
mod common;

use common::Fixture;
use futures_util::StreamExt;
use secret_manager::dbus::proxies::{CollectionProxy, ItemProxy, ServiceProxy};
use secret_manager::dbus::session::SecretStruct;
use secret_manager::session::dh::KeyPair;
use secret_manager::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::HashMap;
use std::time::Duration;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, Value};

async fn plain_session(service: &ServiceProxy<'_>) -> OwnedObjectPath {
    service.open_session(ALGORITHM_PLAIN, &Value::from("")).await.unwrap().1
}

fn props(label: &str, attrs: &[(&str, &str)]) -> HashMap<&'static str, Value<'static>> {
    let attrs: HashMap<String, String> = attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    HashMap::from([
        ("org.freedesktop.Secret.Item.Label", Value::from(label.to_string())),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
    ])
}

fn plain_secret(session: &OwnedObjectPath, bytes: &[u8]) -> SecretStruct {
    SecretStruct { session: session.clone(), parameters: vec![], value: bytes.to_vec(), content_type: "text/plain".into() }
}

async fn collection(conn: &zbus::Connection, path: OwnedObjectPath) -> CollectionProxy<'static> {
    CollectionProxy::builder(conn).path(path).unwrap().cache_properties(CacheProperties::No).build().await.unwrap()
}

async fn item(conn: &zbus::Connection, path: OwnedObjectPath) -> ItemProxy<'static> {
    ItemProxy::builder(conn).path(path).unwrap().cache_properties(CacheProperties::No).build().await.unwrap()
}

fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.to_string(),
        other => panic!("unexpected error {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_search_get_set_delete_with_signals() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    assert_eq!(coll.label().await.unwrap(), "Default");
    assert!(!coll.locked().await.unwrap());

    let mut created = coll.receive_item_created().await.unwrap();
    let (item_path, prompt) = coll
        .create_item(props("git token", &[("app", "git"), ("user", "joe")]), &plain_secret(&session, b"tok"), false)
        .await
        .unwrap();
    assert_eq!(prompt.as_str(), "/");
    assert!(item_path.as_str().starts_with("/org/freedesktop/secrets/collection/default/"));
    assert_eq!(created.next().await.unwrap().args().unwrap().item, item_path);
    assert_eq!(coll.items().await.unwrap(), vec![item_path.clone()]);

    let (u, l) = service.search_items(HashMap::from([("app", "git")])).await.unwrap();
    assert_eq!(u, vec![item_path.clone()]);
    assert!(l.is_empty());
    assert_eq!(coll.search_items(HashMap::from([("user", "joe")])).await.unwrap(), vec![item_path.clone()]);
    assert!(coll.search_items(HashMap::from([("user", "bob")])).await.unwrap().is_empty());

    let it = item(&conn, item_path.clone()).await;
    assert_eq!(it.label().await.unwrap(), "git token");
    assert_eq!(it.attributes().await.unwrap()["app"], "git");
    assert!(!it.locked().await.unwrap());
    assert!(it.created().await.unwrap() > 0);
    let s = it.get_secret(&session).await.unwrap();
    assert_eq!(s.value, b"tok");
    assert_eq!(s.content_type, "text/plain");
    let all = service.get_secrets(&[item_path.clone()], &session).await.unwrap();
    assert_eq!(all[&item_path].value, b"tok");

    let mut changed = coll.receive_item_changed().await.unwrap();
    it.set_secret(&plain_secret(&session, b"tok2")).await.unwrap();
    assert_eq!(changed.next().await.unwrap().args().unwrap().item, item_path);
    assert_eq!(it.get_secret(&session).await.unwrap().value, b"tok2");
    it.set_label("renamed").await.unwrap();
    assert_eq!(it.label().await.unwrap(), "renamed");
    it.set_attributes(HashMap::from([("app", "git"), ("user", "jane")])).await.unwrap();
    assert!(coll.search_items(HashMap::from([("user", "joe")])).await.unwrap().is_empty());

    let (again, _) = coll
        .create_item(props("replaced", &[("app", "git"), ("user", "jane")]), &plain_secret(&session, b"tok3"), true)
        .await
        .unwrap();
    assert_eq!(again, item_path);
    assert_eq!(coll.items().await.unwrap().len(), 1);
    assert_eq!(it.label().await.unwrap(), "replaced");

    let mut deleted = coll.receive_item_deleted().await.unwrap();
    assert_eq!(it.delete().await.unwrap().as_str(), "/");
    assert_eq!(deleted.next().await.unwrap().args().unwrap().item, item_path);
    assert!(coll.items().await.unwrap().is_empty());
    assert!(common::wait_for(Duration::from_secs(2), || async { it.label().await.is_err() }).await, "item object removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dh_session_end_to_end() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let pair = KeyPair::generate();
    let (output, session) = service.open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec())).await.unwrap();
    let cipher = SessionCipher::from_dh(&pair, &Vec::<u8>::try_from(output).unwrap()).unwrap();
    let (parameters, value) = cipher.encrypt(b"encrypted on the wire");
    let secret = SecretStruct { session: session.clone(), parameters, value, content_type: "text/plain".into() };
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll.create_item(props("dh", &[("k", "v")]), &secret, false).await.unwrap();
    let got = service.get_secrets(&[item_path.clone()], &session).await.unwrap();
    let s = &got[&item_path];
    assert_ne!(s.value, b"encrypted on the wire");
    assert_eq!(cipher.decrypt(&s.parameters, &s.value).unwrap().as_slice(), b"encrypted on the wire");
    assert_eq!(fx.daemon.state.lock().await.collections["default"].items().unwrap()[0].secret.as_slice(), b"encrypted on the wire");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_collection_behaviour() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let coll = collection(&conn, fx.default_collection()).await;
    let (item_path, _) = coll.create_item(props("x", &[("app", "git")]), &plain_secret(&session, b"s"), false).await.unwrap();
    fx.lock_default().await;

    assert!(coll.locked().await.unwrap());
    assert_eq!(coll.items().await.unwrap(), vec![item_path.clone()]);
    let (u, l) = service.search_items(HashMap::from([("app", "git")])).await.unwrap();
    assert!(u.is_empty());
    assert_eq!(l, vec![item_path.clone()]);
    let it = item(&conn, item_path.clone()).await;
    assert!(it.locked().await.unwrap());
    assert_eq!(it.label().await.unwrap(), "");
    assert!(it.attributes().await.unwrap().is_empty());
    assert_eq!(error_name(&it.get_secret(&session).await.unwrap_err()), "org.freedesktop.Secret.Error.IsLocked");
    assert_eq!(error_name(&it.delete().await.unwrap_err()), "org.freedesktop.Secret.Error.IsLocked");
    let err = coll.create_item(props("y", &[]), &plain_secret(&session, b"s"), false).await.unwrap_err();
    assert_eq!(error_name(&err), "org.freedesktop.Secret.Error.IsLocked");
    assert!(service.get_secrets(&[item_path.clone()], &session).await.unwrap().is_empty());
    assert_eq!(error_name(&it.get_secret(&secret_manager::dbus::paths::session(99)).await.unwrap_err()), "org.freedesktop.Secret.Error.NoSession");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alias_path_and_set_alias() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = plain_session(&service).await;
    let alias = collection(&conn, secret_manager::dbus::paths::alias("default").unwrap()).await;
    assert_eq!(alias.label().await.unwrap(), "Default");
    let (item_path, _) = alias.create_item(props("via alias", &[("a", "b")]), &plain_secret(&session, b"s"), false).await.unwrap();
    assert!(item_path.as_str().starts_with("/org/freedesktop/secrets/collection/default/"));
    let real = collection(&conn, fx.default_collection()).await;
    assert_eq!(real.items().await.unwrap(), alias.items().await.unwrap());

    service.set_alias("work", &fx.default_collection()).await.unwrap();
    assert_eq!(service.read_alias("work").await.unwrap(), fx.default_collection());
    let work = collection(&conn, secret_manager::dbus::paths::alias("work").unwrap()).await;
    assert_eq!(work.label().await.unwrap(), "Default");
    let text = std::fs::read_to_string(fx.data_dir.path().join("secret-manager").join("aliases.toml")).unwrap();
    assert!(text.contains("work = \"default\""));
    service.set_alias("work", &secret_manager::dbus::paths::root()).await.unwrap();
    assert_eq!(service.read_alias("work").await.unwrap().as_str(), "/");
    assert_eq!(error_name(&service.set_alias("bad name", &fx.default_collection()).await.unwrap_err()), "org.freedesktop.DBus.Error.InvalidArgs");
    assert_eq!(
        error_name(&service.set_alias("x", &secret_manager::dbus::paths::collection("nope")).await.unwrap_err()),
        "org.freedesktop.Secret.Error.NoSuchObject"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_tool_interop() {
    if std::process::Command::new("secret-tool").arg("--version").output().is_err() {
        eprintln!("secret-tool not installed; skipping");
        return;
    }
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let run = |args: &[&str], stdin: &str| {
        let mut cmd = std::process::Command::new("secret-tool");
        cmd.args(args).env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address);
        cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{:?}: {}", args, String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    run(&["store", "--label=Interop", "app", "interop", "user", "joe"], "s3cret\n");
    assert_eq!(run(&["lookup", "app", "interop"], ""), "s3cret");
    assert!(run(&["search", "app", "interop"], "").contains("label = Interop"));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p secret-manager --test dbus_items`
Expected: compile errors (missing proxies methods on server side, missing modules).

- [ ] **Step 4: Implement registry.rs**

```rust
//! Register and unregister collection, alias, and item objects; shared notifications.

use super::collection::{Collection, CollectionRef};
use super::item::Item;
use super::paths;
use super::service::ServiceSignals;
use super::state::Shared;
use zbus::Connection;
use zbus::object_server::SignalEmitter;

pub async fn register_collection(conn: &Connection, state: &Shared, id: &str) -> zbus::Result<()> {
    let server = conn.object_server();
    server.at(paths::collection(id), Collection::new(state.clone(), CollectionRef::Id(id.to_string()))).await?;
    let item_ids = state.lock().await.collections.get(id).map(|v| v.item_ids()).unwrap_or_default();
    for iid in item_ids {
        server.at(paths::item(id, &iid), Item::new(state.clone(), id.to_string(), iid)).await?;
    }
    Ok(())
}

pub async fn unregister_collection(conn: &Connection, id: &str, item_ids: &[String]) {
    let server = conn.object_server();
    for iid in item_ids {
        let _ = server.remove::<Item, _>(paths::item(id, iid)).await;
    }
    let _ = server.remove::<Collection, _>(paths::collection(id)).await;
}

/// Idempotent: an alias object resolves its target at call time, so it is
/// registered once and never removed.
pub async fn register_alias(conn: &Connection, state: &Shared, name: &str) -> zbus::Result<()> {
    if let Some(path) = paths::alias(name) {
        conn.object_server().at(path, Collection::new(state.clone(), CollectionRef::Alias(name.to_string()))).await?;
    }
    Ok(())
}

pub async fn register_item(conn: &Connection, state: &Shared, collection_id: &str, item_id: &str) -> zbus::Result<()> {
    conn.object_server()
        .at(paths::item(collection_id, item_id), Item::new(state.clone(), collection_id.to_string(), item_id.to_string()))
        .await?;
    Ok(())
}

pub async fn register_all(conn: &Connection, state: &Shared) -> zbus::Result<()> {
    let (ids, aliases) = {
        let st = state.lock().await;
        (st.collections.keys().cloned().collect::<Vec<_>>(), st.aliases.keys().cloned().collect::<Vec<_>>())
    };
    for id in ids {
        register_collection(conn, state, &id).await?;
    }
    for name in aliases {
        register_alias(conn, state, &name).await?;
    }
    Ok(())
}

/// `Service.CollectionChanged` plus `PropertiesChanged` for `Collection.Locked`.
pub async fn notify_collection_changed(conn: &Connection, id: &str) {
    if let Ok(emitter) = SignalEmitter::new(conn, paths::SERVICE_PATH) {
        let _ = emitter.collection_changed(paths::collection(id)).await;
    }
    if let Ok(iface) = conn.object_server().interface::<_, Collection>(paths::collection(id)).await {
        let _ = iface.get().await.locked_changed(iface.signal_emitter()).await;
    }
}
```

- [ ] **Step 5: Implement collection.rs**

```rust
//! `org.freedesktop.Secret.Collection`, served at `/collection/<id>` and `/aliases/<name>`.

use super::errors::{Error, Result};
use super::registry;
use super::service::ServiceSignals;
use super::session::SecretStruct;
use super::state::{ServiceState, Shared};
use super::{paths, prop_attributes, prop_string};
use std::collections::{BTreeMap, HashMap};
use zbus::Connection;
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

pub enum CollectionRef {
    Id(String),
    Alias(String),
}

pub struct Collection {
    state: Shared,
    target: CollectionRef,
}

impl Collection {
    pub fn new(state: Shared, target: CollectionRef) -> Self {
        Self { state, target }
    }

    fn id(&self, st: &ServiceState) -> Result<String> {
        match &self.target {
            CollectionRef::Id(id) => st.collections.contains_key(id).then(|| id.clone()).ok_or(Error::NoSuchObject),
            CollectionRef::Alias(name) => st
                .aliases
                .get(name)
                .filter(|id| st.collections.contains_key(*id))
                .cloned()
                .ok_or(Error::NoSuchObject),
        }
    }

    fn unknown() -> zbus::fdo::Error {
        zbus::fdo::Error::UnknownObject("no such collection".into())
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    /// Deletes immediately (no prompt). Requires the collection to be unlocked.
    #[zbus(out_args("prompt"))]
    async fn delete(&self, #[zbus(connection)] conn: &Connection) -> Result<OwnedObjectPath> {
        let (id, vault) = {
            let mut st = self.state.lock().await;
            let id = self.id(&st)?;
            if st.collections[&id].is_locked() {
                return Err(Error::IsLocked);
            }
            let vault = st.collections.remove(&id).ok_or(Error::NoSuchObject)?;
            st.aliases.retain(|_, target| target != &id);
            if let Err(e) = st.save_aliases() {
                tracing::warn!("cannot save aliases: {e}");
            }
            (id, vault)
        };
        let item_ids = vault.item_ids();
        vault.delete_file()?;
        let conn2 = conn.clone();
        let id2 = id.clone();
        tokio::spawn(async move { registry::unregister_collection(&conn2, &id2, &item_ids).await });
        SignalEmitter::new(conn, paths::SERVICE_PATH)?.collection_deleted(paths::collection(&id)).await?;
        Ok(paths::root())
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> Result<Vec<OwnedObjectPath>> {
        let st = self.state.lock().await;
        let id = self.id(&st)?;
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(st.collections[&id].search_ids(&query).into_iter().map(|iid| paths::item(&id, &iid)).collect())
    }

    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = prop_string(&properties, "org.freedesktop.Secret.Item.Label")?.unwrap_or_default();
        let attributes = prop_attributes(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (id, iid, replaced) = {
            let mut st = self.state.lock().await;
            let id = self.id(&st)?;
            let plaintext = st
                .cipher(secret.session.as_str())?
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            let vault = st.collections.get_mut(&id).ok_or(Error::NoSuchObject)?;
            let (iid, replaced) = vault.insert_item(&label, attributes, plaintext.to_vec(), &secret.content_type, replace)?;
            st.touch();
            (id, iid, replaced)
        };
        let item_path = paths::item(&id, &iid);
        if !replaced {
            registry::register_item(conn, &self.state, &id, &iid).await?;
        }
        let emitter = SignalEmitter::new(conn, paths::collection(&id))?;
        if replaced {
            emitter.item_changed(item_path.clone()).await?;
        } else {
            emitter.item_created(item_path.clone()).await?;
        }
        Ok((item_path, paths::root()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let st = self.state.lock().await;
        match self.id(&st) {
            Ok(id) => st.collections[&id].item_ids().into_iter().map(|iid| paths::item(&id, &iid)).collect(),
            Err(_) => Vec::new(),
        }
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        let st = self.state.lock().await;
        self.id(&st).map(|id| st.collections[&id].label().to_string()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&self, label: &str) -> zbus::fdo::Result<()> {
        let mut st = self.state.lock().await;
        let id = self.id(&st).map_err(|_| Self::unknown())?;
        st.collections
            .get_mut(&id)
            .ok_or_else(Self::unknown)?
            .set_label(label)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        let st = self.state.lock().await;
        self.id(&st).map(|id| st.collections[&id].is_locked()).unwrap_or(true)
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let st = self.state.lock().await;
        self.id(&st).map(|id| st.collections[&id].created()).unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let st = self.state.lock().await;
        self.id(&st).map(|id| st.collections[&id].modified()).unwrap_or(0)
    }

    #[zbus(signal)]
    pub async fn item_created(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn item_deleted(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn item_changed(emitter: &SignalEmitter<'_>, item: OwnedObjectPath) -> zbus::Result<()>;
}
```

- [ ] **Step 6: Implement item.rs**

```rust
//! `org.freedesktop.Secret.Item`.

use super::collection::CollectionSignals;
use super::errors::{Error, Result};
use super::paths;
use super::session::SecretStruct;
use super::state::Shared;
use std::collections::HashMap;
use zbus::Connection;
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

pub struct Item {
    state: Shared,
    collection: String,
    id: String,
}

impl Item {
    pub fn new(state: Shared, collection: String, id: String) -> Self {
        Self { state, collection, id }
    }

    /// Read one field of the decrypted item; `None` while locked or missing.
    async fn with_item<T>(&self, f: impl FnOnce(&crate::vault::format::Item) -> T) -> Option<T> {
        let st = self.state.lock().await;
        st.collections.get(&self.collection).and_then(|v| v.item(&self.id).ok()).map(f)
    }

    async fn update(&self, f: impl FnOnce(&mut crate::vault::format::Item)) -> zbus::fdo::Result<()> {
        let mut st = self.state.lock().await;
        let vault = st
            .collections
            .get_mut(&self.collection)
            .ok_or_else(|| zbus::fdo::Error::UnknownObject("no such collection".into()))?;
        vault.update_item(&self.id, f).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    async fn delete(&self, #[zbus(connection)] conn: &Connection) -> Result<OwnedObjectPath> {
        {
            let mut st = self.state.lock().await;
            let vault = st.collections.get_mut(&self.collection).ok_or(Error::NoSuchObject)?;
            vault.delete_item(&self.id)?;
            st.touch();
        }
        let path = paths::item(&self.collection, &self.id);
        let conn2 = conn.clone();
        let p = path.clone();
        tokio::spawn(async move {
            let _ = conn2.object_server().remove::<Item, _>(p.as_str()).await;
        });
        SignalEmitter::new(conn, paths::collection(&self.collection))?.item_deleted(path).await?;
        Ok(paths::root())
    }

    async fn get_secret(&self, session: OwnedObjectPath) -> Result<SecretStruct> {
        let mut st = self.state.lock().await;
        st.touch();
        let cipher = st.cipher(session.as_str())?;
        let vault = st.collections.get(&self.collection).ok_or(Error::NoSuchObject)?;
        let item = vault.item(&self.id)?;
        let (parameters, value) = cipher.encrypt(&item.secret);
        Ok(SecretStruct { session, parameters, value, content_type: item.content_type.clone() })
    }

    async fn set_secret(&self, secret: SecretStruct, #[zbus(connection)] conn: &Connection) -> Result<()> {
        {
            let mut st = self.state.lock().await;
            let plaintext = st
                .cipher(secret.session.as_str())?
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            let vault = st.collections.get_mut(&self.collection).ok_or(Error::NoSuchObject)?;
            let content_type = secret.content_type.clone();
            vault.update_item(&self.id, move |i| {
                i.secret = Zeroizing::new(plaintext.to_vec());
                i.content_type = content_type;
            })?;
            st.touch();
        }
        SignalEmitter::new(conn, paths::collection(&self.collection))?
            .item_changed(paths::item(&self.collection, &self.id))
            .await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        let st = self.state.lock().await;
        st.collections.get(&self.collection).map(|v| v.is_locked()).unwrap_or(true)
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.with_item(|i| i.attributes.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).await.unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(&self, attributes: HashMap<String, String>) -> zbus::fdo::Result<()> {
        self.update(|i| i.attributes = attributes.into_iter().collect()).await
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.with_item(|i| i.label.clone()).await.unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&self, label: &str) -> zbus::fdo::Result<()> {
        let label = label.to_string();
        self.update(|i| i.label = label).await
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.with_item(|i| i.created).await.unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.with_item(|i| i.modified).await.unwrap_or(0)
    }
}
```

- [ ] **Step 7: Extend service.rs and daemon.rs**

Add to the `#[interface]` block of `Service` (imports: `super::registry`, `super::session::SecretStruct`, `zbus::Connection`):
```rust
    async fn get_secrets(&self, items: Vec<OwnedObjectPath>, session: OwnedObjectPath) -> Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let mut st = self.state.lock().await;
        st.touch();
        let cipher = st.cipher(session.as_str())?;
        let mut out = HashMap::new();
        for path in items {
            let Some((cid, iid)) = st.resolve_item(path.as_str()) else { continue };
            let Some(vault) = st.collections.get(&cid) else { continue };
            // Locked items are omitted, as the spec allows.
            let Ok(item) = vault.item(&iid) else { continue };
            let (parameters, value) = cipher.encrypt(&item.secret);
            out.insert(path, SecretStruct { session: session.clone(), parameters, value, content_type: item.content_type.clone() });
        }
        Ok(out)
    }

    async fn set_alias(&self, name: &str, collection: OwnedObjectPath, #[zbus(connection)] conn: &Connection) -> Result<()> {
        if !paths::is_segment(name) {
            return Err(Error::invalid_args("alias names must match [A-Za-z0-9_]+"));
        }
        {
            let mut st = self.state.lock().await;
            if collection.as_str() == "/" {
                st.aliases.remove(name);
            } else {
                let id = st.resolve_collection(collection.as_str()).ok_or(Error::NoSuchObject)?;
                st.aliases.insert(name.to_string(), id);
            }
            st.save_aliases().map_err(Error::failed)?;
        }
        if collection.as_str() != "/" {
            registry::register_alias(conn, &self.state, name).await?;
        }
        Ok(())
    }
```

In `daemon.rs`, replace the `// Task 10:` comment with:
```rust
        crate::dbus::registry::register_all(&connection, &state).await?;
```

Add `pub mod collection; pub mod item; pub mod registry;` to `dbus/mod.rs`.

- [ ] **Step 8: Run tests until green, fmt, clippy, commit**

Run: `cargo test -p secret-manager --test dbus_items && cargo test --workspace && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 5 tests pass (the interop test runs because `secret-tool` is installed locally).

```bash
git add -A
git commit -m "Add Collection and Item interfaces with object registry"
```

---

### Task 11: Prompts: Unlock, Lock, CreateCollection

**Files:**
- Create: `crates/secret-manager/src/dbus/prompt.rs`
- Modify: `crates/secret-manager/src/dbus/mod.rs` (add `pub mod prompt;`), `service.rs` (add `unlock`, `lock`, `create_collection`)
- Create: `crates/secret-manager/tests/dbus_prompts.rs`

**Interfaces:**
- Consumes: `prompt::{Pinentry, PinRequest, PinOutcome}`, `registry::{register_collection, register_alias, notify_collection_changed}`, `state`
- Produces:
  - `dbus::prompt::{Prompt::new(state, path, PromptAction), PromptAction::{Unlock{collections: Vec<String>, requested: Vec<OwnedObjectPath>}, CreateCollection{label: String, alias: Option<String>}}, PromptSignals}`
  - `dbus::prompt::unlock_collection(conn, state, id) -> bool` (pinentry loop, up to 3 attempts; also reused by nothing else, but public for tests)
  - `Service` gains `Unlock`, `Lock`, `CreateCollection`

- [ ] **Step 1: Write the failing integration tests**

`crates/secret-manager/tests/dbus_prompts.rs`:
```rust
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
    CollectionProxy::builder(conn).path(path).unwrap().cache_properties(CacheProperties::No).build().await.unwrap()
}

/// Subscribe, trigger, and wait for `Completed`. Returns `(dismissed, result)`.
async fn perform(conn: &zbus::Connection, prompt: &OwnedObjectPath) -> (bool, OwnedValue) {
    let proxy = PromptProxy::builder(conn).path(prompt.clone()).unwrap().build().await.unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.prompt("").await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(10), completed.next()).await.unwrap().unwrap();
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
    assert!(prompt.as_str().starts_with("/org/freedesktop/secrets/prompt/"));
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    assert_eq!(Vec::<OwnedObjectPath>::try_from(result).unwrap(), vec![fx.default_collection()]);
    assert!(!coll.locked().await.unwrap());
    assert_eq!(changed.next().await.unwrap().args().unwrap().collection, fx.default_collection());
    assert!(fx.pinentry_log().contains("GETPIN"));

    // Already unlocked: no prompt.
    let (unlocked, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert_eq!(unlocked, vec![fx.default_collection()]);
    assert_eq!(prompt.as_str(), "/");
    // Prompt object is gone.
    assert!(common::wait_for(Duration::from_secs(2), || async {
        PromptProxy::builder(&conn).path(prompt.clone()).unwrap().build().await.unwrap().dismiss().await.is_err()
    })
    .await);
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
    assert!(collection(&conn, fx.default_collection()).await.locked().await.unwrap());
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
    let proxy = PromptProxy::builder(&conn).path(prompt.clone()).unwrap().build().await.unwrap();
    let mut completed = proxy.receive_completed().await.unwrap();
    proxy.dismiss().await.unwrap();
    let sig = tokio::time::timeout(Duration::from_secs(5), completed.next()).await.unwrap().unwrap();
    assert!(sig.args().unwrap().dismissed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unlock_by_item_path_and_lock() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let session = service.open_session(ALGORITHM_PLAIN, &Value::from("")).await.unwrap().1;
    let coll = collection(&conn, fx.default_collection()).await;
    let attrs: HashMap<String, String> = HashMap::from([("k".to_string(), "v".to_string())]);
    let props = HashMap::from([
        ("org.freedesktop.Secret.Item.Label", Value::from("x")),
        ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs)),
    ]);
    let secret = SecretStruct { session: session.clone(), parameters: vec![], value: b"s".to_vec(), content_type: "text/plain".into() };
    let (item_path, _) = coll.create_item(props, &secret, false).await.unwrap();

    let mut changed = service.receive_collection_changed().await.unwrap();
    let (locked, prompt) = service.lock(&[item_path.clone()]).await.unwrap();
    assert_eq!(locked, vec![item_path.clone()]);
    assert_eq!(prompt.as_str(), "/");
    assert!(coll.locked().await.unwrap());
    assert_eq!(changed.next().await.unwrap().args().unwrap().collection, fx.default_collection());

    let (_, prompt) = service.unlock(&[item_path.clone()]).await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    assert_eq!(Vec::<OwnedObjectPath>::try_from(result).unwrap(), vec![item_path.clone()]);
    assert!(!coll.locked().await.unwrap());
    let got = service.get_secrets(&[item_path.clone()], &session).await.unwrap();
    assert_eq!(got[&item_path].value, b"s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_with_alias_and_delete() {
    let fx = Fixture::start_with_pin(Some("newpw")).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut created = service.receive_collection_created().await.unwrap();
    let props = HashMap::from([("org.freedesktop.Secret.Collection.Label", Value::from("Work Keys"))]);
    let (path, prompt) = service.create_collection(props.clone(), "work").await.unwrap();
    assert_eq!(path.as_str(), "/");
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(!dismissed);
    let new_path = OwnedObjectPath::try_from(result).unwrap();
    assert_eq!(new_path, paths::collection("work_keys"));
    assert_eq!(created.next().await.unwrap().args().unwrap().collection, new_path);
    assert!(fx.pinentry_log().contains("SETREPEAT"));
    assert!(fx.data_dir.path().join("secret-manager").join("work_keys.vault").exists());
    assert_eq!(service.read_alias("work").await.unwrap(), new_path);
    let work = collection(&conn, new_path.clone()).await;
    assert_eq!(work.label().await.unwrap(), "Work Keys");
    assert!(!work.locked().await.unwrap(), "freshly created collections start unlocked");
    assert!(service.collections().await.unwrap().contains(&new_path));

    // Existing alias short-circuits without a prompt.
    let (path, prompt) = service.create_collection(props, "work").await.unwrap();
    assert_eq!(path, new_path);
    assert_eq!(prompt.as_str(), "/");

    let mut deleted = service.receive_collection_deleted().await.unwrap();
    assert_eq!(work.delete().await.unwrap().as_str(), "/");
    assert_eq!(deleted.next().await.unwrap().args().unwrap().collection, new_path);
    assert!(!fx.data_dir.path().join("secret-manager").join("work_keys.vault").exists());
    assert_eq!(service.read_alias("work").await.unwrap().as_str(), "/");
    assert!(!service.collections().await.unwrap().contains(&new_path));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_collection_cancelled() {
    let fx = Fixture::start_with_pin(None).await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let props = HashMap::from([("org.freedesktop.Secret.Collection.Label", Value::from("Nope"))]);
    let (_, prompt) = service.create_collection(props, "").await.unwrap();
    let (dismissed, result) = perform(&conn, &prompt).await;
    assert!(dismissed);
    assert_eq!(OwnedObjectPath::try_from(result).unwrap().as_str(), "/");
    assert_eq!(service.collections().await.unwrap(), vec![fx.default_collection()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_tool_unlocks_through_prompt() {
    if std::process::Command::new("secret-tool").arg("--version").output().is_err() {
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
    child.stdin.take().unwrap().write_all(b"s3cret\n").await.unwrap();
    let out = child.wait_with_output().await.unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(fx.pinentry_log().contains("GETPIN"));

    let out = tokio::process::Command::new("secret-tool")
        .args(["lookup", "app", "prompted"])
        .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address)
        .output()
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "s3cret");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager --test dbus_prompts`
Expected: compile errors (`unlock`, `lock`, `create_collection` missing on the server side surface as runtime `UnknownMethod` errors once the proxies compile; either way the tests fail).

- [ ] **Step 3: Implement prompt.rs**

```rust
//! `org.freedesktop.Secret.Prompt`: pinentry-driven unlock and collection creation.

use super::errors::{Error, Result};
use super::paths;
use super::registry;
use super::service::ServiceSignals;
use super::state::Shared;
use crate::prompt::{PinOutcome, PinRequest};
use crate::vault::{Vault, VaultError};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub enum PromptAction {
    Unlock { collections: Vec<String>, requested: Vec<OwnedObjectPath> },
    CreateCollection { label: String, alias: Option<String> },
}

pub struct Prompt {
    state: Shared,
    path: OwnedObjectPath,
    action: Mutex<Option<PromptAction>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Prompt {
    pub fn new(state: Shared, path: OwnedObjectPath, action: PromptAction) -> Self {
        Self { state, path, action: Mutex::new(Some(action)), task: Mutex::new(None) }
    }
}

fn owned(v: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(v).expect("no file descriptors in prompt results")
}

fn no_paths() -> OwnedValue {
    owned(Value::from(Vec::<OwnedObjectPath>::new()))
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(&self, _window_id: &str, #[zbus(connection)] conn: &Connection) -> Result<()> {
        let action = self.action.lock().await.take().ok_or_else(|| Error::failed("prompt already performed"))?;
        let conn = conn.clone();
        let state = self.state.clone();
        let path = self.path.clone();
        let handle = tokio::spawn(async move {
            let (dismissed, result) = run(&conn, &state, action).await;
            finish(&conn, &state, &path, dismissed, result).await;
        });
        *self.task.lock().await = Some(handle);
        Ok(())
    }

    async fn dismiss(&self, #[zbus(connection)] conn: &Connection) -> Result<()> {
        if let Some(handle) = self.task.lock().await.take() {
            handle.abort();
        }
        let dismissed_result = match self.action.lock().await.take() {
            Some(PromptAction::CreateCollection { .. }) | None => owned(Value::from(paths::root())),
            Some(PromptAction::Unlock { .. }) => no_paths(),
        };
        finish(conn, &self.state, &self.path, true, dismissed_result).await;
        Ok(())
    }

    #[zbus(signal)]
    pub async fn completed(emitter: &SignalEmitter<'_>, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}

/// Emit `Completed`, forget the prompt, and remove the object (deferred: may run inside `dismiss`).
async fn finish(conn: &Connection, state: &Shared, path: &OwnedObjectPath, dismissed: bool, result: OwnedValue) {
    state.lock().await.prompt_owners.remove(path.as_str());
    if let Ok(emitter) = SignalEmitter::new(conn, path.clone()) {
        let _ = emitter.completed(dismissed, Value::from(result)).await;
    }
    let conn = conn.clone();
    let path = path.clone();
    tokio::spawn(async move {
        let _ = conn.object_server().remove::<Prompt, _>(path.as_str()).await;
    });
}

async fn run(conn: &Connection, state: &Shared, action: PromptAction) -> (bool, OwnedValue) {
    match action {
        PromptAction::Unlock { collections, requested } => {
            for id in &collections {
                if !unlock_collection(conn, state, id).await {
                    return (true, no_paths());
                }
            }
            let unlocked: Vec<OwnedObjectPath> = {
                let st = state.lock().await;
                requested.into_iter().filter(|p| st.is_unlocked_path(p.as_str())).collect()
            };
            (false, owned(Value::from(unlocked)))
        }
        PromptAction::CreateCollection { label, alias } => match create_collection(conn, state, &label, alias.as_deref()).await {
            Some(path) => (false, owned(Value::from(path))),
            None => (true, owned(Value::from(paths::root()))),
        },
    }
}

/// Ask for the collection's password up to three times. True when unlocked.
pub async fn unlock_collection(conn: &Connection, state: &Shared, id: &str) -> bool {
    let (pinentry, label) = {
        let st = state.lock().await;
        let Some(vault) = st.collections.get(id) else { return false };
        if !vault.is_locked() {
            return true;
        }
        (st.pinentry.clone(), vault.label().to_string())
    };
    let mut error = None;
    for _ in 0..3 {
        let req = PinRequest {
            title: "secret-manager".into(),
            description: format!("An application wants access to the keyring '{label}', but it is locked."),
            prompt: "Password:".into(),
            error: error.take(),
            repeat: false,
        };
        let pin = match pinentry.ask(&req).await {
            Ok(PinOutcome::Pin(pin)) => pin,
            Ok(PinOutcome::Cancelled) => return false,
            Err(e) => {
                tracing::warn!("pinentry failed: {e}");
                return false;
            }
        };
        let result = {
            let mut st = state.lock().await;
            match st.collections.get_mut(id) {
                Some(vault) => vault.unlock(pin.as_bytes()),
                None => return false,
            }
        };
        match result {
            Ok(()) => {
                state.lock().await.touch();
                registry::notify_collection_changed(conn, id).await;
                return true;
            }
            Err(VaultError::WrongPassword) => error = Some("Wrong password, please try again.".into()),
            Err(e) => {
                tracing::warn!("cannot unlock '{id}': {e}");
                return false;
            }
        }
    }
    false
}

async fn create_collection(conn: &Connection, state: &Shared, label: &str, alias: Option<&str>) -> Option<OwnedObjectPath> {
    let pinentry = state.lock().await.pinentry.clone();
    let req = PinRequest {
        title: "secret-manager".into(),
        description: format!("Choose a password for the new keyring '{label}'."),
        prompt: "Password:".into(),
        error: None,
        repeat: true,
    };
    let pin = match pinentry.ask(&req).await {
        Ok(PinOutcome::Pin(pin)) if !pin.is_empty() => pin,
        Ok(_) => return None,
        Err(e) => {
            tracing::warn!("pinentry failed: {e}");
            return None;
        }
    };
    let id = {
        let mut st = state.lock().await;
        let id = st.unique_collection_id(label);
        let path = st.vault_dir.join(format!("{id}.vault"));
        match Vault::create(&path, label, pin.as_bytes(), st.kdf) {
            Ok(vault) => {
                st.collections.insert(id.clone(), vault);
                if let Some(a) = alias {
                    st.aliases.insert(a.to_string(), id.clone());
                    if let Err(e) = st.save_aliases() {
                        tracing::warn!("cannot save aliases: {e}");
                    }
                }
                id
            }
            Err(e) => {
                tracing::warn!("cannot create collection '{label}': {e}");
                return None;
            }
        }
    };
    if let Err(e) = registry::register_collection(conn, state, &id).await {
        tracing::warn!("cannot register collection '{id}': {e}");
    }
    if let Some(a) = alias {
        let _ = registry::register_alias(conn, state, a).await;
    }
    if let Ok(emitter) = SignalEmitter::new(conn, paths::SERVICE_PATH) {
        let _ = emitter.collection_created(paths::collection(&id)).await;
    }
    Some(paths::collection(&id))
}
```

- [ ] **Step 4: Add Unlock, Lock, CreateCollection to service.rs**

Imports to add: `super::prompt::{Prompt, PromptAction}`, `super::prop_string`. Methods inside the `#[interface]` block:
```rust
    #[zbus(out_args("unlocked", "prompt"))]
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut st = self.state.lock().await;
        let mut unlocked = Vec::new();
        let mut collections: Vec<String> = Vec::new();
        let mut requested = Vec::new();
        for path in objects {
            let Some(cid) = st.collection_id_of_path(path.as_str()) else { continue };
            if !st.collections[&cid].is_locked() {
                unlocked.push(path);
                continue;
            }
            if !collections.contains(&cid) {
                collections.push(cid);
            }
            requested.push(path);
        }
        if collections.is_empty() {
            return Ok((unlocked, paths::root()));
        }
        let prompt_path = st.new_prompt_path();
        st.prompt_owners.insert(prompt_path.to_string(), sender(&header));
        drop(st);
        let prompt = Prompt::new(self.state.clone(), prompt_path.clone(), PromptAction::Unlock { collections, requested });
        server.at(prompt_path.clone(), prompt).await?;
        Ok((unlocked, prompt_path))
    }

    #[zbus(out_args("locked", "prompt"))]
    async fn lock(&self, objects: Vec<OwnedObjectPath>, #[zbus(connection)] conn: &Connection) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let (locked, changed) = {
            let mut st = self.state.lock().await;
            let mut locked = Vec::new();
            let mut changed: Vec<String> = Vec::new();
            for path in objects {
                let Some(cid) = st.collection_id_of_path(path.as_str()) else { continue };
                if let Some(vault) = st.collections.get_mut(&cid) {
                    if !vault.is_locked() {
                        vault.lock();
                        if !changed.contains(&cid) {
                            changed.push(cid);
                        }
                    }
                    locked.push(path);
                }
            }
            (locked, changed)
        };
        for cid in changed {
            registry::notify_collection_changed(conn, &cid).await;
        }
        Ok((locked, paths::root()))
    }

    #[zbus(out_args("collection", "prompt"))]
    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = prop_string(&properties, "org.freedesktop.Secret.Collection.Label")?.unwrap_or_else(|| "Unnamed".to_string());
        let alias = if alias.is_empty() {
            None
        } else if paths::is_segment(alias) {
            Some(alias.to_string())
        } else {
            return Err(Error::invalid_args("alias names must match [A-Za-z0-9_]+"));
        };
        let mut st = self.state.lock().await;
        if let Some(existing) = alias.as_ref().and_then(|a| st.aliases.get(a)).filter(|id| st.collections.contains_key(*id)) {
            return Ok((paths::collection(existing), paths::root()));
        }
        let prompt_path = st.new_prompt_path();
        st.prompt_owners.insert(prompt_path.to_string(), sender(&header));
        drop(st);
        let prompt = Prompt::new(self.state.clone(), prompt_path.clone(), PromptAction::CreateCollection { label, alias });
        server.at(prompt_path.clone(), prompt).await?;
        Ok((paths::root(), prompt_path))
    }
```

Add `pub mod prompt;` to `dbus/mod.rs`.

- [ ] **Step 5: Run tests until green, fmt, clippy, commit**

Run: `cargo test -p secret-manager --test dbus_prompts && cargo test --workspace && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 7 tests pass.

```bash
git add -A
git commit -m "Add prompts with pinentry-driven unlock and collection creation"
```

---

### Task 12: Daemon completion, control handler, `sm init`, `sm daemon`

**Files:**
- Modify: `crates/secret-manager/src/daemon.rs` (full version below)
- Create: `crates/secret-manager/src/cli/mod.rs`, `crates/secret-manager/src/cli/vault_cmds.rs`
- Modify: `crates/secret-manager/src/main.rs`, `crates/secret-manager/src/lib.rs` (add `pub mod cli;`)
- Modify: `crates/secret-manager/tests/common/mod.rs` (idle option, config file for the CLI)
- Create: `crates/secret-manager/tests/daemon.rs`, `crates/secret-manager/tests/cli_init.rs`

**Interfaces:**
- Consumes: `control::{ControlServer, Handler}`, `control_protocol::*`, `dbus::registry`, `dbus::prompt::Prompt`, `dbus::session::Session`
- Produces:
  - `Daemon::start` now binds the control socket, watches client names, runs the idle lock; `Daemon::run_until_shutdown(self)`
  - `cli::{Cli, Command, CliError::{NotFound, Usage, Unreachable, Failed}, run(Cli) -> ExitCode, read_password(prompt) -> Result<Zeroizing<String>, CliError>, read_new_password(prompt), load_config() -> Result<Config, CliError>}`
  - `cli::vault_cmds::{init(collection: &str) -> Result<(), CliError>}`
  - Fixture gains `start_with_idle(Duration)`, writes `config.toml` with fast KDF and the fake pinentry for CLI runs

- [ ] **Step 1: Extend the fixture**

In `tests/common/mod.rs`, replace `start_with_pin` with a general constructor and keep the two wrappers:
```rust
    pub async fn start_with_pin(pin: Option<&str>) -> Fixture {
        Self::start_custom(pin, Duration::ZERO).await
    }

    pub async fn start_with_idle(idle: Duration) -> Fixture {
        Self::start_custom(Some(PASSWORD), idle).await
    }

    pub async fn start_custom(pin: Option<&str>, idle: Duration) -> Fixture {
        // ... body of the old start_with_pin, with two changes:
        //   VaultConfig { dir: vault_dir.clone(), auto_lock_after: idle }
        // and, before building `opts`, write the CLI config file:
        let config_dir = data_dir.path().join("config").join("secret-manager");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            format!(
                "[vault]\ndir = \"{}\"\n[prompt]\npinentry = \"{}\"\n[kdf]\nm_cost_kib = 8\nt_cost = 1\np_cost = 1\n",
                vault_dir.display(),
                fake_pinentry().display()
            ),
        )
        .unwrap();
        // ...
    }
```

- [ ] **Step 2: Write the failing tests**

`crates/secret-manager/tests/daemon.rs`:
```rust
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
    tokio::task::spawn_blocking(move || call(&sock, &req)).await.unwrap().unwrap()
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
    assert!(matches!(control(&fx, Request::Unlock { collection: "default".into(), password: pw("nope") }).await, Response::Error(_)));
    assert!(matches!(control(&fx, Request::Unlock { collection: "missing".into(), password: pw(PASSWORD) }).await, Response::Error(_)));

    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut changed = service.receive_collection_changed().await.unwrap();
    assert_eq!(control(&fx, Request::Unlock { collection: "default".into(), password: pw(PASSWORD) }).await, Response::Ok);
    assert_eq!(changed.next().await.unwrap().args().unwrap().collection, fx.default_collection());
    match control(&fx, Request::Status).await {
        Response::Status { collections, .. } => assert!(!collections[0].locked),
        other => panic!("{other:?}"),
    }
    assert_eq!(control(&fx, Request::Lock { collection: None }).await, Response::Ok);
    assert!(fx.daemon.state.lock().await.collections["default"].is_locked());

    assert!(matches!(
        control(&fx, Request::ChangePassword { collection: "default".into(), old: pw("bad"), new: pw("x") }).await,
        Response::Error(_)
    ));
    assert_eq!(control(&fx, Request::ChangePassword { collection: "default".into(), old: pw(PASSWORD), new: pw("new") }).await, Response::Ok);
    assert_eq!(control(&fx, Request::Lock { collection: Some("default".into()) }).await, Response::Ok);
    assert!(matches!(control(&fx, Request::Unlock { collection: "default".into(), password: pw(PASSWORD) }).await, Response::Error(_)));
    assert_eq!(control(&fx, Request::Unlock { collection: "default".into(), password: pw("new") }).await, Response::Ok);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_picks_up_new_vault_files() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let mut created = service.receive_collection_created().await.unwrap();
    let dir = fx.data_dir.path().join("secret-manager");
    Vault::create(&dir.join("extra.vault"), "Extra", b"x", KdfParams::FAST_FOR_TESTS).unwrap();
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok);
    let extra = paths::collection("extra");
    assert_eq!(created.next().await.unwrap().args().unwrap().collection, extra);
    assert!(service.collections().await.unwrap().contains(&extra));
    let coll = CollectionProxy::builder(&conn).path(extra).unwrap().build().await.unwrap();
    assert_eq!(coll.label().await.unwrap(), "Extra");
    assert_eq!(control(&fx, Request::Reload).await, Response::Ok, "reload is idempotent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_and_prompts_die_with_their_client() {
    let fx = Fixture::start().await;
    let conn = fx.client().await;
    let service = ServiceProxy::new(&conn).await.unwrap();
    let (_, session) = service.open_session(ALGORITHM_PLAIN, &Value::from("")).await.unwrap();
    let (_, prompt) = service.unlock(&[fx.default_collection()]).await.unwrap();
    assert_eq!(fx.daemon.state.lock().await.sessions.len(), 1);
    assert_eq!(fx.daemon.state.lock().await.prompt_owners.len(), 1);
    drop(service);
    drop(conn);
    assert!(wait_for(Duration::from_secs(3), || async {
        let st = fx.daemon.state.lock().await;
        st.sessions.is_empty() && st.prompt_owners.is_empty()
    })
    .await);
    let conn2 = fx.client().await;
    let s = SessionProxy::builder(&conn2).path(session).unwrap().build().await.unwrap();
    assert!(s.close().await.is_err(), "session object removed");
    let p = PromptProxy::builder(&conn2).path(prompt).unwrap().build().await.unwrap();
    assert!(p.dismiss().await.is_err(), "prompt object removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_lock_locks_after_inactivity() {
    let fx = Fixture::start_with_idle(Duration::from_millis(500)).await;
    fx.unlock_default().await;
    fx.daemon.state.lock().await.touch();
    assert!(!fx.daemon.state.lock().await.collections["default"].is_locked());
    assert!(wait_for(Duration::from_secs(5), || async { fx.daemon.state.lock().await.collections["default"].is_locked() }).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_daemon_exits_with_code_3() {
    let fx = Fixture::start().await;
    let mut cmd = fx.sm();
    cmd.arg("daemon");
    let out = cmd.timeout(Duration::from_secs(20)).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
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
```

`crates/secret-manager/tests/cli_init.rs`:
```rust
mod common;

use common::{Fixture, wait_for};
use predicates::prelude::*;
use secret_manager::dbus::paths;
use secret_manager::dbus::proxies::ServiceProxy;
use secret_manager::vault::Vault;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_creates_vault_and_running_daemon_reloads() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["init", "--collection", "Work"])
        .write_stdin("hunter2\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("work.vault"));
    let dir = fx.data_dir.path().join("secret-manager");
    let mut v = Vault::open(&dir.join("work.vault")).unwrap();
    v.unlock(b"hunter2").unwrap();
    assert_eq!(v.label(), "Work");

    let service = ServiceProxy::new(&fx.client().await).await.unwrap();
    assert!(wait_for(Duration::from_secs(3), || async {
        service.collections().await.unwrap().contains(&paths::collection("work"))
    })
    .await);
    assert_eq!(service.read_alias("default").await.unwrap(), fx.default_collection(), "existing default alias untouched");

    fx.sm().args(["init", "--collection", "Work"]).write_stdin("x\n").assert().code(1).stderr(predicate::str::contains("already exists"));
    fx.sm().args(["init", "--collection", "Other"]).write_stdin("\n").assert().code(2).stderr(predicate::str::contains("empty"));
}

#[test]
fn init_without_daemon_sets_default_alias() {
    let data = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", data.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_CONFIG_HOME", data.path().join("config"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .arg("init")
        .write_stdin("pw\n")
        .assert()
        .success();
    let dir = data.path().join("secret-manager");
    assert!(dir.join("default.vault").exists());
    let aliases = std::fs::read_to_string(dir.join("aliases.toml")).unwrap();
    assert!(aliases.contains("default = \"default\""));
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p secret-manager --test daemon --test cli_init`
Expected: compile errors (`start_with_idle`, `control_socket` path unused, `run_until_shutdown`, `cli` module).

- [ ] **Step 4: Write the full daemon.rs**

Replace the file:
```rust
//! Daemon assembly: vaults, bus connection, control socket, housekeeping tasks.

use crate::config::Config;
use crate::control::{ControlServer, Handler};
use crate::dbus::paths::{self, BUS_NAME, SERVICE_PATH};
use crate::dbus::prompt::Prompt;
use crate::dbus::registry;
use crate::dbus::service::{Service, ServiceSignals};
use crate::dbus::session::Session;
use crate::dbus::state::{ServiceState, Shared};
use crate::prompt::Pinentry;
use control_protocol::{CollectionStatus, Request, Response};
use futures_util::StreamExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::connection::Builder;
use zbus::object_server::SignalEmitter;

#[derive(Debug, Clone)]
pub enum BusAddress {
    Session,
    Address(String),
}

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config: Config,
    pub bus: BusAddress,
    /// Override for `control_protocol::socket_path()` (tests).
    pub control_socket: Option<PathBuf>,
    /// Extra environment for the pinentry child (tests).
    pub pinentry_env: Vec<(String, String)>,
    /// How often the idle-lock timer checks. Production: 30 s.
    pub idle_check_interval: Duration,
}

impl DaemonOptions {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            bus: BusAddress::Session,
            control_socket: None,
            pinentry_env: Vec::new(),
            idle_check_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("another secret service already owns {BUS_NAME}")]
    NameTaken,
    #[error("bus error: {0}")]
    ZBus(zbus::Error),
    #[error("cannot load vaults: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot bind control socket: {0}")]
    Control(std::io::Error),
}

impl From<zbus::Error> for DaemonError {
    fn from(e: zbus::Error) -> Self {
        match e {
            zbus::Error::NameTaken => DaemonError::NameTaken,
            other => DaemonError::ZBus(other),
        }
    }
}

pub struct Daemon {
    pub connection: Connection,
    pub state: Shared,
    tasks: Vec<JoinHandle<()>>,
}

impl Daemon {
    pub async fn start(opts: DaemonOptions) -> Result<Daemon, DaemonError> {
        let mut pinentry = Pinentry::new(&opts.config.prompt.pinentry);
        for (k, v) in &opts.pinentry_env {
            pinentry = pinentry.env(k, v);
        }
        let mut state = ServiceState::new(opts.config.vault.dir.clone(), opts.config.kdf.into(), pinentry);
        state.load_vaults()?;
        let state: Shared = Arc::new(tokio::sync::Mutex::new(state));

        let builder = match &opts.bus {
            BusAddress::Session => Builder::session()?,
            BusAddress::Address(a) => Builder::address(a.as_str())?,
        };
        let connection = builder
            .name(BUS_NAME)?
            .serve_at(SERVICE_PATH, Service::new(state.clone()))?
            .build()
            .await?;
        registry::register_all(&connection, &state).await?;

        let socket = opts.control_socket.clone().unwrap_or_else(control_protocol::socket_path);
        let server = ControlServer::bind(&socket).await.map_err(DaemonError::Control)?;

        let mut tasks = vec![
            tokio::spawn(server.run(control_handler(state.clone(), connection.clone()))),
            tokio::spawn(watch_clients(connection.clone(), state.clone())),
        ];
        let idle = opts.config.vault.auto_lock_after;
        if !idle.is_zero() {
            tasks.push(tokio::spawn(idle_lock(connection.clone(), state.clone(), idle, opts.idle_check_interval)));
        }
        tracing::info!("serving {BUS_NAME}; control socket at {}", socket.display());
        Ok(Daemon { connection, state, tasks })
    }

    /// Block until SIGTERM or SIGINT, then stop.
    pub async fn run_until_shutdown(self) {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
        tracing::info!("shutting down");
        self.shutdown();
    }

    /// Abort background tasks; the control socket file is removed with its server.
    /// The bus name is released when `connection` drops.
    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn control_handler(state: Shared, conn: Connection) -> Handler {
    Arc::new(move |req| {
        let state = state.clone();
        let conn = conn.clone();
        Box::pin(async move { handle_control(state, conn, req).await })
    })
}

async fn handle_control(state: Shared, conn: Connection, req: Request) -> Response {
    match req {
        Request::Unlock { collection, password } => {
            let result = {
                let mut st = state.lock().await;
                match st.collections.get_mut(&collection) {
                    Some(vault) => vault.unlock(password.as_bytes()).map_err(|e| e.to_string()),
                    None => Err(format!("no collection '{collection}'")),
                }
            };
            match result {
                Ok(()) => {
                    state.lock().await.touch();
                    registry::notify_collection_changed(&conn, &collection).await;
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::Lock { collection } => {
            let changed = {
                let mut st = state.lock().await;
                let targets: Vec<String> = match collection {
                    Some(c) => vec![c],
                    None => st.collections.keys().cloned().collect(),
                };
                let mut changed = Vec::new();
                for id in targets {
                    match st.collections.get_mut(&id) {
                        Some(vault) => {
                            if !vault.is_locked() {
                                vault.lock();
                                changed.push(id);
                            }
                        }
                        None => return Response::Error(format!("no collection '{id}'")),
                    }
                }
                changed
            };
            for id in changed {
                registry::notify_collection_changed(&conn, &id).await;
            }
            Response::Ok
        }
        Request::ChangePassword { collection, old, new } => {
            let mut st = state.lock().await;
            let kdf = st.kdf;
            match st.collections.get_mut(&collection) {
                Some(vault) => match vault.change_password(old.as_bytes(), new.as_bytes(), kdf) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e.to_string()),
                },
                None => Response::Error(format!("no collection '{collection}'")),
            }
        }
        Request::Status => {
            let st = state.lock().await;
            Response::Status {
                collections: st
                    .collections
                    .iter()
                    .map(|(id, v)| CollectionStatus {
                        id: id.clone(),
                        label: v.label().to_string(),
                        locked: v.is_locked(),
                        items: v.item_ids().len(),
                    })
                    .collect(),
                uptime_secs: st.started.elapsed().as_secs(),
            }
        }
        Request::Reload => {
            let new_ids = {
                let mut st = state.lock().await;
                match st.load_vaults() {
                    Ok(ids) => ids,
                    Err(e) => return Response::Error(e.to_string()),
                }
            };
            if let Err(e) = registry::register_all(&conn, &state).await {
                return Response::Error(e.to_string());
            }
            for id in new_ids {
                if let Ok(emitter) = SignalEmitter::new(&conn, SERVICE_PATH) {
                    let _ = emitter.collection_created(paths::collection(&id)).await;
                }
            }
            Response::Ok
        }
    }
}

/// Drop sessions and prompts whose owning client left the bus.
async fn watch_clients(conn: Connection, state: Shared) {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else { return };
    let Ok(mut stream) = dbus.receive_name_owner_changed().await else { return };
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else { continue };
        if args.new_owner.is_some() {
            continue;
        }
        let name = args.name.to_string();
        let (sessions, prompts) = {
            let mut st = state.lock().await;
            let sessions: Vec<String> = st.sessions.iter().filter(|(_, e)| e.owner == name).map(|(p, _)| p.clone()).collect();
            for p in &sessions {
                st.sessions.remove(p);
            }
            let prompts: Vec<String> = st.prompt_owners.iter().filter(|(_, o)| **o == name).map(|(p, _)| p.clone()).collect();
            for p in &prompts {
                st.prompt_owners.remove(p);
            }
            (sessions, prompts)
        };
        for p in sessions {
            let _ = conn.object_server().remove::<Session, _>(p.as_str()).await;
        }
        for p in prompts {
            let _ = conn.object_server().remove::<Prompt, _>(p.as_str()).await;
        }
    }
}

async fn idle_lock(conn: Connection, state: Shared, after: Duration, check_every: Duration) {
    let mut ticker = tokio::time::interval(check_every);
    loop {
        ticker.tick().await;
        let ids: Vec<String> = {
            let mut st = state.lock().await;
            if st.last_activity.elapsed() < after {
                continue;
            }
            let mut ids = Vec::new();
            for (id, vault) in st.collections.iter_mut() {
                if !vault.is_locked() {
                    vault.lock();
                    ids.push(id.clone());
                }
            }
            ids
        };
        for id in ids {
            tracing::info!("auto-locked '{id}' after inactivity");
            registry::notify_collection_changed(&conn, &id).await;
        }
    }
}
```

- [ ] **Step 5: Write cli/mod.rs and cli/vault_cmds.rs**

`cli/mod.rs`:
```rust
//! Command line interface. Every subcommand except `daemon` is a client.

pub mod vault_cmds;

use crate::config::Config;
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read};
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "secret-manager", bin_name = "sm", version, about = "Secret Service daemon and CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new collection vault
    Init {
        /// Label of the collection; the file name is derived from it
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Run the D-Bus secret service
    Daemon {
        /// Kept for readability in unit files; the daemon always runs in the foreground
        #[arg(long)]
        foreground: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Exit 1: nothing matched, or the user dismissed a prompt.
    #[error("{0}")]
    NotFound(String),
    /// Exit 2: bad arguments or input.
    #[error("{0}")]
    Usage(String),
    /// Exit 3: daemon or bus unreachable, or bus name taken.
    #[error("{0}")]
    Unreachable(String),
    /// Exit 1: any other failure.
    #[error("{0}")]
    Failed(String),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::NotFound(_) | CliError::Failed(_) => 1,
            CliError::Usage(_) => 2,
            CliError::Unreachable(_) => 3,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Failed(e.to_string())
    }
}

impl From<crate::vault::VaultError> for CliError {
    fn from(e: crate::vault::VaultError) -> Self {
        CliError::Failed(e.to_string())
    }
}

pub fn load_config() -> Result<Config, CliError> {
    Config::load().map_err(|e| CliError::Failed(e.to_string()))
}

/// Read a password: hidden prompt on a TTY, one line from stdin otherwise.
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{prompt}: ")).map(Zeroizing::new).map_err(CliError::from)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string()))
    }
}

/// Read a new password, confirmed when interactive. Rejects empty passwords.
pub fn read_new_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    let first = read_password(prompt)?;
    if first.is_empty() {
        return Err(CliError::Usage("empty password not allowed".into()));
    }
    if std::io::stdin().is_terminal() {
        let second = read_password("Repeat")?;
        if *first != *second {
            return Err(CliError::Usage("passwords do not match".into()));
        }
    }
    Ok(first)
}

/// Read all of stdin as a secret, dropping one trailing newline.
pub fn read_secret_from_stdin() -> Result<Zeroizing<Vec<u8>>, CliError> {
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(read_password("Secret")?.as_bytes().to_vec()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut buf)?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

pub async fn run(cli: Cli) -> ExitCode {
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secret-manager: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Init { collection } => vault_cmds::init(&collection),
        Command::Daemon { .. } => daemon().await,
    }
}

async fn daemon() -> Result<(), CliError> {
    use crate::daemon::{Daemon, DaemonError, DaemonOptions};
    let config = load_config()?;
    let daemon = Daemon::start(DaemonOptions::new(config)).await.map_err(|e| match e {
        DaemonError::NameTaken => CliError::Unreachable(e.to_string()),
        other => CliError::Failed(other.to_string()),
    })?;
    daemon.run_until_shutdown().await;
    Ok(())
}
```

`cli/vault_cmds.rs`:
```rust
//! init / lock / unlock / status / change-password

use super::{CliError, load_config, read_new_password};
use crate::dbus::state::{load_aliases, save_aliases_to};
use crate::vault::{Vault, collection_id_from_label};
use control_protocol::{Request, Response, call, socket_path};

pub fn init(collection: &str) -> Result<(), CliError> {
    let config = load_config()?;
    let id = collection_id_from_label(collection);
    let path = config.vault.dir.join(format!("{id}.vault"));
    if path.exists() {
        return Err(CliError::Failed(format!("collection '{id}' already exists at {}", path.display())));
    }
    let password = read_new_password(&format!("Choose a password for collection '{collection}'"))?;
    Vault::create(&path, collection, password.as_bytes(), config.kdf.into())?;

    let mut aliases = load_aliases(&config.vault.dir)?;
    if !aliases.contains_key("default") {
        aliases.insert("default".to_string(), id.clone());
        save_aliases_to(&config.vault.dir, &aliases)?;
    }
    match call(&socket_path(), &Request::Reload) {
        Ok(Response::Ok) => {}
        Ok(Response::Error(e)) => eprintln!("warning: running daemon did not reload: {e}"),
        Ok(_) => {}
        Err(_) => {} // no daemon running; it will pick the file up on start
    }
    println!("Created collection '{collection}' at {}", path.display());
    Ok(())
}
```

`main.rs`:
```rust
use clap::Parser;
use secret_manager::cli::{Cli, run};
use tracing_subscriber::EnvFilter;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(run(cli))
}
```

Add `pub mod cli;` to `lib.rs`.

- [ ] **Step 6: Run tests until green, fmt, clippy, commit**

Run: `cargo test -p secret-manager --test daemon --test cli_init && cargo test --workspace && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 6 daemon tests and 2 init tests pass.

```bash
git add -A
git commit -m "Complete daemon with control socket, client cleanup, idle lock; add init and daemon commands"
```

---

### Task 13: CLI secrets: get, set, delete, list

**Files:**
- Create: `crates/secret-manager/src/cli/client.rs`, `crates/secret-manager/src/cli/secrets.rs`
- Modify: `crates/secret-manager/src/cli/mod.rs` (variants, dispatch, `pub mod client; pub mod secrets;`)
- Modify: `crates/secret-manager/Cargo.toml` (add `serde_json = "1"`)
- Create: `crates/secret-manager/tests/cli_secrets.rs`

**Interfaces:**
- Consumes: `dbus::proxies::*`, `session::{dh::KeyPair, SessionCipher}`, `dbus::session::SecretStruct`
- Produces:
  - `cli::client::{Client, ItemInfo{path, label, attributes, locked, modified}, map_zbus(zbus::Error) -> CliError}` with `Client::connect().await`, `search(&BTreeMap)`, `unlock(&[OwnedObjectPath]) -> Result<Vec<OwnedObjectPath>>`, `perform_prompt(&OwnedObjectPath) -> Result<OwnedValue>`, `get_secret(&OwnedObjectPath) -> Result<Zeroizing<Vec<u8>>>`, `item_info(&OwnedObjectPath)`, `default_collection()`, `store(attrs, label, secret) -> Result<OwnedObjectPath>`, `delete_item(&OwnedObjectPath)`, `all_items()`, `encrypt(&[u8], content_type) -> SecretStruct`
  - `cli::secrets::{get, set, delete, list, parse_attrs(&[String]) -> Result<BTreeMap<String,String>, CliError>}`
  - CLI: `sm get <ATTR=VALUE>... [--label L]`, `sm set <ATTR=VALUE>... --label L`, `sm delete <ATTR=VALUE>...`, `sm list [<ATTR=VALUE>...] [--json]`

- [ ] **Step 1: Write the failing tests**

`crates/secret-manager/tests/cli_secrets.rs`:
```rust
mod common;

use common::Fixture;
use predicates::prelude::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_get_list_delete_round_trip() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm().args(["set", "app=git", "user=joe", "--label", "git token"]).write_stdin("s3cret\n").assert().success();
    fx.sm().args(["get", "app=git", "user=joe"]).assert().success().stdout("s3cret");
    fx.sm().args(["get", "app=git"]).assert().success().stdout("s3cret");
    fx.sm().args(["get", "app=git", "--label", "git token"]).assert().success().stdout("s3cret");
    fx.sm().args(["get", "app=git", "--label", "other"]).assert().code(1);
    fx.sm().args(["get", "user=nobody"]).assert().code(1).stderr(predicate::str::contains("no matching secret"));

    // replace keeps a single item
    fx.sm().args(["set", "app=git", "user=joe", "--label", "git token 2"]).write_stdin("newer").assert().success();
    fx.sm().args(["get", "app=git"]).assert().success().stdout("newer");
    fx.sm().args(["list"]).assert().success().stdout(predicate::str::contains("git token 2").and(predicate::str::contains("app=git")));
    fx.sm().args(["list", "app=git"]).assert().success().stdout(predicate::str::contains("user=joe"));
    fx.sm().args(["list", "app=nope"]).assert().success().stdout("");
    let json = fx.sm().args(["list", "--json"]).assert().success().get_output().stdout.clone();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed[0]["label"], "git token 2");
    assert_eq!(parsed[0]["attributes"]["user"], "joe");
    assert_eq!(parsed[0]["locked"], false);
    assert!(!fx.sm().args(["list"]).assert().get_output().stdout.windows(5).any(|w| w == b"newer"), "list never prints secrets");

    fx.sm().args(["delete", "app=git"]).assert().success();
    fx.sm().args(["get", "app=git"]).assert().code(1);
    fx.sm().args(["delete", "app=git"]).assert().code(1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn most_recent_item_wins_and_binary_secrets_survive() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm().args(["set", "k=v", "n=1", "--label", "one"]).write_stdin("first").assert().success();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fx.sm().args(["set", "k=v", "n=2", "--label", "two"]).write_stdin("second").assert().success();
    fx.sm().args(["get", "k=v"]).assert().success().stdout("second");
    let bytes: Vec<u8> = vec![0, 1, 2, 255, 10, 13, 10];
    fx.sm().args(["set", "bin=1", "--label", "bin"]).write_stdin(bytes.clone()).assert().success();
    let out = fx.sm().args(["get", "bin=1"]).assert().success().get_output().stdout.clone();
    assert_eq!(out, &bytes[..bytes.len() - 1], "exactly one trailing newline is stripped on set");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_errors_and_unreachable() {
    let fx = Fixture::start().await;
    fx.sm().args(["get", "noequals"]).assert().code(2).stderr(predicate::str::contains("ATTR=VALUE"));
    fx.sm().args(["set", "a=b"]).assert().code(2); // clap: --label required
    fx.sm().args(["get"]).assert().code(2);
    fx.sm().args(["get", "a=b"]).env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus").assert().code(3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_prompts_to_unlock() {
    let fx = Fixture::start().await; // locked, pinentry answers pw
    fx.sm().args(["set", "a=b", "--label", "x"]).write_stdin("v").assert().success();
    assert!(fx.pinentry_log().contains("GETPIN"), "set unlocked through the prompt");
    fx.lock_default().await;
    fx.sm().args(["get", "a=b"]).assert().success().stdout("v");
    fx.sm().args(["list"]).assert().success().stdout(predicate::str::contains("x"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dismissed_prompt_exits_1() {
    let fx = Fixture::start_with_pin(None).await;
    fx.sm().args(["set", "a=b", "--label", "x"]).write_stdin("v").assert().code(1).stderr(predicate::str::contains("dismissed"));
    fx.unlock_default().await;
    fx.sm().args(["set", "a=b", "--label", "x"]).write_stdin("v").assert().success();
    fx.lock_default().await;
    fx.sm().args(["get", "a=b"]).assert().code(1).stderr(predicate::str::contains("dismissed"));
    fx.sm().args(["list"]).assert().success().stdout(predicate::str::contains("[locked]"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interop_with_secret_tool() {
    if std::process::Command::new("secret-tool").arg("--version").output().is_err() {
        return;
    }
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    fx.sm().args(["set", "app=interop", "--label", "from sm"]).write_stdin("shared").assert().success();
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "app", "interop"])
        .env("DBUS_SESSION_BUS_ADDRESS", &fx.bus.address)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "shared");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager --test cli_secrets`
Expected: failures (subcommands unknown, exit 2 everywhere).

- [ ] **Step 3: Implement client.rs**

```rust
//! Secret Service client used by the CLI: session setup, prompts, item helpers.

use super::CliError;
use crate::dbus::proxies::{CollectionProxy, ItemProxy, PromptProxy, ServiceProxy};
use crate::dbus::session::SecretStruct;
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

pub fn map_zbus(e: zbus::Error) -> CliError {
    match &e {
        zbus::Error::MethodError(name, msg, _) => {
            let msg = msg.clone().unwrap_or_default();
            match name.as_str() {
                "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.NameHasNoOwner"
                | "org.freedesktop.DBus.Error.NoReply" => CliError::Unreachable(format!(
                    "secret service is not running ({msg}); start it with `systemctl --user start secret-manager`"
                )),
                "org.freedesktop.Secret.Error.IsLocked" => CliError::Failed("collection is locked".into()),
                other => CliError::Failed(format!("{other}: {msg}")),
            }
        }
        zbus::Error::InputOutput(_) | zbus::Error::Address(_) => {
            CliError::Unreachable(format!("cannot reach the session bus: {e}"))
        }
        _ => CliError::Failed(e.to_string()),
    }
}

#[derive(Debug, Clone)]
pub struct ItemInfo {
    pub path: OwnedObjectPath,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub locked: bool,
    pub modified: u64,
}

pub struct Client {
    pub conn: Connection,
    pub service: ServiceProxy<'static>,
    pub session: OwnedObjectPath,
    cipher: SessionCipher,
}

impl Client {
    /// Connect to the session bus and open a DH session (plain if the service refuses DH).
    pub async fn connect() -> Result<Client, CliError> {
        let conn = Connection::session()
            .await
            .map_err(|e| CliError::Unreachable(format!("cannot connect to the session bus: {e}")))?;
        let service = ServiceProxy::builder(&conn)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(map_zbus)?;
        let pair = KeyPair::generate();
        let (session, cipher) = match service.open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec())).await {
            Ok((output, path)) => {
                let peer = Vec::<u8>::try_from(output).map_err(|e| CliError::Failed(format!("bad DH reply: {e}")))?;
                let cipher = SessionCipher::from_dh(&pair, &peer).map_err(|e| CliError::Failed(e.to_string()))?;
                (path, cipher)
            }
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == "org.freedesktop.DBus.Error.NotSupported" => {
                let (_, path) = service.open_session(ALGORITHM_PLAIN, &Value::from("")).await.map_err(map_zbus)?;
                (path, SessionCipher::plain())
            }
            Err(e) => return Err(map_zbus(e)),
        };
        Ok(Client { conn, service, session, cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8], content_type: &str) -> SecretStruct {
        let (parameters, value) = self.cipher.encrypt(plaintext);
        SecretStruct { session: self.session.clone(), parameters, value, content_type: content_type.to_string() }
    }

    pub fn decrypt(&self, secret: &SecretStruct) -> Result<Zeroizing<Vec<u8>>, CliError> {
        self.cipher.decrypt(&secret.parameters, &secret.value).map_err(|e| CliError::Failed(e.to_string()))
    }

    pub async fn search(&self, attrs: &BTreeMap<String, String>) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), CliError> {
        let map: HashMap<&str, &str> = attrs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        self.service.search_items(map).await.map_err(map_zbus)
    }

    /// Unlock objects, driving any prompt. Dismissal is `CliError::NotFound`.
    pub async fn unlock(&self, objects: &[OwnedObjectPath]) -> Result<Vec<OwnedObjectPath>, CliError> {
        let (mut unlocked, prompt) = self.service.unlock(objects).await.map_err(map_zbus)?;
        if prompt.as_str() != "/" {
            let result = self.perform_prompt(&prompt).await?;
            unlocked.extend(Vec::<OwnedObjectPath>::try_from(result).unwrap_or_default());
        }
        Ok(unlocked)
    }

    pub async fn perform_prompt(&self, prompt: &OwnedObjectPath) -> Result<OwnedValue, CliError> {
        let proxy = PromptProxy::builder(&self.conn).path(prompt.clone()).map_err(map_zbus)?.build().await.map_err(map_zbus)?;
        let mut completed = proxy.receive_completed().await.map_err(map_zbus)?;
        proxy.prompt("").await.map_err(map_zbus)?;
        let signal = tokio::time::timeout(PROMPT_TIMEOUT, completed.next())
            .await
            .map_err(|_| CliError::Failed("timed out waiting for the password prompt".into()))?
            .ok_or_else(|| CliError::Failed("prompt vanished".into()))?;
        let args = signal.args().map_err(map_zbus)?;
        if args.dismissed {
            return Err(CliError::NotFound("password prompt dismissed".into()));
        }
        args.result.try_to_owned().map_err(|e| CliError::Failed(e.to_string()))
    }

    async fn item_proxy(&self, path: &OwnedObjectPath) -> Result<ItemProxy<'static>, CliError> {
        ItemProxy::builder(&self.conn)
            .path(path.clone())
            .map_err(map_zbus)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(map_zbus)
    }

    async fn collection_proxy(&self, path: &OwnedObjectPath) -> Result<CollectionProxy<'static>, CliError> {
        CollectionProxy::builder(&self.conn)
            .path(path.clone())
            .map_err(map_zbus)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(map_zbus)
    }

    pub async fn get_secret(&self, item: &OwnedObjectPath) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let secret = self.item_proxy(item).await?.get_secret(&self.session).await.map_err(map_zbus)?;
        self.decrypt(&secret)
    }

    pub async fn item_info(&self, item: &OwnedObjectPath) -> Result<ItemInfo, CliError> {
        let proxy = self.item_proxy(item).await?;
        Ok(ItemInfo {
            path: item.clone(),
            label: proxy.label().await.map_err(map_zbus)?,
            attributes: proxy.attributes().await.map_err(map_zbus)?.into_iter().collect(),
            locked: proxy.locked().await.map_err(map_zbus)?,
            modified: proxy.modified().await.map_err(map_zbus)?,
        })
    }

    pub async fn default_collection(&self) -> Result<OwnedObjectPath, CliError> {
        let path = self.service.read_alias("default").await.map_err(map_zbus)?;
        if path.as_str() == "/" {
            return Err(CliError::Failed("no default collection; create one with `sm init`".into()));
        }
        Ok(path)
    }

    /// Store into the default collection, replacing an item with identical attributes.
    pub async fn store(&self, attrs: &BTreeMap<String, String>, label: &str, secret: &[u8]) -> Result<OwnedObjectPath, CliError> {
        let collection = self.default_collection().await?;
        let proxy = self.collection_proxy(&collection).await?;
        if proxy.locked().await.map_err(map_zbus)? {
            self.unlock(std::slice::from_ref(&collection)).await?;
        }
        let attrs_map: HashMap<String, String> = attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let props = HashMap::from([
            ("org.freedesktop.Secret.Item.Label", Value::from(label.to_string())),
            ("org.freedesktop.Secret.Item.Attributes", Value::from(attrs_map)),
        ]);
        let (item, _prompt) = proxy.create_item(props, &self.encrypt(secret, "text/plain"), true).await.map_err(map_zbus)?;
        Ok(item)
    }

    pub async fn delete_item(&self, item: &OwnedObjectPath) -> Result<(), CliError> {
        self.item_proxy(item).await?.delete().await.map(|_| ()).map_err(map_zbus)
    }

    /// Every item path in every collection.
    pub async fn all_items(&self) -> Result<Vec<OwnedObjectPath>, CliError> {
        let mut out = Vec::new();
        for c in self.service.collections().await.map_err(map_zbus)? {
            out.extend(self.collection_proxy(&c).await?.items().await.map_err(map_zbus)?);
        }
        Ok(out)
    }
}
```

- [ ] **Step 4: Implement secrets.rs**

```rust
//! get / set / delete / list, argument-compatible with `secret-tool`.

use super::client::{Client, ItemInfo};
use super::{CliError, read_secret_from_stdin};
use std::collections::BTreeMap;
use std::io::Write;
use zbus::zvariant::OwnedObjectPath;

pub fn parse_attrs(args: &[String]) -> Result<BTreeMap<String, String>, CliError> {
    let mut out = BTreeMap::new();
    for a in args {
        let (k, v) = a
            .split_once('=')
            .filter(|(k, _)| !k.is_empty())
            .ok_or_else(|| CliError::Usage(format!("expected ATTR=VALUE, got '{a}'")))?;
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

/// Search, unlocking what is locked. Errors with NotFound on a dismissed prompt.
async fn find(client: &Client, query: &BTreeMap<String, String>) -> Result<Vec<OwnedObjectPath>, CliError> {
    let (mut items, locked) = client.search(query).await?;
    if !locked.is_empty() {
        items.extend(client.unlock(&locked).await?);
    }
    Ok(items)
}

pub async fn get(attrs: Vec<String>, label: Option<String>) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    let client = Client::connect().await?;
    let mut best: Option<ItemInfo> = None;
    for path in find(&client, &query).await? {
        let info = client.item_info(&path).await?;
        if label.as_deref().is_some_and(|l| l != info.label) {
            continue;
        }
        if best.as_ref().is_none_or(|b| info.modified > b.modified) {
            best = Some(info);
        }
    }
    let Some(info) = best else {
        return Err(CliError::NotFound("no matching secret".into()));
    };
    let secret = client.get_secret(&info.path).await?;
    let mut out = std::io::stdout().lock();
    out.write_all(&secret)?;
    out.flush()?;
    Ok(())
}

pub async fn set(attrs: Vec<String>, label: String) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    if query.is_empty() {
        return Err(CliError::Usage("at least one ATTR=VALUE is required".into()));
    }
    let secret = read_secret_from_stdin()?;
    let client = Client::connect().await?;
    client.store(&query, &label, &secret).await?;
    Ok(())
}

pub async fn delete(attrs: Vec<String>) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    if query.is_empty() {
        return Err(CliError::Usage("at least one ATTR=VALUE is required".into()));
    }
    let client = Client::connect().await?;
    let items = find(&client, &query).await?;
    if items.is_empty() {
        return Err(CliError::NotFound("no matching secret".into()));
    }
    for item in &items {
        client.delete_item(item).await?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ListEntry {
    path: String,
    label: String,
    attributes: BTreeMap<String, String>,
    locked: bool,
    modified: u64,
}

/// Labels and attributes only. Locked items show as `[locked]`; no prompt is raised.
pub async fn list(attrs: Vec<String>, json: bool) -> Result<(), CliError> {
    let query = parse_attrs(&attrs)?;
    let client = Client::connect().await?;
    let paths = if query.is_empty() {
        client.all_items().await?
    } else {
        let (mut u, l) = client.search(&query).await?;
        u.extend(l);
        u
    };
    let mut entries = Vec::new();
    for p in paths {
        let info = client.item_info(&p).await?;
        entries.push(ListEntry {
            path: info.path.to_string(),
            label: if info.locked { "[locked]".to_string() } else { info.label },
            attributes: info.attributes,
            locked: info.locked,
            modified: info.modified,
        });
    }
    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &entries).map_err(|e| CliError::Failed(e.to_string()))?;
        writeln!(out)?;
    } else {
        for e in entries {
            let attrs: Vec<String> = e.attributes.iter().map(|(k, v)| format!("{k}={v}")).collect();
            writeln!(out, "{}\t{}", e.label, attrs.join(" "))?;
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Wire the subcommands**

In `cli/mod.rs` add `pub mod client; pub mod secrets;` and these variants to `Command`:
```rust
    /// Print a secret to stdout (no trailing newline)
    Get {
        /// Attribute filters; all must match
        #[arg(required = true, value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
        /// Only consider items with this label
        #[arg(long)]
        label: Option<String>,
    },
    /// Store a secret read from stdin
    Set {
        #[arg(required = true, value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
        #[arg(long)]
        label: String,
    },
    /// Delete every item matching the attributes
    Delete {
        #[arg(required = true, value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
    },
    /// List items (labels and attributes, never secrets)
    List {
        #[arg(value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
```
and dispatch arms:
```rust
        Command::Get { attrs, label } => secrets::get(attrs, label).await,
        Command::Set { attrs, label } => secrets::set(attrs, label).await,
        Command::Delete { attrs } => secrets::delete(attrs).await,
        Command::List { attrs, json } => secrets::list(attrs, json).await,
```
Add `serde_json = "1"` to the crate dependencies.

- [ ] **Step 6: Run tests until green, fmt, clippy, commit**

Run: `cargo test -p secret-manager --test cli_secrets && cargo test --workspace && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 6 tests pass.

```bash
git add -A
git commit -m "Add get, set, delete, list commands with DH session client"
```

---

### Task 14: CLI vault management and shell completions

**Files:**
- Modify: `crates/secret-manager/src/cli/vault_cmds.rs` (add `lock`, `unlock`, `status`, `change_password`), `crates/secret-manager/src/cli/mod.rs` (variants, dispatch, completions)
- Create: `crates/secret-manager/tests/cli_vault.rs`

**Interfaces:**
- Produces: `cli::vault_cmds::{lock(Option<String>), unlock(String), status(), change_password(String), control(Request) -> Result<Response, CliError>}`; CLI `sm lock [--collection C]`, `sm unlock [--collection C]`, `sm status`, `sm change-password [--collection C]`, `sm completions <bash|zsh|fish|elvish|powershell>`

- [ ] **Step 1: Write the failing tests**

`crates/secret-manager/tests/cli_vault.rs`:
```rust
mod common;

use common::Fixture;
use predicates::prelude::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn status_unlock_lock_change_password() {
    let fx = Fixture::start().await;
    fx.sm().arg("status").assert().success().stdout(predicate::str::contains("default").and(predicate::str::contains("locked")));
    fx.sm().arg("unlock").write_stdin("wrong\n").assert().code(1).stderr(predicate::str::contains("wrong password"));
    fx.sm().arg("unlock").write_stdin("pw\n").assert().success();
    fx.sm().arg("status").assert().success().stdout(predicate::str::contains("unlocked"));
    assert!(!fx.daemon.state.lock().await.collections["default"].is_locked());
    fx.sm().arg("lock").assert().success();
    assert!(fx.daemon.state.lock().await.collections["default"].is_locked());
    fx.sm().args(["unlock", "--collection", "nope"]).write_stdin("pw\n").assert().code(1).stderr(predicate::str::contains("no collection"));

    fx.sm().arg("change-password").write_stdin("pw\nnewpw\n").assert().success();
    fx.sm().arg("lock").assert().success();
    fx.sm().arg("unlock").write_stdin("pw\n").assert().code(1);
    fx.sm().arg("unlock").write_stdin("newpw\n").assert().success();
    fx.sm().arg("change-password").write_stdin("newpw\n\n").assert().code(2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_daemon_exits_3() {
    let fx = Fixture::start().await;
    let empty = tempfile::tempdir().unwrap();
    fx.sm().arg("status").env("XDG_RUNTIME_DIR", empty.path()).assert().code(3).stderr(predicate::str::contains("systemctl --user start secret-manager"));
}

#[test]
fn completions_render() {
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.args(["completions", "bash"]).assert().success().stdout(predicate::str::contains("sm"));
    let mut cmd = assert_cmd::Command::cargo_bin("secret-manager").unwrap();
    cmd.args(["completions", "zsh"]).assert().success().stdout(predicate::str::contains("compdef"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager --test cli_vault`
Expected: exit code 2 (unknown subcommand) assertions fail.

- [ ] **Step 3: Implement the commands**

Append to `cli/vault_cmds.rs` (add `use super::read_password;` and `use control_protocol::{ProtocolError, Zeroizing};`):
```rust
/// One request over the control socket; protocol-level errors map to exit codes.
pub fn control(req: Request) -> Result<Response, CliError> {
    match call(&socket_path(), &req) {
        Ok(Response::Error(e)) => Err(CliError::Failed(e)),
        Ok(r) => Ok(r),
        Err(ProtocolError::Connect(e)) => Err(CliError::Unreachable(format!(
            "daemon not running ({e}); start it with `systemctl --user start secret-manager`"
        ))),
        Err(e) => Err(CliError::Failed(e.to_string())),
    }
}

pub fn lock(collection: Option<String>) -> Result<(), CliError> {
    control(Request::Lock { collection })?;
    println!("Locked.");
    Ok(())
}

pub fn unlock(collection: String) -> Result<(), CliError> {
    let password = read_password(&format!("Password for '{collection}'"))?;
    control(Request::Unlock { collection: collection.clone(), password: Zeroizing::new(password.to_string()) })?;
    println!("Unlocked '{collection}'.");
    Ok(())
}

pub fn status() -> Result<(), CliError> {
    match control(Request::Status)? {
        Response::Status { collections, uptime_secs } => {
            println!("daemon up {}s", uptime_secs);
            println!("{:<16} {:<24} {:<9} {}", "ID", "LABEL", "STATE", "ITEMS");
            for c in collections {
                println!("{:<16} {:<24} {:<9} {}", c.id, c.label, if c.locked { "locked" } else { "unlocked" }, c.items);
            }
            Ok(())
        }
        other => Err(CliError::Failed(format!("unexpected reply {other:?}"))),
    }
}

pub fn change_password(collection: String) -> Result<(), CliError> {
    let old = read_password("Current password")?;
    let new = read_new_password("New password")?;
    control(Request::ChangePassword {
        collection: collection.clone(),
        old: Zeroizing::new(old.to_string()),
        new: Zeroizing::new(new.to_string()),
    })?;
    println!("Password changed for '{collection}'.");
    Ok(())
}
```

Variants for `Command`:
```rust
    /// Lock one collection, or all of them
    Lock {
        #[arg(long)]
        collection: Option<String>,
    },
    /// Unlock a collection with its password
    Unlock {
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Show daemon and collection state
    Status,
    /// Change a collection's master password
    ChangePassword {
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Print shell completions
    Completions {
        shell: clap_complete::Shell,
    },
```
Dispatch arms:
```rust
        Command::Lock { collection } => vault_cmds::lock(collection),
        Command::Unlock { collection } => vault_cmds::unlock(collection),
        Command::Status => vault_cmds::status(),
        Command::ChangePassword { collection } => vault_cmds::change_password(collection),
        Command::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "sm", &mut std::io::stdout());
            Ok(())
        }
```

- [ ] **Step 4: Run tests until green, fmt, clippy, commit**

Run: `cargo test -p secret-manager --test cli_vault && cargo test --workspace && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 3 tests pass.

```bash
git add -A
git commit -m "Add lock, unlock, status, change-password and completions"
```

---

### Task 15: SSH subcommands and askpass

**Files:**
- Create: `crates/secret-manager/src/cli/ssh.rs`
- Modify: `crates/secret-manager/src/cli/mod.rs` (`pub mod ssh;`, `Ssh` variant, `argv_with_dispatch`), `crates/secret-manager/src/cli/secrets.rs` (make `find` `pub(crate)`), `crates/secret-manager/src/main.rs` (use `argv_with_dispatch`)
- Create: `crates/secret-manager/tests/cli_ssh.rs`

**Interfaces:**
- Consumes: `cli::client::Client`, `cli::secrets::find(&Client, &BTreeMap) -> Result<Vec<OwnedObjectPath>, CliError>`, `prompt::Pinentry`
- Produces:
  - `cli::ssh::{SSH_SCHEMA = "org.secret-manager.ssh", SshCommand::{Add{path, no_passphrase}, List, Remove{path}, Askpass{prompt: Vec<String>}}, add, list, remove, askpass, classify_prompt(&str, Option<&str>) -> AskpassKind, AskpassKind::{Passphrase(PathBuf), Confirm, Other}}`
  - `cli::argv_with_dispatch(impl IntoIterator<Item = OsString>) -> Vec<OsString>`
  - Item layout: attributes `xdg:schema=org.secret-manager.ssh`, `path=<canonical>`, `has_passphrase=true|false`; label `SSH key <path>`; keys without a passphrase store an empty secret

- [ ] **Step 1: Write the failing tests**

Unit tests appended to `cli/ssh.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_prompts() {
        assert_eq!(
            classify_prompt("Enter passphrase for key '/home/j/.ssh/id_ed25519': ", None),
            AskpassKind::Passphrase(PathBuf::from("/home/j/.ssh/id_ed25519"))
        );
        assert_eq!(classify_prompt("Enter passphrase for \"k\": ", None), AskpassKind::Passphrase(PathBuf::from("k")));
        assert_eq!(classify_prompt("Are you sure you want to continue connecting (yes/no/[fingerprint])?", None), AskpassKind::Confirm);
        assert_eq!(classify_prompt("anything", Some("confirm")), AskpassKind::Confirm);
        assert_eq!(classify_prompt("Enter PIN for authenticator:", None), AskpassKind::Other);
    }
}
```

Unit test appended to `cli/mod.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn askpass_symlink_dispatches_to_ssh_askpass() {
        let args = argv_with_dispatch(["/usr/bin/sm-askpass", "Enter passphrase for key '/k': "].map(OsString::from));
        assert_eq!(args, ["secret-manager", "ssh", "askpass", "Enter passphrase for key '/k': "].map(OsString::from));
        let args = argv_with_dispatch(["/usr/bin/sm", "status"].map(OsString::from));
        assert_eq!(args, ["/usr/bin/sm", "status"].map(OsString::from));
    }
}
```

`crates/secret-manager/tests/cli_ssh.rs`:
```rust
mod common;

use common::Fixture;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

fn make_key(dir: &Path, name: &str, passphrase: &str) -> PathBuf {
    let path = dir.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "test", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_list_askpass_remove() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_test", "pass123");
    let plain = make_key(keys.path(), "id_plain", "");

    fx.sm().args(["ssh", "add"]).arg(&key).write_stdin("pass123\n").assert().success();
    fx.sm().args(["ssh", "add", "--no-passphrase"]).arg(&plain).assert().success();
    fx.sm()
        .args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("{}\tpassphrase: stored", key.display())))
        .stdout(predicate::str::contains(format!("{}\tpassphrase: none", plain.display())));

    let ssh_prompt = format!("Enter passphrase for key '{}': ", key.display());
    fx.sm().args(["ssh", "askpass", &ssh_prompt]).assert().success().stdout("pass123\n");
    let keygen_prompt = format!("Enter passphrase for \"{}\": ", key.display());
    fx.sm().args(["ssh", "askpass", &keygen_prompt]).assert().success().stdout("pass123\n");
    fx.sm()
        .current_dir(keys.path())
        .args(["ssh", "askpass", "Enter passphrase for \"id_test\": "])
        .assert()
        .success()
        .stdout("pass123\n");

    fx.sm().args(["ssh", "add", "--no-passphrase"]).arg(&key).assert().success();
    let out = fx.sm().args(["ssh", "list"]).assert().success().get_output().stdout.clone();
    assert_eq!(String::from_utf8_lossy(&out).matches("id_test").count(), 1, "re-adding replaces, never duplicates");

    fx.sm().args(["ssh", "remove"]).arg(&key).assert().success();
    fx.sm().args(["ssh", "remove"]).arg(&key).assert().code(1);
    fx.sm().args(["ssh", "list"]).assert().success().stdout(predicate::str::contains("id_test").not());
    fx.sm().args(["ssh", "add", "/nonexistent/key"]).assert().code(2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_keygen_uses_sm_askpass_symlink() {
    let fx = Fixture::start().await;
    fx.unlock_default().await;
    let keys = tempfile::tempdir().unwrap();
    let key = make_key(keys.path(), "id_e2e", "pass123");
    fx.sm().args(["ssh", "add"]).arg(&key).write_stdin("pass123\n").assert().success();

    let link = keys.path().join("sm-askpass");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_secret-manager"), &link).unwrap();
    let mut cmd = std::process::Command::new("ssh-keygen");
    cmd.args(["-y", "-f"])
        .arg(&key)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", fx.data_dir.path())
        .env("SSH_ASKPASS", &link)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(std::process::Stdio::null());
    for (k, v) in fx.envs() {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pubkey = std::fs::read_to_string(format!("{}.pub", key.display())).unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1), pubkey.split_whitespace().nth(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn askpass_falls_back_to_pinentry() {
    let fx = Fixture::start().await;
    fx.sm()
        .args(["ssh", "askpass", "Enter passphrase for key '/no/such/key': "])
        .env("FAKE_PIN", "typed")
        .assert()
        .success()
        .stdout("typed\n");
    fx.sm().args(["ssh", "askpass", "Enter PIN for authenticator:"]).env("FAKE_PIN", "typed").assert().success().stdout("typed\n");
    fx.sm()
        .args(["ssh", "askpass", "Are you sure you want to continue connecting (yes/no/[fingerprint])?"])
        .env("SSH_ASKPASS_PROMPT", "confirm")
        .env("FAKE_CONFIRM", "yes")
        .assert()
        .success()
        .stdout("yes\n");
    fx.sm().args(["ssh", "askpass", "continue? (yes/no)"]).env("FAKE_CONFIRM", "no").assert().success().stdout("no\n");
    fx.sm().args(["ssh", "askpass", "Enter passphrase for key '/no/such/key': "]).env_remove("FAKE_PIN").assert().code(1);
    fx.sm()
        .args(["ssh", "askpass", "Enter passphrase for key '/no/such/key': "])
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("FAKE_PIN", "offline")
        .assert()
        .success()
        .stdout("offline\n");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p secret-manager ssh`
Expected: compile errors (`cli::ssh` missing).

- [ ] **Step 3: Implement ssh.rs**

```rust
//! ssh add / list / remove / askpass.
//!
//! Keys are ordinary items: `xdg:schema=org.secret-manager.ssh`, `path=<canonical>`,
//! `has_passphrase=true|false`. Keys without a passphrase hold an empty secret so
//! `ssh list` can inventory them.

use super::client::Client;
use super::secrets::find;
use super::{CliError, load_config, read_password};
use crate::prompt::{PinOutcome, PinRequest, Pinentry};
use clap::Subcommand;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const SSH_SCHEMA: &str = "org.secret-manager.ssh";

#[derive(Subcommand, Debug)]
pub enum SshCommand {
    /// Register a key; prompts for its passphrase unless --no-passphrase
    Add {
        path: PathBuf,
        #[arg(long)]
        no_passphrase: bool,
    },
    /// List registered keys
    List,
    /// Forget a key
    Remove { path: PathBuf },
    /// SSH_ASKPASS entry point: answers ssh's passphrase prompt from the vault
    Askpass {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        prompt: Vec<String>,
    },
}

fn canonical(path: &Path) -> Result<PathBuf, CliError> {
    std::fs::canonicalize(path).map_err(|e| CliError::Usage(format!("{}: {e}", path.display())))
}

fn key_query(path: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("xdg:schema".to_string(), SSH_SCHEMA.to_string()),
        ("path".to_string(), path.to_string_lossy().into_owned()),
    ])
}

fn key_attrs(path: &Path, has_passphrase: bool) -> BTreeMap<String, String> {
    let mut attrs = key_query(path);
    attrs.insert("has_passphrase".to_string(), has_passphrase.to_string());
    attrs
}

pub async fn add(path: PathBuf, no_passphrase: bool) -> Result<(), CliError> {
    let path = canonical(&path)?;
    let secret: Zeroizing<Vec<u8>> = if no_passphrase {
        Zeroizing::new(Vec::new())
    } else {
        Zeroizing::new(read_password(&format!("Passphrase for {}", path.display()))?.as_bytes().to_vec())
    };
    let client = Client::connect().await?;
    for item in find(&client, &key_query(&path)).await? {
        client.delete_item(&item).await?;
    }
    client.store(&key_attrs(&path, !no_passphrase), &format!("SSH key {}", path.display()), &secret).await?;
    println!("Registered {}{}", path.display(), if no_passphrase { " (no passphrase)" } else { "" });
    Ok(())
}

pub async fn list() -> Result<(), CliError> {
    let client = Client::connect().await?;
    let query = BTreeMap::from([("xdg:schema".to_string(), SSH_SCHEMA.to_string())]);
    let mut out = std::io::stdout().lock();
    for item in find(&client, &query).await? {
        let info = client.item_info(&item).await?;
        let path = info.attributes.get("path").cloned().unwrap_or_default();
        let stored = info.attributes.get("has_passphrase").is_some_and(|v| v == "true");
        writeln!(out, "{path}\tpassphrase: {}", if stored { "stored" } else { "none" })?;
    }
    Ok(())
}

pub async fn remove(path: PathBuf) -> Result<(), CliError> {
    let path = canonical(&path).unwrap_or(path);
    let client = Client::connect().await?;
    let items = find(&client, &key_query(&path)).await?;
    if items.is_empty() {
        return Err(CliError::NotFound(format!("{} is not registered", path.display())));
    }
    for item in &items {
        client.delete_item(item).await?;
    }
    println!("Removed {}", path.display());
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum AskpassKind {
    Passphrase(PathBuf),
    Confirm,
    Other,
}

/// `ssh` asks `Enter passphrase for key '/p': `; `ssh-keygen` asks `Enter passphrase for "/p": `.
/// `SSH_ASKPASS_PROMPT=confirm` marks yes/no questions on OpenSSH >= 8.4.
pub fn classify_prompt(prompt: &str, askpass_prompt_env: Option<&str>) -> AskpassKind {
    if askpass_prompt_env == Some("confirm") {
        return AskpassKind::Confirm;
    }
    let re = regex::Regex::new(r#"(?i)passphrase for(?: key)? ["']([^"']+)["']"#).expect("static regex");
    if let Some(c) = re.captures(prompt) {
        return AskpassKind::Passphrase(PathBuf::from(&c[1]));
    }
    if prompt.contains("(yes/no") {
        return AskpassKind::Confirm;
    }
    AskpassKind::Other
}

pub async fn askpass(words: Vec<String>) -> Result<(), CliError> {
    let prompt = words.join(" ");
    let env = std::env::var("SSH_ASKPASS_PROMPT").ok();
    let kind = classify_prompt(&prompt, env.as_deref());
    if let AskpassKind::Passphrase(path) = &kind {
        if let Some(pass) = lookup_passphrase(path).await {
            println!("{}", pass.as_str());
            return Ok(());
        }
    }
    fallback(&prompt, kind == AskpassKind::Confirm).await
}

/// Vault lookup. Any failure (no daemon, dismissed prompt, unknown key, empty
/// secret) yields `None` so the caller falls back to an interactive prompt.
async fn lookup_passphrase(path: &Path) -> Option<Zeroizing<String>> {
    let path = canonical(path).unwrap_or_else(|_| path.to_path_buf());
    let client = Client::connect().await.ok()?;
    let items = find(&client, &key_query(&path)).await.ok()?;
    let item = items.first()?;
    let secret = client.get_secret(item).await.ok()?;
    if secret.is_empty() {
        return None;
    }
    String::from_utf8(secret.to_vec()).ok().map(Zeroizing::new)
}

async fn fallback(prompt: &str, confirm: bool) -> Result<(), CliError> {
    let config = load_config()?;
    let pinentry = Pinentry::new(&config.prompt.pinentry);
    let req = PinRequest {
        title: "ssh".into(),
        description: prompt.to_string(),
        prompt: if confirm { String::new() } else { "Passphrase:".into() },
        error: None,
        repeat: false,
    };
    if confirm {
        let yes = pinentry.confirm(&req).await.map_err(|e| CliError::Failed(e.to_string()))?;
        println!("{}", if yes { "yes" } else { "no" });
        return Ok(());
    }
    match pinentry.ask(&req).await.map_err(|e| CliError::Failed(e.to_string()))? {
        PinOutcome::Pin(pin) => {
            println!("{}", pin.as_str());
            Ok(())
        }
        PinOutcome::Cancelled => Err(CliError::NotFound("cancelled".into())),
    }
}
```

- [ ] **Step 4: Wire it up**

In `cli/secrets.rs` change `async fn find` to `pub(crate) async fn find`.

In `cli/mod.rs`: add `pub mod ssh;`, `use std::ffi::{OsStr, OsString}; use std::path::Path;`, the variant
```rust
    /// SSH key passphrases and the askpass helper
    Ssh {
        #[command(subcommand)]
        command: ssh::SshCommand,
    },
```
the dispatch arm
```rust
        Command::Ssh { command } => match command {
            ssh::SshCommand::Add { path, no_passphrase } => ssh::add(path, no_passphrase).await,
            ssh::SshCommand::List => ssh::list().await,
            ssh::SshCommand::Remove { path } => ssh::remove(path).await,
            ssh::SshCommand::Askpass { prompt } => ssh::askpass(prompt).await,
        },
```
and
```rust
/// Invoked as `sm-askpass <prompt>` (a symlink), behave as `secret-manager ssh askpass <prompt>`.
pub fn argv_with_dispatch(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let is_askpass = args.first().is_some_and(|a| Path::new(a).file_name() == Some(OsStr::new("sm-askpass")));
    if !is_askpass {
        return args;
    }
    let rest = args.split_off(1);
    let mut out = vec![OsString::from("secret-manager"), OsString::from("ssh"), OsString::from("askpass")];
    out.extend(rest);
    out
}
```

In `main.rs` replace `Cli::parse()` with `Cli::parse_from(secret_manager::cli::argv_with_dispatch(std::env::args_os()))`.

- [ ] **Step 5: Run tests until green, fmt, clippy, commit**

Run: `cargo test -p secret-manager ssh && cargo test --workspace && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 2 unit tests and 3 integration tests pass. `ssh-keygen` end-to-end proves the askpass path works with real OpenSSH.

```bash
git add -A
git commit -m "Add ssh add/list/remove and the sm-askpass helper"
```

---

### Task 16: PAM module

**Files:**
- Modify: `crates/pam_secret_manager/Cargo.toml` (dev-dependencies), `crates/pam_secret_manager/src/lib.rs`
- Create: `crates/pam_secret_manager/tests/pam_stack.rs`

**Interfaces:**
- Consumes: `control_protocol::{Request, Response, Zeroizing, call, socket_path_for_runtime_dir}`
- Produces: `libpam_secret_manager.so` exporting `pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`, `pam_sm_open_session`, `pam_sm_close_session`, `pam_sm_chauthtok`; options `collection=<id>`, `auto_start=no`, `socket=<path>`; `parse_options(&[String]) -> Options{collection, auto_start, socket}`

- [ ] **Step 1: Write the failing tests**

Unit tests in `lib.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options_with_defaults() {
        let o = parse_options(&[]);
        assert_eq!(o, Options { collection: "default".into(), auto_start: true, socket: None });
        let o = parse_options(&["collection=work".into(), "auto_start=no".into(), "socket=/tmp/s".into(), "bogus".into()]);
        assert_eq!(o, Options { collection: "work".into(), auto_start: false, socket: Some(PathBuf::from("/tmp/s")) });
    }

    #[test]
    fn resolves_uid_of_current_user() {
        let user = std::env::var("USER").expect("USER set");
        // SAFETY: getuid has no preconditions.
        assert_eq!(uid_of(&user), Some(unsafe { libc::getuid() }));
        assert_eq!(uid_of("definitely-not-a-user-9f2c"), None);
    }
}
```

`crates/pam_secret_manager/tests/pam_stack.rs`:
```rust
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
    first_existing(&["/usr/lib/libpam_wrapper.so", "/usr/lib64/libpam_wrapper.so", "/usr/lib/x86_64-linux-gnu/libpam_wrapper.so"])
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
    exe.parent().unwrap().parent().unwrap().join("libpam_secret_manager.so")
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
    assert!(module_path().exists(), "{} missing; run cargo build -p pam_secret_manager", module_path().display());
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
        stream.write_all(&encode_frame(&Response::Ok).unwrap()).unwrap();
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
        Request::Unlock { collection, password } => {
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
    let mut ctx = Context::new("secret-manager-test", Some(&user), Conversation::with_credentials(&user, "hunter2")).unwrap();
    ctx.authenticate(Flag::NONE).expect("authenticate");
    let _session = ctx.open_session(Flag::NONE).expect("open_session");
}
```

Add to `crates/pam_secret_manager/Cargo.toml`:
```toml
[dev-dependencies]
pam-client = "0.5"
tempfile = "3"
```

If the inner run passes but the fake socket never receives `Unlock`, check `journalctl -t pam_secret_manager` for "no authentication token available": that means `pam_matrix` did not export `PAM_AUTHTOK` on this distro; replace its line with `auth optional pam_unix.so` (which always sets it) and keep `pam_permit.so` as the required module.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pam_secret_manager`
Expected: compile errors for missing items.

- [ ] **Step 3: Implement lib.rs**

```rust
//! PAM module that unlocks the secret-manager vault at login.
//!
//! * `auth`: copy the password PAM already collected into module data. Never prompts.
//! * `session`: start the user's daemon if needed and send `Unlock`.
//! * `password`: forward old/new passwords so the vault follows `passwd`.
//!
//! Every failure is logged to syslog and returns `PAM_SUCCESS`; a broken vault
//! must never block login. Options: `collection=<id>` (default `default`),
//! `auto_start=no`, `socket=<path>` (tests only).

use control_protocol::{Request, Response, Zeroizing, call, socket_path_for_runtime_dir};
use pamsm::{Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule, pam_module};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DATA_KEY: &str = "secret_manager_password";
/// `PAM_PRELIM_CHECK` from <security/pam_modules.h>; pamsm does not expose it.
const PAM_PRELIM_CHECK: i32 = 0x4000;
const START_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Password(Zeroizing<String>);

impl PamData for Password {}

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub collection: String,
    pub auto_start: bool,
    pub socket: Option<PathBuf>,
}

pub fn parse_options(args: &[String]) -> Options {
    let mut opts = Options { collection: "default".into(), auto_start: true, socket: None };
    for arg in args {
        match arg.split_once('=') {
            Some(("collection", v)) => opts.collection = v.to_string(),
            Some(("auto_start", v)) => opts.auto_start = !matches!(v, "no" | "false" | "0"),
            Some(("socket", v)) => opts.socket = Some(PathBuf::from(v)),
            _ => log(&format!("ignoring unknown option '{arg}'")),
        }
    }
    opts
}

fn log(msg: &str) {
    if let Ok(text) = CString::new(format!("pam_secret_manager: {msg}")) {
        // SAFETY: "%s" is a valid format with exactly one C-string argument that outlives the call.
        unsafe { libc::syslog(libc::LOG_WARNING | libc::LOG_AUTHPRIV, c"%s".as_ptr(), text.as_ptr()) };
    }
}

fn uid_of(user: &str) -> Option<u32> {
    let name = CString::new(user).ok()?;
    // SAFETY: passwd is plain data; zeroed is a valid initial value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 16384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the duration of the call and `buf` outlives `pwd`'s use.
    let rc = unsafe {
        libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut result)
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(pwd.pw_uid)
}

fn user_name(pamh: &Pam) -> Option<String> {
    pamh.get_user(None).ok().flatten().map(|u| u.to_string_lossy().into_owned())
}

fn socket_for(pamh: &Pam, opts: &Options) -> Option<PathBuf> {
    if let Some(s) = &opts.socket {
        return Some(s.clone());
    }
    let uid = uid_of(&user_name(pamh)?)?;
    Some(socket_path_for_runtime_dir(Path::new(&format!("/run/user/{uid}"))))
}

fn start_daemon(user: &str) {
    let result = std::process::Command::new("systemctl")
        .args(["--user", &format!("--machine={user}@.host"), "start", "secret-manager.service"])
        .status();
    match result {
        Ok(s) if s.success() => {}
        Ok(s) => log(&format!("systemctl exited with {s}")),
        Err(e) => log(&format!("cannot run systemctl: {e}")),
    }
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    path.exists()
}

fn send(sock: &Path, req: Request, what: &str) {
    match call(sock, &req) {
        Ok(Response::Ok) => {}
        Ok(Response::Error(e)) => log(&format!("{what} failed: {e}")),
        Ok(_) => {}
        Err(e) => log(&format!("{what}: {e}")),
    }
}

struct PamSecretManager;

impl PamServiceModule for PamSecretManager {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        match pamh.get_cached_authtok() {
            Ok(Some(tok)) => {
                let password = Password(Zeroizing::new(tok.to_string_lossy().into_owned()));
                // SAFETY: DATA_KEY is only ever paired with `Password` in send_data/retrieve_data.
                if let Err(e) = unsafe { pamh.send_data(DATA_KEY, password) } {
                    log(&format!("cannot stash password: {e}"));
                }
            }
            Ok(None) => log("no authentication token available; nothing to unlock later"),
            Err(e) => log(&format!("cannot read authentication token: {e}")),
        }
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let opts = parse_options(&args);
        // SAFETY: same type as stored under DATA_KEY in `authenticate`.
        let Ok(Password(password)) = (unsafe { pamh.retrieve_data::<Password>(DATA_KEY) }) else {
            return PamError::SUCCESS;
        };
        let Some(sock) = socket_for(&pamh, &opts) else {
            log("cannot determine the control socket path");
            return PamError::SUCCESS;
        };
        if !sock.exists() && opts.auto_start {
            if let Some(user) = user_name(&pamh) {
                start_daemon(&user);
            }
            if !wait_for(&sock, START_TIMEOUT) {
                log("daemon did not start in time; vault stays locked");
                return PamError::SUCCESS;
            }
        }
        send(&sock, Request::Unlock { collection: opts.collection, password }, "unlock");
        PamError::SUCCESS
    }

    fn chauthtok(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        if flags.bits() & PAM_PRELIM_CHECK != 0 {
            return PamError::SUCCESS;
        }
        let opts = parse_options(&args);
        let (Ok(Some(old)), Ok(Some(new))) = (pamh.get_cached_oldauthtok(), pamh.get_cached_authtok()) else {
            return PamError::SUCCESS;
        };
        let Some(sock) = socket_for(&pamh, &opts) else {
            return PamError::SUCCESS;
        };
        let req = Request::ChangePassword {
            collection: opts.collection,
            old: Zeroizing::new(old.to_string_lossy().into_owned()),
            new: Zeroizing::new(new.to_string_lossy().into_owned()),
        };
        send(&sock, req, "password change");
        PamError::SUCCESS
    }

    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn close_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn acct_mgmt(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(PamSecretManager);
```

- [ ] **Step 4: Run tests, fmt, clippy, commit**

Run: `cargo build -p pam_secret_manager && cargo test -p pam_secret_manager && cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
Expected: 2 unit tests pass; `pam_stack_unlocks_vault` prints "skipping" on this machine (no pam_wrapper) and passes. Also confirm the symbols: `nm -D target/debug/libpam_secret_manager.so | grep pam_sm_` lists all six hooks.

```bash
git add -A
git commit -m "Add PAM module that unlocks the vault at login"
```

---

### Task 17: Packaging and documentation

**Files:**
- Create: `dist/secret-manager.service`, `dist/org.freedesktop.secrets.service`, `dist/environment.d/50-secret-manager.conf`, `dist/pam.d/secret-manager`, `Makefile`, `docs/install-arch.md`, `docs/install-debian.md`, `README.md`
- Create: `crates/secret-manager/tests/packaging.rs`

**Interfaces:**
- Produces: `make build`, `make install [DESTDIR=… PREFIX=/usr PAMDIR=…]`, installed paths: `$PREFIX/bin/{secret-manager,sm,sm-askpass}`, `$PAMDIR/pam_secret_manager.so`, `$PREFIX/lib/systemd/user/secret-manager.service`, `$PREFIX/share/dbus-1/services/org.freedesktop.secrets.service`, `$PREFIX/lib/environment.d/50-secret-manager.conf`, shell completions for bash/zsh/fish

- [ ] **Step 1: Write the failing test**

`crates/secret-manager/tests/packaging.rs`:
```rust
//! Sanity checks on the shipped unit, activation, and Makefile install list.

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn unit_and_activation_files_agree() {
    let unit = std::fs::read_to_string(root().join("dist/secret-manager.service")).unwrap();
    assert!(unit.contains("Type=dbus"));
    assert!(unit.contains("BusName=org.freedesktop.secrets"));
    assert!(unit.contains("ExecStart=/usr/bin/secret-manager daemon --foreground"));
    assert!(unit.contains("Conflicts=gnome-keyring-daemon.service"));
    let activation = std::fs::read_to_string(root().join("dist/org.freedesktop.secrets.service")).unwrap();
    assert!(activation.contains("Name=org.freedesktop.secrets"));
    assert!(activation.contains("SystemdService=secret-manager.service"));
    let env = std::fs::read_to_string(root().join("dist/environment.d/50-secret-manager.conf")).unwrap();
    assert!(env.contains("SSH_ASKPASS=/usr/bin/sm-askpass"));
    assert!(env.contains("SSH_ASKPASS_REQUIRE=prefer"));
}

#[test]
fn make_install_dry_run_lists_every_artifact() {
    let out = std::process::Command::new("make")
        .args(["-n", "install", "DESTDIR=/tmp/sm-dry", "CARGO=true"])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "/tmp/sm-dry/usr/bin/secret-manager",
        "sm-askpass",
        "pam_secret_manager.so",
        "systemd/user/secret-manager.service",
        "dbus-1/services/org.freedesktop.secrets.service",
        "environment.d/50-secret-manager.conf",
        "bash-completion/completions/sm",
        "zsh/site-functions/_sm",
        "fish/vendor_completions.d/sm.fish",
    ] {
        assert!(text.contains(needle), "missing {needle} in:\n{text}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p secret-manager --test packaging`
Expected: file-not-found panics.

- [ ] **Step 3: Write the dist files and Makefile**

`dist/secret-manager.service`:
```ini
[Unit]
Description=secret-manager Secret Service daemon
Documentation=https://github.com/quinnjr/secret-manager
Conflicts=gnome-keyring-daemon.service
After=graphical-session-pre.target

[Service]
Type=dbus
BusName=org.freedesktop.secrets
ExecStart=/usr/bin/secret-manager daemon --foreground
Restart=on-failure
RestartSec=2
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
```

`dist/org.freedesktop.secrets.service`:
```ini
[D-BUS Service]
Name=org.freedesktop.secrets
Exec=/usr/bin/secret-manager daemon --foreground
SystemdService=secret-manager.service
```

`dist/environment.d/50-secret-manager.conf`:
```sh
SSH_ASKPASS=/usr/bin/sm-askpass
SSH_ASKPASS_REQUIRE=prefer
```

`dist/pam.d/secret-manager` (a snippet users paste into their stacks; see docs):
```
# Add to the PAM stacks of your login paths (login, sddm, gdm-password,
# lightdm, sshd). Place the session line after pam_systemd.so.
auth      optional  pam_secret_manager.so
session   optional  pam_secret_manager.so
password  optional  pam_secret_manager.so
```

`Makefile` (recipe lines start with a tab):
```make
PREFIX  ?= /usr
DESTDIR ?=
PAMDIR  ?= $(PREFIX)/lib/security
CARGO   ?= cargo
BIN      = target/release/secret-manager
PAMSO    = target/release/libpam_secret_manager.so
BINDIR   = $(DESTDIR)$(PREFIX)/bin

.PHONY: build install uninstall test

build:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace

install: build
	install -Dm755 $(BIN) $(BINDIR)/secret-manager
	ln -sf secret-manager $(BINDIR)/sm
	ln -sf secret-manager $(BINDIR)/sm-askpass
	install -Dm755 $(PAMSO) $(DESTDIR)$(PAMDIR)/pam_secret_manager.so
	install -Dm644 dist/secret-manager.service $(DESTDIR)$(PREFIX)/lib/systemd/user/secret-manager.service
	install -Dm644 dist/org.freedesktop.secrets.service $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.secrets.service
	install -Dm644 dist/environment.d/50-secret-manager.conf $(DESTDIR)$(PREFIX)/lib/environment.d/50-secret-manager.conf
	install -Dm644 dist/pam.d/secret-manager $(DESTDIR)$(PREFIX)/share/doc/secret-manager/pam.d-snippet
	install -Dm644 docs/install-arch.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-arch.md
	install -Dm644 docs/install-debian.md $(DESTDIR)$(PREFIX)/share/doc/secret-manager/install-debian.md
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions $(DESTDIR)$(PREFIX)/share/zsh/site-functions $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	$(BIN) completions bash > $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sm
	$(BIN) completions zsh  > $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sm
	$(BIN) completions fish > $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/sm.fish

uninstall:
	rm -f $(BINDIR)/secret-manager $(BINDIR)/sm $(BINDIR)/sm-askpass
	rm -f $(DESTDIR)$(PAMDIR)/pam_secret_manager.so
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/user/secret-manager.service
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.secrets.service
	rm -f $(DESTDIR)$(PREFIX)/lib/environment.d/50-secret-manager.conf
	rm -rf $(DESTDIR)$(PREFIX)/share/doc/secret-manager
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/sm $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_sm $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/sm.fish
```

- [ ] **Step 4: Write the docs**

`docs/install-arch.md`:
````markdown
# Installing on Arch Linux

## Build and install

```sh
sudo pacman -S --needed rust pinentry dbus openssh pam
make
sudo make install
```

`sudo make install` puts the binary at `/usr/bin/secret-manager` with the `sm`
and `sm-askpass` symlinks, the PAM module in `/usr/lib/security`, the systemd
user unit, the D-Bus activation file, an `environment.d` file for
`SSH_ASKPASS`, and shell completions.

## Replace gnome-keyring or kwallet as the Secret Service

Only one service may own `org.freedesktop.secrets` on the session bus.

```sh
systemctl --user disable --now gnome-keyring-daemon.service gnome-keyring-daemon.socket 2>/dev/null
systemctl --user mask gnome-keyring-daemon.service
```

If `gnome-keyring` is installed, its own activation file also claims the bus
name. Override it for your user so the bus starts secret-manager instead:

```sh
mkdir -p ~/.local/share/dbus-1/services
cp /usr/share/dbus-1/services/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/
```

KWallet does not claim `org.freedesktop.secrets` unless `kwallet-secrets`
(`ksecretd`) is enabled; disable that in System Settings › KDE Wallet.

## Create your vault and start the daemon

```sh
sm init                       # creates the "default" collection
systemctl --user enable --now secret-manager.service
sm status
```

## Unlock at login (PAM)

Add the three lines from `/usr/share/doc/secret-manager/pam.d-snippet` to the
stacks you log in through. The `session` line must come after `pam_systemd.so`
so `/run/user/<uid>` exists:

| Login path        | File                      |
|-------------------|---------------------------|
| console           | `/etc/pam.d/login`        |
| SDDM              | `/etc/pam.d/sddm`         |
| GDM               | `/etc/pam.d/gdm-password` |
| LightDM           | `/etc/pam.d/lightdm`      |
| ssh               | `/etc/pam.d/sshd`         |
| `passwd` sync     | `/etc/pam.d/passwd`       |

Example for `/etc/pam.d/sddm`:

```
auth      include   system-login
auth      optional  pam_secret_manager.so
account   include   system-login
password  include   system-login
password  optional  pam_secret_manager.so
session   include   system-login
session   optional  pam_secret_manager.so
```

Log out and back in, then `sm status` should show `default` unlocked.
Problems are logged to the journal: `journalctl -t pam_secret_manager`.

## SSH passphrases

```sh
sm ssh add ~/.ssh/id_ed25519          # prompts for the key's passphrase once
sm ssh add ~/.ssh/id_deploy --no-passphrase
sm ssh list
```

The installed `environment.d` file sets `SSH_ASKPASS=/usr/bin/sm-askpass` and
`SSH_ASKPASS_REQUIRE=prefer` for systemd user sessions. Shells started outside
a systemd session (for example a plain `startx`) need the same two variables
exported in your profile.

## Configuration

`~/.config/secret-manager/config.toml`, all keys optional:

```toml
[vault]
dir = "~/.local/share/secret-manager"
auto_lock_after = "0s"      # "15m" locks after 15 minutes of inactivity

[prompt]
pinentry = "pinentry"       # e.g. "/usr/bin/pinentry-qt"

[kdf]
m_cost_kib = 65536
t_cost = 3
p_cost = 1
```
````

`docs/install-debian.md`: same structure with these differences:
- build deps: `sudo apt install rustup pinentry-curses pinentry-gnome3 dbus openssh-client libpam0g-dev build-essential`
- install: `sudo make install PAMDIR=/usr/lib/x86_64-linux-gnu/security` (`dpkg-architecture -qDEB_HOST_MULTIARCH` gives the triplet on other architectures)
- PAM files: `common-auth`, `common-session`, `common-password` (append the lines after the `pam_systemd.so` line in `common-session`), and a note that Debian's `pam-auth-update` will not manage these lines.
- Disable gnome-keyring: `systemctl --user mask gnome-keyring-daemon.service` plus the same user-local activation file override, and `sudo apt purge gnome-keyring` as the simplest alternative.

`README.md`:
````markdown
# secret-manager

A freedesktop Secret Service daemon written in Rust, with a `secret-tool`
compatible CLI, SSH passphrase storage, and a PAM module that unlocks your
vault when you log in. It replaces gnome-keyring or kwallet as the
`org.freedesktop.secrets` provider, so Chrome, git-credential-libsecret,
NetworkManager, and everything using libsecret keep working.

* Vaults are one file per collection, Argon2id + XChaCha20-Poly1305, with a
  hashed attribute index so lookups work while locked and only prompt when a
  secret is actually needed.
* Both Secret Service transport algorithms are implemented (`plain` and
  `dh-ietf1024-sha256-aes128-cbc-pkcs7`).
* Prompts go through `pinentry`, so it works on any desktop and on a TTY.

## Quick start

```sh
make && sudo make install
sm init
systemctl --user enable --now secret-manager.service
sm set app=example user=me --label "example token"   # secret from stdin
sm get app=example
sm ssh add ~/.ssh/id_ed25519
```

See `docs/install-arch.md` and `docs/install-debian.md` for replacing
gnome-keyring, PAM setup, and SSH askpass wiring.

## Commands

| Command | Purpose |
|---------|---------|
| `sm init [--collection L]` | create a vault |
| `sm daemon` | run the service (normally via systemd) |
| `sm get ATTR=VALUE... [--label L]` | print a secret, no trailing newline |
| `sm set ATTR=VALUE... --label L` | store a secret from stdin |
| `sm delete ATTR=VALUE...` | delete matching items |
| `sm list [ATTR=VALUE...] [--json]` | list labels and attributes |
| `sm lock / unlock / status / change-password` | manage the vault |
| `sm ssh add/list/remove/askpass` | SSH passphrases and the askpass helper |
| `sm completions <shell>` | shell completions |

Exit codes: 0 ok, 1 not found or prompt dismissed, 2 usage error, 3 daemon
unreachable.

## Development

```sh
cargo test --workspace
```

Integration tests start a private `dbus-daemon` and a scripted `pinentry`;
`secret-tool` and `ssh-keygen` are used when present. The PAM test needs
`pam_wrapper` and skips itself otherwise.
````

- [ ] **Step 5: Run the tests, then a real install into a staging directory**

Run: `cargo test -p secret-manager --test packaging && cargo build --release --workspace && make install DESTDIR=/tmp/claude-1000/-home-joseph-Projects-secret-manager/66852961-9f35-4bbd-9373-0f79273de7d5/scratchpad/stage && find /tmp/claude-1000/-home-joseph-Projects-secret-manager/66852961-9f35-4bbd-9373-0f79273de7d5/scratchpad/stage -type f -o -type l | sort`
Expected: both tests pass; the staged tree lists the binary, two symlinks, the `.so`, unit, activation file, environment file, docs, and three completion files. `systemd-analyze --user verify dist/secret-manager.service` reports nothing worse than the missing `/usr/bin/secret-manager` on an uninstalled machine.

- [ ] **Step 6: fmt, clippy, full test run, commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add -A
git commit -m "Add packaging, systemd and D-Bus activation files, and install docs"
```

---

## Self-review (done while writing; kept here for the executor)

- Spec coverage: vault format (Tasks 3–5), D-Bus surface (9–11), prompts (7, 11), control socket (2, 8, 12), PAM (16), CLI (12–15), SSH (15), configuration (1), packaging (17), error handling (per task), testing (per task). The `Reload` request and `socket=` PAM option are the only additions beyond the spec; `Reload` is in the spec's control socket section and `socket=` exists only for the pam_wrapper test.
- Cross-task names to keep identical: `Vault::insert_item(label, attributes, secret, content_type, replace) -> (String, bool)`; `ServiceState::{resolve_item, collection_id_of_path, is_unlocked_path, search_ids}`; `registry::{register_collection, unregister_collection(conn, id, item_ids), register_alias, register_item, register_all, notify_collection_changed}`; `Client::{search, unlock, perform_prompt, get_secret, item_info, store, delete_item, all_items}`; `secrets::find` (`pub(crate)`); `Fixture::{start, start_with_pin, start_with_idle, start_custom, unlock_default, lock_default, sm, envs, control_socket, pinentry_log, default_collection}`; `common::wait_for`.
- Every `ObjectServer::at`/`remove` call passes an owned `OwnedObjectPath` or a `&str`; never `&OwnedObjectPath`.
- Interface impl blocks contain only D-Bus methods, properties, and signals; helper methods live in separate `impl` blocks (`Collection::id`, `Collection::unknown`, `Item::with_item`, `Item::update`).
- An object never removes itself from the `ObjectServer` inside its own method; those removals are spawned (`Session::close`, `Item::delete`, `Collection::delete`, `Prompt` completion).
