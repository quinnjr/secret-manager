# secret-manager design

Date: 2026-09-05
Status: approved for planning

## Goal

A Rust implementation of the freedesktop Secret Service. It owns
`org.freedesktop.secrets` on the session bus, stores secrets in encrypted
vault files, stores SSH key passphrases and serves them to `ssh` through
`SSH_ASKPASS`, unlocks at login through a PAM module, and exposes everything
to shell scripts through a `secret-tool` compatible CLI.

Targets: Linux, any desktop or none, packaged for Arch and Debian. No
desktop toolkit is linked. Prompts go through `pinentry`.

Out of scope for this release: an `ssh-agent` implementation, storing private
key material, a GUI manager, network sync.

## Workspace layout

```
Cargo.toml                 workspace
crates/control-protocol/   lib: control socket message types, framing, sync client (std only)
crates/secret-manager/     bin: daemon + CLI
  src/main.rs
  src/cli/                 clap definitions, one file per subcommand group
  src/vault/               format.rs, crypto.rs, store.rs
  src/dbus/                service.rs, collection.rs, item.rs, session.rs, prompt.rs, errors.rs
  src/session/             plain.rs, dh.rs (transport encryption for secrets)
  src/prompt/              pinentry.rs (Assuan client)
  src/control/             unix socket protocol shared by CLI and PAM
  src/config.rs
crates/pam_secret_manager/ cdylib: PAM module, depends only on control-protocol
dist/                      systemd user unit, D-Bus service file, pam.d snippets
docs/                      install guides for Arch and Debian
```

The `daemon` subcommand wires vault + dbus + control socket into one tokio
runtime. Every other subcommand is a client: D-Bus for secrets, the control
socket for vault management. The CLI therefore exercises the same code path
as Chrome, libsecret, or `git-credential-libsecret`.

## Vault format

Location: `$XDG_DATA_HOME/secret-manager/<collection-id>.vault`, one file per
collection. `<collection-id>` is the D-Bus object path leaf, derived from the
label (lowercase, `[a-z0-9_]`, deduplicated with a numeric suffix).

File layout: header, then one ciphertext blob.

Header, `postcard` encoded, plaintext:

| field         | type              | notes                                  |
|---------------|-------------------|----------------------------------------|
| magic         | `[u8; 8]`         | `SMVAULT\0`                            |
| version       | `u16`             | 1                                      |
| label         | `String`          | user visible collection name           |
| created       | `u64`             | unix seconds                           |
| modified      | `u64`             | unix seconds                           |
| kdf           | `KdfParams`       | Argon2id `m_cost`, `t_cost`, `p_cost`  |
| salt          | `[u8; 16]`        | random per password                    |
| nonce         | `[u8; 24]`        | random per write                       |
| index         | `Vec<IndexEntry>` | item ids + salted attribute hashes     |

`IndexEntry { id: String, attr_hashes: Vec<[u8; 32]> }` where each hash is
`SHA-256(salt || len(key) || key || value)` over one attribute pair, sorted.
The index lets `SearchItems` work on a locked collection: the daemon hashes
the query pairs with the same salt and returns items whose hash set contains
all of them. Item ids are the object path leaves, so a client can call
`Unlock` on the matches and be prompted. Labels, attribute plaintext, and
secrets stay inside the encrypted body, matching gnome-keyring's hashed
attribute scheme for locked keyrings. Anyone with the file can test guesses
against the hashes; that is the accepted trade-off, as in gnome-keyring.

Body: XChaCha20-Poly1305 over `postcard(Vec<Item>)`. The exact header bytes
are the associated data, so changing the label, KDF parameters, or salt
without the key fails authentication.

```rust
struct Item {
    id: String,                       // object path leaf, uuid v4
    label: String,
    attributes: BTreeMap<String, String>,
    secret: Zeroizing<Vec<u8>>,
    content_type: String,             // default "text/plain"
    created: u64,
    modified: u64,
}
```

Key derivation: Argon2id, defaults 64 MiB, 3 iterations, 1 lane, 32 byte
output. Parameters live in the header so they can be raised on the next
`change-password`. `change-password` re-encrypts with a fresh salt and nonce.

Writes: serialize to `<file>.tmp` in the same directory, `fsync`, `rename`
over the original. A crash never leaves a half-written vault.

Memory: the derived key and decrypted items are held in `Zeroizing` buffers
and dropped on `Lock`, on idle timeout, and on daemon shutdown.

`init` creates the `default` collection and points the `default` alias at
it, writing `aliases.toml` next to the vault files. If a daemon is running,
`init` sends `Reload` so the new collection appears on the bus immediately.
`CreateCollection` creates additional vaults with their own password.

Crates: `argon2 0.5`, `chacha20poly1305 0.10`, `zeroize`, `postcard`,
`serde`, `rand_core 0.6` (`OsRng`), `uuid` (simple form, since object path
segments forbid `-`). Newer RustCrypto majors exist; the 0.5/0.10/0.12
generation is pinned because its API is stable and well known.

## D-Bus surface

Bus name `org.freedesktop.secrets`, session bus. Root `/org/freedesktop/secrets`.
Implemented with `zbus` `#[interface]` macros. Object paths:

- `/org/freedesktop/secrets` — `org.freedesktop.Secret.Service`
- `/org/freedesktop/secrets/collection/<id>` — `Collection`
- `/org/freedesktop/secrets/collection/<id>/<item-id>` — `Item`
- `/org/freedesktop/secrets/aliases/default` — alias path forwarded to the
  default collection
- `/org/freedesktop/secrets/session/s<n>` — `Session`
- `/org/freedesktop/secrets/prompt/p<n>` — `Prompt`

Service: `OpenSession`, `CreateCollection`, `SearchItems`, `Unlock`, `Lock`,
`GetSecrets`, `ReadAlias`, `SetAlias`; property `Collections`; signals
`CollectionCreated`, `CollectionDeleted`, `CollectionChanged`.

Collection: `Delete`, `SearchItems`, `CreateItem`; properties `Items`,
`Label` (writable), `Locked`, `Created`, `Modified`; signals `ItemCreated`,
`ItemDeleted`, `ItemChanged`.

Item: `Delete`, `GetSecret`, `SetSecret`; properties `Locked`, `Attributes`
(writable), `Label` (writable), `Created`, `Modified`.

Session: `Close`. Prompt: `Prompt(window_id)`, `Dismiss`; signal
`Completed(dismissed: bool, result: Variant)`.

Session algorithms:

- `plain` — secret bytes pass unencrypted, `parameters` empty.
- `dh-ietf1024-sha256-aes128-cbc-pkcs7` — RFC 2409 second Oakley group
  (1024-bit MODP), client and server exchange public keys, shared secret
  through HKDF-SHA256 with empty salt and info to 16 bytes, AES-128-CBC with
  PKCS7 padding, `parameters` carries the 16 byte IV. Required, since
  libsecret and Chrome negotiate it by default.

State: one `Arc<Mutex<ServiceState>>` holding loaded collections, open
sessions keyed by object path with their owning bus name, and pending
prompts. Sessions and prompts owned by a client are dropped when that
client's name disappears (`NameOwnerChanged`).

Errors map to `org.freedesktop.Secret.Error.IsLocked`, `NoSession`,
`NoSuchObject`. Anything else is `org.freedesktop.DBus.Error.Failed` with a
message.

Attribute search is exact match on every supplied pair, across all
collections for `Service.SearchItems` and within one for
`Collection.SearchItems`. Results are split into `unlocked` and `locked`.

`SearchItems`, `Collections`, and `Items` work on locked collections through
the plaintext index in the vault header. On a locked item, `Label` returns
`""` and `Attributes` returns an empty dict; `GetSecret` returns `IsLocked`.
Once unlocked, everything is served from the decrypted body.

Crates: `zbus 5`, `tokio`, `aes 0.8`, `cbc 0.1`, `hkdf 0.12`, `sha2 0.10`,
`num-bigint 0.4`. The DH exponentiation is not constant time; the keys are
ephemeral per session, which matches libsecret's threat model.

## Prompts

`Prompt.Prompt()` spawns `pinentry` and drives it over Assuan on
stdin/stdout: `SETDESC`, `SETPROMPT`, `SETERROR` on retry, `GETPIN`.
Pinentry chooses GUI or curses itself from `DISPLAY`, `WAYLAND_DISPLAY`,
and `GPG_TTY`. `OPTION ttyname`/`ttytype` are forwarded when the daemon has
a TTY. The binary is `pinentry` on `PATH` unless overridden by
`prompt.pinentry` in the config or `PINENTRY` in the environment.

Three wrong passwords or a cancel emit `Completed(dismissed = true)`. A
correct password unlocks the collection and emits `Completed(false, [paths])`.
`Dismiss` kills the pinentry child.

When the CLI needs a password itself (`init`, `unlock`, `change-password`)
it reads from the TTY with `rpassword`, and only falls back to pinentry when
stdin is not a TTY.

## Control socket

`$XDG_RUNTIME_DIR/secret-manager/control.sock`, directory mode 0700, socket
mode 0600, created by the daemon. Peer UID is checked with `SO_PEERCRED` and
must equal the daemon's UID or be 0, because the PAM module runs as root
during display-manager and console logins.

Protocol: `u32` big-endian length prefix, then a `postcard` encoded message.

```rust
enum Request {
    Unlock { collection: String, password: Zeroizing<String> },
    Lock { collection: Option<String> },        // None = all
    ChangePassword { collection: String, old: Zeroizing<String>, new: Zeroizing<String> },
    Status,
    Reload,          // rescan the vault directory; used by `sm init`
}
enum Response {
    Ok,
    Status { collections: Vec<CollectionStatus>, uptime_secs: u64 },
    Error(String),
}
struct CollectionStatus { id: String, label: String, locked: bool, items: usize }
```

Used by the CLI for `lock`, `unlock`, `status`, `change-password`, `init`
(`Reload`), and by the PAM module. Never carries secrets other than the
master password. The types, framing, and a blocking std-only client live in
the `control-protocol` crate so the PAM module does not link tokio or zbus.

## PAM module

Crate `pam_secret_manager`, cdylib, using `pamsm` (feature `libpam`).

- `pam_sm_authenticate`: read the cached `PAM_AUTHTOK` without prompting,
  copy it into PAM data under `secret_manager_password` as a `Zeroizing`
  string. Return `PAM_SUCCESS`.
- `pam_sm_open_session`: resolve the socket as
  `/run/user/<uid>/secret-manager/control.sock` from the PAM user's uid. If
  absent, run `systemctl --user --machine=<user>@.host start
  secret-manager.service` and poll for the socket up to 5 s. Send
  `Unlock { collection: "default", password }`. Any failure is logged to
  syslog at `LOG_WARNING` and the hook still returns `PAM_SUCCESS`. Login is
  never blocked by the vault. The module must be listed after `pam_systemd`
  in the session stack.
- `pam_sm_chauthtok` (`PAM_UPDATE_AUTHTOK` phase): send `ChangePassword`
  with `PAM_OLDAUTHTOK` and `PAM_AUTHTOK`. Same failure policy.
- `pam_sm_setcred`, `pam_sm_close_session`: `PAM_SUCCESS`.

Option `collection=<name>` overrides `default`. Option `auto_start=no`
disables the `systemctl` call.

`dist/pam.d/` ships snippets and `docs/` lists the lines to add to `login`,
`sddm`, `gdm-password`, `lightdm`, `sshd` on Arch and Debian.

## CLI

Binary `secret-manager`, symlink `sm` installed alongside.

```
sm init [--collection default]          create a vault, prompt for password
sm daemon [--foreground]                run the D-Bus service
sm get   <attr>=<val>...  [--label L]   secret to stdout, no trailing newline, exit 1 if absent
sm set   <attr>=<val>...  --label L     secret from stdin
sm delete <attr>=<val>...
sm list  [<attr>=<val>...] [--json]     labels + attributes, never secrets
sm lock | unlock | status | change-password
sm ssh add <path> [--no-passphrase]     register a key; prompts for passphrase unless flag
sm ssh list
sm ssh remove <path>
sm ssh askpass <prompt-text>            SSH_ASKPASS entry point
sm completions <shell>
```

`get` and `set` follow `secret-tool lookup`/`store` argument shapes so
existing scripts and `git-credential-libsecret` work unchanged. `set` on an
existing exact attribute match replaces the secret (`CreateItem` with
`replace = true`). `get` with several matches prints the most recently
modified.

`daemon` without `--foreground` is the same as with it; the flag exists for
readability in unit files. The daemon exits with a clear message if another
process already owns the bus name.

Exit codes: 0 ok, 1 not found or dismissed, 2 usage error, 3 daemon
unreachable.

## SSH

SSH items are ordinary items in the default collection with attributes:

| attribute        | value                                  |
|------------------|----------------------------------------|
| `xdg:schema`     | `org.secret-manager.ssh`               |
| `path`           | absolute, canonicalised key path       |
| `has_passphrase` | `true` or `false`                      |

`ssh add` with `--no-passphrase` stores an empty secret. `ssh list` shows
path and whether a passphrase is stored. `ssh remove` deletes the item.

`ssh askpass <prompt>` extracts a quoted path from the prompt using the
pattern `'(.+)'` preceded by `passphrase for`, canonicalises it, searches by
`path`. On a hit it prints the passphrase and exits 0. If the prompt is not a
passphrase request (host key confirmation, PIN, other) or no item matches, it
runs pinentry with the original prompt text and prints whatever the user
enters, so `ssh` keeps working.

Installation: an `sm-askpass` symlink to the binary, which dispatches to
`ssh askpass` when invoked under that name. Users set
`SSH_ASKPASS=sm-askpass` and `SSH_ASKPASS_REQUIRE=prefer`. Docs show the
`environment.d` file for this.

## Configuration

`$XDG_CONFIG_HOME/secret-manager/config.toml`, all optional:

```toml
[vault]
dir = "~/.local/share/secret-manager"
auto_lock_after = "0s"      # 0 disables

[prompt]
pinentry = "pinentry"

[kdf]
m_cost_kib = 65536
t_cost = 3
p_cost = 1
```

## Packaging

`dist/secret-manager.service` (systemd user unit, `Type=dbus`,
`BusName=org.freedesktop.secrets`) and
`dist/org.freedesktop.secrets.service` (D-Bus activation) so the daemon
starts on first use. `Conflicts=gnome-keyring-daemon.service` documented.
`docs/install-arch.md` and `docs/install-debian.md` cover binary, symlinks,
units, PAM lines, and the askpass environment.

## Error handling

- Vault file unreadable or authentication failure on decrypt: collection is
  reported locked, `Unlock` prompts again, syslog gets the reason.
- Wrong password: prompt retries up to three times, then dismissed.
- Pinentry missing: `Prompt` completes dismissed with a logged error, CLI
  prints an install hint.
- Bus name already owned: daemon exits 3.
- Control socket unreachable from CLI: exit 3 with a hint to start the
  service.
- All I/O and crypto errors flow through one `Error` enum per module using
  `thiserror`; the binary uses `anyhow` at the top.

## Testing

- Vault: round-trip, tamper detection on header and body, KDF parameter
  upgrade on change-password, atomic write survives a simulated crash
  (temp file present, original intact).
- Session: DH shared-secret and AES vectors captured from libsecret; plain
  session pass-through.
- D-Bus: integration tests start a private `dbus-daemon` with a temp
  `XDG_DATA_HOME`, run the daemon in-process, then drive it with `zbus`
  proxies and, when present, the `secret-tool` binary. Cover open session
  both algorithms, create/search/get/set/delete, lock/unlock via prompt with
  a fake `pinentry` script, alias handling, client disconnect cleanup.
- CLI: `assert_cmd` tests against the same fixture daemon.
- Control socket: unlock, wrong password, peer UID rejection.
- PAM: `pamtester` in CI with a throwaway PAM service file pointing at the
  built `.so`, verifying auth + open_session unlocks a fixture vault.
- SSH askpass: prompt parsing table tests, end-to-end with a passphrase
  protected test key and `ssh-keygen -y` under `SSH_ASKPASS`.
