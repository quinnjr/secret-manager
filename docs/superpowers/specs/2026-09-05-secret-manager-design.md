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

## Crate layout

One crate produces both artifacts: the `secret-manager` binary and the
`cdylib` PAM loads. Cargo features, not separate crates, keep them apart.

```
Cargo.toml                 the only manifest
src/lib.rs                 module list, feature-gated
src/main.rs                binary entry point            [feature: daemon]
src/vault/                 format.rs, crypto.rs, store.rs        (always)
src/config.rs              config file and XDG paths             (always)
src/protocol.rs            control socket types, framing, sync client (always)
src/pam/mod.rs             PAM logic: header read, KDF bounds, send  (always)
src/pam/hooks.rs           the pam_sm_* entry points     [feature: pam]
src/cli/                   clap definitions              [feature: daemon]
src/dbus/                  service, collection, item, session, prompt, errors
src/session/               mod.rs, dh.rs (transport encryption for secrets)
src/prompt/                pinentry.rs (Assuan client)
src/control/               unix socket server
src/kdf.rs                 serialised, bounded key derivation
tests/                     integration tests
dist/                      systemd user unit, D-Bus service file, pam.d snippets
docs/                      install guides for Arch and Debian, plus install-common.md
```

`default = ["daemon"]` builds the binary; it links neither `pamsm` nor
`libpam`, and exports no PAM symbols. `--no-default-features --features pam`
builds the `cdylib`, which links `libpam` and nothing async: no tokio, no
zbus, no clap. `src/pam/mod.rs` compiles under both, so a plain `cargo test`
exercises the login logic without PAM installed. `make build` runs both.

The `daemon` subcommand wires vault + dbus + control socket into one tokio
runtime. Every other subcommand is a client: D-Bus for secrets, the control
socket for vault management. The CLI therefore exercises the same code path
as Chrome, libsecret, or `git-credential-libsecret`.

## Vault format

Location: `$XDG_DATA_HOME/secret-manager/<collection-id>.vault`, one file per
collection. `<collection-id>` is the D-Bus object path leaf, derived from the
label (lowercase, `[a-z0-9_]`, deduplicated with a numeric suffix).

File layout: `magic(8) | header_len u32 LE | header (postcard) | ciphertext`.
`magic` and `header_len` are fixed-width and outside the postcard encoding, so
the header can be framed without decoding it first; everything from `magic`
through the end of the header is the AEAD associated data. The `Header`
struct itself starts at `version` (it does not repeat the magic):

| field         | type              | notes                                  |
|---------------|-------------------|----------------------------------------|
| version       | `u16`             | 3                                      |
| label         | `String`          | user visible collection name           |
| created       | `u64`             | unix seconds                           |
| modified      | `u64`             | unix seconds                           |
| kdf           | `KdfParams`       | Argon2id `m_cost`, `t_cost`, `p_cost`  |
| salt          | `[u8; 16]`        | random per password                    |
| index_salt    | `[u8; 16]`        | random, independent of `salt`, for attribute hashing |
| nonce         | `[u8; 24]`        | random per write                       |
| index         | `Vec<IndexEntry>` | item ids, optionally + salted attribute hashes |

`IndexEntry { id: String, attr_hashes: Vec<[u8; 32]> }` where, when
`locked_search = true`, each hash is
`SHA-256(index_salt || len(key) || key || value)` over one attribute pair,
sorted. The index lets `SearchItems` work on a locked collection: the daemon
hashes the query pairs with the same `index_salt` and returns items whose
hash set contains all of them. Item ids are the object path leaves, so a
client can call `Unlock` on the matches and be prompted. With
`locked_search = false` the index is ids-only (`attr_hashes` empty) and
`SearchItems` matches nothing on a locked collection. Labels, attribute
plaintext, and secrets stay inside the encrypted body, matching
gnome-keyring's hashed attribute scheme for locked keyrings. Anyone with the
file can test guesses against the hashes when they are present; that is the
accepted trade-off, as in gnome-keyring. `index_salt` is deliberately
separate from the Argon2id `salt` so the two purposes (key derivation vs.
attribute hashing) never share randomness.

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

`Vault::unlock` verifies the supplied password even when the vault is
already unlocked (comparing it against the live key rather than skipping
the check), so a stale or wrong password sent to an already-unlocked
collection is rejected rather than silently accepted.

A `<id>.vault` file that fails to open (bad magic, truncated, undecodable
header) is not skipped: it is reported as a permanently-locked collection
using its file stem as both id and label, and an `Unlock` attempt against
it returns the original format error instead of `WrongPassword`, so the
difference between "wrong password" and "not a valid vault file" is
visible to the caller.

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
`CollectionCreated`, `CollectionDeleted`, `CollectionChanged`. `SetAlias`
will repoint an alias that already points to a different, still existing
collection: any session-bus client can do this, which is inherent to the
same-uid Secret Service model (see "Amendment 2026-09-06: security audit
fixes").

Collection: `Delete`, `SearchItems`, `CreateItem`; properties `Items`,
`Label` (writable), `Locked`, `Created`, `Modified`; signals `ItemCreated`,
`ItemDeleted`, `ItemChanged`. `Delete` returns a prompt **on a collection it
can delete**: it asks for confirmation through pinentry (`Permanently delete
the keyring '<label>' and all <N> secrets?`) and the collection is unlinked
only once that prompt is run and confirmed; a cancel or refusal leaves the
collection untouched and completes the prompt with `Completed(true, "/")`.
`Item.Delete` stays immediate, no prompt.

A **locked** collection, and a broken one (which has no vault to count items
in, and is treated as locked), is refused with `IsLocked` before any prompt
is created. That is deliberate and pinned by test, not an oversight: the
dialog names the label and the item count, so it cannot be built without
reading the header, and prompting for a destructive confirmation the service
would then have to refuse anyway is worse than refusing first. A client that
wants to delete a locked collection calls `Unlock` and then `Delete`. The
"always returns a prompt" this paragraph used to open with was simply false
against the implementation.

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

Because `SearchItems` on a locked collection is served straight from the
in-memory index, the hashed-attribute oracle described under "Vault format"
is reachable by *any* session-bus client, not only someone with the vault
file: a caller can probe attribute guesses through the D-Bus API itself,
with no need for file access. This is an accepted trade-off, matching
gnome-keyring's behaviour for locked keyrings, and is called out again here
because the D-Bus surface is a lower bar to reach than the filesystem.

Crates: `zbus 5`, `tokio`, `aes 0.8`, `cbc 0.1`, `hkdf 0.12`, `sha2 0.10`,
`crypto-bigint 0.6`. The DH exponentiation is constant-time in the exponent
via `crypto-bigint`'s Montgomery `pow`, and the exponent is zeroized on drop;
the keys are ephemeral per session, which matches libsecret's threat model.

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

`Collection.Delete` prompts use `Pinentry::confirm` (a yes/no Assuan
`CONFIRM`, not `GETPIN`) instead: refusal or cancel emits
`Completed(true, "/")` with the collection left untouched, and confirmation
emits `Completed(false, <collection path>)` after the collection has
already been removed from state, unlinked from disk, and unregistered from
the bus. The delete only happens once the confirmation is claimed under the
same commit gate `Unlock`/`CreateCollection` use, so a `Dismiss` arriving
after the user confirms can no longer race the unlink.

When the CLI needs a password itself (`init`, `unlock`, `change-password`)
it reads from the TTY with `rpassword`, and only falls back to pinentry when
stdin is not a TTY.

## Control socket

`$XDG_RUNTIME_DIR/secret-manager/control.sock`, directory mode 0700, socket
mode 0600, created by the daemon. `XDG_RUNTIME_DIR` is required; there is no
`/tmp` fallback, since a world-writable fallback directory would let another
local user race the daemon for the socket path. Clients verify the peer's
uid with `SO_PEERCRED` on every connection and must see either the daemon's
own uid or 0 (root), because the PAM module runs as root during
display-manager and console logins.

Protocol: `u32` big-endian length prefix, then a frame body of
`[version u8 = 4][postcard encoded message]`. The version byte lets a future
protocol change be rejected cleanly instead of failing postcard decoding.

```rust
enum Request {
    Lock { collection: Option<String> },        // None = all
    Status,
    Reload,          // rescan the vault directory; `sm reload`, and `sm init`
    UnlockWithKey { collection: String, key: Zeroizing<[u8; 32]> },
    ChangeKey { collection: String, old_key: Zeroizing<[u8; 32]>, new_salt: [u8; 16], new_kdf: KdfParams, new_key: Zeroizing<[u8; 32]> },
}
enum Response {
    Ok,
    Status { collections: Vec<CollectionStatus>, uptime_secs: u64, aliases_error: Option<String> },
    Error(String),
}
struct CollectionStatus { id: String, label: String, locked: bool, items: usize, warning: Option<String> }
```

The password never crosses the socket: both the CLI (`sm unlock`, `sm
change-password`) and the PAM module read the vault header from disk (salt
and Argon2 parameters), derive the key locally, and send only the derived
key. There is no request that lets whatever answers the socket choose the
salt or the KDF parameters. Used by the CLI for `lock`, `unlock`, `status`,
`change-password`, `init` (`Reload`), and by the PAM module. The types,
framing, and a blocking std-only client live in `src/protocol.rs`, which is
compiled under every feature set so the PAM module does not link tokio or
zbus to speak it.

## PAM module

`src/pam/`, built as this crate's `cdylib` under the `pam` feature and
installed as `pam_secret_manager.so`, using `pamsm` (feature `libpam`). The
entry points live in `hooks.rs`, the only file that touches `pamsm`;
everything they call sits in `mod.rs` and is unit-tested without it.

- `pam_sm_authenticate`: read the cached `PAM_AUTHTOK` without prompting,
  copy it into PAM data under `secret_manager_password` as a `Zeroizing`
  string. Return `PAM_SUCCESS`.
- `pam_sm_open_session`: resolve the vault directory (`vault_dir=` option, or
  `<home>/.local/share/secret-manager` by default) and read
  `<collection>.vault`'s header from disk. If the header cannot be read, log
  and skip the unlock. Otherwise clamp its KDF parameters to the login-time
  bounds (19 MiB–64 MiB, 2–4 passes, ≤2 lanes), derive the vault key with
  Argon2id, and wipe the password. Resolve the socket as
  `/run/user/<uid>/secret-manager/control.sock` from the PAM user's uid (the
  `socket=` option is honoured only when *not* running as root, i.e. never
  during a real login — it exists solely for tests). If the socket is
  absent, run `systemctl --user --machine=<user>@.host start
  secret-manager.service` and poll for the socket up to 5 s. Send
  `UnlockWithKey { collection: "default", key }`. Any failure is logged to
  syslog at `LOG_WARNING` and the hook still returns `PAM_SUCCESS`. Login is
  never blocked by the vault. The module must be listed after `pam_systemd`
  in the session stack. Every hook is wrapped in `catch_unwind` so a panic
  cannot fail a login; hooks always return `PAM_SUCCESS`.
- `pam_sm_chauthtok` (`PAM_UPDATE_AUTHTOK` phase): read the header, derive
  both the old key (from the header's current salt/params) and a new key
  (fresh salt, current config's params) locally, and send
  `ChangeKey { collection, old_key, new_salt, new_kdf, new_key }`. Same failure
  policy.
- `pam_sm_setcred`, `pam_sm_close_session`: `PAM_SUCCESS`.

Option `collection=<name>` overrides `default`. Option `auto_start=no`
disables the `systemctl` call. Option `vault_dir=<path>` overrides the
directory the header is read from, for users who set `[vault] dir` in their
config (PAM cannot read the user's config file). Option `socket=<path>` is
test-only and ignored whenever the module runs as root.

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

Exit codes: 0 ok, 1 not found, prompt dismissed, or any other failure (I/O,
vault, config), 2 usage error, 3 daemon or bus unreachable, or
`XDG_RUNTIME_DIR` unset.

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
`ssh askpass` when invoked under that name. The shipped `environment.d` file
sets only `SSH_ASKPASS=sm-askpass`, so `ssh` still only calls it when it has
no controlling terminal — a terminal session keeps prompting interactively.
It deliberately does not set `SSH_ASKPASS_REQUIRE`; docs document
`prefer`/`force` as an explicit opt-in with a warning about what it removes
when combined with PAM auto-unlock and a long or disabled `auto_lock_after`.

## Configuration

`$XDG_CONFIG_HOME/secret-manager/config.toml`, all optional:

```toml
[vault]
dir = "~/.local/share/secret-manager"
auto_lock_after = "15m"     # default; "0s" disables
lock_memory = false
locked_search = true

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
units, PAM lines, and the askpass environment; `docs/install-common.md`
holds the vault/SSH/configuration/troubleshooting steps shared by both, so
they stay written once. The Makefile installs `docs/install-common.md`
alongside the two distro guides.

The three shipped files that hard-code `/usr/bin/` (the unit's `ExecStart`,
the D-Bus activation file's `Exec`, and the `environment.d` file's
`SSH_ASKPASS`) are rewritten at install time with `sed` into a temp file
before `install -Dm644`, substituting `$(PREFIX)/bin/` for `/usr/bin/`, so a
non-default `PREFIX` (e.g. packaging into `/opt`) does not leave the shipped
paths pointing at `/usr/bin`.

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
- **The three property setters cannot return a typed error, and do not.**
  `Collection::set_label`, `Item::set_label` and `Item::set_attributes` are
  zbus `#[zbus(property)]` setters, whose generated code calls
  `zbus::fdo::Error::from` on the returned error directly. Our `Error` uses
  its own `org.freedesktop.Secret.Error.*` wire names through a custom
  `DBusError` impl and has no `From<Error> for zbus::fdo::Error`, so a
  setter cannot return it. All three therefore report a locked vault as
  `org.freedesktop.DBus.Error.Failed`, with the name they *meant*
  (`org.freedesktop.Secret.Error.IsLocked`) written into the description
  text so it is legible rather than lost. Every other method returns the
  typed error. This is a deviation from the wire behaviour the rest of this
  document describes; it is documented at `dbus::errors` and pinned by a
  test, and it is recorded here because a caller reading only this document
  would otherwise match on an error name it will never receive.

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


## Amendment 2026-09-06: security audit fixes

* **Vault header v3.** Adds `index_salt` (random, independent of the Argon2
  salt) and validates `kdf` against ceilings (256 MiB, 64 passes, 16 lanes)
  before any derivation. `VERSION` is 3; there is no migration from any
  earlier version (pre-release, no v1 or v2 files were ever shipped) — the
  daemon logs "vault predates version 3; recreate it with `sm init`" and
  reports the collection as broken.
* **`locked_search`.** With `[vault] locked_search = false` the header index
  carries item ids only; searches on a locked collection match nothing. An
  unlocked collection is always searched through its plaintext items.
* **Control protocol v3.** The password-carrying `Unlock`/`ChangePassword`
  requests and the `KdfParams` request are removed entirely. The request set
  is now `Lock`, `Status`, `Reload`, `UnlockWithKey`, `ChangeKey`. Both the
  CLI and the PAM module read the vault header from disk and derive the key
  locally; nothing that answers the socket can choose the salt or KDF
  parameters any more. Argon2 runs without the daemon's state lock held on
  every path, key derivations are domain-separated with a context string
  (login-time derivation cannot be replayed as a vault-file derivation or
  vice versa), and the daemon serialises derivations to at most two
  concurrent, on the blocking pool.
* **Process hardening.** `PR_SET_DUMPABLE=0` at daemon start; optional
  `mlockall` (`[vault] lock_memory`), which now checks `RLIMIT_MEMLOCK` up
  front and refuses (logging) rather than locking less than the process
  needs; unit adds `RestrictAddressFamilies=AF_UNIX AF_NETLINK`,
  `UMask=0077`, `SystemCallArchitectures=native`, `MemoryMax=1G`.
  `PrivateNetwork`, `MemoryDenyWriteExecute` and `PrivateDevices` were tried
  and reverted: all three are inherited by the `pinentry` child and break
  X11 pinentry, software-GL/JIT rendering, or the host TTY path.
* **Sessions and prompts.** Secret reads and writes require the caller to own
  the session. Prompts are serialised through one pinentry at a time and are
  aborted (pinentry killed) when the owning client leaves the bus. Control
  connections are bounded (16 in flight, 5 s each).
* **Defaults.** `auto_lock_after` defaults to `15m`. KDF settings below
  19 MiB / 2 passes are accepted with a warning; login-time derivation is
  bounded more tightly, at 19 MiB–64 MiB / 2–4 passes / ≤2 lanes, because it
  runs as root inside the login process, once per session, with no
  concurrency cap.
* **Rotation.** `change-password` (and `ChangeKey`) leave a collection in the
  lock state it had on entry. Temp files use `O_EXCL` random names.
* **One crate.** The daemon, the CLI, and the PAM module are a single crate
  with feature-gated modules (`daemon`, `pam`); see "Crate layout". The PAM
  `cdylib` still links no async runtime. DH uses `crypto-bigint`
  (constant-time exponentiation, zeroized exponent).
* **`SetAlias`.** Any session-bus client can repoint an alias, including one
  that already targets a different, still-existing collection. This was
  previously refused as a deliberate deviation from silent overwrite, but
  the guard was removed: it was bypassable by clearing the alias first and
  it deviated from the spec for no security gain, since any same-uid client
  can already read every collection's contents. This is inherent to the
  same-uid Secret Service model — see "Known gaps" in the README.
* **Testing.** The `pam_wrapper` harness was dropped when the crates merged:
  it never ran (the package is not installed here) and it would have made
  every `cargo test` pull `bindgen` and `libclang` through `pam-client`. The
  module's logic is unit-tested instead; only libpam's own call into the
  hooks is now untested.


## Amendment 2026-09-07: control protocol v4, and PAM tested through libpam

* **`PROTOCOL_VERSION` is 4.** The frame body is
  `[version u8 = 4][postcard encoded message]`. The request set is unchanged
  from the v3 amendment above — `Lock`, `Status`, `Reload`, `UnlockWithKey`,
  `ChangeKey`, in that order, and still no password-carrying request. The
  bump is for two added response fields, below: postcard encodes struct
  fields positionally, so adding one is a wire break even though no variant
  moved. The "Control socket" section's code block is the current shape.
* **`Response::Status` carries `aliases_error: Option<String>`.** A corrupt
  `aliases.toml` no longer stops the daemon starting, so this is the only way
  an operator learns that alias lookups are refusing and the file is waiting
  to be repaired.
* **`CollectionStatus` carries `warning: Option<String>`.** A per-collection
  condition the operator should know about, such as an attribute index that
  could not be rewritten to match `locked_search`.
* **`Request::ChangeKey`'s field order.** It is
  `{ collection, old_key, new_salt, new_kdf, new_key }`, and the KDF field is
  named `new_kdf`. Earlier revisions of this document listed
  `{ ..., new_key, kdf }` — the last two transposed — in both this section
  and the PAM section. Because postcard encodes struct-variant fields
  positionally, a reader built from the old text would have parsed the new
  key as the KDF parameters. Both places are corrected; the code was always
  as written here.
* **Testing: the PAM module is driven through a real libpam stack.**
  `tests/pam_stack.rs` runs in a plain `cargo test` — no `pam_wrapper`, no
  root, and nothing written to `/etc/pam.d`. It uses `pam_start_confdir`
  (Linux-PAM ≥ 1.4) to point libpam at a temporary config directory whose
  service file loads the built cdylib by absolute path, and `dlopen`s libpam
  rather than linking it, so a machine without it skips instead of failing to
  build. It covers a full login transaction (auth stashes the token, session
  unlocks the collection, the stash is then cleared), a wrong password, the
  user name the stack hands the module, and `chauthtok` key rotation. It
  skips — with a printed reason — when libpam predates 1.4, when
  `target/pam/release/libsecret_manager.so` is missing or older than `src/`,
  or when `pam_unix.so` (which caches `PAM_AUTHTOK` for the module to read)
  is absent. The `pam_wrapper` note in the 2026-09-06 amendment is
  superseded. What remains untested is the root-only half: the real
  `/run/user/<uid>` socket, the `systemctl --machine` auto-start, `socket=`
  being ignored as root (the suite asserts it is *honoured* below root, and
  refuses to run as root at all), and the error arms of `send_data` /
  `retrieve_data`.
