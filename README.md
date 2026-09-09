# secret-manager

A freedesktop Secret Service daemon written in Rust, with a `secret-tool`
compatible CLI, SSH passphrase storage, and a PAM module that unlocks your
vault when you log in. It replaces gnome-keyring or kwallet as the
`org.freedesktop.secrets` provider, so Chrome, git-credential-libsecret,
NetworkManager, and everything using libsecret keep working.

* Vaults are one file per collection, Argon2id + XChaCha20-Poly1305, with a
  hashed attribute index so lookups work while locked and only prompt when a
  secret is actually needed. The index is optional: see `locked_search` in
  `docs/install-common.md` for what it reveals.
* The PAM module never sends your login password anywhere: it derives the
  vault key itself and hands only that to the daemon.
* The daemon is non-dumpable (no `ptrace`, no core files) and can pin its
  memory out of swap (`lock_memory`).
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
gnome-keyring, PAM setup, and SSH askpass wiring, and `docs/install-common.md`
for the vault/SSH/configuration steps shared by both.

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
| `sm reload` | tell a running daemon to rescan the vault directory |
| `sm import --from gnome-keyring\|kwallet` | migrate an existing keyring or wallet |
| `sm ssh add/list/remove/askpass` | SSH passphrases and the askpass helper |
| `sm completions <shell>` | shell completions |

Exit codes: 0 ok · 1 not found, prompt dismissed, or any other failure (I/O,
vault, config) · 2 usage error · 3 daemon or bus unreachable, or
`XDG_RUNTIME_DIR` unset.

`sm delete` is strict: if an unlock prompt is dismissed it fails (exit 1) and
deletes nothing. `sm get` still prompts when a match is locked, but is lenient
about the answer: a dismissed prompt is tolerated when something already
matched, and is a failure (exit 1) when nothing did. `sm list` never unlocks
at all — it prints locked entries as `[locked]` and prompts for nothing.

`sm import` moves an existing gnome-keyring keyring or KWallet wallet into a
new collection of its own; it never writes to the source and never merges
into a collection that already exists. Start with
`sm import --from gnome-keyring --inventory`, which reads the source's
cleartext headers and prints what is there — no password, no daemon — and
then `--dry-run`, which performs the whole extraction and every check and
writes nothing. Both print the same three-way tally the real run does:
**fully portable** items, which carry an `xdg:schema` so the application that
wrote them finds them again unchanged; items whose **attributes are preserved
but whose discoverability is uncertain**, a meaningful attribute set with no
schema, where libsecret's matching is lenient on some lookup paths and not
others; and **preserved only** items — a native KWallet entry has no
attributes at all, so `sm list` and `sm get` will find it and no libsecret
client that did not write it ever will. No attribute is ever synthesised to
improve those numbers: an invented schema is a guess, and a wrong guess
produces an item that looks migrated and is unreachable. A real run verifies
what it wrote — the source's own header count, per-item fingerprints, a
length histogram, and a lookup probe through the daemon — before it reports
success, and `--report PATH` writes the per-item verdict as JSON, holding no
secret and no attribute value. `docs/superpowers/specs/2026-09-08-migration-assistant.md`
is the full account.

`SetAlias` will repoint an alias that already targets another collection:
any session-bus client can do this, which is inherent to the same-uid
Secret Service model (see "Known gaps").

## Development

```sh
cargo test                                          # daemon, CLI, PAM logic
cargo build --no-default-features --features pam    # the PAM cdylib
make fuzz                                           # 60s on each fuzz target
```

Everything is one crate. The binary and the PAM module are separated by
features rather than by crates: the default build has no `libpam` and no PAM
entry points, and the `pam` build has no tokio, zbus, or clap. `make build`
produces both.

Integration tests start a private `dbus-daemon` and a scripted `pinentry`;
`secret-tool` and `ssh-keygen` are used when present.

Anything that parses bytes we did not write is fuzzed. `tests/prop_*.rs` are
bounded property tests that run on stable in a normal `cargo test`; `fuzz/`
holds the matching cargo-fuzz targets, which need nightly and run for as long
as you give them. Both encode the same invariants — see `docs/fuzzing.md`.

The PAM login-unlock path (see "Unlock at login" in `docs/install-arch.md`
and `docs/install-debian.md`) has unit tests for everything it decides:
reading the vault header, the login KDF bounds, the exact key it derives and
sends, the stale-socket rule, and the runtime-directory checks. On top of
that, `tests/pam_stack.rs` drives the built cdylib through a real libpam
stack in a plain `cargo test` — no `pam_wrapper`, no root, nothing written to
`/etc/pam.d` — using `pam_start_confdir` to point libpam at a temporary
config directory. It covers a whole login transaction, a wrong password, the
user name the stack resolves, and `chauthtok` rotation, and skips with a
printed reason when libpam predates 1.4, when `pam_unix.so` is absent, or
when the cdylib has not been built by `make build` (or is older than the
sources it was compiled from).
What is left uncovered is the root-only half; see "Known gaps".

## Versioning

This is 0.x, so the CLI, the control protocol and the on-disk vault format
may all still change. What will not change quietly is your vault: a
`format::VERSION` bump is the one change that stops an existing vault
opening, and it lands only in a minor release (0.1.x to 0.2.0), never in a
patch. Upgrading within 0.1.x will never ask you to recreate a vault, so an
unattended patch upgrade is safe to take; a minor bump is the one to read
about first. See "Known gaps" for what recreating currently costs.

## Known gaps

* **PAM coverage stops at the uid boundary** — `tests/pam_stack.rs` drives
  the built cdylib through a real libpam stack, so the `pam_sm_*` entry
  points, the stash that carries the token from the auth stack to the session
  stack, and the unlock itself all execute under test. That suite runs as an
  ordinary user, and refuses to run as root, so the root-only half of the
  module is still exercised only by unit tests of its decision functions:
  connecting to the real `/run/user/<uid>` control socket, the
  `systemctl --machine=<user>@.host` auto-start, and `socket=` being ignored
  when the module is root. The error arms of `send_data`/`retrieve_data` are
  likewise unreached — libpam does not fail them in a healthy transaction.
  Test login-unlock on a spare session or user before trusting it in your
  main session.
* **The on-disk format is not stable yet** — a loss-of-access gap, not a
  disclosure one: a vault the build refuses to open is still sealed. A vault
  file records the version it was written at, and a build supports exactly
  one (`format::VERSION`, currently 3). The daemon, the CLI and the PAM
  module all refuse a file they do not understand rather than guessing at
  it: one older than the build is reported with "recreate it with
  `sm init`", a newer one by naming the version it found. There is no
  migration code behind that refusal. A vault whose version matches the
  build always opens — only a bump can strand a file, none has happened
  since v0.1.0, and versions 1 and 2 existed only pre-release, so no shipped
  vault has ever needed migrating. If a later release does bump it, the move
  can be scripted rather than retyped: `sm list --json` prints every item's
  full attribute set, and feeding each set back to `sm get` reads that
  item's secret, so the contents can be carried into a recreated vault.
  Items sharing identical attributes collapse to the newest, so check for
  those first. Beyond that, prefer credentials you can re-issue over ones
  that exist only here; anything unrepeatable deserves a copy somewhere with
  protection comparable to this vault — an encrypted backup or another
  password manager, not a plaintext file.
* **Swap** — `[vault] lock_memory = true` pins the daemon in RAM, but it
  only works when the session's `RLIMIT_MEMLOCK` hard limit allows it
  (most distributions cap user sessions at 8 MiB, which is too small).
  Until you raise that limit, run on hosts with encrypted swap or no swap
  (see "Swap and memory exposure" in `docs/install-common.md`).
* **Same-uid trust** — the daemon trusts every process running as the same
  user, which is what the Secret Service model requires: it is a session-bus
  service, and the session bus itself does not distinguish between callers
  of the same uid. The strongest boundary this project enforces is between
  different uids, not between processes sharing one. Like every Secret
  Service, any process running as you can read unlocked secrets over the
  bus, claim the bus name first, repoint an alias, or bind the control
  socket before the daemon. Both the PAM module and the CLI
  read the vault header straight from disk (salt and Argon2 parameters) and
  derive the vault key locally, sending only that key over the socket. A
  same-uid impostor that wins the socket race can receive that key — no
  worse than what it could already get by reading unlocked secrets over the
  bus — but never the login password, and never a hash it could compute
  under a salt or parameters of its own choosing.
* **Pinentry is a separate, dumpable process** — the daemon makes itself
  non-dumpable, but the `pinentry` child it spawns is an ordinary, dumpable
  process that briefly holds the typed password in its own memory. Set
  `kernel.yama.ptrace_scope=1` to limit `ptrace` to descendants on
  distributions (Debian included) that ship it at `0`.
