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
| `sm ssh add/list/remove/askpass` | SSH passphrases and the askpass helper |
| `sm completions <shell>` | shell completions |

Exit codes: 0 ok · 1 not found, prompt dismissed, or any other failure (I/O,
vault, config) · 2 usage error · 3 daemon or bus unreachable, or
`XDG_RUNTIME_DIR` unset.

`sm delete` is strict: if an unlock prompt is dismissed it fails (exit 1) and
deletes nothing. `sm get` and `sm list` stay lenient and return the best
already-unlocked match instead of prompting.

`SetAlias` will repoint an alias that already targets another collection:
any session-bus client can do this, which is inherent to the same-uid
Secret Service model (see "Known gaps").

## Development

```sh
cargo test                                          # daemon, CLI, PAM logic
cargo build --no-default-features --features pam    # the PAM cdylib
```

Everything is one crate. The binary and the PAM module are separated by
features rather than by crates: the default build has no `libpam` and no PAM
entry points, and the `pam` build has no tokio, zbus, or clap. `make build`
produces both.

Integration tests start a private `dbus-daemon` and a scripted `pinentry`;
`secret-tool` and `ssh-keygen` are used when present.

The PAM login-unlock path (see "Unlock at login" in `docs/install-arch.md`
and `docs/install-debian.md`) has unit tests for everything it decides:
reading the vault header, the login KDF bounds, the exact key it derives and
sends, the stale-socket rule, and the runtime-directory checks. What no test
covers is libpam itself calling the hooks; see "Known gaps".

## Known gaps

* **PAM end-to-end coverage** — the module's logic is unit-tested, but no
  automated test drives it through a real libpam stack, so the wiring
  between the `pam_sm_*` entry points and that logic has never executed
  here. Closing this needs a CI runner with `pam_wrapper` and `pam_matrix`
  installed and a harness that loads the built `pam_secret_manager.so`.
  Test login-unlock on a spare session or user before trusting it in your
  main session.
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
