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

The PAM login-unlock path (see "Unlock at login" in `docs/install-arch.md`
and `docs/install-debian.md`) is only exercised end to end by that test,
and only on machines that have `pam_wrapper` and `pam_matrix` installed. It
has not been run on the development machine. If you rely on it, test login
unlock on a spare session or user before trusting it in your main session.
