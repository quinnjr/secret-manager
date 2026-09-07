# Common setup

These steps are the same on every distribution, once the package (binary,
PAM module, units, docs) is installed.

## Building

Always build as your normal user and only `sudo` the install step: `make
install` refuses to run if the build artifacts (binaries and shell
completions) aren't ready yet, telling you to run `make build` first.
Completions for bash, zsh, and fish are generated during `make build` (it
runs the freshly built binary as your own user); `make install` only copies
files with `install -Dm644`/`-Dm755` and never executes a binary it did not
build itself. Do not run `sudo make build` — that builds (and leaves Cargo's
cache) as root for no benefit.

## Create your vault and start the daemon

```sh
sm init                       # creates the "default" collection
systemctl --user enable --now secret-manager.service
sm status
```

## SSH passphrases

```sh
sm ssh add ~/.ssh/id_ed25519          # prompts for the key's passphrase once
sm ssh add ~/.ssh/id_deploy --no-passphrase
sm ssh list
```

The installed `environment.d` file sets `SSH_ASKPASS=/usr/bin/sm-askpass`
for systemd user sessions. Shells started outside a systemd session (for
example a plain `startx`) need the same variable exported in your profile.

By default `ssh` only invokes `SSH_ASKPASS` when it has no controlling
terminal, so a terminal session still prompts you directly and each use of a
stored key gets your explicit consent.

**`SSH_ASKPASS_REQUIRE=prefer` / `force` is an explicit, security-relevant
opt-in, not a default we ship.** Setting it makes `ssh` call the askpass
helper even from a terminal, so passphrase prompts are satisfied silently
from the vault. Combined with PAM auto-unlock at login and
`auto_lock_after = "0s"` (vault never auto-locks), this removes all
per-use consent for SSH keys: once logged in, anything that can invoke
`ssh` on your behalf can use every stored key without a prompt. If you want
the convenience anyway, also set a real `auto_lock_after` (see
Configuration below) so an idle session eventually re-locks the vault.

## Configuration

`~/.config/secret-manager/config.toml`, all keys optional. The file path
can be overridden with the `SECRET_MANAGER_CONFIG` environment variable.

```toml
[vault]
dir = "~/.local/share/secret-manager"
auto_lock_after = "15m"     # default; "0s" disables auto-lock (see the SSH warning above)
lock_memory = false         # mlockall the daemon; needs a raised RLIMIT_MEMLOCK
locked_search = true        # hash attributes into the vault header (see below)

[prompt]
pinentry = "pinentry"       # e.g. "/usr/bin/pinentry-qt"

[kdf]
m_cost_kib = 65536          # values below 19456 / t_cost 2 log a warning
t_cost = 3
p_cost = 1
```

The daemon refuses any parameter set above 256 MiB, 64 passes or 16 lanes,
whether it comes from this file or from a vault header, so a tampered vault
cannot request an unbounded allocation; derivations are additionally limited
to two at a time and the unit caps the service at `MemoryMax=1G`.

### What `locked_search` reveals

With `locked_search = true` (the default, and how gnome-keyring behaves)
each item's attributes are stored in the vault header as salted SHA-256
hashes so `SearchItems` can match them while the collection is locked.
Anyone holding the file (a backup, a stolen disk) can confirm guesses
against those hashes quickly, learning for example which services,
usernames and SSH key paths you have entries for. Secrets themselves stay
encrypted.

The index is not only a file-holder risk: it is also an online oracle over
D-Bus. Any client on your session bus can call `SearchItems` against a
locked collection and probe attribute guesses through the live daemon, with
no need for file access at all. This is the freedesktop Secret Service
specification's behaviour, and every implementation of it (gnome-keyring
included) shares the same trade-off for locked keyrings.

Set `locked_search = false` to store item ids only: this closes both the
file-holder oracle and the online D-Bus oracle, at the cost that searches
against a locked collection match nothing until it is unlocked. Existing
headers are rewritten without the hashes the next time each collection
unlocks.

## Swap and memory exposure

Derived keys and decrypted secrets are held only in process memory. The
daemon makes itself non-dumpable at start (no core files, and no `ptrace`
or `/proc/<pid>/mem` access from other processes of your uid, whatever the
kernel's Yama setting), and every buffer that carried a password or key is
wiped when freed.

The kernel can still page that memory to swap. `[vault] lock_memory = true`
calls `mlockall` so it cannot, but a user service may only lock as much as
the session's hard `RLIMIT_MEMLOCK` allows, and distributions usually set
that to 8 MiB (too small: each unlock maps `m_cost_kib`). The daemon now
checks `RLIMIT_MEMLOCK` up front and refuses to enable the lock (logging why)
rather than calling `mlockall` and leaving the process to believe it is
protected when the kernel would reject or truncate the lock. Raise the limit
in `/etc/security/limits.d/` (`@users - memlock 524288`) and uncomment
`LimitMEMLOCK=512M` in the unit to make the check pass. Otherwise use
encrypted swap, or no swap at all, if an attacker with access to the swap
device is in your threat model.

The daemon's own memory is non-dumpable, but the `pinentry` process it spawns
to collect a password is a separate, ordinary, dumpable process that briefly
holds the typed password in its own address space. `kernel.yama.ptrace_scope`
governs whether another same-uid process can `ptrace` it; distributions that
ship `0` (unrestricted) leave that window open, so set
`kernel.yama.ptrace_scope=1` (limits `ptrace` to a process's descendants) if
that matters to your threat model.

## What the PAM module sends

Nothing that answers the control socket can choose the salt or the Argon2
parameters any more. At login the module reads the collection's vault header
straight off disk (`<home>/.local/share/secret-manager/<collection>.vault`
by default, or the directory named by `vault_dir=` below), derives the
vault key itself in its own (root) process using the salt and parameters
recorded in that header, wipes the password, and sends only the derived key
to the daemon — the socket never carries a password or a `KdfParams`-style
request that could hand an impostor the choice of salt or cost. If the
header cannot be read (missing file, bad permissions, corrupt header), PAM
logs the reason and skips the unlock; it never falls back to parameters
supplied over the socket.

The control socket lives in your runtime directory, so any process already
running as you could still bind it before the daemon; what such an impostor
receives is only the vault key derived from the on-disk header — the same
thing it could already get by reading your unlocked secrets over the bus —
never your reusable login password, and never a hash computed under
parameters or a salt of its own choosing.

Login-time key derivation is bounded independently of the vault-wide
ceiling: the header's parameters are clamped to 19 MiB–256 MiB, 2–8 passes,
and at most 4 lanes before PAM will run Argon2id on them, so a tampered
header cannot make a login hang or exhaust memory. The module also refuses
to touch `$XDG_RUNTIME_DIR/secret-manager` unless it is a real directory
owned by you.

`passwd` works the same way: the CLI reads the header, derives the old and
new keys locally, and the vault is re-keyed (`ChangeKey`) without the daemon
ever seeing either password.

## PAM module options

Append options to the `pam_secret_manager.so` lines (space separated):

| option              | default                            | meaning                                                                    |
|---------------------|-------------------------------------|-----------------------------------------------------------------------------|
| `collection=<id>`   | `default`                           | vault collection to unlock                                                 |
| `auto_start=no`     | (unset)                             | do not `systemctl --user start` the daemon if its control socket is down   |
| `vault_dir=<path>`  | `<home>/.local/share/secret-manager` | absolute directory to read `<collection>.vault` from; set this when the user's `[vault] dir` is customised, since PAM cannot read their config file |
| `socket=<path>`     | (unset)                             | test-only override for the control socket path; **ignored** whenever the module is running as root (i.e. every real login) |

## Troubleshooting

**`secret-manager.service` is `failed` or `start-limit-hit`**

Another process already owns `org.freedesktop.secrets` on the session bus
(KWallet's `ksecretd`, or `gnome-keyring-daemon`).

```sh
systemctl --user status secret-manager.service
systemctl --user reset-failed secret-manager.service
```

Confirm the competing service is disabled or masked (see "Replace
gnome-keyring or kwallet" in your distro's install guide) before starting
secret-manager again.

**The D-Bus activation override reverts after an upgrade**

Your per-user override at `~/.local/share/dbus-1/services/` is a copy of
`org.freedesktop.secrets.service`, not a symlink, so a package upgrade that
reinstalls the system copy does not update it. If activation falls back to
gnome-keyring or kwallet after upgrading, redo the `cp` step from your
distro's install guide.

## Known gaps

See "Known gaps" in the top-level README for the current state of PAM CI
coverage and the swap/mlock trade-off above.
