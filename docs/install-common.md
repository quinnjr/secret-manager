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

## Moving from gnome-keyring or KWallet

`sm import` writes a new collection and never merges into an existing
one. Run it while the old provider is still running — disabling it
first strands whatever it alone can still see. Three passes, in order:

```sh
sm import --from kwallet --inventory     # headers only; no password, no daemon
sm import --from kwallet --dry-run       # full extraction, writes nothing
sm import --from kwallet --set-default --report ~/migration-report.json
```

(`--from gnome-keyring` for the other source. `--inventory` names every
container the headers describe; `--collection` overrides the new
collection's label, which otherwise follows the source's own name.)

The dry run ends with a tally per item — fully portable, attributes
preserved, preserved only — plus refused; see "Commands" in `README.md`
for what each promises the application that wrote it. The count line is
the gate: it reconciles the file header against everything the walk
produced, and a real (non-dry) run additionally compares every
fingerprint against the file it just wrote.

### Entries the source daemon never lists

A source daemon can omit entries its own file holds — observed live
with kwalletd, which dropped whole folders from its listings. The
import diffs the file's cleartext index against what the walk produced
and names every missing entry it can (`67 in the header, 32 walked, 35
never listed by the daemon`), recovering names through the attribute
sidecar where one names them. Those entries are not migrated — no tool
speaking that daemon's API could reach them — so the run withholds the
decommission advice until none remain. Keep the old provider (and, for
KWallet, its sidecar file) until such entries are re-homed by hand;
their secrets stay readable through whichever API does serve them.

## Cutover order

1. Migrate first and read the report: tallies as expected, count line
   reconciled, fingerprints matched on the real run.
2. Disable the old provider per your distro's guide (units, autostart,
   activation override, PAM lines old out and ours in, with
   `collection=<id>` if the vault's id is not `default`).
3. If the running kernel differs from the installed one (`uname -r`
   against the packaged version), reboot rather than logging out: a
   display manager that cannot start its greeter leaves you with no
   graphical way back in.
4. Log in by typing your password (autologin has none to unlock with),
   then verify: `sm status` shows the collection unlocked,
   `busctl --user status org.freedesktop.secrets` names
   `secret-manager`, and the item count matches the report.
5. Every PAM file touched has a backup next to it; the D-Bus override
   and autostart shadows delete cleanly. Roll those back first if the
   new login misbehaves.

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
terminal — that is precisely when there would otherwise be no prompt at
all. To keep a use of a stored key from being silent in that case, the
askpass helper itself asks for confirmation through `pinentry`, naming the
key it is about to release the passphrase for. Set
`SM_ASKPASS_NO_CONFIRM=1` in the environment to skip that confirmation and
release the passphrase immediately, the way a bare askpass helper normally
would.

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

Derived keys and decrypted secrets are held only in process memory. Both
the daemon and the `sm` CLI make themselves non-dumpable at start (no core
files, and no `ptrace` or `/proc/<pid>/mem` access from other processes of
your uid, whatever the kernel's Yama setting), and every buffer that
carried a password or key is wiped when freed.

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

The daemon's and the CLI's own memory are non-dumpable, but the `pinentry` process it spawns
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
ceiling, and more tightly than it: the header's parameters are clamped to
19 MiB–64 MiB, 2–4 passes, and at most 2 lanes before PAM will run Argon2id
on them, so a tampered header cannot make a login hang or exhaust memory.
The login path is tighter than the daemon's own 256 MiB/64-pass/16-lane
ceiling because it runs as root, inside the login process itself, once per
session, with no concurrency cap — the daemon can afford a higher ceiling
because it serialises derivations (at most two at a time) and is bounded by
`MemoryMax` in the unit, neither of which applies to a login attempt. The
module also refuses to touch `$XDG_RUNTIME_DIR/secret-manager` unless it is
a real directory owned by you.

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

## `sm import`: timeouts and timestamps

`sm import` bounds every wait it cannot answer itself, so a dialog nobody
can see is an error rather than a hang. The bounds are constants
(`src/import/gnome.rs`, `src/import/kwallet.rs`) — none is currently
configurable by flag or config key:

| Route | Bound | Value | What it guards |
|---|---|---|---|
| gnome-keyring | `COMMAND_TIMEOUT` | 5 s | one `busctl`/`ps` helper |
| gnome-keyring | `CALL_TIMEOUT` | 20 s | one D-Bus call or property read |
| gnome-keyring | `STARTUP_TIMEOUT` | 20 s | private bus and `gnome-keyring-daemon` coming up |
| gnome-keyring | `PROMPT_TIMEOUT` | 10 s | an unlock prompt on the private bus, where no prompter runs |
| gnome-keyring | `SECRETS_FALLBACK_TIMEOUT` | 120 s | aggregate budget for the per-item `GetSecret` fallback |
| kwallet | `DEFAULT_OPEN_TIMEOUT` | 120 s | waiting for `walletAsyncOpened` |
| kwallet | `DEFAULT_CALL_TIMEOUT` | 60 s | every other kwalletd call, including reads that can raise the per-application access prompt |
| kwallet | `DEFAULT_CLOSE_TIMEOUT` | 10 s | the closing `close` call, whose answer is ignored |

The SSH-with-no-display hang is governed by `DEFAULT_OPEN_TIMEOUT` on the
KWallet route and `PROMPT_TIMEOUT` on the gnome-keyring route. KWallet's
unlock dialog is a Qt widget needing a display: over SSH with no display it
cannot appear, so the import requires the wallet to be already open and says
so plainly instead of waiting — and when a dialog *can* appear, the wait is
bounded at two minutes, long enough to find it and type a password.

Walk budgets refuse rather than truncate: at most 512 collections and
100,000 items per collection on the gnome-keyring route; at most 200,000
entries, a 16 MiB / 100,000-row sidecar, and 4,096 entries per serialised
map on the KWallet route.

A KWallet entry with no sidecar row — or a row with no usable
`$fdo_created`/`$fdo_modified` — lands at `created = modified = 0` (the
Unix epoch), never `now()`: stamping the import's own clock onto 66 items
would destroy the newest-wins ordering `sm get` uses to break
attribute-set collisions. Such items are reported as `epoch_stamped_items`.

## Troubleshooting

**`secret-manager.service` is `failed` or `start-limit-hit`**

Another process already owns `org.freedesktop.secrets` on the session bus
(KWallet's `ksecretd`, or `gnome-keyring-daemon`). Find out which, rather
than guessing — the two need different steps, and `ksecretd` can hold the
name on a machine where gnome-keyring is the one named in the activation
file:

```sh
busctl --user status org.freedesktop.secrets | grep -E 'Pid|Comm'
```

```sh
systemctl --user status secret-manager.service
systemctl --user reset-failed secret-manager.service
```

Confirm the competing service is disabled or masked (see "Replace
gnome-keyring or kwallet" in your distro's install guide) before starting
secret-manager again. Note that `ksecretd` keeps the name for the life of
the session, so after disabling KWallet you must log out and back in — no
amount of restarting `secret-manager.service` will take it.

**Unlock never happens: the vault is still locked after login**

Check what the module said, from that login attempt:

```sh
journalctl -b -g pam_secret_manager
```

`cannot open .../<id>.vault: No such file or directory` means the
`collection=` on the PAM lines does not name an existing vault id — the
module opens `<id>.vault` literally and does not resolve the daemon's
`default` alias. `control socket ... Connection reset by peer` means the
daemon refused the module: it runs as root at login and is allowed only
when the daemon sees root as root. A user-namespaced sandbox around the
daemon (mount sandboxing on a user unit implies one) maps every foreign
uid to the overflow uid, so root arrives unrecognisable — run the daemon
outside such sandboxing, or the login path can never authenticate to it.

**`secret-manager.service` fails with `218/CAPABILITIES` or sits at
`start-limit-hit`**

A unit drop-in conflicts with what a user unit may hold — notably any
`CapabilityBoundingSet` beyond the base unit's empty set. Inspect
`~/.config/systemd/user/secret-manager.service.d/`, remove or narrow
the override, then `systemctl --user daemon-reload` and
`systemctl --user reset-failed secret-manager.service` before starting
it again.

**Repeated `pinentry failed: Inappropriate ioctl for device` while locked**

Prompts need a session context the daemon does not always have (no TTY,
no display agent reachable). Unlock with `sm unlock` (terminal
password) or at login instead of answering per-item dialogs; the
failures are the locked state announcing itself, not a broken pinentry.

**The D-Bus activation override reverts after an upgrade**

Your per-user override at `~/.local/share/dbus-1/services/` is a copy of
`org.freedesktop.secrets.service`, not a symlink, so a package upgrade that
reinstalls the system copy does not update it. If activation falls back to
gnome-keyring or kwallet after upgrading, redo the `cp` step from your
distro's install guide.

## Known gaps

See "Known gaps" in the top-level README for what the PAM module's tests do
and do not reach, and the swap/mlock trade-off above.
