# Security audit — secret-manager (branch `design-spec`, 2026-09-06)

Scope: every crate on the branch including the uncommitted review-fix wave
(HEAD `c45c4bb` + 41 modified files): vault crypto and format, session
transport, D-Bus interfaces, control socket protocol and server, PAM module,
pinentry client, CLI, systemd unit, Makefile and docs. Dependency scan with
`cargo audit` (clean; one unmaintained transitive crate, `atomic-polyfill`
via `postcard`/`heapless`). Method: full manual read at Fable depth, plus
source checks of `argon2 0.5.3` and `pamsm 0.5.5` where behaviour mattered.

## Threat model used

1. **Other local users** (different uid) and network attackers: must never
   reach secrets or the control socket. This is the primary boundary.
2. **Root-context correctness**: the PAM module runs as root inside someone
   else's login; it must not be steerable by the user it serves.
3. **Same-uid processes**: the Secret Service model treats these as trusted,
   but the *login password* is a higher-value asset than the vault, and
   process-memory exposure is worth reducing.
4. **File holders** (backups, stolen disk): must learn nothing beyond what the
   design accepts.

## Verdict

No finding lets another uid or the network read secrets. The primary
boundary holds: the vault is a sound Argon2id + XChaCha20-Poly1305 design
with the header bound as AAD, the control socket verifies `SO_PEERCRED` in
both directions and refuses a `/tmp` fallback, and the PAM module is
careful about `PATH`, environment, timeouts and failure policy.

The material findings are one design-level issue (H1) that leaks the
**login password** to any same-uid process that wins a socket race, one
robustness hole (M1) around untrusted KDF parameters, and process-memory
exposure (M2, M3). Everything else is hardening.

## Resolution (same day)

Every finding below was addressed on the branch after the audit; each fix
landed with a failing test first. Status per finding:

| Sev | ID | Title | Status |
|-----|----|-------|--------|
| High | H1 | PAM sends the login password to whoever binds the control socket first | Fixed: protocol v3; CLI and PAM derive from the on-disk vault header; only the key crosses the socket; login-time KDF bounded 19–256 MiB / 2–8 passes |
| Medium | M1 | KDF parameters are trusted from the cleartext header with no ceiling | Fixed: ceilings 256 MiB / 64 / 16 in `derive_key` and `VaultFile::decode`; derivations serialised, at most 2 concurrent on the blocking pool |
| Medium | M2 | Daemon memory is dumpable/ptrace-able by same-uid processes on default Debian | Fixed: `prctl(PR_SET_DUMPABLE, 0)` at start; opt-in `lock_memory` calls `mlockall` after an up-front `RLIMIT_MEMLOCK` check, refusing (and logging) rather than locking less than needed |
| Medium | M3 | Password bytes survive unzeroized on the socket and pinentry paths | Fixed: `Zeroizing` frames on both sides, `Zeroizing` pinentry line/data/unescape buffers |
| Medium | M4 | Hashed attribute index is an offline dictionary oracle for file holders | Fixed: separate `index_salt`; `locked_search = false` stores ids only and rescrubs on unlock; documented |
| Low | L1 | `ChangePassword` leaves a previously locked vault unlocked | Fixed: lock state preserved by `change_key` |
| Low | L2 | Control connections have no read timeout or concurrency bound | Fixed: 5 s per connection, 16 in flight |
| Low | L3 | Prompt task and pinentry outlive a disconnected client | Fixed: abort handles in state, aborted on `NameOwnerChanged` |
| Low | L4 | Unlimited concurrent prompts | Fixed: one pinentry dialog at a time |
| Low | L5 | Root PAM follows user-controlled paths under `/run/user/<uid>` | Fixed: `runtime_subdir_is_safe` (real dir, owned by uid) before any use |
| Low | L6 | `write_atomic` opens a fixed `.vault.tmp` with create+truncate | Fixed: `O_EXCL` random-suffix temp, cleaned on failure |
| Low | L7 | `SecretStruct` derives `Debug` and can print plaintext | Fixed: redacting `Debug` |
| Low | L8 | Session ownership is not enforced on secret read/write calls | Fixed: `ServiceState::cipher(path, sender)` |
| Low | L9 | Unit could be tightened further | Fixed: `RestrictAddressFamilies`, `PrivateNetwork`, `UMask`, `SystemCallArchitectures` |
| Low | L10 | Config allows a trivially weak KDF | Fixed: warning below the OWASP floor (refusal would break fast test fixtures) |
| Info | I1 | DH private exponent is not zeroized; `modpow` is not constant time | Fixed: `crypto-bigint` Montgomery `pow`, exponent zeroized on drop |
| Info | I2 | `auto_lock_after` defaults to never with PAM auto-unlock | Fixed: default `15m` |
| Info | I3 | Any same-uid process can own `org.freedesktop.secrets` first | Inherent to Secret Service; documented in README "Known gaps" |

## H1 — PAM sends the login password to whoever binds the control socket first

**Where**: `crates/pam_secret_manager/src/lib.rs:282-305` (`open_session`),
`:332-337` (`chauthtok`); `crates/control-protocol/src/lib.rs:252-262`
(`call_expecting_uid` checks uid only); `crates/secret-manager/src/control/server.rs:86-88`.

**What**: At login the module connects to
`/run/user/<uid>/secret-manager/control.sock`, verifies only that the peer
runs as `<uid>`, and sends `Unlock { password }` in the clear (the socket is
local, but the *peer* is the trust question). Any process already running as
that user can bind the path before the real daemon does: a lingering user
service (`loginctl enable-linger`), a user timer, or malware left from an
earlier session. `open_session` runs *before* `start_daemon`, and a stale
socket is deliberately removed and rebound, so the race is easy to win. The
same applies to `chauthtok`, which forwards both old and new passwords.

**Impact**: Disclosure of the user's *login* password, which unlocks `sudo`,
SSH password auth and other hosts, to a same-uid attacker who otherwise
could only read the vault once it was unlocked. The uid check does its job
against other users; it cannot distinguish the real daemon from an
impostor with the same uid. Checking `/proc/<pid>/exe` or the cgroup does
not help: the user can override the user unit, or run the real binary under
`LD_PRELOAD`.

**Parity note**: `pam_gnome_keyring` has the same exposure through its own
control socket, so this is a known trade-off, not a regression. It is still
the one place where this design can be strictly better.

**Fix (robust)**: Never send the password. Have PAM derive the vault key
itself and send that:

1. Protocol v2: add `UnlockWithKey { collection, key: Zeroizing<[u8;32]> }`
   and `ChangeKey { collection, old_key, new_salt, new_key, kdf }`.
2. PAM reads the vault header (`VaultFile::decode` is cheap; move it and
   `derive_key` into a small no-tokio crate, or into `control-protocol`),
   runs Argon2id with the header's salt/params, zeroizes the password, and
   sends the key. For `chauthtok` it generates the new salt and derives both
   keys.
3. Clamp the header's KDF params before deriving (see M1), because root
   would now be running Argon2 on a user-controlled header.

Cost: ~0.3 s of Argon2 in the login path, which the daemon was spending
anyway. An impostor then learns only the vault key, which it would obtain
from the unlocked daemon regardless.

**Fix (minimum)**: Document in `docs/install-common.md` and the PAM snippet
that the module trusts any same-uid listener, and recommend `auto_start=no`
plus a daemon started by systemd *before* login sessions is not possible;
so the documentation route is honest but weak.

---

## M1 — KDF parameters are trusted from the cleartext header with no ceiling

**Where**: `crates/secret-manager/src/vault/format.rs:33-42` (header),
`crates/secret-manager/src/vault/crypto.rs:75-93` (`derive_key`),
`crates/secret-manager/src/vault/store.rs:161`, `171`.

**What**: `KdfParams` is read from the unauthenticated header (AAD only
protects it *after* a successful decrypt) and passed straight to
`Params::new`. `argon2 0.5.3` accepts `m_cost` up to `u32::MAX` KiB (4 TiB)
and `t_cost` up to `u32::MAX`. A header with `m_cost_kib = 0xFFFF_FFFF`
makes the next unlock attempt allocate 4 TiB (Rust aborts the process on
allocation failure), and a huge `t_cost` spins the CPU for hours. Both
happen while the global `ServiceState` mutex is held
(`dbus/prompt.rs:313-316`, `daemon.rs:179-181`), so every D-Bus and control
call stalls, and the PAM `Unlock` times out.

**Who can trigger it**: anyone who can write the 0600 vault file: the user,
root, a restored backup, or a vault file someone hands you. Low likelihood,
but the failure is a hard crash of the secret service and it becomes a
root-context issue if H1's fix moves derivation into PAM.

**Fix**: In `Vault::open` (and again in `derive_key`) reject or clamp:
`m_cost_kib <= 1 << 20` (1 GiB), `t_cost <= 64`, `p_cost <= 16`, and
`m_cost_kib >= 8 * p_cost`. Surface a `FormatError::UnsafeKdf` so the
collection lands in `broken` with a clear message. Also run Argon2 outside
the state lock: derive the key first (`derive_key` needs only salt and
params), then take the lock to call `crypto::open`.

---

## M2 — Daemon memory is dumpable/ptrace-able by same-uid processes on default Debian

**Where**: `crates/secret-manager/src/daemon.rs:82` (no `prctl`),
`dist/secret-manager.service` (`LimitCORE=0` only).

**What**: While unlocked the daemon holds every secret and the derived key
in plain process memory. `LimitCORE=0` stops core files, but nothing stops
`ptrace`, `/proc/<pid>/mem`, or `process_vm_readv` from another process of
the same uid. On this machine `kernel.yama.ptrace_scope=1` limits that to
descendants, but Debian ships `ptrace_scope=0` by default, and the README
already documents the swap exposure.

**Fix**: One call at daemon start:
`libc::prctl(libc::PR_SET_DUMPABLE, 0)` makes the process non-dumpable,
which blocks non-root ptrace and `/proc/<pid>/{mem,maps,environ}` regardless
of Yama. Optionally `mlockall(MCL_CURRENT | MCL_FUTURE)` with
`LimitMEMLOCK=` raised in the unit (Argon2 needs 64 MiB, so set at least
256M); if that is too coarse, `mlock` just the `Key` and item buffers.

---

## M3 — Password bytes survive unzeroized on the socket and pinentry paths

**Where**:
- `crates/secret-manager/src/control/server.rs:90-105`: `read_frame` returns
  a plain `Vec<u8>` holding the postcard-encoded `Unlock`/`ChangePassword`
  request, including the password; `handle_connection` drops it unwiped.
- `crates/secret-manager/src/prompt/pinentry.rs:226-239`: the `line` buffer
  and `Reply::Data(String)` hold the (escaped) PIN; `:281` the `unescape`
  temporary holds the raw PIN. None are `Zeroizing`.

**What**: The project is otherwise disciplined about `Zeroizing` (frames,
`Request`, `PinOutcome`, `Item.secret`, `Key`), so these are gaps rather
than policy. Freed heap pages keep their contents until reused; combined
with M2 or swap they are recoverable.

**Fix**: `Zeroizing<Vec<u8>>` from `read_frame` (both server and
`read_frame_sync`); `Zeroizing<String>` for `line` and `Reply::Data`; have
`unescape` return `Zeroizing<String>` and build into a `Zeroizing<Vec<u8>>`.

---

## M4 — Hashed attribute index is an offline dictionary oracle for file holders

**Where**: `crates/secret-manager/src/vault/format.rs:82-108`
(`attribute_hash`, `build_index`), header field `index`.

**What**: To allow `SearchItems` while locked, every `(key, value)` pair is
stored in the *cleartext* header as `SHA-256(salt || len(key) || key ||
value)`. That is one hash per guess with no stretching, so anyone holding
the file can confirm guesses at GPU speed: `xdg:schema=org.secret-manager.ssh`,
`path=/home/joseph/.ssh/id_ed25519`, `server=github.com`, `user=<name>`,
and so on. The index also exposes item count and attributes-per-item. The
salt is the Argon2 salt, reused for a second purpose.

**Impact**: Metadata disclosure only (which services, accounts and SSH keys
exist); secrets stay protected. gnome-keyring makes the same trade
(hashed attributes in the keyring file), but neither the spec nor the docs
state it here.

**Fix**: State the leak in the spec and `docs/install-common.md`. Use a
separate random `index_salt` in the header. Offer `[vault] locked_search =
false` to omit the index entirely (search then requires unlock, as KWallet
behaves) for users whose threat model includes file theft.

---

## L1 — `ChangePassword` leaves a previously locked vault unlocked

**Where**: `crates/secret-manager/src/vault/store.rs:338-340`,
`crates/secret-manager/src/daemon.rs:233-235`.

`change_password` unlocks with `old` when the vault is locked and stays
unlocked on success (the daemon even emits the lock-state change as a
feature). Running `passwd` or `sm change-password` against a locked vault
therefore silently opens it. Re-lock when `was_locked` after a successful
rotation.

## L2 — Control connections have no read timeout or concurrency bound

**Where**: `crates/secret-manager/src/control/server.rs:45-65`, `104-113`.

A connection that never sends its frame holds a task forever; there is no
cap on concurrent connections. Only same-uid or root can connect, so this is
self-inflicted, but a 5 s `tokio::time::timeout` around `handle_connection`
and a `Semaphore` of, say, 16 would close it.

## L3 — Prompt task and pinentry outlive a disconnected client

**Where**: `crates/secret-manager/src/daemon.rs:334-350`,
`crates/secret-manager/src/dbus/prompt.rs:126-131`.

When the owning client leaves the bus, `watch_clients` removes the `Prompt`
object and its `prompt_owners` entry, but the spawned task (and its
pinentry dialog) keeps running. If the user answers the orphan dialog the
vault unlocks with nobody waiting. Keep the `JoinHandle` reachable from
state and abort it on owner disconnect (abort already kills pinentry via
`kill_on_drop`).

## L4 — Unlimited concurrent prompts

Every `Service.Unlock`/`CreateCollection`/`Collection.Delete` spawns its
own pinentry; nothing serializes them. gnome-keyring queues prompts. A
`tokio::sync::Mutex<()>` held across the pinentry exchange in
`unlock_collection_inner`, `create_collection` and `delete_collection`
prevents a dialog storm and makes dismissal semantics simpler.

## L5 — Root PAM follows user-controlled paths under `/run/user/<uid>`

**Where**: `crates/pam_secret_manager/src/lib.rs:294` (`remove_file`),
`:208-217` (`wait_for`), `:151` (path construction).

The uid check on the *connection* is the correct defence and is present.
`remove_file` as root, however, follows a user-planted directory symlink
(`secret-manager -> /somewhere`) and unlinks `/somewhere/control.sock`.
With `fs.protected_hardlinks=1` nothing more is reachable, so impact is
negligible; still, verify `secret-manager` is a directory owned by `uid` and
not a symlink (`lstat`) before touching anything beneath it.

## L6 — `write_atomic` opens a fixed `.vault.tmp` with create+truncate

**Where**: `crates/secret-manager/src/vault/store.rs:428-435`.

`OpenOptions::create(true).truncate(true).mode(0o600)` follows a
pre-existing symlink and keeps a pre-existing file's wider mode. The
directory is 0700, so only the owner or root can plant one. Use
`create_new(true)` with a random suffix (or `O_NOFOLLOW`) and delete on
failure.

## L7 — `SecretStruct` derives `Debug` and can print plaintext

**Where**: `crates/secret-manager/src/dbus/session.rs:11`.

For `plain` sessions `value` *is* the secret. Nothing prints it today
(checked every `{:?}` site), but every other secret-bearing type in the
tree has a redacting `Debug`; give this one the same.

## L8 — Session ownership is not enforced on secret read/write calls

**Where**: `crates/secret-manager/src/dbus/item.rs:82`, `:104`,
`service.rs:101`, `collection.rs:122`.

`Session.Close` checks the caller, but `GetSecret`, `GetSecrets`,
`SetSecret` and `CreateItem` accept any session path. With DH sessions a
foreign caller cannot decrypt or forge, and a same-uid caller could open
its own `plain` session anyway, so there is no gain for an attacker;
enforcing `SessionEntry.owner == sender` is cheap consistency.

## L9 — Unit could be tightened further

`dist/secret-manager.service` is already strong. Safe additions:
`RestrictAddressFamilies=AF_UNIX`, `PrivateNetwork=yes` (the daemon uses
only unix sockets), `UMask=0077` (protects `aliases.toml` and anything
written with default perms), `SystemCallArchitectures=native`, and
`LimitMEMLOCK=256M` if M2's `mlockall` is adopted. Avoid `ReadWritePaths`
and `ProtectSystem=strict`, which already failed with 226/NAMESPACE on this
host.

## L10 — Config allows a trivially weak KDF

`[kdf] m_cost_kib = 8` is accepted. Warn (or refuse) below
`m_cost_kib < 19456` / `t_cost < 2`, the OWASP floor, in `Config::from_str`.

## I1 — DH private exponent is not zeroized; `modpow` is not constant time

`crates/secret-manager/src/session/dh.rs:33-49`. Documented in code.
`num-bigint` has no zeroize support and its `modpow` is variable-time; the
exponent lives for one session on a local bus. Degenerate-key checks are
correct for a safe prime. Acceptable; a `crypto-bigint` port would close it.

## I2 — `auto_lock_after` defaults to never with PAM auto-unlock

With the shipped defaults the vault is open for the whole login session,
which is what gnome-keyring does too. `docs/install-common.md` already warns
in the SSH section. Consider a default such as `15m` or a prominent note at
`sm init`.

## I3 — Any same-uid process can own `org.freedesktop.secrets` first

The session bus lets any connection request any name. A same-uid impostor
can therefore impersonate the service and phish the master password through
its own pinentry. Inherent to Secret Service; noted for completeness.

---

## What is done well

- Vault: Argon2id (64 MiB / 3 / 1), XChaCha20-Poly1305 with a fresh 24-byte
  nonce per save, header bound as AAD, constant-time key compare, atomic
  write with fsync and 0600/0700, rollback on failed saves and rotations.
- Control socket: no `/tmp` fallback, `SO_PEERCRED` verified by both client
  and server, versioned framing with a 1 MiB cap, `Zeroizing` frames,
  redacting `Debug` on `Request`, overall call deadline.
- PAM: never fails a login, absolute `systemctl` with `env_clear`, bounded
  child wait, syslog sanitisation, password cleared after use, `getpwnam_r`
  with `ERANGE` retry.
- D-Bus: prompt ownership and exactly-once completion, session ownership on
  `Close`, name replacement disabled, path segments validated everywhere
  (no traversal into `vault_dir`), broken vaults reported as locked rather
  than crashing.
- Transport: DH degenerate-peer rejection, HKDF per libsecret, random IV
  per message.
- Supply chain: `cargo audit` clean; `unsafe` confined to nine libc calls,
  each with a SAFETY comment.

## Suggested order of work

1. M1 clamp (small, unblocks H1's robust fix).
2. M2 `PR_SET_DUMPABLE` (one line) and M3 zeroizing (four sites).
3. H1 protocol v2 with key derivation in PAM.
4. M4 documentation and `locked_search` option.
5. Lows in any order; L1, L3 and L7 are each a few lines.

## Review follow-up (same day)

A subsequent 7-domain review of this fix wave (vault crypto/format, session
transport, D-Bus surface, control protocol/server, PAM module, packaging/unit
files, docs) found 65 further items: 1 Critical, 15 High, 25 Medium, 24 Low.
All 65 were applied on the branch, landing protocol v3 (password removed
from the control socket entirely), vault header v3, tightened vault-wide
and login-time KDF ceilings, domain-separated key derivation, serialised
Argon2 on the daemon's blocking pool, an up-front `RLIMIT_MEMLOCK` check
before `mlockall`, `catch_unwind`-wrapped PAM hooks, the `vault_dir=` PAM
option, the `SetAlias` deviation from silent overwrite, and the systemd unit
and Makefile fixes described elsewhere in this branch's docs.


---

# Second audit — 2026-09-07

A fresh review of the committed tree (six parallel domain audits plus direct
verification) found 5 Critical, 12 High, and about 25 Medium and Low items.
All are fixed. Findings were confirmed by test or by reading before being
acted on; two agent findings that contradicted the code were checked and one
turned out to be right about a fix that had never landed (below).

## Two fixes the previous round claimed but did not make

An edit script aborted on a failed assertion and its output was filtered, so
two changes were reported as done and were not in the tree:

* `create_collection` still ran Argon2 while holding the daemon's state
  mutex, bypassing the derivation cap.
* `delete_collection` still unlinked the vault file in one lock scope and
  removed the collection from state in another, leaving the race the fix was
  supposed to close.

Both are fixed here, and the commit message for `26949d9` overstates them.

## Critical

| ID | Finding | Resolution |
|----|---------|------------|
| C1 | The control-socket deadline did not bound reads. `SO_RCVTIMEO` limits one `read(2)`, but `read_exact` loops, so a peer feeding one byte per tick held the caller forever. Measured: 179 s against an 800 ms budget, as root inside `sshd`. | A `Deadline`/`TimedStream` pair re-arms the socket timeout from the remaining budget before every syscall. Regression test drives a drip-feeding listener. |
| C2 | A FIFO in place of the vault file hung root permanently. `O_NOFOLLOW` does not refuse FIFOs and the code never checked the file type, so `mkfifo default.vault` blocked `open(2)` inside the login forever. | `O_NONBLOCK | O_CLOEXEC` added and non-regular files rejected after `fstat`. Test asserts refusal within seconds. |
| C3 | `cargo build --all-features` produced a PAM module containing tokio, zbus and clap, loaded as root, with no failure to warn the packager. | `compile_error!` makes `daemon` + `pam` mutually exclusive. The PAM build is library-only; the Makefile says so. |
| C4 | `sm delete` deleted part of a set and exited 0 when one of several prompts was cancelled, because the strict path checked only the error, never coverage. | Coverage check against the locked set; nothing is deleted on a shortfall. Same fix applied to `sm ssh remove` and `ssh add`. |
| C5 | Root unlinked `control.sock` through a path it re-resolved after validating, across a window spanning a file read and a 5 s connect, so a directory swap redirected the unlink. | Descriptor-based `SocketDir`: validated once by `fstat`, used via `unlinkat` and `/proc/self/fd`. Test proves a post-validation swap does not redirect it. |

## High

Login KDF ceiling lowered to 64 MiB / 4 passes / 2 lanes with a total-work
bound, since the derivation runs as root once per session with no
concurrency cap. A prompt with no owner entry was treated as authorized and
could be taken over by any bus client after a dismissal; `check_owner` now
fails closed and completion consumes the action. The `SetAlias` anti-steal
guard was removed: it was bypassable by clearing the alias first, so it
deviated from the spec for no gain. Consent dialogs no longer render a
client-supplied label verbatim, and show the immutable collection id.
`Reload` moved off the state mutex onto the blocking pool, serialized. The
`mlockall` budget is sized from the maximum KDF a header can request rather
than the configured one. `--collection` is validated instead of being pasted
into a path. `sm ssh askpass` now asks for confirmation before releasing a
passphrase, with `SM_ASKPASS_NO_CONFIRM=1` as the documented opt-out.

## Medium and Low

Hardening failures are fatal rather than logged, and the CLI makes itself
non-dumpable too. Per-client caps on sessions and prompts; a `GetSecrets`
item cap; a pinentry dialog timeout; session and prompt paths carry 64 random
bits. `Vault::create` reserves its name exclusively before deriving; the
header has a write-side size ceiling; `Vault::open` refuses oversized files;
`change_key` rejects a reused salt and rotates the index salt; the temp-file
sweep matches the real name shape and an age; the RNG no longer panics on the
save path. Accept errors back off; oversized responses return a readable
error; the bus watcher retries instead of abandoning cleanup. `make install`
refuses a `PAMSO` without PAM symbols, installs it 0644, and only touches
`sm` symlinks that belong to this package. Syslog input is sanitized inside
`log` itself, including bidi overrides.

## Verified sound, unchanged

Total AEAD coverage over every header field, no nonce reuse across saves and
rotations, no parser panic across 20,000 mutated inputs, no object-path
escape, and a genuine safe prime for the DH group so the small-subgroup
rejection is complete. These are now a permanent test (`tests/invariants.rs`)
rather than a one-off check.

---

# Third audit — 2026-09-07

Same threat model. Three reviewers worked the CLI/askpass, PAM, and D-Bus
surfaces independently; the vault and daemon findings were handled directly.
Every fix below carries a test that was confirmed **red before the fix** —
that discipline caught two findings whose "fix" would otherwise have been
inert, and is the reason the two hang bugs are known to be real hangs.

## HIGH — decrypt before consent (askpass)

`sm-askpass` looked the key up and **decrypted** the passphrase before showing
the confirmation dialog, so declining still cost a decryption, and an unlock
prompt could fire for a request the user was about to refuse. The order is now
classify → resolve → `SearchItems` → confirm → unlock/decrypt. The pre-consent
lookup uses a raw search that never unlocks, never prompts and never
decrypts. Test `declining_does_not_unlock_the_collection` sets a working PIN,
so an unlock *would* have succeeded, and asserts the collection is still
locked after a decline.

## HIGH — the askpass dialog could name the wrong key

The prompt path was resolved more than once, so the dialog could name a
symlink while the lookup matched its target. The path is now resolved exactly
once and the dialog names the *matched item's* registered path.
`the_consent_dialog_names_the_real_key_behind_a_symlink` asserts the dialog
does not contain the symlink's name.

## HIGH — PAM read of the vault header was unbounded

`O_NONBLOCK` bounds only the `open`, not the subsequent `read`. A vault file
on a FUSE or NFS mount, or any non-answering server, blocked **root** for as
long as it liked during login. Header reads now poll for readability against
the login budget before every `read`. Documented honestly: a *local* regular
file's read is not interruptible by this deadline, but that case cannot
stall; the attacker-reachable cases return `EAGAIN` and take the bounded
path. Two of its tests hung indefinitely before the fix.

## HIGH — PAM connect followed a symlink at the final component

This corrects an overclaim in the second audit. Validating the runtime
directory on a descriptor and using `/proc/self/fd` defeats a **directory**
swap, but the `connect` is still name-resolved, so a symlink planted at the
socket's own name redirected it. `connect_path()` now does
`fstatat(..., AT_SYMLINK_NOFOLLOW)` and requires `S_IFSOCK`. Its test failed
before the fix by returning a path that would have connected out of the
directory. The docstring no longer claims more than it delivers: the unlink
is inode-safe, the connect is only *narrowed* (there is no `connectat`), and
the residue is contained by the `SO_PEERCRED` check — worst case is
redirection to another of the user's own listeners, which is not an
escalation.

## HIGH — a hostile collection label could forge the consent dialog

`display_label` stripped control characters and bidi overrides, but a label
could still reproduce the `"` and `()` the dialog uses structurally and so
forge a complete, plausible clause naming a *different* collection. Verified
attack: a 58-character label rendered
`Permanently delete the keyring "x" (id: default) and all 0 secrets? Nothing
to worry about" (id: work) and all 47 secrets?`.

Fixed on both sides. The daemon's authoritative clause now comes **first**
and carries the id it actually operates on; the label goes on its own line
after `Its label is:`; and `display_label` maps `"`, `(` and `)` to spaces so
the label cannot reproduce the punctuation the clause is built from. The same
payload now renders inertly, confined to the trailing label line.

## HIGH — a disconnect vetoed every collection in a multi-collection unlock

One collection's commit gate leaked into the next, so an owner disconnect
could suppress dialogs for collections it had no say over. The gate is now
reset per collection and ownership re-checked each iteration.

## HIGH — prompt dialog lock wait was unbounded; session quota checked too late

`ask`/`confirm` now bound the dialog-lock wait with the prompt timeout (a
queued dialog waited 5.1 s instead of 300 ms before the fix). `open_session`
checks the per-client quota **before** the algorithm match, so the modular
exponentiations no longer run for a request that is about to be refused, and
re-checks under the lock afterwards.

## MEDIUM — non-atomic multi-item delete

`sm delete` and `sm ssh remove` issued N separate `Item.Delete` calls; a
failure partway left a half-deleted set with the secret still present. Added
a daemon-side all-or-nothing `DeleteItems`, deliberately **not** on
`org.freedesktop.Secret.Collection` — the freedesktop spec has no batch
delete and libsecret clients must see the spec's methods exactly — but on a
private `org.secret_manager.Collection1` interface at the same path. It
validates every path before mutating, then performs one `Vault::save` with
the store's existing in-memory rollback. Signals and unexports happen only
after the save succeeds. The CLI falls back to the per-item loop when the
interface is absent, and its message then says the items were left untouched
rather than naming survivors. A test asserts via introspection that
`DeleteItems` is absent from the spec interface and that per-item
`Item.Delete` is unchanged.

## MEDIUM/LOW — remainder

Argon2 in PAM now respects the login budget (bound stated honestly as the
budget *plus at most one KDF-ceiling derivation*, since Argon2 is not
interruptible). Per-item secret cap enforced in `create_item`. Unicode
formatting characters — including the `U+202A–202E` range the finding list
omitted — stripped from anything shown in a dialog or listed by `sm ssh
list`. `ssh-add`'s prompt forms recognised; relative key paths resolved and
released only if they canonicalise to a registered key; `sm ssh` refuses to
choose between two items claiming the same key rather than releasing an
attacker-planted one. Object-path escaping widened to every byte below
`0x20` plus `0x7f`. Prompt abort handle no longer duplicated across two
fields. Dismissal re-checked on both sides of every dialog.

## Dependency

`postcard`'s default features pulled in `heapless 0.7`, whose
`atomic-polyfill` dependency is unmaintained (RUSTSEC-2023-0089). It was
never compiled for this host — it only applies to bare-metal targets — but
the feature is unused, so it is now `default-features = false`. Dependency
count 183 → 172 and `cargo audit` is clean with no allowed warnings.

## Process note

The oversize-vault refusal test built a real 256 MiB vault and cost 42.4 s of
every run. The ceiling is now injectable for tests, so the test proves *more*
(it re-runs the same insert with the real ceiling restored, showing the
refusal was the limit and nothing else) in under a second. Whole unit suite
44 s → 13 s.

One reviewer's own report miscounted a suite's test total, and another was
interrupted mid-run leaving three deliberate "neutering" stubs in the source.
Both were caught by checking the tree directly rather than trusting the
reports; the stubs were confirmed removed by inspecting the real function
bodies. An earlier claim in this document that `/proc/self/fd` pinning closed
the PAM path-swap hole was incomplete, and is corrected above.

## State

283 tests pass. `cargo clippy --all-targets -- -D warnings` and the
`pam`-only lib clippy are both clean, `cargo fmt --check` is clean, and
`cargo audit` reports nothing. `make build` produces a daemon with no libpam
linked and a PAM module with six `pam_sm_*` entry points and no tokio.

---

# Fuzzing — 2026-09-07

Added after the third audit: 16 cargo-fuzz targets (`fuzz/`) and matching
bounded property tests (`tests/prop_*.rs`) that run on stable in a normal
`cargo test`. `docs/fuzzing.md` is the guide. Three findings came out of
building them.

## Finding — `escape_control` used a narrower invisible-character table

The third audit's entry above claims invisible formatting characters are
"stripped from anything shown in a dialog **or listed by `sm ssh list`**".
Only the first half was true. `src/cli/secrets.rs` carried its *own* copy of
the table, omitting the private-use planes (`U+E000–F8FF`,
`U+F0000–10FFFD`), the Arabic number signs (`U+0600–0605`, `U+06DD`,
`U+070F`), `U+180E`, the interlinear annotations (`U+FFF9–FFFB`), the musical
controls, and the tag characters (`U+E0020–E007F`). A planted item could
therefore hide or garble part of a listing row that the consent dialogs
already refused to hide.

Fixed by deleting the duplicate: `escape_control` now imports the one table
in `src/dbus/prompt.rs`. Reproducing inputs `U+F0000` and `U+EEFF`; the
regression case is in `escape_control_hides_unicode_format_characters`, red
before the fix.

**The lesson is about the fuzzer, not the bug.** Sixty seconds of fuzzing did
not find this, and could not have: the shared generator built characters with
`char::from(u8)`, so it could never emit anything above U+00FF. The proptest
mirror, using `any::<char>()`, found it in milliseconds. The generator now
draws from the whole scalar range on a dedicated arm. Any target that
classifies characters must be fed the entire space, not a byte's worth of it.

## Finding — a key path containing `\r` was released to askpass

The property asserted after the second audit — any path released by
`classify_prompt` is non-empty and free of line terminators — did not hold.
The quoted alternatives in the prompt regex are `[^']+` and `[^"]+`, which
admit `\r` and `\n`, and the single-line guard tested only `\n`. So
`Enter passphrase for key 'a\rb': ` classified as a passphrase request for a
path containing a carriage return. Not exploitable — every display site
escapes the path — but the stated invariant was false. Fixed in
`passphrase_path`, where both callers pass through.

The "absolute" half of that invariant is false *by design* and was left
alone: the quoted forms deliberately accept relative paths (`ssh -i ./key`),
which `askpass` resolves and matches against registered keys. The targets
assert absoluteness only for the unquoted `ssh-add` form, which is where the
code actually promises it.

## Finding — the control frame was not canonical

`postcard::from_bytes` stops at the end of the first complete message and
ignores what follows, so a peer could append arbitrary bytes to a valid
request and have it accepted (`Response::Ok` plus `ff ff ff` decoded as
`Ok`). Multiple varint encodings also decode to the same variant.

Not exploitable as the protocol stands — the length prefix delimits a frame,
one message is read per frame, and no frame is hashed, signed or compared —
but a frame that decodes should have been consumed in full, or "the frame
received" and "the message acted on" are different objects. `decode_frame`
now uses `take_from_bytes` and rejects a non-empty remainder with
`ProtocolError::TrailingBytes`. The non-canonical varint acceptance is inside
postcard and is documented rather than forked; it matters only if anything
ever starts signing or deduplicating frames.

## Note on what the session cipher can promise

`session_cipher` does **not** assert that corrupting a ciphertext produces an
error, because that is not true. The Secret Service spec mandates
`dh-ietf1024-sha256-aes128-cbc-pkcs7`, which is unauthenticated: roughly 255
times in 256 the PKCS#7 check fails, and otherwise decryption succeeds and
returns garbage. The target asserts the property that does hold — corruption
never yields the original plaintext — which follows from CBC decryption being
a bijection on (IV, ciphertext) and PKCS#7 being injective. This is a
property of the spec's transport, not a defect in this crate, and it is why
the vault format uses an AEAD instead.

---

# Negative-test coverage audit — 2026-09-07

A different question from the three audits above: not "is this branch wrong"
but "is this branch *tested*". Three read-only analysts enumerated every
failure mode reachable in `src/` and cross-referenced the 181 inline unit
tests, the 59 integration tests, the property tests and the 16 fuzz targets.
48 findings; the tests are in the tree.

## Finding — the per-item secret cap was bypassable

`Collection::CreateItem` enforces `MAX_ITEM_SECRET` (1 MiB). `Item::SetSecret`
did not. So the cap added as MEDIUM 6 in the third audit above was a speed
bump: a client could create a one-byte item and then replace its secret with
a hundred megabytes over the same session. The comment on the constant states
the consequence exactly — a collection pushed past the vault size limit stops
saving entirely — so this was a denial of service against the whole
collection, reachable by any bus client, in two ordinary method calls.

Fixed by applying the same check in `set_secret`. Regression test:
`set_secret_rejects_an_oversized_secret` in `tests/dbus_items.rs`, which also
pins that exactly `MAX_ITEM_SECRET` bytes is still accepted.

This is the second incomplete fix from the third audit found by later work —
`escape_control`'s duplicate invisible-character table was the first — and
neither was found by review or by fuzzing. Both were found by asking which
branches nothing exercises.

## What the coverage analysis was worth

The findings clustered where the *consequences* are worst rather than where
the code is newest:

- **`Vault::change_key`'s KDF ceilings had no test at all.** `new_kdf.validate()?`
  is the only enforcement of the ceilings on the write path: the peer-chosen
  `new_kdf` travels from the control socket through `handle_control` and
  `daemon::change_key` into `Vault::change_key` with no intermediate check,
  and every existing test passed `FAST`. Deleting that line would let a
  same-uid client write a header whose parameters every later `open` must
  refuse — permanently unopenable, on every host.
- **A departed owner's prompt re-locking what it opened** was *executed* by an
  existing test but its effect was never asserted. The `vault.lock()` loop
  could have been deleted with the whole suite still green, leaving a
  decrypted vault open in memory for a client that had disconnected.
- **An empty stored secret released to askpass.** A key registered with
  `--no-passphrase` stores an empty secret, and the suite already documents
  that OpenSSH reads an empty answer as *approval*. The guard existed; nothing
  tested it.
- **`control::server::read_frame` is a second frame reader**, separate from
  `protocol::read_frame_sync`. The property tests and fuzz target cover the
  protocol copy; the daemon uses this one on every inbound connection, and its
  allocation bound was untested.

## Finding — an aborted prompt left vaults open for a departed owner

`run`'s `Unlock` loop resets the commit gate at the top of **every**
collection. So a client that disconnects while a *later* dialog is on screen
leaves the gate `false`, and `watch_clients` aborts the task — correctly,
since nothing is half-committed. But an abort only takes effect at an await
point and never reaches the re-lock branch at the end of the loop, so any
collection opened in an earlier iteration stayed decrypted in memory with no
owner. That contradicts the intent stated in that branch's own comment.

The existing `an_owner_disconnect_stops_the_remaining_unlock_dialogs` test
sits in exactly this state and asserts only about a collection the prompt
never opened, so it passed either way.

Fixed by recording what each prompt has unlocked in shared state
(`prompt_unlocked`), which an abort cannot destroy: the abort path re-locks
those collections and emits the signals with the lock released, while a
prompt that completes normally drops the record instead, since its owner is
still there. Regression test
`an_aborted_prompt_relocks_the_collections_it_had_already_opened`, confirmed
red before the fix with "a vault the aborted prompt had already opened stayed
unlocked with no owner".

## The three gaps that were said to be uncloseable

All three were closed. Two of the reasons they had been written off were
wrong, which is worth recording.

**The control socket's wrong-uid rejection.** Written off as needing root.
It does not: `SO_PEERCRED` translates credentials into the *reading*
process's user namespace. But the obvious recipe is a trap — with the usual
`0 <uid> 1` map the connecting parent appears as uid **0**, which
`uid_allowed` allows because root is allowed; with no map at all, listener
and peer both read back as the overflow uid, so `peer == me` and that is
allowed too. Either version passes while proving nothing. The real test uses
`newuidmap` with a delegated `/etc/subuid` range to give the child a genuine
second kernel uid: `a_connection_from_a_genuinely_foreign_uid_is_refused`
reports "daemon uid 1000, peer uid 100000 (delegated sub-uid), refused
unserved", and skips with a printed reason where no range is delegated. The
`Err(_)` fail-closed arm, which had no coverage at all, is now tested through
the extracted `peer_allowed_from`.

**`hooks.rs` through libpam.** `pam_wrapper` is not installed and the answer
was not to install it. The untestable part was never libpam — it was that the
decisions were tangled up with the glue. The three hook bodies now call
`authenticate_decision`, `open_session_decision` and `chauthtok_decision` in
`src/pam/mod.rs`, which compile and test without the `pam` feature. Two
seams only (target resolution and daemon start, both because *when* they run
is part of the ordering); everything else uses the real `SocketDir`,
`Budget`, vault files and listeners. 25 tests now cover the ordering: the
stash cleared on all 16 exit paths, no derivation after the budget is spent,
and the retry unlock gated on `waited && dir.revalidate()` in all four
combinations — including the case that proves `revalidate` is never consulted
when `waited` is false.

Three of `open_session`'s four budget checks turn out to be unreachable
defence in depth rather than live guards (the preceding call consults the
same budget and refuses first), and one inner arm is dead outright. It was
preserved verbatim and documented rather than deleted. `chauthtok`'s check is
genuinely reachable — it is the one that sits after two non-interruptible
Argon2 derivations — and is tested.

What remains untestable without libpam is now specific rather than vague:
the `pam_module!` ABI surface; the `PamData` round-trip between the auth and
session stacks; whether `clear_stashed_password` actually overwrites the
stash rather than deciding to; `get_user`/`get_cached_authtok` behaviour; the
hard-coded `PAM_PRELIM_CHECK` constant matching the platform header; and the
lossy UTF-8 conversion of an authtok, which lives on the untested side of the
line. The second and third are the ones that fail silently.

### Amendment — that list was closed too, with libpam

It did not need `pam_wrapper`, root, or an edit to `/etc/pam.d`.
`tests/pam_stack.rs` drives the shipped cdylib through a real libpam stack:

* `pam_start_confdir` (Linux-PAM ≥ 1.4) points libpam at a temporary config
  directory whose service file names `target/pam/release/libsecret_manager.so`
  by absolute path, so libpam does the `dlopen` and the `pam_module!` ABI is
  exercised for real.
* libpam itself is loaded with `dlopen`/`dlsym`, not linked, so a machine
  without it — or without the built cdylib — skips with a printed reason
  instead of failing to build the suite.
* An application may not `pam_set_item(PAM_AUTHTOK)`; Linux-PAM refuses it
  from outside a module. `auth optional pam_unix.so nodelay` ahead of us does
  it instead: `pam_get_authtok` prompts through the test's conversation
  function and caches the answer into `PAM_AUTHTOK` *before* it verifies it,
  so the token is there even though the verify then fails and `optional` lets
  the stack continue.
* Nothing goes through the environment — the module is dlopened into the test
  process — so `vault_dir=` and `socket=` are module arguments in the service
  file, and the suite asserts it is not root, since `socket=` is ignored for
  root.

The assertions are about the daemon, not the module: after `pam_authenticate`
plus `pam_open_session` in one transaction the collection is *actually*
unlocked, which is the round-trip. Re-locking it and running `open_session` a
second time in the same transaction leaves it locked, which is
`clear_stashed_password` landing rather than deciding to. Two transactions
differing only in the name given to `pam_start_confdir` — one unresolvable,
one real — pin `get_user`. A wrong password is refused with the same-shaped
run using the right one as the control. `pam_chauthtok` rotates the key.

Each was confirmed red by mutating the module: pointing `retrieve_data` at
another key breaks the round-trip test, making `clear_stashed_password` a
no-op breaks the second-`open_session` test, and setting `PAM_PRELIM_CHECK` to
`PAM_UPDATE_AUTHTOK` breaks the rotation test.

One thing libpam still will not show: a `PAM_PRELIM_CHECK` value that names no
other flag is behaviourally invisible, because libpam sanitizes `PAM_AUTHTOK`
and `PAM_OLDAUTHTOK` on entry to the password stack and pam_unix sets only the
old one on the prelim pass, so the module never has a complete pair to act on
whichever pass it thinks is real. `the_prelim_check_constant_matches_the_platform_header`
covers the value directly instead, comparing the literal in `src/pam/mod.rs`
with `<security/pam_modules.h>`.

Still out of reach: the lossy UTF-8 conversion of an authtok (libpam's own
prompt reader will not carry invalid UTF-8 into `PAM_AUTHTOK`), the
`send_data`/`retrieve_data` error arms, and everything root-only — the real
`/run/user/<uid>` socket path, `systemctl --machine`, and `socket=` being
ignored.

**`Client::connect`'s hang guard.** Closed by making the timeout injectable
through the existing `test-util` feature — the same mechanism as
`KdfParams::FAST_FOR_TESTS` — so the shipped build is unchanged.

## State

411 tests pass, twice over (`make test-pam` rebuilds the cdylib first, so
`tests/pam_stack.rs` runs against a current one rather than skipping). Clippy clean at `-D warnings` for the default,
`pam` and fuzz builds; `cargo fmt --check` and `cargo audit` clean; `make
build` yields a daemon with no libpam linked and a PAM module with six
`pam_sm_*` symbols.

---

# Fourth audit — security and denial of service — 2026-09-07

DoS as a first-class target rather than a footnote. Five read-only analysts:
resource exhaustion and cap bypasses, concurrency and starvation, algorithmic
complexity, the day's new code with fresh eyes, and the external attack
surface. The distinction asked for throughout was between *a nuisance the
user ends by killing the attacking process* and *the daemon or a collection
is now unusable*.

## Two regressions in the previous fix, found and fixed

Today's `prompt_unlocked` fix — the record of what a prompt has unlocked, so
an aborted prompt re-locks it — was wrong in two ways.

**It re-locked collections it never opened.** `unlock_collection_inner`
returns `Unlocked` when a collection is *already* open, so the record claimed
it, and the abort path then sealed a vault a **different, still-connected
client** legitimately held. Reachable with no password and no dialog: call
`Unlock` on a locked collection, wait for someone else to unlock it, call
`Prompt`, disconnect. There is now a distinct `AlreadyUnlocked` outcome that
succeeds without claiming ownership.

**The record was written two await points after the unlock**, after
`notify_collection_changed`, which yields. An abort landing there lost the
record — the original bug in a smaller window. It is now written under the
same lock that performs the unlock, so the invariant is no longer
probabilistic.

## The cap-bypass pattern had three more instances

`MAX_ITEM_SECRET` was fixed this morning on `SetSecret`. The analysts were
asked to find its twins, and did: the item's **label**, **attributes** and
**content type** are all caller-supplied, all serialised into the same
encrypted blob, and all counted against `MAX_VAULT_BYTES` — and none was
bounded. The cap's own comment says it exists so no client can push a
collection past the vault size limit "with one `CreateItem` call". Still
true; it just took the label instead. 256 calls through the secret, **two**
through the label.

Now capped on every write path: `MAX_ITEM_LABEL` 4 KiB,
`MAX_ITEM_ATTRIBUTES` 64 pairs, `MAX_ATTRIBUTE_KEY` 256 B,
`MAX_ATTRIBUTE_VALUE` 512 B, `MAX_ITEM_CONTENT_TYPE` 256 B.

## `SearchItems` hashed the query once per item

`IndexEntry::matches` called `attribute_hash` inside the per-entry loop, and
nothing bounds an attribute value's length. A single legal D-Bus message
carries a 64 MiB value; at 1,000 items that is **64 GB hashed, about a
minute with the global state mutex held** — against collections that are
locked by default, with no consent, no unlock, and repeatable.

The digests are hoisted: `O(items × query_bytes)` becomes `O(query_bytes)`
once plus 32-byte comparisons. With `locked_search = false` the attacker's
bytes are now never hashed at all, because an id-only index cannot satisfy a
non-empty query however it hashes. The residual — one 64 MiB hash, ~200 ms,
linear — is the same cost as any other 64 MiB message the daemon accepts.

## An unbounded collection label bricked `sm status` permanently

The label lives in the header with only `MAX_HEADER` (16 MiB) above it. A
2 MiB label saves fine and is then on disk; `Request::Status` copies it
verbatim, the response exceeds `MAX_FRAME`, and the daemon answers **every**
`Status` with "response too large" — for all collections, across restarts.
There is no CLI command to rename a collection, so an ordinary user cannot
recover. Sized just under `MAX_HEADER` it instead freezes the index: every
later `CreateItem` overflows the header and every save is refused.

`MAX_LABEL` is 4 KiB, enforced in `set_label` and in `build` (so `create` is
covered before the RNG and KDF run). It is exactly `MAX_FRAME / 256` and
`MAX_HEADER / 4096`, and those relations are `const _: () = assert!(...)`
compile-time assertions beside the constant, so neither cap can move without
this being revisited.

## `auto_lock_after` could be defeated by any client, on two paths

`Service.GetSecrets` and `Item.GetSecret` both called `st.touch()` *before*
the session-ownership check. `GetSecrets([], "/bogus")` every few minutes —
no session, no unlocked collection, no knowledge of any path — kept
`last_activity` fresh so the idle timer never fired and the vault keys stayed
in daemon memory indefinitely. Both now touch only after the call is
authorised; the mutating paths already did.

## The dialog wait budget equalled the dialog hold budget

One 120 s constant served both, so a client that raised a dialog nobody
answered always outlasted the victim queued behind it — and the victim's
prompt completed as **dismissed with no dialog ever shown**. The budgets are
now separate, the wait sized from the real worst-case occupancy, and giving
up is `PinentryError::Busy`, never a cancellation: a user who was never shown
a dialog is no longer told they dismissed it. A `DialogSession` also keeps
all three password attempts on one slot, so mistyping no longer sends the
user to the back of the queue.

The guarantee is stated honestly on the constant: **one full hostile
occupancy survived, not starvation-freedom.** No finite wait budget beats an
unbounded FIFO queue of hostile waiters.

## Alias growth, and smaller items

`SetAlias` had no cap on name length or alias count, rewrote the whole file
non-atomically on every call, and never unexported alias objects — growth in
disk and daemon memory that survived restarts. Now bounded (128-byte names,
256 aliases), objects reclaimed when an alias is cleared, and the file
written temp + fsync + rename. `Unlock`/`Lock` took uncapped object arrays
where their siblings were capped at 1024; capped, and checked before the
mutex is taken. `Vault::delete_items` was O(items × ids); now O(items + ids).
A client label reaching a log line raw, and daemon error text reaching the
terminal unescaped, are both escaped now.

## Two findings deliberately not patched

**Every item write does a whole-vault re-encrypt and two `fsync`s under the
global state mutex.** The stated rule is "never hold the lock across an
`.await`", and that holds at all 47 sites — but it is phrased for `.await`,
and a *synchronous* blocking syscall goes straight through it. A
`collection.rs` comment asserts the critical section is short "as
`CLAUDE.md` requires": true as written, false in effect. At a 256 MiB
collection one `CreateItem` is roughly a second of mutex-held,
executor-blocking work and about 1.25 GiB of transient RSS. This is a
decision about the locking model, not a patch.

**A same-uid process that squats `control.sock` bricks the daemon
permanently.** `bind` probes with a connect before unlinking — a deliberate
defence against unlinking a live daemon's socket — which is exactly what
makes the squat stick. `Restart=on-failure` then retries into
`StartLimitBurst`, and the unit stays failed *after the attacker exits*
until someone runs `systemctl --user reset-failed`. It is the only finding
where killing the attacker does not fix it.

**Also escalated, not decided:** a truncated `aliases.toml` refuses daemon
startup, while a corrupt *vault* file is tolerated as `broken`. The atomic
write removes the daemon's own ability to create that state, but a backup
tool or a disk-full event still can. The alternative — dropping aliases on a
parse error — makes `ReadAlias("default")` answer `/` and clients quietly
write to a different collection, which is worse. Worth a deliberate choice.

## State

522 tests pass. Clippy clean at `-D warnings` for the default and `pam`
builds; `cargo fmt --check` clean.

---

# The two deferred findings — 2026-09-07

Both findings the fourth audit documented rather than patched are now fixed.

## Vault I/O no longer runs under the global state mutex

Each collection's `Vault` sits behind its own lock (`Arc<Mutex<Vault>>`); the
state mutex covers map lookups, aliases, sessions and prompt bookkeeping and
nothing else. A mutation and the save it triggers both happen under the
collection's lock, wrapped in `block_in_place` so the two `fsync`s release the
async worker rather than parking it. Writes are still synchronous with
respect to the caller — a successful `CreateItem` still means the item is on
disk, because returning earlier would trade a denial of service for silent
data loss.

**The rule that failed is restated in `CLAUDE.md`.** It said the state mutex
is never held across an `.await` that can block. That was true at all 47
sites, and useless: it is phrased for `.await`, and a synchronous `fsync`
walks straight through it. It now says nothing slow or blocking may happen
under that lock — not an `.await`, and not a blocking syscall either — with
the test that "if work is bounded by the data rather than by a constant, it
does not belong under this lock".

Two consequences of splitting the locks were not obvious in advance and are
load-bearing:

- Confirming an item *exists* needs the collection's lock, so path resolution
  stops at the collection and each caller finishes it (`PathTarget::Item`).
- "Remove from the map" and "unlink the file" can no longer share one guard.
  A confirmed delete now calls `Vault::retire` under the vault's own lock
  before unlinking, and every later save refuses with `VaultError::Retired`
  rather than recreating the file that was just deleted. Without that, a
  `CreateItem` racing a delete resurrects the collection.

The ordering rule enforced is stronger than global-before-collection:
**nothing ever holds two locks at once**, so there is no cycle to reason
about. `tests/dbus_locking.rs` guards it two ways — a source scan that
refuses any statement taking a lock while a `let`-bound guard is alive, in
either direction, and a runtime test that *holds* a collection's lock by hand
(exactly what a save in flight holds) and asserts an unrelated write and a
state-only property still answer. The second measures no duration: each check
is "immediately, or never", so it cannot flake. Both were confirmed to fail
against a deliberately reintroduced regression.

## A squatted control socket no longer keeps the daemon down

`bind` refused to take a socket anything was still answering, to avoid
unlinking a live daemon's. That reasoning does not survive the startup order:
`Daemon::start` acquires the bus name first, refusing replacement in both
directions, and D-Bus makes that name unique — so a second *legitimate*
daemon can never reach the bind. The only party the refusal ever met was a
same-uid impostor, and for that party it was a permanent denial of service:
the unit fails, `Restart=on-failure` retries into `StartLimitBurst`, and it
stays failed *after the squatter exits* until someone runs
`systemctl --user reset-failed`.

The daemon now takes the path over, and does it atomically: bind a private
`.control.<random>.sock` and `rename(2)` it across, rather than
unlink-then-bind. There is no instant in which the path is absent or unbound,
so a squatter cannot win by re-binding in a gap — losing that race is what
made a squat stick. A second test watches the path throughout the bind and
fails if it ever vanishes.

The impostor keeps its own socket and any client already connected to it —
the accepted residue of gap I3, unchanged. What it loses is the ability to
keep the real daemon from starting.

## One unexplained test failure, recorded rather than dismissed

The first full-suite run after the host recovered from process exhaustion
reported 454 passed and 1 failed, with 71 tests missing — a binary that
aborted early rather than a test that asserted wrongly, which is the shape of
a failed `spawn`. It was not captured, and it has not recurred in **15
consecutive full-suite runs**, 15 runs of the five locking-sensitive suites
(96 tests each, no early aborts), or 10 runs of `cli_init` alone.

The environmental explanation fits — the host had just been unable to
`posix_spawn` at all, and the suites that failed spawn both a `dbus-daemon`
and the CLI — but it was not reproduced, so it is written down rather than
explained away. If it returns, the thing to look at first is
`registry::register_collection`, which now takes each vault's lock during a
`Reload`; it cannot deadlock, since nothing holds the state lock there, but
it can queue behind a save.

## State

525 tests pass. Clippy clean at `-D warnings` for the default and `pam`
builds; `cargo fmt --check` clean.

---

# The alias asymmetry — 2026-09-07

A corrupt `<id>.vault` was tolerated: it became a permanently locked
collection carrying its error, and the daemon carried on. A corrupt
`aliases.toml` propagated out of `scan_vault_dir` and **refused to start the
daemon at all** — so the file holding nothing but convenience mappings was
the one that could take the service down, and anything that truncated it (a
backup tool, a full disk, a hand edit) took the keyring with it. Making the
write atomic removed the daemon's own ability to create that state; it did
nothing about anyone else's.

The two are now symmetric. The daemon starts, and the alias table is
**unusable rather than silently empty** — which is the distinction that
matters:

- `ReadAlias` returns an error, not `/`. `/` means "no such alias", and
  answering that would invite a client to claim a name the user already owns.
- `SetAlias` refuses, and `ServiceState::save_aliases` refuses as a backstop.
  Writing would replace a file the operator may still be able to repair with
  one built from the empty table we fell back to, turning a recoverable parse
  error into silent data loss.
- Alias resolution yields nothing, so no path silently reaches a different
  collection than the caller meant.
- `Status` carries the reason and `sm status` prints it, since the daemon no
  longer announces the problem by failing to start. That needed a new field on
  `Response::Status`, so `PROTOCOL_VERSION` is 4.
- Repairing or deleting the file and reloading clears the condition.

The three unit tests were confirmed red against the old propagation. Two
existing tests were rewritten because they pinned the old contract, and both
are called out: `reload_reports_a_vault_directory_it_cannot_scan` used a
malformed alias file as its second route into the failure arm, and the
protocol test pinned `PROTOCOL_VERSION == 3`. That version pin is kept rather
than dropped — the wire format and the version have to move together, and it
should fail loudly when only one of them does.

## A note on the PAM stack tests

The version bump made all five `tests/pam_stack.rs` tests fail, because they
`dlopen` a prebuilt cdylib and the one on disk still spoke v3. The version
check was working exactly as intended across a real skew, but the symptom —
"the password stashed by `pam_sm_authenticate` did not reach
`pam_sm_open_session`" — is a genuine bug's message, and it sends you looking
in the wrong place. The suite now compares the module's mtime against the
newest file in `src/` and skips with an explicit "run `make build`" rather
than failing as though the round trip were broken.

## State

528 tests pass, twice over. Clippy clean at `-D warnings` for the default and
`pam` builds; `cargo fmt --check` clean.

## Review of the alias fix — 2026-09-07

The fix above held its headline property *by accident*, and a review found
nine further defects in it. All are fixed here, each with a test confirmed red
first.

**The guard was on two of eleven call sites.** `ServiceState::alias_target` is
the single funnel for alias resolution and was unguarded; it returned `None`
while degraded only because the map happened to be empty. The paths that
carry `GetSecrets`, `CreateItem`, `SetSecret` and `Delete` under an alias
object path were among the nine that never asked. "Unusable but non-empty" is
now unrepresentable rather than guarded: `ServiceState::aliases` is an
`AliasTable` — `Usable(map)` or `Degraded { reason, known }` — and
`alias_target` returns a `Result`, so the compiler enumerated every site that
had to decide, and each one says in a comment what it decided.

**A `Reload` wiped a live, working table.** `merge_scan` assigned the empty
fallback unconditionally, so a file that went bad under a running daemon
broke every alias in it *permanently* — the same table was then forbidden
from ever being written back. `tests/daemon.rs` pins that rule for
collections; nothing pinned it for aliases. The last table read successfully
is now kept, which is what `Degraded`'s `known` is for, and that answers the
question of what `ReadAlias` should say: a name the daemon has already read
still resolves (availability), a name it has not is refused — never `/`,
which is the answer that invites a claim. At startup with a corrupt file
`known` is empty, so every name falls into the second case on its own.

**The prompt path mutated the table and only warned.** `create_collection`
and `delete_collection` inserted into `st.aliases`, then logged the refusal
from `save_aliases` and carried on, so the daemon gave two different answers
for one name and the mapping vanished at the next reload. The alias work is
refused up front now; the collection operation still succeeds. A *write*
failure with a readable table is unchanged and still deliberate — see
`an_unwritable_alias_file_blocks_neither_create_nor_delete`, which pins it.

**`SetAlias`'s guard was on the wrong side of the branch.** It sat inside the
repointing branch, so `SetAlias(name, "/")` removed the entry, bounced off the
`save_aliases` backstop, and returned before `registry::unregister_alias` —
leaking the two exported objects that clearing exists to reclaim, with the
entry gone from memory anyway. The guard is above the split, and the write
now happens *before* the in-memory commit, so an I/O failure on the healthy
path can no longer leave the daemon disagreeing with its own file after
telling the client the call failed.

**The error string was unbounded and unsanitized.** `toml`'s `Display` echoes
the offending source line, so a 500 KB single-line `aliases.toml` produced a
512 KB error — larger than `MAX_FRAME` on its own, destroying the whole
`Status` reply and losing the collection table along with the diagnostic —
and it reproduced raw control bytes into `tracing::error!` and into D-Bus
errors, forging journal lines from a file the daemon only reads. It is now an
`AliasError`: sanitized and bounded to `MAX_ALIAS_ERROR` at its single point
of construction, and prefixed with `aliases.toml`, which the message never
named.

**The file was read with no size cap.** Vault files get `check_vault_size`
from `stat` before any read; `aliases.toml` got nothing, so a multi-gigabyte
file was read whole at startup — and `Reload` is reachable from any same-uid
peer, so on demand thereafter. `MAX_ALIAS_BYTES` mirrors the vault's
stat-before-read.

**It degraded on every error, not just a parse failure.** `EACCES`, `EIO` and
`EISDIR` came back as "repair or delete aliases.toml", which is meaningless
advice for a permission fault, and started the daemon into a state where
`SetAlias` could never recreate the file. Only `ErrorKind::InvalidData`
degrades; everything else propagates, as `read_dir` two lines above does.

**`sm init` still treated it as fatal**, and did so *after* `Vault::create`
had written the vault: a half-finished init that never printed the id the
user needs, never sent the `Reload`, and reported "collection already exists"
on the re-run. It warns and carries on.

**The recovery instruction named a command that did not exist.** There is now
an `sm reload`; it is independently useful, and `sm init` — the only other
`Reload` sender — is exactly the command this state used to break.

**One test was vacuous.** `assert_eq!(st.alias_target("default"), None)`
passed with or without any guard, because the fixture cannot parse and the
map was empty either way. It asserts the refusal now, and reaches the paths
that carry secrets. Two integration tests drive `ReadAlias`, `SetAlias` and
`CreateCollection` against a daemon whose alias file went bad under it —
which is what nothing did before, and why the misplaced `SetAlias` guard
survived.

`PROTOCOL_VERSION` stays 4: `Response::Status::aliases_error` is unchanged on
the wire.

## State

537 tests pass, twice over. Clippy clean at `-D warnings` for the default and
`pam` builds; `cargo fmt --check` clean; `cargo +nightly check` clean on the
excluded `fuzz/` crate.
