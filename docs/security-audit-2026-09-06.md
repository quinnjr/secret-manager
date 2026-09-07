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
