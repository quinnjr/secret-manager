# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A freedesktop Secret Service provider: one Rust crate that produces three
things — the `secret-manager` daemon, the `sm` CLI (secret-tool compatible,
plus an `sm-askpass` argv0 alias), and a PAM module that unlocks the vault at
login. It replaces gnome-keyring or kwallet as the owner of
`org.freedesktop.secrets`.

`README.md` is the user-facing overview.
`docs/superpowers/specs/2026-09-05-secret-manager-design.md` is the design
spec and the source of truth for the format and the protocol; its amendment
section records deliberate changes. `docs/security-audit-2026-09-06.md`
records two security audits and what each finding's fix was.
`docs/superpowers/specs/2026-09-08-migration-assistant.md` specs `sm import`,
which moves a user off gnome-keyring or kwallet; it is implemented
(`src/cli/import.rs`). The KWallet and gnome-keyring decommissioning steps in
the install guides remain reasoned rather than verified on a live desktop
session, and `sm import` says so.

## Build and test

```sh
cargo build                                          # the binary
cargo build --no-default-features --features pam --lib   # the PAM cdylib
cargo test                                           # everything
cargo test --test dbus_prompts                       # one integration binary
cargo test --lib vault::                             # one module's unit tests
cargo test --test cli_ssh remove_refuses             # one test by name
cargo clippy --all-targets -- -D warnings
cargo clippy --no-default-features --features pam --lib -- -D warnings
cargo +nightly check --manifest-path fuzz/Cargo.toml --all-targets
make build                                           # both release artifacts
```

**`cargo build --all-features` fails on purpose.** `daemon` and `pam` are
mutually exclusive features, enforced by a `compile_error!` in `src/lib.rs`,
because the PAM module is dlopened as root and must not contain tokio, zbus,
or clap. For the same reason the `pam` build is library-only: integration
tests pull the crate back in with its default features through a
dev-dependency, so `--features pam --all-targets` trips the guard.

`make build` runs two cargo invocations and puts the PAM artifact in
`target/pam/release/libsecret_manager.so`, separate from the default build's
`target/release/`, so the two `.so` files cannot be confused. `make install`
refuses a PAM artifact that lacks `pam_sm_open_session`.

## Architecture

**Three processes, two IPC surfaces.** The daemon owns the bus name and holds
the vaults. The CLI and the PAM module are clients. Secrets travel over
**D-Bus** (the freedesktop Secret Service API, so libsecret clients work).
Lifecycle operations — lock, unlock, status, reload, key rotation — travel
over a **private control socket** at
`$XDG_RUNTIME_DIR/secret-manager/control.sock`, defined in `src/protocol.rs`.

**The central invariant: no password crosses the control socket.** Control
protocol v3 onward has no password-carrying request (`PROTOCOL_VERSION` is
now 4). Both the CLI and the PAM module
read the collection's vault header from disk, derive the key locally with
Argon2id, and send only the key. Nothing that answers the socket can choose a
salt or a KDF cost. Preserve this when touching `src/protocol.rs`,
`src/cli/vault_cmds.rs`, or `src/pam/`.

**Trust model.** The uid boundary is the one the code enforces: another user
or the network must reach nothing. Same-uid processes are semi-trusted, which
the Secret Service model requires. The PAM module is the exception — it runs
as **root inside the target user's login** and treats that user as hostile,
so everything it touches in the user's tree is validated on a file
descriptor, never by re-resolving a path.

**Vault file** (`src/vault/format.rs`, `store.rs`):
`magic(8) | header_len u32 LE | postcard(Header) | XChaCha20-Poly1305`.
Everything before the ciphertext is the AEAD associated data, so no header
field can be altered undetected. The header is *not* authenticated until a
successful decrypt, so anything read from it is attacker-controlled — KDF
parameters are validated against ceilings before Argon2 ever runs. Saves are
atomic: `O_EXCL` random temp name, fsync, rename, directory fsync, with
in-memory rollback if the write fails.

The header also carries a **hashed attribute index** so `SearchItems` works on
a locked collection. That is a documented trade: it lets a file holder, and
any bus client, confirm attribute guesses. `[vault] locked_search = false`
stores ids only.

**Daemon state** (`src/dbus/state.rs`) lives behind one async mutex, and each
collection's `Vault` behind its own — `collections: BTreeMap<String,
Arc<tokio::sync::Mutex<Vault>>>`. Three rules follow.

*Nothing slow or blocking may happen under the state mutex.* Not an `.await`
that can block, and **not a synchronous blocking call either**: a `write`, an
`fsync`, a whole-vault re-encrypt, an Argon2 arena. The rule used to be
phrased for `.await` alone, and a plain blocking syscall walked straight
through it — every item write did a whole-collection re-encrypt and two
`fsync`s under the global mutex, which at a large collection is about a second
during which every other bus call, every control request and the housekeeping
tasks are stopped. If work is bounded by the *data*, not by a constant, it
does not belong under this lock.

*Lock order is global-then-collection, and nothing ever holds both.* Take the
state lock, clone out the `Arc`s (`ServiceState::vault`, `all_vaults`,
`resolve_path`), **drop the state guard**, and only then lock a vault. Never
await a collection's lock while holding the state lock; never take the state
lock while holding a collection's. Anything that walks every collection —
`Status`, `search_all`, `idle_lock`, `Reload`, `register_all`, `Lock` with no
argument — snapshots the `Arc`s under the state lock, releases it, and works
through them one at a time. The mutation *and* the save it triggers belong to
the collection's lock, wrapped in `state::block_in_place` so the save's
`fsync`s release the async worker instead of parking it. A write still
finishes before its caller is answered: a successful `CreateItem` means the
item is on disk.

Two consequences of splitting the locks are load-bearing. Confirming an item
*exists* needs the collection's lock, so `resolve_path` stops at the
collection and every caller finishes the resolution itself (see
`state::PathTarget::Item`). And "remove from the map" and "unlink the file"
can no longer share one guard, so a confirmed delete calls `Vault::retire`
under the vault's own lock before unlinking: every later save refuses with
`VaultError::Retired` rather than recreating the file it just deleted.

*Never run Argon2 under the state mutex* — every derivation goes through
`src/kdf.rs`, which caps concurrency and moves the work to the blocking pool.

**Prompts** (`src/dbus/prompt.rs`) are the consent gate and the subtlest part
of the codebase. Each is owned by the client that obtained it, checked
fail-closed; a commit gate guarantees exactly one `Completed` even when a
`Dismiss` races the running task; a prompt whose owner disconnects is aborted
unless it has already committed, and a vault it opened is re-locked. Labels
are client-supplied, so anything shown in a dialog goes through
`display_label` first.

## Conventions

- Anything holding a password, key, or plaintext is `Zeroizing`, and types
  that carry secrets have hand-written `Debug` impls that redact. Adding a
  field to `Request` or a secret-bearing struct means updating its `Debug`.
- Text from a peer (a D-Bus label, a daemon error, a PAM username) is
  sanitized before it reaches a log or a dialog.
- Wire and disk formats are versioned. `Request`/`Response` variant order is
  wire-significant (postcard encodes the index), and `format::VERSION` bumps
  break existing vaults. There is still no migration code: `check_header`
  refuses a mismatch outright — reached through `format::decode_header` and
  `VaultFile::decode`, so the daemon, the CLI and the PAM module all refuse
  alike — telling the user to recreate with `sm init` if the file predates
  the build, and naming the version it found if it postdates it.
  That was free before v0.1.0, when no vault existed that we had not made
  ourselves. It is not free now — a bump strands files people actually have,
  so a `VERSION` change needs the migration written alongside it, or it needs
  not to happen. Refusing to open is the correct floor, not the answer. The
  README promises such a bump lands only in a minor release, never a patch,
  so a `VERSION` change in a patch release is a broken promise, not a
  judgement call.
- The daemon refuses to start rather than silently downgrade: if it cannot
  make itself non-dumpable, or if `[vault] lock_memory = true` and
  `RLIMIT_MEMLOCK` cannot cover a derivation, startup fails.

## Tests

Integration tests spin up a private `dbus-daemon` and a scripted pinentry;
`tests/common/mod.rs` has the fixture (`Fixture::start`,
`start_with_config`, `.sm()` to run the CLI against it, `.client()` for a bus
connection). The fake pinentry at `tests/fixtures/fake-pinentry.sh` is driven
by `FAKE_PIN`, `FAKE_CONFIRM`, `FAKE_LOG` (records every Assuan line, so tests
assert on what the dialog said) and `FAKE_DELAY` (to race a dialog).

`tests/invariants.rs` holds property tests that reading cannot settle: parser
fuzzing, AEAD coverage of every header field, nonce uniqueness, object-path
escape. `tests/packaging.rs` locks in the Makefile and unit file.

`tests/dbus_locking.rs` guards the lock rules above. It holds one
collection's lock by hand — a save in flight holds exactly that and nothing
else — and asserts a write to another collection and a state-only property
still answer, so the proof needs no duration and cannot flake. That is the
half a green run *can* establish; beside it sits the half it cannot, because
what has to hold is a property of the source and not of one execution.

That half is a `syn`-based scan of `src/dbus/` and `src/daemon.rs` — the real
Rust grammar, not a lexer — which builds the call graph and asks of every
statement whether it can run with a lock held. It refuses a second
acquisition, and blocking work: an `fsync` stops the same tasks a bad `.await`
would, and phrasing the rule for awaits alone is what let the original bug
through. **Because it follows calls to a fixed point, no rule here is
defeatable by moving the offending line one `fn` deeper** — which is how
`unique_collection_id` hid, its whole body a one-line delegation to something
that looped over `symlink_metadata`.

The two locks are not interchangeable and the scan does not conflate them.
Under a **collection's** lock, `state::block_in_place` is the sanctioned
wrapper and exempts the save it wraps. Under the **state** guard nothing is
exempt, and `block_in_place` is *itself* an offence there: it releases the
async worker, never the mutex, so it is the marker of blocking work in the one
place blocking work may not go.

A guard region starts where the state is genuinely held: a `let`-bound
acquisition, for as long as its binding lives; a `match`/`while let`/`if
let`/`for` scrutinee that locks, which is refused outright because a scrutinee
is not a terminating scope; the whole body of a helper whose signature takes
`&ServiceState`, `&mut ServiceState` or the guard itself, which can only have
been called with the state held; and the body of a closure passed to a callee
that runs it under the guard — `update_aliases` invokes its `edit` argument
with the state held, so the closure written at the call site is as much inside
the region as `update_aliases` is. A `&Shared` parameter is deliberately none
of these: it is the lock, not a guard, so locking inside it is the intended
pattern.

A `&self`/`&mut self` receiver in an `impl ServiceState` *is* `&ServiceState`
one position further in, so **holding `&self` on the state is holding the
guard**, and the whole body is a region — seeded, with no exception in the
tree. Nothing is ever handed a `ServiceState` that no mutex owns: the one
place that used to be, `ServiceState::load_vaults`, fused the blocking
vault-directory scan to the pure merge and was called on the owned value one
line before `Arc::new(Mutex::new(state))`. It is gone. Startup takes the two
steps `Reload` had always taken — the free `scan_vault_dir`, which takes no
state precisely so it can never run behind a receiver, and then `merge_scan`,
which is allocation-only. **Nothing blocking may sit behind a receiver on
`ServiceState`**; if a blocking half needs the state's fields, clone them out
and pass them to a free function. Seeding is the stronger rule and it is why
it is worth restoring: a blocking receiver method is reported the moment it is
written, not when it first acquires a guarded caller.

The hole a seed cannot see is a method nothing calls at all, and it is closed
by naming it: a `&self` method on `ServiceState` that blocks, or takes a lock,
and that no production caller reaches is reported as **dead and dangerous**.
"Nothing calls it" is not a defence there — the only caller such a method can
ever gain is one that already holds the guard, so the fix is deletion, not a
carefully placed call — and it is what both `unique_collection_id` and
`save_aliases` were before they were deleted, each kept alive by its own unit
tests.

Run `cargo fmt` before trusting a failure from any of this — it reads
formatted source.

Argon2 at the real cost makes tests slow, so tests use
`KdfParams::FAST_FOR_TESTS`, exposed to integration tests through the
`test-util` feature and a self dev-dependency.

`secret-tool` and `ssh-keygen` are used by some tests when present, which is
how libsecret interop is checked.

## Fuzzing

Two layers, and `docs/fuzzing.md` is the full guide. `tests/prop_*.rs` are
bounded proptest cases that run on stable in a plain `cargo test`;
`fuzz/` holds cargo-fuzz/libFuzzer targets that need nightly and run for as
long as you give them. Both encode the *same* invariants, so the fast layer
guards every commit and the slow layer explores.

```sh
make fuzz                     # 60s per target
make fuzz-one TARGET=vault_decode FUZZ_TIME=900
make fuzz-long                # 1 hour per target, before a release
```

`fuzz/` is a standalone crate with its own `[workspace]`, and the parent
manifest excludes it, so a normal `cargo build` never sees it — **and neither
does any gate**: `cargo test`, `cargo clippy --all-targets` and
`cargo fmt --check` all stay green while the fuzz crate does not compile.
Adding a field to a type the targets construct is enough to break it. Run the
`cargo +nightly check --manifest-path fuzz/Cargo.toml --all-targets` above, or
`make test`, which now does. It enables the
`fuzzing` feature, which exposes `src/fuzz_api.rs` — thin wrappers over
`pub(crate)` helpers that sit on attacker-fed input. Nothing we ship sets
that feature, and it must not be used to widen the real API.

The targets are **structure-aware** on purpose: random bytes bounce off the
magic number and the length prefix and never reach the interesting code, so
`fuzz/src/lib.rs` generates inputs already well-formed in the boring respects
and hostile in the interesting ones. Adding a target means writing the file,
adding a `[[bin]]`, and adding it to `FUZZ_TARGETS` in the Makefile — all
three are cross-checked by `tests/packaging.rs`, because a target that is
never run looks like coverage and isn't.
