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
protocol v3 has no password-carrying request. Both the CLI and the PAM module
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

**Daemon state** (`src/dbus/state.rs`) lives behind one async mutex. Two rules
follow: never hold it across an `.await` that can block, and never run Argon2
under it — every derivation goes through `src/kdf.rs`, which caps concurrency
and moves the work to the blocking pool.

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
  break existing vaults — pre-release, there is no migration, so the daemon
  tells the user to recreate.
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
manifest excludes it, so a normal `cargo build` never sees it. It enables the
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
