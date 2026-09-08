# Fuzzing

Two layers, deliberately:

- **`tests/prop_*.rs`** — bounded [proptest] cases that run on stable in a
  plain `cargo test`. They encode the same invariants as the fuzz targets, so
  every commit enforces them and a regression fails CI immediately.
- **`fuzz/`** — [cargo-fuzz]/libFuzzer targets that run for as long as you
  give them. They need nightly, and they explore far past what a bounded
  property test reaches.

If you only do one thing: `cargo test` already covers the invariants. Reach
for `make fuzz` when you touch anything that parses bytes you did not write.

## Running

```sh
make fuzz-list                                  # the target names
make fuzz                                       # 60s per target (smoke)
make fuzz FUZZ_TIME=600                         # 10 min per target
make fuzz-long                                  # 1 hour per target
make fuzz-one TARGET=vault_decode FUZZ_TIME=900 # one target, longer
make fuzz-coverage TARGET=vault_decode          # needs llvm-tools-preview
```

`make fuzz` exits non-zero on the first crash and leaves the offending input
in `fuzz/artifacts/<target>/`.

## When a target crashes

```sh
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<file>   # minimize
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>    # replay
```

Then **turn it into a regression test** in the crate's own suite and fix the
bug. Do not commit the raw artifact — `fuzz/artifacts/` is gitignored on
purpose. A crashing input that only exists as a binary blob in the repo is
evidence nobody reads; the same input as a named test is a permanent guard.

## Why the targets are structure-aware

A fuzzer fed uniformly random bytes spends essentially its whole budget being
rejected by the first few checks in a parser — the 8-byte magic, the length
prefix, a postcard tag, an AEAD tag. It never reaches the code that
manipulates attacker-controlled *values*.

So `fuzz/src/lib.rs` (crate `smfuzz`) builds inputs that are already
well-formed in the uninteresting respects and hostile in the interesting
ones: a real magic number with an absurd length prefix, a valid header with
a hostile label and an out-of-range KDF cost, a correct frame prefix wrapping
a truncated body. `hostile_string` biases towards the characters that are the
entire attack surface of the sanitisers — quotes, parens, controls, bidi
overrides, invisible formatters.

Targets that also want the dumb "not a vault at all" case still get it: every
generator is reachable from raw bytes, and several targets fuzz the raw form
alongside the structured one.

## The corpus

`fuzz/corpus/<target>/seed-*` are hand-written seeds and **are committed** —
they are what gets a fuzzer past the magic number on a cold start. Everything
else libFuzzer writes into the corpus during a run is gitignored: it is large,
uninteresting to read, and regenerable.

`fuzz/dictionaries/*.dict` give libFuzzer the literal tokens that matter
(magic bytes, protocol keywords, the punctuation the consent dialogs are
built from), which it cannot discover by mutation alone.

## What each target covers

| Target | Attacker-controlled input | Core invariant |
|---|---|---|
| `vault_decode` | the vault file, before any authentication | no panic; peak allocation stays inside a bound derived from the input length, measured by a `GlobalAlloc` counter rather than left to libFuzzer's `-rss_limit_mb`; a declared header length above `MAX_HEADER` is refused before anything is sized by it; `aad` is exactly the parsed prefix, and covers every byte the decoder consumed |
| `vault_roundtrip` | a header | encode/decode is an identity, so the AEAD-authenticated prefix really describes the parsed header |
| `vault_open_unlock` | a sealed vault | a wrong key never opens it; any corruption fails rather than yielding plaintext |
| `vault_items_codec` | the decrypted item blob | round-trips; hostile bytes never panic |
| `kdf_params` | KDF cost in an unauthenticated header | out-of-range costs are refused *before* Argon2 runs |
| `attribute_index` | the hashed search index | hashing is deterministic and salt-dependent; index hits match real attribute matches |
| `protocol_frame` | the control socket | oversized frames refused, never allocated; truncation is an error |
| `protocol_roundtrip` | control requests | exact round-trip, and variant indices are pinned (postcard encodes them positionally, so reordering is a silent wire break) |
| `dh_peer_public` | a D-Bus client's DH public key | degenerate and small-subgroup values rejected; no panic on any length |
| `session_cipher` | session ciphertext | round-trips; corruption never returns the original plaintext |
| `display_label` | a collection label rendered into a consent dialog | output cannot reproduce the dialog's own punctuation, is bounded, and is idempotent |
| `escape_control_sanitize` | attribute values, and PAM text reaching syslog | no control or bidi characters survive; benign input is unchanged |
| `pinentry_escape` | a hostile pinentry server's reply | escape/unescape round-trips; malformed escapes never panic |
| `dbus_paths` | client-supplied object paths | parse/construct round-trips; no component ever contains `/` |
| `askpass_prompt` | the prompt OpenSSH hands to `SSH_ASKPASS` | any released path is absolute, non-empty, and newline-free |
| `config_toml` | the config file | no panic; an accepted config has sane KDF parameters |

## Adding a target

1. Write `fuzz/fuzz_targets/<name>.rs`.
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add the name to `FUZZ_TARGETS` in the `Makefile`.

Steps 2 and 3 are checked against each other by
`tests/packaging.rs::every_fuzz_target_is_declared_and_runnable`, so a target
that exists but is never run — the worst kind, because it looks like coverage
— fails the suite.

[proptest]: https://docs.rs/proptest
[cargo-fuzz]: https://rust-fuzz.github.io/book/cargo-fuzz.html
