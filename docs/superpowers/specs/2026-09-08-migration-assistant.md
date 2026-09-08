# secret-manager migration assistant

Date: 2026-09-08
Status: implemented (`src/cli/import.rs`, wired as `Command::Import`). The
KWallet and gnome-keyring decommissioning steps remain reasoned rather than
verified on a live desktop session; everything else here is built, and the
fingerprint definition below was tightened during implementation

## Goal

`sm import`, a subcommand that moves a user's existing secrets out of
gnome-keyring or KWallet and into a secret-manager vault, tells them honestly
what survived the move, and proves it before suggesting they turn the old
service off.

The measure of success is not "the bytes were copied". It is **the client
still finds its secret**. Chrome, `git-credential-libsecret` and
`nm-applet` look secrets up by *attribute set*, never by label. An import
that alters, normalises, synthesises or drops one attribute pair produces a
vault that looks complete and is useless to the application that wrote it.
Everything below follows from that.

Out of scope: PKCS#11 objects and certificates, gnome-keyring's ssh-agent
function, KWallet's per-application access lists (no target exists — see
"What cannot survive"), writing back to either source, and any form of
two-way sync. Importing *into* an existing collection is also out of scope,
for a reason given under "Why a new collection, always".

## What migration can and cannot promise

This is the part to get right before any code is written, because the
honest answer is different for the two sources and different again per item.
The assistant sorts every item into one of three outcomes and reports the
tally:

**Fully portable.** The item carries an `xdg:schema` attribute. Copy the
attribute map verbatim and the application that wrote it will find it again
with no configuration. This is the good case and, on real data, it is most
of them.

**Attributes preserved, discoverability uncertain.** The item has a
meaningful attribute set but no `xdg:schema` — the `(server, type, user)`
shape that `ksshaskpass` and network clients write, for instance. libsecret's
matching is lenient about a missing schema on some lookup paths and not
others. The import copies what is there and says plainly that it cannot
promise the client will match.

**Preserved only.** A native KWallet entry, whose identity is
`(folder, key)` and which has no attributes at all. The label, the bytes, the
folder, the type and the timestamps all survive, and `sm list` and `sm get`
will find it. No libsecret client that did not write it ever will.

That last case is worth stating without hedging, because it is the one a
migration tool is tempted to lie about. **There is no rule that turns
`("Passwords", "my router")` into `{xdg:schema: …, server: …, user: …}`.**
Any schema the importer invents is a guess about what some future client
will query for, and a wrong guess is worse than an absent one: it produces an
item that looks migrated and is unreachable. So the assistant never
synthesises an attribute. It reports the count and moves on.

Measured on the author's machine, the KWallet split is 38 fully portable of
66 — because those items were written *through* KWallet's Secret Service
bridge by libsecret clients, not by KDE applications. That is a much better
outcome than the pessimistic reading suggests, and it is the reason the
three-way tally exists rather than a blanket warning.

## Establishing which source you are actually talking to

The obvious design — connect to `org.freedesktop.secrets`, enumerate, copy —
has a failure that is not theoretical. On the author's machine that name is
owned by `/usr/bin/ksecretd`, KWallet's Secret Service bridge, while
gnome-keyring is masked and its keyring files sit unread on disk. A user
asking to migrate gnome-keyring would have silently migrated their KWallet
data instead, and the verification step would have agreed with itself,
because both halves would have been reading the same wrong source.

So, before anything else:

```
busctl --user status org.freedesktop.secrets   → PID
ps -p <PID> -o cmd=                            → identity
```

`sm import --from gnome-keyring` **refuses to use the session-bus route**
unless that command names `gnome-keyring-daemon`. It says who does own the
name and what to do about it. This check is not advisory and has no override
flag; a `--from` that disagrees with the bus is a user error worth stopping
for, not a warning worth printing.

KWallet needs no such check, because the assistant does not use the Secret
Service name for it at all (see below).

## Sources

### gnome-keyring

Keyrings live in `$XDG_DATA_HOME/keyrings/`. A one-line `default` file names
the keyring that holds the `default` alias — the basename, no suffix.

`*.keyring` files are the legacy binary format: magic
`GnomeKeyring\n\r\0\n`, then `major`, `minor`, a crypto id and a hash id.
The assistant refuses anything other than `major=0, minor=0`.

The header is followed by a **cleartext item index** — item ids, item types,
and attribute *key names*, with attribute values stored as unsalted MD5. It
exists so gnome-keyring can answer `SearchItems` while locked.

The exact layout, verified against real files during implementation (the
first draft of this spec described it only loosely, and the difference
matters): each item is `id u32 | type u32 | attr_count u32`, and each
attribute is `u32 len + name | u32 attr_type`, followed — for `attr_type = 0`,
a string — by a *length-prefixed 32-character lowercase hex* rendering of the
MD5, not sixteen raw bytes; for `attr_type = 1`, a uint32, by a bare `u32`
hash. `0xFFFFFFFF` is the NULL string marker. A `u32` ciphertext length sits
between the index and the encrypted body, and `offset + len` equals the file
length on both real files.

Two consequences, and the spec uses both:

- It is a free, password-free **inventory**: how many keyrings, how many
  items, which attribute names, which item types. `sm import --inventory`
  prints this and exits, so a user can see what a migration would involve
  before committing to typing a password.
- It is an independent **count** to check the extraction against. If the
  file says 28 items and the D-Bus walk yielded 27, something was skipped
  and the assistant must say so rather than reporting success.

The encrypted half is AES-128-CBC under an iterated-MD5 key derivation, with
an MD5 digest of the plaintext prepended for integrity. Iteration counts are
per-file and calibrated at creation — 3457 and 1166 in the two files
measured here, which is weak by any modern standard. **The assistant does not
implement this.** See "Why we do not parse the encrypted half".

`login.keyring` is unlocked by the login password, delivered by
`pam_gnome_keyring`. It typically contains a *chained keyring password* — a
secret whose purpose is to unlock another keyring. Importing that as if it
were a user secret would copy an unlock credential into a different trust
domain, so items of that type are **refused, listed, and not written**.

The type numbering is gnome-keyring's own: 3 is a chained keyring password,
4 an encryption-key password. But every item in the cleartext index of both
real files here carries type `0`, so **the plaintext index may not be a
reliable source for this refusal** and it should be made on the live walk,
against the item's D-Bus `Type`, with the index used only as a hint. Confirm
before relying on either — the type property is already listed under "Open
questions".

The in-memory `session` collection is never on disk and dies with the
daemon. Skipped silently.

`user.keystore` is a different format entirely (`Gnome Keyring Store 2`) and
holds PKCS#11 objects. Out of scope, never parsed, and the subject of a
warning under "Decommissioning".

### KWallet

`~/.local/share/kwalletd/kdewallet.kwl`: magic `KWALLET\n\r\0\r\n`, then
`major=0`, `minor=1`, a cipher id and a hash id. Minor 1 is the KWallet5/6
format — Blowfish under a PBKDF2 key derived with the 56-byte
`kdewallet.salt`. As with gnome-keyring, the assistant reads the header to
identify and refuse unknown versions, and does not decrypt.

Its header is likewise a cleartext index, of `MD5(folderName)` and
`MD5(entryName)`, giving folder and entry *counts* with no password. Same two
uses: inventory, and a count to verify against.

The interesting file is **`kdewallet_attributes.json`**, unencrypted, mode
`0600`. It holds, for all 66 entries measured here, keyed by
`"<folder>/<entry>"`:

```jsonc
{ "$fdo_created": "…", "$fdo_modified": "…",
  "$fdo_mime_type": "text/plain",
  "attributes": { /* the libsecret attribute map, keys and values, in clear */ } }
```

This exists because the Secret Service API requires attribute lookup on a
*locked* collection and the wallet format has nowhere to put attributes. For
the importer it is a gift: **every attribute, content type and timestamp can
be read with the wallet locked.** Only the secret bytes need it open.

It is also worth recording in the comparison this project's README already
invites. `[vault] locked_search = true` stores
`SHA-256(index_salt || len(key) || key || value)` — a file holder can
*confirm a guess*. KWallet's sidecar hands over `server=`, `user=`, `url=`
values with no guessing, and the `.kwl` index adds unsalted MD5 of every
folder and entry name. Our documented trade is the weaker disclosure of the
two, and `locked_search = false` has no KWallet equivalent. That belongs in
`docs/install-common.md`, stated as fact rather than as a boast.

## Extraction

### Why we do not parse the encrypted half

Both formats are easy to *parse* and hard to *decrypt safely*. The
gnome-keyring path needs iterated-MD5 key derivation and AES-128-CBC; the
KWallet path needs PBKDF2-SHA512 and Blowfish-CBC. Neither primitive exists
in this codebase, and adding MD5, AES-CBC and Blowfish to a project whose
entire cryptographic surface is Argon2id and XChaCha20-Poly1305 — for a
one-shot tool — is a bad trade on its own terms.

The decisive argument is the failure mode. A subtly wrong key derivation
produces garbage indistinguishable from a wrong password, so the user is told
"wrong password" when the truth is "our KDF is broken". That is precisely
the class of bug that cannot be caught by testing against our own output,
because our own output would be wrong in both directions.

So: **cleartext headers are parsed, ciphertext is never touched.** Secrets
come from the source's own daemon, which already has the key material and
whose KDF is by definition correct.

### gnome-keyring: a private bus

Since our daemon wants `org.freedesktop.secrets` and gnome-keyring provides
it, the two cannot both hold it. The assistant sidesteps the conflict rather
than negotiating it:

1. Start a private session bus (`dbus-daemon --session --print-address`),
   exported only to the child.
2. Start `gnome-keyring-daemon --start --foreground --components=secrets`
   against that bus, with a private `--control-directory` so it cannot
   collide with a real `/run/user/<uid>/keyring`.
3. Unlock: `--unlock` reads the login password from **stdin**, never argv.
4. Enumerate and read over the standard Secret Service API on the private
   bus.

The real daemon on the real session bus is untouched throughout, so a
migration can be run *after* installing secret-manager — which is when users
discover they need one.

**The sharp edge is prompts.** A keyring that is not the login keyring and
is not chained to it requires an unlock prompt, and on a private bus with no
prompter running, `Unlock` returns a prompt path that will never complete.
The assistant must treat "prompt cannot be answered" as a named, reported
error with a timeout — never a block. This is the most likely way the tool
hangs in the field and it deserves an explicit test.

### KWallet: no private bus needed

KWallet's own service, `org.kde.kwalletd6`, is a *different bus name* from
`org.freedesktop.secrets`. The assistant talks to it directly while
secret-manager holds the Secret Service name — no private bus, no
displacement, no ordering constraint. This is strictly simpler than the
gnome-keyring path and should be implemented first.

Enumeration is blind and total: `wallets()` → `openAsync(name, 0, appid,
false)` → wait for `walletAsyncOpened` → `folderList` → `entryList` →
`entryType` → `readPassword` / `readMap` / `readEntry`. Use `openAsync`, not
`open`: `open` blocks while an unlock dialog is up.

Two operational notes. `appid` becomes persistent state in the wallet's
access list, so the assistant uses a stable, honest one:
`secret-manager-import`. And the unlock dialog is a Qt widget needing a
display — over SSH with no display it cannot appear, so the assistant
requires the wallet to be already open in that case and says so plainly
rather than waiting. With `pam_kwallet5` in the stack, which is the normal
KDE configuration, the wallet is already open and no dialog occurs at all.

`kwallet-query` is not used. It cannot enumerate folders, cannot read `Map`
or `Stream` entries, cannot report an entry's type, and prints secrets to
stdout — into the terminal's scrollback and the user's shell history. It is
a fine tool for a human spot-check and an unacceptable transport.

## Mapping

### gnome-keyring

Near-total. A keyring becomes a collection; an item becomes an item;
attributes are copied byte-for-byte; `Created`/`Modified` carry across; the
`default` file becomes the `default` alias. Item types other than generic
have no target — our daemon exposes no `Type` property — so they flatten,
and the report says which items lost a type.

### KWallet

The models do not correspond, and the mapping is a decision rather than a
translation:

| KWallet | secret-manager |
|---|---|
| wallet | collection |
| folder | attribute `kwallet:folder` |
| entry name | `label`, plus attribute `kwallet:key` |
| `Password` value | secret, `text/plain` |
| `Stream` value | secret, `application/octet-stream` |
| `Map` value | secret as canonical JSON, `application/json` |
| entry type | attribute `kwallet:type` |
| `$fdo_*` sidecar fields | `created`, `modified`, `content_type` |
| `attributes` sidecar | merged into item attributes verbatim |

Folder becomes an attribute rather than a collection because one vault file
per folder is absurd for 25 folders and 66 items, and because libsecret
clients search the default collection. `(kwallet:folder, kwallet:key)` is the
uniqueness key, which also makes re-import idempotent.

A `Map` entry has no single secret. It is serialised whole, as canonical
JSON, rather than exploded into one item per key: exploding invents items
that never existed and makes any future round-trip ambiguous. Maps are rare —
one of 66 entries here is non-text.

This mapping is not invented. KWallet's own bridge reached the same shape
from the other direction: `ksecretd` stores incoming Secret Service items in
a single flat wallet folder literally named `Secret Service`, uses integer
item ids decoupled from folder and entry names, and keeps attributes,
content type and timestamps in the JSON sidecar because the wallet format
cannot hold them.

### The `kwallet:` prefix is namespace pollution, deliberately

Adding `kwallet:folder` to an item's attribute map **changes its identity**,
because our `replace` semantics compare the whole map for equality and
libsecret clients match on subsets. For an item that already carries an
`xdg:schema`, adding keys is a real risk: a client searching its exact
recorded attribute set still matches (subset matching), but any client
comparing maps for equality does not.

The decision: **`kwallet:` attributes are added only to items that have no
`xdg:schema`.** A fully portable item is copied with its attribute map
untouched, exactly as libsecret wrote it, and its KWallet provenance is
recorded in the import report rather than in the vault. Provenance is worth
less than a working lookup.

## Import

### Why a new collection, always

`sm import` writes a **new** collection and never merges into an existing
one. Three reasons, in descending order of severity:

`Reload` does not re-read a collection the daemon already holds — the scan
skips ids in `already_loaded`. An offline write into a live collection is
therefore invisible until restart, and the daemon's next save serialises its
own in-memory item list straight over the top of it. The import would appear
to succeed and then silently vanish.

A new collection is safe to create beside a running daemon regardless:
`Vault::create` publishes with `RENAME_NOREPLACE`, so the create either wins
or fails cleanly, and `sm reload` picks up an id that was not already
loaded.

And it is reversible. If the import is wrong, the user deletes one file and
has lost nothing. Merging into `default` mixes imported items with real ones
and there is no undo.

The `default` alias is left alone unless the user passes `--set-default`.

### Timestamps require a new vault API

`created` and `modified` are assigned by `insert_item`, never supplied, and
`Item.Created`/`Item.Modified` are read-only D-Bus properties with no setter.
Every existing write path stamps `now()`.

This matters more than it looks. `sm get` breaks an attribute-set collision
by choosing the newest `modified` and warning. An import that lands 66 items
at the same instant destroys that ordering, so the tie-break becomes
arbitrary exactly where the user has duplicate-looking credentials — the case
where choosing correctly matters most.

Both sources have the data: gnome-keyring stores per-item ctime/mtime,
KWallet's sidecar stores `$fdo_created`/`$fdo_modified` as unix seconds. So
the spec adds one library API:

```rust
impl Vault {
    /// Insert many items with their original timestamps, in one save.
    pub fn import_items(&mut self, items: Vec<ImportItem>) -> Result<(), VaultError>;
}
```

`ImportItem` carries label, attributes, secret, content type, `created` and
`modified`. Ids remain daemon-assigned — nothing needs to preserve them, and
letting a caller choose one invites collisions.

### One save, not N

Every `CreateItem` today re-encrypts the entire collection and performs two
fsyncs: build the whole hashed index, postcard-encode every item, seal the
whole blob, write a temp file, fsync it, rename, fsync the directory. A
500-item import through that path is 500 full re-encrypts and 1000 fsyncs,
writing O(N²) bytes — hundreds of megabytes for a few hundred kilobytes of
secrets.

`import_items` therefore validates every element first, mutates the vector
once, and saves once, with whole-list rollback if the save fails. The
precedent is `Vault::delete_items`, which already has exactly this shape, and
its doc comments are effectively the specification for this one.

### The offline path bypasses every cap, so the importer re-applies them

This is the trap in the design and it must be written down. Every per-item
limit lives in the D-Bus layer, not in the vault:

| Limit | Value |
|---|---|
| `MAX_ITEM_SECRET` | 1 MiB |
| `MAX_ITEM_LABEL` | 4 KiB |
| `MAX_ITEM_ATTRIBUTES` | 64 pairs |
| `MAX_ATTRIBUTE_KEY` | 256 B |
| `MAX_ATTRIBUTE_VALUE` | 512 B |
| `MAX_ITEM_CONTENT_TYPE` | 256 B |

`Vault::insert_item` enforces none of them. An importer writing vault files
directly could therefore produce a collection the daemon serves happily but
which **no D-Bus client could ever have created**, and whose items may be
unreadable or unmodifiable through the very API they exist to be reached by.

`import_items` re-applies all six, and the assistant checks every item
against them **before writing anything**, reporting which items would be
rejected. A migration that fails halfway leaves the user worse off than one
that refuses at the start.

### Encoding

Attribute keys, values, labels and content types are Rust `String`. A source
attribute containing non-UTF-8 bytes **cannot be represented**. Lossy
conversion is not acceptable here: it changes the attribute, and a changed
attribute is a silently broken lookup, which is the exact failure this whole
document is organised around. Such items are refused and listed.

Secrets are `Vec<u8>` and may hold arbitrary bytes including NUL, so binary
values need no special handling — provided they never go through `sm set`,
which strips one trailing newline unconditionally and would corrupt any
secret whose final byte is `0x0a`. The importer uses the library API
directly and never shells out to its own CLI.

## Verification

The import is not finished when the bytes are written. It is finished when
the assistant has proved the copy is faithful, without printing a single
secret.

**Fingerprints.** For each item, source and destination:

```
fp = SHA-256( canonical_attrs || u64be(len label) || label
              || u64be(len content_type) || content_type || SHA-256(secret) )
canonical_attrs = for (k,v) sorted by k:  u64be(len k) || k || u64be(len v) || v
```

The length prefixes are load-bearing — without them `{"a":"bc"}` and
`{"ab":"c"}` collide. Implementation tightened this twice against the first
draft: the prefixes are `u64be`, not `u32be`, since a `u32` truncates above
4 GiB and reintroduces the ambiguity it exists to remove; and `label` and
`content_type` are length-prefixed too rather than joined with `0x00`, because
a Rust `String` may contain NUL and two different items could otherwise share
a fingerprint. The sorted fingerprint lists must match; mismatches are
reported by attribute *keys* and object path, never values.

**An independent count.** Both sources' cleartext headers give an item count
with no password. If the file says 28 and the walk produced 27, the import
failed regardless of what the fingerprints agree on. For KWallet there is a
stronger version: recompute `MD5(folder)` and `MD5(key)` for every imported
item and assert membership in the `.kwl` hash table, proving no name was
mangled, using only hashes.

**A lookup probe, which is the one that matters.** For each distinct source
attribute set, issue `SearchItems` against the running daemon with exactly
those attributes and assert it returns exactly one item. The fingerprints
prove the data copied; this proves it is *findable*, which is the actual
promise. Its pass/fail counts are what populate the three-way tally.

**Secret-length histogram**, source versus destination, bucketed. Catches
truncation and encoding bugs — a stripped trailing NUL, a UTF-8
re-encoding — that fingerprints would also catch but that a histogram
localises.

The assistant never deletes or modifies a source file. Verification earns the
right to *suggest* decommissioning, printed as commands the user runs
themselves.

## Decommissioning

`docs/install-arch.md` and `docs/install-debian.md` cover replacing both
providers, and the assistant references them rather than restating them.
Research for this spec found four gaps in those documents; they have since
been fixed there, which is where they belonged:

- XDG autostart, which starts gnome-keyring from a desktop session even with
  the systemd unit masked.
- A warning that masking the unit removes the user's PKCS#11 provider too,
  since the packaged unit runs `pkcs11,secrets` as one process.
- Real KWallet instructions. The previous single sentence pointed at a GUI
  and was wrong in the case that matters: `ksecretd` claims the bus name at
  runtime and holds it even when the system activation file names
  gnome-keyring, so the documented `cp` does not displace it.
- `pam_kwallet5` in the login stacks, and the two further bus names
  `ksecretd` owns — including the xdg-desktop-portal Secret backend, which
  keeps routing sandboxed applications to KWallet after the main name is
  taken.

The assistant adds one thing itself, because it is a consequence of
migrating rather than of installing: `ksecretd` holds the bus name for the
life of the session, so a log-out and back in is required. Anything short of
that leaves the old provider in place and the user concluding the migration
failed.

## What cannot survive

Named here so the report can name them too:

- **gnome-keyring application ACLs.** Format 0 records, per item, which
  executables may read it without prompting. Secret Service has no
  equivalent and neither do we, so "only `/usr/bin/foo` may read this"
  becomes "anything on the session bus may read this". This is a security
  downgrade at the migration boundary and is reported per item, loudly — not
  as a footnote.
- **KWallet per-application access control**, the same downgrade from the
  other direction.
- **Empty KWallet folders.** Four of 25 here. A collection-of-items model has
  nowhere to put a folder with no entries; they are simply lost, and the
  report says how many.
- **Item types.** gnome-keyring's `NETWORK_PASSWORD`, `NOTE` and friends, and
  KWallet's folder semantics, flatten to attributes or vanish.
- **Chained and encryption-key items**, refused rather than imported.
- **`localWallet()`/`networkWallet()`**, which has no analogue in aliases.
- **GPG-backed KWallet wallets**, whose unlock model is a GnuPG key rather
  than a password. Readable via `kwalletd6`, but nothing about the unlock
  transfers.

## CLI surface

```
sm import --from gnome-keyring|kwallet [options]
  --inventory              read cleartext headers only; print and exit
  --dry-run                extract and check, write nothing
  --collection LABEL       destination label (default: source name)
  --set-default            point the `default` alias at the result
  --report PATH            write the per-item report as JSON
```

`--inventory` needs no password and no daemon. `--dry-run` performs the full
extraction and every pre-flight check, then discards — the intended first
run, since it surfaces the three-way tally and any cap violations before
anything is written.

A subcommand rather than a second binary: `src/cli/` is already entirely
behind the `daemon` feature, so the feature-guard cost is zero, whereas a new
`[[bin]]` would need `required-features`, Makefile install/uninstall changes
and updates to `tests/packaging.rs`. The extraction and mapping logic lives
under `src/vault/` or a sibling module that does not pull in zbus, so it
stays reachable from a non-`daemon` build; only the D-Bus transports need the
feature.

## Testing

The existing fixture already does most of this. `tests/common/mod.rs` starts
a private `dbus-daemon`, a daemon with `KdfParams::FAST_FOR_TESTS`, and a
scripted pinentry, and three existing tests drive a real `secret-tool`
against it — which is the same shape as driving a real source daemon.

What is new:

- **A two-bus fixture.** The current one's daemon already owns
  `org.freedesktop.secrets` on its bus, so a source-daemon fixture needs a
  second bus. This is the piece to build first; the gnome-keyring path
  cannot be tested honestly without it.
- **Golden files.** A small `.keyring` and a small `.kwl` with a known
  password, committed as fixtures, so the header parsers and the inventory
  counts are tested against real bytes rather than against our own encoder.
- **The unanswerable-prompt case**, asserted to time out with the named
  error rather than block.
- **Fidelity properties**, in the style of `tests/invariants.rs`: attributes
  survive a round trip byte-for-byte for arbitrary UTF-8 keys and values; a
  non-UTF-8 attribute is refused rather than converted; a secret ending in
  `0x0a` survives; timestamps land exactly.
- **Cap enforcement**, asserting `import_items` rejects each of the six
  limits — because that is the one place where the offline path could
  silently produce items the D-Bus API could not.

## Open questions

Flagged rather than guessed, because a confident wrong claim about a foreign
format becomes a wrong implementation:

- The exact iterated-MD5 derivation and MD5-prefix integrity check in
  gnome-keyring's format 0. Confirmed in shape from the on-disk structure;
  read `egg/egg-symkey.c` before relying on it. Only matters if the offline
  decryption fallback is ever built, which this spec declines.
- KWallet's cipher and hash enum numbering (`3` and `2` observed). Corroborated
  by the 56-byte salt and a body that is an exact multiple of the Blowfish
  block size, but verify against `backendpersisthandler.cpp`.
- `KWallet::Wallet::EntryType` numbering, and whether `readMap` returns a Qt
  `QDataStream`-serialised `QMap<QString,QString>` — which would need
  decoding in Rust, and is the one place the KWallet path might need real
  work.
- gnome-keyring's non-standard `Item.Type` D-Bus property and its value
  strings.
- The exact stdin terminator `gnome-keyring-daemon --unlock` expects.
- Whether a `uint32`-typed attribute is rendered as its decimal string on the
  Secret Service surface. If it is not, a value like `port` round-trips
  wrongly and breaks a lookup silently.
