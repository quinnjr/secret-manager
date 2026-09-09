//! `sm import`: moving a user's secrets out of gnome-keyring or KWallet.
//!
//! The measure of success is not that the bytes were copied — it is that the
//! client still finds its secret. Chrome, `git-credential-libsecret` and
//! `nm-applet` look secrets up by *attribute set*, never by label, so an
//! import that alters, normalises, synthesises or drops one attribute pair
//! produces a vault that looks complete and is useless to the application
//! that wrote it. Every type here follows from that: attributes are carried
//! verbatim or the item is refused, and nothing is ever invented.
//!
//! The module is split four ways. [`formats`] parses the **cleartext**
//! headers of both source formats — no password, no daemon, no decryption —
//! which is what `--inventory` prints and what gives verification an
//! independent item count. [`gnome`] and [`kwallet`] drive each source's own
//! daemon for the secret bytes, because that daemon's key derivation is by
//! definition correct and ours would be a guess. [`verify`] proves the copy.
//!
//! ## The report carries keys, never values
//!
//! [`ImportReport`] is written to a file the user may paste into a bug
//! report. It therefore holds no secret, and no attribute *value* either:
//! values are `server=`, `user=`, `url=` — the very disclosure this project
//! criticises KWallet's sidecar for. The type system enforces it rather than
//! a review comment: an [`ItemReport`] can only hold [`AttributeKeys`], which
//! has no constructor that keeps a value, and mismatches are reported by key
//! and object path exactly as the spec's verification section requires.

pub mod formats;
pub mod gnome;
pub mod kwallet;
pub mod verify;

use crate::vault::format::CapViolation;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

/// The attribute every libsecret client writes and searches on. Its presence
/// is what separates a fully portable item from a merely preserved one.
pub const XDG_SCHEMA: &str = "xdg:schema";

/// Attribute names this importer *synthesises*, which therefore say nothing
/// about whether any client can find the item.
///
/// `kwallet::map_entry` adds exactly these three to exactly the entries that
/// arrived with no attributes at all — a native KWallet entry, whose identity
/// is `(folder, key)`. They are provenance we wrote, not a searchable
/// attribute set the source wrote, and no libsecret client has ever searched
/// on `kwallet:folder`. Counting them as "attributes preserved" would report
/// the one case a migration tool is tempted to lie about as "might work" when
/// the truth is [`Outcome::PreservedOnly`], so [`Outcome::classify`] ignores
/// them.
///
/// The names live here, beside the classifier that must know them, and
/// `kwallet` is their single definition — a second copy of the strings is the
/// only way the two could drift apart.
pub const SYNTHESISED_ATTRIBUTES: [&str; 3] =
    [kwallet::ATTR_FOLDER, kwallet::ATTR_KEY, kwallet::ATTR_TYPE];

/// True for an attribute name this importer invented **on the KWallet
/// path**, which is the only path that synthesises anything. See
/// [`SYNTHESISED_ATTRIBUTES`].
///
/// The source is a parameter so that the discount stops at the KWallet path:
/// `kwallet:` is a user-writable namespace, so a gnome-keyring item may
/// genuinely carry an attribute named `kwallet:folder` — unlikely, but a real,
/// searchable attribute that nothing here wrote, and discounting it would
/// misreport the item as [`Outcome::PreservedOnly`].
///
/// That argument does not extend to the source it excludes, and this function
/// deliberately does not pretend otherwise. A *KWallet* item can carry a real
/// `kwallet:key` too — one written into the sidecar by hand — and
/// `kwallet::map_entry` records that as an attribute conflict rather than
/// overwriting it, so the name survives into the map as user data. This
/// function discounts it anyway, and such an item is reported
/// [`Outcome::PreservedOnly`] when a client could in principle have searched
/// on it. The classification is by name, not by provenance, because the map
/// that reaches [`Outcome::classify`] no longer records which of its keys this
/// importer inserted.
///
/// The error is one-directional: it can only under-promise. An item is called
/// "no libsecret client will find it" when the truth is "probably none will",
/// never the reverse, so no user is told a migration went better than it did.
/// Making it exact means threading "did we insert this key?" out of
/// `kwallet::map_entry` and into the classifier, which is the honest fix and
/// not one a doc comment can perform.
pub fn is_synthesised_attribute(source: Source, key: &str) -> bool {
    source == Source::KWallet && SYNTHESISED_ATTRIBUTES.contains(&key)
}

/// Where an item came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Source {
    #[serde(rename = "gnome-keyring")]
    GnomeKeyring,
    #[serde(rename = "kwallet")]
    KWallet,
}

impl Source {
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::GnomeKeyring => "gnome-keyring",
            Source::KWallet => "kwallet",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which container an item was read out of, in the source's own vocabulary.
///
/// Kept beside every item because the mapping deliberately throws some of it
/// away: `kwallet:folder` is added only to items that have no `xdg:schema`
/// (adding keys to a portable item changes its identity), so for the items
/// where provenance is *not* recorded in the vault it is recorded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: Source,
    /// Keyring display name, or wallet name.
    pub container: String,
    /// KWallet folder. `None` for gnome-keyring, which has no folders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// KWallet entry name. `None` for gnome-keyring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// gnome-keyring's per-keyring item id, which the cleartext index gives
    /// us with no password. `None` for KWallet, whose entries have no id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<u32>,
}

impl Provenance {
    pub fn gnome(container: impl Into<String>, item_id: u32) -> Self {
        Self {
            source: Source::GnomeKeyring,
            container: container.into(),
            folder: None,
            entry: None,
            item_id: Some(item_id),
        }
    }

    pub fn kwallet(
        container: impl Into<String>,
        folder: impl Into<String>,
        entry: impl Into<String>,
    ) -> Self {
        Self {
            source: Source::KWallet,
            container: container.into(),
            folder: Some(folder.into()),
            entry: Some(entry.into()),
            item_id: None,
        }
    }
}

/// One item as read from a source, before any mapping.
///
/// Attributes are already `String`s here, and every route that produces one
/// hands us text that has already been UTF-8 validated: D-Bus `s` and `a{ss}`
/// are validated by the marshaller, and the KWallet sidecar is JSON, whose
/// parser rejects invalid UTF-8 outright. So there is no live path on which a
/// non-UTF-8 attribute could reach this type, and none of the lossy
/// conversions that would silently break a lookup. Should a future route ever
/// read raw attribute bytes, it must refuse the item rather than convert it —
/// and it must add the refusal variant at the same time, in the same commit
/// as the code that constructs it.
#[derive(Clone)]
pub struct SourceItem {
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    /// Unix seconds, from the source. Never `now()`: `sm get` breaks an
    /// attribute-set collision by choosing the newest `modified`, and an
    /// import that lands every item at one instant destroys that ordering
    /// exactly where the user has duplicate-looking credentials.
    pub created: u64,
    pub modified: u64,
    pub provenance: Provenance,
}

// Hand-written: the secret is redacted, and so are attribute *values*, which
// are `server=`/`user=`/`url=` and have no business in a log line either.
impl fmt::Debug for SourceItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceItem")
            .field("label", &self.label)
            .field("attribute_keys", &AttributeKeys::of(&self.attributes))
            .field("secret", &"..")
            .field("content_type", &self.content_type)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl SourceItem {
    /// See [`Outcome::classify`].
    pub fn outcome(&self) -> Outcome {
        Outcome::classify(self.provenance.source, &self.attributes)
    }

    /// The first cap this item violates, if any. Checked *before* anything is
    /// written: a migration that fails halfway leaves the user worse off than
    /// one that refuses at the start.
    pub fn cap_violation(&self) -> Option<Refusal> {
        check_caps(
            &self.label,
            &self.attributes,
            self.secret.len(),
            &self.content_type,
        )
    }
}

/// The three-way classification the spec's "What migration can and cannot
/// promise" defines. Nothing here is a judgement about the *data*: it is a
/// statement about whether a libsecret client can still find the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Carries a non-empty `xdg:schema`. Copy the attribute map verbatim and
    /// the application that wrote it finds it again with no configuration.
    FullyPortable,
    /// A meaningful attribute set but no `xdg:schema` — the
    /// `(server, type, user)` shape network clients write. libsecret's
    /// matching is lenient about a missing schema on some lookup paths and
    /// not others, so this promises the copy and not the lookup.
    AttributesPreserved,
    /// A native KWallet entry, whose identity is `(folder, key)` and which
    /// has no attributes at all. `sm list` and `sm get` find it; no libsecret
    /// client that did not write it ever will.
    PreservedOnly,
}

impl Outcome {
    /// Classify by attribute map alone.
    ///
    /// An `xdg:schema` with an *empty* value is deliberately not
    /// [`Outcome::FullyPortable`]: a client searching for
    /// `xdg:schema=org.freedesktop.Secret.Generic` does not match an empty
    /// one, so calling it portable would be the same lie as synthesising a
    /// schema outright.
    ///
    /// Attributes *we* synthesised do not count towards
    /// [`Outcome::AttributesPreserved`] either, and for the same reason. The
    /// map reaching this function has already been through
    /// `kwallet::map_entry`, which stamps [`SYNTHESISED_ATTRIBUTES`] onto
    /// precisely the schema-less items — so classifying on "the map is
    /// non-empty" would report every native KWallet entry as "might work"
    /// when what is true of it is that no libsecret client that did not write
    /// it ever will find it.
    ///
    /// The denylist is scoped to the source that has one: only
    /// `kwallet::map_entry` synthesises, so on the gnome-keyring path a
    /// `kwallet:*` attribute is an ordinary attribute somebody wrote and
    /// counts like any other.
    pub fn classify(source: Source, attributes: &BTreeMap<String, String>) -> Outcome {
        match attributes.get(XDG_SCHEMA) {
            Some(schema) if !schema.is_empty() => Outcome::FullyPortable,
            _ if attributes
                .keys()
                .any(|k| !is_synthesised_attribute(source, k.as_str())) =>
            {
                Outcome::AttributesPreserved
            }
            _ => Outcome::PreservedOnly,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::FullyPortable => "fully portable",
            Outcome::AttributesPreserved => "attributes preserved, discoverability uncertain",
            Outcome::PreservedOnly => "preserved only",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The six per-item caps, as `vault::format` defines them.
///
/// This module used to carry its own copy of the enum, the limits, the
/// `as_str`/`Display` and the ordering. `vault::format` now owns the single
/// predicate every layer shares — the D-Bus entry points, `Vault::import_items`
/// and this pre-flight — so a re-export is all that is left. Two copies of "in
/// what order, measured how, `>` or `>=`" is the drift that shows up as a
/// pre-check passing an item the write then refuses halfway through a
/// migration.
pub use crate::vault::format::Cap;

impl From<CapViolation> for Refusal {
    fn from(violation: CapViolation) -> Self {
        Refusal::CapViolation {
            cap: violation.cap,
            actual: violation.actual,
            limit: violation.limit,
        }
    }
}

/// The first cap `label`/`attributes`/`secret_len`/`content_type` violate.
///
/// The measurement is [`crate::vault::format::check_caps`]; this only maps its
/// [`CapViolation`] into the report's own vocabulary. An item the D-Bus API
/// could never have created is one `Vault::insert_item` would happily store,
/// and which no D-Bus client could then read back.
///
/// Sizes only ever reach the report as *numbers*: a `Refusal` names the cap,
/// the measured size and the limit, never the oversized value itself.
///
/// # The policy, stated once
///
/// **A cap violation refuses one item; it never aborts the migration.** The
/// violating item is listed in the report with its `Refusal` and not written,
/// and every other item is imported as normal.
///
/// This function is a *classifier*, not a gate: it is deliberately callable
/// during extraction, before a destination vault exists, so that a `--dry-run`
/// and a real run agree about which items are refusable. The rule it does not
/// state — because it belongs to the caller — is that no item may be written
/// before every item has been classified: an import that discovers the
/// twenty-eighth item is oversized after writing twenty-seven leaves the user
/// with a half-populated vault and no way to tell which half. Check first,
/// write second; refuse items, not runs.
///
/// Two callers exist, one per source, and both do what this doc says: the
/// violating item goes to the refused list and the walk continues.
/// `gnome::drain_batch` reaches it through [`SourceItem::cap_violation`];
/// `kwallet::walk` calls it directly on the mapped entry. `cli::import` does
/// **not** re-check — by the time it sees `extraction.items` every violating
/// item has already been removed from that list — so there is one policy here,
/// written down once, and no second gate that could contradict it.
pub fn check_caps(
    label: &str,
    attributes: &BTreeMap<String, String>,
    secret_len: usize,
    content_type: &str,
) -> Option<Refusal> {
    crate::vault::format::check_caps(label, attributes, secret_len, content_type).map(Refusal::from)
}

/// Why an item was not written. Every variant is one the spec names, and no
/// variant carries a secret or an attribute value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Refusal {
    /// A gnome-keyring item whose purpose is to unlock *another* keyring.
    /// Importing it would copy an unlock credential into a different trust
    /// domain, so it is refused, listed, and not written.
    ChainedKeyringItem { item_type: u32 },
    /// The item's `Type` property exists but the read of it failed or timed
    /// out, so nothing was established about what the item is.
    ///
    /// Distinct from [`Refusal::ChainedKeyringItem`] on purpose, and the
    /// distinction is the whole point: recording an unknown type as "type 3
    /// unlocks another keyring" puts a statement in a security report that is
    /// not true of the item it names. What is true is that the source daemon
    /// would not answer, and the direction that guesses "it is harmless" is
    /// the direction that imports an unlock credential.
    UnreadableItemType,
    /// The item's attribute map could not be read.
    ///
    /// Attributes are the item's identity — every libsecret client looks a
    /// secret up by attribute set — so an item whose map is unknown cannot be
    /// written: a copy with an empty or guessed map is a secret the
    /// application that wrote it will never find again. One such item refuses
    /// itself and the walk continues; the rest of the keyring is still worth
    /// importing.
    UnreadableAttributes,
    /// An item the D-Bus API could never have created. See [`Cap`].
    CapViolation {
        cap: Cap,
        actual: usize,
        limit: usize,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::ChainedKeyringItem { item_type } => write!(
                f,
                "item type {item_type} unlocks another keyring; importing it would move an \
                 unlock credential into a different trust domain"
            ),
            Refusal::UnreadableItemType => f.write_str(
                "the source daemon would not say what type this item is, and an item type \
                 that cannot be read may be an unlock credential for another keyring; \
                 unlock the source keyring and re-run the import, or copy this one item \
                 across by hand once you have checked what it is",
            ),
            Refusal::UnreadableAttributes => f.write_str(
                "the source daemon would not return this item's attributes, which are how \
                 every application finds its secret again; importing it without them would \
                 produce a copy nothing can look up. Re-run the import, and if it fails the \
                 same way copy this one item across by hand",
            ),
            Refusal::CapViolation { cap, actual, limit } => write!(
                f,
                "{cap} is {actual} bytes, over the {limit} the Secret Service API allows"
            ),
        }
    }
}

/// The attribute *names* of an item, and nothing else.
///
/// [`AttributeKeys::of`] builds one from a map whose values are dropped on the
/// way in, so no code path can put an attribute value into a report by
/// accident. That is the whole point of the newtype.
///
/// Two other doors exist and neither is a hole in *that* guarantee, because
/// what the newtype protects is the report this process writes, not the
/// contents of a file someone hands back to it.
///
/// - [`AttributeKeys::from_names`] takes arbitrary strings, so
///   `AttributeKeys::from_names(attributes.values().cloned())` compiles and
///   fills a report with `server=`/`user=` *values*. It is `pub(crate)`, which
///   reduces "no code path can do this by accident" to a claim about code in
///   this repository — a claim review can actually settle.
/// - `#[derive(Deserialize)]` with `#[serde(transparent)]` on a `pub` type is
///   a **public** constructor from any JSON array of strings, reachable by any
///   downstream crate with no `unsafe` and no crate-private call. It exists so
///   a report can be read back and its tally checked, and the strings it
///   admits are whatever the file on disk holds. So a deserialized
///   `AttributeKeys` carries only the guarantee that *whoever wrote the file*
///   put names in it; nothing this crate emits ever takes that route.
///
/// The structural fix for both is a distinct `AttributeName` type that only a
/// parser can mint, with the `Deserialize` going through it; until that
/// exists, [`AttributeKeys::of`] is the only constructor whose input shape
/// makes a value impossible.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttributeKeys(BTreeSet<String>);

impl AttributeKeys {
    /// The keys of `attributes`. The values are not read.
    pub fn of(attributes: &BTreeMap<String, String>) -> Self {
        Self(attributes.keys().cloned().collect())
    }

    /// From names that are already just names — the gnome-keyring cleartext
    /// index, which stores key names and hashed values, hands us exactly
    /// this.
    ///
    /// `pub(crate)` on purpose: it takes any strings at all, so
    /// `AttributeKeys::from_names(attributes.values().cloned())` compiles and
    /// fills a report with `server=`/`user=` *values*. Keeping it inside the
    /// crate reduces "no code path can do this by accident" to a claim about
    /// code in this repository, which is a claim review can actually settle.
    /// See the type's own doc for the other constructor — the derived,
    /// `pub`-by-inheritance `Deserialize` — and why it is not the same kind of
    /// hole.
    pub(crate) fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(names.into_iter().map(Into::into).collect())
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.0.contains(key)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Per-item outcome, with no value of any kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemReport {
    pub provenance: Provenance,
    /// The item's label. A label is UI text, not a credential, and without it
    /// a report cannot be read by the person it is for.
    pub label: String,
    pub attribute_keys: AttributeKeys,
    pub content_type: String,
    /// `None` when the item was refused and therefore has no outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub refusals: Vec<Refusal>,
    /// Length only — never the bytes. Feeds the verification histogram that
    /// localises truncation and re-encoding bugs.
    pub secret_len: usize,
    /// A source item type with no target: our daemon exposes no `Type`
    /// property, so `NETWORK_PASSWORD` and friends flatten and the report
    /// says which items lost one.
    ///
    /// Only a type this build *recognises*, because it is the on-disk
    /// format's numbering and there is no number for a string we do not know.
    /// A type the source named and this build cannot place goes in
    /// [`ItemReport::unknown_item_type`] instead — never here, and never in
    /// the `None` that means "nothing was lost".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost_item_type: Option<u32>,
    /// The item carried a `Type` this build does not recognise, verbatim
    /// except for sanitisation.
    ///
    /// A type string is not an attribute value and not a secret: it is a
    /// well-known constant the source daemon chose from, `xdg:schema`'s
    /// cousin, and printing it is the whole point — a future gnome-keyring
    /// type that flattened is a thing the reader of a migration report must be
    /// able to name. It is peer text on its way to a terminal all the same, so
    /// whoever sets it puts it through `display_label` first.
    ///
    /// Distinct from [`ItemReport::lost_item_type`] because the two say
    /// different things. `lost_item_type: None` means *nothing was lost*;
    /// folding an unrecognised type into it would report a flattened type as
    /// no type at all, which is the one thing a migration report may not do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_item_type: Option<String>,
    /// The item carried a per-application access list the Secret Service has
    /// no equivalent for. "Only `/usr/bin/foo` may read this" becomes
    /// "anything on the session bus may read this" — a security downgrade at
    /// the migration boundary, reported per item and loudly.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acl_downgrade: bool,
}

impl ItemReport {
    /// A report for an item that was written, derived from the item itself so
    /// the keys in the report are the keys in the vault.
    pub fn imported(item: &SourceItem) -> Self {
        Self {
            provenance: item.provenance.clone(),
            label: item.label.clone(),
            attribute_keys: AttributeKeys::of(&item.attributes),
            content_type: item.content_type.clone(),
            outcome: Some(item.outcome()),
            refusals: Vec::new(),
            secret_len: item.secret.len(),
            lost_item_type: None,
            unknown_item_type: None,
            acl_downgrade: false,
        }
    }

    /// A report for an item that was not written. It has no outcome: refusing
    /// is not a fourth outcome, it is the absence of one.
    pub fn refused(provenance: Provenance, label: impl Into<String>, refusal: Refusal) -> Self {
        Self {
            provenance,
            label: label.into(),
            attribute_keys: AttributeKeys::default(),
            content_type: String::new(),
            outcome: None,
            refusals: vec![refusal],
            secret_len: 0,
            lost_item_type: None,
            unknown_item_type: None,
            acl_downgrade: false,
        }
    }

    pub fn is_refused(&self) -> bool {
        !self.refusals.is_empty()
    }
}

/// The three-way tally, plus what was refused.
///
/// The counters are only ever moved by [`Tally::record_outcome`] and
/// [`Tally::record_refused`], which is what keeps a tally and the items it
/// summarises in step. The fields are private and the accessors below are the
/// only way out, so a call site cannot reach past `record_outcome` to bump a
/// counter directly; `src/cli/import.rs` prints the summary through those
/// accessors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    fully_portable: usize,
    attributes_preserved: usize,
    preserved_only: usize,
    refused: usize,
}

impl Tally {
    /// Items that were written — the three outcomes, not the refusals.
    pub fn imported(&self) -> usize {
        self.fully_portable + self.attributes_preserved + self.preserved_only
    }

    /// Items written carrying a non-empty `xdg:schema`. See
    /// [`Outcome::FullyPortable`].
    pub fn fully_portable(&self) -> usize {
        self.fully_portable
    }

    pub fn attributes_preserved(&self) -> usize {
        self.attributes_preserved
    }

    pub fn preserved_only(&self) -> usize {
        self.preserved_only
    }

    pub fn refused(&self) -> usize {
        self.refused
    }

    /// Every item the walk produced, written or not.
    pub fn seen(&self) -> usize {
        self.imported() + self.refused
    }

    /// Count one item that was written, under `outcome`.
    ///
    /// The counters are incremented here and nowhere else. `tally.refused +=
    /// 1` written at a call site is how a tally comes to disagree with the
    /// items it summarises, and the disagreement is invisible until someone
    /// reads the report and believes it.
    pub fn record_outcome(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::FullyPortable => self.fully_portable += 1,
            Outcome::AttributesPreserved => self.attributes_preserved += 1,
            Outcome::PreservedOnly => self.preserved_only += 1,
        }
    }

    /// Count one item that was not written.
    pub fn record_refused(&mut self) {
        self.refused += 1;
    }

    fn record(&mut self, report: &ItemReport) {
        if report.is_refused() {
            self.record_refused();
            return;
        }
        match report.outcome {
            Some(outcome) => self.record_outcome(outcome),
            // An item with neither an outcome nor a refusal is a bug in the
            // caller, not a category; count it as refused so the totals still
            // add up and the discrepancy is visible rather than swallowed.
            None => self.record_refused(),
        }
    }
}

/// What `--report PATH` writes, and what `--dry-run` prints.
///
/// `Deserialize` is hand-written below: a report whose `tally` disagrees with
/// its `items` is refused rather than read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub source: Source,
    /// Destination collection label.
    pub collection: String,
    pub tally: Tally,
    pub items: Vec<ItemReport>,
    /// KWallet folders with no entries. A collection-of-items model has
    /// nowhere to put them, so they are lost and the report says how many.
    #[serde(default)]
    pub empty_folders: usize,
    /// The item count read from the source's **cleartext** header, with no
    /// password. If the file says 28 and the walk produced 27 the import
    /// failed regardless of what the fingerprints agree on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_item_count: Option<usize>,
}

impl ImportReport {
    pub fn new(source: Source, collection: impl Into<String>) -> Self {
        Self {
            source,
            collection: collection.into(),
            tally: Tally::default(),
            items: Vec::new(),
            empty_folders: 0,
            header_item_count: None,
        }
    }

    /// Adds an item report and updates the tally, so the two cannot disagree.
    pub fn push(&mut self, report: ItemReport) {
        self.tally.record(&report);
        self.items.push(report);
    }

    /// The tally these items add up to, recomputed from scratch.
    ///
    /// Used by [`ImportReport`]'s `Deserialize`, so a report read back from
    /// JSON cannot carry a tally its own items contradict.
    fn recomputed_tally(items: &[ItemReport]) -> Tally {
        let mut tally = Tally::default();
        for item in items {
            tally.record(item);
        }
        tally
    }
}

/// The wire shape of an [`ImportReport`], with no invariant attached.
///
/// Only [`ImportReport`]'s hand-written `Deserialize` builds one, and it
/// refuses to hand back a report whose tally disagrees with its items.
#[derive(Deserialize)]
#[serde(rename = "ImportReport")]
struct ImportReportRepr {
    source: Source,
    collection: String,
    tally: Tally,
    items: Vec<ItemReport>,
    #[serde(default)]
    empty_folders: usize,
    #[serde(default)]
    header_item_count: Option<usize>,
}

/// Hand-written so the tally is *checked*, not merely read.
///
/// [`ImportReport::push`] is the only thing that builds a report in this
/// process and it keeps the two in step by construction. Deserialization is
/// the other door into the type, and it is the one that matters most: the
/// JSON report is the artefact a user keeps, pastes into a bug report and
/// trusts when deciding whether their credentials survived. A file whose
/// `tally` says "0 refused" while its `items` list four refusals must be an
/// error at the point it is read, not a summary someone acts on.
impl<'de> Deserialize<'de> for ImportReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let repr = ImportReportRepr::deserialize(deserializer)?;
        let recomputed = ImportReport::recomputed_tally(&repr.items);
        if recomputed != repr.tally {
            return Err(serde::de::Error::custom(format!(
                "the report's tally {:?} disagrees with the {} items it summarises, \
                 which add up to {recomputed:?}",
                repr.tally,
                repr.items.len(),
            )));
        }
        Ok(ImportReport {
            source: repr.source,
            collection: repr.collection,
            tally: repr.tally,
            items: repr.items,
            empty_folders: repr.empty_folders,
            header_item_count: repr.header_item_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{
        MAX_ATTRIBUTE_KEY, MAX_ATTRIBUTE_VALUE, MAX_ITEM_ATTRIBUTES, MAX_ITEM_CONTENT_TYPE,
        MAX_ITEM_LABEL, MAX_ITEM_SECRET,
    };

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn item(pairs: &[(&str, &str)]) -> SourceItem {
        SourceItem {
            label: "router".into(),
            attributes: attrs(pairs),
            secret: Zeroizing::new(b"hunter2".to_vec()),
            content_type: "text/plain".into(),
            created: 1_699_383_593,
            modified: 1_699_387_319,
            provenance: Provenance::kwallet("kdewallet", "Passwords", "my router"),
        }
    }

    #[test]
    fn an_xdg_schema_is_what_makes_an_item_portable() {
        assert_eq!(
            item(&[("xdg:schema", "org.freedesktop.Secret.Generic")]).outcome(),
            Outcome::FullyPortable
        );
        assert_eq!(
            item(&[("server", "example.com"), ("user", "joseph")]).outcome(),
            Outcome::AttributesPreserved
        );
        assert_eq!(item(&[]).outcome(), Outcome::PreservedOnly);
    }

    /// The case the classifier used to get wrong, and the one the spec calls
    /// the one a migration tool is tempted to lie about.
    ///
    /// `kwallet::map_entry` stamps `kwallet:folder`, `kwallet:key` and
    /// `kwallet:type` onto exactly the entries that arrived with *no*
    /// attributes, so by the time `classify` sees the map it is never empty.
    /// Classifying on "non-empty" reported every native KWallet entry as
    /// `AttributesPreserved` — "might work" — when the truth is that no
    /// libsecret client which did not write it ever will find it.
    #[test]
    fn a_synthesised_attribute_map_is_preserved_only_not_preserved_attributes() {
        // Exactly what `kwallet::map_entry` leaves on a native entry with no
        // sidecar row: three synthesised keys and nothing else.
        let mapped = item(&[
            (kwallet::ATTR_FOLDER, "Passwords"),
            (kwallet::ATTR_KEY, "my router"),
            (kwallet::ATTR_TYPE, "password"),
        ]);
        assert!(
            !mapped.attributes.is_empty(),
            "the map is empty, so this test would pass for the wrong reason"
        );
        assert!(
            mapped
                .attributes
                .keys()
                .all(|k| is_synthesised_attribute(Source::KWallet, k)),
            "a key nobody synthesised crept into the fixture: {:?}",
            AttributeKeys::of(&mapped.attributes)
        );
        assert_eq!(mapped.outcome(), Outcome::PreservedOnly);

        // One real attribute alongside them is enough to make the item's
        // attribute set something a client could have searched on.
        let mut with_real = mapped.clone();
        with_real
            .attributes
            .insert("server".into(), "example.com".into());
        assert_eq!(with_real.outcome(), Outcome::AttributesPreserved);
    }

    /// The names the classifier ignores are `kwallet`'s own constants, not a
    /// second copy of the same strings that could drift away from them.
    #[test]
    fn the_synthesised_names_are_kwallets_own_constants() {
        assert_eq!(
            SYNTHESISED_ATTRIBUTES,
            [kwallet::ATTR_FOLDER, kwallet::ATTR_KEY, kwallet::ATTR_TYPE]
        );
        for key in SYNTHESISED_ATTRIBUTES {
            assert!(is_synthesised_attribute(Source::KWallet, key));
            // Nothing synthesises on the gnome-keyring path, so the same
            // name there is an attribute somebody wrote.
            assert!(!is_synthesised_attribute(Source::GnomeKeyring, key));
        }
        assert!(!is_synthesised_attribute(Source::KWallet, XDG_SCHEMA));
        assert!(!is_synthesised_attribute(Source::KWallet, "server"));
        assert!(!is_synthesised_attribute(
            Source::KWallet,
            "kwallet:folder2"
        ));
    }

    /// `kwallet:` is a user-writable namespace. A gnome-keyring item that
    /// really carries `kwallet:folder` carries an attribute a client can
    /// search on, and discounting it would report a preserved, searchable
    /// item as one no client will ever find.
    #[test]
    fn the_denylist_does_not_reach_the_gnome_path() {
        let synthesised: Vec<(&str, &str)> = SYNTHESISED_ATTRIBUTES
            .iter()
            .map(|k| (*k, "written by the user"))
            .collect();
        let map = attrs(&synthesised);
        assert_eq!(
            Outcome::classify(Source::KWallet, &map),
            Outcome::PreservedOnly
        );
        assert_eq!(
            Outcome::classify(Source::GnomeKeyring, &map),
            Outcome::AttributesPreserved
        );
    }

    /// An empty schema value matches nothing, so calling it portable would be
    /// the same lie as synthesising one.
    #[test]
    fn an_empty_schema_value_is_not_portable() {
        assert_eq!(
            item(&[("xdg:schema", "")]).outcome(),
            Outcome::AttributesPreserved
        );
        assert_eq!(
            Outcome::classify(Source::KWallet, &attrs(&[("xdg:schema", "")])),
            Outcome::AttributesPreserved
        );
    }

    /// The three-way split is a property of the item's attributes. Neither
    /// the label nor the secret may move an item between buckets, and the
    /// source only ever decides which names this importer wrote itself (see
    /// `the_denylist_does_not_reach_the_gnome_path`).
    #[test]
    fn classification_ignores_everything_but_the_attributes() {
        let mut a = item(&[("server", "example.com")]);
        let mut b = a.clone();
        b.provenance = Provenance::gnome("Default keyring", 7);
        b.label = String::new();
        b.secret = Zeroizing::new(Vec::new());
        b.content_type = "application/octet-stream".into();
        b.created = 0;
        b.modified = 0;
        assert_eq!(a.outcome(), b.outcome());
        a.attributes.clear();
        assert_ne!(a.outcome(), b.outcome());
    }

    #[test]
    fn each_of_the_six_caps_is_enforced() {
        type Break = fn(&mut SourceItem);
        let cases: &[(Cap, Break)] = &[
            (Cap::Secret, |i| {
                i.secret = Zeroizing::new(vec![0u8; MAX_ITEM_SECRET + 1]);
            }),
            (Cap::Label, |i| i.label = "x".repeat(MAX_ITEM_LABEL + 1)),
            (Cap::ContentType, |i| {
                i.content_type = "x".repeat(MAX_ITEM_CONTENT_TYPE + 1);
            }),
            (Cap::AttributeCount, |i| {
                i.attributes = (0..=MAX_ITEM_ATTRIBUTES)
                    .map(|n| (format!("k{n}"), "v".to_string()))
                    .collect();
            }),
            (Cap::AttributeKey, |i| {
                i.attributes
                    .insert("k".repeat(MAX_ATTRIBUTE_KEY + 1), "v".into());
            }),
            (Cap::AttributeValue, |i| {
                i.attributes
                    .insert("k".into(), "v".repeat(MAX_ATTRIBUTE_VALUE + 1));
            }),
        ];
        for (cap, break_it) in cases {
            let mut it = item(&[("xdg:schema", "org.freedesktop.Secret.Generic")]);
            assert_eq!(it.cap_violation(), None, "{cap} baseline");
            break_it(&mut it);
            match it.cap_violation() {
                Some(Refusal::CapViolation {
                    cap: got, limit, ..
                }) => {
                    assert_eq!(got, *cap);
                    assert_eq!(limit, cap.limit());
                }
                other => panic!("{cap}: expected a cap violation, got {other:?}"),
            }
        }
    }

    /// The cap is `>`, not `>=`: an item of exactly the limit is one the
    /// D-Bus API would have accepted, and refusing it would strand data.
    ///
    /// All six caps at once, which is the claim the comment makes. Two of
    /// them — the secret and the attribute *key* — used to be left at their
    /// baseline size here while the doc comment spoke for all six, so a
    /// `>=` in either would have passed this test.
    #[test]
    fn an_item_at_exactly_the_cap_is_accepted() {
        let mut it = item(&[]);
        it.secret = Zeroizing::new(vec![0u8; MAX_ITEM_SECRET]);
        it.label = "x".repeat(MAX_ITEM_LABEL);
        it.content_type = "x".repeat(MAX_ITEM_CONTENT_TYPE);
        // Every key is exactly `MAX_ATTRIBUTE_KEY` long and still distinct:
        // a zero-padded index, so the count cap is at its limit too and no
        // two keys collide into a shorter map.
        it.attributes = (0..MAX_ITEM_ATTRIBUTES)
            .map(|n| {
                (
                    format!("{n:0>width$}", width = MAX_ATTRIBUTE_KEY),
                    "v".repeat(MAX_ATTRIBUTE_VALUE),
                )
            })
            .collect();
        assert_eq!(it.attributes.len(), MAX_ITEM_ATTRIBUTES);
        assert!(it.attributes.keys().all(|k| k.len() == MAX_ATTRIBUTE_KEY));
        assert_eq!(it.cap_violation(), None);
    }

    #[test]
    fn the_tally_cannot_disagree_with_the_items() {
        let mut report = ImportReport::new(Source::KWallet, "kdewallet (imported)");
        report.push(ItemReport::imported(&item(&[(
            "xdg:schema",
            "org.freedesktop.Secret.Generic",
        )])));
        report.push(ItemReport::imported(&item(&[("server", "example.com")])));
        report.push(ItemReport::imported(&item(&[])));
        report.push(ItemReport::refused(
            Provenance::gnome("Login", 1),
            "Unlock password for Default keyring",
            Refusal::ChainedKeyringItem { item_type: 3 },
        ));
        assert_eq!(
            report.tally,
            Tally {
                fully_portable: 1,
                attributes_preserved: 1,
                preserved_only: 1,
                refused: 1,
            }
        );
        assert_eq!(report.tally.imported(), 3);
        assert_eq!(report.tally.seen(), report.items.len());
    }

    /// A report read back from JSON cannot carry a tally its own items
    /// contradict. The JSON report is the artefact a user trusts when
    /// deciding whether their credentials survived, so "0 refused" beside a
    /// list of four refusals is an error at the point of reading, not a
    /// summary anyone acts on.
    #[test]
    fn a_tally_that_disagrees_with_its_items_will_not_deserialize() {
        let mut report = ImportReport::new(Source::KWallet, "kdewallet (imported)");
        report.push(ItemReport::refused(
            Provenance::gnome("Login", 1),
            "chained",
            Refusal::ChainedKeyringItem { item_type: 3 },
        ));
        let json = serde_json::to_string(&report).unwrap();
        assert!(serde_json::from_str::<ImportReport>(&json).is_ok());

        // The same items, with the tally quietly zeroed.
        let doctored = json.replace(r#""refused":1"#, r#""refused":0"#);
        assert_ne!(
            doctored, json,
            "the tally field was not where it was patched"
        );
        let err = serde_json::from_str::<ImportReport>(&doctored).unwrap_err();
        assert!(
            err.to_string().contains("disagrees with the 1 items"),
            "{err}"
        );
    }

    /// The whole reason `AttributeKeys` exists. A value that appears in the
    /// JSON is a disclosure bug, so it is asserted rather than reviewed for.
    #[test]
    fn the_json_report_holds_no_secret_and_no_attribute_value() {
        let mut it = item(&[
            ("xdg:schema", "org.freedesktop.Secret.Generic"),
            ("server", "secret-host.example.com"),
            ("user", "joseph"),
        ]);
        it.secret = Zeroizing::new(b"correct horse battery staple".to_vec());
        let mut report = ImportReport::new(Source::KWallet, "kdewallet (imported)");
        report.push(ItemReport::imported(&it));
        let json = serde_json::to_string_pretty(&report).unwrap();
        for leaked in [
            "correct horse battery staple",
            "secret-host.example.com",
            "joseph",
            "org.freedesktop.Secret.Generic",
        ] {
            assert!(!json.contains(leaked), "{leaked:?} leaked into {json}");
        }
        // The keys, the counts and the outcome are all there.
        for kept in ["xdg:schema", "server", "user", "fully-portable", "kwallet"] {
            assert!(json.contains(kept), "{kept:?} missing from {json}");
        }
    }

    #[test]
    fn debug_redacts_the_secret_and_the_attribute_values() {
        let mut it = item(&[("server", "secret-host.example.com")]);
        it.secret = Zeroizing::new(b"hunter2".to_vec());
        let text = format!("{it:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("secret-host.example.com"), "{text}");
        assert!(text.contains("server"), "{text}");
    }

    #[test]
    fn attribute_keys_drop_values_on_the_way_in() {
        let keys = AttributeKeys::of(&attrs(&[("b", "2"), ("a", "1")]));
        assert_eq!(keys.iter().collect::<Vec<_>>(), ["a", "b"]);
        assert!(keys.contains("a"));
        assert_eq!(keys.len(), 2);
        assert!(!keys.is_empty());
        assert!(AttributeKeys::default().is_empty());
        assert_eq!(keys, AttributeKeys::from_names(["a", "b"]));
    }

    #[test]
    fn a_report_round_trips_through_json() {
        let mut report = ImportReport::new(Source::GnomeKeyring, "Default keyring");
        report.header_item_count = Some(1);
        report.empty_folders = 4;
        let mut ir = ItemReport::imported(&item(&[("xdg:schema", "org.gnome.keyring.Note")]));
        ir.lost_item_type = Some(2);
        ir.acl_downgrade = true;
        report.push(ir);
        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: ImportReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    /// The report is an artefact a user keeps, so `Refusal`'s wire form is
    /// fixed. Re-pointing [`Cap`] at `vault::format` must not have moved a
    /// byte of it: same variant names, same kebab-case renaming, same field
    /// names. Every variant is listed, so adding one without deciding its
    /// wire form fails here.
    #[test]
    fn every_refusal_has_a_fixed_wire_form() {
        let cases = [
            (
                Refusal::ChainedKeyringItem { item_type: 3 },
                r#"{"reason":"chained-keyring-item","item_type":3}"#,
            ),
            (
                Refusal::UnreadableItemType,
                r#"{"reason":"unreadable-item-type"}"#,
            ),
            (
                Refusal::UnreadableAttributes,
                r#"{"reason":"unreadable-attributes"}"#,
            ),
            (
                Refusal::CapViolation {
                    cap: Cap::AttributeValue,
                    actual: 513,
                    limit: 512,
                },
                r#"{"reason":"cap-violation","cap":"attribute-value","actual":513,"limit":512}"#,
            ),
        ];
        for (refusal, json) in cases {
            assert_eq!(serde_json::to_string(&refusal).unwrap(), json);
            assert_eq!(serde_json::from_str::<Refusal>(json).unwrap(), refusal);
        }
        // Every cap name too: `Cap` is serialized inside a `CapViolation`, so
        // its renaming is part of the report's wire form as much as the
        // refusal's own is.
        for (cap, name) in [
            (Cap::Secret, "secret"),
            (Cap::Label, "label"),
            (Cap::AttributeCount, "attribute-count"),
            // Deliberately not the kebab-case of the variant: the JSON is
            // user-facing and every message spells this cap "attribute
            // name". Pinned in `vault::format::Cap`.
            (Cap::AttributeKey, "attribute-name"),
            (Cap::AttributeValue, "attribute-value"),
            (Cap::ContentType, "content-type"),
        ] {
            assert_eq!(serde_json::to_string(&cap).unwrap(), format!("\"{name}\""));
        }
    }

    /// The two refusals that exist because a read failed must say what the
    /// user can do about it, and must not describe the item as something
    /// nobody established it is.
    #[test]
    fn an_unreadable_property_reads_as_itself_and_not_as_a_chained_keyring() {
        let unreadable_type = Refusal::UnreadableItemType.to_string();
        assert!(
            unreadable_type.contains("re-run the import"),
            "{unreadable_type}"
        );
        assert!(
            !unreadable_type.contains("item type 3"),
            "an unknown type must not be reported as a known one: {unreadable_type}"
        );
        let unreadable_attrs = Refusal::UnreadableAttributes.to_string();
        assert!(
            unreadable_attrs.contains("attributes"),
            "{unreadable_attrs}"
        );
        assert!(unreadable_attrs.contains("by hand"), "{unreadable_attrs}");
    }

    #[test]
    fn sources_and_outcomes_render() {
        assert_eq!(Source::GnomeKeyring.to_string(), "gnome-keyring");
        assert_eq!(Source::KWallet.to_string(), "kwallet");
        assert_eq!(Outcome::PreservedOnly.to_string(), "preserved only");
        assert!(
            Refusal::CapViolation {
                cap: Cap::Secret,
                actual: 2,
                limit: 1,
            }
            .to_string()
            .contains("secret is 2 bytes")
        );
        assert!(
            Refusal::ChainedKeyringItem { item_type: 3 }
                .to_string()
                .contains("another keyring")
        );
    }
}
