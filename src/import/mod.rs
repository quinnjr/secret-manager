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

use crate::vault::format::{
    MAX_ATTRIBUTE_KEY, MAX_ATTRIBUTE_VALUE, MAX_ITEM_ATTRIBUTES, MAX_ITEM_CONTENT_TYPE,
    MAX_ITEM_LABEL, MAX_ITEM_SECRET,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

/// The attribute every libsecret client writes and searches on. Its presence
/// is what separates a fully portable item from a merely preserved one.
pub const XDG_SCHEMA: &str = "xdg:schema";

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
/// Attributes are already `String`s here: a source attribute holding
/// non-UTF-8 bytes cannot be represented, and lossy conversion is not an
/// option because a changed attribute is a silently broken lookup. The
/// extractor refuses such an item with [`Refusal::NonUtf8Attribute`] rather
/// than constructing a `SourceItem` for it.
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
        Outcome::classify(&self.attributes)
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
    pub fn classify(attributes: &BTreeMap<String, String>) -> Outcome {
        match attributes.get(XDG_SCHEMA) {
            Some(schema) if !schema.is_empty() => Outcome::FullyPortable,
            _ if !attributes.is_empty() => Outcome::AttributesPreserved,
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

/// One of the six per-item limits that live in the D-Bus layer and nowhere
/// else. `Vault::insert_item` enforces none of them, so an importer writing
/// vault files directly could produce a collection the daemon serves happily
/// but which no D-Bus client could ever have created — and whose items may be
/// unreadable through the very API they exist to be reached by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cap {
    Secret,
    Label,
    AttributeCount,
    AttributeKey,
    AttributeValue,
    ContentType,
}

impl Cap {
    /// The single definition of each limit lives in `vault::format`; this is
    /// a view of it, never a second copy that can drift.
    pub const fn limit(self) -> usize {
        match self {
            Cap::Secret => MAX_ITEM_SECRET,
            Cap::Label => MAX_ITEM_LABEL,
            Cap::AttributeCount => MAX_ITEM_ATTRIBUTES,
            Cap::AttributeKey => MAX_ATTRIBUTE_KEY,
            Cap::AttributeValue => MAX_ATTRIBUTE_VALUE,
            Cap::ContentType => MAX_ITEM_CONTENT_TYPE,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Cap::Secret => "secret",
            Cap::Label => "label",
            Cap::AttributeCount => "attribute count",
            Cap::AttributeKey => "attribute name",
            Cap::AttributeValue => "attribute value",
            Cap::ContentType => "content type",
        }
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The first cap `label`/`attributes`/`secret_len`/`content_type` violate.
///
/// Sizes only ever reach the report as *numbers*: a `Refusal` names the cap,
/// the measured size and the limit, never the oversized value itself.
pub fn check_caps(
    label: &str,
    attributes: &BTreeMap<String, String>,
    secret_len: usize,
    content_type: &str,
) -> Option<Refusal> {
    let over = |cap: Cap, actual: usize| {
        (actual > cap.limit()).then(|| Refusal::CapViolation {
            cap,
            actual,
            limit: cap.limit(),
        })
    };
    over(Cap::Secret, secret_len)
        .or_else(|| over(Cap::Label, label.len()))
        .or_else(|| over(Cap::ContentType, content_type.len()))
        .or_else(|| over(Cap::AttributeCount, attributes.len()))
        .or_else(|| {
            attributes.iter().find_map(|(k, v)| {
                over(Cap::AttributeKey, k.len()).or_else(|| over(Cap::AttributeValue, v.len()))
            })
        })
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
    /// A source attribute holding bytes that are not UTF-8. Lossy conversion
    /// changes the attribute and a changed attribute is a broken lookup, so
    /// the item is refused instead. `key` is `None` when it is the key itself
    /// that failed to decode and so cannot be named.
    NonUtf8Attribute {
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
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
            Refusal::NonUtf8Attribute { key: Some(k) } => {
                write!(f, "attribute {k} is not valid UTF-8 and cannot be copied")
            }
            Refusal::NonUtf8Attribute { key: None } => {
                write!(
                    f,
                    "an attribute name is not valid UTF-8 and cannot be copied"
                )
            }
            Refusal::CapViolation { cap, actual, limit } => write!(
                f,
                "{cap} is {actual} bytes, over the {limit} the Secret Service API allows"
            ),
        }
    }
}

/// The attribute *names* of an item, and nothing else.
///
/// The only way to build one is from a map whose values are dropped on the
/// way in, so no code path can put an attribute value into a report by
/// accident. That is the whole point of the newtype.
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
    pub fn from_names<I, S>(names: I) -> Self
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

impl<'a> IntoIterator for &'a AttributeKeys {
    type Item = &'a str;
    type IntoIter = Box<dyn Iterator<Item = &'a str> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost_item_type: Option<u32>,
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
            acl_downgrade: false,
        }
    }

    pub fn is_refused(&self) -> bool {
        !self.refusals.is_empty()
    }
}

/// The three-way tally, plus what was refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub fully_portable: usize,
    pub attributes_preserved: usize,
    pub preserved_only: usize,
    pub refused: usize,
}

impl Tally {
    /// Items that were written — the three outcomes, not the refusals.
    pub fn imported(&self) -> usize {
        self.fully_portable + self.attributes_preserved + self.preserved_only
    }

    /// Every item the walk produced, written or not.
    pub fn seen(&self) -> usize {
        self.imported() + self.refused
    }

    fn record(&mut self, report: &ItemReport) {
        if report.is_refused() {
            self.refused += 1;
            return;
        }
        match report.outcome {
            Some(Outcome::FullyPortable) => self.fully_portable += 1,
            Some(Outcome::AttributesPreserved) => self.attributes_preserved += 1,
            Some(Outcome::PreservedOnly) => self.preserved_only += 1,
            // An item with neither an outcome nor a refusal is a bug in the
            // caller, not a category; count it as refused so the totals still
            // add up and the discrepancy is visible rather than swallowed.
            None => self.refused += 1,
        }
    }
}

/// What `--report PATH` writes, and what `--dry-run` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// `Some(header_count)` when the cleartext header's item count and the
    /// number of items the walk produced disagree. The caller must report
    /// this rather than success: something was skipped.
    pub fn count_mismatch(&self) -> Option<usize> {
        let expected = self.header_item_count?;
        (expected != self.tally.seen()).then_some(expected)
    }

    /// The report as JSON. Carries keys, counts and outcomes; no secret and
    /// no attribute value can reach it, because no type it holds has a field
    /// that could carry one.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// An empty schema value matches nothing, so calling it portable would be
    /// the same lie as synthesising one.
    #[test]
    fn an_empty_schema_value_is_not_portable() {
        assert_eq!(
            item(&[("xdg:schema", "")]).outcome(),
            Outcome::AttributesPreserved
        );
        assert_eq!(
            Outcome::classify(&attrs(&[("xdg:schema", "")])),
            Outcome::AttributesPreserved
        );
    }

    /// The three-way split is a property of the item alone. Nothing about the
    /// source, the label or the secret may move an item between buckets.
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
    #[test]
    fn an_item_at_exactly_the_cap_is_accepted() {
        let mut it = item(&[]);
        it.label = "x".repeat(MAX_ITEM_LABEL);
        it.content_type = "x".repeat(MAX_ITEM_CONTENT_TYPE);
        it.attributes = (0..MAX_ITEM_ATTRIBUTES)
            .map(|n| (format!("k{n}"), "v".repeat(MAX_ATTRIBUTE_VALUE)))
            .collect();
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

    /// The independent count is the check the fingerprints cannot make: if
    /// the header says 28 and the walk yielded 27, the import failed.
    #[test]
    fn a_count_mismatch_is_reported() {
        let mut report = ImportReport::new(Source::GnomeKeyring, "Default keyring");
        report.header_item_count = Some(2);
        report.push(ItemReport::imported(&item(&[])));
        assert_eq!(report.count_mismatch(), Some(2));
        report.push(ItemReport::imported(&item(&[])));
        assert_eq!(report.count_mismatch(), None);
        // A refused item still counts as seen: it was in the file.
        report.header_item_count = Some(3);
        report.push(ItemReport::refused(
            Provenance::gnome("Default keyring", 9),
            "chained",
            Refusal::ChainedKeyringItem { item_type: 3 },
        ));
        assert_eq!(report.count_mismatch(), None);
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
        let json = report.to_json().unwrap();
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
        let back: ImportReport = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(back, report);
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
            Refusal::NonUtf8Attribute { key: None }
                .to_string()
                .contains("not valid UTF-8")
        );
        assert!(
            Refusal::ChainedKeyringItem { item_type: 3 }
                .to_string()
                .contains("another keyring")
        );
    }
}
