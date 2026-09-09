//! Proving the copy is faithful, without printing a single secret.
//!
//! This module owns the four checks the spec names: per-item fingerprints
//! (`SHA-256` over length-prefixed canonical attributes, label, content type
//! and `SHA-256(secret)`), the independent item count taken from the source's
//! cleartext header, the `SearchItems` lookup probe that decides the
//! three-way tally, and the bucketed secret-length histogram.
//!
//! Mismatches are reported by attribute *key* and object path only, which is
//! why [`super::AttributeKeys`] is the only attribute type that reaches an
//! [`super::ImportReport`].
//!
//! ## Why the probe lives here only as a plan
//!
//! `SearchItems` is a D-Bus call and the transport belongs to the CLI, not to
//! a verification library: this module builds the [`ProbeQuery`] list, the
//! caller issues the calls, and [`ProbeResult`]s come back here to be judged
//! and tallied. That keeps every rule in one testable place and keeps the
//! rules themselves reachable without a bus.
//!
//! ## MD5
//!
//! [`md5`] is a hundred lines of the algorithm rather than a dependency. It
//! exists for exactly one purpose — recomputing `MD5(folder)` and `MD5(key)`
//! to prove membership in a `.kwl` hash table — which is a *comparison
//! against a foreign file's index*, never a security decision, and the crate
//! must stay free of a hash whose presence in a dependency tree invites
//! precisely the wrong reading. Nothing else here may call it.

use super::formats::{Md5Hash, WalletInventory};
use super::{AttributeKeys, ItemReport, Outcome, SourceItem, Tally};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

/// A per-item fingerprint. Derived from the secret but never invertible to
/// it, and never printed as anything but hex in a mismatch line.
pub type Fingerprint = [u8; 32];

/// `for (k,v) sorted by k: u64be(len k) || k || u64be(len v) || v`.
///
/// The length prefixes are the whole point: without them `{"a": "bc"}` and
/// `{"ab": "c"}` serialise to the same bytes and two items with genuinely
/// different attribute sets get the same fingerprint — the failure this
/// verification exists to catch, silently passing itself.
///
/// The prefix is `u64` and not `u32` because a `u32` one is a *lossy* length:
/// `len as u32` truncates above 4 GiB and hands back exactly the ambiguity
/// the prefix was added to remove. A `usize` never truncates into a `u64` on
/// any target this runs on.
pub fn canonical_attrs(attributes: &BTreeMap<String, String>) -> Vec<u8> {
    // `BTreeMap` iteration is already sorted by key, which is the sort the
    // spec asks for; nothing here re-sorts, so nothing here can sort
    // differently on the two sides.
    let mut out = Vec::new();
    for (k, v) in attributes {
        push_prefixed(&mut out, k.as_bytes());
        push_prefixed(&mut out, v.as_bytes());
    }
    out
}

/// `u64be(len) || bytes`.
fn push_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// `SHA-256(canonical_attrs || u64be(len label) || label || u64be(len
/// content_type) || content_type || SHA-256(secret))`.
///
/// The label and the content type are length-prefixed for the same reason the
/// attributes are: joined by a bare separator byte, the pair `("ab", "c")` and
/// the pair `("a", "bc")` produce the same bytes once the separator is one of
/// the characters a label may contain, and two different items share a
/// fingerprint.
///
/// The secret is hashed before it is mixed in, so this function's caller can
/// hold the digest of an item it no longer has the bytes of, and so no code
/// path that logs a fingerprint can ever have held the secret in the same
/// buffer.
pub fn fingerprint(
    attributes: &BTreeMap<String, String>,
    label: &str,
    content_type: &str,
    secret: &[u8],
) -> Fingerprint {
    let mut prefixed = Vec::new();
    push_prefixed(&mut prefixed, label.as_bytes());
    push_prefixed(&mut prefixed, content_type.as_bytes());
    let mut h = Sha256::new();
    h.update(canonical_attrs(attributes));
    h.update(&prefixed);
    h.update(Sha256::digest(secret));
    h.finalize().into()
}

/// The fingerprint of an item as the source gave it.
pub fn fingerprint_source(item: &SourceItem) -> Fingerprint {
    fingerprint(
        &item.attributes,
        &item.label,
        &item.content_type,
        &item.secret,
    )
}

/// One side's fingerprint, with the only two identifiers a mismatch may be
/// reported by: the attribute *keys* and, on the destination side, the object
/// path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintEntry {
    #[serde(with = "hex_fp")]
    pub fingerprint: Fingerprint,
    pub attribute_keys: AttributeKeys,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
}

impl FingerprintEntry {
    pub fn source(item: &SourceItem) -> Self {
        Self {
            fingerprint: fingerprint_source(item),
            attribute_keys: AttributeKeys::of(&item.attributes),
            object_path: None,
        }
    }

    /// A destination item, identified by the object path a client would use
    /// to reach it.
    pub fn destination(
        attributes: &BTreeMap<String, String>,
        label: &str,
        content_type: &str,
        secret: &[u8],
        object_path: impl Into<String>,
    ) -> Self {
        Self {
            fingerprint: fingerprint(attributes, label, content_type, secret),
            attribute_keys: AttributeKeys::of(attributes),
            object_path: Some(object_path.into()),
        }
    }

    /// The first 16 hex characters of the digest — enough to name a row in a
    /// report, and not a value anything can be recovered from.
    pub fn short(&self) -> String {
        self.fingerprint[..8]
            .iter()
            .fold(String::new(), |mut s, b| {
                use fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

/// Serde for a fixed-size digest, as lowercase hex. A JSON array of 32
/// numbers is unreadable in the one place this is meant to be read: a report
/// pasted into a bug.
mod hex_fp {
    use super::Fingerprint;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(fp: &Fingerprint, s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(64);
        for b in fp {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Fingerprint, D::Error> {
        let text = String::deserialize(d)?;
        let bytes: Result<Vec<u8>, _> = (0..text.len())
            .step_by(2)
            .map(|i| {
                text.get(i..i + 2)
                    .ok_or_else(|| serde::de::Error::custom("odd-length fingerprint"))
                    .and_then(|pair| u8::from_str_radix(pair, 16).map_err(serde::de::Error::custom))
            })
            .collect();
        let bytes = bytes?;
        Fingerprint::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("fingerprint is not 32 bytes"))
    }
}

/// Which side of the copy an item is missing from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Side {
    /// In the source, not in the destination: the item did not arrive, or
    /// arrived changed.
    MissingFromDestination,
    /// In the destination, not in the source: the destination holds something
    /// the walk never produced.
    UnexpectedInDestination,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Side::MissingFromDestination => "missing from the new collection",
            Side::UnexpectedInDestination => "present in the new collection but not in the source",
        })
    }
}

/// One item whose fingerprint has no partner on the other side. Named by
/// attribute keys and object path, never by a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintMismatch {
    pub side: Side,
    pub attribute_keys: AttributeKeys,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
    /// The digest prefix, so two rows of the same shape can be told apart.
    pub fingerprint: String,
}

/// Compare the two sorted fingerprint lists as multisets.
///
/// A multiset and not a set: two identical items are a thing a source can
/// hold, and losing one of them is exactly the kind of loss that a
/// set-difference would call equal.
pub fn compare_fingerprints(
    source: &[FingerprintEntry],
    destination: &[FingerprintEntry],
) -> Vec<FingerprintMismatch> {
    let mut remaining: BTreeMap<Fingerprint, usize> = BTreeMap::new();
    for entry in destination {
        *remaining.entry(entry.fingerprint).or_insert(0) += 1;
    }
    let mut out = Vec::new();
    for entry in source {
        match remaining.get_mut(&entry.fingerprint) {
            Some(n) if *n > 0 => *n -= 1,
            _ => out.push(FingerprintMismatch {
                side: Side::MissingFromDestination,
                attribute_keys: entry.attribute_keys.clone(),
                object_path: entry.object_path.clone(),
                fingerprint: entry.short(),
            }),
        }
    }
    // Whatever is left over on the destination side was never accounted for.
    let mut surplus: BTreeMap<Fingerprint, usize> = remaining
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .collect::<BTreeMap<_, _>>();
    for entry in destination {
        let Some(n) = surplus.get_mut(&entry.fingerprint) else {
            continue;
        };
        if *n == 0 {
            continue;
        }
        *n -= 1;
        out.push(FingerprintMismatch {
            side: Side::UnexpectedInDestination,
            attribute_keys: entry.attribute_keys.clone(),
            object_path: entry.object_path.clone(),
            fingerprint: entry.short(),
        });
    }
    out
}

// --------------------------------------------------------------------------
// The independent count
// --------------------------------------------------------------------------

/// The cleartext header's item count against the number of items the walk
/// produced. If the file says 28 and the walk produced 27 the import failed,
/// whatever the fingerprints agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountCheck {
    /// `None` when the source file could not be read at all — the check is
    /// then *not made*, which is reported rather than counted as a pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_item_count: Option<usize>,
    /// Every item the walk **accounted for**: written, refused, or skipped.
    ///
    /// All three, because the number this is compared against is the count in
    /// the source's own header, and the header counts items in the file
    /// regardless of what we then decided about them. An item refused for a
    /// cap violation was in the file; so was one skipped because its secret
    /// would not decrypt. Omitting either category would report a count
    /// mismatch for an item nothing is wrong with — the check would fire on
    /// our own decisions instead of on a shortfall — which is the opposite of
    /// what it is for.
    pub walked: usize,
}

impl CountCheck {
    pub fn new(header_item_count: Option<usize>, walked: usize) -> Self {
        Self {
            header_item_count,
            walked,
        }
    }

    /// `false` only when the check was made *and* failed. An absent header
    /// count is `true` here and reported separately by [`CountCheck::made`];
    /// a missing check must not read as a failed one.
    pub fn passed(&self) -> bool {
        self.header_item_count.is_none_or(|n| n == self.walked)
    }

    pub fn made(&self) -> bool {
        self.header_item_count.is_some()
    }
}

impl fmt::Display for CountCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.header_item_count {
            None => write!(f, "not made: the source header gave no item count"),
            Some(n) if n == self.walked => write!(f, "{n} in the header, {n} walked"),
            Some(n) => write!(f, "{n} in the header, {} walked", self.walked),
        }
    }
}

// --------------------------------------------------------------------------
// The KWallet hash-table membership check
// --------------------------------------------------------------------------

/// An imported KWallet item whose `(MD5(folder), MD5(entry))` is not in the
/// `.kwl` index — which means a name was mangled between the file and us.
///
/// The names themselves are not in this struct: `folder` and `entry` are
/// KWallet's own vocabulary and go in the report as provenance already, so a
/// miss is named by its hashes, which is all the check ever handled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashMiss {
    pub folder_hash: String,
    pub entry_hash: String,
}

/// Recompute both hashes for every imported item and assert membership in the
/// wallet's cleartext hash table.
///
/// Items with no KWallet provenance (a gnome-keyring item, or one whose
/// folder or entry the extractor did not record) are not checked: there is no
/// hash to look up, and inventing one would report a miss for an item the
/// index never claimed to hold.
///
/// # Why the index is transposed first
///
/// [`WalletInventory::contains_entry`] is a linear scan of every folder and,
/// within a matching folder, of every entry hash. That is right for one
/// lookup and wrong for this loop, which does one per imported item: the
/// product is quadratic in input the parser accepts from a hostile file —
/// `MAX_ENTRIES` entries against an index of the same order — and a `.kwl`
/// that parses cleanly could hold this function for hours without a single
/// byte being decrypted. So the pairs are hoisted into a set once, and the
/// per-item work becomes one hash lookup. `contains_entry` stays as it is for
/// the single-shot callers it suits.
pub fn check_wallet_hash_table(inventory: &WalletInventory, items: &[SourceItem]) -> Vec<HashMiss> {
    let mut out = Vec::new();
    let index: HashSet<(Md5Hash, Md5Hash)> = inventory
        .folders
        .iter()
        .flat_map(|f| {
            f.entry_hashes
                .iter()
                .map(move |entry| (f.folder_hash, *entry))
        })
        .collect();
    for item in items {
        let (Some(folder), Some(entry)) = (
            item.provenance.folder.as_deref(),
            item.provenance.entry.as_deref(),
        ) else {
            continue;
        };
        let folder_hash = md5(folder.as_bytes());
        let entry_hash = md5(entry.as_bytes());
        if !index.contains(&(folder_hash, entry_hash)) {
            out.push(HashMiss {
                folder_hash: hex(&folder_hash),
                entry_hash: hex(&entry_hash),
            });
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// RFC 1321 MD5, for one purpose only: recomputing the two name hashes a
/// `.kwl` index stores, so membership can be proved without ever holding a
/// decrypted name beside them. See this module's header — it is a comparison
/// against a foreign file, never a security decision, and nothing else in
/// this crate may call it.
///
/// `pub(crate)`, so that "nothing else may call it" is enforced at the crate
/// boundary by the compiler rather than only asserted in a comment: an MD5
/// exported to every downstream consumer is an invitation to use it for
/// something other than the one comparison it exists for.
pub(crate) fn md5(bytes: &[u8]) -> Md5Hash {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    // K[i] = floor(2^32 * abs(sin(i + 1))), as the RFC tabulates it.
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    // The padded message: the bytes, a 0x80, zeros to 56 mod 64, then the
    // bit length little-endian. Built once rather than streamed; the only
    // inputs are KWallet folder and entry names, which are short.
    let mut msg = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            b = b.wrapping_add(sum);
            a = tmp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// --------------------------------------------------------------------------
// The lookup probe
// --------------------------------------------------------------------------

/// One `SearchItems` call the caller is to make: exactly the source item's
/// attributes, and the number of items that must come back.
///
/// The attribute *values* are here because the call needs them; they are the
/// one place in this module values exist, they never reach a report, and
/// [`ProbeResult`] deliberately cannot carry them back.
#[derive(Clone, PartialEq, Eq)]
pub struct ProbeQuery {
    pub attributes: BTreeMap<String, String>,
    /// How many source items carry exactly this attribute set. Normally 1;
    /// more when the source itself held duplicates, and then the destination
    /// must hold that many too.
    pub expected: usize,
}

/// Keys only, as [`super::SourceItem`] does. A derived `Debug` on the one
/// type in this module that holds attribute *values* is how those values
/// reach a log line or a panic message.
impl fmt::Debug for ProbeQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeQuery")
            .field("attribute_keys", &self.keys())
            .field("expected", &self.expected)
            .finish()
    }
}

impl ProbeQuery {
    pub fn keys(&self) -> AttributeKeys {
        AttributeKeys::of(&self.attributes)
    }
}

/// The distinct attribute sets to probe, in a deterministic order.
///
/// An item with **no** attributes is not probed: `SearchItems({})` matches
/// every item in every collection, so a probe for it would pass for reasons
/// that have nothing to do with this import. Those items are
/// [`Outcome::PreservedOnly`] by construction — the outcome that already says
/// no libsecret client will find them — so there is nothing a probe could add.
pub fn probe_plan(items: &[SourceItem]) -> Vec<ProbeQuery> {
    let mut counts: BTreeMap<BTreeMap<String, String>, usize> = BTreeMap::new();
    for item in items {
        if item.attributes.is_empty() {
            continue;
        }
        *counts.entry(item.attributes.clone()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(attributes, expected)| ProbeQuery {
            attributes,
            expected,
        })
        .collect()
}

/// What one probe found. Carries keys, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub attribute_keys: AttributeKeys,
    pub expected: usize,
    /// `None` when the probe could not be issued at all (no daemon), which is
    /// reported as *not proved*, never as proved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found: Option<usize>,
}

impl ProbeResult {
    pub fn new(query: &ProbeQuery, found: usize) -> Self {
        Self {
            attribute_keys: query.keys(),
            expected: query.expected,
            found: Some(found),
        }
    }

    pub fn not_issued(query: &ProbeQuery) -> Self {
        Self {
            attribute_keys: query.keys(),
            expected: query.expected,
            found: None,
        }
    }

    pub fn passed(&self) -> bool {
        self.found == Some(self.expected)
    }
}

/// Pass/fail/not-issued across every probe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub passed: usize,
    pub failed: usize,
    /// Probes that could not be issued — no running daemon, or a dry run.
    pub not_issued: usize,
}

impl ProbeSummary {
    pub fn of(results: &[ProbeResult]) -> Self {
        let mut s = Self::default();
        for r in results {
            match r.found {
                None => s.not_issued += 1,
                Some(_) if r.passed() => s.passed += 1,
                Some(_) => s.failed += 1,
            }
        }
        s
    }

    pub fn total(&self) -> usize {
        self.passed + self.failed + self.not_issued
    }
}

/// The three-way tally, with the probe's verdict applied.
///
/// The classification in [`Outcome`] is a statement about the attributes; the
/// probe is a statement about whether the daemon actually returns the item.
/// Where they disagree the probe wins, downgrading
/// [`Outcome::FullyPortable`] to [`Outcome::AttributesPreserved`] — "the
/// attributes are there, the lookup is not proved" is exactly what a failed
/// probe means, and reporting it as fully portable would promise the one
/// thing the import demonstrably did not deliver.
///
/// Matching is by attribute key set, because a key set is all an
/// [`ItemReport`] is allowed to hold. Two different attribute *sets* sharing
/// one key set therefore share a verdict: the pessimistic direction, which is
/// the correct one for a promise.
pub fn tally_with_probes(items: &[ItemReport], probes: &[ProbeResult]) -> Tally {
    // A set, not a list. The lookup below runs once per item and the failed
    // probes are drawn from the same items, so a linear scan here is a
    // whole-`BTreeSet` comparison per (item, failed probe) pair — quadratic in
    // the report, in the one place a large import is guaranteed to be large.
    let failed: BTreeSet<&AttributeKeys> = probes
        .iter()
        .filter(|p| p.found.is_some() && !p.passed())
        .map(|p| &p.attribute_keys)
        .collect();
    let mut tally = Tally::default();
    for item in items {
        if item.is_refused() {
            tally.record_refused();
            continue;
        }
        let downgraded = failed.contains(&item.attribute_keys);
        // Counted through `Tally`'s own recording API rather than by touching
        // its counters: this function and `ImportReport::push` are the two
        // places a tally is built, and they must agree about what each
        // category means.
        match item.outcome {
            Some(Outcome::FullyPortable) if !downgraded => {
                tally.record_outcome(Outcome::FullyPortable);
            }
            Some(Outcome::FullyPortable | Outcome::AttributesPreserved) => {
                tally.record_outcome(Outcome::AttributesPreserved);
            }
            Some(Outcome::PreservedOnly) => tally.record_outcome(Outcome::PreservedOnly),
            // No outcome and no refusal is a bug in whoever built the report;
            // counting it as refused keeps the totals adding up.
            None => tally.record_refused(),
        }
    }
    tally
}

// --------------------------------------------------------------------------
// The secret-length histogram
// --------------------------------------------------------------------------

/// Upper bounds of the histogram's buckets, in bytes. Anything larger falls
/// into a final open-ended bucket.
pub const BUCKET_BOUNDS: [usize; 7] = [0, 16, 64, 256, 1024, 16 * 1024, 256 * 1024];

/// A bucketed distribution of secret *lengths* — never of secrets.
///
/// Source against destination, this localises what a fingerprint mismatch
/// only detects: a stripped trailing newline moves items one bucket down at a
/// specific size, a UTF-8 re-encoding moves the multibyte ones up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Histogram {
    /// One count per bucket, plus the open-ended one.
    counts: Vec<usize>,
}

/// A deserialized histogram's length is checked, not trusted: `counts` comes
/// off a JSON report anyone may have edited, and a short vector would make
/// [`Histogram::add`] index out of bounds.
impl<'de> Deserialize<'de> for Histogram {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let counts = Vec::<usize>::deserialize(d)?;
        if counts.is_empty() {
            return Ok(Self::new());
        }
        if counts.len() != Histogram::BUCKETS {
            return Err(serde::de::Error::custom(format!(
                "a histogram has {} buckets, not {}",
                Histogram::BUCKETS,
                counts.len()
            )));
        }
        Ok(Self { counts })
    }
}

impl Histogram {
    /// The bounded buckets plus the open-ended one.
    const BUCKETS: usize = BUCKET_BOUNDS.len() + 1;

    pub fn new() -> Self {
        Self {
            counts: vec![0; Self::BUCKETS],
        }
    }

    pub fn add(&mut self, len: usize) {
        // Resize rather than test for empty: a `counts` of any other wrong
        // length would index out of bounds below, and `Default` alone can
        // produce one.
        if self.counts.len() != Self::BUCKETS {
            self.counts.resize(Self::BUCKETS, 0);
        }
        let bucket = BUCKET_BOUNDS
            .iter()
            .position(|bound| len <= *bound)
            .unwrap_or(BUCKET_BOUNDS.len());
        self.counts[bucket] += 1;
    }

    pub fn of_lengths(lengths: impl IntoIterator<Item = usize>) -> Self {
        let mut h = Self::new();
        for len in lengths {
            h.add(len);
        }
        h
    }

    /// `(label, count)` per bucket, in ascending order.
    pub fn rows(&self) -> Vec<(String, usize)> {
        let mut rows = Vec::with_capacity(self.counts.len());
        let mut low = 0usize;
        for (i, count) in self.counts.iter().enumerate() {
            let label = match BUCKET_BOUNDS.get(i) {
                Some(0) => "0".to_string(),
                Some(high) => format!("{low}-{high}"),
                None => format!("{low}+"),
            };
            rows.push((label, *count));
            low = BUCKET_BOUNDS.get(i).map_or(low, |b| b + 1);
        }
        rows
    }

    pub fn total(&self) -> usize {
        self.counts.iter().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// One bucket where the two sides disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramDiff {
    pub bucket: String,
    pub source: usize,
    pub destination: usize,
}

/// Over the *longer* of the two, never the shorter: a `zip` stops at the
/// shorter side, so a difference in a trailing bucket — the open-ended one,
/// where a truncation to a huge length lands — would read as no difference at
/// all.
pub fn compare_histograms(source: &Histogram, destination: &Histogram) -> Vec<HistogramDiff> {
    let src = source.rows();
    let dst = destination.rows();
    (0..src.len().max(dst.len()))
        .filter_map(|i| {
            let s = src.get(i).map_or(0, |(_, n)| *n);
            let d = dst.get(i).map_or(0, |(_, n)| *n);
            if s == d {
                return None;
            }
            let bucket = src
                .get(i)
                .or_else(|| dst.get(i))
                .map(|(label, _)| label.clone())
                .unwrap_or_default();
            Some(HistogramDiff {
                bucket,
                source: s,
                destination: d,
            })
        })
        .collect()
}

// --------------------------------------------------------------------------
// The whole verification
// --------------------------------------------------------------------------

/// Everything the four checks concluded. Serialised beside the import report,
/// and holding — by construction — no secret and no attribute value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    pub count: CountCheck,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprint_mismatches: Vec<FingerprintMismatch>,
    /// `None` when no fingerprint comparison was made — a dry run has no
    /// destination to compare against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints_compared: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash_table_misses: Vec<HashMiss>,
    /// `None` for a source with no hash table to check against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_table_checked: Option<usize>,
    pub probes: ProbeSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_probes: Vec<ProbeResult>,
    pub source_lengths: Histogram,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_lengths: Option<Histogram>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub length_differences: Vec<HistogramDiff>,
}

impl Verification {
    /// Every check that was *made* agreed. A check that could not be made —
    /// no header count, no daemon to probe — is neither a pass nor a failure
    /// and is reported by [`Verification::unproved`].
    pub fn passed(&self) -> bool {
        self.count.passed()
            && self.fingerprint_mismatches.is_empty()
            && self.hash_table_misses.is_empty()
            && self.probes.failed == 0
            && self.length_differences.is_empty()
    }

    /// The checks that could not be made, phrased for a terminal. An empty
    /// list is what earns the right to suggest decommissioning.
    pub fn unproved(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.count.made() {
            out.push("the source header gave no independent item count".to_string());
        }
        if self.fingerprints_compared.is_none() {
            out.push("no destination was written, so no fingerprint was compared".to_string());
        }
        if self.probes.not_issued > 0 {
            out.push(format!(
                "{} of {} lookup probes were not issued, so discoverability is unproved",
                self.probes.not_issued,
                self.probes.total()
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{ItemReport, Provenance};
    use zeroize::Zeroizing;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn item(pairs: &[(&str, &str)], secret: &[u8]) -> SourceItem {
        SourceItem {
            label: "router".into(),
            attributes: attrs(pairs),
            secret: Zeroizing::new(secret.to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
            provenance: Provenance::kwallet("kdewallet", "Passwords", "my router"),
        }
    }

    /// The case the length prefixes exist for. Without them both maps
    /// serialise to `abc` and the two items share a fingerprint, so an import
    /// that swapped one for the other would verify clean.
    #[test]
    fn the_length_prefixes_catch_the_ab_bc_collision() {
        let one = attrs(&[("a", "bc")]);
        let two = attrs(&[("ab", "c")]);
        // The concatenation without prefixes really is identical - this is
        // the collision, spelled out, so the test cannot pass for some other
        // reason.
        let naive =
            |m: &BTreeMap<String, String>| m.iter().fold(String::new(), |acc, (k, v)| acc + k + v);
        assert_eq!(naive(&one), naive(&two), "the collision is real");
        assert_ne!(canonical_attrs(&one), canonical_attrs(&two));
        assert_ne!(
            fingerprint(&one, "l", "text/plain", b"s"),
            fingerprint(&two, "l", "text/plain", b"s"),
        );
    }

    /// Canonicalisation depends on the content and not on the order the pairs
    /// were inserted in: two sources that walk a map differently must agree.
    #[test]
    fn canonicalisation_is_order_independent_and_content_sensitive() {
        let mut forwards = BTreeMap::new();
        forwards.insert("a".to_string(), "1".to_string());
        forwards.insert("b".to_string(), "2".to_string());
        forwards.insert("c".to_string(), "3".to_string());
        let mut backwards = BTreeMap::new();
        backwards.insert("c".to_string(), "3".to_string());
        backwards.insert("b".to_string(), "2".to_string());
        backwards.insert("a".to_string(), "1".to_string());
        assert_eq!(canonical_attrs(&forwards), canonical_attrs(&backwards));

        // Every component of the fingerprint moves it.
        let base = fingerprint(&forwards, "label", "text/plain", b"secret");
        let mut changed = forwards.clone();
        changed.insert("a".to_string(), "9".to_string());
        assert_ne!(
            base,
            fingerprint(&changed, "label", "text/plain", b"secret")
        );
        assert_ne!(
            base,
            fingerprint(&forwards, "labeL", "text/plain", b"secret")
        );
        assert_ne!(
            base,
            fingerprint(&forwards, "label", "text/plaiN", b"secret")
        );
        assert_ne!(
            base,
            fingerprint(&forwards, "label", "text/plain", b"secreT")
        );
        // Including a secret that differs only in a trailing newline, which
        // is the exact corruption `sm set` would introduce.
        assert_ne!(
            fingerprint(&forwards, "label", "text/plain", b"secret\n"),
            fingerprint(&forwards, "label", "text/plain", b"secret"),
        );
    }

    /// The same collision, one field further along: with `label` and
    /// `content_type` joined by a bare `0x00` instead of length-prefixed, a
    /// label that itself contains a NUL moves the boundary and two different
    /// items hash the same.
    #[test]
    fn the_label_and_content_type_are_prefixed_too() {
        let a = attrs(&[]);
        assert_ne!(
            fingerprint(&a, "x\u{0}y", "text/plain", b"s"),
            fingerprint(&a, "x", "y\u{0}text/plain", b"s"),
        );
        // And a label whose bytes are a prefix of the next field's is not the
        // same item either.
        assert_ne!(
            fingerprint(&a, "ab", "c", b"s"),
            fingerprint(&a, "a", "bc", b"s"),
        );
    }

    /// An empty value and an absent key are different attribute sets, which
    /// the prefixes also have to distinguish.
    #[test]
    fn an_empty_value_is_not_an_absent_key() {
        assert_ne!(
            canonical_attrs(&attrs(&[("a", "")])),
            canonical_attrs(&attrs(&[])),
        );
        assert_ne!(
            canonical_attrs(&attrs(&[("a", ""), ("b", "")])),
            canonical_attrs(&attrs(&[("ab", "")])),
        );
    }

    #[test]
    fn matching_fingerprint_lists_produce_no_mismatch() {
        let items = [item(&[("server", "a")], b"one"), item(&[], b"two")];
        let source: Vec<_> = items.iter().map(FingerprintEntry::source).collect();
        let destination: Vec<_> = items
            .iter()
            .enumerate()
            .map(|(n, i)| {
                FingerprintEntry::destination(
                    &i.attributes,
                    &i.label,
                    &i.content_type,
                    &i.secret,
                    format!("/org/freedesktop/secrets/collection/imported/{n}"),
                )
            })
            .collect();
        assert!(compare_fingerprints(&source, &destination).is_empty());
    }

    #[test]
    fn a_changed_item_is_reported_from_both_sides_by_keys_and_path() {
        let source = vec![FingerprintEntry::source(&item(&[("server", "a")], b"one"))];
        let changed = item(&[("server", "a")], b"one\n");
        let destination = vec![FingerprintEntry::destination(
            &changed.attributes,
            &changed.label,
            &changed.content_type,
            &changed.secret,
            "/org/freedesktop/secrets/collection/imported/abc",
        )];
        let mismatches = compare_fingerprints(&source, &destination);
        assert_eq!(mismatches.len(), 2, "{mismatches:?}");
        assert_eq!(mismatches[0].side, Side::MissingFromDestination);
        assert_eq!(mismatches[1].side, Side::UnexpectedInDestination);
        assert_eq!(
            mismatches[1].object_path.as_deref(),
            Some("/org/freedesktop/secrets/collection/imported/abc")
        );
        // Keys, never values.
        let json = serde_json::to_string(&mismatches).unwrap();
        assert!(json.contains("server"), "{json}");
        assert!(!json.contains("\"a\""), "{json}");
        assert!(!json.contains("one"), "{json}");
    }

    /// A duplicate that is lost must be reported, which a set difference
    /// would call equal.
    #[test]
    fn losing_one_of_two_identical_items_is_a_mismatch() {
        let it = item(&[("server", "a")], b"one");
        let source = vec![FingerprintEntry::source(&it), FingerprintEntry::source(&it)];
        let destination = vec![FingerprintEntry::source(&it)];
        let mismatches = compare_fingerprints(&source, &destination);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].side, Side::MissingFromDestination);
    }

    #[test]
    fn a_fingerprint_entry_round_trips_through_json_as_hex() {
        let entry = FingerprintEntry::source(&item(&[("a", "b")], b"s"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains(&entry.short()), "{json}");
        let back: FingerprintEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn the_count_check_distinguishes_absent_from_failed() {
        assert!(CountCheck::new(Some(28), 28).passed());
        assert!(!CountCheck::new(Some(28), 27).passed());
        let absent = CountCheck::new(None, 27);
        assert!(absent.passed());
        assert!(!absent.made());
        assert!(absent.to_string().contains("not made"));
        assert!(CountCheck::new(Some(28), 27).to_string().contains("27"));
    }

    /// The RFC 1321 test suite, plus the case a padding bug hides in: an
    /// input of exactly one block.
    #[test]
    fn md5_matches_the_rfc_test_vectors() {
        let cases: &[(&str, &str)] = &[
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(hex(&md5(input.as_bytes())), *expected, "{input:?}");
        }
        // The padding boundaries, each against a golden digest rather than
        // against each other: a padding bug that corrupts two neighbouring
        // lengths equally still leaves them unequal, so `assert_ne!` alone
        // pins nothing. 55/56 is where the second block starts and 119/120 is
        // where the third does.
        let boundaries: &[(&str, &str)] = &[
            (
                "1234567890123456789012345678901234567890123456789012345",
                "c9ccf168914a1bcfc3229f1948e67da0",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456",
                "49f193adce178490e34d1b3a4ec0064c",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                "6261005311809757906e04c0d670492d",
            ),
            (
                "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "1d453b96d48d5e0cec4a20a71fecaa81",
            ),
        ];
        for (input, expected) in boundaries {
            assert_eq!(
                hex(&md5(input.as_bytes())),
                *expected,
                "{} bytes",
                input.len()
            );
        }
    }

    #[test]
    fn the_wallet_hash_table_catches_a_mangled_name() {
        use crate::import::formats::{WalletFolderIndex, WalletInventory};
        let inventory = WalletInventory {
            cipher: 3,
            hash: 2,
            folders: vec![WalletFolderIndex {
                folder_hash: md5(b"Passwords"),
                entry_hashes: vec![md5(b"my router")],
            }],
            ciphertext_offset: 0,
        };
        let good = item(&[], b"s");
        assert!(check_wallet_hash_table(&inventory, std::slice::from_ref(&good)).is_empty());

        let mut mangled = good.clone();
        mangled.provenance = Provenance::kwallet("kdewallet", "Passwords", "my  router");
        let misses = check_wallet_hash_table(&inventory, &[mangled]);
        assert_eq!(misses.len(), 1);
        assert_eq!(misses[0].folder_hash, hex(&md5(b"Passwords")));

        // A gnome-keyring item has no folder or entry to hash and is skipped
        // rather than reported as a miss.
        let mut gnome = good;
        gnome.provenance = Provenance::gnome("Default keyring", 3);
        assert!(check_wallet_hash_table(&inventory, &[gnome]).is_empty());
    }

    #[test]
    fn the_probe_plan_is_one_query_per_distinct_attribute_set() {
        let items = [
            item(&[("server", "a")], b"1"),
            item(&[("server", "a")], b"2"),
            item(&[("server", "b")], b"3"),
            // No attributes: not probeable, because `SearchItems({})` matches
            // everything.
            item(&[], b"4"),
        ];
        let plan = probe_plan(&items);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].expected, 2);
        assert_eq!(plan[1].expected, 1);
        assert_eq!(plan[0].keys(), AttributeKeys::from_names(["server"]));
    }

    #[test]
    fn a_probe_that_was_not_issued_is_not_a_pass() {
        let plan = probe_plan(&[item(&[("server", "a")], b"1")]);
        let issued = ProbeResult::new(&plan[0], 1);
        let missed = ProbeResult::new(&plan[0], 0);
        let skipped = ProbeResult::not_issued(&plan[0]);
        assert!(issued.passed());
        assert!(!missed.passed());
        assert!(!skipped.passed());
        let summary = ProbeSummary::of(&[issued, missed, skipped]);
        assert_eq!(
            summary,
            ProbeSummary {
                passed: 1,
                failed: 1,
                not_issued: 1,
            }
        );
        assert_eq!(summary.total(), 3);
    }

    /// The probe decides the tally: attributes that are present but not
    /// findable are "attributes preserved", never "fully portable".
    #[test]
    fn a_failed_probe_downgrades_a_portable_item() {
        let portable = item(&[("xdg:schema", "org.freedesktop.Secret.Generic")], b"1");
        let reports = vec![ItemReport::imported(&portable)];
        let plan = probe_plan(std::slice::from_ref(&portable));

        let passing = tally_with_probes(&reports, &[ProbeResult::new(&plan[0], 1)]);
        assert_eq!(passing.fully_portable, 1);
        assert_eq!(passing.attributes_preserved, 0);

        let failing = tally_with_probes(&reports, &[ProbeResult::new(&plan[0], 0)]);
        assert_eq!(failing.fully_portable, 0);
        assert_eq!(failing.attributes_preserved, 1);

        // A probe that was never issued proves nothing and changes nothing:
        // the classification stands and `unproved()` says why.
        let unissued = tally_with_probes(&reports, &[ProbeResult::not_issued(&plan[0])]);
        assert_eq!(unissued.fully_portable, 1);
    }

    #[test]
    fn the_tally_still_counts_refusals_and_preserved_only_items() {
        use crate::import::Refusal;
        let reports = vec![
            ItemReport::imported(&item(&[], b"1")),
            ItemReport::refused(
                Provenance::gnome("Login", 1),
                "chained",
                Refusal::ChainedKeyringItem { item_type: 3 },
            ),
        ];
        let tally = tally_with_probes(&reports, &[]);
        assert_eq!(tally.preserved_only, 1);
        assert_eq!(tally.refused, 1);
        assert_eq!(tally.seen(), 2);
    }

    #[test]
    fn the_histogram_buckets_lengths_and_the_comparison_localises_a_truncation() {
        let source = Histogram::of_lengths([0, 1, 16, 17, 300, 1_000_000]);
        assert_eq!(source.total(), 6);
        let rows = source.rows();
        assert_eq!(rows[0], ("0".to_string(), 1));
        assert_eq!(rows.last().unwrap().1, 1, "the open-ended bucket");
        assert!(rows.last().unwrap().0.ends_with('+'));

        // One secret lost its trailing newline: 17 bytes became 16, which
        // moves it a bucket down and the fingerprints only say "different".
        let destination = Histogram::of_lengths([0, 1, 16, 16, 300, 1_000_000]);
        let diff = compare_histograms(&source, &destination);
        assert_eq!(diff.len(), 2);
        assert_eq!(diff[0].bucket, "1-16");
        assert_eq!((diff[0].source, diff[0].destination), (2, 3));
        assert!(compare_histograms(&source, &source).is_empty());
        assert!(Histogram::new().is_empty());
    }

    /// `counts` comes off a JSON file and is not trusted: a short vector would
    /// make `add` index out of bounds, and a comparison that stopped at the
    /// shorter side would call a difference in the trailing buckets equal.
    #[test]
    fn a_histogram_validates_its_length_and_compares_over_the_longer_one() {
        let full = serde_json::to_string(&Histogram::of_lengths([1])).unwrap();
        assert_eq!(
            serde_json::from_str::<Histogram>(&full).unwrap(),
            Histogram::of_lengths([1])
        );
        // Too short to index, and too long to be this histogram: both refused
        // rather than accepted and indexed into.
        assert!(serde_json::from_str::<Histogram>("[1,2,3]").is_err());
        assert!(
            serde_json::from_str::<Histogram>("[0,0,0,0,0,0,0,0,0,0]").is_err(),
            "an over-long histogram is not this histogram"
        );
        // An empty vector is the default, and adding to it must not panic.
        let mut empty: Histogram = serde_json::from_str("[]").unwrap();
        empty.add(1_000_000);
        assert_eq!(empty.total(), 1);

        // The open-ended bucket is the last one, so a `zip` against a shorter
        // side is exactly where a real difference would be dropped.
        let short = Histogram { counts: vec![0; 3] };
        let long = Histogram::of_lengths([1_000_000]);
        let diff = compare_histograms(&short, &long);
        assert_eq!(diff.len(), 1, "{diff:?}");
        assert_eq!((diff[0].source, diff[0].destination), (0, 1));
        assert!(diff[0].bucket.ends_with('+'), "{:?}", diff[0].bucket);
        assert_eq!(compare_histograms(&long, &short).len(), 1);
    }

    #[test]
    fn a_verification_passes_only_when_every_check_it_made_agreed() {
        let mut v = Verification {
            count: CountCheck::new(Some(2), 2),
            fingerprint_mismatches: Vec::new(),
            fingerprints_compared: Some(2),
            hash_table_misses: Vec::new(),
            hash_table_checked: Some(2),
            probes: ProbeSummary {
                passed: 2,
                failed: 0,
                not_issued: 0,
            },
            failed_probes: Vec::new(),
            source_lengths: Histogram::of_lengths([4, 5]),
            destination_lengths: Some(Histogram::of_lengths([4, 5])),
            length_differences: Vec::new(),
        };
        assert!(v.passed());
        assert!(v.unproved().is_empty());

        v.probes.failed = 1;
        assert!(!v.passed());
        v.probes.failed = 0;
        v.count = CountCheck::new(Some(3), 2);
        assert!(!v.passed());

        // Absent checks are unproved, not failed.
        let dry = Verification {
            count: CountCheck::new(None, 2),
            fingerprints_compared: None,
            destination_lengths: None,
            probes: ProbeSummary {
                passed: 0,
                failed: 0,
                not_issued: 2,
            },
            ..v.clone()
        };
        assert_eq!(dry.unproved().len(), 3);

        let json = serde_json::to_string(&v).unwrap();
        let back: Verification = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}
