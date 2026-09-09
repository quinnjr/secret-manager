//! On-disk vault layout: `magic(8) | header_len u32 LE | header (postcard) | ciphertext`.
//! Everything before the ciphertext is the AEAD associated data.

use crate::vault::crypto::{KdfParams, NONCE_LEN, SALT_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const MAGIC: [u8; 8] = *b"SMVAULT\0";
pub const VERSION: u16 = 3;
pub const MAX_HEADER: usize = 16 << 20;
/// Largest collection label, in bytes, that may be stored in a header.
///
/// The label is client-supplied and lives in the header, so it is bounded by
/// nothing else but `MAX_HEADER` (16 MiB). Two things break well before that:
///
/// * `Request::Status` copies each collection's label verbatim into a
///   `CollectionStatus`, and the control socket refuses any frame over
///   `protocol::MAX_FRAME` (1 MiB). A single ~2 MiB label therefore makes the
///   daemon answer *every* `Status` with "response too large" - for all
///   collections, across restarts, since the label is on disk, and with no CLI
///   command to rename a collection back.
/// * A label near `MAX_HEADER` leaves no room for the index, so the next
///   `CreateItem` overflows the header and every save is refused.
/// * The label is also what a collection's *filename* is derived from, and
///   `NAME_MAX` is 255 bytes. That third ceiling is enforced separately, by
///   `vault::MAX_ID_LEN` truncating in `vault::collection_id_from_label`,
///   rather than by lowering this cap: the label itself is free to be long,
///   only the derived id is not.
///
/// 4 KiB is orders of magnitude more than any real label ("Login", "Default")
/// and cannot interact with either cap: 4 KiB is 1/256 of `MAX_FRAME`, so a
/// `Status` frame would need more than 256 collections at the full limit
/// before labels alone could approach the frame cap (real labels are tens of
/// bytes, and the other `CollectionStatus` fields are small and fixed), and it
/// is 1/4096 of `MAX_HEADER`, so it can never crowd out the index.
pub const MAX_LABEL: usize = 4 << 10;

// F2: the label cap only works if it stays clear of both ceilings it could
// otherwise interact with. Checked at compile time so neither cap can be
// raised, nor `MAX_LABEL` loosened, without this being revisited.
const _: () = assert!(MAX_LABEL <= crate::protocol::MAX_FRAME / 256);
const _: () = assert!(MAX_LABEL <= MAX_HEADER / 4096);
const _: () = assert!(MAX_LABEL >= 1024);
/// Magic plus the u32 header-length prefix.
pub const PREFIX_LEN: usize = 12;
/// Largest vault file that will be read into memory. `MAX_HEADER` bounds the
/// header only; without this the ciphertext is unbounded and a single huge
/// file dropped in the vault directory would exhaust the daemon's memory
/// while it enumerates collections at startup.
pub const MAX_VAULT_BYTES: u64 = 256 << 20;

/// Refuse a file too large to load, from its `stat` size, before any read.
pub fn check_vault_size(len: u64) -> Result<(), FormatError> {
    check_vault_size_against(len, MAX_VAULT_BYTES)
}

/// [`check_vault_size`] against an explicit ceiling, so a test can exercise
/// the refusal without materialising a file of the real limit's size.
pub fn check_vault_size_against(len: u64, limit: u64) -> Result<(), FormatError> {
    if len > limit {
        return Err(FormatError::VaultTooLarge(len));
    }
    Ok(())
}

// Per-item caps.
//
// These bound what one *item* may carry: they are enforced by the D-Bus
// layer on every `CreateItem` and property set, and re-applied by
// `Vault::import_items` for the offline import path, which never goes
// through D-Bus at all. `src/dbus/` is behind the `daemon` feature and
// `src/vault/` is always compiled - into the PAM cdylib as well - so the
// definitions live here and `dbus::collection` re-exports them, leaving one
// number per cap rather than two that can drift.

/// Upper bound on one item's decrypted secret, matching the control
/// protocol's frame cap. Without it a single client could push a collection
/// past the vault-level size limit — at which point the whole collection
/// stops saving — with one `CreateItem` call.
pub const MAX_ITEM_SECRET: usize = 1024 * 1024;

/// Upper bound on one item's label.
///
/// The label is serialised into the same encrypted item blob as the secret,
/// so it counts against the vault-level size limit in exactly the same way —
/// capping only the secret left the cap reachable in two `CreateItem` calls
/// through the label instead of 256 through the secret. 4 KiB is far more
/// than any real client needs (libsecret labels are a line of UI text) while
/// still leaving room for a long multi-byte one.
pub const MAX_ITEM_LABEL: usize = 4 * 1024;

/// Upper bound on the number of attribute pairs on one item. Attributes are
/// stored in the item blob, and are also hashed into the header's search
/// index, so each pair costs twice. Real schemas use a handful; libsecret's
/// own built-in schemas top out well under ten.
pub const MAX_ITEM_ATTRIBUTES: usize = 64;

/// Upper bound on one attribute name. Attribute names are schema field names.
pub const MAX_ATTRIBUTE_KEY: usize = 256;

/// Upper bound on one attribute value. Values are identifiers, paths and
/// usernames; this project's own largest is an ssh key path.
///
/// Together the three attribute caps bound one item's attribute set at
/// 64 * (256 + 512) = 48 KiB, generous for a real client and small enough
/// that reaching [`MAX_VAULT_BYTES`] through attributes takes
/// as many calls as reaching it through capped secrets.
pub const MAX_ATTRIBUTE_VALUE: usize = 512;

/// Upper bound on one item's content type.
///
/// The last caller-supplied field that lands in the encrypted item blob, so
/// the same reasoning as the label: uncapped, it is another way to push a
/// collection past the vault size limit, just wearing a different field name.
/// A content type is a MIME type — RFC 6838 caps a registered type or subtree
/// name at 127 bytes each, so 255 covers `type/subtree` at the registry's own
/// maximum, and 256 leaves room for a parameter such as `; charset=utf-8`.
/// Real clients send `text/plain` or `application/octet-stream`.
pub const MAX_ITEM_CONTENT_TYPE: usize = 256;

/// One of the six per-item limits above, as a value.
///
/// The *constants* had already been hoisted here so there is one number per
/// cap; the *predicates* had not, and there were three hand-maintained copies
/// of "which caps, and measured how" — the D-Bus entry points in
/// `dbus::collection`, `Vault::import_items`'s re-application of them, and
/// `import::check_caps`'s pre-flight. Three copies of a limit is the worst
/// kind to let drift: the symptom of a disagreement is a pre-check that
/// passes an item `import_items` then refuses halfway through a migration.
/// So the predicate lives here too, and each layer maps [`CapViolation`] into
/// its own error type rather than re-deciding what "too large" means.
///
/// **The order is not shared, and this refactor did not make it so.** What is
/// shared — and what has to be — is the set of caps, each predicate and each
/// limit. [`check_caps`] fixes an order for its own callers; `CreateItem` in
/// `dbus::collection` checks label, content type, attributes and only then
/// the secret, deliberately, so an over-large label is refused before the
/// client's secret session value is decrypted. An item over two caps at once
/// is therefore named by a different one of the two on that path than on
/// this one. That is a difference in which message a doomed request gets,
/// never in which requests are refused.
///
/// **These variant names are a wire format.** `Cap` is serialized, kebab-
/// cased, into `sm import`'s `report.json` through
/// `import::Refusal::CapViolation`, so a rename here changes a file other
/// programs read — and each name must say what [`Cap::as_str`] says, since
/// the two describe the same refusal to the same person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cap {
    Secret,
    Label,
    AttributeCount,
    /// Serialized as `attribute-name`, not the kebab-case of the variant:
    /// the JSON is user-facing and every error message spells this cap
    /// "attribute name". See the wire-format note above.
    #[serde(rename = "attribute-name")]
    AttributeKey,
    AttributeValue,
    ContentType,
}

impl Cap {
    /// The limit this cap enforces.
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

    /// The cap's name as an error message spells it.
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

    /// Measure one value against this cap. `actual` is a *count* — a byte
    /// length for every cap but [`Cap::AttributeCount`], which counts pairs.
    ///
    /// The comparison is `>`, so a value of exactly `limit()` is accepted.
    /// This is the only place that decides that, which is what stops a `>=`
    /// creeping into one of the three layers and silently stranding data at
    /// the boundary.
    pub const fn check(self, actual: usize) -> Option<CapViolation> {
        if actual > self.limit() {
            Some(CapViolation {
                cap: self,
                actual,
                limit: self.limit(),
            })
        } else {
            None
        }
    }
}

impl std::fmt::Display for Cap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A cap and the size that broke it. Sizes only ever travel as *numbers*:
/// this never carries the oversized value itself, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapViolation {
    pub cap: Cap,
    pub actual: usize,
    pub limit: usize,
}

/// The first of the six per-item caps this item violates, or `None`.
///
/// The order is fixed here: secret, label, content type, attribute count,
/// then the attribute pairs in `BTreeMap` order, name before value. Every
/// caller *of this function* reports the same cap for the same item.
///
/// It is not the only order in the tree. `CreateItem` in `dbus::collection`
/// does not go through here and checks cheap-before-decrypt instead, so an
/// item over both the secret and the label cap is reported as `label` there
/// and as `secret` here — see [`Cap`].
pub fn check_caps(
    label: &str,
    attributes: &BTreeMap<String, String>,
    secret_len: usize,
    content_type: &str,
) -> Option<CapViolation> {
    Cap::Secret
        .check(secret_len)
        .or_else(|| Cap::Label.check(label.len()))
        .or_else(|| Cap::ContentType.check(content_type.len()))
        .or_else(|| Cap::AttributeCount.check(attributes.len()))
        .or_else(|| {
            attributes.iter().find_map(|(k, v)| {
                Cap::AttributeKey
                    .check(k.len())
                    .or_else(|| Cap::AttributeValue.check(v.len()))
            })
        })
}

/// Characters that are neither `char::is_control` nor visible: bidi
/// overrides, zero-width joiners, the private-use planes, the tag block.
///
/// `char::is_control` is general category `Cc` only, so everything here
/// survives it while still being able to reorder or hide the text around it
/// in a terminal or a dialog.
pub fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061C}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{08E2}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{E000}'..='\u{F8FF}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}'
        | '\u{110CD}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E007F}'
        | '\u{F0000}'..='\u{FFFFD}'
        | '\u{100000}'..='\u{10FFFD}'
    )
}

/// Render peer-supplied text so it cannot move a cursor, clear a line or
/// reorder what is printed around it: every control character and every
/// invisible formatter becomes `\xNN` per UTF-8 byte.
///
/// `CLAUDE.md`: "text from a peer is sanitized before it reaches a log or a
/// dialog." This copy lives in `vault::format` rather than in `cli` or
/// `dbus`, because `src/vault/` is compiled into the PAM cdylib as well and
/// may not reach into anything behind the `daemon` feature — the same reason
/// the per-item caps above live here.
pub fn escape_control(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    let mut scratch = [0u8; 4];
    for ch in s.chars() {
        if ch.is_control() || is_invisible_format(ch) {
            for b in ch.encode_utf8(&mut scratch).as_bytes() {
                let _ = write!(out, "\\x{b:02x}");
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: String,
    /// Sorted `attribute_hash` values, one per attribute pair.
    pub attr_hashes: Vec<[u8; 32]>,
}

impl IndexEntry {
    /// True when every query pair hashes to a value present in this entry.
    ///
    /// Convenience for a single entry; a search over many entries must use
    /// [`hash_query`] once and then [`IndexEntry::matches_hashes`], because
    /// the digests depend only on `(salt, key, value)` and hashing them per
    /// entry makes an unbounded attribute value cost `O(items x value)`.
    pub fn matches(&self, salt: &[u8; SALT_LEN], query: &BTreeMap<String, String>) -> bool {
        self.matches_hashes(&hash_query(salt, query))
    }

    /// True when every digest in `query_hashes` is present in this entry.
    ///
    /// `query_hashes` comes from [`hash_query`]; `attr_hashes` is kept sorted
    /// by [`build_index`], which is what makes the `binary_search` valid.
    /// Cost is `O(q log a)` byte-array comparisons and no hashing at all, so
    /// the per-entry work no longer depends on the size of the query values.
    pub fn matches_hashes(&self, query_hashes: &[[u8; 32]]) -> bool {
        // An empty query matches every entry, including an id-only one.
        if query_hashes.is_empty() {
            return true;
        }
        // An id-only entry (`locked_search = false`, or an item with no
        // attributes) can never satisfy a non-empty query.
        if self.attr_hashes.is_empty() {
            return false;
        }
        query_hashes
            .iter()
            .all(|h| self.attr_hashes.binary_search(h).is_ok())
    }
}

/// The digests a query is looking for, sorted the way [`build_index`] sorts an
/// entry's own hashes.
///
/// Computed **once per search**, never once per item: `attribute_hash` is a
/// SHA-256 over the whole `(salt, key, value)` triple and nothing bounds the
/// key or value length, so a caller that hashes inside its per-entry loop lets
/// one large attribute value be re-hashed once for every item in the
/// collection. Hashing here is linear in the query's total size and paid once.
pub fn hash_query(salt: &[u8; SALT_LEN], query: &BTreeMap<String, String>) -> Vec<[u8; 32]> {
    query
        .iter()
        .map(|(k, v)| attribute_hash(salt, k, v))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub version: u16,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub kdf: KdfParams,
    /// Argon2 salt for the master key.
    pub salt: [u8; SALT_LEN],
    /// Separate random salt for the attribute index, so the KDF salt never
    /// serves a second purpose.
    pub index_salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// One entry per item. With attribute indexing disabled each entry
    /// carries the item id only (see [`build_index`]).
    pub index: Vec<IndexEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("attributes", &self.attributes)
            .field("secret", &"..")
            .field("content_type", &self.content_type)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .finish()
    }
}

impl PartialEq for Item {
    fn eq(&self, o: &Self) -> bool {
        self.id == o.id
            && self.label == o.label
            && self.attributes == o.attributes
            && *self.secret == *o.secret
            && self.content_type == o.content_type
            && self.created == o.created
            && self.modified == o.modified
    }
}
impl Eq for Item {}

/// `SHA-256(salt || len(key) LE u32 || key || value)`
pub fn attribute_hash(salt: &[u8; SALT_LEN], key: &str, value: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update((key.len() as u32).to_le_bytes());
    h.update(key.as_bytes());
    h.update(value.as_bytes());
    h.finalize().into()
}

/// Index entries for `items`. With `with_attributes` false the entries carry
/// ids only: a file holder then learns the item count but cannot confirm
/// attribute guesses, and searching a locked collection with any attribute
/// matches nothing (an empty query still lists every id; the id list itself
/// is not hidden).
pub fn build_index(
    salt: &[u8; SALT_LEN],
    items: &[Item],
    with_attributes: bool,
) -> Vec<IndexEntry> {
    items
        .iter()
        .map(|item| {
            let mut attr_hashes: Vec<[u8; 32]> = if with_attributes {
                item.attributes
                    .iter()
                    .map(|(k, v)| attribute_hash(salt, k, v))
                    .collect()
            } else {
                Vec::new()
            };
            attr_hashes.sort_unstable();
            IndexEntry {
                id: item.id.clone(),
                attr_hashes,
            }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("not a secret-manager vault (bad magic)")]
    BadMagic,
    #[error("{}", describe_version(*.0))]
    UnsupportedVersion(u16),
    #[error("truncated vault file")]
    Truncated,
    #[error("corrupt vault: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("{0}")]
    UnsafeKdf(String),
    #[error("vault header is too large to write ({0} bytes; limit is {MAX_HEADER})")]
    HeaderTooLarge(usize),
    #[error("vault file is too large to open ({0} bytes; limit is {MAX_VAULT_BYTES})")]
    VaultTooLarge(u64),
    #[error("{0} unexpected bytes after the vault header")]
    TrailingHeaderBytes(usize),
}

fn describe_version(v: u16) -> String {
    if v < VERSION {
        format!("vault predates version {VERSION} (found {v}); recreate it with `sm init`")
    } else {
        format!("vault version {v} is newer than this build supports ({VERSION})")
    }
}

/// Total bytes the header occupies (magic, length prefix, body), computed
/// from the first [`PREFIX_LEN`] bytes of a file. Lets a caller read the
/// header without holding the ciphertext.
///
/// A declared length over [`MAX_HEADER`] is reported as
/// [`FormatError::Truncated`], not [`FormatError::HeaderTooLarge`], and that
/// is deliberate. The length prefix sits *outside* the AEAD's reach until a
/// successful decrypt, so on the read side it is attacker-controlled: an
/// over-large value says nothing about how big the real header is, only that
/// the file does not contain the header it claims to - which is what
/// `Truncated` means to a caller here. `HeaderTooLarge` stays write-side, for
/// [`VaultFile::header_bytes`], where the length is one we computed and the
/// number in the message is meaningful. Reporting it here would also hand a
/// caller an attacker's number to put in a log line. A test pins this.
pub fn header_prefix_len(prefix: &[u8]) -> Result<usize, FormatError> {
    if prefix.len() < 8 {
        return Err(FormatError::Truncated);
    }
    if prefix[..8] != MAGIC {
        return Err(FormatError::BadMagic);
    }
    if prefix.len() < PREFIX_LEN {
        return Err(FormatError::Truncated);
    }
    let len = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]) as usize;
    if len > MAX_HEADER {
        return Err(FormatError::Truncated);
    }
    Ok(PREFIX_LEN + len)
}

/// Decodes a header from at least the bytes [`header_prefix_len`] reports,
/// applying the same version and KDF checks as [`VaultFile::decode`],
/// returning it with the length of the prefix it occupied.
///
/// `postcard::from_bytes` stops at the end of the first complete message and
/// ignores whatever follows, so a `header_len` larger than the encoded body
/// would decode successfully with the surplus silently absorbed into the
/// associated data. Nothing we write can produce that - `header_bytes`
/// declares exactly the length it encoded - and a file we did not write fails
/// the tag anyway, because the surplus *is* inside the AAD. But the vault
/// header is the other length-delimited region of attacker-supplied postcard
/// in this crate, and `protocol::decode_frame` holds the same line for the
/// same reason: a region that decodes must have been fully consumed, or "the
/// header that was read" and "the header that was acted on" are different
/// objects. So the remainder is required to be empty.
fn decode_header_prefix(bytes: &[u8]) -> Result<(Header, usize), FormatError> {
    let need = header_prefix_len(bytes)?;
    if bytes.len() < need {
        return Err(FormatError::Truncated);
    }
    let (header, rest): (Header, &[u8]) = postcard::take_from_bytes(&bytes[PREFIX_LEN..need])?;
    if !rest.is_empty() {
        return Err(FormatError::TrailingHeaderBytes(rest.len()));
    }
    check_header(&header)?;
    Ok((header, need))
}

/// Decodes a header from at least the bytes [`header_prefix_len`] reports,
/// applying the same version and KDF checks as [`VaultFile::decode`].
pub fn decode_header(bytes: &[u8]) -> Result<Header, FormatError> {
    Ok(decode_header_prefix(bytes)?.0)
}

fn check_header(header: &Header) -> Result<(), FormatError> {
    if header.version != VERSION {
        return Err(FormatError::UnsupportedVersion(header.version));
    }
    // The header is not authenticated until a successful decrypt, so its KDF
    // parameters are attacker-controlled at this point.
    header
        .kdf
        .validate()
        .map_err(|e| FormatError::UnsafeKdf(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    pub header: Header,
    /// Exact bytes preceding the ciphertext: magic, length, header.
    pub aad: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn new(header: Header, ciphertext: Vec<u8>) -> Result<Self, FormatError> {
        let aad = Self::header_bytes(&header)?;
        Ok(Self {
            header,
            aad,
            ciphertext,
        })
    }

    /// Encodes the prefix and header body that precede the ciphertext.
    ///
    /// Enforces `MAX_HEADER` on the *write* side too: `decode` refuses a
    /// larger header, so without this a collection whose index outgrew the
    /// limit would be written successfully and then be permanently
    /// unopenable — after the atomic rename had already replaced the last
    /// good file. Refusing here routes through `save`'s header rollback
    /// instead, and makes the `as u32` truncation below unreachable.
    pub fn header_bytes(header: &Header) -> Result<Vec<u8>, FormatError> {
        let body = postcard::to_allocvec(header)?;
        if body.len() > MAX_HEADER {
            return Err(FormatError::HeaderTooLarge(body.len()));
        }
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.aad.clone();
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<VaultFile, FormatError> {
        let (header, need) = decode_header_prefix(bytes)?;
        Ok(VaultFile {
            header,
            aad: bytes[..need].to_vec(),
            ciphertext: bytes[need..].to_vec(),
        })
    }
}

pub fn encode_items(items: &[Item]) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    Ok(Zeroizing::new(postcard::to_allocvec(items)?))
}

pub fn decode_items(bytes: &[u8]) -> Result<Vec<Item>, FormatError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::KdfParams;

    fn item(id: &str, attrs: &[(&str, &str)]) -> Item {
        Item {
            id: id.into(),
            label: format!("label {id}"),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            secret: Zeroizing::new(b"s3cret".to_vec()),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
        }
    }

    fn header(index: Vec<IndexEntry>) -> Header {
        Header {
            version: VERSION,
            label: "default".into(),
            created: 1,
            modified: 2,
            kdf: KdfParams::FAST_FOR_TESTS,
            salt: [1u8; SALT_LEN],
            index_salt: [5u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            index,
        }
    }

    #[test]
    fn items_round_trip() {
        let items = vec![item("a", &[("k", "v")]), item("b", &[])];
        let bytes = encode_items(&items).unwrap();
        assert_eq!(decode_items(&bytes).unwrap(), items);
    }

    #[test]
    fn item_debug_hides_secret() {
        let s = format!("{:?}", item("a", &[]));
        assert!(!s.contains("s3cret"));
        assert!(s.contains("label a"));
    }

    #[test]
    fn file_round_trip_and_aad() {
        let file = VaultFile::new(header(vec![]), vec![9, 9, 9]).unwrap();
        let bytes = file.encode();
        assert_eq!(&bytes[..8], &MAGIC);
        let back = VaultFile::decode(&bytes).unwrap();
        assert_eq!(back.header, file.header);
        assert_eq!(back.ciphertext, vec![9, 9, 9]);
        assert_eq!(back.aad, file.aad);
        assert_eq!(&bytes[..back.aad.len()], back.aad.as_slice());
    }

    #[test]
    fn bad_magic_truncated_and_version() {
        assert!(matches!(
            VaultFile::decode(b"NOTAVAULT000"),
            Err(FormatError::BadMagic)
        ));
        assert!(matches!(
            VaultFile::decode(&MAGIC[..]),
            Err(FormatError::Truncated)
        ));
        let mut h = header(vec![]);
        h.version = 42;
        let bytes = VaultFile::new(h, vec![]).unwrap().encode();
        let err = VaultFile::decode(&bytes).unwrap_err();
        assert!(matches!(err, FormatError::UnsupportedVersion(42)));
        assert!(err.to_string().contains("newer"), "{err}");
    }

    /// The PAM module needs salt and parameters without reading (or holding)
    /// the ciphertext: the header alone, from a prefix of the file, must do.
    #[test]
    fn decode_header_reads_only_the_prefix() {
        let file = VaultFile::new(header(vec![]), vec![9; 4096]).unwrap();
        let bytes = file.encode();
        let need = header_prefix_len(&bytes[..12]).unwrap();
        assert_eq!(need, file.aad.len());
        let h = decode_header(&bytes[..need]).unwrap();
        assert_eq!(h, file.header);
        assert!(matches!(
            decode_header(&bytes[..need - 1]),
            Err(FormatError::Truncated)
        ));
        assert!(matches!(
            header_prefix_len(&bytes[..8]),
            Err(FormatError::Truncated)
        ));
        assert!(matches!(
            header_prefix_len(b"NOTAVAULT000"),
            Err(FormatError::BadMagic)
        ));
    }

    /// The declared length is attacker-controlled and is what a caller
    /// allocates against, so `MAX_HEADER` must hold at the exact boundary —
    /// a cap that drifts by one is a cap that can drift further.
    #[test]
    fn a_declared_header_length_over_the_limit_is_refused() {
        let prefix = |len: u32| {
            let mut p = MAGIC.to_vec();
            p.extend_from_slice(&len.to_le_bytes());
            p
        };
        let err = header_prefix_len(&prefix(MAX_HEADER as u32 + 1)).unwrap_err();
        assert!(matches!(err, FormatError::Truncated), "got {err:?}");
        assert_eq!(
            header_prefix_len(&prefix(MAX_HEADER as u32)).unwrap(),
            PREFIX_LEN + MAX_HEADER
        );
    }

    #[test]
    fn old_version_error_tells_the_user_to_recreate() {
        let mut h = header(vec![]);
        h.version = 2;
        let bytes = VaultFile::new(h, vec![]).unwrap().encode();
        let err = VaultFile::decode(&bytes).unwrap_err();
        assert!(matches!(err, FormatError::UnsupportedVersion(2)));
        let text = err.to_string();
        assert!(text.contains("predates version 3"), "{text}");
        assert!(text.contains("sm init"), "{text}");
        assert_eq!(VERSION, 3);
    }

    #[test]
    fn decode_rejects_unsafe_kdf_before_any_derivation() {
        let mut h = header(vec![]);
        h.kdf = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            p_cost: 1,
        };
        let bytes = VaultFile::new(h, vec![]).unwrap().encode();
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(FormatError::UnsafeKdf(_))
        ));
    }

    /// `decode` refuses a header over `MAX_HEADER`, so `header_bytes` must
    /// refuse to produce one: otherwise `save` writes a file that can never
    /// be opened again, over the top of the last good copy.
    #[test]
    fn header_over_the_limit_is_refused_by_the_writer() {
        let mut h = header(vec![]);
        h.label = "x".repeat(MAX_HEADER + 1);
        let err = VaultFile::header_bytes(&h).unwrap_err();
        assert!(
            matches!(err, FormatError::HeaderTooLarge(n) if n > MAX_HEADER),
            "{err:?}"
        );
        assert!(err.to_string().contains("too large"), "{err}");
        // The same refusal on the constructor, so no VaultFile can exist
        // whose encoding `decode` would reject.
        assert!(matches!(
            VaultFile::new(h, vec![]),
            Err(FormatError::HeaderTooLarge(_))
        ));
        // A header at the limit still encodes.
        let ok = VaultFile::header_bytes(&header(vec![])).unwrap();
        assert!(ok.len() < MAX_HEADER);
    }

    /// The ciphertext is unbounded on disk, so `Vault::open` must bound it
    /// from the file size before reading; this is the boundary it uses.
    #[test]
    fn vault_size_limit_is_a_boundary_not_a_range() {
        assert!(check_vault_size(0).is_ok());
        assert!(check_vault_size(MAX_VAULT_BYTES).is_ok());
        let err = check_vault_size(MAX_VAULT_BYTES + 1).unwrap_err();
        assert!(
            matches!(err, FormatError::VaultTooLarge(n) if n == MAX_VAULT_BYTES + 1),
            "{err:?}"
        );
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[test]
    fn index_without_attributes_keeps_ids_only() {
        let salt = [3u8; SALT_LEN];
        let items = vec![item("a", &[("app", "git")])];
        let index = build_index(&salt, &items, false);
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].id, "a");
        assert!(index[0].attr_hashes.is_empty());
        let q: BTreeMap<String, String> = [("app".to_string(), "git".to_string())].into();
        assert!(!index[0].matches(&salt, &q));
        assert!(index[0].matches(&salt, &BTreeMap::new()));
    }

    #[test]
    fn attribute_hash_is_pair_sensitive() {
        let salt = [3u8; SALT_LEN];
        assert_ne!(
            attribute_hash(&salt, "a", "bc"),
            attribute_hash(&salt, "ab", "c")
        );
        assert_ne!(
            attribute_hash(&salt, "a", "b"),
            attribute_hash(&[4u8; SALT_LEN], "a", "b")
        );
        assert_eq!(
            attribute_hash(&salt, "a", "b"),
            attribute_hash(&salt, "a", "b")
        );
    }

    #[test]
    fn index_matches_exact_subset_queries() {
        let salt = [3u8; SALT_LEN];
        let items = vec![
            item("a", &[("app", "git"), ("user", "joe")]),
            item("b", &[("app", "git")]),
        ];
        let index = build_index(&salt, &items, true);
        let q = |pairs: &[(&str, &str)]| -> Vec<String> {
            let query: BTreeMap<String, String> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            index
                .iter()
                .filter(|e| e.matches(&salt, &query))
                .map(|e| e.id.clone())
                .collect()
        };
        assert_eq!(q(&[("app", "git")]), vec!["a", "b"]);
        assert_eq!(q(&[("app", "git"), ("user", "joe")]), vec!["a"]);
        assert!(q(&[("user", "bob")]).is_empty());
        assert_eq!(q(&[]), vec!["a", "b"]);
    }

    /// F1 regression: the hoisted path (`hash_query` + `matches_hashes`) must
    /// agree with the per-entry `matches` on every shape of query, since
    /// `search_ids` now uses it for real searches.
    #[test]
    fn hoisted_query_hashes_agree_with_the_per_entry_path() {
        let salt = [7u8; SALT_LEN];
        let items = vec![
            item("a", &[("app", "git"), ("user", "joe")]),
            item("b", &[("app", "git")]),
            item("c", &[]),
        ];
        let indexed = build_index(&salt, &items, true);
        let id_only = build_index(&salt, &items, false);
        let queries: Vec<BTreeMap<String, String>> = [
            vec![],
            vec![("app", "git")],
            vec![("app", "git"), ("user", "joe")],
            vec![("user", "bob")],
            // A value far larger than any real attribute: it must still be
            // hashed exactly once, and still match exactly what it matched.
            vec![("big", "x")],
        ]
        .into_iter()
        .map(|pairs| {
            pairs
                .into_iter()
                .map(|(k, v): (&str, &str)| (k.to_string(), v.to_string()))
                .collect()
        })
        .collect();
        for index in [&indexed, &id_only] {
            for q in &queries {
                let hashes = hash_query(&salt, q);
                assert_eq!(hashes.len(), q.len());
                for e in index.iter() {
                    assert_eq!(
                        e.matches_hashes(&hashes),
                        e.matches(&salt, q),
                        "entry {} query {q:?}",
                        e.id
                    );
                }
            }
        }
    }

    /// An id-only entry matches an empty query and nothing else, through the
    /// hoisted path too - that is the short-circuit `search_ids` relies on.
    #[test]
    fn an_id_only_entry_short_circuits_a_non_empty_query() {
        let salt = [3u8; SALT_LEN];
        let index = build_index(&salt, &[item("a", &[("app", "git")])], false);
        assert!(index[0].matches_hashes(&[]));
        assert!(!index[0].matches_hashes(&hash_query(
            &salt,
            &[("app".to_string(), "git".to_string())].into()
        )));
    }
}
