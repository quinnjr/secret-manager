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
/// Magic plus the u32 header-length prefix.
pub const PREFIX_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: String,
    /// Sorted `attribute_hash` values, one per attribute pair.
    pub attr_hashes: Vec<[u8; 32]>,
}

impl IndexEntry {
    /// True when every query pair hashes to a value present in this entry.
    pub fn matches(&self, salt: &[u8; SALT_LEN], query: &BTreeMap<String, String>) -> bool {
        query.iter().all(|(k, v)| {
            self.attr_hashes
                .binary_search(&attribute_hash(salt, k, v))
                .is_ok()
        })
    }
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
/// applying the same version and KDF checks as [`VaultFile::decode`].
pub fn decode_header(bytes: &[u8]) -> Result<Header, FormatError> {
    let need = header_prefix_len(bytes)?;
    if bytes.len() < need {
        return Err(FormatError::Truncated);
    }
    let header: Header = postcard::from_bytes(&bytes[PREFIX_LEN..need])?;
    check_header(&header)?;
    Ok(header)
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

    pub fn header_bytes(header: &Header) -> Result<Vec<u8>, FormatError> {
        let body = postcard::to_allocvec(header)?;
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
        let need = header_prefix_len(bytes)?;
        if bytes.len() < need {
            return Err(FormatError::Truncated);
        }
        let header: Header = postcard::from_bytes(&bytes[PREFIX_LEN..need])?;
        check_header(&header)?;
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
}
