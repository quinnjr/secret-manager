//! Bounded property tests for the `sm import` cleartext header parsers.
//!
//! A `.keyring` or a `.kwl` is a file on disk that a hostile party may have
//! written, and `sm import --inventory` reads it with no authentication of
//! any kind — the integrity check lives inside the encrypted half, which
//! these parsers never touch. So the invariant is the one
//! `tests/prop_vault.rs` asserts of the vault decoder: **any** byte string is
//! either parsed or rejected with a typed error, and never panics, never
//! allocates from a length field, and never runs off the end of the buffer.
//!
//! Uniformly random bytes bounce off the magic number, so most of the
//! strategies below are structure-aware in the style of `fuzz/src/lib.rs`:
//! a real magic with a hostile count, a well-formed prologue with a truncated
//! index, a valid file with one byte changed.
//!
//! # Reaching the code, and proving it
//!
//! An earlier version of this file did not reach `parse_keyring_item` at all.
//! Two filters compounded: the version tuple was drawn `(0u8..4, 0u8..4)`, so
//! fifteen cases in sixteen were refused by the version gate *before* any
//! length or count was read, and the declared item count was a bare
//! `any::<u32>()`, which is an impossible length for a file of this size in
//! all but about one draw in a million. The attribute loop, both value
//! encodings, the NULL marker and the unknown-type refusal therefore had zero
//! property coverage — the exact failure `docs/fuzzing.md` describes, and
//! reproduced inside the structure-aware generator that exists to prevent it.
//!
//! So the generators here weight every gate towards the value that gets past
//! it, and every count is a `prop_oneof!` of honest, boundary and arbitrary
//! values rather than one of the three. Two things then follow that a
//! "did not panic" assertion cannot give:
//!
//! - a case that is honest in *every* respect must parse, and must parse to
//!   the values it was built from — a real oracle, not an absence of a crash;
//! - [`the_generators_reach_every_shape_the_parsers_can_produce`] samples the
//!   strategies and asserts the distribution: so many cases parsed, so many
//!   reached the item loop, so many hit each refusal. A generator that stops
//!   reaching the interesting code fails that test instead of silently
//!   testing the magic number nine hundred times.

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use secret_manager::import::Source;
use secret_manager::import::formats::{
    self, HeaderError, KEYRING_MAGIC, KWALLET_MAGIC, KeyringInventory, MAX_SOURCE_BYTES,
    WalletInventory, parse_default_file, parse_keyring_header, parse_wallet_header,
};
use std::collections::BTreeSet;

fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

// --------------------------------------------------------------------------
// Counts and lengths
// --------------------------------------------------------------------------

/// A declared count or length: mostly an honest small number, sometimes one
/// of the boundary values that decide the `count` check, sometimes anything
/// at all.
///
/// The mix is the point. Only small values reach the loop the count guards;
/// only the boundary values exercise the guard itself; only the arbitrary arm
/// finds what neither anticipated. Drawing a bare `any::<u32>()`, as this
/// file used to, is all guard and no loop.
fn declared_count() -> impl Strategy<Value = u32> {
    prop_oneof![
        6 => 0u32..5,
        3 => prop_oneof![
            Just(0u32),
            Just(1u32),
            Just(u32::MAX),
            Just(u32::MAX - 1),
            Just(1u32 << 30),
            Just(0x0F00_0000u32),
        ],
        1 => any::<u32>(),
    ]
}

/// `None` means "encode the honest length"; `Some(n)` overrides it with `n`.
fn maybe_declared() -> impl Strategy<Value = Option<u32>> {
    prop_oneof![7 => Just(None), 3 => declared_count().prop_map(Some)]
}

// --------------------------------------------------------------------------
// gnome-keyring
// --------------------------------------------------------------------------

/// One attribute in a keyring's cleartext index.
#[derive(Debug, Clone)]
struct AttrSpec {
    name: Vec<u8>,
    /// Encode the name as the format's NULL (`0xffffffff`) instead.
    null_name: bool,
    declared_name_len: Option<u32>,
    attr_type: u32,
    value: Vec<u8>,
    declared_value_len: Option<u32>,
}

impl AttrSpec {
    fn encode(&self, out: &mut Vec<u8>) {
        if self.null_name {
            out.extend_from_slice(&be(u32::MAX));
        } else {
            out.extend_from_slice(&be(self
                .declared_name_len
                .unwrap_or(self.name.len() as u32)));
            out.extend_from_slice(&self.name);
        }
        out.extend_from_slice(&be(self.attr_type));
        match self.attr_type {
            // A hashed string value, length-prefixed.
            0 => {
                out.extend_from_slice(&be(self
                    .declared_value_len
                    .unwrap_or(self.value.len() as u32)));
                out.extend_from_slice(&self.value);
            }
            // A 32-bit hash.
            1 => out.extend_from_slice(&be(0xDEAD_BEEF)),
            // Anything else is refused before a value is read, so none is
            // written: writing one would move the failure to the next field.
            _ => {}
        }
    }

    /// The name this attribute contributes, when it contributes one.
    fn honest_name(&self) -> Option<&str> {
        if self.null_name || self.declared_name_len.is_some() {
            return None;
        }
        std::str::from_utf8(&self.name).ok()
    }

    /// Whether this attribute is encoded exactly as a real file would encode
    /// it — every length honest, a type the format defines, a UTF-8 name.
    fn is_honest(&self) -> bool {
        self.honest_name().is_some()
            && matches!(self.attr_type, 0 | 1)
            && (self.attr_type != 0 || self.declared_value_len.is_none())
    }
}

fn attr_spec() -> impl Strategy<Value = AttrSpec> {
    (
        prop_oneof![
            // The names a real keyring actually carries. `xdg:schema` is the
            // one the whole classification turns on.
            4 => prop::sample::select(vec![
                "xdg:schema", "server", "user", "account", "port", "keyring", "",
            ])
            .prop_map(|s| s.as_bytes().to_vec()),
            1 => vec(any::<u8>(), 0..6),
        ],
        prop_oneof![9 => Just(false), 1 => Just(true)],
        maybe_declared(),
        prop_oneof![5 => Just(0u32), 4 => Just(1u32), 1 => any::<u32>()],
        vec(any::<u8>(), 0..34),
        maybe_declared(),
    )
        .prop_map(
            |(name, null_name, declared_name_len, attr_type, value, declared_value_len)| AttrSpec {
                name,
                null_name,
                declared_name_len,
                attr_type,
                value,
                declared_value_len,
            },
        )
}

#[derive(Debug, Clone)]
struct ItemSpec {
    id: u32,
    item_type: u32,
    attrs: Vec<AttrSpec>,
    declared_attr_count: Option<u32>,
}

impl ItemSpec {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&be(self.id));
        out.extend_from_slice(&be(self.item_type));
        out.extend_from_slice(&be(self
            .declared_attr_count
            .unwrap_or(self.attrs.len() as u32)));
        for a in &self.attrs {
            a.encode(out);
        }
    }

    fn is_honest(&self) -> bool {
        self.declared_attr_count.is_none() && self.attrs.iter().all(AttrSpec::is_honest)
    }

    /// The attribute *names*, as a set — which is what the index yields.
    fn names(&self) -> BTreeSet<String> {
        self.attrs
            .iter()
            .filter_map(|a| a.honest_name().map(str::to_string))
            .collect()
    }
}

fn item_spec() -> impl Strategy<Value = ItemSpec> {
    (
        any::<u32>(),
        // Weighted onto the types the format defines, including the two
        // unlock-credential types the importer must refuse, without giving up
        // the arbitrary case.
        prop_oneof![8 => 0u32..6, 2 => any::<u32>()],
        vec(attr_spec(), 0..4),
        maybe_declared(),
    )
        .prop_map(|(id, item_type, attrs, declared_attr_count)| ItemSpec {
            id,
            item_type,
            attrs,
            declared_attr_count,
        })
}

#[derive(Debug, Clone)]
struct KeyringSpec {
    major: u8,
    minor: u8,
    name: Vec<u8>,
    null_name: bool,
    declared_name_len: Option<u32>,
    hash_iterations: u32,
    items: Vec<ItemSpec>,
    declared_item_count: Option<u32>,
    ciphertext: Vec<u8>,
    declared_ciphertext_len: Option<u32>,
}

const KEYRING_CREATED: u64 = 1_699_383_593;
const KEYRING_SALT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

impl KeyringSpec {
    fn encode(&self) -> Vec<u8> {
        let mut out = KEYRING_MAGIC.to_vec();
        // The crypto and hash ids are read past, never validated.
        out.extend_from_slice(&[self.major, self.minor, 0, 0]);
        if self.null_name {
            out.extend_from_slice(&be(u32::MAX));
        } else {
            out.extend_from_slice(&be(self
                .declared_name_len
                .unwrap_or(self.name.len() as u32)));
            out.extend_from_slice(&self.name);
        }
        out.extend_from_slice(&KEYRING_CREATED.to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes()); // modified
        out.extend_from_slice(&be(0)); // flags
        out.extend_from_slice(&be(0)); // lock timeout
        out.extend_from_slice(&be(self.hash_iterations));
        out.extend_from_slice(&KEYRING_SALT);
        out.extend_from_slice(&[0; 16]); // four reserved words
        out.extend_from_slice(&be(self
            .declared_item_count
            .unwrap_or(self.items.len() as u32)));
        for item in &self.items {
            item.encode(&mut out);
        }
        out.extend_from_slice(&be(self
            .declared_ciphertext_len
            .unwrap_or(self.ciphertext.len() as u32)));
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// The display name a parse must produce, when the file is honest.
    fn honest_display_name(&self) -> Option<String> {
        if self.null_name {
            return Some(String::new());
        }
        if self.declared_name_len.is_some() {
            return None;
        }
        std::str::from_utf8(&self.name).ok().map(str::to_string)
    }

    /// `true` when nothing about this file is malformed, so the parser is
    /// *obliged* to accept it and to produce exactly the values below.
    fn is_honest(&self) -> bool {
        (self.major, self.minor) == (0, 0)
            && self.honest_display_name().is_some()
            && self.declared_item_count.is_none()
            && self.declared_ciphertext_len.is_none()
            && self.items.iter().all(ItemSpec::is_honest)
    }

    /// Assert a parse of an honest file against what it was built from. This
    /// is the oracle: "did not panic" would pass on a parser that returned an
    /// empty inventory for every input.
    fn check_parsed(&self, inv: &KeyringInventory) -> Result<(), TestCaseError> {
        prop_assert_eq!(&inv.display_name, &self.honest_display_name().unwrap());
        prop_assert_eq!(inv.created, KEYRING_CREATED);
        prop_assert_eq!(inv.modified, 0);
        prop_assert_eq!(inv.flags, 0);
        prop_assert_eq!(inv.lock_timeout, 0);
        prop_assert_eq!(inv.hash_iterations, self.hash_iterations);
        prop_assert_eq!(inv.salt, KEYRING_SALT);
        prop_assert_eq!(inv.item_count(), self.items.len());
        prop_assert_eq!(inv.ciphertext_len, self.ciphertext.len());
        for (got, want) in inv.items.iter().zip(&self.items) {
            prop_assert_eq!(got.id, want.id);
            prop_assert_eq!(got.item_type, want.item_type);
            // Duplicate names collapse: the index yields a *set*.
            let names: BTreeSet<String> = got.attribute_keys.iter().map(str::to_string).collect();
            prop_assert_eq!(names, want.names());
            prop_assert_eq!(got.is_unlock_credential(), matches!(want.item_type, 3 | 4));
        }
        Ok(())
    }
}

fn keyring_spec() -> impl Strategy<Value = KeyringSpec> {
    (
        // Weighted hard onto 0.0. The version gate runs before any length is
        // read, so an even spread here is a filter on everything below it.
        prop_oneof![7 => Just((0u8, 0u8)), 3 => (0u8..3, 0u8..3)],
        prop_oneof![
            3 => prop::sample::select(vec!["Sample keyring", "login", ""])
                .prop_map(|s| s.as_bytes().to_vec()),
            1 => vec(any::<u8>(), 0..12),
        ],
        prop_oneof![9 => Just(false), 1 => Just(true)],
        maybe_declared(),
        prop_oneof![4 => Just(3457u32), 1 => any::<u32>()],
        vec(item_spec(), 0..4),
        maybe_declared(),
        vec(any::<u8>(), 0..48),
        maybe_declared(),
    )
        .prop_map(
            |(
                (major, minor),
                name,
                null_name,
                declared_name_len,
                hash_iterations,
                items,
                declared_item_count,
                ciphertext,
                declared_ciphertext_len,
            )| KeyringSpec {
                major,
                minor,
                name,
                null_name,
                declared_name_len,
                hash_iterations,
                items,
                declared_item_count,
                ciphertext,
                declared_ciphertext_len,
            },
        )
}

// --------------------------------------------------------------------------
// KWallet
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct FolderSpec {
    hash: [u8; 16],
    entries: Vec<[u8; 16]>,
    declared_entry_count: Option<u32>,
}

impl FolderSpec {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&be(self
            .declared_entry_count
            .unwrap_or(self.entries.len() as u32)));
        for e in &self.entries {
            out.extend_from_slice(e);
        }
    }

    fn is_honest(&self) -> bool {
        self.declared_entry_count.is_none()
    }

    fn encoded_len(&self) -> usize {
        20 + 16 * self.entries.len()
    }
}

fn folder_spec() -> impl Strategy<Value = FolderSpec> {
    (
        any::<[u8; 16]>(),
        vec(any::<[u8; 16]>(), 0..4),
        maybe_declared(),
    )
        .prop_map(|(hash, entries, declared_entry_count)| FolderSpec {
            hash,
            entries,
            declared_entry_count,
        })
}

#[derive(Debug, Clone)]
struct WalletSpec {
    major: u8,
    minor: u8,
    folders: Vec<FolderSpec>,
    declared_folder_count: Option<u32>,
    /// The encrypted half, which the parser must stop before.
    ciphertext: Vec<u8>,
}

impl WalletSpec {
    fn encode(&self) -> Vec<u8> {
        let mut out = KWALLET_MAGIC.to_vec();
        out.extend_from_slice(&[self.major, self.minor, 3, 2]);
        out.extend_from_slice(&be(self
            .declared_folder_count
            .unwrap_or(self.folders.len() as u32)));
        for f in &self.folders {
            f.encode(&mut out);
        }
        out.extend_from_slice(&self.ciphertext);
        out
    }

    fn is_honest(&self) -> bool {
        (self.major, self.minor) == (0, 1)
            && self.declared_folder_count.is_none()
            && self.folders.iter().all(FolderSpec::is_honest)
    }

    fn check_parsed(&self, inv: &WalletInventory) -> Result<(), TestCaseError> {
        prop_assert_eq!((inv.cipher, inv.hash), (3, 2));
        prop_assert_eq!(inv.folder_count(), self.folders.len());
        prop_assert_eq!(
            inv.entry_count(),
            self.folders.iter().map(|f| f.entries.len()).sum::<usize>()
        );
        prop_assert_eq!(
            inv.ciphertext_offset,
            KWALLET_MAGIC.len()
                + 4
                + 4
                + self
                    .folders
                    .iter()
                    .map(FolderSpec::encoded_len)
                    .sum::<usize>()
        );
        for (got, want) in inv.folders.iter().zip(&self.folders) {
            prop_assert_eq!(got.folder_hash, want.hash);
            prop_assert_eq!(&got.entry_hashes, &want.entries);
            // The membership check verification relies on.
            for e in &want.entries {
                prop_assert!(inv.contains_entry(&want.hash, e));
            }
        }
        Ok(())
    }
}

fn wallet_spec() -> impl Strategy<Value = WalletSpec> {
    (
        prop_oneof![7 => Just((0u8, 1u8)), 3 => (0u8..3, 0u8..3)],
        vec(folder_spec(), 0..5),
        maybe_declared(),
        vec(any::<u8>(), 0..32),
    )
        .prop_map(
            |((major, minor), folders, declared_folder_count, ciphertext)| WalletSpec {
                major,
                minor,
                folders,
                declared_folder_count,
                ciphertext,
            },
        )
}

// --------------------------------------------------------------------------
// The invariants every parse must satisfy, honest or not
// --------------------------------------------------------------------------

/// Every parse either succeeds or returns a `HeaderError`. There is no third
/// outcome, and in particular no panic: this is a `Result`-returning API on
/// attacker-controlled bytes, so a panic here is a denial of service in
/// `sm import --inventory`.
fn keyring_never_panics(bytes: &[u8]) {
    if let Ok(inv) = parse_keyring_header(bytes) {
        // A success is a claim about the file, so check the claim.
        assert!(inv.ciphertext_offset <= bytes.len());
        assert!(inv.ciphertext_offset + inv.ciphertext_len <= bytes.len());
        // Nothing was allocated that the file could not hold: the smallest
        // item encoding is 12 bytes.
        assert!(inv.item_count() * 12 <= bytes.len());
        assert!(inv.unlock_credential_count() <= inv.item_count());
        // The keys really are a set, and counting them agrees with the items.
        let counts = inv.attribute_key_counts();
        assert!(counts.values().all(|&n| n <= inv.item_count()));
    }
}

fn wallet_never_panics(bytes: &[u8]) {
    if let Ok(inv) = parse_wallet_header(bytes) {
        assert!(inv.ciphertext_offset <= bytes.len());
        assert!(inv.folder_count() * 20 <= bytes.len());
        assert!(inv.entry_count() * 16 <= bytes.len());
        assert!(inv.empty_folder_count() <= inv.folder_count());
        for f in &inv.folders {
            for e in &f.entry_hashes {
                assert!(inv.contains_entry(&f.folder_hash, e));
            }
        }
    }
}

proptest! {
    /// Arbitrary bytes. Mostly rejected at the magic, which is the point of
    /// having the structured strategies below as well.
    #[test]
    fn no_parser_panics_on_arbitrary_bytes(bytes in vec(any::<u8>(), 0..512)) {
        keyring_never_panics(&bytes);
        wallet_never_panics(&bytes);
        // The parsers are independent, and the property is stronger than
        // "neither panics": each refuses the other's file at its own magic,
        // so no byte string can be read as both a keyring and a wallet.
        let keyring = parse_keyring_header(&bytes);
        let wallet = parse_wallet_header(&bytes);
        prop_assert!(
            !(keyring.is_ok() && wallet.is_ok()),
            "one byte string parsed as both formats"
        );
        if keyring.is_ok() {
            prop_assert!(
                matches!(wallet, Err(HeaderError::BadMagic(Source::KWallet))),
                "a keyring reached the wallet parser past its magic: {wallet:?}"
            );
        }
        if wallet.is_ok() {
            prop_assert!(
                matches!(keyring, Err(HeaderError::BadMagic(Source::GnomeKeyring))),
                "a wallet reached the keyring parser past its magic: {keyring:?}"
            );
        }
    }

    /// The structured keyring case, with the oracle attached: a file that is
    /// honest in every respect must parse, and must parse to the values it
    /// was built from.
    #[test]
    fn a_hostile_keyring_is_refused_and_an_honest_one_parses_exactly(spec in keyring_spec()) {
        let bytes = spec.encode();
        keyring_never_panics(&bytes);
        wallet_never_panics(&bytes);
        match parse_keyring_header(&bytes) {
            Ok(inv) => {
                if spec.is_honest() {
                    spec.check_parsed(&inv)?;
                }
                // Whether honest or not, a success is bounded by the file.
                prop_assert!(inv.ciphertext_offset + inv.ciphertext_len <= bytes.len());
            }
            Err(e) => prop_assert!(
                !spec.is_honest(),
                "an honest keyring was refused with {e}: {spec:?}"
            ),
        }
    }

    /// The same, for a wallet index.
    #[test]
    fn a_hostile_wallet_is_refused_and_an_honest_one_parses_exactly(spec in wallet_spec()) {
        let bytes = spec.encode();
        wallet_never_panics(&bytes);
        keyring_never_panics(&bytes);
        match parse_wallet_header(&bytes) {
            Ok(inv) => {
                if spec.is_honest() {
                    spec.check_parsed(&inv)?;
                }
                prop_assert!(inv.ciphertext_offset <= bytes.len());
            }
            Err(e) => prop_assert!(
                !spec.is_honest(),
                "an honest wallet was refused with {e}: {spec:?}"
            ),
        }
    }

    /// Truncating a *structured* file at every boundary, which is where the
    /// item and attribute loops live. The whole-file truncation test below
    /// only ever cuts the one golden layout.
    #[test]
    fn truncating_a_generated_keyring_anywhere_is_an_error(
        spec in keyring_spec(),
        cut in 0.0f64..1.0,
    ) {
        let bytes = spec.encode();
        let n = (bytes.len() as f64 * cut) as usize;
        prop_assume!(n < bytes.len());
        keyring_never_panics(&bytes[..n]);
        // A *strict* prefix of an honest file is never itself a parse. The
        // conjunct used to be `&& spec.ciphertext.is_empty()`, which
        // discarded exactly the cases where the cut lands in the trailing
        // region — which is where the `ciphertext length` guard lives, so the
        // one assertion in this test skipped the arm it was best placed to
        // reach. It is unnecessary: with a non-empty ciphertext, a cut inside
        // it leaves a file whose declared length exceeds what remains, and a
        // cut before it removes a structural field.
        if spec.is_honest() {
            prop_assert!(parse_keyring_header(&bytes[..n]).is_err());
        }
    }

    /// Truncation is the commonest malformation — an interrupted write, a
    /// partial read — and it must be an error at every one of the several
    /// hundred boundaries in a real file, never a panic and never a
    /// silently short inventory.
    #[test]
    fn truncating_a_real_file_anywhere_is_an_error(
        n in 0usize..GOLDEN_KEYRING.len(),
        m in 0usize..WALLET_INDEX_END,
    ) {
        prop_assert!(parse_keyring_header(&GOLDEN_KEYRING[..n]).is_err());
        prop_assert!(parse_wallet_header(&GOLDEN_WALLET[..m]).is_err());
    }

    /// A single flipped byte either parses to something self-consistent or
    /// is refused. It must never parse to an inventory that claims more than
    /// the file holds.
    #[test]
    fn one_corrupted_byte_never_produces_an_inconsistent_inventory(
        at in 0usize..GOLDEN_KEYRING.len(),
        with in any::<u8>(),
    ) {
        let mut bytes = GOLDEN_KEYRING.to_vec();
        bytes[at] = with;
        keyring_never_panics(&bytes);
        let mut bytes = GOLDEN_WALLET.to_vec();
        let at = at % bytes.len();
        bytes[at] = with;
        wallet_never_panics(&bytes);
    }

    /// The `default` file names a keyring that becomes a *filename*. Any
    /// accepted name is a single safe component; a rejected one is rejected
    /// with the one error this can produce.
    #[test]
    fn an_accepted_default_name_is_always_a_safe_basename(s in ".{0,64}") {
        match parse_default_file(&s) {
            Ok(name) => {
                prop_assert!(!name.is_empty());
                prop_assert!(!name.contains('/'));
                prop_assert!(!name.contains('\\'));
                prop_assert!(!name.contains('\0'));
                prop_assert!(name != "." && name != "..");
                prop_assert_eq!(name.trim(), &name);
                // Feeding the result back gives the same name — unless it
                // still ends in `.keyring`, which is the doubled-suffix case:
                // `x.keyring.keyring` is the honest `default` contents for a
                // file of that name, so exactly one suffix comes off and a
                // second pass would strip a real part of the name.
                if !name.ends_with(".keyring") {
                    prop_assert_eq!(parse_default_file(&name).unwrap(), name);
                }
            }
            Err(e) => prop_assert_eq!(e, HeaderError::InvalidDefaultName),
        }
    }

    /// The size guard is a `>` at the exact boundary, checked from a `stat`
    /// size before a byte is read.
    #[test]
    fn the_size_cap_holds_at_its_boundary(len in any::<u64>()) {
        match formats::check_source_size(len) {
            Ok(()) => prop_assert!(len <= MAX_SOURCE_BYTES),
            Err(HeaderError::FileTooLarge(got)) => {
                prop_assert_eq!(got, len);
                prop_assert!(len > MAX_SOURCE_BYTES);
            }
            Err(e) => prop_assert!(false, "unexpected {e}"),
        }
    }
}

// --------------------------------------------------------------------------
// The distribution the generators actually produce
// --------------------------------------------------------------------------

/// What one generated case reached in the parser.
#[derive(Default, Debug)]
struct Reach {
    cases: usize,
    parsed: usize,
    honest: usize,
    /// Cases that got as far as `parse_keyring_item` — an item was decoded,
    /// or the failure came from inside it.
    item_loop: usize,
    /// Cases where an *attribute* was decoded or refused, so the attribute
    /// loop itself ran.
    attribute_loop: usize,
    /// Both value encodings, which are separate arms of the same `match`.
    string_values: usize,
    uint32_values: usize,
    unknown_attribute_type: usize,
    null_name: usize,
    non_utf8: usize,
    impossible_length: usize,
    truncated: usize,
    unsupported_version: usize,
}

impl Reach {
    /// Assert a floor, and *report the observation either way*.
    ///
    /// The number printed here is the one the next person should retune a
    /// floor from. A floor set from a guess rather than a measurement is the
    /// failure mode this whole file is about: `unsupported_version` sat at
    /// 128 against an observed ~1100, so an order-of-magnitude regression in
    /// the arm it names would not have moved it.
    fn require(&self, name: &str, got: usize, floor: usize) {
        println!(
            "reach: {got:>5} / {} cases reached {name} (floor {floor})",
            self.cases
        );
        assert!(
            got >= floor,
            "the generator reached {name} in only {got} of {} cases, under the floor of \
             {floor}. That is the failure this file exists to prevent: a strategy whose \
             own filters keep it out of the code it is meant to cover. Full distribution: \
             {self:#?}",
            self.cases
        );
    }
}

/// True for an error that can only be raised from *inside the attribute
/// loop* — an attribute was actually being decoded when the file was
/// refused.
///
/// This is deliberately narrower than [`from_item_parser`], and the two used
/// to be one predicate that incremented both counters. That made the
/// `attribute_loop` floor satisfiable by files that never entered the loop:
/// `Truncated { field: "item id" | "item type" | "attribute count" }` fails
/// before the count is even read, and `ImpossibleLength { field: "attribute
/// count" }` fails on the guard *preceding* the loop. The floor that is
/// supposed to guarantee `AttrSpec` does anything could therefore be met
/// entirely by files that died at "item id" — the same defect this file was
/// rewritten to eliminate, one level in.
fn from_attribute_loop(e: &HeaderError) -> bool {
    matches!(
        e,
        HeaderError::UnknownAttributeType { .. }
            | HeaderError::NullName { .. }
            | HeaderError::NonUtf8 {
                field: "attribute name"
            }
            | HeaderError::Truncated {
                field: "attribute name" | "attribute type" | "attribute value"
            }
            | HeaderError::ImpossibleLength {
                field: "attribute name" | "attribute value",
                ..
            }
    )
}

/// True for an error that can only be raised from inside
/// `parse_keyring_item` — the item loop ran, whether or not it got as far as
/// an attribute. Every attribute-loop error is one of these; the extra
/// variants are the four fields read before the loop is entered.
fn from_item_parser(e: &HeaderError) -> bool {
    from_attribute_loop(e)
        || matches!(
            e,
            HeaderError::Truncated {
                field: "item id" | "item type" | "attribute count"
            } | HeaderError::ImpossibleLength {
                field: "attribute count",
                ..
            }
        )
}

/// The test that makes the rest of this file mean something.
///
/// It samples the strategies and asserts the *shape reached*, not the absence
/// of a panic: how many cases parsed, how many got into the item loop, how
/// many exercised each attribute encoding and each refusal. Every floor here
/// was violated by the generators this file replaced — the item loop was
/// reached in zero cases out of any number, because the version gate and an
/// `any::<u32>()` item count between them rejected about 94% of draws before
/// a single item was read, and the surviving 6% almost never carried one.
#[test]
fn the_generators_reach_every_shape_the_parsers_can_produce() {
    let mut runner = TestRunner::deterministic();
    let strategy = keyring_spec();
    let mut r = Reach::default();

    for _ in 0..4096 {
        let spec = strategy.new_tree(&mut runner).unwrap().current();
        let bytes = spec.encode();
        r.cases += 1;
        if spec.is_honest() {
            r.honest += 1;
        }
        // What the *encoding* contains, which is what decides whether the
        // parser can reach these arms at all.
        let attrs: Vec<&AttrSpec> = spec.items.iter().flat_map(|i| &i.attrs).collect();

        match parse_keyring_header(&bytes) {
            Ok(inv) => {
                r.parsed += 1;
                if !inv.items.is_empty() {
                    r.item_loop += 1;
                    if inv.items.iter().any(|i| !i.attribute_keys.is_empty()) {
                        r.attribute_loop += 1;
                    }
                    if attrs.iter().any(|a| a.attr_type == 0) {
                        r.string_values += 1;
                    }
                    if attrs.iter().any(|a| a.attr_type == 1) {
                        r.uint32_values += 1;
                    }
                }
            }
            Err(e) => {
                // Each counter gets its own witness. An error raised before
                // the attribute count is read says the item loop ran and
                // nothing more.
                if from_item_parser(&e) {
                    r.item_loop += 1;
                }
                if from_attribute_loop(&e) {
                    r.attribute_loop += 1;
                }
                match e {
                    HeaderError::UnknownAttributeType { .. } => r.unknown_attribute_type += 1,
                    HeaderError::NullName { .. } => r.null_name += 1,
                    HeaderError::NonUtf8 { .. } => r.non_utf8 += 1,
                    HeaderError::ImpossibleLength { .. } => r.impossible_length += 1,
                    HeaderError::Truncated { .. } => r.truncated += 1,
                    HeaderError::UnsupportedVersion { .. } => r.unsupported_version += 1,
                    _ => {}
                }
            }
        }
    }

    // A real invariant rather than a floor: an attribute cannot be decoded
    // by a case that never entered the item loop, so this can only be
    // violated by the two counters drifting apart the way they had.
    assert!(
        r.attribute_loop <= r.item_loop,
        "the attribute loop was counted {} times against {} item-loop cases: {r:#?}",
        r.attribute_loop,
        r.item_loop
    );

    // Floors, not exact counts: the generator may be retuned, but it may not
    // stop reaching any of these. Every number below was set against a run of
    // this test — `require` prints what it observed — and the observation is
    // in the comment beside it. Three of them used to sit so far under the
    // arm they name that it could have collapsed by an order of magnitude
    // without failing: the version gate at 128 against 1115, the NULL name
    // at 16 against 132, the impossible length at 128 against 1277.
    r.require("a successful parse", r.parsed, 512); // observed 751
    r.require("an honest, fully-checked file", r.honest, 256); // 300
    r.require("parse_keyring_item", r.item_loop, 512); // 1126
    r.require("the attribute loop", r.attribute_loop, 256); // 797
    // The two value encodings are only counted on a *successful* parse that
    // carries items, which is the strictest way to say the arm really ran, so
    // these floors are lower than the share of cases that encode one.
    r.require("a hashed string attribute value", r.string_values, 32); // 60
    r.require("a uint32 attribute value", r.uint32_values, 32); // 67
    // 233 observed.
    r.require(
        "the unknown-attribute-type refusal",
        r.unknown_attribute_type,
        32,
    );
    r.require("the NULL attribute name refusal", r.null_name, 64); // 132
    r.require("the non-UTF-8 refusal", r.non_utf8, 32); // 584
    r.require("the impossible-length refusal", r.impossible_length, 512); // 1277
    // Truncation is rare here *by construction*: the generator writes
    // complete files, so only a declared length overshooting the bytes
    // actually written produces one. Four cases in 4096 — this floor cannot
    // detect much and does not pretend to; it says the path is live, and
    // `truncating_a_generated_keyring_anywhere_is_an_error` is where
    // truncation is exercised on purpose.
    r.require("the truncation error", r.truncated, 2); // 4
    r.require("the version gate", r.unsupported_version, 512); // 1115
}

/// The same, for the wallet generator and the entry-hash loop, which had no
/// property coverage of its own either.
#[test]
fn the_wallet_generator_reaches_the_entry_hash_loop() {
    let mut runner = TestRunner::deterministic();
    let strategy = wallet_spec();
    let mut r = Reach::default();

    for _ in 0..4096 {
        let spec = strategy.new_tree(&mut runner).unwrap().current();
        let bytes = spec.encode();
        r.cases += 1;
        if spec.is_honest() {
            r.honest += 1;
        }
        match parse_wallet_header(&bytes) {
            Ok(inv) => {
                r.parsed += 1;
                if !inv.folders.is_empty() {
                    r.item_loop += 1;
                }
                if inv.entry_count() > 0 {
                    r.attribute_loop += 1;
                }
            }
            Err(e) => match e {
                HeaderError::ImpossibleLength { .. } => r.impossible_length += 1,
                HeaderError::Truncated { .. } => r.truncated += 1,
                HeaderError::UnsupportedVersion { .. } => r.unsupported_version += 1,
                _ => {}
            },
        }
    }

    // Observed beside each, as above.
    r.require("a successful parse", r.parsed, 512); // observed 1696
    r.require("an honest, fully-checked file", r.honest, 512); // 1140
    r.require("the folder loop", r.item_loop, 512); // 1131
    r.require("the entry-hash loop", r.attribute_loop, 256); // 997
    r.require("the impossible-length refusal", r.impossible_length, 512); // 1227
    r.require("the version gate", r.unsupported_version, 512); // 1119
}

/// Where the golden wallet's cleartext index ends. Truncating *after* it
/// still parses, and must: the parser deliberately stops at
/// `ciphertext_offset` and never looks at the encrypted half, so a wallet
/// with its ciphertext cut short is not a header error. `index_end_is_where_
/// the_parser_stops` pins the number.
const WALLET_INDEX_END: usize = 16 + 4 + 3 * 20 + 4 * 16;

#[test]
fn the_index_end_is_where_the_parser_stops() {
    let inv = parse_wallet_header(GOLDEN_WALLET).unwrap();
    assert_eq!(inv.ciphertext_offset, WALLET_INDEX_END);
    assert!(GOLDEN_WALLET.len() > WALLET_INDEX_END);
    // Everything from the index end on is ciphertext, and cutting it makes no
    // difference to the header.
    assert_eq!(
        parse_wallet_header(&GOLDEN_WALLET[..WALLET_INDEX_END]),
        Ok(inv)
    );
}

const GOLDEN_KEYRING: &[u8] = include_bytes!("fixtures/import/sample.keyring");
const GOLDEN_WALLET: &[u8] = include_bytes!("fixtures/import/sample.kwl");
