//! Properties that must hold for any input, checked directly rather than
//! through the code paths that happen to use them.
//!
//! These came out of a security audit: each one is a claim the design makes
//! that reading alone cannot settle — that no attacker-supplied byte string
//! panics a parser, that the AEAD covers every header field, that a nonce is
//! never reused, and that no object path escapes its namespace.
use secret_manager::protocol::{Request, Response, decode_frame};
use secret_manager::vault::Vault;
use secret_manager::vault::crypto::{self, KdfParams, SALT_LEN};
use secret_manager::vault::format::{self, VaultFile};
use std::collections::BTreeMap;

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// No attacker-supplied byte string may panic a parser.
#[test]
fn parsers_never_panic_on_hostile_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.vault");
    Vault::create(&path, "L", b"pw", KdfParams::FAST_FOR_TESTS).unwrap();
    let good = std::fs::read(&path).unwrap();

    let mut st = 0x12345678u64;
    let mut cases = 0;
    for _ in 0..20_000 {
        let mut b = good.clone();
        match lcg(&mut st) % 4 {
            0 => {
                // flip bytes
                for _ in 0..(1 + lcg(&mut st) % 8) {
                    let i = (lcg(&mut st) as usize) % b.len();
                    b[i] ^= (lcg(&mut st) % 256) as u8;
                }
            }
            1 => {
                // truncate
                let n = (lcg(&mut st) as usize) % b.len();
                b.truncate(n);
            }
            2 => {
                // extend
                let n = (lcg(&mut st) as usize) % 64;
                for _ in 0..n {
                    b.push((lcg(&mut st) % 256) as u8);
                }
            }
            _ => {
                // random of random length
                let n = (lcg(&mut st) as usize) % 512;
                b = (0..n).map(|_| (lcg(&mut st) % 256) as u8).collect();
            }
        }
        let _ = VaultFile::decode(&b);
        let _ = format::decode_header(&b);
        if b.len() >= 12 {
            let _ = format::header_prefix_len(&b[..12]);
        }
        let _ = format::decode_items(&b);
        let _ = decode_frame::<Request>(&b);
        let _ = decode_frame::<Response>(&b);
        cases += 1;
    }
    assert_eq!(cases, 20_000);
}

/// A giant declared header length must not allocate; only the real file size counts.
#[test]
fn absurd_header_length_is_rejected_without_allocating() {
    let mut b = Vec::new();
    b.extend_from_slice(b"SMVAULT\0");
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&[0u8; 32]);
    assert!(VaultFile::decode(&b).is_err());
    assert!(format::decode_header(&b).is_err());
    assert!(format::header_prefix_len(&b[..12]).is_err());
}

/// Every header field is covered by the AEAD's associated data: changing any
/// one of them must make the correct password fail.
/// One tweak to a decoded header, so the AEAD-coverage test can name each
/// field it flips.
type HeaderMutation = Box<dyn Fn(&mut format::Header)>;

#[test]
fn every_header_field_is_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.vault");
    let mut v = Vault::create(&path, "Label", b"pw", KdfParams::FAST_FOR_TESTS).unwrap();
    v.insert_item(
        "i",
        BTreeMap::from([("a".into(), "b".into())]),
        b"s".to_vec(),
        "text/plain",
        false,
    )
    .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let file = VaultFile::decode(&bytes).unwrap();

    let mutate: Vec<(&str, HeaderMutation)> = vec![
        (
            "label",
            Box::new(|h: &mut format::Header| h.label = "evil".into()),
        ),
        ("created", Box::new(|h: &mut format::Header| h.created ^= 1)),
        (
            "modified",
            Box::new(|h: &mut format::Header| h.modified ^= 1),
        ),
        (
            "index_salt",
            Box::new(|h: &mut format::Header| h.index_salt[0] ^= 1),
        ),
        (
            "index id",
            Box::new(|h: &mut format::Header| {
                if let Some(e) = h.index.first_mut() {
                    e.id = "zzz".into();
                }
            }),
        ),
        (
            "index hash",
            Box::new(|h: &mut format::Header| {
                if let Some(e) = h.index.first_mut()
                    && let Some(x) = e.attr_hashes.first_mut()
                {
                    x[0] ^= 1;
                }
            }),
        ),
        (
            "kdf t_cost",
            Box::new(|h: &mut format::Header| h.kdf.t_cost += 1),
        ),
    ];
    for (name, f) in mutate {
        let mut h = file.header.clone();
        f(&mut h);
        let forged = VaultFile::new(h, file.ciphertext.clone()).unwrap();
        std::fs::write(&path, forged.encode()).unwrap();
        let mut v = Vault::open(&path).unwrap();
        assert!(
            v.unlock(b"pw").is_err(),
            "tampering with {name} was not detected"
        );
    }
    // The salt is the one field whose change is detected by deriving a
    // different key rather than by the AAD; check it too.
    let mut h = file.header.clone();
    h.salt[0] ^= 1;
    let forged = VaultFile::new(h, file.ciphertext.clone()).unwrap();
    std::fs::write(&path, forged.encode()).unwrap();
    assert!(
        Vault::open(&path).unwrap().unlock(b"pw").is_err(),
        "salt change undetected"
    );
}

/// Every save must use a fresh nonce, including across key rotations.
#[test]
fn nonces_are_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.vault");
    let mut v = Vault::create(&path, "L", b"pw", KdfParams::FAST_FOR_TESTS).unwrap();
    let mut seen = std::collections::HashSet::new();
    for i in 0..60 {
        v.insert_item(
            &format!("i{i}"),
            BTreeMap::new(),
            b"s".to_vec(),
            "text/plain",
            false,
        )
        .unwrap();
        let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
        assert!(seen.insert(h.nonce), "nonce reused after {i} saves");
    }
    for i in 0..10 {
        let salt = crypto::random_bytes::<SALT_LEN>();
        let key = crypto::derive_key(
            format!("pw{i}").as_bytes(),
            &salt,
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap();
        let old = if i == 0 {
            crypto::derive_key(
                b"pw",
                &{
                    let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
                    h.salt
                },
                KdfParams::FAST_FOR_TESTS,
            )
            .unwrap()
        } else {
            let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
            crypto::derive_key(
                format!("pw{}", i - 1).as_bytes(),
                &h.salt,
                KdfParams::FAST_FOR_TESTS,
            )
            .unwrap()
        };
        v.change_key(&old, &salt, KdfParams::FAST_FOR_TESTS, &key)
            .unwrap();
        let h = format::decode_header(&std::fs::read(&path).unwrap()).unwrap();
        assert!(seen.insert(h.nonce), "nonce reused after rotation {i}");
    }
}

/// Object paths must never escape their namespace.
#[test]
fn object_paths_cannot_escape() {
    use secret_manager::dbus::paths;
    for hostile in [
        "/org/freedesktop/secrets/collection/../../../etc/passwd",
        "/org/freedesktop/secrets/collection/a%2Fb",
        "/org/freedesktop/secrets/collection/",
        "/org/freedesktop/secrets/collection//x",
        "/org/freedesktop/secrets/collection/a/b/c",
        "/org/freedesktop/secrets/collection/a b",
        "/org/freedesktop/secrets/collection/a\0b",
        "/org/freedesktop/secrets/collection/.",
        "/org/freedesktop/secrets/collection/..",
        "/org/freedesktop/secrets/aliases/../collection/x",
    ] {
        match paths::parse(hostile) {
            None => {}
            Some(t) => {
                let ids: Vec<String> = match t {
                    paths::Target::Collection(c) => vec![c],
                    paths::Target::Alias(a) => vec![a],
                    paths::Target::Item { collection, item } => vec![collection, item],
                    paths::Target::AliasItem { alias, item } => vec![alias, item],
                };
                for id in ids {
                    assert!(
                        paths::is_segment(&id),
                        "{hostile} yielded unsafe segment {id:?}"
                    );
                    assert!(!id.contains('/') && !id.contains("..") && !id.contains('\0'));
                }
            }
        }
    }
}
