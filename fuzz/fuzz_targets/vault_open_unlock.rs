//! The seal/open path end to end: the property that the vault is a vault.
//!
//! Everything else in the format is bookkeeping around three claims. A key
//! that is not the right key never yields plaintext. A file that is not
//! byte-for-byte the file we sealed never yields plaintext — and because the
//! header is the associated data, that covers the *whole* file, not just the
//! ciphertext: a flipped bit in the label, the salt, the index, or the length
//! prefix must be as fatal as a flipped bit in the AEAD tag. And when the key
//! is right and the file is intact, the items come back exactly as they went
//! in, secrets included.
//!
//! Those are attacker-facing claims, not internal ones: on a shared-uid box
//! the vault file is writable by anything running as the user, and the PAM
//! module opens a file inside a login the target user controls.
//!
//! Most of the work happens in memory against the `crypto` layer, because a
//! `Vault::create` per execution means a temp directory, four fsyncs and a
//! rename, which costs more than every assertion here put together. The
//! on-disk path is exercised on a low-frequency branch so it is still
//! covered without setting the run's exec rate.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use secret_manager::vault::crypto::{self, Key, KEY_LEN, NONCE_LEN, SALT_LEN};
use secret_manager::vault::format::{self, Header, Item, VaultFile};
use smfuzz::FAST;
use zeroize::Zeroizing;

#[derive(Debug)]
struct Input {
    password: Vec<u8>,
    /// A second password, used to check that a key derived from anything but
    /// the real password is refused. May coincidentally equal `password`;
    /// the assertion is conditioned on it not doing so.
    other_password: Vec<u8>,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    label: String,
    items: Vec<Item>,
    /// Where to damage the finished file, as an offset and a bit mask. Taken
    /// modulo the file length so every byte — prefix, header, ciphertext,
    /// AEAD tag — is reachable.
    corrupt_at: usize,
    corrupt_mask: u8,
    /// Run the real `Vault::create`/`open`/`unlock` path this execution.
    on_disk: bool,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n = u.arbitrary_len::<u8>()?.min(4);
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            if u.is_empty() {
                break;
            }
            items.push(smfuzz::item(u)?);
        }
        Ok(Input {
            password: u.arbitrary()?,
            other_password: u.arbitrary()?,
            salt: u.arbitrary()?,
            nonce: u.arbitrary()?,
            label: smfuzz::hostile_string(u)?,
            items,
            corrupt_at: u.arbitrary()?,
            // Never zero: a no-op "corruption" would leave the file intact
            // and the assertion below would be false for the right reason.
            corrupt_mask: u.int_in_range(1..=255)?,
            on_disk: u.ratio(1, 64)?,
        })
    }
}

/// Seal `items` into a complete vault file under `key`.
fn build_file(header: Header, key: &Key, items: &[Item]) -> VaultFile {
    let plain = format::encode_items(items).expect("owned items always encode");
    let file = VaultFile::new(header, Vec::new()).expect("the header is small and well formed");
    let ciphertext = crypto::seal(key, &file.header.nonce, &file.aad, &plain)
        .expect("XChaCha20-Poly1305 cannot fail on a valid key and nonce");
    VaultFile::new(file.header, ciphertext).expect("the header did not change")
}

fuzz_target!(|input: Input| {
    let Input {
        password,
        other_password,
        salt,
        nonce,
        label,
        items,
        corrupt_at,
        corrupt_mask,
        on_disk,
    } = input;

    let key = crypto::derive_key(&password, &salt, FAST).expect("FAST is inside the ceilings");

    let header = Header {
        version: format::VERSION,
        label,
        created: 0,
        modified: 1,
        kdf: FAST,
        salt,
        index_salt: [7u8; SALT_LEN],
        // The index is part of the aad, so an item list with hostile
        // attributes exercises the authenticated prefix as well as the
        // ciphertext.
        nonce,
        index: format::build_index(&[7u8; SALT_LEN], &items, true),
    };

    let file = build_file(header, &key, &items);
    let bytes = file.encode();

    // 1. The honest path. What was sealed comes back, item for item.
    let decoded = VaultFile::decode(&bytes).expect("a file we just wrote must decode");
    assert_eq!(decoded.aad, file.aad, "the authenticated prefix moved");
    let plain = crypto::open(
        &key,
        &decoded.header.nonce,
        &decoded.aad,
        &decoded.ciphertext,
    )
    .expect("the right key on an intact file must open it");
    let back = format::decode_items(&plain).expect("the plaintext we sealed must decode");
    assert_eq!(back, items, "items changed across seal and open");

    // 2. A wrong key never opens the file. Flipping one bit of the derived
    // key is the cheapest possible "wrong key", and the strongest: it is as
    // close to correct as a key can be.
    let mut wrong = *key.as_bytes();
    wrong[usize::from(corrupt_mask) % KEY_LEN] ^= 1;
    let wrong_key = Key::from_zeroizing(Zeroizing::new(wrong));
    assert!(
        crypto::open(
            &wrong_key,
            &decoded.header.nonce,
            &decoded.aad,
            &decoded.ciphertext
        )
        .is_err(),
        "a key differing in one bit opened the vault"
    );

    // A key derived from a different password is the realistic case, and the
    // one the daemon's `WrongPassword` answer rests on. One extra Argon2 per
    // execution at `FAST` cost is affordable; at real cost it would not be.
    if other_password != password {
        let other = crypto::derive_key(&other_password, &salt, FAST).unwrap();
        assert_ne!(
            other.as_bytes(),
            key.as_bytes(),
            "two different passwords derived the same key under the same salt"
        );
        assert!(
            crypto::open(
                &other,
                &decoded.header.nonce,
                &decoded.aad,
                &decoded.ciphertext
            )
            .is_err(),
            "a key derived from the wrong password opened the vault"
        );
    }

    // 3. Single-byte corruption anywhere in the file is fatal. Not "usually
    // fails" — never yields plaintext. Anything before the ciphertext is the
    // associated data, so this is one assertion covering the header fields,
    // the length prefix and the magic alike.
    let mut damaged = bytes.clone();
    let at = corrupt_at % damaged.len();
    damaged[at] ^= corrupt_mask;
    assert_ne!(damaged, bytes, "the corruption was a no-op");
    match VaultFile::decode(&damaged) {
        // Rejected by the parser: the header gate caught it first, which is
        // a stronger outcome than an AEAD failure and equally acceptable.
        Err(_) => {}
        Ok(bad) => {
            assert!(
                crypto::open(&key, &bad.header.nonce, &bad.aad, &bad.ciphertext).is_err(),
                "a file with a corrupted byte at offset {at} still decrypted"
            );
        }
    }

    // Truncation is corruption too, and the one a partial write produces.
    if bytes.len() > format::PREFIX_LEN {
        let short = &bytes[..bytes.len() - 1];
        if let Ok(t) = VaultFile::decode(short) {
            assert!(
                crypto::open(&key, &t.header.nonce, &t.aad, &t.ciphertext).is_err(),
                "a truncated file still decrypted"
            );
        }
    }

    if !on_disk {
        return;
    }

    // 4. The same three claims through the real store: a file created on
    // disk, reopened, and unlocked. This is what the daemon actually runs, so
    // it has to be covered — just not on every execution.
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let path = dir.path().join("fuzz.vault");
    let Ok(mut vault) = secret_manager::vault::Vault::create(&path, "fuzz", &password, FAST) else {
        return;
    };
    for item in &items {
        // Ids are assigned by the store, so only the attributes and the
        // secret can be compared afterwards.
        if vault
            .insert_item(
                &item.label,
                item.attributes.clone(),
                item.secret.to_vec(),
                &item.content_type,
                false,
            )
            .is_err()
        {
            return;
        }
    }

    let mut reopened = secret_manager::vault::Vault::open(&path).expect("we just wrote this file");
    assert!(
        reopened.is_locked(),
        "a freshly opened vault must be locked"
    );
    assert_eq!(
        reopened.item_ids().len(),
        items.len(),
        "the header index does not describe the items that were written"
    );

    if other_password != password {
        assert!(
            reopened.unlock(&other_password).is_err(),
            "the wrong password unlocked a vault on disk"
        );
        assert!(
            reopened.is_locked(),
            "a failed unlock left the vault unlocked"
        );
    }

    reopened
        .unlock(&password)
        .expect("the right password must unlock the vault it created");
    let read_back = reopened.items().expect("unlocked");
    assert_eq!(
        read_back.len(),
        items.len(),
        "items were lost between write and read"
    );
    for (a, b) in read_back.iter().zip(items.iter()) {
        assert_eq!(a.label, b.label, "label changed on the disk round trip");
        assert_eq!(
            a.attributes, b.attributes,
            "attributes changed on the disk round trip"
        );
        assert_eq!(
            &a.secret[..],
            &b.secret[..],
            "secret changed on the disk round trip"
        );
        assert_eq!(
            a.content_type, b.content_type,
            "content type changed on the disk round trip"
        );
    }

    // Corrupt the file on disk and confirm the store refuses it, rather than
    // handing back items decrypted from something nobody sealed.
    let Ok(raw) = std::fs::read(&path) else {
        return;
    };
    let mut damaged = raw.clone();
    let at = corrupt_at % damaged.len();
    damaged[at] ^= corrupt_mask;
    if std::fs::write(&path, &damaged).is_ok() {
        if let Ok(mut v) = secret_manager::vault::Vault::open(&path) {
            // A flipped bit inside the postcard varint that carries
            // `m_cost_kib` can turn 8 KiB into a legal-but-expensive 256 MiB,
            // and `unlock` would then honour it: in range, so not the
            // ceiling's problem, but a quarter-gigabyte allocation per
            // execution is the fuzzer's problem. Only derive when the
            // surviving parameters are still cheap.
            if v.kdf().m_cost_kib > 1024 || v.kdf().t_cost > 4 {
                return;
            }
            assert!(
                v.unlock(&password).is_err(),
                "a corrupted vault file on disk still unlocked (offset {at})"
            );
            assert!(
                !v.verify_password(&password).unwrap_or(false),
                "verify_password accepted a corrupted vault file"
            );
        }
    }
});
