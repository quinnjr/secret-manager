//! Control-protocol and session properties, as bounded cases.
//!
//! These mirror the `fuzz/fuzz_targets/protocol_*`, `dh_peer_public` and
//! `session_cipher` targets. Those need nightly and run for as long as you
//! give them; this file encodes the same invariants as deterministic
//! proptest cases so `cargo test` enforces them on every commit.
//!
//! Case counts are deliberately small where the work per case is a 1024-bit
//! modexp or an Argon2 derivation. The point is regression cover, not
//! search — the fuzzer does the searching.
use proptest::prelude::*;
use secret_manager::protocol::{
    self, CollectionStatus, KEY_LEN, KdfParams, MAX_FRAME, PROTOCOL_VERSION, ProtocolError,
    REQUEST_VARIANTS, Request, Response, SALT_LEN, Zeroizing, decode_frame, read_frame_sync,
};
use secret_manager::session::{SessionCipher, SessionError, dh};
use std::io::Cursor;

/// `Request` has no `PartialEq`: deriving one would put a non-constant-time
/// comparison on a key-bearing type. Identity is checked field by field.
fn same_request(a: &Request, b: &Request) -> bool {
    match (a, b) {
        (Request::Lock { collection: x }, Request::Lock { collection: y }) => x == y,
        (Request::Status, Request::Status) => true,
        (Request::Reload, Request::Reload) => true,
        (
            Request::UnlockWithKey {
                collection: c1,
                key: k1,
            },
            Request::UnlockWithKey {
                collection: c2,
                key: k2,
            },
        ) => c1 == c2 && k1[..] == k2[..],
        (
            Request::ChangeKey {
                collection: c1,
                old_key: o1,
                new_salt: s1,
                new_kdf: d1,
                new_key: n1,
            },
            Request::ChangeKey {
                collection: c2,
                old_key: o2,
                new_salt: s2,
                new_kdf: d2,
                new_key: n2,
            },
        ) => c1 == c2 && o1[..] == o2[..] && s1 == s2 && d1 == d2 && n1[..] == n2[..],
        _ => false,
    }
}

/// postcard encodes an enum variant as its zero-based declaration index and
/// nothing else — no name, no tag. Reordering `Request` therefore turns one
/// side's `Lock` into the other side's `Status`, with no version mismatch to
/// catch it, and the daemon, the CLI and the PAM module are three separately
/// built artifacts that can come from different commits.
///
/// This is the test that turns that into a build failure. If it fires
/// because a variant was deliberately added or moved, the fix is to bump
/// `PROTOCOL_VERSION` and update the indices here — not to relax the test.
#[test]
fn variant_indices_are_pinned_to_declaration_order() {
    fn index_of<T: serde::Serialize>(msg: &T) -> u8 {
        let frame = protocol::encode_frame(msg).expect("encode");
        assert_eq!(
            frame[4], PROTOCOL_VERSION,
            "frame carries the wrong version"
        );
        frame[5]
    }
    let key = Zeroizing::new([0u8; KEY_LEN]);

    assert_eq!(index_of(&Request::Lock { collection: None }), 0, "Lock");
    assert_eq!(index_of(&Request::Status), 1, "Status");
    assert_eq!(index_of(&Request::Reload), 2, "Reload");
    assert_eq!(
        index_of(&Request::UnlockWithKey {
            collection: String::new(),
            key: key.clone(),
        }),
        3,
        "UnlockWithKey"
    );
    assert_eq!(
        index_of(&Request::ChangeKey {
            collection: String::new(),
            old_key: key.clone(),
            new_salt: [0u8; SALT_LEN],
            new_kdf: KdfParams::FAST_FOR_TESTS,
            new_key: key.clone(),
        }),
        4,
        "ChangeKey"
    );

    assert_eq!(index_of(&Response::Ok), 0, "Ok");
    assert_eq!(
        index_of(&Response::Status {
            collections: Vec::new(),
            uptime_secs: 0,
            aliases_error: None,
        }),
        1,
        "Status"
    );
    assert_eq!(index_of(&Response::Error(String::new())), 2, "Error");

    // The name table is used in logs and diagnostics; it must not drift out
    // of step with the enum it describes.
    assert_eq!(
        REQUEST_VARIANTS,
        [
            Request::Lock { collection: None }.variant_name(),
            Request::Status.variant_name(),
            Request::Reload.variant_name(),
            Request::UnlockWithKey {
                collection: String::new(),
                key: key.clone(),
            }
            .variant_name(),
            Request::ChangeKey {
                collection: String::new(),
                old_key: key.clone(),
                new_salt: [0u8; SALT_LEN],
                new_kdf: KdfParams::FAST_FOR_TESTS,
                new_key: key,
            }
            .variant_name(),
        ]
    );
}

fn any_request() -> impl Strategy<Value = Request> {
    prop_oneof![
        proptest::option::of(".{0,32}").prop_map(|collection| Request::Lock { collection }),
        Just(()).prop_map(|_| Request::Status),
        Just(()).prop_map(|_| Request::Reload),
        (".{0,32}", any::<[u8; KEY_LEN]>()).prop_map(|(collection, key)| {
            Request::UnlockWithKey {
                collection,
                key: Zeroizing::new(key),
            }
        }),
        (
            ".{0,32}",
            any::<[u8; KEY_LEN]>(),
            any::<[u8; SALT_LEN]>(),
            any::<(u32, u32, u32)>(),
            any::<[u8; KEY_LEN]>(),
        )
            .prop_map(
                |(collection, old, salt, (m, t, p), new)| Request::ChangeKey {
                    collection,
                    old_key: Zeroizing::new(old),
                    new_salt: salt,
                    new_kdf: KdfParams {
                        m_cost_kib: m,
                        t_cost: t,
                        p_cost: p,
                    },
                    new_key: Zeroizing::new(new),
                }
            ),
    ]
}

fn any_response() -> impl Strategy<Value = Response> {
    prop_oneof![
        Just(()).prop_map(|_| Response::Ok),
        (
            proptest::collection::vec(
                (
                    ".{0,16}",
                    ".{0,16}",
                    any::<bool>(),
                    0usize..1000,
                    proptest::option::of(".{0,16}")
                ),
                0..4
            ),
            any::<u64>(),
            proptest::option::of(".{0,64}")
        )
            .prop_map(|(rows, uptime_secs, aliases_error)| Response::Status {
                aliases_error,
                collections: rows
                    .into_iter()
                    .map(|(id, label, locked, items, warning)| CollectionStatus {
                        id,
                        label,
                        locked,
                        items,
                        warning,
                    })
                    .collect(),
                uptime_secs,
            }),
        ".{0,64}".prop_map(Response::Error),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The key in `UnlockWithKey`/`ChangeKey` is the only secret this
    /// protocol carries, and it goes through an unusual `Zeroizing`
    /// serialisation buffer. A key that came back one byte short would look
    /// exactly like a wrong password.
    #[test]
    fn request_round_trips_exactly(req in any_request()) {
        let frame = protocol::encode_frame(&req).expect("encode");
        prop_assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4,
            "the length prefix must describe the rest of the frame exactly"
        );
        prop_assert_eq!(frame[4], PROTOCOL_VERSION);
        let back = decode_frame::<Request>(&frame[4..]).expect("decode");
        prop_assert!(same_request(&req, &back), "{:?} != {:?}", req, back);
    }

    #[test]
    fn response_round_trips_exactly(resp in any_response()) {
        let frame = protocol::encode_frame(&resp).expect("encode");
        prop_assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        let back = decode_frame::<Response>(&frame[4..]).expect("decode");
        prop_assert_eq!(resp, back);
    }

    /// Keys must not reach a log or a panic message. Checked on the same
    /// values the round trip proves are really in the message.
    #[test]
    fn secret_bearing_requests_redact_their_debug(req in any_request()) {
        let shown = format!("{req:?}");
        match &req {
            Request::UnlockWithKey { key, .. } => {
                prop_assert!(shown.contains("<redacted>"));
                let rendered = format!("{:?}", &key[..]);
                prop_assert!(!shown.contains(&rendered), "UnlockWithKey Debug leaked the key");
            }
            Request::ChangeKey { old_key, new_key, new_salt, .. } => {
                prop_assert!(shown.contains("<redacted>"));
                for secret in [&old_key[..], &new_key[..], &new_salt[..]] {
                    let rendered = format!("{secret:?}");
                    prop_assert!(!shown.contains(&rendered), "ChangeKey Debug leaked a secret");
                }
            }
            _ => {}
        }
    }

    /// A peer speaking another revision is refused by the version gate,
    /// before its payload reaches postcard.
    #[test]
    fn a_foreign_version_is_refused_before_decoding(version in any::<u8>(), body in proptest::collection::vec(any::<u8>(), 0..64)) {
        prop_assume!(version != PROTOCOL_VERSION);
        let mut framed = vec![version];
        framed.extend_from_slice(&body);
        prop_assert!(matches!(
            decode_frame::<Request>(&framed),
            Err(ProtocolError::UnsupportedVersion(v)) if v == version
        ));
        prop_assert!(matches!(
            decode_frame::<Response>(&framed),
            Err(ProtocolError::UnsupportedVersion(v)) if v == version
        ));
    }

    /// Arbitrary bytes off the socket must not panic either decoder.
    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode_frame::<Request>(&bytes);
        let _ = decode_frame::<Response>(&bytes);
    }

    /// A frame declaring more than `MAX_FRAME` is refused on the prefix
    /// alone. `read_frame_sync` sizes its buffer from the peer's number, so
    /// this check is the only thing between a hostile local process and an
    /// arbitrary allocation.
    #[test]
    fn an_oversized_frame_is_refused_on_its_prefix(len in (MAX_FRAME as u32 + 1)..=u32::MAX) {
        // Deliberately only the prefix: if the reader tried to read the body
        // before checking the length, it would see an eof error instead.
        let bytes = len.to_be_bytes();
        match read_frame_sync(&mut Cursor::new(&bytes[..])) {
            Err(ProtocolError::FrameTooLarge(n)) => prop_assert_eq!(n as u32, len),
            other => prop_assert!(false, "{:?}", other),
        }
    }

    /// A frame shorter than its prefix claims is an error, never a silent
    /// short read: a truncated `UnlockWithKey` must not become a request
    /// with a partly-zero key.
    #[test]
    fn a_truncated_frame_is_an_error(len in 1usize..4096, short_by in 1usize..64) {
        let short_by = short_by.min(len);
        let mut bytes = (len as u32).to_be_bytes().to_vec();
        bytes.resize(4 + len - short_by, 0xab);
        match read_frame_sync(&mut Cursor::new(&bytes[..])) {
            Err(ProtocolError::Io(e)) => {
                prop_assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            other => prop_assert!(false, "truncated frame gave {:?}", other),
        }
    }

    /// A complete frame reads back byte for byte, and only the declared
    /// number of bytes is consumed.
    #[test]
    fn a_complete_frame_reads_back_exactly(body in proptest::collection::vec(any::<u8>(), 0..2048), trailing in proptest::collection::vec(any::<u8>(), 0..16)) {
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&trailing);
        let mut cursor = Cursor::new(&bytes[..]);
        let got = read_frame_sync(&mut cursor).expect("a complete frame must read");
        prop_assert_eq!(&got[..], &body[..]);
        prop_assert_eq!(cursor.position() as usize, 4 + body.len(), "the reader ran past its frame");
    }
}

/// The RFC 2409 second Oakley group prime, big-endian, duplicated from the
/// implementation on purpose: a test that asked the code for its own modulus
/// would agree with it whatever it had been changed to.
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);

fn prime_plus(delta: i32) -> [u8; 128] {
    let mut b = [0u8; 128];
    for (i, out) in b.iter_mut().enumerate() {
        *out = u8::from_str_radix(&PRIME_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    let mut carry = delta;
    for i in (0..128).rev() {
        if carry == 0 {
            break;
        }
        let v = b[i] as i32 + carry;
        b[i] = v.rem_euclid(256) as u8;
        carry = v.div_euclid(256);
    }
    b
}

/// In a safe-prime group the only elements of small order are 1 and p-1, so
/// {0, 1, p-1}, everything at or above p, and everything wider than the
/// modulus is the complete set a peer must not be allowed to use. Anything
/// accepted from that set would let the client fix the shared secret to a
/// value it already knows and read every secret the session carries.
#[test]
fn degenerate_peer_public_keys_are_rejected() {
    let me = dh::KeyPair::generate();
    let cases: [(&str, Vec<u8>); 8] = [
        ("empty", vec![]),
        ("zero", vec![0]),
        ("one", vec![1]),
        (
            "one padded",
            prime_plus(0)
                .iter()
                .map(|_| 0)
                .take(127)
                .chain([1])
                .collect(),
        ),
        ("p-1", prime_plus(-1).to_vec()),
        ("p", prime_plus(0).to_vec()),
        ("p+1", prime_plus(1).to_vec()),
        ("129 bytes", vec![1u8; 129]),
    ];
    for (name, bytes) in cases {
        assert!(
            matches!(me.derive_aes_key(&bytes), Err(dh::DhError::InvalidPeerKey)),
            "{name} was not rejected"
        );
        assert!(
            matches!(
                SessionCipher::from_dh(&me, &bytes),
                Err(SessionError::Dh(dh::DhError::InvalidPeerKey))
            ),
            "{name} was not rejected by from_dh"
        );
    }
}

/// The two values just inside the boundary must still work, or a legitimate
/// client is locked out.
#[test]
fn peer_public_keys_inside_the_range_are_accepted() {
    let me = dh::KeyPair::generate();
    for (name, bytes) in [("two", vec![2u8]), ("p-2", prime_plus(-2).to_vec())] {
        let k = me
            .derive_aes_key(&bytes)
            .unwrap_or_else(|e| panic!("{name} was refused: {e:?}"));
        assert_eq!(k.len(), 16);
        // Deterministic, and independent of how many leading zeros the
        // client chose to send.
        assert_eq!(
            *k,
            *me.derive_aes_key(&bytes).unwrap(),
            "{name} not deterministic"
        );
        let mut padded = vec![0u8; 128 - bytes.len()];
        padded.extend_from_slice(&bytes);
        assert_eq!(
            *k,
            *me.derive_aes_key(&padded).unwrap(),
            "{name} padding-sensitive"
        );
    }
}

proptest! {
    // A 1024-bit modexp per case; a few dozen is plenty for regression cover.
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any byte string at all off the bus, of any length.
    #[test]
    fn arbitrary_peer_public_keys_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        let me = dh::KeyPair::generate();
        if bytes.len() > 128 {
            prop_assert!(matches!(me.derive_aes_key(&bytes), Err(dh::DhError::InvalidPeerKey)));
        } else {
            let _ = me.derive_aes_key(&bytes);
        }
    }
}

/// One agreed session for the whole file. The key agreement is covered
/// above; re-running a pair of 1024-bit modexps per case would make these
/// tests measure `crypto-bigint` rather than the cipher.
fn agreed_session() -> &'static (SessionCipher, SessionCipher) {
    static S: std::sync::OnceLock<(SessionCipher, SessionCipher)> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let client = dh::KeyPair::generate();
        let server = dh::KeyPair::generate();
        let c = SessionCipher::from_dh(&client, server.public_bytes()).unwrap();
        let s = SessionCipher::from_dh(&server, client.public_bytes()).unwrap();
        (c, s)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn session_encrypt_decrypt_round_trips(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let (c, s) = agreed_session();
        let (iv, ct) = c.encrypt(&plaintext);
        prop_assert_eq!(iv.len(), 16);
        // PKCS#7 always adds a block; a ciphertext the same length as the
        // plaintext would mean the padding was skipped.
        prop_assert_eq!(ct.len(), (plaintext.len() / 16 + 1) * 16);
        let back = s.decrypt(&iv, &ct).unwrap();
        prop_assert_eq!(back.as_slice(), &plaintext[..]);
    }

    /// The Secret Service spec fixes this at AES-128-CBC with PKCS#7 and no
    /// MAC, so a corrupted ciphertext is *not* reliably detectable — about
    /// 255 times in 256 the padding check fails, and the rest of the time
    /// decryption succeeds and returns garbage. Asserting "corruption is an
    /// error" would assert something false. What does hold, and what is
    /// checked here, is that corruption never yields the original plaintext:
    /// CBC decryption is a bijection on (IV, ciphertext) and PKCS#7 padding
    /// is injective.
    #[test]
    fn corruption_never_yields_the_original_plaintext(
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
        at in any::<u16>(),
        xor in 1u8..=255,
        in_iv in any::<bool>(),
    ) {
        let (c, s) = agreed_session();
        let (mut iv, mut ct) = c.encrypt(&plaintext);
        if in_iv {
            let i = at as usize % iv.len();
            iv[i] ^= xor;
        } else {
            let i = at as usize % ct.len();
            ct[i] ^= xor;
        }
        if let Ok(garbage) = s.decrypt(&iv, &ct) {
            prop_assert_ne!(garbage.as_slice(), &plaintext[..]);
        }
    }

    /// The `(oayays)` secret struct is entirely client-supplied, with
    /// lengths of the client's choosing. A wrong-length IV must be an error
    /// on the length, before any block is touched.
    #[test]
    fn arbitrary_client_ciphertext_never_panics(
        params in proptest::collection::vec(any::<u8>(), 0..40),
        value in proptest::collection::vec(any::<u8>(), 0..80),
    ) {
        let (c, _) = agreed_session();
        match c.decrypt(&params, &value) {
            Err(SessionError::BadIv(n)) => {
                prop_assert_eq!(n, params.len());
                prop_assert_ne!(params.len(), 16);
            }
            Err(SessionError::Decrypt) => prop_assert_eq!(params.len(), 16),
            Err(e) => prop_assert!(false, "unexpected {:?}", e),
            Ok(out) => {
                prop_assert_eq!(params.len(), 16);
                prop_assert_eq!(value.len() % 16, 0);
                prop_assert!(!value.is_empty());
                prop_assert!(out.len() < value.len(), "unpadding removed nothing");
            }
        }
    }

    /// The plain transport is what a client that skipped the DH negotiation
    /// gets; it must be a faithful pass-through in both directions.
    #[test]
    fn the_plain_transport_passes_through(plaintext in proptest::collection::vec(any::<u8>(), 0..256)) {
        let c = SessionCipher::plain();
        let (params, value) = c.encrypt(&plaintext);
        prop_assert!(params.is_empty());
        prop_assert_eq!(&value[..], &plaintext[..]);
        let back = c.decrypt(&params, &value).unwrap();
        prop_assert_eq!(back.as_slice(), &plaintext[..]);
    }
}
