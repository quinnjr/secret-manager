//! The control protocol's two standing promises, checked against every
//! message shape the fuzzer can build.
//!
//! The first is that encode/decode is the identity. `UnlockWithKey` and
//! `ChangeKey` carry the vault key itself — the only secret this protocol
//! ever moves — and they go through a `Zeroizing` serialisation buffer that
//! is deliberately unusual. A key that came back one byte short, or with a
//! byte from the previous message's scratch buffer, would unlock nothing and
//! would look like a wrong password.
//!
//! The second is wire order. postcard encodes an enum variant as its
//! zero-based declaration index and nothing else: no name, no tag. Swapping
//! two variants of `Request` therefore turns a `Lock` on one side into a
//! `Status` on the other, silently, with no version mismatch to catch it —
//! and the daemon, the CLI and the PAM module are three separately-built
//! artifacts that can be from different builds. The index assertions below
//! are what turns that into a test failure instead of a field report.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::protocol::{
    self, decode_frame, CollectionStatus, KdfParams, Request, Response, Zeroizing, KEY_LEN,
    PROTOCOL_VERSION, REQUEST_VARIANTS, SALT_LEN,
};

/// The fuzzer's raw material for one message. Building `Request` through a
/// mirror rather than deriving `Arbitrary` on it keeps the derive out of the
/// shipped crate and lets the secret-bearing variants get full-entropy keys.
#[derive(Debug, arbitrary::Arbitrary)]
enum Msg {
    Lock(Option<String>),
    Status,
    Reload,
    UnlockWithKey(String, [u8; KEY_LEN]),
    ChangeKey(
        String,
        [u8; KEY_LEN],
        [u8; SALT_LEN],
        u32,
        u32,
        u32,
        [u8; KEY_LEN],
    ),
    RespOk,
    RespStatus(
        Vec<(String, String, bool, u16, Option<String>)>,
        u64,
        Option<String>,
    ),
    RespError(String),
}

/// `Request` has no `PartialEq` — deriving one would put a timing-unsafe
/// comparison on a key-bearing type — so identity is checked field by field.
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

/// The postcard variant index of an encoded frame: the byte after the
/// 4-byte length prefix and the version byte. Indices 0..=4 are a single
/// varint byte, which is exactly the range this protocol uses.
fn variant_index(frame: &[u8]) -> u8 {
    assert_eq!(
        frame[4], PROTOCOL_VERSION,
        "frame carries the wrong version"
    );
    frame[5]
}

/// Every `Request` and `Response` variant, pinned to the index its
/// declaration order gives it. A reordering is a wire-compatibility break
/// between the daemon and a PAM module built from a different commit, and
/// nothing else in the tree would notice it.
fn assert_wire_order() {
    let key = Zeroizing::new([0u8; KEY_LEN]);
    let reqs: [(Request, u8, &str); 5] = [
        (Request::Lock { collection: None }, 0, "Lock"),
        (Request::Status, 1, "Status"),
        (Request::Reload, 2, "Reload"),
        (
            Request::UnlockWithKey {
                collection: String::new(),
                key: key.clone(),
            },
            3,
            "UnlockWithKey",
        ),
        (
            Request::ChangeKey {
                collection: String::new(),
                old_key: key.clone(),
                new_salt: [0u8; SALT_LEN],
                new_kdf: KdfParams {
                    m_cost_kib: 8,
                    t_cost: 1,
                    p_cost: 1,
                },
                new_key: key.clone(),
            },
            4,
            "ChangeKey",
        ),
    ];
    for (req, want, name) in &reqs {
        let frame = protocol::encode_frame(req).expect("encode");
        assert_eq!(
            variant_index(&frame),
            *want,
            "Request::{name} must encode as variant {want}; the enum has been reordered"
        );
        assert_eq!(
            req.variant_name(),
            *name,
            "variant_name disagrees with the declaration order"
        );
        assert_eq!(
            REQUEST_VARIANTS[*want as usize], *name,
            "REQUEST_VARIANTS is out of step with the enum"
        );
    }
    assert_eq!(
        REQUEST_VARIANTS.len(),
        reqs.len(),
        "a Request variant is unpinned"
    );

    let resps: [(Response, u8, &str); 3] = [
        (Response::Ok, 0, "Ok"),
        (
            Response::Status {
                collections: Vec::new(),
                uptime_secs: 0,
                aliases_error: None,
            },
            1,
            "Status",
        ),
        (Response::Error(String::new()), 2, "Error"),
    ];
    for (resp, want, name) in &resps {
        let frame = protocol::encode_frame(resp).expect("encode");
        assert_eq!(
            variant_index(&frame),
            *want,
            "Response::{name} must encode as variant {want}; the enum has been reordered"
        );
        assert_eq!(resp.variant_name(), *name);
    }
}

/// Rebuilds a request with a fixed collection name, keeping its secrets.
///
/// Only the name changes, so the `Debug` impl takes exactly the same branch
/// and prints exactly the same fields; the one thing that differs is that the
/// input can no longer choose text that appears in the output.
fn with_benign_collection(req: &Request) -> Request {
    const NAME: &str = "collection";
    match req {
        Request::Lock { .. } => Request::Lock {
            collection: Some(NAME.to_string()),
        },
        Request::Status => Request::Status,
        Request::Reload => Request::Reload,
        Request::UnlockWithKey { key, .. } => Request::UnlockWithKey {
            collection: NAME.to_string(),
            key: key.clone(),
        },
        Request::ChangeKey {
            old_key,
            new_salt,
            new_kdf,
            new_key,
            ..
        } => Request::ChangeKey {
            collection: NAME.to_string(),
            old_key: old_key.clone(),
            new_salt: *new_salt,
            new_kdf: *new_kdf,
            new_key: new_key.clone(),
        },
    }
}

fuzz_target!(|msg: Msg| {
    // Cheap and unconditional: the pinning must fail on the very first
    // execution after a reordering, not only once the fuzzer happens to
    // build the reordered variant.
    assert_wire_order();

    match msg {
        Msg::RespOk | Msg::RespStatus(..) | Msg::RespError(_) => {
            let resp = match msg {
                Msg::RespOk => Response::Ok,
                Msg::RespStatus(rows, uptime_secs, aliases_error) => Response::Status {
                    aliases_error,
                    collections: rows
                        .into_iter()
                        .map(|(id, label, locked, items, warning)| CollectionStatus {
                            id,
                            label,
                            locked,
                            items: items as usize,
                            warning,
                        })
                        .collect(),
                    uptime_secs,
                },
                Msg::RespError(e) => Response::Error(e),
                _ => unreachable!(),
            };
            let Ok(frame) = protocol::encode_frame(&resp) else {
                // Only an over-cap message may fail to encode.
                return;
            };
            assert_eq!(
                u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
                frame.len() - 4,
                "the length prefix must describe the rest of the frame exactly"
            );
            let back = decode_frame::<Response>(&frame[4..]).expect("a frame we wrote must decode");
            assert_eq!(resp, back, "response did not survive the round trip");
        }
        other => {
            let req = match other {
                Msg::Lock(collection) => Request::Lock { collection },
                Msg::Status => Request::Status,
                Msg::Reload => Request::Reload,
                Msg::UnlockWithKey(collection, k) => Request::UnlockWithKey {
                    collection,
                    key: Zeroizing::new(k),
                },
                Msg::ChangeKey(collection, old, salt, m, t, p, new) => Request::ChangeKey {
                    collection,
                    old_key: Zeroizing::new(old),
                    new_salt: salt,
                    new_kdf: KdfParams {
                        m_cost_kib: m,
                        t_cost: t,
                        p_cost: p,
                    },
                    new_key: Zeroizing::new(new),
                },
                _ => unreachable!(),
            };
            let Ok(frame) = protocol::encode_frame(&req) else {
                return;
            };
            assert_eq!(
                u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
                frame.len() - 4,
                "the length prefix must describe the rest of the frame exactly"
            );
            let back = decode_frame::<Request>(&frame[4..]).expect("a frame we wrote must decode");
            assert!(
                same_request(&req, &back),
                "request did not survive the round trip: {req:?} -> {back:?}"
            );

            // A key that reaches a log or a panic message is the whole point
            // of the hand-written `Debug`, so check it on the same values the
            // round trip just proved are really in there.
            //
            // The collection name is fuzzer-controlled and is legitimately
            // printed unredacted, so a "does the output contain these bytes"
            // check can be defeated by naming the collection after the
            // rendering of the secret — which is exactly what the fuzzer did
            // (`new_salt = [93; 15] ++ [62]` with a collection literally
            // called "[93, 93, ..., 62]"). That is a false leak: the secret is
            // in the output because the *name* is, not because the key was
            // printed. So the redaction check runs against a copy carrying the
            // same secrets under a fixed, benign name, which leaves no channel
            // for the input to smuggle the expected text into the output.
            let shown = format!("{:?}", with_benign_collection(&req));
            match &req {
                Request::UnlockWithKey { key, .. } => {
                    assert!(shown.contains("<redacted>"), "UnlockWithKey Debug: {shown}");
                    assert!(
                        !shown.contains(&format!("{:?}", &key[..])),
                        "UnlockWithKey Debug leaked the key"
                    );
                }
                Request::ChangeKey {
                    old_key,
                    new_key,
                    new_salt,
                    ..
                } => {
                    assert!(shown.contains("<redacted>"), "ChangeKey Debug: {shown}");
                    for secret in [&old_key[..], &new_key[..], &new_salt[..]] {
                        assert!(
                            !shown.contains(&format!("{:?}", secret)),
                            "ChangeKey Debug leaked a secret"
                        );
                    }
                }
                _ => {}
            }
        }
    }
});
