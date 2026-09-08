//! Raw bytes off the control socket.
//!
//! The socket lives in `$XDG_RUNTIME_DIR` and is uid-checked, but every
//! same-uid process is semi-trusted at best: any of them can connect and
//! speak whatever it likes. `read_frame_sync` sizes an allocation from the
//! peer's own length prefix and `decode_frame` hands the remainder to
//! postcard, so these three functions are the entire parsing surface a
//! hostile local process gets to aim at the daemon *and* at the PAM module,
//! which runs this same code as root.
//!
//! Uniformly random bytes are nearly useless here: four random bytes almost
//! never form a length prefix that agrees with the body that follows, so an
//! unstructured fuzzer would only ever re-test the `> MAX_FRAME` branch. The
//! generator below therefore builds frames that are already correct in the
//! boring respects — real prefix, real version byte — and hostile in the one
//! respect under test.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::protocol::{
    self, decode_frame, read_frame_sync, ProtocolError, Request, Response, MAX_FRAME,
    PROTOCOL_VERSION,
};
use std::io::Cursor;

/// The peak-allocation counter lives in `smfuzz` so more than one target can
/// assert the real bound rather than leaning on `-rss_limit_mb`. libFuzzer
/// itself is C++ and allocates through `malloc` directly, so it does not
/// pollute the counter.
#[global_allocator]
static ALLOC: smfuzz::PeakAlloc = smfuzz::PeakAlloc;

/// Slack for the bookkeeping `read_frame_sync` does around the body buffer
/// (the `Zeroizing` wrapper, the 4-byte prefix). Anything bigger than this
/// that is not the body itself is an allocation the peer should not have
/// been able to provoke.
const OVERHEAD: usize = 64;

/// How the fuzzer's bytes become something the reader will look at.
#[derive(Debug, arbitrary::Arbitrary)]
enum FrameCase {
    /// The dumb case, kept because "not a frame at all" must also be safe.
    Raw(Vec<u8>),
    /// A hand-built frame: the prefix and the version byte are whatever the
    /// fuzzer wants, which covers correct-prefix/wrong-version and
    /// correct-prefix/truncated-body without needing luck.
    Built {
        declared_len: u32,
        version: u8,
        body: Vec<u8>,
    },
    /// A real encoded message with one byte overwritten. This is the only
    /// way the fuzzer reliably reaches postcard's own decoders with a body
    /// that is *nearly* valid.
    Damaged {
        request: bool,
        at: u16,
        xor: u8,
        collection: String,
    },
    /// The two lengths the limit check is defined at. A fuzzer will not find
    /// `0x00100000` on its own, and off-by-one here is the difference
    /// between a 1 MiB cap and no cap at all.
    AtLimit { over: bool, extra_body: bool },
}

impl FrameCase {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            FrameCase::Raw(b) => b.clone(),
            FrameCase::Built {
                declared_len,
                version,
                body,
            } => {
                let mut out = Vec::with_capacity(5 + body.len());
                out.extend_from_slice(&declared_len.to_be_bytes());
                out.push(*version);
                out.extend_from_slice(body);
                out
            }
            FrameCase::Damaged {
                request,
                at,
                xor,
                collection,
            } => {
                let mut frame = if *request {
                    protocol::encode_frame(&Request::Lock {
                        collection: Some(collection.clone()),
                    })
                } else {
                    protocol::encode_frame(&Response::Error(collection.clone()))
                }
                .map(|f| f.to_vec())
                .unwrap_or_default();
                if !frame.is_empty() {
                    let i = *at as usize % frame.len();
                    frame[i] ^= *xor;
                }
                frame
            }
            FrameCase::AtLimit { over, extra_body } => {
                let len = if *over { MAX_FRAME + 1 } else { MAX_FRAME };
                let mut out = (len as u32).to_be_bytes().to_vec();
                if *extra_body {
                    out.push(PROTOCOL_VERSION);
                }
                out
            }
        }
    }
}

fuzz_target!(|case: FrameCase| {
    let bytes = case.to_bytes();

    // --- decode_frame: the body parser, fed the raw bytes as a body. ---
    //
    // The version gate must run before postcard sees anything, so the error
    // for a body whose first byte is not the current version is knowable
    // without decoding it.
    for body in [&bytes[..], bytes.get(4..).unwrap_or(&[])] {
        let req = decode_frame::<Request>(body);
        let resp = decode_frame::<Response>(body);
        match body.first() {
            None => {
                assert!(
                    matches!(req, Err(ProtocolError::Encoding(_))),
                    "empty body must be an encoding error"
                );
                assert!(matches!(resp, Err(ProtocolError::Encoding(_))));
            }
            Some(&v) if v != PROTOCOL_VERSION => {
                // A peer on another revision is refused by version, never by
                // whatever postcard would have made of its payload.
                assert!(
                    matches!(req, Err(ProtocolError::UnsupportedVersion(g)) if g == v),
                    "version {v} body decoded as something other than UnsupportedVersion"
                );
                assert!(
                    matches!(resp, Err(ProtocolError::UnsupportedVersion(g)) if g == v),
                    "version {v} body decoded as something other than UnsupportedVersion"
                );
            }
            Some(_) => {
                // Correct version: postcard may accept or reject. What must
                // hold either way is that decoding is a fixpoint — whatever
                // the peer sent, re-encoding what we understood it to mean
                // yields a body we understand identically. (postcard is not
                // self-delimiting and tolerates trailing bytes and
                // non-canonical varints, so the *input* is not required to
                // equal the re-encoding; the frame length is what bounds it.)
                if let Ok(r) = req {
                    let re = protocol::encode_frame(&r).expect("re-encode of a decoded request");
                    let again = decode_frame::<Request>(&re[4..])
                        .expect("a re-encoded request must decode");
                    assert_eq!(
                        r.variant_name(),
                        again.variant_name(),
                        "request changed meaning across a re-encode"
                    );
                }
                if let Ok(r) = resp {
                    let re = protocol::encode_frame(&r).expect("re-encode of a decoded response");
                    let again = decode_frame::<Response>(&re[4..])
                        .expect("a re-encoded response must decode");
                    assert_eq!(r, again, "response changed meaning across a re-encode");
                }
            }
        }
    }

    // --- read_frame_sync: the allocation surface. ---
    let declared = if bytes.len() >= 4 {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    } else {
        None
    };

    let mut cursor = Cursor::new(&bytes[..]);
    smfuzz::reset_peak();
    let got = read_frame_sync(&mut cursor);
    let peak = smfuzz::peak();

    match (declared, got) {
        (None, Err(ProtocolError::Io(e))) => {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "a stream too short for a length prefix must be an eof error"
            );
            assert!(peak <= OVERHEAD, "allocated {peak} for a headerless stream");
        }
        (None, other) => panic!("{} bytes is not a frame, got {other:?}", bytes.len()),

        (Some(len), Err(ProtocolError::FrameTooLarge(reported))) => {
            // The cap is refused on the prefix alone: nothing sized by the
            // peer's number may be allocated, whatever it claimed.
            assert!(len > MAX_FRAME, "{len} is within the cap but was refused");
            assert_eq!(reported, len, "the refusal must name the declared length");
            assert!(
                peak <= OVERHEAD,
                "allocated {peak} for a frame declaring {len} bytes, over the {MAX_FRAME} cap"
            );
        }
        (Some(len), Err(ProtocolError::Io(e))) => {
            // Short read. It must be an error, never a truncated success.
            assert!(
                len <= MAX_FRAME,
                "{len} exceeds the cap but was read anyway"
            );
            assert!(
                bytes.len() - 4 < len,
                "eof reported for a frame that had all {len} of its bytes"
            );
            assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            assert!(
                peak <= len.max(OVERHEAD),
                "allocated {peak} while reading a truncated {len}-byte frame"
            );
        }
        (Some(len), Ok(body)) => {
            assert!(
                len <= MAX_FRAME,
                "read a frame of {len} bytes, over the cap"
            );
            assert_eq!(body.len(), len, "body length disagrees with the prefix");
            assert_eq!(&body[..], &bytes[4..4 + len], "body is not the bytes read");
            assert!(
                peak <= len.max(OVERHEAD),
                "allocated {peak} to read a declared {len} bytes"
            );
            // The body buffer is a single `vec![0u8; len]`, so a non-empty
            // frame must have shown up in the counter. Without this the
            // bounds above would pass vacuously if the allocator hook ever
            // stopped seeing the reader's allocations.
            assert!(
                len == 0 || peak >= len,
                "the allocation counter saw {peak} for a {len}-byte body; it is not observing the reader"
            );
        }
        (Some(len), other) => panic!("frame declaring {len} bytes gave {other:?}"),
    }
});
