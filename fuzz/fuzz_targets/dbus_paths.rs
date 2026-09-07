//! Object paths: built from client-supplied ids, parsed back from
//! client-supplied strings.
//!
//! A collection id and an item id both originate with a bus client, and both
//! end up as path *segments* — so the escaping question is the classic one:
//! can a value smuggle a `/` and address an object it was never given? On the
//! way back in, `parse` is handed the raw path from an arbitrary method call,
//! so it must not panic and must never hand the daemon a `Target` whose
//! components could re-address something else.
//!
//! The constructors are deliberately partial: `collection` and `item` panic
//! on a segment that is not `[A-Za-z0-9_]+` (`ObjectPath::try_from` rejects
//! it), which is the loud failure the callers want — every one of them
//! validates with `is_segment` first. `alias` is the one that takes untrusted
//! input directly, and it returns `Option`. Both halves of that contract are
//! asserted here.
#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use secret_manager::dbus::paths::{
    self, Target, ALIASES_PREFIX, COLLECTIONS_PREFIX, PROMPTS_PREFIX, SESSIONS_PREFIX,
};

/// No component of a parsed target may contain a separator, a `.`, or
/// anything else outside the segment charset: that is the property that stops
/// `../` and `a/b` from re-addressing another object.
fn check_component(s: &str, path: &str) {
    assert!(
        !s.contains('/'),
        "a parsed component carries a separator: {s:?} from {path:?}"
    );
    assert!(
        paths::is_segment(s),
        "a parsed component is not a valid segment: {s:?} from {path:?}"
    );
}

fn check_target(t: &Target, path: &str) {
    match t {
        Target::Collection(c) | Target::Alias(c) => check_component(c, path),
        Target::Item {
            collection: a,
            item: b,
        }
        | Target::AliasItem { alias: a, item: b } => {
            check_component(a, path);
            check_component(b, path);
        }
    }
}

/// An id biased towards the segment charset, so most iterations exercise the
/// round trip rather than being rejected at the first byte, while the escapes
/// an attacker would actually try (`/`, `..`, a trailing separator, a NUL)
/// still appear often enough to matter.
fn id(u: &mut Unstructured) -> arbitrary::Result<String> {
    const HOSTILE: &[&str] = &["/", "..", ".", "", "a/b", "_", "\0", "%2f", "-", " "];
    let len = u.arbitrary_len::<u8>()?.min(48);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        if u.is_empty() {
            break;
        }
        if u.ratio(1, 6)? {
            s.push_str(u.choose(HOSTILE)?);
        } else {
            s.push(char::from(u.arbitrary::<u8>()?));
        }
    }
    Ok(s)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let (Ok(a), Ok(b)) = (id(&mut u), id(&mut u)) else {
        return;
    };

    // `parse` is the entry point for any string a client puts in a method
    // argument, including the ones the constructors would have refused.
    for candidate in [
        a.clone(),
        b.clone(),
        format!("{COLLECTIONS_PREFIX}{a}"),
        format!("{COLLECTIONS_PREFIX}{a}/{b}"),
        format!("{COLLECTIONS_PREFIX}{a}/{b}/{a}"),
        format!("{ALIASES_PREFIX}{a}"),
        format!("{ALIASES_PREFIX}{a}/{b}"),
        format!("{SESSIONS_PREFIX}{a}"),
        format!("{PROMPTS_PREFIX}{a}"),
    ] {
        if let Some(t) = paths::parse(&candidate) {
            check_target(&t, &candidate);
        }
    }
    // A session or prompt path is never a collection or an item: those
    // objects are owned by one client and must not be reachable through the
    // collection lookup.
    assert!(paths::parse(&format!("{SESSIONS_PREFIX}{a}")).is_none());
    assert!(paths::parse(&format!("{PROMPTS_PREFIX}{a}")).is_none());
    assert!(paths::parse(paths::SERVICE_PATH).is_none());
    assert!(paths::parse("/").is_none());

    // `alias` is the constructor that takes untrusted input directly, so its
    // refusal is the contract, not a debug assertion.
    match paths::alias(&a) {
        Some(p) => {
            assert!(paths::is_segment(&a), "alias accepted a non-segment {a:?}");
            assert!(p.as_str().starts_with(ALIASES_PREFIX), "{p}");
            assert_eq!(paths::parse(p.as_str()), Some(Target::Alias(a.clone())));
        }
        None => assert!(!paths::is_segment(&a), "alias refused a segment {a:?}"),
    }

    // The infallible constructors are only ever called on validated segments;
    // calling them on anything else is a bug in the caller, not an input the
    // daemon can be fed, so the round trip is asserted exactly there.
    if paths::is_segment(&a) {
        let c = paths::collection(&a);
        assert!(c.as_str().starts_with(COLLECTIONS_PREFIX), "{c}");
        assert_eq!(
            paths::parse(c.as_str()),
            Some(Target::Collection(a.clone()))
        );

        if paths::is_segment(&b) {
            let i = paths::item(&a, &b);
            assert!(i.as_str().starts_with(COLLECTIONS_PREFIX), "{i}");
            assert_eq!(
                paths::parse(i.as_str()),
                Some(Target::Item {
                    collection: a.clone(),
                    item: b.clone(),
                })
            );
            // Distinct ids must give distinct paths: an id that can collide
            // with another would let one client address another's item.
            if a != b {
                assert_ne!(paths::item(&a, &b), paths::item(&b, &a));
            }
        }
    }

    // Session and prompt paths are generated, not parsed, but they still have
    // to satisfy the segment rule — they are formatted with a random suffix,
    // and a suffix outside the charset would panic in `owned`.
    let Ok(n) = u.arbitrary::<u64>() else { return };
    let s = paths::session(n);
    assert!(s.as_str().starts_with(SESSIONS_PREFIX), "{s}");
    let p = paths::prompt(n);
    assert!(p.as_str().starts_with(PROMPTS_PREFIX), "{p}");
    for path in [s, p] {
        let seg = path.as_str().rsplit('/').next().expect("a final segment");
        assert!(paths::is_segment(seg), "{seg}");
    }
});
