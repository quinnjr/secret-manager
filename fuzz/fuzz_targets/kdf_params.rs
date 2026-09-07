//! The KDF ceilings, which are the only thing standing between a tampered
//! header and the daemon's memory.
//!
//! A vault header is not authenticated until a successful decrypt, so the
//! `m_cost_kib`, `t_cost` and `p_cost` a reader picks up are chosen by
//! whoever last wrote the file. The `argon2` crate will happily accept
//! `m_cost` up to 4 TiB and `t_cost` up to `u32::MAX`, so a single edited
//! header would abort the process on allocation or spin it for hours — and
//! the PAM module runs this path as root inside a login the target user
//! controls.
//!
//! The invariant is therefore about *ordering*, not merely about outcome:
//! parameters outside the ceilings must be refused **before** Argon2 is
//! reached. The target asserts that structurally — it computes the verdict
//! from the ceilings and compares it against the validator, and only ever
//! hands Argon2 a parameter set it has already proven to be small. Actually
//! running the absurd cases would allocate a quarter-gigabyte per execution
//! and turn the fuzzer into a benchmark of malloc.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secret_manager::vault::crypto::{self, CryptoError, KdfParams, NONCE_LEN, SALT_LEN};
use secret_manager::vault::format::{self, FormatError, Header, VaultFile};

/// A minimal, otherwise-valid header carrying `kdf`. Everything but the KDF
/// is fixed, so a refusal can only be attributable to the parameters.
fn header_with_kdf(kdf: KdfParams) -> Header {
    Header {
        version: format::VERSION,
        label: "default".into(),
        created: 0,
        modified: 0,
        kdf,
        salt: [1u8; SALT_LEN],
        index_salt: [2u8; SALT_LEN],
        nonce: [3u8; NONCE_LEN],
        index: Vec::new(),
    }
}

/// The ceilings, restated from the documentation rather than read from the
/// code under test: an assertion that recomputes the implementation cannot
/// catch the implementation drifting.
const MAX_M_COST_KIB: u32 = 256 * 1024;
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

/// Whether these parameters are inside every documented bound, including
/// Argon2's own 8-KiB-per-lane floor.
fn within_ceilings(p: KdfParams) -> bool {
    p.p_cost >= 1
        && p.p_cost <= MAX_P_COST
        && p.t_cost >= 1
        && p.t_cost <= MAX_T_COST
        && p.m_cost_kib <= MAX_M_COST_KIB
        && p.m_cost_kib >= 8u32.saturating_mul(p.p_cost)
}

/// Cheap enough to actually derive with. Everything else is checked without
/// touching Argon2.
fn cheap(p: KdfParams) -> bool {
    within_ceilings(p) && p.m_cost_kib <= 64 && p.t_cost <= 2 && p.p_cost <= 2
}

fuzz_target!(|input: (u32, u32, u32)| {
    let (m_cost_kib, t_cost, p_cost) = input;
    let params = KdfParams {
        m_cost_kib,
        t_cost,
        p_cost,
    };

    let verdict = params.validate();

    // The validator and the documented ceilings must agree exactly. A gap in
    // either direction is a bug: one way lets a hostile header through, the
    // other refuses a vault the daemon itself wrote.
    assert_eq!(
        verdict.is_ok(),
        within_ceilings(params),
        "validate() and the documented ceilings disagree on {params:?}"
    );

    match verdict {
        Ok(()) => {
            // An accepted set must be inside every ceiling individually, so
            // that a future ceiling change cannot be satisfied by the
            // aggregate check above alone.
            assert!(params.p_cost >= 1 && params.p_cost <= MAX_P_COST);
            assert!(params.t_cost >= 1 && params.t_cost <= MAX_T_COST);
            assert!(params.m_cost_kib <= MAX_M_COST_KIB);
            assert!(params.m_cost_kib >= 8 * params.p_cost);
        }
        Err(e) => {
            assert!(
                matches!(e, CryptoError::UnsafeKdf(_)),
                "out-of-range parameters were refused for the wrong reason: {e:?}"
            );
            // The ordering property. `derive_key` validates first, so a
            // refused set must come back as `UnsafeKdf` — never as a KDF
            // error from Argon2, which would mean Argon2 had already been
            // constructed with attacker-chosen costs. This call is safe to
            // make precisely *because* the refusal happens first: if it did
            // not, this line would allocate `m_cost_kib` and the fuzzer
            // would die here, which is itself the failure signal.
            let derived = crypto::derive_key(b"pw", &[0u8; SALT_LEN], params);
            assert!(
                matches!(derived, Err(CryptoError::UnsafeKdf(_))),
                "derive_key reached Argon2 with parameters outside the ceilings"
            );

            // The same refusal must happen on the parse path, before anyone
            // holding the file gets a derivation out of us. `decode` gates on
            // the header's KDF for exactly this reason.
            let bytes = VaultFile::new(header_with_kdf(params), vec![0u8; 16])
                .unwrap()
                .encode();
            assert!(
                matches!(VaultFile::decode(&bytes), Err(FormatError::UnsafeKdf(_))),
                "a header carrying out-of-range KDF parameters was accepted by decode"
            );
            assert!(matches!(
                format::decode_header(&bytes),
                Err(FormatError::UnsafeKdf(_))
            ));
            return;
        }
    }

    // Only now, on a set already proven to be inside the ceilings and small,
    // is a real derivation affordable. It must be deterministic and salt
    // sensitive, or the ceiling check would be guarding a KDF that does not
    // bind the header's salt.
    if cheap(params) {
        let a = crypto::derive_key(b"pw", &[1u8; SALT_LEN], params).unwrap();
        let b = crypto::derive_key(b"pw", &[1u8; SALT_LEN], params).unwrap();
        let c = crypto::derive_key(b"pw", &[2u8; SALT_LEN], params).unwrap();
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "derivation is not deterministic"
        );
        assert_ne!(a.as_bytes(), c.as_bytes(), "derivation ignores the salt");
    }
});
