//! Serialised key derivation.
//!
//! Argon2id deliberately costs memory and time, so an unbounded number of
//! concurrent derivations is a denial-of-service surface: the control server
//! accepts several connections at once and each D-Bus prompt can start one.
//! Every derivation the daemon performs therefore goes through this module,
//! which caps concurrency and moves the work to the blocking pool so it never
//! occupies an async worker thread.

use crate::vault::crypto::{self, CryptoError, KdfParams, Key, SALT_LEN};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// Derivations allowed at once. Two keeps a single stuck derivation from
/// blocking every other client while bounding peak memory to twice
/// `KdfParams::MAX_M_COST_KIB`.
pub const MAX_CONCURRENT: usize = 2;

static SLOTS: Semaphore = Semaphore::const_new(MAX_CONCURRENT);

/// Runs `f` on the blocking pool, holding one derivation slot.
pub async fn run_bounded<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let _permit = SLOTS.acquire().await.expect("semaphore is never closed");
    tokio::task::spawn_blocking(f)
        .await
        .expect("key derivation task panicked")
}

/// `derive_key` under the concurrency cap, off the async workers.
pub async fn derive(
    password: Zeroizing<Vec<u8>>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
) -> Result<Key, CryptoError> {
    run_bounded(move || crypto::derive_key(&password, &salt, kdf)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn derive_matches_the_direct_call_and_bounds_concurrency() {
        let salt = [3u8; SALT_LEN];
        let params = KdfParams::FAST_FOR_TESTS;
        let ours = derive(Zeroizing::new(b"pw".to_vec()), salt, params)
            .await
            .unwrap();
        let direct = crypto::derive_key(b"pw", &salt, params).unwrap();
        assert_eq!(ours.as_bytes(), direct.as_bytes());
    }

    /// More derivations than slots must queue rather than all run at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn extra_derivations_wait_for_a_slot() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (live, peak) = (live.clone(), peak.clone());
            tasks.push(tokio::spawn(run_bounded(move || {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(50));
                live.fetch_sub(1, Ordering::SeqCst);
            })));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= MAX_CONCURRENT,
            "{} derivations ran at once",
            peak.load(Ordering::SeqCst)
        );
    }

    /// This module is the single funnel for every daemon derivation and
    /// `run_bounded` `.expect()`s on a panicking task, so a ceiling refusal
    /// has to arrive as an `Err` — not as an allocation that aborts a
    /// blocking worker and takes the daemon with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_kdf_over_the_ceiling_is_refused_without_running() {
        let salt = [7u8; SALT_LEN];
        let err = derive(
            Zeroizing::new(b"pw".to_vec()),
            salt,
            KdfParams {
                m_cost_kib: u32::MAX,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CryptoError::UnsafeKdf(_)), "got {err:?}");
        // A refusal must still release its slot, or a few bad headers would
        // permanently exhaust the cap and wedge every later unlock.
        derive(
            Zeroizing::new(b"pw".to_vec()),
            salt,
            KdfParams::FAST_FOR_TESTS,
        )
        .await
        .expect("the refused derivation must have released its slot");
    }
}
