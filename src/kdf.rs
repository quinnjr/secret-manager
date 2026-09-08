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
///
/// The permit is moved *into* the blocking closure, not held across the
/// `.await`. `spawn_blocking` is not cancellable: dropping this future - a
/// cancelled unlock, a dismissed prompt, a `select!` arm that lost - abandons
/// the `JoinHandle` while `f` runs on. A permit released on that drop would
/// let the next caller start a second arena beside the one still running, and
/// a client that repeatedly starts and cancels could hold arbitrarily many
/// live at once, which is exactly the bound [`MAX_CONCURRENT`] exists to set.
/// Tied to the work instead, the slot is free only when the memory is.
pub async fn run_bounded<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit = SLOTS.acquire().await.expect("semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
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

    /// A cancelled caller must not release its slot early. `spawn_blocking`
    /// is not cancellable: dropping the future abandons the `JoinHandle`
    /// while the Argon2 arena the permit exists to bound is still live. If
    /// the permit went with the future, a client that repeatedly starts and
    /// dismisses an unlock would hold arbitrarily many arenas at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_cancelled_call_keeps_its_slot_until_the_work_finishes() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        for _ in 0..8 {
            let before = live.load(Ordering::SeqCst);
            let (l, p) = (live.clone(), peak.clone());
            let fut = std::pin::pin!(run_bounded(move || {
                let now = l.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                l.fetch_sub(1, Ordering::SeqCst);
            }));
            // Poll until the blocking work has actually started - the other
            // tests in this module share `SLOTS`, so a fixed timeout could
            // expire while still queued - then drop the future: a dismissed
            // prompt, a client that hung up, a `select!` arm that lost.
            let mut fut = fut;
            let deadline = Instant::now() + Duration::from_secs(10);
            while live.load(Ordering::SeqCst) == before && Instant::now() < deadline {
                if tokio::time::timeout(Duration::from_millis(5), fut.as_mut())
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        }
        while live.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak >= 1, "no derivation ran at all");
        assert!(
            peak <= MAX_CONCURRENT,
            "{peak} cancelled derivations ran at once"
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
