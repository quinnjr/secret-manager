//! Preset GPG passphrases into gpg-agent after an unlock (daemon side).
//!
//! Only runs when `[gpg] enabled = true` — an explicit opt-in, since this
//! spawns gpg-agent helpers unasked and most users have no gpg. Callers
//! invoke [`note_unlocked`] at an unlock success point holding no guard;
//! it snapshots what it needs under one brief state lock, drops it, and
//! does everything else in a spawned task: read each collection's
//! enrolled items one at a time (read-only, never unlocking anything —
//! a collection that re-locked meanwhile is skipped, and this path must
//! never raise a dialog), then run discovery and the agent pipe with no
//! lock held at all, inside [`block_in_place`] so the waits release the
//! async worker instead of parking it.
//!
//! Every failure is log-only: an unlock must never fail because the agent
//! did. Anything reaching a log from a peer (a bus-client-settable keyid,
//! agent reply text) goes through `escape_control` first.

use super::state::{Shared, VaultRef, block_in_place};
use crate::gpg::{self, Bins};
use crate::sanitize::escape_control;
use zeroize::Zeroizing;

/// Called wherever the daemon finishes unlocking a collection, with no
/// guard held. Returns after spawning the background work; disabled (the
/// default) returns before any task exists, so the opt-out path is
/// synchronous and total.
pub async fn note_unlocked(state: &Shared) {
    // One brief acquisition: clone the config, then drop the guard before
    // spawning. The handles are snapshotted inside the task itself, so a
    // vault created between the unlock and the task still gets read.
    let enabled = state.lock().await.gpg.enabled;
    if !enabled {
        return;
    }
    let state = state.clone();
    // `spawn` is detached: nothing held here is held inside the task, and
    // the task itself takes only one collection lock at a time below.
    tokio::spawn(async move {
        run_preset(&state).await;
    });
}

async fn run_preset(state: &Shared) {
    let (vaults, cfg): (Vec<(String, VaultRef)>, crate::config::GpgConfig) = {
        let st = state.lock().await;
        (st.all_vaults(), st.gpg.clone())
    };
    if !cfg.enabled {
        return;
    }
    let mut pairs: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut warnings = Vec::new();
    for (_id, vault) in &vaults {
        // One collection at a time, read-only: never hold two locks, never
        // unlock, never save. Each guard dies at the end of its iteration.
        let vault = vault.lock().await;
        if vault.is_locked() {
            continue;
        }
        let items = match vault.items() {
            Ok(items) => items,
            Err(e) => {
                tracing::warn!("gpg preset: cannot read a collection: {e}");
                continue;
            }
        };
        // One shared rule for every vault, unit-tested in `crate::gpg`:
        // schema + keyid match, allowlist, non-empty secret, first wins.
        warnings.extend(gpg::collect_enrolled(items, &cfg.keys, &mut pairs));
    }
    // No guard is held here — every vault guard died with its iteration —
    // so blocking on child processes only ever parks this task's worker
    // slot, which `block_in_place` hands back for the duration.
    let bins = Bins::from_config(&cfg);
    block_in_place(move || {
        let (done, failed) = gpg::preset_enrolled(&bins, &pairs);
        if done > 0 {
            tracing::info!("gpg preset: fed {done} key(s) to the agent");
        }
        for w in warnings {
            tracing::warn!("gpg preset: {}", escape_control(&w));
        }
        for f in failed {
            tracing::warn!("gpg preset: {}", escape_control(&f));
        }
    });
}
