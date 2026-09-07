//! Daemon assembly: vaults, bus connection, control socket, housekeeping tasks.

use crate::config::Config;
use crate::control::{ControlServer, Handler};
use crate::dbus::paths::{self, BUS_NAME, SERVICE_PATH};
use crate::dbus::prompt::Prompt;
use crate::dbus::registry;
use crate::dbus::service::{Service, ServiceSignals};
use crate::dbus::session::Session;
use crate::dbus::state::{ServiceState, Shared};
use crate::prompt::Pinentry;
use crate::protocol::{CollectionStatus, Request, Response};
use crate::vault::crypto::{KdfParams, Key};
use futures_util::StreamExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::connection::Builder;
use zbus::object_server::SignalEmitter;

#[derive(Debug, Clone)]
pub enum BusAddress {
    Session,
    Address(String),
}

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config: Config,
    pub bus: BusAddress,
    /// Override for `crate::protocol::socket_path()` (tests).
    pub control_socket: Option<PathBuf>,
    /// Extra environment for the pinentry child (tests).
    pub pinentry_env: Vec<(String, String)>,
    /// How often the idle-lock timer checks. Production: 30 s.
    pub idle_check_interval: Duration,
}

impl DaemonOptions {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            bus: BusAddress::Session,
            control_socket: None,
            pinentry_env: Vec::new(),
            idle_check_interval: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("another secret service already owns {BUS_NAME}")]
    NameTaken,
    #[error("bus error: {0}")]
    ZBus(zbus::Error),
    #[error("cannot load vaults: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot bind control socket: {0}")]
    Control(std::io::Error),
    #[error("XDG_RUNTIME_DIR is not set; cannot locate the control socket")]
    NoRuntimeDir,
    #[error("cannot apply the requested process hardening: {0}")]
    Hardening(std::io::Error),
}

impl From<zbus::Error> for DaemonError {
    fn from(e: zbus::Error) -> Self {
        match e {
            zbus::Error::NameTaken => DaemonError::NameTaken,
            other => DaemonError::ZBus(other),
        }
    }
}

pub struct Daemon {
    pub connection: Connection,
    pub state: Shared,
    tasks: Vec<JoinHandle<()>>,
}

/// Make the process non-dumpable: no core files, and no `ptrace` or
/// `/proc/<pid>/mem` from other processes of the same uid, whatever the
/// kernel's Yama setting. Every unlocked secret and vault key lives in this
/// process's memory.
pub fn disable_dumping() -> std::io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes an integer flag and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Pin all current and future pages in RAM so nothing is written to swap.
///
/// `RLIMIT_MEMLOCK` must cover the whole process, including the Argon2 arena
/// each unlock maps, and user sessions usually cap it at 8 MiB. The limit is
/// therefore checked up front and the option refused when it cannot be
/// honoured: locking lazily (`MCL_ONFAULT`) would instead succeed here and
/// then kill the daemon on the first derivation that exceeds the limit.
pub fn lock_memory() -> std::io::Result<()> {
    // Size the budget from the largest derivation the daemon can be asked to
    // perform, not from the configured one: a collection's header carries its
    // own KDF parameters and `ChangeKey` can raise them to the ceiling, so a
    // config-sized check would pass here and fault later.
    let needed = u64::from(KdfParams::MAX_M_COST_KIB) * 1024 * crate::kdf::MAX_CONCURRENT as u64
        + 64 * 1024 * 1024;
    // SAFETY: getrlimit writes a plain rlimit struct through a valid pointer.
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The soft limit is ours to raise up to the hard limit; only give up when
    // even that is too small, so an operator who raised LimitMEMLOCK does not
    // also have to think about the soft/hard split.
    if lim.rlim_cur != libc::RLIM_INFINITY
        && (lim.rlim_cur as u64) < needed
        && (lim.rlim_max == libc::RLIM_INFINITY || (lim.rlim_max as u64) >= needed)
    {
        let raised = libc::rlimit {
            rlim_cur: if lim.rlim_max == libc::RLIM_INFINITY {
                needed as libc::rlim_t
            } else {
                lim.rlim_max
            },
            rlim_max: lim.rlim_max,
        };
        // SAFETY: setrlimit reads a valid rlimit through a live pointer.
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) } == 0 {
            lim = raised;
        }
    }
    if lim.rlim_cur != libc::RLIM_INFINITY && (lim.rlim_cur as u64) < needed {
        return Err(std::io::Error::other(format!(
            "RLIMIT_MEMLOCK is {} bytes but at least {needed} are needed; raise LimitMEMLOCK= in the unit (within the session's hard limit)",
            lim.rlim_cur
        )));
    }
    // SAFETY: mlockall takes flags only.
    match unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

impl Daemon {
    pub async fn start(opts: DaemonOptions) -> Result<Daemon, DaemonError> {
        // Both of these protect key material and both were asked for; a
        // silent downgrade would leave the operator believing in a property
        // the daemon is not providing.
        disable_dumping().map_err(DaemonError::Hardening)?;
        if opts.config.vault.lock_memory {
            lock_memory().map_err(DaemonError::Hardening)?;
            tracing::info!("memory locked; secrets will not be swapped");
        }
        let mut pinentry = Pinentry::new(&opts.config.prompt.pinentry);
        for (k, v) in &opts.pinentry_env {
            pinentry = pinentry.env(k, v);
        }
        let mut state = ServiceState::new(
            opts.config.vault.dir.clone(),
            opts.config.kdf.into(),
            pinentry,
        );
        state.index_attributes = opts.config.vault.locked_search;
        let swept = crate::vault::store::sweep_stale_temp_files(&opts.config.vault.dir);
        if swept > 0 {
            tracing::info!("removed {swept} stale vault temp file(s) left by an interrupted save");
        }
        state.load_vaults()?;
        let state: Shared = Arc::new(tokio::sync::Mutex::new(state));

        let builder = match &opts.bus {
            BusAddress::Session => Builder::session()?,
            BusAddress::Address(a) => Builder::address(a.as_str())?,
        };
        let connection = builder
            .name(BUS_NAME)?
            // zbus's `RequestNameFlags` defaults to `AllowReplacement | ReplaceExisting |
            // DoNotQueue` (its own `#[bitflags(default = ...)]`, not an empty set), so
            // without disabling both here, a second daemon would silently steal the bus
            // name from the first instead of failing with `NameTaken`.
            .allow_name_replacements(false)
            .replace_existing_names(false)
            .serve_at(SERVICE_PATH, Service::new(state.clone()))?
            .build()
            .await?;
        registry::register_all(&connection, &state).await?;

        let socket = match opts.control_socket.clone() {
            Some(s) => s,
            None => crate::protocol::socket_path().map_err(|_| DaemonError::NoRuntimeDir)?,
        };
        let server = ControlServer::bind(&socket)
            .await
            .map_err(DaemonError::Control)?;

        let mut tasks = vec![
            tokio::spawn(server.run(control_handler(state.clone(), connection.clone()))),
            tokio::spawn(watch_clients(connection.clone(), state.clone())),
        ];
        let idle = opts.config.vault.auto_lock_after;
        if !idle.is_zero() {
            tasks.push(tokio::spawn(idle_lock(
                connection.clone(),
                state.clone(),
                idle,
                opts.idle_check_interval,
            )));
        }
        tracing::info!("serving {BUS_NAME}; control socket at {}", socket.display());
        Ok(Daemon {
            connection,
            state,
            tasks,
        })
    }

    /// Block until SIGTERM or SIGINT, then stop.
    pub async fn run_until_shutdown(self) {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
        tracing::info!("shutting down");
        drop(self);
    }
}

impl Drop for Daemon {
    /// Stop background tasks. The control socket file is removed with its
    /// server; the bus name is released when `connection` drops.
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn control_handler(state: Shared, conn: Connection) -> Handler {
    Arc::new(move |req| {
        let state = state.clone();
        let conn = conn.clone();
        Box::pin(async move { handle_control(state, conn, req).await })
    })
}

async fn handle_control(state: Shared, conn: Connection, req: Request) -> Response {
    match req {
        Request::UnlockWithKey { collection, key } => {
            unlock_with_key(&state, &conn, &collection, &Key::from_zeroizing(key)).await
        }
        Request::ChangeKey {
            collection,
            old_key,
            new_salt,
            new_kdf,
            new_key,
        } => {
            change_key(
                &state,
                &conn,
                &collection,
                &Key::from_zeroizing(old_key),
                &new_salt,
                new_kdf,
                &Key::from_zeroizing(new_key),
            )
            .await
        }
        Request::Lock { collection } => {
            let changed = {
                let mut st = state.lock().await;
                let targets: Vec<String> = match collection {
                    Some(c) => vec![c],
                    None => st.collections.keys().cloned().collect(),
                };
                let mut changed = Vec::new();
                let mut missing = None;
                for id in targets {
                    match st.collections.get_mut(&id) {
                        Some(vault) => {
                            if !vault.is_locked() {
                                vault.lock();
                                changed.push(id);
                            }
                        }
                        // Only reachable for a named collection, in which case
                        // `targets` held exactly that one and nothing was
                        // locked; the loop still continues so the invariant
                        // survives a future multi-collection request.
                        None => missing = Some(id),
                    }
                }
                (changed, missing)
            };
            let (changed, missing) = changed;
            for id in changed {
                registry::notify_collection_changed(&conn, &id).await;
            }
            match missing {
                Some(id) => Response::Error(format!("no collection '{id}'")),
                None => Response::Ok,
            }
        }
        Request::Status => {
            let st = state.lock().await;
            let mut collections: Vec<CollectionStatus> = st
                .collections
                .iter()
                .map(|(id, v)| CollectionStatus {
                    id: id.clone(),
                    label: v.label().to_string(),
                    locked: v.is_locked(),
                    items: v.item_ids().len(),
                    warning: v.index_warning().map(str::to_string),
                })
                .collect();
            collections.extend(st.broken.iter().map(|(id, (_, err))| CollectionStatus {
                id: id.clone(),
                label: id.clone(),
                locked: true,
                items: 0,
                warning: Some(err.clone()),
            }));
            Response::Status {
                collections,
                uptime_secs: st.started.elapsed().as_secs(),
            }
        }
        Request::Reload => {
            // Scanning the vault directory reads whole files from disk. Doing
            // that under the state mutex, on an async worker, lets any peer
            // stall every other request, and 16 connections multiply it. One
            // reload at a time, on the blocking pool.
            static RELOAD: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
            let _reload = RELOAD.acquire().await.expect("semaphore is never closed");
            let (dir, index_attributes, loaded) = {
                let st = state.lock().await;
                (st.vault_dir.clone(), st.index_attributes, st.loaded_ids())
            };
            // The scan opens and parses every vault file, so it runs on the
            // blocking pool with no lock held; only the merge takes the mutex.
            let scanned = tokio::task::spawn_blocking(move || {
                crate::dbus::state::scan_vault_dir(&dir, index_attributes, &loaded)
            })
            .await;
            let new_ids = match scanned {
                Ok(Ok(scan)) => state.lock().await.merge_scan(scan),
                Ok(Err(e)) => return Response::Error(e.to_string()),
                Err(e) => return Response::Error(format!("reload failed: {e}")),
            };
            if let Err(e) = registry::register_all(&conn, &state).await {
                return Response::Error(e.to_string());
            }
            for id in &new_ids {
                if let Ok(emitter) = SignalEmitter::new(&conn, SERVICE_PATH) {
                    let _ = emitter.collection_created(paths::collection(id)).await;
                }
            }
            if !new_ids.is_empty() {
                registry::notify_collections_changed(&conn).await;
            }
            Response::Ok
        }
    }
}

async fn unlock_with_key(
    state: &Shared,
    conn: &Connection,
    collection: &str,
    key: &Key,
) -> Response {
    let result = {
        let mut st = state.lock().await;
        match st.collections.get_mut(collection) {
            // One message for both "no such collection" and "wrong key".
            // Collection ids are not secret from this socket — `Status`
            // enumerates them, and the CLI needs that — so this is not an
            // anti-enumeration measure; it just keeps a failed unlock from
            // reporting which of the two it was.
            Some(vault) => vault
                .unlock_with_key(key)
                .map_err(|_| "cannot unlock that collection".to_string()),
            // A vault that failed to load is a different, non-secret
            // condition the operator needs to see.
            None => match st.broken_error(collection) {
                Some(e) => Err(e.to_string()),
                None => Err("cannot unlock that collection".to_string()),
            },
        }
    };
    match result {
        Ok(()) => {
            state.lock().await.touch();
            registry::notify_collection_changed(conn, collection).await;
            Response::Ok
        }
        Err(e) => Response::Error(e),
    }
}

async fn change_key(
    state: &Shared,
    _conn: &Connection,
    collection: &str,
    old_key: &Key,
    new_salt: &[u8; 16],
    new_kdf: KdfParams,
    new_key: &Key,
) -> Response {
    let mut st = state.lock().await;
    match st.collections.get_mut(collection) {
        Some(vault) => {
            let was_locked = vault.is_locked();
            match vault.change_key(old_key, new_salt, new_kdf, new_key) {
                Ok(()) => {
                    // `change_key` restores the lock state it found, so no
                    // `CollectionChanged` is owed.
                    debug_assert_eq!(was_locked, vault.is_locked());
                    Response::Ok
                }
                Err(e) => Response::Error(e.to_string()),
            }
        }
        None => Response::Error(format!("no collection '{collection}'")),
    }
}

/// Drop sessions and prompts whose owning client left the bus, aborting any
/// prompt task (and its pinentry) still running for that client.
async fn watch_clients(conn: Connection, state: Shared) {
    // Losing this watch means sessions and prompts are never reclaimed, so a
    // failure is retried rather than logged once and abandoned.
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match watch_clients_once(&conn, &state).await {
            Ok(()) => tracing::warn!("bus client watch ended; restarting it"),
            Err(e) => tracing::error!("bus client watch failed: {e}; retrying in {backoff:?}"),
        }
        // A run that lasted is evidence the bus is healthy again; without this
        // reset one transient failure degrades cleanup to a 30 s cadence for
        // the life of the daemon.
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// One run of the watch, returning when the signal stream ends.
async fn watch_clients_once(conn: &Connection, state: &Shared) -> zbus::Result<()> {
    let dbus = zbus::fdo::DBusProxy::new(conn).await?;
    let mut stream = dbus.receive_name_owner_changed().await?;
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else { continue };
        if args.new_owner.is_some() {
            continue;
        }
        let name = args.name.to_string();
        let mut relock: Vec<String> = Vec::new();
        let (sessions, prompts) = {
            let mut st = state.lock().await;
            let sessions: Vec<String> = st
                .sessions
                .iter()
                .filter(|(_, e)| e.owner == name)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &sessions {
                st.sessions.remove(p);
            }
            let prompts: Vec<String> = st
                .prompt_owners
                .iter()
                .filter(|(_, o)| **o == name)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &prompts {
                st.prompt_owners.remove(p);
                let commit = st.prompt_commits.remove(p);
                if let Some(task) = st.prompt_tasks.remove(p) {
                    // A prompt that has passed its commit gate is doing
                    // irreversible work (unlinking a vault file, re-sealing a
                    // collection). Aborting it there would drop a change the
                    // user already confirmed and leave the daemon disagreeing
                    // with the disk, so let it finish; its own `finish` call
                    // completes the prompt exactly once.
                    // An atomic, so this cannot fail and cannot be confused
                    // with contention; a missing gate means the prompt never
                    // reached its commit point, so aborting is safe.
                    let committed = commit
                        .as_ref()
                        .map(|c| c.load(std::sync::atomic::Ordering::Acquire))
                        .unwrap_or(false);
                    if committed {
                        tracing::debug!("not aborting prompt {p}: it has already committed");
                    } else {
                        task.abort();
                        // The task's own re-lock branch runs at the end of
                        // its loop, which an abort never reaches. The commit
                        // gate is reset per collection, so a disconnect
                        // during a later dialog aborts a task that has
                        // already opened earlier collections; without this
                        // they would stay decrypted in memory with no owner.
                        if let Some(ids) = st.prompt_unlocked.remove(p) {
                            for id in ids {
                                if let Some(vault) = st.collections.get_mut(&id) {
                                    vault.lock();
                                }
                                relock.push(id);
                            }
                        }
                    }
                }
            }
            (sessions, prompts)
        };
        // Signals go out with the lock released.
        for id in &relock {
            registry::notify_collection_changed(conn, id).await;
        }
        for p in sessions {
            let _ = conn.object_server().remove::<Session, _>(p.as_str()).await;
        }
        for p in prompts {
            let _ = conn.object_server().remove::<Prompt, _>(p.as_str()).await;
        }
    }
    Ok(())
}

async fn idle_lock(conn: Connection, state: Shared, after: Duration, check_every: Duration) {
    let mut ticker = tokio::time::interval(check_every);
    loop {
        ticker.tick().await;
        let ids: Vec<String> = {
            let mut st = state.lock().await;
            if st.last_activity.elapsed() < after {
                continue;
            }
            let mut ids = Vec::new();
            for (id, vault) in st.collections.iter_mut() {
                if !vault.is_locked() {
                    vault.lock();
                    ids.push(id.clone());
                }
            }
            ids
        };
        for id in ids {
            tracing::info!("auto-locked '{id}' after inactivity");
            registry::notify_collection_changed(&conn, &id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `lock_memory` must refuse rather than lock lazily: `MCL_ONFAULT` would
    /// succeed here and then kill the daemon on the first derivation that
    /// exceeded the limit. Which branch runs depends on the host's limit, so
    /// the test asserts the right one for whichever it is.
    #[test]
    fn lock_memory_refuses_when_the_limit_cannot_cover_a_derivation() {
        // SAFETY: getrlimit writes a plain rlimit struct through a valid pointer.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) },
            0
        );
        let needed =
            u64::from(KdfParams::MAX_M_COST_KIB) * 1024 * crate::kdf::MAX_CONCURRENT as u64
                + 64 * 1024 * 1024;
        let enough = lim.rlim_cur == libc::RLIM_INFINITY || lim.rlim_cur as u64 >= needed;
        match lock_memory() {
            Ok(()) => assert!(enough, "locked memory despite a limit of {}", lim.rlim_cur),
            Err(e) => {
                assert!(!enough, "refused despite a sufficient limit: {e}");
                assert!(e.to_string().contains("RLIMIT_MEMLOCK"), "{e}");
            }
        }
    }

    /// Only a name clash becomes `NameTaken`; every other bus failure keeps
    /// its own text. The distinction is load-bearing: `main` turns
    /// `NameTaken` into exit code 3 and the "already owns" message, and a
    /// mapping that swallowed other errors would report a broken bus as a
    /// second daemon.
    #[test]
    fn only_a_name_clash_maps_to_name_taken() {
        assert!(matches!(
            DaemonError::from(zbus::Error::NameTaken),
            DaemonError::NameTaken
        ));
        let other = DaemonError::from(zbus::Error::InvalidField);
        assert!(other.to_string().starts_with("bus error"), "{other}");
        assert!(matches!(other, DaemonError::ZBus(_)));
    }

    /// Startup sweeps temp files an interrupted save left behind, and it does
    /// so before the bus is touched, so a daemon that cannot reach the bus
    /// has still cleaned up. Only the shape `write_atomic` produces, and only
    /// when it is older than `STALE_TEMP_AGE`.
    #[tokio::test]
    async fn start_sweeps_stale_vault_temp_files_before_touching_the_bus() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("default.vault.0123456789abcdef.tmp");
        let fresh = dir.path().join("default.vault.fedcba9876543210.tmp");
        let innocent = dir.path().join("notes.backup.tmp");
        for f in [&stale, &fresh, &innocent] {
            std::fs::write(f, b"partial save").unwrap();
        }
        age_file(
            &stale,
            crate::vault::store::STALE_TEMP_AGE + Duration::from_secs(60),
        );

        let mut config = Config::default();
        config.vault.dir = dir.path().to_path_buf();
        let mut opts = DaemonOptions::new(config);
        // No bus: `start` gets as far as the connection and fails there,
        // which is after the sweep and proves the ordering.
        opts.bus = BusAddress::Address("unix:path=/nonexistent/secret-manager-tests".into());
        let Err(err) = Daemon::start(opts).await else {
            panic!("a daemon must not come up on a nonexistent bus address")
        };
        assert!(
            matches!(err, DaemonError::ZBus(_)),
            "expected the bus step to be what failed, got {err}"
        );

        assert!(!stale.exists(), "a stale temp file must be swept at start");
        assert!(
            fresh.exists(),
            "a temp file younger than the threshold stays"
        );
        assert!(
            innocent.exists(),
            "a name `write_atomic` never produces must not be deleted"
        );
    }

    /// `[vault] lock_memory = true` is a promise the daemon cannot keep on a
    /// host whose `RLIMIT_MEMLOCK` cannot cover a derivation, and it refuses
    /// to start rather than run with secrets that may be swapped out. The
    /// hardening runs before the vault directory or the bus, so the refusal
    /// does not depend on either. Which branch applies depends on the host's
    /// limit, so the test asserts the right one for whichever it is.
    #[tokio::test]
    async fn start_refuses_lock_memory_it_cannot_honour() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.vault.dir = dir.path().to_path_buf();
        config.vault.lock_memory = true;
        let mut opts = DaemonOptions::new(config);
        opts.bus = BusAddress::Address("unix:path=/nonexistent/secret-manager-tests".into());

        let Err(err) = Daemon::start(opts).await else {
            panic!("a daemon must not come up on a nonexistent bus address")
        };
        match err {
            DaemonError::Hardening(e) => assert!(
                !memlock_is_sufficient(),
                "refused hardening despite a sufficient RLIMIT_MEMLOCK: {e}"
            ),
            // A host that can honour it gets no further than the bus.
            other => assert!(
                memlock_is_sufficient(),
                "expected a hardening refusal on a host limited to less than \
                 a derivation, got {other}"
            ),
        }
    }

    /// Bytes needed by `lock_memory`, and whether this host's limit covers it.
    fn memlock_is_sufficient() -> bool {
        // SAFETY: getrlimit writes a plain rlimit struct through a valid pointer.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) },
            0
        );
        let needed =
            u64::from(KdfParams::MAX_M_COST_KIB) * 1024 * crate::kdf::MAX_CONCURRENT as u64
                + 64 * 1024 * 1024;
        lim.rlim_cur == libc::RLIM_INFINITY || lim.rlim_cur as u64 >= needed
    }

    /// Backdate a file's mtime by `age`, so a sweep sees it as stale without
    /// the test waiting.
    fn age_file(path: &std::path::Path, age: Duration) {
        let when = std::time::SystemTime::now() - age;
        let secs = when
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as libc::time_t;
        let tv = libc::timeval {
            tv_sec: secs,
            tv_usec: 0,
        };
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a NUL-terminated path and `times` is a live array of
        // two `timeval`s, which is exactly what `utimes` reads.
        let rc = unsafe { libc::utimes(c.as_ptr(), [tv, tv].as_ptr()) };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    }
}
