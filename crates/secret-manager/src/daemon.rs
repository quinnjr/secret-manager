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
use control_protocol::{CollectionStatus, Request, Response};
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
    /// Override for `control_protocol::socket_path()` (tests).
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

impl Daemon {
    pub async fn start(opts: DaemonOptions) -> Result<Daemon, DaemonError> {
        let mut pinentry = Pinentry::new(&opts.config.prompt.pinentry);
        for (k, v) in &opts.pinentry_env {
            pinentry = pinentry.env(k, v);
        }
        let mut state = ServiceState::new(
            opts.config.vault.dir.clone(),
            opts.config.kdf.into(),
            pinentry,
        );
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

        let socket = opts
            .control_socket
            .clone()
            .unwrap_or_else(control_protocol::socket_path);
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
        self.shutdown();
    }

    /// Stop background tasks. The control socket file is removed with its
    /// server; the bus name is released when `connection` drops.
    ///
    /// Dropping a `Daemon` has the same effect (see `impl Drop for Daemon`
    /// below): callers that own a `Daemon` alongside other `Drop` fields
    /// (as the integration test fixture does) cannot destructure it to call
    /// an explicit `self`-consuming method, so the cleanup itself lives in
    /// `Drop` and `shutdown` is a readable, explicit alias for it.
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for Daemon {
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
        Request::Unlock {
            collection,
            password,
        } => {
            let result = {
                let mut st = state.lock().await;
                match st.collections.get_mut(&collection) {
                    Some(vault) => vault.unlock(password.as_bytes()).map_err(|e| e.to_string()),
                    None => Err(format!("no collection '{collection}'")),
                }
            };
            match result {
                Ok(()) => {
                    state.lock().await.touch();
                    registry::notify_collection_changed(&conn, &collection).await;
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::Lock { collection } => {
            let changed = {
                let mut st = state.lock().await;
                let targets: Vec<String> = match collection {
                    Some(c) => vec![c],
                    None => st.collections.keys().cloned().collect(),
                };
                let mut changed = Vec::new();
                for id in targets {
                    match st.collections.get_mut(&id) {
                        Some(vault) => {
                            if !vault.is_locked() {
                                vault.lock();
                                changed.push(id);
                            }
                        }
                        None => return Response::Error(format!("no collection '{id}'")),
                    }
                }
                changed
            };
            for id in changed {
                registry::notify_collection_changed(&conn, &id).await;
            }
            Response::Ok
        }
        Request::ChangePassword {
            collection,
            old,
            new,
        } => {
            let mut st = state.lock().await;
            let kdf = st.kdf;
            match st.collections.get_mut(&collection) {
                Some(vault) => match vault.change_password(old.as_bytes(), new.as_bytes(), kdf) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e.to_string()),
                },
                None => Response::Error(format!("no collection '{collection}'")),
            }
        }
        Request::Status => {
            let st = state.lock().await;
            Response::Status {
                collections: st
                    .collections
                    .iter()
                    .map(|(id, v)| CollectionStatus {
                        id: id.clone(),
                        label: v.label().to_string(),
                        locked: v.is_locked(),
                        items: v.item_ids().len(),
                    })
                    .collect(),
                uptime_secs: st.started.elapsed().as_secs(),
            }
        }
        Request::Reload => {
            let new_ids = {
                let mut st = state.lock().await;
                match st.load_vaults() {
                    Ok(ids) => ids,
                    Err(e) => return Response::Error(e.to_string()),
                }
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

/// Drop sessions and prompts whose owning client left the bus.
async fn watch_clients(conn: Connection, state: Shared) {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
        return;
    };
    let Ok(mut stream) = dbus.receive_name_owner_changed().await else {
        return;
    };
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else { continue };
        if args.new_owner.is_some() {
            continue;
        }
        let name = args.name.to_string();
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
            }
            (sessions, prompts)
        };
        for p in sessions {
            let _ = conn.object_server().remove::<Session, _>(p.as_str()).await;
        }
        for p in prompts {
            let _ = conn.object_server().remove::<Prompt, _>(p.as_str()).await;
        }
    }
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
