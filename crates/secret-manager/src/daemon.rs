//! Daemon assembly: vaults, bus connection, control socket, housekeeping tasks.

use crate::config::Config;
use crate::dbus::paths::{BUS_NAME, SERVICE_PATH};
use crate::dbus::service::Service;
use crate::dbus::state::{ServiceState, Shared};
use crate::prompt::Pinentry;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use zbus::Connection;
use zbus::connection::Builder;

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
            .serve_at(SERVICE_PATH, Service::new(state.clone()))?
            .build()
            .await?;

        crate::dbus::registry::register_all(&connection, &state).await?;
        // Task 12: control server, client watcher, idle lock.
        let tasks = Vec::new();
        tracing::info!("serving {BUS_NAME}");
        Ok(Daemon {
            connection,
            state,
            tasks,
        })
    }

    /// Stop background tasks. The bus name is released when the connection drops.
    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
