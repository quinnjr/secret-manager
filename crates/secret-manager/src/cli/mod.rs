//! Command line interface. Every subcommand except `daemon` is a client.

pub mod vault_cmds;

use crate::config::Config;
use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read};
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "secret-manager",
    bin_name = "sm",
    version,
    about = "Secret Service daemon and CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new collection vault
    Init {
        /// Label of the collection; the file name is derived from it
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Run the D-Bus secret service
    Daemon {
        /// Kept for readability in unit files; the daemon always runs in the foreground
        #[arg(long)]
        foreground: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Exit 1: nothing matched, or the user dismissed a prompt.
    #[error("{0}")]
    NotFound(String),
    /// Exit 2: bad arguments or input.
    #[error("{0}")]
    Usage(String),
    /// Exit 3: daemon or bus unreachable, or bus name taken.
    #[error("{0}")]
    Unreachable(String),
    /// Exit 1: any other failure.
    #[error("{0}")]
    Failed(String),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::NotFound(_) | CliError::Failed(_) => 1,
            CliError::Usage(_) => 2,
            CliError::Unreachable(_) => 3,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Failed(e.to_string())
    }
}

impl From<crate::vault::VaultError> for CliError {
    fn from(e: crate::vault::VaultError) -> Self {
        CliError::Failed(e.to_string())
    }
}

pub fn load_config() -> Result<Config, CliError> {
    Config::load().map_err(|e| CliError::Failed(e.to_string()))
}

/// Read a password: hidden prompt on a TTY, one line from stdin otherwise.
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{prompt}: "))
            .map(Zeroizing::new)
            .map_err(CliError::from)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(Zeroizing::new(
            line.trim_end_matches(['\n', '\r']).to_string(),
        ))
    }
}

/// Read a new password, confirmed when interactive. Rejects empty passwords.
pub fn read_new_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    let first = read_password(prompt)?;
    if first.is_empty() {
        return Err(CliError::Usage("empty password not allowed".into()));
    }
    if std::io::stdin().is_terminal() {
        let second = read_password("Repeat")?;
        if *first != *second {
            return Err(CliError::Usage("passwords do not match".into()));
        }
    }
    Ok(first)
}

/// Read all of stdin as a secret, dropping one trailing newline.
pub fn read_secret_from_stdin() -> Result<Zeroizing<Vec<u8>>, CliError> {
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(read_password("Secret")?.as_bytes().to_vec()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut buf)?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

pub async fn run(cli: Cli) -> ExitCode {
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secret-manager: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Init { collection } => vault_cmds::init(&collection),
        Command::Daemon { .. } => daemon().await,
    }
}

async fn daemon() -> Result<(), CliError> {
    use crate::daemon::{Daemon, DaemonError, DaemonOptions};
    let config = load_config()?;
    let daemon = Daemon::start(DaemonOptions::new(config))
        .await
        .map_err(|e| match e {
            DaemonError::NameTaken => CliError::Unreachable(e.to_string()),
            other => CliError::Failed(other.to_string()),
        })?;
    daemon.run_until_shutdown().await;
    Ok(())
}
