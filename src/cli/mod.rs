//! Command line interface. Every subcommand except `daemon` is a client.

pub mod client;
pub mod secrets;
pub mod ssh;
pub mod vault_cmds;

use crate::config::Config;
use clap::{Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::io::{IsTerminal, Read};
use std::path::Path;
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
        /// Label of the collection; the id (and file name) is derived from it
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Run the D-Bus secret service
    Daemon {
        /// Kept for readability in unit files; the daemon always runs in the foreground
        #[arg(long)]
        foreground: bool,
    },
    /// Print a secret to stdout (no trailing newline)
    Get {
        /// Attribute filters; all must match
        #[arg(required = true, value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
        /// Only consider items with this label
        #[arg(long)]
        label: Option<String>,
    },
    /// Store a secret read from stdin
    Set {
        #[arg(required = true, value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
        #[arg(long)]
        label: String,
    },
    /// Delete every item matching the attributes
    Delete {
        #[arg(required = true, value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
    },
    /// List items (labels and attributes, never secrets)
    List {
        #[arg(value_name = "ATTR=VALUE")]
        attrs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Lock one collection, or all of them
    Lock {
        #[arg(long)]
        collection: Option<String>,
    },
    /// Unlock a collection with its password
    Unlock {
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Show daemon and collection state
    Status,
    /// Tell a running daemon to rescan the vault directory
    Reload,
    /// Change a collection's master password
    ChangePassword {
        #[arg(long, default_value = "default")]
        collection: String,
    },
    /// Print shell completions
    Completions { shell: clap_complete::Shell },
    /// SSH key passphrases and the askpass helper
    Ssh {
        #[command(subcommand)]
        command: ssh::SshCommand,
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
        let mut line = Zeroizing::new(String::new());
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

/// Largest secret accepted on stdin, matching the control protocol's frame
/// cap. Without a cap, `sm set < /dev/zero` grows until the OOM killer fires,
/// and a killed process's pages are never zeroized.
pub const MAX_SECRET: usize = crate::protocol::MAX_FRAME;

/// Read all of stdin as a secret, dropping one trailing newline.
pub fn read_secret_from_stdin() -> Result<Zeroizing<Vec<u8>>, CliError> {
    if std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(read_password("Secret")?.as_bytes().to_vec()));
    }
    // Allocate the whole buffer up front. A `Vec::new()` that grows into this
    // doubles about twenty times on the way, and every intermediate allocation
    // is freed *unwiped*, leaving copies of the secret's prefix in the heap
    // that no `Zeroizing` drop ever reaches.
    //
    // Read two bytes past the limit: one to notice an oversized input without
    // ever holding more than that, and one so a secret of exactly the limit
    // written with a trailing newline (`printf '%s\n'`) still fits.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_SECRET + 2));
    std::io::stdin()
        .take(MAX_SECRET as u64 + 2)
        .read_to_end(&mut buf)?;
    // The newline is not part of the secret, so it is dropped *before* the
    // size check: otherwise a 1 MiB secret is rejected for its delimiter.
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.len() > MAX_SECRET {
        // Interpolated, never spelled out: `MAX_SECRET` is derived from
        // `MAX_FRAME`, so a literal here would start lying the moment the
        // frame cap moved.
        return Err(CliError::Usage(format!(
            "secret exceeds {MAX_SECRET} bytes"
        )));
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
        Command::Get { attrs, label } => secrets::get(attrs, label).await,
        Command::Set { attrs, label } => secrets::set(attrs, label).await,
        Command::Delete { attrs } => secrets::delete(attrs).await,
        Command::List { attrs, json } => secrets::list(attrs, json).await,
        Command::Lock { collection } => vault_cmds::lock(collection),
        Command::Unlock { collection } => vault_cmds::unlock(collection),
        Command::Status => vault_cmds::status(),
        Command::Reload => vault_cmds::reload(),
        Command::ChangePassword { collection } => vault_cmds::change_password(collection),
        Command::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "sm", &mut std::io::stdout());
            Ok(())
        }
        Command::Ssh { command } => match command {
            ssh::SshCommand::Add {
                path,
                no_passphrase,
            } => ssh::add(path, no_passphrase).await,
            ssh::SshCommand::List => ssh::list().await,
            ssh::SshCommand::Remove { path } => ssh::remove(path).await,
            ssh::SshCommand::Askpass { prompt } => ssh::askpass(prompt).await,
        },
    }
}

/// Invoked as `sm-askpass <prompt>` (a symlink), behave as `secret-manager ssh askpass <prompt>`.
pub fn argv_with_dispatch(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let is_askpass = args
        .first()
        .is_some_and(|a| Path::new(a).file_name() == Some(OsStr::new("sm-askpass")));
    if !is_askpass {
        return args;
    }
    let rest = args.split_off(1);
    let mut out = vec![
        OsString::from("secret-manager"),
        OsString::from("ssh"),
        OsString::from("askpass"),
    ];
    out.extend(rest);
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn askpass_symlink_dispatches_to_ssh_askpass() {
        let args = argv_with_dispatch(
            ["/usr/bin/sm-askpass", "Enter passphrase for key '/k': "].map(OsString::from),
        );
        assert_eq!(
            args,
            [
                "secret-manager",
                "ssh",
                "askpass",
                "Enter passphrase for key '/k': "
            ]
            .map(OsString::from)
        );
        let args = argv_with_dispatch(["/usr/bin/sm", "status"].map(OsString::from));
        assert_eq!(args, ["/usr/bin/sm", "status"].map(OsString::from));
    }
}
