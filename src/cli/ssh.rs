//! ssh add / list / remove / askpass.
//!
//! Keys are ordinary items: `xdg:schema=org.secret-manager.ssh`, `path=<canonical>`,
//! `has_passphrase=true|false`. Keys without a passphrase hold an empty secret so
//! `ssh list` can inventory them.

use super::client::Client;
use super::secrets::find;
use super::{CliError, load_config, read_password};
use crate::prompt::{PinOutcome, PinRequest, Pinentry};
use clap::Subcommand;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const SSH_SCHEMA: &str = "org.secret-manager.ssh";

#[derive(Subcommand, Debug)]
pub enum SshCommand {
    /// Register a key; prompts for its passphrase unless --no-passphrase
    Add {
        path: PathBuf,
        #[arg(long)]
        no_passphrase: bool,
    },
    /// List registered keys
    List,
    /// Forget a key
    Remove { path: PathBuf },
    /// SSH_ASKPASS entry point: answers ssh's passphrase prompt from the vault
    Askpass {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        prompt: Vec<String>,
    },
}

fn canonical(path: &Path) -> Result<PathBuf, CliError> {
    std::fs::canonicalize(path).map_err(|e| CliError::Usage(format!("{}: {e}", path.display())))
}

/// Fallback for a path whose file no longer exists: canonicalize the parent
/// directory (resolving any symlinks in it) and re-attach the file name, so
/// the result matches what `add` recorded via `canonical` while the file was
/// still there. Falls back further to `std::path::absolute` if even the
/// parent directory cannot be resolved.
fn canonicalize_missing(path: &Path) -> Result<PathBuf, CliError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Usage(format!("{}: no file name", path.display())))?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    match parent {
        Some(parent) => match std::fs::canonicalize(parent) {
            Ok(parent) => Ok(parent.join(file_name)),
            Err(_) => std::path::absolute(path).map_err(CliError::from),
        },
        None => std::path::absolute(path).map_err(CliError::from),
    }
}

fn key_query(path: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("xdg:schema".to_string(), SSH_SCHEMA.to_string()),
        ("path".to_string(), path.to_string_lossy().into_owned()),
    ])
}

fn key_attrs(path: &Path, has_passphrase: bool) -> BTreeMap<String, String> {
    let mut attrs = key_query(path);
    attrs.insert("has_passphrase".to_string(), has_passphrase.to_string());
    attrs
}

pub async fn add(path: PathBuf, no_passphrase: bool) -> Result<(), CliError> {
    let path = canonical(&path)?;
    let secret: Zeroizing<Vec<u8>> = if no_passphrase {
        Zeroizing::new(Vec::new())
    } else {
        Zeroizing::new(
            read_password(&format!("Passphrase for {}", path.display()))?
                .as_bytes()
                .to_vec(),
        )
    };
    let client = Client::connect().await?;
    for item in find(&client, &key_query(&path)).await? {
        client.delete_item(&item).await?;
    }
    client
        .store(
            &key_attrs(&path, !no_passphrase),
            &format!("SSH key {}", path.display()),
            &secret,
        )
        .await?;
    println!(
        "Registered {}{}",
        path.display(),
        if no_passphrase {
            " (no passphrase)"
        } else {
            ""
        }
    );
    Ok(())
}

pub async fn list() -> Result<(), CliError> {
    let client = Client::connect().await?;
    let query = BTreeMap::from([("xdg:schema".to_string(), SSH_SCHEMA.to_string())]);
    let mut out = std::io::stdout().lock();
    for item in find(&client, &query).await? {
        let info = client.item_info(&item).await?;
        let path = info.attributes.get("path").cloned().unwrap_or_default();
        let stored = info
            .attributes
            .get("has_passphrase")
            .is_some_and(|v| v == "true");
        writeln!(
            out,
            "{path}\tpassphrase: {}",
            if stored { "stored" } else { "none" }
        )?;
    }
    Ok(())
}

pub async fn remove(path: PathBuf) -> Result<(), CliError> {
    // The key file may already be gone (that's often why it's being removed),
    // so canonicalize falls back to resolving the parent directory (which
    // still exists, symlinks and all) and re-attaching the file name, instead
    // of `std::path::absolute`, which would leave a symlinked parent
    // unresolved and so fail to match the canonical path recorded by `add`.
    let path = canonical(&path).or_else(|_| canonicalize_missing(&path))?;
    let client = Client::connect().await?;
    let items = find(&client, &key_query(&path)).await?;
    if items.is_empty() {
        return Err(CliError::NotFound(format!(
            "{} is not registered",
            path.display()
        )));
    }
    for item in &items {
        client.delete_item(item).await?;
    }
    println!("Removed {}", path.display());
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum AskpassKind {
    Passphrase(PathBuf),
    Confirm,
    Other,
}

/// `ssh` asks `Enter passphrase for key '/p': `; `ssh-keygen` asks `Enter passphrase for "/p": `.
/// `SSH_ASKPASS_PROMPT=confirm` marks yes/no questions on OpenSSH >= 8.4.
pub fn classify_prompt(prompt: &str, askpass_prompt_env: Option<&str>) -> AskpassKind {
    if askpass_prompt_env == Some("confirm") {
        return AskpassKind::Confirm;
    }
    let re =
        regex::Regex::new(r#"(?i)passphrase for(?: key)? ["']([^"']+)["']"#).expect("static regex");
    if let Some(c) = re.captures(prompt) {
        return AskpassKind::Passphrase(PathBuf::from(&c[1]));
    }
    if prompt.contains("(yes/no") {
        return AskpassKind::Confirm;
    }
    AskpassKind::Other
}

pub async fn askpass(words: Vec<String>) -> Result<(), CliError> {
    let prompt = words.join(" ");
    let env = std::env::var("SSH_ASKPASS_PROMPT").ok();
    let kind = classify_prompt(&prompt, env.as_deref());
    if let AskpassKind::Passphrase(path) = &kind
        && let Some(pass) = lookup_passphrase(path).await
    {
        println!("{}", pass.as_str());
        return Ok(());
    }
    fallback(&prompt, kind == AskpassKind::Confirm).await
}

/// Vault lookup. Any failure (no daemon, dismissed prompt, unknown key, empty
/// secret) yields `None` so the caller falls back to an interactive prompt.
async fn lookup_passphrase(path: &Path) -> Option<Zeroizing<String>> {
    let path = canonical(path).unwrap_or_else(|_| path.to_path_buf());
    let client = Client::connect().await.ok()?;
    let items = find(&client, &key_query(&path)).await.ok()?;
    let item = items.first()?;
    let secret = client.get_secret(item).await.ok()?;
    if secret.is_empty() {
        return None;
    }
    std::str::from_utf8(&secret)
        .ok()
        .map(|s| Zeroizing::new(s.to_string()))
}

async fn fallback(prompt: &str, confirm: bool) -> Result<(), CliError> {
    let config = load_config()?;
    let pinentry = Pinentry::new(&config.prompt.pinentry);
    let req = PinRequest {
        title: "ssh".into(),
        description: prompt.to_string(),
        prompt: if confirm {
            String::new()
        } else {
            "Passphrase:".into()
        },
        error: None,
        repeat: false,
    };
    if confirm {
        let yes = pinentry
            .confirm(&req)
            .await
            .map_err(|e| CliError::Failed(e.to_string()))?;
        println!("{}", if yes { "yes" } else { "no" });
        return Ok(());
    }
    match pinentry
        .ask(&req)
        .await
        .map_err(|e| CliError::Failed(e.to_string()))?
    {
        PinOutcome::Pin(pin) => {
            println!("{}", pin.as_str());
            Ok(())
        }
        PinOutcome::Cancelled => Err(CliError::NotFound("cancelled".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_prompts() {
        assert_eq!(
            classify_prompt("Enter passphrase for key '/home/j/.ssh/id_ed25519': ", None),
            AskpassKind::Passphrase(PathBuf::from("/home/j/.ssh/id_ed25519"))
        );
        assert_eq!(
            classify_prompt("Enter passphrase for \"k\": ", None),
            AskpassKind::Passphrase(PathBuf::from("k"))
        );
        assert_eq!(
            classify_prompt(
                "Are you sure you want to continue connecting (yes/no/[fingerprint])?",
                None
            ),
            AskpassKind::Confirm
        );
        assert_eq!(
            classify_prompt("anything", Some("confirm")),
            AskpassKind::Confirm
        );
        assert_eq!(
            classify_prompt("Enter PIN for authenticator:", None),
            AskpassKind::Other
        );
    }
}
