//! init / lock / unlock / status / change-password

use super::secrets::escape_control;
use super::{CliError, load_config, read_new_password, read_password};
use crate::config::Config;
use crate::dbus::state::{load_aliases, save_aliases_to};
use crate::protocol::{ProtocolError, Request, Response, call, socket_path};
use crate::vault::crypto::{self, KdfParams, SALT_LEN};
use crate::vault::format;
use crate::vault::{Vault, collection_id_from_label};
use std::io::Read;
use std::path::Path;

/// `--collection` on a command that resolves an *existing* collection is
/// pasted straight into `<dir>/<id>.vault`, so only an already-normalized id
/// may be accepted. `../../../tmp/planted` would otherwise have the CLI read
/// an arbitrary file's header and hash the user's master password with the
/// salt and Argon2 parameters found there.
fn validated_collection_id(value: &str) -> Result<String, CliError> {
    if collection_id_from_label(value) == value {
        Ok(value.to_string())
    } else {
        Err(CliError::Usage(format!(
            "invalid collection id '{value}'; ids use [a-z0-9_] only \
             (`sm init` prints the id it derives from a label)"
        )))
    }
}

pub fn init(collection: &str) -> Result<(), CliError> {
    let config = load_config()?;
    let id = collection_id_from_label(collection);
    let path = config.vault.dir.join(format!("{id}.vault"));
    if path.exists() {
        return Err(CliError::Failed(format!(
            "collection '{id}' already exists at {}",
            path.display()
        )));
    }
    let password = read_new_password(&format!("Choose a password for collection '{collection}'"))?;
    Vault::create(&path, collection, password.as_bytes(), config.kdf.into())?;

    let mut aliases = load_aliases(&config.vault.dir)?;
    if !aliases.contains_key("default") {
        aliases.insert("default".to_string(), id.clone());
        save_aliases_to(&config.vault.dir, &aliases)?;
    }
    // XDG_RUNTIME_DIR unset means there's nowhere a daemon could have bound
    // its socket; treat it the same as "no daemon running".
    if let Ok(path) = socket_path() {
        match call(&path, &Request::Reload) {
            Ok(Response::Error(e)) => {
                eprintln!("warning: running daemon did not reload: {e}");
            }
            // No daemon is listening; it will pick the new file up on start.
            Err(ProtocolError::Connect(_)) | Ok(_) => {}
            // Anything else means a daemon is there but the call failed, so
            // the new collection may stay invisible until it restarts.
            Err(e) => eprintln!("warning: could not tell the running daemon to reload: {e}"),
        }
    }
    println!("Created collection '{collection}' at {}", path.display());
    // The label is normalized into the id; every later command takes the id,
    // so say what it is rather than let the user retype the label.
    println!("Its id is '{id}' — use `sm unlock --collection {id}`.");
    Ok(())
}

/// Salt and Argon2 parameters of a collection, read from the vault file's
/// header. Deriving from the file rather than asking the daemon means no
/// process that merely answers the control socket can choose the salt or the
/// cost of the hash we compute from the user's password.
fn header_params(
    config: &Config,
    collection: &str,
) -> Result<([u8; SALT_LEN], KdfParams), CliError> {
    let path = config.vault.dir.join(format!("{collection}.vault"));
    let header = read_header(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CliError::NotFound(format!(
            "no collection '{collection}' at {}",
            path.display()
        )),
        _ => CliError::Failed(format!("{}: {e}", path.display())),
    })?;
    Ok((header.salt, header.kdf))
}

/// Reads just the header: the length prefix says how much of the file the
/// header occupies, so the ciphertext is never loaded.
fn read_header(path: &Path) -> std::io::Result<format::Header> {
    let mut file = std::fs::File::open(path)?;
    let mut prefix = [0u8; format::PREFIX_LEN];
    file.read_exact(&mut prefix)?;
    let total = format::header_prefix_len(&prefix)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut bytes = vec![0u8; total];
    bytes[..format::PREFIX_LEN].copy_from_slice(&prefix);
    file.read_exact(&mut bytes[format::PREFIX_LEN..])?;
    format::decode_header(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// One request over the control socket; protocol-level errors map to exit codes.
pub fn control(req: Request) -> Result<Response, CliError> {
    let path = socket_path().map_err(|e| match e {
        ProtocolError::NoRuntimeDir => CliError::Unreachable(
            "XDG_RUNTIME_DIR is not set; the daemon's control socket cannot be located".into(),
        ),
        other => CliError::Failed(other.to_string()),
    })?;
    match call(&path, &req) {
        // The daemon's message is peer-supplied text on its way to a
        // terminal: whatever answers the socket chose it, and a `\r` or an
        // ANSI escape in it would rewrite lines the user has already read.
        // Same table as `sm list` uses for a label.
        Ok(Response::Error(e)) => Err(CliError::Failed(escape_control(&e))),
        Ok(r) => Ok(r),
        Err(ProtocolError::Connect(e)) => Err(CliError::Unreachable(format!(
            "daemon not running ({e}); start it with `systemctl --user start secret-manager`"
        ))),
        Err(e) => Err(CliError::Failed(e.to_string())),
    }
}

pub fn lock(collection: Option<String>) -> Result<(), CliError> {
    let collection = collection
        .map(|c| validated_collection_id(&c))
        .transpose()?;
    control(Request::Lock { collection })?;
    println!("Locked.");
    Ok(())
}

pub fn unlock(collection: String) -> Result<(), CliError> {
    let collection = validated_collection_id(&collection)?;
    let config = load_config()?;
    let (salt, kdf) = header_params(&config, &collection)?;
    let password = read_password(&format!("Password for '{collection}'"))?;
    let key = crypto::derive_key(password.as_bytes(), &salt, kdf)
        .map_err(|e| CliError::Failed(e.to_string()))?;
    control(Request::UnlockWithKey {
        collection: collection.clone(),
        // `Zeroizing::new(*key.as_bytes())` would build the array on the
        // stack first and leave that copy unwiped; `to_zeroizing` clones the
        // already-wrapped buffer.
        key: key.to_zeroizing(),
    })?;
    println!("Unlocked '{collection}'.");
    Ok(())
}

pub fn status() -> Result<(), CliError> {
    match control(Request::Status)? {
        Response::Status {
            collections,
            uptime_secs,
            aliases_error,
        } => {
            println!("daemon up {}s", uptime_secs);
            println!("{:<16} {:<24} {:<9} ITEMS", "ID", "LABEL", "STATE");
            // Ids, labels and warnings all come off the socket, so they are
            // escaped before they are printed for the same reason.
            for c in &collections {
                println!(
                    "{:<16} {:<24} {:<9} {}",
                    escape_control(&c.id),
                    escape_control(&c.label),
                    if c.locked { "locked" } else { "unlocked" },
                    c.items
                );
            }
            for c in &collections {
                if let Some(w) = &c.warning {
                    println_warning(&c.id, w);
                }
            }
            // The daemon starts without a usable alias table rather than
            // refusing to run, so this is the only place the operator is told
            // that alias lookups are refusing and the file is waiting to be
            // repaired.
            if let Some(e) = &aliases_error {
                eprintln!(
                    "secret-manager: the alias table is unreadable ({}); \
                     alias lookups are refused and nothing will overwrite it. \
                     Repair or delete aliases.toml, then run `sm reload`.",
                    escape_control(e)
                );
            }
            Ok(())
        }
        other => Err(CliError::Failed(format!("unexpected reply {other:?}"))),
    }
}

fn println_warning(id: &str, warning: &str) {
    eprintln!(
        "warning: {}: {}",
        escape_control(id),
        escape_control(warning)
    );
}

pub fn change_password(collection: String) -> Result<(), CliError> {
    let collection = validated_collection_id(&collection)?;
    let config = load_config()?;
    let (salt, kdf) = header_params(&config, &collection)?;
    let old = read_password("Current password")?;
    let new = read_new_password("New password")?;
    let new_kdf: KdfParams = config.kdf.into();
    // The panicking form would abort the process on an unavailable system
    // RNG, mid-way through a password change; report it instead.
    let new_salt =
        crypto::try_random_bytes::<SALT_LEN>().map_err(|e| CliError::Failed(e.to_string()))?;
    let old_key = crypto::derive_key(old.as_bytes(), &salt, kdf)
        .map_err(|e| CliError::Failed(e.to_string()))?;
    let new_key = crypto::derive_key(new.as_bytes(), &new_salt, new_kdf)
        .map_err(|e| CliError::Failed(e.to_string()))?;
    control(Request::ChangeKey {
        collection: collection.clone(),
        old_key: old_key.to_zeroizing(),
        new_salt,
        new_kdf,
        new_key: new_key.to_zeroizing(),
    })?;
    println!("Password changed for '{collection}'.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_ids_are_validated() {
        for good in ["default", "my_work", "w0rk", "a"] {
            assert_eq!(validated_collection_id(good).unwrap(), good);
        }
        // Path traversal is the reason this exists: `<dir>/<id>.vault`.
        for bad in [
            "../x",
            "..",
            "/etc/passwd",
            "/tmp/planted",
            "My Work",
            "UPPER",
            "trailing_",
            "",
        ] {
            let err = validated_collection_id(bad).expect_err("{bad} must be rejected");
            assert!(matches!(err, CliError::Usage(_)), "{bad}: {err:?}");
            assert!(err.to_string().contains("[a-z0-9_]"));
        }
    }
}
