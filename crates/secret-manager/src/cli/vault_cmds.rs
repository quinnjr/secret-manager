//! init / lock / unlock / status / change-password

use super::{CliError, load_config, read_new_password, read_password};
use crate::dbus::state::{load_aliases, save_aliases_to};
use crate::vault::{Vault, collection_id_from_label};
use control_protocol::{ProtocolError, Request, Response, Zeroizing, call, socket_path};

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
    match call(&socket_path(), &Request::Reload) {
        Ok(Response::Ok) => {}
        Ok(Response::Error(e)) => eprintln!("warning: running daemon did not reload: {e}"),
        Ok(_) => {}
        Err(_) => {} // no daemon running; it will pick the file up on start
    }
    println!("Created collection '{collection}' at {}", path.display());
    Ok(())
}

/// One request over the control socket; protocol-level errors map to exit codes.
pub fn control(req: Request) -> Result<Response, CliError> {
    match call(&socket_path(), &req) {
        Ok(Response::Error(e)) => Err(CliError::Failed(e)),
        Ok(r) => Ok(r),
        Err(ProtocolError::Connect(e)) => Err(CliError::Unreachable(format!(
            "daemon not running ({e}); start it with `systemctl --user start secret-manager`"
        ))),
        Err(e) => Err(CliError::Failed(e.to_string())),
    }
}

pub fn lock(collection: Option<String>) -> Result<(), CliError> {
    control(Request::Lock { collection })?;
    println!("Locked.");
    Ok(())
}

pub fn unlock(collection: String) -> Result<(), CliError> {
    let password = read_password(&format!("Password for '{collection}'"))?;
    control(Request::Unlock {
        collection: collection.clone(),
        password: Zeroizing::new(password.to_string()),
    })?;
    println!("Unlocked '{collection}'.");
    Ok(())
}

pub fn status() -> Result<(), CliError> {
    match control(Request::Status)? {
        Response::Status {
            collections,
            uptime_secs,
        } => {
            println!("daemon up {}s", uptime_secs);
            println!("{:<16} {:<24} {:<9} ITEMS", "ID", "LABEL", "STATE");
            for c in collections {
                println!(
                    "{:<16} {:<24} {:<9} {}",
                    c.id,
                    c.label,
                    if c.locked { "locked" } else { "unlocked" },
                    c.items
                );
            }
            Ok(())
        }
        other => Err(CliError::Failed(format!("unexpected reply {other:?}"))),
    }
}

pub fn change_password(collection: String) -> Result<(), CliError> {
    let old = read_password("Current password")?;
    let new = read_new_password("New password")?;
    control(Request::ChangePassword {
        collection: collection.clone(),
        old: Zeroizing::new(old.to_string()),
        new: Zeroizing::new(new.to_string()),
    })?;
    println!("Password changed for '{collection}'.");
    Ok(())
}
