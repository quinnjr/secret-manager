//! init / lock / unlock / status / change-password

use super::{CliError, load_config, read_new_password};
use crate::dbus::state::{load_aliases, save_aliases_to};
use crate::vault::{Vault, collection_id_from_label};
use control_protocol::{Request, Response, call, socket_path};

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
