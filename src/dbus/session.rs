//! `org.freedesktop.Secret.Session` and the `(oayays)` secret struct.

use super::errors::{Error, Result};
use super::require_sender;
use super::state::Shared;
use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::message::Header;
use zbus::zvariant::{OwnedObjectPath, Type};

#[derive(Clone, Serialize, Deserialize, Type)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

/// `value` is the plaintext secret on a `plain` session, so it never prints.
impl std::fmt::Debug for SecretStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStruct")
            .field("session", &self.session)
            .field(
                "parameters",
                &format_args!("[{} bytes]", self.parameters.len()),
            )
            .field("value", &format_args!("[{} bytes]", self.value.len()))
            .field("content_type", &self.content_type)
            .finish()
    }
}

pub struct Session {
    state: Shared,
    path: OwnedObjectPath,
}

impl Session {
    pub fn new(state: Shared, path: OwnedObjectPath) -> Self {
        Self { state, path }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> Result<()> {
        {
            let who = require_sender(&header)?;
            let mut st = self.state.lock().await;
            match st.sessions.get(self.path.as_str()) {
                // Unknown and foreign are the same answer, so session paths
                // cannot be probed for existence.
                Some(entry) if entry.owner != who => return Err(Error::NoSession),
                Some(_) => {
                    st.sessions.remove(self.path.as_str());
                }
                None => return Err(Error::NoSession),
            }
        }
        let conn = conn.clone();
        let path = self.path.clone();
        // Removing the object from inside its own method call deadlocks; defer it.
        tokio::spawn(async move {
            let _ = conn
                .object_server()
                .remove::<Session, _>(path.as_str())
                .await;
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_struct_debug_hides_the_value() {
        let s = SecretStruct {
            session: OwnedObjectPath::try_from("/s").unwrap(),
            parameters: vec![],
            value: b"hunter2".to_vec(),
            content_type: "text/plain".into(),
        };
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("104"), "byte-wise leak: {rendered}");
        assert!(rendered.contains("text/plain"));
    }
}
