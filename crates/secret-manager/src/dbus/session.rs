//! `org.freedesktop.Secret.Session` and the `(oayays)` secret struct.

use super::errors::Result;
use super::state::Shared;
use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::zvariant::{OwnedObjectPath, Type};

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
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
    async fn close(&self, #[zbus(connection)] conn: &zbus::Connection) -> Result<()> {
        self.state.lock().await.sessions.remove(self.path.as_str());
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
