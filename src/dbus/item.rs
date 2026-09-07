//! `org.freedesktop.Secret.Item`.

use super::collection::{self, CollectionSignals};
use super::errors::{Error, Result};
use super::paths;
use super::require_sender;
use super::session::SecretStruct;
use super::state::Shared;
use std::collections::HashMap;
use zbus::Connection;
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zeroize::Zeroizing;

pub struct Item {
    state: Shared,
    collection: String,
    id: String,
}

impl Item {
    pub fn new(state: Shared, collection: String, id: String) -> Self {
        Self {
            state,
            collection,
            id,
        }
    }

    /// Read one field of the decrypted item; `None` while locked or missing.
    async fn with_item<T>(&self, f: impl FnOnce(&crate::vault::format::Item) -> T) -> Option<T> {
        let st = self.state.lock().await;
        st.collections
            .get(&self.collection)
            .and_then(|v| v.item(&self.id).ok())
            .map(f)
    }

    async fn update(
        &self,
        f: impl FnOnce(&mut crate::vault::format::Item),
    ) -> zbus::fdo::Result<()> {
        let mut st = self.state.lock().await;
        let vault = st
            .collections
            .get_mut(&self.collection)
            .ok_or_else(|| zbus::fdo::Error::UnknownObject("no such collection".into()))?;
        vault
            .update_item(&self.id, f)
            .map_err(super::errors::vault_error_to_fdo)
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    async fn delete(&self, #[zbus(connection)] conn: &Connection) -> Result<OwnedObjectPath> {
        {
            let mut st = self.state.lock().await;
            let vault = st
                .collections
                .get_mut(&self.collection)
                .ok_or(Error::NoSuchObject)?;
            vault.delete_item(&self.id)?;
            st.touch();
        }
        let path = paths::item(&self.collection, &self.id);
        let conn2 = conn.clone();
        let p = path.clone();
        tokio::spawn(async move {
            let _ = conn2.object_server().remove::<Item, _>(p.as_str()).await;
        });
        SignalEmitter::new(conn, paths::collection(&self.collection))?
            .item_deleted(path)
            .await?;
        Ok(paths::root())
    }

    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<SecretStruct> {
        let mut st = self.state.lock().await;
        st.touch();
        let cipher = st.cipher(session.as_str(), &require_sender(&header)?)?;
        let vault = st
            .collections
            .get(&self.collection)
            .ok_or(Error::NoSuchObject)?;
        let item = vault.item(&self.id)?;
        let (parameters, value) = cipher.encrypt(&item.secret);
        Ok(SecretStruct {
            session,
            parameters,
            value,
            content_type: item.content_type.clone(),
        })
    }

    async fn set_secret(
        &self,
        secret: SecretStruct,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        {
            let mut st = self.state.lock().await;
            let plaintext = st
                .cipher(secret.session.as_str(), &require_sender(&header)?)?
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            // The same cap `CreateItem` enforces. Without it here the cap is
            // only a speed bump: create a one-byte item, then replace its
            // secret with a hundred megabytes and the collection is past the
            // vault size limit anyway, at which point it stops saving
            // entirely. Found while auditing negative-test coverage.
            if plaintext.len() > collection::MAX_ITEM_SECRET {
                return Err(Error::invalid_args(format!(
                    "secret is too large; at most {} bytes per item",
                    collection::MAX_ITEM_SECRET
                )));
            }
            let vault = st
                .collections
                .get_mut(&self.collection)
                .ok_or(Error::NoSuchObject)?;
            let content_type = secret.content_type.clone();
            vault.update_item(&self.id, move |i| {
                i.secret = Zeroizing::new(plaintext.to_vec());
                i.content_type = content_type;
            })?;
            st.touch();
        }
        SignalEmitter::new(conn, paths::collection(&self.collection))?
            .item_changed(paths::item(&self.collection, &self.id))
            .await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        let st = self.state.lock().await;
        st.collections
            .get(&self.collection)
            .map(|v| v.is_locked())
            .unwrap_or(true)
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.with_item(|i| {
            i.attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(&self, attributes: HashMap<String, String>) -> zbus::fdo::Result<()> {
        self.update(|i| i.attributes = attributes.into_iter().collect())
            .await
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.with_item(|i| i.label.clone())
            .await
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&self, label: &str) -> zbus::fdo::Result<()> {
        let label = label.to_string();
        self.update(|i| i.label = label).await
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.with_item(|i| i.created).await.unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.with_item(|i| i.modified).await.unwrap_or(0)
    }
}
