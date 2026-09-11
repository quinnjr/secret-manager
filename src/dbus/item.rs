//! `org.freedesktop.Secret.Item`.

use super::collection::{self, CollectionSignals};
use super::errors::{Error, Result};
use super::paths;
use super::require_sender;
use super::session::SecretStruct;
use super::state::{Shared, VaultRef, block_in_place};
use crate::session::SessionCipher;
use crate::vault::format::Cap;
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

    /// This item's collection, looked up under one brief acquisition of the
    /// state lock. The vault is locked only after that guard is dropped; see
    /// `state::VaultRef`.
    async fn vault(&self) -> Option<VaultRef> {
        self.state.lock().await.vault(&self.collection)
    }

    /// Read one field of the decrypted item; `None` while locked or missing.
    ///
    /// Fail-closed: `Locked` and `NoSuchItem` both read as absent, so a
    /// deleted item in an unlocked collection never reports "unlocked but
    /// blank". The underlying variant is debug-logged so a swallow is still
    /// diagnosable; `Retired` cannot arise from `Vault::item` (it is a
    /// save-path error) and would likewise read as absent here, where the
    /// property getters have no `UnknownObject` to return.
    async fn with_item<T>(&self, f: impl FnOnce(&crate::vault::format::Item) -> T) -> Option<T> {
        let vault = self.vault().await?;
        let vault = vault.lock().await;
        match vault.item(&self.id) {
            Ok(item) => Some(f(item)),
            Err(e) => {
                tracing::debug!(
                    collection = %self.collection,
                    id = %self.id,
                    error = ?e,
                    "with_item miss"
                );
                None
            }
        }
    }

    async fn update(
        &self,
        f: impl FnOnce(&mut crate::vault::format::Item),
    ) -> zbus::fdo::Result<()> {
        let vault = self
            .vault()
            .await
            .ok_or_else(|| zbus::fdo::Error::UnknownObject("no such collection".into()))?;
        // The edit is a whole-vault re-encrypt and two `fsync`s, so it runs
        // on this collection's lock with the state lock free, and off the
        // async worker.
        let mut vault = vault.lock().await;
        block_in_place(|| vault.update_item(&self.id, f)).map_err(super::errors::vault_error_to_fdo)
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("prompt"))]
    async fn delete(&self, #[zbus(connection)] conn: &Connection) -> Result<OwnedObjectPath> {
        {
            let vault = self.vault().await.ok_or(Error::NoSuchObject)?;
            let mut vault = vault.lock().await;
            block_in_place(|| vault.delete_item(&self.id))?;
        }
        self.state.lock().await.touch();
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
    ) -> Result<(SecretStruct,)> {
        let (cipher, vault) = {
            let st = self.state.lock().await;
            let cipher =
                SessionCipher::clone(st.cipher(session.as_str(), &require_sender(&header)?)?);
            let vault = st.vault(&self.collection).ok_or(Error::NoSuchObject)?;
            (cipher, vault)
        };
        let (parameters, value, content_type) = {
            let vault = vault.lock().await;
            let item = vault.item(&self.id)?;
            let (parameters, value) = cipher.encrypt(&item.secret);
            // `Plain` hands back the plaintext itself; taking ownership here
            // is what wipes it when the reply is done with.
            (parameters, Zeroizing::new(value), item.content_type.clone())
        };
        // Only an authorised read counts as activity. Touching first meant any
        // bus client could refresh `last_activity` with a bogus or another
        // client's session path — no session, no unlocked collection and no
        // real item path needed — so `idle_lock` never fired and the keys
        // stayed in daemon memory indefinitely.
        self.state.lock().await.touch();
        // A one-tuple, not a bare struct: zbus writes message-body signature
        // headers with top-level struct parentheses stripped
        // (`SignatureSerializer` uses `to_string_no_parens`), so a bare
        // `SecretStruct` return goes out as `oayays` while introspection —
        // and the spec, and every strict client — expects one `(oayays)`
        // struct. The tuple's own signature is `((oayays))`, the strip
        // leaves exactly one layer, and introspection iterates the single
        // element, so all three agree. If a future zbus stops stripping,
        // `get_secret_reply_is_a_single_struct_on_the_wire` fails and this
        // wrapper goes away with it.
        Ok((SecretStruct {
            session,
            parameters,
            value,
            content_type,
        },))
    }

    async fn set_secret(
        &self,
        secret: SecretStruct,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        // The content type is written into the same item blob as the secret,
        // so `CreateItem`'s cap on it has to hold here too, or the cap is a
        // speed bump: create an item with a short one, then replace it.
        collection::check_content_type(&secret.content_type)?;
        {
            let (cipher, vault) = {
                let st = self.state.lock().await;
                let cipher = SessionCipher::clone(
                    st.cipher(secret.session.as_str(), &require_sender(&header)?)?,
                );
                // Cheap checks before the caller-sized decrypt: `secret.value`
                // is bounded only by the bus message size (128 MiB), so
                // decrypting first meant a client could spend that work and
                // only then be told the secret was over the cap, or the
                // collection locked. `MAX_ITEM_CIPHERTEXT` bounds the
                // plaintext from above only — the exact check on the
                // plaintext is still below.
                if secret.value.len() > collection::MAX_ITEM_CIPHERTEXT {
                    return Err(Error::invalid_args(format!(
                        "secret is too large; at most {} bytes per item",
                        collection::MAX_ITEM_SECRET
                    )));
                }
                let vault = st.vault(&self.collection).ok_or(Error::NoSuchObject)?;
                (cipher, vault)
            };
            let mut vault = vault.lock().await;
            if vault.is_locked() {
                return Err(Error::IsLocked);
            }
            let plaintext = cipher
                .decrypt(&secret.parameters, &secret.value)
                .map_err(Error::failed)?;
            // The same cap `CreateItem` enforces, through the same `Cap`, so
            // a boundary change here is one edit and not four. Without it the
            // cap is only a speed bump: create a one-byte item, then replace
            // its secret with a hundred megabytes and the collection is past
            // the vault size limit anyway, at which point it stops saving
            // entirely. Found while auditing negative-test coverage.
            if let Some(over) = Cap::Secret.check(plaintext.len()) {
                return Err(Error::invalid_args(collection::cap_message(over)));
            }
            let content_type = secret.content_type.clone();
            block_in_place(|| {
                vault.update_item(&self.id, move |i| {
                    i.secret = Zeroizing::new(plaintext.to_vec());
                    i.content_type = content_type;
                })
            })?;
        }
        self.state.lock().await.touch();
        SignalEmitter::new(conn, paths::collection(&self.collection))?
            .item_changed(paths::item(&self.collection, &self.id))
            .await?;
        Ok(())
    }

    /// Whether this item can be read.
    ///
    /// Routed through [`Item::with_item`], not through `Vault::is_locked`
    /// alone, so an item that no longer exists reads as locked. Between a
    /// delete and the `object_server` unexport that follows it, the object is
    /// still on the bus with nothing behind it; answering `is_locked` for its
    /// *collection* made a deleted item in an unlocked collection report
    /// `Locked = false` while `Label` and `Attributes` — which both go
    /// through `with_item` — answered empty. "Unlocked but blank" is not a
    /// state this interface has; "locked" is what every other property
    /// already says in that window.
    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.with_item(|_| false).await.unwrap_or(true)
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
        // Same caps as `CreateItem`: the attributes go into the same encrypted
        // item blob, so a setter without them makes the create-path cap a
        // speed bump — create a small item, then grow it here.
        collection::check_attributes(
            attributes.len(),
            attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        )?;
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
        // Same cap as `CreateItem`, for the same reason as `set_attributes`.
        collection::check_label(label)?;
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
