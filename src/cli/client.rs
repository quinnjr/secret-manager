//! Secret Service client used by the CLI: session setup, prompts, item helpers.

use super::CliError;
use crate::dbus::proxies::{CollectionProxy, ItemProxy, PromptProxy, ServiceProxy};
use crate::dbus::session::SecretStruct;
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use futures_util::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

pub fn map_zbus(e: zbus::Error) -> CliError {
    match &e {
        zbus::Error::MethodError(name, msg, _) => {
            let msg = msg.clone().unwrap_or_default();
            match name.as_str() {
                "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.NameHasNoOwner"
                | "org.freedesktop.DBus.Error.NoReply" => CliError::Unreachable(format!(
                    "secret service is not running ({msg}); start it with `systemctl --user start secret-manager`"
                )),
                "org.freedesktop.Secret.Error.IsLocked" => {
                    CliError::Failed("collection is locked".into())
                }
                other => CliError::Failed(format!("{other}: {msg}")),
            }
        }
        zbus::Error::InputOutput(_) | zbus::Error::Address(_) => {
            CliError::Unreachable(format!("cannot reach the session bus: {e}"))
        }
        _ => CliError::Failed(e.to_string()),
    }
}

#[derive(Debug, Clone)]
pub struct ItemInfo {
    pub path: OwnedObjectPath,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub locked: bool,
    pub modified: u64,
}

pub struct Client {
    pub conn: Connection,
    pub service: ServiceProxy<'static>,
    pub session: OwnedObjectPath,
    cipher: SessionCipher,
}

impl Client {
    /// Connect to the session bus and open a DH session (plain if the service refuses DH).
    pub async fn connect() -> Result<Client, CliError> {
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
        let timed_out = || CliError::Unreachable("session bus did not answer within 10 s".into());

        let conn = tokio::time::timeout(CONNECT_TIMEOUT, Connection::session())
            .await
            .map_err(|_| timed_out())?
            .map_err(|e| {
                CliError::Unreachable(format!("cannot connect to the session bus: {e}"))
            })?;
        let service = ServiceProxy::builder(&conn)
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(map_zbus)?;
        let pair = KeyPair::generate();
        let (session, cipher) = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            service.open_session(ALGORITHM_DH, &Value::from(pair.public_bytes().to_vec())),
        )
        .await
        .map_err(|_| timed_out())?
        {
            Ok((output, path)) => {
                let peer = Vec::<u8>::try_from(output)
                    .map_err(|e| CliError::Failed(format!("bad DH reply: {e}")))?;
                let cipher = SessionCipher::from_dh(&pair, &peer)
                    .map_err(|e| CliError::Failed(e.to_string()))?;
                (path, cipher)
            }
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.DBus.Error.NotSupported" =>
            {
                let (_, path) = tokio::time::timeout(
                    CONNECT_TIMEOUT,
                    service.open_session(ALGORITHM_PLAIN, &Value::from("")),
                )
                .await
                .map_err(|_| timed_out())?
                .map_err(map_zbus)?;
                (path, SessionCipher::plain())
            }
            Err(e) => return Err(map_zbus(e)),
        };
        Ok(Client {
            conn,
            service,
            session,
            cipher,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], content_type: &str) -> SecretStruct {
        let (parameters, value) = self.cipher.encrypt(plaintext);
        SecretStruct {
            session: self.session.clone(),
            parameters,
            value,
            content_type: content_type.to_string(),
        }
    }

    pub fn decrypt(&self, secret: &SecretStruct) -> Result<Zeroizing<Vec<u8>>, CliError> {
        self.cipher
            .decrypt(&secret.parameters, &secret.value)
            .map_err(|e| CliError::Failed(e.to_string()))
    }

    pub async fn search(
        &self,
        attrs: &BTreeMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), CliError> {
        let map: HashMap<&str, &str> = attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.service.search_items(map).await.map_err(map_zbus)
    }

    /// Unlock objects, driving any prompt. Dismissal is `CliError::NotFound`.
    pub async fn unlock(
        &self,
        objects: &[OwnedObjectPath],
    ) -> Result<Vec<OwnedObjectPath>, CliError> {
        let (mut unlocked, prompt) = self.service.unlock(objects).await.map_err(map_zbus)?;
        if prompt.as_str() != "/" {
            let result = self.perform_prompt(&prompt).await?;
            let more = Vec::<OwnedObjectPath>::try_from(result)
                .map_err(|e| CliError::Failed(format!("bad unlock result: {e}")))?;
            unlocked.extend(more);
        }
        Ok(unlocked)
    }

    pub async fn perform_prompt(&self, prompt: &OwnedObjectPath) -> Result<OwnedValue, CliError> {
        let proxy = PromptProxy::builder(&self.conn)
            .path(prompt.clone())
            .map_err(map_zbus)?
            .build()
            .await
            .map_err(map_zbus)?;
        let mut completed = proxy.receive_completed().await.map_err(map_zbus)?;
        proxy.prompt("").await.map_err(map_zbus)?;
        let signal = tokio::time::timeout(PROMPT_TIMEOUT, completed.next())
            .await
            .map_err(|_| CliError::Failed("timed out waiting for the password prompt".into()))?
            .ok_or_else(|| CliError::Failed("prompt vanished".into()))?;
        let args = signal.args().map_err(map_zbus)?;
        if args.dismissed {
            return Err(CliError::NotFound("password prompt dismissed".into()));
        }
        args.result
            .try_to_owned()
            .map_err(|e| CliError::Failed(e.to_string()))
    }

    async fn item_proxy(&self, path: &OwnedObjectPath) -> Result<ItemProxy<'static>, CliError> {
        ItemProxy::builder(&self.conn)
            .path(path.clone())
            .map_err(map_zbus)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(map_zbus)
    }

    async fn collection_proxy(
        &self,
        path: &OwnedObjectPath,
    ) -> Result<CollectionProxy<'static>, CliError> {
        CollectionProxy::builder(&self.conn)
            .path(path.clone())
            .map_err(map_zbus)?
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(map_zbus)
    }

    pub async fn get_secret(&self, item: &OwnedObjectPath) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let secret = self
            .item_proxy(item)
            .await?
            .get_secret(&self.session)
            .await
            .map_err(map_zbus)?;
        self.decrypt(&secret)
    }

    pub async fn item_info(&self, item: &OwnedObjectPath) -> Result<ItemInfo, CliError> {
        let proxy = self.item_proxy(item).await?;
        Ok(ItemInfo {
            path: item.clone(),
            label: proxy.label().await.map_err(map_zbus)?,
            attributes: proxy
                .attributes()
                .await
                .map_err(map_zbus)?
                .into_iter()
                .collect(),
            locked: proxy.locked().await.map_err(map_zbus)?,
            modified: proxy.modified().await.map_err(map_zbus)?,
        })
    }

    pub async fn default_collection(&self) -> Result<OwnedObjectPath, CliError> {
        let path = self.service.read_alias("default").await.map_err(map_zbus)?;
        if path.as_str() == "/" {
            return Err(CliError::Failed(
                "no default collection; create one with `sm init`".into(),
            ));
        }
        Ok(path)
    }

    /// Store into the default collection, replacing an item with identical attributes.
    pub async fn store(
        &self,
        attrs: &BTreeMap<String, String>,
        label: &str,
        secret: &[u8],
    ) -> Result<OwnedObjectPath, CliError> {
        let collection = self.default_collection().await?;
        let proxy = self.collection_proxy(&collection).await?;
        if proxy.locked().await.map_err(map_zbus)? {
            self.unlock(std::slice::from_ref(&collection)).await?;
        }
        let attrs_map: HashMap<String, String> =
            attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let props = HashMap::from([
            (
                "org.freedesktop.Secret.Item.Label",
                Value::from(label.to_string()),
            ),
            (
                "org.freedesktop.Secret.Item.Attributes",
                Value::from(attrs_map),
            ),
        ]);
        let (item, _prompt) = proxy
            .create_item(props, &self.encrypt(secret, "text/plain"), true)
            .await
            .map_err(map_zbus)?;
        Ok(item)
    }

    pub async fn delete_item(&self, item: &OwnedObjectPath) -> Result<(), CliError> {
        self.item_proxy(item)
            .await?
            .delete()
            .await
            .map(|_| ())
            .map_err(map_zbus)
    }

    /// Every item path in every collection.
    pub async fn all_items(&self) -> Result<Vec<OwnedObjectPath>, CliError> {
        let mut out = Vec::new();
        for c in self.service.collections().await.map_err(map_zbus)? {
            out.extend(
                self.collection_proxy(&c)
                    .await?
                    .items()
                    .await
                    .map_err(map_zbus)?,
            );
        }
        Ok(out)
    }
}
