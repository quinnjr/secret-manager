//! Secret Service client used by the CLI: session setup, prompts, item helpers.

use super::CliError;
use super::secrets::escape_control;
use crate::dbus::proxies::{
    CollectionAdminProxy, CollectionProxy, ItemProxy, PromptProxy, ServiceProxy,
};
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

/// How long [`Client::connect`] waits for the session bus.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Environment variable that shortens [`CONNECT_TIMEOUT`]; honoured only when
/// the `test-util` feature is on, which no shipped build enables.
#[cfg(feature = "test-util")]
pub const CONNECT_TIMEOUT_ENV: &str = "SM_CONNECT_TIMEOUT_MS";

/// The deadline [`Client::connect`] actually uses.
///
/// A bus that accepts the connection and then says nothing is exactly what
/// the timeout exists for, and asserting on it at the shipped 10 s costs 10 s
/// of wall clock. Under `test-util` — the same feature that exposes
/// `KdfParams::FAST_FOR_TESTS` — `SM_CONNECT_TIMEOUT_MS` may shorten it.
/// With the feature off this is [`CONNECT_TIMEOUT`] and nothing else: no
/// environment is read and no override exists in the binary we ship.
fn connect_timeout() -> Duration {
    #[cfg(feature = "test-util")]
    if let Some(ms) = std::env::var(CONNECT_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    CONNECT_TIMEOUT
}

/// Maps a D-Bus method-error name to the CLI error it becomes.
///
/// Split out of [`map_zbus`] so it can be tested: `zbus::Error::MethodError`
/// carries a `zbus::Message`, which cannot be constructed in a unit test, so
/// the mapping is otherwise reachable only from a live bus. The exit code
/// this decides is the CLI's contract with scripts — `Unreachable` is 3 and
/// `Failed` is 1 — so which name lands in which arm is worth pinning.
///
/// Both the error name and its description come from whoever owns the bus
/// name, and the CLI prints the result straight to a terminal with
/// `eprintln!`. A same-uid impostor can own `org.freedesktop.secrets` first
/// (accepted gap I3), so both halves are peer text and both go through
/// [`escape_control`], like every other peer string the CLI prints.
pub(crate) fn method_error_to_cli(name: &str, msg: &str) -> CliError {
    match name {
        "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner"
        | "org.freedesktop.DBus.Error.NoReply" => CliError::Unreachable(format!(
            "secret service is not running ({}); start it with `systemctl --user start secret-manager`",
            escape_control(msg)
        )),
        "org.freedesktop.Secret.Error.IsLocked" => CliError::Failed("collection is locked".into()),
        other => CliError::Failed(format!(
            "{}: {}",
            escape_control(other),
            escape_control(msg)
        )),
    }
}

pub fn map_zbus(e: zbus::Error) -> CliError {
    match &e {
        zbus::Error::MethodError(name, msg, _) => {
            method_error_to_cli(name.as_str(), &msg.clone().unwrap_or_default())
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
        let deadline = connect_timeout();
        // The deadline, not a literal: `connect_timeout` is shortened under
        // `test-util`, and a hardcoded "10 s" would then describe a wait that
        // never happened.
        let timed_out =
            || CliError::Unreachable(format!("session bus did not answer within {deadline:?}"));

        let conn = tokio::time::timeout(deadline, Connection::session())
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
            deadline,
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
                    deadline,
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
            value: Zeroizing::new(value),
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

    /// Everything `sm list` shows about one item, in a single round trip.
    ///
    /// The proxy is built with `CacheProperties::No` — the daemon's properties
    /// change under it, and a stale `Locked` is the difference between showing
    /// a secret and refusing to — so nothing is amortised across calls and the
    /// four generated property getters were four `Properties.Get` messages.
    /// `sm list` with no filter calls this once per item across every
    /// collection, so that was 4N round trips for N items. `GetAll` is one.
    ///
    /// The per-item calls are *not* issued concurrently instead: they are
    /// independent, but a `try_join_all` would report whichever of four
    /// failures raced to the front while the others were cancelled mid-flight,
    /// and the CLI prints that error verbatim. One call has one error.
    ///
    /// A property the daemon does not return, or returns with the wrong type,
    /// is a protocol error rather than a silent default: `sm list` would
    /// otherwise print an unlabelled item, or an item as unlocked, on the
    /// strength of a missing field.
    pub async fn item_info(&self, item: &OwnedObjectPath) -> Result<ItemInfo, CliError> {
        let mut props = zbus::fdo::PropertiesProxy::builder(&self.conn)
            .destination("org.freedesktop.secrets")
            .map_err(map_zbus)?
            .path(item.clone())
            .map_err(map_zbus)?
            .build()
            .await
            .map_err(map_zbus)?
            .get_all(
                zbus::names::InterfaceName::try_from("org.freedesktop.Secret.Item")
                    .expect("a literal, valid interface name"),
            )
            .await
            .map_err(|e| map_zbus(e.into()))?;

        fn take<T: TryFrom<OwnedValue>>(
            props: &mut HashMap<String, OwnedValue>,
            name: &str,
        ) -> Result<T, CliError> {
            props
                .remove(name)
                .ok_or_else(|| {
                    CliError::Failed(format!("the item has no {} property", escape_control(name)))
                })?
                .try_into()
                .map_err(|_| {
                    CliError::Failed(format!(
                        "the item's {} property has the wrong type",
                        escape_control(name)
                    ))
                })
        }

        Ok(ItemInfo {
            path: item.clone(),
            label: take::<String>(&mut props, "Label")?,
            attributes: take::<HashMap<String, String>>(&mut props, "Attributes")?
                .into_iter()
                .collect(),
            locked: take::<bool>(&mut props, "Locked")?,
            modified: take::<u64>(&mut props, "Modified")?,
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
        let (item, prompt) = proxy
            .create_item(props, &self.encrypt(secret, "text/plain"), true)
            .await
            .map_err(map_zbus)?;
        // Our own daemon always answers `/` here, but `CreateItem` is
        // specified to be allowed to return a prompt instead of an item, and
        // the provider on the other end need not be ours — a foreign
        // implementation, or the same-uid impostor the README accepts as
        // possible. Discarding the prompt made `sm set` print nothing, store
        // nothing, and exit 0. `unlock` drives its prompt; so does this.
        if prompt.as_str() != "/" {
            let result = self.perform_prompt(&prompt).await?;
            return OwnedObjectPath::try_from(result)
                .map_err(|e| CliError::Failed(format!("bad CreateItem result: {e}")));
        }
        if item.as_str() == "/" {
            return Err(CliError::Failed(
                "the secret service returned neither an item nor a prompt for CreateItem".into(),
            ));
        }
        Ok(item)
    }

    pub async fn delete_item(&self, item: &OwnedObjectPath) -> Result<(), CliError> {
        // As with `store` above: `Item.Delete` may answer with a prompt, and
        // a discarded one is a delete that never happened reported as success.
        let prompt = self
            .item_proxy(item)
            .await?
            .delete()
            .await
            .map_err(map_zbus)?;
        if prompt.as_str() != "/" {
            self.perform_prompt(&prompt).await?;
        }
        Ok(())
    }

    /// Delete every item in `items` from `collection` in one atomic call, via
    /// the daemon's private batch interface (see
    /// `dbus::collection::CollectionAdmin`): either all of them are gone from
    /// the vault file or none is, where N separate `Item.Delete` calls could
    /// leave the set half-deleted.
    ///
    /// `Ok(false)` means this daemon does not export the batch interface at
    /// all (an older build), and the caller should fall back to deleting one
    /// at a time. Every other failure is reported as an error, and on the
    /// batch path a failure means nothing was deleted.
    pub async fn delete_items(
        &self,
        collection: &OwnedObjectPath,
        items: &[OwnedObjectPath],
    ) -> Result<bool, CliError> {
        let proxy = CollectionAdminProxy::builder(&self.conn)
            .path(collection.clone())
            .map_err(map_zbus)?
            .build()
            .await
            .map_err(map_zbus)?;
        match proxy.delete_items(items).await {
            Ok(()) => Ok(true),
            Err(zbus::Error::MethodError(name, _, _))
                if matches!(
                    name.as_str(),
                    "org.freedesktop.DBus.Error.UnknownInterface"
                        | "org.freedesktop.DBus.Error.UnknownMethod"
                        | "org.freedesktop.DBus.Error.UnknownObject"
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(map_zbus(e)),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Which name lands in which arm decides the process exit code, and that
    /// is what a script branches on. Only the transport arm is reachable from
    /// an integration test (a bogus bus address), so the method-error names
    /// are pinned here.
    #[test]
    fn a_method_error_name_decides_the_exit_code() {
        for name in [
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "org.freedesktop.DBus.Error.NameHasNoOwner",
            "org.freedesktop.DBus.Error.NoReply",
        ] {
            let err = method_error_to_cli(name, "no owner");
            assert!(
                matches!(err, CliError::Unreachable(_)),
                "{name} must be reported as unreachable, got {err:?}"
            );
            assert_eq!(err.exit_code(), 3, "{name}");
            assert!(err.to_string().contains("systemctl --user start"), "{name}");
        }

        // A locked collection is a plain failure, and the daemon's own message
        // is deliberately dropped for a fixed one.
        let err = method_error_to_cli("org.freedesktop.Secret.Error.IsLocked", "ignored");
        assert!(matches!(err, CliError::Failed(_)), "{err:?}");
        assert_eq!(err.exit_code(), 1);
        assert_eq!(err.to_string(), "collection is locked");

        // Anything else keeps both the name and the peer's message, so an
        // unrecognised error is still diagnosable.
        let err = method_error_to_cli("com.example.Whatever", "went wrong");
        assert!(matches!(err, CliError::Failed(_)), "{err:?}");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("com.example.Whatever"));
        assert!(err.to_string().contains("went wrong"));
    }

    /// F3: the peer picks both the error name and its description, and the
    /// CLI prints the result to a terminal. Escaping them is the mitigation
    /// for a same-uid impostor owning the bus name first (accepted gap I3),
    /// and every other peer string the CLI prints already goes through
    /// `escape_control`.
    #[test]
    fn a_peer_error_reaches_the_terminal_escaped() {
        let err = method_error_to_cli(
            "com.example.Whatever",
            "oops\n\u{1b}[2Ksecret-manager: everything is fine",
        );
        let text = err.to_string();
        assert!(!text.contains('\n'), "raw newline forges a line: {text:?}");
        assert!(
            !text.contains('\u{1b}'),
            "raw escape injects ANSI: {text:?}"
        );
        assert!(text.contains("\\x0a") && text.contains("\\x1b"), "{text:?}");

        // The name is peer text too, and lands in the same line.
        let err = method_error_to_cli("com.example.\u{1b}[31mRed", "why");
        assert!(!err.to_string().contains('\u{1b}'), "{err:?}");

        // And the transport arm, which interpolates the description into its
        // own advice, escapes it as well.
        let err = method_error_to_cli("org.freedesktop.DBus.Error.NoReply", "a\rb");
        let text = err.to_string();
        assert!(!text.contains('\r'), "{text:?}");
        assert!(text.contains("\\x0d"), "{text:?}");
    }
}
