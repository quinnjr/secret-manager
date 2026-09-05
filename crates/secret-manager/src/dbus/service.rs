//! `org.freedesktop.Secret.Service`.

use super::errors::{Error, Result};
use super::paths;
use super::sender;
use super::session::Session;
use super::state::{SessionEntry, Shared};
use crate::session::dh::KeyPair;
use crate::session::{ALGORITHM_DH, ALGORITHM_PLAIN, SessionCipher};
use std::collections::{BTreeMap, HashMap};
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub struct Service {
    state: Shared,
}

impl Service {
    pub fn new(state: Shared) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    async fn open_session(
        &self,
        algorithm: &str,
        input: Value<'_>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        let (cipher, output) = match algorithm {
            ALGORITHM_PLAIN => (SessionCipher::plain(), Value::from("")),
            ALGORITHM_DH => {
                let peer = Vec::<u8>::try_from(input)
                    .map_err(|_| Error::invalid_args("input must be a byte array"))?;
                let pair = KeyPair::generate();
                let cipher = SessionCipher::from_dh(&pair, &peer).map_err(Error::invalid_args)?;
                (cipher, Value::from(pair.public_bytes().to_vec()))
            }
            other => {
                return Err(Error::not_supported(format!(
                    "unsupported algorithm '{other}'"
                )));
            }
        };
        let owner = sender(&header);
        let path = {
            let mut st = self.state.lock().await;
            let path = st.new_session_path();
            st.sessions
                .insert(path.to_string(), SessionEntry { owner, cipher });
            path
        };
        server
            .at(path.clone(), Session::new(self.state.clone(), path.clone()))
            .await?;
        let output = OwnedValue::try_from(output).map_err(Error::failed)?;
        Ok((output, path))
    }

    #[zbus(out_args("unlocked", "locked"))]
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        Ok(self.state.lock().await.search_all(&query))
    }

    async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath> {
        let st = self.state.lock().await;
        Ok(st
            .aliases
            .get(name)
            .filter(|id| st.collections.contains_key(*id))
            .map(|id| paths::collection(id))
            .unwrap_or_else(paths::root))
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.state
            .lock()
            .await
            .collections
            .keys()
            .map(|id| paths::collection(id))
            .collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    pub async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;
}
