//! `org.freedesktop.Secret.Session` and the `(oayays)` secret struct.

use super::errors::{Error, Result};
use super::require_sender;
use super::state::Shared;
use serde::{Deserialize, Serialize};
use zbus::interface;
use zbus::message::Header;
use zbus::zvariant::{OwnedObjectPath, Type};
use zeroize::Zeroizing;

/// The Secret Service `(oayays)` transport struct.
///
/// `value` is `Zeroizing` because on a `plain` session it *is* the plaintext
/// secret, and every holder of one — `GetSecret`, `GetSecrets`, `CreateItem`,
/// `SetSecret`, the CLI's own encrypt/decrypt pair, and any collection-sized
/// batch a caller accumulates — would otherwise drop it unwiped. Fixing it at
/// the definition is what makes that true for all of them at once rather than
/// at whichever call site last remembered to wipe by hand.
///
/// `parameters` is deliberately *not* `Zeroizing`. It is empty on a `plain`
/// session and the AES-CBC IV on a `dh-ietf1024-sha256-aes128-cbc-pkcs7` one
/// (`SessionCipher::encrypt`); an IV is public by construction and travels
/// over the bus in the clear as part of the protocol, so wiping it protects
/// nothing. The negotiated AES key never appears in this struct — it lives in
/// `SessionCipher`, which is `Zeroizing` in its own right.
///
/// The wire format must not change, so the signature is stated literally
/// rather than derived field by field: `Zeroizing<Vec<u8>>` has no `Type`
/// impl of its own, and `#[zvariant(signature)]` is the whole fix. `serde`
/// needs nothing — zeroize's `serde` feature (already enabled) serializes
/// `Zeroizing<Z>` as `Z`, so no hand-written `Deserialize` — which would be
/// the one change here able to get the wire format wrong — is involved.
/// `secret_struct_signature_is_unchanged` pins the signature and
/// `secret_struct_round_trips_over_the_wire` pins the bytes.
#[derive(Clone, Serialize, Deserialize, Type)]
#[zvariant(signature = "(oayays)")]
pub struct SecretStruct {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Zeroizing<Vec<u8>>,
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
            value: Zeroizing::new(b"hunter2".to_vec()),
            content_type: "text/plain".into(),
        };
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("104"), "byte-wise leak: {rendered}");
        assert!(rendered.contains("text/plain"));
    }

    /// The `value` field is `Zeroizing`, which has no `Type` impl, so the
    /// signature is spelled out on the struct. If that literal and the field
    /// list ever disagree, every libsecret client breaks: pin it.
    #[test]
    fn secret_struct_signature_is_unchanged() {
        assert_eq!(SecretStruct::SIGNATURE.to_string(), "(oayays)");
    }

    /// Wrapping `value` must not alter a single byte on the wire. zeroize's
    /// `Serialize`/`Deserialize` for `Zeroizing<Z>` are transparent, and this
    /// asserts it against the unwrapped encoding rather than trusting it.
    #[test]
    fn secret_struct_round_trips_over_the_wire() {
        use zbus::zvariant::{LE, serialized::Context, to_bytes};

        let ctxt = Context::new_dbus(LE, 0);
        let s = SecretStruct {
            session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s0").unwrap(),
            parameters: vec![1, 2, 3, 4],
            value: Zeroizing::new(b"hunter2".to_vec()),
            content_type: "text/plain".into(),
        };
        let wrapped = to_bytes(ctxt, &s).unwrap();

        // The same value with a plain `Vec<u8>`, encoded as its own type.
        #[derive(Serialize, Type)]
        struct Plain {
            session: OwnedObjectPath,
            parameters: Vec<u8>,
            value: Vec<u8>,
            content_type: String,
        }
        let plain = Plain {
            session: OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s0").unwrap(),
            parameters: vec![1, 2, 3, 4],
            value: b"hunter2".to_vec(),
            content_type: "text/plain".into(),
        };
        assert_eq!(Plain::SIGNATURE.to_string(), "(oayays)");
        assert_eq!(&*wrapped, &*to_bytes(ctxt, &plain).unwrap());

        let (back, _): (SecretStruct, _) = wrapped.deserialize().unwrap();
        assert_eq!(&*back.value, b"hunter2");
        assert_eq!(back.parameters, vec![1, 2, 3, 4]);
        assert_eq!(back.content_type, "text/plain");
        assert_eq!(back.session.as_str(), "/org/freedesktop/secrets/session/s0");
    }
}
