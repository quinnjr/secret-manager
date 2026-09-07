//! Errors in the `org.freedesktop.Secret.Error` namespace.
//!
//! `#[derive(zbus::DBusError)]`'s `#[zbus(error)] ZBus(zbus::Error)` fallback variant
//! always sends the literal wire name `org.freedesktop.zbus.Error` for that variant,
//! folding the real error name into the description string instead. That breaks the
//! "unknown algorithm -> `org.freedesktop.DBus.Error.NotSupported`" contract (verified
//! against zbus 5.19: `open_session` with a bogus algorithm arrived at the client as
//! `MethodError("org.freedesktop.zbus.Error", Some("org.freedesktop.DBus.Error.NotSupported: ..."))`
//! instead of a `NotSupported` error). So `DBusError` is implemented by hand here: the
//! `ZBus` variant forwards to the wrapped `zbus::fdo::Error`'s own `DBusError` impl when
//! present, which preserves its real wire name.

use crate::vault::VaultError;
use zbus::DBusError as _;
use zbus::message::{Header, Message};
use zbus::names::ErrorName;

#[derive(Debug)]
pub enum Error {
    ZBus(zbus::Error),
    IsLocked,
    NoSession,
    NoSuchObject,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn failed(msg: impl std::fmt::Display) -> Self {
        Error::ZBus(zbus::fdo::Error::Failed(msg.to_string()).into())
    }

    pub fn invalid_args(msg: impl std::fmt::Display) -> Self {
        Error::ZBus(zbus::fdo::Error::InvalidArgs(msg.to_string()).into())
    }

    pub fn not_supported(msg: impl std::fmt::Display) -> Self {
        Error::ZBus(zbus::fdo::Error::NotSupported(msg.to_string()).into())
    }
}

impl From<VaultError> for Error {
    /// Anything but `Locked`/`NoSuchItem` becomes a deliberately generic
    /// `Failed`: a vault I/O or format error's own text names the vault file
    /// path, which is daemon-internal detail no bus caller needs (LOW 3). The
    /// detail is logged instead.
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => Error::IsLocked,
            VaultError::NoSuchItem(_) => Error::NoSuchObject,
            other => {
                tracing::warn!("vault error reported to a bus caller: {other}");
                Error::failed("cannot access the collection")
            }
        }
    }
}

/// zbus 5's `#[zbus(property)]` setters must return an error that converts
/// into `zbus::fdo::Error` (its generated code calls `zbus::fdo::Error::from`
/// on the error directly — verified against zbus 5.19's `zbus_macros::iface`
/// codegen), so our hand-rolled `Error` — whose `IsLocked` etc. use their own
/// `org.freedesktop.Secret.Error.*` wire names via a custom `DBusError` impl,
/// not a `From<Error> for zbus::fdo::Error` — cannot be returned from one.
/// Every property setter (`Collection::set_label`, `Item::set_label`,
/// `Item::set_attributes`) is therefore stuck reporting a locked vault as
/// `org.freedesktop.DBus.Error.Failed` on the wire; this keeps the intended
/// name legible in the description text instead of losing it entirely.
pub fn vault_error_to_fdo(e: VaultError) -> zbus::fdo::Error {
    match e {
        VaultError::Locked => zbus::fdo::Error::Failed(
            "org.freedesktop.Secret.Error.IsLocked: collection is locked".into(),
        ),
        // Generic on the wire for the same reason as `From<VaultError>`.
        other => {
            tracing::warn!("vault error reported to a bus caller: {other}");
            zbus::fdo::Error::Failed("cannot access the collection".into())
        }
    }
}

impl From<zbus::fdo::Error> for Error {
    fn from(e: zbus::fdo::Error) -> Self {
        Error::ZBus(e.into())
    }
}

impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        Error::ZBus(e)
    }
}

impl zbus::DBusError for Error {
    fn name(&self) -> ErrorName<'_> {
        match self {
            Error::ZBus(zbus::Error::FDO(inner)) => inner.name(),
            Error::ZBus(_) => ErrorName::from_static_str_unchecked("org.freedesktop.zbus.Error"),
            Error::IsLocked => {
                ErrorName::from_static_str_unchecked("org.freedesktop.Secret.Error.IsLocked")
            }
            Error::NoSession => {
                ErrorName::from_static_str_unchecked("org.freedesktop.Secret.Error.NoSession")
            }
            Error::NoSuchObject => {
                ErrorName::from_static_str_unchecked("org.freedesktop.Secret.Error.NoSuchObject")
            }
        }
    }

    fn description(&self) -> Option<&str> {
        match self {
            Error::ZBus(zbus::Error::FDO(inner)) => inner.description(),
            Error::ZBus(e) => e.description(),
            Error::IsLocked | Error::NoSession | Error::NoSuchObject => None,
        }
    }

    fn create_reply(&self, call: &Header<'_>) -> zbus::Result<Message> {
        match self {
            Error::ZBus(zbus::Error::FDO(inner)) => inner.create_reply(call),
            Error::ZBus(_) => match self.description() {
                Some(desc) => Message::error(call, self.name())?.build(&desc),
                None => Message::error(call, self.name())?.build(&()),
            },
            Error::IsLocked | Error::NoSession | Error::NoSuchObject => {
                Message::error(call, self.name())?.build(&())
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            self.name(),
            self.description().unwrap_or("no description")
        )
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault I/O error names the vault file; that path must not reach the
    /// wire (LOW 3).
    #[test]
    fn vault_io_errors_are_generic_on_the_wire() {
        let io = || VaultError::Io {
            path: "/home/u/.local/share/secret-manager/private.vault".into(),
            source: std::io::Error::other("permission denied"),
        };
        assert!(
            io().to_string().contains("private.vault"),
            "fixture assumption: {}",
            io()
        );
        let text = Error::from(io()).to_string();
        assert!(text.contains("cannot access the collection"), "{text}");
        assert!(!text.contains("private.vault"), "path leaked: {text}");
        let fdo = vault_error_to_fdo(io()).to_string();
        assert!(!fdo.contains("private.vault"), "path leaked: {fdo}");

        // The mapped variants keep their own wire names.
        assert!(matches!(Error::from(VaultError::Locked), Error::IsLocked));
        assert!(matches!(
            Error::from(VaultError::NoSuchItem("x".into())),
            Error::NoSuchObject
        ));
    }

    /// A `zbus::Error` that is *not* an `fdo::Error` is the one family the
    /// hand-written `DBusError` impl cannot forward, so it has to answer for
    /// itself: the module exists because the derive folded every real error
    /// name into a description string, and these three methods are what stop
    /// that happening again. `Unsupported` stands in for the internal zbus
    /// failures that reach the wire through `From<zbus::Error>` (an object
    /// export that fails in `Service::unlock`, a signal emitter that cannot be
    /// built in `Collection::create_item`).
    #[test]
    fn a_non_fdo_zbus_error_reports_the_zbus_name_and_keeps_its_text() {
        let e = Error::from(zbus::Error::Unsupported);
        assert!(matches!(e, Error::ZBus(zbus::Error::Unsupported)));
        assert_eq!(e.name().as_str(), "org.freedesktop.zbus.Error");
        assert_eq!(
            e.description(),
            zbus::Error::Unsupported.description(),
            "the description must carry the wrapped error's own text"
        );

        // An `fdo::Error` wrapped by the same enum keeps its real wire name
        // instead of being flattened into `org.freedesktop.zbus.Error` - the
        // whole reason `DBusError` is implemented by hand here.
        let fdo = Error::from(zbus::fdo::Error::UnknownObject("no".into()));
        assert_eq!(
            fdo.name().as_str(),
            "org.freedesktop.DBus.Error.UnknownObject"
        );
        assert_eq!(fdo.description(), Some("no"));
    }

    /// The three `org.freedesktop.Secret.Error.*` variants carry no
    /// description, so `Display` must still say something usable in a log.
    #[test]
    fn secret_service_variants_have_a_name_but_no_description() {
        for (e, name) in [
            (Error::IsLocked, "org.freedesktop.Secret.Error.IsLocked"),
            (Error::NoSession, "org.freedesktop.Secret.Error.NoSession"),
            (
                Error::NoSuchObject,
                "org.freedesktop.Secret.Error.NoSuchObject",
            ),
        ] {
            assert_eq!(e.name().as_str(), name);
            assert_eq!(e.description(), None);
            assert_eq!(e.to_string(), format!("{name}: no description"));
        }
    }

    /// `create_reply` is what a bus client actually receives. Each family has
    /// to produce the right error name on the wire: the `Secret.Error.*`
    /// variants with an empty body, a wrapped `fdo::Error` through its own
    /// impl, and a non-fdo `zbus::Error` under the zbus name with its text as
    /// the body.
    #[test]
    fn create_reply_puts_each_family_on_the_wire_under_its_own_name() {
        let call = Message::method_call("/org/freedesktop/secrets", "Unlock")
            .unwrap()
            .interface("org.freedesktop.Secret.Service")
            .unwrap()
            .build(&())
            .unwrap();
        let header = call.header();
        let name_of = |e: &Error| {
            let reply = e.create_reply(&header).unwrap();
            reply.header().error_name().unwrap().to_string()
        };
        assert_eq!(
            name_of(&Error::IsLocked),
            "org.freedesktop.Secret.Error.IsLocked"
        );
        assert_eq!(
            name_of(&Error::NoSession),
            "org.freedesktop.Secret.Error.NoSession"
        );
        assert_eq!(
            name_of(&Error::NoSuchObject),
            "org.freedesktop.Secret.Error.NoSuchObject"
        );
        assert_eq!(
            name_of(&Error::not_supported("nope")),
            "org.freedesktop.DBus.Error.NotSupported",
            "a wrapped fdo error must keep its own name, not the zbus one"
        );
        let generic = Error::from(zbus::Error::Unsupported);
        assert_eq!(name_of(&generic), "org.freedesktop.zbus.Error");
        let reply = generic.create_reply(&header).unwrap();
        assert_eq!(
            reply.body().deserialize::<String>().unwrap(),
            generic.description().unwrap(),
            "the description is the only place the real cause survives"
        );
    }

    /// A wrapped `MethodError` is the one non-fdo `zbus::Error` that can carry
    /// no description at all (an error reply with an empty body). The reply
    /// built for it must still be a well-formed error message under the zbus
    /// name, with an empty body rather than a `None` serialised into it.
    #[test]
    fn a_non_fdo_error_without_a_description_still_builds_a_reply() {
        let call = Message::method_call("/org/freedesktop/secrets", "Unlock")
            .unwrap()
            .interface("org.freedesktop.Secret.Service")
            .unwrap()
            .build(&())
            .unwrap();
        let bodyless = Message::error(&call.header(), "org.example.Bare")
            .unwrap()
            .build(&())
            .unwrap();
        let e = Error::from(zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from("org.example.Bare").unwrap(),
            None,
            bodyless,
        ));
        assert_eq!(e.description(), None);
        assert_eq!(
            e.name().as_str(),
            "org.freedesktop.zbus.Error",
            "only an fdo error may keep its own name through this enum"
        );
        let reply = e.create_reply(&call.header()).unwrap();
        assert_eq!(
            reply.header().error_name().unwrap().to_string(),
            "org.freedesktop.zbus.Error"
        );
        assert!(
            reply.body().deserialize::<()>().is_ok(),
            "a description-less error must produce an empty body"
        );
    }
}
