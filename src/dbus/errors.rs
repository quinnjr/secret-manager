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
}
