//! secret-manager: a freedesktop Secret Service daemon, CLI, and PAM module.
//!
//! One crate, three artifacts. The vault format, the control protocol, and
//! the PAM module's logic are always compiled; the service and its CLI sit
//! behind the `daemon` feature, and the `pam_sm_*` entry points behind
//! `pam`, so the library PAM loads as root carries no async runtime.

pub mod config;
pub mod pam;
pub mod protocol;
pub mod vault;

#[cfg(feature = "daemon")]
pub mod cli;
#[cfg(feature = "daemon")]
pub mod control;
#[cfg(feature = "daemon")]
pub mod daemon;
#[cfg(feature = "daemon")]
pub mod dbus;
#[cfg(feature = "daemon")]
pub mod kdf;
#[cfg(feature = "daemon")]
pub mod prompt;
#[cfg(feature = "daemon")]
pub mod session;
