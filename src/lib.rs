//! secret-manager: a freedesktop Secret Service daemon, CLI, and PAM module.
//!
//! One crate, three artifacts. The vault format, the control protocol, and
//! the PAM module's logic are always compiled; the service and its CLI sit
//! behind the `daemon` feature, and the `pam_sm_*` entry points behind
//! `pam`, so the library PAM loads as root carries no async runtime.

// The `pam` cdylib is dlopened as root by sshd/login. Building it with the
// daemon's dependencies would put an async runtime, a D-Bus stack and an
// argument parser inside that library — exactly what the feature split
// exists to prevent — and nothing in the artifacts themselves would show it.
// `make build` invokes the two feature sets separately; this stops any other
// invocation (`--all-features`, a CI matrix, `cargo install --all-features`)
// from producing a silently dangerous module.
#[cfg(all(feature = "daemon", feature = "pam"))]
compile_error!(
    "the `daemon` and `pam` features are mutually exclusive: build the binary with \
     default features and the PAM module with `--no-default-features --features pam` \
     (see the Makefile)"
);

pub mod config;
#[cfg(feature = "fuzzing")]
pub mod fuzz_api;
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
