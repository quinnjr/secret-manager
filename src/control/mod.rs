//! Unix control socket used by the CLI and the PAM module.
pub mod server;
pub use server::{ControlServer, Handler, read_frame};
