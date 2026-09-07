//! Password prompting through pinentry.
pub mod pinentry;
pub use pinentry::{PinOutcome, PinRequest, Pinentry, PinentryError};
