//! Identity, pairing, and the encrypted link.
//!
//! Crate-private. None of this is a caller's business yet: an embedder would
//! want `Identity` and `TrustedPeers`, and those can be re-exported the day
//! somebody asks. Publishing them now would be a promise made to nobody, and
//! withdrawing a promise costs a major version where making one costs nothing.

pub mod discovery;
pub mod endpoint;
pub mod identity;
pub mod pairing;
pub mod verify;
pub mod wire;

pub use identity::Identity;
