//! The error surface.
//!
//! Errors are typed because callers act on them. A permission failure prompts
//! the user, an unsupported backend prints what was probed and why, and a
//! pairing rejection is not the same as a network failure even though both stop
//! the connection.

use std::io;

/// The result type used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Anything that can go wrong in Wraith.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No capture or injection backend is usable on this machine.
    ///
    /// The message names what was probed, since "unsupported" alone sends the
    /// user to an issue tracker rather than to their compositor's settings.
    #[error("no usable backend on this machine: {0}")]
    UnsupportedPlatform(String),

    /// The operating system withheld a permission the backend requires.
    ///
    /// Distinct from a plain failure because it is recoverable by the user, and
    /// the remedy differs per platform.
    #[error("permission denied by the operating system: {0}")]
    PermissionDenied(String),

    /// A backend refused an operation it had accepted before, or never could.
    #[error("input backend failed: {0}")]
    Backend(String),

    /// The configuration file is missing, unreadable, or describes an
    /// impossible desk.
    #[error("configuration: {0}")]
    Config(String),

    /// The peer refused, in its own words.
    ///
    /// Displayed verbatim rather than prefixed, because it is already a
    /// complete sentence written by the other machine and wrapping it would
    /// read as "configuration: configuration: the codes do not match".
    #[error("{0}")]
    PeerRefused(String),

    /// Filesystem, socket, or process failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
}
