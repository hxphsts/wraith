//! The hexagon boundary.
//!
//! The domain is driven through [`inject::Inject`], [`capture::Capture`] and
//! [`screen_info::ScreenInfo`], and [`clipboard::Clipboard`] sits alongside them
//! for the feature the domain does not touch. Each has a fake alongside the real
//! adapters, which is what makes the boundary real rather than aspirational: an
//! abstraction with only one implementation is a comment, not a seam. The fakes
//! are test-only and not part of this crate's API.
//!
//! [`permissions`] sits here too and is not a port. It is the data a caller gets
//! back when it asks what this machine will allow, and it has no trait because
//! there is nothing to substitute: `platform` answers it directly.
//!
//! # Why the ports are synchronous
//!
//! Load bearing, rather than an oversight.
//!
//! Every operation behind them is a non-blocking local call: XTEST, the wlroots
//! virtual keyboard, `CGEventPost`, libei emit. None of them benefit from being
//! awaited. And crucially, `Drop` cannot await, so the guarantee that a held key
//! is released when a session is torn down depends on injection being callable
//! from a destructor.
//!
//! [`clipboard::Clipboard`] is synchronous too, for a different reason. Its
//! backends genuinely block, but each is single-thread-affine (an X11 selection
//! owned by one connection, a wayland event queue, an `NSPasteboard` poll), so
//! one thread owns the backend and the runtime talks to it over a channel,
//! exactly as it does with the injector. Making the trait async would buy
//! nothing the thread does not already, and would drag the first async trait
//! into a crate that keeps tokio at the run seam, in `run/clipboard.rs`.

pub mod capture;
pub mod clipboard;
pub mod inject;
pub mod permissions;
pub mod screen_info;

/// Recording stand-ins for the ports.
///
/// Test-only. They assert what they were asked to do rather than scripting what
/// a caller must ask, which is the difference between a test that survives a
/// refactor and one that encodes the implementation it was written against.
#[cfg(test)]
pub mod fake;

pub use capture::{Capture, CaptureError};
pub use clipboard::{Clipboard, ClipboardContents, ClipboardError, MIME_TEXT};
pub use inject::{Inject, InjectError};
pub use permissions::{Ability, Grant, Permissions};
pub use screen_info::{LocalScreen, ScreenInfo, ScreenInfoError};
