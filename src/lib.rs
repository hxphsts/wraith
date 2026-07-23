//! Wraith, a software KVM switch.
//!
//! One keyboard and mouse driving several machines over a local network, with a
//! shared clipboard. Push the cursor off the edge of one screen and it arrives
//! on the next.
//!
//! Wraith runs from the command line: `wraith pair` links two machines, `wraith
//! serve` runs a session. It is headless and peer to peer, each machine
//! authenticated by a pinned key, and works on Linux (X11) and macOS.
//!
//! # The guarantee
//!
//! A key held on a remote machine is always released: on screen leave, on
//! disconnect, on timeout, on panic, and on process exit. Several of the layers
//! that enforce it hold even when the sending machine has already stopped.
//!
//! # Modules
//!
//! The crate is hexagonal. [`domain`] is the pure core, with no I/O, platform,
//! async, or clock; time reaches it as data. [`ports`] are the traits it is
//! driven through and [`platform`] the adapters behind them, the only place
//! `#[cfg(target_os)]` appears. [`config`], [`peers`], and [`control`] are the
//! desk on disk, the trust store, and the socket a window drives a session over.
//! [`status`] turns those into what a window shows, [`unstick`] recovers a stuck
//! key, [`cli`] is the binary's entry, and [`error`] is the crate's error type.
//!
//! The transport and session orchestration are private, so the public surface
//! stays small enough to keep stable.

pub mod cli;
pub mod config;
pub mod control;
pub mod domain;
pub mod error;
pub mod peers;
pub mod platform;
pub mod ports;
pub mod status;
pub mod unstick;

mod net;
mod run;

/// The crate's own internals, opened for its own integration tests.
///
/// **Not public API.** Nothing reachable through here carries a compatibility
/// promise, and any release may move or delete any of it.
///
/// It exists because an integration test is a separate crate. Proving the
/// transport against a real QUIC endpoint, rather than against a `Vec`, would
/// otherwise mean publishing every signature in `net` in order to write the
/// test that makes the security argument checkable.
#[cfg(feature = "_internals")]
#[doc(hidden)]
pub mod internals {
    pub use crate::net::{endpoint, identity, verify, wire};
}

pub use error::{Error, Result};
