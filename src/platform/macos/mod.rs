//! macOS adapters.
//!
//! # Telling our own input apart
//!
//! A machine's capture sees the events it injects. Left alone that is a loop:
//! the receiving machine injects, captures its own injection, and if its cursor
//! happens to be remote it forwards that straight back to where it came from.
//!
//! X11 solves this with the device id, since XTEST synthesises through named
//! virtual devices. macOS has no equivalent device, but it does have a spare
//! field on every event: `kCGEventSourceUserData`. Injection stamps it and the
//! tap ignores anything carrying the stamp.
//!
//! Unlike the X11 filter this costs nothing else. There, ignoring the XTEST
//! devices also ignores every other client's synthetic input, because they all
//! share the same devices. Here the stamp is ours alone, so an automation tool
//! driving this Mac still crosses screens normally.

/// The value injection stamps on every event it creates.
///
/// Arbitrary, and only has to be a value nothing else would set. Zero would not
/// do: it is what an untagged event already carries.
pub const OUR_EVENTS: i64 = 0x0057_5241_4954_4800; // "WRAITH" with room either side

pub mod clipboard;
pub mod codes;
pub mod cursor;
pub mod inject;
pub mod permissions;
pub mod tap;
