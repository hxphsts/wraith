//! Reading the two TCC grants, without prompting.
//!
//! The preflight calls are the whole point: they answer whether a grant exists
//! and never show a dialog, so they can be polled while a window waits for the
//! user to come back from System Settings. Their requesting counterparts prompt
//! once per process and are called from a button instead.
//!
//! See `tap.rs` for why an ad-hoc-signed build makes the capture answer
//! unreliable: `CGPreflightListenEventAccess` checks the bundle identifier while
//! `CGEventTapCreate` checks the binary's cdhash, and on an unsigned build those
//! disagree. A green tick here on a locally built binary is not a promise.

use crate::ports::{Ability, Grant, Permissions};

// Vendored rather than taken from a stale crate, matching `inject.rs`: these are
// stable public C symbols in ApplicationServices and there are only four.
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    /// Whether this process may post events. Does not prompt.
    fn CGPreflightPostEventAccess() -> bool;
    /// Asks for Accessibility, prompting once.
    fn CGRequestPostEventAccess() -> bool;
    /// Whether this process may observe events. Does not prompt.
    fn CGPreflightListenEventAccess() -> bool;
    /// Asks for Input Monitoring, prompting once.
    fn CGRequestListenEventAccess() -> bool;
}

/// Both grants, as they stand right now.
#[must_use]
pub fn state() -> Permissions {
    // SAFETY: both are preflight calls taking no arguments and returning a
    // bool, and neither has a side effect beyond reading the TCC database.
    let (inject, capture) =
        unsafe { (CGPreflightPostEventAccess(), CGPreflightListenEventAccess()) };

    Permissions {
        inject: grant(inject),
        capture: grant(capture),
    }
}

/// Prompts for whatever is missing.
///
/// Only for what is actually missing, because requesting a grant already given
/// is a wasted round trip, and on some releases it re-opens System Settings.
pub fn request() {
    let now = state();

    // SAFETY: the request calls take no arguments and return a bool. They may
    // show a dialog, which is the reason this is not called from a poll.
    unsafe {
        if now.inject.blocks() {
            CGRequestPostEventAccess();
        }
        if now.capture.blocks() {
            CGRequestListenEventAccess();
        }
    }
}

/// Opens the settings pane that governs one ability.
///
/// Requests first, and not out of politeness. An app that has never asked is
/// absent from the list entirely, so opening the pane on its own would show a
/// window with no Wraith in it and nothing to switch on. The request adds the
/// row; this puts the user in front of it.
pub fn reveal(ability: Ability) {
    request();

    let pane = match ability {
        Ability::Inject => "Privacy_Accessibility",
        Ability::Capture => "Privacy_ListenEvent",
    };

    let url = format!("x-apple.systempreferences:com.apple.preference.security?{pane}");

    // Spawned rather than waited on, because this is called from the window's
    // click handler and `open` returns only once Settings has come up.
    if let Err(error) = std::process::Command::new("open").arg(&url).spawn() {
        tracing::warn!(%error, pane, "cannot open System Settings, so the grant has to be found by hand");
    }
}

const fn grant(allowed: bool) -> Grant {
    if allowed {
        Grant::Given
    } else {
        Grant::Withheld
    }
}
