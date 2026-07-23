//! The adapters, and the only place `#[cfg(target_os)]` appears.
//!
//! Everywhere else in the crate is platform-agnostic. A `#[cfg` outside this
//! module is a leak, and the fix is a new port rather than another cfg.

// A platform with no backend still resolves `open_inject` and friends, because
// they have a fallback arm that returns an error, and then fails much later with
// a wall of missing types from the modules that were cfg'd out. One sentence at
// the top is a better answer than that.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "wraith has a backend for Linux and macOS so far. See the milestone table in \
     the README."
);

pub mod probe;
pub mod service;
pub mod socket;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

use crate::error::{Error, Result};
use crate::ports::{Capture, Clipboard, Inject};

/// Opens the best available injection backend for this machine.
///
/// The error path carries every rejection, because a user whose compositor is
/// missing a protocol needs to know which one.
#[cfg(target_os = "linux")]
pub fn open_inject() -> Result<Box<dyn Inject>> {
    let env = probe::gather_linux_env();
    let outcome = probe::choose_linux_backend(&env);

    match outcome.chosen {
        Some(probe::BackendChoice::Wlroots) => {
            let backend = linux::wlroots::WlrootsInject::open()
                .map_err(|error| Error::Backend(error.to_string()))?;
            Ok(Box::new(backend))
        }
        Some(probe::BackendChoice::X11) => {
            let backend =
                linux::x11::X11Inject::open().map_err(|error| Error::Backend(error.to_string()))?;
            Ok(Box::new(backend))
        }
        Some(other) => Err(Error::UnsupportedPlatform(format!(
            "the {other} backend is chosen for this session but is not implemented yet, \
             see the milestone table in the README"
        ))),
        None => Err(Error::UnsupportedPlatform(outcome.failure_summary())),
    }
}

/// Opens the best available capture backend for this machine.
#[cfg(target_os = "linux")]
pub fn open_capture() -> Result<Box<dyn Capture>> {
    let env = probe::gather_linux_env();
    let outcome = probe::choose_linux_backend(&env);

    match outcome.chosen {
        Some(probe::BackendChoice::X11) => {
            let backend = linux::x11_capture::X11Capture::open()
                .map_err(|error| Error::Backend(error.to_string()))?;
            Ok(Box::new(backend))
        }
        Some(other) => Err(Error::UnsupportedPlatform(format!(
            "the {other} backend is chosen for this session but its capture half is not \
             implemented yet, see the milestone table in the README"
        ))),
        None => Err(Error::UnsupportedPlatform(outcome.failure_summary())),
    }
}

/// Opens the best available capture backend for this machine.
#[cfg(target_os = "macos")]
pub fn open_capture() -> Result<Box<dyn Capture>> {
    let backend = macos::tap::MacOsCapture::open().map_err(|error| match error {
        crate::ports::capture::CaptureError::PermissionDenied(why) => Error::PermissionDenied(why),
        other => Error::Backend(other.to_string()),
    })?;

    Ok(Box::new(backend))
}

/// Opens the best available capture backend for this machine.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn open_capture() -> Result<Box<dyn Capture>> {
    Err(Error::UnsupportedPlatform(
        "Linux and macOS are implemented so far, see the milestone table in the README".to_owned(),
    ))
}

/// Opens the best available injection backend for this machine.
#[cfg(target_os = "macos")]
pub fn open_inject() -> Result<Box<dyn Inject>> {
    let backend = macos::inject::MacOsInject::open().map_err(|error| match error {
        crate::ports::inject::InjectError::PermissionDenied(why) => Error::PermissionDenied(why),
        other => Error::Backend(other.to_string()),
    })?;

    Ok(Box::new(backend))
}

/// Opens the best available injection backend for this machine.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn open_inject() -> Result<Box<dyn Inject>> {
    Err(Error::UnsupportedPlatform(
        "Linux and macOS are implemented so far, see the milestone table in the README".to_owned(),
    ))
}

/// Opens the clipboard backend for this machine, if it has one.
///
/// Best-effort: a machine with no clipboard backend still shares input, and
/// `run` degrades to a session that does not sync the clipboard. So the error is
/// carried for `wraith probe` to report rather than to stop a session.
///
/// The reachable surface mirrors capture. A wlroots session has no capture
/// backend yet, so its cursor never crosses and a wlr-data-control clipboard
/// would never fire; it lands with wlr capture rather than ahead of it.
#[cfg(target_os = "linux")]
pub fn open_clipboard() -> Result<Box<dyn Clipboard>> {
    let env = probe::gather_linux_env();
    let outcome = probe::choose_linux_backend(&env);

    match outcome.chosen {
        Some(probe::BackendChoice::X11) => {
            let backend = linux::x11_clipboard::X11Clipboard::open().map_err(clipboard_error)?;
            Ok(Box::new(backend))
        }
        Some(other) => Err(Error::UnsupportedPlatform(format!(
            "the {other} backend is chosen for this session but its clipboard half is not \
             implemented yet, so the clipboard will not follow the cursor"
        ))),
        None => Err(Error::UnsupportedPlatform(outcome.failure_summary())),
    }
}

/// Opens the best available clipboard backend for this machine.
#[cfg(target_os = "macos")]
pub fn open_clipboard() -> Result<Box<dyn Clipboard>> {
    let backend = macos::clipboard::MacOsClipboard::open().map_err(clipboard_error)?;
    Ok(Box::new(backend))
}

/// Maps a clipboard backend error to the crate error, keeping a permission
/// refusal distinct so the window can tell the user to grant it rather than
/// reporting an opaque backend failure, exactly as capture and injection do.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn clipboard_error(error: crate::ports::ClipboardError) -> Error {
    match error {
        crate::ports::ClipboardError::PermissionDenied(why) => Error::PermissionDenied(why),
        other => Error::Backend(other.to_string()),
    }
}

/// How big this machine's screen is, through whichever backend was chosen.
///
/// A port rather than a `#[cfg]` at the call site, which is the rule this module
/// exists to keep. It also fixes what the cfg version got wrong: that one named
/// X11 unconditionally, so a Wayland session where `x11rb` cannot connect fell
/// through to a hardcoded 1920x1080 and then announced that size to every peer.
/// Edge fractions are measured against it, so a wrong answer here puts every
/// crossing in the wrong place on both machines.
///
/// `None` when no backend can say, which is the caller's cue to pick a default
/// out loud rather than have one substituted quietly.
#[must_use]
pub fn local_screen() -> Option<crate::ports::LocalScreen> {
    use crate::ports::ScreenInfo as _;

    // Exactly one of these is compiled, so each is the tail expression of the
    // function rather than an early exit.
    #[cfg(target_os = "linux")]
    {
        let env = probe::gather_linux_env();

        // Whichever backend was actually chosen, rather than a guess. Those are
        // different answers on a wlroots session running XWayland, where an X11
        // connection succeeds and reports the XWayland screen instead.
        match probe::choose_linux_backend(&env).chosen {
            Some(probe::BackendChoice::Wlroots) => linux::wlroots::WlrootsInject::open()
                .ok()
                .and_then(|backend| backend.local_screen().ok()),
            Some(probe::BackendChoice::X11) => linux::x11::X11Inject::open()
                .ok()
                .and_then(|backend| backend.local_screen().ok()),
            _ => None,
        }
    }

    #[cfg(target_os = "macos")]
    {
        macos::inject::MacOsInject::open()
            .ok()
            .and_then(|backend| backend.local_screen().ok())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

/// What this machine will let Wraith do.
///
/// Never prompts, so it is safe on a timer. A grant is given in another process
/// and nothing tells this one, so asking again is the only way to find out.
#[cfg_attr(
    not(target_os = "macos"),
    expect(
        clippy::missing_const_for_fn,
        reason = "const only where the answer is a constant, which is every target but macOS"
    )
)]
#[must_use]
pub fn permissions() -> crate::ports::Permissions {
    #[cfg(target_os = "macos")]
    {
        macos::permissions::state()
    }

    // Nothing gates input here. Wayland restricts capture, but by protocol
    // availability rather than by a grant, and `probe` is what reports that.
    #[cfg(not(target_os = "macos"))]
    {
        use crate::ports::{Grant, Permissions};

        Permissions {
            inject: Grant::NotRequired,
            capture: Grant::NotRequired,
        }
    }
}

/// Asks for anything missing, prompting once per grant.
///
/// Called from a button the user pressed, never on a timer: macOS shows the
/// dialog once per process per grant, and a poll that prompts turns into a
/// stream of dialogs nobody can escape.
#[cfg_attr(
    not(target_os = "macos"),
    expect(
        clippy::missing_const_for_fn,
        reason = "const only where the answer is a constant, which is every target but macOS"
    )
)]
pub fn request_permissions() {
    #[cfg(target_os = "macos")]
    {
        macos::permissions::request();
    }
}

/// Opens the settings where an ability is granted, and asks for it on the way.
///
/// Also from a button, for the same reason. The two are one call rather than
/// two because a request that the user dismisses leaves them needing the
/// settings, and settings the user reaches before any request has been made
/// show no row for Wraith at all.
#[cfg_attr(
    not(target_os = "macos"),
    expect(
        clippy::missing_const_for_fn,
        reason = "const only where the answer is a constant, which is every target but macOS"
    )
)]
pub fn reveal_permission(ability: crate::ports::Ability) {
    #[cfg(target_os = "macos")]
    {
        macos::permissions::reveal(ability);
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Nothing to open. `Grant::NotRequired` is what these platforms report,
        // so the window never offers the control that would call this.
        let _ = ability;
    }
}
