//! Synthesising input on the local machine.

use crate::domain::{InputEvent, Point};

/// What injection can fail at.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InjectError {
    /// The display server or compositor refused, or went away.
    #[error("injection backend failed: {0}")]
    Backend(String),

    /// The operating system withheld a permission. Recoverable by the user.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The event has no representation on this platform.
    ///
    /// A button beyond what the backend models, for instance. Never fatal: the
    /// event is dropped and the session continues.
    #[error("event not representable on this backend: {0}")]
    Unrepresentable(String),
}

/// Synthesises input events on this machine.
///
/// Synchronous, and deliberately so. See the module documentation in
/// [`super`]: the release-on-teardown guarantee depends on this being callable
/// from `Drop`.
pub trait Inject: Send {
    /// Emits events in order.
    ///
    /// Implementations must treat releasing a key that is already up as a
    /// no-op rather than an error, because the paranoid sweep relies on exactly
    /// that. It releases every modifier unconditionally, and most of them will
    /// not have been down.
    fn emit(&mut self, events: &[InputEvent]) -> Result<(), InjectError>;

    /// Moves the pointer to an absolute position on the local screen.
    ///
    /// Used on arrival from another machine, where a relative delta has no
    /// meaning because the cursor was somewhere else entirely.
    fn warp_absolute(&mut self, at: Point) -> Result<(), InjectError>;

    /// Pushes anything buffered to the display server.
    fn flush(&mut self) -> Result<(), InjectError>;

    /// Where the real pointer is, if this backend can be asked.
    ///
    /// The session tracks the cursor by accumulating relative motion, and that
    /// estimate drifts: the deltas it accumulates are unaccelerated, while the
    /// pointer the user watches has the display server's acceleration curve
    /// applied. On a wide screen the two disagree by enough that the cursor
    /// crosses to the next machine while the visible pointer is still short of
    /// the edge.
    ///
    /// `None` where there is no way to ask. wlroots deliberately does not let a
    /// client read the pointer, so that backend goes on dead reckoning, which
    /// is the honest answer rather than a guess.
    fn pointer(&self) -> Option<&dyn crate::ports::ScreenInfo> {
        None
    }

    /// Whether the transport releases held keys by itself if this process dies.
    ///
    /// True for libei and the wlroots virtual keyboard, where the compositor
    /// cleans up when the client socket closes. **False for X11 XTEST**, which
    /// has no such notion, and which is exactly why Deskflow's stuck keys
    /// survive killing the process.
    ///
    /// Used only to decide how loudly to warn at startup, and to decide whether
    /// `wraith unstick` is worth mentioning in the log line.
    fn releases_on_disconnect(&self) -> bool {
        false
    }

    /// Which keys the system currently reports as physically down.
    ///
    /// `None` means this backend cannot tell, which is the common case: most
    /// injection protocols are write-only. X11 can answer, through `QueryKeymap`.
    ///
    /// Where it is available this turns `wraith unstick` from "release events
    /// were sent" into "the keys are demonstrably up", which is the difference
    /// between hoping and knowing for a command whose entire purpose is
    /// recovering from a state nobody can see.
    fn held_keys(&self) -> Option<Vec<crate::domain::Scancode>> {
        None
    }

    /// A short name for logs and `wraith probe`.
    fn backend_name(&self) -> &'static str;
}
