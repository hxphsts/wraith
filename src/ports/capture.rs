//! Observing local input, and withholding it from this machine.

use crate::domain::InputEvent;

/// What capture can fail at.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    #[error("capture backend failed: {0}")]
    Backend(String),

    /// The operating system withheld a permission. Recoverable by the user.
    ///
    /// On macOS this is Input Monitoring, which cannot be worked around: an
    /// `NSEvent` global monitor needs only Accessibility but cannot suppress
    /// events, and a KVM must consume input locally while the cursor is remote.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The capture session ended and will not resume without being rebuilt.
    #[error("capture session ended: {0}")]
    SessionLost(String),
}

/// Observes input on this machine, and optionally stops it reaching the desktop.
///
/// Synchronous. See the module documentation in [`super`].
pub trait Capture: Send {
    /// Waits up to `timeout_ms` and appends whatever was observed.
    ///
    /// Appends rather than returns, so a caller in the hot path reuses one
    /// buffer for the life of the process and a thousand events per second
    /// allocate nothing. Returning empty on timeout is normal, not an error.
    fn poll(&mut self, timeout_ms: u32, out: &mut Vec<InputEvent>) -> Result<(), CaptureError>;

    /// Whether captured input is withheld from the local desktop.
    ///
    /// True while the cursor is on another machine. This is the part that makes
    /// a KVM different from an input logger, and the part that needs the more
    /// invasive permission on every platform.
    fn set_suppressed(&mut self, suppressed: bool) -> Result<(), CaptureError>;

    /// A short name for logs and `wraith probe`.
    fn backend_name(&self) -> &'static str;
}
