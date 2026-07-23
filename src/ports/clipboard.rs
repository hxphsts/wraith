//! Reading and offering this machine's clipboard.

use core::fmt;

/// The mime type of the only representation this version carries.
///
/// Images arrive as `image/png` unchanged, once the transport learns to chunk a
/// payload larger than a frame. See `research/08-clipboard.md`.
pub const MIME_TEXT: &str = "text/plain;charset=utf-8";

/// One clipboard payload, in one representation.
///
/// A single best representation rather than a list of them, which is what keeps
/// this simple: `mime` names the type and `bytes` is its content. `text/plain`
/// today, `image/png` tomorrow, with no change to this shape.
#[derive(Clone, PartialEq, Eq)]
pub struct ClipboardContents {
    pub mime: String,
    pub bytes: Vec<u8>,
}

impl ClipboardContents {
    /// A UTF-8 text payload.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            mime: MIME_TEXT.to_owned(),
            bytes: text.into().into_bytes(),
        }
    }

    /// Whether this is the text type this version handles.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.mime == MIME_TEXT
    }
}

impl fmt::Debug for ClipboardContents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the bytes. A clipboard holds whatever was last copied, which is
        // routinely a password, so the same rule the identity and pairing types
        // follow applies here: the length and the type, and nothing readable.
        f.debug_struct("ClipboardContents")
            .field("mime", &self.mime)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// What clipboard access can fail at.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClipboardError {
    #[error("clipboard backend failed: {0}")]
    Backend(String),

    /// The operating system withheld a permission. Recoverable by the user.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// A payload too large for a single frame. Chunking is a later version.
    #[error("a clipboard payload of {0} bytes is larger than a frame allows")]
    TooLarge(usize),
}

/// The system clipboard, as Wraith drives it.
///
/// Synchronous, like the other ports, and for a structural reason rather than an
/// oversight. The backends are single-thread-affine and none are async: an X11
/// selection is owned by one connection that must stay alive to serve paste
/// requests, a wayland data-control device lives on one event queue, and macOS
/// has no change event at all and is polled. So one thread owns the backend and
/// the runtime talks to it over a channel, exactly as the injector does, in
/// `run/clipboard.rs`.
pub trait Clipboard: Send {
    /// Offer these contents as this machine's clipboard.
    ///
    /// On X11 this takes ownership of the CLIPBOARD selection, after which the
    /// backend serves the bytes to any client that pastes; on wayland it offers
    /// through data-control; on macOS it writes the pasteboard.
    fn set_offer(&mut self, contents: &ClipboardContents) -> Result<(), ClipboardError>;

    /// Waits up to `timeout_ms` for the local clipboard to change, and returns
    /// the new contents if it did.
    ///
    /// `None` on timeout, like [`super::capture::Capture::poll`] returning
    /// nothing. This is the watch: an XFixes owner-change on X11, a data-control
    /// event on wayland, a `changeCount` that advanced on macOS.
    fn poll_change(&mut self, timeout_ms: u32)
    -> Result<Option<ClipboardContents>, ClipboardError>;

    /// A short name for logs and `wraith probe`.
    fn backend_name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_carries_the_utf8_mime_and_the_bytes() {
        let it = ClipboardContents::text("hello");
        assert_eq!(it.mime, MIME_TEXT);
        assert_eq!(it.bytes, b"hello");
        assert!(it.is_text());
    }

    #[test]
    fn debug_never_prints_the_bytes() {
        // A clipboard routinely holds a password. The Debug must show the shape
        // and nothing readable, the same guarantee identity and pairing keep.
        let secret = ClipboardContents::text("hunter2");
        let shown = format!("{secret:?}");
        assert!(!shown.contains("hunter2"), "the bytes leaked: {shown}");
        assert!(shown.contains('7'), "the length should be shown: {shown}");
    }

    #[test]
    fn a_foreign_mime_is_not_text() {
        let image = ClipboardContents {
            mime: "image/png".to_owned(),
            bytes: vec![0x89, b'P', b'N', b'G'],
        };
        assert!(!image.is_text());
    }
}
