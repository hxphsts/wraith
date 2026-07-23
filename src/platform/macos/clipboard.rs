//! macOS clipboard, via `NSPasteboard`.
//!
//! # A poll, not an event
//!
//! `NSPasteboard` has no change notification. The documented way to notice a new
//! copy is to read `changeCount`, an integer the system bumps on every write, and
//! compare it to the last value seen. So the watch is a poll: `poll_change`
//! sleeps for its budget, then checks whether the count moved. This is why the
//! port is shaped as a timeout poll rather than an evented wait, and why the
//! same shape suits X11 and wayland, where a real event exists, without harm.
//!
//! # No stored pasteboard
//!
//! `generalPasteboard` returns the one shared instance, cheap to fetch, so it is
//! fetched per call rather than held. That keeps this type free of any Objective-C
//! pointer, which is what lets it move to the clipboard thread as a plain `Send`
//! value with nothing to reason about.

use std::fmt;
use std::time::Duration;

use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::NSString;

use crate::ports::clipboard::{Clipboard, ClipboardContents, ClipboardError, MIME_TEXT};

/// Reads and writes this Mac's clipboard.
pub struct MacOsClipboard {
    /// The `changeCount` last seen. A poll compares against it to tell a new
    /// copy from no change.
    change_seen: isize,
    /// The bytes last offered, so this machine's own write is not read straight
    /// back as if it were a local copy. See the echo skip in `poll_change`.
    offered: Option<Vec<u8>>,
}

impl fmt::Debug for MacOsClipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the bytes. `offered` holds whatever was last copied, routinely a
        // password, so this reports only whether something is held, the same rule
        // the X11 backend and `ClipboardContents` keep.
        f.debug_struct("MacOsClipboard")
            .field("change_seen", &self.change_seen)
            .field("offering", &self.offered.is_some())
            .finish()
    }
}

impl MacOsClipboard {
    /// Reads the current change count so the first poll reports only what
    /// arrives after startup.
    pub fn open() -> Result<Self, ClipboardError> {
        Ok(Self {
            change_seen: NSPasteboard::generalPasteboard().changeCount(),
            offered: None,
        })
    }
}

impl Clipboard for MacOsClipboard {
    fn set_offer(&mut self, contents: &ClipboardContents) -> Result<(), ClipboardError> {
        let text = std::str::from_utf8(&contents.bytes)
            .map_err(|_| ClipboardError::Backend("the clipboard text was not utf-8".to_owned()))?;
        let string = NSString::from_str(text);

        let pasteboard = NSPasteboard::generalPasteboard();
        pasteboard.clearContents();

        // SAFETY: `NSPasteboardTypeString` is a framework constant, valid for the
        // life of the process.
        let type_ = unsafe { NSPasteboardTypeString };
        if !pasteboard.setString_forType(&string, type_) {
            return Err(ClipboardError::Backend(
                "the pasteboard refused the write".to_owned(),
            ));
        }

        // Record the count this write produced so the poll does not read it back.
        self.change_seen = pasteboard.changeCount();
        self.offered = Some(contents.bytes.clone());
        Ok(())
    }

    fn poll_change(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<ClipboardContents>, ClipboardError> {
        // No native event, so sleep the budget and then compare. The thread
        // calls this on a loop, which turns it into a steady poll.
        std::thread::sleep(Duration::from_millis(u64::from(timeout_ms)));

        let pasteboard = NSPasteboard::generalPasteboard();
        let now = pasteboard.changeCount();
        if now == self.change_seen {
            return Ok(None);
        }
        self.change_seen = now;

        // SAFETY: `NSPasteboardTypeString` is a framework constant, valid for the
        // life of the process.
        let type_ = unsafe { NSPasteboardTypeString };
        let Some(string) = pasteboard.stringForType(type_) else {
            // A non-text copy: an image, or files. Text only for now, so it is
            // left alone rather than mishandled.
            return Ok(None);
        };

        let bytes = string.to_string().into_bytes();
        if self.offered.as_ref() == Some(&bytes) {
            // This machine's own write, echoed back. Reporting it would hand a
            // peer's clipboard straight back to it on the next crossing.
            return Ok(None);
        }

        Ok(Some(ClipboardContents {
            mime: MIME_TEXT.to_owned(),
            bytes,
        }))
    }

    fn backend_name(&self) -> &'static str {
        "macos-pasteboard"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_bytes() {
        // The same guarantee the X11 backend and `ClipboardContents` keep: a
        // clipboard routinely holds a password, so its Debug shows the shape and
        // nothing readable. Built directly, since `open` needs a pasteboard.
        let held = MacOsClipboard {
            change_seen: 3,
            offered: Some(b"hunter2".to_vec()),
        };
        let shown = format!("{held:?}");
        assert!(!shown.contains("hunter2"), "the bytes leaked: {shown}");
        assert!(
            shown.contains("offering"),
            "the shape should be shown: {shown}"
        );
    }
}
