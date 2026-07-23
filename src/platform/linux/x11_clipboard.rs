//! X11 clipboard, via selection ownership and XFixes.
//!
//! # Ownership is the clipboard
//!
//! X11 has no clipboard store. A selection is *owned* by a window, and a paste
//! is the server asking that window for the bytes. So offering a clipboard means
//! taking ownership of the `CLIPBOARD` selection on a window Wraith keeps alive,
//! and then answering every `SelectionRequest` that follows with the offered
//! bytes. The window is never mapped: it exists only to hold the selection and
//! receive those requests.
//!
//! # Watching is XFixes
//!
//! There is no event for "the clipboard changed" in core X. XFixes adds one:
//! `SelectionNotify` fires when any window takes the selection. When that owner
//! is another application, Wraith converts the selection to read the new copy;
//! when it is Wraith's own window, the notify is ignored, because that is the
//! echo of an offer Wraith just made and reporting it would loop a peer's
//! clipboard straight back to it.
//!
//! # One connection, one thread
//!
//! The owning window and the requests to it must share a connection, and that
//! connection is single-thread-affine, which is the whole reason the clipboard
//! runs on its own thread. `poll_change` is where the event queue is pumped:
//! serving pastes and detecting local copies happen in the same drain.

use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, SELECTION_NOTIFY_EVENT,
    SelectionNotifyEvent, SelectionRequestEvent, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

use crate::ports::clipboard::{Clipboard, ClipboardContents, ClipboardError, MIME_TEXT};

/// The largest selection Wraith reads from another application, in bytes.
///
/// A clipboard over a frame cannot cross yet anyway, so a larger local copy is
/// read up to here and no further rather than pulled in whole and then refused.
const READ_BYTES_MAX: u32 = 64 * 1024;

/// The XFixes version selection notifications arrived in.
const XFIXES_MAJOR: u32 = 5;
const XFIXES_MINOR: u32 = 0;

/// The atoms the selection protocol names.
struct Atoms {
    clipboard: Atom,
    targets: Atom,
    utf8_string: Atom,
    string: Atom,
    incr: Atom,
    /// Where a converted selection is delivered, on Wraith's own window.
    property: Atom,
}

/// Owns the `CLIPBOARD` selection and serves it.
pub struct X11Clipboard {
    conn: RustConnection,
    window: u32,
    atoms: Atoms,
    /// The bytes served to any application that pastes. `None` until an offer.
    offered: Option<Vec<u8>>,
    /// True between requesting a conversion and its `SelectionNotify`, so a
    /// notify that completes a read started in an earlier poll is still handled.
    converting: bool,
}

impl std::fmt::Debug for X11Clipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Clipboard")
            .field("window", &self.window)
            .field("offering", &self.offered.is_some())
            .finish_non_exhaustive()
    }
}

/// Maps any x11rb failure to a backend error.
fn backend(context: &str, error: impl std::fmt::Display) -> ClipboardError {
    ClipboardError::Backend(format!("{context}: {error}"))
}

impl X11Clipboard {
    /// Connects, creates the owning window, and arms the XFixes watch.
    pub fn open() -> Result<Self, ClipboardError> {
        let (conn, screen_num) =
            x11rb::connect(None).map_err(|error| backend("cannot reach the X display", error))?;
        let root = conn
            .setup()
            .roots
            .get(screen_num)
            .ok_or_else(|| ClipboardError::Backend("no screen on this display".to_owned()))?
            .root;

        // The reply is consumed rather than dropped: the extension is registered
        // for event decoding by the request itself, but awaiting the version
        // keeps this in step with the other backends and surfaces a refusal here
        // rather than later.
        conn.xfixes_query_version(XFIXES_MAJOR, XFIXES_MINOR)
            .map_err(|error| backend("the X server has no XFixes extension", error))?
            .reply()
            .map_err(|error| backend("cannot read the XFixes version", error))?;

        let atoms = intern_atoms(&conn)?;
        let window = create_owner_window(&conn, root)?;

        conn.xfixes_select_selection_input(
            window,
            atoms.clipboard,
            SelectionEventMask::SET_SELECTION_OWNER,
        )
        .map_err(|error| backend("cannot watch the clipboard", error))?;
        conn.flush()
            .map_err(|error| backend("cannot flush", error))?;

        Ok(Self {
            conn,
            window,
            atoms,
            offered: None,
            converting: false,
        })
    }

    /// Answers one `SelectionRequest` with the offered bytes, or refuses it.
    fn serve_request(&self, request: SelectionRequestEvent) -> Result<(), ClipboardError> {
        let property = self.fill_request(&request).unwrap_or(0);

        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: request.time,
            requestor: request.requestor,
            selection: request.selection,
            target: request.target,
            property,
        };
        self.conn
            .send_event(false, request.requestor, EventMask::NO_EVENT, notify)
            .map_err(|error| backend("cannot answer a paste", error))?;
        self.conn
            .flush()
            .map_err(|error| backend("cannot flush", error))?;
        Ok(())
    }

    /// Writes the requested target onto the requestor's property, or `None`.
    fn fill_request(&self, request: &SelectionRequestEvent) -> Option<Atom> {
        let offered = self.offered.as_ref()?;

        if request.target == self.atoms.targets {
            let targets = [
                self.atoms.targets,
                self.atoms.utf8_string,
                self.atoms.string,
            ];
            self.conn
                .change_property32(
                    PropMode::REPLACE,
                    request.requestor,
                    request.property,
                    x11rb::protocol::xproto::AtomEnum::ATOM,
                    &targets,
                )
                .ok()?;
            return Some(request.property);
        }

        if request.target == self.atoms.utf8_string || request.target == self.atoms.string {
            self.conn
                .change_property8(
                    PropMode::REPLACE,
                    request.requestor,
                    request.property,
                    request.target,
                    offered,
                )
                .ok()?;
            return Some(request.property);
        }

        None
    }

    /// Reacts to a new selection owner: another application's copy is read,
    /// Wraith's own is ignored as the echo of an offer it just made.
    fn note_new_owner(&mut self, owner: u32, time: u32) -> Result<(), ClipboardError> {
        if owner == self.window || owner == 0 {
            return Ok(());
        }
        // The one log that says the watch is alive: a local copy was seen and is
        // being read. Its absence in a trace means no XFixes owner-change arrived.
        tracing::debug!(owner, "a local clipboard change, reading it");
        self.conn
            .convert_selection(
                self.window,
                self.atoms.clipboard,
                self.atoms.utf8_string,
                self.atoms.property,
                time,
            )
            .map_err(|error| backend("cannot read the new clipboard", error))?;
        self.conn
            .flush()
            .map_err(|error| backend("cannot flush", error))?;
        self.converting = true;
        Ok(())
    }

    /// Reads a completed conversion off Wraith's own property.
    fn take_conversion(
        &mut self,
        property: Atom,
    ) -> Result<Option<ClipboardContents>, ClipboardError> {
        self.converting = false;
        if property == 0 {
            // The owner refused to convert to UTF8_STRING. Logged because it is
            // otherwise indistinguishable from nothing having been copied.
            tracing::debug!("the clipboard owner offered no text");
            return Ok(None);
        }

        let reply = self
            .conn
            .get_property(
                true,
                self.window,
                property,
                x11rb::protocol::xproto::AtomEnum::ANY,
                0,
                READ_BYTES_MAX / 4,
            )
            .map_err(|error| backend("cannot fetch the clipboard", error))?
            .reply()
            .map_err(|error| backend("cannot read the clipboard reply", error))?;

        // An INCR transfer means the copy is larger than one round trip, which
        // is larger than a frame will carry anyway. Left for the chunking phase.
        if reply.type_ == self.atoms.incr || reply.value.is_empty() {
            tracing::debug!(
                bytes = reply.value.len(),
                incr = reply.type_ == self.atoms.incr,
                "the clipboard copy is empty or too large to carry yet"
            );
            return Ok(None);
        }

        // We asked for UTF8_STRING, so trust the reply only if the owner answered
        // in a text type. Labelling anything else as text would carry bytes the
        // far side would then paste as mojibake.
        if reply.type_ != self.atoms.utf8_string && reply.type_ != self.atoms.string {
            tracing::debug!("the clipboard conversion returned a non-text type");
            return Ok(None);
        }

        Ok(Some(ClipboardContents {
            mime: MIME_TEXT.to_owned(),
            bytes: reply.value,
        }))
    }

    /// Handles one event, returning a local change if it was one.
    fn handle(&mut self, event: &Event) -> Result<Option<ClipboardContents>, ClipboardError> {
        match event {
            Event::SelectionRequest(request) => {
                self.serve_request(*request)?;
                Ok(None)
            }
            Event::XfixesSelectionNotify(notify) => {
                self.note_new_owner(notify.owner, notify.timestamp)?;
                Ok(None)
            }
            Event::SelectionNotify(notify) if self.converting => {
                self.take_conversion(notify.property)
            }
            _ => Ok(None),
        }
    }
}

impl Clipboard for X11Clipboard {
    fn set_offer(&mut self, contents: &ClipboardContents) -> Result<(), ClipboardError> {
        self.offered = Some(contents.bytes.clone());
        self.conn
            .set_selection_owner(self.window, self.atoms.clipboard, x11rb::CURRENT_TIME)
            .map_err(|error| backend("cannot take the clipboard", error))?;
        self.conn
            .flush()
            .map_err(|error| backend("cannot flush", error))?;
        Ok(())
    }

    fn poll_change(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<ClipboardContents>, ClipboardError> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            while let Some(event) = self
                .conn
                .poll_for_event()
                .map_err(|error| backend("cannot read events", error))?
            {
                if let Some(contents) = self.handle(&event)? {
                    return Ok(Some(contents));
                }
            }

            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn backend_name(&self) -> &'static str {
        "x11-clipboard"
    }
}

/// Interns every atom the protocol names, in one round trip each.
fn intern_atoms(conn: &RustConnection) -> Result<Atoms, ClipboardError> {
    let intern = |name: &[u8]| -> Result<Atom, ClipboardError> {
        Ok(conn
            .intern_atom(false, name)
            .map_err(|error| backend("cannot intern an atom", error))?
            .reply()
            .map_err(|error| backend("cannot read an atom", error))?
            .atom)
    };

    Ok(Atoms {
        clipboard: intern(b"CLIPBOARD")?,
        targets: intern(b"TARGETS")?,
        utf8_string: intern(b"UTF8_STRING")?,
        string: intern(b"STRING")?,
        incr: intern(b"INCR")?,
        property: intern(b"WRAITH_CLIPBOARD")?,
    })
}

/// Creates the unmapped window that holds the selection.
fn create_owner_window(conn: &RustConnection, root: u32) -> Result<u32, ClipboardError> {
    let window = conn
        .generate_id()
        .map_err(|error| backend("cannot allocate a window", error))?;

    conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        window,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        x11rb::COPY_FROM_PARENT,
        &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )
    .map_err(|error| backend("cannot create the owner window", error))?;

    Ok(window)
}
