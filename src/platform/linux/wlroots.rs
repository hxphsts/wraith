//! wlroots injection, through the virtual pointer and keyboard protocols.
//!
//! # Who this is for
//!
//! Hyprland, Sway, Wayfire, niri, and river. None of them implement the
//! `RemoteDesktop` portal, and Deskflow closes reports from their users as
//! upstream's problem. See `research/01-competitive-landscape.md`.
//!
//! These two protocols are what lan-mouse and waynergy use to work there, and
//! they are the reason a portal-only design strands a large share of the Linux
//! users who actually want this tool.
//!
//! # What this covers
//!
//! Injection only, which makes a wlroots machine a **receiver**: the cursor can
//! cross onto it and typing lands. Capture, which would let it also be the
//! machine you type on, needs a layer-shell surface on each screen edge and is
//! the remaining piece. That asymmetry is fine for the common case, since the
//! machine with the keyboard is usually the one you are sitting at.
//!
//! # Keycodes
//!
//! `zwp_virtual_keyboard_v1` takes evdev codes directly, which is why the wire
//! carries them. No table, no offset, no translation.

use std::os::fd::AsFd as _;

use wayland_client::protocol::wl_pointer::{Axis, ButtonState};
use wayland_client::protocol::{wl_output, wl_registry, wl_seat};
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle};
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::{
    zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1,
    zwp_virtual_keyboard_v1::ZwpVirtualKeyboardV1,
};
use wayland_protocols_wlr::virtual_pointer::v1::client::{
    zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1,
    zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1,
};

use crate::domain::{Button, InputEvent, KeyState, Point, Scancode};
use crate::ports::inject::{Inject, InjectError};

/// What one detent of the wheel is worth on the continuous axis.
///
/// Fifteen is the convention every Wayland compositor and toolkit assumes, being
/// what X11 button 4 and 5 have always meant.
const DETENT_LENGTH: f64 = 15.0;

/// evdev button codes, which is what the virtual pointer protocol wants.
mod evdev_button {
    pub const LEFT: u32 = 0x110;
    pub const RIGHT: u32 = 0x111;
    pub const MIDDLE: u32 = 0x112;
    pub const SIDE: u32 = 0x113;
    pub const EXTRA: u32 = 0x114;
}

/// A minimal keymap the compositor can load.
///
/// The virtual keyboard protocol requires one before any key is sent. This says
/// "US layout, standard evdev rules", which is right because the codes on the
/// wire are already positions: the receiving machine's own layout is applied on
/// top, so a Dvorak user gets Dvorak whatever the sender has.
const KEYMAP: &str = r#"xkb_keymap {
    xkb_keycodes { include "evdev" };
    xkb_types    { include "complete" };
    xkb_compat   { include "complete" };
    xkb_symbols  { include "pc+us+inet(evdev)" };
};
"#;

/// Injects input into a wlroots compositor.
pub struct WlrootsInject {
    queue: EventQueue<State>,
    state: State,
    pointer: ZwlrVirtualPointerV1,
    keyboard: ZwpVirtualKeyboardV1,
    /// Where the pointer is believed to be, for absolute placement.
    ///
    /// The protocol has both relative and absolute motion, and relative is used
    /// for ordinary movement. This is only consulted for a warp on arrival.
    cursor: Point,
    width_px: u32,
    height_px: u32,
    /// A monotonically increasing millisecond stamp.
    ///
    /// The protocol wants a timestamp per event, and compositors use it to
    /// order and to detect stalls. A counter is enough: it only has to increase.
    time_ms: u32,
}

impl std::fmt::Debug for WlrootsInject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WlrootsInject")
            .field("cursor", &self.cursor)
            .field("width_px", &self.width_px)
            .field("height_px", &self.height_px)
            .finish_non_exhaustive()
    }
}

/// What the registry hands back.
///
/// Held for the life of the connection rather than read once. The seat and the
/// two managers own the globals the virtual devices are bound from, and dropping
/// them early destroys the devices this backend is made of.
#[derive(Default)]
struct State {
    seat: Option<wl_seat::WlSeat>,
    pointer_manager: Option<ZwlrVirtualPointerManagerV1>,
    keyboard_manager: Option<ZwpVirtualKeyboardManagerV1>,

    /// Bound purely to be told the mode, which is the one thing the compositor
    /// has to say that Wraith needs.
    output: Option<wl_output::WlOutput>,

    /// The current mode of the first output to report one, in pixels.
    ///
    /// `zwlr_virtual_pointer_v1.motion_absolute` takes a position as a fraction
    /// of an extent, so this is what an arrival is placed against. Guessing it
    /// puts every crossing in the wrong place by however far the guess is from
    /// the truth, and the error grows with the display.
    output_px: Option<(u32, u32)>,
}

impl State {
    /// Names the protocols a compositor is missing, for the error message.
    ///
    /// A user on GNOME needs to be told their compositor does not offer these
    /// rather than that something failed, because nothing is broken: they want
    /// the portal backend instead.
    fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.pointer_manager.is_none() {
            missing.push("zwlr_virtual_pointer_manager_v1");
        }
        if self.keyboard_manager.is_none() {
            missing.push("zwp_virtual_keyboard_manager_v1");
        }
        if self.seat.is_none() {
            missing.push("wl_seat");
        }
        missing
    }
}

impl WlrootsInject {
    /// Connects and binds the virtual devices.
    pub fn open() -> Result<Self, InjectError> {
        let connection = Connection::connect_to_env().map_err(|error| {
            InjectError::Backend(format!("cannot reach the Wayland compositor: {error}"))
        })?;

        let display = connection.display();
        let mut queue = connection.new_event_queue();
        let handle = queue.handle();
        display.get_registry(&handle, ());

        let mut state = State::default();
        queue.roundtrip(&mut state).map_err(|error| {
            InjectError::Backend(format!("cannot enumerate Wayland globals: {error}"))
        })?;

        let missing = state.missing();
        if !missing.is_empty() {
            return Err(InjectError::Backend(format!(
                "this compositor does not offer {}. That is normal on GNOME and KDE, which \
                 use the RemoteDesktop portal instead",
                missing.join(" or ")
            )));
        }

        let seat = state.seat.clone().expect("checked above");
        let pointer = state
            .pointer_manager
            .as_ref()
            .expect("checked above")
            .create_virtual_pointer(Some(&seat), &handle, ());

        let keyboard = state
            .keyboard_manager
            .as_ref()
            .expect("checked above")
            .create_virtual_keyboard(&seat, &handle, ());

        let mut inject = Self {
            queue,
            state,
            pointer,
            keyboard,
            cursor: Point::new(0, 0),
            // Replaced below by what the compositor reports. Kept as a fallback
            // rather than a failure because injection still works without an
            // output: only absolute placement needs the extent, and a receiver
            // that cannot be crossed onto precisely is better than one that
            // refuses to start.
            width_px: 1_920,
            height_px: 1_080,
            time_ms: 0,
        };

        inject.learn_output_size();
        inject.load_keymap()?;
        Ok(inject)
    }

    /// Asks the compositor how big the screen actually is.
    ///
    /// A second roundtrip, because binding `wl_output` in the first one is what
    /// makes it send its modes: they arrive after the bind rather than with it.
    ///
    /// Best effort by design. A compositor with no output, which is a headless
    /// one, can still receive keystrokes, and refusing to start there would
    /// trade a working receiver for an exact one.
    fn learn_output_size(&mut self) {
        if self.queue.roundtrip(&mut self.state).is_err() {
            tracing::debug!("no reply from the compositor about its outputs");
            return;
        }

        let Some((width_px, height_px)) = self.state.output_px else {
            tracing::warn!(
                width_px = self.width_px,
                height_px = self.height_px,
                "the compositor named no output, so absolute placement uses a default size"
            );
            return;
        };

        if width_px == 0 || height_px == 0 {
            return;
        }

        self.width_px = width_px;
        self.height_px = height_px;
        tracing::debug!(width_px, height_px, "the compositor reported its output");
    }

    /// Gives the compositor a keymap, which it demands before any key.
    ///
    /// Written to an anonymous file because the protocol passes it as a file
    /// descriptor rather than a string.
    fn load_keymap(&mut self) -> Result<(), InjectError> {
        use std::io::{Seek as _, SeekFrom, Write as _};

        let mut file = tempfile()?;
        file.write_all(KEYMAP.as_bytes())
            .map_err(|error| InjectError::Backend(format!("cannot write the keymap: {error}")))?;
        file.flush()
            .map_err(|error| InjectError::Backend(format!("cannot flush the keymap: {error}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| InjectError::Backend(format!("cannot rewind the keymap: {error}")))?;

        let size = u32::try_from(KEYMAP.len())
            .map_err(|_| InjectError::Backend("the keymap is implausibly large".to_owned()))?;

        // Format 1 is xkb_v1, the only one the protocol defines.
        self.keyboard.keymap(1, file.as_fd(), size);
        self.flush()
    }

    /// The next timestamp.
    ///
    /// Wrapping is fine and takes forty-nine days. Compositors care that the
    /// value moves forward, not what it means.
    const fn stamp(&mut self) -> u32 {
        self.time_ms = self.time_ms.wrapping_add(1);
        self.time_ms
    }

    fn emit_key(&mut self, code: Scancode, state: KeyState) {
        let time = self.stamp();
        let pressed = u32::from(state == KeyState::Pressed);

        // evdev codes go straight through. No offset, no table: this is why the
        // wire carries evdev in the first place.
        self.keyboard.key(time, u32::from(code.0), pressed);
    }

    fn emit_button(&mut self, button: Button, state: KeyState) {
        let time = self.stamp();
        let code = evdev_button_code(button);
        let pressed = if state == KeyState::Pressed {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };

        self.pointer.button(time, code, pressed);
        self.pointer.frame();
    }

    fn emit_motion(&mut self, dx_milli: i32, dy_milli: i32) {
        let (dx, dy) = (dx_milli / 1_000, dy_milli / 1_000);
        if dx == 0 && dy == 0 {
            // Sub-pixel motion. The protocol takes whole pixels as a fixed
            // point value, and sending zero would be a wasted round trip.
            return;
        }

        let time = self.stamp();
        self.cursor = Point::new(self.cursor.x_px + dx, self.cursor.y_px + dy);

        self.pointer.motion(time, f64::from(dx), f64::from(dy));
        self.pointer.frame();
    }

    fn emit_scroll(&mut self, h_v120: i32, v_v120: i32) {
        let time = self.stamp();

        // `axis_discrete` wants a count of detents in its last argument, not a
        // value120. They are the same word in two protocols and not the same
        // number: `wl_pointer.axis_value120` is 120 per detent, and passing that
        // here scrolls a hundred and twenty steps for one notch of the wheel.
        //
        // The axis argument beside it is the same motion expressed as a length,
        // and one detent is conventionally 15 there.
        if v_v120 != 0 {
            self.pointer.axis_discrete(
                time,
                Axis::VerticalScroll,
                f64::from(v_v120) * DETENT_LENGTH / 120.0,
                v_v120 / 120,
            );
        }
        if h_v120 != 0 {
            self.pointer.axis_discrete(
                time,
                Axis::HorizontalScroll,
                f64::from(h_v120) * DETENT_LENGTH / 120.0,
                h_v120 / 120,
            );
        }

        if v_v120 != 0 || h_v120 != 0 {
            self.pointer.frame();
        }
    }
}

impl crate::ports::ScreenInfo for WlrootsInject {
    /// What the compositor said its output was, read once at open.
    ///
    /// Wraith reports one logical screen per machine, so the first output is the
    /// answer even where there are several: a multi-monitor desktop is one
    /// continuous space that this compositor already manages.
    fn local_screen(&self) -> Result<crate::ports::LocalScreen, crate::ports::ScreenInfoError> {
        Ok(crate::ports::LocalScreen {
            width_px: self.width_px,
            height_px: self.height_px,
        })
    }

    /// Refused rather than guessed.
    ///
    /// The virtual pointer protocol is write-only: a compositor accepts motion
    /// and never says where the pointer ended up. Answering with `self.cursor`
    /// would return this backend's own last write, which is dead reckoning
    /// wearing the costume of a measurement, and `CursorMachine::resync` would
    /// then pin the position to wherever the last warp left it rather than
    /// correcting the drift it exists to correct.
    fn cursor_position(&self) -> Result<Point, crate::ports::ScreenInfoError> {
        Err(crate::ports::ScreenInfoError::Backend(
            "the wlroots virtual pointer protocol cannot report a position".to_owned(),
        ))
    }
}

impl Inject for WlrootsInject {
    fn emit(&mut self, events: &[InputEvent]) -> Result<(), InjectError> {
        // Nothing here can fail: every Wraith event has a wlroots equivalent,
        // because both speak evdev. Only the flush talks to the compositor, and
        // that is where a broken connection shows up.
        for &event in events {
            match event {
                InputEvent::Key { code, state } => self.emit_key(code, state),
                InputEvent::Button { button, state } => self.emit_button(button, state),
                InputEvent::MotionRel { dx_milli, dy_milli } => {
                    self.emit_motion(dx_milli, dy_milli);
                }
                InputEvent::Scroll { h_v120, v_v120 } => self.emit_scroll(h_v120, v_v120),
            }
        }
        self.flush()
    }

    fn warp_absolute(&mut self, at: Point) -> Result<(), InjectError> {
        let time = self.stamp();
        self.cursor = at;

        let x = u32::try_from(at.x_px).unwrap_or(0);
        let y = u32::try_from(at.y_px).unwrap_or(0);

        self.pointer
            .motion_absolute(time, x, y, self.width_px, self.height_px);
        self.pointer.frame();
        self.flush()
    }

    fn flush(&mut self) -> Result<(), InjectError> {
        // Wayland buffers requests, so nothing reaches the compositor until the
        // queue is flushed. Forgetting this is the classic way to have input
        // that arrives in bursts or not at all.
        self.queue.flush().map_err(|error| {
            InjectError::Backend(format!("cannot flush to the compositor: {error}"))
        })
    }

    fn releases_on_disconnect(&self) -> bool {
        // Destroying the virtual keyboard releases everything it was holding,
        // and the compositor destroys it when the client socket closes. So
        // unlike X11 XTEST, a killed Wraith leaves nothing held.
        true
    }

    fn backend_name(&self) -> &'static str {
        "wlroots-virtual"
    }
}

impl Drop for WlrootsInject {
    fn drop(&mut self) {
        // Explicit, rather than relying on the socket closing. A compositor
        // that is slow to notice the disconnect would otherwise hold a key for
        // as long as it took to notice.
        self.keyboard.destroy();
        self.pointer.destroy();
        let _ = self.queue.flush();
    }
}

/// A Wraith button as an evdev code.
const fn evdev_button_code(button: Button) -> u32 {
    match button {
        Button::Left => evdev_button::LEFT,
        Button::Right => evdev_button::RIGHT,
        Button::Middle => evdev_button::MIDDLE,
        Button::Back => evdev_button::SIDE,
        Button::Forward => evdev_button::EXTRA,
        // Anything else continues from the standard range rather than
        // colliding with it.
        Button::Other(n) => evdev_button::EXTRA + 1 + n as u32,
    }
}

/// An anonymous file for the keymap.
///
/// Anonymous for real, rather than a path in `/tmp` unlinked immediately after.
/// A name derived from the process id is one another account can guess and plant
/// a symlink at, and an open that creates and truncates follows it, emptying
/// whatever it points at. There is no window here because there is no name.
///
/// This is also what every other Wayland client does for a keymap.
fn tempfile() -> Result<std::fs::File, InjectError> {
    use std::os::fd::FromRawFd as _;

    // SAFETY: the name is a NUL terminated literal, and for `memfd_create` it
    // is only a label shown in /proc rather than a path anything resolves.
    let fd = unsafe { libc::memfd_create(c"wraith-keymap".as_ptr(), libc::MFD_CLOEXEC) };

    if fd < 0 {
        return Err(InjectError::Backend(format!(
            "cannot create a keymap file: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: a descriptor this call has just created and nothing else holds,
    // so taking ownership of it here cannot double close.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        (): &(),
        _connection: &Connection,
        handle: &QueueHandle<Self>,
    ) {
        let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        else {
            return;
        };

        match interface.as_str() {
            "wl_seat" => {
                state.seat = Some(registry.bind(name, version.min(7), handle, ()));
            }
            "zwlr_virtual_pointer_manager_v1" => {
                state.pointer_manager = Some(registry.bind(name, version.min(2), handle, ()));
            }
            "zwp_virtual_keyboard_manager_v1" => {
                state.keyboard_manager = Some(registry.bind(name, version.min(1), handle, ()));
            }
            // The first output only. Wraith crosses between machines, and a
            // multi-monitor desktop is one continuous space its own compositor
            // already manages, so there is nothing here to stitch together.
            "wl_output" if state.output.is_none() => {
                state.output = Some(registry.bind(name, version.min(2), handle, ()));
            }
            _ => {}
        }
    }
}

macro_rules! ignore_events {
    ($($kind:ty),* $(,)?) => {
        $(
            impl Dispatch<$kind, ()> for State {
                fn event(
                    _state: &mut Self,
                    _proxy: &$kind,
                    _event: <$kind as wayland_client::Proxy>::Event,
                    (): &(),
                    _connection: &Connection,
                    _handle: &QueueHandle<Self>,
                ) {
                    // None of these send anything Wraith needs. Injection is
                    // one-directional: the compositor has nothing to tell us.
                }
            }
        )*
    };
}

impl Dispatch<wl_output::WlOutput, ()> for State {
    fn event(
        state: &mut Self,
        _output: &wl_output::WlOutput,
        event: wl_output::Event,
        (): &(),
        _connection: &Connection,
        _handle: &QueueHandle<Self>,
    ) {
        // Only the mode flagged current. An output advertises every mode it can
        // do, and the others are what it is capable of rather than what it is
        // showing.
        let wl_output::Event::Mode {
            flags,
            width,
            height,
            ..
        } = event
        else {
            return;
        };

        if !matches!(flags, wayland_client::WEnum::Value(mode) if mode.contains(wl_output::Mode::Current))
        {
            return;
        }

        state.output_px = Some((
            u32::try_from(width).unwrap_or(0),
            u32::try_from(height).unwrap_or(0),
        ));
    }
}

ignore_events!(
    wl_seat::WlSeat,
    ZwlrVirtualPointerManagerV1,
    ZwlrVirtualPointerV1,
    ZwpVirtualKeyboardManagerV1,
    ZwpVirtualKeyboardV1,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keymap_file_works_and_has_no_path_to_plant_against() {
        // Needs no compositor: the point is that the descriptor is usable and
        // that nothing had to be named in a shared directory to get it.
        use std::io::{Read as _, Seek as _, Write as _};

        let mut file = tempfile().expect("no anonymous file");
        file.write_all(b"xkb_keymap {}").unwrap();
        file.rewind().unwrap();

        let mut back = String::new();
        file.read_to_string(&mut back).unwrap();

        assert_eq!(back, "xkb_keymap {}", "the keymap did not survive the file");
    }

    #[test]
    fn the_common_buttons_use_their_evdev_codes() {
        // The protocol takes evdev codes, and getting these wrong makes a left
        // click arrive as something else entirely.
        assert_eq!(evdev_button_code(Button::Left), 0x110);
        assert_eq!(evdev_button_code(Button::Right), 0x111);
        assert_eq!(evdev_button_code(Button::Middle), 0x112);
    }

    #[test]
    fn no_two_buttons_share_a_code() {
        let codes: Vec<u32> = [
            Button::Left,
            Button::Right,
            Button::Middle,
            Button::Back,
            Button::Forward,
            Button::Other(0),
            Button::Other(1),
        ]
        .into_iter()
        .map(evdev_button_code)
        .collect();

        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(unique.len(), codes.len(), "two buttons collide: {codes:?}");
    }

    #[test]
    fn an_exotic_button_does_not_collide_with_a_standard_one() {
        // Otherwise a mouse with extra buttons would send phantom clicks.
        assert!(evdev_button_code(Button::Other(0)) > evdev_button_code(Button::Forward));
    }

    #[test]
    fn the_keymap_names_the_evdev_rules() {
        // The codes on the wire are evdev positions, so the compositor must
        // interpret them with evdev rules or every key lands somewhere else.
        assert!(
            KEYMAP.contains("evdev"),
            "the keymap does not use evdev codes"
        );
        assert!(KEYMAP.contains("xkb_keymap"), "not a keymap at all");
    }

    #[test]
    fn a_compositor_missing_everything_names_everything() {
        // A GNOME user needs to be told their compositor does not offer these,
        // not that something failed, because nothing is broken: they want the
        // portal backend.
        let missing = State::default().missing();

        assert_eq!(missing.len(), 3);
        assert!(missing.contains(&"zwlr_virtual_pointer_manager_v1"));
        assert!(missing.contains(&"zwp_virtual_keyboard_manager_v1"));
    }
}
