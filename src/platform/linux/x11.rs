//! X11 injection, via the XTEST extension.
//!
//! # The one thing X11 cannot do
//!
//! XTEST has no notion of releasing a client's synthetic key presses when that
//! client dies. A process killed while holding a key leaves it held, with
//! nothing in the server that will ever change its mind.
//!
//! That is precisely why Deskflow's stuck modifier survives killing the process.
//! libei and the wlroots virtual keyboard both clean up when the client socket
//! closes, so the problem is worst on the oldest backend and there is no
//! in-process fix, because the process is gone.
//!
//! `wraith unstick` exists for exactly this case: a fresh process that opens its
//! own connection and releases everything. [`X11Inject`] reports
//! `releases_on_disconnect() == false` so the startup log says so out loud.

use x11rb::connection::{Connection, RequestConnection as _};
use x11rb::protocol::xproto::{ConnectionExt as _, Screen};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::domain::{Button, InputEvent, KeyState, Point, Scancode};
use crate::ports::inject::{Inject, InjectError};
use crate::ports::screen_info::{LocalScreen, ScreenInfo, ScreenInfoError};

/// X11 core protocol event types, as XTEST expects them.
mod event_type {
    pub const KEY_PRESS: u8 = 2;
    pub const KEY_RELEASE: u8 = 3;
    pub const BUTTON_PRESS: u8 = 4;
    pub const BUTTON_RELEASE: u8 = 5;
    pub const MOTION_NOTIFY: u8 = 6;
}

/// An evdev scancode plus this is the X11 keycode for the same physical key.
///
/// A fixed offset, not a lookup table. X11 reserves keycodes 0 through 7, and
/// the XKB evdev rules that every modern X server uses simply shift the kernel's
/// codes up past them. This is why evdev is the right canonical wire format: the
/// X11 translation is one addition.
pub(super) const EVDEV_TO_X11_KEYCODE_OFFSET: u16 = 8;

/// XTEST wants a relative motion flagged by passing this as the root window.
const RELATIVE_MOTION_ROOT: u32 = 0;

/// The most scroll clicks one event may turn into.
///
/// A bound on work rather than a tuning knob. Scroll units arrive from a peer,
/// and the loop that turns them into button presses is the one place in this
/// crate where a single frame's contents decide how long the injector thread is
/// busy. A real wheel sends a handful; a flick on a high-resolution trackpad
/// sends a few dozen.
const CLICKS_PER_EVENT_MAX: i32 = 64;

/// Injects input into an X11 display through XTEST.
pub struct X11Inject {
    connection: RustConnection,
    root: u32,
    width_px: u32,
    height_px: u32,
}

impl std::fmt::Debug for X11Inject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Inject")
            .field("root", &self.root)
            .field("width_px", &self.width_px)
            .field("height_px", &self.height_px)
            .finish_non_exhaustive()
    }
}

impl X11Inject {
    /// Connects to the display named by `DISPLAY` and checks XTEST is present.
    ///
    /// XTEST is compiled into every mainstream X server, but it can be disabled,
    /// and a missing extension must read as "this backend is unavailable" rather
    /// than surfacing later as every injection silently doing nothing.
    pub fn open() -> Result<Self, InjectError> {
        let (connection, screen_num) = x11rb::connect(None).map_err(|error| {
            InjectError::Backend(format!("cannot reach the X display: {error}"))
        })?;

        connection
            .extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)
            .map_err(|error| InjectError::Backend(format!("cannot query extensions: {error}")))?
            .ok_or_else(|| {
                InjectError::Backend(
                    "the X server has no XTEST extension, so input cannot be injected".to_owned(),
                )
            })?;

        let screen = screen_of(&connection, screen_num)?;

        Ok(Self {
            root: screen.root,
            width_px: u32::from(screen.width_in_pixels),
            height_px: u32::from(screen.height_in_pixels),
            connection,
        })
    }

    /// Sends one XTEST request.
    fn fake_input(
        &self,
        type_: u8,
        detail: u8,
        root: u32,
        x_px: i16,
        y_px: i16,
    ) -> Result<(), InjectError> {
        self.connection
            .xtest_fake_input(type_, detail, 0, root, x_px, y_px, 0)
            .map_err(|error| InjectError::Backend(format!("XTEST request failed: {error}")))?;
        Ok(())
    }

    fn emit_key(&self, code: Scancode, state: KeyState) -> Result<(), InjectError> {
        let keycode = code.0.saturating_add(EVDEV_TO_X11_KEYCODE_OFFSET);
        let detail = u8::try_from(keycode).map_err(|_| {
            InjectError::Unrepresentable(format!(
                "scancode {} is beyond the X11 keycode range",
                code.0
            ))
        })?;

        let type_ = match state {
            KeyState::Pressed => event_type::KEY_PRESS,
            KeyState::Released => event_type::KEY_RELEASE,
        };
        self.fake_input(type_, detail, self.root, 0, 0)
    }

    fn emit_button(&self, button: Button, state: KeyState) -> Result<(), InjectError> {
        let type_ = match state {
            KeyState::Pressed => event_type::BUTTON_PRESS,
            KeyState::Released => event_type::BUTTON_RELEASE,
        };
        self.fake_input(type_, x11_button(button)?, self.root, 0, 0)
    }

    fn emit_motion(&self, dx_milli: i32, dy_milli: i32) -> Result<(), InjectError> {
        let dx_px = clamp_to_i16(dx_milli / 1_000);
        let dy_px = clamp_to_i16(dy_milli / 1_000);

        if dx_px == 0 && dy_px == 0 {
            // Sub-pixel motion. Dropping it is correct: X11 has no sub-pixel
            // pointer position, so sending a zero-delta motion would be a wasted
            // round trip that moves nothing.
            return Ok(());
        }
        self.fake_input(
            event_type::MOTION_NOTIFY,
            1,
            RELATIVE_MOTION_ROOT,
            dx_px,
            dy_px,
        )
    }

    fn emit_scroll(&self, h_v120: i32, v_v120: i32) -> Result<(), InjectError> {
        // X11 has no scroll axis. It has buttons 4 through 7, one click each, so
        // a high-resolution wheel reporting 15 units of 120 accumulates nothing
        // and correctly produces no click.
        for (units, positive, negative) in [(v_v120, 5u8, 4u8), (h_v120, 7u8, 6u8)] {
            let button = if units / 120 > 0 { positive } else { negative };

            for _ in 0..scroll_clicks(units) {
                self.fake_input(event_type::BUTTON_PRESS, button, self.root, 0, 0)?;
                self.fake_input(event_type::BUTTON_RELEASE, button, self.root, 0, 0)?;
            }
        }
        Ok(())
    }
}

impl Inject for X11Inject {
    fn pointer(&self) -> Option<&dyn crate::ports::ScreenInfo> {
        Some(self)
    }

    fn emit(&mut self, events: &[InputEvent]) -> Result<(), InjectError> {
        for &event in events {
            let sent = match event {
                InputEvent::Key { code, state } => self.emit_key(code, state),
                InputEvent::Button { button, state } => self.emit_button(button, state),
                InputEvent::MotionRel { dx_milli, dy_milli } => {
                    self.emit_motion(dx_milli, dy_milli)
                }
                InputEvent::Scroll { h_v120, v_v120 } => self.emit_scroll(h_v120, v_v120),
            };

            match sent {
                Ok(()) => {}
                // An event X11 has no way to express is skipped, not fatal. One
                // exotic key must never abort the rest of a batch, because that
                // batch is often a chord release and abandoning it halfway is
                // exactly the failure this project exists to prevent.
                Err(InjectError::Unrepresentable(what)) => {
                    tracing::debug!(reason = %what, "skipping an event X11 cannot express");
                }
                Err(error) => return Err(error),
            }
        }
        self.flush()
    }

    fn warp_absolute(&mut self, at: Point) -> Result<(), InjectError> {
        self.fake_input(
            event_type::MOTION_NOTIFY,
            0,
            self.root,
            clamp_to_i16(at.x_px),
            clamp_to_i16(at.y_px),
        )?;
        self.flush()
    }

    fn flush(&mut self) -> Result<(), InjectError> {
        self.connection
            .flush()
            .map_err(|error| InjectError::Backend(format!("cannot flush to the X server: {error}")))
    }

    fn releases_on_disconnect(&self) -> bool {
        // See the module documentation. XTEST has no such notion, and this
        // returning false is what makes the startup warning appear.
        false
    }

    fn held_keys(&self) -> Option<Vec<Scancode>> {
        // QueryKeymap returns a 32-byte bitmap of the physical key state as the
        // server sees it, which is the ground truth a sweep can be checked
        // against. Reporting None on failure rather than an error, because a
        // diagnostic that cannot run must not fail the operation it describes.
        let keymap = self.connection.query_keymap().ok()?.reply().ok()?;

        let held = keymap
            .keys
            .iter()
            .enumerate()
            .flat_map(|(byte, bits)| {
                (0..8u16).filter_map(move |bit| {
                    if bits & (1 << bit) == 0 {
                        return None;
                    }
                    let keycode = u16::try_from(byte).ok()? * 8 + bit;
                    keycode
                        .checked_sub(EVDEV_TO_X11_KEYCODE_OFFSET)
                        .map(Scancode)
                })
            })
            .collect();

        Some(held)
    }

    fn backend_name(&self) -> &'static str {
        "x11-xtest"
    }
}

impl ScreenInfo for X11Inject {
    fn local_screen(&self) -> Result<LocalScreen, ScreenInfoError> {
        Ok(LocalScreen {
            width_px: self.width_px,
            height_px: self.height_px,
        })
    }

    fn cursor_position(&self) -> Result<Point, ScreenInfoError> {
        let reply = self
            .connection
            .query_pointer(self.root)
            .map_err(|error| {
                ScreenInfoError::Backend(format!("cannot query the pointer: {error}"))
            })?
            .reply()
            .map_err(|error| {
                ScreenInfoError::Backend(format!("the pointer query failed: {error}"))
            })?;

        Ok(Point::new(i32::from(reply.root_x), i32::from(reply.root_y)))
    }
}

fn screen_of(connection: &RustConnection, index: usize) -> Result<Screen, InjectError> {
    connection
        .setup()
        .roots
        .get(index)
        .cloned()
        .ok_or_else(|| InjectError::Backend(format!("the X server has no screen {index}")))
}

/// How many button presses a scroll value becomes.
///
/// Clamped, and that is the point of the function. The value arrives in a
/// datagram from a peer that is authenticated but whose content is still
/// untrusted, and this is the one loop in the crate whose length a single frame
/// decides. Unbounded, `i32::MAX` is seventeen million XTEST round trips on the
/// injector thread, which is the whole session wedged by one malformed frame.
fn scroll_clicks(units: i32) -> i32 {
    (units / 120).saturating_abs().min(CLICKS_PER_EVENT_MAX)
}

/// A Wraith button as an X11 button number.
///
/// X11 numbers buttons from one, and reserves four through seven for scroll, so
/// the back and forward buttons land at eight and nine.
fn x11_button(button: Button) -> Result<u8, InjectError> {
    Ok(match button {
        Button::Left => 1,
        Button::Middle => 2,
        Button::Right => 3,
        Button::Back => 8,
        Button::Forward => 9,
        // X11 numbers buttons from one, so zero has no meaning. Dropping the
        // event is right: the session should not end over an exotic button.
        Button::Other(0) => {
            return Err(InjectError::Unrepresentable(
                "button 0 has no X11 number".to_owned(),
            ));
        }
        Button::Other(n) => n,
    })
}

/// A pixel coordinate as the `i16` the X11 wire format uses.
///
/// Saturating rather than truncating. A wrap here would place the cursor at the
/// opposite edge of the screen, which is the worst possible failure for a tool
/// whose entire job is putting the cursor where the user meant.
fn clamp_to_i16(value: i32) -> i16 {
    i16::try_from(value).unwrap_or_else(|_| {
        if value.is_negative() {
            i16::MIN
        } else {
            i16::MAX
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_evdev_scancode_is_an_x11_keycode_minus_eight() {
        // KEY_A is 30 in evdev and 38 in X11. If this offset is ever wrong,
        // every keystroke lands as a different letter, so it is worth pinning.
        assert_eq!(Scancode(30).0 + EVDEV_TO_X11_KEYCODE_OFFSET, 38);
        assert_eq!(Scancode(1).0 + EVDEV_TO_X11_KEYCODE_OFFSET, 9, "Escape");
        assert_eq!(
            Scancode(42).0 + EVDEV_TO_X11_KEYCODE_OFFSET,
            50,
            "left shift"
        );
    }

    #[test]
    fn the_common_buttons_map_to_the_x11_numbering() {
        assert_eq!(x11_button(Button::Left).unwrap(), 1);
        assert_eq!(x11_button(Button::Middle).unwrap(), 2);
        assert_eq!(x11_button(Button::Right).unwrap(), 3);
    }

    #[test]
    fn a_hostile_scroll_value_cannot_wedge_the_injector_thread() {
        // The bound is the whole reason this function exists. Without it one
        // datagram is seventeen million round trips.
        assert_eq!(scroll_clicks(i32::MAX), CLICKS_PER_EVENT_MAX);
        assert_eq!(scroll_clicks(i32::MIN), CLICKS_PER_EVENT_MAX);
    }

    #[test]
    fn ordinary_scrolling_is_untouched_by_the_bound() {
        // One detent, either way, and a high-resolution wheel reporting less
        // than a detent, which correctly produces nothing.
        assert_eq!(scroll_clicks(120), 1);
        assert_eq!(scroll_clicks(-120), 1);
        assert_eq!(scroll_clicks(15), 0);
        assert_eq!(scroll_clicks(0), 0);
        assert_eq!(scroll_clicks(120 * 5), 5);
    }

    #[test]
    fn back_and_forward_skip_the_scroll_button_range() {
        // Four through seven are the scroll wheel in X11, so back and forward
        // must not collide with them.
        assert_eq!(x11_button(Button::Back).unwrap(), 8);
        assert_eq!(x11_button(Button::Forward).unwrap(), 9);
    }

    #[test]
    fn coordinates_beyond_the_wire_format_saturate_rather_than_wrapping() {
        // Wrapping would put the cursor at the opposite edge of the screen.
        assert_eq!(clamp_to_i16(100_000), i16::MAX);
        assert_eq!(clamp_to_i16(-100_000), i16::MIN);
        assert_eq!(clamp_to_i16(960), 960);
    }
}
