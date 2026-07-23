//! X11 capture, via XInput2 raw events.
//!
//! # Observing and suppressing are the same mechanism
//!
//! Raw events are delivered to every listener on the root window, which gives
//! observation. The X specification adds one clause that makes them also give
//! suppression: **while a grab is active, raw events go only to the grabbing
//! client.**
//!
//! So a single selection covers both modes. Ungrabbed, Wraith sees the input and
//! so does the focused application. Grabbed, Wraith sees it and nobody else
//! does. No second mechanism, and no window to keep focused.
//!
//! # Why raw events rather than ordinary ones
//!
//! Raw events carry `axisvalues_raw`, the pointer deltas before the server
//! applies its acceleration curve. That is what a KVM wants: the far machine
//! will apply its own acceleration, and passing already-accelerated deltas would
//! apply it twice and make the pointer feel wrong in a way that is hard to name.
//!
//! They also carry the hardware keycode rather than a keysym, which is the same
//! evdev-plus-eight space the injection side uses. See
//! `EVDEV_TO_X11_KEYCODE_OFFSET` in the sibling injection module.
//!
//! # The feedback loop
//!
//! XTEST events are indistinguishable from real ones to almost everything, so a
//! machine's own capture sees the input it injects. Left alone that is a loop:
//! the receiving machine injects, captures its own injection, and if its cursor
//! happens to be remote, forwards it straight back.
//!
//! Raw events carry a `sourceid` naming the device they came from, and XTEST
//! synthesises through dedicated virtual devices. Ignoring those devices breaks
//! the loop at its source, which is better than trying to recognise the events
//! after the fact.
//!
//! The cost is that **all** XTEST input is ignored, not only Wraith's own. X11
//! routes every client's XTEST through the same two virtual devices, so there is
//! no way to tell ours from `xdotool`'s. Automation tools driving this machine
//! therefore do not cross to another screen. That is the right trade: the
//! alternative is two peers forwarding the same keystroke to each other forever.
//!
//! It also means `xdotool` cannot be used to simulate user input in a test of
//! the crossing logic, which is why that lives in `tests/two_machines.rs`
//! against the ports rather than against a display server.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::Duration;

use x11rb::connection::{Connection, RequestConnection as _};
use x11rb::protocol::Event;
use x11rb::protocol::xinput::{
    self, ConnectionExt as _, Device, DeviceType, EventMask, XIEventMask,
};
use x11rb::protocol::xproto::{GrabMode, GrabStatus};
use x11rb::rust_connection::RustConnection;

use super::x11::EVDEV_TO_X11_KEYCODE_OFFSET;
use crate::domain::{Button, InputEvent, KeyState, Scancode};
use crate::ports::capture::{Capture, CaptureError};

/// How many events may queue before the reader thread starts dropping.
///
/// A thousand is roughly one second of a 1000 Hz pointer. If the consumer falls
/// that far behind, the oldest samples are already stale, and dropping motion is
/// the correct failure. Transitions are never dropped: see [`Reader::send`].
const QUEUE_CAPACITY: usize = 1_024;

/// The XInput2 version Wraith needs. Raw events arrived in 2.0.
const XI_MAJOR: u16 = 2;
const XI_MINOR: u16 = 0;

/// Captures input from an X11 display.
pub struct X11Capture {
    /// Shared with the reader thread, and that sharing is load bearing.
    ///
    /// During a grab the X server delivers raw events only to **the grabbing
    /// client**. A grab issued on a second connection would therefore suppress
    /// input from the desktop and from Wraith alike, which is the worst of both
    /// outcomes. One connection means one client, so the grab and the event
    /// selection are the same principal.
    ///
    /// `RustConnection` is internally locked and designed for exactly this: one
    /// thread blocking in `wait_for_event` while another sends requests.
    control: Arc<RustConnection>,
    root: u32,
    /// The master pointer and keyboard, which is what a grab must name.
    ///
    /// XIGrabDevice rejects ALL_MASTER with a BadDevice error, so the devices
    /// have to be enumerated and taken individually. Both, always: grabbing one
    /// without the other would leave half the input reaching the local desktop.
    masters: Vec<u16>,
    events: Receiver<InputEvent>,
    suppressed: bool,
}

impl std::fmt::Debug for X11Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Capture")
            .field("root", &self.root)
            .field("suppressed", &self.suppressed)
            .finish_non_exhaustive()
    }
}

impl X11Capture {
    /// Connects, checks XInput2, and starts the reader thread.
    pub fn open() -> Result<Self, CaptureError> {
        let (control, screen_num) = x11rb::connect(None).map_err(|error| {
            CaptureError::Backend(format!("cannot reach the X display: {error}"))
        })?;
        let control = Arc::new(control);

        check_xinput(&control)?;

        let root = control
            .setup()
            .roots
            .get(screen_num)
            .ok_or_else(|| CaptureError::Backend(format!("no screen {screen_num}")))?
            .root;

        let masters = master_devices(&control)?;
        let synthetic = synthetic_devices(&control)?;
        tracing::debug!(?synthetic, "ignoring these devices as our own injection");
        if masters.is_empty() {
            return Err(CaptureError::Backend(
                "the X server reports no master input devices, so there is nothing to grab"
                    .to_owned(),
            ));
        }

        let (sender, events) = sync_channel(QUEUE_CAPACITY);
        // The reader owns the list, since it is the only thing that filters.
        spawn_reader(&control, root, synthetic, sender)?;

        Ok(Self {
            control,
            root,
            masters,
            events,
            suppressed: false,
        })
    }

    fn grab(&self) -> Result<(), CaptureError> {
        for (taken, &device) in self.masters.iter().enumerate() {
            let outcome = self.grab_one(device);

            if let Err(error) = outcome {
                // Half a grab is worse than none: the pointer would be captured
                // while the keyboard still typed into the local desktop. Undo
                // whatever succeeded before giving up.
                for &done in &self.masters[..taken] {
                    let _ = self.ungrab_one(done);
                }
                let _ = self.control.flush();
                return Err(error);
            }
        }

        self.control
            .flush()
            .map_err(|error| CaptureError::Backend(format!("cannot flush: {error}")))
    }

    fn grab_one(&self, device: u16) -> Result<(), CaptureError> {
        let reply = self
            .control
            .xinput_xi_grab_device(
                self.root,
                x11rb::CURRENT_TIME,
                0,
                device,
                GrabMode::ASYNC,
                GrabMode::ASYNC,
                // NO_OWNER, so nothing reaches the ordinary client stack while
                // the grab is held.
                xinput::GrabOwner::NO_OWNER,
                &[u32::from(raw_event_mask())],
            )
            .map_err(|error| CaptureError::Backend(format!("grab request failed: {error}")))?
            .reply()
            .map_err(|error| CaptureError::Backend(format!("grab failed: {error}")))?;

        if reply.status == GrabStatus::SUCCESS {
            return Ok(());
        }

        Err(CaptureError::Backend(format!(
            "the X server refused to grab device {device}: {:?}. Another client is probably \
             already grabbing, which an open menu or an active drag will do",
            reply.status
        )))
    }

    fn ungrab_one(&self, device: u16) -> Result<(), CaptureError> {
        self.control
            .xinput_xi_ungrab_device(x11rb::CURRENT_TIME, device)
            .map_err(|error| CaptureError::Backend(format!("ungrab request failed: {error}")))?;
        Ok(())
    }

    fn ungrab(&self) -> Result<(), CaptureError> {
        // Every device is attempted even if one fails, because a device left
        // grabbed locks the user out of their own machine.
        let mut first_error = None;
        for &device in &self.masters {
            if let Err(error) = self.ungrab_one(device) {
                first_error.get_or_insert(error);
            }
        }

        self.control
            .flush()
            .map_err(|error| CaptureError::Backend(format!("cannot flush: {error}")))?;

        first_error.map_or(Ok(()), Err)
    }
}

impl Capture for X11Capture {
    fn poll(&mut self, timeout_ms: u32, out: &mut Vec<InputEvent>) -> Result<(), CaptureError> {
        match self
            .events
            .recv_timeout(Duration::from_millis(u64::from(timeout_ms)))
        {
            Ok(event) => out.push(event),
            // A quiet keyboard, which is the common case rather than an error.
            Err(RecvTimeoutError::Timeout) => return Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                return Err(CaptureError::SessionLost(
                    "the X11 reader thread stopped, so the display server has gone away".to_owned(),
                ));
            }
        }

        // Drain whatever else is already queued, so one poll can return a burst
        // rather than making the caller round-trip per event.
        while let Ok(event) = self.events.try_recv() {
            out.push(event);
        }
        Ok(())
    }

    fn set_suppressed(&mut self, suppressed: bool) -> Result<(), CaptureError> {
        if suppressed == self.suppressed {
            return Ok(());
        }

        if suppressed {
            self.grab()?;
        } else {
            self.ungrab()?;
        }

        self.suppressed = suppressed;
        tracing::debug!(suppressed, "local input suppression changed");
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "x11-xinput2"
    }
}

impl Drop for X11Capture {
    fn drop(&mut self) {
        // Releasing the grab matters more than most cleanup. A leaked device
        // grab leaves the user unable to type into anything at all, which is a
        // considerably worse outcome than the stuck key this project is about.
        if self.suppressed
            && let Err(error) = self.ungrab()
        {
            tracing::error!(%error, "could not release the device grab on shutdown");
        }
    }
}

/// The device an event came from, for the events that name one.
const fn source_of(event: &Event) -> Option<u16> {
    match event {
        Event::XinputRawKeyPress(raw) | Event::XinputRawKeyRelease(raw) => Some(raw.sourceid),
        Event::XinputRawButtonPress(raw)
        | Event::XinputRawButtonRelease(raw)
        | Event::XinputRawMotion(raw) => Some(raw.sourceid),
        _ => None,
    }
}

/// The XTEST virtual devices.
///
/// Found by name because XInput2 has no flag for "this device is synthetic".
/// The X server names them "Virtual core XTEST pointer" and "Virtual core XTEST
/// keyboard", and has done since XInput2 shipped.
fn synthetic_devices(connection: &RustConnection) -> Result<Vec<u16>, CaptureError> {
    let reply = connection
        .xinput_xi_query_device(Device::ALL)
        .map_err(|error| CaptureError::Backend(format!("cannot list devices: {error}")))?
        .reply()
        .map_err(|error| CaptureError::Backend(format!("device query failed: {error}")))?;

    Ok(reply
        .infos
        .iter()
        .filter(|info| is_xtest_device(&info.name))
        .map(|info| info.deviceid)
        .collect())
}

/// Whether a device name identifies an XTEST virtual device.
fn is_xtest_device(name: &[u8]) -> bool {
    String::from_utf8_lossy(name)
        .to_ascii_uppercase()
        .contains("XTEST")
}

/// The master pointer and master keyboard device ids.
fn master_devices(connection: &RustConnection) -> Result<Vec<u16>, CaptureError> {
    let reply = connection
        .xinput_xi_query_device(Device::ALL)
        .map_err(|error| CaptureError::Backend(format!("cannot list devices: {error}")))?
        .reply()
        .map_err(|error| CaptureError::Backend(format!("device query failed: {error}")))?;

    Ok(reply
        .infos
        .iter()
        .filter(|info| {
            info.enabled
                && matches!(
                    info.type_,
                    DeviceType::MASTER_POINTER | DeviceType::MASTER_KEYBOARD
                )
        })
        .map(|info| info.deviceid)
        .collect())
}

fn check_xinput(connection: &RustConnection) -> Result<(), CaptureError> {
    connection
        .extension_information(xinput::X11_EXTENSION_NAME)
        .map_err(|error| CaptureError::Backend(format!("cannot query extensions: {error}")))?
        .ok_or_else(|| CaptureError::Backend("the X server has no XInput extension".to_owned()))?;

    let version = connection
        .xinput_xi_query_version(XI_MAJOR, XI_MINOR)
        .map_err(|error| CaptureError::Backend(format!("cannot query XInput: {error}")))?
        .reply()
        .map_err(|error| CaptureError::Backend(format!("XInput version query failed: {error}")))?;

    if version.major_version < XI_MAJOR {
        return Err(CaptureError::Backend(format!(
            "the X server offers XInput {}.{}, and raw events need {XI_MAJOR}.{XI_MINOR}",
            version.major_version, version.minor_version
        )));
    }
    Ok(())
}

/// Every raw input event Wraith cares about.
fn raw_event_mask() -> XIEventMask {
    XIEventMask::RAW_KEY_PRESS
        | XIEventMask::RAW_KEY_RELEASE
        | XIEventMask::RAW_BUTTON_PRESS
        | XIEventMask::RAW_BUTTON_RELEASE
        | XIEventMask::RAW_MOTION
}

/// Selects raw events and starts the thread that reads them.
///
/// A dedicated thread because `wait_for_event` blocks, and the [`Capture`]
/// contract is a bounded poll. The thread ends when the channel is dropped.
fn spawn_reader(
    connection: &Arc<RustConnection>,
    root: u32,
    synthetic: Vec<u16>,
    sender: SyncSender<InputEvent>,
) -> Result<(), CaptureError> {
    connection
        .xinput_xi_select_events(
            root,
            &[EventMask {
                deviceid: Device::ALL_MASTER.into(),
                mask: vec![raw_event_mask()],
            }],
        )
        .map_err(|error| CaptureError::Backend(format!("cannot select raw events: {error}")))?;

    connection
        .flush()
        .map_err(|error| CaptureError::Backend(format!("cannot flush: {error}")))?;

    let connection = Arc::clone(connection);
    std::thread::Builder::new()
        .name("wraith-x11-capture".to_owned())
        .spawn(move || {
            Reader {
                connection,
                synthetic,
                sender,
            }
            .run();
        })
        .map_err(|error| CaptureError::Backend(format!("cannot start the reader: {error}")))?;

    Ok(())
}

struct Reader {
    connection: Arc<RustConnection>,
    synthetic: Vec<u16>,
    sender: SyncSender<InputEvent>,
}

impl Reader {
    fn run(self) {
        loop {
            match self.connection.wait_for_event() {
                // The receiver being gone means the session ended.
                Ok(event) => {
                    if source_of(&event).is_some_and(|id| self.synthetic.contains(&id)) {
                        // Our own injection coming back around.
                        continue;
                    }
                    if let Some(input) = translate(&event)
                        && self.send(input).is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "the X11 capture connection ended");
                    return;
                }
            }
        }
    }

    /// Queues an event, preferring to drop motion over blocking.
    ///
    /// A full queue means the consumer is a second behind, at which point the
    /// oldest motion samples are worthless. But a transition must never be
    /// dropped, because losing one desynchronises the receiver's held set, which
    /// is the entire failure this project exists to prevent. So transitions
    /// block and motion does not.
    fn send(&self, event: InputEvent) -> Result<(), ()> {
        if event.is_transition() {
            return self.sender.send(event).map_err(|_| ());
        }

        match self.sender.try_send(event) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                tracing::trace!("dropping a motion sample, the consumer is behind");
                Ok(())
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(()),
        }
    }
}

/// An X11 event as a Wraith one, or `None` if it is not input.
fn translate(event: &Event) -> Option<InputEvent> {
    match event {
        Event::XinputRawKeyPress(raw) => Some(key(raw.detail, KeyState::Pressed)),
        Event::XinputRawKeyRelease(raw) => Some(key(raw.detail, KeyState::Released)),
        Event::XinputRawButtonPress(raw) => button_or_scroll(raw.detail, KeyState::Pressed),
        Event::XinputRawButtonRelease(raw) => button_or_scroll(raw.detail, KeyState::Released),
        Event::XinputRawMotion(raw) => motion(&raw.axisvalues_raw),
        _ => None,
    }
}

fn key(x11_keycode: u32, state: KeyState) -> InputEvent {
    // Saturating rather than wrapping: an out-of-range keycode should read as
    // "the lowest key" rather than as some unrelated key near the top.
    let code = u16::try_from(x11_keycode)
        .unwrap_or(u16::MAX)
        .saturating_sub(EVDEV_TO_X11_KEYCODE_OFFSET);

    InputEvent::Key {
        code: Scancode(code),
        state,
    }
}

/// X11 buttons four through seven are the scroll wheel, not buttons.
///
/// Only a press is turned into scroll, because X11 sends a press and release
/// pair per click and emitting both would double every scroll.
fn button_or_scroll(detail: u32, state: KeyState) -> Option<InputEvent> {
    match detail {
        1 => Some(InputEvent::Button {
            button: Button::Left,
            state,
        }),
        2 => Some(InputEvent::Button {
            button: Button::Middle,
            state,
        }),
        3 => Some(InputEvent::Button {
            button: Button::Right,
            state,
        }),
        4..=7 if state == KeyState::Released => None,
        4 => Some(InputEvent::Scroll {
            h_v120: 0,
            v_v120: 120,
        }),
        5 => Some(InputEvent::Scroll {
            h_v120: 0,
            v_v120: -120,
        }),
        6 => Some(InputEvent::Scroll {
            h_v120: -120,
            v_v120: 0,
        }),
        7 => Some(InputEvent::Scroll {
            h_v120: 120,
            v_v120: 0,
        }),
        8 => Some(InputEvent::Button {
            button: Button::Back,
            state,
        }),
        9 => Some(InputEvent::Button {
            button: Button::Forward,
            state,
        }),
        other => u8::try_from(other).ok().map(|n| InputEvent::Button {
            button: Button::Other(n),
            state,
        }),
    }
}

/// Raw pointer deltas, in thousandths of a pixel.
///
/// `axisvalues_raw` is unaccelerated, which is what the far machine needs so it
/// can apply its own curve rather than inheriting ours on top of its own.
fn motion(axes: &[xinput::Fp3232]) -> Option<InputEvent> {
    let dx_milli = axes.first().copied().map_or(0, fp3232_to_milli);
    let dy_milli = axes.get(1).copied().map_or(0, fp3232_to_milli);

    if dx_milli == 0 && dy_milli == 0 {
        return None;
    }
    Some(InputEvent::MotionRel { dx_milli, dy_milli })
}

/// An X11 fixed-point value as thousandths.
///
/// `Fp3232` is a signed 32-bit integer part and an unsigned 32-bit fraction, and
/// the value is `integral + frac / 2^32`. The fraction is always added, never
/// subtracted, because X produces the pair by flooring: -1.5 arrives as an
/// integral of -2 and a fraction of a half, not as -1 and a negative half.
///
/// Multiplying the fraction by 1000 before shifting keeps three decimal places
/// without floating point, so the conversion is exact and reproducible in tests.
fn fp3232_to_milli(value: xinput::Fp3232) -> i32 {
    let whole = value.integral.saturating_mul(1_000);
    let fraction = i32::try_from((u64::from(value.frac) * 1_000) >> 32).unwrap_or(0);

    whole.saturating_add(fraction)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(integral: i32, frac: u32) -> xinput::Fp3232 {
        xinput::Fp3232 { integral, frac }
    }

    #[test]
    fn the_xtest_devices_are_recognised_by_name() {
        // The only handle X gives us. If the naming ever changes, a machine
        // starts capturing its own injection and two peers ping-pong forever.
        assert!(is_xtest_device(b"Virtual core XTEST pointer"));
        assert!(is_xtest_device(b"Virtual core XTEST keyboard"));
    }

    #[test]
    fn a_real_device_is_not_mistaken_for_xtest() {
        // A false positive here silently drops the user's actual keyboard.
        assert!(!is_xtest_device(b"Virtual core pointer"));
        assert!(!is_xtest_device(b"Virtual core keyboard"));
        assert!(!is_xtest_device(b"AT Translated Set 2 keyboard"));
        assert!(!is_xtest_device(b"Logitech MX Master 3"));
        assert!(!is_xtest_device(b""));
    }

    #[test]
    fn a_device_name_that_is_not_utf8_does_not_panic() {
        assert!(!is_xtest_device(&[0xff, 0xfe, 0x00]));
    }

    #[test]
    fn an_x11_keycode_becomes_an_evdev_scancode() {
        // X11 38 is evdev 30, which is KEY_A. The inverse of the injection side.
        assert_eq!(
            key(38, KeyState::Pressed),
            InputEvent::Key {
                code: Scancode(30),
                state: KeyState::Pressed
            }
        );
    }

    #[test]
    fn a_keycode_below_the_offset_saturates_rather_than_wrapping() {
        // Keycodes 0 through 7 are reserved and should never arrive, but
        // wrapping would turn one into a plausible key near the top of the range.
        assert_eq!(
            key(3, KeyState::Pressed),
            InputEvent::Key {
                code: Scancode(0),
                state: KeyState::Pressed
            }
        );
    }

    #[test]
    fn the_common_buttons_translate() {
        let pressed = KeyState::Pressed;

        assert_eq!(
            button_or_scroll(1, pressed),
            Some(InputEvent::Button {
                button: Button::Left,
                state: pressed
            })
        );
        assert_eq!(
            button_or_scroll(3, pressed),
            Some(InputEvent::Button {
                button: Button::Right,
                state: pressed
            })
        );
    }

    #[test]
    fn wheel_buttons_become_scroll_rather_than_clicks() {
        assert_eq!(
            button_or_scroll(4, KeyState::Pressed),
            Some(InputEvent::Scroll {
                h_v120: 0,
                v_v120: 120
            })
        );
        assert_eq!(
            button_or_scroll(5, KeyState::Pressed),
            Some(InputEvent::Scroll {
                h_v120: 0,
                v_v120: -120
            })
        );
    }

    #[test]
    fn a_wheel_release_is_dropped_so_scrolling_is_not_doubled() {
        // X11 sends press and release per detent. Emitting both would scroll
        // twice as far as the user asked.
        assert_eq!(button_or_scroll(4, KeyState::Released), None);
        assert_eq!(button_or_scroll(7, KeyState::Released), None);
    }

    #[test]
    fn back_and_forward_survive_the_scroll_range() {
        assert_eq!(
            button_or_scroll(8, KeyState::Pressed),
            Some(InputEvent::Button {
                button: Button::Back,
                state: KeyState::Pressed
            })
        );
    }

    #[test]
    fn whole_pixel_motion_converts_exactly() {
        assert_eq!(
            motion(&[fp(5, 0), fp(-3, 0)]),
            Some(InputEvent::MotionRel {
                dx_milli: 5_000,
                dy_milli: -3_000
            })
        );
    }

    #[test]
    fn sub_pixel_motion_keeps_three_decimal_places() {
        // Half a pixel is 500 thousandths. Losing this is what makes a
        // high-resolution pointer feel like it stutters.
        let half = 1u32 << 31;

        assert_eq!(
            motion(&[fp(0, half), fp(0, 0)]),
            Some(InputEvent::MotionRel {
                dx_milli: 500,
                dy_milli: 0
            })
        );
    }

    #[test]
    fn the_fraction_is_added_even_when_the_integral_is_negative() {
        // X floors, so -1.5 arrives as an integral of -2 and a fraction of a
        // half. Subtracting the fraction because the integral is negative
        // reports -2.5, which makes every leftward and upward motion with a
        // sub-pixel component faster than the same motion the other way.
        let half = 1u32 << 31;

        assert_eq!(fp3232_to_milli(fp(-2, half)), -1_500);
        assert_eq!(fp3232_to_milli(fp(-1, half)), -500);

        // The two directions have to be mirror images at the same speed, which
        // is the property the sign error broke.
        let quarter = 1u32 << 30;
        assert_eq!(fp3232_to_milli(fp(0, quarter)), 250);
        assert_eq!(fp3232_to_milli(fp(-1, quarter)), -750);
    }

    #[test]
    fn motion_with_no_movement_is_dropped() {
        assert_eq!(motion(&[fp(0, 0), fp(0, 0)]), None);
        assert_eq!(motion(&[]), None);
    }

    #[test]
    fn motion_on_a_single_axis_device_does_not_panic() {
        // A device reporting one valuator is unusual but legal.
        assert_eq!(
            motion(&[fp(4, 0)]),
            Some(InputEvent::MotionRel {
                dx_milli: 4_000,
                dy_milli: 0
            })
        );
    }
}
