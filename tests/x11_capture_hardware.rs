//! Capture and suppression against a real X server.
//!
//! ```sh
//! Xvfb :99 & DISPLAY=:99 just test-hardware
//! ```
//!
//! The unit tests prove the event translation. These prove the claims only a
//! real server can settle: that while suppressing **nobody else sees the
//! input**, and that Wraith does not see its own injection.
//!
//! Note what cannot be tested here. Capture deliberately ignores XTEST, and
//! XTEST is the only way to synthesise input on a headless server, so there is
//! no way to feed capture a realistic event. The crossing logic is therefore
//! tested against the ports in `tests/two_machines.rs`, and the translation in
//! the unit tests beside the code.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{ConnectionExt as _, EventMask};

use wraith::domain::{InputEvent, KeyState, Scancode};
use wraith::platform::linux::x11::X11Inject;
use wraith::platform::linux::x11_capture::X11Capture;
use wraith::ports::{Capture, Inject};
use wraith::unstick;

const KEY_B: Scancode = Scancode(48);

/// Long enough that a loaded machine does not fail spuriously, short enough
/// that a genuine failure does not stall the suite.
const SETTLE: Duration = Duration::from_millis(400);

const fn press(code: Scancode) -> InputEvent {
    InputEvent::Key {
        code,
        state: KeyState::Pressed,
    }
}

const fn release(code: Scancode) -> InputEvent {
    InputEvent::Key {
        code,
        state: KeyState::Released,
    }
}

/// A separate X client watching the root window, standing in for the desktop.
///
/// This is the only way to prove suppression. Asserting that Wraith sees events
/// says nothing about whether anyone else does, and "nobody else does" is the
/// entire difference between a KVM and a keylogger.
struct Bystander {
    connection: x11rb::rust_connection::RustConnection,
}

impl Bystander {
    fn new() -> Option<Self> {
        let (connection, screen_num) = x11rb::connect(None).ok()?;
        let root = connection.setup().roots.get(screen_num)?.root;

        connection
            .change_window_attributes(
                root,
                &x11rb::protocol::xproto::ChangeWindowAttributesAux::new()
                    .event_mask(EventMask::KEY_PRESS | EventMask::KEY_RELEASE),
            )
            .ok()?;

        // A round trip, not just a flush. `flush` only pushes the request out;
        // it does not wait for the server to apply it. Without this the first
        // injected event can race the event-mask change and vanish, which
        // shows up as a suppression test failing for reasons unrelated to
        // suppression.
        connection.get_input_focus().ok()?.reply().ok()?;

        Some(Self { connection })
    }

    /// How many key events arrived since the last call.
    fn drain_key_events(&self) -> usize {
        let _ = self.connection.flush();
        let mut seen = 0;

        while let Ok(Some(event)) = self.connection.poll_for_event() {
            if matches!(event, Event::KeyPress(_) | Event::KeyRelease(_)) {
                seen += 1;
            }
        }
        seen
    }
}

/// Polls until an event arrives or the deadline passes.
fn poll_until(capture: &mut dyn Capture, deadline: Duration) -> Vec<InputEvent> {
    let started = Instant::now();
    let mut out = Vec::new();

    while started.elapsed() < deadline {
        capture.poll(50, &mut out).expect("capture failed");
        if !out.is_empty() {
            // Give any trailing events of the same burst a moment to arrive.
            std::thread::sleep(Duration::from_millis(50));
            capture.poll(0, &mut out).expect("capture failed");
            return out;
        }
    }
    out
}

fn open() -> Option<(X11Capture, X11Inject)> {
    let capture = X11Capture::open().ok()?;
    let mut inject = X11Inject::open().ok()?;
    unstick::sweep(&mut inject, true).ok()?;
    Some((capture, inject))
}

#[test]
#[ignore = "needs a real X display"]
fn capture_ignores_this_machines_own_injection() {
    // Without this a receiving machine captures what it injects, and with its
    // cursor remote it forwards that straight back to where it came from. Two
    // peers then trade the same keystroke forever.
    //
    // Measured before the filter existed: eight injected releases came back as
    // eight captured events.
    let Some((mut capture, mut inject)) = open() else {
        eprintln!("skipping, no usable X display");
        return;
    };

    inject.emit(&[press(KEY_B), release(KEY_B)]).unwrap();

    let seen = poll_until(&mut capture, SETTLE);

    assert!(
        seen.is_empty(),
        "capture echoed our own injection back: {seen:?}"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn input_reaches_the_desktop_when_not_suppressed() {
    // The control for the next test. Without this, that one could pass simply
    // because the bystander never receives anything.
    let Some((_capture, mut inject)) = open() else {
        return;
    };
    let Some(bystander) = Bystander::new() else {
        return;
    };

    bystander.drain_key_events();
    inject.emit(&[press(KEY_B), release(KEY_B)]).unwrap();
    std::thread::sleep(SETTLE);

    assert!(
        bystander.drain_key_events() > 0,
        "the bystander saw nothing while unsuppressed"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn suppression_takes_input_away_from_everyone_else() {
    // The claim that makes this a KVM rather than an injector.
    //
    // Paired with `input_reaches_the_desktop_when_not_suppressed`, which is what
    // stops this passing trivially. Without that control, a bystander that never
    // receives anything at all would look like perfect suppression.
    let Some((mut capture, mut inject)) = open() else {
        return;
    };
    let Some(bystander) = Bystander::new() else {
        return;
    };

    capture.set_suppressed(true).expect("could not grab");
    bystander.drain_key_events();

    inject.emit(&[press(KEY_B), release(KEY_B)]).unwrap();
    std::thread::sleep(SETTLE);
    let leaked = bystander.drain_key_events();

    capture.set_suppressed(false).expect("could not ungrab");

    assert_eq!(
        leaked, 0,
        "{leaked} events reached the desktop while suppressed"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn releasing_suppression_gives_input_back() {
    let Some((mut capture, mut inject)) = open() else {
        return;
    };
    let Some(bystander) = Bystander::new() else {
        return;
    };

    capture.set_suppressed(true).expect("could not grab");
    capture.set_suppressed(false).expect("could not ungrab");

    bystander.drain_key_events();
    inject.emit(&[press(KEY_B), release(KEY_B)]).unwrap();
    std::thread::sleep(SETTLE);

    assert!(
        bystander.drain_key_events() > 0,
        "input did not come back after ungrabbing"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn suppression_is_released_when_the_capture_is_dropped() {
    // A leaked device grab is worse than the stuck key this project is about:
    // it leaves the user unable to type anything at all, including the command
    // that would fix it.
    let Some((mut capture, mut inject)) = open() else {
        return;
    };
    let Some(bystander) = Bystander::new() else {
        return;
    };

    capture.set_suppressed(true).expect("could not grab");
    drop(capture);

    bystander.drain_key_events();
    inject.emit(&[press(KEY_B), release(KEY_B)]).unwrap();
    std::thread::sleep(SETTLE);

    assert!(
        bystander.drain_key_events() > 0,
        "the grab outlived the capture that held it"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn setting_the_same_suppression_twice_is_harmless() {
    // Several call sites can converge on the same state, and a second grab of
    // an already-grabbed device is an error the caller should never have to
    // think about.
    let Some((mut capture, _inject)) = open() else {
        return;
    };

    capture.set_suppressed(true).expect("first grab");
    capture
        .set_suppressed(true)
        .expect("second grab must be a no-op");
    capture.set_suppressed(false).expect("first ungrab");
    capture
        .set_suppressed(false)
        .expect("second ungrab must be a no-op");
}
