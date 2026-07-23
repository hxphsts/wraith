//! wlroots, against a real compositor.
//!
//! ```sh
//! just test-hardware
//! ```
//!
//! **These have never been run.** The backend was written against the
//! `wlr-virtual-pointer` and `virtual-keyboard` protocol definitions and
//! compiles and lints clean, but no wlroots compositor has executed it. Treat a
//! failure here as a bug in the backend.
//!
//! # Where they apply
//!
//! Hyprland, Sway, Wayfire, niri, river. They skip on GNOME and KDE, which do
//! not offer these protocols and want the portal backend instead, and that skip
//! is the expected result rather than a problem.
//!
//! # What is covered
//!
//! Injection, which makes a wlroots machine a receiver: the cursor crosses onto
//! it and typing lands. Capture, which would let it also be the machine you type
//! on, needs a layer-shell surface per screen edge and is not written yet.
//!
//! # Watching it work
//!
//! There is no way to read back what a compositor received, so unlike the X11
//! tests these cannot assert on the outcome. Run them with something focused
//! that shows keystrokes, `wev` or a text editor, and watch. What they do assert
//! is that nothing errors and that the session is left clean.

#![cfg(target_os = "linux")]

use wraith::domain::input::MODIFIER_SCANCODES;
use wraith::domain::{Button, InputEvent, KeyState, Point, Scancode};
use wraith::platform::linux::wlroots::WlrootsInject;
use wraith::ports::Inject;
use wraith::unstick;

const KEY_B: Scancode = Scancode(48);
const LEFT_SHIFT: Scancode = Scancode(42);

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

/// Opens the backend, or skips with the reason.
///
/// On GNOME or KDE the skip is correct: those compositors do not offer these
/// protocols, and the message says so rather than implying a fault.
fn injector() -> Option<WlrootsInject> {
    match WlrootsInject::open() {
        Ok(inject) => Some(inject),
        Err(error) => {
            eprintln!("skipping: {error}");
            None
        }
    }
}

/// Leaves the keyboard clean whatever the test did.
struct Cleanup(WlrootsInject);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = unstick::sweep(&mut self.0, true);
    }
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn the_backend_opens_on_a_wlroots_compositor() {
    // The first thing to check. On GNOME or KDE this skips, which is right.
    let Some(inject) = injector() else { return };

    assert_eq!(inject.backend_name(), "wlroots-virtual");
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn the_compositor_accepts_a_keymap() {
    // The protocol refuses every key until a keymap is loaded, and loading it
    // happens during open. If open succeeds, the keymap was accepted.
    let Some(inject) = injector() else { return };

    drop(Cleanup(inject));
}

#[test]
#[ignore = "needs a wlroots compositor, watch a focused text field"]
fn a_keystroke_is_accepted() {
    // Nothing can be read back, so watch a focused editor. What is asserted is
    // that the compositor did not reject the request.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    guard
        .0
        .emit(&[press(KEY_B), release(KEY_B)])
        .expect("the compositor refused a keystroke");
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn a_chord_is_accepted_in_order() {
    // Shift down, B, Shift up. If the ordering were wrong the far machine would
    // see a lowercase letter, and if the release were dropped Shift would stay
    // down, which is the failure this project exists to prevent.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    guard
        .0
        .emit(&[
            press(LEFT_SHIFT),
            press(KEY_B),
            release(KEY_B),
            release(LEFT_SHIFT),
        ])
        .expect("the compositor refused a chord");
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn every_modifier_is_accepted() {
    // A modifier the compositor refuses is one that could never be released.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    for &code in MODIFIER_SCANCODES {
        guard
            .0
            .emit(&[press(code), release(code)])
            .unwrap_or_else(|error| panic!("{code:?} was refused: {error}"));
    }
}

#[test]
#[ignore = "needs a wlroots compositor, watch the pointer"]
fn the_pointer_moves() {
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    for _ in 0..20 {
        guard
            .0
            .emit(&[InputEvent::MotionRel {
                dx_milli: 10_000,
                dy_milli: 0,
            }])
            .expect("the compositor refused motion");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn sub_pixel_motion_is_dropped_rather_than_sent() {
    // The protocol takes whole pixels, so a 400 milli delta must round to
    // nothing rather than to one, or a high-resolution mouse drifts.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    guard
        .0
        .emit(&[InputEvent::MotionRel {
            dx_milli: 400,
            dy_milli: 400,
        }])
        .expect("a sub-pixel delta should be a silent no-op");
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn the_pointer_can_be_warped() {
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    guard
        .0
        .warp_absolute(Point::new(400, 300))
        .expect("the compositor refused a warp");
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn buttons_and_scroll_are_accepted() {
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    guard
        .0
        .emit(&[
            InputEvent::Button {
                button: Button::Left,
                state: KeyState::Pressed,
            },
            InputEvent::Button {
                button: Button::Left,
                state: KeyState::Released,
            },
            InputEvent::Scroll {
                h_v120: 0,
                v_v120: 120,
            },
        ])
        .expect("the compositor refused a button or scroll");
}

#[test]
#[ignore = "needs a wlroots compositor"]
fn the_backend_reports_that_it_cleans_up_after_itself() {
    // Unlike X11 XTEST, destroying the virtual keyboard releases what it held,
    // and the compositor destroys it when the client socket closes. So a killed
    // Wraith leaves nothing held here and `wraith unstick` is unnecessary.
    let Some(inject) = injector() else { return };

    assert!(
        inject.releases_on_disconnect(),
        "if this is false, a killed Wraith can strand a key and unstick is needed"
    );
}

#[test]
#[ignore = "needs a wlroots compositor, verify by hand afterwards"]
fn a_full_sweep_leaves_the_keyboard_usable() {
    // The important manual check. After this, typing on the machine should work
    // normally. If it does not, the backend has stranded something.
    let Some(inject) = injector() else { return };
    let mut inject = inject;

    let swept = unstick::sweep(&mut inject, true).expect("a full sweep must not fail");

    assert!(swept.keys > 0);
    assert_eq!(
        swept.still_held, None,
        "wlroots cannot report held keys, so this is unverified"
    );
}
