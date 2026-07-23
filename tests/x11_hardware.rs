//! End to end against a real X server.
//!
//! `#[ignore]` because these need a display. Run them with:
//!
//! ```sh
//! just test-hardware              # against your own session
//! Xvfb :99 & DISPLAY=:99 just test-hardware
//! ```
//!
//! The unit tests elsewhere prove the sweep emits the right events. These prove
//! the events do the right thing to an actual X server, which is a different
//! claim and the one that matters to a user with a stuck Ctrl key.

#![cfg(target_os = "linux")]

use wraith::domain::input::MODIFIER_SCANCODES;
use wraith::domain::{InputEvent, KeyState, Point, Scancode};
use wraith::platform::linux::x11::X11Inject;
use wraith::ports::Inject;
use wraith::unstick;

const LEFT_SHIFT: Scancode = Scancode(42);
const LEFT_CTRL: Scancode = Scancode(29);
const KEY_A: Scancode = Scancode(30);

const fn press(code: Scancode) -> InputEvent {
    InputEvent::Key {
        code,
        state: KeyState::Pressed,
    }
}

/// Opens X on a known-clean keyboard, or skips loudly rather than failing.
///
/// A skip is right here: an absent display means the test could not run, not
/// that the code is wrong.
///
/// The opening sweep matters. These tests share one display server with each
/// other and with whatever else is on it, and the keyboard state there is
/// global mutable state. Serialising the binary (see `.config/nextest.toml`)
/// stops them overlapping; starting clean stops a leak from anything else.
fn open() -> Option<Cleanup> {
    match X11Inject::open() {
        Ok(mut inject) => {
            unstick::sweep(&mut inject, true).ok()?;
            Some(Cleanup(inject))
        }
        Err(error) => {
            eprintln!("skipping, no usable X display: {error}");
            None
        }
    }
}

/// Leaves the keyboard clean whatever the test did.
///
/// Without this a failing assertion would leave the developer's own keyboard
/// holding Ctrl, which would be a memorably bad way to learn this lesson.
struct Cleanup(X11Inject);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = unstick::sweep(&mut self.0, true);
    }
}

#[test]
#[ignore = "needs a real X display"]
fn a_held_modifier_is_visible_in_the_server_keymap() {
    // Establishes that the verification mechanism itself works. Without this,
    // the next test could pass by the keymap always reporting empty.
    let Some(mut guard) = open() else { return };

    guard.0.emit(&[press(LEFT_SHIFT)]).unwrap();

    let held = guard.0.held_keys().expect("X11 can report held keys");
    assert!(
        held.contains(&LEFT_SHIFT),
        "the server did not report shift down, held: {held:?}"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn unstick_releases_a_modifier_left_held() {
    // The scenario this whole command exists for. Deskflow's stuck key survives
    // killing the process precisely because nothing does this.
    let Some(mut guard) = open() else { return };

    guard
        .0
        .emit(&[press(LEFT_CTRL), press(LEFT_SHIFT)])
        .unwrap();
    let before = guard.0.held_keys().unwrap();
    assert!(
        before.contains(&LEFT_CTRL),
        "setup failed, ctrl was not held"
    );

    let swept = unstick::sweep(&mut guard.0, false).unwrap();

    assert!(
        swept.verified_clear(),
        "still held after the sweep: {:?}",
        swept.still_held
    );
    assert_eq!(swept.keys, MODIFIER_SCANCODES.len());
}

#[test]
#[ignore = "needs a real X display"]
fn the_default_sweep_leaves_a_held_letter_alone() {
    // The default sweep is modifiers only, deliberately. A stuck letter is
    // visible to the user and harmless; a stuck modifier turns every keystroke
    // into a shortcut. The narrowness is for correctness rather than speed: a
    // full sweep would also release whatever the user is physically holding.
    let Some(mut guard) = open() else { return };

    guard.0.emit(&[press(KEY_A)]).unwrap();
    unstick::sweep(&mut guard.0, false).unwrap();

    let held = guard.0.held_keys().unwrap();
    assert!(
        held.contains(&KEY_A),
        "the modifier sweep should not have touched a letter"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn the_full_sweep_releases_everything() {
    let Some(mut guard) = open() else { return };

    guard
        .0
        .emit(&[press(KEY_A), press(LEFT_CTRL), press(Scancode(57))])
        .unwrap();

    let swept = unstick::sweep(&mut guard.0, true).unwrap();

    assert!(
        swept.verified_clear(),
        "still held after a full sweep: {:?}",
        swept.still_held
    );
}

#[test]
#[ignore = "needs a real X display"]
fn sweeping_a_clean_keyboard_is_a_no_op() {
    // Idempotence against the real server, not just the ledger. Running unstick
    // twice, or when nothing was wrong, must not produce phantom input.
    let Some(mut guard) = open() else { return };

    unstick::sweep(&mut guard.0, true).unwrap();
    let swept = unstick::sweep(&mut guard.0, true).unwrap();

    assert!(swept.verified_clear());
}

#[test]
#[ignore = "needs a real X display"]
fn the_evdev_to_x11_offset_round_trips_through_the_server() {
    // The single riskiest constant in the backend. If the offset is wrong every
    // keystroke lands as a different key, and this is the only test that can
    // catch it, because it is the only one that asks the server what it saw.
    let Some(mut guard) = open() else { return };

    guard.0.emit(&[press(KEY_A)]).unwrap();

    let held = guard.0.held_keys().unwrap();
    assert_eq!(
        held,
        vec![KEY_A],
        "pressing evdev 30 should read back as evdev 30, got {held:?}"
    );
}

#[test]
#[ignore = "needs a real X display"]
fn a_key_held_by_a_dead_client_stays_held() {
    // The central empirical claim of this project, and the reason `unstick`
    // exists at all: X11 XTEST has no notion of releasing a client's synthetic
    // key presses when that client goes away.
    //
    // If this ever starts failing, the X server has grown that notion, and the
    // README, the research record, and the x11 module docs all need correcting.
    // Asserting it here rather than believing it is the difference between a
    // documented fact and a repeated rumour.
    //
    // The observer is load bearing, and its absence is what makes a naive
    // version of this test lie. An X server resets itself when its last client
    // disconnects, which clears the keyboard state for a reason that has nothing
    // to do with XTEST. A real session always has a window manager holding the
    // server open, so the observer is what makes this model reality rather than
    // an empty Xvfb.
    let Some(mut observer) = open() else { return };

    // Deliberately not the `open` helper, because its Cleanup guard sweeps on
    // drop and that is exactly what must not happen to the holder.
    let mut holder = X11Inject::open().expect("a second connection");
    holder.emit(&[press(LEFT_CTRL)]).unwrap();
    assert!(
        holder.held_keys().unwrap().contains(&LEFT_CTRL),
        "setup failed"
    );

    // Really close the socket, which is what a SIGKILLed process looks like
    // from the server's side. `mem::forget` would leak the connection and leave
    // the client very much alive, proving nothing.
    drop(holder);

    let held = observer.0.held_keys().unwrap();

    assert!(
        held.contains(&LEFT_CTRL),
        "the X server released a dead client's key, so `unstick` may no longer be needed \
         and the documentation claiming otherwise is now wrong. held: {held:?}"
    );

    unstick::sweep(&mut observer.0, true).unwrap();
}

#[test]
#[ignore = "needs a real X display"]
fn the_pointer_can_be_warped_to_an_absolute_position() {
    use wraith::ports::ScreenInfo;

    let Some(mut guard) = open() else { return };

    guard.0.warp_absolute(Point::new(400, 300)).unwrap();

    assert_eq!(guard.0.cursor_position().unwrap(), Point::new(400, 300));
}

#[test]
#[ignore = "needs a real X display"]
fn relative_motion_accumulates_from_where_the_pointer_was() {
    use wraith::ports::ScreenInfo;

    let Some(mut guard) = open() else { return };

    guard.0.warp_absolute(Point::new(400, 300)).unwrap();
    guard
        .0
        .emit(&[InputEvent::MotionRel {
            dx_milli: 50_000,
            dy_milli: -20_000,
        }])
        .unwrap();

    assert_eq!(guard.0.cursor_position().unwrap(), Point::new(450, 280));
}

#[test]
#[ignore = "needs a real X display"]
fn sub_pixel_motion_does_not_move_the_pointer() {
    use wraith::ports::ScreenInfo;

    // X11 has no sub-pixel pointer position, so a 400 milli delta must round to
    // nothing rather than to a whole pixel. Otherwise a high-resolution mouse
    // would drift.
    let Some(mut guard) = open() else { return };

    guard.0.warp_absolute(Point::new(400, 300)).unwrap();
    guard
        .0
        .emit(&[InputEvent::MotionRel {
            dx_milli: 400,
            dy_milli: 400,
        }])
        .unwrap();

    assert_eq!(guard.0.cursor_position().unwrap(), Point::new(400, 300));
}
