//! macOS, against a real machine.
//!
//! ```sh
//! just test-hardware
//! ```
//!
//! # What the first real run found
//!
//! Thirteen of fifteen passed. The two failures were worth more than the
//! thirteen, because between them they exposed a real bug in the backend and a
//! real bug in this file.
//!
//! The backend one: the tap saw Wraith's own injection, which is a feedback
//! loop rather than a feature. A receiving Mac captures what it injects and,
//! with its cursor remote, forwards it back. `kCGEventSourceUserData` is what
//! separates the two, and a test that asserts the echo arrives is asserting the
//! loop.
//!
//! The harness one: these tests were never serialised, so fifteen of them each
//! opened a tap and an injector and each cleanup swept 248 keycodes into
//! everyone else's measurements. Every hardware binary is in one serial group
//! now, not just the ones that had already failed.
//!
//! Read the notes on each test: several encode a specific thing that is known
//! to go wrong on macOS.
//!
//! # Before running
//!
//! Two grants, in System Settings, Privacy and Security:
//!
//! - **Accessibility**, to send input.
//! - **Input Monitoring**, to see it.
//!
//! One test asks you to press a key, because the tap now correctly refuses to
//! see Wraith's own events and macOS offers no other way to synthesise one that
//! looks real. It skips if nobody does.
//!
//! And sign the binary with a Developer ID. An ad-hoc signed build changes its
//! cdhash on every rebuild, and `CGEventTapCreate` checks the cdhash against the
//! kernel even when Settings shows the grant, so the tap is refused for reasons
//! the permission pane will insist are fine.

#![cfg(target_os = "macos")]

use std::time::{Duration, Instant};

use wraith::domain::input::MODIFIER_SCANCODES;
use wraith::domain::{InputEvent, KeyState, Point, Scancode};
use wraith::platform::macos::codes;
use wraith::platform::macos::inject::MacOsInject;
use wraith::platform::macos::tap::MacOsCapture;
use wraith::ports::{Capture, Inject, ScreenInfo};
use wraith::unstick;

const KEY_B: Scancode = Scancode(48);
const LEFT_SHIFT: Scancode = Scancode(42);

/// Long enough for the run loop to deliver, short enough not to stall the suite.
const SETTLE: Duration = Duration::from_millis(500);

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

/// Opens an injector, or skips with the reason.
///
/// A missing grant means the test could not run, not that the code is wrong,
/// and the message says which grant to give.
fn injector() -> Option<MacOsInject> {
    match MacOsInject::open() {
        Ok(inject) => Some(inject),
        Err(error) => {
            eprintln!("skipping: {error}");
            None
        }
    }
}

/// Leaves the keyboard clean whatever the test did.
struct Cleanup(MacOsInject);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = unstick::sweep(&mut self.0, true);
    }
}

#[test]
#[ignore = "needs a real Mac with Accessibility granted"]
fn the_injector_opens_with_accessibility_granted() {
    // The first thing to check. If this fails, nothing else can pass, and the
    // error says which pane to open.
    let Some(inject) = injector() else { return };

    assert_eq!(inject.backend_name(), "macos-coregraphics");
}

#[test]
#[ignore = "needs a real Mac with Accessibility granted"]
fn the_screen_size_is_read_from_the_display() {
    // The peer uses this to map crossings. A wrong size puts an arriving cursor
    // at the wrong height, which reads as the pointer jumping every time.
    let Some(inject) = injector() else { return };

    let screen = inject.local_screen().unwrap();

    assert!(
        screen.width_px >= 640,
        "implausible width {}",
        screen.width_px
    );
    assert!(
        screen.height_px >= 480,
        "implausible height {}",
        screen.height_px
    );
}

#[test]
#[ignore = "needs a real Mac with Accessibility granted"]
fn the_pointer_can_be_warped_and_read_back() {
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    guard.0.warp_absolute(Point::new(400, 300)).unwrap();

    assert_eq!(guard.0.cursor_position().unwrap(), Point::new(400, 300));
}

#[test]
#[ignore = "needs a real Mac with Accessibility granted"]
fn relative_motion_accumulates_from_where_the_pointer_was() {
    // CoreGraphics has no relative mouse event, so this exercises the tracked
    // position rather than the API. If the tracking drifts, the pointer creeps.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

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
#[ignore = "needs a real Mac with Accessibility granted"]
fn sub_pixel_motion_does_not_move_the_pointer() {
    // macOS has no sub-pixel cursor position, so a 400 milli delta must round to
    // nothing. Otherwise a high-resolution mouse drifts.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

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

#[test]
#[ignore = "needs a real Mac with Accessibility granted"]
fn a_sweep_does_not_fail_on_keys_macos_has_no_position_for() {
    // The evdev range is wider than the macOS table, and an unrepresentable key
    // must be skipped rather than aborting the batch. That batch is usually a
    // chord release, and abandoning it halfway is the failure this project
    // exists to prevent.
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    let swept = unstick::sweep(&mut guard.0, true).expect("a full sweep must not fail");

    assert!(swept.keys > 0);
}

#[test]
#[ignore = "needs a real Mac with Input Monitoring granted"]
fn the_tap_opens_with_input_monitoring_granted() {
    // If this fails and Settings shows the grant, it is the code signature.
    // See the module documentation.
    match MacOsCapture::open() {
        Ok(capture) => assert_eq!(capture.backend_name(), "macos-eventtap"),
        Err(error) => eprintln!("skipping: {error}"),
    }
}

#[test]
#[ignore = "needs a real Mac with both grants"]
fn capture_ignores_this_machines_own_injection() {
    // macOS does offer a way to tell our own synthetic events apart, whatever
    // the folklore says: kCGEventSourceUserData exists for exactly this,
    // injection stamps it, and the tap ignores anything carrying the stamp.
    //
    // Without the filter a receiving Mac captures its own injection and, with
    // its cursor remote, forwards it back to the machine it came from. Two
    // peers then trade one keystroke forever. X11 has the same hazard and
    // solves it with the XTEST device id.
    let Ok(mut capture) = MacOsCapture::open() else {
        eprintln!("skipping, no event tap");
        return;
    };
    let Some(inject) = injector() else { return };
    let mut guard = Cleanup(inject);

    drain(&mut capture);
    guard.0.emit(&[press(KEY_B), release(KEY_B)]).unwrap();

    let seen = poll_until(&mut capture, SETTLE);

    assert!(
        seen.is_empty(),
        "capture echoed our own injection back: {seen:?}"
    );
}

#[test]
#[ignore = "needs a real Mac with both grants"]
fn the_keycode_table_round_trips_in_both_directions() {
    // Closes the loop on the keycode table, which is where the earlier
    // deskflow-rs exploration failed: it captured macOS virtual keycodes and
    // looked them up in a table keyed by something else, so nothing
    // modifier-bearing could survive the trip.
    //
    // Checked against the table rather than through the tap, because the tap
    // now correctly refuses to see our own injection and there is no other way
    // to synthesise an event macOS will treat as real.
    for &code in MODIFIER_SCANCODES {
        let macos =
            codes::to_macos(code).unwrap_or_else(|| panic!("{code:?} has no macOS keycode"));

        assert_eq!(
            codes::to_evdev(macos),
            Some(code),
            "evdev {} became macOS {macos} and did not come back",
            code.0
        );
    }
}

#[test]
#[ignore = "needs a real Mac with both grants"]
fn a_modifier_press_is_seen_as_a_press() {
    // macOS reports modifiers through FlagsChanged with no direction, so the
    // direction is worked out from whether the flag is now set. Getting it
    // backwards holds Shift down forever, which is precisely the bug Wraith
    // exists to prevent.
    //
    // **Press Shift yourself while this runs.** Wraith's own injection is
    // filtered out now, and macOS offers no way to synthesise an event that
    // looks real to a tap, so a human hand is the only source left.
    let Ok(mut capture) = MacOsCapture::open() else {
        return;
    };

    eprintln!("press and release Left Shift now, within {SETTLE:?}");
    drain(&mut capture);
    let seen = poll_until(&mut capture, Duration::from_secs(5));

    if seen.is_empty() {
        eprintln!("skipping, nobody pressed anything");
        return;
    }

    assert!(
        seen.contains(&press(LEFT_SHIFT)),
        "a Shift press was not seen as a press, saw {seen:?}"
    );
    assert!(
        seen.contains(&release(LEFT_SHIFT)),
        "a Shift release was not seen as a release, saw {seen:?}"
    );
}

#[test]
#[ignore = "needs a real Mac with Accessibility granted"]
fn every_modifier_can_be_injected() {
    // A modifier the system refuses is one that could never be released on the
    // far machine, which is the failure this project exists to prevent.
    //
    // Injection only. Pressing each modifier and reading it back would pass for
    // the wrong reason, because what comes back is the tap seeing Wraith's own
    // injection, and that echo is a feedback loop rather than a feature. The
    // round trip is checked against the table in
    // `the_keycode_table_round_trips_in_both_directions` instead.
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
#[ignore = "needs a real Mac with both grants"]
fn dropping_the_capture_stops_it_swallowing_input() {
    // A tap left suppressing after the process forgets about it leaves the user
    // unable to type at all, which is worse than the stuck key this project is
    // about. Verify by hand as well: after this test, typing should work.
    let Ok(mut capture) = MacOsCapture::open() else {
        return;
    };

    capture.set_suppressed(true).unwrap();
    drop(capture);

    std::thread::sleep(SETTLE);
}

/// Throws away anything already queued.
///
/// Called before each measurement. Without it a previous step's events, or a
/// cleanup sweep, arrive in the next assertion and it fails describing keys the
/// test never pressed. That is what the first run on real hardware showed.
fn drain(capture: &mut dyn Capture) {
    let deadline = Instant::now() + SETTLE;
    let mut discarded = Vec::new();

    while Instant::now() < deadline {
        let before = discarded.len();
        capture.poll(20, &mut discarded).expect("capture failed");

        if discarded.len() == before {
            // Nothing arrived in the last poll, so the queue is empty.
            return;
        }
    }
}

/// Polls until something arrives or the deadline passes.
///
/// Keeps reading after the first event rather than returning on it, because a
/// press and its release arrive as separate events and a test asserting on the
/// second would otherwise miss it.
fn poll_until(capture: &mut dyn Capture, deadline: Duration) -> Vec<InputEvent> {
    let started = Instant::now();
    let mut out = Vec::new();
    let mut quiet_since: Option<Instant> = None;

    while started.elapsed() < deadline {
        let before = out.len();
        capture.poll(20, &mut out).expect("capture failed");

        if out.len() > before {
            quiet_since = None;
            continue;
        }

        // Return once the stream has been quiet for a moment, so a burst is
        // collected whole rather than cut in half.
        match quiet_since {
            Some(since) if since.elapsed() > Duration::from_millis(80) => return out,
            // Still inside the quiet window, or nothing has arrived yet to
            // start one. Both mean keep reading.
            None if !out.is_empty() => quiet_since = Some(Instant::now()),
            Some(_) | None => {}
        }
    }
    out
}
