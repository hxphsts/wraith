//! `wraith capture`, the diagnostic for the capture side.
//!
//! Prints what the machine sees. Useful for three things: confirming a backend
//! works at all, checking that scancodes arrive in the evdev space the wire
//! expects, and watching what suppression does before trusting a live session
//! with it.

use std::time::{Duration, Instant};

use crate::domain::{InputEvent, KeyState};
use crate::error::{Error, Result};
use crate::platform;
use crate::ports::Capture;

/// How long each poll waits before looping.
///
/// Short enough that the deadline is honoured promptly, long enough that an
/// idle keyboard costs nothing.
const POLL_TIMEOUT_MS: u32 = 100;

/// Prints local input until the deadline.
///
/// `seconds` of zero runs until interrupted. Suppression is bounded by the same
/// deadline on purpose: a bug that left the grab held would otherwise lock the
/// user out of their own machine with no way to type the command that fixes it.
pub fn run(suppress: bool, seconds: u64) -> Result<()> {
    let mut capture = platform::open_capture()?;

    if suppress {
        tracing::warn!(
            seconds,
            "suppressing local input. Nothing else on this machine receives input until \
             the deadline"
        );
        capture
            .set_suppressed(true)
            .map_err(|error| Error::Backend(error.to_string()))?;
    }

    let outcome = pump(capture.as_mut(), seconds);

    // Released before the error is propagated, because leaving a device grab
    // held is worse than whatever went wrong.
    if suppress && let Err(error) = capture.set_suppressed(false) {
        tracing::error!(%error, "could not release input suppression");
    }

    outcome
}

fn pump(capture: &mut dyn Capture, seconds: u64) -> Result<()> {
    let deadline = (seconds > 0).then(|| Instant::now() + Duration::from_secs(seconds));
    let mut batch = Vec::new();
    let mut seen = 0_u64;

    println!("backend: {}", capture.backend_name());

    loop {
        if deadline.is_some_and(|at| Instant::now() >= at) {
            println!("\n{seen} events");
            return Ok(());
        }

        batch.clear();
        capture
            .poll(POLL_TIMEOUT_MS, &mut batch)
            .map_err(|error| Error::Backend(error.to_string()))?;

        for event in &batch {
            seen += 1;
            println!("{}", describe(*event));
        }
    }
}

/// One event, as a line.
///
/// Scancodes are printed in decimal because that is how evdev names them, and
/// how they appear in `/usr/include/linux/input-event-codes.h`. Someone
/// checking whether the offset arithmetic is right wants to compare against that
/// file, not against hex.
fn describe(event: InputEvent) -> String {
    match event {
        InputEvent::Key { code, state } => {
            format!("key      {:>4}  {}", code.0, verb(state))
        }
        InputEvent::Button { button, state } => {
            format!("button  {button:?}  {}", verb(state))
        }
        InputEvent::MotionRel { dx_milli, dy_milli } => {
            format!("motion  {:>8.3} {:>8.3}", milli(dx_milli), milli(dy_milli))
        }
        InputEvent::Scroll { h_v120, v_v120 } => {
            format!("scroll  h {h_v120:>5}  v {v_v120:>5}")
        }
    }
}

const fn verb(state: KeyState) -> &'static str {
    match state {
        KeyState::Pressed => "down",
        KeyState::Released => "up",
    }
}

/// Thousandths as a decimal, for display only.
fn milli(value: i32) -> f64 {
    f64::from(value) / 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Button, Scancode};
    use crate::ports::fake::ScriptedCapture;

    #[test]
    fn a_key_press_names_its_scancode_in_decimal() {
        // Decimal so it can be compared against input-event-codes.h directly.
        let line = describe(InputEvent::Key {
            code: Scancode(30),
            state: KeyState::Pressed,
        });

        assert!(line.contains("30"), "got {line}");
        assert!(line.contains("down"), "got {line}");
    }

    #[test]
    fn motion_is_shown_in_whole_pixels_with_the_fraction_kept() {
        let line = describe(InputEvent::MotionRel {
            dx_milli: 1_500,
            dy_milli: -250,
        });

        assert!(line.contains("1.500"), "got {line}");
        assert!(line.contains("-0.250"), "got {line}");
    }

    #[test]
    fn every_event_kind_renders() {
        // A missing arm would be a compile error, but an empty or panicking
        // render would not, and this is a diagnostic that has to work when
        // something else is already broken.
        let events = [
            InputEvent::Key {
                code: Scancode(1),
                state: KeyState::Released,
            },
            InputEvent::Button {
                button: Button::Left,
                state: KeyState::Pressed,
            },
            InputEvent::MotionRel {
                dx_milli: 0,
                dy_milli: 0,
            },
            InputEvent::Scroll {
                h_v120: 0,
                v_v120: 120,
            },
        ];

        for event in events {
            assert!(!describe(event).is_empty());
        }
    }

    #[test]
    fn the_pump_stops_at_its_deadline_even_with_input_arriving() {
        // The deadline is what makes --suppress safe to try. If a busy keyboard
        // could hold the loop open, a bug here would lock the user out.
        let mut capture = ScriptedCapture::new(vec![vec![InputEvent::Key {
            code: Scancode(30),
            state: KeyState::Pressed,
        }]]);

        let started = Instant::now();
        pump(&mut capture, 1).unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the deadline was not honoured"
        );
    }
}
