//! Reading local input, and withholding it while the cursor is away.
//!
//! The backend lives on its own thread because none of them are shareable and
//! all of them want one owner. That thread cannot be called into, so everything
//! crossing the boundary crosses as a flag: [`capture_gate`] is the whole of the
//! conversation, and suppression changes a few times a minute rather than a few
//! times a millisecond.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::domain::Input;
use crate::platform;

pub fn spawn_capture(events: mpsc::Sender<Input>, state: CaptureState) {
    std::thread::Builder::new()
        .name("wraith-capture-pump".to_owned())
        .spawn(move || {
            let Ok(mut capture) = platform::open_capture() else {
                tracing::warn!("no capture backend, so this machine can only receive input");
                return;
            };
            tracing::info!(backend = capture.backend_name(), "capturing local input");
            state.opened(capture.backend_name());

            let mut batch = Vec::new();
            loop {
                capture_gate::apply(capture.as_mut());

                batch.clear();
                if let Err(error) = capture.poll(50, &mut batch) {
                    tracing::warn!(%error, "capture stopped");
                    break;
                }

                if batch
                    .iter()
                    .any(|&event| events.blocking_send(Input::Local(event)).is_err())
                {
                    break;
                }
            }

            // Whatever ended it. Leaving suppression applied would hand the
            // machine back to a user who cannot type on it, and leaving the
            // gate's applied flag set would mean a second session in this
            // process never suppresses at all.
            release_capture(capture.as_mut());
            state.closed();
        })
        .ok();
}

/// What the capture thread made of this machine.
///
/// Shared so the control socket can report it. A session that is running and
/// connected but capturing nothing looks identical to a broken network from
/// outside, and on macOS that is the ordinary shape of Input Monitoring not
/// being granted.
#[derive(Debug, Clone, Default)]
pub struct CaptureState {
    backend: Arc<Mutex<Option<String>>>,
}

impl CaptureState {
    fn opened(&self, backend: &str) {
        if let Ok(mut held) = self.backend.lock() {
            *held = Some(backend.to_owned());
        }
    }

    fn closed(&self) {
        if let Ok(mut held) = self.backend.lock() {
            *held = None;
        }
    }

    pub(crate) fn backend(&self) -> Option<String> {
        self.backend.lock().ok().and_then(|held| held.clone())
    }
}

/// Hands local input back, whatever state the gate was in.
///
/// The last thing the capture thread does. Without it, stopping a session while
/// the cursor was on another machine leaves this one suppressing its own
/// keyboard with nothing left running to undo it.
pub fn release_capture(capture: &mut dyn crate::ports::Capture) {
    if let Err(error) = capture.set_suppressed(false) {
        tracing::warn!(%error, "cannot hand local input back");
    }
    capture_gate::reset();
}

/// A flag the capture thread polls to learn whether to suppress.
///
/// The capture backend lives on its own thread and is not shareable, so the
/// session cannot call it directly. A flag is the smallest thing that crosses
/// the boundary, and suppression changes a few times a minute rather than a few
/// times a millisecond.
pub mod capture_gate {
    use std::sync::atomic::{AtomicBool, Ordering};

    static WANTED: AtomicBool = AtomicBool::new(false);
    static APPLIED: AtomicBool = AtomicBool::new(false);

    pub fn set(on: bool) {
        WANTED.store(on, Ordering::Relaxed);
    }

    #[must_use]
    pub fn wanted() -> bool {
        WANTED.load(Ordering::Relaxed)
    }

    /// Brings the backend in line with the flag, if it has drifted.
    pub fn apply(capture: &mut dyn crate::ports::Capture) {
        let wanted = wanted();
        if wanted == APPLIED.load(Ordering::Relaxed) {
            return;
        }

        match capture.set_suppressed(wanted) {
            Ok(()) => APPLIED.store(wanted, Ordering::Relaxed),
            Err(error) => tracing::warn!(%error, "cannot change input suppression"),
        }
    }

    /// Resets both flags.
    ///
    /// Called when the capture thread exits, not only by tests. `APPLIED`
    /// surviving a session means the next one in this process believes the
    /// backend is already suppressed and never asks again, so suppression
    /// silently stops working.
    pub fn reset() {
        WANTED.store(false, Ordering::Relaxed);
        APPLIED.store(false, Ordering::Relaxed);
    }
}
