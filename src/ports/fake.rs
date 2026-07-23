//! In-memory implementations of the three ports.
//!
//! These are fakes rather than mocks. They record what happened and let a test
//! assert on it afterwards, and they never script expectations about what is
//! about to be called. A mock that fails on an unexpected call tests the shape
//! of the implementation; a fake that records tests its behaviour.
//!
//! Test-only, and gated `#[cfg(test)]` in `ports::mod`. Their value is that a
//! port with one implementation is not a boundary, so having a second keeps the
//! hexagon honest, and that argument is served by compiling them for the tests
//! rather than by shipping them as API nobody outside has asked for.

use std::sync::{Arc, Mutex};

use crate::domain::{InputEvent, Point};
use crate::ports::capture::{Capture, CaptureError};
use crate::ports::clipboard::{Clipboard, ClipboardContents, ClipboardError};
use crate::ports::inject::{Inject, InjectError};
use crate::ports::screen_info::{LocalScreen, ScreenInfo, ScreenInfoError};

/// Everything a [`RecordingInject`] was asked to do.
///
/// Shared behind a mutex so a test can inspect it after the injector that owns
/// it has been dropped, which is the only way to observe the release that
/// `Drop` performs.
#[derive(Debug, Default)]
pub struct InjectLog {
    pub events: Vec<InputEvent>,
    pub warps: Vec<Point>,
    pub flushes: usize,
}

impl InjectLog {
    /// Whether this event was ever emitted.
    #[must_use]
    pub fn saw(&self, event: InputEvent) -> bool {
        self.events.contains(&event)
    }
}

/// An [`Inject`] that records instead of injecting.
#[derive(Debug, Clone)]
pub struct RecordingInject {
    log: Arc<Mutex<InjectLog>>,
    /// When set, every `emit` fails with this message.
    fail_with: Option<String>,
    /// What `held_keys` reports. `None` models a write-only backend.
    reports_held: Option<Vec<crate::domain::Scancode>>,
}

impl Default for RecordingInject {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingInject {
    #[must_use]
    pub fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(InjectLog::default())),
            fail_with: None,
            reports_held: None,
        }
    }

    /// An injector that answers `held_keys`, modelling X11.
    #[must_use]
    pub fn reporting_held(mut self, held: Vec<crate::domain::Scancode>) -> Self {
        self.reports_held = Some(held);
        self
    }

    /// An injector that fails every emit, for testing the error paths.
    ///
    /// Worth having: most production failures come from untested error handling,
    /// and the teardown path in particular must not panic when injection fails.
    #[must_use]
    pub fn failing(message: impl Into<String>) -> Self {
        Self {
            log: Arc::new(Mutex::new(InjectLog::default())),
            fail_with: Some(message.into()),
            reports_held: None,
        }
    }

    /// A handle to the log, which outlives the injector.
    #[must_use]
    pub fn log(&self) -> Arc<Mutex<InjectLog>> {
        Arc::clone(&self.log)
    }

    /// Every event emitted so far.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which means a test already failed elsewhere.
    #[must_use]
    pub fn events(&self) -> Vec<InputEvent> {
        self.log.lock().expect("inject log poisoned").events.clone()
    }
}

impl Inject for RecordingInject {
    fn emit(&mut self, events: &[InputEvent]) -> Result<(), InjectError> {
        if let Some(message) = &self.fail_with {
            return Err(InjectError::Backend(message.clone()));
        }
        self.log
            .lock()
            .expect("inject log poisoned")
            .events
            .extend_from_slice(events);
        Ok(())
    }

    fn warp_absolute(&mut self, at: Point) -> Result<(), InjectError> {
        if let Some(message) = &self.fail_with {
            return Err(InjectError::Backend(message.clone()));
        }
        self.log.lock().expect("inject log poisoned").warps.push(at);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), InjectError> {
        self.log.lock().expect("inject log poisoned").flushes += 1;
        Ok(())
    }

    fn held_keys(&self) -> Option<Vec<crate::domain::Scancode>> {
        self.reports_held.clone()
    }

    fn backend_name(&self) -> &'static str {
        "recording"
    }
}

/// A [`Capture`] that replays a scripted sequence.
#[derive(Debug, Default)]
pub struct ScriptedCapture {
    /// Each poll drains one batch. An exhausted script polls empty forever,
    /// which is what a quiet keyboard looks like.
    batches: Vec<Vec<InputEvent>>,
    suppressed: bool,
}

impl ScriptedCapture {
    #[must_use]
    pub fn new(batches: Vec<Vec<InputEvent>>) -> Self {
        // Reversed so draining is a pop from the end rather than a shift.
        Self {
            batches: batches.into_iter().rev().collect(),
            suppressed: false,
        }
    }

    #[must_use]
    pub const fn is_suppressed(&self) -> bool {
        self.suppressed
    }

    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.batches.is_empty()
    }
}

impl Capture for ScriptedCapture {
    fn poll(&mut self, _timeout_ms: u32, out: &mut Vec<InputEvent>) -> Result<(), CaptureError> {
        if let Some(batch) = self.batches.pop() {
            out.extend(batch);
        }
        Ok(())
    }

    fn set_suppressed(&mut self, suppressed: bool) -> Result<(), CaptureError> {
        self.suppressed = suppressed;
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "scripted"
    }
}

/// A [`ScreenInfo`] with fixed geometry.
#[derive(Clone, Copy, Debug)]
pub struct FixedScreenInfo {
    pub screen: LocalScreen,
    pub cursor: Point,
}

impl Default for FixedScreenInfo {
    fn default() -> Self {
        Self {
            screen: LocalScreen {
                width_px: 1920,
                height_px: 1080,
            },
            cursor: Point::new(960, 540),
        }
    }
}

impl ScreenInfo for FixedScreenInfo {
    fn local_screen(&self) -> Result<LocalScreen, ScreenInfoError> {
        Ok(self.screen)
    }

    fn cursor_position(&self) -> Result<Point, ScreenInfoError> {
        Ok(self.cursor)
    }
}

/// What a [`RecordingClipboard`] holds and was told.
///
/// Shared behind a mutex so a test can drive the backend from one handle and
/// assert from another, the way the real thread holds the backend while the run
/// layer sends it work.
#[derive(Debug, Default)]
pub struct ClipboardLog {
    /// Everything `set_offer` was handed, in order.
    pub offered: Vec<ClipboardContents>,
    /// Local changes the watch will report, one per `poll_change`.
    pub changes: Vec<ClipboardContents>,
}

/// A [`Clipboard`] that records offers and replays scripted local changes.
#[derive(Debug, Clone)]
pub struct RecordingClipboard {
    log: Arc<Mutex<ClipboardLog>>,
}

impl Default for RecordingClipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingClipboard {
    #[must_use]
    pub fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(ClipboardLog::default())),
        }
    }

    /// The shared log, to inspect from a test after the backend has moved into
    /// a thread.
    #[must_use]
    pub fn log(&self) -> Arc<Mutex<ClipboardLog>> {
        Arc::clone(&self.log)
    }

    /// Queues a local change the next `poll_change` will report.
    ///
    /// Reversed on drain so the first queued is the first reported.
    pub fn queue_change(&self, contents: ClipboardContents) {
        self.log.lock().unwrap().changes.insert(0, contents);
    }

    /// What was offered, in order.
    #[must_use]
    pub fn offered(&self) -> Vec<ClipboardContents> {
        self.log.lock().unwrap().offered.clone()
    }
}

impl Clipboard for RecordingClipboard {
    fn set_offer(&mut self, contents: &ClipboardContents) -> Result<(), ClipboardError> {
        self.log.lock().unwrap().offered.push(contents.clone());
        Ok(())
    }

    fn poll_change(
        &mut self,
        _timeout_ms: u32,
    ) -> Result<Option<ClipboardContents>, ClipboardError> {
        Ok(self.log.lock().unwrap().changes.pop())
    }

    fn backend_name(&self) -> &'static str {
        "recording"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeyState, Scancode};

    fn press(code: u16) -> InputEvent {
        InputEvent::Key {
            code: Scancode(code),
            state: KeyState::Pressed,
        }
    }

    #[test]
    fn the_recording_injector_keeps_every_event_in_order() {
        let mut inject = RecordingInject::new();

        inject.emit(&[press(30), press(31)]).unwrap();
        inject.emit(&[press(32)]).unwrap();

        assert_eq!(inject.events(), vec![press(30), press(31), press(32)]);
    }

    #[test]
    fn the_log_outlives_the_injector() {
        // This is the only way to observe what a Drop implementation emitted.
        let inject = RecordingInject::new();
        let log = inject.log();

        {
            let mut owned = inject;
            owned.emit(&[press(30)]).unwrap();
        }

        assert!(log.lock().unwrap().saw(press(30)));
    }

    #[test]
    fn a_failing_injector_reports_every_emit_as_an_error() {
        let mut inject = RecordingInject::failing("display server went away");

        assert!(inject.emit(&[press(30)]).is_err());
        assert!(inject.events().is_empty());
    }

    #[test]
    fn a_scripted_capture_drains_one_batch_per_poll() {
        let mut capture = ScriptedCapture::new(vec![vec![press(30)], vec![press(31), press(32)]]);
        let mut out = Vec::new();

        capture.poll(0, &mut out).unwrap();
        assert_eq!(out, vec![press(30)]);

        capture.poll(0, &mut out).unwrap();
        assert_eq!(out, vec![press(30), press(31), press(32)]);
    }

    #[test]
    fn an_exhausted_capture_polls_empty_rather_than_failing() {
        // A quiet keyboard is not an error.
        let mut capture = ScriptedCapture::new(vec![]);
        let mut out = Vec::new();

        capture.poll(0, &mut out).unwrap();

        assert!(out.is_empty());
        assert!(capture.is_exhausted());
    }

    #[test]
    fn suppression_is_observable() {
        let mut capture = ScriptedCapture::new(vec![]);
        assert!(!capture.is_suppressed());

        capture.set_suppressed(true).unwrap();
        assert!(capture.is_suppressed());
    }
}
