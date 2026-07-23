//! The injection thread, and the destructor that guarantees release.
//!
//! # Layer 6
//!
//! [`InjectSession`] owns an injector and flushes a paranoid release when
//! dropped. That covers scope exit and, critically, a panic unwinding through
//! the session loop.
//!
//! **It works only because [`Inject`] is synchronous.** A destructor cannot
//! await, so an async injection port would silently delete this layer. That is
//! the whole reason the hot-path ports are sync, and it is why
//! `panic = "unwind"` is pinned in the release profile.
//!
//! # Why a dedicated thread
//!
//! X11, libei, and CoreGraphics all want to be driven from one thread, and none
//! of them are async. The runtime talks to this thread over a channel, which is
//! also the seam that keeps the domain free of tokio.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::Duration;

use crate::domain::{InputEvent, Point, ReleaseReason};
use crate::ports::Inject;

/// How many injection requests may queue.
///
/// Small on purpose. If the injector falls behind, the events in the queue are
/// already stale and the right answer is backpressure rather than a growing
/// buffer of input the user typed a second ago.
const QUEUE_CAPACITY: usize = 256;

/// How often the thread wakes when nothing is arriving.
const TICK_MS: u64 = 50;

/// How long a teardown waits for the thread to report that it has let go.
///
/// Generous. The thread wakes every `TICK_MS` and a release is a handful of
/// synthetic events, so this elapsing means the backend itself has wedged, and
/// the warning is then the only thing that will say so.
const RELEASE_WAIT_MS: u64 = 2_000;

/// What the session asks the injection thread to do.
#[derive(Debug)]
pub enum Request {
    /// Inject these events.
    Emit(Vec<InputEvent>),
    /// Put the pointer at an absolute position.
    Warp(Point),
    /// Release everything and stop.
    Shutdown,
}

/// A handle to the injection thread.
///
/// Owns the thread rather than merely addressing it, which is what makes the
/// release guarantee hold on the ordinary exit path. Asking the thread to stop
/// only queues a message; nothing but the join below proves it was acted on
/// before the process went away.
#[derive(Debug)]
pub struct Injector {
    requests: SyncSender<Request>,

    /// Signalled once the thread has released everything and is on its way out.
    ///
    /// Behind a mutex so the handle stays `Sync`, which the session needs in
    /// order to hold a reference to it across an await.
    released: std::sync::Mutex<Receiver<()>>,

    /// Taken by `Drop`, which is the only thing that joins.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Injector {
    /// Starts the thread, taking ownership of the backend.
    ///
    /// `found` carries the real pointer position back to the session, on the
    /// backends that can be asked. This thread is where that has to happen: it
    /// is the one that owns a handle to the display server, and every backend
    /// wants to be driven from a single thread.
    pub fn start(
        inject: Box<dyn Inject>,
        found: Option<std::sync::mpsc::Sender<Point>>,
    ) -> std::io::Result<Self> {
        let (requests, inbox) = sync_channel(QUEUE_CAPACITY);
        let (done, released) = sync_channel(1);

        let thread = std::thread::Builder::new()
            .name("wraith-inject".to_owned())
            .spawn(move || {
                run(InjectSession::new(inject), &inbox, found.as_ref());
                // After `run` returns, so the release it performs has already
                // happened when a waiting teardown is woken.
                let _ = done.try_send(());
            })?;

        Ok(Self {
            requests,
            released: std::sync::Mutex::new(released),
            thread: Some(thread),
        })
    }

    /// Queues events, dropping them if the thread has gone.
    ///
    /// A closed channel means shutdown is already under way, and reporting it as
    /// an error at every call site would add noise to a path that has nothing
    /// useful to do about it.
    pub fn emit(&self, events: Vec<InputEvent>) {
        if events.is_empty() {
            return;
        }
        if self.requests.send(Request::Emit(events)).is_err() {
            tracing::debug!("dropping injection, the injector has stopped");
        }
    }

    pub fn warp(&self, at: Point) {
        let _ = self.requests.send(Request::Warp(at));
    }

    /// Asks the thread to release everything and stop.
    ///
    /// Returns without waiting. `Drop` is what makes the release actually
    /// happen before the process goes, so a caller wanting the guarantee should
    /// let the handle fall out of scope rather than rely on this alone.
    pub fn shutdown(&self) {
        let _ = self.requests.send(Request::Shutdown);
    }
}

impl Drop for Injector {
    /// Waits for the thread to let go.
    ///
    /// Layer 6 releases held input from `InjectSession::drop`, on the injection
    /// thread. Nothing about that helps if the process exits first: `run` can
    /// return, `main` can finish, and the thread can be torn down by the
    /// operating system with the queued shutdown still unread, leaving every
    /// key held on a machine whose user is not touching it.
    ///
    /// So the wait is the guarantee, not the request that precedes it.
    fn drop(&mut self) {
        let _ = self.requests.send(Request::Shutdown);

        let waited = self
            .released
            .get_mut()
            .map(|released| released.recv_timeout(Duration::from_millis(RELEASE_WAIT_MS)));

        let Some(thread) = self.thread.take() else {
            return;
        };

        // Joining only once the thread has said it is done, so a wedged backend
        // costs a warning and a detached thread rather than a process that
        // never exits.
        if matches!(waited, Ok(Ok(()))) {
            let _ = thread.join();
        } else {
            tracing::error!(
                waited_ms = RELEASE_WAIT_MS,
                "the injection thread did not report releasing, so input may still be held"
            );
        }
    }
}

/// An injector paired with the promise that it will let go.
///
/// The `Drop` implementation is the point of the type. Everything else is a
/// thin pass-through.
struct InjectSession {
    inject: Box<dyn Inject>,
    /// What has been injected and not yet released.
    ///
    /// Tracked here rather than read back from the backend, because most
    /// backends cannot be read back and the destructor must work on all of them.
    held: crate::domain::HeldSet,
}

impl InjectSession {
    fn new(inject: Box<dyn Inject>) -> Self {
        Self {
            inject,
            held: crate::domain::HeldSet::new(),
        }
    }

    fn emit(&mut self, events: &[InputEvent]) {
        for &event in events {
            self.held.apply(event);
        }

        if let Err(error) = self.inject.emit(events) {
            tracing::warn!(%error, "injection failed");
        }
    }

    /// Tells the session where the pointer really is.
    ///
    /// Only while this machine has the cursor. With the cursor away the local
    /// pointer is parked and reporting it would drag the session's idea of the
    /// cursor back to a screen it has left.
    fn report_pointer(&self, found: Option<&std::sync::mpsc::Sender<Point>>) {
        let (Some(found), Some(pointer)) = (found, self.inject.pointer()) else {
            return;
        };
        if crate::run::serve::capture_gate::wanted() {
            return;
        }

        match crate::ports::ScreenInfo::cursor_position(pointer) {
            Ok(at) => {
                let _ = found.send(at);
            }
            Err(error) => tracing::debug!(%error, "cannot read the pointer"),
        }
    }

    fn warp(&mut self, at: Point) {
        if let Err(error) = self.inject.warp_absolute(at) {
            tracing::warn!(%error, "cannot move the pointer");
        }
    }

    /// Releases everything, plus every modifier unconditionally.
    ///
    /// Idempotent, because several paths converge here and none of them
    /// coordinate: an explicit shutdown, the channel closing, and the
    /// destructor can all fire for the same exit.
    fn release_all(&mut self, reason: ReleaseReason) {
        let mut events = self.held.release_events();
        self.held.clear();

        events.extend(
            crate::domain::input::MODIFIER_SCANCODES
                .iter()
                .map(|&code| InputEvent::Key {
                    code,
                    state: crate::domain::KeyState::Released,
                }),
        );

        if let Err(error) = self.inject.emit(&events) {
            tracing::error!(?reason, %error, "could not release held input");
            return;
        }
        let _ = self.inject.flush();

        tracing::debug!(?reason, released = events.len(), "released held input");
    }
}

impl Drop for InjectSession {
    fn drop(&mut self) {
        // Layer 6. Runs on scope exit and on a panic unwinding through the
        // thread, which is the case nothing else covers.
        //
        // Deliberately unconditional rather than checking `held`: the ledger
        // can be wrong, and a dozen redundant releases cost nothing.
        self.release_all(ReleaseReason::Teardown);
    }
}

/// The thread body.
fn run(
    mut session: InjectSession,
    inbox: &Receiver<Request>,
    found: Option<&std::sync::mpsc::Sender<Point>>,
) {
    loop {
        match inbox.recv_timeout(Duration::from_millis(TICK_MS)) {
            Ok(Request::Emit(events)) => session.emit(&events),
            Ok(Request::Warp(at)) => session.warp(at),
            Ok(Request::Shutdown) => {
                session.release_all(ReleaseReason::SessionClose);
                return;
            }
            Err(RecvTimeoutError::Timeout) => session.report_pointer(found),
            Err(RecvTimeoutError::Disconnected) => {
                // The session dropped the handle without saying goodbye, which
                // is what a panic elsewhere looks like from here.
                return;
            }
        }
    }
    // `session` is dropped on every path out, so the release always happens.
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::domain::input::MODIFIER_SCANCODES;
    use crate::domain::{KeyState, Scancode};
    use crate::ports::fake::{InjectLog, RecordingInject};

    const CTRL: Scancode = Scancode(29);
    const KEY_C: Scancode = Scancode(46);

    fn press(code: Scancode) -> InputEvent {
        InputEvent::Key {
            code,
            state: KeyState::Pressed,
        }
    }

    fn release(code: Scancode) -> InputEvent {
        InputEvent::Key {
            code,
            state: KeyState::Released,
        }
    }

    fn session() -> (InjectSession, Arc<Mutex<InjectLog>>) {
        let inject = RecordingInject::new();
        let log = inject.log();
        (InjectSession::new(Box::new(inject)), log)
    }

    #[test]
    fn dropping_the_session_releases_what_it_held() {
        // The layer that covers a panic. Without it, an unwind through the
        // session loop strands whatever was down at the time.
        let (mut session, log) = session();
        session.emit(&[press(CTRL), press(KEY_C)]);

        drop(session);

        let (saw_ctrl, saw_c) = {
            let seen = log.lock().unwrap();
            (seen.saw(release(CTRL)), seen.saw(release(KEY_C)))
        };

        assert!(saw_ctrl, "Ctrl was not released on drop");
        assert!(saw_c, "C was not released on drop");
    }

    #[test]
    fn dropping_the_handle_waits_for_the_thread_to_let_go() {
        // Layer 6 releases on the injection thread, which is no use if the
        // process leaves before the thread gets there. Dropping the handle has
        // to be the thing that waits.
        //
        // There is deliberately no sleep below. The assertion runs the instant
        // `drop` returns, so it only holds if `drop` really waited: a handle
        // that merely queued the request loses this race almost every time.
        let inject = RecordingInject::new();
        let log = inject.log();

        let injector = Injector::start(Box::new(inject), None).unwrap();
        injector.emit(vec![press(CTRL), press(KEY_C)]);

        drop(injector);

        let (saw_ctrl, saw_c) = {
            let seen = log.lock().unwrap();
            (seen.saw(release(CTRL)), seen.saw(release(KEY_C)))
        };

        assert!(saw_ctrl, "Ctrl was still held on exit");
        assert!(saw_c, "C was still held on exit");
    }

    #[test]
    fn dropping_the_session_sweeps_every_modifier_even_if_nothing_was_held() {
        // The tracked set can be wrong. A dozen redundant releases cost nothing
        // and cover the case where it is.
        let (session, log) = session();

        drop(session);

        let swept: Vec<Scancode> = {
            let seen = log.lock().unwrap();
            MODIFIER_SCANCODES
                .iter()
                .copied()
                .filter(|&c| seen.saw(release(c)))
                .collect()
        };

        assert_eq!(
            swept.len(),
            MODIFIER_SCANCODES.len(),
            "swept only {swept:?}"
        );
    }

    #[test]
    fn dropping_during_a_panic_still_releases() {
        // The case the whole design exists for, exercised rather than assumed.
        let inject = RecordingInject::new();
        let log = inject.log();

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut session = InjectSession::new(Box::new(inject));
            session.emit(&[press(CTRL)]);
            panic!("something went wrong mid-chord");
        }));

        assert!(outcome.is_err(), "the panic should have propagated");
        assert!(
            log.lock().unwrap().saw(release(CTRL)),
            "a panic left Ctrl held, which is the exact failure this project exists to prevent"
        );
    }

    #[test]
    fn an_explicit_release_is_idempotent() {
        // Shutdown, channel closure, and Drop can all fire for one exit.
        let (mut session, log) = session();
        session.emit(&[press(CTRL)]);

        session.release_all(ReleaseReason::SessionClose);
        let after_first = log.lock().unwrap().events.len();
        session.release_all(ReleaseReason::SessionClose);
        let after_second = log.lock().unwrap().events.len();

        // The second sweep still emits the unconditional modifiers, but must
        // not emit Ctrl again from the tracked set.
        assert_eq!(
            after_second - after_first,
            MODIFIER_SCANCODES.len(),
            "the second release repeated a tracked key"
        );
    }

    #[test]
    fn a_failing_backend_does_not_panic_the_destructor() {
        // A destructor that panics while unwinding aborts the process, which
        // would turn a recoverable error into a guaranteed stuck key.
        let inject = RecordingInject::failing("the display server went away");
        let mut session = InjectSession::new(Box::new(inject));

        session.emit(&[press(CTRL)]);
        drop(session);
    }

    #[test]
    fn the_injector_thread_releases_on_shutdown() {
        let inject = RecordingInject::new();
        let log = inject.log();
        let injector = Injector::start(Box::new(inject), None).unwrap();

        injector.emit(vec![press(CTRL)]);
        injector.shutdown();

        // The thread releases before exiting, so give it a moment to run.
        for _ in 0..50 {
            if log.lock().unwrap().saw(release(CTRL)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the injector thread did not release on shutdown");
    }

    #[test]
    fn a_closed_channel_releases_without_being_asked() {
        // The thread's last line of defence, reached when the sender goes away
        // without a shutdown ever being queued. Driven against `run` directly,
        // because a dropped `Injector` always sends one and so cannot get here.
        let inject = RecordingInject::new();
        let log = inject.log();

        let (requests, inbox) = sync_channel(QUEUE_CAPACITY);
        let worker =
            std::thread::spawn(move || run(InjectSession::new(Box::new(inject)), &inbox, None));

        requests.send(Request::Emit(vec![press(CTRL)])).unwrap();
        drop(requests);
        worker.join().unwrap();

        assert!(
            log.lock().unwrap().saw(release(CTRL)),
            "a closed channel left a key held"
        );
    }

    #[test]
    fn emitting_nothing_costs_nothing() {
        let inject = RecordingInject::new();
        let log = inject.log();
        let injector = Injector::start(Box::new(inject), None).unwrap();

        injector.emit(vec![]);
        std::thread::sleep(Duration::from_millis(60));

        assert!(log.lock().unwrap().events.is_empty());
    }
}
