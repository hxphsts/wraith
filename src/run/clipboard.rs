//! The clipboard thread, and the cache the crossing reads.
//!
//! # Why a dedicated thread
//!
//! Like the injector, the clipboard backend is single-thread-affine and not
//! async: an X11 selection is owned by one connection that must stay alive to
//! serve paste requests, a wayland data-control device lives on one event queue,
//! and macOS has no change event and is polled. So one thread owns the backend,
//! and the runtime hands it work over a channel and hears about local changes
//! over another. This is the seam that keeps the port sync and the domain free
//! of any clipboard concept at all.
//!
//! # What follows the cursor
//!
//! The thread watches the local clipboard and reports every change into a shared
//! [`Cache`]. When the cursor leaves this machine toward a peer, the run layer
//! reads the cache synchronously and sends its contents on. The domain is never
//! involved: it decides when and to whom the cursor crosses, and that is all the
//! clipboard needs from it.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ports::{Clipboard as ClipboardPort, ClipboardContents};

/// How many set requests may queue.
///
/// Small, like the injector's: a clipboard the receiver has not caught up on is
/// already superseded, so backpressure beats a growing buffer.
const QUEUE_CAPACITY: usize = 16;

/// How long the thread blocks watching for a local change before checking for a
/// set request. Also the staleness bound: a copy immediately followed by a
/// crossing, faster than this, syncs on the next crossing rather than this one.
const POLL_MS: u32 = 200;

/// The current local clipboard, shared with the run layer.
///
/// Written by the watch as the clipboard changes, read at a crossing. `None`
/// until the first change is seen, which is the honest state: nothing has been
/// observed to hand over yet.
pub type Cache = Arc<Mutex<Option<ClipboardContents>>>;

/// What the run layer asks the clipboard thread to do.
///
/// One variant today. Shutdown is not a request: the thread stops when the last
/// [`Clipboard`] drops its sender and the channel disconnects, which is why
/// [`ThreadHandle`] can join without sending anything.
enum Request {
    /// Offer these contents as this machine's clipboard.
    Set(ClipboardContents),
}

/// A handle to the clipboard thread.
///
/// Cloneable, because the per-peer readers each need to hand it an arriving
/// clipboard, and the cloneable half is only the send channel. `Drop` on the
/// last clone joins the thread.
#[derive(Clone)]
pub struct Clipboard {
    requests: SyncSender<Request>,
    /// Held only so the last clone joins the thread on drop. Never read, which
    /// is the shape of every RAII guard.
    #[expect(
        dead_code,
        reason = "the join happens in Drop, which dead-code analysis cannot see"
    )]
    thread: Arc<ThreadHandle>,
}

/// Owns the join handle so it is joined once, when the last `Clipboard` drops.
struct ThreadHandle(Mutex<Option<std::thread::JoinHandle<()>>>);

impl Clipboard {
    /// Starts the thread, taking ownership of the backend.
    ///
    /// `changed` carries local clipboard changes back to the run layer, which
    /// keeps the [`Cache`] fresh. This thread is the one place the backend is
    /// touched, for the reasons in the module documentation.
    pub fn start(
        backend: Box<dyn ClipboardPort>,
        changed: std::sync::mpsc::Sender<ClipboardContents>,
    ) -> std::io::Result<Self> {
        let (requests, inbox) = sync_channel(QUEUE_CAPACITY);

        let thread = std::thread::Builder::new()
            .name("wraith-clipboard".to_owned())
            .spawn(move || run(backend, &inbox, &changed))?;

        Ok(Self {
            requests,
            thread: Arc::new(ThreadHandle(Mutex::new(Some(thread)))),
        })
    }

    /// Offers these contents as this machine's clipboard.
    ///
    /// Non-blocking: it queues the payload for the thread, which owns the
    /// backend. A closed channel means teardown is under way and there is
    /// nothing useful to do about a dropped set.
    pub fn set(&self, contents: ClipboardContents) {
        if self.requests.send(Request::Set(contents)).is_err() {
            tracing::debug!("dropping a clipboard set, the thread has stopped");
        }
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        // Only the last `Clipboard` clone reaches here, because the handle is
        // behind an `Arc`. A `Clipboard`'s fields drop in declaration order, so
        // its `requests` sender is already gone by the time this runs; that was
        // the last sender, so the thread's next `recv_timeout` returns
        // `Disconnected` and it exits within one poll interval. Join it, so a
        // teardown does not race the thread's final backend touch.
        if let Some(thread) = self.0.get_mut().ok().and_then(Option::take) {
            let _ = thread.join();
        }
    }
}

/// The thread body.
///
/// Blocks watching for a local change, and in between serves set requests. One
/// loop, one connection, because the backend cannot be touched from two threads.
fn run(
    mut backend: Box<dyn ClipboardPort>,
    inbox: &Receiver<Request>,
    changed: &std::sync::mpsc::Sender<ClipboardContents>,
) {
    tracing::debug!(backend = backend.backend_name(), "clipboard thread started");
    loop {
        match inbox.recv_timeout(Duration::from_millis(u64::from(POLL_MS))) {
            Ok(Request::Set(contents)) => {
                if let Err(error) = backend.set_offer(&contents) {
                    tracing::warn!(%error, "cannot set the clipboard");
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => match backend.poll_change(POLL_MS) {
                Ok(Some(contents)) => {
                    if changed.send(contents).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::debug!(%error, "cannot read the clipboard"),
            },
        }
    }
}

/// Keeps the [`Cache`] fresh from the thread's change reports.
///
/// A plain OS thread bridging the sync `changed` channel into the shared cache,
/// the same shape as the pointer watch. Ends when the clipboard thread drops its
/// sender.
pub fn spawn_watch(cache: Cache, changed: std::sync::mpsc::Receiver<ClipboardContents>) {
    std::thread::Builder::new()
        .name("wraith-clipboard-watch".to_owned())
        .spawn(move || {
            while let Ok(contents) = changed.recv() {
                if let Ok(mut held) = cache.lock() {
                    *held = Some(contents);
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::fake::RecordingClipboard;

    #[test]
    fn a_local_change_reaches_the_cache() {
        let backend = RecordingClipboard::new();
        backend.queue_change(ClipboardContents::text("copied here"));

        let (changed_tx, changed_rx) = std::sync::mpsc::channel();
        let cache: Cache = Arc::new(Mutex::new(None));
        spawn_watch(Arc::clone(&cache), changed_rx);

        let _clipboard = Clipboard::start(Box::new(backend), changed_tx).unwrap();

        // The thread polls every POLL_MS; wait long enough for one poll and the
        // watch to write the cache.
        for _ in 0..50 {
            if cache.lock().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(
            cache.lock().unwrap().as_ref().map(|c| c.bytes.clone()),
            Some(b"copied here".to_vec()),
            "the local change never reached the cache"
        );
    }

    #[test]
    fn a_set_reaches_the_backend() {
        let backend = RecordingClipboard::new();
        let log = backend.log();

        let (changed_tx, _changed_rx) = std::sync::mpsc::channel();
        let clipboard = Clipboard::start(Box::new(backend), changed_tx).unwrap();

        clipboard.set(ClipboardContents::text("from a peer"));

        for _ in 0..50 {
            if !log.lock().unwrap().offered.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(
            log.lock().unwrap().offered.first().map(|c| c.bytes.clone()),
            Some(b"from a peer".to_vec()),
            "the set never reached the backend"
        );
    }
}
