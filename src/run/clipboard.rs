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
//! [`Cache`], which holds both the current contents and how much of them each
//! peer already has. When the cursor leaves this machine toward a peer, the run
//! layer asks the cache synchronously for whatever that peer is missing, which
//! is usually nothing. The domain is never involved: it decides when and to whom
//! the cursor crosses, and that is all the clipboard needs from it.

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::domain::PeerId;
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

/// A count of the genuine clipboard states this machine has held.
///
/// Zero means nothing has been observed yet. It advances only when the clipboard
/// truly becomes something else, which is what lets a crossing tell a fresh copy
/// from one it has already handed over.
pub type Generation = u64;

/// The current local clipboard, and how much of it each peer already has.
///
/// Written by the watch as the clipboard changes, read at a crossing. Cloning
/// shares rather than copies, so the run layer and every peer reader see one
/// state.
///
/// The generation is the whole reason this is not a bare `Option`. A crossing
/// used to hand over whatever was last copied here, however long ago and however
/// many times that same copy had already crossed, so crossing back with nothing
/// newly copied overwrote the other machine's fresher clipboard with this
/// machine's older one. A peer is now handed the clipboard only when the
/// generation has moved past what that peer already has.
#[derive(Clone, Debug, Default)]
pub struct Cache(Arc<Mutex<Shared>>);

/// What the [`Cache`] guards, so every rule is decided under one lock.
#[derive(Debug, Default)]
struct Shared {
    /// The clipboard as this machine last saw it. `None` until something is
    /// observed, which is the honest state: nothing to hand over yet.
    contents: Option<ClipboardContents>,
    /// Advanced only when `contents` genuinely becomes something else.
    generation: Generation,
    /// The generation each peer has already exchanged with us. Entries go when a
    /// link ends, so this is bounded by the number of live links rather than by
    /// every machine ever seen.
    settled: BTreeMap<PeerId, Generation>,
}

impl Cache {
    /// Records a clipboard change observed on this machine.
    ///
    /// Contents equal to what is already held do not advance the generation.
    /// That is the echo guard: offering a peer's clipboard on the local backend
    /// makes that backend report the very same bytes back as a local change one
    /// poll later, and counting that as a new copy would hand the peer its own
    /// clipboard straight back at the next crossing.
    pub fn observe_local(&self, contents: ClipboardContents) {
        let Ok(mut shared) = self.0.lock() else {
            return;
        };

        if shared.contents.as_ref() == Some(&contents) {
            return;
        }

        shared.contents = Some(contents);
        shared.generation += 1;
    }

    /// Records a clipboard adopted from `peer`.
    ///
    /// The generation advances, so the copy still crosses to a third machine on
    /// the next crossing, but `peer` is settled at that same generation, so it is
    /// never handed back what it just gave us. That pair is the fix: propagate
    /// forward, never bounce back.
    pub fn adopt_from(&self, peer: PeerId, contents: ClipboardContents) {
        let Ok(mut shared) = self.0.lock() else {
            return;
        };

        if shared.contents.as_ref() != Some(&contents) {
            shared.contents = Some(contents);
            shared.generation += 1;
        }

        let generation = shared.generation;
        shared.settled.insert(peer, generation);
    }

    /// The clipboard this peer has not been given yet, and its generation.
    ///
    /// `None` when nothing has been copied, or when this peer already has the
    /// current generation. The generation comes back with the bytes so the caller
    /// settles the peer at what it actually sent rather than at whatever the
    /// generation has become since, which matters because a local copy can land
    /// between this call and the send.
    #[must_use]
    pub fn pending_for(&self, peer: PeerId) -> Option<(Generation, ClipboardContents)> {
        let shared = self.0.lock().ok()?;
        let contents = shared.contents.as_ref()?;
        let had = shared.settled.get(&peer).copied().unwrap_or_default();

        (shared.generation > had).then(|| (shared.generation, contents.clone()))
    }

    /// Records that this peer now has this generation.
    ///
    /// Called once a frame is genuinely on its way, and never by a check that
    /// decided not to send: a clipboard too large to cross has not been handed
    /// over, and settling it would keep it from ever crossing. Takes the higher
    /// of the two, so a late settle cannot walk a peer backwards.
    pub fn settle(&self, peer: PeerId, generation: Generation) {
        let Ok(mut shared) = self.0.lock() else {
            return;
        };

        let had = shared.settled.entry(peer).or_default();
        *had = (*had).max(generation);
    }

    /// Forgets everything remembered about a peer.
    ///
    /// Called when the link ends. Without it the map grows by one entry for every
    /// machine ever linked and never shrinks. Forgetting also means a peer that
    /// reconnects is offered the current clipboard once more, which is the right
    /// answer: a link that died may have died holding the frame.
    pub fn forget(&self, peer: PeerId) {
        if let Ok(mut shared) = self.0.lock() {
            shared.settled.remove(&peer);
        }
    }

    /// The current generation, for tests asserting that something did or did not
    /// count as a new copy.
    #[cfg(test)]
    pub(crate) fn generation(&self) -> Generation {
        self.0.lock().map_or(0, |shared| shared.generation)
    }
}

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
                cache.observe_local(contents);
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::fake::RecordingClipboard;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn a_local_change_reaches_the_cache_as_a_new_copy() {
        let backend = RecordingClipboard::new();
        backend.queue_change(ClipboardContents::text("copied here"));

        let (changed_tx, changed_rx) = std::sync::mpsc::channel();
        let cache = Cache::default();
        spawn_watch(cache.clone(), changed_rx);

        let _clipboard = Clipboard::start(Box::new(backend), changed_tx).unwrap();

        // The thread polls every POLL_MS; wait long enough for one poll and the
        // watch to write the cache.
        for _ in 0..50 {
            if cache.generation() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(
            cache.pending_for(peer(1)).map(|(_, c)| c.bytes),
            Some(b"copied here".to_vec()),
            "the local change never reached the cache"
        );
    }

    #[test]
    fn the_same_bytes_seen_again_are_not_a_new_copy() {
        // The backend echoes back whatever we offered it, one poll later. Taking
        // that for a fresh copy is what would hand a peer its own clipboard back.
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));
        cache.observe_local(ClipboardContents::text("A"));

        assert_eq!(cache.generation(), 1);
    }

    #[test]
    fn a_peer_is_handed_a_copy_only_once() {
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));

        let (generation, _) = cache
            .pending_for(peer(1))
            .expect("the copy is new to this peer");
        cache.settle(peer(1), generation);

        assert!(cache.pending_for(peer(1)).is_none());
    }

    #[test]
    fn a_new_copy_after_a_handover_is_pending_again() {
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));
        cache.settle(peer(1), 1);

        cache.observe_local(ClipboardContents::text("B"));

        assert_eq!(
            cache.pending_for(peer(1)).map(|(_, c)| c.bytes),
            Some(b"B".to_vec())
        );
    }

    #[test]
    fn an_adopted_clipboard_is_never_handed_back_to_the_peer_it_came_from() {
        // The reported bug, in one assertion: copy on the Mac, cross to this
        // machine, cross back with nothing copied here, and the Mac keeps its
        // own fresh copy.
        let cache = Cache::default();
        cache.adopt_from(peer(1), ClipboardContents::text("from the mac"));

        assert!(cache.pending_for(peer(1)).is_none());
    }

    #[test]
    fn an_adopted_clipboard_still_crosses_to_a_third_machine() {
        let cache = Cache::default();
        cache.adopt_from(peer(1), ClipboardContents::text("from the mac"));

        assert_eq!(
            cache.pending_for(peer(2)).map(|(_, c)| c.bytes),
            Some(b"from the mac".to_vec())
        );
    }

    #[test]
    fn adopting_the_bytes_we_already_hold_is_not_a_new_copy() {
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));
        cache.adopt_from(peer(1), ClipboardContents::text("A"));

        assert_eq!(cache.generation(), 1);
        assert!(cache.pending_for(peer(1)).is_none());
    }

    #[test]
    fn a_copy_racing_a_handover_is_not_marked_as_delivered() {
        // The lock is released between reading a clipboard and sending it, so a
        // copy landing in between must survive. This is why `settle` takes the
        // generation that was sent rather than reading the current one.
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));
        let (sent, _) = cache.pending_for(peer(1)).expect("A is new to this peer");

        cache.observe_local(ClipboardContents::text("B"));
        cache.settle(peer(1), sent);

        assert_eq!(
            cache.pending_for(peer(1)).map(|(_, c)| c.bytes),
            Some(b"B".to_vec())
        );
    }

    #[test]
    fn settling_never_walks_a_peer_backwards() {
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));
        cache.settle(peer(1), 5);
        cache.settle(peer(1), 2);

        assert!(cache.pending_for(peer(1)).is_none());
    }

    #[test]
    fn a_lost_peer_is_forgotten() {
        // A link that died may have died holding the frame, so the machine that
        // comes back on a fresh connection is offered the clipboard again.
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("A"));
        cache.settle(peer(1), 1);

        cache.forget(peer(1));

        assert!(cache.pending_for(peer(1)).is_some());
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
