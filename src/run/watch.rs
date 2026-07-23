//! Who is listening for crossings.
//!
//! The session emits `Command::Crossed` whether or not anything cares, so this
//! has to be cheap when nobody is watching, which is the ordinary case: the
//! daemon usually runs with no window attached at all. With no subscribers
//! `send` returns without allocating, so a crossing costs one atomic load and a
//! branch.
//!
//! `broadcast` rather than `watch`, and the difference matters. `watch` keeps
//! only the latest value, so two crossings inside one poll interval collapse
//! into one and a fast flick across a screen and back would draw a single
//! effect. Every crossing is an event, not a state.

use tokio::sync::broadcast;

use crate::control::Crossed;

/// How many crossings a slow watcher may fall behind before it starts losing
/// them.
///
/// Small on purpose. A watcher that is 16 crossings behind is drawing history,
/// and dropping the oldest is better than growing a queue nobody will ever
/// catch up with.
const DEPTH: usize = 16;

/// The sending half, held by the session.
#[derive(Clone, Debug)]
pub struct Watchers(broadcast::Sender<Crossed>);

impl Watchers {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(DEPTH);
        Self(tx)
    }

    /// Tells every watcher, and nobody if there are none.
    pub fn announce(&self, crossed: Crossed) {
        // An error here means no receivers, which is the common case and not a
        // failure.
        let _ = self.0.send(crossed);
    }

    /// A new watcher's end.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Crossed> {
        self.0.subscribe()
    }

    /// Whether anything is listening.
    ///
    /// Only the tests ask, and they ask in order to wait for a subscriber
    /// before publishing rather than race it. Production code publishes
    /// regardless, since a broadcast with no receivers is already a no-op.
    #[cfg(test)]
    pub fn any(&self) -> bool {
        self.0.receiver_count() > 0
    }
}

impl Default for Watchers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Direction, Edge, Fraction};

    fn crossing() -> Crossed {
        Crossed::new(Direction::Departure, Edge::Right, Fraction::MIDDLE)
    }

    #[test]
    fn announcing_with_nobody_listening_is_not_an_error() {
        // The ordinary case: the daemon runs with no window attached.
        let watchers = Watchers::new();

        assert!(!watchers.any());
        watchers.announce(crossing());
    }

    #[tokio::test]
    async fn a_watcher_receives_what_was_announced() {
        let watchers = Watchers::new();
        let mut rx = watchers.subscribe();

        assert!(watchers.any());
        watchers.announce(crossing());

        assert_eq!(rx.recv().await.unwrap(), crossing());
    }

    #[tokio::test]
    async fn two_crossings_in_a_row_both_arrive() {
        // The reason this is a broadcast and not a watch. A watch keeps only
        // the newest, so a flick out and back would draw one effect instead of
        // two.
        let watchers = Watchers::new();
        let mut rx = watchers.subscribe();

        let out = Crossed::new(Direction::Departure, Edge::Right, Fraction::MIDDLE);
        let back = Crossed::new(Direction::Arrival, Edge::Right, Fraction::MIDDLE);
        watchers.announce(out);
        watchers.announce(back);

        assert_eq!(rx.recv().await.unwrap(), out);
        assert_eq!(rx.recv().await.unwrap(), back);
    }

    #[tokio::test]
    async fn every_watcher_sees_every_crossing() {
        let watchers = Watchers::new();
        let mut one = watchers.subscribe();
        let mut two = watchers.subscribe();

        watchers.announce(crossing());

        assert_eq!(one.recv().await.unwrap(), crossing());
        assert_eq!(two.recv().await.unwrap(), crossing());
    }
}
