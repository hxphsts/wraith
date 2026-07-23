//! The authoritative record of what is held down.
//!
//! # The problem this exists to solve
//!
//! Deskflow's most-hated bug is a stuck modifier key. Its users call it
//! disqualifying, the stuck key survives killing the process, and the maintainer
//! describes it as random. See `research/01-competitive-landscape.md`.
//!
//! It is not random. It is the consequence of a receiver that replays an event
//! log: any release that is lost, reordered, or never sent leaves the key down
//! forever, because nothing in the design ever revisits the question.
//!
//! # The inversion
//!
//! **The receiver is authoritative over its own machine.** It never trusts the
//! sender to say what is held. It keeps its own record of what it is actually
//! holding, and treats the sender's view as a hint to reconcile against.
//!
//! # Nine layers
//!
//! | Layer | Fires on | Bound | Needs the sender alive |
//! |---|---|---|---|
//! | 1 Reliable transition path | always | none | yes |
//! | 2 Snapshot reconciliation | any desync | 100 ms | yes |
//! | 3 Explicit leave | screen leave | none | yes |
//! | 4 Idle watchdog | sender vanishes | 900 ms | **no** |
//! | 5 Connection close | disconnect | 900 ms | no |
//! | 6 Drop paranoid release | scope exit, panic unwind | none | no |
//! | 7 Signal handler | SIGINT, SIGTERM | one tick | no |
//! | 8 Compositor cleanup | abort, SIGKILL | immediate | libei and wlroots only |
//! | 9 `wraith unstick` | anything, including X11 after SIGKILL | manual | no |
//!
//! This module owns layers 1, 2, 4, and the mechanism behind 3, 5, 6, and 9.
//! Layer 6 lives in `run::injector`, layer 7 in `run::serve::shutdown_signal`,
//! and 8 is the operating system's.
//!
//! Layer 7 is what keeps layer 6 rather than a separate defence: `SIGTERM` ends
//! a process without unwinding, so a signal nobody catches takes the destructor
//! with it and leaves the far machine's watchdog as the only thing left.

use super::ids::{Millis, Seq};
use super::input::{HeldSet, InputEvent, InputFrame, KeyState, MODIFIER_SCANCODES, Modifiers};

/// Timing for the self-healing layers.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct LedgerConfig {
    /// Release everything if no traffic at all arrives for this long.
    ///
    /// Sized at roughly three keepalive intervals, so an ordinary gap in typing
    /// never trips it but a dead sender always does. This is layer 4, and it is
    /// the one that works with the sender already gone.
    pub idle_release_ms: u64,

    /// How often the sender re-asserts its held set while anything is held.
    ///
    /// Bounds how long a desync can persist. Costs nothing when quiescent,
    /// because a snapshot is only due while something is actually down.
    pub snapshot_interval_ms: u64,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            idle_release_ms: 900,
            snapshot_interval_ms: 100,
        }
    }
}

/// Why a datagram was discarded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DropReason {
    /// Older than something already applied. The unreliable path reorders.
    Stale,
}

/// Why the held set is being emptied. Carried into logs, not onto the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReleaseReason {
    /// The cursor went back to the sender's own screen.
    ScreenLeave,
    /// The connection ended, gracefully or otherwise.
    Disconnect,
    /// Layer 4. Nothing arrived for `idle_release_ms`.
    IdleWatchdog,
    /// The session is closing in an orderly way.
    SessionClose,
    /// Layer 6. A destructor ran, possibly during a panic unwind.
    Teardown,
}

/// The held-key record for one peer.
#[derive(Clone, Debug)]
pub struct InputLedger {
    held: HeldSet,
    last_seq: Option<Seq>,
    last_traffic_at_ms: Millis,
    last_snapshot_at_ms: Millis,
    config: LedgerConfig,
}

impl InputLedger {
    #[must_use]
    pub fn new(now_ms: Millis, config: LedgerConfig) -> Self {
        Self {
            held: HeldSet::new(),
            last_seq: None,
            last_traffic_at_ms: now_ms,
            last_snapshot_at_ms: now_ms,
            config,
        }
    }

    // ---- receiver side ----

    /// Applies transitions from the reliable path.
    ///
    /// Layer 1. These cannot be lost or reordered, so this is a straight apply
    /// that also updates the held set. The events are returned rather than the
    /// input echoed back, because a press of an already-held key is auto-repeat
    /// and must still reach the target application even though the set did not
    /// change.
    pub fn apply_transitions(&mut self, events: &[InputEvent], now_ms: Millis) -> Vec<InputEvent> {
        self.last_traffic_at_ms = now_ms;

        let mut applied = Vec::with_capacity(events.len());
        for &event in events {
            if !event.is_transition() {
                // Motion on the reliable path is a protocol error rather than
                // something to inject, since the sender chose the wrong path.
                continue;
            }
            self.held.apply(event);
            applied.push(event);
        }
        applied
    }

    /// Applies a datagram from the unreliable path.
    ///
    /// Motion and scroll only. A stale frame is dropped whole, and dropping it
    /// desynchronises nothing because motion is an increment rather than a state
    /// edge. That asymmetry is the entire reason for the two paths.
    pub fn apply_frame(
        &mut self,
        frame: &InputFrame,
        now_ms: Millis,
    ) -> Result<Vec<InputEvent>, DropReason> {
        if self.last_seq.is_some_and(|last| frame.seq <= last) {
            return Err(DropReason::Stale);
        }

        self.last_seq = Some(frame.seq);
        self.last_traffic_at_ms = now_ms;

        Ok(frame
            .events
            .iter()
            .copied()
            .filter(|e| !e.is_transition())
            .collect())
    }

    /// Reconciles against the sender's authoritative view.
    ///
    /// Layer 2. Anything held here that the sender does not claim is released.
    /// This is what makes a residual desync self-healing within one snapshot
    /// interval instead of lasting until reboot.
    pub fn reconcile(&mut self, authoritative: &HeldSet, now_ms: Millis) -> Vec<InputEvent> {
        self.last_traffic_at_ms = now_ms;

        let events = self.held.difference_release_events(authoritative);
        for &event in &events {
            self.held.apply(event);
        }
        events
    }

    /// Releases everything believed held. Idempotent.
    ///
    /// Safe to call when nothing is held, in which case it returns no events.
    /// That matters because several layers can fire for the same disconnect and
    /// none of them coordinate.
    pub fn release_all(&mut self, reason: ReleaseReason) -> Vec<InputEvent> {
        let events = self.held.release_events();
        self.held.clear();

        if !events.is_empty() {
            tracing::debug!(?reason, released = events.len(), "releasing held input");
        }
        events
    }

    /// Releases everything believed held, plus every modifier unconditionally.
    ///
    /// The belt-and-braces sweep. It releases modifiers whether or not the
    /// ledger thinks they are down, because the ledger itself could be wrong and
    /// a dozen redundant release events cost nothing. A redundant release of a
    /// key that is already up is a no-op on every backend.
    ///
    /// Used by layers 6 and 9, where correctness matters more than tidiness.
    pub fn release_all_paranoid(&mut self, reason: ReleaseReason) -> Vec<InputEvent> {
        let mut events = self.release_all(reason);

        events.extend(MODIFIER_SCANCODES.iter().map(|&code| InputEvent::Key {
            code,
            state: KeyState::Released,
        }));
        events
    }

    /// Layer 4, polled from the injector loop's timeout arm.
    ///
    /// Returns events only once the idle deadline has passed with something
    /// still held. Needs no cooperation from the sender, which is the point:
    /// this is what fires when the sender has been killed mid-chord.
    pub fn poll_watchdog(&mut self, now_ms: Millis) -> Option<Vec<InputEvent>> {
        if self.held.is_empty() {
            return None;
        }
        if now_ms.since(self.last_traffic_at_ms) < self.config.idle_release_ms {
            return None;
        }

        tracing::warn!(
            idle_ms = now_ms.since(self.last_traffic_at_ms),
            held = self.held.len(),
            "sender went quiet while holding input, releasing"
        );
        Some(self.release_all(ReleaseReason::IdleWatchdog))
    }

    // ---- sender side ----

    /// Records an outbound transition, so the snapshot stays truthful.
    pub fn note_sent(&mut self, event: InputEvent, now_ms: Millis) {
        if event.is_transition() {
            self.held.apply(event);
        }
        self.last_traffic_at_ms = now_ms;
    }

    /// The held set, when a snapshot is due.
    ///
    /// Returns `None` while quiescent, so an idle link carries no snapshot
    /// traffic at all. The receiver's watchdog covers the quiescent case, and it
    /// does so without needing anything sent.
    pub fn snapshot_due(&mut self, now_ms: Millis) -> Option<HeldSet> {
        if self.held.is_empty() {
            return None;
        }
        if now_ms.since(self.last_snapshot_at_ms) < self.config.snapshot_interval_ms {
            return None;
        }

        self.last_snapshot_at_ms = now_ms;
        Some(self.held.clone())
    }

    // ---- observation ----

    #[must_use]
    pub const fn held(&self) -> &HeldSet {
        &self.held
    }

    #[must_use]
    pub fn modifiers(&self) -> Modifiers {
        self.held.modifiers()
    }

    /// Whether nothing is held. The invariant every teardown path establishes.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use smallvec::smallvec;

    use super::*;
    use crate::domain::input::{Button, Scancode};

    const SHIFT: Scancode = Scancode(42);
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

    fn ledger() -> InputLedger {
        InputLedger::new(Millis::ZERO, LedgerConfig::default())
    }

    #[test]
    fn a_new_ledger_is_quiescent() {
        assert!(ledger().is_quiescent());
    }

    #[test]
    fn transitions_update_the_held_set() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT), press(KEY_C)], Millis(10));

        assert!(ledger.held().holds_key(SHIFT));
        assert!(ledger.held().holds_key(KEY_C));
        assert_eq!(ledger.modifiers(), Modifiers::SHIFT);
    }

    #[test]
    fn auto_repeat_is_still_forwarded_though_the_set_is_unchanged() {
        // The application on the far side needs the repeat, even though the
        // ledger already knows the key is down.
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(KEY_C)], Millis(10));

        let repeated = ledger.apply_transitions(&[press(KEY_C)], Millis(20));

        assert_eq!(repeated, vec![press(KEY_C)]);
        assert_eq!(ledger.held().len(), 1);
    }

    #[test]
    fn motion_on_the_reliable_path_is_discarded() {
        // The sender chose the wrong path. Injecting it anyway would work, but
        // silently accepting a protocol error hides the bug that caused it.
        let mut ledger = ledger();

        let applied = ledger.apply_transitions(
            &[InputEvent::MotionRel {
                dx_milli: 5,
                dy_milli: 5,
            }],
            Millis(10),
        );

        assert!(applied.is_empty());
    }

    #[test]
    fn release_all_is_idempotent() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT), press(KEY_C)], Millis(10));

        let first = ledger.release_all(ReleaseReason::Disconnect);
        let second = ledger.release_all(ReleaseReason::Disconnect);

        assert_eq!(first.len(), 2);
        assert!(
            second.is_empty(),
            "a second release must be a no-op, not a double release"
        );
        assert!(ledger.is_quiescent());
    }

    #[test]
    fn release_all_orders_modifiers_last() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(CTRL), press(KEY_C)], Millis(10));

        assert_eq!(
            ledger.release_all(ReleaseReason::ScreenLeave),
            vec![release(KEY_C), release(CTRL)]
        );
    }

    #[test]
    fn paranoid_release_sweeps_every_modifier_even_when_nothing_is_held() {
        // The ledger could be wrong. That is the entire premise of the sweep.
        let mut ledger = ledger();

        let events = ledger.release_all_paranoid(ReleaseReason::Teardown);

        assert_eq!(events.len(), MODIFIER_SCANCODES.len());
        for &code in MODIFIER_SCANCODES {
            assert!(events.contains(&release(code)), "{code:?} was not swept");
        }
    }

    #[test]
    fn paranoid_release_covers_held_keys_before_the_sweep() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(KEY_C)], Millis(10));

        let events = ledger.release_all_paranoid(ReleaseReason::Teardown);

        assert_eq!(
            events.first(),
            Some(&release(KEY_C)),
            "held keys are released first"
        );
        assert_eq!(events.len(), 1 + MODIFIER_SCANCODES.len());
    }

    #[test]
    fn reconcile_releases_exactly_what_the_sender_no_longer_claims() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT), press(KEY_C)], Millis(10));

        // The sender says it only holds Shift, so C leaked.
        let mut authoritative = HeldSet::new();
        authoritative.apply(press(SHIFT));

        let events = ledger.reconcile(&authoritative, Millis(20));

        assert_eq!(events, vec![release(KEY_C)]);
        assert!(
            ledger.held().holds_key(SHIFT),
            "Shift is still legitimately held"
        );
        assert!(!ledger.held().holds_key(KEY_C));
    }

    #[test]
    fn reconcile_against_an_agreeing_sender_emits_nothing() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT)], Millis(10));

        let mut authoritative = HeldSet::new();
        authoritative.apply(press(SHIFT));

        assert!(ledger.reconcile(&authoritative, Millis(20)).is_empty());
    }

    #[test]
    fn reconcile_does_not_press_keys_the_sender_holds_and_we_do_not() {
        // Reconciliation only ever releases. Synthesising a press from a
        // snapshot would turn one lost packet into a phantom keystroke.
        let mut ledger = ledger();

        let mut authoritative = HeldSet::new();
        authoritative.apply(press(SHIFT));

        assert!(ledger.reconcile(&authoritative, Millis(20)).is_empty());
        assert!(ledger.is_quiescent());
    }

    #[test]
    fn a_stale_datagram_is_dropped() {
        let mut ledger = ledger();
        let events = smallvec![InputEvent::MotionRel {
            dx_milli: 1_000,
            dy_milli: 0
        }];

        let fresh = InputFrame {
            seq: Seq(5),
            sent_at_ms: Millis(10),
            events: events.clone(),
        };
        assert!(ledger.apply_frame(&fresh, Millis(10)).is_ok());

        let stale = InputFrame {
            seq: Seq(4),
            sent_at_ms: Millis(9),
            events,
        };
        assert_eq!(
            ledger.apply_frame(&stale, Millis(11)),
            Err(DropReason::Stale)
        );
    }

    #[test]
    fn a_repeated_sequence_number_is_dropped() {
        let mut ledger = ledger();
        let frame = InputFrame {
            seq: Seq(5),
            sent_at_ms: Millis(10),
            events: smallvec![InputEvent::Scroll {
                h_v120: 0,
                v_v120: 120
            }],
        };

        assert!(ledger.apply_frame(&frame, Millis(10)).is_ok());
        assert_eq!(
            ledger.apply_frame(&frame, Millis(11)),
            Err(DropReason::Stale)
        );
    }

    #[test]
    fn a_dropped_frame_does_not_advance_the_sequence() {
        let mut ledger = ledger();
        let make = |seq| InputFrame {
            seq,
            sent_at_ms: Millis(10),
            events: smallvec![InputEvent::MotionRel {
                dx_milli: 1,
                dy_milli: 0
            }],
        };

        ledger.apply_frame(&make(Seq(5)), Millis(10)).ok();
        ledger.apply_frame(&make(Seq(3)), Millis(11)).ok();

        // Six is still newer than five, so the rejected three must not have
        // moved the high-water mark backwards.
        assert!(ledger.apply_frame(&make(Seq(6)), Millis(12)).is_ok());
    }

    #[test]
    fn the_watchdog_stays_silent_while_nothing_is_held() {
        let mut ledger = ledger();
        assert!(ledger.poll_watchdog(Millis(100_000)).is_none());
    }

    #[test]
    fn the_watchdog_stays_silent_one_millisecond_before_the_deadline() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT)], Millis(1_000));

        assert!(ledger.poll_watchdog(Millis(1_899)).is_none());
    }

    #[test]
    fn the_watchdog_fires_exactly_on_the_deadline() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT)], Millis(1_000));

        let released = ledger
            .poll_watchdog(Millis(1_900))
            .expect("the deadline has passed");

        assert_eq!(released, vec![release(SHIFT)]);
        assert!(ledger.is_quiescent());
    }

    #[test]
    fn the_watchdog_deadline_resets_on_any_traffic() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT)], Millis(1_000));

        // Motion arriving at 1800 pushes the deadline out to 2700.
        let frame = InputFrame {
            seq: Seq(1),
            sent_at_ms: Millis(1_800),
            events: smallvec![InputEvent::MotionRel {
                dx_milli: 1,
                dy_milli: 0
            }],
        };
        ledger.apply_frame(&frame, Millis(1_800)).ok();

        assert!(ledger.poll_watchdog(Millis(1_900)).is_none());
        assert!(ledger.poll_watchdog(Millis(2_700)).is_some());
    }

    #[test]
    fn the_watchdog_fires_only_once_per_stuck_chord() {
        let mut ledger = ledger();
        ledger.apply_transitions(&[press(SHIFT)], Millis(1_000));

        assert!(ledger.poll_watchdog(Millis(2_000)).is_some());
        assert!(
            ledger.poll_watchdog(Millis(3_000)).is_none(),
            "nothing is held any more"
        );
    }

    #[test]
    fn no_snapshot_is_due_while_quiescent() {
        // An idle link should carry no snapshot traffic at all.
        let mut ledger = ledger();
        assert!(ledger.snapshot_due(Millis(100_000)).is_none());
    }

    #[test]
    fn the_first_snapshot_after_a_press_is_immediate() {
        // The interval runs from the last snapshot, not from the press, and a
        // quiescent ledger emits none. So a key going down after a quiet spell
        // is asserted at once rather than a full interval later, which shrinks
        // the window in which the two ends can disagree to nearly nothing.
        let mut ledger = ledger();
        ledger.note_sent(press(SHIFT), Millis(5_000));

        let snapshot = ledger
            .snapshot_due(Millis(5_000))
            .expect("a held key is asserted at once");

        assert!(snapshot.holds_key(SHIFT));
    }

    #[test]
    fn a_snapshot_is_not_repeated_within_the_interval() {
        let mut ledger = ledger();
        ledger.note_sent(press(SHIFT), Millis(5_000));

        assert!(ledger.snapshot_due(Millis(5_000)).is_some());
        assert!(ledger.snapshot_due(Millis(5_099)).is_none());

        let snapshot = ledger
            .snapshot_due(Millis(5_100))
            .expect("the interval has passed");
        assert!(snapshot.holds_key(SHIFT));
    }

    #[test]
    fn a_snapshot_resets_its_own_interval() {
        let mut ledger = ledger();
        ledger.note_sent(press(SHIFT), Millis(10));

        assert!(ledger.snapshot_due(Millis(110)).is_some());
        assert!(ledger.snapshot_due(Millis(150)).is_none());
        assert!(ledger.snapshot_due(Millis(210)).is_some());
    }

    #[test]
    fn the_sender_ledger_tracks_what_it_announced() {
        let mut ledger = ledger();
        ledger.note_sent(press(CTRL), Millis(10));
        ledger.note_sent(press(KEY_C), Millis(20));
        ledger.note_sent(release(KEY_C), Millis(30));

        let snapshot = ledger
            .snapshot_due(Millis(200))
            .expect("Ctrl is still down");

        assert!(snapshot.holds_key(CTRL));
        assert!(!snapshot.holds_key(KEY_C));
    }

    #[test]
    fn buttons_are_tracked_and_released_like_keys() {
        let mut ledger = ledger();
        let down = InputEvent::Button {
            button: Button::Left,
            state: KeyState::Pressed,
        };
        ledger.apply_transitions(&[down], Millis(10));

        assert!(ledger.held().holds_button(Button::Left));

        let released = ledger.release_all(ReleaseReason::Disconnect);

        assert_eq!(
            released,
            vec![InputEvent::Button {
                button: Button::Left,
                state: KeyState::Released
            }]
        );
    }
}
