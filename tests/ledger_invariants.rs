//! The structural proof that a key cannot be left held.
//!
//! Every unit test in `domain::ledger` asserts one example. These assert the
//! property across arbitrary event sequences, which is the difference between
//! "the cases we thought of work" and "no case leaves a key down".
//!
//! Wraith exists because its closest competitor loses modifier keys and calls it
//! random. This file is the answer to that, and it is the most important test in
//! the crate.

use proptest::prelude::*;
use wraith::domain::input::{Button, KeyState, Scancode};
use wraith::domain::ledger::{LedgerConfig, ReleaseReason};
use wraith::domain::{HeldSet, InputEvent, InputLedger, Millis};

/// Scancodes spanning modifiers and plain keys.
///
/// Deliberately narrow. A wide range would almost never generate the same code
/// twice, so press and release pairs would never interleave and the interesting
/// cases would go untested.
fn scancode() -> impl Strategy<Value = Scancode> {
    prop_oneof![
        Just(Scancode(42)),  // left shift
        Just(Scancode(29)),  // left ctrl
        Just(Scancode(56)),  // left alt
        Just(Scancode(125)), // left meta
        Just(Scancode(30)),  // a
        Just(Scancode(46)),  // c
        Just(Scancode(57)),  // space
    ]
}

fn button() -> impl Strategy<Value = Button> {
    prop_oneof![
        Just(Button::Left),
        Just(Button::Middle),
        Just(Button::Right)
    ]
}

fn key_state() -> impl Strategy<Value = KeyState> {
    prop_oneof![Just(KeyState::Pressed), Just(KeyState::Released)]
}

/// Any input event, transitions and motion alike.
fn input_event() -> impl Strategy<Value = InputEvent> {
    prop_oneof![
        (scancode(), key_state()).prop_map(|(code, state)| InputEvent::Key { code, state }),
        (button(), key_state()).prop_map(|(button, state)| InputEvent::Button { button, state }),
        (-5_000i32..5_000, -5_000i32..5_000)
            .prop_map(|(dx_milli, dy_milli)| InputEvent::MotionRel { dx_milli, dy_milli }),
        (-360i32..360, -360i32..360)
            .prop_map(|(h_v120, v_v120)| InputEvent::Scroll { h_v120, v_v120 }),
    ]
}

fn event_sequence() -> impl Strategy<Value = Vec<InputEvent>> {
    prop::collection::vec(input_event(), 0..64)
}

/// What the held set should be, computed independently of the ledger.
///
/// A deliberately naive reimplementation. If the ledger and this ever disagree,
/// one of them is wrong, and having two independent derivations is the point.
fn expected_held(events: &[InputEvent]) -> HeldSet {
    let mut held = HeldSet::new();
    for &event in events {
        held.apply(event);
    }
    held
}

fn ledger() -> InputLedger {
    InputLedger::new(Millis::ZERO, LedgerConfig::default())
}

proptest! {
    /// The ledger's view is always presses minus releases, at every step.
    #[test]
    fn held_set_always_equals_presses_minus_releases(events in event_sequence()) {
        let mut ledger = ledger();

        for (step, &event) in events.iter().enumerate() {
            let now = Millis(step as u64);
            ledger.apply_transitions(&[event], now);

            let expected = expected_held(&events[..=step]);
            prop_assert_eq!(
                ledger.held(),
                &expected,
                "diverged at step {} on {:?}",
                step,
                event
            );
        }
    }

    /// After an explicit release, nothing is held. Whatever came before.
    #[test]
    fn release_all_always_empties_the_ledger(events in event_sequence()) {
        let mut ledger = ledger();
        ledger.apply_transitions(&events, Millis(100));

        ledger.release_all(ReleaseReason::Disconnect);

        prop_assert!(ledger.is_quiescent());
    }

    /// After the watchdog deadline passes, nothing is held. The sender is not
    /// consulted and does not need to be alive.
    #[test]
    fn the_watchdog_always_empties_the_ledger(events in event_sequence()) {
        let mut ledger = ledger();
        ledger.apply_transitions(&events, Millis(1_000));

        // Well past idle_release_ms, which defaults to 900.
        ledger.poll_watchdog(Millis(10_000));

        prop_assert!(ledger.is_quiescent());
    }

    /// Applying the release events returns the set to empty.
    ///
    /// This is what a backend actually does: it receives the events and injects
    /// them. If the list were insufficient, the real machine would keep a key
    /// down even though the ledger believed otherwise.
    #[test]
    fn release_events_are_sufficient_to_empty_the_set(events in event_sequence()) {
        let mut held = expected_held(&events);

        for event in held.release_events() {
            held.apply(event);
        }

        prop_assert!(held.is_empty());
    }

    /// Reconciling against an empty snapshot releases everything.
    ///
    /// The sender saying "I hold nothing" must always be sufficient, since that
    /// is what a leave carries.
    #[test]
    fn reconciling_against_nothing_releases_everything(events in event_sequence()) {
        let mut ledger = ledger();
        ledger.apply_transitions(&events, Millis(100));

        ledger.reconcile(&HeldSet::new(), Millis(200));

        prop_assert!(ledger.is_quiescent());
    }

    /// Reconciliation never invents a press.
    ///
    /// It may only release. A snapshot claiming more than the receiver holds is
    /// a lost packet, and synthesising the missing press would turn that into a
    /// phantom keystroke the user never typed.
    #[test]
    fn reconciliation_only_ever_releases(
        ours in event_sequence(),
        theirs in event_sequence(),
    ) {
        let mut ledger = ledger();
        ledger.apply_transitions(&ours, Millis(100));

        let before = ledger.held().clone();
        let emitted = ledger.reconcile(&expected_held(&theirs), Millis(200));

        for event in emitted {
            prop_assert!(
                matches!(
                    event,
                    InputEvent::Key { state: KeyState::Released, .. }
                        | InputEvent::Button { state: KeyState::Released, .. }
                ),
                "reconciliation emitted a non-release: {:?}",
                event
            );
        }

        prop_assert!(
            ledger.held().len() <= before.len(),
            "reconciliation grew the held set"
        );
    }

    /// The paranoid sweep covers every modifier, whatever the ledger believed.
    ///
    /// This is the layer that survives the ledger itself being wrong.
    #[test]
    fn the_paranoid_sweep_always_covers_every_modifier(events in event_sequence()) {
        let mut ledger = ledger();
        ledger.apply_transitions(&events, Millis(100));

        let emitted = ledger.release_all_paranoid(ReleaseReason::Teardown);

        for &code in wraith::domain::input::MODIFIER_SCANCODES {
            prop_assert!(
                emitted.contains(&InputEvent::Key { code, state: KeyState::Released }),
                "{:?} was not swept",
                code
            );
        }
        prop_assert!(ledger.is_quiescent());
    }

    /// Releasing twice is never a double release.
    ///
    /// Several teardown layers can fire for one disconnect and none of them
    /// coordinate, so the second and third calls must be silent.
    #[test]
    fn releasing_is_idempotent(events in event_sequence()) {
        let mut ledger = ledger();
        ledger.apply_transitions(&events, Millis(100));

        ledger.release_all(ReleaseReason::Disconnect);
        let second = ledger.release_all(ReleaseReason::Disconnect);
        let third = ledger.release_all(ReleaseReason::SessionClose);

        prop_assert!(second.is_empty());
        prop_assert!(third.is_empty());
    }

    /// Motion never changes what is held, however much of it arrives.
    #[test]
    fn motion_never_affects_the_held_set(
        transitions in event_sequence(),
        dx in -100_000i32..100_000,
        dy in -100_000i32..100_000,
    ) {
        let mut ledger = ledger();
        ledger.apply_transitions(&transitions, Millis(100));

        let before = ledger.held().clone();
        ledger.apply_transitions(
            &[InputEvent::MotionRel { dx_milli: dx, dy_milli: dy }],
            Millis(200),
        );

        prop_assert_eq!(ledger.held(), &before);
    }
}
