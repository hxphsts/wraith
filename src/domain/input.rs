//! Input events and the set of things currently held down.
//!
//! # Why evdev scancodes
//!
//! The wire carries Linux evdev keycodes, on every platform. libei takes them
//! directly, the wlroots virtual keyboard takes them directly, and an X11 keycode
//! is an evdev code plus eight. Only macOS and Windows need a translation table.
//!
//! One translation at one edge beats three key spaces that disagree with each
//! other, which is the failure the earlier deskflow-rs exploration hit: it
//! captured macOS virtual keycodes and looked them up in a USB HID table, so
//! nothing modifier-bearing could round trip. See
//! `research/05-prior-art-deskflow-rs.md`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::ids::{Millis, Seq};

/// A Linux evdev keycode. `KEY_A` is 30.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Scancode(pub u16);

/// Modifier scancodes, in the order they must be released.
///
/// Every one of these is released unconditionally by a paranoid sweep, whether
/// or not the ledger believes it is down. A dozen redundant events cost nothing,
/// and these are the keys whose absence makes software feel broken.
pub const MODIFIER_SCANCODES: &[Scancode] = &[
    Scancode(42),  // KEY_LEFTSHIFT
    Scancode(54),  // KEY_RIGHTSHIFT
    Scancode(29),  // KEY_LEFTCTRL
    Scancode(97),  // KEY_RIGHTCTRL
    Scancode(56),  // KEY_LEFTALT
    Scancode(100), // KEY_RIGHTALT, AltGr
    Scancode(125), // KEY_LEFTMETA
    Scancode(126), // KEY_RIGHTMETA
];

impl Scancode {
    /// The modifier bit this scancode contributes, if it is a modifier at all.
    #[must_use]
    pub const fn modifier(self) -> Option<Modifiers> {
        match self.0 {
            42 | 54 => Some(Modifiers::SHIFT),
            29 | 97 => Some(Modifiers::CTRL),
            56 => Some(Modifiers::ALT),
            100 => Some(Modifiers::ALTGR),
            125 | 126 => Some(Modifiers::SUPER),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_modifier(self) -> bool {
        self.modifier().is_some()
    }
}

/// A pointer button.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum Button {
    Left,
    Middle,
    Right,
    Back,
    Forward,
    Other(u8),
}

/// Whether a key or button went down or came up.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum KeyState {
    Pressed,
    Released,
}

bitflags::bitflags! {
    /// The modifier mask derived from the held set.
    ///
    /// Derived rather than tracked separately, because two sources of truth for
    /// the same fact is how they drift apart.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    #[derive(Serialize, Deserialize)]
    pub struct Modifiers: u16 {
        const SHIFT = 1 << 0;
        const CTRL  = 1 << 1;
        const ALT   = 1 << 2;
        const SUPER = 1 << 3;
        const ALTGR = 1 << 4;
    }
}

/// One thing that happened to an input device.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum InputEvent {
    /// A key transition. Travels on the reliable stream.
    Key { code: Scancode, state: KeyState },

    /// A pointer button transition. Travels on the reliable stream.
    Button { button: Button, state: KeyState },

    /// Relative motion, in thousandths of a device pixel.
    ///
    /// Integers rather than floats so the wire encoding is exact and property
    /// tests are bit-reproducible. Thousandths because high-resolution pointers
    /// report sub-pixel deltas that would otherwise quantise into a stutter.
    ///
    /// Travels on the unreliable datagram path.
    MotionRel { dx_milli: i32, dy_milli: i32 },

    /// Scroll, in value120 units where 120 is one detent.
    ///
    /// Matches `wl_pointer.axis_value120` and libei, so a high-resolution wheel
    /// sends 15 or 30 at a time and a notched one sends 120.
    ///
    /// Travels on the unreliable datagram path.
    Scroll { h_v120: i32, v_v120: i32 },
}

impl InputEvent {
    /// Whether this event is a state edge that must not be lost.
    ///
    /// The reliable and unreliable paths are chosen by this predicate and
    /// nothing else. Losing a transition desynchronises the receiver's held set,
    /// which is the stuck-modifier bug. Losing motion costs a few pixels.
    #[must_use]
    pub const fn is_transition(&self) -> bool {
        matches!(self, Self::Key { .. } | Self::Button { .. })
    }
}

/// A batch of motion and scroll for one datagram.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InputFrame {
    pub seq: Seq,
    pub sent_at_ms: Millis,
    pub events: SmallVec<[InputEvent; 8]>,
}

/// Everything currently held down.
///
/// The single most important type in the crate. Both ends keep one: the sender
/// records what it has announced, and the receiver records what it is actually
/// holding on the local machine. They are reconciled against each other, and the
/// receiver's copy wins for its own machine.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HeldSet {
    keys: BTreeSet<Scancode>,
    buttons: BTreeSet<Button>,
}

impl HeldSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }

    /// How many things are held, keys and buttons together.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len() + self.buttons.len()
    }

    /// Applies a transition. Returns whether the set changed.
    ///
    /// A press of an already-held key returns false, which is how auto-repeat is
    /// distinguished from a genuine new press without a separate repeat flag.
    pub fn apply(&mut self, event: InputEvent) -> bool {
        match event {
            InputEvent::Key { code, state } => match state {
                KeyState::Pressed => self.keys.insert(code),
                KeyState::Released => self.keys.remove(&code),
            },
            InputEvent::Button { button, state } => match state {
                KeyState::Pressed => self.buttons.insert(button),
                KeyState::Released => self.buttons.remove(&button),
            },
            // Motion and scroll hold nothing, so they never change the set.
            InputEvent::MotionRel { .. } | InputEvent::Scroll { .. } => false,
        }
    }

    #[must_use]
    pub fn holds_key(&self, code: Scancode) -> bool {
        self.keys.contains(&code)
    }

    #[must_use]
    pub fn holds_button(&self, button: Button) -> bool {
        self.buttons.contains(&button)
    }

    /// The modifier mask implied by the held keys.
    #[must_use]
    pub fn modifiers(&self) -> Modifiers {
        self.keys
            .iter()
            .filter_map(|code| code.modifier())
            .fold(Modifiers::empty(), |mask, bit| mask | bit)
    }

    /// The events that would return this set to empty.
    ///
    /// **Order is load bearing.** Buttons first, then plain keys, then modifiers
    /// last. Releasing Ctrl before C in a held Ctrl+C would momentarily leave C
    /// down alone, which the receiving application sees as a bare keypress.
    /// Tearing down a chord must never synthesise a different one.
    #[must_use]
    pub fn release_events(&self) -> Vec<InputEvent> {
        let mut events = Vec::with_capacity(self.len());

        events.extend(self.buttons.iter().map(|&button| InputEvent::Button {
            button,
            state: KeyState::Released,
        }));

        let (modifiers, plain): (Vec<_>, Vec<_>) =
            self.keys.iter().partition(|code| code.is_modifier());

        events.extend(plain.into_iter().map(|&code| InputEvent::Key {
            code,
            state: KeyState::Released,
        }));
        events.extend(modifiers.into_iter().map(|&code| InputEvent::Key {
            code,
            state: KeyState::Released,
        }));

        events
    }

    /// The events releasing whatever this set holds that `other` does not.
    ///
    /// This is what reconciliation emits. The receiver holds this set, the
    /// sender says it holds `other`, and the difference is what leaked.
    #[must_use]
    pub fn difference_release_events(&self, other: &Self) -> Vec<InputEvent> {
        let mut extra = Self {
            keys: self.keys.difference(&other.keys).copied().collect(),
            buttons: self.buttons.difference(&other.buttons).copied().collect(),
        };
        let events = extra.release_events();
        extra.clear();
        events
    }

    pub fn clear(&mut self) {
        self.keys.clear();
        self.buttons.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_new_held_set_is_empty() {
        assert!(HeldSet::new().is_empty());
    }

    #[test]
    fn pressing_an_already_held_key_reports_no_change() {
        let mut held = HeldSet::new();

        assert!(held.apply(press(KEY_C)), "the first press changes the set");
        assert!(!held.apply(press(KEY_C)), "auto-repeat does not");
    }

    #[test]
    fn releasing_a_key_that_is_not_held_reports_no_change() {
        let mut held = HeldSet::new();
        assert!(!held.apply(release(KEY_C)));
    }

    #[test]
    fn motion_never_changes_the_held_set() {
        let mut held = HeldSet::new();

        assert!(!held.apply(InputEvent::MotionRel {
            dx_milli: 5_000,
            dy_milli: -2_000
        }));
        assert!(!held.apply(InputEvent::Scroll {
            h_v120: 0,
            v_v120: 120
        }));
        assert!(held.is_empty());
    }

    #[test]
    fn modifiers_are_derived_from_the_held_keys() {
        let mut held = HeldSet::new();
        held.apply(press(SHIFT));
        held.apply(press(CTRL));
        held.apply(press(KEY_C));

        assert_eq!(held.modifiers(), Modifiers::SHIFT | Modifiers::CTRL);

        held.apply(release(SHIFT));
        assert_eq!(held.modifiers(), Modifiers::CTRL);
    }

    #[test]
    fn left_and_right_modifiers_map_to_the_same_bit() {
        let mut left = HeldSet::new();
        left.apply(press(Scancode(42)));

        let mut right = HeldSet::new();
        right.apply(press(Scancode(54)));

        assert_eq!(left.modifiers(), right.modifiers());
    }

    #[test]
    fn release_events_put_modifiers_last() {
        // Tearing down Ctrl+C must not release Ctrl first, because that leaves C
        // held alone and the application sees a bare keypress.
        let mut held = HeldSet::new();
        held.apply(press(CTRL));
        held.apply(press(KEY_C));

        let events = held.release_events();

        assert_eq!(events, vec![release(KEY_C), release(CTRL)]);
    }

    #[test]
    fn release_events_put_buttons_before_keys() {
        let mut held = HeldSet::new();
        held.apply(press(SHIFT));
        held.apply(InputEvent::Button {
            button: Button::Left,
            state: KeyState::Pressed,
        });

        let events = held.release_events();

        assert_eq!(
            events,
            vec![
                InputEvent::Button {
                    button: Button::Left,
                    state: KeyState::Released
                },
                release(SHIFT),
            ]
        );
    }

    #[test]
    fn release_events_of_an_empty_set_are_empty() {
        assert!(HeldSet::new().release_events().is_empty());
    }

    #[test]
    fn applying_release_events_empties_the_set() {
        let mut held = HeldSet::new();
        held.apply(press(SHIFT));
        held.apply(press(CTRL));
        held.apply(press(KEY_C));
        held.apply(InputEvent::Button {
            button: Button::Right,
            state: KeyState::Pressed,
        });

        for event in held.release_events() {
            held.apply(event);
        }

        assert!(
            held.is_empty(),
            "release_events must be sufficient, not merely plausible"
        );
    }

    #[test]
    fn difference_releases_only_what_the_other_set_lacks() {
        // The receiver holds Shift and C. The sender says it only holds Shift.
        // C leaked, and only C should be released.
        let mut receiver = HeldSet::new();
        receiver.apply(press(SHIFT));
        receiver.apply(press(KEY_C));

        let mut sender = HeldSet::new();
        sender.apply(press(SHIFT));

        assert_eq!(
            receiver.difference_release_events(&sender),
            vec![release(KEY_C)]
        );
    }

    #[test]
    fn difference_against_an_identical_set_releases_nothing() {
        let mut held = HeldSet::new();
        held.apply(press(SHIFT));

        assert!(held.difference_release_events(&held.clone()).is_empty());
    }

    #[test]
    fn transitions_are_distinguished_from_motion() {
        assert!(press(KEY_C).is_transition());
        assert!(
            InputEvent::Button {
                button: Button::Left,
                state: KeyState::Pressed
            }
            .is_transition()
        );
        assert!(
            !InputEvent::MotionRel {
                dx_milli: 1,
                dy_milli: 1
            }
            .is_transition()
        );
        assert!(
            !InputEvent::Scroll {
                h_v120: 0,
                v_v120: 120
            }
            .is_transition()
        );
    }

    #[test]
    fn every_modifier_scancode_maps_to_a_modifier_bit() {
        // The paranoid sweep releases this list unconditionally, so an entry
        // that is not actually a modifier would be a silent extra keystroke.
        for &code in MODIFIER_SCANCODES {
            assert!(
                code.is_modifier(),
                "{code:?} is in the sweep but is not a modifier"
            );
        }
    }
}
