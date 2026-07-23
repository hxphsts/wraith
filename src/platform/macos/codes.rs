//! Translating evdev scancodes to macOS virtual keycodes.
//!
//! The wire carries evdev codes on every platform, because libei and the wlroots
//! virtual keyboard take them directly and an X11 keycode is evdev plus eight.
//! macOS is the one platform that needs a real table.
//!
//! # Why physical position rather than letter
//!
//! macOS virtual keycodes name a **position** on an ANSI keyboard, not a
//! character. `kVK_ANSI_A` is 0, and it stays 0 whether the user has a QWERTY,
//! Dvorak, or AZERTY layout selected, because the layout is applied afterwards.
//!
//! evdev codes name a position too. So this table maps position to position and
//! the layout on each machine is applied independently, which is the behaviour a
//! user wants: typing on a QWERTY machine into a Dvorak one produces what the
//! Dvorak machine's layout says, exactly as if the keyboard were plugged into
//! it.
//!
//! Mapping through characters instead would need the sender's layout, the
//! receiver's layout, and a translation between them, and would break the moment
//! either changed. The earlier deskflow-rs exploration tried a character-adjacent
//! approach and could not round-trip a modifier at all.

use crate::domain::Scancode;

/// A macOS virtual keycode.
pub type VirtualKey = u16;

/// evdev to macOS, by physical position.
///
/// Sorted by evdev code so the table can be scanned by eye against
/// `/usr/include/linux/input-event-codes.h`.
const TABLE: &[(u16, VirtualKey)] = &[
    (1, 53),    // ESC        kVK_Escape
    (2, 18),    // 1          kVK_ANSI_1
    (3, 19),    // 2
    (4, 20),    // 3
    (5, 21),    // 4
    (6, 23),    // 5
    (7, 22),    // 6
    (8, 26),    // 7
    (9, 28),    // 8
    (10, 25),   // 9
    (11, 29),   // 0
    (12, 27),   // MINUS      kVK_ANSI_Minus
    (13, 24),   // EQUAL
    (14, 51),   // BACKSPACE  kVK_Delete
    (15, 48),   // TAB
    (16, 12),   // Q
    (17, 13),   // W
    (18, 14),   // E
    (19, 15),   // R
    (20, 17),   // T
    (21, 16),   // Y
    (22, 32),   // U
    (23, 34),   // I
    (24, 31),   // O
    (25, 35),   // P
    (26, 33),   // LEFTBRACE
    (27, 30),   // RIGHTBRACE
    (28, 36),   // ENTER      kVK_Return
    (29, 59),   // LEFTCTRL   kVK_Control
    (30, 0),    // A          kVK_ANSI_A
    (31, 1),    // S
    (32, 2),    // D
    (33, 3),    // F
    (34, 5),    // G
    (35, 4),    // H
    (36, 38),   // J
    (37, 40),   // K
    (38, 37),   // L
    (39, 41),   // SEMICOLON
    (40, 39),   // APOSTROPHE
    (41, 50),   // GRAVE
    (42, 56),   // LEFTSHIFT  kVK_Shift
    (43, 42),   // BACKSLASH
    (44, 6),    // Z
    (45, 7),    // X
    (46, 8),    // C
    (47, 9),    // V
    (48, 11),   // B
    (49, 45),   // N
    (50, 46),   // M
    (51, 43),   // COMMA
    (52, 47),   // DOT
    (53, 44),   // SLASH
    (54, 60),   // RIGHTSHIFT kVK_RightShift
    (55, 67),   // KPASTERISK
    (56, 58),   // LEFTALT    kVK_Option
    (57, 49),   // SPACE
    (58, 57),   // CAPSLOCK
    (59, 122),  // F1
    (60, 120),  // F2
    (61, 99),   // F3
    (62, 118),  // F4
    (63, 96),   // F5
    (64, 97),   // F6
    (65, 98),   // F7
    (66, 100),  // F8
    (67, 101),  // F9
    (68, 109),  // F10
    (69, 71),   // NUMLOCK    kVK_ANSI_KeypadClear
    (71, 89),   // KP7
    (72, 91),   // KP8
    (73, 92),   // KP9
    (74, 78),   // KPMINUS
    (75, 86),   // KP4
    (76, 87),   // KP5
    (77, 88),   // KP6
    (78, 69),   // KPPLUS
    (79, 83),   // KP1
    (80, 84),   // KP2
    (81, 85),   // KP3
    (82, 82),   // KP0
    (83, 65),   // KPDOT
    (87, 103),  // F11
    (88, 111),  // F12
    (96, 76),   // KPENTER
    (97, 62),   // RIGHTCTRL  kVK_RightControl
    (98, 75),   // KPSLASH
    (100, 61),  // RIGHTALT   kVK_RightOption
    (102, 115), // HOME
    (103, 126), // UP
    (104, 116), // PAGEUP
    (105, 123), // LEFT
    (106, 124), // RIGHT
    (107, 119), // END
    (108, 125), // DOWN
    (109, 121), // PAGEDOWN
    (111, 117), // DELETE     kVK_ForwardDelete
    (125, 55),  // LEFTMETA   kVK_Command
    (126, 54),  // RIGHTMETA  kVK_RightCommand
];

/// The macOS keycode for an evdev scancode.
///
/// `None` for a key macOS has no position for, which the caller drops rather
/// than guessing at. A wrong guess types a different character, which is worse
/// than typing nothing.
#[must_use]
pub fn to_macos(code: Scancode) -> Option<VirtualKey> {
    TABLE
        .binary_search_by_key(&code.0, |(evdev, _)| *evdev)
        .ok()
        .map(|index| TABLE[index].1)
}

/// The evdev scancode for a macOS keycode.
///
/// Used by capture, which observes macOS keycodes and must put evdev on the
/// wire. Linear rather than binary, because the table is sorted by the other
/// column and a hundred entries is nothing at keyboard rates.
#[must_use]
pub fn to_evdev(key: VirtualKey) -> Option<Scancode> {
    TABLE
        .iter()
        .find(|(_, macos)| *macos == key)
        .map(|(evdev, _)| Scancode(*evdev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_by_evdev_code() {
        // `to_macos` binary searches it, so an unsorted entry would silently
        // fail to be found and that key would stop working.
        assert!(
            TABLE.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "the table is not sorted by evdev code"
        );
    }

    #[test]
    fn no_two_entries_share_a_macos_keycode() {
        // A duplicate would make `to_evdev` ambiguous, so one of the two keys
        // would translate back to the wrong thing.
        let mut seen: Vec<VirtualKey> = TABLE.iter().map(|(_, macos)| *macos).collect();
        seen.sort_unstable();

        let before = seen.len();
        seen.dedup();

        assert_eq!(
            seen.len(),
            before,
            "two evdev codes map to the same macOS keycode"
        );
    }

    #[test]
    fn every_entry_round_trips() {
        // The property that matters: what capture puts on the wire is what
        // injection turns back into the same physical key.
        for &(evdev, macos) in TABLE {
            assert_eq!(
                to_macos(Scancode(evdev)),
                Some(macos),
                "evdev {evdev} did not translate"
            );
            assert_eq!(
                to_evdev(macos),
                Some(Scancode(evdev)),
                "macOS {macos} did not translate back"
            );
        }
    }

    #[test]
    fn the_letters_land_where_a_us_keyboard_has_them() {
        // Spot checks against Apple's kVK_ constants. If the table drifts,
        // typing produces the wrong letters and this is what says so.
        assert_eq!(to_macos(Scancode(30)), Some(0), "A should be kVK_ANSI_A");
        assert_eq!(to_macos(Scancode(46)), Some(8), "C should be kVK_ANSI_C");
        assert_eq!(to_macos(Scancode(17)), Some(13), "W should be kVK_ANSI_W");
    }

    #[test]
    fn every_modifier_translates() {
        // The keys whose absence is the failure this project exists to
        // prevent. A modifier missing from the table cannot be released.
        for &code in crate::domain::input::MODIFIER_SCANCODES {
            assert!(
                to_macos(code).is_some(),
                "{code:?} has no macOS keycode, so it could never be released"
            );
        }
    }

    #[test]
    fn the_command_key_is_not_confused_with_control() {
        // On macOS, Command is where a Linux user expects Control, and getting
        // this wrong makes every shortcut land on the wrong modifier.
        assert_eq!(
            to_macos(Scancode(125)),
            Some(55),
            "LEFTMETA should be kVK_Command"
        );
        assert_eq!(
            to_macos(Scancode(29)),
            Some(59),
            "LEFTCTRL should be kVK_Control"
        );
    }

    #[test]
    fn an_unmapped_scancode_yields_nothing_rather_than_a_guess() {
        // Typing the wrong character is worse than typing none.
        assert_eq!(to_macos(Scancode(9_999)), None);
        assert_eq!(to_evdev(9_999), None);
    }

    #[test]
    fn backspace_and_delete_are_not_swapped() {
        // macOS names them the other way round from every other platform, which
        // is exactly the sort of thing that gets transposed.
        assert_eq!(
            to_macos(Scancode(14)),
            Some(51),
            "BACKSPACE should be kVK_Delete"
        );
        assert_eq!(
            to_macos(Scancode(111)),
            Some(117),
            "DELETE should be kVK_ForwardDelete"
        );
    }
}
