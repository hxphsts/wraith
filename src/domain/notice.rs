//! What a session has to say for itself.
//!
//! A value rather than a formatted sentence, for the same reason
//! [`crate::status::PeerHealth`] is one: a window wants an icon per kind, a log
//! wants a field it can filter on, and a translation wants the message it has
//! not been given. None of them can do anything with prose.
//!
//! It also keeps the reducer honest. Building these costs no allocation for the
//! variants that carry nothing, where a `format!` per event cost one every time,
//! on a path the session module's own docs say runs a thousand times a second.
//!
//! The prose lives in `Display`, where it can be tested with no window attached.

use core::fmt;

use crate::domain::PeerId;

/// Something a session wants the user told.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Notice {
    /// A peer stopped answering and the watchdog let go of what it held there.
    ///
    /// The one notice that reports a safety layer doing its job, so it is worth
    /// distinguishing from an ordinary disconnect however similar they read.
    HeldInputReleased { peer: PeerId },

    /// A machine joined the desk.
    PeerConnected { name: String },

    /// A machine left.
    PeerDisconnected { peer: PeerId },

    /// The desk was edited out from under the cursor, so it came home.
    DeskChangedUnderCursor,
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeldInputReleased { peer } => {
                write!(f, "released input held by {peer}, which went quiet")
            }
            Self::PeerConnected { name } => write!(f, "{name} connected"),
            Self::PeerDisconnected { peer } => write!(f, "{peer} disconnected"),
            Self::DeskChangedUnderCursor => {
                f.write_str("the desk changed under the cursor, so it came home")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_notice() -> Vec<Notice> {
        vec![
            Notice::HeldInputReleased {
                peer: PeerId([7; 32]),
            },
            Notice::PeerConnected {
                name: "laptop".to_owned(),
            },
            Notice::PeerDisconnected {
                peer: PeerId([7; 32]),
            },
            Notice::DeskChangedUnderCursor,
        ]
    }

    #[test]
    fn every_notice_says_something() {
        for notice in every_notice() {
            assert!(
                !notice.to_string().is_empty(),
                "{notice:?} reads as nothing"
            );
        }
    }

    #[test]
    fn no_two_notices_read_the_same() {
        // A window that groups by message would merge them, and a user would
        // see one machine leaving when two did.
        let mut said: Vec<String> = every_notice().iter().map(ToString::to_string).collect();
        let total = said.len();

        said.sort_unstable();
        said.dedup();

        assert_eq!(said.len(), total, "two notices read identically");
    }

    #[test]
    fn a_watchdog_release_does_not_read_as_an_ordinary_disconnect() {
        // The distinction the window needs in order to say that a safety layer
        // fired rather than that somebody closed a laptop.
        let peer = PeerId([3; 32]);

        assert_ne!(
            Notice::HeldInputReleased { peer }.to_string(),
            Notice::PeerDisconnected { peer }.to_string()
        );
    }
}
