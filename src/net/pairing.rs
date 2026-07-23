//! Pairing two machines over a short human-transferable code.
//!
//! # Why a PAKE and not trust on first use
//!
//! Everyone else in this category ships trust on first use with fingerprint
//! comparison. It is simultaneously the weakest link in the security model,
//! being blind to a man in the middle on the first connection, and the top
//! usability complaint, being a 64-character hex string users hand-edit into a
//! config file. See `research/03-transport-security.md`.
//!
//! A password-authenticated key exchange fixes both at once, which is a rare
//! enough alignment to be worth taking. Both sides derive a strong shared key
//! from a weak six-digit code. A passive attacker learns nothing from watching.
//! An active attacker gets exactly **one** online guess, and then the code is
//! spent: an offer is consumed by the first connection that reaches it, and the
//! next offer mints a code of its own. Guessing six digits is therefore a one in
//! a million shot at a target that has to be re-armed by hand between tries.
//!
//! # Why there is no word list to compare
//!
//! A short authentication string on top of this would be a second thing for the
//! user to do and would prove nothing new: if the codes matched, the key
//! agreement succeeded, and if they did not, it failed. The confirmation step is
//! the exchange itself.
//!
//! # What is deliberately absent
//!
//! There is no path here that establishes trust without a code. Pairing is the
//! only way a peer enters the trusted set, which is what makes an unpaired peer
//! unrepresentable rather than merely refused.

use std::fmt;

use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use spake2::{Ed25519Group, Identity as SpakeIdentity, Password, Spake2};
use zeroize::Zeroizing;

use crate::domain::PeerId;

/// How many digits a pairing code has.
///
/// Six is the familiar length from every other pairing flow a user has met. It
/// is weak on its own, and that is fine: SPAKE2 turns a weak secret into a
/// strong key, and the online guess limit does the rest.
pub const CODE_DIGITS: usize = 6;

/// Domain separation, so a Wraith transcript cannot be replayed elsewhere.
const SPAKE_IDENTITY: &[u8] = b"wraith-pairing-v1";

/// A six-digit pairing code.
///
/// Formats with a space in the middle for reading aloud, and parses with any
/// spacing or punctuation, because the person typing it is copying from someone
/// speaking.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode {
    digits: [u8; CODE_DIGITS],
}

impl PairingCode {
    /// A fresh code from the system random source.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut digits = [0_u8; CODE_DIGITS];

        for digit in &mut digits {
            *digit = rng.random_range(0..10);
        }
        Self { digits }
    }

    /// Parses a code, ignoring anything that is not a digit.
    ///
    /// Forgiving on purpose. "418 902", "418-902", and "418902" are the same
    /// code, and rejecting the first two would be pedantry aimed at the one
    /// person in the interaction who is already doing the tedious part.
    pub fn parse(input: &str) -> Result<Self, PairingError> {
        let digits: Vec<u8> = input
            .chars()
            .filter(char::is_ascii_digit)
            .filter_map(|c| c.to_digit(10))
            .map(|d| u8::try_from(d).unwrap_or(0))
            .collect();

        let digits: [u8; CODE_DIGITS] =
            digits.try_into().map_err(|_| PairingError::MalformedCode)?;

        Ok(Self { digits })
    }

    /// The bytes the key exchange is seeded with.
    /// Wiped by the caller's scope, so a spoken code leaves no copy behind.
    fn as_password(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.digits.to_vec())
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, digit) in self.digits.iter().enumerate() {
            if index == CODE_DIGITS / 2 {
                f.write_str(" ")?;
            }
            write!(f, "{digit}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the digits. A code in a log is a code an attacker can read, and
        // the whole security of the exchange rests on it staying between two
        // people for about a minute.
        f.write_str("PairingCode(hidden)")
    }
}

/// What can go wrong pairing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingError {
    #[error("a pairing code is {CODE_DIGITS} digits")]
    MalformedCode,

    #[error("the codes do not match, so the peer is not who it claims to be")]
    CodeMismatch,

    #[error("the peer sent a malformed pairing message")]
    MalformedMessage,
}

/// What each side sends after the key exchange completes.
///
/// Encrypted is the wrong word for it: the exchange produces a shared key, and
/// this carries the identity plus a tag proving the sender holds that key.
/// Anyone who guessed the code wrong derives a different key and produces a tag
/// that does not check out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAnnouncement {
    pub peer: PeerId,
    pub name: String,
    /// Proof the sender derived the same key from the same code.
    pub confirmation: [u8; 32],
}

/// One side of a pairing exchange.
///
/// Consuming rather than reusable: a `Pairing` performs exactly one exchange and
/// is destroyed by finishing it. That makes replaying a transcript against a
/// half-used state machine impossible to express.
pub struct Pairing {
    state: Spake2<Ed25519Group>,
    peer_id: PeerId,
    name: String,
}

impl fmt::Debug for Pairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pairing")
            .field("peer", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// The opening message, and the state needed to finish.
pub struct Opening {
    pub message: Vec<u8>,
    pub pairing: Pairing,
}

impl fmt::Debug for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opening")
            .field("message_bytes", &self.message.len())
            .finish_non_exhaustive()
    }
}

impl Pairing {
    /// Begins an exchange, producing the message to send.
    ///
    /// Symmetric: both sides run this and neither is the initiator. That matters
    /// because a KVM has no natural client and server for pairing purposes, and
    /// inventing one would mean asking the user which machine goes first.
    #[must_use]
    pub fn start(code: &PairingCode, peer_id: PeerId, name: String) -> Opening {
        let (state, message) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(code.as_password()),
            &SpakeIdentity::new(SPAKE_IDENTITY),
        );

        Opening {
            message,
            pairing: Self {
                state,
                peer_id,
                name,
            },
        }
    }

    /// Completes the exchange against the peer's opening message.
    ///
    /// Returns what to send, plus the shared key used to check their reply.
    pub fn finish(self, peer_message: &[u8]) -> Result<Completed, PairingError> {
        let key = Zeroizing::new(
            self.state
                .finish(peer_message)
                .map_err(|_| PairingError::MalformedMessage)?,
        );

        let announcement = IdentityAnnouncement {
            peer: self.peer_id,
            name: self.name,
            confirmation: confirmation_tag(&key, self.peer_id),
        };

        Ok(Completed { key, announcement })
    }
}

/// A finished exchange, awaiting the peer's announcement.
pub struct Completed {
    /// Wiped when this goes out of scope.
    ///
    /// The SPAKE2 shared key authenticates both announcements, so anyone
    /// holding it can mint one this machine would accept. It lives for the few
    /// milliseconds of an exchange and has no business outliving that in a core
    /// dump or in reused heap.
    key: Zeroizing<Vec<u8>>,
    pub announcement: IdentityAnnouncement,
}

impl fmt::Debug for Completed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The shared key is omitted deliberately.
        f.debug_struct("Completed")
            .field("announcement", &self.announcement)
            .finish_non_exhaustive()
    }
}

impl Completed {
    /// Checks the peer's announcement and yields the identity to trust.
    ///
    /// A wrong code produces a different shared key, so the tag fails here. That
    /// is the only place a mistyped or guessed code is caught, and it is caught
    /// before anything is written to the trust store.
    pub fn accept(&self, peer: &IdentityAnnouncement) -> Result<PeerId, PairingError> {
        let expected = confirmation_tag(&self.key, peer.peer);

        if !tags_match(&expected, &peer.confirmation) {
            return Err(PairingError::CodeMismatch);
        }
        Ok(peer.peer)
    }
}

/// Binds the shared key to the identity being announced.
///
/// The identity is inside the tag rather than beside it, so a man in the middle
/// who somehow held the key still could not substitute a different identity into
/// the message without invalidating it.
fn confirmation_tag(key: &[u8], peer: PeerId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"wraith-pairing-confirm-v1");
    hasher.update(key);
    hasher.update(peer.0);
    hasher.finalize().into()
}

/// Constant-time tag comparison.
///
/// This one genuinely matters. The tag is a secret derived from the code, and a
/// byte-at-a-time comparison would let an attacker recover it incrementally,
/// turning the single online guess described in the module documentation into
/// thirty-two cheap ones.
fn tags_match(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    /// Runs a full exchange between two sides.
    fn exchange(
        left_code: &PairingCode,
        right_code: &PairingCode,
    ) -> (Result<PeerId, PairingError>, Result<PeerId, PairingError>) {
        let left = Pairing::start(left_code, peer(1), "left".to_owned());
        let right = Pairing::start(right_code, peer(2), "right".to_owned());

        let left_done = left.pairing.finish(&right.message).unwrap();
        let right_done = right.pairing.finish(&left.message).unwrap();

        (
            left_done.accept(&right_done.announcement),
            right_done.accept(&left_done.announcement),
        )
    }

    #[test]
    fn a_generated_code_has_the_right_shape() {
        let code = PairingCode::generate();

        assert_eq!(code.digits.len(), CODE_DIGITS);
        assert!(code.digits.iter().all(|d| *d < 10));
    }

    #[test]
    fn a_code_is_displayed_in_two_readable_halves() {
        let code = PairingCode {
            digits: [4, 1, 8, 9, 0, 2],
        };

        assert_eq!(code.to_string(), "418 902");
    }

    #[test]
    fn a_code_parses_however_it_was_punctuated() {
        // The person typing is copying from someone speaking, and rejecting a
        // hyphen would be pedantry aimed at the one doing the tedious part.
        let expected = PairingCode {
            digits: [4, 1, 8, 9, 0, 2],
        };

        for spelling in ["418902", "418 902", "418-902", " 418  902 "] {
            assert_eq!(
                PairingCode::parse(spelling).unwrap(),
                expected,
                "failed on {spelling:?}"
            );
        }
    }

    #[test]
    fn a_code_of_the_wrong_length_is_refused() {
        assert_eq!(
            PairingCode::parse("12345"),
            Err(PairingError::MalformedCode)
        );
        assert_eq!(
            PairingCode::parse("1234567"),
            Err(PairingError::MalformedCode)
        );
        assert_eq!(PairingCode::parse(""), Err(PairingError::MalformedCode));
    }

    #[test]
    fn a_code_never_prints_its_digits_in_debug() {
        // A code in a log is a code an attacker can read.
        let code = PairingCode {
            digits: [4, 1, 8, 9, 0, 2],
        };

        let rendered = format!("{code:?}");

        assert!(
            !rendered.contains('4'),
            "the debug output leaked a digit: {rendered}"
        );
        assert!(
            !rendered.contains("418"),
            "the debug output leaked the code"
        );
    }

    #[test]
    fn matching_codes_pair_both_ways() {
        let code = PairingCode::generate();

        let (left, right) = exchange(&code, &code);

        assert_eq!(
            left.unwrap(),
            peer(2),
            "the left side did not learn the right identity"
        );
        assert_eq!(
            right.unwrap(),
            peer(1),
            "the right side did not learn the left identity"
        );
    }

    #[test]
    fn a_mistyped_code_is_refused_on_both_sides() {
        // The attacker's one guess, and the user's typo, are the same event.
        let (left, right) = exchange(
            &PairingCode {
                digits: [1, 1, 1, 1, 1, 1],
            },
            &PairingCode {
                digits: [2, 2, 2, 2, 2, 2],
            },
        );

        assert_eq!(left, Err(PairingError::CodeMismatch));
        assert_eq!(right, Err(PairingError::CodeMismatch));
    }

    #[test]
    fn a_code_differing_in_one_digit_is_refused() {
        // No partial credit. A near miss must be as fatal as a wild guess,
        // otherwise the guess space is smaller than it looks.
        let (left, _) = exchange(
            &PairingCode {
                digits: [4, 1, 8, 9, 0, 2],
            },
            &PairingCode {
                digits: [4, 1, 8, 9, 0, 3],
            },
        );

        assert_eq!(left, Err(PairingError::CodeMismatch));
    }

    #[test]
    fn a_malformed_opening_message_is_an_error_rather_than_a_panic() {
        // Attacker-controlled input arriving before any authentication.
        let code = PairingCode::generate();

        for garbage in [vec![], vec![0_u8; 1], vec![0xff_u8; 33], vec![7_u8; 4096]] {
            let opening = Pairing::start(&code, peer(1), "x".to_owned());
            let outcome = opening.pairing.finish(&garbage);

            assert!(
                matches!(outcome, Err(PairingError::MalformedMessage)),
                "a {}-byte message should be refused, not accepted",
                garbage.len()
            );
        }
    }

    #[test]
    fn substituting_a_different_identity_invalidates_the_tag() {
        // The identity is bound into the confirmation rather than sitting beside
        // it, so a peer that completed the exchange still cannot announce
        // somebody else's key.
        let code = PairingCode::generate();
        let left = Pairing::start(&code, peer(1), "left".to_owned());
        let right = Pairing::start(&code, peer(2), "right".to_owned());

        let left_done = left.pairing.finish(&right.message).unwrap();
        let right_done = right.pairing.finish(&left.message).unwrap();

        let mut forged = right_done.announcement;
        forged.peer = peer(99);

        assert_eq!(
            left_done.accept(&forged),
            Err(PairingError::CodeMismatch),
            "a substituted identity must invalidate the confirmation"
        );
    }

    #[test]
    fn a_tampered_confirmation_is_refused() {
        let code = PairingCode::generate();
        let left = Pairing::start(&code, peer(1), "left".to_owned());
        let right = Pairing::start(&code, peer(2), "right".to_owned());

        let left_done = left.pairing.finish(&right.message).unwrap();
        let right_done = right.pairing.finish(&left.message).unwrap();

        let mut tampered = right_done.announcement;
        tampered.confirmation[0] ^= 1;

        assert_eq!(left_done.accept(&tampered), Err(PairingError::CodeMismatch));
    }

    #[test]
    fn two_exchanges_with_the_same_code_produce_different_transcripts() {
        // SPAKE2 is randomised per exchange, so a recorded transcript cannot be
        // replayed against a later pairing with the same code.
        let code = PairingCode::generate();

        let first = Pairing::start(&code, peer(1), "x".to_owned());
        let second = Pairing::start(&code, peer(1), "x".to_owned());

        assert_ne!(first.message, second.message);
    }

    #[test]
    fn tag_comparison_catches_a_difference_anywhere() {
        let a = [3_u8; 32];

        for index in 0..32 {
            let mut b = a;
            b[index] ^= 1;
            assert!(
                !tags_match(&a, &b),
                "a difference at byte {index} was missed"
            );
        }
        assert!(tags_match(&a, &a));
    }
}
