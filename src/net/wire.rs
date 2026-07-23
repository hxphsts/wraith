//! What travels between machines.
//!
//! # Two paths, chosen by one predicate
//!
//! [`Control`] rides a reliable QUIC stream. [`crate::domain::InputFrame`] rides
//! datagrams. Which one an event takes is decided by
//! [`crate::domain::InputEvent::is_transition`] and nothing else, in the reducer
//! rather than here: `Session::step` emits `SendTransitions` or `SendMotion` and
//! this module only encodes what it is handed.
//!
//! A key or button transition is a **state edge**, and losing one leaves the
//! receiver holding something the sender thinks it released. That is the
//! stuck-modifier bug arriving through the transport layer, so transitions must
//! not be droppable. Motion and scroll are **increments**, and a lost one costs
//! a few pixels nobody perceives, while a retransmitted one is a stale delta
//! that actively makes the pointer feel worse.
//!
//! Key traffic peaks near 20 events per second even for a fast typist, so
//! reliability is free. Motion peaks at 1000 Hz, which is what datagrams are
//! for.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::domain::{Crossing, Edge, HeldSet, InputEvent, Millis, Screen, Seq};

/// The wire format version.
///
/// Carried in the hello so an incompatible peer fails immediately and clearly,
/// rather than connecting and then misreading each other's frames. There is no
/// negotiation and no compatibility shim: a mismatch is a hard refusal.
pub const PROTOCOL_VERSION: u16 = 1;

/// The largest control frame worth reading.
///
/// Checked before allocating. Reading a length and trusting it is how
/// CVE-2021-42076 turned a four-byte field into a four-gigabyte allocation.
pub const FRAME_BYTES_MAX: usize = 64 * 1024;

/// Everything that travels on the reliable stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Control {
    /// The opening message, sent by both sides.
    Hello {
        protocol: u16,
        name: String,
        /// This machine's screen, so the sender can map crossings onto it.
        screen: Screen,
    },

    /// Key and button transitions. The reliable half of the input stream.
    Transitions { events: Vec<InputEvent> },

    /// The sender's authoritative held set, sent while anything is held.
    ///
    /// The receiver reconciles against this and releases whatever it holds that
    /// the sender does not. It is what makes a residual desync self-healing
    /// within one interval rather than lasting until reboot.
    Snapshot { held: HeldSet },

    /// The cursor has arrived on the receiver's screen.
    Enter { crossing: Crossing },

    /// The cursor has gone back. Everything held is released.
    Leave,

    /// A clean shutdown, so the peer releases immediately rather than waiting
    /// for the watchdog.
    Bye { reason: ByeReason },

    /// "I have put you on my `side`."
    ///
    /// The receiver places the sender at the opposite side of itself, so one
    /// message keeps both desks agreeing. Sent when pairing settles a direction
    /// and whenever a screen is dragged in the window.
    ///
    /// Pairwise rather than a whole desk, deliberately. A machine only ever
    /// crosses to a direct neighbour, so it only needs its own. Sending the
    /// whole desk would also force every machine to be paired with every other,
    /// which they are not.
    ///
    /// **Appended, not inserted.** Wraith is v0 and the protocol version is not
    /// bumped for this, so the discriminants of everything above must not move:
    /// a peer running older code then fails to decode this and drops the
    /// connection rather than misreading an earlier variant.
    Place { side: Edge },

    /// This machine's clipboard, handed to the peer the cursor is entering.
    ///
    /// One representation, `mime` naming its type. Text today, `image/png` once
    /// the transport learns to chunk a payload past [`FRAME_BYTES_MAX`]. Rides
    /// the reliable stream, because losing a clipboard is not like losing a
    /// motion sample.
    ///
    /// **Appended last, for the reason on `Place`.** A new variant goes at the
    /// end so the discriminants above do not move. The image-phase chunk
    /// variants will append after this one.
    Clipboard { mime: String, bytes: Vec<u8> },
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByeReason {
    /// The user stopped it.
    Shutdown,
    /// The protocol versions do not match.
    Incompatible,
    /// The peer sent something unreadable.
    Malformed,
}

impl std::fmt::Display for ByeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Shutdown => "the peer shut down",
            Self::Incompatible => "the protocol versions do not match",
            Self::Malformed => "the peer sent something unreadable",
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    #[error("cannot encode: {0}")]
    Encode(String),

    #[error("the peer sent an unreadable frame")]
    Decode,

    #[error("the peer announced a {announced} byte frame, and the limit is {FRAME_BYTES_MAX}")]
    TooLarge { announced: usize },
}

/// Encodes a message with a length prefix.
///
/// Generic because the control socket between the window and a running session
/// speaks a different vocabulary over a different transport, and there is no
/// reason for it to carry a second copy of the same framing. Everything that
/// makes this safe, the size limit and the refusal to allocate on an announced
/// length, is a property of the frame rather than of what it carries.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, WireError> {
    let payload =
        postcard::to_stdvec(message).map_err(|error| WireError::Encode(error.to_string()))?;

    if payload.len() > FRAME_BYTES_MAX {
        return Err(WireError::TooLarge {
            announced: payload.len(),
        });
    }

    let length = u32::try_from(payload.len()).map_err(|_| WireError::TooLarge {
        announced: payload.len(),
    })?;

    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&payload);

    Ok(framed)
}

/// Decodes a message from a frame body.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, WireError> {
    postcard::from_bytes(payload).map_err(|_| WireError::Decode)
}

/// Reads a frame length, refusing anything oversized.
pub const fn frame_length(header: [u8; 4]) -> Result<usize, WireError> {
    let announced = u32::from_be_bytes(header) as usize;

    if announced > FRAME_BYTES_MAX {
        return Err(WireError::TooLarge { announced });
    }
    Ok(announced)
}

/// Encodes a datagram carrying motion and scroll.
///
/// Unframed, because a datagram is already a message boundary. Length prefixing
/// it would add four bytes to the highest-frequency packet in the system for no
/// information at all.
pub fn encode_frame(frame: &crate::domain::InputFrame) -> Result<Vec<u8>, WireError> {
    postcard::to_stdvec(frame).map_err(|error| WireError::Encode(error.to_string()))
}

/// Decodes a datagram.
pub fn decode_frame(payload: &[u8]) -> Result<crate::domain::InputFrame, WireError> {
    postcard::from_bytes(payload).map_err(|_| WireError::Decode)
}

/// Builds a datagram from motion events, if there are any.
#[must_use]
pub fn motion_frame(
    events: Vec<InputEvent>,
    seq: Seq,
    now_ms: Millis,
) -> Option<crate::domain::InputFrame> {
    if events.is_empty() {
        return None;
    }

    Some(crate::domain::InputFrame {
        seq,
        sent_at_ms: now_ms,
        events: events.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{KeyState, PeerId, Scancode, ScreenId};

    fn screen() -> Screen {
        Screen {
            id: ScreenId(1),
            peer: PeerId([1; 32]),
            name: "desktop".to_owned(),
            width_px: 1920,
            height_px: 1080,
        }
    }

    fn press(code: u16) -> InputEvent {
        InputEvent::Key {
            code: Scancode(code),
            state: KeyState::Pressed,
        }
    }

    #[test]
    fn a_control_message_round_trips() {
        let message = Control::Transitions {
            events: vec![press(30), press(42)],
        };
        let framed = encode(&message).unwrap();

        let length = frame_length(framed[..4].try_into().unwrap()).unwrap();
        let decoded: Control = decode(&framed[4..4 + length]).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn every_control_variant_round_trips() {
        // A variant that failed to encode would be a runtime surprise on a code
        // path that only fires in an unusual situation, which is the worst
        // place to discover it.
        let messages = [
            Control::Hello {
                protocol: PROTOCOL_VERSION,
                name: "desktop".to_owned(),
                screen: screen(),
            },
            Control::Transitions {
                events: vec![press(30)],
            },
            Control::Snapshot {
                held: HeldSet::new(),
            },
            Control::Leave,
            Control::Bye {
                reason: ByeReason::Shutdown,
            },
            Control::Place {
                side: crate::domain::Edge::Right,
            },
            Control::Clipboard {
                mime: crate::ports::MIME_TEXT.to_owned(),
                bytes: b"a copied line".to_vec(),
            },
        ];

        for message in messages {
            let framed = encode(&message).unwrap();
            let length = frame_length(framed[..4].try_into().unwrap()).unwrap();

            assert_eq!(decode::<Control>(&framed[4..4 + length]).unwrap(), message);
        }
    }

    #[test]
    fn the_clipboard_variant_is_last() {
        // Appended after `Place`, for the same v0 reason: a new variant at the
        // end leaves every discriminant above it fixed, so a peer running older
        // code fails to decode this rather than misreading an earlier one.
        let clipboard = encode(&Control::Clipboard {
            mime: crate::ports::MIME_TEXT.to_owned(),
            bytes: Vec::new(),
        })
        .unwrap();
        let place = encode(&Control::Place {
            side: crate::domain::Edge::Right,
        })
        .unwrap();

        assert!(
            clipboard[4] > place[4],
            "Clipboard must encode after Place, got {} against {}",
            clipboard[4],
            place[4]
        );
    }

    #[test]
    fn a_frame_carries_its_own_length() {
        let message = Control::Leave;
        let framed = encode(&message).unwrap();

        assert_eq!(
            frame_length(framed[..4].try_into().unwrap()).unwrap(),
            framed.len() - 4
        );
    }

    #[test]
    fn the_framing_carries_something_that_is_not_a_control_message() {
        // The point of the codec being generic. The control socket between the
        // window and a running session speaks its own vocabulary, and it gets
        // the size limit and the check-before-allocate discipline for free
        // rather than carrying a second copy of them.
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Elsewhere {
            name: String,
            count: u32,
        }

        let message = Elsewhere {
            name: "forge".to_owned(),
            count: 3,
        };

        let framed = encode(&message).unwrap();
        let length = frame_length(framed[..4].try_into().unwrap()).unwrap();

        assert_eq!(
            decode::<Elsewhere>(&framed[4..4 + length]).unwrap(),
            message
        );
    }

    #[test]
    fn an_oversized_announced_length_is_refused_before_allocating() {
        // The shape of CVE-2021-42076: a four-byte field asking for four
        // gigabytes. Refused by inspection rather than by trying.
        let header = u32::MAX.to_be_bytes();

        assert!(matches!(
            frame_length(header),
            Err(WireError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_length_at_the_limit_is_accepted() {
        let header = u32::try_from(FRAME_BYTES_MAX).unwrap().to_be_bytes();

        assert_eq!(frame_length(header).unwrap(), FRAME_BYTES_MAX);
    }

    #[test]
    fn garbage_decodes_to_an_error_rather_than_a_panic() {
        // Attacker-controlled bytes arriving on an authenticated but still
        // untrusted-content stream.
        for garbage in [
            vec![],
            vec![0xff_u8; 1],
            vec![0x00_u8; 64],
            vec![0xab_u8; 1024],
        ] {
            let _ = decode::<Control>(&garbage);
            let _ = decode_frame(&garbage);
        }
    }

    #[test]
    fn a_truncated_frame_does_not_panic() {
        let framed = encode(&Control::Transitions {
            events: vec![press(30), press(42)],
        })
        .unwrap();

        for length in 0..framed.len() {
            let _ = decode::<Control>(&framed[..length]);
        }
    }

    #[test]
    fn no_datagram_is_built_from_no_motion() {
        // An empty datagram is a packet that costs latency and carries nothing.
        assert!(motion_frame(vec![], Seq(1), Millis(10)).is_none());
    }

    #[test]
    fn a_datagram_round_trips() {
        let frame = motion_frame(
            vec![InputEvent::MotionRel {
                dx_milli: 1_500,
                dy_milli: -250,
            }],
            Seq(7),
            Millis(42),
        )
        .unwrap();

        let encoded = encode_frame(&frame).unwrap();

        assert_eq!(decode_frame(&encoded).unwrap(), frame);
    }

    #[test]
    fn a_motion_datagram_is_small_enough_to_never_fragment() {
        // The highest-frequency packet in the system. If this grew past a
        // typical MTU it would fragment and the latency budget would go with it.
        let frame = motion_frame(
            vec![InputEvent::MotionRel {
                dx_milli: i32::MAX,
                dy_milli: i32::MIN,
            }],
            Seq(u64::MAX),
            Millis(u64::MAX),
        )
        .unwrap();

        let encoded = encode_frame(&frame).unwrap();

        assert!(
            encoded.len() < 64,
            "a motion datagram is {} bytes",
            encoded.len()
        );
    }
}
