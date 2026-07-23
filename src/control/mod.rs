//! What the window and a running session say to each other.
//!
//! # One connection, one request
//!
//! A connection carries one [`Request`] and then a stream of [`Response`]s
//! until the session closes it. That single rule removes request ids,
//! correlation tables, multiplexing, reconnection, and keepalives, and it makes
//! **cancelling a pairing the same act as closing the socket**.
//!
//! A status costs one connect per second on a unix socket, which is
//! microseconds. That is the trade, and it is worth naming as one.
//!
//! # What this is not
//!
//! Not a second way to write `config.toml`. The desk has exactly one writer,
//! `serve::Desk`, and the window still edits it by writing the file. This
//! channel is for the questions a file cannot answer, and for the things that
//! have to happen inside the running process.

pub mod client;
pub mod server;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::domain::Edge;
use crate::net::wire::{self, WireError};

/// What this build speaks.
///
/// Carried in [`Status`] rather than in a hello frame, because the only client
/// that matters is the same binary and a handshake per connection at one
/// connection per second is waste.
///
/// **Bump this whenever a `Request` or `Response` variant is added or changed,**
/// and note what changed here. A window that subscribes to something the
/// running session has never heard of cannot decode the reply, so the
/// connection ends, the window reconnects a second later, and the two agree
/// they are on the same version for as long as it takes to notice.
///
/// 1: everything below, as first released.
pub const CONTROL_VERSION: u16 = 1;

/// Something the window asks a running session to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum Request {
    /// What the session is doing. One response.
    Status,

    /// Stop sharing and exit. Acknowledged before the shutdown begins, because
    /// afterwards there is nothing left to answer with.
    Stop,

    /// Re-read both files now rather than at the next poll.
    ///
    /// An optimisation from half a second to instant. The file watch is the
    /// mechanism, and this only makes it feel immediate.
    Reload,

    /// Machines on the LAN that are not paired yet. One response.
    Candidates,

    /// Offer pairing and show a code. Streams until it settles or the caller
    /// closes the connection.
    PairOffer { side: Option<Edge> },

    /// Untrust a machine and take it off the desk. One `Ack`.
    ///
    /// Through the session rather than around it, so the live trust set drops
    /// the key at once rather than at the next poll. Until it does, the machine
    /// just forgotten can still complete a handshake.
    Forget { name: String },

    /// Stream every crossing until the caller closes the connection.
    ///
    /// The same shape as `PairOffer`: a request that answers more than once and
    /// ends when the socket does. Cancelling is hanging up, so there is no
    /// unwatch request to keep in step with this one.
    Watch,

    /// Join a machine that is offering. Streams until it settles.
    PairJoin {
        address: String,
        code: String,
        side: Option<Edge>,
    },

    /// End a running pairing offer. One `Ack`, whether or not one was running.
    ///
    /// Closing the connection remains how the caller that opened an offer gives
    /// up, and is still the only cancel that path needs. This exists for the
    /// caller that did not open it: a window reopened after the one that
    /// started the offer has gone can see the offer in `Status` but has no
    /// socket of its own to close.
    PairCancel,
}

/// What a session says back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum Response {
    Status(Box<Status>),
    Candidates(Vec<Candidate>),

    /// The code to read out, and what to type on the other machine.
    PairingCode {
        code: String,
        join_hint: String,
        seconds_max: u64,
    },

    Paired {
        name: String,
        key: String,
        placed: bool,
    },

    /// One crossing, on a `Watch` stream.
    Crossed(Crossed),

    Ack,
    Refused(Refusal),
}

/// Why a request could not be carried out.
///
/// Typed rather than a string, because the window acts on the difference: a
/// mismatched code puts the cursor back in the code field, and a timeout offers
/// the same code again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    #[error("the codes do not match")]
    CodeMismatch,

    #[error("nobody joined before the timeout")]
    Timeout,

    #[error("a pairing is already running")]
    Busy,

    #[error("the pairing was cancelled")]
    Cancelled,

    #[error("this build speaks control {CONTROL_VERSION}, and the session speaks {theirs}")]
    Incompatible { theirs: u16 },

    /// The other machine's account of what went wrong.
    ///
    /// A string because it came from another process and the window cannot act
    /// on the difference. The variants above are the ones it can.
    #[error("{0}")]
    Peer(String),

    #[error("{0}")]
    Config(String),
}

/// What a session is doing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub protocol: u16,
    pub name: String,
    pub listen: String,
    pub uptime_ms: u64,

    /// How much longer a running pairing offer has, if one is running.
    ///
    /// Here because a window that has just opened has no other way to learn it.
    /// Without this a reopened sheet showed an inert button, and pressing it met
    /// a refusal describing a state nothing on screen had mentioned.
    ///
    /// Milliseconds of session uptime, so it subtracts from `uptime_ms` above
    /// without the two sides agreeing on a wall clock.
    pub pairing_left_ms: Option<u64>,

    /// The capture backend, or `None` if there is none.
    ///
    /// The one signal that explains "running, connected, and nothing happens".
    /// On macOS that is Input Monitoring not granted, and the window has no
    /// other way to learn it.
    pub backend_capture: Option<String>,

    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub name: String,
    pub key: String,
    pub connected: bool,
    pub address: Option<String>,
}

/// The cursor crossed an edge, as told to a watcher.
///
/// A flat copy of [`crate::domain::Command::Crossed`] rather than the command
/// itself, because the domain type is free to change shape and this one is on
/// the wire between two processes that may be different builds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Crossed {
    pub direction: Direction,
    /// The edge of this machine's screen, already resolved. A watcher never
    /// needs to work out which side it means.
    pub edge: Edge,
    /// How far along that edge, as thousandths.
    ///
    /// An integer because `Fraction` is an `f32` and this is a wire type, and a
    /// float on the wire invites two builds disagreeing in the last bit. A
    /// thousandth of a screen edge is far finer than anything drawable.
    pub at_permille: u16,
}

/// Which way the cursor went.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Departure,
    Arrival,
}

impl Crossed {
    /// Builds one from what the reducer emitted.
    #[must_use]
    pub fn new(
        direction: crate::domain::Direction,
        edge: Edge,
        at: crate::domain::Fraction,
    ) -> Self {
        // Rounded rather than truncated so 1.0 lands on 1000 and not 999, which
        // would put an effect at the far corner one pixel short of it.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "Fraction is clamped to 0..=1 on construction, so this is 0..=1000"
        )]
        let at_permille = (at.get() * 1000.0).round() as u16;

        Self {
            direction: direction.into(),
            edge,
            at_permille,
        }
    }

    /// Back to a fraction, for anything that has to position with it.
    #[must_use]
    pub fn at(self) -> f32 {
        f32::from(self.at_permille) / 1000.0
    }
}

impl From<crate::domain::Direction> for Direction {
    fn from(direction: crate::domain::Direction) -> Self {
        match direction {
            crate::domain::Direction::Departure => Self::Departure,
            crate::domain::Direction::Arrival => Self::Arrival,
        }
    }
}

/// A machine on the LAN that is not paired yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub short_key: String,
    pub address: String,
}

/// Reads one length-prefixed frame.
///
/// A `UnixStream` is not a quinn `RecvStream`, which is the only reason this
/// exists rather than reusing the reader in `net::wire`. The framing itself,
/// and its refusal to allocate on an announced length, is shared.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(from: &mut R) -> Result<Vec<u8>, WireError> {
    let mut header = [0_u8; 4];
    from.read_exact(&mut header)
        .await
        .map_err(|_| WireError::Decode)?;

    let length = wire::frame_length(header)?;
    let mut payload = vec![0_u8; length];
    from.read_exact(&mut payload)
        .await
        .map_err(|_| WireError::Decode)?;

    Ok(payload)
}

/// The same, for the window, which has no runtime.
pub(crate) fn read_frame_blocking<R: std::io::Read>(from: &mut R) -> Result<Vec<u8>, WireError> {
    let mut header = [0_u8; 4];
    from.read_exact(&mut header)
        .map_err(|_| WireError::Decode)?;

    let length = wire::frame_length(header)?;
    let mut payload = vec![0_u8; length];
    from.read_exact(&mut payload)
        .map_err(|_| WireError::Decode)?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_round_trips() {
        for request in [
            Request::Status,
            Request::Stop,
            Request::Reload,
            Request::Candidates,
            Request::PairOffer {
                side: Some(Edge::Right),
            },
            Request::Forget {
                name: "laptop".to_owned(),
            },
            Request::PairJoin {
                address: "forge:24811".to_owned(),
                code: "418902".to_owned(),
                side: None,
            },
        ] {
            let framed = wire::encode(&request).unwrap();
            let length = wire::frame_length(framed[..4].try_into().unwrap()).unwrap();

            assert_eq!(
                wire::decode::<Request>(&framed[4..4 + length]).unwrap(),
                request
            );
        }
    }

    #[test]
    fn every_response_round_trips() {
        for response in [
            Response::Ack,
            Response::Refused(Refusal::CodeMismatch),
            Response::Refused(Refusal::Incompatible { theirs: 7 }),
            Response::PairingCode {
                code: "418902".to_owned(),
                join_hint: "forge".to_owned(),
                seconds_max: 120,
            },
            Response::Paired {
                name: "laptop".to_owned(),
                key: "ab".repeat(32),
                placed: false,
            },
            Response::Candidates(vec![Candidate {
                name: "tablet".to_owned(),
                short_key: "abcd".to_owned(),
                address: "10.0.0.2:24811".to_owned(),
            }]),
        ] {
            let framed = wire::encode(&response).unwrap();
            let length = wire::frame_length(framed[..4].try_into().unwrap()).unwrap();

            assert_eq!(
                wire::decode::<Response>(&framed[4..4 + length]).unwrap(),
                response
            );
        }
    }

    #[test]
    fn a_refusal_the_window_acts_on_is_typed_rather_than_a_string() {
        // A mismatched code puts the cursor back in the code field, and a
        // timeout offers the same code again. Both would be unreachable behind
        // a string, which is why only the cases nothing can act on carry one.
        assert!(Refusal::CodeMismatch.to_string().contains("do not match"));
        assert_ne!(Refusal::CodeMismatch, Refusal::Timeout);
    }

    #[tokio::test]
    async fn a_frame_survives_the_reader() {
        let framed = wire::encode(&Request::Status).unwrap();
        let mut cursor = std::io::Cursor::new(framed);

        let payload = read_frame(&mut cursor).await.unwrap();

        assert_eq!(wire::decode::<Request>(&payload).unwrap(), Request::Status);
    }

    #[test]
    fn a_truncated_frame_is_an_error_rather_than_a_hang() {
        let framed = wire::encode(&Request::Status).unwrap();
        let mut cursor = std::io::Cursor::new(&framed[..2]);

        assert!(read_frame_blocking(&mut cursor).is_err());
    }
}
