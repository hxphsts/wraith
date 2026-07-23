//! The pure core.
//!
//! No I/O, no platform knowledge, no async, and no clock. Time arrives as
//! [`ids::Millis`] rather than from `Instant::now`, which is what makes every
//! test here exact: the watchdog tests assert on the millisecond either side of
//! a deadline without sleeping, and the property tests replay arbitrary event
//! sequences deterministically.
//!
//! Nothing in this module may import from `net`, `platform`, or `run`.

pub mod cursor;
pub mod grid;
pub mod ids;
pub mod input;
pub mod layout;
pub mod ledger;
pub mod notice;
pub mod session;

pub use cursor::{CursorConfig, CursorMachine, CursorOutcome, Locus};
pub use grid::{Cell, Grid, GridError};
pub use ids::{Fraction, Millis, PeerId, Point, ScreenId, Seq};
pub use input::{
    Button, HeldSet, InputEvent, InputFrame, KeyState, MODIFIER_SCANCODES, Modifiers, Scancode,
};
pub use layout::{Crossing, Edge, Layout, LayoutError, Screen};
pub use ledger::{DropReason, InputLedger, LedgerConfig, ReleaseReason};
pub use notice::Notice;
pub use session::{Command, Direction, Input, Session, SessionConfig};
