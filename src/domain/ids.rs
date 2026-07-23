//! Identifiers, time, and geometry.
//!
//! Time is the important one. The domain never calls `Instant::now`, it receives
//! [`Millis`] as data. That is what makes every test in `domain` exact rather
//! than timing-dependent, including the watchdog tests that would otherwise need
//! to sleep.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Monotonic milliseconds since the session began.
///
/// Not a wall clock. Comparisons are only meaningful within one session, which
/// is all the domain ever needs.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize,
)]
pub struct Millis(pub u64);

impl Millis {
    pub const ZERO: Self = Self(0);

    /// Milliseconds elapsed since `earlier`, saturating at zero.
    ///
    /// Saturating rather than wrapping because a clock that appears to go
    /// backwards should read as "no time has passed", never as fifty days.
    #[must_use]
    pub const fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    #[must_use]
    pub const fn plus(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }
}

impl fmt::Display for Millis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// A monotonic counter on the unreliable datagram path.
///
/// Datagrams arrive out of order or not at all, so the receiver drops anything
/// that is not newer than what it has already applied.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize,
)]
pub struct Seq(pub u64);

impl Seq {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// A peer's long-term Ed25519 public key.
///
/// The identity is the key. There is no other name for a machine, no registry to
/// consult, and nothing to spoof: a peer either presents this key in the TLS
/// handshake or it is not that peer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// The first eight bytes as hex, which is what a user sees in `wraith peers`.
    ///
    /// Sixteen characters is enough to tell two machines on a desk apart, and
    /// short enough to read aloud. It is never used to make a trust decision, so
    /// the truncation is presentational rather than security relevant.
    #[must_use]
    pub fn short(&self) -> String {
        use std::fmt::Write as _;

        self.0[..8]
            .iter()
            .fold(String::with_capacity(16), |mut out, byte| {
                // Writing into a String is infallible, so the result is discarded
                // rather than unwrapped.
                let _ = write!(out, "{byte:02x}");
                out
            })
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.short())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

/// A screen in the layout.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ScreenId(pub u32);

impl fmt::Display for ScreenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "screen{}", self.0)
    }
}

/// A position along a screen edge. Zero is top or left, one is bottom or right.
///
/// Clamped on construction, so an out-of-range `Fraction` cannot exist. This is
/// what preserves cursor height across screens of different resolutions: leaving
/// one screen 37 percent of the way down its right edge arrives 37 percent of
/// the way down the next screen's left edge, whatever either is measured in.
#[derive(Clone, Copy, PartialEq, PartialOrd, Debug, Default, Serialize, Deserialize)]
pub struct Fraction(f32);

impl Fraction {
    pub const START: Self = Self(0.0);
    pub const MIDDLE: Self = Self(0.5);
    pub const END: Self = Self(1.0);

    /// Clamps into range, mapping a non-finite input to the middle.
    ///
    /// A NaN here would come from a zero-height screen, and silently landing the
    /// cursor in the middle beats propagating a NaN into a coordinate.
    #[must_use]
    pub const fn new(value: f32) -> Self {
        if value.is_finite() {
            Self(value.clamp(0.0, 1.0))
        } else {
            Self::MIDDLE
        }
    }

    /// The fraction of the way `position` lies along a span of `length`.
    #[must_use]
    pub fn of_span(position: i32, length: u32) -> Self {
        if length == 0 {
            return Self::MIDDLE;
        }
        Self::new(as_f32(position) / as_f32_unsigned(length))
    }

    /// This fraction projected onto a span of `length`, in pixels.
    #[must_use]
    pub fn along_span(self, length: u32) -> i32 {
        // Rounding rather than truncating so a midpoint crossing lands on the
        // midpoint, and clamping so the last pixel stays reachable.
        let scaled = (self.0 * as_f32_unsigned(length)).round();
        let last = i32::try_from(length.saturating_sub(1)).unwrap_or(i32::MAX);

        as_pixels(scaled).clamp(0, last)
    }

    #[must_use]
    pub const fn get(self) -> f32 {
        self.0
    }
}

/// A point in a screen's own pixel space, with the origin at its top left.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Point {
    pub x_px: i32,
    pub y_px: i32,
}

impl Point {
    #[must_use]
    pub const fn new(x_px: i32, y_px: i32) -> Self {
        Self { x_px, y_px }
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.x_px, self.y_px)
    }
}

/// A pixel coordinate as `f32`.
///
/// `f32` represents every integer up to 2^24, which is 16.7 million. No display
/// is 16 million pixels across, so this is exact for every real input and the
/// precision-loss lint is describing a case that cannot occur here.
#[expect(
    clippy::cast_precision_loss,
    reason = "screen dimensions are far below 2^24"
)]
const fn as_f32(pixels: i32) -> f32 {
    pixels as f32
}

/// A pixel count as `f32`. See [`as_f32`].
#[expect(
    clippy::cast_precision_loss,
    reason = "screen dimensions are far below 2^24"
)]
const fn as_f32_unsigned(pixels: u32) -> f32 {
    pixels as f32
}

/// A rounded `f32` back to a pixel coordinate.
///
/// Callers pass a value already bounded by a screen dimension, so the
/// truncation the lint warns about cannot happen. Saturation is the behaviour
/// anyway, since Rust float-to-int casts saturate rather than wrap.
#[expect(
    clippy::cast_possible_truncation,
    reason = "input is bounded by a screen dimension"
)]
const fn as_pixels(value: f32) -> i32 {
    value as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millis_since_saturates_rather_than_wrapping() {
        let early = Millis(100);
        let late = Millis(400);

        assert_eq!(late.since(early), 300);
        assert_eq!(
            early.since(late),
            0,
            "a backwards clock reads as no elapsed time"
        );
    }

    #[test]
    fn fraction_clamps_out_of_range_input() {
        assert!((Fraction::new(-3.0).get() - 0.0).abs() < f32::EPSILON);
        assert!((Fraction::new(9.0).get() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn fraction_maps_non_finite_input_to_the_middle() {
        assert_eq!(Fraction::new(f32::NAN), Fraction::MIDDLE);
        assert_eq!(Fraction::new(f32::INFINITY), Fraction::MIDDLE);
    }

    #[test]
    fn fraction_of_a_zero_length_span_is_the_middle() {
        assert_eq!(Fraction::of_span(0, 0), Fraction::MIDDLE);
    }

    #[test]
    fn fraction_round_trips_across_mismatched_resolutions() {
        // Leaving a 1440-tall screen 37 percent down should arrive 37 percent
        // down a 1080-tall one. This is the whole point of the type.
        let departure = Fraction::of_span(533, 1440);
        let arrival = departure.along_span(1080);

        let expected = 399; // 0.37 of 1080
        assert!(
            (arrival - expected).abs() <= 1,
            "arrived at {arrival}, expected within one pixel of {expected}"
        );
    }

    #[test]
    fn fraction_end_lands_on_the_last_pixel_not_past_it() {
        assert_eq!(Fraction::END.along_span(1080), 1079);
    }

    #[test]
    fn peer_id_short_form_is_sixteen_hex_characters() {
        let peer = PeerId([0xab; 32]);
        assert_eq!(peer.short(), "abababababababab");
    }
}
