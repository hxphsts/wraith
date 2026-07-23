//! What this machine's screens look like.

use crate::domain::Point;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScreenInfoError {
    #[error("could not read screen geometry: {0}")]
    Backend(String),
}

/// The local screen geometry.
///
/// A machine reports one logical screen, whatever its physical monitor count.
/// Wraith crosses between machines, and a multi-monitor desktop is already a
/// single continuous space its own compositor manages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct LocalScreen {
    pub width_px: u32,
    pub height_px: u32,
}

/// Reads local screen geometry and pointer position.
///
/// Synchronous. See the module documentation in [`super`].
pub trait ScreenInfo: Send {
    fn local_screen(&self) -> Result<LocalScreen, ScreenInfoError>;

    fn cursor_position(&self) -> Result<Point, ScreenInfoError>;
}
