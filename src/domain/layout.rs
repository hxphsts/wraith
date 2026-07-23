//! The shape of the desk, and how the cursor crosses between screens.
//!
//! A layout is a graph of screens joined at their edges. The only interesting
//! operation is [`Layout::cross`], which maps a departure point on one screen's
//! edge to an arrival point on another's, preserving the fraction of the way
//! along that edge. Leaving a 1440-tall screen 37 percent of the way down
//! arrives 37 percent of the way down a 1080-tall one, so the cursor appears to
//! travel in a straight line even between screens of different sizes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ids::{Fraction, PeerId, Point, ScreenId};

/// A side of a screen.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}

impl Edge {
    /// The edge a cursor arrives at, having left through this one.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
            Self::Top => Self::Bottom,
            Self::Bottom => Self::Top,
        }
    }

    /// Whether crossing this edge preserves the vertical position.
    ///
    /// Left and right edges are vertical lines, so a crossing through one keeps
    /// its height and varies only in x.
    #[must_use]
    pub const fn is_vertical_edge(self) -> bool {
        matches!(self, Self::Left | Self::Right)
    }

    pub const ALL: [Self; 4] = [Self::Left, Self::Right, Self::Top, Self::Bottom];
}

/// One screen in the layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Screen {
    pub id: ScreenId,
    pub peer: PeerId,
    pub name: String,
    pub width_px: u32,
    pub height_px: u32,
}

impl Screen {
    /// One screen, as a peer describes itself.
    ///
    /// A constructor rather than a struct literal, so a field added later is an
    /// ordinary change instead of one that breaks every caller. The dimensions
    /// are what a crossing's fraction is measured against, so a screen that
    /// claims the wrong size lands the cursor in the wrong place.
    #[must_use]
    pub fn new(id: ScreenId, peer: PeerId, name: impl Into<String>, size_px: (u32, u32)) -> Self {
        Self {
            id,
            peer,
            name: name.into(),
            width_px: size_px.0,
            height_px: size_px.1,
        }
    }

    /// The last addressable pixel in each axis.
    #[must_use]
    pub fn last_pixel(&self) -> Point {
        Point::new(
            i32::try_from(self.width_px.saturating_sub(1)).unwrap_or(i32::MAX),
            i32::try_from(self.height_px.saturating_sub(1)).unwrap_or(i32::MAX),
        )
    }
}

/// What a layout can be wrong about.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LayoutError {
    #[error("screen {0} is already in the layout")]
    DuplicateScreen(ScreenId),

    #[error("screen {0} is not in the layout")]
    UnknownScreen(ScreenId),

    #[error("screen {0} cannot be its own neighbour")]
    SelfLink(ScreenId),

    #[error("screen {screen} has zero {axis}")]
    ZeroSized {
        screen: ScreenId,
        axis: &'static str,
    },

    #[error("{0} edge of screen {1} already leads somewhere")]
    EdgeOccupied(&'static str, ScreenId),
}

/// Where a crossing lands.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct Crossing {
    /// The screen being entered.
    pub to: ScreenId,
    /// The edge of that screen the cursor appears at.
    pub entry_edge: Edge,
    /// How far along that edge, preserved from the departure.
    pub at: Fraction,
    /// The arrival point in the entered screen's pixel space.
    pub entry_px: Point,
}

/// The desk: screens, and how they join.
#[derive(Clone, Debug, Default)]
pub struct Layout {
    screens: BTreeMap<ScreenId, Screen>,
    links: BTreeMap<(ScreenId, Edge), ScreenId>,
}

impl Layout {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a screen's real size, learned from its hello.
    ///
    /// The layout is built from a file, which says where a machine sits and
    /// nothing about how big it is, so every remote screen starts as a guess:
    /// this machine's own size. Only the far machine knows the truth, and it
    /// says so within a handshake of connecting.
    ///
    /// Until this is applied, a crossing is mapped onto the wrong rectangle.
    /// Between a 3024x1964 laptop and a 10240x2880 desk that puts the arriving
    /// cursor two thirds of the way up a screen it should have entered at the
    /// very bottom of, with only a third of the width reachable.
    ///
    /// Returns whether anything changed, so a caller can rebuild only when it
    /// has to.
    pub fn resize_screen(&mut self, id: ScreenId, width_px: u32, height_px: u32) -> bool {
        // A zero would divide by zero in `entry_point`, and a peer that reports
        // one is better ignored than believed.
        if width_px == 0 || height_px == 0 {
            return false;
        }

        let Some(screen) = self.screens.get_mut(&id) else {
            return false;
        };
        if screen.width_px == width_px && screen.height_px == height_px {
            return false;
        }

        screen.width_px = width_px;
        screen.height_px = height_px;
        true
    }

    /// Adds a screen. A zero dimension is rejected here rather than producing a
    /// division by zero later.
    pub fn add_screen(&mut self, screen: Screen) -> Result<(), LayoutError> {
        if self.screens.contains_key(&screen.id) {
            return Err(LayoutError::DuplicateScreen(screen.id));
        }
        if screen.width_px == 0 {
            return Err(LayoutError::ZeroSized {
                screen: screen.id,
                axis: "width",
            });
        }
        if screen.height_px == 0 {
            return Err(LayoutError::ZeroSized {
                screen: screen.id,
                axis: "height",
            });
        }

        self.screens.insert(screen.id, screen);
        Ok(())
    }

    /// Joins two screens, and installs the reciprocal link.
    ///
    /// A one-way edge is always a mistake: the cursor would cross and have no
    /// way back. Rather than validate against that later, it is made
    /// unrepresentable by constructing both directions here.
    pub fn link(&mut self, from: ScreenId, edge: Edge, to: ScreenId) -> Result<(), LayoutError> {
        if from == to {
            return Err(LayoutError::SelfLink(from));
        }
        for id in [from, to] {
            if !self.screens.contains_key(&id) {
                return Err(LayoutError::UnknownScreen(id));
            }
        }

        let back = edge.opposite();
        if self.links.contains_key(&(from, edge)) {
            return Err(LayoutError::EdgeOccupied(edge.name(), from));
        }
        if self.links.contains_key(&(to, back)) {
            return Err(LayoutError::EdgeOccupied(back.name(), to));
        }

        self.links.insert((from, edge), to);
        self.links.insert((to, back), from);
        Ok(())
    }

    #[must_use]
    pub fn screen(&self, id: ScreenId) -> Option<&Screen> {
        self.screens.get(&id)
    }

    #[must_use]
    pub fn neighbour(&self, from: ScreenId, edge: Edge) -> Option<ScreenId> {
        self.links.get(&(from, edge)).copied()
    }

    pub fn screens(&self) -> impl Iterator<Item = &Screen> {
        self.screens.values()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.screens.is_empty()
    }

    /// Maps a departure off `edge` of `from`, at fraction `at`, to an arrival.
    ///
    /// Returns `None` when nothing lies that way, which is how the cursor knows
    /// to stay put at the outer boundary of the desk.
    #[must_use]
    pub fn cross(&self, from: ScreenId, edge: Edge, at: Fraction) -> Option<Crossing> {
        let to = self.neighbour(from, edge)?;
        let target = self.screens.get(&to)?;
        let entry_edge = edge.opposite();

        Some(Crossing {
            to,
            entry_edge,
            at,
            entry_px: entry_point(target, entry_edge, at),
        })
    }
}

/// The arrival point, inset one pixel from the edge it enters through.
///
/// The inset matters. Landing exactly on the boundary would place the cursor
/// already touching the wall it just came through, so the very next motion into
/// that wall would satisfy the return test and the cursor would bounce back.
/// One pixel of clearance costs nothing visually and removes the oscillation.
fn entry_point(screen: &Screen, entry_edge: Edge, at: Fraction) -> Point {
    let last = screen.last_pixel();

    match entry_edge {
        Edge::Left => Point::new(1.min(last.x_px), at.along_span(screen.height_px)),
        Edge::Right => Point::new((last.x_px - 1).max(0), at.along_span(screen.height_px)),
        Edge::Top => Point::new(at.along_span(screen.width_px), 1.min(last.y_px)),
        Edge::Bottom => Point::new(at.along_span(screen.width_px), (last.y_px - 1).max(0)),
    }
}

impl Edge {
    const fn name(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Top => "top",
            Self::Bottom => "bottom",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESKTOP: ScreenId = ScreenId(1);
    const LAPTOP: ScreenId = ScreenId(2);

    fn screen(id: ScreenId, width_px: u32, height_px: u32) -> Screen {
        Screen {
            id,
            peer: PeerId([u8::try_from(id.0).unwrap_or(0); 32]),
            name: format!("screen{}", id.0),
            width_px,
            height_px,
        }
    }

    /// A 2560x1440 desktop with a 1920x1080 laptop to its right.
    fn desk() -> Layout {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 2560, 1440)).unwrap();
        layout.add_screen(screen(LAPTOP, 1920, 1080)).unwrap();
        layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();
        layout
    }

    #[test]
    fn opposite_edges_round_trip() {
        for edge in Edge::ALL {
            assert_eq!(edge.opposite().opposite(), edge);
        }
    }

    #[test]
    fn linking_installs_the_reciprocal_edge() {
        // A one-way link would strand the cursor on the far screen.
        let layout = desk();

        assert_eq!(layout.neighbour(DESKTOP, Edge::Right), Some(LAPTOP));
        assert_eq!(layout.neighbour(LAPTOP, Edge::Left), Some(DESKTOP));
    }

    #[test]
    fn an_unlinked_edge_leads_nowhere() {
        let layout = desk();

        assert_eq!(layout.neighbour(DESKTOP, Edge::Left), None);
        assert!(
            layout
                .cross(DESKTOP, Edge::Left, Fraction::MIDDLE)
                .is_none()
        );
    }

    #[test]
    fn a_screen_cannot_be_its_own_neighbour() {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 2560, 1440)).unwrap();

        assert_eq!(
            layout.link(DESKTOP, Edge::Right, DESKTOP),
            Err(LayoutError::SelfLink(DESKTOP))
        );
    }

    #[test]
    fn linking_an_unknown_screen_is_rejected() {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 2560, 1440)).unwrap();

        assert_eq!(
            layout.link(DESKTOP, Edge::Right, LAPTOP),
            Err(LayoutError::UnknownScreen(LAPTOP))
        );
    }

    #[test]
    fn an_edge_cannot_lead_to_two_screens() {
        let mut layout = desk();
        layout.add_screen(screen(ScreenId(3), 800, 600)).unwrap();

        assert!(layout.link(DESKTOP, Edge::Right, ScreenId(3)).is_err());
    }

    #[test]
    fn linking_is_rejected_when_the_reciprocal_edge_is_taken() {
        // The left edge of the laptop already leads to the desktop, so nothing
        // else may claim it even though the forward edge is free.
        let mut layout = desk();
        layout.add_screen(screen(ScreenId(3), 800, 600)).unwrap();

        assert!(layout.link(ScreenId(3), Edge::Right, LAPTOP).is_err());
    }

    #[test]
    fn a_duplicate_screen_is_rejected() {
        let mut layout = desk();
        assert_eq!(
            layout.add_screen(screen(DESKTOP, 800, 600)),
            Err(LayoutError::DuplicateScreen(DESKTOP))
        );
    }

    #[test]
    fn a_zero_sized_screen_is_rejected() {
        // Otherwise the fraction arithmetic divides by zero downstream.
        let mut layout = Layout::new();

        assert!(layout.add_screen(screen(DESKTOP, 0, 1440)).is_err());
        assert!(layout.add_screen(screen(DESKTOP, 2560, 0)).is_err());
    }

    #[test]
    fn crossing_preserves_the_fraction_across_mismatched_resolutions() {
        // Leaving the 1440-tall desktop 37 percent down should arrive 37 percent
        // down the 1080-tall laptop, which is 400 pixels rather than 533.
        let layout = desk();
        let departure = Fraction::of_span(533, 1440);

        let crossing = layout.cross(DESKTOP, Edge::Right, departure).unwrap();

        assert_eq!(crossing.to, LAPTOP);
        assert_eq!(crossing.entry_edge, Edge::Left);
        assert!(
            (crossing.entry_px.y_px - 400).abs() <= 1,
            "arrived at y={}, expected within a pixel of 400",
            crossing.entry_px.y_px
        );
    }

    #[test]
    fn crossing_right_enters_on_the_left() {
        let layout = desk();

        let crossing = layout
            .cross(DESKTOP, Edge::Right, Fraction::MIDDLE)
            .unwrap();

        assert_eq!(crossing.entry_edge, Edge::Left);
        assert_eq!(
            crossing.entry_px.x_px, 1,
            "inset one pixel from the edge it entered"
        );
    }

    #[test]
    fn crossing_left_enters_on_the_right() {
        let layout = desk();

        let crossing = layout.cross(LAPTOP, Edge::Left, Fraction::MIDDLE).unwrap();

        assert_eq!(crossing.to, DESKTOP);
        assert_eq!(crossing.entry_edge, Edge::Right);
        assert_eq!(
            crossing.entry_px.x_px, 2558,
            "inset one pixel from the 2559 boundary"
        );
    }

    #[test]
    fn vertical_crossings_preserve_the_horizontal_fraction() {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 2560, 1440)).unwrap();
        layout.add_screen(screen(LAPTOP, 1920, 1080)).unwrap();
        layout.link(DESKTOP, Edge::Top, LAPTOP).unwrap();

        let crossing = layout.cross(DESKTOP, Edge::Top, Fraction::MIDDLE).unwrap();

        assert_eq!(crossing.entry_edge, Edge::Bottom);
        assert_eq!(crossing.entry_px.x_px, 960, "half of 1920");
        assert_eq!(
            crossing.entry_px.y_px, 1078,
            "inset one pixel from the 1079 boundary"
        );
    }

    #[test]
    fn the_entry_point_is_never_on_the_edge_it_entered_through() {
        // Landing on the boundary would put the cursor already touching the wall
        // it just came through, so the next motion into that wall would bounce
        // it straight back.
        let layout = desk();

        for fraction in [Fraction::START, Fraction::MIDDLE, Fraction::END] {
            let crossing = layout.cross(DESKTOP, Edge::Right, fraction).unwrap();
            assert!(crossing.entry_px.x_px > 0, "landed on the left boundary");
        }
    }

    #[test]
    fn a_crossing_round_trip_returns_to_roughly_where_it_left() {
        let layout = desk();
        let departure = Fraction::of_span(720, 1440);

        let out = layout.cross(DESKTOP, Edge::Right, departure).unwrap();
        let back = layout.cross(out.to, Edge::Left, out.at).unwrap();

        assert_eq!(back.to, DESKTOP);
        assert!(
            (back.entry_px.y_px - 720).abs() <= 1,
            "returned to y={}, expected within a pixel of 720",
            back.entry_px.y_px
        );
    }

    #[test]
    fn a_one_pixel_wide_screen_does_not_produce_a_negative_coordinate() {
        // Degenerate, but the inset arithmetic must not underflow into a
        // coordinate outside the screen.
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 2560, 1440)).unwrap();
        layout.add_screen(screen(LAPTOP, 1, 1)).unwrap();
        layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();

        let crossing = layout
            .cross(DESKTOP, Edge::Right, Fraction::MIDDLE)
            .unwrap();

        assert_eq!(crossing.entry_px, Point::new(0, 0));
    }
}
