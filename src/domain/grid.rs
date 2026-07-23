//! The desk as a grid of cells.
//!
//! # Why cells rather than neighbours
//!
//! A list of declared edges says each fact twice: "my right is the laptop, the
//! laptop's left is me". Nothing checks the two agree, a typo invents a screen,
//! and an edge can point one way only.
//!
//! A grid makes all three unrepresentable. **Adjacency is the link**, so there
//! is exactly one statement of each fact, a name that is not on the desk simply
//! is not on the desk, and every edge is reciprocal because being next to each
//! other is symmetric.
//!
//! It is also what a person pictures. Nobody thinks "my right is the laptop";
//! they think the laptop is over there. That is the whole reason the window can
//! be a picture you drag rather than a form.
//!
//! # What it deliberately cannot express
//!
//! A screen whose right edge leads somewhere its neighbour's left edge does not
//! lead back. A desk is a grid, so this loses nothing anyone wanted.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::layout::Edge;

/// A position on the desk. The local machine is not necessarily the origin.
///
/// Serialised as `[column, row]` rather than as a struct, so a desk file reads
/// `at = [1, 0]` on one line instead of sprouting a `[screen.at]` sub-table
/// that pushes every other field of the screen out below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(from = "(i32, i32)", into = "(i32, i32)")]
pub struct Cell {
    pub column: i32,
    pub row: i32,
}

impl From<(i32, i32)> for Cell {
    fn from((column, row): (i32, i32)) -> Self {
        Self { column, row }
    }
}

impl From<Cell> for (i32, i32) {
    fn from(cell: Cell) -> Self {
        (cell.column, cell.row)
    }
}

impl Cell {
    pub const ORIGIN: Self = Self { column: 0, row: 0 };

    #[must_use]
    pub const fn new(column: i32, row: i32) -> Self {
        Self { column, row }
    }

    /// The cell one step in a direction.
    ///
    /// Saturating, so a desk cannot be pushed off the end of the number line by
    /// a very determined drag.
    #[must_use]
    pub const fn step(self, edge: Edge) -> Self {
        match edge {
            Edge::Left => Self {
                column: self.column.saturating_sub(1),
                row: self.row,
            },
            Edge::Right => Self {
                column: self.column.saturating_add(1),
                row: self.row,
            },
            Edge::Top => Self {
                column: self.column,
                row: self.row.saturating_sub(1),
            },
            Edge::Bottom => Self {
                column: self.column,
                row: self.row.saturating_add(1),
            },
        }
    }

    /// The direction from this cell to an adjacent one, if they touch.
    ///
    /// `None` for diagonals and for anything further away. Diagonal screens are
    /// deliberately not linked: a cursor pushed at a corner has no unambiguous
    /// place to land.
    #[must_use]
    pub const fn direction_to(self, other: Self) -> Option<Edge> {
        match (other.column - self.column, other.row - self.row) {
            (1, 0) => Some(Edge::Right),
            (-1, 0) => Some(Edge::Left),
            (0, 1) => Some(Edge::Bottom),
            (0, -1) => Some(Edge::Top),
            _ => None,
        }
    }
}

/// What a placement can be wrong about.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GridError {
    #[error("{occupant} is already at column {}, row {}", .at.column, .at.row)]
    Occupied { at: Cell, occupant: String },
}

/// Where each screen sits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grid {
    cells: BTreeMap<String, Cell>,
}

impl Grid {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a grid from name and cell pairs, ignoring later collisions.
    ///
    /// Forgiving because it reads a file that may have been edited by hand. A
    /// collision is reported by [`Self::collisions`] rather than refused here,
    /// so the window can show the problem instead of failing to open.
    #[must_use]
    pub fn of(placements: impl IntoIterator<Item = (String, Cell)>) -> Self {
        let mut grid = Self::new();
        for (name, at) in placements {
            grid.cells.entry(name).or_insert(at);
        }
        grid
    }

    /// Puts a screen at a cell, refusing to stack it on another.
    pub fn place(&mut self, name: &str, at: Cell) -> Result<(), GridError> {
        if let Some(occupant) = self.at(at)
            && occupant != name
        {
            return Err(GridError::Occupied {
                at,
                occupant: occupant.to_owned(),
            });
        }

        self.cells.insert(name.to_owned(), at);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.cells.remove(name).is_some()
    }

    #[must_use]
    pub fn cell_of(&self, name: &str) -> Option<Cell> {
        self.cells.get(name).copied()
    }

    #[must_use]
    pub fn at(&self, cell: Cell) -> Option<&str> {
        self.cells
            .iter()
            .find(|(_, placed)| **placed == cell)
            .map(|(name, _)| name.as_str())
    }

    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.cells.contains_key(name)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, Cell)> {
        self.cells.iter().map(|(name, at)| (name.as_str(), *at))
    }

    /// The extent of the desk, for sizing a picture of it.
    ///
    /// An empty desk reports the origin twice, so a caller can draw a single
    /// empty cell rather than special-casing nothing.
    #[must_use]
    pub fn bounds(&self) -> (Cell, Cell) {
        let mut min = Cell::ORIGIN;
        let mut max = Cell::ORIGIN;

        for cell in self.cells.values() {
            min.column = min.column.min(cell.column);
            min.row = min.row.min(cell.row);
            max.column = max.column.max(cell.column);
            max.row = max.row.max(cell.row);
        }
        (min, max)
    }

    /// The screens touching this one, and which way.
    ///
    /// The only place links come from. Because adjacency is symmetric, every
    /// edge yielded here has its reciprocal yielded from the other side, so a
    /// one-way link cannot exist.
    pub fn neighbours(&self, name: &str) -> impl Iterator<Item = (Edge, &str)> {
        let here = self.cell_of(name);

        Edge::ALL.into_iter().filter_map(move |edge| {
            let here = here?;
            self.at(here.step(edge)).map(|neighbour| (edge, neighbour))
        })
    }

    /// The nearest empty cell in a direction.
    ///
    /// Walks outward rather than returning the adjacent cell, so pairing a third
    /// machine "to the right" puts it beyond the second rather than on top of
    /// it. Bounded, because a saturating step on a full row would otherwise spin
    /// forever.
    #[must_use]
    pub fn free_cell(&self, from: Cell, toward: Edge) -> Cell {
        let mut candidate = from.step(toward);

        for _ in 0..self.cells.len().saturating_add(1) {
            if self.at(candidate).is_none() {
                return candidate;
            }
            candidate = candidate.step(toward);
        }
        candidate
    }

    /// Every screen reachable from this one by walking adjacent cells.
    ///
    /// A screen the cursor can never arrive at is worth reporting, because it
    /// looks placed and does nothing. Includes the starting screen.
    #[must_use]
    pub fn reachable_from(&self, name: &str) -> BTreeSet<&str> {
        let mut seen = BTreeSet::new();
        if !self.contains(name) {
            return seen;
        }

        let mut queue = VecDeque::from([name]);
        while let Some(here) = queue.pop_front() {
            let Some(here) = self
                .cells
                .get_key_value(here)
                .map(|(name, _)| name.as_str())
            else {
                continue;
            };
            if !seen.insert(here) {
                continue;
            }
            queue.extend(self.neighbours(here).map(|(_, neighbour)| neighbour));
        }
        seen
    }

    /// Screens sharing a cell with another, which a hand-edited file can create.
    #[must_use]
    pub fn collisions(&self) -> Vec<(&str, Cell)> {
        let mut seen: BTreeMap<Cell, &str> = BTreeMap::new();
        let mut clashing = Vec::new();

        for (name, at) in self.iter() {
            if seen.insert(at, name).is_some() {
                clashing.push((name, at));
            }
        }
        clashing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grid(placements: &[(&str, i32, i32)]) -> Grid {
        Grid::of(
            placements
                .iter()
                .map(|(name, column, row)| ((*name).to_owned(), Cell::new(*column, *row))),
        )
    }

    /// A desktop with a laptop to its right.
    fn desk() -> Grid {
        grid(&[("desktop", 0, 0), ("laptop", 1, 0)])
    }

    fn neighbours(grid: &Grid, name: &str) -> Vec<(Edge, String)> {
        grid.neighbours(name)
            .map(|(edge, to)| (edge, to.to_owned()))
            .collect()
    }

    #[test]
    fn a_cell_is_written_as_a_pair_on_one_line() {
        // A sub-table would push the other fields of a screen out of order and
        // make a desk file three times as long.
        #[derive(serde::Serialize)]
        struct Holder {
            at: Cell,
        }

        let written = toml::to_string(&Holder {
            at: Cell::new(1, -2),
        })
        .unwrap();

        assert_eq!(written.trim(), "at = [1, -2]");
    }

    #[test]
    fn a_cell_survives_a_round_trip_through_toml() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Holder {
            at: Cell,
        }

        let written = toml::to_string(&Holder {
            at: Cell::new(-3, 4),
        })
        .unwrap();

        assert_eq!(
            toml::from_str::<Holder>(&written).unwrap().at,
            Cell::new(-3, 4)
        );
    }

    #[test]
    fn a_step_moves_one_cell_in_each_direction() {
        let origin = Cell::ORIGIN;

        assert_eq!(origin.step(Edge::Right), Cell::new(1, 0));
        assert_eq!(origin.step(Edge::Left), Cell::new(-1, 0));
        assert_eq!(origin.step(Edge::Bottom), Cell::new(0, 1));
        assert_eq!(origin.step(Edge::Top), Cell::new(0, -1));
    }

    #[test]
    fn a_step_and_its_opposite_return_to_where_they_started() {
        for edge in Edge::ALL {
            assert_eq!(
                Cell::new(3, 4).step(edge).step(edge.opposite()),
                Cell::new(3, 4)
            );
        }
    }

    #[test]
    fn a_step_at_the_end_of_the_number_line_saturates() {
        // A very determined drag should stop, not wrap around to the far side
        // of the desk.
        let edge = Cell::new(i32::MAX, i32::MIN);

        assert_eq!(edge.step(Edge::Right).column, i32::MAX);
        assert_eq!(edge.step(Edge::Top).row, i32::MIN);
    }

    #[test]
    fn the_direction_between_touching_cells_is_reported() {
        let here = Cell::new(2, 2);

        assert_eq!(here.direction_to(Cell::new(3, 2)), Some(Edge::Right));
        assert_eq!(here.direction_to(Cell::new(1, 2)), Some(Edge::Left));
        assert_eq!(here.direction_to(Cell::new(2, 3)), Some(Edge::Bottom));
        assert_eq!(here.direction_to(Cell::new(2, 1)), Some(Edge::Top));
    }

    #[test]
    fn a_diagonal_neighbour_has_no_direction() {
        // Deliberate. A cursor pushed at a corner has no unambiguous place to
        // land, so corners are not links.
        assert_eq!(Cell::ORIGIN.direction_to(Cell::new(1, 1)), None);
        assert_eq!(Cell::ORIGIN.direction_to(Cell::new(-1, 1)), None);
    }

    #[test]
    fn a_distant_cell_has_no_direction() {
        assert_eq!(Cell::ORIGIN.direction_to(Cell::new(2, 0)), None);
        assert_eq!(Cell::ORIGIN.direction_to(Cell::ORIGIN), None);
    }

    #[test]
    fn adjacency_yields_the_link_and_its_reciprocal() {
        // The property that makes a one-way edge unrepresentable.
        let desk = desk();

        assert_eq!(
            neighbours(&desk, "desktop"),
            vec![(Edge::Right, "laptop".to_owned())]
        );
        assert_eq!(
            neighbours(&desk, "laptop"),
            vec![(Edge::Left, "desktop".to_owned())]
        );
    }

    #[test]
    fn every_link_in_a_bigger_desk_is_reciprocal() {
        let desk = grid(&[("a", 0, 0), ("b", 1, 0), ("c", 1, 1), ("d", 0, 1)]);

        for (name, _) in desk.iter() {
            for (edge, other) in desk.neighbours(name) {
                assert!(
                    desk.neighbours(other)
                        .any(|back| back == (edge.opposite(), name)),
                    "{name} says {edge:?} to {other}, which does not say {:?} back",
                    edge.opposite()
                );
            }
        }
    }

    #[test]
    fn a_diagonal_screen_is_not_a_neighbour() {
        let desk = grid(&[("here", 0, 0), ("corner", 1, 1)]);

        assert!(neighbours(&desk, "here").is_empty());
    }

    #[test]
    fn a_gap_breaks_the_chain() {
        // Two screens with an empty cell between them are not linked, which is
        // what the picture shows and so what the cursor should do.
        let desk = grid(&[("left", 0, 0), ("right", 2, 0)]);

        assert!(neighbours(&desk, "left").is_empty());
        assert_eq!(desk.reachable_from("left").len(), 1);
    }

    #[test]
    fn a_screen_can_have_four_neighbours() {
        let desk = grid(&[
            ("middle", 0, 0),
            ("west", -1, 0),
            ("east", 1, 0),
            ("north", 0, -1),
            ("south", 0, 1),
        ]);

        assert_eq!(desk.neighbours("middle").count(), 4);
    }

    #[test]
    fn a_screen_not_on_the_desk_has_no_neighbours() {
        assert!(neighbours(&desk(), "nowhere").is_empty());
    }

    #[test]
    fn placing_reports_the_occupant_rather_than_stacking() {
        let mut desk = desk();

        let outcome = desk.place("tablet", Cell::new(1, 0));

        assert_eq!(
            outcome,
            Err(GridError::Occupied {
                at: Cell::new(1, 0),
                occupant: "laptop".to_owned()
            })
        );
        assert_eq!(desk.cell_of("tablet"), None);
    }

    #[test]
    fn placing_a_screen_where_it_already_is_succeeds() {
        // Dropping a tile back where it started is a no-op, not an error.
        let mut desk = desk();

        assert!(desk.place("laptop", Cell::new(1, 0)).is_ok());
    }

    #[test]
    fn moving_a_screen_frees_the_cell_it_left() {
        let mut desk = desk();

        desk.place("laptop", Cell::new(0, 1)).unwrap();

        assert_eq!(desk.at(Cell::new(1, 0)), None);
        assert_eq!(desk.at(Cell::new(0, 1)), Some("laptop"));
    }

    #[test]
    fn the_free_cell_beside_an_empty_desk_is_the_adjacent_one() {
        let desk = grid(&[("only", 0, 0)]);

        assert_eq!(desk.free_cell(Cell::ORIGIN, Edge::Right), Cell::new(1, 0));
    }

    #[test]
    fn the_free_cell_walks_past_an_occupied_one() {
        // Pairing a third machine "to the right" should put it beyond the
        // second, not on top of it.
        let desk = desk();

        assert_eq!(desk.free_cell(Cell::ORIGIN, Edge::Right), Cell::new(2, 0));
    }

    #[test]
    fn the_free_cell_walks_past_several() {
        let desk = grid(&[("a", 0, 0), ("b", 1, 0), ("c", 2, 0), ("d", 3, 0)]);

        assert_eq!(desk.free_cell(Cell::ORIGIN, Edge::Right), Cell::new(4, 0));
    }

    #[test]
    fn the_free_cell_search_terminates_on_a_saturated_row() {
        // A saturating step at the end of the number line stops moving, so an
        // unbounded search would spin forever.
        let desk = grid(&[("a", i32::MAX, 0)]);

        let _ = desk.free_cell(Cell::new(i32::MAX, 0), Edge::Right);
    }

    #[test]
    fn everything_joined_is_reachable() {
        let desk = grid(&[("a", 0, 0), ("b", 1, 0), ("c", 2, 0)]);

        assert_eq!(
            desk.reachable_from("a"),
            ["a", "b", "c"].into_iter().collect()
        );
    }

    #[test]
    fn a_stranded_screen_is_not_reachable() {
        // It looks placed and does nothing, which is worth telling the user.
        let desk = grid(&[("a", 0, 0), ("b", 1, 0), ("island", 9, 9)]);

        let reachable = desk.reachable_from("a");

        assert!(!reachable.contains("island"));
        assert_eq!(reachable.len(), 2);
    }

    #[test]
    fn reachability_follows_a_corner() {
        // Not diagonally, but around: a to b to c is fine even though a and c
        // are diagonal to each other.
        let desk = grid(&[("a", 0, 0), ("b", 1, 0), ("c", 1, 1)]);

        assert!(desk.reachable_from("a").contains("c"));
    }

    #[test]
    fn nothing_is_reachable_from_a_screen_that_is_not_there() {
        assert!(desk().reachable_from("nowhere").is_empty());
    }

    #[test]
    fn an_empty_desk_reports_the_origin_as_its_bounds() {
        // So a caller can draw one empty cell rather than special-case nothing.
        assert_eq!(Grid::new().bounds(), (Cell::ORIGIN, Cell::ORIGIN));
    }

    #[test]
    fn the_bounds_span_every_screen_including_negatives() {
        let desk = grid(&[("west", -2, 0), ("here", 0, 0), ("south", 0, 3)]);

        assert_eq!(desk.bounds(), (Cell::new(-2, 0), Cell::new(0, 3)));
    }

    #[test]
    fn a_hand_written_collision_is_reported_rather_than_refused() {
        // Building must not fail, or a bad file would stop the window opening
        // and the window is where you would fix it.
        let desk = grid(&[("a", 0, 0), ("b", 0, 0)]);

        assert_eq!(desk.collisions().len(), 1);
    }

    #[test]
    fn a_clean_desk_has_no_collisions() {
        assert!(desk().collisions().is_empty());
    }
}
