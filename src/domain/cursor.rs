//! Where the cursor is, and when it crosses.
//!
//! # Why the rule is not the same in both directions
//!
//! Leaving the machine that physically owns the pointer, the display server
//! clamps it at the desktop boundary. An overshoot therefore cannot be
//! observed: the position stops at the last pixel while the deltas keep
//! arriving. The only honest signal is resting on that pixel and still pushing
//! outward, which is what `wall_pressed` tests.
//!
//! Leaving a machine whose cursor is elsewhere, the position is imaginary and
//! nothing clamps it, so the overshoot is real and is the sharper of the two
//! signals. That is `wall_hit`.
//!
//! Every tool in this category converged on the same split, for the same
//! reason. Applying the overshoot rule to both is what made leaving a machine
//! require a shove.
//!
//! # Not crossing by accident
//!
//! Touching an edge is not intent to leave through it. Three things separate
//! the two, and none of them is a delay the user can feel:
//!
//! - the pointer must already have been on the edge before this motion, so a
//!   flick across a wide desk lands on the far edge instead of sailing past it;
//! - the motion must push into that edge, so running down the right-hand
//!   scrollbar, or up to the macOS menu bar, stays put;
//! - after a crossing the return edge is inert for a cooldown, which together
//!   with the one-pixel entry inset in [`super::layout`] is what stops an
//!   arriving cursor bouncing straight back.

use super::ids::{Fraction, Millis, Point, ScreenId};
use super::layout::{Crossing, Edge, Layout};

/// Which machine the cursor is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Locus {
    /// On this machine. Input is consumed locally.
    Local,
    /// On a remote screen. Input is captured and forwarded.
    Remote { screen: ScreenId },
}

/// Tuning for the crossing feel.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CursorConfig {
    /// How long the return edge stays inert after a crossing.
    pub cooldown_ms: u64,
}

impl Default for CursorConfig {
    fn default() -> Self {
        Self { cooldown_ms: 300 }
    }
}

/// What a motion resulted in.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CursorOutcome {
    /// The cursor moved, or was held at a wall, but stayed on this screen.
    Stay,
    /// The cursor left. The caller must suppress local input and tell the peer.
    Cross(Crossing),
}

/// The cursor's position and crossing state.
#[derive(Clone, Debug)]
pub struct CursorMachine {
    locus: Locus,
    home: ScreenId,
    /// Position on whichever screen the cursor is currently on.
    position: Point,
    /// Motion smaller than a pixel, carried to the next event.
    ///
    /// Without this, dividing each delta by a thousand on its own discards the
    /// remainder every time, and a steady stream of half-pixel deltas moves the
    /// cursor nowhere at all rather than slowly. That is exactly what a
    /// high-resolution pointer sends when it is moved deliberately, which is the
    /// case the thousandths in `MotionRel` exist for.
    ///
    /// Invisible on X11 and macOS, where `resync` corrects from the real pointer
    /// twenty times a second. Not invisible on wlroots, where `Inject::pointer`
    /// is `None` by design and this arithmetic is the only thing tracking the
    /// cursor, so the backend with no correction is the one that needs it most.
    residue_milli: Point,

    cooldown_until_ms: Millis,
    config: CursorConfig,
}

impl CursorMachine {
    #[must_use]
    pub const fn new(home: ScreenId, at: Point, config: CursorConfig) -> Self {
        Self {
            locus: Locus::Local,
            home,
            position: at,
            residue_milli: Point::new(0, 0),
            cooldown_until_ms: Millis::ZERO,
            config,
        }
    }

    /// Corrects the tracked position from the real pointer.
    ///
    /// Dead reckoning drifts. The position starts at the middle of the screen
    /// rather than wherever the pointer was, and the deltas accumulated are
    /// unaccelerated while the pointer the user watches is not. Both errors are
    /// one-way and neither ever corrects itself, so on a wide screen the cursor
    /// crosses while the visible pointer is still short of the edge.
    ///
    /// A backend that cannot read the real pointer must return `None` from
    /// [`crate::ports::Inject::pointer`] rather than answer with its own last
    /// write. Answering with dead reckoning does not merely fail to correct the
    /// drift, it pins the position to wherever the last warp left it.
    ///
    /// Only while the cursor is here. Away, the local pointer is parked and
    /// this would drag the session back onto a screen it has left.
    ///
    /// And not during the settle window after a crossing. On arrival the warp
    /// to the entry edge is dispatched to the injector thread, which runs it a
    /// tick behind the model, so a pointer poll in that gap reads the machine's
    /// old real position and would pin the cursor back to where it was before
    /// it ever left. The warp is authoritative until it has visibly landed, so
    /// the same cooldown that stops the cursor bouncing back across the edge
    /// stops it here too.
    pub fn resync(&mut self, at: Point, now_ms: Millis) {
        if self.locus == Locus::Local && now_ms >= self.cooldown_until_ms {
            self.position = at;
        }
    }

    /// Integrates a motion, and decides whether it crosses.
    pub fn on_motion(
        &mut self,
        layout: &Layout,
        dx_milli: i32,
        dy_milli: i32,
        now_ms: Millis,
    ) -> CursorOutcome {
        let Some(screen) = layout.screen(self.current_screen()) else {
            return CursorOutcome::Stay;
        };
        let last = screen.last_pixel();

        let before = self.position;

        // Whole pixels out, the fraction back into the carry. The residue is
        // signed and always smaller than a pixel, so it cannot build into a jump.
        let (step_x, carry_x) = split_milli(dx_milli, self.residue_milli.x_px);
        let (step_y, carry_y) = split_milli(dy_milli, self.residue_milli.y_px);
        self.residue_milli = Point::new(carry_x, carry_y);

        let unclamped_x = self.position.x_px.saturating_add(step_x);
        let unclamped_y = self.position.y_px.saturating_add(step_y);

        self.position = Point::new(
            unclamped_x.clamp(0, last.x_px),
            unclamped_y.clamp(0, last.y_px),
        );

        // Which rule applies depends on whose pointer this is, and the
        // asymmetry is forced by the platform rather than chosen.
        //
        // Here, the pointer is real and the display server clamps it at the
        // desktop boundary, so an overshoot can never be observed: the position
        // simply stops at the last pixel while the deltas keep arriving. The
        // only honest signal is resting on that pixel and still pushing outward.
        //
        // Away, the cursor is imaginary and nothing clamps it, so the overshoot
        // is real and is the more precise signal of the two.
        let found = match self.locus {
            Locus::Local => wall_pressed(before, last, dx_milli, dy_milli),
            Locus::Remote { .. } => wall_hit(unclamped_x, unclamped_y, last),
        };

        let Some(wall) = found else {
            return CursorOutcome::Stay;
        };

        self.try_cross(layout, screen.width_px, screen.height_px, wall, now_ms)
    }

    /// Takes the cursor, from either side of a crossing.
    ///
    /// `now_ms` starts the cooldown here rather than in `try_cross`, so both
    /// sides of a crossing get the same anti-oscillation window. Starting it
    /// only on the departing side leaves the arriving machine with none: it
    /// lands one pixel inside its own edge, and the next push sends the cursor
    /// straight back where it came from.
    pub fn accept_crossing(&mut self, crossing: Crossing, now_ms: Millis) {
        self.locus = if crossing.to == self.home {
            Locus::Local
        } else {
            Locus::Remote {
                screen: crossing.to,
            }
        };
        self.position = crossing.entry_px;
        self.residue_milli = Point::new(0, 0);
        self.cooldown_until_ms = now_ms.plus(self.config.cooldown_ms);
    }

    /// Brings the cursor home unconditionally.
    ///
    /// Ignores the cooldown and the layout, because the entire point is to work
    /// when something else has gone wrong. Reached when a peer is lost or the
    /// layout changes under a remote cursor.
    pub fn force_home(&mut self, layout: &Layout, now_ms: Millis) -> Option<Crossing> {
        if self.locus == Locus::Local {
            return None;
        }

        let home = layout.screen(self.home)?;
        let centre = Point::new(home.last_pixel().x_px / 2, home.last_pixel().y_px / 2);
        let crossing = Crossing {
            to: self.home,
            entry_edge: Edge::Left,
            at: Fraction::MIDDLE,
            entry_px: centre,
        };

        self.accept_crossing(crossing, now_ms);
        Some(crossing)
    }

    #[must_use]
    pub const fn locus(&self) -> Locus {
        self.locus
    }

    #[must_use]
    pub const fn position(&self) -> Point {
        self.position
    }

    #[must_use]
    pub const fn is_remote(&self) -> bool {
        matches!(self.locus, Locus::Remote { .. })
    }

    /// The screen the cursor is currently on.
    #[must_use]
    pub const fn current_screen(&self) -> ScreenId {
        match self.locus {
            Locus::Local => self.home,
            Locus::Remote { screen } => screen,
        }
    }

    /// Where this wall leads, if anywhere, and if the cooldown has expired.
    fn try_cross(
        &mut self,
        layout: &Layout,
        width_px: u32,
        height_px: u32,
        wall: Edge,
        now_ms: Millis,
    ) -> CursorOutcome {
        if now_ms < self.cooldown_until_ms {
            return CursorOutcome::Stay;
        }

        let at = if wall.is_vertical_edge() {
            Fraction::of_span(self.position.y_px, height_px)
        } else {
            Fraction::of_span(self.position.x_px, width_px)
        };

        let Some(crossing) = layout.cross(self.current_screen(), wall, at) else {
            // The outer boundary of the desk. Nothing lies that way.
            return CursorOutcome::Stay;
        };

        self.accept_crossing(crossing, now_ms);

        CursorOutcome::Cross(crossing)
    }
}

/// Whole pixels of movement, and the sub-pixel remainder to carry forward.
///
/// Truncating toward zero, so the carry keeps the sign of the motion and a slow
/// drag left is never rounded into a jitter.
const fn split_milli(milli: i32, carried: i32) -> (i32, i32) {
    let total = milli.saturating_add(carried);
    (total / 1_000, total % 1_000)
}

/// The wall a clamped pointer is resting on and still pushing into.
///
/// The direction test is what stops sliding along the top row to reach a menu
/// from throwing the cursor onto the machine above. Position alone is not
/// intent, and every edge of a screen is somewhere a pointer legitimately goes.
const fn wall_pressed(at: Point, last: Point, dx_milli: i32, dy_milli: i32) -> Option<Edge> {
    if at.x_px <= 0 && dx_milli < 0 {
        Some(Edge::Left)
    } else if at.x_px >= last.x_px && dx_milli > 0 {
        Some(Edge::Right)
    } else if at.y_px <= 0 && dy_milli < 0 {
        Some(Edge::Top)
    } else if at.y_px >= last.y_px && dy_milli > 0 {
        Some(Edge::Bottom)
    } else {
        None
    }
}

/// The wall an unclamped position has moved beyond.
///
/// Takes the unclamped position so that motion which would have gone past the
/// edge is distinguished from motion that merely arrived at it. Only meaningful
/// for a cursor that is elsewhere, where nothing clamps it.
const fn wall_hit(unclamped_x: i32, unclamped_y: i32, last: Point) -> Option<Edge> {
    if unclamped_x < 0 {
        Some(Edge::Left)
    } else if unclamped_x > last.x_px {
        Some(Edge::Right)
    } else if unclamped_y < 0 {
        Some(Edge::Top)
    } else if unclamped_y > last.y_px {
        Some(Edge::Bottom)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ids::PeerId;
    use crate::domain::layout::Screen;

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

    /// A 1920x1080 desktop with a 1920x1080 laptop to its right.
    fn desk() -> Layout {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 1920, 1080)).unwrap();
        layout.add_screen(screen(LAPTOP, 1920, 1080)).unwrap();
        layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();
        layout
    }

    #[test]
    fn motion_smaller_than_a_pixel_still_moves_the_cursor() {
        // What a high-resolution pointer sends when it is moved deliberately,
        // and the case the thousandths in `MotionRel` exist for. Dividing each
        // delta on its own threw the remainder away every time, so this moved
        // the cursor nowhere at all rather than slowly.
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(500, 500), CursorConfig::default());

        for _ in 0..10 {
            cursor.on_motion(&layout, 500, 0, Millis(0));
        }

        assert_eq!(
            cursor.position.x_px, 505,
            "ten half-pixel steps are five pixels"
        );
    }

    #[test]
    fn the_sub_pixel_carry_keeps_the_sign_of_the_motion() {
        // Truncation toward zero, so a slow drag left stays a drag left rather
        // than rounding into a jitter.
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(500, 500), CursorConfig::default());

        for _ in 0..10 {
            cursor.on_motion(&layout, -500, 0, Millis(0));
        }

        assert_eq!(cursor.position.x_px, 495);
    }

    #[test]
    fn taking_the_cursor_clears_the_sub_pixel_carry() {
        // A crossing states where the cursor is rather than integrating toward
        // it, so a fraction left over from the screen it left must not nudge
        // the one it arrives on.
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(500, 500), CursorConfig::default());

        cursor.on_motion(&layout, 500, 0, Millis(0));
        cursor.accept_crossing(
            Crossing {
                to: LAPTOP,
                entry_edge: Edge::Left,
                at: Fraction::MIDDLE,
                entry_px: Point::new(1, 540),
            },
            Millis(0),
        );

        assert_eq!(cursor.residue_milli, Point::new(0, 0));
    }

    fn cursor_at_right_edge() -> CursorMachine {
        CursorMachine::new(DESKTOP, Point::new(1919, 540), CursorConfig::default())
    }

    /// Two 5120x2880 monitors side by side, as a real machine reports them: one
    /// logical screen 10240 wide.
    fn wide_desk() -> Layout {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 10240, 2880)).unwrap();
        layout.add_screen(screen(LAPTOP, 3024, 1964)).unwrap();
        layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();
        layout
    }

    /// The reported desk: a Mac with a Linux box directly above it.
    fn stacked_desk() -> Layout {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, 1512, 982)).unwrap();
        layout.add_screen(screen(LAPTOP, 10240, 2880)).unwrap();
        layout.link(DESKTOP, Edge::Top, LAPTOP).unwrap();
        layout
    }

    /// One shove of `px` pixels into the wall, delivered in a single motion.
    fn shove(cursor: &mut CursorMachine, layout: &Layout, px: i32, now: u64) -> CursorOutcome {
        cursor.on_motion(layout, px * 1_000, 0, Millis(now))
    }

    #[test]
    fn a_resync_corrects_a_drifted_position() {
        // The estimate starts at the middle of the screen rather than wherever
        // the pointer was, and then accumulates unaccelerated deltas while the
        // pointer the user watches has the display server's curve applied.
        // Both errors are one way and neither corrects itself.
        let mut cursor = cursor_at_right_edge();

        cursor.resync(Point::new(100, 900), Millis::ZERO);

        assert_eq!(cursor.position(), Point::new(100, 900));
    }

    #[test]
    fn a_resync_is_ignored_while_the_cursor_is_away() {
        // With the cursor on another machine the local pointer is parked, so
        // reporting it would drag the session back onto a screen it has left.
        let mut cursor = cursor_at_right_edge();
        cursor.accept_crossing(
            Crossing {
                to: LAPTOP,
                entry_edge: Edge::Left,
                at: Fraction::MIDDLE,
                entry_px: Point::new(1, 540),
            },
            Millis::ZERO,
        );
        let away = cursor.position();

        // Past the settle window, so only the locus, not the cooldown, holds it.
        cursor.resync(Point::new(0, 0), Millis(1_000));

        assert_eq!(cursor.position(), away);
        assert!(cursor.is_remote());
    }

    #[test]
    fn a_pointer_report_during_the_settle_window_does_not_undo_the_entry_warp() {
        // The reported bug. On arrival the model is at the entry edge, but the
        // injector runs the warp a tick late, so a pointer poll in that gap
        // reads the machine's old real position. Resyncing onto it puts the
        // cursor back where it was before it ever left, and the next motion
        // integrates from there.
        let mut cursor = cursor_at_right_edge();

        // Away first, so coming back is a genuine arrival.
        cursor.accept_crossing(
            Crossing {
                to: LAPTOP,
                entry_edge: Edge::Left,
                at: Fraction::MIDDLE,
                entry_px: Point::new(1, 540),
            },
            Millis::ZERO,
        );

        // The cursor comes home, entering the bottom edge. Cooldown runs to 800.
        let entry = Point::new(960, 1079);
        cursor.accept_crossing(
            Crossing {
                to: DESKTOP,
                entry_edge: Edge::Bottom,
                at: Fraction::MIDDLE,
                entry_px: entry,
            },
            Millis(500),
        );
        assert_eq!(cursor.position(), entry);

        // The stale position this machine still reports from before it left.
        let stale = Point::new(1919, 540);
        cursor.resync(stale, Millis(600));
        assert_eq!(
            cursor.position(),
            entry,
            "a stale report undid the entry warp"
        );

        // Once the warp has landed and the window is over, correction resumes.
        cursor.resync(stale, Millis(900));
        assert_eq!(cursor.position(), stale);
    }

    #[test]
    fn a_new_cursor_is_local() {
        let cursor = cursor_at_right_edge();

        assert_eq!(cursor.locus(), Locus::Local);
        assert!(!cursor.is_remote());
        assert_eq!(cursor.current_screen(), DESKTOP);
    }

    #[test]
    fn motion_within_the_screen_never_crosses() {
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(960, 540), CursorConfig::default());

        assert_eq!(
            cursor.on_motion(&layout, 10_000, 0, Millis(10)),
            CursorOutcome::Stay
        );
        assert_eq!(cursor.position(), Point::new(970, 540));
    }

    #[test]
    fn the_position_is_clamped_to_the_screen() {
        // From the middle, so the flick lands on the edge rather than leaving
        // through it, and there is a clamped position left to assert.
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(960, 540), CursorConfig::default());

        shove(&mut cursor, &layout, 5_000, 10);

        assert_eq!(cursor.position().x_px, 1919, "clamped to the last pixel");
    }

    #[test]
    fn a_deliberate_shove_crosses() {
        let layout = desk();
        let mut cursor = cursor_at_right_edge();

        // Twenty pixels in one motion, past the sixteen-pixel threshold.
        let outcome = shove(&mut cursor, &layout, 20, 10);

        match outcome {
            CursorOutcome::Cross(crossing) => {
                assert_eq!(crossing.to, LAPTOP);
                assert_eq!(crossing.entry_edge, Edge::Left);
            }
            CursorOutcome::Stay => panic!("a twenty pixel shove should cross"),
        }
        assert_eq!(cursor.locus(), Locus::Remote { screen: LAPTOP });
    }

    #[test]
    fn sliding_along_an_edge_does_not_cross() {
        // Resting on the right edge and running down it, which is what reaching
        // for a scrollbar looks like. Touching an edge is not intent to leave
        // through it, and on macOS the menu bar makes the top edge somewhere
        // the pointer is asked to go many times an hour.
        let layout = desk();
        let mut cursor = cursor_at_right_edge();

        for step in 0..20 {
            let outcome = cursor.on_motion(&layout, 0, 8_000, Millis(step * 10));
            assert_eq!(outcome, CursorOutcome::Stay, "crossed on step {step}");
        }

        assert!(!cursor.is_remote());
    }

    #[test]
    fn a_corrected_position_is_not_by_itself_a_crossing() {
        // Correction happens twenty times a second, so it must be inert on its
        // own: only motion decides.
        //
        // This is deliberately not a guard against a backend that lies about
        // where the pointer is. Nothing here can be. The position arriving
        // through `resync` is the only ground truth this machine has, and a
        // backend answering with its own last write pins the session against
        // whichever edge that write landed on, defeating any edge rule that
        // could be written. That defence belongs to the adapter, which is why
        // `Inject::pointer` says to return `None` rather than guess.
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(960, 540), CursorConfig::default());

        let stale = Point::new(1918, 540);

        for step in 0..40 {
            cursor.resync(stale, Millis(step * 50));

            // Away from the edge the report claims, so nothing here is a
            // crossing however many times the lie is repeated.
            let outcome = cursor.on_motion(&layout, -4_000, 0, Millis(step * 50));
            assert_eq!(outcome, CursorOutcome::Stay, "crossed on step {step}");
        }

        assert!(!cursor.is_remote());
    }

    #[test]
    fn crossing_back_immediately_is_refused_during_the_cooldown() {
        // Without this the cursor oscillates: it arrives against the opposite
        // wall and the same gesture sends it straight back.
        let layout = desk();
        let mut cursor = cursor_at_right_edge();

        assert!(matches!(
            shove(&mut cursor, &layout, 20, 10),
            CursorOutcome::Cross(_)
        ));

        // Still within the 300 ms cooldown.
        let back = cursor.on_motion(&layout, -20_000, 0, Millis(100));

        assert_eq!(back, CursorOutcome::Stay);
        assert!(cursor.is_remote(), "still on the laptop");
    }

    #[test]
    fn crossing_back_is_permitted_once_the_cooldown_expires() {
        let layout = desk();
        let mut cursor = cursor_at_right_edge();

        shove(&mut cursor, &layout, 20, 10);

        // Past the 300 ms cooldown, and a deliberate shove leftwards.
        let back = cursor.on_motion(&layout, -20_000, 0, Millis(500));

        match back {
            CursorOutcome::Cross(crossing) => assert_eq!(crossing.to, DESKTOP),
            CursorOutcome::Stay => panic!("the cooldown should have expired"),
        }
        assert_eq!(cursor.locus(), Locus::Local, "back on the home screen");
    }

    #[test]
    fn the_outer_boundary_of_the_desk_holds_the_cursor() {
        // Nothing lies left of the desktop, so no amount of pushing crosses.
        let layout = desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(0, 540), CursorConfig::default());

        assert_eq!(shove(&mut cursor, &layout, -500, 10), CursorOutcome::Stay);
        assert_eq!(cursor.position().x_px, 0);
    }

    #[test]
    fn the_crossing_preserves_the_height_it_left_at() {
        let layout = desk();
        let mut cursor =
            CursorMachine::new(DESKTOP, Point::new(1919, 270), CursorConfig::default());

        let CursorOutcome::Cross(crossing) = shove(&mut cursor, &layout, 20, 10) else {
            panic!("expected a crossing");
        };

        // A quarter of the way down a 1080-tall screen, on both sides.
        assert!((crossing.entry_px.y_px - 270).abs() <= 1);
    }

    #[test]
    fn force_home_returns_the_cursor_from_a_remote_screen() {
        let layout = desk();
        let mut cursor = cursor_at_right_edge();
        shove(&mut cursor, &layout, 20, 10);
        assert!(cursor.is_remote());

        let crossing = cursor
            .force_home(&layout, Millis::ZERO)
            .expect("the cursor was remote");

        assert_eq!(crossing.to, DESKTOP);
        assert_eq!(cursor.locus(), Locus::Local);
    }

    #[test]
    fn force_home_works_from_anywhere_on_the_desk() {
        // It exists to work when something else has already gone wrong, so it
        // ignores the cooldown and the layout alike.
        let layout = desk();
        let mut cursor = cursor_at_right_edge();
        shove(&mut cursor, &layout, 20, 10);

        assert!(cursor.force_home(&layout, Millis::ZERO).is_some());
        assert_eq!(cursor.locus(), Locus::Local);
    }

    #[test]
    fn force_home_is_a_no_op_when_already_local() {
        let layout = desk();
        let mut cursor = cursor_at_right_edge();

        assert!(cursor.force_home(&layout, Millis::ZERO).is_none());
    }

    #[test]
    fn motion_on_a_screen_the_layout_does_not_know_is_ignored() {
        // Defensive: a peer could vanish between the crossing and the next
        // motion, and the cursor must not panic on the missing screen.
        let layout = Layout::new();
        let mut cursor = cursor_at_right_edge();

        assert_eq!(
            cursor.on_motion(&layout, 20_000, 0, Millis(10)),
            CursorOutcome::Stay
        );
    }

    #[test]
    fn crossing_a_wide_screen_takes_its_whole_width() {
        // The reported bug, at the reported size. Starting in the middle of a
        // 10240 wide desk and travelling exactly half the width arrives at the
        // far edge and must not cross: there is one pixel of screen left.
        //
        // Every other test here starts the cursor already touching the edge,
        // which is why none of them caught this.
        let layout = wide_desk();
        let mut cursor =
            CursorMachine::new(DESKTOP, Point::new(5120, 1440), CursorConfig::default());

        let outcome = shove(&mut cursor, &layout, 5119, 0);

        assert_eq!(
            outcome,
            CursorOutcome::Stay,
            "half a screen is not a crossing"
        );
        assert_eq!(cursor.position().x_px, 10239, "and it reached the far edge");
    }

    #[test]
    fn a_wide_screen_still_crosses_at_its_actual_edge() {
        // The mirror of the above: past the edge, with enough push, it goes.
        let layout = wide_desk();
        let mut cursor =
            CursorMachine::new(DESKTOP, Point::new(10239, 1440), CursorConfig::default());

        let mut outcome = CursorOutcome::Stay;
        for step in 0..12 {
            outcome = shove(&mut cursor, &layout, 40, step * 10);
            if matches!(outcome, CursorOutcome::Cross(_)) {
                break;
            }
        }

        assert!(
            matches!(outcome, CursorOutcome::Cross(_)),
            "pushing at the true edge must cross"
        );
    }

    #[test]
    fn where_it_crosses_is_where_it_was_along_the_edge() {
        // The fraction is what places the cursor on the far machine, so a wrong
        // one lands it in the wrong part of the other screen even when the
        // crossing itself is right.
        let layout = wide_desk();
        let quarter = 2880 / 4;
        let mut cursor =
            CursorMachine::new(DESKTOP, Point::new(10239, quarter), CursorConfig::default());

        let mut crossing = None;
        for step in 0..12 {
            if let CursorOutcome::Cross(at) = shove(&mut cursor, &layout, 40, step * 10) {
                crossing = Some(at);
                break;
            }
        }

        let crossing = crossing.expect("it crosses");
        assert!(
            (crossing.at.get() - 0.25).abs() < 0.01,
            "left a quarter down, got {}",
            crossing.at.get()
        );
    }

    #[test]
    fn an_arriving_cursor_gets_the_same_cooldown_as_a_departing_one() {
        // The asymmetry that makes a crossing bounce. A machine handed the
        // cursor lands one pixel inside its own edge, so without a cooldown of
        // its own the next push throws it straight back where it came from.
        // Both sides have to arm one, and this is the arriving side.
        let mut cursor = cursor_at_right_edge();
        let layout = desk();

        cursor.accept_crossing(
            Crossing {
                to: DESKTOP,
                entry_edge: Edge::Left,
                at: Fraction::MIDDLE,
                entry_px: Point::new(1, 540),
            },
            Millis(1_000),
        );

        // Hard against the left edge, which is one pixel away, immediately.
        let outcome = cursor.on_motion(&layout, -40_000, 0, Millis(1_010));

        assert_eq!(
            outcome,
            CursorOutcome::Stay,
            "an arrival must not be able to bounce straight back"
        );
    }

    #[test]
    fn reaching_the_top_edge_and_still_rising_crosses_upward() {
        // The reported direction, and the one nothing tested. Every vertical
        // case in this file was a bottom edge, and the only one of those was a
        // negative test.
        let layout = stacked_desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(700, 400), CursorConfig::default());

        // Up to the edge. The flick lands there rather than leaving.
        let landing = cursor.on_motion(&layout, 0, -400_000, Millis(0));
        assert_eq!(landing, CursorOutcome::Stay, "a flick lands on the edge");
        assert_eq!(cursor.position().y_px, 0);
        assert!(!cursor.is_remote());

        // Still rising, so this one leaves.
        let CursorOutcome::Cross(crossing) = cursor.on_motion(&layout, 0, -8_000, Millis(20))
        else {
            panic!("pushing on past the top edge must cross");
        };

        assert_eq!(crossing.to, LAPTOP);
        assert_eq!(crossing.entry_edge, Edge::Bottom, "it enters from below");
        assert_eq!(
            crossing.entry_px.y_px, 2878,
            "one pixel inside the far bottom edge, not the middle of it"
        );
        assert!(cursor.is_remote());
    }

    #[test]
    fn the_horizontal_fraction_survives_a_vertical_crossing() {
        // Leaving at 700 of 1512 across must arrive at the same fraction of
        // 10240, which is what makes the pointer appear under the hand rather
        // than wherever the far machine last left it.
        let layout = stacked_desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(700, 0), CursorConfig::default());

        let CursorOutcome::Cross(crossing) = cursor.on_motion(&layout, 0, -4_000, Millis(0)) else {
            panic!("must cross");
        };

        // 700 of 1512 across, mapped onto 10240, is 4740 and a fraction.
        assert_eq!(crossing.entry_px.x_px, 4741);
    }

    #[test]
    fn away_from_home_it_takes_an_overshoot_and_not_a_touch() {
        // The other half of the asymmetry. With the cursor on the far machine
        // the position is imaginary and unclamped, so resting on its edge is
        // not a crossing: only exceeding it is.
        let layout = stacked_desk();
        let mut cursor = CursorMachine::new(DESKTOP, Point::new(700, 400), CursorConfig::default());

        cursor.on_motion(&layout, 0, -400_000, Millis(0));
        assert!(matches!(
            cursor.on_motion(&layout, 0, -8_000, Millis(20)),
            CursorOutcome::Cross(_)
        ));

        // Now on the far screen, sitting on its bottom edge and pushing down.
        // Under the local rule this would leave; under the remote one it must
        // travel the whole screen first.
        cursor.resync(Point::new(5000, 2879), Millis(1_000));
        let outcome = cursor.on_motion(&layout, 0, 1_000, Millis(1_000));

        assert_eq!(outcome, CursorOutcome::Stay, "a touch is not an overshoot");
        assert!(cursor.is_remote(), "and it is still away");
    }
}
