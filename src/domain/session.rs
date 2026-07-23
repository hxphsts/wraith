//! The reducer. Everything the domain decides happens here.
//!
//! # Why a reducer
//!
//! [`Session::step`] takes one input and appends commands. No I/O, no async, no
//! clock: time arrives as [`Millis`] like any other data.
//!
//! That shape is what makes the tests worth anything. A test is a `Vec<Input>`
//! compared against a `Vec<Command>`, with nothing mocked, because `Command` is
//! plain data rather than a call into something. The alternative, a session that
//! owns its transport and its backends, can only be tested by pretending to be
//! those things, and then the test asserts the shape of the implementation
//! rather than its behaviour.
//!
//! # Allocation
//!
//! `out` is cleared and refilled rather than returned, so a caller keeps one
//! `Vec` alive for the life of the process. At 1000 motion events per second
//! that matters.

use std::collections::BTreeMap;

use super::cursor::{CursorConfig, CursorMachine, CursorOutcome, Locus};
use super::ids::{Fraction, Millis, PeerId, Point, ScreenId};
use super::input::{HeldSet, InputEvent, InputFrame};
use super::layout::{Crossing, Edge, Layout, Screen};
use super::ledger::{InputLedger, LedgerConfig, ReleaseReason};
use super::notice::Notice;

/// Everything that can happen to a session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Input {
    /// Where the pointer on this machine actually is.
    ///
    /// The cursor is otherwise tracked by accumulating relative motion, and
    /// that estimate drifts for two reasons: it starts at the middle of the
    /// screen rather than wherever the pointer happened to be, and the deltas
    /// it accumulates are unaccelerated while the pointer the user watches has
    /// the display server's curve applied. Left uncorrected the cursor crosses
    /// to the next machine while the visible pointer is still short of the
    /// edge.
    ///
    /// Ignored unless the cursor is here, since with it away the local pointer
    /// is parked and would drag the session back onto a screen it has left.
    LocalPointerAt { at: Point },

    /// Time passed. Drives the watchdog and the snapshot.
    Tick { now_ms: Millis },

    /// Input observed on this machine.
    Local(InputEvent),

    /// A peer connected and told us about its screen.
    PeerConnected { peer: PeerId, screen: Screen },

    /// A peer's connection ended, however it ended.
    PeerLost { peer: PeerId },

    /// Transitions arrived on the reliable stream.
    PeerTransitions {
        peer: PeerId,
        events: Vec<InputEvent>,
    },

    /// Motion arrived on a datagram.
    PeerFrame { peer: PeerId, frame: InputFrame },

    /// A peer's authoritative held set, to reconcile against.
    PeerSnapshot { peer: PeerId, held: HeldSet },

    /// A peer says the cursor has arrived here.
    PeerEnter { peer: PeerId, crossing: Crossing },

    /// A peer says the cursor has gone back.
    PeerLeave { peer: PeerId },

    /// A peer says where it has put this machine on its own desk.
    ///
    /// The mirror is applied here, so one message keeps both desks agreeing
    /// rather than leaving them to drift.
    PeerPlaced { peer: PeerId, side: Edge },

    /// The desk changed, from a drag in the window or a peer's placement.
    LayoutChanged { layout: Layout },
}

/// Which way the cursor went across an edge.
///
/// The two are drawn differently on purpose. A departure is a glow on a screen
/// that has already been looked away from, so it is short and front loaded; an
/// arrival has to say where the cursor landed, so it is anchored and back
/// loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The cursor is leaving this machine.
    Departure,
    /// The cursor has landed on this machine.
    Arrival,
}

/// What the outside world should do about it.
///
/// Plain data, deliberately. A command that was a closure or a channel send
/// would make the reducer untestable without mocking whatever it called.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Command {
    /// Send transitions to a peer on the reliable stream.
    SendTransitions {
        peer: PeerId,
        events: Vec<InputEvent>,
    },

    /// Send motion to a peer on a datagram.
    SendMotion {
        peer: PeerId,
        events: Vec<InputEvent>,
    },

    /// Send the held set, so the peer can reconcile.
    SendSnapshot { peer: PeerId, held: HeldSet },

    /// Tell a peer the cursor has arrived.
    SendEnter { peer: PeerId, crossing: Crossing },

    /// Tell a peer the cursor has gone.
    SendLeave { peer: PeerId },

    /// Inject these events on this machine.
    Inject(Vec<InputEvent>),

    /// Start or stop withholding local input from the desktop.
    Suppress(bool),

    /// Put the local pointer here, on arrival from another machine.
    WarpLocal(Point),

    /// Write a peer's placement to the desk, and rebuild the layout from it.
    ///
    /// The reducer does no I/O, so it says what should be written and `run`
    /// writes it.
    SavePlacement { peer: PeerId, side: Edge },

    /// A peer says it now goes by this name. Record it against its identity.
    ///
    /// Only the peer knows what it calls itself, and the desk here may still
    /// carry a name it has since changed. Routing already prefers the identity
    /// key, so this is the label catching up rather than anything load bearing.
    SaveName { peer: PeerId, name: String },

    /// Tell the user something they need to know.
    Notify(Notice),

    /// The cursor crossed an edge of this machine's screen.
    ///
    /// Emitted purely for the outside world, like [`Command::Notify`], and
    /// nothing in the session depends on it. It exists so the window can draw
    /// something at the edge without inferring a crossing from motion, which
    /// would be guessing at what the reducer already knows exactly.
    ///
    /// `edge` is resolved into *this* machine's frame before it leaves here. A
    /// departure carries the edge the cursor left by, which is the opposite of
    /// the entered screen's entry edge, and doing that conversion once here
    /// beats every consumer remembering to call `opposite`.
    Crossed {
        direction: Direction,
        edge: Edge,
        at: Fraction,
    },
}

/// Tuning for the session as a whole.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct SessionConfig {
    pub cursor: CursorConfig,
    pub ledger: LedgerConfig,
}

/// The whole domain state for one machine.
#[derive(Debug)]
pub struct Session {
    layout: Layout,
    cursor: CursorMachine,
    /// One ledger per peer. The receiving side of each.
    ledgers: BTreeMap<PeerId, InputLedger>,
    /// What this machine has announced to each peer. The sending side.
    announced: BTreeMap<PeerId, InputLedger>,
    /// Which screen belongs to which peer.
    screens: BTreeMap<ScreenId, PeerId>,
    home: ScreenId,
    last_tick_ms: Millis,
    config: SessionConfig,
}

impl Session {
    #[must_use]
    pub fn new(layout: Layout, home: ScreenId, at: Point, config: SessionConfig) -> Self {
        Self {
            cursor: CursorMachine::new(home, at, config.cursor),
            screens: layout
                .screens()
                .map(|screen| (screen.id, screen.peer))
                .collect(),
            layout,
            ledgers: BTreeMap::new(),
            announced: BTreeMap::new(),
            home,
            last_tick_ms: Millis::ZERO,
            config,
        }
    }

    /// The only way in.
    pub fn step(&mut self, input: Input, out: &mut Vec<Command>) {
        out.clear();

        match input {
            Input::Tick { now_ms } => self.on_tick(now_ms, out),
            Input::Local(event) => self.on_local(event, out),
            Input::LocalPointerAt { at } => self.cursor.resync(at, self.last_tick_ms),
            Input::PeerConnected { peer, screen } => self.on_peer_connected(peer, &screen, out),
            Input::PeerLost { peer } => self.on_peer_lost(peer, out),
            Input::PeerTransitions { peer, events } => self.on_peer_transitions(peer, &events, out),
            Input::PeerFrame { peer, frame } => self.on_peer_frame(peer, &frame, out),
            Input::PeerSnapshot { peer, held } => self.on_peer_snapshot(peer, &held, out),
            Input::PeerEnter { peer, crossing } => self.on_peer_enter(peer, crossing, out),
            Input::PeerLeave { peer } => self.on_peer_leave(peer, out),
            Input::PeerPlaced { peer, side } => Self::on_peer_placed(peer, side, out),
            Input::LayoutChanged { layout } => self.on_layout_changed(layout, out),
        }
    }

    /// The desk as this session sees it, sizes included.
    ///
    /// Public so a caller can see what a peer's hello taught it, which is
    /// otherwise invisible and was wrong for the whole life of a session.
    #[must_use]
    pub const fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Where the cursor currently is.
    #[must_use]
    pub const fn locus(&self) -> Locus {
        self.cursor.locus()
    }

    /// Whether any peer is holding anything.
    #[must_use]
    pub fn any_held(&self) -> bool {
        self.ledgers.values().any(|ledger| !ledger.is_quiescent())
    }

    fn on_tick(&mut self, now_ms: Millis, out: &mut Vec<Command>) {
        self.last_tick_ms = now_ms;

        // The watchdog first, because a released key matters more than a
        // snapshot and should not queue behind one.
        for (peer, ledger) in &mut self.ledgers {
            if let Some(events) = ledger.poll_watchdog(now_ms) {
                out.push(Command::Inject(events));
                out.push(Command::Notify(Notice::HeldInputReleased { peer: *peer }));
            }
        }

        for (peer, ledger) in &mut self.announced {
            if let Some(held) = ledger.snapshot_due(now_ms) {
                out.push(Command::SendSnapshot { peer: *peer, held });
            }
        }
    }

    fn on_local(&mut self, event: InputEvent, out: &mut Vec<Command>) {
        let now_ms = self.last_tick_ms;

        // Motion is what can cross an edge, so it is examined first and may
        // change where everything after it goes.
        if let InputEvent::MotionRel { dx_milli, dy_milli } = event {
            let outcome = self
                .cursor
                .on_motion(&self.layout, dx_milli, dy_milli, now_ms);

            if let CursorOutcome::Cross(crossing) = outcome {
                self.begin_crossing(crossing, out);
                return;
            }
        }

        let Locus::Remote { screen } = self.cursor.locus() else {
            // The cursor is here, so local input belongs to this machine and
            // Wraith does nothing with it.
            return;
        };

        let Some(peer) = self.screens.get(&screen).copied() else {
            return;
        };

        if let Some(ledger) = self.announced.get_mut(&peer) {
            ledger.note_sent(event, now_ms);
        }

        if event.is_transition() {
            out.push(Command::SendTransitions {
                peer,
                events: vec![event],
            });
        } else {
            out.push(Command::SendMotion {
                peer,
                events: vec![event],
            });
        }
    }

    fn on_peer_connected(&mut self, peer: PeerId, screen: &Screen, out: &mut Vec<Command>) {
        let now_ms = self.last_tick_ms;

        self.screens.insert(screen.id, peer);
        self.ledgers
            .insert(peer, InputLedger::new(now_ms, self.config.ledger));
        self.announced
            .insert(peer, InputLedger::new(now_ms, self.config.ledger));

        // The size the layout has for this peer is a guess: the file says where
        // a machine sits and nothing about how big it is, so `build_layout`
        // seeds every remote screen with the local one's dimensions. The hello
        // carries the truth and this is the only place it can be applied.
        //
        // Without it a crossing is mapped onto the wrong rectangle for the whole
        // life of the session, which lands the arriving cursor in the middle of
        // the far screen instead of at the edge it entered by.
        if self
            .layout
            .resize_screen(screen.id, screen.width_px, screen.height_px)
        {
            tracing::debug!(
                screen = %screen.name,
                width = screen.width_px,
                height = screen.height_px,
                "learned a peer's real screen size"
            );
        }

        // The layout was built from a file, which may carry a name this machine
        // has since changed. What a machine says about itself wins.
        if self
            .layout
            .screen(screen.id)
            .is_some_and(|known| known.name != screen.name)
        {
            out.push(Command::SaveName {
                peer,
                name: screen.name.clone(),
            });
        }

        out.push(Command::Notify(Notice::PeerConnected {
            name: screen.name.clone(),
        }));
    }

    fn on_peer_lost(&mut self, peer: PeerId, out: &mut Vec<Command>) {
        // Whatever that peer was holding here is released now rather than at the
        // watchdog deadline, since the connection ending is already proof it has
        // stopped speaking.
        if let Some(mut ledger) = self.ledgers.remove(&peer) {
            let events = ledger.release_all_paranoid(ReleaseReason::Disconnect);
            if !events.is_empty() {
                out.push(Command::Inject(events));
            }
        }
        self.announced.remove(&peer);

        // If the cursor was on that peer's screen it has nowhere to be, so it
        // comes home. Leaving it stranded would mean local input going nowhere.
        if let Locus::Remote { screen } = self.cursor.locus()
            && self.screens.get(&screen) == Some(&peer)
        {
            self.go_home(out);
        }

        self.screens.retain(|_, owner| *owner != peer);
        out.push(Command::Notify(Notice::PeerDisconnected { peer }));
    }

    fn on_peer_transitions(&mut self, peer: PeerId, events: &[InputEvent], out: &mut Vec<Command>) {
        let now_ms = self.last_tick_ms;

        if let Some(ledger) = self.ledgers.get_mut(&peer) {
            let applied = ledger.apply_transitions(events, now_ms);
            if !applied.is_empty() {
                out.push(Command::Inject(applied));
            }
        }
    }

    fn on_peer_frame(&mut self, peer: PeerId, frame: &InputFrame, out: &mut Vec<Command>) {
        let now_ms = self.last_tick_ms;

        if let Some(ledger) = self.ledgers.get_mut(&peer)
            && let Ok(events) = ledger.apply_frame(frame, now_ms)
            && !events.is_empty()
        {
            out.push(Command::Inject(events));
        }
    }

    fn on_peer_snapshot(&mut self, peer: PeerId, held: &HeldSet, out: &mut Vec<Command>) {
        let now_ms = self.last_tick_ms;

        if let Some(ledger) = self.ledgers.get_mut(&peer) {
            let events = ledger.reconcile(held, now_ms);
            if !events.is_empty() {
                tracing::warn!(%peer, released = events.len(), "reconciled a desynchronised peer");
                out.push(Command::Inject(events));
            }
        }
    }

    fn on_peer_enter(&mut self, peer: PeerId, crossing: Crossing, out: &mut Vec<Command>) {
        let _ = peer;

        // Position, then reveal, and in that order.
        //
        // Releasing suppression first opens a window in which the injector's
        // pointer poll passes the capture gate, reads the position the cursor
        // had before it left, and resyncs the session back onto it. The warp
        // still happens, so the pointer is in the right place while the model
        // believes it is somewhere else, and the next motion is integrated from
        // the wrong point.
        out.push(Command::WarpLocal(crossing.entry_px));

        // Second, and the reason this function exists as more than a warp.
        //
        // Departure suppresses, and there are two returns that have to release
        // it. `begin_crossing` covers the one this machine's own edge logic
        // detects; a peer handing the cursor back arrives here instead. Release
        // only the first and this machine sits suppressed with the cursor
        // logically local: the keyboard and mouse are dead until the cursor
        // model drifts far enough to declare an arrival of its own, which is
        // what "I have to move three times before it wakes up" is.
        out.push(Command::Suppress(false));
        out.push(Command::Crossed {
            direction: Direction::Arrival,
            edge: crossing.entry_edge,
            at: crossing.at,
        });
        self.cursor.accept_crossing(crossing, self.last_tick_ms);
    }

    fn on_peer_leave(&mut self, peer: PeerId, out: &mut Vec<Command>) {
        // The peer says the cursor went back to it, so anything it was holding
        // here is released. This is the fast path; the watchdog is the slow one.
        if let Some(ledger) = self.ledgers.get_mut(&peer) {
            let events = ledger.release_all(ReleaseReason::ScreenLeave);
            if !events.is_empty() {
                out.push(Command::Inject(events));
            }
        }
    }

    /// A peer has placed this machine on its desk.
    ///
    /// The mirror: it says this machine is on its `side`, so it is on this
    /// machine's opposite side. Only recorded here; `run` writes the file and
    /// feeds the rebuilt layout back as [`Input::LayoutChanged`].
    fn on_peer_placed(peer: PeerId, side: Edge, out: &mut Vec<Command>) {
        out.push(Command::SavePlacement {
            peer,
            side: side.opposite(),
        });
    }

    /// Replaces the desk.
    ///
    /// The cursor may be standing on a screen that no longer exists, which
    /// happens when a screen is dragged away or a peer rearranges its desk. It
    /// comes home, releasing everything on the way, exactly as a lost peer
    /// does. Leaving it stranded would mean local input going to a screen that
    /// is not there.
    fn on_layout_changed(&mut self, layout: Layout, out: &mut Vec<Command>) {
        self.layout = layout;
        self.screens = self
            .layout
            .screens()
            .map(|screen| (screen.id, screen.peer))
            .collect();

        let still_there = match self.cursor.locus() {
            Locus::Local => self.layout.screen(self.home).is_some(),
            Locus::Remote { screen } => self.layout.screen(screen).is_some(),
        };

        if !still_there {
            self.go_home(out);
            out.push(Command::Notify(Notice::DeskChangedUnderCursor));
        }
    }

    /// Hands the cursor to whichever machine owns the screen it crossed into.
    fn begin_crossing(&self, crossing: Crossing, out: &mut Vec<Command>) {
        let arriving_here = crossing.to == self.home;

        if arriving_here {
            // Position, then reveal, for the reason set out in full on
            // `on_peer_enter`. This is the same arrival reached by the other
            // route, self detected rather than announced by a peer, and the
            // order it needs is the same order.
            out.push(Command::WarpLocal(crossing.entry_px));
            out.push(Command::Suppress(false));
            out.push(Command::Crossed {
                direction: Direction::Arrival,
                edge: crossing.entry_edge,
                at: crossing.at,
            });

            // Tell whoever had the cursor that it is gone, so they release.
            out.extend(
                self.screens
                    .values()
                    .map(|peer| Command::SendLeave { peer: *peer }),
            );
            return;
        }

        let Some(peer) = self.screens.get(&crossing.to).copied() else {
            return;
        };

        out.push(Command::Suppress(true));
        out.push(Command::Crossed {
            direction: Direction::Departure,
            // The edge left by, which is the far side of the one being entered.
            edge: crossing.entry_edge.opposite(),
            at: crossing.at,
        });
        out.push(Command::SendEnter { peer, crossing });
    }

    /// Brings the cursor home and releases everything on the way.
    fn go_home(&mut self, out: &mut Vec<Command>) {
        if self.cursor.locus() == Locus::Local {
            return;
        }

        // Released before the leave is sent, so a peer that never receives the
        // leave has already been told to let go.
        for (peer, ledger) in &mut self.announced {
            let events = ledger.release_all(ReleaseReason::ScreenLeave);
            if !events.is_empty() {
                out.push(Command::SendTransitions {
                    peer: *peer,
                    events,
                });
            }
        }
        out.extend(
            self.screens
                .values()
                .map(|peer| Command::SendLeave { peer: *peer }),
        );

        self.cursor.force_home(&self.layout, self.last_tick_ms);
        out.push(Command::Suppress(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::input::{KeyState, Scancode};

    const DESKTOP: ScreenId = ScreenId(1);
    const LAPTOP: ScreenId = ScreenId(2);
    const ME: PeerId = PeerId([1; 32]);
    const THEM: PeerId = PeerId([2; 32]);

    const CTRL: Scancode = Scancode(29);
    const KEY_C: Scancode = Scancode(46);

    fn press(code: Scancode) -> InputEvent {
        InputEvent::Key {
            code,
            state: KeyState::Pressed,
        }
    }

    fn release(code: Scancode) -> InputEvent {
        InputEvent::Key {
            code,
            state: KeyState::Released,
        }
    }

    fn screen(id: ScreenId, peer: PeerId, name: &str) -> Screen {
        Screen {
            id,
            peer,
            name: name.to_owned(),
            width_px: 1920,
            height_px: 1080,
        }
    }

    /// A desktop with a laptop to its right, both 1920x1080.
    fn session() -> Session {
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, ME, "desktop")).unwrap();
        layout.add_screen(screen(LAPTOP, THEM, "laptop")).unwrap();
        layout
            .link(DESKTOP, crate::domain::Edge::Right, LAPTOP)
            .unwrap();

        let mut session = Session::new(
            layout,
            DESKTOP,
            Point::new(1919, 540),
            SessionConfig::default(),
        );

        let mut out = Vec::new();
        session.step(Input::Tick { now_ms: Millis(0) }, &mut out);
        session.step(
            Input::PeerConnected {
                peer: THEM,
                screen: screen(LAPTOP, THEM, "laptop"),
            },
            &mut out,
        );
        session
    }

    /// Pushes the cursor across to the laptop.
    fn cross(session: &mut Session, out: &mut Vec<Command>) {
        session.step(
            Input::Local(InputEvent::MotionRel {
                dx_milli: 20_000,
                dy_milli: 0,
            }),
            out,
        );
    }

    #[test]
    fn a_new_session_has_the_cursor_at_home() {
        assert_eq!(session().locus(), Locus::Local);
    }

    #[test]
    fn local_input_is_not_forwarded_while_the_cursor_is_here() {
        // Otherwise Wraith would be a keylogger that also happens to switch
        // screens.
        let mut session = session();
        let mut out = Vec::new();

        session.step(Input::Local(press(KEY_C)), &mut out);

        assert!(out.is_empty(), "local input leaked: {out:?}");
    }

    #[test]
    fn a_deliberate_shove_crosses_and_starts_suppressing() {
        let mut session = session();
        let mut out = Vec::new();

        cross(&mut session, &mut out);

        assert!(
            out.contains(&Command::Suppress(true)),
            "did not suppress: {out:?}"
        );
        assert!(
            out.iter()
                .any(|c| matches!(c, Command::SendEnter { peer, .. } if *peer == THEM)),
            "did not tell the peer: {out:?}"
        );
        assert!(matches!(session.locus(), Locus::Remote { screen } if screen == LAPTOP));
    }

    #[test]
    fn input_is_forwarded_once_the_cursor_is_remote() {
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);

        session.step(Input::Local(press(KEY_C)), &mut out);

        assert_eq!(
            out,
            vec![Command::SendTransitions {
                peer: THEM,
                events: vec![press(KEY_C)]
            }]
        );
    }

    #[test]
    fn a_transition_goes_on_the_stream_and_motion_on_a_datagram() {
        // The split that keeps a lost packet from stranding a modifier.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);

        session.step(Input::Local(press(CTRL)), &mut out);
        assert!(matches!(out.first(), Some(Command::SendTransitions { .. })));

        session.step(
            Input::Local(InputEvent::MotionRel {
                dx_milli: 500,
                dy_milli: 0,
            }),
            &mut out,
        );
        assert!(matches!(out.first(), Some(Command::SendMotion { .. })));
    }

    #[test]
    fn arriving_input_from_a_peer_is_injected() {
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerTransitions {
                peer: THEM,
                events: vec![press(KEY_C)],
            },
            &mut out,
        );

        assert_eq!(out, vec![Command::Inject(vec![press(KEY_C)])]);
    }

    #[test]
    fn input_from_an_unknown_peer_is_ignored() {
        // Belt and braces behind the pinned verifier: even if an unpaired peer
        // somehow reached the session, it has no ledger and injects nothing.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerTransitions {
                peer: PeerId([9; 32]),
                events: vec![press(KEY_C)],
            },
            &mut out,
        );

        assert!(out.is_empty());
    }

    #[test]
    fn a_peer_going_quiet_releases_what_it_held() {
        // The layer that needs nothing from the sender, which is the whole
        // point of it.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerTransitions {
                peer: THEM,
                events: vec![press(CTRL)],
            },
            &mut out,
        );
        assert!(session.any_held());

        session.step(
            Input::Tick {
                now_ms: Millis(5_000),
            },
            &mut out,
        );

        assert!(
            out.iter()
                .any(|c| matches!(c, Command::Inject(events) if events.contains(&release(CTRL)))),
            "the watchdog did not release: {out:?}"
        );
        assert!(!session.any_held());
    }

    #[test]
    fn losing_a_peer_releases_everything_it_held_immediately() {
        // Faster than the watchdog, because a closed connection is already
        // proof the sender has stopped.
        let mut session = session();
        let mut out = Vec::new();
        session.step(
            Input::PeerTransitions {
                peer: THEM,
                events: vec![press(CTRL)],
            },
            &mut out,
        );

        session.step(Input::PeerLost { peer: THEM }, &mut out);

        assert!(
            out.iter()
                .any(|c| matches!(c, Command::Inject(events) if events.contains(&release(CTRL)))),
            "a lost peer left a key held: {out:?}"
        );
    }

    #[test]
    fn losing_the_peer_holding_the_cursor_brings_it_home() {
        // Otherwise local input goes to a machine that is no longer there, and
        // the user has a dead keyboard with no clue why.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);
        assert_ne!(session.locus(), Locus::Local);

        session.step(Input::PeerLost { peer: THEM }, &mut out);

        assert_eq!(
            session.locus(),
            Locus::Local,
            "the cursor was stranded on a dead peer"
        );
        assert!(
            out.contains(&Command::Suppress(false)),
            "input was left suppressed: {out:?}"
        );
    }

    #[test]
    fn a_peer_leaving_releases_what_it_held_here() {
        let mut session = session();
        let mut out = Vec::new();
        session.step(
            Input::PeerTransitions {
                peer: THEM,
                events: vec![press(CTRL)],
            },
            &mut out,
        );

        session.step(Input::PeerLeave { peer: THEM }, &mut out);

        assert_eq!(out, vec![Command::Inject(vec![release(CTRL)])]);
    }

    #[test]
    fn reconciliation_releases_what_the_peer_no_longer_claims() {
        let mut session = session();
        let mut out = Vec::new();
        session.step(
            Input::PeerTransitions {
                peer: THEM,
                events: vec![press(CTRL), press(KEY_C)],
            },
            &mut out,
        );

        let mut authoritative = HeldSet::new();
        authoritative.apply(press(CTRL));
        session.step(
            Input::PeerSnapshot {
                peer: THEM,
                held: authoritative,
            },
            &mut out,
        );

        assert_eq!(out, vec![Command::Inject(vec![release(KEY_C)])]);
    }

    #[test]
    fn an_agreeing_snapshot_produces_no_commands() {
        // The common case, a hundred times a second while a key is held. It
        // must be silent or the log and the wire both fill with nothing.
        let mut session = session();
        let mut out = Vec::new();
        session.step(
            Input::PeerTransitions {
                peer: THEM,
                events: vec![press(CTRL)],
            },
            &mut out,
        );

        let mut authoritative = HeldSet::new();
        authoritative.apply(press(CTRL));
        session.step(
            Input::PeerSnapshot {
                peer: THEM,
                held: authoritative,
            },
            &mut out,
        );

        assert!(out.is_empty(), "an agreeing snapshot produced {out:?}");
    }

    #[test]
    fn going_home_releases_what_this_machine_had_announced() {
        // The cursor leaving with a key still down is exactly how a modifier
        // gets stranded on the far machine. Driven by the desk changing under
        // the cursor, which is one of the two ways home is reached, and the one
        // that leaves the peer connected to be told.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);
        session.step(Input::Local(press(CTRL)), &mut out);

        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, ME, "desktop")).unwrap();
        session.step(Input::LayoutChanged { layout }, &mut out);

        assert!(
            out.iter().any(|c| matches!(
                c,
                Command::SendTransitions { events, .. } if events.contains(&release(CTRL))
            )),
            "went home still holding Ctrl: {out:?}"
        );
    }

    #[test]
    fn a_peer_that_renamed_itself_is_recorded_under_the_new_name() {
        // Routing prefers the identity key, so a stale label breaks nothing.
        // It is still confusing to see a machine on one desk under a name it
        // stopped answering to.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerConnected {
                peer: THEM,
                screen: Screen {
                    name: "workstation".to_owned(),
                    ..screen(LAPTOP, THEM, "laptop")
                },
            },
            &mut out,
        );

        assert!(out.iter().any(|command| matches!(
            command,
            Command::SaveName { peer, name }
                if *peer == THEM && name == "workstation"
        )));
    }

    #[test]
    fn a_peer_whose_name_agrees_writes_nothing() {
        // The no-ping-pong property: two machines reconnecting must not take
        // turns rewriting each other's desk.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerConnected {
                peer: THEM,
                screen: screen(LAPTOP, THEM, "laptop"),
            },
            &mut out,
        );

        assert!(
            !out.iter()
                .any(|command| matches!(command, Command::SaveName { .. }))
        );
    }

    #[test]
    fn a_peer_saying_the_cursor_arrived_warps_and_stops_suppressing() {
        let mut session = session();
        let mut out = Vec::new();

        let crossing = Crossing {
            to: DESKTOP,
            entry_edge: crate::domain::Edge::Left,
            at: crate::domain::Fraction::MIDDLE,
            entry_px: Point::new(1, 540),
        };
        session.step(
            Input::PeerEnter {
                peer: THEM,
                crossing,
            },
            &mut out,
        );

        assert!(
            out.contains(&Command::WarpLocal(Point::new(1, 540))),
            "no warp: {out:?}"
        );

        // The half this test was named for and did not check. It passed for as
        // long as it existed while the command it claims to assert was never
        // emitted at all, which is how a machine that goes deaf on every second
        // crossing shipped.
        assert!(
            out.contains(&Command::Suppress(false)),
            "named for suppression and never checked it: {out:?}"
        );

        assert_eq!(session.locus(), Locus::Local);
    }

    #[test]
    fn a_snapshot_is_sent_while_this_machine_holds_something_remotely() {
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);
        session.step(Input::Local(press(CTRL)), &mut out);

        session.step(
            Input::Tick {
                now_ms: Millis(500),
            },
            &mut out,
        );

        assert!(
            out.iter()
                .any(|c| matches!(c, Command::SendSnapshot { peer, .. } if *peer == THEM)),
            "no snapshot while holding Ctrl remotely: {out:?}"
        );
    }

    #[test]
    fn no_snapshot_is_sent_while_nothing_is_held() {
        // An idle link should carry no traffic at all.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::Tick {
                now_ms: Millis(5_000),
            },
            &mut out,
        );

        assert!(
            !out.iter()
                .any(|c| matches!(c, Command::SendSnapshot { .. })),
            "an idle session sent a snapshot: {out:?}"
        );
    }

    #[test]
    fn a_peer_placement_is_mirrored_before_being_saved() {
        // The peer says this machine is on its right, so it is on this
        // machine's left. Getting the mirror backwards would put every desk
        // the wrong way round.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerPlaced {
                peer: THEM,
                side: crate::domain::Edge::Right,
            },
            &mut out,
        );

        assert_eq!(
            out,
            vec![Command::SavePlacement {
                peer: THEM,
                side: crate::domain::Edge::Left
            }]
        );
    }

    #[test]
    fn a_desk_change_that_keeps_the_current_screen_leaves_the_cursor_alone() {
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);
        let was = session.locus();

        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, ME, "desktop")).unwrap();
        layout.add_screen(screen(LAPTOP, THEM, "laptop")).unwrap();
        layout
            .link(DESKTOP, crate::domain::Edge::Right, LAPTOP)
            .unwrap();

        session.step(Input::LayoutChanged { layout }, &mut out);

        assert_eq!(session.locus(), was, "the cursor moved for no reason");
    }

    #[test]
    fn a_desk_change_that_removes_the_current_screen_brings_the_cursor_home() {
        // A screen dragged away, or a peer that rearranged its own desk.
        // Leaving the cursor there would send local input to a screen that is
        // not on the desk any more.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);
        assert_ne!(session.locus(), Locus::Local);

        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, ME, "desktop")).unwrap();

        session.step(Input::LayoutChanged { layout }, &mut out);

        assert_eq!(session.locus(), Locus::Local, "the cursor was stranded");
        assert!(
            out.contains(&Command::Suppress(false)),
            "input was left suppressed: {out:?}"
        );
    }

    #[test]
    fn a_desk_change_releases_what_was_held_on_the_screen_that_vanished() {
        // Same reasoning as a lost peer: nothing may be left down.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);
        session.step(Input::Local(press(CTRL)), &mut out);

        session.step(
            Input::LayoutChanged {
                layout: Layout::new(),
            },
            &mut out,
        );

        assert!(
            out.iter().any(|c| matches!(
                c,
                Command::SendTransitions { events, .. } if events.contains(&release(CTRL))
            )),
            "the desk changed while holding Ctrl and it was not released: {out:?}"
        );
    }

    #[test]
    fn step_clears_the_output_between_calls() {
        // The caller reuses one Vec for the life of the process, so a step that
        // appended without clearing would replay every earlier command.
        let mut session = session();
        let mut out = vec![Command::Notify(Notice::DeskChangedUnderCursor)];

        session.step(Input::Tick { now_ms: Millis(1) }, &mut out);

        assert!(!out.contains(&Command::Notify(Notice::DeskChangedUnderCursor)));
    }

    /// Every `Crossed` a run produced.
    fn crossings(out: &[Command]) -> Vec<(Direction, Edge)> {
        out.iter()
            .filter_map(|command| match command {
                Command::Crossed {
                    direction, edge, ..
                } => Some((*direction, *edge)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn leaving_announces_a_departure_on_the_edge_left_by() {
        // The laptop is to the right, so its entry edge is its Left, and the
        // edge left by here is the Right. Getting this backwards puts the
        // effect on the wrong side of the screen, which is the single most
        // likely mistake in the whole feature.
        let mut session = session();
        let mut out = Vec::new();

        cross(&mut session, &mut out);

        assert_eq!(
            crossings(&out),
            vec![(Direction::Departure, Edge::Right)],
            "one departure, on the right"
        );
    }

    #[test]
    fn arriving_from_a_peer_announces_an_arrival() {
        // The other path into a crossing, and a separate function, so it needs
        // its own emission rather than inheriting one.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerEnter {
                peer: THEM,
                crossing: Crossing {
                    to: DESKTOP,
                    entry_edge: Edge::Right,
                    at: Fraction::MIDDLE,
                    entry_px: Point::new(1919, 540),
                },
            },
            &mut out,
        );

        assert_eq!(crossings(&out), vec![(Direction::Arrival, Edge::Right)]);
    }

    #[test]
    fn a_crossing_carries_how_far_along_the_edge_it_was() {
        // The fraction is what positions the effect, so a crossing that always
        // reported the middle would look right in every test and wrong on a
        // real screen.
        let mut session = session();
        let mut out = Vec::new();

        session.step(
            Input::PeerEnter {
                peer: THEM,
                crossing: Crossing {
                    to: DESKTOP,
                    entry_edge: Edge::Right,
                    at: Fraction::new(0.25),
                    entry_px: Point::new(1919, 270),
                },
            },
            &mut out,
        );

        let at = out.iter().find_map(|command| match command {
            Command::Crossed { at, .. } => Some(*at),
            _ => None,
        });

        assert_eq!(at, Some(Fraction::new(0.25)));
    }

    #[test]
    fn going_home_is_not_reported_as_a_crossing() {
        // `go_home` warps without crossing an edge, so drawing an edge effect
        // for it would put a wisp on a screen the cursor did not travel to.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);

        out.clear();
        let mut layout = Layout::new();
        layout.add_screen(screen(DESKTOP, ME, "desktop")).unwrap();
        session.step(Input::LayoutChanged { layout }, &mut out);

        assert!(
            crossings(&out).is_empty(),
            "coming home is a warp, not a crossing"
        );
    }

    /// A screen of a given size, for the geometry tests below.
    fn sized(id: ScreenId, peer: PeerId, name: &str, width_px: u32, height_px: u32) -> Screen {
        Screen {
            id,
            peer,
            name: name.to_owned(),
            width_px,
            height_px,
        }
    }

    #[test]
    fn a_peers_real_size_replaces_the_guess() {
        // The layout is built from a file that says where a machine sits and
        // nothing about how big it is, so every remote screen starts as a copy
        // of this one. The hello is the only place the truth arrives.
        let mut layout = Layout::new();
        layout
            .add_screen(sized(DESKTOP, ME, "desktop", 3024, 1964))
            .unwrap();
        layout
            .add_screen(sized(LAPTOP, THEM, "laptop", 3024, 1964))
            .unwrap();
        layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();

        let mut session = Session::new(
            layout,
            DESKTOP,
            Point::new(3023, 982),
            SessionConfig::default(),
        );
        let mut out = Vec::new();
        session.step(Input::Tick { now_ms: Millis(0) }, &mut out);

        session.step(
            Input::PeerConnected {
                peer: THEM,
                screen: sized(LAPTOP, THEM, "laptop", 10240, 2880),
            },
            &mut out,
        );

        assert_eq!(
            session
                .layout()
                .screen(LAPTOP)
                .map(|s| (s.width_px, s.height_px)),
            Some((10240, 2880)),
            "the hello's size must win over the guess"
        );
    }

    #[test]
    fn a_crossing_lands_at_the_far_edge_of_the_real_screen() {
        // The reported bug, at the reported sizes. A laptop crossing right onto
        // a 10240x2880 desk must arrive against that desk's left edge, not
        // against a phantom one 3024 wide.
        let mut layout = Layout::new();
        layout
            .add_screen(sized(DESKTOP, ME, "desktop", 3024, 1964))
            .unwrap();
        layout
            .add_screen(sized(LAPTOP, THEM, "laptop", 3024, 1964))
            .unwrap();
        layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();

        let mut session = Session::new(
            layout,
            DESKTOP,
            Point::new(3023, 982),
            SessionConfig::default(),
        );
        let mut out = Vec::new();
        session.step(Input::Tick { now_ms: Millis(0) }, &mut out);
        session.step(
            Input::PeerConnected {
                peer: THEM,
                screen: sized(LAPTOP, THEM, "laptop", 10240, 2880),
            },
            &mut out,
        );

        out.clear();
        cross(&mut session, &mut out);

        let crossing = out
            .iter()
            .find_map(|command| match command {
                Command::SendEnter { crossing, .. } => Some(*crossing),
                _ => None,
            })
            .expect("it crosses");

        assert_eq!(crossing.entry_edge, Edge::Left);

        // One, not zero: `entry_point` insets a pixel so the arriving cursor is
        // inside the screen rather than on the boundary it just came through.
        assert_eq!(crossing.entry_px.x_px, 1, "hard against the far left edge");

        // The point of the whole thing. Half way down the real 2880 is about
        // 1440, while half way down a guessed 1964 is about 982: a third of the
        // way up a screen the cursor should have entered at the middle of.
        assert!(
            crossing.entry_px.y_px > 1300,
            "mapped onto the real height, got {}",
            crossing.entry_px.y_px
        );
    }

    #[test]
    fn crossing_left_lands_on_the_far_desks_rightmost_monitor() {
        // The real desk, in the arrangement the user tested: a 3024x1964 laptop
        // with a 10240x2880 two-monitor desk to its LEFT. Going left must enter
        // that desk at its right edge, which is physically the second monitor,
        // since the right hand panel spans x 5120..10239.
        //
        // Against the guessed size this landed at about x=3022, a third of the
        // way across the FIRST monitor, which is what "it does not use the whole
        // screen" looked like from the outside.
        let mut layout = Layout::new();
        layout
            .add_screen(sized(DESKTOP, ME, "ember", 3024, 1964))
            .unwrap();
        layout
            .add_screen(sized(LAPTOP, THEM, "forge", 3024, 1964))
            .unwrap();
        layout.link(DESKTOP, Edge::Left, LAPTOP).unwrap();

        let mut session = Session::new(
            layout,
            DESKTOP,
            Point::new(0, 982),
            SessionConfig::default(),
        );
        let mut out = Vec::new();
        session.step(Input::Tick { now_ms: Millis(0) }, &mut out);
        session.step(
            Input::PeerConnected {
                peer: THEM,
                screen: sized(LAPTOP, THEM, "forge", 10240, 2880),
            },
            &mut out,
        );

        out.clear();
        session.step(
            Input::Local(InputEvent::MotionRel {
                dx_milli: -20_000,
                dy_milli: 0,
            }),
            &mut out,
        );

        let crossing = out
            .iter()
            .find_map(|command| match command {
                Command::SendEnter { crossing, .. } => Some(*crossing),
                _ => None,
            })
            .expect("it crosses left");

        assert_eq!(crossing.entry_edge, Edge::Right, "enters by the far right");
        assert!(
            crossing.entry_px.x_px >= 5120,
            "must land on the second monitor, got x={}",
            crossing.entry_px.x_px
        );
        assert_eq!(crossing.entry_px.x_px, 10238, "one pixel inside the edge");
    }

    #[test]
    fn a_peer_handing_the_cursor_back_releases_suppression() {
        // The asymmetry that locked the machine out. Departure sets the gate,
        // and until this test existed only the machine's own edge detection
        // cleared it, so a cursor pushed back by the *other* side left this one
        // deaf to its own keyboard.
        let mut session = session();
        let mut out = Vec::new();

        cross(&mut session, &mut out);
        assert!(out.contains(&Command::Suppress(true)), "leaving suppresses");

        out.clear();
        session.step(
            Input::PeerEnter {
                peer: THEM,
                crossing: Crossing {
                    to: DESKTOP,
                    entry_edge: Edge::Right,
                    at: Fraction::MIDDLE,
                    entry_px: Point::new(1919, 540),
                },
            },
            &mut out,
        );

        assert!(
            out.contains(&Command::Suppress(false)),
            "and being handed it back must release, got {out:?}"
        );
    }

    #[test]
    fn the_pointer_is_warped_before_suppression_is_released() {
        // Position, then reveal. Suppression gates capture rather than
        // injection, so a warp lands either way; what the order decides is
        // whether the injector's pointer poll can slip through the gate between
        // the two and resync the session onto the position the cursor had
        // before it ever left.
        let mut session = session();
        let mut out = Vec::new();
        cross(&mut session, &mut out);

        out.clear();
        session.step(
            Input::PeerEnter {
                peer: THEM,
                crossing: Crossing {
                    to: DESKTOP,
                    entry_edge: Edge::Right,
                    at: Fraction::MIDDLE,
                    entry_px: Point::new(1919, 540),
                },
            },
            &mut out,
        );

        // Unwrapped before comparing, because these are `Option<usize>` and
        // `None < Some(_)` is true: comparing them directly passes when the
        // warp is missing entirely, which is the failure worth catching.
        let released = out
            .iter()
            .position(|command| *command == Command::Suppress(false))
            .expect("suppression is released on arrival");
        let warped = out
            .iter()
            .position(|command| matches!(command, Command::WarpLocal(_)))
            .expect("the pointer is warped on arrival");

        assert!(warped < released, "warp first, then release: {out:?}");
    }

    #[test]
    fn a_self_detected_arrival_is_ordered_like_an_announced_one() {
        // The same transition by the other route. `on_peer_enter` handles a
        // peer saying the cursor is coming back; this is the local edge logic
        // deciding the same thing, and it had the two commands the other way
        // round while the comment on the other path explained why that is wrong.
        let mut session = session();
        let mut out = Vec::new();

        cross(&mut session, &mut out);

        // Past the cooldown, then push back against the edge it left by.
        session.step(
            Input::Tick {
                now_ms: Millis(5_000),
            },
            &mut out,
        );
        out.clear();
        session.step(
            Input::Local(InputEvent::MotionRel {
                dx_milli: -40_000,
                dy_milli: 0,
            }),
            &mut out,
        );

        let released = out
            .iter()
            .position(|command| *command == Command::Suppress(false))
            .expect("a self detected arrival releases suppression");
        let warped = out
            .iter()
            .position(|command| matches!(command, Command::WarpLocal(_)))
            .expect("a self detected arrival warps the pointer");

        assert!(warped < released, "warp first, then release: {out:?}");
    }

    #[test]
    fn the_cursor_is_never_on_both_machines_at_once() {
        // The invariant the whole handoff exists to keep. Leaving means this
        // machine no longer holds it; being handed it back means it does. There
        // is no step where both are true, and none where neither is.
        let mut session = session();
        let mut out = Vec::new();

        assert_eq!(session.locus(), Locus::Local, "starts here");

        cross(&mut session, &mut out);
        assert_ne!(session.locus(), Locus::Local, "and leaves");

        session.step(
            Input::PeerEnter {
                peer: THEM,
                crossing: Crossing {
                    to: DESKTOP,
                    entry_edge: Edge::Right,
                    at: Fraction::MIDDLE,
                    entry_px: Point::new(1919, 540),
                },
            },
            &mut out,
        );
        assert_eq!(session.locus(), Locus::Local, "and comes back");
    }
}
