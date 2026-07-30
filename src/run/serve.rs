//! `wraith serve`, the running KVM.
//!
//! # Shape
//!
//! One task owns the [`Session`] and is the only thing that touches it.
//! Everything else feeds it over a channel: the capture thread, each peer's
//! reader, and a ticker. The reducer stays pure and single-threaded, which is
//! what makes its behaviour in production the same as in a test.
//!
//! ```text
//!   capture thread ─┐
//!   peer readers  ──┼──> events ──> Session::step ──> commands ─┬─> injector thread
//!   ticker        ──┘                                           └─> peer writers
//! ```
//!
//! # Symmetry
//!
//! Every machine both listens and dials. There is no server and no client,
//! because a desk has no natural centre and asking the user to nominate one is
//! a configuration question with no good answer. Whichever side dials opens the
//! control stream, and that is the only asymmetry.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use quinn::{Connection, Endpoint};
use tokio::sync::mpsc;

use crate::config::{Config, Peer, Peers};
use crate::control::{self, Crossed};
use crate::domain::{
    Cell, Command, Edge, Input, Layout, Millis, PeerId, Point, Screen, ScreenId, Seq, Session,
    SessionConfig,
};
use crate::error::{Error, Result};
use crate::net::discovery::{self, Discovery};
use crate::net::verify::{TrustedPeers, subject_public_key};
use crate::net::wire::{self, Control, PROTOCOL_VERSION};
use crate::net::{Identity, endpoint};
use crate::platform;
use crate::ports::ClipboardContents;
use crate::run::clipboard::{self, Cache};
use crate::run::injector::Injector;
use crate::run::watch::Watchers;

/// How often the session ticks.
///
/// Drives the watchdog and the snapshot. Twenty milliseconds is far finer
/// than either deadline and costs nothing.
const TICK_MS: u64 = 20;

/// How long before retrying a peer that is not answering.
const RECONNECT_MS: u64 = 2_000;

/// How many events may queue between the feeders and the session task.
const CHANNEL_CAPACITY: usize = 4_096;

/// How often the desk file is checked for a change from the window.
///
/// A person dragging a screen will wait half a second without noticing, and
/// polling this slowly costs nothing.
const DESK_POLL_MS: u64 = 500;
mod capture;

use capture::spawn_capture;
pub use capture::{CaptureState, capture_gate};

/// A monotonic clock the session can be fed from.
///
/// The domain takes [`Millis`] as data. This is the one place that turns a real
/// clock into that, so everything downstream stays testable.
#[derive(Debug, Clone, Copy)]
struct Clock {
    started: Instant,
}

impl Clock {
    fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    fn now(self) -> Millis {
        Millis(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// Runs until interrupted.
pub async fn run(identity: Arc<Identity>, mut config: Config, listen: SocketAddr) -> Result<()> {
    let (peers, local_name, geometry, layout, home) = read_the_desk(&mut config)?;

    // The injector thread owns the display handle, so it is the one that can
    // ask where the pointer really is. See `Input::LocalPointerAt`.
    let (found, pointers) = std::sync::mpsc::channel();
    let injector = Injector::start(platform::open_inject()?, Some(found)).map_err(Error::Io)?;
    let session = Session::new(layout, home, geometry.centre(), SessionConfig::default());

    // The clipboard follows the cursor. Its backend is single-thread-affine like
    // the injector's, so it too runs on its own thread; its absence is not fatal,
    // a machine with none still shares input. The cache is the current local
    // clipboard and what each peer has already been given, written by the thread
    // as the clipboard changes and read at a crossing.
    let clip_cache = Cache::default();
    let clipboard = start_clipboard(&clip_cache);

    let clock = Clock::start();
    let (events, inbox) = mpsc::channel(CHANNEL_CAPACITY);
    let outgoing = Outgoing::default();
    let hello = Control::Hello {
        protocol: PROTOCOL_VERSION,
        name: local_name.clone(),
        screen: local_screen(home, &local_name, geometry),
    };

    let capture = CaptureState::default();
    spawn_pointer_watch(events.clone(), pointers);
    spawn_ticker(events.clone(), clock);
    spawn_capture(events.clone(), capture.clone());

    let feed = Feed {
        events: events.clone(),
        outgoing: outgoing.clone(),
        hello,
        clipboard: clipboard.clone(),
        clip_cache: clip_cache.clone(),
    };
    let network = start_network(&identity, peers, listen, &local_name, feed)?;

    let desk = Desk::new(
        Config::path(),
        network.roster.clone(),
        events.clone(),
        outgoing.clone(),
        geometry,
    );
    spawn_file_watch(desk.clone(), network.roster.clone());

    // Made here rather than inside the session, because both halves need it:
    // the reducer's commands go in and the control server hands out receivers.
    let watchers = Watchers::new();

    let (listening, halt) = start_control(
        &identity,
        &local_name,
        listen,
        &outgoing,
        network.roster,
        capture,
        &watchers,
    );

    let (server, announcing) = (network.server, network.announcing);
    let effects = Effects {
        injector: &injector,
        outgoing: &outgoing,
        desk: &desk,
        watchers: &watchers,
        clip_cache: &clip_cache,
    };
    let outcome = pump(session, inbox, &effects, clock, halt).await;

    shut_down(&injector, &outgoing, &server, announcing, listening);
    // Held until here so the clipboard thread outlives the session rather than
    // stopping the moment the last peer reader drops its clone.
    drop(clipboard);
    outcome
}

/// Starts the clipboard thread, or says why there is none and carries on.
///
/// The clipboard is best-effort: a machine whose compositor offers no
/// data-control, or a platform with no adapter yet, shares input all the same.
/// So a failure here is a warning and a `None`, not an error that stops `run`.
fn start_clipboard(cache: &Cache) -> Option<clipboard::Clipboard> {
    let backend = match platform::open_clipboard() {
        Ok(backend) => backend,
        Err(error) => {
            tracing::warn!(%error, "no clipboard backend, the clipboard will not follow the cursor");
            return None;
        }
    };

    let (changed, changes) = std::sync::mpsc::channel();
    clipboard::spawn_watch(cache.clone(), changes);

    match clipboard::Clipboard::start(backend, changed) {
        Ok(handle) => Some(handle),
        Err(error) => {
            tracing::warn!(%error, "the clipboard thread did not start");
            None
        }
    }
}

/// Everything the session needs before anything is started.
///
/// Split off so `run` reads as the wiring it is. The desk is repaired, then
/// checked, then turned into a layout, and none of that touches the network.
fn read_the_desk(
    config: &mut Config,
) -> Result<(Peers, String, Geometry, crate::domain::Layout, ScreenId)> {
    heal(config)?;
    config
        .validate()
        .map_err(|error| Error::Config(error.to_string()))?;

    let peers = Peers::load(&Peers::path()).map_err(|error| Error::Config(error.to_string()))?;
    if peers.peer.is_empty() {
        // A warning rather than a refusal. A machine with nothing paired is
        // exactly the machine that is about to pair, and pairing needs this
        // running to do it from the window. Refusing to start makes that
        // impossible: no session without a pairing, and no pairing without a
        // session.
        tracing::warn!(
            "no paired machines yet, so there is nothing to share input with. \
             Pair one from the window, or run `wraith pair` on both machines"
        );
    }

    let local_name = config.local_name();
    let geometry = local_geometry();
    let (layout, home) = build_layout(config, &peers, &local_name, geometry)?;

    Ok((peers, local_name, geometry, layout, home))
}

/// Starts the control socket, and hands back the way to stop the session.
///
/// Bound before the session starts pumping, so a window that starts this process
/// and immediately asks for a status is answered rather than told nothing is
/// running.
fn start_control(
    identity: &Arc<Identity>,
    local_name: &str,
    listen: SocketAddr,
    outgoing: &Outgoing,
    roster: Roster,
    capture: CaptureState,
    watchers: &Watchers,
) -> (
    Option<tokio::task::JoinHandle<()>>,
    tokio::sync::watch::Receiver<bool>,
) {
    let (stop, halt) = tokio::sync::watch::channel(false);

    let control = control::server::Handle {
        identity: Arc::clone(identity),
        name: local_name.to_owned(),
        listen,
        clock_started: Instant::now(),
        outgoing: outgoing.clone(),
        roster,
        capture,
        stop,
        pairing: control::server::PairingSlot::default(),
        watchers: watchers.clone(),
    };

    (control::server::spawn(control), halt)
}

/// Lets go of everything, in the order that matters.
fn shut_down(
    injector: &Injector,
    outgoing: &Outgoing,
    server: &Endpoint,
    announcing: Option<Discovery>,
    listening: Option<tokio::task::JoinHandle<()>>,
) {
    // Before anything else, because a peer left holding a key is the failure
    // this project exists to prevent. Dropping the injector in the caller is
    // what waits for that to have happened.
    injector.shutdown();
    outgoing.say_goodbye();
    server.close(0_u8.into(), b"shutdown");
    drop(announcing);

    // Aborted rather than dropped. Dropping a `JoinHandle` detaches its task, so
    // the listener would go on accepting against a socket the next line unlinks
    // out from under it.
    if let Some(listening) = listening {
        listening.abort();
    }
    platform::socket::control_unlink();
}

/// Puts this machine back on its own desk, before anything reads it.
///
/// Repaired rather than refused. A desk that does not name this machine is a
/// one-line fault in one file, and refusing it before the injector, the
/// listener or the control socket exist leaves the window reporting a session
/// that never answered, with no way to reach the file at fault. Same reasoning
/// as the empty trust store below.
///
/// The only writer outside `Desk`, and it runs before `Desk` exists, so the two
/// cannot race and the mtime left here is the one `Desk::new` records.
fn heal(config: &mut Config) -> Result<()> {
    let repair = config.repair_local();
    if !repair.changed() {
        return Ok(());
    }

    tracing::warn!(
        ?repair,
        name = %config.local_name(),
        "this desk did not name this machine, so it has been put back on it"
    );

    config
        .save(&Config::path())
        .map_err(|error| Error::Config(error.to_string()))
}

/// Everything listening or dialling, once it is all up.
struct Network {
    server: Endpoint,
    announcing: Option<Discovery>,
    roster: Roster,
}

/// The session-wide wiring a peer link is handed.
///
/// Where its inputs go, how to reply, the hello to open with, the clipboard that
/// inbound copies are set on, and the cache read to hand this machine's clipboard
/// back when a peer reclaims the cursor. Bundled for the same reason as
/// [`Effects`]: they travel together to every peer and passing them apart pushed
/// the serving path past the argument limit. Cloned per connection.
#[derive(Clone)]
struct Feed {
    events: mpsc::Sender<Input>,
    outgoing: Outgoing,
    hello: Control,
    /// `None` when this machine has no clipboard backend.
    clipboard: Option<clipboard::Clipboard>,
    /// The local clipboard, read at a crossing to hand a peer taking the cursor.
    /// Shared with the watch, which keeps it current. Same instance as the one
    /// [`Effects`] reads for the outbound `SendEnter` hook.
    clip_cache: Cache,
}

/// Binds, announces, accepts, and starts dialling.
///
/// Split out of `run` because `run` was over the line limit, and because the
/// order in here matters in a way worth having in one place: the trust set is
/// built before either endpoint, and discovery starts before dialling so an
/// address learned from the network is in place by the first retry.
fn start_network(
    identity: &Identity,
    peers: Peers,
    listen: SocketAddr,
    local_name: &str,
    feed: Feed,
) -> Result<Network> {
    // One trust set, shared by both endpoints and by the reload. Cloning it
    // shares rather than copies, which is what lets a machine paired later be
    // accepted without rebinding anything.
    let trusted = peers.trusted();
    let server = endpoint::server(identity, trusted.clone(), listen)
        .map_err(|error| Error::Config(error.to_string()))?;

    let found = Discovered::default();
    let announcing = start_discovery(identity, local_name, listen.port(), &found);

    spawn_accepts(server.clone(), feed.clone());

    let dialer = Dialer::new(identity, trusted.clone(), feed, found)?;
    dialer.ensure(&peers);

    tracing::info!(
        name = %local_name,
        listen = %listen,
        peers = peers.peer.len(),
        "wraith is running"
    );

    Ok(Network {
        server,
        announcing,
        roster: Roster::new(Peers::path(), peers, trusted, dialer),
    })
}

/// Everything a command can reach.
///
/// Bundled because they travel together and always have: every one of them is
/// needed to carry out a command and none is needed alone. Passing them
/// individually pushed both `pump` and `apply` past the argument limit, which is
/// the shape complaining rather than the limit being wrong.
struct Effects<'a> {
    injector: &'a Injector,
    outgoing: &'a Outgoing,
    desk: &'a Desk,
    watchers: &'a Watchers,
    /// The local clipboard, read at a crossing to hand the entered peer. Shared
    /// with the clipboard watch, which keeps it current.
    clip_cache: &'a Cache,
}

/// The session task. The only thing that touches the reducer.
async fn pump(
    mut session: Session,
    mut inbox: mpsc::Receiver<Input>,
    effects: &Effects<'_>,
    clock: Clock,
    mut halt: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut commands = Vec::new();
    let mut seq = Seq::ZERO;

    loop {
        let input = tokio::select! {
            received = inbox.recv() => match received {
                Some(input) => input,
                None => return Ok(()),
            },
            () = shutdown_signal(&mut halt) => {
                tracing::info!("shutting down");
                return Ok(());
            }
        };

        session.step(input, &mut commands);

        // drain rather than into_iter, so the Vec keeps its allocation across
        // iterations. At a thousand motion events a second that is the point.
        #[expect(
            clippy::iter_with_drain,
            reason = "the buffer is reused every iteration"
        )]
        for command in commands.drain(..) {
            apply(command, effects, &mut seq, clock.now());
        }
    }
}

/// Carries out one command.
fn apply(command: Command, effects: &Effects<'_>, seq: &mut Seq, now_ms: Millis) {
    let Effects {
        injector,
        outgoing,
        desk,
        watchers,
        clip_cache,
    } = effects;

    match command {
        Command::SavePlacement { peer, side } => desk.place_peer(peer, side),
        Command::SaveName { peer, name } => desk.rename_peer(peer, &name),

        Command::Inject(events) => injector.emit(events),
        Command::WarpLocal(at) => injector.warp(at),

        Command::SendTransitions { peer, events } => {
            outgoing.send(peer, &Control::Transitions { events });
        }
        Command::SendSnapshot { peer, held } => outgoing.send(peer, &Control::Snapshot { held }),
        Command::SendEnter { peer, crossing } => {
            // The cursor is leaving toward this peer, so hand it this machine's
            // clipboard on the way, but only when there is a copy this peer has
            // not already been given. Non-blocking: encode and queue, like Enter.
            outgoing.send(peer, &Control::Enter { crossing });
            if let Some(clipboard) = clipboard_to_send(clip_cache, peer) {
                outgoing.send(peer, &clipboard);
            }
        }
        Command::SendLeave { peer } => outgoing.send(peer, &Control::Leave),

        Command::SendMotion { peer, events } => {
            *seq = seq.next();
            if let Some(frame) = wire::motion_frame(events, *seq, now_ms) {
                outgoing.send_datagram(peer, &frame);
            }
        }

        Command::Suppress(on) => capture_gate::set(on),
        // Structured, so a log can be filtered by what happened rather than by
        // grepping the sentence it was rendered into.
        Command::Notify(notice) => tracing::info!(%notice, "session notice"),

        Command::Crossed {
            direction,
            edge,
            at,
        } => watchers.announce(Crossed::new(direction, edge, at)),
    }
}

/// The trust store as a running session sees it.
///
/// Owns the reload, so a machine paired while this is running joins without a
/// restart. Three things have to happen for that and only the first is obvious:
/// the layout has to learn the new screen, a dial task has to exist for it, and
/// the TLS verifier has to accept it. The third is why `TrustedPeers` is a live
/// handle rather than a set copied in at bind time.
#[derive(Clone)]
pub struct Roster {
    path: PathBuf,
    peers: Arc<Mutex<Peers>>,
    trusted: TrustedPeers,
    dialer: Dialer,
    /// What was last read, so a poll can tell a real change from no change.
    seen: Arc<Mutex<Option<SystemTime>>>,
}

impl std::fmt::Debug for Roster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Roster")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Roster {
    fn new(path: PathBuf, peers: Peers, trusted: TrustedPeers, dialer: Dialer) -> Self {
        let seen = modified_at(&path);

        Self {
            path,
            peers: Arc::new(Mutex::new(peers)),
            trusted,
            dialer,
            seen: Arc::new(Mutex::new(seen)),
        }
    }

    pub(crate) fn snapshot(&self) -> Peers {
        self.peers
            .lock()
            .map(|peers| peers.clone())
            .unwrap_or_default()
    }

    /// Re-reads the trust store and catches everything up to it.
    pub(crate) fn reload(&self) {
        let peers = match Peers::load(&self.path) {
            Ok(peers) => peers,
            Err(error) => {
                tracing::warn!(%error, "cannot re-read the trust store");
                return;
            }
        };

        // Order matters. Trust first, so a dial task started on the next line
        // cannot complete a handshake against a verifier that has not heard of
        // the peer yet.
        if !self
            .trusted
            .replace(peers.peer.iter().filter_map(Peer::peer_id))
        {
            // The old set is still in force, which means a machine the user has
            // just forgotten is still trusted. Nothing here can put that right,
            // so say so rather than reporting a reload that did not happen.
            tracing::error!(
                "the trust store could not be replaced, so a forgotten machine is still \
                 trusted until this session is restarted"
            );
        }
        self.dialer.ensure(&peers);

        if let Ok(mut held) = self.peers.lock() {
            *held = peers;
        }
    }

    fn reload_if_changed(&self) {
        let now = modified_at(&self.path);

        let changed = match self.seen.lock() {
            Ok(mut seen) if *seen != now => {
                *seen = now;
                true
            }
            _ => false,
        };

        if changed {
            tracing::info!("the trust store changed on disk, reloading");
            self.reload();
        }
    }

    /// Machines seen on the LAN that are not paired with this one.
    ///
    /// Offered to the window so there is no address to type. It fills in
    /// **where** a machine is and never **whether** to trust it: mDNS is
    /// unauthenticated and anyone can announce any name, so the six digits
    /// remain the only thing between a friendly-looking row and the trust
    /// store.
    pub(crate) fn candidates(&self) -> Vec<crate::control::Candidate> {
        let known: BTreeSet<String> = self
            .snapshot()
            .peer
            .iter()
            .filter_map(crate::config::Peer::peer_id)
            .map(discovery::short_key)
            .collect();

        self.dialer
            .found
            .seen()
            .into_iter()
            .filter(|(short_key, _)| !known.contains(short_key))
            .map(|(short_key, address)| {
                // Discovery announces the session port, and pairing listens one
                // above it. Derived rather than announced, which is right for
                // any machine on the default ports and wrong for one told to
                // listen somewhere else: that case still has the address field
                // to type into.
                let mut pairing = address;
                pairing.set_port(address.port().saturating_add(1));

                crate::control::Candidate {
                    name: short_key.clone(),
                    short_key,
                    address: pairing.to_string(),
                }
            })
            .collect()
    }
}

/// The desk on disk, and the one place it is written.
///
/// Owns `config.toml` so that three writers cannot race: a placement arriving
/// from a peer, a drag in the window, and the reload that follows either.
#[derive(Clone)]
struct Desk {
    path: PathBuf,
    roster: Roster,
    /// What was last read or written, so a reload can tell a real change from
    /// our own write coming back around.
    seen: Arc<Mutex<Option<SystemTime>>>,
    events: mpsc::Sender<Input>,
    /// So a desk edited here reaches the machines it mentions.
    ///
    /// The window writes the file and exits. Nothing else would ever tell the
    /// other machine it had moved, and a desk that disagrees with itself is the
    /// failure this whole change set exists to remove.
    outgoing: Outgoing,
    geometry: Geometry,
}

impl std::fmt::Debug for Desk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Desk")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Desk {
    fn new(
        path: PathBuf,
        roster: Roster,
        events: mpsc::Sender<Input>,
        outgoing: Outgoing,
        geometry: Geometry,
    ) -> Self {
        let seen = modified_at(&path);

        Self {
            path,
            roster,
            seen: Arc::new(Mutex::new(seen)),
            events,
            outgoing,
            geometry,
        }
    }

    /// Records where a peer says it has put this machine.
    ///
    /// The direction is a hint: `free_cell` finds the nearest empty cell that
    /// way, so a third machine arriving "to the right" lands beyond the second
    /// rather than on top of it.
    fn place_peer(&self, peer: PeerId, side: Edge) {
        let Some(name) = self.name_of(peer) else {
            tracing::warn!(%peer, "a placement arrived from a machine that is not paired");
            return;
        };

        let mut config = match Config::load(&self.path) {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, "cannot read the desk to record a placement");
                return;
            }
        };

        let local = config.local_name();
        let grid = config.grid();
        let anchor = grid.cell_of(&local).unwrap_or(Cell::ORIGIN);

        // Already where the peer says it is, so nothing to write. Without this
        // two machines rewriting each other's files would never settle.
        if grid
            .cell_of(&name)
            .is_some_and(|at| anchor.direction_to(at) == Some(side))
        {
            return;
        }

        let at = grid.free_cell(anchor, side);
        let key = self.key_of(peer);

        if let Err(error) = config.place(&name, at, key.as_deref()) {
            tracing::warn!(%error, "cannot place the peer on the desk");
            return;
        }

        self.write(&config);
        tracing::info!(%name, ?side, "a peer placed itself on the desk");
    }

    /// Records what a peer now calls itself.
    ///
    /// **By key only, never by name.** Two machines that briefly share a name
    /// would otherwise take turns renaming each other's screen forever, and the
    /// key is what routing already uses.
    fn rename_peer(&self, peer: PeerId, name: &str) {
        let Some(key) = self.key_of(peer) else {
            return;
        };

        let mut config = match Config::load(&self.path) {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, "cannot read the desk to record a name");
                return;
            }
        };

        let Some(from) = config
            .screen_for_key(&key)
            .map(|screen| screen.name.clone())
        else {
            return;
        };

        // Nothing to do, which is also what stops two machines writing at each
        // other on every reconnect.
        if from == name {
            return;
        }

        if config.screen_of(name).is_some() {
            tracing::warn!(
                %from,
                %name,
                "a peer renamed itself onto a name this desk already uses, so its                  label is left alone"
            );
            return;
        }

        if let Some(screen) = config
            .screen
            .iter_mut()
            .find(|screen| screen.key.as_deref() == Some(key.as_str()))
        {
            name.clone_into(&mut screen.name);
        }
        config.screen.sort_by(|a, b| a.name.cmp(&b.name));

        self.write(&config);
        tracing::info!(%from, %name, "a peer changed what it calls itself");
    }

    /// Writes the desk and reloads from it.
    fn write(&self, config: &Config) {
        if let Err(error) = config.save(&self.path) {
            tracing::error!(%error, "cannot write the desk");
            return;
        }

        if let Ok(mut seen) = self.seen.lock() {
            *seen = modified_at(&self.path);
        }
        self.reload(config);
    }

    /// Rebuilds the layout, hands it to the session, and mirrors it outward.
    fn reload(&self, config: &Config) {
        let peers = self.roster.snapshot();

        match build_layout(config, &peers, &config.local_name(), self.geometry) {
            // `try_send` rather than an await, because this is sync and runs
            // inside async tasks: blocking here would stall a runtime worker.
            //
            // A full bus is the one case that needs saying, and forgetting the
            // mtime is what makes it recoverable: the file watch compares
            // against what it last saw, so a discarded send leaves the desk on
            // disk and the layout in memory disagreeing until something else
            // happens to touch the file, which on a settled desk is never.
            Ok((layout, _)) => {
                if self
                    .events
                    .try_send(Input::LayoutChanged { layout })
                    .is_err()
                {
                    tracing::warn!("the session is saturated, so the desk will be re-read shortly");
                    if let Ok(mut seen) = self.seen.lock() {
                        *seen = None;
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "the desk changed into something unusable"),
        }

        self.mirror(config, &peers);
    }

    /// Tells every neighbour where this machine has put it.
    ///
    /// Sent on every reload rather than only on an edit, which also settles a
    /// peer that was offline when the drag happened: it hears the placement the
    /// next time either side reloads.
    ///
    /// This does not ping-pong. A peer already sitting where the frame says it
    /// is writes nothing, and only a write triggers a reload, so the exchange
    /// stops after one round trip. See `place_peer`.
    fn mirror(&self, config: &Config, peers: &Peers) {
        let local = config.local_name();
        let grid = config.grid();

        for (side, name) in grid.neighbours(&local) {
            let Some(peer) = peers.peer.iter().find(|peer| {
                config
                    .screen_for_key(&peer.key)
                    .is_some_and(|screen| screen.name == name)
                    || peer.name == name
            }) else {
                continue;
            };

            if let Some(id) = peer.peer_id() {
                tracing::debug!(name = %peer.name, ?side, "telling a machine where it sits");
                self.outgoing.send(id, &Control::Place { side });
            } else {
                tracing::warn!(name = %peer.name, "a paired machine has an unreadable key");
            }
        }
    }

    /// Reloads if the file changed underneath us.
    ///
    /// Polled rather than watched, because a desk changes a few times a day and
    /// an inotify dependency for that is not a trade worth making.
    fn reload_if_changed(&self) {
        let now = modified_at(&self.path);

        let changed = match self.seen.lock() {
            Ok(mut seen) if *seen != now => {
                *seen = now;
                true
            }
            _ => false,
        };

        if !changed {
            return;
        }

        match Config::load(&self.path) {
            Ok(config) => {
                tracing::info!("the desk changed on disk, reloading");
                self.reload(&config);
            }
            Err(error) => tracing::warn!(%error, "the desk changed into something unreadable"),
        }
    }

    fn name_of(&self, peer: PeerId) -> Option<String> {
        let key = crate::config::encode_hex(&peer.0);
        let peers = self.roster.snapshot();

        peers
            .peer
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.name.clone())
    }

    fn key_of(&self, peer: PeerId) -> Option<String> {
        let key = crate::config::encode_hex(&peer.0);
        let peers = self.roster.snapshot();

        peers
            .peer
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.key.clone())
    }
}

/// When a file was last written, or `None` if it is not there.
fn modified_at(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok())
}

/// Addresses learned from the network, by short identity.
///
/// A discovered address beats a configured one, because a configured address is
/// whatever was true when someone last edited the file and a discovered one is
/// true now. That is the whole reason discovery exists: a DHCP lease changing
/// should not need a config edit.
#[derive(Clone, Default)]
struct Discovered {
    addresses: Arc<Mutex<BTreeMap<String, SocketAddr>>>,
}

impl Discovered {
    /// Records an address, keeping the best one seen for a machine.
    ///
    /// A machine announces several addresses and each resolution carries a
    /// subset, so overwriting unconditionally means whichever arrived last
    /// wins. In practice that is usually a link-local IPv6, which cannot be
    /// dialled without a scope identifier, so the peer is found and then never
    /// reached.
    fn learn(&self, short_key: String, address: SocketAddr) {
        let Ok(mut addresses) = self.addresses.lock() else {
            return;
        };

        match addresses.get(&short_key) {
            Some(existing)
                if discovery::reachability(existing.ip())
                    >= discovery::reachability(address.ip()) => {}
            _ => {
                addresses.insert(short_key, address);
            }
        }
    }

    fn address_of(&self, peer: PeerId) -> Option<SocketAddr> {
        self.addresses
            .lock()
            .ok()?
            .get(&discovery::short_key(peer))
            .copied()
    }

    /// Everything learned so far, by short identity.
    fn seen(&self) -> Vec<(String, SocketAddr)> {
        self.addresses.lock().map_or_else(
            |_| Vec::new(),
            |addresses| {
                addresses
                    .iter()
                    .map(|(key, address)| (key.clone(), *address))
                    .collect()
            },
        )
    }
}

/// Announces this machine and watches for others.
///
/// Returns the handle, which withdraws the announcement when dropped. A failure
/// is logged rather than fatal: discovery is a convenience, and a machine with a
/// configured address works without it.
fn start_discovery(
    identity: &Identity,
    name: &str,
    port: u16,
    found: &Discovered,
) -> Option<Discovery> {
    let discovery = match Discovery::advertise(identity.peer_id(), name, port) {
        Ok(discovery) => discovery,
        Err(error) => {
            tracing::warn!(%error, "no LAN discovery, so peers need a configured address");
            return None;
        }
    };

    let found = found.clone();
    let ours = discovery::short_key(identity.peer_id());

    if let Err(error) = discovery.browse(move |peer| {
        if peer.short_key == ours {
            return;
        }
        tracing::info!(name = %peer.name, address = %peer.address, "found a machine on the LAN");
        found.learn(peer.short_key, peer.address);
    }) {
        tracing::warn!(%error, "cannot watch for machines on the LAN");
    }

    Some(discovery)
}

/// A peer's connection and the queue feeding its control stream.
struct Link {
    connection: Connection,
    /// Control messages waiting to go out, in the order they were issued.
    ///
    /// A queue rather than a lock around the stream, and the ordering is the
    /// whole reason. Key transitions ride this stream precisely so a press and
    /// its release cannot be reordered, and a task per message would hand that
    /// ordering to the scheduler: two tasks racing for the same lock acquire it
    /// in whatever order they happen to be polled, so a release can overtake its
    /// press and leave the key held on a machine nobody is touching.
    ///
    /// One writer draining this in receive order makes that unrepresentable
    /// rather than unlikely. It also keeps the framing intact, since only the
    /// writer ever touches the stream.
    ///
    /// Unbounded because a control message must not be dropped. Transitions are
    /// human-rate and motion goes by datagram, so there is nothing here to flood
    /// it, and a peer that has genuinely stopped reading is torn down by the
    /// connection's own idle timeout, which drops the sender and ends the writer.
    control: mpsc::UnboundedSender<Vec<u8>>,
}

impl Link {
    /// Takes ownership of the stream and starts the writer behind it.
    fn new(connection: Connection, mut send: quinn::SendStream) -> Self {
        let (control, mut queued) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            while let Some(bytes) = queued.recv().await {
                // Logged rather than dropped. A control write that fails
                // silently is how a placement goes missing with nothing to show
                // for it.
                if let Err(error) = send.write_all(&bytes).await {
                    tracing::warn!(%error, "cannot write to a peer");
                    return;
                }
            }
        });

        Self {
            connection,
            control,
        }
    }
}

/// Everything this machine can currently write to.
#[derive(Clone, Default)]
pub struct Outgoing {
    peers: Arc<Mutex<BTreeMap<PeerId, Arc<Link>>>>,
}

impl std::fmt::Debug for Outgoing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outgoing").finish_non_exhaustive()
    }
}

impl Outgoing {
    /// Registers a link, unless this peer already has a live one.
    ///
    /// Returns whether it was taken. A second connection to a peer we can
    /// already reach is refused rather than allowed to displace the first,
    /// because displacing it makes the reader on the old link report a lost
    /// peer and the session release input on a link that is actually alive.
    ///
    /// Enforced here rather than left to `should_dial` alone, which cannot
    /// guarantee it: a machine only one side can route to has to dial whatever
    /// the tie-break says, so both sides dialling is reachable by design.
    fn insert(&self, peer: PeerId, link: Arc<Link>) -> bool {
        let Ok(mut peers) = self.peers.lock() else {
            return false;
        };

        if let Some(existing) = peers.get(&peer)
            && existing.connection.close_reason().is_none()
        {
            return false;
        }

        peers.insert(peer, link);
        true
    }

    fn remove(&self, peer: PeerId) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.remove(&peer);
        }
    }

    fn get(&self, peer: PeerId) -> Option<Arc<Link>> {
        self.peers.lock().ok()?.get(&peer).cloned()
    }

    #[must_use]
    pub fn is_connected(&self, peer: PeerId) -> bool {
        self.peers
            .lock()
            .is_ok_and(|peers| peers.contains_key(&peer))
    }

    /// Queues a control message behind everything already issued for this peer.
    ///
    /// Fire and forget: a write failing means the connection is going away, and
    /// the reader task reports that as a lost peer, which is what actually
    /// triggers the release. Reporting it twice adds nothing.
    fn send(&self, peer: PeerId, message: &Control) {
        let Some(link) = self.get(peer) else {
            return;
        };

        let bytes = match wire::encode(message) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "cannot encode a control message");
                return;
            }
        };

        if link.control.send(bytes).is_err() {
            tracing::debug!(%peer, "dropping a control message, the writer has stopped");
        }
    }

    /// Sends motion, dropping it if the link is congested.
    ///
    /// Dropping is correct. A motion sample that could not go out immediately is
    /// already stale, and queueing it trades latency for pixels nobody wanted.
    fn send_datagram(&self, peer: PeerId, frame: &crate::domain::InputFrame) {
        let Some(link) = self.get(peer) else {
            return;
        };

        match wire::encode_frame(frame) {
            Ok(bytes) => {
                if link.connection.send_datagram(bytes.into()).is_err() {
                    tracing::trace!("dropped a motion datagram, the link is congested");
                }
            }
            Err(error) => tracing::warn!(%error, "cannot encode motion"),
        }
    }

    /// Tells every peer this machine is going, so they release at once.
    fn say_goodbye(&self) {
        let Ok(peers) = self.peers.lock() else {
            return;
        };

        for link in peers.values() {
            link.connection.close(0_u8.into(), b"shutdown");
        }
    }
}

/// This machine's screen size.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub width_px: u32,
    pub height_px: u32,
}

impl Geometry {
    fn centre(self) -> Point {
        Point::new(
            i32::try_from(self.width_px / 2).unwrap_or(0),
            i32::try_from(self.height_px / 2).unwrap_or(0),
        )
    }
}

/// What this machine claims to be when nothing can measure it.
const GEOMETRY_FALLBACK: Geometry = Geometry {
    width_px: 1920,
    height_px: 1080,
};

fn local_screen(id: ScreenId, name: &str, geometry: Geometry) -> Screen {
    Screen::new(
        id,
        PeerId([0; 32]),
        name,
        (geometry.width_px, geometry.height_px),
    )
}

/// Builds the layout from the config, resolving names to paired identities.
fn build_layout(
    config: &Config,
    peers: &Peers,
    local_name: &str,
    geometry: Geometry,
) -> Result<(Layout, ScreenId)> {
    let grid = config.grid();
    let mut layout = Layout::new();
    let mut home = None;

    // Ids by sorted name rather than by position in the file. The window
    // rewrites that file on every drag, and a positional id would renumber
    // every screen whenever one moved.
    let mut names: Vec<&str> = grid.iter().map(|(name, _)| name).collect();
    names.sort_unstable();

    let ids: BTreeMap<&str, ScreenId> = names
        .iter()
        .enumerate()
        .map(|(index, name)| (*name, ScreenId(u32::try_from(index).unwrap_or(0))))
        .collect();

    for name in &names {
        let id = ids[name];
        let local = *name == local_name;
        if local {
            home = Some(id);
        }

        let peer = if local {
            PeerId([0; 32])
        } else {
            resolve_peer(config, peers, name)?
        };

        // A remote screen's real size arrives in its hello, within a handshake
        // of connecting. Until then the local size stands in, since most desks
        // are built from similar displays and a wrong guess only affects where
        // the cursor lands for the first fraction of a second.
        layout
            .add_screen(Screen::new(
                id,
                peer,
                *name,
                (geometry.width_px, geometry.height_px),
            ))
            .map_err(|error| Error::Config(error.to_string()))?;
    }

    // Adjacency yields each pair once from each side and `Layout::link` installs
    // the reciprocal, so linking only in one direction is both necessary and
    // sufficient. The old form declared each link twice and had to discard the
    // second attempt.
    for name in &names {
        for (edge, neighbour) in grid.neighbours(name) {
            if name < &neighbour {
                layout
                    .link(ids[name], edge, ids[neighbour])
                    .map_err(|error| Error::Config(error.to_string()))?;
            }
        }
    }

    let home =
        home.ok_or_else(|| Error::Config(format!("no screen on the desk is called {local_name}")))?;

    Ok((layout, home))
}

/// The identity behind a screen name.
///
/// By key first, so a machine renamed on its own side is still found here. The
/// name is the fallback, for a desk written before the key was known.
fn resolve_peer(config: &Config, peers: &Peers, name: &str) -> Result<PeerId> {
    let by_key = config
        .screen
        .iter()
        .find(|screen| screen.name == name)
        .and_then(|screen| screen.key.as_deref())
        .and_then(|key| peers.peer.iter().find(|peer| peer.key == key))
        .and_then(crate::config::Peer::peer_id);

    by_key
        .or_else(|| peers.find(name).and_then(crate::config::Peer::peer_id))
        .ok_or_else(|| {
            Error::Config(format!(
                "the desk has {name} on it, which is not paired with this machine. Run \
                 `wraith pair` for it, or `wraith peers` to see what is paired"
            ))
        })
}

fn local_geometry() -> Geometry {
    // Through the platform port, so the `#[cfg]` deciding which backend answers
    // stays in the one module allowed to have one.
    if let Some(screen) = platform::local_screen() {
        return Geometry {
            width_px: screen.width_px,
            height_px: screen.height_px,
        };
    }

    // Said out loud, because this size goes out in `Hello` as a claim about this
    // machine, and every peer measures its edge fractions against it. A wrong
    // one is not a degraded crossing, it is a crossing that lands somewhere else.
    tracing::warn!(
        width_px = GEOMETRY_FALLBACK.width_px,
        height_px = GEOMETRY_FALLBACK.height_px,
        "no backend could report the screen size, so peers are told a default"
    );
    GEOMETRY_FALLBACK
}

/// Carries the real pointer position from the injector thread to the session.
///
/// A thread rather than a task, because the sender is a blocking std channel
/// and the injector is not async. It costs one thread and a few messages a
/// second, and it is what keeps the cursor's idea of where it is from drifting
/// away from the pointer the user is watching.
fn spawn_pointer_watch(events: mpsc::Sender<Input>, pointers: std::sync::mpsc::Receiver<Point>) {
    std::thread::Builder::new()
        .name("wraith-pointer".to_owned())
        .spawn(move || {
            while let Ok(at) = pointers.recv() {
                if events.blocking_send(Input::LocalPointerAt { at }).is_err() {
                    return;
                }
            }
        })
        .ok();
}

/// Watches both files, so a drag or a pairing reaches a running session.
///
/// A poll rather than an inotify watch: these change a few times a day, and a
/// filesystem-notification dependency for that is not a trade worth making.
///
/// Watching the trust store as well as the desk means a machine paired by any
/// route arrives within half a second, whether that was the window, `wraith
/// pair` in another terminal, or an editor. One mechanism, and no route to
/// pairing has to know this exists.
fn spawn_file_watch(desk: Desk, roster: Roster) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(DESK_POLL_MS));

        loop {
            ticker.tick().await;

            // Trust first. A desk naming a machine this session does not trust
            // yet would build a layout with a screen nothing can connect to.
            roster.reload_if_changed();
            desk.reload_if_changed();
        }
    });
}

fn spawn_ticker(events: mpsc::Sender<Input>, clock: Clock) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));

        loop {
            ticker.tick().await;
            if events
                .send(Input::Tick {
                    now_ms: clock.now(),
                })
                .await
                .is_err()
            {
                return;
            }
        }
    });
}

/// Accepts incoming peers. The dialling side opens the control stream.
fn spawn_accepts(server: Endpoint, feed: Feed) {
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let feed = feed.clone();

            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::debug!(%error, "an inbound connection failed");
                        return;
                    }
                };

                let Some(peer) = peer_of(&connection) else {
                    tracing::warn!("an accepted peer presented no identifiable key");
                    return;
                };

                match connection.accept_bi().await {
                    Ok((send, recv)) => {
                        serve_peer(peer, connection, send, recv, feed).await;
                    }
                    Err(error) => tracing::debug!(%error, "the peer opened no control stream"),
                }
            });
        }
    });
}

/// Dials every paired peer that has an address, retrying forever.
/// What a dial task needs, bundled because it is the same handful of things for
/// every peer and because a reload has to be able to start one more of them
/// later.
#[derive(Clone)]
struct Dialer {
    client: Endpoint,
    ours: PeerId,
    feed: Feed,
    found: Discovered,
    /// Peers that already have a retry task.
    ///
    /// Without it a reload would spawn a second task per peer on every poll,
    /// and by the tenth reload a peer would be dialled ten times a second.
    dialling: Arc<Mutex<BTreeSet<PeerId>>>,
}

impl std::fmt::Debug for Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialer").finish_non_exhaustive()
    }
}

impl Dialer {
    fn new(
        identity: &Identity,
        trusted: TrustedPeers,
        feed: Feed,
        found: Discovered,
    ) -> Result<Self> {
        // Built once. The trust set inside is a live handle, so a machine
        // paired later is accepted without rebuilding this.
        let client = endpoint::client(identity, trusted)
            .map_err(|error| Error::Config(error.to_string()))?;

        Ok(Self {
            client,
            ours: identity.peer_id(),
            feed,
            found,
            dialling: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    /// Starts a retry task for every peer that has not got one.
    ///
    /// Idempotent, which is what lets the file watch and a pairing both call it
    /// without coordinating.
    fn ensure(&self, peers: &Peers) {
        for peer in &peers.peer {
            let Some(peer_id) = peer.peer_id() else {
                continue;
            };

            if !should_dial(self.ours, peer_id, peer.address.is_some()) {
                tracing::debug!(name = %peer.name, "waiting to be dialled by this peer");
                continue;
            }

            let fresh = self
                .dialling
                .lock()
                .is_ok_and(|mut dialling| dialling.insert(peer_id));

            if !fresh {
                continue;
            }

            self.start(peer_id, peer.name.clone(), peer.address.clone());
        }
    }

    fn start(&self, peer_id: PeerId, name: String, configured: Option<String>) {
        let (client, found, feed) = (self.client.clone(), self.found.clone(), self.feed.clone());

        tokio::spawn(async move {
            let mut said_nowhere = false;

            loop {
                if !feed.outgoing.is_connected(peer_id) {
                    match reachable_at(peer_id, &found, configured.as_deref()) {
                        Some(address) => {
                            said_nowhere = false;
                            dial_once(&client, peer_id, address, &name, feed.clone()).await;
                        }
                        // Said once rather than every two seconds, and said at
                        // all because the silence here was indistinguishable
                        // from a machine that was being dialled and refusing.
                        None if !said_nowhere => {
                            said_nowhere = true;
                            tracing::warn!(
                                %name,
                                "nowhere to reach this machine: nothing discovered on the \
                                 network and no address recorded when it was paired. \
                                 Pair again, or put its address in peers.toml"
                            );
                        }
                        None => {}
                    }
                }
                tokio::time::sleep(Duration::from_millis(RECONNECT_MS)).await;
            }
        });
    }
}

/// Whether this machine dials, or waits to be dialled.
///
/// A machine that recorded an address during pairing dials, whatever the
/// tie-break says. That machine is the one that joined, which means it is the
/// one with a route: the other side records no address at all and may have no
/// way to reach back. A laptop behind NAT pairing with a host on the open
/// internet is the ordinary case, not the exotic one, and a rule that told the
/// laptop to wait left the pair connectionless with the cursor stopping dead at
/// the screen edge.
///
/// Without an address it falls back to comparing keys, which is arbitrary but
/// stable and computable by both sides without exchanging anything. That is the
/// discovery case, where the address arrives from the LAN symmetrically.
///
/// Both sides dialling is survivable either way: `Outgoing::insert` refuses the
/// second connection rather than letting it displace the first.
const fn should_dial(ours: PeerId, theirs: PeerId, have_address: bool) -> bool {
    if have_address {
        return true;
    }

    key_order_dials(ours, theirs)
}

/// The tie-break, for when neither side has an address to prefer.
const fn key_order_dials(ours: PeerId, theirs: PeerId) -> bool {
    let mut index = 0;
    while index < 32 {
        if ours.0[index] != theirs.0[index] {
            return ours.0[index] < theirs.0[index];
        }
        index += 1;
    }
    // Identical keys means a machine paired with itself, which is a
    // configuration mistake rather than something to dial.
    false
}

/// Where to dial a peer, preferring what the network says over what the file does.
fn reachable_at(peer: PeerId, found: &Discovered, configured: Option<&str>) -> Option<SocketAddr> {
    found
        .address_of(peer)
        .or_else(|| configured.and_then(|address| address.parse().ok()))
}

async fn dial_once(
    client: &Endpoint,
    peer_id: PeerId,
    resolved: SocketAddr,
    name: &str,
    feed: Feed,
) {
    let connection = match client.connect(resolved, "wraith") {
        Ok(connecting) => match connecting.await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::debug!(%name, %error, "cannot reach the peer");
                return;
            }
        },
        Err(error) => {
            tracing::warn!(%name, %error, "cannot start a connection");
            return;
        }
    };

    match connection.open_bi().await {
        Ok((send, recv)) => {
            serve_peer(peer_id, connection, send, recv, feed).await;
        }
        Err(error) => tracing::debug!(%name, %error, "cannot open a control stream"),
    }
}

/// Runs one peer until its connection ends.
async fn serve_peer(
    peer: PeerId,
    connection: Connection,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    feed: Feed,
) {
    let Feed {
        events,
        outgoing,
        hello,
        clipboard,
        clip_cache,
    } = feed;

    // The hello goes out before the link is registered, so nothing can be sent
    // ahead of it and be misread as a hello.
    if let Ok(bytes) = wire::encode(&hello)
        && send.write_all(&bytes).await.is_err()
    {
        return;
    }

    let taken = outgoing.insert(peer, Arc::new(Link::new(connection.clone(), send)));

    // Already reachable by another connection, so this one is redundant. Closed
    // rather than served, and without telling the session anything: the peer is
    // not lost, it is doubly found.
    if !taken {
        tracing::debug!(%peer, "refusing a second connection to a peer already linked");
        connection.close(0_u8.into(), b"already linked");
        return;
    }

    let reader = read_control(
        peer,
        recv,
        events.clone(),
        clipboard,
        outgoing.clone(),
        clip_cache.clone(),
    );
    let datagrams = read_datagrams(peer, connection.clone(), events.clone());

    tokio::select! {
        () = reader => {}
        () = datagrams => {}
        _ = connection.closed() => {}
    }

    // Whatever ended it, the session must hear about it. This is what turns a
    // dropped connection into a released key rather than a stuck one.
    outgoing.remove(peer);
    // What this peer had already been given dies with the link. Keeping it would
    // grow the map by one entry per machine ever linked, and would withhold the
    // clipboard from that same machine when it comes back on a fresh connection
    // that may have missed the frame.
    clip_cache.forget(peer);
    let _ = events.send(Input::PeerLost { peer }).await;

    tracing::debug!(%peer, "the peer link ended");
}

/// Reads length-prefixed control frames until the stream ends.
async fn read_control(
    peer: PeerId,
    mut recv: quinn::RecvStream,
    events: mpsc::Sender<Input>,
    clipboard: Option<clipboard::Clipboard>,
    outgoing: Outgoing,
    clip_cache: Cache,
) {
    // Whether the cursor is on this machine, taken from this peer. The peer's
    // `Enter` brings it here; its `Leave` takes it back, which is the moment we
    // hand our clipboard over. The guard is why: the arrival broadcast sends
    // `Leave` to every peer, but only the one the cursor actually came from
    // should answer, so an idle peer never overwrites the reclaiming machine.
    let mut had_cursor = false;

    loop {
        let mut header = [0_u8; 4];
        if recv.read_exact(&mut header).await.is_err() {
            return;
        }

        let length = match wire::frame_length(header) {
            Ok(length) => length,
            Err(error) => {
                // An oversized frame is refused by inspection rather than by
                // trying to allocate it. This runs against a peer that is
                // authenticated but whose content is still untrusted.
                tracing::warn!(%peer, %error, "refusing an oversized frame");
                return;
            }
        };

        let mut payload = vec![0_u8; length];
        if recv.read_exact(&mut payload).await.is_err() {
            return;
        }

        let Ok(message) = wire::decode(&payload) else {
            tracing::warn!(%peer, "the peer sent an unreadable control frame");
            return;
        };

        // The clipboard is not domain state, so it is set on the backend here
        // rather than turned into an `Input`. Handled before `to_input`, which
        // is why that function's `Clipboard` arm is never reached.
        if let Control::Clipboard { mime, bytes } = message {
            receive_clipboard(peer, mime, bytes, clipboard.as_ref(), &clip_cache);
            continue;
        }

        // A crossing carries the clipboard both ways. The outbound half rides
        // `SendEnter` (see `apply`); this is the inbound half. When the peer
        // reclaims the cursor it took from us, we are the side losing it, so we
        // hand our clipboard back. Then `Leave` falls through to the domain as
        // usual. The peer that never took the cursor never set `had_cursor`, so
        // the arrival broadcast's `Leave` to it answers with nothing.
        match &message {
            Control::Enter { .. } => had_cursor = true,
            Control::Leave => {
                if let Some(clip) = clipboard_for_reclaim(had_cursor, &clip_cache, peer) {
                    tracing::debug!(%peer, "handing the clipboard to the peer taking the cursor");
                    outgoing.send(peer, &clip);
                }
                had_cursor = false;
            }
            _ => {}
        }

        if let Some(input) = to_input(peer, message)
            && events.send(input).await.is_err()
        {
            return;
        }
    }
}

/// Offers a peer's clipboard locally, if this version handles its type.
///
/// Text only here. A peer offering any other type is refused rather than written
/// blind to the local clipboard, which keeps an untrusted mime from reaching the
/// pasting application. A machine with no clipboard backend simply drops it.
fn receive_clipboard(
    peer: PeerId,
    mime: String,
    bytes: Vec<u8>,
    clipboard: Option<&clipboard::Clipboard>,
    cache: &Cache,
) {
    let Some(contents) = clipboard_to_set(mime, bytes) else {
        tracing::debug!(%peer, "ignoring a clipboard type this version does not handle");
        return;
    };

    // Recorded before it is offered locally, and recorded even where there is no
    // backend to offer it on. Before, because the backend echoes an offer back as
    // a local change and the cache has to already know those bytes to recognise
    // the echo. Even without a backend, because a machine the cursor merely
    // passes through still has to carry the clipboard onward to a third machine,
    // and still has to not hand it back to this peer.
    cache.adopt_from(peer, contents.clone());

    if let Some(clipboard) = clipboard {
        clipboard.set(contents);
    }
}

/// Headroom left under [`wire::FRAME_BYTES_MAX`] for a clipboard's framing: the
/// mime string, the variant tag, and the length varints that ride with the
/// bytes. Comfortably more than any of those need.
const CLIPBOARD_FRAMING_MARGIN: usize = 256;

/// The clipboard to hand a peer the cursor is crossing to, if it has not already
/// been given it.
///
/// Read at the crossing rather than pushed on every copy: the machine losing the
/// cursor hands its clipboard to the machine gaining it. `None` when nothing has
/// been copied yet, when this peer already has the current copy, or when the copy
/// is too large to cross.
fn clipboard_to_send(cache: &Cache, peer: PeerId) -> Option<Control> {
    let (generation, contents) = cache.pending_for(peer)?;

    // Dropped here, with a clear line, rather than silently at encode time. A
    // copy larger than a frame cannot cross until the transport learns to chunk;
    // until then it stays put, the peer is deliberately left unsettled so the
    // same copy is offered again once chunking lands, and the frame it would have
    // overflowed carries the crossing's other messages intact.
    if contents.bytes.len() > wire::FRAME_BYTES_MAX.saturating_sub(CLIPBOARD_FRAMING_MARGIN) {
        tracing::debug!(
            bytes = contents.bytes.len(),
            "the clipboard is too large to follow the cursor yet, leaving it"
        );
        return None;
    }

    // Settled as the frame is built, because `Outgoing::send` is fire and forget
    // and has no success to wait for. A link that dies loses the frame, but dying
    // also ends the reader, which forgets the peer, so the copy is offered again
    // on the next link.
    cache.settle(peer, generation);

    Some(Control::Clipboard {
        mime: contents.mime,
        bytes: contents.bytes,
    })
}

/// The clipboard to hand a peer reclaiming the cursor, if we held it for them.
///
/// The first guard is `had_cursor`: the arrival broadcast sends `Leave` to every
/// peer, but only the one that actually took the cursor should be answered.
/// Without it, idle peers would each overwrite the reclaiming machine's
/// clipboard. The second is the generation, which is what keeps the peer from
/// being handed a copy it already has, including the one it just gave us.
fn clipboard_for_reclaim(had_cursor: bool, cache: &Cache, peer: PeerId) -> Option<Control> {
    had_cursor.then(|| clipboard_to_send(cache, peer)).flatten()
}

/// An inbound clipboard frame as contents to offer, or nothing if unhandled.
///
/// This version handles text only, so a foreign mime yields `None` and is
/// dropped by the caller.
fn clipboard_to_set(mime: String, bytes: Vec<u8>) -> Option<ClipboardContents> {
    let contents = ClipboardContents { mime, bytes };
    contents.is_text().then_some(contents)
}

/// Reads motion datagrams until the connection ends.
async fn read_datagrams(peer: PeerId, connection: Connection, events: mpsc::Sender<Input>) {
    while let Ok(bytes) = connection.read_datagram().await {
        let Ok(frame) = wire::decode_frame(&bytes) else {
            // A corrupt datagram is dropped rather than fatal. Motion is
            // disposable by design, and killing the link over one bad packet
            // would turn a lost pixel into a lost session.
            tracing::trace!(%peer, "dropping an unreadable motion datagram");
            continue;
        };

        if events.send(Input::PeerFrame { peer, frame }).await.is_err() {
            return;
        }
    }
}

/// A control message as a session input.
fn to_input(peer: PeerId, message: Control) -> Option<Input> {
    match message {
        Control::Hello {
            protocol,
            name,
            mut screen,
        } => {
            if protocol != PROTOCOL_VERSION {
                tracing::warn!(
                    %peer,
                    theirs = protocol,
                    ours = PROTOCOL_VERSION,
                    "refusing a peer speaking a different protocol"
                );
                return None;
            }

            // The peer describes its own screen but cannot know its identity as
            // this machine records it, so that is filled in here.
            screen.peer = peer;
            tracing::info!(%name, width = screen.width_px, height = screen.height_px, "peer ready");

            Some(Input::PeerConnected { peer, screen })
        }
        Control::Transitions { events } => Some(Input::PeerTransitions { peer, events }),
        Control::Snapshot { held } => Some(Input::PeerSnapshot { peer, held }),
        Control::Enter { crossing } => Some(Input::PeerEnter { peer, crossing }),
        Control::Leave => Some(Input::PeerLeave { peer }),
        Control::Place { side } => Some(Input::PeerPlaced { peer, side }),
        Control::Bye { reason } => {
            tracing::info!(%peer, %reason, "the peer said goodbye");
            Some(Input::PeerLost { peer })
        }
        // The clipboard is not domain state, so it does not become an `Input`.
        // The receive loop handles it before this and never reaches here; the
        // arm exists so the match stays exhaustive over `Control`.
        Control::Clipboard { .. } => None,
    }
}

/// The identity behind a connection, from the certificate it presented.
fn peer_of(connection: &Connection) -> Option<PeerId> {
    let identity = connection.peer_identity()?;
    let certificates = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;

    subject_public_key(certificates.first()?).map(PeerId)
}

/// Returns when the session should stop, whoever asked.
///
/// Three ways in, because there are three kinds of caller: a person pressing
/// ctrl-c in a terminal, the window sending `Stop` over the control socket, and
/// a service manager sending `SIGTERM`. A session started by a service manager
/// has no terminal at all, so the interrupt alone was never going to be enough.
async fn shutdown_signal(stop: &mut tokio::sync::watch::Receiver<bool>) {
    if *stop.borrow_and_update() {
        return;
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = stop.changed() => {}
        () = terminated() => {}
    }
}

/// Resolves on `SIGTERM`.
///
/// Layer 7, and it is worth being precise about what it buys. `SIGTERM`'s
/// default action ends the process without unwinding, so `InjectSession::drop`
/// never runs: catching it here is what keeps layer 6 as well, and without both
/// a service manager stopping this machine leaves every key it was holding on
/// the far one until that machine's watchdog fires nine hundred milliseconds
/// later. Catching it turns an abrupt kill back into an ordinary shutdown.
///
/// Never resolves if the handler cannot be installed, so the other two arms of
/// the select still decide. A session that cannot listen for one signal is
/// better than a session that will not start.
async fn terminated() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            terminate.recv().await;
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "cannot listen for SIGTERM, so a service manager stopping this \
                 session will not release held keys cleanly"
            );
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Peer, ScreenConfig};

    const GEOMETRY: Geometry = Geometry {
        width_px: 1920,
        height_px: 1080,
    };

    /// Every control message reaches the wire in the order it was issued.
    ///
    /// The property the reliable stream exists for. A release overtaking its
    /// press leaves the key held on a machine nobody is touching, which is the
    /// failure this whole project is a response to.
    ///
    /// What this does and does not prove: it exercises the real queue against a
    /// real QUIC stream and would fail outright if anything reintroduced a task
    /// per message under load. It is not a reproduction of the ordering race
    /// itself, which needed two runtime workers to reach the same lock in the
    /// wrong order and so could not be made to fail on demand. The guarantee is
    /// now structural, and this is what guards it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn control_messages_arrive_in_the_order_they_were_issued() {
        use crate::domain::{InputEvent, KeyState, Scancode};
        use crate::net::verify::TrustedPeers;

        /// Enough that a scheduler reordering anything would show up.
        const MESSAGES: u16 = 1_000;

        let listener = Identity::generate();
        let dialer = Identity::generate();
        let trusted = TrustedPeers::of([listener.peer_id(), dialer.peer_id()]);

        let server =
            endpoint::server(&listener, trusted.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();

        let reading = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) = connection.accept_bi().await.unwrap();

            let mut seen = Vec::with_capacity(MESSAGES as usize);
            for _ in 0..MESSAGES {
                let mut header = [0_u8; 4];
                recv.read_exact(&mut header).await.unwrap();
                let length = wire::frame_length(header).unwrap();

                let mut payload = vec![0_u8; length];
                recv.read_exact(&mut payload).await.unwrap();
                seen.push(wire::decode::<Control>(&payload).unwrap());
            }
            seen
        });

        let client = endpoint::client(&dialer, trusted).unwrap();
        let connection = client.connect(address, "wraith").unwrap().await.unwrap();
        let (send, _recv) = connection.open_bi().await.unwrap();

        let peer = listener.peer_id();
        let outgoing = Outgoing::default();
        outgoing.insert(peer, Arc::new(Link::new(connection.clone(), send)));

        // The scancode carries the index, so any permutation is visible rather
        // than only a swap of two adjacent alike messages.
        let issued: Vec<Control> = (0..MESSAGES)
            .map(|index| Control::Transitions {
                events: vec![InputEvent::Key {
                    code: Scancode(index),
                    state: if index % 2 == 0 {
                        KeyState::Pressed
                    } else {
                        KeyState::Released
                    },
                }],
            })
            .collect();

        for message in &issued {
            outgoing.send(peer, message);
        }

        let seen = reading.await.unwrap();
        assert_eq!(seen, issued, "every message, in the order it was issued");
    }

    fn paired(name: &str, byte: u8) -> Peer {
        Peer {
            name: name.to_owned(),
            key: crate::config::encode_hex(&[byte; 32]),
            address: None,
        }
    }

    /// A desktop with a laptop to its right.
    fn two_screen_config(local: &str) -> Config {
        Config {
            name: Some(local.to_owned()),
            listen: None,
            screen: vec![
                ScreenConfig::new("desktop", crate::domain::Cell::ORIGIN),
                ScreenConfig::new("laptop", crate::domain::Cell::new(1, 0)),
            ],
            ..Config::default()
        }
    }

    #[test]
    fn screen_ids_do_not_depend_on_the_order_of_the_file() {
        // The window rewrites the file on every drag. Positional ids would
        // renumber every screen whenever one moved.
        let peers = Peers {
            peer: vec![paired("laptop", 7)],
        };

        let forwards = two_screen_config("desktop");
        let mut backwards = forwards.clone();
        backwards.screen.reverse();

        let (a, home_a) = build_layout(&forwards, &peers, "desktop", GEOMETRY).unwrap();
        let (b, home_b) = build_layout(&backwards, &peers, "desktop", GEOMETRY).unwrap();

        assert_eq!(home_a, home_b);
        assert_eq!(
            a.screen(home_a).unwrap().name,
            b.screen(home_b).unwrap().name
        );
    }

    #[test]
    fn a_peer_renamed_on_its_own_side_is_still_resolved() {
        // Matching by name alone would silently drop it off the desk.
        let peers = Peers {
            peer: vec![paired("was-called-this", 7)],
        };
        let config = Config {
            name: Some("desktop".to_owned()),
            listen: None,
            screen: vec![
                ScreenConfig::new("desktop", crate::domain::Cell::ORIGIN),
                ScreenConfig::new("laptop", crate::domain::Cell::new(1, 0))
                    .with_key(crate::config::encode_hex(&[7; 32])),
            ],
            ..Config::default()
        };

        assert!(build_layout(&config, &peers, "desktop", GEOMETRY).is_ok());
    }

    #[test]
    fn a_two_screen_desk_builds() {
        let peers = Peers {
            peer: vec![paired("laptop", 7)],
        };

        let (layout, home) =
            build_layout(&two_screen_config("desktop"), &peers, "desktop", GEOMETRY).unwrap();

        assert_eq!(layout.screens().count(), 2);
        assert_eq!(layout.screen(home).unwrap().name, "desktop");
    }

    #[test]
    fn the_links_are_reciprocal() {
        // Adjacency is symmetric, so a one-way link cannot be expressed. The
        // old form declared each link twice and had to discard the second.
        let peers = Peers {
            peer: vec![paired("laptop", 7)],
        };

        let (layout, home) =
            build_layout(&two_screen_config("desktop"), &peers, "desktop", GEOMETRY).unwrap();
        let laptop = layout.neighbour(home, crate::domain::Edge::Right).unwrap();

        assert_eq!(
            layout.neighbour(laptop, crate::domain::Edge::Left),
            Some(home)
        );
    }

    #[test]
    fn a_desk_holding_an_unpaired_machine_says_what_to_do_about_it() {
        // The likeliest first-run mistake, so the error must be actionable
        // rather than merely correct.
        let error = build_layout(
            &two_screen_config("desktop"),
            &Peers::default(),
            "desktop",
            GEOMETRY,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("laptop"),
            "the error does not name the machine: {error}"
        );
        assert!(
            error.contains("wraith pair"),
            "the error does not say what to do: {error}"
        );
    }

    #[test]
    fn the_local_screen_is_the_home_screen() {
        let peers = Peers {
            peer: vec![paired("desktop", 7)],
        };

        let (layout, home) =
            build_layout(&two_screen_config("laptop"), &peers, "laptop", GEOMETRY).unwrap();

        assert_eq!(layout.screen(home).unwrap().name, "laptop");
    }

    #[test]
    fn the_cursor_starts_in_the_middle_of_the_screen() {
        assert_eq!(GEOMETRY.centre(), Point::new(960, 540));
    }

    #[test]
    fn a_hello_carries_the_real_screen_size() {
        // The peer uses this to map crossings, so a wrong size puts the cursor
        // at the wrong height on arrival.
        let screen = local_screen(
            ScreenId(0),
            "desktop",
            Geometry {
                width_px: 2560,
                height_px: 1440,
            },
        );

        assert_eq!(screen.width_px, 2560);
        assert_eq!(screen.height_px, 1440);
    }

    #[test]
    fn a_hello_is_attributed_to_the_authenticated_peer_rather_than_what_it_claims() {
        // The peer describes its screen, but its identity comes from the
        // certificate it authenticated with. Trusting a self-declared identity
        // here would undo the pinning entirely.
        let authenticated = PeerId([9; 32]);
        let claimed = Screen {
            id: ScreenId(0),
            peer: PeerId([1; 32]),
            name: "laptop".to_owned(),
            width_px: 1920,
            height_px: 1080,
        };

        let input = to_input(
            authenticated,
            Control::Hello {
                protocol: PROTOCOL_VERSION,
                name: "laptop".to_owned(),
                screen: claimed,
            },
        );

        match input {
            Some(Input::PeerConnected { screen, .. }) => {
                assert_eq!(screen.peer, authenticated, "a peer renamed itself");
            }
            other => panic!("expected a connection, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_speaking_another_protocol_is_refused() {
        let input = to_input(
            PeerId([1; 32]),
            Control::Hello {
                protocol: PROTOCOL_VERSION + 1,
                name: "future".to_owned(),
                screen: local_screen(ScreenId(0), "future", GEOMETRY),
            },
        );

        assert!(input.is_none(), "a mismatched protocol connected anyway");
    }

    #[test]
    fn every_control_message_maps_to_an_input() {
        let peer = PeerId([1; 32]);

        assert!(to_input(peer, Control::Transitions { events: vec![] }).is_some());
        assert!(
            to_input(
                peer,
                Control::Snapshot {
                    held: crate::domain::HeldSet::new()
                }
            )
            .is_some()
        );
        assert!(to_input(peer, Control::Leave).is_some());
        assert!(
            to_input(
                peer,
                Control::Bye {
                    reason: wire::ByeReason::Shutdown
                }
            )
            .is_some()
        );
    }

    #[test]
    fn a_goodbye_reads_as_a_lost_peer() {
        // So the release happens immediately rather than at the watchdog.
        let peer = PeerId([1; 32]);

        let input = to_input(
            peer,
            Control::Bye {
                reason: wire::ByeReason::Shutdown,
            },
        );

        assert!(matches!(input, Some(Input::PeerLost { peer: lost }) if lost == peer));
    }

    #[test]
    fn a_discovered_address_beats_a_configured_one() {
        // A configured address is whatever was true when the file was last
        // edited. A discovered one is true now, which is the entire point.
        let peer = PeerId([5; 32]);
        let found = Discovered::default();
        found.learn(
            crate::net::discovery::short_key(peer),
            "10.0.0.5:24810".parse().unwrap(),
        );

        let address = reachable_at(peer, &found, Some("192.168.1.9:24810"));

        assert_eq!(address, Some("10.0.0.5:24810".parse().unwrap()));
    }

    #[test]
    fn a_better_discovered_address_replaces_a_worse_one() {
        let peer = PeerId([5; 32]);
        let short = crate::net::discovery::short_key(peer);
        let found = Discovered::default();

        found.learn(short.clone(), "[fe80::1]:24810".parse().unwrap());
        found.learn(short, "192.168.1.9:24810".parse().unwrap());

        assert_eq!(
            found.address_of(peer),
            Some("192.168.1.9:24810".parse().unwrap())
        );
    }

    #[test]
    fn a_worse_discovered_address_does_not_replace_a_better_one() {
        // Each resolution carries a subset of a machine's addresses, so a good
        // one arriving first must not be displaced by a link-local one arriving
        // second.
        let peer = PeerId([5; 32]);
        let short = crate::net::discovery::short_key(peer);
        let found = Discovered::default();

        found.learn(short.clone(), "192.168.1.9:24810".parse().unwrap());
        found.learn(short, "[fe80::1]:24810".parse().unwrap());

        assert_eq!(
            found.address_of(peer),
            Some("192.168.1.9:24810".parse().unwrap())
        );
    }

    #[test]
    fn a_configured_address_is_used_when_nothing_is_discovered() {
        // Discovery is a convenience. A machine on a network without mDNS, or
        // across a subnet, still works from the file.
        let peer = PeerId([5; 32]);

        let address = reachable_at(peer, &Discovered::default(), Some("192.168.1.9:24810"));

        assert_eq!(address, Some("192.168.1.9:24810".parse().unwrap()));
    }

    #[test]
    fn a_peer_with_neither_address_is_not_dialled() {
        // It dials us instead, which is the other half of the tie-break.
        assert_eq!(
            reachable_at(PeerId([5; 32]), &Discovered::default(), None),
            None
        );
    }

    #[test]
    fn an_unparseable_configured_address_is_ignored_rather_than_fatal() {
        // One bad line in the trust store should not stop the other peers
        // connecting.
        let address = reachable_at(
            PeerId([5; 32]),
            &Discovered::default(),
            Some("not-an-address"),
        );

        assert_eq!(address, None);
    }

    #[test]
    fn exactly_one_side_of_a_pair_dials() {
        // Without this both machines dial each other, every pair holds two
        // connections, and they displace each other in a loop that looks like
        // the peer constantly disconnecting.
        let low = PeerId([1; 32]);
        let high = PeerId([2; 32]);

        assert!(key_order_dials(low, high));
        assert!(!key_order_dials(high, low));
    }

    #[test]
    fn the_dial_decision_is_settled_by_the_first_differing_byte() {
        let a = PeerId([
            0, 5, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let b = PeerId([
            0, 5, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
            9, 9, 9,
        ]);

        assert!(
            !key_order_dials(a, b),
            "the third byte decides, and 9 is above 8"
        );
        assert!(key_order_dials(b, a));
    }

    #[test]
    fn a_machine_does_not_dial_itself() {
        let me = PeerId([7; 32]);

        assert!(!key_order_dials(me, me));
    }

    #[test]
    fn the_side_holding_an_address_dials_whatever_the_tie_break_says() {
        // The case that left a real pair connectionless. The Mac joined, so it
        // is the only side with an address, and the key comparison told it to
        // wait for a machine that had no way to reach it.
        let high = PeerId([2; 32]);
        let low = PeerId([1; 32]);

        assert!(
            !key_order_dials(high, low),
            "the tie-break alone would have it wait"
        );
        assert!(
            should_dial(high, low, true),
            "but it is the only side that knows where the other one is"
        );
    }

    #[test]
    fn a_side_with_no_address_still_follows_the_tie_break() {
        // Discovery supplies addresses to both sides symmetrically, so there is
        // nothing to prefer and the arbitrary rule is the right one.
        let high = PeerId([2; 32]);
        let low = PeerId([1; 32]);

        assert!(should_dial(low, high, false));
        assert!(!should_dial(high, low, false));
    }

    #[test]
    fn the_capture_gate_tracks_what_was_last_set() {
        capture_gate::reset();
        assert!(!capture_gate::wanted());

        capture_gate::set(true);
        assert!(capture_gate::wanted());

        capture_gate::reset();
    }

    #[test]
    fn nothing_copied_yet_hands_over_nothing() {
        // The honest empty state: a machine that has copied nothing this session
        // sends no clipboard when the cursor leaves it.
        let cache = Cache::default();
        assert!(clipboard_to_send(&cache, PeerId([1; 32])).is_none());
    }

    #[test]
    fn a_crossing_hands_over_the_cached_clipboard() {
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("copied"));

        match clipboard_to_send(&cache, PeerId([1; 32])) {
            Some(Control::Clipboard { mime, bytes }) => {
                assert_eq!(mime, crate::ports::MIME_TEXT);
                assert_eq!(bytes, b"copied");
            }
            other => panic!("expected a clipboard frame, got {other:?}"),
        }
    }

    #[test]
    fn an_inbound_foreign_type_is_refused() {
        // The receive path writes text only. An image or any other type is
        // dropped rather than written blind to the local clipboard, which is
        // what keeps an untrusted mime away from the pasting application.
        assert!(clipboard_to_set("image/png".to_owned(), vec![0x89]).is_none());
        assert!(clipboard_to_set(crate::ports::MIME_TEXT.to_owned(), b"ok".to_vec()).is_some());
    }

    #[test]
    fn the_peer_reclaiming_the_cursor_is_handed_the_clipboard() {
        // The return direction: the peer took the cursor and now gives it back,
        // so we hand our clipboard over as it leaves.
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("from here"));

        match clipboard_for_reclaim(true, &cache, PeerId([1; 32])) {
            Some(Control::Clipboard { bytes, .. }) => assert_eq!(bytes, b"from here"),
            other => panic!("expected a clipboard frame, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_never_held_the_cursor_is_handed_nothing() {
        // The arrival broadcast sends Leave to every peer. Only the one that took
        // the cursor answers; an idle peer must not overwrite the reclaiming
        // machine's clipboard with its own.
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("stale"));
        assert!(clipboard_for_reclaim(false, &cache, PeerId([1; 32])).is_none());
    }

    #[test]
    fn an_oversized_clipboard_is_left_rather_than_overflowing_the_frame() {
        // A copy too big for a frame cannot cross until chunking lands. It is
        // left in place here so the crossing's other messages still encode,
        // rather than being dropped at send time with a misleading log.
        let peer = PeerId([1; 32]);
        let cache = Cache::default();
        cache.observe_local(ClipboardContents {
            mime: crate::ports::MIME_TEXT.to_owned(),
            bytes: vec![b'x'; wire::FRAME_BYTES_MAX],
        });

        assert!(clipboard_to_send(&cache, peer).is_none());
        assert!(
            cache.pending_for(peer).is_some(),
            "refusing to send must not mark the peer as having it"
        );
    }

    #[test]
    fn an_inbound_text_clipboard_reaches_the_backend() {
        use crate::ports::fake::RecordingClipboard;

        let backend = RecordingClipboard::new();
        let log = backend.log();
        let (changed, _changes) = std::sync::mpsc::channel();
        let handle = clipboard::Clipboard::start(Box::new(backend), changed).unwrap();

        receive_clipboard(
            PeerId([1; 32]),
            crate::ports::MIME_TEXT.to_owned(),
            b"from a peer".to_vec(),
            Some(&handle),
            &Cache::default(),
        );

        for _ in 0..50 {
            if !log.lock().unwrap().offered.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(
            log.lock().unwrap().offered.first().map(|c| c.bytes.clone()),
            Some(b"from a peer".to_vec()),
            "the peer's clipboard never reached the backend"
        );
    }

    /// An inbound text clipboard from `peer`, with no local backend to offer it
    /// on. The cache is what these tests are about, and a backend would only add
    /// a thread and a sleep to each one.
    fn arrives_from(cache: &Cache, peer: PeerId, text: &str) {
        receive_clipboard(
            peer,
            crate::ports::MIME_TEXT.to_owned(),
            text.as_bytes().to_vec(),
            None,
            cache,
        );
    }

    #[test]
    fn a_peer_is_not_handed_back_the_clipboard_it_just_gave_us() {
        // The reported bug. Copy on the Mac, cross to this machine, cross back
        // with nothing copied here: the Mac must keep the copy it just made.
        let mac = PeerId([1; 32]);
        let cache = Cache::default();
        arrives_from(&cache, mac, "copied on the mac");

        assert!(clipboard_for_reclaim(true, &cache, mac).is_none());
    }

    #[test]
    fn a_clipboard_from_one_peer_still_crosses_to_a_third_machine() {
        let cache = Cache::default();
        arrives_from(&cache, PeerId([1; 32]), "copied on the mac");

        match clipboard_to_send(&cache, PeerId([2; 32])) {
            Some(Control::Clipboard { bytes, .. }) => assert_eq!(bytes, b"copied on the mac"),
            other => panic!("expected a clipboard frame, got {other:?}"),
        }
    }

    #[test]
    fn a_handed_over_clipboard_is_not_handed_over_twice() {
        let peer = PeerId([1; 32]);
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("copied"));

        assert!(clipboard_to_send(&cache, peer).is_some());
        assert!(clipboard_to_send(&cache, peer).is_none());
    }

    #[test]
    fn a_copy_made_after_a_handover_crosses_again() {
        let peer = PeerId([1; 32]);
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("first"));
        assert!(clipboard_to_send(&cache, peer).is_some());

        cache.observe_local(ClipboardContents::text("second"));

        match clipboard_to_send(&cache, peer) {
            Some(Control::Clipboard { bytes, .. }) => assert_eq!(bytes, b"second"),
            other => panic!("expected a clipboard frame, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_reconnects_is_handed_the_clipboard_again() {
        // What `serve_peer` promises when a link ends: the frame may have died
        // with it, so the machine that comes back is offered the copy once more.
        let peer = PeerId([1; 32]);
        let cache = Cache::default();
        cache.observe_local(ClipboardContents::text("copied"));
        assert!(clipboard_to_send(&cache, peer).is_some());

        cache.forget(peer);

        assert!(clipboard_to_send(&cache, peer).is_some());
    }

    #[test]
    fn an_inbound_clipboard_is_recorded_even_with_no_backend() {
        // A machine the cursor passes through carries the clipboard onward, even
        // where there is nothing local to offer it on.
        let cache = Cache::default();
        arrives_from(&cache, PeerId([1; 32]), "passing through");

        assert!(clipboard_to_send(&cache, PeerId([2; 32])).is_some());
    }
}
