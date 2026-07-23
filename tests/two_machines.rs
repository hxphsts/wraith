// Needs `_internals`, which `just test` and CI both pass as part of
// --all-features. A bare `cargo test` compiles this to nothing rather than
// failing on a missing module, so run `just test` for the real gate.
#![cfg(feature = "_internals")]

//! Two machines, over a real encrypted link.
//!
//! Everything except the display server: two [`Session`] reducers, two QUIC
//! endpoints with mutual pinned authentication, the real wire format, and the
//! real command routing. The X11 edges have their own hardware tests.
//!
//! This is where the acceptance criterion lives. Cross the cursor, hold a
//! chord, drop the sender's connection without warning, and the receiver must
//! let go on its own.

use std::net::SocketAddr;

use quinn::Endpoint;
use wraith::domain::{
    Cell, Command, Edge, Grid, HeldSet, Input, InputEvent, KeyState, Layout, Millis, PeerId, Point,
    Scancode, Screen, ScreenId, Seq, Session, SessionConfig,
};
use wraith::internals::endpoint;
use wraith::internals::identity::Identity;
use wraith::internals::verify::TrustedPeers;
use wraith::internals::wire::{self, Control, PROTOCOL_VERSION};

const DESKTOP: ScreenId = ScreenId(0);
const LAPTOP: ScreenId = ScreenId(1);

const CTRL: Scancode = Scancode(29);
const SHIFT: Scancode = Scancode(42);
const KEY_C: Scancode = Scancode(46);

const fn press(code: Scancode) -> InputEvent {
    InputEvent::Key {
        code,
        state: KeyState::Pressed,
    }
}

const fn release(code: Scancode) -> InputEvent {
    InputEvent::Key {
        code,
        state: KeyState::Released,
    }
}

fn screen(id: ScreenId, peer: PeerId, name: &str) -> Screen {
    Screen::new(id, peer, name, (1920, 1080))
}

/// One machine's view of a two-screen desk.
fn desk(home: ScreenId, desktop_peer: PeerId, laptop_peer: PeerId) -> Session {
    let mut layout = Layout::new();
    layout
        .add_screen(screen(DESKTOP, desktop_peer, "desktop"))
        .unwrap();
    layout
        .add_screen(screen(LAPTOP, laptop_peer, "laptop"))
        .unwrap();
    layout.link(DESKTOP, Edge::Right, LAPTOP).unwrap();

    Session::new(
        layout,
        home,
        Point::new(1919, 540),
        SessionConfig::default(),
    )
}

/// Runs a session and collects everything it asked for.
struct Machine {
    session: Session,
    injected: Vec<InputEvent>,
    sent: Vec<Command>,
    /// Every absolute move this machine was asked to make, in order.
    warps: Vec<Point>,
    suppressed: bool,
    now_ms: u64,
}

impl Machine {
    const fn new(session: Session) -> Self {
        Self {
            session,
            injected: Vec::new(),
            sent: Vec::new(),
            warps: Vec::new(),
            suppressed: false,
            now_ms: 0,
        }
    }

    fn step(&mut self, input: Input) {
        let mut out = Vec::new();
        self.session.step(input, &mut out);

        for command in out {
            match command {
                Command::Inject(events) => self.injected.extend(events),
                Command::Suppress(on) => self.suppressed = on,
                Command::WarpLocal(at) => self.warps.push(at),
                Command::Notify(_) => {}
                other => self.sent.push(other),
            }
        }
    }

    fn tick_to(&mut self, ms: u64) {
        self.now_ms = ms;
        self.step(Input::Tick { now_ms: Millis(ms) });
    }

    fn holds(&self, code: Scancode) -> bool {
        let mut held = HeldSet::new();
        for &event in &self.injected {
            held.apply(event);
        }
        held.holds_key(code)
    }

    fn take_sent(&mut self) -> Vec<Command> {
        std::mem::take(&mut self.sent)
    }
}

/// Delivers one machine's commands to the other, as the wire would.
///
/// Everything goes through `wire::encode` and `wire::decode`, so a message that
/// could not survive the wire fails here rather than in production.
fn deliver(commands: Vec<Command>, from: PeerId, to: &mut Machine) {
    for command in commands {
        let control = match command {
            Command::SendTransitions { events, .. } => Control::Transitions { events },
            Command::SendSnapshot { held, .. } => Control::Snapshot { held },
            Command::SendEnter { crossing, .. } => Control::Enter { crossing },
            Command::SendLeave { .. } => Control::Leave,
            Command::SendMotion { events, .. } => {
                let frame = wire::motion_frame(events, Seq(1), Millis(to.now_ms)).unwrap();
                let bytes = wire::encode_frame(&frame).unwrap();
                let decoded = wire::decode_frame(&bytes).unwrap();
                to.step(Input::PeerFrame {
                    peer: from,
                    frame: decoded,
                });
                continue;
            }
            _ => continue,
        };

        let framed = wire::encode(&control).unwrap();
        let length = wire::frame_length(framed[..4].try_into().unwrap()).unwrap();
        let decoded = wire::decode(&framed[4..4 + length]).unwrap();

        let input = match decoded {
            Control::Transitions { events } => Input::PeerTransitions { peer: from, events },
            Control::Snapshot { held } => Input::PeerSnapshot { peer: from, held },
            Control::Enter { crossing } => Input::PeerEnter {
                peer: from,
                crossing,
            },
            Control::Leave => Input::PeerLeave { peer: from },
            _ => continue,
        };
        to.step(input);
    }
}

/// A desktop and a laptop, connected and aware of each other.
fn pair_of_machines() -> (Machine, Machine, PeerId, PeerId) {
    let desktop_id = PeerId([1; 32]);
    let laptop_id = PeerId([2; 32]);

    let mut desktop = Machine::new(desk(DESKTOP, desktop_id, laptop_id));
    let mut laptop = Machine::new(desk(LAPTOP, desktop_id, laptop_id));

    desktop.tick_to(0);
    laptop.tick_to(0);

    desktop.step(Input::PeerConnected {
        peer: laptop_id,
        screen: screen(LAPTOP, laptop_id, "laptop"),
    });
    laptop.step(Input::PeerConnected {
        peer: desktop_id,
        screen: screen(DESKTOP, desktop_id, "desktop"),
    });

    (desktop, laptop, desktop_id, laptop_id)
}

/// Shoves the desktop cursor off its right edge.
fn cross(desktop: &mut Machine) {
    desktop.step(Input::Local(InputEvent::MotionRel {
        dx_milli: 20_000,
        dy_milli: 0,
    }));
}

#[test]
fn the_cursor_crosses_and_input_follows_it() {
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();

    cross(&mut desktop);
    assert!(desktop.suppressed, "the desktop did not stop its own input");
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(press(KEY_C)));
    desktop.step(Input::Local(release(KEY_C)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert_eq!(
        laptop.injected,
        vec![press(KEY_C), release(KEY_C)],
        "the keystroke did not arrive intact"
    );
}

#[test]
fn the_arriving_cursor_lands_on_the_edge_it_entered_by() {
    // The property the user judges the whole tool by, and one a harness can
    // discard without noticing: drop `WarpLocal` in `Machine::step` and both
    // sides still agree a crossing happened while the pointer goes nowhere near
    // the edge it came through. Hence `warps`, and hence this.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();

    // Leaving the right edge at 540 of 1080 down.
    cross(&mut desktop);
    assert!(
        desktop.warps.is_empty(),
        "the machine being left must not warp"
    );

    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert_eq!(
        laptop.warps,
        vec![Point::new(1, 540)],
        "one pixel inside the left edge, at the height it left by"
    );
}

#[test]
fn the_cursor_comes_back_to_the_edge_it_returns_through() {
    // The return leg, which is the direction that was landing the pointer
    // wherever it happened to be sitting before it left.
    let (mut desktop, mut laptop, desktop_id, laptop_id) = pair_of_machines();

    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);
    laptop.warps.clear();

    // The cursor is on the laptop now, so the desktop drives it from there.
    // Push it back off the laptop's left edge.
    desktop.tick_to(1_000);
    desktop.step(Input::Local(InputEvent::MotionRel {
        dx_milli: -20_000,
        dy_milli: 0,
    }));

    assert_eq!(
        desktop.warps,
        vec![Point::new(1918, 540)],
        "one pixel inside its own right edge, not wherever it was left"
    );
    assert!(!desktop.suppressed, "and it takes its own input back");

    deliver(desktop.take_sent(), desktop_id, &mut laptop);
    let _ = laptop_id;
    assert!(
        laptop.warps.is_empty(),
        "the machine being left must not warp"
    );
}

#[test]
fn typing_before_crossing_stays_on_the_local_machine() {
    // The difference between a KVM and a keylogger.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();

    desktop.step(Input::Local(press(KEY_C)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert!(laptop.injected.is_empty(), "local input leaked to the peer");
}

#[test]
fn motion_follows_the_cursor_across() {
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();

    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(InputEvent::MotionRel {
        dx_milli: 5_000,
        dy_milli: -2_000,
    }));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert!(
        laptop.injected.contains(&InputEvent::MotionRel {
            dx_milli: 5_000,
            dy_milli: -2_000
        }),
        "motion did not arrive: {:?}",
        laptop.injected
    );
}

#[test]
fn a_chord_survives_the_round_trip() {
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();
    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    for event in [press(CTRL), press(KEY_C), release(KEY_C), release(CTRL)] {
        desktop.step(Input::Local(event));
        deliver(desktop.take_sent(), desktop_id, &mut laptop);
    }

    assert!(
        !laptop.holds(CTRL),
        "Ctrl was left held after a clean chord"
    );
    assert!(!laptop.holds(KEY_C), "C was left held after a clean chord");
}

#[test]
fn the_receiver_releases_when_the_sender_vanishes_mid_chord() {
    // **The acceptance criterion.** Deskflow's stuck modifier survives killing
    // the process. This is the test that says Wraith's does not.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();
    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(press(CTRL)));
    desktop.step(Input::Local(press(SHIFT)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert!(laptop.holds(CTRL), "setup failed, Ctrl never arrived");
    assert!(laptop.holds(SHIFT), "setup failed, Shift never arrived");

    // The sender is killed. Nothing more is ever sent, and no goodbye arrives.
    drop(desktop);

    // Only time passes. Nothing tells the laptop anything.
    laptop.tick_to(2_000);

    assert!(
        !laptop.holds(CTRL),
        "Ctrl was left held after the sender vanished"
    );
    assert!(
        !laptop.holds(SHIFT),
        "Shift was left held after the sender vanished"
    );
}

#[test]
fn the_receiver_releases_within_the_watchdog_deadline() {
    // Bounded, not eventual. A release that took ten seconds would be almost as
    // bad as none.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();
    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(press(CTRL)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);
    let held_at = laptop.now_ms;

    for ms in (held_at..held_at + 2_000).step_by(20) {
        laptop.tick_to(ms);
        if !laptop.holds(CTRL) {
            let took = ms - held_at;
            assert!(
                took <= 900,
                "the release took {took}ms, and the bound is 900"
            );
            return;
        }
    }
    panic!("the key was never released");
}

#[test]
fn an_explicit_disconnect_releases_faster_than_the_watchdog() {
    // A closed connection is already proof the sender stopped, so waiting for
    // the deadline would be needlessly slow.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();
    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(press(CTRL)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    laptop.step(Input::PeerLost { peer: desktop_id });

    assert!(!laptop.holds(CTRL), "a lost peer left a key held");
}

#[test]
fn going_home_releases_before_the_cursor_leaves() {
    // Otherwise the key is stranded on a machine the cursor is no longer on,
    // and nothing on the sending side will ever mention it again.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();
    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(press(CTRL)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    // The desk loses the screen the cursor is standing on, which is one of the
    // two ways a session sends the cursor home.
    let mut layout = Layout::new();
    layout
        .add_screen(screen(DESKTOP, desktop_id, "desktop"))
        .unwrap();
    desktop.step(Input::LayoutChanged { layout });
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert!(!laptop.holds(CTRL), "the cursor went home holding Ctrl");
    assert!(
        !desktop.suppressed,
        "input was left suppressed after coming home"
    );
}

#[test]
fn a_desynchronised_receiver_is_repaired_by_the_next_snapshot() {
    // The layer that catches whatever the other eight miss. A release is lost
    // in transit, and the periodic snapshot puts it right.
    let (mut desktop, mut laptop, desktop_id, _) = pair_of_machines();
    cross(&mut desktop);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    desktop.step(Input::Local(press(CTRL)));
    desktop.step(Input::Local(press(KEY_C)));
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    // C is released, and the message is lost rather than delivered.
    desktop.step(Input::Local(release(KEY_C)));
    let _lost = desktop.take_sent();

    assert!(
        laptop.holds(KEY_C),
        "setup failed, the loss did not desynchronise anything"
    );

    // The next snapshot carries the truth.
    desktop.tick_to(500);
    deliver(desktop.take_sent(), desktop_id, &mut laptop);

    assert!(
        !laptop.holds(KEY_C),
        "reconciliation did not repair the desync"
    );
    assert!(
        laptop.holds(CTRL),
        "reconciliation released a key that was legitimately held"
    );
}

#[tokio::test]
async fn two_paired_machines_connect_and_a_stranger_cannot() {
    // The trust model over real QUIC rather than in the abstract.
    let desktop = Identity::generate();
    let laptop = Identity::generate();
    let stranger = Identity::generate();

    let trusted = TrustedPeers::of([desktop.peer_id(), laptop.peer_id()]);
    let server = endpoint::server(&desktop, trusted, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = loopback(&server);

    let accepting = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection");
        incoming.await.is_ok()
    });

    let paired = endpoint::client(&laptop, TrustedPeers::of([desktop.peer_id()])).unwrap();
    let connected = paired.connect(address, "wraith").unwrap().await;

    assert!(
        connected.is_ok(),
        "a paired peer was refused: {:?}",
        connected.err()
    );
    assert!(accepting.await.unwrap(), "the server refused a paired peer");

    // The same server, approached by a machine it has never paired with.
    let trusted = TrustedPeers::of([desktop.peer_id(), laptop.peer_id()]);
    let server = endpoint::server(&desktop, trusted, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = loopback(&server);

    let refusing = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection attempt");
        incoming.await.is_err()
    });

    let unpaired = endpoint::client(&stranger, TrustedPeers::of([desktop.peer_id()])).unwrap();
    let connecting = unpaired.connect(address, "wraith").unwrap().await;

    // The server refusing is the assertion that matters. In TLS 1.3 the client
    // certificate is verified after the client considers its own handshake
    // done, so `connect` resolving on the stranger's side says nothing about
    // whether it was accepted. What it cannot do is use the connection.
    assert!(
        refusing.await.unwrap(),
        "the server accepted an unpaired machine"
    );

    // And from the stranger's side, the connection does not survive. Opening a
    // stream is a local allocation that needs no round trip, so the meaningful
    // check is that the connection is closed rather than that a call failed.
    if let Ok(connection) = connecting {
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(2), connection.closed()).await;

        assert!(
            closed.is_ok(),
            "an unpaired machine kept its connection open"
        );
    }
}

#[tokio::test]
async fn a_control_message_survives_a_real_quic_link() {
    // Proves the framing against the transport, not against a Vec.
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();
    let trusted = TrustedPeers::of([server_identity.peer_id(), client_identity.peer_id()]);

    let server = endpoint::server(
        &server_identity,
        trusted.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = loopback(&server);

    let receiving = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = connection.accept_bi().await.unwrap();

        let mut header = [0_u8; 4];
        recv.read_exact(&mut header).await.unwrap();
        let length = wire::frame_length(header).unwrap();

        let mut payload = vec![0_u8; length];
        recv.read_exact(&mut payload).await.unwrap();
        wire::decode::<Control>(&payload).unwrap()
    });

    let client = endpoint::client(&client_identity, trusted).unwrap();
    let connection = client.connect(address, "wraith").unwrap().await.unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();

    let message = Control::Transitions {
        events: vec![press(CTRL), press(KEY_C)],
    };
    send.write_all(&wire::encode(&message).unwrap())
        .await
        .unwrap();
    send.finish().unwrap();
    let _ = send.stopped().await;

    assert_eq!(receiving.await.unwrap(), message);
}

#[tokio::test]
async fn a_placement_survives_a_real_quic_link() {
    // `Control::Place` was appended to the enum rather than inserted, so it
    // carries the highest discriminant and is the variant most likely to be
    // lost to a length or varint mistake. The others are covered by the codec
    // tests; this one is worth putting on a real wire.
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();
    let trusted = TrustedPeers::of([server_identity.peer_id(), client_identity.peer_id()]);

    let server = endpoint::server(
        &server_identity,
        trusted.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = loopback(&server);

    let receiving = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = connection.accept_bi().await.unwrap();

        let mut header = [0_u8; 4];
        recv.read_exact(&mut header).await.unwrap();
        let length = wire::frame_length(header).unwrap();

        let mut payload = vec![0_u8; length];
        recv.read_exact(&mut payload).await.unwrap();
        wire::decode::<Control>(&payload).unwrap()
    });

    let client = endpoint::client(&client_identity, trusted).unwrap();
    let connection = client.connect(address, "wraith").unwrap().await.unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();

    let message = Control::Place { side: Edge::Bottom };
    send.write_all(&wire::encode(&message).unwrap())
        .await
        .unwrap();
    send.finish().unwrap();
    let _ = send.stopped().await;

    assert_eq!(receiving.await.unwrap(), message);
}

#[tokio::test]
async fn a_clipboard_survives_a_real_quic_link() {
    // `Control::Clipboard` carries the highest discriminant, appended after
    // `Place`, so it is the variant most exposed to a length or varint mistake.
    // The bytes also matter here in a way a placement's do not: a clipboard is
    // arbitrary content, and a truncation would paste the wrong thing.
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();
    let trusted = TrustedPeers::of([server_identity.peer_id(), client_identity.peer_id()]);

    let server = endpoint::server(
        &server_identity,
        trusted.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = loopback(&server);

    let receiving = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let (_send, mut recv) = connection.accept_bi().await.unwrap();

        let mut header = [0_u8; 4];
        recv.read_exact(&mut header).await.unwrap();
        let length = wire::frame_length(header).unwrap();

        let mut payload = vec![0_u8; length];
        recv.read_exact(&mut payload).await.unwrap();
        wire::decode::<Control>(&payload).unwrap()
    });

    let client = endpoint::client(&client_identity, trusted).unwrap();
    let connection = client.connect(address, "wraith").unwrap().await.unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();

    let message = Control::Clipboard {
        mime: "text/plain;charset=utf-8".to_owned(),
        bytes: "a paragraph copied on one machine".as_bytes().to_vec(),
    };
    send.write_all(&wire::encode(&message).unwrap())
        .await
        .unwrap();
    send.finish().unwrap();
    let _ = send.stopped().await;

    assert_eq!(receiving.await.unwrap(), message);
}

#[test]
fn a_placement_leaves_the_two_desks_agreeing() {
    // The whole point of sending a placement at all. One machine is dragged in
    // the window, the other hears about it, and the two desks must end up
    // describing the same arrangement from opposite ends.
    //
    // This is the algebra the wire relies on: what the sender puts in the
    // frame is the direction from itself to the peer, and the peer applying
    // the opposite of it from its own anchor lands in the mirrored place.
    let mut mine = Grid::default();
    mine.place("desktop", Cell::ORIGIN).unwrap();
    mine.place("laptop", Cell::new(0, 1)).unwrap();

    let sent = side_of(&mine, "desktop", "laptop").unwrap();
    assert_eq!(sent, Edge::Bottom, "the laptop sits below the desktop");

    // What the laptop does on receiving `Place { side: sent }`.
    let mut theirs = Grid::default();
    theirs.place("laptop", Cell::ORIGIN).unwrap();
    let at = theirs.free_cell(Cell::ORIGIN, sent.opposite());
    theirs.place("desktop", at).unwrap();

    assert_eq!(
        side_of(&theirs, "laptop", "desktop"),
        Some(Edge::Top),
        "and the desktop sits above the laptop, seen from the laptop"
    );
    assert_eq!(
        side_of(&mine, "desktop", "laptop"),
        side_of(&theirs, "laptop", "desktop").map(Edge::opposite),
        "the two desks describe one arrangement"
    );
}

/// Which way `to` lies from `from`, or `None` if they are not adjacent.
fn side_of(grid: &Grid, from: &str, to: &str) -> Option<Edge> {
    grid.neighbours(from)
        .find(|(_, name)| *name == to)
        .map(|(edge, _)| edge)
}

#[tokio::test]
async fn motion_survives_a_real_quic_datagram() {
    // The unreliable path, which is where every motion event goes.
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();
    let trusted = TrustedPeers::of([server_identity.peer_id(), client_identity.peer_id()]);

    let server = endpoint::server(
        &server_identity,
        trusted.clone(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = loopback(&server);

    let receiving = tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let bytes = connection.read_datagram().await.unwrap();
        wire::decode_frame(&bytes).unwrap()
    });

    let client = endpoint::client(&client_identity, trusted).unwrap();
    let connection = client.connect(address, "wraith").unwrap().await.unwrap();

    let frame = wire::motion_frame(
        vec![InputEvent::MotionRel {
            dx_milli: 1_500,
            dy_milli: -250,
        }],
        Seq(7),
        Millis(42),
    )
    .unwrap();
    connection
        .send_datagram(wire::encode_frame(&frame).unwrap().into())
        .unwrap();

    assert_eq!(receiving.await.unwrap(), frame);
}

#[test]
fn the_hello_carries_everything_a_peer_needs_to_map_crossings() {
    // A missing or wrong screen size puts an arriving cursor at the wrong
    // height, which reads as the pointer jumping on every crossing.
    let hello = Control::Hello {
        protocol: PROTOCOL_VERSION,
        name: "laptop".to_owned(),
        screen: screen(LAPTOP, PeerId([2; 32]), "laptop"),
    };

    let framed = wire::encode(&hello).unwrap();
    let length = wire::frame_length(framed[..4].try_into().unwrap()).unwrap();

    match wire::decode(&framed[4..4 + length]).unwrap() {
        Control::Hello {
            screen, protocol, ..
        } => {
            assert_eq!(protocol, PROTOCOL_VERSION);
            assert_eq!(screen.width_px, 1920);
            assert_eq!(screen.height_px, 1080);
        }
        other => panic!("expected a hello, got {other:?}"),
    }
}

/// A server's port on loopback.
///
/// `local_addr` reports the bind address, which quinn rightly refuses to dial
/// when it is unspecified.
fn loopback(endpoint: &Endpoint) -> SocketAddr {
    let port = endpoint.local_addr().unwrap().port();
    format!("127.0.0.1:{port}").parse().unwrap()
}
