//! `wraith pair`, the only way a peer enters the trust store.
//!
//! One machine offers and prints a code, the other joins and types it. Both come
//! away holding the other's identity key.
//!
//! # Why the pairing link is unauthenticated and that is fine
//!
//! The pairing connection cannot use the pinned verifier, because pinning is
//! exactly what pairing establishes. So it accepts any certificate, and the
//! SPAKE2 exchange running on top provides the authentication instead. A man in
//! the middle who intercepts the connection still has to guess the code, gets
//! one attempt, and learns nothing from watching.
//!
//! This is the one place in Wraith where a connection is accepted without
//! pinning, and nothing that happens on it can add a peer to the trust store
//! except a completed exchange.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use crate::config::{Config, Peer, Peers, encode_hex};
use crate::domain::{Cell, Edge};
use crate::error::{Error, Result};
use crate::net::endpoint::{DEFAULT_PAIR_PORT, DEFAULT_PORT};
use crate::net::identity::Identity;
use crate::net::pairing::{IdentityAnnouncement, Pairing, PairingCode};

/// How long to wait for the other side before giving up.
///
/// Long enough to read a code aloud and have it typed, short enough that an
/// abandoned pairing does not leave a socket open all afternoon.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest pairing message worth reading.
///
/// A SPAKE2 message is 33 bytes and an announcement is under 200. The cap exists
/// because this is pre-authentication input, and an unbounded read here is
/// CVE-2021-42076 with the serial numbers filed off.
const MESSAGE_BYTES_MAX: usize = 4_096;

const PAIRING_ALPN: &[u8] = b"wraith-pair/1";

/// A pairing offer, bound and holding a code, with nobody joined yet.
///
/// Split from the waiting so a caller can show the code immediately. The CLI
/// prints it and the window draws it, and neither has to wait two minutes to
/// find out what it was.
pub struct Offer {
    endpoint: Endpoint,
    code: PairingCode,
    address: SocketAddr,
}

impl Offer {
    /// Binds and mints a code. Port zero takes whatever is free.
    pub(crate) fn open(identity: &Identity, port: u16) -> Result<Self> {
        let endpoint = pairing_server(identity, port)?;
        let address = endpoint.local_addr().map_err(Error::Io)?;

        Ok(Self {
            endpoint,
            code: PairingCode::generate(),
            address,
        })
    }

    pub(crate) const fn code(&self) -> &PairingCode {
        &self.code
    }

    pub(crate) const fn port(&self) -> u16 {
        self.address.port()
    }

    /// Waits for a machine to join, and runs the exchange.
    ///
    /// **Cancel by dropping the future.** The endpoint goes with it and the
    /// port is released, which is why nothing above this needs a cancel
    /// message. It is also why an offer must never outlive the intent to pair:
    /// this endpoint accepts an unpaired peer, and that is the one door in the
    /// whole system that does.
    pub(crate) async fn accept(
        self,
        identity: &Identity,
        name: &str,
        side: Option<Edge>,
        wait_max: Duration,
    ) -> Result<Paired> {
        let connecting = tokio::time::timeout(wait_max, self.endpoint.accept())
            .await
            .map_err(|_| Error::Config(crate::control::Refusal::Timeout.to_string()))?
            .ok_or_else(|| Error::Config("the pairing endpoint closed".to_owned()))?;

        let connection = connecting
            .await
            .map_err(|error| Error::Config(format!("the pairing connection failed: {error}")))?;

        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|error| Error::Config(format!("the peer opened no stream: {error}")))?;

        let outcome = exchange(identity, name, &self.code, side, send, recv).await;
        report(outcome, &connection, &self.endpoint).await
    }
}

/// Offers pairing, printing a code for the other machine.
pub async fn offer(identity: &Identity, name: &str, port: u16, side: Option<Edge>) -> Result<()> {
    let offer = Offer::open(identity, port)?;

    println!("pairing code   {}", offer.code());
    println!();
    println!("on the other machine, run:");
    println!("    wraith pair --join {}", join_hint(offer.port()));
    println!();
    println!("waiting, {} seconds", PAIRING_TIMEOUT.as_secs());

    let paired = offer.accept(identity, name, side, PAIRING_TIMEOUT).await?;
    let recorded = record(&paired, None)?;

    announce(&recorded);
    Ok(())
}

/// Joins a pairing offer, asking for the code.
pub async fn join(
    identity: &Identity,
    name: &str,
    address: &str,
    code: Option<&str>,
    side: Option<Edge>,
) -> Result<()> {
    let address = resolve(address)?;

    let code = match code {
        Some(text) => PairingCode::parse(text).map_err(|error| Error::Config(error.to_string()))?,
        None => prompt_for_code()?,
    };

    // The joining machine decides the desk, because it is where the person is
    // standing: they are the one who just typed the code. The offering side
    // sends nothing and applies the mirror.
    let side = side.or_else(prompt_for_side);

    let paired = join_once(identity, name, address, &code, side).await?;
    let recorded = record(&paired, Some(address))?;

    announce(&recorded);
    Ok(())
}

/// One join attempt, with the address and code already settled.
///
/// The protocol half of `join`, with nothing read from a terminal and nothing
/// printed, so the window can drive it.
pub async fn join_once(
    identity: &Identity,
    name: &str,
    address: SocketAddr,
    code: &PairingCode,
    side: Option<Edge>,
) -> Result<Paired> {
    let endpoint = pairing_client(identity)?;
    let connection = endpoint
        .connect(address, "wraith")
        .map_err(|error| Error::Config(format!("cannot start the connection: {error}")))?
        .await
        .map_err(|error| Error::Config(format!("cannot reach {address}: {error}")))?;

    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| Error::Config(format!("cannot open a stream: {error}")))?;

    let outcome = exchange(identity, name, code, side, send, recv).await;
    report(outcome, &connection, &endpoint).await
}

/// Closes the connection, telling the peer why if it went wrong.
///
/// Without this, a side that refuses the pairing simply vanishes, and the other
/// machine reports a lost connection for what was actually a mismatched code.
/// The reason is not sensitive: both sides already know the exchange failed, and
/// only the code itself would be worth hiding.
async fn report(
    outcome: Result<Paired>,
    connection: &quinn::Connection,
    endpoint: &Endpoint,
) -> Result<Paired> {
    match outcome {
        Ok(paired) => {
            settle(connection, endpoint).await;
            Ok(paired)
        }
        Err(error) => {
            connection.close(1_u8.into(), error.to_string().as_bytes());
            endpoint.wait_idle().await;
            Err(error)
        }
    }
}

/// Closes the connection and waits for the last frame to reach the peer.
///
/// Without this the process exits, the socket dies, and the other side reports
/// "connection lost" for an exchange that actually succeeded. Both sides write
/// their announcement before reading the other's, so the last writer is always
/// racing its own shutdown.
async fn settle(connection: &quinn::Connection, endpoint: &Endpoint) {
    connection.close(0_u8.into(), b"paired");
    endpoint.wait_idle().await;
}

/// The exchange itself, identical on both sides.
///
/// Symmetric because SPAKE2's symmetric mode has no initiator, which is right
/// for a KVM: neither machine is naturally the client, and inventing an order
/// would mean asking the user which one goes first.
pub async fn exchange(
    identity: &Identity,
    name: &str,
    code: &PairingCode,
    side: Option<Edge>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<Paired> {
    let opening = Pairing::start(code, identity.peer_id(), name.to_owned());

    tracing::debug!("sending the pairing opening");
    write_frame(&mut send, &opening.message).await?;
    tracing::debug!("waiting for the peer opening");
    let peer_message = read_frame(&mut recv).await?;
    tracing::debug!("got the peer opening");

    let completed = opening
        .pairing
        .finish(&peer_message)
        .map_err(|error| Error::Config(error.to_string()))?;

    let announcement = postcard::to_stdvec(&completed.announcement)
        .map_err(|error| Error::Config(format!("cannot encode the announcement: {error}")))?;
    write_frame(&mut send, &announcement).await?;
    tracing::debug!("sent our announcement, waiting for theirs");

    let their_bytes = read_frame(&mut recv).await?;
    tracing::debug!("got their announcement");
    let theirs: IdentityAnnouncement = postcard::from_bytes(&their_bytes)
        .map_err(|_| Error::Config("the peer sent a malformed announcement".to_owned()))?;

    let peer_id = completed
        .accept(&theirs)
        .map_err(|error| Error::Config(error.to_string()))?;

    // The fifth frame carries the desk, and only one side decides it. The
    // joining machine is where the person is standing, since they are the one
    // typing the code, so it sends a direction and this side sends nothing.
    // Whichever receives one applies the mirror.
    let ours = postcard::to_stdvec(&side)
        .map_err(|error| Error::Config(format!("cannot encode the placement: {error}")))?;
    write_frame(&mut send, &ours).await?;

    let theirs_bytes = read_frame(&mut recv).await?;
    let theirs_side: Option<Edge> = postcard::from_bytes(&theirs_bytes)
        .map_err(|_| Error::Config("the peer sent a malformed placement".to_owned()))?;

    // Ours if we chose, otherwise the mirror of theirs. Both sides compute the
    // same desk from one answer.
    let agreed = side.or_else(|| theirs_side.map(Edge::opposite));

    // Nothing more will be written, so the stream is finished and then waited
    // on until the peer has acknowledged every byte.
    //
    // The wait is load bearing. `Connection::close` discards unsent stream data,
    // so whichever side finishes first would otherwise close the connection out
    // from under its own final frame and the other side would report a lost
    // connection for an exchange that actually succeeded.
    let _ = send.finish();
    let _ = send.stopped().await;

    Ok(Paired {
        peer: Peer {
            name: theirs.name,
            key: encode_hex(&peer_id.0),
            address: None,
        },
        side: agreed,
    })
}

/// Where that machine will be listening once pairing is over.
///
/// The address dialled here is the **pairing** endpoint, which exists only
/// while an offer is outstanding. Storing it verbatim recorded a port nothing
/// would ever answer on again, so the two machines never found each other after
/// pairing and the cursor stopped dead at the screen edge.
///
/// That was invisible while pairing and serving shared one port. Splitting them
/// is what turned a harmless copy into a wrong answer.
///
/// The host is what matters and it carries over unchanged. The port is
/// corrected to the session default, which is right for any machine that has
/// not been told to listen somewhere else. One that has still has its address
/// field, and discovery finds it either way.
const fn session_address(pairing: SocketAddr) -> SocketAddr {
    let mut session = pairing;
    session.set_port(DEFAULT_PORT);
    session
}

/// What a completed pairing yields.
#[derive(Debug, Clone)]
pub struct Paired {
    peer: Peer,
    /// Which side of this machine the peer sits on, once both agree.
    ///
    /// `None` only when neither side chose, which means both were run without a
    /// terminal and without `--side`.
    side: Option<Edge>,
}

impl Paired {
    /// The peer's identity key, hex encoded.
    pub(crate) fn key(&self) -> &str {
        &self.peer.key
    }
}

/// Writes a length-prefixed frame.
async fn write_frame(send: &mut quinn::SendStream, payload: &[u8]) -> Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| Error::Config("the pairing message is too large".to_owned()))?;

    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|error| Error::Config(format!("cannot write: {error}")))?;
    send.write_all(payload)
        .await
        .map_err(|error| Error::Config(format!("cannot write: {error}")))?;

    Ok(())
}

/// Reads a length-prefixed frame, refusing anything oversized.
///
/// The cap is checked before allocating. Reading a length and then trusting it
/// is how CVE-2021-42076 turned a four-byte field into a four-gigabyte
/// allocation, and this runs before any authentication at all.
async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| read_error(&e))?;

    let length = u32::from_be_bytes(header) as usize;
    if length > MESSAGE_BYTES_MAX {
        return Err(Error::Config(format!(
            "the peer announced a {length} byte pairing message, and the limit is \
             {MESSAGE_BYTES_MAX}"
        )));
    }

    let mut payload = vec![0_u8; length];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| read_error(&e))?;

    Ok(payload)
}

/// A read failure, preferring the peer's own account of it.
///
/// When the other side refuses a pairing it closes with the reason, and
/// repeating that reason here is far more useful than "connection lost". A
/// mismatched code should read as a mismatched code on both machines, since
/// that is the one failure a user is likely to cause and needs to understand.
fn read_error(error: &quinn::ReadExactError) -> Error {
    use quinn::{ConnectionError, ReadError, ReadExactError};

    if let ReadExactError::ReadError(ReadError::ConnectionLost(ConnectionError::ApplicationClosed(
        closed,
    ))) = error
        && let Ok(reason) = std::str::from_utf8(&closed.reason)
        && !reason.is_empty()
    {
        return Error::PeerRefused(reason.to_owned());
    }

    Error::Config(format!("the pairing connection ended: {error}"))
}

/// Adds the peer to the trust store, and puts it on the desk.
///
/// Two files, because a paired machine that is nowhere on the desk can never
/// receive the cursor. Writing only the trust store leaves the user with a
/// config file to compose by hand.
pub fn record(paired: &Paired, address: Option<SocketAddr>) -> Result<Recorded> {
    let mut peer = paired.peer.clone();
    peer.address = address.map(|address| session_address(address).to_string());

    let peers_path = Peers::path();
    let mut peers = Peers::load(&peers_path).map_err(|error| Error::Config(error.to_string()))?;

    let name = peer.name.clone();
    let key = peer.key.clone();
    peers.upsert(peer);
    peers
        .save(&peers_path)
        .map_err(|error| Error::Config(error.to_string()))?;

    let config_path = Config::path();
    let mut config =
        Config::load(&config_path).map_err(|error| Error::Config(error.to_string()))?;

    // No agreed side means nobody chose one: neither a flag nor a terminal on
    // either machine, which is the ordinary case when pairing from the window.
    // The peer is paired and trusted, it just has nowhere to stand yet, and the
    // tray under the desk is exactly where it waits.
    let Some(side) = paired.side else {
        return Ok(Recorded { name, desk: None });
    };

    let local = config.local_name();
    let anchor = config.grid().cell_of(&local).unwrap_or(Cell::ORIGIN);
    let at = config.grid().free_cell(anchor, side);

    config
        .place(&name, at, Some(&key))
        .map_err(|error| Error::Config(error.to_string()))?;
    config
        .save(&config_path)
        .map_err(|error| Error::Config(error.to_string()))?;

    let drawn = picture(&config, &local);
    Ok(Recorded {
        name,
        desk: Some(drawn),
    })
}

/// What recording a pairing did.
pub struct Recorded {
    pub name: String,
    /// The desk it produced, or `None` if the machine is not placed yet.
    pub desk: Option<String>,
}

/// Tells the user what `record` did. The only printing left in this module.
fn announce(recorded: &Recorded) {
    println!();
    println!("paired with {}", recorded.name);
    println!();

    let Some(desk) = &recorded.desk else {
        println!("nobody chose a side, so it is not on the desk yet.");
        println!("run `wraith ui` to place it, or pair again with --side.");
        return;
    };

    print!("{desk}");
    println!();
    println!("both machines know the desk. run `wraith serve` on each.");
}

/// The desk, drawn in text.
///
/// Worth the twenty lines: it is the confirmation that the one question the
/// user answered produced the arrangement they meant, and it is the only view
/// they get without the window.
fn picture(config: &Config, local: &str) -> String {
    use std::fmt::Write as _;

    let grid = config.grid();
    let (min, max) = grid.bounds();

    let width = grid
        .iter()
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(4)
        .max(4);

    let mut out = String::new();
    for row in min.row..=max.row {
        for column in min.column..=max.column {
            let name = grid.at(Cell::new(column, row)).unwrap_or("");
            let _ = write!(out, "  {name:<width$}");
        }
        out.push('\n');

        // A marker under the local machine, so it is obvious which one you are
        // sitting at without colour or a legend.
        for column in min.column..=max.column {
            let here = grid.at(Cell::new(column, row)) == Some(local);
            let mark = if here { "[you]" } else { "" };
            let _ = write!(out, "  {mark:<width$}");
        }
        out.push('\n');
    }
    out
}

/// What to tell the user to type on the other machine.
///
/// The bound address is `0.0.0.0`, which is not something anyone can connect
/// to, so printing it verbatim would be actively unhelpful. The hostname is the
/// right answer on a LAN, and the port is only mentioned when it is not the
/// default because otherwise it is noise.
pub fn join_hint(port: u16) -> String {
    let host = crate::config::hostname();

    if port == DEFAULT_PAIR_PORT {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn prompt_for_code() -> Result<PairingCode> {
    use std::io::{BufRead as _, Write as _};

    print!("pairing code: ");
    std::io::stdout().flush().map_err(Error::Io)?;

    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(Error::Io)?;

    PairingCode::parse(&line).map_err(|error| Error::Config(error.to_string()))
}

/// Asks which side the peer is on.
///
/// The one question pairing asks. Everything else about the desk is already
/// known: both names, both identities, and each screen's size.
///
/// **Returns `None` when stdin is not a terminal**, rather than blocking. A
/// script or a CI run that hangs waiting for an answer nobody is there to give
/// is worse than a desk that needs arranging afterwards.
fn prompt_for_side() -> Option<Edge> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};

    if !std::io::stdin().is_terminal() {
        tracing::debug!("not a terminal, so not asking which side the peer is on");
        return None;
    }

    println!();
    print!("which side of this machine is it on? [R]ight, [l]eft, [u]p, [d]own: ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return None;
    }

    // Right by default, because a second machine beside the first is what
    // almost everyone means and an empty answer should not be a dead end.
    Some(parse_side(&line).unwrap_or(Edge::Right))
}

/// A typed answer as a direction.
///
/// Public so `--side` and the prompt agree on what an answer means.
///
/// Forgiving: the first letter is enough, and so is the whole word.
pub fn parse_side(input: &str) -> Option<Edge> {
    match input.trim().to_ascii_lowercase().chars().next()? {
        'r' => Some(Edge::Right),
        'l' => Some(Edge::Left),
        'u' | 't' => Some(Edge::Top),
        'd' | 'b' => Some(Edge::Bottom),
        _ => None,
    }
}

/// A host, or a host and port, as a socket address.
///
/// A bare name that does not resolve is retried as an mDNS one. The offering
/// machine prints its short hostname, which is the readable thing to type, and
/// on a LAN with no search domain only `ember.local` actually resolves. mDNS is
/// already how machines find each other here, so meeting the hint halfway costs
/// one extra lookup on a path that has already failed.
pub fn resolve(input: &str) -> Result<SocketAddr> {
    match lookup(input) {
        Ok(address) => Ok(address),
        Err(error) if !input.contains('.') && !input.contains(':') => {
            lookup(&format!("{input}.local")).map_err(|_| error)
        }
        Err(error) => Err(error),
    }
}

fn lookup(input: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs as _;

    // A bare host is far more likely than a host with a port, since the port is
    // the same on every machine and typing it is noise.
    let with_port = if input.contains(':') {
        input.to_owned()
    } else {
        format!("{input}:{DEFAULT_PAIR_PORT}")
    };

    with_port
        .to_socket_addrs()
        .map_err(|error| Error::Config(format!("cannot resolve {input}: {error}")))?
        .next()
        .ok_or_else(|| Error::Config(format!("{input} resolved to no address")))
}

/// Accepts any certificate, because pinning is what pairing establishes.
///
/// Safe only because SPAKE2 runs on top and nothing reaches the trust store
/// without completing it. Deliberately private to this module so it cannot be
/// reached from the session path by accident.
#[derive(Debug)]
struct AcceptAnyPeer(Arc<rustls::crypto::CryptoProvider>);

impl AcceptAnyPeer {
    fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyPeer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn credentials(
    identity: &Identity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let credentials = identity
        .certificate()
        .map_err(|error| Error::Config(error.to_string()))?;

    Ok((
        vec![CertificateDer::from(credentials.certificate_der)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(credentials.key_der.to_vec())),
    ))
}

pub fn pairing_server(identity: &Identity, port: u16) -> Result<Endpoint> {
    let (chain, key) = credentials(identity)?;

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| Error::Config(error.to_string()))?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(|error| Error::Config(error.to_string()))?;

    tls.alpn_protocols = vec![PAIRING_ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| Error::Config(error.to_string()))?;
    let address: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .map_err(|_| Error::Config(format!("{port} is not a usable port")))?;

    Endpoint::server(ServerConfig::with_crypto(Arc::new(quic)), address).map_err(Error::Io)
}

pub fn pairing_client(identity: &Identity) -> Result<Endpoint> {
    let (chain, key) = credentials(identity)?;

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| Error::Config(error.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyPeer::new()))
    .with_client_auth_cert(chain, key)
    .map_err(|error| Error::Config(error.to_string()))?;

    tls.alpn_protocols = vec![PAIRING_ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| Error::Config(error.to_string()))?;

    let mut endpoint =
        Endpoint::client("0.0.0.0:0".parse().expect("a valid bind address")).map_err(Error::Io)?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic)));

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server's port on the loopback interface.
    ///
    /// `local_addr` reports `0.0.0.0`, which is a bind address rather than a
    /// destination, and quinn rightly refuses to dial it.
    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        let port = endpoint.local_addr().unwrap().port();
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn a_recorded_address_points_at_the_session_not_the_pairing_port() {
        // The pairing endpoint exists only while an offer is outstanding.
        // Recording it left two machines dialling a port nothing would answer
        // on again, and the cursor stopped dead at the screen edge.
        let dialled: SocketAddr = "192.168.6.108:24811".parse().unwrap();

        let recorded = session_address(dialled);

        assert_eq!(recorded.ip(), dialled.ip(), "the host carries over");
        assert_eq!(recorded.port(), DEFAULT_PORT);
    }

    #[test]
    fn a_side_is_parsed_from_a_letter_or_a_word() {
        // Whoever is typing has just read a six-digit code aloud. One letter is
        // enough, and so is the whole word.
        assert_eq!(parse_side("r"), Some(Edge::Right));
        assert_eq!(parse_side("right"), Some(Edge::Right));
        assert_eq!(parse_side("  LEFT \n"), Some(Edge::Left));
        assert_eq!(parse_side("up"), Some(Edge::Top));
        assert_eq!(parse_side("down"), Some(Edge::Bottom));
    }

    #[test]
    fn an_unrecognised_side_is_not_guessed_at() {
        // The caller turns this into the default. Guessing here would make a
        // typo silently mean something.
        assert_eq!(parse_side("sideways"), None);
        assert_eq!(parse_side(""), None);
        assert_eq!(parse_side("   "), None);
    }

    #[test]
    fn the_join_hint_omits_the_default_port() {
        // The port is the same everywhere, so mentioning it is noise.
        assert!(!join_hint(DEFAULT_PAIR_PORT).contains(':'));
        assert!(join_hint(9999).ends_with(":9999"));
    }

    #[test]
    fn a_bare_host_gets_the_default_port() {
        // The port is the same on every machine, so typing it is noise.
        let address = resolve("127.0.0.1").unwrap();

        assert_eq!(address.port(), DEFAULT_PAIR_PORT);
    }

    #[test]
    fn an_explicit_port_is_honoured() {
        let address = resolve("127.0.0.1:9999").unwrap();

        assert_eq!(address.port(), 9999);
    }

    #[test]
    fn an_unresolvable_host_names_itself_in_the_error() {
        let error = resolve("no-such-host.invalid").unwrap_err().to_string();

        assert!(error.contains("no-such-host.invalid"), "got {error}");
    }

    #[tokio::test]
    async fn two_machines_with_the_same_code_pair() {
        // The whole flow over a real QUIC connection, which is the only way to
        // catch a framing or ordering mistake between the two sides.
        let code = PairingCode::generate();
        let left = Identity::generate();
        let right = Identity::generate();
        let (left_id, right_id) = (left.peer_id(), right.peer_id());

        let server = pairing_server(&left, 0).unwrap();
        let address = loopback(&server);

        let offered_code = code.clone();
        let accepting = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            exchange(&left, "left", &offered_code, None, send, recv).await
        });

        let client = pairing_client(&right).unwrap();
        let connection = client.connect(address, "wraith").unwrap().await.unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        let joined = exchange(&right, "right", &code, Some(Edge::Right), send, recv)
            .await
            .unwrap();

        let offered = accepting.await.unwrap().unwrap();

        assert_eq!(
            joined.peer.key,
            encode_hex(&left_id.0),
            "the joiner learned the wrong key"
        );
        assert_eq!(
            offered.peer.key,
            encode_hex(&right_id.0),
            "the offerer learned the wrong key"
        );
        assert_eq!(joined.peer.name, "left");
        assert_eq!(offered.peer.name, "right");
    }

    #[tokio::test]
    async fn a_wrong_code_refuses_the_pairing() {
        // The attacker's single online guess. It must fail on both sides and
        // leave nothing behind.
        let left = Identity::generate();
        let right = Identity::generate();

        let server = pairing_server(&left, 0).unwrap();
        let address = loopback(&server);

        let accepting = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            exchange(
                &left,
                "left",
                &PairingCode::parse("111111").unwrap(),
                None,
                send,
                recv,
            )
            .await
        });

        let client = pairing_client(&right).unwrap();
        let connection = client.connect(address, "wraith").unwrap().await.unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        let joined = exchange(
            &right,
            "right",
            &PairingCode::parse("222222").unwrap(),
            Some(Edge::Right),
            send,
            recv,
        )
        .await;

        assert!(joined.is_err(), "a wrong code must not pair");
        assert!(
            accepting.await.unwrap().is_err(),
            "the offering side must refuse too"
        );
    }
}
