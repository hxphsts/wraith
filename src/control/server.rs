//! The session's half of the control socket.
//!
//! One task per client. A client that stalls or vanishes costs one task and
//! nothing else, which is why a pairing lasting two minutes does not hold up a
//! status poll arriving every second.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;
use tokio::sync::Mutex;

use super::{PeerStatus, Refusal, Request, Response, Status, read_frame};
use crate::domain::Edge;
use crate::error::Error;
use crate::net::Identity;
use crate::net::endpoint::DEFAULT_PAIR_PORT;
use crate::net::pairing::PairingCode;
use crate::net::wire;
use crate::platform::socket::{self, ControlListener, ControlStream};
use crate::run::pair;
use crate::run::serve::{CaptureState, Outgoing, Roster};
use crate::run::watch::Watchers;

/// How long a pairing offer stays open.
const PAIRING_SECONDS_MAX: u64 = 120;

/// Everything the control socket is allowed to see and do.
///
/// One struct rather than nine arguments. Everything on it is already shared,
/// so cloning is a handful of `Arc` bumps.
#[derive(Clone)]
pub(crate) struct Handle {
    pub identity: Arc<Identity>,
    pub name: String,
    pub listen: SocketAddr,
    pub clock_started: Instant,
    pub outgoing: Outgoing,
    pub roster: Roster,
    pub capture: CaptureState,
    pub stop: tokio::sync::watch::Sender<bool>,
    /// At most one pairing at a time, and it says so out loud.
    ///
    /// Two windows both offering would race for the pairing port and show two
    /// codes, only one of which could work. Refusing the second is clearer than
    /// letting them fight.
    pub pairing: PairingSlot,

    /// Handed to every `Watch` connection.
    pub watchers: Watchers,
}

/// The one pairing a session runs at a time.
///
/// More than exclusion, because the window needs two answers a bare mutex
/// cannot give: whether an offer is running, and how to end one this window did
/// not start. A window that has just been reopened knows neither, and without
/// both it meets a refusal it has no way to clear.
#[derive(Clone, Default)]
pub(crate) struct PairingSlot {
    busy: Arc<Mutex<()>>,

    /// Session uptime at which the running offer gives up, or zero for none.
    ///
    /// Uptime rather than a wall clock, because `Status` already carries
    /// `uptime_ms` and the window can subtract without the two machines having
    /// to agree what time it is.
    until_ms: Arc<std::sync::atomic::AtomicU64>,

    ends: Arc<tokio::sync::Notify>,
}

impl PairingSlot {
    /// Ends the running offer, if there is one.
    fn end(&self) {
        self.ends.notify_waiters();
    }

    /// How much longer the running offer has, if one is running.
    fn left_ms(&self, uptime_ms: u64) -> Option<u64> {
        let until = self.until_ms.load(std::sync::atomic::Ordering::Relaxed);

        (until > uptime_ms).then(|| until - uptime_ms)
    }
}

/// Clears the deadline however the offer ends.
///
/// A `Drop` rather than a line at the bottom of `on_pair_offer`, because that
/// function leaves through a refusal, a cancel, a timeout and a success, and a
/// deadline left behind means a window told forever that a pairing is running.
struct Running(Arc<std::sync::atomic::AtomicU64>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Starts listening, if the socket can be bound.
///
/// A session that cannot bind still runs. The control socket is how the window
/// talks to it, and losing that is worth a warning rather than refusing to
/// share a keyboard.
pub(crate) fn spawn(handle: Handle) -> Option<tokio::task::JoinHandle<()>> {
    let listener = match socket::control_listen() {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(%error, "no control socket, so the window cannot reach this session");
            return None;
        }
    };

    tracing::info!(path = %socket::control_path().display(), "listening for the window");
    Some(tokio::spawn(accept_loop(handle, listener)))
}

async fn accept_loop(handle: Handle, listener: ControlListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(serve_client(handle.clone(), stream));
            }
            Err(error) => {
                tracing::warn!(%error, "the control socket stopped accepting");
                return;
            }
        }
    }
}

async fn serve_client(handle: Handle, mut stream: ControlStream) {
    let payload = match read_frame(&mut stream).await {
        Ok(payload) => payload,
        Err(error) => {
            tracing::debug!(%error, "an unreadable control request");
            return;
        }
    };

    let Ok(request) = wire::decode::<Request>(&payload) else {
        // Almost certainly a different build. Say so rather than going quiet,
        // since a window that hangs is worse than one that reports a mismatch.
        let _ = reply(
            &mut stream,
            &Response::Refused(Refusal::Incompatible { theirs: 0 }),
        )
        .await;
        return;
    };

    if let Err(error) = on_request(&handle, request, &mut stream).await {
        tracing::debug!(%error, "a control request ended early");
    }
}

async fn on_request(
    handle: &Handle,
    request: Request,
    out: &mut ControlStream,
) -> std::io::Result<()> {
    match request {
        Request::Status => reply(out, &Response::Status(Box::new(status_of(handle)))).await,

        Request::Stop => {
            // Acknowledged first. Afterwards there is nothing left to answer
            // with, and a window waiting for a reply would wait forever.
            reply(out, &Response::Ack).await?;
            tracing::info!("stopping, asked by the window");
            let _ = handle.stop.send(true);
            Ok(())
        }

        Request::Reload => {
            handle.roster.reload();
            reply(out, &Response::Ack).await
        }

        Request::Candidates => {
            let found = handle.roster.candidates();
            reply(out, &Response::Candidates(found)).await
        }

        Request::Forget { name } => on_forget(handle, &name, out).await,

        Request::PairCancel => {
            handle.pairing.end();
            reply(out, &Response::Ack).await
        }

        Request::Watch => on_watch(&handle.watchers, out).await,

        Request::PairOffer { side } => on_pair_offer(handle, side, out).await,

        Request::PairJoin {
            address,
            code,
            side,
        } => on_pair_join(handle, &address, &code, side, out).await,
    }
}

/// Untrusts a machine and takes it off the desk.
async fn on_forget(handle: &Handle, name: &str, out: &mut ControlStream) -> std::io::Result<()> {
    let forgotten = match crate::peers::forget_named(name) {
        Ok(forgotten) => forgotten,
        Err(error) => return refuse(out, &error).await,
    };

    // Immediately. Until the live trust set drops the key, the machine just
    // forgotten can still complete a handshake.
    handle.roster.reload();

    tracing::info!(
        name = %forgotten.name,
        unplaced = forgotten.unplaced,
        "forgot a machine"
    );
    reply(out, &Response::Ack).await
}

/// Offers pairing, streaming the code and then the outcome.
///
/// Two ways out, and both are needed. The client closing the connection drops
/// the offer future, the endpoint goes with it, and the pairing port is
/// released: that covers the caller giving up while it is still there to give
/// up. A closed window is not there to close anything, so `PairCancel` ends the
/// offer from another connection entirely.
async fn on_pair_offer(
    handle: &Handle,
    side: Option<Edge>,
    out: &mut ControlStream,
) -> std::io::Result<()> {
    let Ok(_busy) = handle.pairing.busy.try_lock() else {
        return reply(out, &Response::Refused(Refusal::Busy)).await;
    };

    let uptime_ms = uptime_of(handle);
    handle.pairing.until_ms.store(
        uptime_ms.saturating_add(PAIRING_SECONDS_MAX.saturating_mul(1_000)),
        std::sync::atomic::Ordering::Relaxed,
    );
    let _running = Running(Arc::clone(&handle.pairing.until_ms));

    let offer = match pair::Offer::open(&handle.identity, DEFAULT_PAIR_PORT) {
        Ok(offer) => offer,
        Err(error) => return refuse(out, &error).await,
    };

    reply(
        out,
        &Response::PairingCode {
            code: offer.code().to_string(),
            join_hint: pair::join_hint(offer.port()),
            seconds_max: PAIRING_SECONDS_MAX,
        },
    )
    .await?;

    let waiting = offer.accept(
        &handle.identity,
        &handle.name,
        side,
        Duration::from_secs(PAIRING_SECONDS_MAX),
    );

    // Whichever finishes first. A closed connection means the user gave up, and
    // dropping the future here is what releases the unauthenticated port.
    let paired = tokio::select! {
        outcome = waiting => outcome,
        () = closed(out) => {
            tracing::info!("the pairing was cancelled");
            return Ok(());
        }
        () = handle.pairing.ends.notified() => {
            tracing::info!("the pairing was cancelled from elsewhere");
            return reply(out, &Response::Refused(Refusal::Cancelled)).await;
        }
    };

    settle(handle, paired, None, out).await
}

async fn on_pair_join(
    handle: &Handle,
    address: &str,
    code: &str,
    side: Option<Edge>,
    out: &mut ControlStream,
) -> std::io::Result<()> {
    // No lock. The mutex guards the pairing **port**, which only an offer
    // binds; a join takes an ephemeral one and shares nothing.
    //
    // Taking it here was a real bug: the window offers the moment its panel
    // opens, so on two machines that can both bind, each side held its own
    // offer for two minutes and neither could ever join the other. The panel
    // shows both halves at once precisely so either may be used, and the
    // session has to allow that.
    let address = match pair::resolve(address) {
        Ok(address) => address,
        Err(error) => return refuse(out, &error).await,
    };
    let code = match PairingCode::parse(code) {
        Ok(code) => code,
        Err(error) => {
            return reply(out, &Response::Refused(Refusal::Config(error.to_string()))).await;
        }
    };

    let paired = pair::join_once(&handle.identity, &handle.name, address, &code, side).await;
    settle(handle, paired, Some(address), out).await
}

/// Records a finished pairing and tells the client what happened.
async fn settle(
    handle: &Handle,
    paired: crate::error::Result<pair::Paired>,
    address: Option<SocketAddr>,
    out: &mut ControlStream,
) -> std::io::Result<()> {
    let paired = match paired {
        Ok(paired) => paired,
        Err(error) => return refuse(out, &error).await,
    };

    let recorded = match pair::record(&paired, address) {
        Ok(recorded) => recorded,
        Err(error) => return refuse(out, &error).await,
    };

    // Immediately, rather than at the next poll. The machine is trusted, dialled
    // and on the desk before the window has finished drawing the confirmation.
    handle.roster.reload();

    reply(
        out,
        &Response::Paired {
            name: recorded.name,
            key: paired.key().to_owned(),
            placed: recorded.desk.is_some(),
        },
    )
    .await
}

/// Milliseconds since this session started.
fn uptime_of(handle: &Handle) -> u64 {
    u64::try_from(handle.clock_started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn status_of(handle: &Handle) -> Status {
    let peers = handle.roster.snapshot();
    let uptime_ms = uptime_of(handle);

    Status {
        protocol: super::CONTROL_VERSION,
        name: handle.name.clone(),
        listen: handle.listen.to_string(),
        uptime_ms,
        pairing_left_ms: handle.pairing.left_ms(uptime_ms),
        backend_capture: handle.capture.backend(),
        peers: peers
            .peer
            .iter()
            .map(|peer| PeerStatus {
                name: peer.name.clone(),
                key: peer.key.clone(),
                connected: peer
                    .peer_id()
                    .is_some_and(|id| handle.outgoing.is_connected(id)),
                address: peer.address.clone(),
            })
            .collect(),
    }
}

/// Turns an internal error into something the window can act on.
///
/// Only the cases a window does something different about are typed. Everything
/// else is the message, because inventing a variant nobody branches on is worse
/// than carrying the sentence.
async fn refuse(out: &mut ControlStream, error: &Error) -> std::io::Result<()> {
    reply(out, &Response::Refused(classify(error))).await
}

/// Which refusal an internal error is, so far as a window can tell.
///
/// By message, which is not lovely, but the alternative is a typed error
/// travelling from `net::pairing` through two layers that have no opinion about
/// it. The two cases here are the only ones the window branches on, and a
/// misclassification costs a slightly worse sentence rather than a wrong action.
fn classify(error: &Error) -> Refusal {
    let text = error.to_string();

    if text.contains("do not match") {
        Refusal::CodeMismatch
    } else if text.contains("before the timeout") {
        Refusal::Timeout
    } else {
        Refusal::Peer(text)
    }
}

async fn reply(out: &mut ControlStream, response: &Response) -> std::io::Result<()> {
    let bytes = wire::encode(response).map_err(|error| std::io::Error::other(error.to_string()))?;

    out.write_all(&bytes).await?;
    out.flush().await
}

/// Streams crossings until the caller hangs up.
///
/// Two things end this: the client closing the socket, which is how a window
/// stops watching, and the broadcast lagging, which means this watcher fell far
/// enough behind that it is drawing history. Both are ordinary.
async fn on_watch(watchers: &Watchers, out: &mut ControlStream) -> std::io::Result<()> {
    let mut crossings = watchers.subscribe();

    loop {
        tokio::select! {
            received = crossings.recv() => match received {
                Ok(crossed) => reply(out, &Response::Crossed(crossed)).await?,

                // Dropping a watcher that cannot keep up beats letting it
                // draw effects for crossings that finished long ago.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, "a watcher fell behind, dropping it");
                    return Ok(());
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
            },

            () = closed(out) => return Ok(()),
        }
    }
}

/// Returns when the client goes away.
///
/// The client sends exactly one request and then only reads, so anything
/// arriving here is the connection ending.
async fn closed(stream: &mut ControlStream) {
    use tokio::io::AsyncReadExt as _;

    let mut scratch = [0_u8; 1];
    loop {
        match stream.read(&mut scratch).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Crossed;
    use tokio::net::UnixStream;

    #[test]
    fn a_slot_with_nothing_in_it_reports_no_pairing() {
        let slot = PairingSlot::default();

        assert_eq!(slot.left_ms(0), None);
        assert_eq!(slot.left_ms(9_999), None);
    }

    #[test]
    fn a_running_offer_reports_what_is_left_of_it() {
        // Uptime in, uptime out. The window subtracts against the `uptime_ms`
        // in the same status, so neither side needs a wall clock.
        let slot = PairingSlot::default();
        slot.until_ms
            .store(5_000, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(slot.left_ms(1_000), Some(4_000));
        assert_eq!(slot.left_ms(4_900), Some(100));
    }

    #[test]
    fn an_offer_that_has_run_out_reports_nothing_rather_than_wrapping() {
        // These are unsigned, so a subtraction the wrong way round would report
        // a pairing with several million years left on it.
        let slot = PairingSlot::default();
        slot.until_ms
            .store(5_000, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(slot.left_ms(5_000), None);
        assert_eq!(slot.left_ms(6_000), None);
    }

    #[test]
    fn the_deadline_is_cleared_however_the_offer_ends() {
        // `on_pair_offer` leaves through a refusal, a cancel, a timeout and a
        // success. A deadline left behind is a window told forever that a
        // pairing it cannot see is running.
        let slot = PairingSlot::default();
        slot.until_ms
            .store(5_000, std::sync::atomic::Ordering::Relaxed);

        {
            let _running = Running(Arc::clone(&slot.until_ms));
            assert_eq!(slot.left_ms(0), Some(5_000));
        }

        assert_eq!(slot.left_ms(0), None, "the guard clears it on the way out");
    }

    #[test]
    fn a_mismatched_code_is_typed_rather_than_a_sentence() {
        // The window puts the cursor back in the code field for this one, so it
        // has to survive the trip as something it can branch on.
        //
        // Built from the error the pairing actually returns rather than from a
        // copy of its wording. `classify` matches on that text, so a reword
        // upstream has to fail here rather than silently degrading every
        // mismatch to `Refusal::Peer`.
        let error = Error::Config(crate::net::pairing::PairingError::CodeMismatch.to_string());

        assert!(matches!(classify(&error), Refusal::CodeMismatch));
    }

    #[test]
    fn a_timeout_is_typed_so_the_same_code_can_be_offered_again() {
        // Same coupling, to the one place the sentence is written.
        let error = Error::Config(Refusal::Timeout.to_string());

        assert!(matches!(classify(&error), Refusal::Timeout));
    }

    #[test]
    fn anything_else_keeps_its_sentence() {
        let error = Error::Config("the compositor has no virtual pointer".to_owned());

        match classify(&error) {
            Refusal::Peer(text) => assert!(text.contains("virtual pointer")),
            other => panic!("expected the sentence to survive, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_watcher_is_sent_a_crossing_over_the_socket() {
        // End to end over a real unix socket rather than against the broadcast
        // alone, because the thing that breaks is the framing and the encode,
        // not the channel.
        use crate::domain::{Direction as DomainDirection, Edge, Fraction};

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let watchers = Watchers::new();

        let serving = tokio::spawn({
            let watchers = watchers.clone();
            async move { on_watch(&watchers, &mut server).await }
        });

        // The subscribe happens inside the task, so announcing before it lands
        // would send to nobody and the read below would hang.
        while !watchers.any() {
            tokio::task::yield_now().await;
        }

        let sent = Crossed::new(DomainDirection::Arrival, Edge::Left, Fraction::new(0.25));
        watchers.announce(sent);

        let payload = super::read_frame(&mut client).await.unwrap();
        let response: Response = wire::decode(&payload).unwrap();

        assert_eq!(response, Response::Crossed(sent));

        // Hanging up is how a watcher unsubscribes, and the stream must end
        // rather than leaking a task per window that was ever opened.
        drop(client);
        assert!(serving.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn a_watcher_that_hangs_up_ends_the_stream() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let watchers = Watchers::new();

        let serving = tokio::spawn({
            let watchers = watchers.clone();
            async move { on_watch(&watchers, &mut server).await }
        });

        while !watchers.any() {
            tokio::task::yield_now().await;
        }
        drop(client);

        assert!(serving.await.unwrap().is_ok(), "the stream ends on hangup");
    }
}
