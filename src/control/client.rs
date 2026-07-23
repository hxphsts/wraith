//! Talking to a running session, from a process that is not one.
//!
//! Blocking, on ordinary threads. Both callers are sync: the CLI has no runtime
//! and the window draws on gpui's foreground, and adding a tokio runtime to
//! either would be a cost with nothing to show for it. The window keeps these
//! calls off its frame thread instead, which is what `session::spawn_poll` and
//! `session::Watching` are for.

use std::io::Write as _;
use std::path::Path;

use super::{Request, Response, read_frame_blocking};
use crate::error::{Error, Result};
use crate::net::wire;
use crate::platform::socket::{self, ControlClient, Presence};

/// Sends one request and collects every response until the session closes.
///
/// The whole protocol. A status yields one response, a pairing yields several,
/// and both end the same way.
fn call(request: &Request) -> Result<Vec<Response>> {
    let mut responses = Vec::new();

    stream(request, |response| {
        responses.push(response);
        Flow::Continue
    })?;

    Ok(responses)
}

/// Whether a streaming caller wants the rest of the responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// Stop reading and drop the connection.
    ///
    /// Closing the socket is how a caller cancels, which is why this exists
    /// rather than a separate cancel request: the session already treats a
    /// closed connection as the end of the exchange.
    Stop,
}

/// Ends a streaming call from somewhere other than the thread reading it.
///
/// Cancelling is closing the socket, and a caller that spawned a thread to do
/// the reading cannot manage that by dropping its end of a channel: the thread
/// is blocked in [`pump`], and the callback that would notice only runs when a
/// response arrives. For an offer nobody has joined yet, none ever does.
#[derive(Debug)]
pub struct Cancel(ControlClient);

impl Cancel {
    /// Hangs up, which unblocks the reader and ends the exchange.
    pub fn now(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// Opens a streaming call and hands back a way to end it.
///
/// Split from [`stream`] so a caller that reads on another thread can keep hold
/// of something that cancels. The connect and the write happen here, on the
/// caller's thread, so a session that is not running is reported immediately
/// rather than through the channel.
pub fn stream_from(request: &Request) -> Result<(ControlClient, Cancel)> {
    let mut connection = connect()?;
    send(&mut connection, request)?;

    let cancel = Cancel(connection.try_clone().map_err(Error::Io)?);

    Ok((connection, cancel))
}

/// Reads responses until the caller stops, or the far end hangs up.
pub fn pump(
    mut connection: ControlClient,
    mut on_response: impl FnMut(Response) -> Flow,
) -> Result<()> {
    while let Ok(payload) = read_frame_blocking(&mut connection) {
        let Ok(response) = wire::decode::<Response>(&payload) else {
            return Err(Error::Config(
                "the running session sent something this build cannot read, \
                 so the two are different versions"
                    .to_owned(),
            ));
        };

        if on_response(response) == Flow::Stop {
            return Ok(());
        }
    }

    Ok(())
}

/// Sends one request and hands over each response as it arrives.
///
/// Collecting every response first is right for a status and wrong for a
/// pairing. The code has to reach the screen while the offer is still open, and
/// a caller that only sees it once the exchange settles has nothing to read out.
pub fn stream(request: &Request, on_response: impl FnMut(Response) -> Flow) -> Result<()> {
    let (connection, _cancel) = stream_from(request)?;

    pump(connection, on_response)
}

/// Opens the connection, with a sentence rather than an errno when nothing is
/// there.
fn connect() -> Result<ControlClient> {
    connect_at(&socket::control_path())
}

fn connect_at(path: &Path) -> Result<ControlClient> {
    match socket::probe_at(path) {
        Presence::Running => socket::control_connect_at(path).map_err(Error::Io),
        // A corpse and an absence are the same fact to a client: there is
        // nothing to talk to. Only the next session to start may act on the
        // difference, and it does so by clearing it.
        Presence::Absent | Presence::Stale => Err(Error::Config(
            "wraith is not running on this machine. Start it from the window, \
             or run `wraith serve`"
                .to_owned(),
        )),
    }
}

/// Writes one framed request.
fn send(stream: &mut ControlClient, request: &Request) -> Result<()> {
    let bytes = wire::encode(request).map_err(|error| Error::Config(error.to_string()))?;

    stream.write_all(&bytes).map_err(Error::Io)?;
    stream.flush().map_err(Error::Io)
}

/// What a session is doing, or an error saying nothing is.
pub fn status() -> Result<super::Status> {
    match call(&Request::Status)?.into_iter().next() {
        Some(Response::Status(status)) => Ok(*status),
        Some(Response::Refused(refusal)) => Err(Error::Config(refusal.to_string())),
        _ => Err(Error::Config(
            "the running session did not answer with a status".to_owned(),
        )),
    }
}

/// Machines seen on the LAN that are not paired yet.
///
/// Only a running session can answer: discovery is its listener, and the config
/// file records what is already paired rather than what is merely reachable.
pub fn candidates() -> Result<Vec<super::Candidate>> {
    match call(&Request::Candidates)?.into_iter().next() {
        Some(Response::Candidates(found)) => Ok(found),
        Some(Response::Refused(refusal)) => Err(Error::Config(refusal.to_string())),
        _ => Err(Error::Config(
            "the running session did not answer with candidates".to_owned(),
        )),
    }
}

/// Asks a session to stop.
pub fn stop() -> Result<()> {
    expect_ack(call(&Request::Stop)?)
}

/// Ends a pairing offer this caller did not open.
pub fn pair_cancel() -> Result<()> {
    expect_ack(call(&Request::PairCancel)?)
}

/// Asks a session to re-read its files now.
pub fn reload() -> Result<()> {
    expect_ack(call(&Request::Reload)?)
}

fn expect_ack(responses: Vec<Response>) -> Result<()> {
    match responses.into_iter().next() {
        Some(Response::Ack) => Ok(()),
        Some(Response::Refused(refusal)) => Err(Error::Config(refusal.to_string())),
        _ => Err(Error::Config(
            "the running session did not acknowledge".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    #[test]
    fn nothing_running_says_so_rather_than_returning_an_errno() {
        // The first thing anyone hits, and "No such file or directory" is not
        // an answer a person can act on. An explicit absent path rather than the
        // shared environment variable, so this never races the socket tests.
        let error = connect_at(Path::new("/tmp/wraith-nothing-here.sock"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("not running"), "got {error}");
        assert!(error.contains("wraith serve"), "and says what to do");
    }

    #[test]
    fn cancelling_ends_a_read_that_nothing_is_going_to_answer() {
        // The shape of a pairing offer: the far end is alive and simply has
        // nothing to say yet, because nobody has joined. This is the state a
        // dropped channel cannot get out of, and the state a window sat in for
        // two minutes while its session held the pairing port.
        let (reader, _far_end) = UnixStream::pair().unwrap();
        let cancel = Cancel(reader.try_clone().unwrap());

        let (done, finished) = channel();
        std::thread::spawn(move || {
            let outcome = pump(reader, |_| Flow::Continue);
            let _ = done.send(outcome.is_ok());
        });

        cancel.now();

        let ended = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("cancelling must end the read, and nothing else will");

        assert!(ended, "hanging up is an ordinary end, not a failure");
    }

    #[test]
    fn a_cancel_that_is_never_used_leaves_the_exchange_alone() {
        // `stream` builds one and drops it immediately. Closing the clone must
        // not take the original connection with it.
        let (reader, mut far_end) = UnixStream::pair().unwrap();

        {
            let _unused = Cancel(reader.try_clone().unwrap());
        }

        far_end.write_all(b"x").unwrap();
        far_end.flush().unwrap();

        let mut seen = [0_u8; 1];
        assert!(
            std::io::Read::read_exact(&mut { reader }, &mut seen).is_ok(),
            "the connection outlives a dropped cancel"
        );
    }
}
