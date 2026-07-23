//! The control socket, and where this operating system keeps one.
//!
//! # Why a unix socket
//!
//! The window and a running session are separate processes, and the window has
//! to be able to ask questions a file cannot answer: whether a peer is actually
//! connected, and what the capture backend made of this machine.
//!
//! Not a loopback TCP port. Loopback is not restricted to the same user, so a
//! control port would let any local account stop the session and drive the
//! pairing flow. A unix socket carries filesystem permissions, which is exactly
//! the authorisation model wanted here.
//!
//! # Why same-user is the whole of the authorisation
//!
//! A process running as this user can already read `identity.pem`, rewrite
//! `peers.toml`, and attach a debugger to the session. There is no privilege
//! boundary between it and the daemon, so a token or a challenge would be
//! ceremony protecting nothing. The boundary that matters is the uid, and the
//! kernel enforces it. Hence 0600 in a 0700 directory and no handshake.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// The listening half, owned by a running session.
pub type ControlListener = tokio::net::UnixListener;

/// One accepted client, from the session's side.
pub type ControlStream = tokio::net::UnixStream;

/// The connecting half, used by the window and the CLI.
///
/// Blocking, deliberately. The window has no tokio runtime and adding one to
/// draw a rectangle is a cost with no return.
pub type ControlClient = std::os::unix::net::UnixStream;

/// Whether anything is listening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// A session is running and answering.
    Running,
    /// Nothing is there.
    Absent,
    /// A socket file exists but refuses. A session was killed without cleaning
    /// up. Indistinguishable from `Absent` to anyone but the next daemon to
    /// start, which is the only place it is safe to act on.
    Stale,
}

/// Where the daemon listens.
///
/// `$TMPDIR` on macOS rather than Application Support, because `sun_path` is
/// 104 bytes there and a long home directory plus a long path is close enough
/// to the limit to fail on somebody else's machine. macOS already gives each
/// user a private `/var/folders/...` at mode 0700.
#[must_use]
pub fn control_path() -> PathBuf {
    path_or_runtime_dir(std::env::var_os("WRAITH_CONTROL_SOCKET"))
}

/// The override resolution, split out so a test can exercise it without setting
/// a process-wide variable that races every other test under one `cargo test`.
fn path_or_runtime_dir(explicit: Option<OsString>) -> PathBuf {
    explicit.map_or_else(|| runtime_dir().join("control.sock"), PathBuf::from)
}

#[cfg(target_os = "macos")]
fn runtime_dir() -> PathBuf {
    std::env::var_os("TMPDIR")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join("wraith")
}

#[cfg(not(target_os = "macos"))]
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map_or_else(
            || {
                // Not /tmp/wraith, which any user could have created first and
                // would then own. The uid in the name makes it ours or nobody's.
                std::env::temp_dir().join(format!("wraith-{}", uid()))
            },
            PathBuf::from,
        )
        .join("wraith")
}

/// Binds, clearing a socket left behind by a session that was killed.
///
/// **Connects before it unlinks.** A socket that answers means another Wraith
/// is already running and this one must not displace it; one that refuses is a
/// corpse. Doing it in that order makes the daemon single-instance without a
/// lock file, and is the only moment at which removing the file is safe.
///
/// Clients never unlink. A client tidying up races a daemon halfway through
/// binding, and the daemon is the only party that knows it is about to own it.
pub fn control_listen() -> io::Result<ControlListener> {
    // An override names a directory this process did not create, so a parent it
    // cannot tighten is tolerated there and fatal on the path Wraith picks.
    let tolerate_loose_parent = std::env::var_os("WRAITH_CONTROL_SOCKET").is_some();
    listen_at(&control_path(), tolerate_loose_parent)
}

/// Binds at an explicit path, so a test drives the single-instance logic against
/// its own socket rather than through the shared `WRAITH_CONTROL_SOCKET`.
fn listen_at(path: &Path, tolerate_loose_parent: bool) -> io::Result<ControlListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;

        // Fatal on the path Wraith picks for itself, because that leaf
        // directory is one it creates and same-user permissions are the whole
        // of the authorisation for this socket. A directory another account can
        // write to makes the 0600 below beside the point: they cannot read the
        // socket, but they can unlink it and bind their own in its place.
        if let Err(error) = restrict(parent, 0o700) {
            if tolerate_loose_parent {
                tracing::debug!(%error, parent = %parent.display(), "cannot tighten the socket directory");
            } else {
                return Err(error);
            }
        }
    }

    if matches!(probe_at(path), Presence::Running) {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "another wraith is already running on this machine",
        ));
    }
    let _ = std::fs::remove_file(path);

    let listener = ControlListener::bind(path)?;
    restrict(path, 0o600)?;

    Ok(listener)
}

/// Connects, blocking.
pub fn control_connect() -> io::Result<ControlClient> {
    control_connect_at(&control_path())
}

/// Connects at an explicit path, so the client layer can be tested against a
/// socket it names rather than through the shared environment variable.
pub(crate) fn control_connect_at(path: &Path) -> io::Result<ControlClient> {
    ControlClient::connect(path)
}

/// Whether a session is listening, without sending a request.
#[must_use]
pub fn control_probe() -> Presence {
    probe_at(&control_path())
}

pub(crate) fn probe_at(path: &Path) -> Presence {
    if !path.exists() {
        return Presence::Absent;
    }

    match ControlClient::connect(path) {
        Ok(_) => Presence::Running,
        Err(_) => Presence::Stale,
    }
}

/// Removes the socket on the way out.
///
/// Best effort. A `SIGKILL` skips it, which is what the connect-before-unlink
/// order in [`control_listen`] exists to survive.
pub fn control_unlink() {
    let _ = std::fs::remove_file(control_path());
}

#[cfg(unix)]
fn restrict(path: &std::path::Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Scoped to where it is used. macOS takes its runtime directory from `$TMPDIR`,
/// which is already per-user, so it never needs a uid in a path.
#[cfg(all(unix, not(target_os = "macos")))]
fn uid() -> u32 {
    // From the kernel rather than from `$UID`, which is a shell variable that
    // no shell exports. A daemon started by systemd, by a launcher, or by the
    // window sees nothing there, so every user on the machine would land on the
    // same directory name and the first to arrive would own it for all of them.
    //
    // SAFETY: `getuid` takes no arguments, is documented as always succeeding,
    // and reads nothing this process owns.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_path_wins_over_the_runtime_directory() {
        assert_eq!(
            path_or_runtime_dir(Some("/tmp/wraith-somewhere.sock".into())),
            PathBuf::from("/tmp/wraith-somewhere.sock"),
        );
    }

    #[test]
    fn nothing_there_reads_as_absent() {
        assert_eq!(
            probe_at(&PathBuf::from("/tmp/wraith-not-here-at-all.sock")),
            Presence::Absent
        );
    }

    #[test]
    fn a_socket_file_that_refuses_reads_as_stale() {
        // A session killed without cleaning up. It must not read as running, or
        // the window would sit waiting for a reply from a corpse. It must not
        // read as absent either, or a starting daemon would refuse to clear it.
        let path = std::env::temp_dir().join("wraith-stale-test.sock");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not a socket").unwrap();

        assert_eq!(probe_at(&path), Presence::Stale);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_second_daemon_refuses_rather_than_displacing_the_first() {
        // The single-instance property, and the reason listen connects before
        // it unlinks. Two sessions in one process would fight over the capture
        // gate and the injector backend.
        let path = std::env::temp_dir().join("wraith-single-instance-test.sock");
        let _ = std::fs::remove_file(&path);

        let first = listen_at(&path, true).unwrap();
        let second = listen_at(&path, true);

        assert!(second.is_err(), "the second bind must refuse");
        assert_eq!(probe_at(&path), Presence::Running);

        drop(first);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn the_runtime_directory_is_named_for_the_real_user() {
        // Checked against the owner of a file this process just created, which
        // is an answer arrived at independently of the one under test.
        //
        // Reading `$UID` instead gave every account on the machine the same
        // directory name, and the first to start owned it for all of them.
        use std::os::unix::fs::MetadataExt as _;

        let probe = std::env::temp_dir().join(format!("wraith-uid-probe-{}", std::process::id()));
        std::fs::write(&probe, b"").unwrap();
        let owner = std::fs::metadata(&probe).unwrap().uid();
        let _ = std::fs::remove_file(&probe);

        assert_eq!(
            uid(),
            owner,
            "the runtime directory is named for someone else"
        );
    }

    #[tokio::test]
    async fn a_stale_socket_is_cleared_by_the_next_daemon() {
        // The other half: a corpse must not lock the machine out for good.
        let path = std::env::temp_dir().join("wraith-corpse-test.sock");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"left behind by a kill").unwrap();

        let listener = listen_at(&path, true).expect("a corpse must not block a fresh start");

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }
}
