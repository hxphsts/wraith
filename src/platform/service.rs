//! Starting a session that outlives whoever started it.
//!
//! The window may be closed. Sharing a keyboard should not stop because
//! somebody tidied their desktop, so the session is a detached process in its
//! own process group rather than a child that dies with its parent.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::net::identity::config_dir;
use crate::platform::socket::{self, Presence};

/// How long to wait for a started session to answer.
const START_MS_MAX: u64 = 3_000;

/// How often to check while waiting.
const START_POLL_MS: u64 = 50;

/// Where a detached session's output goes.
///
/// Truncated at each start, so it holds the reason for the current run rather
/// than growing without bound. Without it a session that exits immediately does
/// so with nothing to show for it, which is the failure a user is most likely to
/// hit and least able to explain.
#[must_use]
pub fn log_path() -> PathBuf {
    config_dir().join("wraith.log")
}

/// Starts a detached session and waits for its socket to answer.
///
/// The wait is the point. Returning the moment the process is spawned would
/// report success for a session that dies half a second later because the
/// compositor is missing a protocol, and the window would show "not sharing"
/// with no explanation.
pub fn start_detached() -> Result<()> {
    if matches!(socket::control_probe(), Presence::Running) {
        return Ok(());
    }

    spawn(&log_path())?;

    let deadline = Instant::now() + Duration::from_millis(START_MS_MAX);
    while Instant::now() < deadline {
        if matches!(socket::control_probe(), Presence::Running) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(START_POLL_MS));
    }

    Err(Error::Backend(format!(
        "wraith started but did not answer within {}ms.\n{}",
        START_MS_MAX,
        last_words(&log_path())
    )))
}

#[cfg(unix)]
fn spawn(log: &std::path::Path) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let exe = session_binary(&std::env::current_exe().map_err(Error::Io)?);
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    let out = std::fs::File::create(log).map_err(Error::Io)?;
    let err = out.try_clone().map_err(Error::Io)?;

    std::process::Command::new(exe)
        .arg("serve")
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err)
        // Its own process group, so a ctrl-c in the terminal that launched the
        // window does not take the session with it.
        .process_group(0)
        .spawn()
        .map_err(Error::Io)?;

    Ok(())
}

/// Which binary runs the session.
///
/// Not always this one. The CLI is `wraith` and starting a session from it means
/// re-running itself, but the window is `wraith-app`, which parses no arguments
/// at all: spawning `current_exe() serve` from there opens a second window and
/// reports success. So the sibling is preferred when this process is not the CLI.
///
/// Falling back to a bare name lets `PATH` answer, which is right for an
/// installed pair that does not sit in one directory.
fn session_binary(current: &Path) -> PathBuf {
    if current.file_stem().is_some_and(|name| name == "wraith") {
        return current.to_owned();
    }

    // Beside whatever is running, which is where every layout puts it: the
    // build directory, the installed bundle, and the AppImage all keep the two
    // binaries together.
    let sibling = current.with_file_name("wraith");
    if sibling.is_file() && !same_file(&sibling, current) {
        return sibling;
    }

    PathBuf::from("wraith")
}

/// Whether two paths name the same file on disk.
///
/// Needed because macOS filesystems are case insensitive by default, so from an
/// app bundle's `MacOS/Wraith` the sibling `wraith` resolves straight back to
/// the window. Spawning that is the exact bug the sibling lookup exists to
/// avoid, arriving by a different route.
fn same_file(one: &Path, other: &Path) -> bool {
    match (std::fs::canonicalize(one), std::fs::canonicalize(other)) {
        (Ok(one), Ok(other)) => one == other,
        // An unreadable path is not a match, and the caller has a fallback.
        _ => false,
    }
}

/// The tail of the log, for an error that would otherwise say nothing.
fn last_words(log: &std::path::Path) -> String {
    const LINES_MAX: usize = 6;

    let Ok(text) = std::fs::read_to_string(log) else {
        return format!("Nothing was written to {}", log.display());
    };

    let tail: Vec<&str> = text.lines().rev().take(LINES_MAX).collect();
    if tail.is_empty() {
        return format!("Nothing was written to {}", log.display());
    }

    tail.into_iter()
        .rev()
        .map(plain)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strips terminal colour codes.
///
/// The session logs through `tracing`, which colours its output whether the
/// sink is a terminal or a file, so the log this reads is full of escapes. They
/// are invisible in a terminal and arrive in the window as literal `[32m`,
/// which turns an error message that names the actual problem into something
/// that looks like the app is broken as well.
fn plain(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();

    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }

        // CSI runs until a letter. Anything else after the escape is a short
        // sequence whose next character is the whole of it.
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_log_still_says_where_it_looked() {
        // The error a user sees when a session dies before writing anything.
        // "did not answer" alone leaves them with nowhere to go.
        let words = last_words(&PathBuf::from("/tmp/wraith-no-such-log"));

        assert!(words.contains("wraith-no-such-log"));
    }

    #[test]
    fn the_log_tail_is_what_the_error_carries() {
        let log = std::env::temp_dir().join("wraith-tail-test.log");
        std::fs::write(&log, "first\nsecond\nthe real reason\n").unwrap();

        let words = last_words(&log);

        assert!(words.contains("the real reason"));
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn colour_codes_do_not_reach_the_window() {
        // tracing colours its output even into a file, so the log tail is full
        // of escapes. Left in, an error that names the real problem arrives
        // looking like the app is broken too.
        let coloured = "\u{1b}[32m INFO\u{1b}[0m capturing with \u{1b}[1mx11\u{1b}[0m";

        assert_eq!(plain(coloured), " INFO capturing with x11");
    }

    #[test]
    fn a_line_without_escapes_is_untouched() {
        let plain_line = "cannot bind to 0.0.0.0:24810: Address already in use";

        assert_eq!(plain(plain_line), plain_line);
    }

    #[test]
    fn the_cli_runs_itself() {
        let cli = PathBuf::from("/usr/local/bin/wraith");

        assert_eq!(session_binary(&cli), cli);
    }

    #[test]
    fn the_window_does_not_run_itself() {
        // The bug this exists for. wraith-app parses no arguments, so spawning
        // `wraith-app serve` opens a second window and reports success, and the
        // user is left with two windows and no session.
        let window = PathBuf::from("/nowhere/that/exists/wraith-app");

        assert_ne!(session_binary(&window), window);
        assert_eq!(session_binary(&window), PathBuf::from("wraith"));
    }

    #[test]
    fn a_case_insensitive_sibling_of_itself_is_refused() {
        // On macOS the bundle ships the window as MacOS/Wraith, and on a case
        // insensitive filesystem the sibling "wraith" is that same file. Taking
        // it would spawn the window again, which is the bug the whole lookup
        // exists to prevent.
        let dir = std::env::temp_dir().join("wraith-case-test");
        std::fs::create_dir_all(&dir).unwrap();

        let window = dir.join("Wraith");
        std::fs::write(&window, b"#!/bin/sh\n").unwrap();

        let chosen = session_binary(&window);
        assert!(
            !same_file(&chosen, &window),
            "chose itself: {}",
            chosen.display()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_bundled_cli_is_found_beside_the_window() {
        // The installed layout: `Wraith.app/Contents/MacOS` holds `wraith-app`
        // and `wraith` side by side, and the AppImage holds the same pair.
        let dir = std::env::temp_dir().join("wraith-bundle-test");
        std::fs::create_dir_all(&dir).unwrap();

        let cli = dir.join("wraith");
        std::fs::write(&cli, b"#!/bin/sh\n").unwrap();
        let window = dir.join("wraith-app");
        std::fs::write(&window, b"#!/bin/sh\n").unwrap();

        assert_eq!(session_binary(&window), cli);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sibling_is_preferred_to_the_path() {
        // The ordinary layout: target/debug/wraith-app beside target/debug/wraith.
        let dir = std::env::temp_dir().join("wraith-sibling-test");
        std::fs::create_dir_all(&dir).unwrap();
        let cli = dir.join("wraith");
        std::fs::write(&cli, b"#!/bin/sh\n").unwrap();

        assert_eq!(session_binary(&dir.join("wraith-app")), cli);

        std::fs::remove_dir_all(&dir).ok();
    }
}
