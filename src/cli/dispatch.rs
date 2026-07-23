//! Turning a parsed command line into work.
//!
//! Separate from the binary because `main.rs` is its own crate and can only
//! reach `pub` items. With the dispatch living here instead, `run` and `net`
//! stay crate-private rather than being published to make one binary compile.

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::net::endpoint::{DEFAULT_PAIR_PORT, DEFAULT_PORT};
use crate::net::identity::{self, Identity};

use super::{Cli, Command};

/// Parses the command line and runs it.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli);

    match dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Printed rather than logged: a failure the user asked for is a
            // result, not an event, and it should survive RUST_LOG=off.
            eprintln!("wraith: {error}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(cli: &Cli) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cli.log_filter()));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();
}

fn dispatch(cli: &Cli) -> crate::error::Result<()> {
    match &cli.command {
        Command::Status => status(),
        Command::Stop => stop(),
        Command::Unstick { all } => unstick(*all),
        Command::Capture { suppress, seconds } => crate::run::dump::run(*suppress, *seconds),
        Command::Bench { iterations } => crate::run::bench::run(*iterations),
        Command::Probe => crate::platform::probe::report(),
        Command::Watch => watch(),
        Command::Serve { listen } => serve(listen.as_deref()),
        Command::Pair {
            join,
            code,
            side,
            port,
            cancel,
        } => {
            if *cancel {
                crate::control::client::pair_cancel()
            } else {
                pair(join.as_deref(), code.as_deref(), side.as_deref(), *port)
            }
        }
        Command::Peers { forget } => forget
            .as_deref()
            .map_or_else(crate::peers::list, crate::peers::forget),
    }
}

/// Runs the KVM until interrupted.
fn serve(listen: Option<&str>) -> crate::error::Result<()> {
    let identity = Identity::load_or_generate(&identity::default_path())
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;
    let config =
        Config::load(&Config::path()).map_err(|e| crate::error::Error::Config(e.to_string()))?;

    let address = listen
        .map(str::to_owned)
        .or_else(|| config.listen.clone())
        .unwrap_or_else(|| format!("0.0.0.0:{DEFAULT_PORT}"))
        .parse()
        .map_err(|_| crate::error::Error::Config("the listen address is not valid".to_owned()))?;

    // Multi-threaded, unlike pairing: the session task, the peer readers, and
    // the timer all want to run at once, and a motion event waiting behind a
    // reconnect attempt would show up as a stuttering pointer.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(crate::error::Error::Io)?;

    runtime.block_on(crate::run::serve::run(
        std::sync::Arc::new(identity),
        config,
        address,
    ))
}

/// Pairing needs an async runtime, and nothing else so far does.
///
/// Built here rather than wrapping main in #[tokio::main], so `unstick` and
/// `capture` stay free of it. `unstick` in particular has to work when things
/// are already wrong, and a runtime it does not need is one more thing that
/// could fail first.
fn pair(
    join: Option<&str>,
    code: Option<&str>,
    side: Option<&str>,
    port: Option<u16>,
) -> crate::error::Result<()> {
    let identity = Identity::load_or_generate(&identity::default_path())
        .map_err(|error| crate::error::Error::Config(error.to_string()))?;

    let config =
        Config::load(&Config::path()).map_err(|e| crate::error::Error::Config(e.to_string()))?;
    let name = config.local_name();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(crate::error::Error::Io)?;

    let side = match side {
        Some(text) => Some(crate::run::pair::parse_side(text).ok_or_else(|| {
            crate::error::Error::Config(format!(
                "{text} is not a side. Try right, left, up, or down"
            ))
        })?),
        None => None,
    };

    runtime.block_on(async {
        match join {
            Some(address) => crate::run::pair::join(&identity, &name, address, code, side).await,
            None => {
                crate::run::pair::offer(&identity, &name, port.unwrap_or(DEFAULT_PAIR_PORT), side)
                    .await
            }
        }
    })
}

/// Prints every crossing until interrupted.
///
/// The diagnostic for the crossing side: it says whether the session decided a
/// crossing happened at all, which separates a protocol problem from a drawing
/// one when an edge effect does not appear.
fn watch() -> crate::error::Result<()> {
    use crate::control::client::Flow;
    use crate::control::{Direction, Response};

    eprintln!("watching for crossings, ctrl-c to stop");

    crate::control::client::stream(&crate::control::Request::Watch, |response| {
        if let Response::Crossed(crossed) = response {
            let way = match crossed.direction {
                Direction::Departure => "left",
                Direction::Arrival => "arrived at",
            };
            // The percentage rather than the raw permille, because this is read
            // by a person checking it against where they moved the mouse.
            println!(
                "{way} the {:?} edge, {:.0}% along",
                crossed.edge,
                crossed.at() * 100.0
            );
        }
        Flow::Continue
    })
}

/// Prints what the running session is doing.
///
/// The one place "connected" can be told from "paired but silent", because only
/// the running process knows. Everything else reads files, which cannot say.
fn status() -> crate::error::Result<()> {
    let status = crate::control::client::status()?;

    println!("sharing as {} on {}", status.name, status.listen);
    println!("up {}", uptime(status.uptime_ms));

    match &status.backend_capture {
        Some(backend) => println!("capturing with {backend}"),
        // The single most useful line in the whole command. A session that is
        // running and connected but capturing nothing is otherwise
        // indistinguishable from a broken network.
        None => println!(
            "not capturing on this machine, so the cursor can arrive but never leave.\n\
             On macOS grant Input Monitoring in System Settings, Privacy and Security"
        ),
    }

    if let Some(left_ms) = status.pairing_left_ms {
        println!(
            "a pairing is running, {} left. End it with `wraith pair --cancel`",
            uptime(left_ms)
        );
    }

    if status.peers.is_empty() {
        println!();
        println!("no machines paired yet. Run `wraith pair` on this and one other");
        return Ok(());
    }

    println!();
    for peer in &status.peers {
        let health = if peer.connected {
            "connected"
        } else {
            "not answering"
        };
        println!(
            "  {:<16} {:<18} {health}",
            peer.name,
            crate::status::short_key(&peer.key)
        );
    }

    Ok(())
}

fn stop() -> crate::error::Result<()> {
    crate::control::client::stop()?;
    println!("stopped");
    Ok(())
}

fn uptime(ms: u64) -> String {
    let seconds = ms / 1_000;

    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3_599 => format!("{}m {}s", seconds / 60, seconds % 60),
        _ => format!("{}h {}m", seconds / 3_600, (seconds % 3_600) / 60),
    }
}

fn unstick(all: bool) -> crate::error::Result<()> {
    let swept = crate::unstick::run(all)?;

    match &swept.still_held {
        Some(held) if held.is_empty() => {
            println!(
                "released {} keys, and the system reports nothing held",
                swept.keys
            );
        }
        Some(held) => println!(
            "released {} keys, but {} still reported held: {}\n\
             that is either a key you are pressing right now, or something outside Wraith",
            swept.keys,
            held.len(),
            held.iter()
                .map(|c| c.0.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        None => println!(
            "released {} keys (this backend cannot confirm the result)",
            swept.keys
        ),
    }

    if swept.backend_self_releases {
        println!(
            "note: this backend releases held keys on its own when a client dies, so a stuck\n\
             key here is more likely a compositor bug than an abandoned Wraith session"
        );
    }
    Ok(())
}
