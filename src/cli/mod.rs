//! The command line surface.

mod dispatch;

pub use dispatch::main;

use clap::{Parser, Subcommand};

/// A software KVM switch. One keyboard and mouse, every machine on the desk.
#[derive(Debug, Parser)]
#[command(name = "wraith", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Increase log detail. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// What the running session is doing, and which machines are answering.
    ///
    /// The one command that can tell "connected" from "paired but silent",
    /// because only the running process knows.
    Status,

    /// Stop the running session.
    Stop,

    /// Release every modifier key on this machine.
    ///
    /// The escape hatch for a peer that died holding one. You should never need
    /// it, and it exists because on X11 a `SIGKILL` skips every destructor and
    /// XTEST has no notion of releasing a dead client's keys.
    Unstick {
        /// Sweep every key, not just the modifiers. Slower, and rarely needed.
        #[arg(long)]
        all: bool,
    },

    /// Share this machine's input with the peers in the layout.
    ///
    /// Runs until interrupted. Every machine both listens and dials, so there
    /// is no server to nominate.
    Serve {
        /// The address to listen on.
        #[arg(long)]
        listen: Option<String>,
    },

    /// Pair with another machine, which is the only way to trust one.
    ///
    /// Run it on both machines. One prints a six-digit code, the other types
    /// it. There is no other path into the trust store, and no way to skip it.
    Pair {
        /// Join a machine that is already offering, by hostname or address.
        #[arg(long, value_name = "ADDRESS")]
        join: Option<String>,

        /// The code, if you would rather not be prompted for it.
        #[arg(long, requires = "join")]
        code: Option<String>,

        /// Which side of this machine the other one sits on.
        ///
        /// Skips the question. Given on the joining machine, since that is the
        /// one that decides; the other applies the mirror.
        #[arg(long, value_name = "right|left|up|down")]
        side: Option<String>,

        /// The port to offer on.
        #[arg(long)]
        port: Option<u16>,

        /// End the offer a running session is showing, and pair nothing.
        ///
        /// For an offer nobody is left holding: a window that was closed while
        /// showing a code, or a `pair` that was killed rather than interrupted.
        #[arg(long, conflicts_with_all = ["join", "code", "side", "port"])]
        cancel: bool,
    },

    /// List the machines this one has paired with.
    Peers {
        /// Forget a machine, which is the only way to untrust one.
        #[arg(long, value_name = "NAME")]
        forget: Option<String>,
    },

    /// Print local input events as they happen.
    ///
    /// The diagnostic for the capture side. Nothing is sent anywhere and
    /// nothing is suppressed unless you ask, so it is safe to leave running.
    Capture {
        /// Also take input away from the local desktop, as a live session does.
        ///
        /// Dangerous on the machine you are typing on: while this is set,
        /// nothing else receives input. It releases on exit, and the timeout
        /// exists so a crash cannot leave you locked out.
        #[arg(long)]
        suppress: bool,

        /// Stop after this many seconds. Zero runs until interrupted.
        #[arg(long, default_value_t = 10)]
        seconds: u64,
    },

    /// Measure what Wraith adds to input latency.
    ///
    /// Nobody in this category publishes numbers, so these are checkable and
    /// reproducible rather than a marketing claim.
    Bench {
        /// How many samples to take after the warmup.
        #[arg(long, default_value_t = 20_000)]
        iterations: usize,
    },

    /// Report what Wraith makes of this machine.
    ///
    /// Prints the backends it probed, which one it would choose, and why the
    /// others were rejected.
    Probe,

    /// Print crossings as they happen.
    ///
    /// The diagnostic for the crossing side, and the thing to reach for when an
    /// edge effect does not appear: this says whether the session decided a
    /// crossing happened at all, which separates a protocol problem from a
    /// drawing one. Runs until interrupted.
    Watch,
}

impl Cli {
    /// The tracing filter implied by the verbosity flags.
    ///
    /// `RUST_LOG` wins if set, since someone who has gone to the trouble of
    /// setting it wants something more specific than a count of `-v`.
    pub fn log_filter(&self) -> String {
        match self.verbose {
            0 => "wraith=info".to_owned(),
            1 => "wraith=debug".to_owned(),
            _ => "wraith=trace".to_owned(),
        }
    }
}
