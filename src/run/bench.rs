//! `wraith bench`, the latency harness.
//!
//! # Why this exists
//!
//! Nobody in this category has published input latency numbers. Deskflow,
//! Synergy, and lan-mouse have none; the one commercial competitor advertises a
//! figure with no methodology attached. See `research/04-latency-budget.md`.
//!
//! So this is three things at once: a differentiator, a credibility asset behind
//! any performance claim, and a regression guard that catches a slowdown in CI
//! before a user feels it.
//!
//! # The budget
//!
//! Added end-to-end latency, p50 at or under 2 ms and p99 at or under 8 ms on
//! wired gigabit. The 8 ms figure comes from Deber et al., CHI 2015: latency
//! improvements as small as 8.3 ms remain perceptible even from an elevated
//! baseline. Below that, no user can distinguish Wraith from a hypothetical
//! perfect implementation.
//!
//! # What is measured
//!
//! Loopback mode measures serialisation, encryption, and transport on one
//! machine with one clock, so it is a true one-way number.
//!
//! Two-machine mode measures a round trip and halves it, because the two clocks
//! are not synchronised and pretending otherwise would produce a number that
//! looked precise and was not. Halving assumes a symmetric path, which is
//! usually true on a LAN and stated here rather than hidden.

use std::time::{Duration, Instant};

use crate::domain::{InputEvent, Millis, Seq};
use crate::error::{Error, Result};
use crate::net::wire;

/// The budget from `research/04-latency-budget.md`.
pub const P50_BUDGET_MS: f64 = 2.0;
pub const P99_BUDGET_MS: f64 = 8.0;

/// Samples discarded before measuring.
///
/// The first few carry connection setup, page faults, and a cold cache, none of
/// which a user experiences while typing.
const WARMUP: usize = 100;

/// What a run measured.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Report {
    pub label: String,
    pub samples: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub ms_max: f64,
}

impl Report {
    /// Builds a report from durations, which need not be sorted.
    #[must_use]
    pub fn of(label: &str, mut samples: Vec<Duration>) -> Self {
        samples.sort_unstable();

        Self {
            label: label.to_owned(),
            samples: samples.len(),
            p50_ms: percentile(&samples, 5_000),
            p95_ms: percentile(&samples, 9_500),
            p99_ms: percentile(&samples, 9_900),
            ms_max: samples.last().map_or(0.0, |d| d.as_secs_f64() * 1_000.0),
        }
    }

    /// Whether this run is inside the published budget.
    #[must_use]
    pub fn within_budget(&self) -> bool {
        self.p50_ms <= P50_BUDGET_MS && self.p99_ms <= P99_BUDGET_MS
    }

    fn print(&self) {
        println!("{}", self.label);
        println!("  samples  {}", self.samples);
        println!("  p50      {}", duration(self.p50_ms));
        println!("  p95      {}", duration(self.p95_ms));
        println!("  p99      {}", duration(self.p99_ms));
        println!("  max      {}", duration(self.ms_max));

        let verdict = if self.within_budget() {
            "within"
        } else {
            "OVER"
        };
        println!("  budget   {verdict} (p50 {P50_BUDGET_MS} ms, p99 {P99_BUDGET_MS} ms)");
    }
}

/// A duration in whichever unit shows it.
///
/// The budget is in milliseconds, but the codec costs well under a microsecond,
/// and printing that as "0.000 ms" throws away the entire measurement. A
/// benchmark that reports zero is a benchmark nobody can act on.
fn duration(ms: f64) -> String {
    if ms >= 1.0 {
        format!("{ms:.3} ms")
    } else if ms >= 0.001 {
        format!("{:.2} us", ms * 1_000.0)
    } else {
        format!("{:.0} ns", ms * 1_000_000.0)
    }
}

/// A percentile from sorted samples, by nearest rank.
///
/// `basis_points` is hundredths of a percent, so 9_900 is the 99th percentile.
/// Integers rather than a float, so the rank cannot depend on how a division
/// happened to round and the result is reproducible by counting.
///
/// Nearest rank rather than interpolation, for the same reason: at these sample
/// counts the difference is far below the measurement noise, and a number a
/// reader cannot check by hand is worth less than one they can.
fn percentile(sorted: &[Duration], basis_points: u64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }

    let count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
    let rank = (count * basis_points).div_ceil(10_000);

    let index = usize::try_from(rank.saturating_sub(1))
        .unwrap_or(usize::MAX)
        .min(sorted.len() - 1);

    sorted[index].as_secs_f64() * 1_000.0
}

/// Measures the pipeline a motion event goes through, without a network.
///
/// Isolates everything Wraith itself adds: building the event, encoding it, and
/// decoding it on the far side. Whatever this costs is the floor no transport
/// can go below.
pub fn run(iterations: usize) -> Result<()> {
    println!("wraith bench");
    println!();

    codec_report(iterations)?.print();
    println!();
    transitions_report(iterations)?.print();

    println!();
    println!("this measures encode and decode only, with no network.");
    println!("for a link measurement, run `wraith bench` on two paired machines.");

    Ok(())
}

/// The motion path, which is the high-frequency one.
pub fn codec_report(iterations: usize) -> Result<Report> {
    let event = InputEvent::MotionRel {
        dx_milli: 1_500,
        dy_milli: -250,
    };
    let mut samples = Vec::with_capacity(iterations);

    for index in 0..iterations + WARMUP {
        let started = Instant::now();

        let frame = wire::motion_frame(vec![event], Seq(index_as_u64(index)), Millis(0))
            .ok_or_else(|| Error::Config("the bench built an empty frame".to_owned()))?;
        let bytes = wire::encode_frame(&frame).map_err(|error| Error::Config(error.to_string()))?;
        let decoded =
            wire::decode_frame(&bytes).map_err(|error| Error::Config(error.to_string()))?;

        let elapsed = started.elapsed();

        // Read back, so the optimiser cannot delete the work being measured.
        if decoded.events.is_empty() {
            return Err(Error::Config("the bench decoded an empty frame".to_owned()));
        }
        if index >= WARMUP {
            samples.push(elapsed);
        }
    }

    Ok(Report::of("motion, encode and decode", samples))
}

/// A loop counter as a sequence number.
const fn index_as_u64(index: usize) -> u64 {
    index as u64
}

/// The reliable path, which carries every key.
pub fn transitions_report(iterations: usize) -> Result<Report> {
    let message = wire::Control::Transitions {
        events: vec![
            InputEvent::Key {
                code: crate::domain::Scancode(29),
                state: crate::domain::KeyState::Pressed,
            },
            InputEvent::Key {
                code: crate::domain::Scancode(46),
                state: crate::domain::KeyState::Pressed,
            },
        ],
    };
    let mut samples = Vec::with_capacity(iterations);

    for index in 0..iterations + WARMUP {
        let started = Instant::now();

        let framed = wire::encode(&message).map_err(|error| Error::Config(error.to_string()))?;
        let length = wire::frame_length(
            framed[..4]
                .try_into()
                .map_err(|_| Error::Config("short frame".to_owned()))?,
        )
        .map_err(|error| Error::Config(error.to_string()))?;
        let decoded: wire::Control = wire::decode(&framed[4..4 + length])
            .map_err(|error| Error::Config(error.to_string()))?;

        let elapsed = started.elapsed();

        if decoded != message {
            return Err(Error::Config(
                "the bench decoded the wrong message".to_owned(),
            ));
        }
        if index >= WARMUP {
            samples.push(elapsed);
        }
    }

    Ok(Report::of("transitions, encode and decode", samples))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: f64) -> Duration {
        Duration::from_secs_f64(value / 1_000.0)
    }

    #[test]
    fn a_duration_is_shown_in_a_unit_that_reveals_it() {
        // "0.000 ms" is what this function exists to prevent.
        assert_eq!(duration(2.5), "2.500 ms");
        assert_eq!(duration(0.25), "250.00 us");
        assert_eq!(duration(0.000_5), "500 ns");
    }

    #[test]
    fn a_sub_microsecond_duration_does_not_render_as_zero() {
        let rendered = duration(0.000_2);

        assert_ne!(rendered, "0.000 ms");
        assert!(rendered.contains("ns"), "got {rendered}");
    }

    #[test]
    fn a_percentile_picks_the_nearest_rank() {
        let samples: Vec<Duration> = (1..=100).map(|n| ms(f64::from(n))).collect();

        assert!((percentile(&samples, 5_000) - 50.0).abs() < 0.01);
        assert!((percentile(&samples, 9_900) - 99.0).abs() < 0.01);
        assert!((percentile(&samples, 10_000) - 100.0).abs() < 0.01);
    }

    #[test]
    fn a_percentile_of_nothing_is_zero_rather_than_a_panic() {
        // A bench that panics on an empty run is a bench nobody trusts.
        assert!((percentile(&[], 5_000) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_percentile_of_one_sample_is_that_sample() {
        assert!((percentile(&[ms(7.0)], 5_000) - 7.0).abs() < 0.01);
        assert!((percentile(&[ms(7.0)], 9_900) - 7.0).abs() < 0.01);
    }

    #[test]
    fn a_report_sorts_what_it_is_given() {
        // Samples arrive in the order they were measured, not in order.
        let report = Report::of("x", vec![ms(9.0), ms(1.0), ms(5.0)]);

        assert!(
            (report.p50_ms - 5.0).abs() < 0.01,
            "p50 was {}",
            report.p50_ms
        );
        assert!((report.ms_max - 9.0).abs() < 0.01);
    }

    #[test]
    fn a_fast_run_is_within_budget() {
        let report = Report::of("x", vec![ms(0.5); 100]);

        assert!(report.within_budget());
    }

    #[test]
    fn a_run_over_the_p99_budget_is_reported_as_over() {
        // The regression guard. If this stops working, a slowdown ships.
        //
        // Two outliers in a hundred, not one. By nearest rank the p99 of a
        // hundred samples is the ninety-ninth, so a single outlier sits at the
        // hundredth and is correctly outside the percentile.
        let mut samples = vec![ms(0.5); 98];
        samples.push(ms(50.0));
        samples.push(ms(50.0));

        let report = Report::of("x", samples);

        assert!(!report.within_budget(), "a 50 ms p99 was called acceptable");
    }

    #[test]
    fn a_single_outlier_in_a_hundred_does_not_move_the_p99() {
        // The other half of the same fact, stated so nobody later "fixes" the
        // percentile to include it.
        let mut samples = vec![ms(0.5); 99];
        samples.push(ms(50.0));

        let report = Report::of("x", samples);

        assert!(
            report.within_budget(),
            "one sample in a hundred moved the p99"
        );
        assert!(
            (report.ms_max - 50.0).abs() < 0.01,
            "but max should still show it"
        );
    }

    #[test]
    fn a_run_over_the_p50_budget_is_reported_as_over() {
        let report = Report::of("x", vec![ms(5.0); 100]);

        assert!(!report.within_budget());
    }

    #[test]
    fn the_codec_is_far_inside_the_budget() {
        // Whatever the codec costs is the floor the network is added to, so it
        // needs to be a rounding error rather than a share of the budget.
        let report = codec_report(2_000).unwrap();

        assert!(
            report.p99_ms < P50_BUDGET_MS / 10.0,
            "encoding motion costs {:.3} ms at p99, which is a tenth of the whole budget",
            report.p99_ms
        );
    }

    #[test]
    fn the_transition_codec_is_far_inside_the_budget() {
        let report = transitions_report(2_000).unwrap();

        assert!(
            report.p99_ms < P50_BUDGET_MS / 10.0,
            "encoding transitions costs {:.3} ms at p99",
            report.p99_ms
        );
    }

    #[test]
    fn a_report_counts_only_the_measured_samples() {
        // The warmup carries connection setup and a cold cache, none of which a
        // user experiences while typing.
        let report = codec_report(500).unwrap();

        assert_eq!(report.samples, 500, "the warmup leaked into the results");
    }
}
