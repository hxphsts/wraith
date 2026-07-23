//! The orchestration that wires the domain to the adapters.
//!
//! Crate-private. Everything here is the machinery of a running session rather
//! than anything a caller would drive: `serve` alone is two thousand lines of
//! task plumbing whose every signature would be a semver commitment. The parts
//! a caller genuinely needs are public elsewhere, as `crate::config`,
//! `crate::control`, `crate::peers` and `crate::unstick`.

pub mod bench;
pub mod clipboard;
pub mod dump;
pub mod injector;
pub mod pair;
pub mod serve;
pub mod watch;
