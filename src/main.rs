//! The `wraith` binary.
//!
//! A shim. Everything it would otherwise do lives in `wraith::cli`, because a
//! binary is its own crate and can only reach `pub` items: a dispatch written
//! here would force `run` and `net` to be published surface in order to compile
//! one executable.

fn main() -> std::process::ExitCode {
    wraith::cli::main()
}
