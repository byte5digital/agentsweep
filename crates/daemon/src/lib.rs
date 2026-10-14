//! The AgentSweep daemon.
//!
//! It runs as a user-level launch agent, watches the Surfaces, runs the three
//! Scan kinds and is the only process that writes the Event Log, the Baseline,
//! the verdict cache, the state file and the settings file, and the only one
//! that touches the Keychain (spec section 6.2). This crate is the only one that turns the
//! core's `daemon` feature on, so the write side of the chains exists in this
//! binary and in no other.
//!
//! What it does so far: opens the stores and says what verifying them found,
//! binds the socket the specification names, runs a Full Scan over the machine
//! at start, watches the roots that Scan declared and scans what changes on
//! them, runs the daily Full Scan when it is due, compacts the Baseline behind
//! a completed Full Scan, caches what a Scan derived in the state file, and
//! answers a signed peer of the same version with Health, the Scan summary and
//! the Findings that stand. It carries out the actions a client asks for by
//! Finding, Item or Receipt id, quarantines by itself what a stable Rule proves
//! bad during a Scan, and takes out again what keeps coming back. It asks the
//! Rule Feed at start and once a day, verifies a newer Rule Pack against the
//! keys pinned in the binary and puts it in force for every Tier, with the
//! Full Scan a new pack brings. The Rule Feed toggle is kept in the settings
//! file, which a rebuilt state file leaves alone.
//!
//! The daemon has no asynchronous runtime: every part of it is a blocking
//! thread, the socket is served through `interprocess` and the watcher gathers
//! its batches with a debouncer of its own. ADR 0011 records why, and what to
//! swap if the AI Judgement queue ever wants a runtime.
//!
//! The binary is a few lines around [`run`]; everything else is here so that a
//! test can start a daemon against a temporary home, a temporary data
//! directory and a temporary socket, which is the only kind of machine the
//! suite is allowed to touch.

#![warn(missing_docs)]

/// Writes one line to the daemon's log.
///
/// The log is `tracing`: the rotated file under `~/Library/Logs/AgentSweep`
/// for the installed daemon, the standard error stream for a developer run
/// (see [`log`]). A line names paths and ids and never content or a sensitive
/// field (spec section 6.9).
macro_rules! say {
    ($($argument:tt)*) => {
        tracing::info!("{}", format_args!($($argument)*))
    };
}

pub mod actions;
pub mod budgets;
pub mod bundle_watch;
pub mod change_scan;
pub mod due;
pub mod engine;
pub mod folder_scan;
pub mod full_scan;
pub mod gate;
pub mod gate_answer;
pub mod integrity;
pub mod log;
pub mod machine;
pub mod options;
pub mod overview;
pub mod peer_check;
pub mod permission;
pub mod rule_feed;
pub mod service;
pub mod sessions;
pub mod settings;
pub mod stores;
pub mod watcher;

pub use options::{Invocation, Options, OptionsError, USAGE};
pub use service::{Background, Daemon, Running, Tuning, run, start};
