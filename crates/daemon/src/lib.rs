//! The AgentSweep daemon.
//!
//! It runs as a user-level launch agent, watches the Surfaces, runs the three
//! Scan kinds and is the only process that writes the Event Log, the Baseline,
//! the verdict cache and the state file, and the only one that touches the
//! Keychain (spec section 6.2). This crate is the only one that turns the
//! core's `daemon` feature on, so the write side of the chains exists in this
//! binary and in no other.
//!
//! What it does so far: opens the stores and says what verifying them found,
//! binds the socket the specification names, runs a Full Scan over the machine
//! at start, watches the roots that Scan declared and scans what changes on
//! them, runs the daily Full Scan when it is due, compacts the Baseline behind
//! a completed Full Scan, caches what a Scan derived in the state file, and
//! answers a signed peer of the same version with Health, the Scan summary and
//! the Findings that stand. The actions and the Rule Feed arrive with the
//! tickets after this one.
//!
//! The binary is a few lines around [`run`]; everything else is here so that a
//! test can start a daemon against a temporary home, a temporary data
//! directory and a temporary socket, which is the only kind of machine the
//! suite is allowed to touch.

#![warn(missing_docs)]

pub mod change_scan;
pub mod due;
pub mod full_scan;
pub mod machine;
pub mod options;
pub mod peer_check;
pub mod service;
pub mod stores;
pub mod watcher;

pub use options::{Invocation, Options, OptionsError, USAGE};
pub use service::{Background, Daemon, Running, Tuning, run, start};
