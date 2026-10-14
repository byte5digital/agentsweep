//! The Gate's entries in an Agent's user settings, written and taken away by
//! the daemon.
//!
//! The daemon is the one writer of a Surface (spec section 6.2), so it is the
//! one that registers the Gate (spec section 7.6). Where the entries go and
//! what they look like is the Surface Adapter's (the owner's decision of
//! 2026-10-14, keeping ADR 0002): this module hands an adapter the daemon's
//! own writer and the command the Gate runs, and records what the adapter
//! wrote. Every entry written appends one `gate-registered` event and every
//! entry taken away one `gate-removed` event, each naming the Agent, the entry
//! locator and the Hook Item's content hash, so the known-action rebuild
//! accepts the Hook Item the write left and the next Scan raises no Drift on
//! it (spec section 4.6.4).
//!
//! When to register and when to check is not decided here: the check on every
//! Full Scan and the switch in Settings come with their own tickets and call
//! these two functions.

use std::path::Path;

use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::chain::ChainError;
use agentsweep_core::eventlog::{Action, Actor, Event};
use agentsweep_core::gate_registration::{AtomicWriter, GateCommand, GateEntry, GateError};
use agentsweep_core::host::Host;
use agentsweep_core::item::Kind;
use agentsweep_core::keychain::KeySource;
use agentsweep_core::paths::DataDirectory;

use crate::stores::open_the_event_log;

/// Why a Gate write or its record did not happen.
#[derive(Debug)]
pub enum GateWriteError {
    /// The adapter did not write: no Gate, a file that keeps changing, one
    /// that does not parse, or one that cannot be written.
    Gate(GateError),
    /// The entries were written but the Event Log could not record them.
    Log(ChainError),
}

impl std::fmt::Display for GateWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateWriteError::Gate(error) => write!(f, "{error}"),
            GateWriteError::Log(error) => write!(f, "the Event Log: {error}"),
        }
    }
}

impl std::error::Error for GateWriteError {}

/// The command the Gate runs: the command line interface beside this
/// daemon's own executable in the bundle.
pub fn bundled_command() -> Option<GateCommand> {
    GateCommand::beside(&std::env::current_exe().ok()?)
}

/// Writes the Gate's entries for one Agent and records every entry written.
pub fn register(
    adapter: &dyn SurfaceAdapter,
    host: &Host,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    command: &GateCommand,
) -> Result<Vec<GateEntry>, GateWriteError> {
    let written = adapter
        .register_gate(host, &AtomicWriter, command)
        .map_err(GateWriteError::Gate)?;
    record(
        Action::GateRegistered,
        adapter.descriptor().agent,
        &written,
        directory,
        keys,
    )?;
    if !written.is_empty() {
        say!(
            "the Gate was registered with {}: {} entries in {}",
            adapter.descriptor().agent,
            written.len(),
            shown(&written)
        );
    }
    Ok(written)
}

/// Takes the Gate's entries away from one Agent and records every entry taken
/// away.
pub fn remove(
    adapter: &dyn SurfaceAdapter,
    host: &Host,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    command: &GateCommand,
) -> Result<Vec<GateEntry>, GateWriteError> {
    let removed = adapter
        .remove_gate(host, &AtomicWriter, command)
        .map_err(GateWriteError::Gate)?;
    record(
        Action::GateRemoved,
        adapter.descriptor().agent,
        &removed,
        directory,
        keys,
    )?;
    if !removed.is_empty() {
        say!(
            "the Gate was removed from {}: {} entries in {}",
            adapter.descriptor().agent,
            removed.len(),
            shown(&removed)
        );
    }
    Ok(removed)
}

/// One event per entry, naming the Agent, the entry locator and the Hook
/// Item's content hash.
fn record(
    action: Action,
    agent: &str,
    entries: &[GateEntry],
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(), GateWriteError> {
    if entries.is_empty() {
        return Ok(());
    }
    let (mut writer, _) = open_the_event_log(directory, keys).map_err(GateWriteError::Log)?;
    for entry in entries {
        let event = Event::new(action, Actor::Auto)
            .about(&entry.item_id, Kind::Hook, &entry.content_hash)
            .noting("agent", agent)
            .noting("locator", entry.locator.as_str());
        writer.append(&event).map_err(GateWriteError::Log)?;
    }
    Ok(())
}

/// The file the entries are in, for the log line. A path is not a sensitive
/// value; the entries' content is never logged.
fn shown(entries: &[GateEntry]) -> String {
    entries
        .first()
        .map(|entry| entry.path.as_path())
        .unwrap_or(Path::new(""))
        .display()
        .to_string()
}
