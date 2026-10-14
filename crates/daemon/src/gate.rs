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
//! Every Full Scan calls [`verify`] for every Agent it detected, before it
//! enumerates (spec section 7.6): the mending write is then already in the
//! Event Log when the Scan rebuilds its known actions, so the Scan that mends
//! reads the fresh entries `unchanged`. The switch in Settings comes with its
//! own ticket and calls [`register`] and [`remove`].

use std::path::Path;

use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::chain::ChainError;
use agentsweep_core::eventlog::{Action, Actor, Event};
use agentsweep_core::gate_registration::{
    AtomicWriter, GateCheck, GateCommand, GateEntry, GateError, GateWrite,
};
use agentsweep_core::health::GateTrouble;
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

/// Writes the Gate's entries for one Agent, takes away its entries under
/// another command line interface path, and records every entry written or
/// taken away.
pub fn register(
    adapter: &dyn SurfaceAdapter,
    host: &Host,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    command: &GateCommand,
) -> Result<GateWrite, GateWriteError> {
    let write = adapter
        .register_gate(host, &AtomicWriter, command)
        .map_err(GateWriteError::Gate)?;
    record(adapter.descriptor().agent, &write, directory, keys)?;
    if !write.written.is_empty() {
        say!(
            "the Gate was registered with {}: {} entries in {}",
            adapter.descriptor().agent,
            write.written.len(),
            shown(&write.written)
        );
    }
    if !write.removed.is_empty() {
        say!(
            "the Gate's entries under another path were replaced in {}: {} entries in {}",
            adapter.descriptor().agent,
            write.removed.len(),
            shown(&write.removed)
        );
    }
    Ok(write)
}

/// Takes the Gate's entries away from one Agent and records every entry taken
/// away.
pub fn remove(
    adapter: &dyn SurfaceAdapter,
    host: &Host,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    command: &GateCommand,
) -> Result<GateWrite, GateWriteError> {
    let write = adapter
        .remove_gate(host, &AtomicWriter, command)
        .map_err(GateWriteError::Gate)?;
    record(adapter.descriptor().agent, &write, directory, keys)?;
    if !write.removed.is_empty() {
        say!(
            "the Gate was removed from {}: {} entries in {}",
            adapter.descriptor().agent,
            write.removed.len(),
            shown(&write.removed)
        );
    }
    Ok(write)
}

/// Verifies one detected Agent's Gate entries and mends them, which is what
/// every Full Scan does for every Agent it detected (spec section 7.6).
///
/// Answers with the Health line the Agent is to carry, or nothing when the
/// check passed or the mending write went through. A mending write is the
/// daemon's own and a known action: it raises no Finding and notifies
/// nobody. Managed policy that drops the user's hooks writes nothing. The
/// user's own switch is never written back; the entries are kept in place
/// beside it and the line says the Gate cannot run there.
pub fn verify(
    adapter: &dyn SurfaceAdapter,
    host: &Host,
    directory: &DataDirectory,
    keys: &dyn KeySource,
    command: &GateCommand,
) -> Option<GateTrouble> {
    let agent = adapter.descriptor().agent;
    let mended = |kept: Option<GateTrouble>| match register(adapter, host, directory, keys, command)
    {
        Ok(_) => kept,
        Err(error) => {
            say!("the Gate could not be registered with {agent}: {error}");
            Some(GateTrouble::RegistrationFailed)
        }
    };
    match adapter.check_gate(host, command) {
        GateCheck::NoGate | GateCheck::Registered => None,
        GateCheck::ManagedPolicy => Some(GateTrouble::ManagedPolicy),
        GateCheck::SwitchedOffByUser => mended(Some(GateTrouble::SwitchedOffByUser)),
        GateCheck::Missing(_) | GateCheck::Unreadable(_) => mended(None),
    }
}

/// One `gate-removed` event per entry taken away, then one `gate-registered`
/// event per entry written, each naming the Agent, the entry locator and the
/// Hook Item's content hash. Pins filed again under a new position are noted
/// on the first event of the write; a pin is never an Item.
fn record(
    agent: &str,
    write: &GateWrite,
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(), GateWriteError> {
    if write.written.is_empty() && write.removed.is_empty() {
        return Ok(());
    }
    let (mut writer, _) = open_the_event_log(directory, keys).map_err(GateWriteError::Log)?;
    let entries = write
        .removed
        .iter()
        .map(|entry| (Action::GateRemoved, entry))
        .chain(
            write
                .written
                .iter()
                .map(|entry| (Action::GateRegistered, entry)),
        );
    for (index, (action, entry)) in entries.enumerate() {
        let mut event = Event::new(action, Actor::Auto)
            .about(&entry.item_id, Kind::Hook, &entry.content_hash)
            .noting("agent", agent)
            .noting("locator", entry.locator.as_str());
        if index == 0 && write.pins_rekeyed > 0 {
            event = event.noting("pins_rekeyed", write.pins_rekeyed.to_string().as_str());
        }
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
