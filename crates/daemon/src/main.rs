//! The AgentSweep daemon, binary `agentsweepd`.
//!
//! It runs as a user-level launch agent, watches the Surfaces, runs the three
//! Scan kinds and is the only process that writes the Event Log, the Baseline,
//! the verdict cache and the state file, and the only one that touches the
//! Keychain. It arrives with milestone 6 of the build plan.
//!
//! What is here so far is that boundary and nothing else: this crate is the
//! only one that turns the core's `daemon` feature on, so the write side of
//! the chains and the Keychain-backed key source exist in this binary and in
//! no other.

use agentsweep_core::baseline::{Baseline, BaselineWriter};
use agentsweep_core::chain::{ChainError, ChainState};
use agentsweep_core::eventlog::{EventLog, EventLogWriter};
use agentsweep_core::keychain::{KeySource, LoginKeychain};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::verdicts::{CacheError, VerdictCache, VerdictCacheWriter};

/// The key source the daemon uses: the item in the user's login Keychain.
/// Building it touches nothing; the Keychain is read on the first load.
fn key_source() -> LoginKeychain {
    LoginKeychain::for_the_daemon()
}

/// Verifies the Event Log and opens it for appending, which only this binary
/// can do. The state comes back with the writer: "records tampered" freezes
/// automatic Quarantine, "protection state was reset" does not.
///
/// Milestone 6 calls it at daemon start. Until then it has only the test
/// below for a caller, and it is here so the write boundary is a compile
/// error rather than a comment.
#[allow(dead_code)]
fn open_the_event_log(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(EventLogWriter, ChainState), ChainError> {
    EventLogWriter::open(&EventLog::in_data_directory(directory), keys)
}

/// The same for the Baseline, the second chain under the same key. A Scan pass
/// decides what to accept and this binary is the only one that can write it
/// down.
#[allow(dead_code)]
fn open_the_baseline(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(BaselineWriter, ChainState), ChainError> {
    BaselineWriter::open(&Baseline::in_data_directory(directory), keys)
}

/// And for the Verdict cache, which is not a chain and so has nothing to
/// verify first: a record that does not verify later is a cache miss.
#[allow(dead_code)]
fn open_the_verdict_cache(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<VerdictCacheWriter, CacheError> {
    VerdictCacheWriter::open(&VerdictCache::in_data_directory(directory), keys)
}

fn main() {
    let directory = DataDirectory::for_user();
    println!(
        "{} {}",
        agentsweep_core::DAEMON_LABEL,
        agentsweep_core::VERSION
    );
    println!(
        "event log: {}",
        directory.map_or_else(
            || "no home directory".to_string(),
            |directory| directory.event_log().display().to_string()
        )
    );
    // Named, not called: milestone 6 opens the log at start. Reading the
    // Keychain here would prompt on every launch for nothing.
    let _ = key_source();
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::eventlog::{Action, Actor, Event};
    use agentsweep_core::keychain::MemoryKeySource;

    #[test]
    fn the_binary_name_is_the_machine_readable_product_name_with_a_d() {
        assert_eq!(
            env!("CARGO_BIN_NAME"),
            format!("{}d", agentsweep_core::NAME)
        );
    }

    #[test]
    fn the_daemon_writes_the_event_log_and_reads_it_back() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        let keys = MemoryKeySource::empty();

        let (mut writer, state) = open_the_event_log(&directory, &keys).expect("an open Event Log");
        assert_eq!(state, ChainState::Intact);
        writer
            .append(&Event::new(Action::GateRegistered, Actor::Auto).noting("agent", "claude-code"))
            .expect("an appended event");

        let view = EventLog::in_data_directory(&directory)
            .read(&keys)
            .expect("a readable Event Log");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.events.len(), 1);
        assert_eq!(view.events[0].event.action, Action::GateRegistered);
    }

    /// The Baseline is the same primitive as the Event Log, written by the
    /// same one binary. Milestone 5 built the records; milestone 6 opens the
    /// chain at start, and this is the boundary it will open it through.
    #[test]
    fn the_daemon_writes_the_baseline_and_reads_it_back() {
        use agentsweep_core::baseline::{AcceptedBy, BaselineRecord};
        use agentsweep_core::coverage::{CoverageKey, CoverageRecord};
        use agentsweep_core::envelope::Timestamp;
        use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};

        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        let keys = MemoryKeySource::empty();
        let at = Timestamp::now();

        let item = Item::file(
            "claude-code",
            Scope::User,
            Kind::InstructionFile,
            "~/.claude/CLAUDE.md",
            temporary.path().join("CLAUDE.md"),
            Provenance::Manual,
            Activation::Active,
            b"# demo\n".to_vec(),
        );
        let record = BaselineRecord::accepting(&item, at, AcceptedBy::Bootstrap);

        let (mut writer, state) = open_the_baseline(&directory, &keys).expect("an open Baseline");
        assert_eq!(state, ChainState::Intact);
        writer
            .cover(&CoverageRecord::new(
                CoverageKey::of("claude-code", &Scope::User, Kind::InstructionFile),
                at,
            ))
            .expect("written coverage");
        writer.accept(&record).expect("an accepted hash");

        let view = Baseline::in_data_directory(&directory)
            .read(&keys)
            .expect("a readable Baseline");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.record(&item.id), Some(&record));
        assert!(
            view.coverage()
                .covers("claude-code", &Scope::User, Kind::InstructionFile)
        );
    }

    /// The Verdict cache is empty until AI Judgement, and its writer is the
    /// daemon's alone all the same.
    #[test]
    fn the_daemon_is_the_only_writer_of_the_verdict_cache() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        let keys = MemoryKeySource::empty();

        let _writer = open_the_verdict_cache(&directory, &keys).expect("an open Verdict cache");
        let view = VerdictCache::in_data_directory(&directory)
            .read(&keys)
            .expect("a readable Verdict cache");
        assert!(view.is_empty());
    }

    #[test]
    fn the_key_source_is_the_login_keychain_item_of_the_daemon() {
        // Constructing it reads nothing, so this test never goes near the
        // developer's own Keychain.
        let _ = key_source();
        assert_eq!(
            agentsweep_core::keychain::KEYCHAIN_SERVICE,
            agentsweep_core::DAEMON_LABEL
        );
    }
}
