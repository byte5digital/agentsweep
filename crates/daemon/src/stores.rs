//! The stores only this binary may open for writing.
//!
//! The daemon is the only writer of the Event Log, the Baseline, the verdict
//! cache and the state file (spec section 6.2). That boundary is a compile
//! error rather than a comment: this crate is the only one that turns the
//! core's `daemon` feature on, so no other binary can even name the types
//! below.

use agentsweep_core::baseline::{Baseline, BaselineWriter};
use agentsweep_core::chain::{ChainError, ChainState};
use agentsweep_core::eventlog::{EventLog, EventLogWriter};
use agentsweep_core::keychain::KeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::verdicts::{CacheError, VerdictCache, VerdictCacheWriter};

/// Verifies the Event Log and opens it for appending.
///
/// The state comes back with the writer: "records tampered" freezes automatic
/// Quarantine, "protection state was reset" does not. The daemon opens it once
/// at start, which is also what turns a key that went missing into one chain
/// restart rather than into one per write.
pub fn open_the_event_log(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(EventLogWriter, ChainState), ChainError> {
    EventLogWriter::open(&EventLog::in_data_directory(directory), keys)
}

/// The same for the Baseline, the second chain under the same key. A Scan pass
/// decides what to accept and this binary is the only one that can write it
/// down.
pub fn open_the_baseline(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(BaselineWriter, ChainState), ChainError> {
    BaselineWriter::open(&Baseline::in_data_directory(directory), keys)
}

/// Verifies both chains, then opens both for appending, answering with what
/// verification found on each.
///
/// Both chains share the one key. Opening one after the key went missing
/// generates the new key, and the other, verified only then, would read its
/// old records against the new key as tampered. Verifying both first keeps a
/// missing key "protection state was reset" on both chains (spec section
/// 5.5): each starts again, pointing at its old head.
pub fn open_both_chains(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<(ChainState, ChainState), ChainError> {
    let log = EventLog::in_data_directory(directory);
    let baseline = Baseline::in_data_directory(directory);
    let found_events = log.chain().verify(keys)?;
    let found_baseline = baseline.chain().verify(keys)?;
    let (_, events) = EventLogWriter::open_verified(&log, found_events, keys)?;
    let (_, baseline) = BaselineWriter::open_verified(&baseline, found_baseline, keys)?;
    Ok((events, baseline))
}

/// And for the Verdict cache, which is not a chain and so has nothing to
/// verify first: a record that does not verify later is a cache miss.
///
/// Nothing fills it until AI Judgement has its milestone; the writer is opened
/// here so that the boundary is the same one the other two stores have.
#[allow(dead_code)]
pub fn open_the_verdict_cache(
    directory: &DataDirectory,
    keys: &dyn KeySource,
) -> Result<VerdictCacheWriter, CacheError> {
    VerdictCacheWriter::open(&VerdictCache::in_data_directory(directory), keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::eventlog::{Action, Actor, Event};
    use agentsweep_core::keychain::MemoryKeySource;

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
    /// same one binary.
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

    /// A key that went missing is a reset on both chains, never a reset on
    /// the first and tampering on the second.
    #[test]
    fn a_missing_key_restarts_both_chains_rather_than_breaking_the_second() {
        use agentsweep_core::baseline::{AcceptedBy, BaselineRecord};
        use agentsweep_core::envelope::Timestamp;
        use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};
        use agentsweep_core::keychain::KeySource as _;

        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        let keys = MemoryKeySource::empty();
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
        {
            let (mut events, _) = open_the_event_log(&directory, &keys).expect("an Event Log");
            events
                .append(&Event::new(Action::GateRegistered, Actor::Auto))
                .expect("an event");
            let (mut baseline, _) = open_the_baseline(&directory, &keys).expect("a Baseline");
            baseline
                .accept(&BaselineRecord::accepting(
                    &item,
                    Timestamp::now(),
                    AcceptedBy::Bootstrap,
                ))
                .expect("an accepted hash");
        }
        keys.forget().expect("the key goes away");

        let (events, baseline) = open_both_chains(&directory, &keys).expect("both chains");
        assert_eq!(events, ChainState::KeyMissing);
        assert_eq!(baseline, ChainState::KeyMissing);
        let view = Baseline::in_data_directory(&directory)
            .read(&keys)
            .expect("a readable Baseline");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.restarts, 1);
        assert!(
            view.record(&item.id).is_some(),
            "the old record carries over"
        );
    }

    #[test]
    fn the_key_source_is_the_login_keychain_item_of_the_daemon() {
        assert_eq!(
            agentsweep_core::keychain::KEYCHAIN_SERVICE,
            agentsweep_core::DAEMON_LABEL
        );
    }
}
