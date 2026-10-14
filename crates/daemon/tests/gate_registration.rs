//! The Gate's entries written and taken away through the daemon, end to end.
//!
//! The daemon registers the Gate with Claude Code by appending its three hook
//! groups to the user settings file, records one `gate-registered` event per
//! entry, and the next Full Scan reads the three Hook Items as AgentSweep's
//! own write: `unchanged`, with no Finding of any Tier and no Drift (spec
//! sections 4.6.4, 7.2 and 7.6). Every test runs against a temporary home and
//! a temporary data directory with the chain key held in the process; nothing
//! touches the real home, the real data directory or the login Keychain.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_core::baseline::{AcceptedBy, Baseline};
use agentsweep_core::eventlog::{Action, EventLog};
use agentsweep_core::finding::Source;
use agentsweep_core::gate_registration::{GateCheck, GateCommand, GateEntry};
use agentsweep_core::item::Kind;
use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::state::Trigger;
use agentsweep_daemon::full_scan::{self, ScanRun, Unwatched};
use agentsweep_daemon::gate;
use agentsweep_daemon::machine::Machine;

use agentsweep_core::adapter::SurfaceAdapter;

/// Keeps one test's temporary paths apart from another's.
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Where the bundle puts the command line interface. Nothing runs it, and it
/// sits outside every temporary directory so no Rule reads it as a command
/// planted in one.
const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";

/// A user settings file with another key and a hook group of the user's own.
const USERS_OWN: &str = r#"{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/lint.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
"#;

/// One temporary machine and one temporary data directory.
struct Sandbox {
    root: PathBuf,
    keys: MemoryKeySource,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-gate-registration-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        std::fs::write(root.join("home/.claude/settings.json"), USERS_OWN)
            .expect("a settings file");
        Sandbox {
            root,
            keys: MemoryKeySource::empty(),
        }
    }

    fn machine(&self) -> Machine {
        Machine::named(self.root.join("home"))
    }

    fn data(&self) -> DataDirectory {
        DataDirectory::at(self.root.join("data"))
    }

    fn settings(&self) -> PathBuf {
        self.root.join("home/.claude/settings.json")
    }

    fn full_scan(&self) -> ScanRun {
        full_scan::run(
            &self.machine(),
            &self.data(),
            &self.keys,
            &[],
            Trigger::ScanNow,
            &Unwatched,
        )
        .expect("a Full Scan")
    }

    fn register(&self) -> Vec<GateEntry> {
        gate::register(
            &ClaudeCode::new(),
            &self.machine().host(Vec::new()),
            &self.data(),
            &self.keys,
            &GateCommand::at(CLI),
        )
        .expect("the Gate registered")
        .written
    }

    fn remove(&self) -> Vec<GateEntry> {
        gate::remove(
            &ClaudeCode::new(),
            &self.machine().host(Vec::new()),
            &self.data(),
            &self.keys,
            &GateCommand::at(CLI),
        )
        .expect("the Gate removed")
        .removed
    }

    /// The Gate events in the Event Log, in order.
    fn gate_events(&self) -> Vec<(Action, String, String, String, String)> {
        EventLog::in_data_directory(&self.data())
            .read(&self.keys)
            .expect("a readable Event Log")
            .events
            .into_iter()
            .filter(|recorded| {
                matches!(
                    recorded.event.action,
                    Action::GateRegistered | Action::GateRemoved
                )
            })
            .map(|recorded| {
                let event = recorded.event;
                (
                    event.action,
                    event.detail.get("agent").cloned().unwrap_or_default(),
                    event.detail.get("locator").cloned().unwrap_or_default(),
                    event.content_hash,
                    event
                        .item_id
                        .map(|id| id.as_str().to_string())
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    /// Spec acceptance: no test touches the real home. Every path the Gate
    /// wrote sits inside this sandbox, which sits in the temporary directory.
    fn assert_stays_inside(&self, entries: &[GateEntry]) {
        assert!(self.root.starts_with(std::env::temp_dir()));
        assert!(self.machine().home().starts_with(&self.root));
        for entry in entries {
            assert!(
                entry.path.starts_with(&self.root),
                "{} is outside the sandbox",
                entry.path.display()
            );
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn expected_events(
    action: Action,
    entries: &[GateEntry],
) -> Vec<(Action, String, String, String, String)> {
    entries
        .iter()
        .map(|entry| {
            (
                action,
                "claude-code".to_string(),
                entry.locator.clone(),
                entry.content_hash.clone(),
                entry.item_id.as_str().to_string(),
            )
        })
        .collect()
}

/// Spec sections 4.6.4 and 7.6: the registration is AgentSweep's own write,
/// so the Full Scan after it reads the three Hook Items `unchanged`, raises
/// no Finding of any Tier on them and no Drift anywhere.
#[test]
fn a_full_scan_after_registration_accepts_the_three_hook_items_as_agentsweeps_write() {
    let sandbox = Sandbox::new("accepted");
    // The first Full Scan covers the user settings file, so a Hook Item that
    // appears after it is `added` unless a known action stands behind it.
    let first = sandbox.full_scan();
    assert!(
        first
            .standing
            .iter()
            .all(|found| found.finding.source != Source::Drift),
        "{:?}",
        first.standing
    );

    let written = sandbox.register();
    sandbox.assert_stays_inside(&written);
    assert_eq!(written.len(), 3, "{written:?}");
    assert_eq!(
        sandbox.gate_events(),
        expected_events(Action::GateRegistered, &written),
        "one gate-registered event per entry, naming the Agent, the locator and the hash"
    );

    let second = sandbox.full_scan();
    for entry in &written {
        assert!(
            second.looked_at.contains(&entry.item_id),
            "{} was not enumerated",
            entry.item_id
        );
        assert!(
            second
                .standing
                .iter()
                .all(|found| found.finding.item_id != entry.item_id),
            "a Finding on {}: {:?}",
            entry.item_id,
            second.standing
        );
    }
    assert!(
        second
            .standing
            .iter()
            .all(|found| found.finding.source != Source::Drift),
        "{:?}",
        second.standing
    );
    let baseline = Baseline::in_data_directory(&sandbox.data())
        .read(&sandbox.keys)
        .expect("a readable Baseline");
    for entry in &written {
        let record = baseline.record(&entry.item_id).expect("a Baseline record");
        assert_eq!(record.kind, Kind::Hook);
        assert_eq!(record.accepted_hash, entry.content_hash, "unchanged");
        assert_eq!(record.last_seen_hash, entry.content_hash);
        assert_eq!(record.accepted_by, AcceptedBy::AgentsweepWrite);
    }

    // Registering again finds every entry in place: nothing is written and
    // nothing is recorded.
    assert!(sandbox.register().is_empty());
    assert_eq!(sandbox.gate_events().len(), 3);
    assert_eq!(
        ClaudeCode::new().check_gate(&sandbox.machine().host(Vec::new()), &GateCommand::at(CLI)),
        GateCheck::Registered
    );
}

/// Without the event the same entries are a change nobody stands behind,
/// which is the Drift question the registration must not raise.
#[test]
fn the_same_entries_without_the_event_are_drift() {
    let sandbox = Sandbox::new("unrecorded");
    sandbox.full_scan();
    ClaudeCode::new()
        .register_gate(
            &sandbox.machine().host(Vec::new()),
            &agentsweep_core::gate_registration::AtomicWriter,
            &GateCommand::at(CLI),
        )
        .expect("written without a record");
    let run = sandbox.full_scan();
    assert!(
        run.standing
            .iter()
            .any(|found| found.finding.source == Source::Drift),
        "{:?}",
        run.standing
    );
}

#[test]
fn removal_takes_the_entries_away_and_records_each_one() {
    let sandbox = Sandbox::new("removed");
    sandbox.full_scan();
    let written = sandbox.register();

    let removed = sandbox.remove();
    sandbox.assert_stays_inside(&removed);

    assert_eq!(removed, written);
    assert_eq!(
        std::fs::read_to_string(sandbox.settings()).expect("the settings file"),
        USERS_OWN,
        "the user's own group and every other key are as they were"
    );
    let mut expected = expected_events(Action::GateRegistered, &written);
    expected.extend(expected_events(Action::GateRemoved, &removed));
    assert_eq!(sandbox.gate_events(), expected);

    // The Hook Items are gone, which is never a Finding.
    let run = sandbox.full_scan();
    assert!(
        run.standing
            .iter()
            .all(|found| found.finding.source != Source::Drift),
        "{:?}",
        run.standing
    );
}
