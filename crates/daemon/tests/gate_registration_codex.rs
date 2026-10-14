//! The Gate's Codex entries written and taken away through the daemon, end
//! to end.
//!
//! The daemon registers the Gate with Codex by appending its two hook groups
//! to the user hooks file and pinning each in the user config layer, records
//! one `gate-registered` event per Hook Item, and the next Full Scan reads
//! both Hook Items as AgentSweep's own write and active, with no Finding of
//! any Tier and no Drift on the hooks or the pin records (spec sections
//! 4.6.4, 4.6.5, 7.2 and 7.6). Every test runs against a temporary home and a
//! temporary data directory with the chain key held in the process; nothing
//! touches the real home, the real data directory or the login Keychain.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_adapter_codex::Codex;
use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::baseline::{AcceptedBy, Baseline};
use agentsweep_core::eventlog::{Action, EventLog};
use agentsweep_core::finding::Source;
use agentsweep_core::gate_registration::{GateCheck, GateCommand, GateEntry};
use agentsweep_core::item::{Activation, Kind};
use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::state::Trigger;
use agentsweep_daemon::full_scan::{self, ScanRun, Unwatched};
use agentsweep_daemon::gate;
use agentsweep_daemon::machine::Machine;

/// Keeps one test's temporary paths apart from another's.
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Where the bundle puts the command line interface. Nothing runs it, and it
/// sits outside every temporary directory so no Rule reads it as a command
/// planted in one.
const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";

/// A user hooks file with a group of the user's own.
const USERS_HOOKS: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/.codex/lint.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
"#;

/// A user config layer with comments and tables of the user's own.
const USERS_CONFIG: &str = "# The user's own layer.\n\
model = \"gpt-5-codex\"\n\
\n\
[features]\n\
hooks = true\n\
\n\
# Shown in the terminal.\n\
[tui]\n\
notifications = true\n";

/// One temporary machine and one temporary data directory.
struct Sandbox {
    root: PathBuf,
    keys: MemoryKeySource,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-gate-registration-codex-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.codex")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        std::fs::write(root.join("home/.codex/hooks.json"), USERS_HOOKS).expect("a hooks file");
        std::fs::write(root.join("home/.codex/config.toml"), USERS_CONFIG).expect("a config layer");
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

    fn hooks(&self) -> PathBuf {
        self.root.join("home/.codex/hooks.json")
    }

    fn config(&self) -> PathBuf {
        self.root.join("home/.codex/config.toml")
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
            &Codex::new(),
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
            &Codex::new(),
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
                "codex".to_string(),
                entry.locator.clone(),
                entry.content_hash.clone(),
                entry.item_id.as_str().to_string(),
            )
        })
        .collect()
}

fn no_drift(run: &ScanRun) {
    assert!(
        run.standing
            .iter()
            .all(|found| found.finding.source != Source::Drift),
        "{:?}",
        run.standing
    );
}

/// Spec sections 4.6.4, 4.6.5 and 7.6: the registration is AgentSweep's own
/// write, so the Full Scan after it reads both Hook Items `unchanged` and
/// active, raises no Finding of any Tier on them, and the pin records raise
/// no Drift.
#[test]
fn a_full_scan_after_registration_accepts_both_hook_items_and_the_pins() {
    let sandbox = Sandbox::new("accepted");
    // The first Full Scan covers the user hooks file and the config layer, so
    // a Hook Item that appears after it is `added` unless a known action
    // stands behind it.
    no_drift(&sandbox.full_scan());

    let written = sandbox.register();
    sandbox.assert_stays_inside(&written);
    assert_eq!(written.len(), 2, "{written:?}");
    assert_eq!(
        sandbox.gate_events(),
        expected_events(Action::GateRegistered, &written),
        "one gate-registered event per entry, naming the Agent, the locator and the hash"
    );

    let second = sandbox.full_scan();
    no_drift(&second);
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
    let host = sandbox.machine().host(Vec::new());
    let enumeration = Codex::new().enumerate(&host, &[]);
    for entry in &written {
        let item = enumeration
            .items
            .iter()
            .find(|item| item.id == entry.item_id)
            .expect("the Hook Item");
        assert_eq!(item.activation, Activation::Active, "pinned and trusted");
    }
    let baseline = Baseline::in_data_directory(&sandbox.data())
        .read(&sandbox.keys)
        .expect("a readable Baseline");
    for entry in &written {
        let record = baseline.record(&entry.item_id).expect("a Baseline record");
        assert_eq!(record.kind, Kind::Hook);
        assert_eq!(record.accepted_hash, entry.content_hash, "unchanged");
        assert_eq!(record.accepted_by, AcceptedBy::AgentsweepWrite);
    }

    // Registering again finds every entry in place and pinned: nothing is
    // written and nothing is recorded.
    assert!(sandbox.register().is_empty());
    assert_eq!(sandbox.gate_events().len(), 2);
    assert_eq!(
        Codex::new().check_gate(&host, &GateCommand::at(CLI)),
        GateCheck::Registered
    );
}

#[test]
fn removal_takes_the_entries_and_the_pins_away_and_records_each_one() {
    let sandbox = Sandbox::new("removed");
    sandbox.full_scan();
    let written = sandbox.register();

    let removed = sandbox.remove();
    sandbox.assert_stays_inside(&removed);

    assert_eq!(removed, written);
    assert_eq!(
        std::fs::read_to_string(sandbox.hooks()).expect("the hooks file"),
        USERS_HOOKS,
        "the user's own group is as it was"
    );
    assert_eq!(
        std::fs::read_to_string(sandbox.config()).expect("the config layer"),
        USERS_CONFIG,
        "every other key, comment and table is as it was"
    );
    let mut expected = expected_events(Action::GateRegistered, &written);
    expected.extend(expected_events(Action::GateRemoved, &removed));
    assert_eq!(sandbox.gate_events(), expected);

    // The Hook Items are gone, which is never a Finding.
    no_drift(&sandbox.full_scan());
}

/// Without the event the same pinned entries are a change nobody stands
/// behind, which is the Drift question the registration must not raise.
#[test]
fn the_same_entries_without_the_event_are_drift() {
    let sandbox = Sandbox::new("unrecorded");
    sandbox.full_scan();
    Codex::new()
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
