//! The registration check every Full Scan runs, end to end (spec sections
//! 6.4, 6.6 and 7.6).
//!
//! Every test runs Full Scans against a temporary home with a temporary data
//! directory and the chain key held in the process. The administrator's
//! directories are a `system` directory beside the home, the way a fixture
//! lays them out. Nothing touches the real home, the real data directory or
//! the login Keychain, and the command line interface the entries name is a
//! path nothing runs.
//!
//! Notifications are the app's, fired for Finding changes the daemon has not
//! yet recorded as notified (spec section 6.7): a Scan that raises no Finding
//! notifies nobody, which is how "no notification" is checked here.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::drift::Change;
use agentsweep_core::entry_edit::{EntryPath, Format, drop_toml, insert_toml, read_entry};
use agentsweep_core::evaluation::NoCache;
use agentsweep_core::eventlog::{Action, EventLog};
use agentsweep_core::finding::Source;
use agentsweep_core::gate_registration::{GateCheck, GateCommand};
use agentsweep_core::health::{GateLine, GateTrouble};
use agentsweep_core::keychain::MemoryKeySource;
use agentsweep_core::packs::LoadedPack;
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::scan_pass::BACKGROUND_WORKERS;
use agentsweep_core::state::Trigger;
use agentsweep_daemon::full_scan::{FullScan, ScanRun, Unwatched};
use agentsweep_daemon::machine::Machine;
use serde_json::{Value, json};

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_adapter_codex::Codex;

/// Keeps one test's temporary paths apart from another's.
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Where the bundle puts the command line interface. Nothing runs it, and it
/// sits outside every temporary directory.
const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";

/// One temporary machine with both Agents installed and one temporary data
/// directory.
struct Sandbox {
    root: PathBuf,
    keys: MemoryKeySource,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-gate-check-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Claude Code");
        std::fs::create_dir_all(root.join("home/.codex")).expect("an installed Codex");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
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

    fn hooks(&self) -> PathBuf {
        self.root.join("home/.codex/hooks.json")
    }

    fn config(&self) -> PathBuf {
        self.root.join("home/.codex/config.toml")
    }

    /// Writes a file below the sandbox, creating the directories above it.
    fn write(&self, relative: &str, content: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(&path, content).expect("a file");
        path
    }

    /// One Full Scan that verifies and mends the Gate's registration, the
    /// way the daemon's Full Scans do. The bundled pack is compiled once for
    /// the whole test binary, as the daemon compiles it once.
    fn full_scan(&self) -> ScanRun {
        self.full_scan_with(Some(&GateCommand::at(CLI)))
    }

    /// One Full Scan that verifies and mends the Gate's registration under
    /// this command, or leaves the Gate alone when handed none.
    fn full_scan_with(&self, command: Option<&GateCommand>) -> ScanRun {
        static PACK: OnceLock<LoadedPack> = OnceLock::new();
        let pack = PACK.get_or_init(|| LoadedPack::bundled().expect("the bundled pack"));
        let readable = std::collections::BTreeSet::new();
        FullScan {
            machine: &self.machine(),
            access: agentsweep_daemon::permission::Access {
                readable: &readable,
                folders: &agentsweep_daemon::permission::Disk,
            },
            directory: &self.data(),
            keys: &self.keys,
            pack: &pack.rules,
            manifest: &pack.manifest,
            previous: &[],
            cache: &NoCache,
            workers: BACKGROUND_WORKERS,
            progress: &Unwatched,
            acts: true,
            gate: command,
        }
        .run(Trigger::ScanNow)
        .expect("a Full Scan")
    }

    /// The Gate events in the Event Log, in order: the action and the Item.
    fn gate_events(&self) -> Vec<(Action, String)> {
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
                (
                    recorded.event.action,
                    recorded
                        .event
                        .item_id
                        .map(|id| id.as_str().to_string())
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    /// A command line interface that reads as a native executable, built
    /// into `target/debug` of a checkout at `checkout`, below the sandbox.
    /// Its bytes are a Mach-O header and nothing else, so nothing could run
    /// it.
    fn built_cli(&self, checkout: &str) -> GateCommand {
        let path = self.root.join(checkout).join("target/debug/agentsweep");
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe];
        bytes.resize(64, 0);
        std::fs::write(&path, bytes).expect("a built command line interface");
        GateCommand::at(path)
    }

    fn check(&self, adapter: &dyn SurfaceAdapter) -> GateCheck {
        adapter.check_gate(&self.machine().host(Vec::new()), &GateCommand::at(CLI))
    }

    fn read_json(&self, path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("the file")).expect("JSON")
    }

    fn write_json(&self, path: &Path, value: &Value) {
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(value).expect("JSON")),
        )
        .expect("the file");
    }

    /// The Codex pin of the group at `index` of `event`, by its snake-case
    /// state name.
    fn pin_key(&self, event: &str) -> String {
        format!("{}:{event}:0:0", self.hooks().display())
    }

    fn edit_config(&self, edit: impl Fn(&str) -> String) {
        let text = std::fs::read_to_string(self.config()).expect("the config layer");
        std::fs::write(self.config(), edit(&text)).expect("the config layer");
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // A test that took write permission away gives it back, so the
        // sandbox can go.
        for directory in ["home/.claude", "home/.codex"] {
            let path = self.root.join(directory);
            if path.exists() {
                let _ = set_mode(&path, 0o755);
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn record(path: &[&str]) -> EntryPath {
    EntryPath::of(path)
}

/// The ids of the Gate's own entries a Scan wrote, by the events it appended.
fn registered_since(before: usize, events: &[(Action, String)]) -> Vec<String> {
    events[before..]
        .iter()
        .filter(|(action, _)| *action == Action::GateRegistered)
        .map(|(_, id)| id.clone())
        .collect()
}

/// Spec sections 6.8 and 7.6: the first Full Scan registers the Gate with
/// both detected Agents, and the Full Scan after it finds every entry in
/// place, writes nothing and appends no event.
#[test]
fn the_first_full_scan_registers_both_agents_and_the_next_writes_nothing() {
    let sandbox = Sandbox::new("first");
    let first = sandbox.full_scan();
    assert_eq!(first.gate_lines, Some(Vec::new()));
    let events = sandbox.gate_events();
    let claude = events
        .iter()
        .filter(|(_, id)| id.starts_with("claude-code/"))
        .count();
    let codex = events
        .iter()
        .filter(|(_, id)| id.starts_with("codex/"))
        .count();
    assert_eq!((claude, codex), (3, 2), "{events:?}");
    assert!(
        events
            .iter()
            .all(|(action, _)| *action == Action::GateRegistered)
    );
    assert_eq!(sandbox.check(&ClaudeCode::new()), GateCheck::Registered);
    assert_eq!(sandbox.check(&Codex::new()), GateCheck::Registered);
    // The Scan that registered already read its own write: no Finding and
    // no Drift on the entries it left.
    for (_, id) in &events {
        assert!(
            first.looked_at.iter().any(|seen| seen.as_str() == id),
            "{id}"
        );
    }
    assert!(first.standing.is_empty(), "{:?}", first.standing);

    let settings = std::fs::read(sandbox.settings()).expect("the settings file");
    let hooks = std::fs::read(sandbox.hooks()).expect("the hooks file");
    let config = std::fs::read(sandbox.config()).expect("the config layer");
    let second = sandbox.full_scan();
    assert_eq!(second.gate_lines, Some(Vec::new()));
    assert_eq!(sandbox.gate_events(), events, "no event appended");
    assert_eq!(
        std::fs::read(sandbox.settings()).expect("the file"),
        settings
    );
    assert_eq!(std::fs::read(sandbox.hooks()).expect("the file"), hooks);
    assert_eq!(std::fs::read(sandbox.config()).expect("the file"), config);
    assert!(second.standing.is_empty(), "{:?}", second.standing);
}

/// AgentSweep's own Gate entries are never a Finding, wherever the command
/// line interface they name lives: in the app bundle, in `target/debug` of a
/// checkout, and in `target/debug` of a checkout below a `.claude` directory,
/// which is where Claude Code keeps its worktrees and where Rule 0014 reads an
/// Agent configuration directory. Neither the Full Scan that registers nor the
/// one after it raises a Finding on any of them, for either Agent.
#[test]
fn a_full_scan_right_after_registration_raises_no_finding_on_the_gates_entries() {
    let checkouts = [
        ("bundle", None),
        ("checkout", Some("checkout")),
        ("worktree", Some("checkout/.claude/worktrees/integration")),
    ];
    for (name, checkout) in checkouts {
        let sandbox = Sandbox::new(&format!("own-{name}"));
        let command = match checkout {
            Some(checkout) => sandbox.built_cli(checkout),
            None => GateCommand::at(CLI),
        };
        let first = sandbox.full_scan_with(Some(&command));
        let events = sandbox.gate_events();
        let claude = events
            .iter()
            .filter(|(_, id)| id.starts_with("claude-code/"))
            .count();
        let codex = events
            .iter()
            .filter(|(_, id)| id.starts_with("codex/"))
            .count();
        assert_eq!((claude, codex), (3, 2), "{name}: {events:?}");
        for (_, id) in &events {
            assert!(
                first.looked_at.iter().any(|seen| seen.as_str() == id),
                "{name}: {id}"
            );
        }
        assert!(first.standing.is_empty(), "{name}: {:?}", first.standing);

        let second = sandbox.full_scan_with(Some(&command));
        assert_eq!(sandbox.gate_events(), events, "{name}: no event appended");
        assert!(second.standing.is_empty(), "{name}: {:?}", second.standing);
    }
}

/// What clears the Gate's entries is AgentSweep's own registration of exactly
/// that content, not their look: the same entries copied onto a machine whose
/// Event Log never registered them are judged like any other hook, and a
/// native executable below a `.claude` directory is Rule 0014's.
#[test]
fn the_same_entries_written_by_someone_else_are_judged() {
    let registered = Sandbox::new("copied-from");
    let command = registered.built_cli("checkout/.claude/worktrees/integration");
    registered.full_scan_with(Some(&command));

    let copied = Sandbox::new("copied-to");
    for (from, to) in [
        (registered.settings(), copied.settings()),
        (registered.hooks(), copied.hooks()),
        (registered.config(), copied.config()),
    ] {
        std::fs::copy(from, to).expect("a copied file");
    }
    let run = copied.full_scan_with(None);
    let hits: Vec<&str> = run
        .standing
        .iter()
        .filter(|found| found.finding.source == Source::Rule(14))
        .map(|found| found.finding.item_id.as_str())
        .collect();
    assert_eq!(
        hits.iter()
            .filter(|id| id.starts_with("claude-code/user/hook/"))
            .count(),
        3,
        "{:?}",
        run.standing
    );
    assert_eq!(
        hits.iter()
            .filter(|id| id.starts_with("codex/user/hook/"))
            .count(),
        2,
        "{:?}",
        run.standing
    );
}

/// One way the Gate's registration can be undone between two Full Scans.
struct Failure {
    name: &'static str,
    mutate: fn(&Sandbox),
    /// True when the mutation edits an entry in a way that leaves it in the
    /// file beside the fresh one, a Hook Item the Drift rules show.
    leaves_an_edited_entry: bool,
}

fn edit_claude_group(sandbox: &Sandbox, event: &str, edit: impl Fn(&mut Value)) {
    let mut file = sandbox.read_json(&sandbox.settings());
    let groups = file["hooks"][event].as_array_mut().expect("groups");
    let ours = groups
        .iter_mut()
        .find(|group| group["hooks"][0]["args"][0] == "gate")
        .expect("the Gate's group");
    edit(ours);
    sandbox.write_json(&sandbox.settings(), &file);
}

fn failures() -> Vec<Failure> {
    vec![
        Failure {
            name: "an entry deleted",
            mutate: |sandbox| {
                let mut file = sandbox.read_json(&sandbox.settings());
                file["hooks"]
                    .as_object_mut()
                    .expect("hooks")
                    .remove("UserPromptSubmit");
                sandbox.write_json(&sandbox.settings(), &file);
            },
            leaves_an_edited_entry: false,
        },
        Failure {
            name: "its command changed",
            mutate: |sandbox| {
                edit_claude_group(sandbox, "PreToolUse", |group| {
                    group["hooks"][0]["command"] =
                        json!("/Volumes/Old/AgentSweep.app/Contents/MacOS/agentsweep");
                });
            },
            leaves_an_edited_entry: false,
        },
        Failure {
            name: "its arguments changed",
            mutate: |sandbox| {
                edit_claude_group(sandbox, "UserPromptExpansion", |group| {
                    group["hooks"][0]["args"] = json!(["gate", "--agent", "claude-code", "-q"]);
                });
            },
            leaves_an_edited_entry: true,
        },
        Failure {
            name: "its timeout changed",
            mutate: |sandbox| {
                edit_claude_group(sandbox, "UserPromptSubmit", |group| {
                    group["hooks"][0]["timeout"] = json!(600);
                });
            },
            leaves_an_edited_entry: true,
        },
        Failure {
            name: "the Codex pin deleted",
            mutate: |sandbox| {
                let key = sandbox.pin_key("user_prompt_submit");
                sandbox.edit_config(|text| {
                    drop_toml(text, &record(&["hooks", "state", &key]))
                        .expect("dropped")
                        .0
                });
            },
            leaves_an_edited_entry: false,
        },
        Failure {
            name: "the pin's hash changed",
            mutate: |sandbox| {
                let key = sandbox.pin_key("pre_tool_use");
                sandbox.edit_config(|text| {
                    insert_toml(
                        text,
                        &record(&["hooks", "state", &key]),
                        &json!({"trusted_hash": format!("sha256:{}", "0".repeat(64))}),
                    )
                    .expect("a stale pin")
                });
            },
            leaves_an_edited_entry: false,
        },
        Failure {
            name: "enabled = false on the pin",
            mutate: |sandbox| {
                let key = sandbox.pin_key("user_prompt_submit");
                sandbox.edit_config(|text| {
                    let path = record(&["hooks", "state", &key]);
                    let mut pin = read_entry(Format::Toml, text, &path).expect("a pin");
                    pin["enabled"] = json!(false);
                    insert_toml(text, &path, &pin).expect("switched off")
                });
            },
            leaves_an_edited_entry: false,
        },
    ]
}

/// Spec section 7.6: every failure is mended by the next Full Scan, silently.
/// The mending write is a known action, so the Scan that writes it and the
/// one after raise no Finding on the fresh entry, no Health line is raised,
/// and `gate-registered` events are appended.
#[test]
fn each_failure_is_mended_by_the_next_full_scan_silently() {
    for failure in failures() {
        let sandbox = Sandbox::new("failure");
        sandbox.full_scan();
        sandbox.full_scan();
        let before = sandbox.gate_events().len();

        (failure.mutate)(&sandbox);
        let mending = sandbox.full_scan();

        let name = failure.name;
        assert_eq!(mending.gate_lines, Some(Vec::new()), "{name}");
        let events = sandbox.gate_events();
        let fresh = registered_since(before, &events);
        assert!(!fresh.is_empty(), "{name}: no gate-registered event");
        assert_eq!(
            sandbox.check(&ClaudeCode::new()),
            GateCheck::Registered,
            "{name}"
        );
        assert_eq!(
            sandbox.check(&Codex::new()),
            GateCheck::Registered,
            "{name}"
        );

        let after = sandbox.full_scan();
        assert_eq!(
            sandbox.gate_events().len(),
            events.len(),
            "{name}: mended once"
        );
        for run in [&mending, &after] {
            for id in &fresh {
                assert!(
                    run.standing
                        .iter()
                        .all(|found| found.finding.item_id.as_str() != id),
                    "{name}: a Finding on the fresh entry {id}: {:?}",
                    run.standing
                );
            }
            let others: Vec<_> = run
                .standing
                .iter()
                .filter(|found| found.finding.source != Source::Drift)
                .collect();
            assert!(others.is_empty(), "{name}: {others:?}");
            match failure.leaves_an_edited_entry {
                true => assert_eq!(run.standing.len(), 1, "{name}: {:?}", run.standing),
                false => assert!(run.standing.is_empty(), "{name}: {:?}", run.standing),
            }
        }
    }
}

/// Spec section 7.6: an entry an attacker edited is not repaired in place.
/// It stays in the file beside the fresh one, a Hook Item whose locator
/// changed, which the Scan shows as Drift: the edited Hook Item is new
/// where AgentSweep's entry stood, which is "replaced".
#[test]
fn an_edited_entry_stays_beside_the_fresh_one_and_shows_as_drift() {
    let sandbox = Sandbox::new("edited");
    let first = sandbox.full_scan();
    sandbox.full_scan();
    let original: Vec<String> = sandbox
        .gate_events()
        .into_iter()
        .map(|(_, id)| id)
        .filter(|id| id.contains("#UserPromptSubmit/"))
        .filter(|id| id.starts_with("claude-code/"))
        .collect();
    assert_eq!(original.len(), 1);
    assert!(first.looked_at.iter().any(|id| id.as_str() == original[0]));

    edit_claude_group(&sandbox, "UserPromptSubmit", |group| {
        group["hooks"][0]["timeout"] = json!(600);
    });
    let run = sandbox.full_scan();

    let file = sandbox.read_json(&sandbox.settings());
    let groups = file["hooks"]["UserPromptSubmit"]
        .as_array()
        .expect("groups");
    assert_eq!(groups.len(), 2, "{file}");
    assert_eq!(
        groups[0]["hooks"][0]["timeout"], 600,
        "the edited one stays"
    );
    assert_eq!(
        groups[1]["hooks"][0]["timeout"], 5,
        "the fresh one is appended"
    );

    let drift: Vec<_> = run
        .standing
        .iter()
        .filter(|found| found.finding.source == Source::Drift)
        .collect();
    assert_eq!(drift.len(), 1, "{:?}", run.standing);
    let edited = &drift[0].finding;
    assert!(
        edited
            .item_id
            .as_str()
            .starts_with("claude-code/user/hook/")
    );
    assert!(edited.item_id.as_str().contains("#UserPromptSubmit/"));
    assert_ne!(edited.item_id.as_str(), original[0]);
    assert_eq!(
        edited.drift.as_ref().map(|drift| drift.change),
        Some(Change::Added)
    );
    // The fresh entry is AgentSweep's own write under the original locator,
    // known to the Scan, so it raises nothing.
    assert!(run.looked_at.iter().any(|id| id.as_str() == original[0]));
    assert!(
        run.standing
            .iter()
            .all(|found| found.finding.item_id.as_str() != original[0])
    );
}

/// Spec section 7.6: managed policy that drops the user's hooks means no
/// write for that Agent and the managed-policy line; once the policy goes, a
/// Full Scan registers and the line clears.
#[test]
fn managed_policy_writes_nothing_and_raises_its_line_until_it_goes() {
    let sandbox = Sandbox::new("managed");
    let claude = sandbox.write(
        "system/Library/Application Support/ClaudeCode/managed-settings.json",
        "{\"allowManagedHooksOnly\": true}",
    );
    let codex = sandbox.write(
        "system/etc/codex/requirements.toml",
        "allow_managed_hooks_only = true\n",
    );

    let blocked = sandbox.full_scan();

    let lines = blocked.gate_lines.expect("checked");
    assert_eq!(
        lines,
        vec![
            GateLine {
                agent: "claude-code".to_string(),
                name: "Claude Code".to_string(),
                trouble: GateTrouble::ManagedPolicy,
            },
            GateLine {
                agent: "codex".to_string(),
                name: "Codex".to_string(),
                trouble: GateTrouble::ManagedPolicy,
            },
        ]
    );
    assert!(sandbox.gate_events().is_empty());
    assert!(!sandbox.settings().exists());
    assert!(!sandbox.hooks().exists());
    assert!(!sandbox.config().exists());

    std::fs::remove_file(claude).expect("the policy goes");
    std::fs::remove_file(codex).expect("the policy goes");
    let cleared = sandbox.full_scan();
    assert_eq!(cleared.gate_lines, Some(Vec::new()));
    assert_eq!(sandbox.gate_events().len(), 5);
    assert_eq!(sandbox.check(&ClaudeCode::new()), GateCheck::Registered);
    assert_eq!(sandbox.check(&Codex::new()), GateCheck::Registered);
}

/// A managed `disableAllHooks` counts as managed policy (the owner's
/// decision of 2026-10-14).
#[test]
fn a_managed_disable_all_hooks_is_managed_policy() {
    let sandbox = Sandbox::new("managed-disable");
    sandbox.write(
        "system/Library/Application Support/ClaudeCode/managed-settings.json",
        "{\"disableAllHooks\": true}",
    );
    let run = sandbox.full_scan();
    let lines = run.gate_lines.expect("checked");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].agent, "claude-code");
    assert_eq!(lines[0].trouble, GateTrouble::ManagedPolicy);
    assert!(!sandbox.settings().exists());
}

/// A registration write that fails raises the registration-failed line for
/// that Agent alone; the other Agent is registered. The line clears on the
/// first Full Scan whose check passes.
#[test]
fn an_unwritable_settings_file_raises_the_registration_failed_line() {
    let sandbox = Sandbox::new("unwritable");
    std::fs::write(sandbox.settings(), "{}\n").expect("a settings file");
    // The write goes through a temporary file renamed over the original, so
    // the directory is what has to refuse it.
    set_mode(&sandbox.root.join("home/.claude"), 0o555).expect("read only");

    let failed = sandbox.full_scan();

    assert_eq!(
        failed.gate_lines,
        Some(vec![GateLine {
            agent: "claude-code".to_string(),
            name: "Claude Code".to_string(),
            trouble: GateTrouble::RegistrationFailed,
        }])
    );
    assert_eq!(
        std::fs::read_to_string(sandbox.settings()).expect("the file"),
        "{}\n"
    );
    assert_eq!(sandbox.check(&Codex::new()), GateCheck::Registered);

    set_mode(&sandbox.root.join("home/.claude"), 0o755).expect("writable again");
    let passed = sandbox.full_scan();
    assert_eq!(passed.gate_lines, Some(Vec::new()));
    assert_eq!(sandbox.check(&ClaudeCode::new()), GateCheck::Registered);
}

/// An Agent that is not detected is neither registered nor named; one
/// installed later is registered by the next Full Scan.
#[test]
fn an_agent_that_is_not_detected_is_left_alone_until_it_is_installed() {
    let sandbox = Sandbox::new("detected");
    std::fs::remove_dir_all(sandbox.root.join("home/.codex")).expect("no Codex");

    let run = sandbox.full_scan();
    assert_eq!(run.gate_lines, Some(Vec::new()));
    assert!(
        !sandbox.root.join("home/.codex").exists(),
        "nothing written"
    );
    assert!(
        sandbox
            .gate_events()
            .iter()
            .all(|(_, id)| id.starts_with("claude-code/"))
    );

    // Even where something about Codex would raise a line, an Agent that is
    // not there is not named.
    sandbox.write(
        "system/etc/codex/requirements.toml",
        "allow_managed_hooks_only = true\n",
    );
    assert_eq!(sandbox.full_scan().gate_lines, Some(Vec::new()));
    std::fs::remove_file(sandbox.root.join("system/etc/codex/requirements.toml"))
        .expect("the policy goes");

    std::fs::create_dir_all(sandbox.root.join("home/.codex")).expect("Codex installed");
    let before = sandbox.gate_events().len();
    let installed = sandbox.full_scan();
    assert_eq!(installed.gate_lines, Some(Vec::new()));
    let fresh = registered_since(before, &sandbox.gate_events());
    assert_eq!(fresh.len(), 2, "{fresh:?}");
    assert!(fresh.iter().all(|id| id.starts_with("codex/")));
    assert_eq!(sandbox.check(&Codex::new()), GateCheck::Registered);
}

/// The owner's decision of 2026-10-14: a User-scope `disableAllHooks` and
/// Codex's user-layer `[features] hooks = false` are the user's own choice.
/// They are never written; the entries are kept in place and the line says
/// the Gate cannot run there.
#[test]
fn the_users_own_switch_is_never_written_and_raises_its_line() {
    let sandbox = Sandbox::new("user-off");
    std::fs::write(sandbox.settings(), "{\n  \"disableAllHooks\": true\n}\n")
        .expect("a settings file");
    std::fs::write(sandbox.config(), "[features]\nhooks = false\n").expect("a config layer");

    let run = sandbox.full_scan();

    assert_eq!(
        run.gate_lines,
        Some(vec![
            GateLine {
                agent: "claude-code".to_string(),
                name: "Claude Code".to_string(),
                trouble: GateTrouble::SwitchedOffByUser,
            },
            GateLine {
                agent: "codex".to_string(),
                name: "Codex".to_string(),
                trouble: GateTrouble::SwitchedOffByUser,
            },
        ])
    );
    assert_eq!(
        sandbox.read_json(&sandbox.settings())["disableAllHooks"],
        true
    );
    let config = std::fs::read_to_string(sandbox.config()).expect("the config layer");
    assert!(
        config.starts_with("[features]\nhooks = false\n"),
        "{config}"
    );
    assert_eq!(
        sandbox.gate_events().len(),
        5,
        "the entries are kept in place"
    );

    // Switching hooks back on is the user's to do; the next Full Scan finds
    // the entries in place and the line clears.
    let mut file = sandbox.read_json(&sandbox.settings());
    file.as_object_mut()
        .expect("an object")
        .remove("disableAllHooks");
    sandbox.write_json(&sandbox.settings(), &file);
    sandbox.edit_config(|text| text.replacen("hooks = false", "hooks = true", 1));
    let back = sandbox.full_scan();
    assert_eq!(back.gate_lines, Some(Vec::new()));
    assert_eq!(sandbox.gate_events().len(), 5);
}

/// The daemon carries the lines its Full Scans leave in Health, at their
/// rung, and drops a line on the first Full Scan whose check passes.
#[test]
fn the_daemon_carries_the_line_in_health_until_a_check_passes() {
    use agentsweep_core::health::Rung;
    use agentsweep_core::settings::Posture;
    use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
    use agentsweep_daemon::{Daemon, Tuning};

    let sandbox = Sandbox::new("daemon");
    std::fs::write(sandbox.settings(), "{}\n").expect("a settings file");
    set_mode(&sandbox.root.join("home/.claude"), 0o555).expect("read only");
    let options = Options {
        data_dir: sandbox.data(),
        socket: sandbox.root.join("unused.sock"),
        home: Some(sandbox.root.join("home")),
        key_source: KeySourceChoice::Memory,
        log: LogChoice::Stderr,
    };
    let daemon = Daemon::open_tuned(
        &options,
        std::sync::Arc::new(agentsweep_ipc::peer::SameUser),
        Box::new(MemoryKeySource::empty()),
        Tuning {
            gate: Some(GateCommand::at(CLI)),
            ..Tuning::default()
        },
    )
    .expect("an open daemon");
    // Asks for a Full Scan and waits until one that started after the last
    // has finished.
    let full_scan = || {
        let before = daemon.status().scan.map(|scan| scan.started_at);
        daemon.scan(Trigger::ScanNow);
        for _ in 0..12_000 {
            let after = daemon.status().scan.map(|scan| scan.started_at);
            if !daemon.health().scanning && after.is_some() && after != before {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("the Full Scan did not finish");
    };

    full_scan();
    let health = daemon.health();
    assert_eq!(health.rung(), Rung::GateLine, "{health:?}");
    assert_eq!(
        health.headline(),
        "The check could not be added to Claude Code."
    );
    assert_eq!(
        health.headline_in(Posture::Developer),
        "Gate registration failed: Claude Code."
    );

    set_mode(&sandbox.root.join("home/.claude"), 0o755).expect("writable again");
    full_scan();
    let health = daemon.health();
    assert!(health.gate_lines.is_empty(), "{health:?}");
    assert!(
        health.headline().starts_with("All clear"),
        "{}",
        health.headline()
    );
}
