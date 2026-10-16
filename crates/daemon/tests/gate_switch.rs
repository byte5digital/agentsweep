//! The Gate switch through the daemon, end to end (spec sections 6.9, 7.6,
//! 8.10 and 9.6).
//!
//! Every daemon here runs against a temporary home with both Agents
//! installed, a temporary data directory and the chain key held in the
//! process. The administrator's directories are a `system` directory beside
//! the home. Nothing touches the real home, the real data directory or the
//! login Keychain, and the command line interface the entries name is a path
//! nothing runs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::eventlog::{Action, EventLog};
use agentsweep_core::gate_registration::{GateCheck, GateCommand};
use agentsweep_core::keychain::{ChainKey, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::paths::DataDirectory;
use agentsweep_core::settings::SettingsFile;
use agentsweep_core::state::Trigger;
use agentsweep_daemon::gate::Removal;
use agentsweep_daemon::machine::Machine;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service;
use agentsweep_daemon::{Daemon, Tuning};
use agentsweep_ipc::Client;
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::Role;

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_adapter_codex::Codex;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// Where the bundle puts the command line interface. Nothing runs it, and it
/// sits outside every temporary directory.
const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";

/// The user's own Claude Code settings, with a hook of their own.
const USERS_SETTINGS: &str = r#"{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/.claude/lint.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
"#;

/// The user's own Codex hooks file, with a group of their own.
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

/// The user's own Codex config layer.
const USERS_CONFIG: &str = "# The user's own layer.\n\
model = \"gpt-5-codex\"\n\
\n\
[features]\n\
hooks = true\n";

/// The one chain key a sandbox's daemons share, so a restarted daemon reads
/// the Event Log the first one wrote.
#[derive(Clone, Debug)]
struct SharedKey(Arc<MemoryKeySource>);

impl KeySource for SharedKey {
    fn load(&self) -> Result<Option<ChainKey>, KeyError> {
        self.0.load()
    }

    fn renew(&self) -> Result<ChainKey, KeyError> {
        self.0.renew()
    }

    fn forget(&self) -> Result<(), KeyError> {
        self.0.forget()
    }
}

struct Sandbox {
    root: PathBuf,
    keys: SharedKey,
}

impl Sandbox {
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-gate-switch-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Claude Code");
        std::fs::create_dir_all(root.join("home/.codex")).expect("an installed Codex");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        let sandbox = Sandbox {
            root,
            keys: SharedKey(Arc::new(MemoryKeySource::empty())),
        };
        std::fs::write(sandbox.claude_settings(), USERS_SETTINGS).expect("the user's settings");
        std::fs::write(sandbox.codex_hooks(), USERS_HOOKS).expect("the user's hooks");
        std::fs::write(sandbox.codex_config(), USERS_CONFIG).expect("the user's config");
        sandbox
    }

    fn machine(&self) -> Machine {
        Machine::named(self.root.join("home"))
    }

    fn data(&self) -> DataDirectory {
        DataDirectory::at(self.root.join("data"))
    }

    fn claude_settings(&self) -> PathBuf {
        self.root.join("home/.claude/settings.json")
    }

    fn codex_hooks(&self) -> PathBuf {
        self.root.join("home/.codex/hooks.json")
    }

    fn codex_config(&self) -> PathBuf {
        self.root.join("home/.codex/config.toml")
    }

    fn settings_file(&self) -> SettingsFile {
        SettingsFile::in_data_directory(&self.data())
    }

    fn socket(&self) -> PathBuf {
        // Short, because a socket path has a small limit.
        std::env::temp_dir().join(format!(
            "asg-{}-{}.sock",
            std::process::id(),
            self.root
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.rsplit('-').next())
                .unwrap_or("0")
        ))
    }

    fn options(&self) -> Options {
        Options {
            data_dir: self.data(),
            socket: self.socket(),
            home: Some(self.root.join("home")),
            key_source: KeySourceChoice::Memory,
            log: LogChoice::Stderr,
        }
    }

    /// A daemon on this sandbox whose Full Scans verify the Gate under the
    /// test's command line interface path.
    fn open(&self) -> Arc<Daemon> {
        Daemon::open_tuned(
            &self.options(),
            Arc::new(SameUser),
            Box::new(self.keys.clone()),
            Tuning {
                gate: Some(GateCommand::at(CLI)),
                ..Tuning::default()
            },
        )
        .expect("an open daemon")
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

    fn check(&self, adapter: &dyn SurfaceAdapter) -> GateCheck {
        adapter.check_gate(&self.machine().host(Vec::new()), &GateCommand::at(CLI))
    }

    fn registered(&self) -> bool {
        self.check(&ClaudeCode::new()) == GateCheck::Registered
            && self.check(&Codex::new()) == GateCheck::Registered
    }

    /// Neither Agent carries an AgentSweep entry, and the user's own files
    /// are exactly as they were.
    fn assert_only_the_users_own(&self) {
        assert!(
            matches!(self.check(&ClaudeCode::new()), GateCheck::Missing(_)),
            "{:?}",
            self.check(&ClaudeCode::new())
        );
        assert!(
            matches!(self.check(&Codex::new()), GateCheck::Missing(_)),
            "{:?}",
            self.check(&Codex::new())
        );
        assert_eq!(read(&self.claude_settings()), USERS_SETTINGS);
        assert_eq!(read(&self.codex_hooks()), USERS_HOOKS);
        assert_eq!(read(&self.codex_config()), USERS_CONFIG);
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = set_mode(&self.root.join("home/.claude"), 0o755);
        let _ = std::fs::remove_file(self.socket());
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("the file")
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Asks for a Full Scan and waits until one that started after the last has
/// finished.
fn full_scan(daemon: &Arc<Daemon>) {
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
}

fn count(events: &[(Action, String)], action: Action) -> usize {
    events.iter().filter(|(found, _)| *found == action).count()
}

/// Spec sections 7.6 and 8.10: switching off takes every AgentSweep entry and
/// pin away, one `gate-removed` event per entry, and leaves the user's own
/// hooks as they were; a Full Scan afterwards writes nothing, even where a
/// write would fail, and raises no Gate line and no Finding.
#[test]
fn switching_off_removes_every_entry_and_the_next_full_scan_writes_nothing() {
    let sandbox = Sandbox::new("off");
    let daemon = sandbox.open();
    full_scan(&daemon);
    assert!(
        sandbox.registered(),
        "the first Full Scan registers the Gate"
    );
    let registered = sandbox.gate_events();
    assert_eq!(count(&registered, Action::GateRegistered), 5);

    assert!(!daemon.set_gate_hooks(false).expect("switched"));
    let events = sandbox.gate_events();
    let removed: Vec<&String> = events[registered.len()..]
        .iter()
        .map(|(action, id)| {
            assert_eq!(*action, Action::GateRemoved);
            id
        })
        .collect();
    let written: Vec<&String> = registered.iter().map(|(_, id)| id).collect();
    let mut removed_sorted = removed.clone();
    removed_sorted.sort();
    let mut written_sorted = written.clone();
    written_sorted.sort();
    assert_eq!(removed_sorted, written_sorted, "one event per entry");
    sandbox.assert_only_the_users_own();
    assert!(!daemon.health().gate_hooks);
    assert!(!daemon.gate_hooks_enabled());
    assert!(
        !sandbox
            .settings_file()
            .read()
            .expect("a settings file")
            .gate_hooks
    );

    // A write would fail here and raise "could not be added", so a Full
    // Scan that raises no line proves it did not try.
    set_mode(&sandbox.root.join("home/.claude"), 0o555).expect("read only");
    full_scan(&daemon);
    set_mode(&sandbox.root.join("home/.claude"), 0o755).expect("writable again");
    assert_eq!(sandbox.gate_events(), events, "the Full Scan wrote nothing");
    let health = daemon.health();
    assert!(health.gate_lines.is_empty(), "{health:?}");
    assert!(!health.gate_hooks);
    assert!(health.headline().starts_with("All clear"), "{health:?}");
    sandbox.assert_only_the_users_own();
}

/// Spec section 7.6: switching on runs the registration check at once,
/// without waiting for a Full Scan, and switching on while on writes nothing.
#[test]
fn switching_on_registers_both_agents_at_once_and_again_writes_nothing() {
    let sandbox = Sandbox::new("on");
    std::fs::write(sandbox.settings_file().path(), "{\"gate_hooks\": false}\n")
        .expect("a settings file with the Gate off");
    let daemon = sandbox.open();
    assert!(!daemon.health().gate_hooks);
    full_scan(&daemon);
    assert!(sandbox.gate_events().is_empty(), "off registers nothing");
    sandbox.assert_only_the_users_own();

    let scans = daemon.status().scan.map(|scan| scan.started_at);
    assert!(daemon.set_gate_hooks(true).expect("switched"));
    assert_eq!(
        daemon.status().scan.map(|scan| scan.started_at),
        scans,
        "no Full Scan was needed"
    );
    let events = sandbox.gate_events();
    assert_eq!(count(&events, Action::GateRegistered), 5, "{events:?}");
    assert_eq!(
        events
            .iter()
            .filter(|(_, id)| id.starts_with("claude-code/"))
            .count(),
        3
    );
    assert!(sandbox.registered());
    assert!(daemon.health().gate_hooks);

    let settings = std::fs::read(sandbox.settings_file().path()).expect("a settings file");
    let claude = read(&sandbox.claude_settings());
    assert!(daemon.set_gate_hooks(true).expect("still on"));
    assert_eq!(sandbox.gate_events(), events, "nothing recorded");
    assert_eq!(
        std::fs::read(sandbox.settings_file().path()).expect("a settings file"),
        settings,
        "the settings file is as it was"
    );
    assert_eq!(read(&sandbox.claude_settings()), claude);

    // The Full Scan after it finds every entry in place and raises nothing.
    full_scan(&daemon);
    assert_eq!(sandbox.gate_events(), events);
    let status = daemon.status();
    assert!(status.health.gate_lines.is_empty());
    assert!(
        status.findings.is_empty(),
        "the Gate's own entries raise no Finding: {:?}",
        status.findings
    );
}

/// Spec sections 6.5 and 6.9: the switch is a user choice, kept in the
/// settings file, so a rebuilt state file cannot turn it back on.
#[test]
fn switching_off_survives_a_lost_state_file_and_a_restart() {
    let sandbox = Sandbox::new("restart");
    let first = sandbox.open();
    full_scan(&first);
    assert!(sandbox.registered());
    first.set_gate_hooks(false).expect("switched");
    let events = sandbox.gate_events();
    drop(first);

    std::fs::remove_file(sandbox.data().state_file()).expect("a state file to delete");
    let second = sandbox.open();
    assert!(!second.gate_hooks_enabled());
    assert!(!second.health().gate_hooks);
    full_scan(&second);
    assert_eq!(sandbox.gate_events(), events, "nothing registered");
    sandbox.assert_only_the_users_own();
    assert!(second.health().gate_lines.is_empty());
}

/// Spec section 6.9: a settings file that cannot be read leaves the Gate at
/// its default, on, raises the settings note, and no registration writes
/// over it.
#[test]
fn an_unreadable_settings_file_leaves_the_gate_on_and_is_not_rewritten() {
    let sandbox = Sandbox::new("unreadable");
    let broken = b"{\"gate_hooks\": false,,}\n";
    std::fs::write(sandbox.settings_file().path(), broken).expect("a broken settings file");
    let daemon = sandbox.open();
    let health = daemon.health();
    assert!(health.gate_hooks);
    assert!(health.settings_unreadable);
    assert!(
        health
            .notes()
            .contains(&agentsweep_core::health::SETTINGS_UNREADABLE.to_string()),
        "{:?}",
        health.notes()
    );

    full_scan(&daemon);
    assert!(sandbox.registered(), "the default registers the Gate");
    assert_eq!(count(&sandbox.gate_events(), Action::GateRegistered), 5);
    assert_eq!(
        std::fs::read(sandbox.settings_file().path()).expect("the settings file"),
        broken,
        "left as it is"
    );
    assert!(daemon.health().settings_unreadable);
}

/// Spec section 9.6: the removal is one operation of its own, which leaves
/// the switch where it stands and the user's own hooks and pins untouched,
/// so Uninstall can call it on every path.
#[test]
fn the_removal_is_callable_on_its_own_and_leaves_the_users_hooks() {
    let sandbox = Sandbox::new("removal");
    let daemon = sandbox.open();
    full_scan(&daemon);
    assert!(sandbox.registered());

    let removal = daemon.remove_the_gate();
    assert_eq!(
        removal,
        Removal {
            removed: 5,
            failed: Vec::new()
        }
    );
    sandbox.assert_only_the_users_own();
    assert!(daemon.gate_hooks_enabled(), "the switch did not move");
    assert_eq!(count(&sandbox.gate_events(), Action::GateRemoved), 5);

    // Called again it finds nothing of AgentSweep's and writes nothing.
    assert_eq!(daemon.remove_the_gate(), Removal::default());
    assert_eq!(count(&sandbox.gate_events(), Action::GateRemoved), 5);
    sandbox.assert_only_the_users_own();
}

/// The `gate-hooks` request reads and sets the switch over the socket, like
/// `rule-feed`, and the status answer's Health carries it.
#[test]
fn the_gate_hooks_request_reads_and_sets_the_switch() {
    let sandbox = Sandbox::new("request");
    let daemon = sandbox.open();
    let running = service::start_with(&sandbox.options(), daemon).expect("a listening daemon");
    let background = running.serve_in_the_background();
    let daemon = background.daemon();
    full_scan(daemon);

    let mut client = Client::connect_at(&sandbox.socket(), Role::Cli).expect("a client");
    assert!(client.gate_hooks().expect("an answer"));
    assert!(!client.set_gate_hooks(false).expect("an answer"));
    assert!(!client.gate_hooks().expect("an answer"));
    assert!(!client.status().expect("a status").health.gate_hooks);
    sandbox.assert_only_the_users_own();
    assert!(client.set_gate_hooks(true).expect("an answer"));
    assert!(client.status().expect("a status").health.gate_hooks);
    assert!(sandbox.registered());
}
