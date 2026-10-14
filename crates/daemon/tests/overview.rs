//! What the Overview names beside the Findings, end to end: one record per
//! Agent with its version read from disk, one record per pooled project root
//! with the Agents that registered it, and the Items in the Ambiguous Band,
//! as the status and the subscribe stream carry them (spec section 8.1).
//!
//! Every test starts a daemon against a temporary home, a temporary data
//! directory and a temporary socket, with the chain key held in the process.
//! Nothing touches the real home, the real data directory, the documented
//! socket or the login Keychain.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use agentsweep_core::keychain::{ChainKey, KeyError, KeySource, MemoryKeySource};
use agentsweep_core::overview::{Overview, ProjectAgent, ProjectCheck};
use agentsweep_core::paths::DataDirectory;
use agentsweep_daemon::Tuning;
use agentsweep_daemon::options::{KeySourceChoice, LogChoice, Options};
use agentsweep_daemon::service::{self, Background, Daemon};
use agentsweep_daemon::watcher::Timings;
use agentsweep_ipc::Client;
use agentsweep_ipc::peer::SameUser;
use agentsweep_ipc::protocol::{Role, StateEvent, Status};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// The one chain key a sandbox's daemons share, as a Mac's Keychain would.
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

/// The skill Heuristic 0520 ships as a bad Fixture. Override phrasing alone
/// weighs 3, which is the Ambiguous Band on a skill nothing else fires on.
const AMBIGUOUS_SKILL: &str = include_str!(
    "../../../rules/0520-override-phrasing/bad/skill-declares-developer-mode/tree/SKILL.md"
);

/// The skill Heuristic 0522 ships as a bad Fixture. A run-first instruction
/// alone weighs 1, which is Clear; changed since the Baseline, Heuristic 0581
/// adds 1 and the Score reaches the Ambiguous Band.
const RUN_FIRST_SKILL: &str = include_str!(
    "../../../rules/0522-run-first-instruction/bad/skill-first-step-installs-a-package/tree/SKILL.md"
);

/// A skill no Heuristic fires on.
const PLAIN_SKILL: &str = "---\nname: release-helper\ndescription: Draft the release notes.\n---\n\nCollect the merged pull requests and write them up under the next version heading.\n";

/// One machine to scan, one data directory and one socket, all temporary.
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    socket: PathBuf,
    keys: SharedKey,
}

impl Sandbox {
    /// A home where Claude Code is installed and Codex is not.
    fn new(purpose: &str) -> Sandbox {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-overview-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("home/.claude")).expect("an installed Agent");
        std::fs::create_dir_all(root.join("data")).expect("a data directory");
        let socket = std::env::temp_dir().join(format!(
            "aso-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        let sandbox = Sandbox {
            home: root.join("home"),
            root,
            socket,
            keys: SharedKey(Arc::new(MemoryKeySource::empty())),
        };
        sandbox.claude_code_registry(&[]);
        sandbox
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.home.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, content).expect("a file");
    }

    fn project(&self, name: &str) -> PathBuf {
        let project = self.root.join(name);
        std::fs::create_dir_all(&project).expect("a project");
        project
    }

    fn claude_code_registry(&self, projects: &[&Path]) {
        let entries: Vec<String> = projects
            .iter()
            .map(|root| {
                format!(
                    "    \"{}\": {{\"hasTrustDialogAccepted\": true}}",
                    root.display()
                )
            })
            .collect();
        self.write(
            ".claude.json",
            &format!(
                "{{\n  \"projects\": {{\n{}\n  }}\n}}\n",
                entries.join(",\n")
            ),
        );
    }

    fn install_codex(&self, projects: &[&Path]) {
        self.write(".codex/version.json", "{\"version\": \"0.144.5\"}");
        let tables: Vec<String> = projects
            .iter()
            .map(|root| {
                format!(
                    "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                    root.display()
                )
            })
            .collect();
        self.write(".codex/config.toml", &tables.join("\n"));
    }

    fn options(&self) -> Options {
        Options {
            data_dir: DataDirectory::at(self.root.join("data")),
            socket: self.socket.clone(),
            home: Some(self.home.clone()),
            key_source: KeySourceChoice::Memory,
            log: LogChoice::Stderr,
        }
    }

    fn open(&self) -> Arc<Daemon> {
        Daemon::open_tuned(
            &self.options(),
            Arc::new(SameUser),
            Box::new(self.keys.clone()),
            Tuning {
                watch: Timings::of(Duration::from_millis(100), Duration::from_millis(500)),
                ..Tuning::default()
            },
        )
        .expect("an open daemon")
    }

    fn start(&self) -> Background {
        let running = service::start_with(&self.options(), self.open()).expect("a daemon");
        let background = running.serve_in_the_background();
        wait_for_a_scan(background.daemon());
        background
    }

    fn status(&self) -> Status {
        Client::connect_at(&self.socket, Role::Cli)
            .expect("a client")
            .status()
            .expect("a status")
    }

    /// Every Overview the stream carries, read on a thread of its own so a
    /// test that waits for one never waits forever.
    fn overviews(&self) -> mpsc::Receiver<Overview> {
        let mut stream = Client::connect_at(&self.socket, Role::App)
            .expect("a client")
            .subscribe()
            .expect("a subscription");
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            while let Ok(Some(event)) = stream.next_event() {
                if let StateEvent::OverviewChanged { overview } = event
                    && send.send(*overview).is_err()
                {
                    return;
                }
            }
        });
        receive
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_for_a_scan(daemon: &Arc<Daemon>) {
    for _ in 0..3_600 {
        if !daemon.health().scanning && daemon.status().scan.is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the Full Scan did not finish");
}

/// Waits for an Overview on the stream that satisfies the condition.
fn an_overview_where(
    overviews: &mpsc::Receiver<Overview>,
    condition: impl Fn(&Overview) -> bool,
) -> Overview {
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match overviews.recv_timeout(left) {
            Ok(overview) if condition(&overview) => return overview,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    panic!("no Overview on the stream satisfied the condition");
}

fn ambiguous_names(overview: &Overview) -> Vec<String> {
    overview
        .ambiguous
        .iter()
        .map(|entry| {
            entry
                .item_id
                .as_str()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// Both Agents are listed with the version read from disk, their project and
/// Item counts, and Codex names the two layers it does not read. Every pooled
/// root appears once with the Agents that registered it. The Ambiguous Item
/// is in the Ambiguous list and in no Finding list; the Clear one is in
/// neither. A restarted daemon has all of it before it scans again.
#[test]
fn the_status_names_both_agents_every_pooled_root_and_the_ambiguous_items() {
    let sandbox = Sandbox::new("both");
    sandbox.write(
        ".claude/cache/changelog.md",
        "# Changelog\n\n## 2.1.273\n\n- something\n",
    );
    let only_claude = sandbox.project("only-claude");
    let shared = sandbox.project("shared");
    sandbox.claude_code_registry(&[&only_claude, &shared]);
    sandbox.install_codex(&[&shared]);
    sandbox.write(".claude/skills/release-helper/SKILL.md", AMBIGUOUS_SKILL);
    sandbox.write(".claude/skills/notes/SKILL.md", RUN_FIRST_SKILL);

    let status = {
        let _daemon = sandbox.start();
        sandbox.status()
    };
    let overview = &status.overview;

    let agents: Vec<&str> = overview
        .agents
        .iter()
        .map(|agent| agent.agent.as_str())
        .collect();
    assert_eq!(agents, vec!["claude-code", "codex"]);
    let claude = &overview.agents[0];
    let codex = &overview.agents[1];
    assert!(claude.installed && codex.installed);
    assert_eq!(claude.display_name, "Claude Code");
    assert_eq!(claude.version.as_deref(), Some("2.1.273"));
    assert_eq!(codex.version.as_deref(), Some("0.144.5"));
    assert_eq!(
        claude.config_dir,
        sandbox.home.join(".claude").display().to_string()
    );
    assert_eq!(
        codex.config_dir,
        sandbox.home.join(".codex").display().to_string()
    );
    assert_eq!(claude.projects, 2);
    assert_eq!(codex.projects, 1);
    assert!(claude.items >= 2, "both skills: {claude:?}");
    assert!(
        claude.items + codex.items <= status.health.items,
        "the counts are the Full Scan's: {overview:?}"
    );
    assert!(claude.layers_not_read.is_empty());
    assert_eq!(
        codex.layers_not_read,
        vec!["the cloud enterprise bundle", "the MDM managed preference"]
    );

    let roots: Vec<&str> = overview
        .projects
        .iter()
        .map(|project| project.root.as_str())
        .collect();
    let mut expected = vec![
        only_claude.display().to_string(),
        shared.display().to_string(),
    ];
    expected.sort();
    assert_eq!(roots, expected, "every pooled root once");
    let record_of = |root: &Path| {
        overview
            .projects
            .iter()
            .find(|project| project.root == root.display().to_string())
            .expect("a project record")
    };
    let agent = |agent: &str, registered: bool| ProjectAgent {
        agent: agent.to_string(),
        registered,
    };
    assert_eq!(
        record_of(&only_claude).agents,
        vec![agent("claude-code", true), agent("codex", false)]
    );
    assert_eq!(
        record_of(&shared).agents,
        vec![agent("claude-code", true), agent("codex", true)]
    );
    assert!(
        overview
            .projects
            .iter()
            .all(|project| project.check == ProjectCheck::Checked)
    );

    assert_eq!(ambiguous_names(overview), vec!["release-helper"]);
    let ambiguous = &overview.ambiguous[0];
    assert_eq!(ambiguous.score, 3);
    let lines: Vec<(i64, i64)> = ambiguous
        .heuristics
        .iter()
        .map(|line| (line.id, line.weight))
        .collect();
    assert_eq!(lines, vec![(520, 3)]);
    assert!(!ambiguous.heuristics[0].plain.is_empty());
    for name in ["release-helper", "notes"] {
        assert!(
            !status
                .findings
                .iter()
                .any(|finding| finding.item_id.as_str().ends_with(name)),
            "{name} is in no Finding list: {:?}",
            status.findings
        );
    }

    // The state file keeps it: a daemon that has not scanned yet answers with
    // what the last one found.
    let reopened = sandbox.open();
    assert_eq!(reopened.status().overview, status.overview);
}

/// An Agent that is not installed is listed as not installed, never left out.
#[test]
fn an_agent_that_is_not_installed_is_listed_as_such() {
    let sandbox = Sandbox::new("absent");
    let _daemon = sandbox.start();
    let status = sandbox.status();

    let codex = status
        .overview
        .agents
        .iter()
        .find(|agent| agent.agent == "codex")
        .expect("Codex is listed");
    assert!(!codex.installed);
    assert_eq!(codex.version, None);
    assert_eq!(codex.projects, 0);
    assert_eq!(codex.items, 0);
    let claude = &status.overview.agents[0];
    assert!(claude.installed);
    assert_eq!(claude.version, None, "no version on disk reads as unknown");
    assert_eq!(
        status.to_value()["agents"][0]["version"],
        "unknown",
        "{}",
        status.to_value()
    );
}

/// A Change Scan that moves an Item out of the Ambiguous Band, and one that
/// moves another into it, each send the Overview on the stream.
#[test]
fn a_change_scan_that_moves_an_item_across_the_band_is_on_the_stream() {
    let sandbox = Sandbox::new("change");
    sandbox.write(".claude/skills/release-helper/SKILL.md", AMBIGUOUS_SKILL);
    sandbox.write(".claude/skills/notes/SKILL.md", RUN_FIRST_SKILL);
    let _daemon = sandbox.start();
    assert_eq!(
        ambiguous_names(&sandbox.status().overview),
        vec!["release-helper"]
    );
    let overviews = sandbox.overviews();

    // Out of the Band: the override phrasing is gone, and a change alone
    // weighs 1.
    sandbox.write(".claude/skills/release-helper/SKILL.md", PLAIN_SKILL);
    let out = an_overview_where(&overviews, |overview| overview.ambiguous.is_empty());
    assert!(!out.agents.is_empty(), "the Agent records stand");
    assert!(sandbox.status().overview.ambiguous.is_empty());

    // Into the Band: the run-first instruction weighs 1, and its change 1.
    sandbox.write(
        ".claude/skills/notes/SKILL.md",
        &format!("{RUN_FIRST_SKILL}\nKeep the headings as they are.\n"),
    );
    let into = an_overview_where(&overviews, |overview| !overview.ambiguous.is_empty());
    assert_eq!(ambiguous_names(&into), vec!["notes"]);
    assert_eq!(into.ambiguous[0].score, 2);
    assert_eq!(ambiguous_names(&sandbox.status().overview), vec!["notes"]);
}
