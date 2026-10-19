//! The Inventory of onboarding screen 2 (spec sections 6.8 and 8.3): which
//! Agents are on this Mac and how many projects each of them lists.
//!
//! The app runs it itself, before any daemon is registered, by calling each
//! Agent adapter's `detect` and `projects` as they are. Nothing is
//! enumerated, nothing is written, no Agent binary is run (spec section 3.2),
//! and the Host the adapters are handed is confined to the files directly in
//! the home and to each Agent's config directory: the registries live there,
//! and a project folder, which may sit in a location macOS protects, is never
//! reached. The project counts come from the Agents' own lists.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_adapter_codex::Codex;
use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::host::{Confinement, Host, Touched};

/// The line under the Agents (spec section 8.3, screen 2).
pub const OWN_LISTS: &str =
    "Projects come from the agents' own lists, AgentSweep never crawls your disk.";

/// What the screen says when no Agent was found.
pub const NONE_FOUND: &str = "AgentSweep found neither Claude Code nor Codex on this Mac.";

/// One Agent the Inventory found installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Found {
    /// The machine-readable Agent id.
    pub agent: &'static str,
    /// The name shown to a person.
    pub name: &'static str,
    /// The version read from disk, absent when it could not be read.
    pub version: Option<String>,
    /// How many distinct project roots the Agent's own registries list.
    pub projects: usize,
    /// The config layers the adapter declares it does not read, in its own
    /// words.
    pub not_read: &'static [&'static str],
}

impl Found {
    /// The line that says what was not read, absent when the adapter
    /// declares nothing.
    pub fn not_read_line(&self) -> Option<String> {
        match self.not_read {
            [] => None,
            [one] => Some(format!("AgentSweep does not read {one}.")),
            [rest @ .., last] => Some(format!(
                "AgentSweep does not read {} or {last}.",
                rest.join(", ")
            )),
        }
    }

    /// "3 projects", "1 project", "No projects".
    pub fn projects_line(&self) -> String {
        match self.projects {
            0 => "No projects".to_string(),
            1 => "1 project".to_string(),
            n => format!("{n} projects"),
        }
    }
}

/// What the Inventory found: the installed Agents, in adapter order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Inventory {
    /// The Agents found installed.
    pub agents: Vec<Found>,
}

impl Inventory {
    /// The Inventory of this Mac: the home the environment names and the
    /// search path it was started with, which `detect` looks in by stat
    /// only. Absent without a home.
    pub fn of_this_mac() -> Option<Inventory> {
        let home = std::env::var_os("HOME").filter(|home| !home.is_empty())?;
        let search_path = std::env::var("PATH")
            .map(|path| path.split(':').map(PathBuf::from).collect())
            .unwrap_or_default();
        Some(take(Path::new(&home), search_path, None))
    }

    /// Screen 2's view: each Agent with its project count and what was not
    /// read, the fixed line, and whether anything was found at all.
    pub fn to_value(&self) -> Value {
        json!({
            "agents": self.agents.iter().map(|found| json!({
                "agent": found.agent,
                "name": found.name,
                "version": found.version,
                "projects": found.projects_line(),
                "notRead": found.not_read_line(),
            })).collect::<Vec<_>>(),
            "none": self.agents.is_empty().then_some(NONE_FOUND),
            "ownLists": OWN_LISTS,
        })
    }
}

/// The Agent adapters the Inventory asks.
pub fn agents() -> Vec<Box<dyn SurfaceAdapter>> {
    vec![Box::new(ClaudeCode::new()), Box::new(Codex::new())]
}

/// Where the Inventory may reach under `home`: the files directly in it,
/// where the registries are, and each Agent's config directory.
pub fn confinement(home: &Path, adapters: &[Box<dyn SurfaceAdapter>]) -> Confinement {
    adapters.iter().fold(
        Confinement::default().files_in(home),
        |confinement, adapter| {
            confinement.tree(&home.join(adapter.descriptor().default_config_dir))
        },
    )
}

/// Runs the Inventory over `home`, the binaries looked for in `search_path`,
/// recording every path reached in `touched` when one is given.
pub fn take(home: &Path, search_path: Vec<PathBuf>, touched: Option<Arc<Touched>>) -> Inventory {
    let adapters = agents();
    let mut host = Host::new(home.to_path_buf(), Vec::new())
        .with_search_path(search_path)
        .confined(confinement(home, &adapters));
    if let Some(touched) = touched {
        host = host.recording(touched);
    }
    let agents = adapters
        .iter()
        .filter_map(|adapter| {
            let detection = adapter.detect(&host);
            if !detection.installed {
                return None;
            }
            let roots: BTreeSet<PathBuf> = adapter
                .projects(&host)
                .into_iter()
                .map(|registration| registration.root)
                .collect();
            let descriptor = adapter.descriptor();
            Some(Found {
                agent: descriptor.agent,
                name: descriptor.display_name,
                version: detection.version,
                projects: roots.len(),
                not_read: adapter.layers_not_read(),
            })
        })
        .collect();
    Inventory { agents }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::fs;
    use std::time::SystemTime;

    /// A temporary Mac: a home with Claude Code and Codex installed, three
    /// projects between them, one of them in Documents and one outside the
    /// home, and a search path with nothing on it.
    struct Mac {
        _temporary: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        projects: Vec<PathBuf>,
    }

    impl Mac {
        fn new() -> Mac {
            let temporary = tempfile::TempDir::new().expect("a temporary directory");
            let root = temporary.path().to_path_buf();
            let home = root.join("home");
            let alpha = home.join("Documents/alpha");
            let beta = home.join("Developer/beta");
            let gamma = root.join("elsewhere/gamma");
            for project in [&alpha, &beta, &gamma] {
                fs::create_dir_all(project.join(".git")).expect("a project folder");
                fs::write(project.join("AGENTS.md"), "notes\n").expect("a project file");
            }
            let mac = Mac {
                _temporary: temporary,
                root,
                home,
                projects: vec![alpha, beta, gamma],
            };
            mac.install_claude_code();
            mac.install_codex();
            fs::create_dir_all(mac.root.join("bin")).expect("a search path directory");
            mac
        }

        fn write(&self, relative: &str, content: &str) {
            let path = self.home.join(relative);
            fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            fs::write(path, content).expect("a fixture file");
        }

        fn install_claude_code(&self) {
            self.write(
                ".claude/cache/changelog.md",
                "# Changelog\n\n## 2.1.273\n\n- something\n",
            );
            let [alpha, beta, _] = &self.projects[..] else {
                unreachable!()
            };
            self.write(
                ".claude.json",
                &format!(
                    "{{\"projects\": {{\"{}\": {{\"hasTrustDialogAccepted\": true}}, \
                     \"{}\": {{\"hasTrustDialogAccepted\": false}}}}}}",
                    alpha.display(),
                    beta.display()
                ),
            );
        }

        fn install_codex(&self) {
            let [alpha, _, gamma] = &self.projects[..] else {
                unreachable!()
            };
            self.write(".codex/version.json", "{\"version\": \"0.200.0\"}");
            self.write(
                ".codex/config.toml",
                &format!(
                    "model = \"o9\"\n\n[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                    alpha.display()
                ),
            );
            // A root Codex knows from a session log alone, which its trust
            // lookup would resolve up to a git root inside the project.
            self.write(
                ".codex/sessions/2026/10/19/rollout-one.jsonl",
                &format!(
                    "{{\"type\":\"session_meta\",\"payload\":{{\"cwd\":\"{}\"}}}}\n",
                    gamma.display()
                ),
            );
        }

        fn take(&self, touched: Option<Arc<Touched>>) -> Inventory {
            take(&self.home, vec![self.root.join("bin")], touched)
        }

        /// Every path under the temporary root with its length, mode,
        /// modification time and content, to show nothing was written.
        fn snapshot(&self) -> BTreeMap<PathBuf, (u64, SystemTime, Vec<u8>)> {
            let mut found = BTreeMap::new();
            let mut pending = vec![self.root.clone()];
            while let Some(path) = pending.pop() {
                let metadata = fs::symlink_metadata(&path).expect("metadata");
                let content = match metadata.is_file() {
                    true => fs::read(&path).expect("content"),
                    false => Vec::new(),
                };
                if metadata.is_dir() {
                    for entry in fs::read_dir(&path).expect("a listing") {
                        pending.push(entry.expect("an entry").path());
                    }
                }
                found.insert(
                    path,
                    (
                        metadata.len(),
                        metadata.modified().expect("a time"),
                        content,
                    ),
                );
            }
            found
        }
    }

    /// Both Agents and their project counts, read from the registries only:
    /// every path reached is a file directly in the home or inside an Agent's
    /// config directory, no project folder is reached, and nothing changes on
    /// disk.
    #[test]
    fn the_inventory_reports_both_agents_from_their_registries_and_touches_nothing_else() {
        let mac = Mac::new();
        let before = mac.snapshot();
        let touched = Arc::new(Touched::default());

        let inventory = mac.take(Some(Arc::clone(&touched)));

        let summary: Vec<_> = inventory
            .agents
            .iter()
            .map(|found| (found.agent, found.projects, found.version.as_deref()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("claude-code", 2, Some("2.1.273")),
                ("codex", 2, Some("0.200.0")),
            ]
        );

        let paths = touched.paths();
        assert!(paths.contains(&mac.home.join(".claude.json")));
        assert!(paths.contains(&mac.home.join(".codex/config.toml")));
        let claude = mac.home.join(".claude");
        let codex = mac.home.join(".codex");
        for path in &paths {
            let in_home = path.parent() == Some(mac.home.as_path());
            assert!(
                in_home || path.starts_with(&claude) || path.starts_with(&codex),
                "the Inventory reached {}",
                path.display()
            );
            for project in &mac.projects {
                assert!(
                    !path.starts_with(project),
                    "the Inventory reached into {}",
                    project.display()
                );
            }
        }
        assert_eq!(mac.snapshot(), before, "the Inventory wrote something");
    }

    /// `detect` finds an Agent by a stat on the search path and never runs
    /// it: the stand-in binary would leave a mark if it were started.
    #[cfg(unix)]
    #[test]
    fn the_inventory_never_starts_a_process() {
        use std::os::unix::fs::PermissionsExt;

        let mac = Mac::new();
        fs::remove_dir_all(mac.home.join(".claude")).expect("no config directory");
        let mark = mac.root.join("started");
        let binary = mac.root.join("bin/claude");
        fs::write(
            &binary,
            format!("#!/bin/sh\necho defanged > '{}'\n", mark.display()),
        )
        .expect("a stand-in binary");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("executable");

        let inventory = mac.take(None);

        assert_eq!(inventory.agents[0].agent, "claude-code");
        assert_eq!(inventory.agents[0].version, None);
        assert!(!mark.exists(), "the Inventory started the Agent binary");
    }

    /// The line about Codex's managed layers is the adapter's own declaration
    /// and shows only while Codex is installed.
    #[test]
    fn codexs_not_read_line_comes_from_its_adapter_and_only_when_it_is_installed() {
        let mac = Mac::new();
        let inventory = mac.take(None);
        let codex = &inventory.agents[1];
        assert_eq!(codex.not_read, Codex::new().layers_not_read());
        assert_eq!(
            codex.not_read_line().as_deref(),
            Some(
                "AgentSweep does not read the cloud enterprise bundle or the MDM managed \
                 preference."
            )
        );
        assert_eq!(inventory.agents[0].not_read_line(), None);
        let view = inventory.to_value();
        assert_eq!(view["agents"][1]["notRead"], codex.not_read_line().unwrap());
        assert_eq!(view["agents"][0]["notRead"], Value::Null);
        assert_eq!(view["ownLists"], OWN_LISTS);
        assert_eq!(view["none"], Value::Null);

        fs::remove_dir_all(mac.home.join(".codex")).expect("no Codex");
        let inventory = mac.take(None);
        assert_eq!(inventory.agents.len(), 1);
        assert!(
            !inventory
                .to_value()
                .to_string()
                .contains("enterprise bundle")
        );

        fs::remove_dir_all(mac.home.join(".claude")).expect("no Claude Code");
        let view = mac.take(None).to_value();
        assert_eq!(view["none"], NONE_FOUND);
    }

    #[test]
    fn a_project_count_reads_as_words() {
        let mut found = Found {
            agent: "codex",
            name: "Codex",
            version: None,
            projects: 0,
            not_read: &[],
        };
        assert_eq!(found.projects_line(), "No projects");
        found.projects = 1;
        assert_eq!(found.projects_line(), "1 project");
        found.projects = 4;
        assert_eq!(found.projects_line(), "4 projects");
    }
}
