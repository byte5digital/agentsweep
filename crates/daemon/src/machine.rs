//! The machine a Scan runs against, and the Surface Adapters that read it.
//!
//! A Surface Adapter never touches the real home: it asks a [`Host`] (spec
//! section 3.1). This is where the daemon builds that Host, which is also
//! where the developer's `--home` override stops being a path and becomes the
//! only machine the Scan can see.
//!
//! An overridden home reads nothing outside itself. The search path stays
//! empty, so a bare command word never resolves against whatever happens to be
//! installed on the machine the daemon is running on, and no absolute system
//! path is read unless a `system` directory sits beside the home, the way a
//! conformance fixture lays one out.

use std::path::{Path, PathBuf};

use agentsweep_adapter_claude_code::ClaudeCode;
use agentsweep_adapter_codex::Codex;
use agentsweep_adapter_workspace::Workspace;
use agentsweep_core::adapter::SurfaceAdapter;
use agentsweep_core::host::Host;

/// The root every absolute system path is resolved against on a real machine.
const SYSTEM_ROOT: &str = "/";

/// The directory a fixture home puts its stand-in for the Managed layers in.
const FIXTURE_SYSTEM: &str = "system";

/// The machine the daemon scans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Machine {
    home: PathBuf,
    system_root: Option<PathBuf>,
    search_path: Vec<PathBuf>,
}

impl Machine {
    /// The machine the daemon is running on: the real home, the real system
    /// root and the search path of the environment it was started in.
    pub fn real(home: PathBuf) -> Machine {
        Machine {
            home,
            system_root: Some(PathBuf::from(SYSTEM_ROOT)),
            search_path: std::env::var("PATH")
                .map(|path| path.split(':').map(PathBuf::from).collect())
                .unwrap_or_default(),
        }
    }

    /// A home the developer named, read as a machine of its own.
    ///
    /// Nothing outside it is read: no `PATH`, and no absolute system path
    /// unless the home has a `system` directory beside it.
    pub fn named(home: PathBuf) -> Machine {
        let system_root = home
            .parent()
            .map(|beside| beside.join(FIXTURE_SYSTEM))
            .filter(|system| system.is_dir());
        Machine {
            home,
            system_root,
            search_path: Vec::new(),
        }
    }

    /// The home this machine is.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The Host an adapter is handed to look for Agents and projects: the home
    /// and nothing pooled yet.
    pub fn inventory(&self) -> Host {
        self.host(Vec::new())
    }

    /// The Host an adapter is handed to enumerate: the home and every pooled
    /// project root.
    pub fn host(&self, roots: Vec<PathBuf>) -> Host {
        let host = Host::new(self.home.clone(), roots).with_search_path(self.search_path.clone());
        match &self.system_root {
            Some(system) => host.with_system_root(system.clone()),
            None => host,
        }
    }
}

/// The Surface Adapters, in the order a Scan runs them.
///
/// The workspace adapter comes first because it reads the git files of every
/// pooled root once for everybody, and what it worked out is stamped onto the
/// Items the Agent adapters yield.
pub fn adapters() -> Vec<Box<dyn SurfaceAdapter>> {
    vec![
        Box::new(Workspace::new()),
        Box::new(ClaudeCode::new()),
        Box::new(Codex::new()),
    ]
}

/// The Agent adapters alone, which are the ones that know a registry of
/// projects and a version on disk.
pub fn agents() -> Vec<Box<dyn SurfaceAdapter>> {
    vec![Box::new(ClaudeCode::new()), Box::new(Codex::new())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_home_reads_nothing_of_the_machine_it_runs_on() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let home = temporary.path().join("home");
        std::fs::create_dir_all(&home).expect("a fake home");

        let machine = Machine::named(home.clone());
        let host = machine.inventory();
        assert_eq!(host.home(), Some(home.as_path()));
        assert!(host.search_path().is_empty());
        assert_eq!(host.system_root(), None);
    }

    /// A conformance fixture lays a `system` directory beside its home, so a
    /// Managed Surface is read from the fixture and never from the real
    /// `/Library`.
    #[test]
    fn a_system_directory_beside_a_named_home_stands_in_for_the_managed_layers() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let home = temporary.path().join("home");
        let system = temporary.path().join("system");
        std::fs::create_dir_all(&home).expect("a fake home");
        std::fs::create_dir_all(&system).expect("a fake system root");

        let machine = Machine::named(home);
        assert_eq!(machine.inventory().system_root(), Some(system.as_path()));
    }

    #[test]
    fn the_real_machine_reads_the_system_root_and_the_search_path() {
        let machine = Machine::real(PathBuf::from("/nowhere/agentsweep"));
        let host = machine.inventory();
        assert_eq!(host.system_root(), Some(Path::new(SYSTEM_ROOT)));
    }

    /// The workspace adapter reads the git files for everybody, so it runs
    /// first and the two Agent adapters follow it.
    #[test]
    fn the_adapters_run_with_the_workspace_first() {
        let ids: Vec<&str> = adapters()
            .iter()
            .map(|adapter| adapter.descriptor().agent)
            .collect();
        assert_eq!(ids, vec!["workspace", "claude-code", "codex"]);
        let agents: Vec<&str> = agents()
            .iter()
            .map(|adapter| adapter.descriptor().agent)
            .collect();
        assert_eq!(agents, vec!["claude-code", "codex"]);
    }
}
