//! The Host: the read-only view of a machine a Surface Adapter is handed.
//!
//! An adapter never touches the real home directly (spec section 3.1). It asks
//! the Host for the home directory, for the config-dir override AgentSweep
//! holds for its Agent, for the pooled project roots and for file contents.
//! Tests build a Host over a temporary directory, which is how the suite stays
//! off the real machine.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The machine a Scan runs against, read-only.
#[derive(Clone, Debug, Default)]
pub struct Host {
    home: Option<PathBuf>,
    config_dirs: BTreeMap<String, PathBuf>,
    project_roots: Vec<PathBuf>,
}

impl Host {
    /// A Host with a home directory and a pool of project roots.
    pub fn new(home: PathBuf, project_roots: Vec<PathBuf>) -> Host {
        Host {
            home: Some(home),
            config_dirs: BTreeMap::new(),
            project_roots,
        }
    }

    /// The Host of a Folder Scan: one project root the user pointed at and no
    /// home, because a Folder Scan reads nothing outside that folder.
    pub fn for_folder_scan(root: PathBuf) -> Host {
        Host {
            home: None,
            config_dirs: BTreeMap::new(),
            project_roots: vec![root],
        }
    }

    /// Sets the config-dir override AgentSweep holds for one Agent. Relocation
    /// is an explicit AgentSweep setting, never followed from an env file or a
    /// settings block.
    pub fn with_config_dir(mut self, agent: &str, dir: PathBuf) -> Host {
        self.config_dirs.insert(agent.to_string(), dir);
        self
    }

    /// The home directory, absent for a Folder Scan.
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// The config directory AgentSweep was told to use for this Agent.
    pub fn config_dir(&self, agent: &str) -> Option<&Path> {
        self.config_dirs.get(agent).map(PathBuf::as_path)
    }

    /// The project roots pooled across every Agent.
    pub fn project_roots(&self) -> &[PathBuf] {
        &self.project_roots
    }

    /// Reads a file. The only way an adapter gets at content.
    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    /// The metadata of a path without following a symbolic link.
    pub fn symlink_metadata(&self, path: &Path) -> io::Result<fs::Metadata> {
        fs::symlink_metadata(path)
    }

    /// The target of a symbolic link.
    pub fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_scan_host_has_one_root_and_no_home() {
        let host = Host::for_folder_scan(PathBuf::from("/src/demo"));
        assert!(host.home().is_none());
        assert_eq!(host.project_roots(), [PathBuf::from("/src/demo")]);
    }

    #[test]
    fn a_config_dir_override_is_per_agent() {
        let host = Host::new(PathBuf::from("/home/u"), Vec::new())
            .with_config_dir("claude-code", PathBuf::from("/home/u/.claude"));
        assert_eq!(
            host.config_dir("claude-code"),
            Some(Path::new("/home/u/.claude"))
        );
        assert_eq!(host.config_dir("codex"), None);
    }
}
