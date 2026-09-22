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

/// The directories a command is never installed into by anything legitimate.
/// A path under one of them is what `mcp.command_in_temp` reports.
const TEMPORARY_DIRECTORIES: [&str; 7] = [
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
    "/dev/shm",
];

/// The interpreters a configuration line puts in front of the file that really
/// carries the code. `bash ~/.claude/hooks/x.sh` runs `x.sh`, and that is the
/// file a Rule wants the type of.
const INTERPRETERS: [&str; 12] = [
    "bash", "sh", "zsh", "dash", "ksh", "node", "bun", "deno", "python", "python3", "ruby", "perl",
];

/// The machine a Scan runs against, read-only.
#[derive(Clone, Debug, Default)]
pub struct Host {
    home: Option<PathBuf>,
    config_dirs: BTreeMap<String, PathBuf>,
    project_roots: Vec<PathBuf>,
    search_path: Vec<PathBuf>,
    system_root: Option<PathBuf>,
}

impl Host {
    /// A Host with a home directory and a pool of project roots.
    pub fn new(home: PathBuf, project_roots: Vec<PathBuf>) -> Host {
        Host {
            home: Some(home),
            project_roots,
            ..Host::default()
        }
    }

    /// The Host of a Folder Scan: one project root the user pointed at and no
    /// home, because a Folder Scan reads nothing outside that folder.
    pub fn for_folder_scan(root: PathBuf) -> Host {
        Host {
            project_roots: vec![root],
            ..Host::default()
        }
    }

    /// Sets the config-dir override AgentSweep holds for one Agent. Relocation
    /// is an explicit AgentSweep setting, never followed from an env file or a
    /// settings block.
    pub fn with_config_dir(mut self, agent: &str, dir: PathBuf) -> Host {
        self.config_dirs.insert(agent.to_string(), dir);
        self
    }

    /// Sets the directories a bare command word is looked for in, the way a
    /// shell would look it up.
    ///
    /// It is empty unless something sets it, so a test never resolves a
    /// command against whatever happens to be installed on the machine the
    /// test runs on. The daemon and the command line interface fill it from
    /// the environment they were started in.
    pub fn with_search_path(mut self, directories: Vec<PathBuf>) -> Host {
        self.search_path = directories;
        self
    }

    /// Sets the prefix every absolute system path is resolved against, which is
    /// how a Managed Surface is read.
    ///
    /// It is absent unless something sets it, so the suite never reads the
    /// real `/Library` of the machine it runs on: a fixture case points it at
    /// a directory of its own and the daemon points it at the root.
    pub fn with_system_root(mut self, root: PathBuf) -> Host {
        self.system_root = Some(root);
        self
    }

    /// The home directory, absent for a Folder Scan.
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// The directories a bare command word is looked for in.
    pub fn search_path(&self) -> &[PathBuf] {
        &self.search_path
    }

    /// The prefix an absolute system path is resolved against, absent when
    /// system paths are not to be read at all.
    pub fn system_root(&self) -> Option<&Path> {
        self.system_root.as_deref()
    }

    /// One absolute system path under the system root, absent when there is
    /// no system root. The leading separator of `absolute` is dropped, so a
    /// fixture's own directory stands in for the real one.
    pub fn system_path(&self, absolute: &str) -> Option<PathBuf> {
        let root = self.system_root.as_ref()?;
        Some(root.join(absolute.trim_start_matches('/')))
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

    /// Reads at most `limit` bytes of a file, which is all it takes to say what
    /// kind of file it is.
    pub fn read_prefix(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
        use std::io::Read as _;
        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.by_ref().take(limit as u64).read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Where one command word lands on this machine, absent when nothing is
    /// there to land on.
    ///
    /// A word that names a path is taken as written, with a leading `~`
    /// expanded and `.` and `..` folded out lexically; a bare word is looked
    /// for in the search path. Nothing is canonicalised through the file
    /// system, because following a symbolic link to decide what a command is
    /// would make the answer depend on what the link points at right now.
    pub fn resolve_command(&self, word: &str, base: Option<&Path>) -> Option<PathBuf> {
        let word = word.trim();
        if word.is_empty() {
            return None;
        }
        if let Some(rest) = word.strip_prefix("~/") {
            return Some(normalise(&self.home.as_ref()?.join(rest)));
        }
        let path = Path::new(word);
        if path.is_absolute() {
            return Some(normalise(path));
        }
        if word.contains('/') {
            return Some(normalise(&base?.join(word)));
        }
        self.search_path
            .iter()
            .map(|directory| directory.join(word))
            .find(|candidate| candidate.is_file())
            .map(|found| normalise(&found))
    }

    /// The file a configuration line would really run: the first word, or,
    /// when that is an interpreter, the first argument that is not a flag.
    ///
    /// A hook command is a shell line rather than a program, so `bash
    /// ~/.claude/hooks/x.sh` resolves to the script and not to `bash`.
    /// Quoting is dropped, because a hook that writes
    /// `"$CLAUDE_PROJECT_DIR"/x.sh` means one path. Nothing else an Agent
    /// expands at run time is guessed at.
    pub fn resolve_command_line(&self, line: &str, base: Option<&Path>) -> Option<PathBuf> {
        let mut words = line
            .split_whitespace()
            .map(|word| word.replace(['"', '\''], ""));
        let first = words.next()?;
        let program = first.rsplit('/').next().unwrap_or_default();
        if INTERPRETERS.contains(&program)
            && let Some(script) = words.find(|word| !word.starts_with('-'))
        {
            return self.resolve_command(&script, base);
        }
        self.resolve_command(&first, base)
    }

    /// True when a resolved path sits in a directory nothing legitimate
    /// installs into.
    ///
    /// The home and the pooled project roots are never such a directory,
    /// whatever the operating system put them under: a fixture home lives in
    /// the per-user temporary directory, and calling the user's own home
    /// temporary would say the opposite of what this fact means.
    pub fn in_temporary_directory(&self, path: &Path) -> bool {
        if self.is_inside_home_or_project(path) {
            return false;
        }
        TEMPORARY_DIRECTORIES
            .iter()
            .any(|directory| path.starts_with(directory))
    }

    /// True when a resolved path sits in the downloads directory of the home.
    pub fn in_downloads(&self, path: &Path) -> bool {
        self.home
            .as_ref()
            .is_some_and(|home| path.starts_with(home.join("Downloads")))
    }

    /// True when anyone on the machine may rewrite the file a command points
    /// at, which makes the command whatever the last writer wanted.
    #[cfg(unix)]
    pub fn is_world_writable(&self, path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        self.symlink_metadata(path)
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o002 != 0)
    }

    /// True when anyone on the machine may rewrite the file a command points
    /// at. There are no world-writable permissions to read here.
    #[cfg(not(unix))]
    pub fn is_world_writable(&self, _path: &Path) -> bool {
        false
    }

    fn is_inside_home_or_project(&self, path: &Path) -> bool {
        self.home
            .as_ref()
            .is_some_and(|home| path.starts_with(home))
            || self.project_roots.iter().any(|root| path.starts_with(root))
    }

    /// The entries of a directory, in a stable order so that two enumerations
    /// of the same tree yield their Items in the same order.
    pub fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        Ok(entries)
    }
}

/// A path with `.` and `..` folded out, without asking the file system
/// anything. Two spellings of one location become one string, and a link is
/// left pointing where it points.
fn normalise(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
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

    /// Nothing reads a system path unless a system root was set, so the suite
    /// can never read the real managed directory of the machine it runs on.
    #[test]
    fn a_system_path_is_absent_until_a_system_root_is_set() {
        let plain = Host::new(PathBuf::from("/home/u"), Vec::new());
        assert_eq!(plain.system_path("/Library/Application Support/X"), None);

        let rooted = plain.with_system_root(PathBuf::from("/fixture"));
        assert_eq!(
            rooted.system_path("/Library/Application Support/X"),
            Some(PathBuf::from("/fixture/Library/Application Support/X"))
        );
    }

    #[test]
    fn a_command_word_that_names_a_path_is_taken_as_written() {
        let host = Host::new(PathBuf::from("/home/u"), Vec::new());
        assert_eq!(
            host.resolve_command("/tmp/./.lint/../.lint/server", None),
            Some(PathBuf::from("/tmp/.lint/server"))
        );
        assert_eq!(
            host.resolve_command("~/.dev-utils/index.js", None),
            Some(PathBuf::from("/home/u/.dev-utils/index.js"))
        );
        assert_eq!(
            host.resolve_command("scripts/x.sh", Some(Path::new("/src/demo"))),
            Some(PathBuf::from("/src/demo/scripts/x.sh"))
        );
    }

    /// A bare word is looked for in the search path, and the search path is
    /// empty unless something set it, so a test never depends on what is
    /// installed on the machine it runs on.
    #[test]
    fn a_bare_command_word_needs_a_search_path() {
        let host = Host::new(PathBuf::from("/home/u"), Vec::new());
        assert_eq!(host.resolve_command("npx", None), None);
        assert!(host.search_path().is_empty());
    }

    #[test]
    fn an_interpreter_resolves_to_the_file_that_carries_the_code() {
        let host = Host::new(PathBuf::from("/home/u"), Vec::new());
        assert_eq!(
            host.resolve_command_line("bash -e ~/.claude/hooks/x.sh session", None),
            Some(PathBuf::from("/home/u/.claude/hooks/x.sh"))
        );
        assert_eq!(
            host.resolve_command_line("/opt/tools/watch --json", None),
            Some(PathBuf::from("/opt/tools/watch"))
        );
        assert_eq!(
            host.resolve_command_line("\"/src/demo\"/.claude/hooks/fmt.sh", None),
            Some(PathBuf::from("/src/demo/.claude/hooks/fmt.sh"))
        );
    }

    /// The user's own home is never a temporary directory, whatever the
    /// operating system put it under. A fixture home lives in the per-user
    /// temporary directory, and so does the quarantine of nothing.
    #[test]
    fn a_temporary_directory_is_one_the_user_does_not_live_in() {
        let host = Host::new(
            PathBuf::from("/var/folders/ab/T/agentsweep-home"),
            vec![PathBuf::from("/var/folders/ab/T/agentsweep-project")],
        );
        assert!(host.in_temporary_directory(Path::new("/tmp/.lint/server")));
        assert!(host.in_temporary_directory(Path::new("/private/var/folders/xy/T/x")));
        assert!(!host.in_temporary_directory(Path::new("/var/folders/ab/T/agentsweep-home/x")));
        assert!(
            !host.in_temporary_directory(Path::new(
                "/var/folders/ab/T/agentsweep-project/.claude/x"
            ))
        );
        assert!(!host.in_temporary_directory(Path::new("/opt/homebrew/bin/node")));
    }

    #[test]
    fn the_downloads_directory_is_the_one_under_the_home() {
        let host = Host::new(PathBuf::from("/home/u"), Vec::new());
        assert!(host.in_downloads(Path::new("/home/u/Downloads/server")));
        assert!(!host.in_downloads(Path::new("/home/u/Documents/server")));
    }
}
