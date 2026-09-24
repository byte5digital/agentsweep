//! Sanitised fixture trees, copied before they are read.
//!
//! A fixture tree is a real install's structure with harmless contents. It
//! lives at `fixtures/<agent>/<case>/` and is copied to a temporary directory
//! before an adapter ever sees it, so no test touches the real home and a
//! Surface Adapter that one day writes cannot write to anything that matters.
//!
//! Two names cannot be committed as they are: a directory called `.git` would
//! become part of this repository, and a file called `.env` is ignored by it.
//! So every path component that starts with `dot-` is committed that way and
//! renamed to a leading dot on the copy.
//!
//! A third name is ignored by this repository as well: `node_modules`. The
//! case that proves a vendored dependency directory is listed and never
//! scanned therefore uses `.venv`, committed as `dot-venv`. The core treats
//! every name of its vendored list the same, so the case reads the same.
//!
//! A symbolic link is committed as a file whose name ends in `.symlink` and
//! whose one line is the target it points at. Most skills on a real machine are
//! links into a shared directory, and a link committed as a link would be
//! followed by every tool that reads this repository.
//!
//! A case is the project root, unless it holds both a `home` and a `project`
//! directory, in which case those are the fake home and the fake project the
//! Host is built from. A `system` directory beside them stands in for the
//! absolute system paths a Managed Surface lives at, so no case ever reads the
//! real `/Library` of the machine it runs on.
//!
//! A registry keys its records by absolute path, which nobody can write down
//! before the copy exists. So a fixture file may name the copy with
//! `{{home}}`, `{{project}}` and `{{root}}`, and the copy puts the real paths
//! in. The snapshot writes them back out as `<root>`, so the case still reads
//! the same wherever it landed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use agentsweep_core::host::Host;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// The directory the fixture trees live in.
pub fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// The names of the cases of one adapter, in a stable order.
pub fn cases(agent: &str) -> Vec<String> {
    let Ok(entries) = fs::read_dir(directory().join(agent)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

/// The snapshot file of one case, beside its tree.
pub fn snapshot_path(agent: &str, case: &str) -> PathBuf {
    directory().join(agent).join(format!("{case}.snapshot"))
}

/// One fixture tree, copied to a temporary directory and removed again when it
/// goes out of scope.
#[derive(Debug)]
pub struct Copy {
    root: PathBuf,
    home: Option<PathBuf>,
    project: PathBuf,
    system: Option<PathBuf>,
}

impl Copy {
    /// Copies one case of one adapter.
    pub fn of(agent: &str, case: &str) -> Copy {
        let source = directory().join(agent).join(case);
        let root = std::env::temp_dir().join(format!(
            "agentsweep-conformance-{agent}-{case}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        copy_tree(&source, &root);

        let home = root.join("home");
        let project = root.join("project");
        let system = root.join("system");
        let copy = if home.is_dir() && project.is_dir() {
            Copy {
                home: Some(home),
                project,
                system: system.is_dir().then_some(system),
                root,
            }
        } else {
            Copy {
                home: None,
                project: root.clone(),
                system: None,
                root,
            }
        };
        copy.name_itself();
        copy
    }

    /// Puts the paths of the copy into the files that name them. A registry
    /// records a project by its absolute path, so a case that has one has to
    /// be told where it landed.
    fn name_itself(&self) {
        let replacements = [
            ("{{root}}", self.root.display().to_string()),
            (
                "{{home}}",
                self.home.clone().unwrap_or_default().display().to_string(),
            ),
            ("{{project}}", self.project.display().to_string()),
        ];
        let mut stack = vec![self.root.clone()];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                // A link is left alone: what it points at is named where it
                // really sits, and walking through one could walk in circles.
                if fs::symlink_metadata(&path).is_ok_and(|found| found.is_symlink()) {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let Ok(content) = fs::read_to_string(&path) else {
                    continue;
                };
                let mut named = content.clone();
                for (placeholder, actual) in &replacements {
                    named = named.replace(placeholder, actual);
                }
                if named != content {
                    fs::write(&path, named).expect("a fixture file that names the copy");
                }
            }
        }
    }

    /// The temporary directory the case was copied into.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The project root an adapter is pointed at.
    pub fn project(&self) -> &Path {
        &self.project
    }

    /// The Host over the copy: the fake home when the case has one, the one
    /// pooled project root, and the fake system root when the case has one.
    ///
    /// The search path stays empty on purpose. A bare command word would
    /// otherwise resolve against whatever is installed on the machine running
    /// the suite, and a snapshot has to read the same everywhere.
    pub fn host(&self) -> Host {
        let host = match &self.home {
            Some(home) => Host::new(home.clone(), vec![self.project.clone()]),
            None => Host::for_folder_scan(self.project.clone()),
        };
        match &self.system {
            Some(system) => host.with_system_root(system.clone()),
            None => host,
        }
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A temporary directory of its own, beside the copies and removed with them.
///
/// The enforcement half of the suite needs somewhere that is not the Surface
/// to put a quarantine store, and it may no more be the real data directory
/// than a fixture tree may be the real home.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// A directory nothing else is using.
    pub fn new(purpose: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "agentsweep-conformance-{purpose}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("a scratch directory");
        Scratch { path }
    }

    /// Where it is.
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("a temporary copy of a fixture tree");
    let entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("the fixture tree {}: {error}", source.display()));
    for entry in entries.filter_map(Result::ok) {
        let from = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(link) = name.strip_suffix(LINK_SUFFIX) {
            linked(&from, &destination.join(undotted(link)));
            continue;
        }
        let to = destination.join(undotted(&name));
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).expect("a file of a fixture tree");
        }
    }
}

/// The suffix of the file that stands in for a symbolic link.
const LINK_SUFFIX: &str = ".symlink";

/// Makes the link one committed file describes. Its target may not exist yet:
/// a link is allowed to point at a directory the copy has not reached.
#[cfg(unix)]
fn linked(from: &Path, to: &Path) {
    let target = fs::read_to_string(from).expect("the target of a committed link");
    std::os::unix::fs::symlink(target.trim(), to).expect("a link of a fixture tree");
}

/// A platform without symbolic links copies the target instead, so a case that
/// has one still runs.
#[cfg(not(unix))]
fn linked(from: &Path, to: &Path) {
    let target = fs::read_to_string(from).expect("the target of a committed link");
    let resolved = to.parent().unwrap_or(to).join(target.trim());
    if resolved.is_dir() {
        copy_tree(&resolved, to);
    }
}

/// `dot-git` on the way in, `.git` on the way out.
fn undotted(name: &str) -> String {
    match name.strip_prefix("dot-") {
        Some(rest) => format!(".{rest}"),
        None => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_committed_name_gets_its_leading_dot_back() {
        assert_eq!(undotted("dot-git"), ".git");
        assert_eq!(undotted("dot-env.local"), ".env.local");
        assert_eq!(undotted("CLAUDE.md"), "CLAUDE.md");
    }

    #[test]
    fn a_copy_is_a_copy_and_goes_away_with_its_value() {
        let root = {
            let copy = Copy::of("workspace", "planted-git-metadata");
            assert!(copy.project().join(".git").join("config").is_file());
            assert!(!copy.project().join("dot-git").exists());
            copy.root().to_path_buf()
        };
        assert!(!root.exists());
    }

    #[test]
    fn the_executable_bit_of_a_hook_survives_the_copy() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let copy = Copy::of("workspace", "planted-git-metadata");
            let hook = copy.project().join(".git").join("hooks").join("pre-commit");
            let mode = fs::metadata(&hook).expect("the hook").permissions().mode();
            assert!(mode & 0o111 != 0, "{mode:o}");
        }
    }

    #[test]
    fn every_adapter_with_a_fixture_directory_has_at_least_one_case() {
        for agent in crate::agent_ids() {
            if directory().join(agent).is_dir() {
                assert!(!cases(agent).is_empty(), "{agent} has no case");
            }
        }
    }
}
