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
//! A case is the project root, unless it holds both a `home` and a `project`
//! directory, in which case those are the fake home and the fake project the
//! Host is built from.

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
        if home.is_dir() && project.is_dir() {
            Copy {
                home: Some(home),
                project,
                root,
            }
        } else {
            Copy {
                home: None,
                project: root.clone(),
                root,
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

    /// The Host over the copy: the fake home when the case has one, and the
    /// one pooled project root.
    pub fn host(&self) -> Host {
        match &self.home {
            Some(home) => Host::new(home.clone(), vec![self.project.clone()]),
            None => Host::for_folder_scan(self.project.clone()),
        }
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("a temporary copy of a fixture tree");
    let entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("the fixture tree {}: {error}", source.display()));
    for entry in entries.filter_map(Result::ok) {
        let from = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let to = destination.join(undotted(&name));
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).expect("a file of a fixture tree");
        }
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
