//! Repository Provenance, stamped onto the Items of every Surface Adapter.
//!
//! Half the class 2 Rules only make sense for files committed in the project:
//! a gitignored `settings.local.json` that self-approves project MCP servers is
//! the user's own doing, the same key in a tracked file from a fresh clone is
//! the CVE. So a project-scope Item carries whether git tracks it and, when it
//! does, the HEAD commit it came with.
//!
//! The reading is the workspace adapter's: it opens the git index, `HEAD` and
//! the refs in process with `gix` and never executes a git binary, because
//! running `git ls-files` inside a cloned repository is itself the attack this
//! scanner looks for. What reaches the core is the answer, as data: one
//! [`RepositoryProvenance`] per project root, which the core stamps onto the
//! Items every other adapter yielded for that root.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::adapter::Enumeration;
use crate::item::{Item, Kind, Provenance, Scope};

/// What one project root's git files say about the files in it.
#[derive(Clone, Debug)]
pub struct RepositoryProvenance {
    commit: String,
    tracked: BTreeSet<String>,
}

impl RepositoryProvenance {
    /// The answer for one repository: the HEAD commit and every path the index
    /// tracks, relative to the repository root with forward slashes.
    pub fn new(commit: impl Into<String>, tracked: impl IntoIterator<Item = String>) -> Self {
        RepositoryProvenance {
            commit: commit.into(),
            tracked: tracked.into_iter().collect(),
        }
    }

    /// The HEAD commit at enumeration time. Empty on an unborn branch, where
    /// the index may still track paths.
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// How many paths the index tracks.
    pub fn tracked_paths(&self) -> usize {
        self.tracked.len()
    }

    /// True when the index tracks this repository-relative path.
    pub fn tracks(&self, relative: &str) -> bool {
        self.tracked.contains(relative)
    }

    /// The Provenance of one repository-relative path: Repository with the
    /// HEAD commit when git tracks it, Manual when it does not.
    pub fn of(&self, relative: &str) -> Provenance {
        if self.tracks(relative) {
            Provenance::Repository {
                commit: self.commit.clone(),
            }
        } else {
            Provenance::Manual
        }
    }
}

/// The Repository Provenance of every pooled project root that could be read.
/// A root that is not a repository, or whose index could not be read, is
/// absent: its Items keep the Provenance their adapter gave them, and the
/// unreadable index travels as a Problem beside them.
#[derive(Clone, Debug, Default)]
pub struct Provenances {
    by_root: BTreeMap<PathBuf, RepositoryProvenance>,
}

impl Provenances {
    /// No project root read yet.
    pub fn new() -> Provenances {
        Provenances::default()
    }

    /// Records what one project root's git files said.
    pub fn insert(&mut self, root: PathBuf, provenance: RepositoryProvenance) {
        self.by_root.insert(root, provenance);
    }

    /// What was read for one project root.
    pub fn get(&self, root: &Path) -> Option<&RepositoryProvenance> {
        self.by_root.get(root)
    }

    /// How many project roots were read.
    pub fn len(&self) -> usize {
        self.by_root.len()
    }

    /// True when no project root could be read.
    pub fn is_empty(&self) -> bool {
        self.by_root.is_empty()
    }

    /// The Provenance of one path in one project root, absent when the root
    /// was not read or the path does not sit inside it.
    pub fn of(&self, root: &Path, path: &Path) -> Option<Provenance> {
        let repository = self.by_root.get(root)?;
        let relative = path.strip_prefix(root).ok()?;
        Some(repository.of(&slashed(relative)))
    }

    /// Stamps Repository Provenance onto one Item.
    ///
    /// Only a project-scope Item whose adapter left the Provenance undetermined
    /// is touched: a marketplace install, a plugin's own file and the Agent's
    /// own writes already know where they came from. Repository Metadata is
    /// left alone as well, because `.git` is never tracked by the repository it
    /// belongs to and "placed by hand" would be the wrong thing to say about
    /// a file that arrived with a clone.
    pub fn stamp_item(&self, item: &mut Item) {
        if item.provenance != Provenance::Unknown || item.kind == Kind::RepositoryMetadata {
            return;
        }
        let Scope::Project(root) = item.scope.clone() else {
            return;
        };
        if let Some(provenance) = self.of(&root, &item.path) {
            item.provenance = provenance;
        }
    }

    /// Stamps every Item of an enumeration, whichever adapter yielded it.
    pub fn stamp(&self, enumeration: &mut Enumeration) {
        for item in &mut enumeration.items {
            self.stamp_item(item);
        }
    }
}

/// A relative path as git writes it in the index: forward slashes, no leading
/// separator.
fn slashed(relative: &Path) -> String {
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<String>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Activation, Item};

    fn item(kind: Kind, root: &str, path: &str, provenance: Provenance) -> Item {
        Item::file(
            "workspace",
            Scope::Project(PathBuf::from(root)),
            kind,
            path,
            PathBuf::from(root).join(path),
            provenance,
            Activation::Unknown,
            b"x".to_vec(),
        )
    }

    fn provenances() -> Provenances {
        let mut provenances = Provenances::new();
        provenances.insert(
            PathBuf::from("/src/demo"),
            RepositoryProvenance::new("0badc0ffee", [".env".to_string(), "CLAUDE.md".to_string()]),
        );
        provenances
    }

    #[test]
    fn a_tracked_file_carries_the_head_commit() {
        let mut tracked = item(Kind::EnvFile, "/src/demo", ".env", Provenance::Unknown);
        provenances().stamp_item(&mut tracked);
        assert_eq!(
            tracked.provenance,
            Provenance::Repository {
                commit: "0badc0ffee".to_string()
            }
        );
        assert_eq!(tracked.provenance.reference(), "0badc0ffee");
    }

    #[test]
    fn an_untracked_file_in_a_read_repository_is_the_users_own() {
        let mut untracked = item(
            Kind::EnvFile,
            "/src/demo",
            ".env.local",
            Provenance::Unknown,
        );
        provenances().stamp_item(&mut untracked);
        assert_eq!(untracked.provenance, Provenance::Manual);
    }

    #[test]
    fn a_root_whose_index_was_not_read_leaves_the_provenance_alone() {
        let mut elsewhere = item(Kind::EnvFile, "/src/other", ".env", Provenance::Unknown);
        provenances().stamp_item(&mut elsewhere);
        assert_eq!(elsewhere.provenance, Provenance::Unknown);
    }

    #[test]
    fn provenance_an_adapter_already_determined_is_never_overwritten() {
        let mut written = item(
            Kind::InstructionFile,
            "/src/demo",
            "CLAUDE.md",
            Provenance::AgentWritten,
        );
        provenances().stamp_item(&mut written);
        assert_eq!(written.provenance, Provenance::AgentWritten);
    }

    #[test]
    fn repository_metadata_is_left_undetermined_because_git_never_tracks_itself() {
        let mut metadata = item(
            Kind::RepositoryMetadata,
            "/src/demo",
            ".git/config",
            Provenance::Unknown,
        );
        provenances().stamp_item(&mut metadata);
        assert_eq!(metadata.provenance, Provenance::Unknown);
    }

    #[test]
    fn a_user_scope_item_is_never_repository_provenance() {
        let mut user = Item::file(
            "claude-code",
            Scope::User,
            Kind::InstructionFile,
            "CLAUDE.md",
            PathBuf::from("/src/demo/CLAUDE.md"),
            Provenance::Unknown,
            Activation::Active,
            b"x".to_vec(),
        );
        provenances().stamp_item(&mut user);
        assert_eq!(user.provenance, Provenance::Unknown);
    }

    #[test]
    fn a_whole_enumeration_is_stamped_at_once() {
        let mut enumeration = Enumeration {
            items: vec![
                item(
                    Kind::InstructionFile,
                    "/src/demo",
                    "CLAUDE.md",
                    Provenance::Unknown,
                ),
                item(
                    Kind::EnvFile,
                    "/src/demo",
                    ".env.local",
                    Provenance::Unknown,
                ),
            ],
            problems: Vec::new(),
        };
        provenances().stamp(&mut enumeration);
        assert_eq!(enumeration.items[0].provenance.as_str(), "repository");
        assert_eq!(enumeration.items[1].provenance.as_str(), "manual");
    }

    #[test]
    fn a_nested_path_is_looked_up_the_way_git_writes_it() {
        let mut provenances = Provenances::new();
        provenances.insert(
            PathBuf::from("/src/demo"),
            RepositoryProvenance::new("c0ffee", [".claude/settings.json".to_string()]),
        );
        assert_eq!(
            provenances.of(
                Path::new("/src/demo"),
                Path::new("/src/demo/.claude/settings.json")
            ),
            Some(Provenance::Repository {
                commit: "c0ffee".to_string()
            })
        );
        assert_eq!(provenances.len(), 1);
        assert!(!provenances.is_empty());
        assert_eq!(
            provenances
                .get(Path::new("/src/demo"))
                .map(RepositoryProvenance::tracked_paths),
            Some(1)
        );
    }
}
