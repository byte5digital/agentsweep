//! The Surface Adapter contract.
//!
//! An adapter is an in-tree crate that knows where one Agent's Surfaces live
//! and how they are structured (ADR 0002). It exposes a static [`Descriptor`]
//! so the core never hardcodes an Agent path, and it never sees a Tier or a
//! Rule.
//!
//! The trait of spec section 3.2 is here whole: the read path, `descriptor`,
//! `detect`, `projects`, `enumerate`, `watch_roots` and `items_for_path`, and
//! the enforcement pair, [`SurfaceAdapter::enforce`] and
//! [`SurfaceAdapter::restore`]. What one Quarantine does to an Item of a kind
//! is not the adapter's to decide: it is the [`ELIGIBILITY`] table of spec
//! section 5.2, and an adapter may only declare which part of a row it can
//! carry out.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::host::Host;
use crate::item::{Item, ItemId, Kind, Scope, Shape};
use crate::quarantine::{Conflict, EnforcementError, Receipt, RestoreReport, Store};

/// What one enforcement step may do to an Item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Primitive {
    /// The core moves a file or tree into the quarantine store.
    MoveOut,
    /// The adapter rewrites one entry out of a shared config file.
    RemoveEntry,
    /// The adapter flips the Agent's own switch, never on its own.
    NativeDisable,
    /// The adapter comments the line or key out in place.
    NeutraliseInPlace,
}

impl Primitive {
    /// The spelling a Receipt step carries.
    pub fn as_str(self) -> &'static str {
        self.recorded().as_str()
    }

    /// The same primitive as a Receipt step names it. The two spellings are
    /// one vocabulary; the enum here is the adapter contract's and the one in
    /// [`crate::eventlog`] is the record's.
    pub fn recorded(self) -> crate::eventlog::Primitive {
        match self {
            Primitive::MoveOut => crate::eventlog::Primitive::MoveOut,
            Primitive::RemoveEntry => crate::eventlog::Primitive::RemoveEntry,
            Primitive::NativeDisable => crate::eventlog::Primitive::NativeDisable,
            Primitive::NeutraliseInPlace => crate::eventlog::Primitive::NeutraliseInPlace,
        }
    }

    /// The primitive a Receipt step names.
    pub fn of_recorded(recorded: crate::eventlog::Primitive) -> Primitive {
        match recorded {
            crate::eventlog::Primitive::MoveOut => Primitive::MoveOut,
            crate::eventlog::Primitive::RemoveEntry => Primitive::RemoveEntry,
            crate::eventlog::Primitive::NativeDisable => Primitive::NativeDisable,
            crate::eventlog::Primitive::NeutraliseInPlace => Primitive::NeutraliseInPlace,
        }
    }
}

impl fmt::Display for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One Surface an adapter knows about, as its static table declares it.
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    /// The kind of Item the Surface yields.
    pub kind: Kind,
    /// How the Surface is reached, for the descriptor's own documentation.
    pub locator: &'static str,
}

/// The static declaration table of one adapter.
#[derive(Clone, Copy, Debug)]
pub struct Descriptor {
    /// The machine-readable Agent id.
    pub agent: &'static str,
    /// The name shown to a person.
    pub display_name: &'static str,
    /// The kinds this adapter yields.
    pub kinds: &'static [Kind],
    /// The config directory relative to the home, before any override.
    pub default_config_dir: &'static str,
    /// The Surfaces the adapter reads.
    pub surfaces: &'static [Surface],
    /// The enforcement primitives the adapter declares per kind.
    pub capabilities: &'static [(Kind, &'static [Primitive])],
}

impl Descriptor {
    /// The primitives this adapter declares for one kind, empty when it
    /// declares none. Managed Items declare none.
    pub fn capabilities_for(&self, kind: Kind) -> &'static [Primitive] {
        self.capabilities
            .iter()
            .find(|(declared, _)| *declared == kind)
            .map(|(_, primitives)| *primitives)
            .unwrap_or(&[])
    }
}

/// What the core does with an Item of one kind once a Tier decided against it
/// (spec section 5.2). Eligibility is per kind, never per Rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Eligibility {
    /// The kind the row describes.
    pub kind: Kind,
    /// The primitives one Quarantine applies, in order. More than one is a
    /// composite, such as a plugin's native disable followed by a move out.
    pub primitives: &'static [Primitive],
    /// True when a stable T0 or T1 Threat Finding may act on this kind by
    /// itself. False means the Finding is raised and a person clicks.
    pub automatic: bool,
}

/// The primitive per kind and what may happen automatically, spec section 5.2.
/// Repository Metadata and env files are neutralised in place and never
/// quarantined automatically, whatever a Rule says about them.
pub static ELIGIBILITY: &[Eligibility] = &[
    row(Kind::InstructionFile, &[Primitive::MoveOut], true),
    row(Kind::Skill, &[Primitive::MoveOut], true),
    row(
        Kind::Plugin,
        &[Primitive::NativeDisable, Primitive::MoveOut],
        true,
    ),
    row(
        Kind::Marketplace,
        &[Primitive::RemoveEntry, Primitive::MoveOut],
        true,
    ),
    row(Kind::McpServer, &[Primitive::RemoveEntry], true),
    row(Kind::Hook, &[Primitive::RemoveEntry], true),
    row(Kind::SettingsEntry, &[Primitive::RemoveEntry], true),
    row(Kind::ExecPolicy, &[Primitive::MoveOut], true),
    row(Kind::Subagent, &[Primitive::MoveOut], true),
    row(Kind::Workflow, &[Primitive::MoveOut], true),
    row(
        Kind::RepositoryMetadata,
        &[Primitive::NeutraliseInPlace],
        false,
    ),
    row(Kind::EnvFile, &[Primitive::NeutraliseInPlace], false),
    // A kind the core has not learned the specifics of is moved out by hand
    // only: a new adapter ships with file-level Rules before it ships with an
    // automatic action.
    row(Kind::Generic, &[Primitive::MoveOut], false),
];

const fn row(kind: Kind, primitives: &'static [Primitive], automatic: bool) -> Eligibility {
    Eligibility {
        kind,
        primitives,
        automatic,
    }
}

/// The eligibility row of one kind.
pub fn eligibility(kind: Kind) -> &'static Eligibility {
    ELIGIBILITY
        .iter()
        .find(|row| row.kind == kind)
        .expect("every kind has an eligibility row")
}

/// Whether a stable T0 or T1 Threat Finding on this Item may quarantine it
/// without asking. Managed Items are read-only for AgentSweep, so Scope can
/// only ever take the answer away, never grant it.
pub fn quarantines_automatically(item: &Item) -> bool {
    item.scope != Scope::Managed && eligibility(item.kind).automatic
}

/// What `detect` found. The Agent binary is never executed: presence is the
/// config directory or a stat on `PATH`, and the version comes from on-disk
/// metadata or is unknown.
#[derive(Clone, Debug, Default)]
pub struct Detection {
    /// True when the Agent is installed on this machine.
    pub installed: bool,
    /// The version read from disk, absent when it cannot be read.
    pub version: Option<String>,
    /// The config directory in effect.
    pub config_dir: Option<PathBuf>,
}

/// What an Agent's own registry says about a project it knows.
#[derive(Clone, Debug)]
pub struct ProjectRegistration {
    /// The project root.
    pub root: PathBuf,
    /// The Agent's own trust state for the project, as written on disk.
    pub native_trust: String,
    /// Which registry the project was found in.
    pub registered_in: String,
}

/// Why a path could not become an Item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemReason {
    /// The path could not be read.
    Unreadable,
    /// The content could not be parsed.
    Unparseable,
    /// The Surface shape is not supported yet.
    Unsupported,
}

impl ProblemReason {
    /// The spelling a Finding's Source carries.
    pub fn as_str(self) -> &'static str {
        match self {
            ProblemReason::Unreadable => "unreadable",
            ProblemReason::Unparseable => "unparseable",
            ProblemReason::Unsupported => "unsupported",
        }
    }

    /// The developer-facing one line of the Finding the core makes from it.
    pub fn title(self) -> &'static str {
        match self {
            ProblemReason::Unreadable => "A Surface that could not be read",
            ProblemReason::Unparseable => "A Surface that could not be parsed",
            ProblemReason::Unsupported => "A Surface that could not be checked fully",
        }
    }

    /// The one sentence the Simple Posture shows. It says what was not done,
    /// never that anything is wrong.
    pub fn plain(self) -> &'static str {
        match self {
            ProblemReason::Unreadable => {
                "AgentSweep could not read this, so it has not been checked."
            }
            ProblemReason::Unparseable => {
                "AgentSweep could not make sense of this file, so it has not been checked."
            }
            ProblemReason::Unsupported => {
                "This is too large for AgentSweep to check all the way through."
            }
        }
    }
}

/// One path an adapter could not turn into an Item. The core makes an
/// informational Exposure Finding from it.
#[derive(Clone, Debug)]
pub struct Problem {
    /// The Surface the path belongs to.
    pub surface: String,
    /// The path itself.
    pub path: PathBuf,
    /// The kind the path would have yielded, when that is known.
    pub kind: Option<Kind>,
    /// Why it did not become an Item.
    pub reason: ProblemReason,
}

/// The result of one eager enumeration pass: complete Items with content and
/// hashes, plus the paths that did not make it.
#[derive(Clone, Debug, Default)]
pub struct Enumeration {
    /// The Items found.
    pub items: Vec<Item>,
    /// The paths that could not be read, parsed or supported.
    pub problems: Vec<Problem>,
}

impl Enumeration {
    /// Folds another enumeration into this one.
    pub fn extend(&mut self, other: Enumeration) {
        self.items.extend(other.items);
        self.problems.extend(other.problems);
    }
}

/// The directories a watcher follows for one adapter, recomputed after every
/// full enumeration so a symlink target is watched once a link into it exists.
/// A home directory and a project root are never watched recursively.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchRoots {
    /// Directories watched with everything below them.
    pub recursive: Vec<PathBuf>,
    /// Directories watched for their own entries only.
    pub non_recursive: Vec<PathBuf>,
}

impl WatchRoots {
    /// Declares a directory watched with everything below it.
    pub fn watch_recursively(&mut self, path: PathBuf) {
        self.non_recursive.retain(|declared| *declared != path);
        if !self.recursive.contains(&path) {
            self.recursive.push(path);
        }
    }

    /// Declares a directory watched for its own entries only. A directory
    /// already watched recursively stays recursive.
    pub fn watch(&mut self, path: PathBuf) {
        if !self.recursive.contains(&path) && !self.non_recursive.contains(&path) {
            self.non_recursive.push(path);
        }
    }

    /// Every declared root, the recursive ones first.
    pub fn all(&self) -> impl Iterator<Item = &Path> {
        self.recursive
            .iter()
            .chain(self.non_recursive.iter())
            .map(PathBuf::as_path)
    }

    /// True when a changed path falls inside one of these roots, which is what
    /// decides whether a Change Scan may be trusted with it.
    pub fn covers(&self, path: &Path) -> bool {
        let parent = path.parent();
        self.non_recursive.iter().any(|root| parent == Some(root))
            || self
                .recursive
                .iter()
                .any(|root| path.strip_prefix(root).is_ok())
    }

    /// Puts both lists in a stable order, so two enumerations of the same tree
    /// declare the same roots in the same order.
    pub fn sort(&mut self) {
        self.recursive.sort();
        self.non_recursive.sort();
    }
}

/// The per-Agent component that knows where that Agent's Surfaces live.
pub trait SurfaceAdapter {
    /// The static declaration table.
    fn descriptor(&self) -> &'static Descriptor;

    /// Whether the Agent is installed, which version is on disk and which
    /// config directory is in effect. Never executes the Agent binary.
    fn detect(&self, host: &Host) -> Detection;

    /// The projects the Agent's own registries list. Never crawls the file
    /// system.
    fn projects(&self, host: &Host) -> Vec<ProjectRegistration>;

    /// Every Item on this Agent's Surfaces, at the user level and at each of
    /// the pooled project roots, with content and hashes in one pass.
    fn enumerate(&self, host: &Host, roots: &[PathBuf]) -> Enumeration;

    /// The directories the watcher follows for this adapter, given what the
    /// last full enumeration found.
    ///
    /// The default watches the directory each Item sits in and nothing below
    /// it, which is the honest answer for an adapter that yields files at
    /// known paths. An adapter with a directory Surface overrides it and
    /// declares that directory recursive.
    fn watch_roots(&self, enumeration: &Enumeration) -> WatchRoots {
        let mut roots = WatchRoots::default();
        for item in &enumeration.items {
            match item.shape {
                Shape::Tree => roots.watch_recursively(item.path.clone()),
                _ => {
                    if let Some(parent) = item.path.parent() {
                        roots.watch(parent.to_path_buf());
                    }
                }
            }
        }
        roots.sort();
        roots
    }

    /// The Items a changed path belongs to. A Change Scan re-enumerates only
    /// these ids.
    ///
    /// The default maps a path to the Item that sits at it and to every tree
    /// Item that contains it, which covers file and entry Items whose locator
    /// is their path.
    fn items_for_path(&self, enumeration: &Enumeration, path: &Path) -> Vec<ItemId> {
        enumeration
            .items
            .iter()
            .filter(|item| {
                item.path == path || (item.shape == Shape::Tree && path.starts_with(&item.path))
            })
            .map(|item| item.id.clone())
            .collect()
    }

    /// Takes one Item out of this Agent's Surface and says what it did.
    ///
    /// The primitives are one row of [`ELIGIBILITY`], in the order they are to
    /// be carried out, and what comes back is the [`Receipt`] of spec section
    /// 5.3: one Quarantine, one Receipt, a step per primitive. The spec writes
    /// the signature as `enforce(host, item, primitive)`; the whole row is
    /// passed at once because a composite kind is still one Quarantine, and
    /// the [`Store`] is passed because the quarantine store belongs to the
    /// core and an adapter never learns where it is.
    ///
    /// The default refuses, so an adapter that has not learned a primitive
    /// yet flags rather than acting.
    fn enforce(
        &self,
        host: &Host,
        store: &dyn Store,
        item: &Item,
        primitives: &[Primitive],
    ) -> Result<Receipt, EnforcementError> {
        let _ = (host, store);
        Err(EnforcementError::Unsupported {
            kind: item.kind,
            primitive: primitives.first().copied().unwrap_or(Primitive::MoveOut),
        })
    }

    /// Puts one Item back by replaying its Receipt in reverse.
    ///
    /// The spec writes the signature as `restore(host, receipt)`; it answers
    /// with a report because spec section 5.4 asks for the outcome of every
    /// reversed step, and it takes the user's answer to a conflict because
    /// Restore refuses by itself and offers the two alternatives.
    ///
    /// The default refuses every step, which is what an adapter that cannot
    /// enforce can also not undo.
    fn restore(
        &self,
        host: &Host,
        store: &dyn Store,
        receipt: &Receipt,
        conflict: Conflict,
    ) -> RestoreReport {
        let _ = (host, store, conflict);
        RestoreReport::of(
            receipt
                .steps
                .iter()
                .rev()
                .map(|step| crate::eventlog::ReceiptStep {
                    outcome: crate::eventlog::Outcome::Failed,
                    detail: "this adapter cannot put a step back".to_string(),
                    ..step.clone()
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Activation, Provenance};

    #[test]
    fn every_kind_has_exactly_one_eligibility_row() {
        for kind in Kind::ALL {
            let rows = ELIGIBILITY.iter().filter(|row| row.kind == kind).count();
            assert_eq!(rows, 1, "{kind} has {rows} eligibility rows");
            assert!(!eligibility(kind).primitives.is_empty(), "{kind}");
        }
    }

    /// Spec section 5.2: whatever a Rule says, these two kinds are neutralised
    /// in place and a person decides.
    #[test]
    fn repository_metadata_and_env_files_are_never_quarantined_automatically() {
        for kind in [Kind::RepositoryMetadata, Kind::EnvFile] {
            let row = eligibility(kind);
            assert_eq!(row.primitives, [Primitive::NeutraliseInPlace], "{kind}");
            assert!(!row.automatic, "{kind}");
        }
    }

    #[test]
    fn a_managed_item_is_never_quarantined_automatically_whatever_its_kind() {
        for kind in Kind::ALL {
            let item = Item::file(
                "claude-code",
                Scope::Managed,
                kind,
                "x",
                PathBuf::from("/Library/Application Support/ClaudeCode/x"),
                Provenance::Unknown,
                Activation::Active,
                b"x".to_vec(),
            );
            assert!(!quarantines_automatically(&item), "{kind}");
        }
    }

    #[test]
    fn a_watch_root_is_declared_once_and_recursive_wins() {
        let mut roots = WatchRoots::default();
        roots.watch(PathBuf::from("/src/demo"));
        roots.watch(PathBuf::from("/src/demo"));
        roots.watch(PathBuf::from("/src/demo/.git/hooks"));
        roots.watch_recursively(PathBuf::from("/src/demo/.git/hooks"));
        assert_eq!(roots.non_recursive, [PathBuf::from("/src/demo")]);
        assert_eq!(roots.recursive, [PathBuf::from("/src/demo/.git/hooks")]);
        assert!(roots.covers(Path::new("/src/demo/.env")));
        assert!(roots.covers(Path::new("/src/demo/.git/hooks/pre-commit")));
        assert!(!roots.covers(Path::new("/src/demo/src/main.rs")));
    }
}
