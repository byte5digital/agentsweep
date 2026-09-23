//! The file and tree Items of this adapter, and the plumbing they share.
//!
//! A tree Item is one directory Claude Code loads as a unit: a skill folder, a
//! plugin version, a marketplace clone. The manifest, the caps and the choice
//! of which files reach a Rule are the core's ([`agentsweep_core::item::Tree`]).
//! What is here is how this adapter names one, where it follows a symbolic
//! link, and what it does with a tree that is too large to check fully.
//!
//! Links are followed one level at a skill or rule root and never inside a
//! tree (spec section 3.3). The identity stays the link's own location on the
//! Surface, so a skill that is a link into the shared directory keeps its place
//! in `~/.claude/skills` as its id and records where the content came from.

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{Enumeration, Problem, ProblemReason};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope, Tree, TreeCaps};

use crate::document;

/// What every file and tree Item of one Scope has in common: where it sits,
/// how it got there, whether Claude Code would load it, and whether the
/// Agent's own registry knows the root it is under.
#[derive(Clone, Debug)]
pub struct Placement {
    /// Managed, User or one project root.
    pub scope: Scope,
    /// How the Item got onto the Surface.
    pub provenance: Provenance,
    /// Whether Claude Code would load it on its next launch.
    pub activation: Activation,
    /// False when the Item sits in a root Claude Code does not know.
    pub registered: bool,
}

impl Placement {
    /// The user's own configuration directory: placed by hand, loaded, and in
    /// a place the Agent cannot fail to know.
    pub fn user() -> Placement {
        Placement {
            scope: Scope::User,
            provenance: Provenance::Manual,
            activation: Activation::Active,
            registered: true,
        }
    }

    /// The managed directory: an administrator's, read-only for AgentSweep.
    pub fn managed() -> Placement {
        Placement {
            scope: Scope::Managed,
            ..Placement::user()
        }
    }

    /// One pooled project root. The Provenance is left undetermined for the
    /// workspace adapter to stamp: whether git tracks a file is the difference
    /// between the user's own configuration and a repository's.
    pub fn project(root: &Path, activation: Activation, registered: bool) -> Placement {
        Placement {
            scope: Scope::Project(root.to_path_buf()),
            provenance: Provenance::Unknown,
            activation,
            registered,
        }
    }

    /// The same placement with another Provenance, which is what a plugin's
    /// own files and a marketplace install carry.
    pub fn from(&self, provenance: Provenance) -> Placement {
        Placement {
            provenance,
            ..self.clone()
        }
    }

    /// The same placement with another Activation, which is what an orphaned
    /// plugin version and a disabled plugin carry.
    pub fn loaded(&self, activation: Activation) -> Placement {
        Placement {
            activation,
            ..self.clone()
        }
    }
}

/// One directory as a tree Item.
///
/// The location on the Surface is the identity; when it is a symbolic link the
/// files come from the target and the Item records both facts.
pub fn read(host: &Host, caps: TreeCaps, placement: &Placement, kind: Kind, path: &Path) -> Item {
    let locator = document::surface_name(host, &placement.scope, path);
    read_as(host, caps, placement, kind, &locator, path)
}

/// The same, for a tree the Agent names itself rather than by its place: a
/// plugin is `<name>@<marketplace>` wherever its version directory happens to
/// sit (spec section 3.3).
pub fn read_as(
    host: &Host,
    caps: TreeCaps,
    placement: &Placement,
    kind: Kind,
    locator: &str,
    path: &Path,
) -> Item {
    let target = host.link_target(path);
    let contents = target.clone().unwrap_or_else(|| path.to_path_buf());
    let item = Item::tree(
        crate::AGENT_ID,
        placement.scope.clone(),
        kind,
        locator,
        path.to_path_buf(),
        placement.provenance.clone(),
        placement.activation,
        Tree::of(host, &contents, caps),
    );
    let mut item = match &target {
        Some(target) => item.through_link(target),
        None => item,
    };
    item.registered = placement.registered;
    item
}

/// One file as an Item, or the Problem that stopped it from becoming one. A
/// path that is not there at all is neither.
pub fn file(
    host: &Host,
    placement: &Placement,
    kind: Kind,
    path: &Path,
) -> Option<Result<Item, Problem>> {
    let link = host.symlink_metadata(path).ok()?;
    let locator = document::surface_name(host, &placement.scope, path);
    let content = match host.read(path) {
        Ok(content) => content,
        Err(_) => {
            return Some(Err(Problem {
                surface: locator.clone(),
                path: path.to_path_buf(),
                kind: Some(kind),
                reason: ProblemReason::Unreadable,
            }));
        }
    };
    let mut item = Item::file(
        crate::AGENT_ID,
        placement.scope.clone(),
        kind,
        &locator,
        path.to_path_buf(),
        placement.provenance.clone(),
        placement.activation,
        content,
    );
    item.registered = placement.registered;
    if link.file_type().is_symlink()
        && let Some(target) = host.link_target(path)
    {
        item = item.through_link(&target);
    }
    Some(Ok(item))
}

/// Puts one tree Item into the enumeration, with the Problem that a tree over
/// the caps carries beside it.
///
/// "Too large to check fully" is never a silence: the manifest holds what was
/// read, the Problem says it is not all, and the core turns a Problem into an
/// informational Finding so the tree never counts as clear (spec section 3.3).
pub fn yielded(host: &Host, enumeration: &mut Enumeration, item: Item) {
    if item.tree.over_caps {
        enumeration.problems.push(Problem {
            surface: document::surface_name(host, &item.scope, &item.path),
            path: item.path.clone(),
            kind: Some(item.kind),
            reason: ProblemReason::Unsupported,
        });
    }
    enumeration.items.push(item);
}

/// The directories directly inside one directory, in sorted order, a symbolic
/// link to a directory among them. Empty when there is no such directory.
pub fn directories_in(host: &Host, directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = host.read_dir(directory) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter(|path| resolved(host, path).is_some_and(|found| found.is_dir()))
        .collect()
}

/// Every file below one directory whose name ends in one of the given
/// suffixes, in sorted order, walking into subdirectories when asked.
///
/// A link at an entry is followed one level, which is how a rule file linked
/// into a shared directory is still read. A link that points at a directory is
/// walked when the walk is recursive.
pub fn files_in(host: &Host, directory: &Path, suffixes: &[&str], recursive: bool) -> Vec<PathBuf> {
    let Ok(entries) = host.read_dir(directory) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for path in entries {
        let Some(location) = resolved(host, &path) else {
            continue;
        };
        if location.is_dir() {
            if recursive {
                found.extend(files_in(host, &path, suffixes, recursive));
            }
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if suffixes.iter().any(|suffix| name.ends_with(suffix)) {
            found.push(path);
        }
    }
    found
}

/// Where the files of one Surface location really are: the location itself, or
/// what it points at when it is a symbolic link.
pub fn contents_of(host: &Host, path: &Path) -> PathBuf {
    host.link_target(path).unwrap_or_else(|| path.to_path_buf())
}

/// Where one entry of a directory really is: itself, or what it points at when
/// it is a symbolic link. Absent when there is nothing there to read.
fn resolved(host: &Host, path: &Path) -> Option<PathBuf> {
    let metadata = host.symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() {
        return host.link_target(path);
    }
    Some(path.to_path_buf())
}
