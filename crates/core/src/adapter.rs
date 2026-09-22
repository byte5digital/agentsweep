//! The Surface Adapter contract.
//!
//! An adapter is an in-tree crate that knows where one Agent's Surfaces live
//! and how they are structured (ADR 0002). It exposes a static [`Descriptor`]
//! so the core never hardcodes an Agent path, and it never sees a Tier or a
//! Rule.
//!
//! This slice carries the read path of the trait in spec section 3.2:
//! `descriptor`, `detect`, `projects` and `enumerate`. The watch roots, the
//! path-to-Item mapping and the enforcement pair arrive with the milestones
//! that need them (1, 4 and 6); their signatures are in the spec and are not
//! anticipated here.

use std::path::PathBuf;

use crate::host::Host;
use crate::item::{Item, Kind};

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
}
