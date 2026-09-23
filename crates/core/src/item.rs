//! The Item: one thing an Agent would load from a Surface.
//!
//! The Item is the unit of identity, Trust, Baseline and Quarantine. This
//! module carries the closed vocabularies a Rule reads back as `item.*` (see
//! the struct-global schema in `rules/README.md`), the [`ItemId`] and the
//! derived file facts a Surface Adapter attaches.
//!
//! All three shapes are here: a file, an entry and a [`Tree`], which carries
//! the manifest of every regular file below one directory and the bytes of the
//! files a Rule is run over. That is why [`Item::scan_units`] returns a list
//! rather than one unit.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::host::Host;

/// The Surface kinds. A closed core enum by design (ADR 0002): Rules, Severity
/// wording and the Quarantine primitive table all key on it, and `Generic`
/// keeps a new Surface Adapter shippable with file-level Rules only.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Kind {
    /// `CLAUDE.md`, `AGENTS.md` and the other files an Agent reads as prose.
    InstructionFile,
    /// A skill directory.
    Skill,
    /// One installed plugin version.
    Plugin,
    /// One marketplace clone.
    Marketplace,
    /// One MCP server entry.
    McpServer,
    /// One hook handler entry.
    Hook,
    /// One settings key.
    SettingsEntry,
    /// An execution policy file.
    ExecPolicy,
    /// A subagent definition.
    Subagent,
    /// A workflow definition.
    Workflow,
    /// The git files an Agent executes before trust.
    RepositoryMetadata,
    /// An env file, for the keys that re-point an Agent only.
    EnvFile,
    /// Anything a Surface Adapter yields before the core learns its specifics.
    Generic,
}

impl Kind {
    /// Every kind, in the order the core pre-filters the Rule corpus.
    pub const ALL: [Kind; 13] = [
        Kind::InstructionFile,
        Kind::Skill,
        Kind::Plugin,
        Kind::Marketplace,
        Kind::McpServer,
        Kind::Hook,
        Kind::SettingsEntry,
        Kind::ExecPolicy,
        Kind::Subagent,
        Kind::Workflow,
        Kind::RepositoryMetadata,
        Kind::EnvFile,
        Kind::Generic,
    ];

    /// The spelling a Rule reads in `item.kind` and lists in its `kinds` meta.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::InstructionFile => "InstructionFile",
            Kind::Skill => "Skill",
            Kind::Plugin => "Plugin",
            Kind::Marketplace => "Marketplace",
            Kind::McpServer => "McpServer",
            Kind::Hook => "Hook",
            Kind::SettingsEntry => "SettingsEntry",
            Kind::ExecPolicy => "ExecPolicy",
            Kind::Subagent => "Subagent",
            Kind::Workflow => "Workflow",
            Kind::RepositoryMetadata => "RepositoryMetadata",
            Kind::EnvFile => "EnvFile",
            Kind::Generic => "Generic",
        }
    }

    /// The segment an [`ItemId`] carries for this kind.
    pub fn id_segment(self) -> &'static str {
        match self {
            Kind::InstructionFile => "instruction-file",
            Kind::Skill => "skill",
            Kind::Plugin => "plugin",
            Kind::Marketplace => "marketplace",
            Kind::McpServer => "mcp-server",
            Kind::Hook => "hook",
            Kind::SettingsEntry => "settings-entry",
            Kind::ExecPolicy => "exec-policy",
            Kind::Subagent => "subagent",
            Kind::Workflow => "workflow",
            Kind::RepositoryMetadata => "repository-metadata",
            Kind::EnvFile => "env-file",
            Kind::Generic => "generic",
        }
    }

    /// Reads back the spelling a Rule uses in its `kinds` meta.
    pub fn parse(text: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == text)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The three shapes an Item comes in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shape {
    /// One file.
    File,
    /// A directory tree scanned file by file.
    Tree,
    /// One entry inside a config file the Surface Adapter parses.
    Entry,
}

impl Shape {
    /// The spelling a Rule reads in `item.shape`.
    pub fn as_str(self) -> &'static str {
        match self {
            Shape::File => "file",
            Shape::Tree => "tree",
            Shape::Entry => "entry",
        }
    }
}

/// Where an Item sits in the Agent's precedence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    /// Read-only for AgentSweep: MDM, system and cloud layers folded in.
    Managed,
    /// The user's own profile layers.
    User,
    /// One project root.
    Project(PathBuf),
}

impl Scope {
    /// The spelling a Rule reads in `item.scope`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Managed => "managed",
            Scope::User => "user",
            Scope::Project(_) => "project",
        }
    }

    /// The segment an [`ItemId`] carries, which names the root for a project.
    pub fn id_segment(&self) -> String {
        match self {
            Scope::Managed => "managed".to_string(),
            Scope::User => "user".to_string(),
            Scope::Project(root) => format!("project:{}", root.display()),
        }
    }

    /// The root every locator in this Scope is relative to.
    pub fn root(&self) -> Option<&Path> {
        match self {
            Scope::Project(root) => Some(root.as_path()),
            _ => None,
        }
    }
}

/// How an Item got onto the Surface. Determined without ever running git.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Provenance {
    /// Placed by hand.
    Manual,
    /// Installed from a marketplace.
    Marketplace {
        /// The marketplace name.
        name: String,
        /// The pinned ref the install registry records.
        pinned_ref: String,
        /// True when the marketplace is an official one.
        official: bool,
    },
    /// Shipped inside a plugin.
    Plugin {
        /// The plugin id.
        id: String,
    },
    /// Written by the Agent itself.
    AgentWritten,
    /// Tracked by git in the project, read in-process with `gix`.
    Repository {
        /// The HEAD commit at enumeration time.
        commit: String,
    },
    /// Not determined.
    Unknown,
}

impl Provenance {
    /// The spelling a Rule reads in `item.provenance`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Provenance::Manual => "manual",
            Provenance::Marketplace { .. } => "marketplace",
            Provenance::Plugin { .. } => "plugin",
            Provenance::AgentWritten => "agent_written",
            Provenance::Repository { .. } => "repository",
            Provenance::Unknown => "unknown",
        }
    }

    /// The spelling a Rule reads in `item.provenance_ref`.
    pub fn reference(&self) -> &str {
        match self {
            Provenance::Marketplace { pinned_ref, .. } => pinned_ref,
            Provenance::Plugin { id } => id,
            Provenance::Repository { commit } => commit,
            _ => "",
        }
    }

    /// True when the Provenance is an official marketplace, which is what the
    /// Allowlist anchors source-level Trust on.
    pub fn is_official(&self) -> bool {
        matches!(self, Provenance::Marketplace { official: true, .. })
    }
}

/// Why an Item would not be loaded on the Agent's next launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InactiveReason {
    /// The Agent does not trust the project yet.
    UntrustedProject,
    /// Switched off in the Agent's own configuration.
    Disabled,
    /// A plugin version no install registry points at.
    Orphaned,
    /// A hook whose recorded handler hash no longer matches.
    StaleHookHash,
}

impl InactiveReason {
    /// The spelling a Rule reads in `item.activation_reason`.
    pub fn as_str(self) -> &'static str {
        match self {
            InactiveReason::UntrustedProject => "untrusted_project",
            InactiveReason::Disabled => "disabled",
            InactiveReason::Orphaned => "orphaned",
            InactiveReason::StaleHookHash => "stale_hook_hash",
        }
    }
}

/// Whether the Agent would load the Item on its next launch. Computed by the
/// Surface Adapter, never by a Rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activation {
    /// The Agent would load it.
    Active,
    /// The Agent would not load it, for the stated reason.
    Inactive(InactiveReason),
    /// Not determined.
    Unknown,
}

impl Activation {
    /// The spelling a Rule reads in `item.activation`.
    pub fn as_str(self) -> &'static str {
        match self {
            Activation::Active => "active",
            Activation::Inactive(_) => "inactive",
            Activation::Unknown => "unknown",
        }
    }

    /// The spelling a Rule reads in `item.activation_reason`, empty when the
    /// Item is not inactive.
    pub fn reason(self) -> &'static str {
        match self {
            Activation::Inactive(reason) => reason.as_str(),
            _ => "",
        }
    }
}

/// What kind of bytes the Item holds, as the Surface Adapter classified them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    /// Text an Agent reads.
    Text,
    /// A native executable: Mach-O, PE, ELF or a `.node` addon.
    Executable,
    /// Any other non-text file that is not one of the categories below.
    Binary,
    /// A compressed archive.
    Archive,
    /// An office document.
    Office,
    /// Interpreter bytecode.
    Bytecode,
    /// An image.
    Image,
    /// Not classified.
    Unknown,
}

impl FileType {
    /// The spelling a Rule reads in `item.file_type`.
    pub fn as_str(self) -> &'static str {
        match self {
            FileType::Text => "text",
            FileType::Executable => "executable",
            FileType::Binary => "binary",
            FileType::Archive => "archive",
            FileType::Office => "office",
            FileType::Bytecode => "bytecode",
            FileType::Image => "image",
            FileType::Unknown => "unknown",
        }
    }
}

/// How the Item compares with the hash AgentSweep last accepted for it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BaselineState {
    /// Equal to the accepted hash.
    Unchanged,
    /// Different from the accepted hash.
    Changed,
    /// First seen under existing coverage and not yet accepted.
    Added,
    /// No coverage existed when the Item was first seen, or there is no
    /// daemon. A Folder Scan is always this, and it is never Drift.
    #[default]
    None,
}

impl BaselineState {
    /// The spelling a Rule reads in `item.baseline`.
    pub fn as_str(self) -> &'static str {
        match self {
            BaselineState::Unchanged => "unchanged",
            BaselineState::Changed => "changed",
            BaselineState::Added => "added",
            BaselineState::None => "none",
        }
    }
}

/// The stable identity of one Item: `<agent>/<scope>/<kind>/<locator>`.
///
/// The same thing on disk yields the same id across Scans and restarts; a
/// rename yields a new id.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ItemId(String);

impl ItemId {
    /// Builds an id from its four parts.
    pub fn new(agent: &str, scope: &Scope, kind: Kind, locator: &str) -> ItemId {
        ItemId(format!(
            "{}/{}/{}/{}",
            agent,
            scope.id_segment(),
            kind.id_segment(),
            locator
        ))
    }

    /// The id as one string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Takes an id back from the form [`ItemId::as_str`] renders, which is how
    /// a record of the Event Log or the Baseline names the Item it is about.
    pub fn from_recorded(text: &str) -> ItemId {
        ItemId(text.to_string())
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One unit of bytes a Rule is run over: the whole file, one file of a tree,
/// or the canonical serialised entry.
#[derive(Clone, Copy, Debug)]
pub struct ScanUnit<'a> {
    /// The relative path within a tree, empty for a file or an entry Item.
    /// It reaches Rules as `item.file`.
    pub file: &'a str,
    /// The bytes to scan.
    pub bytes: &'a [u8],
}

/// One thing an Agent would load from a Surface, as scanned by AgentSweep.
#[derive(Clone, Debug)]
pub struct Item {
    /// The stable identity.
    pub id: ItemId,
    /// The Agent whose Surface Adapter yielded the Item.
    pub agent: String,
    /// The Surface kind.
    pub kind: Kind,
    /// File, tree or entry.
    pub shape: Shape,
    /// Managed, User or Project.
    pub scope: Scope,
    /// Where the Item sits on disk.
    pub path: PathBuf,
    /// How the Item got onto the Surface.
    pub provenance: Provenance,
    /// Whether the Agent would load the Item on its next launch.
    pub activation: Activation,
    /// False when the Item sits in a root its own Agent does not know.
    pub registered: bool,
    /// The size of the content in bytes.
    pub size: u64,
    /// True when the Surface entry is a symbolic link.
    pub is_symlink: bool,
    /// The resolved target of the link, empty when the Item is not a link.
    pub link_target: String,
    /// How the content compares with the accepted hash.
    pub baseline: BaselineState,
    /// The derived facts about the content.
    pub facts: FileFacts,
    /// The normalised view of the Item's kind, as the Surface Adapter parsed
    /// it. Kinds whose Rules are byte Rules carry none.
    pub view: crate::views::ParsedView,
    /// The bytes of a file Item, the canonical serialised form of an entry
    /// Item, and the rendered manifest of a tree Item.
    pub content: Vec<u8>,
    /// The sha256 of the content, lower-case hex. For a tree that is the hash
    /// of the sorted manifest, so Drift can name the file that changed (spec
    /// section 3.3).
    pub content_hash: String,
    /// The files below a tree Item, empty for the other two shapes.
    pub tree: Tree,
}

impl Item {
    /// Builds a file Item from its bytes, deriving the facts, the size and the
    /// content hash.
    #[allow(clippy::too_many_arguments)]
    pub fn file(
        agent: &str,
        scope: Scope,
        kind: Kind,
        locator: &str,
        path: PathBuf,
        provenance: Provenance,
        activation: Activation,
        content: Vec<u8>,
    ) -> Item {
        let id = ItemId::new(agent, &scope, kind, locator);
        Item {
            id,
            agent: agent.to_string(),
            kind,
            shape: Shape::File,
            scope,
            path,
            provenance,
            activation,
            registered: false,
            size: content.len() as u64,
            is_symlink: false,
            link_target: String::new(),
            baseline: BaselineState::None,
            facts: FileFacts::of(&content),
            view: crate::views::ParsedView::None,
            content_hash: sha256_hex(&content),
            content,
            tree: Tree::default(),
        }
    }

    /// Builds an entry Item from the canonical serialised form of the one
    /// entry it is about.
    ///
    /// Those bytes are what a Rule scans, what Trust keys on and what the
    /// Baseline hashes (spec section 4.6.2), so an adapter renders them with
    /// [`canonical_entry`] rather than handing over the slice of the file the
    /// entry happened to be written in.
    #[allow(clippy::too_many_arguments)]
    pub fn entry(
        agent: &str,
        scope: Scope,
        kind: Kind,
        locator: &str,
        path: PathBuf,
        provenance: Provenance,
        activation: Activation,
        content: Vec<u8>,
    ) -> Item {
        let mut item = Item::file(
            agent, scope, kind, locator, path, provenance, activation, content,
        );
        item.shape = Shape::Entry;
        item
    }

    /// Builds a tree Item from the files below one directory.
    ///
    /// The identity is the directory on the Surface, the content is the
    /// rendered manifest and the content hash is the hash of that manifest, so
    /// a changed file inside the tree moves the Item's hash and the manifest
    /// still says which file it was (spec section 3.3).
    #[allow(clippy::too_many_arguments)]
    pub fn tree(
        agent: &str,
        scope: Scope,
        kind: Kind,
        locator: &str,
        path: PathBuf,
        provenance: Provenance,
        activation: Activation,
        tree: Tree,
    ) -> Item {
        let manifest = tree.manifest();
        let mut item = Item::file(
            agent, scope, kind, locator, path, provenance, activation, manifest,
        );
        item.shape = Shape::Tree;
        item.size = tree.total_bytes;
        // The facts of a tree belong to its files, one by one, and are read
        // back per scanned unit; the manifest is not a file an Agent loads.
        item.facts = FileFacts::default();
        item.tree = tree;
        item
    }

    /// Attaches the normalised view the Surface Adapter parsed for this Item.
    pub fn with_view(mut self, view: crate::views::ParsedView) -> Item {
        self.view = view;
        self
    }

    /// Records that the Item was reached through a symbolic link: the identity
    /// stays the link's location on the Surface and the content came from the
    /// target (spec section 3.3).
    pub fn through_link(mut self, target: &Path) -> Item {
        self.is_symlink = true;
        self.link_target = target.display().to_string();
        self
    }

    /// The units a Rule is run over: the whole file, the canonical serialised
    /// entry, or one unit per scanned file of a tree.
    ///
    /// A tree whose files are all vendored, over the size cap or past the
    /// caps yields one empty unit rather than none, so that every Item has a
    /// unit the common `item` global can be built for.
    pub fn scan_units(&self) -> Vec<ScanUnit<'_>> {
        if self.shape != Shape::Tree {
            return vec![ScanUnit {
                file: "",
                bytes: &self.content,
            }];
        }
        let units: Vec<ScanUnit<'_>> = self
            .tree
            .files
            .iter()
            .filter(|file| file.scanned)
            .map(|file| ScanUnit {
                file: &file.path,
                bytes: &file.content,
            })
            .collect();
        if units.is_empty() {
            return vec![ScanUnit {
                file: "",
                bytes: &[],
            }];
        }
        units
    }

    /// The facts of one unit of this Item: the file's own facts inside a tree,
    /// the Item's facts otherwise. Rule 0015 reads `item.file_type` per file
    /// of a Skill tree, which is why this is per unit rather than per Item.
    pub fn facts_of(&self, file: &str) -> FileFacts {
        if file.is_empty() {
            return self.facts;
        }
        self.tree
            .file(file)
            .map(|found| found.facts)
            .unwrap_or(self.facts)
    }
}

/// The caps a tree is read under (spec section 3.3).
///
/// A tree over the count or the byte cap is a Problem, "too large to check
/// fully", and never counts as clear. A single file over the per-file cap is
/// hashed into the manifest and not scanned: the scanner never truncates a
/// file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeCaps {
    /// How many files one tree may hold before it is too large to check.
    pub max_files: usize,
    /// How many bytes one tree may hold before it is too large to check.
    pub max_bytes: u64,
    /// How large one file may be and still be scanned rather than hashed.
    pub max_scanned_file_bytes: u64,
}

impl Default for TreeCaps {
    fn default() -> TreeCaps {
        TreeCaps {
            max_files: 10_000,
            max_bytes: 500_000_000,
            max_scanned_file_bytes: 16 * 1024 * 1024,
        }
    }
}

/// The directories whose contents are listed in the manifest and never scanned:
/// a dependency tree is not what an attacker plants an instruction in, and
/// scanning one would cost more than everything else together.
pub const VENDORED_DIRECTORIES: [&str; 3] = ["node_modules", ".venv", "vendor"];

/// The directory whose contents are not part of a tree at all. A clone's git
/// metadata is the workspace adapter's Repository Metadata, and hashing it here
/// would make every fetch look like Drift.
const GIT_DIRECTORY: &str = ".git";

/// One entry of a tree's manifest: a regular file, or a symbolic link that was
/// not followed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TreeFile {
    /// The path relative to the tree root, with forward slashes.
    pub path: String,
    /// The size in bytes, the length of the target for a link.
    pub size: u64,
    /// The permission bits, as the file system holds them. The manifest
    /// renders the canonical form of them; see [`Tree::manifest`].
    pub mode: u32,
    /// The sha256 of the content, of the target for a link.
    pub sha256: String,
    /// True when the bytes are handed to the Rules.
    pub scanned: bool,
    /// True when the entry is a symbolic link, which is never followed inside
    /// a tree (spec section 3.3).
    pub is_symlink: bool,
    /// The target of that link, empty otherwise.
    pub link_target: String,
    /// The facts derived from the file's bytes.
    pub facts: FileFacts,
    /// The bytes a Rule is run over, empty when the file is only hashed.
    pub content: Vec<u8>,
}

/// The files below one directory: the manifest of every regular file plus the
/// contents of the ones that are scanned.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    /// Every file of the tree, sorted by path.
    pub files: Vec<TreeFile>,
    /// The sum of the sizes in the manifest.
    pub total_bytes: u64,
    /// True when the tree is over a cap and was not read to the end, which is
    /// the Problem "too large to check fully".
    pub over_caps: bool,
}

impl Tree {
    /// Reads one directory into a tree under the given caps.
    ///
    /// Git internals are left out, vendored dependency directories are listed
    /// and not scanned, a file over the per-file cap is hashed and not
    /// scanned, and a symbolic link inside the tree is recorded and never
    /// followed. The walk is in sorted order and stops at the first cap it
    /// crosses, so two reads of one tree yield the same manifest.
    pub fn of(host: &Host, root: &Path, caps: TreeCaps) -> Tree {
        let mut tree = Tree::default();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = host.read_dir(&directory) else {
                continue;
            };
            // Sorted order comes off the Host; the stack reverses it, so the
            // entries go on in reverse to come off in order.
            let mut directories = Vec::new();
            for path in entries.into_iter().rev() {
                let Ok(metadata) = host.symlink_metadata(&path) else {
                    continue;
                };
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if metadata.is_dir() {
                    if name != GIT_DIRECTORY {
                        directories.push(path);
                    }
                    continue;
                }
                let Some(relative) = relative_path(root, &path) else {
                    continue;
                };
                let file = if metadata.file_type().is_symlink() {
                    link_entry(host, &path, relative, &metadata)
                } else {
                    file_entry(host, &path, relative, &metadata, caps)
                };
                tree.total_bytes += file.size;
                tree.files.push(file);
                if tree.files.len() > caps.max_files || tree.total_bytes > caps.max_bytes {
                    tree.over_caps = true;
                    tree.files.sort_by(|one, other| one.path.cmp(&other.path));
                    return tree;
                }
            }
            stack.extend(directories);
        }
        tree.files.sort_by(|one, other| one.path.cmp(&other.path));
        tree
    }

    /// The file at one relative path, absent when the tree holds none.
    pub fn file(&self, path: &str) -> Option<&TreeFile> {
        self.files
            .binary_search_by(|found| found.path.as_str().cmp(path))
            .ok()
            .map(|at| &self.files[at])
    }

    /// The names of the files directly inside one directory of the tree, in
    /// sorted order. What a plugin ships in `bin/` is read from here.
    pub fn names_in(&self, directory: &str) -> Vec<String> {
        let prefix = format!("{directory}/");
        self.files
            .iter()
            .filter_map(|file| file.path.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/'))
            .map(str::to_string)
            .collect()
    }

    /// True when the tree holds a file at one relative path.
    pub fn holds(&self, path: &str) -> bool {
        self.file(path).is_some()
    }

    /// The bytes of one file of the tree, empty when it is not there or was
    /// only hashed.
    pub fn content_of(&self, path: &str) -> &[u8] {
        self.file(path)
            .map(|file| file.content.as_slice())
            .unwrap_or_default()
    }

    /// The manifest, one line per file: the relative path, the size, the mode
    /// and the sha256. It is what a tree Item carries as its content and what
    /// its content hash is taken over.
    pub fn manifest(&self) -> Vec<u8> {
        use fmt::Write as _;
        let mut out = String::new();
        for file in &self.files {
            let _ = write!(
                out,
                "{} {} {:o} {}",
                file.path,
                file.size,
                canonical_mode(file.mode),
                file.sha256
            );
            if file.is_symlink {
                let _ = write!(out, " -> {}", file.link_target);
            }
            out.push('\n');
        }
        if self.over_caps {
            out.push_str("(too large to check fully)\n");
        }
        out.into_bytes()
    }
}

/// The permission bits as the manifest records them: executable or not, the
/// two forms git itself keeps.
///
/// A tree hash is what Trust and the Baseline key on, and the raw bits depend
/// on the umask of whoever wrote the files, so recording them would make one
/// machine's hash of a skill mean nothing on another. What the hash still
/// moves on is the change that matters, a file that became executable; the raw
/// bits stay on the manifest entry for the facts that read them.
fn canonical_mode(mode: u32) -> u32 {
    if mode & 0o111 != 0 { 0o755 } else { 0o644 }
}

/// One regular file of a tree.
fn file_entry(
    host: &Host,
    path: &Path,
    relative: String,
    metadata: &std::fs::Metadata,
    caps: TreeCaps,
) -> TreeFile {
    let size = metadata.len();
    let vendored = VENDORED_DIRECTORIES
        .iter()
        .any(|directory| is_under(&relative, directory));
    let scanned = !vendored && size <= caps.max_scanned_file_bytes;
    if scanned && let Ok(content) = host.read(path) {
        return TreeFile {
            path: relative,
            size,
            mode: mode_of(metadata),
            sha256: sha256_hex(&content),
            scanned: true,
            facts: FileFacts::of(&content),
            content,
            ..TreeFile::default()
        };
    }
    // Hashed and not scanned. The first bytes still say what kind of file it
    // is, which is what Rule 0015 reads for a native executable in a Skill.
    let file_type = host
        .read_prefix(path, FILE_TYPE_PREFIX)
        .map(|prefix| FileFacts::of(&prefix).file_type)
        .unwrap_or(FileType::Unknown);
    TreeFile {
        path: relative,
        size,
        mode: mode_of(metadata),
        sha256: host.sha256_of(path).unwrap_or_default(),
        scanned: false,
        facts: FileFacts {
            file_type,
            ..FileFacts::default()
        },
        ..TreeFile::default()
    }
}

/// One symbolic link inside a tree, recorded and never followed.
fn link_entry(
    host: &Host,
    path: &Path,
    relative: String,
    metadata: &std::fs::Metadata,
) -> TreeFile {
    let target = host
        .read_link(path)
        .map(|target| target.display().to_string())
        .unwrap_or_default();
    TreeFile {
        path: relative,
        size: target.len() as u64,
        mode: mode_of(metadata),
        sha256: sha256_hex(target.as_bytes()),
        scanned: false,
        is_symlink: true,
        link_target: target,
        ..TreeFile::default()
    }
}

/// How many bytes of a file that is not scanned are read to say what kind of
/// file it is. A magic number sits at the front or nowhere.
const FILE_TYPE_PREFIX: usize = 4096;

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

/// The path of one file inside a tree, with forward slashes, absent when it is
/// not below the root.
fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut out = String::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&name.to_string_lossy());
    }
    Some(out)
}

/// True when a relative path has one directory among its parents.
fn is_under(relative: &str, directory: &str) -> bool {
    let mut components: Vec<&str> = relative.split('/').collect();
    components.pop();
    components.contains(&directory)
}

/// The facts a Surface Adapter derives from an Item's bytes. Rules never
/// compute them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileFacts {
    /// What kind of bytes the content holds.
    pub file_type: FileType,
    /// True when the content carries right-to-left script, which is what keeps
    /// Rule 0003 silent on legitimate bidirectional text.
    pub has_rtl_script: bool,
    /// The share of whitespace in the content, in whole percent.
    pub whitespace_percent: i64,
    /// The longest run of consecutive blank lines.
    pub max_blank_run: i64,
}

impl Default for FileFacts {
    fn default() -> FileFacts {
        FileFacts {
            file_type: FileType::Unknown,
            has_rtl_script: false,
            whitespace_percent: 0,
            max_blank_run: 0,
        }
    }
}

impl FileFacts {
    /// Derives the facts from the Item's bytes.
    pub fn of(bytes: &[u8]) -> FileFacts {
        let file_type = classify(bytes);
        let text = if file_type == FileType::Text {
            std::str::from_utf8(bytes).ok()
        } else {
            None
        };
        FileFacts {
            file_type,
            has_rtl_script: text.is_some_and(|t| t.chars().any(is_rtl)),
            whitespace_percent: text.map_or(0, whitespace_percent),
            max_blank_run: text.map_or(0, max_blank_run),
        }
    }
}

/// The canonical serialisation of one config entry: JSON with every object key
/// in sorted order and no insignificant whitespace, whatever format the file
/// it was read from is written in.
///
/// It is the form spec section 4.6.2 calls the canonical sorted-key entry: the
/// bytes a Rule scans for an entry Item, the bytes Trust keys on and the bytes
/// the Baseline hashes. Rendering it here rather than per adapter is what lets
/// the same MCP Rule cover a JSON entry of Claude Code and a TOML entry of
/// Codex, and what keeps an identity from moving when a file is reformatted.
pub fn canonical_entry(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value;
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(&Value::String(key.clone()), out);
                out.push(b':');
                write_canonical(&fields[key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => out.extend_from_slice(scalar.to_string().as_bytes()),
    }
}

/// The sha256 of some bytes, lower-case hex. The hash every store, the
/// Baseline and Trust key on.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn classify(bytes: &[u8]) -> FileType {
    const MACH_O: [&[u8]; 5] = [
        &[0xfe, 0xed, 0xfa, 0xce],
        &[0xfe, 0xed, 0xfa, 0xcf],
        &[0xce, 0xfa, 0xed, 0xfe],
        &[0xcf, 0xfa, 0xed, 0xfe],
        &[0xca, 0xfe, 0xba, 0xbe],
    ];
    if MACH_O.iter().any(|magic| bytes.starts_with(magic))
        || bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
    {
        return FileType::Executable;
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"\x1f\x8b") {
        return FileType::Archive;
    }
    if bytes.starts_with(b"\x89PNG")
        || bytes.starts_with(b"\xff\xd8\xff")
        || bytes.starts_with(b"GIF8")
    {
        return FileType::Image;
    }
    if !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
        return FileType::Text;
    }
    FileType::Binary
}

fn is_rtl(c: char) -> bool {
    matches!(
        c as u32,
        0x0590..=0x08ff | 0xfb1d..=0xfdff | 0xfe70..=0xfeff | 0x10800..=0x10fff | 0x1e800..=0x1efff
    )
}

fn whitespace_percent(text: &str) -> i64 {
    let total = text.chars().count();
    if total == 0 {
        return 0;
    }
    let whitespace = text.chars().filter(|c| c.is_whitespace()).count();
    (whitespace * 100 / total) as i64
}

fn max_blank_run(text: &str) -> i64 {
    let mut longest = 0i64;
    let mut current = 0i64;
    for line in text.lines() {
        if line.trim().is_empty() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_round_trips_through_the_rule_spelling() {
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
            assert!(!kind.id_segment().is_empty());
        }
    }

    #[test]
    fn an_item_id_names_agent_scope_kind_and_locator() {
        let scope = Scope::Project(PathBuf::from("/src/demo"));
        let id = ItemId::new("claude-code", &scope, Kind::InstructionFile, "CLAUDE.md");
        assert_eq!(
            id.as_str(),
            "claude-code/project:/src/demo/instruction-file/CLAUDE.md"
        );
    }

    #[test]
    fn the_content_hash_is_the_sha256_of_the_bytes() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn text_is_classified_as_text_and_a_mach_o_header_as_executable() {
        assert_eq!(classify(b"# CLAUDE.md\n"), FileType::Text);
        assert_eq!(
            classify(&[0xcf, 0xfa, 0xed, 0xfe, 0x00]),
            FileType::Executable
        );
        assert_eq!(classify(&[0x01, 0x00, 0x02]), FileType::Binary);
    }

    #[test]
    fn right_to_left_script_is_detected_and_plain_ascii_is_not() {
        assert!(
            FileFacts::of("\u{0645}\u{0631}\u{062d}\u{0628}\u{0627}".as_bytes()).has_rtl_script
        );
        assert!(!FileFacts::of(b"hello").has_rtl_script);
    }

    #[test]
    fn the_blank_run_is_the_longest_stretch_of_empty_lines() {
        assert_eq!(FileFacts::of(b"a\n\n\n\nb\n\nc").max_blank_run, 3);
    }

    /// The bytes an entry Item carries do not depend on how the file it came
    /// from was written: keys are sorted and nothing but the entry is in them.
    #[test]
    fn the_canonical_form_of_an_entry_sorts_its_keys_and_holds_no_whitespace() {
        let written = serde_json::json!({
            "command": "npx",
            "args": ["-y", "mcp-remote@0.1.12"],
            "env": {"TOKEN": "${GITHUB_TOKEN}"},
        });
        assert_eq!(
            String::from_utf8(canonical_entry(&written)).expect("utf-8"),
            "{\"args\":[\"-y\",\"mcp-remote@0.1.12\"],\"command\":\"npx\",\
             \"env\":{\"TOKEN\":\"${GITHUB_TOKEN}\"}}"
        );
    }

    #[test]
    fn the_same_entry_written_in_another_key_order_canonicalises_the_same_way() {
        let one: serde_json::Value =
            serde_json::from_str("{\"b\":1,\"a\":{\"d\":true,\"c\":null}}").expect("json");
        let other: serde_json::Value =
            serde_json::from_str("{\"a\": {\"c\": null, \"d\": true}, \"b\": 1}").expect("json");
        assert_eq!(canonical_entry(&one), canonical_entry(&other));
        assert_eq!(
            String::from_utf8(canonical_entry(&one)).expect("utf-8"),
            "{\"a\":{\"c\":null,\"d\":true},\"b\":1}"
        );
    }

    #[test]
    fn an_entry_item_is_entry_shaped_and_hashes_its_canonical_form() {
        let content = canonical_entry(&serde_json::json!({"command": "npx"}));
        let item = Item::entry(
            "claude-code",
            Scope::User,
            Kind::McpServer,
            "~/.claude.json#notes",
            PathBuf::from("/home/u/.claude.json"),
            Provenance::Manual,
            Activation::Active,
            content.clone(),
        );
        assert_eq!(item.shape, Shape::Entry);
        assert_eq!(item.content_hash, sha256_hex(&content));
        assert_eq!(
            item.id.as_str(),
            "claude-code/user/mcp-server/~/.claude.json#notes"
        );
    }

    /// A directory of this test's own. Nothing here ever touches a real home.
    struct Directory {
        root: PathBuf,
    }

    impl Directory {
        fn new(name: &str) -> Directory {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().join(format!(
                "agentsweep-tree-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("a directory to read");
            Directory { root }
        }

        fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a directory for a file");
            }
            std::fs::write(&path, content).expect("a file");
            path
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Spec section 3.3: the manifest names every regular file, git internals
    /// are not part of a tree at all, and a vendored dependency directory is
    /// listed without being handed to the Rules.
    #[test]
    fn a_tree_lists_every_file_leaves_git_out_and_does_not_scan_what_is_vendored() {
        let directory = Directory::new("manifest");
        directory.write("SKILL.md", b"---\nname: demo\n---\n\nRun it.\n");
        directory.write("scripts/build.sh", b"#!/bin/sh\necho hello\n");
        directory.write("node_modules/left-pad/index.js", b"module.exports = 1;\n");
        directory.write(".git/config", b"[core]\n");

        let tree = Tree::of(&Host::default(), &directory.root, TreeCaps::default());

        let paths: Vec<&str> = tree.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "SKILL.md",
                "node_modules/left-pad/index.js",
                "scripts/build.sh"
            ]
        );
        assert!(tree.file("SKILL.md").expect("the skill file").scanned);
        assert!(
            !tree
                .file("node_modules/left-pad/index.js")
                .expect("the vendored file")
                .scanned,
            "a dependency tree is listed and not scanned"
        );
        assert!(!tree.over_caps);
        let scanned: Vec<&str> = tree
            .files
            .iter()
            .filter(|file| file.scanned)
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(scanned, ["SKILL.md", "scripts/build.sh"]);
        let manifest = String::from_utf8(tree.manifest()).expect("utf-8");
        assert!(manifest.contains("scripts/build.sh 21 644 "), "{manifest}");
        assert!(!manifest.contains(".git"), "{manifest}");
    }

    /// Rule 0015 asks whether one file of a Skill is a native executable, so
    /// the facts are the scanned file's own and not the tree's.
    #[test]
    fn a_native_executable_in_a_tree_is_named_in_the_manifest_and_typed_per_file() {
        let directory = Directory::new("executable");
        directory.write("SKILL.md", b"---\nname: demo\n---\n");
        let helper = directory.write("bin/helper", &[0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755))
                .expect("an executable file");
        }

        let item = Item::tree(
            "claude-code",
            Scope::User,
            Kind::Skill,
            "~/.claude/skills/demo",
            directory.root.clone(),
            Provenance::Manual,
            Activation::Active,
            Tree::of(&Host::default(), &directory.root, TreeCaps::default()),
        );

        assert_eq!(item.shape, Shape::Tree);
        assert!(
            String::from_utf8_lossy(&item.content).contains("bin/helper"),
            "the manifest names the file"
        );
        assert_eq!(item.facts_of("bin/helper").file_type, FileType::Executable);
        assert!(
            String::from_utf8_lossy(&item.content).contains("bin/helper 6 755 "),
            "the manifest records the canonical mode, so one machine's hash of \
             a tree means the same on another"
        );
        assert_eq!(item.facts_of("SKILL.md").file_type, FileType::Text);
        assert_eq!(item.tree.names_in("bin"), ["helper"]);
        let units: Vec<&str> = item.scan_units().iter().map(|unit| unit.file).collect();
        assert_eq!(units, ["SKILL.md", "bin/helper"]);
    }

    /// Spec section 3.3: a file over the per-file cap is hashed into the
    /// manifest and never scanned, because the scanner never truncates a file.
    #[test]
    fn a_file_over_the_size_cap_is_hashed_and_not_scanned() {
        let directory = Directory::new("large");
        directory.write("SKILL.md", b"---\nname: demo\n---\n");
        directory.write("data.bin", &[b'x'; 64]);
        let caps = TreeCaps {
            max_scanned_file_bytes: 32,
            ..TreeCaps::default()
        };

        let tree = Tree::of(&Host::default(), &directory.root, caps);

        let large = tree.file("data.bin").expect("the large file");
        assert!(!large.scanned);
        assert!(large.content.is_empty());
        assert_eq!(large.size, 64);
        assert_eq!(large.sha256, sha256_hex(&[b'x'; 64]));
    }

    /// A tree over a cap is the Problem "too large to check fully": what was
    /// read is still in the manifest and the manifest says it is not all.
    #[test]
    fn a_tree_over_the_count_cap_says_it_was_not_read_to_the_end() {
        let directory = Directory::new("caps");
        for index in 0..6 {
            directory.write(&format!("file-{index}.md"), b"x\n");
        }
        let caps = TreeCaps {
            max_files: 3,
            ..TreeCaps::default()
        };

        let tree = Tree::of(&Host::default(), &directory.root, caps);

        assert!(tree.over_caps);
        assert!(tree.files.len() <= 4);
        assert!(
            String::from_utf8_lossy(&tree.manifest()).contains("(too large to check fully)"),
            "the manifest says the tree was not read to the end"
        );
    }

    #[test]
    fn a_tree_over_the_byte_cap_says_the_same() {
        let directory = Directory::new("bytes");
        directory.write("one.md", &[b'a'; 40]);
        directory.write("two.md", &[b'b'; 40]);
        let caps = TreeCaps {
            max_bytes: 50,
            ..TreeCaps::default()
        };

        assert!(Tree::of(&Host::default(), &directory.root, caps).over_caps);
    }

    #[test]
    fn a_folder_scan_item_has_no_baseline() {
        let item = Item::file(
            "claude-code",
            Scope::Project(PathBuf::from("/src/demo")),
            Kind::InstructionFile,
            "CLAUDE.md",
            PathBuf::from("/src/demo/CLAUDE.md"),
            Provenance::Unknown,
            Activation::Active,
            b"# demo\n".to_vec(),
        );
        assert_eq!(item.baseline, BaselineState::None);
        assert_eq!(item.size, 7);
        assert_eq!(item.scan_units().len(), 1);
    }
}
