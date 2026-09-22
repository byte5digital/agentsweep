//! The Item: one thing an Agent would load from a Surface.
//!
//! The Item is the unit of identity, Trust, Baseline and Quarantine. This
//! module carries the closed vocabularies a Rule reads back as `item.*` (see
//! the struct-global schema in `rules/README.md`), the [`ItemId`] and the
//! derived file facts a Surface Adapter attaches.
//!
//! Only the file shape is populated in this slice; the tree and entry shapes
//! arrive with milestone 1 of the build plan, which is why [`Item::scan_units`]
//! already returns a list rather than one unit.

use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

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
    /// The content of a file Item. Tree and entry content arrive with
    /// milestone 1 of the build plan.
    pub content: Vec<u8>,
    /// The sha256 of the content, lower-case hex.
    pub content_hash: String,
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

    /// Attaches the normalised view the Surface Adapter parsed for this Item.
    pub fn with_view(mut self, view: crate::views::ParsedView) -> Item {
        self.view = view;
        self
    }

    /// The units a Rule is run over. One for a file Item; one per file for a
    /// tree and the canonical serialised form for an entry, once those shapes
    /// land.
    pub fn scan_units(&self) -> Vec<ScanUnit<'_>> {
        vec![ScanUnit {
            file: "",
            bytes: &self.content,
        }]
    }
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
