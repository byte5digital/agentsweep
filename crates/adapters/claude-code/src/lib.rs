//! The Claude Code Surface Adapter.
//!
//! It knows where Claude Code reads instructions and executable configuration
//! from, enumerates the Items on those Surfaces and enforces the primitives its
//! descriptor declares. It never executes the Agent binary: presence comes from
//! the config directory or a stat on `PATH`, and the version from on-disk
//! metadata.
//!
//! This slice yields one kind, the project instruction file, which is what the
//! first end-to-end path needs. The settings layers, skills, plugins,
//! marketplaces, MCP configs, hooks and the project registry arrive with
//! milestone 1 of the build plan.

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{
    Descriptor, Detection, Enumeration, Primitive, Problem, ProblemReason, ProjectRegistration,
    Surface, SurfaceAdapter,
};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};

/// The Agent id this adapter declares.
pub const AGENT_ID: &str = "claude-code";

/// The name shown to a person.
pub const DISPLAY_NAME: &str = "Claude Code";

/// The instruction file Claude Code reads from a project root.
pub const PROJECT_INSTRUCTION_FILE: &str = "CLAUDE.md";

static KINDS: &[Kind] = &[Kind::InstructionFile];

static SURFACES: &[Surface] = &[Surface {
    kind: Kind::InstructionFile,
    locator: PROJECT_INSTRUCTION_FILE,
}];

static CAPABILITIES: &[(Kind, &[Primitive])] = &[(Kind::InstructionFile, &[Primitive::MoveOut])];

static DESCRIPTOR: Descriptor = Descriptor {
    agent: AGENT_ID,
    display_name: DISPLAY_NAME,
    kinds: KINDS,
    default_config_dir: ".claude",
    surfaces: SURFACES,
    capabilities: CAPABILITIES,
};

/// The Claude Code Surface Adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeCode;

impl ClaudeCode {
    /// A new adapter. It holds no state; the Host carries the machine.
    pub fn new() -> ClaudeCode {
        ClaudeCode
    }

    /// The config directory in effect: the override AgentSweep holds for this
    /// Agent, otherwise the default directory under the home. Relocation is
    /// never followed from an env file or a settings block.
    fn config_dir(&self, host: &Host) -> Option<PathBuf> {
        if let Some(dir) = host.config_dir(AGENT_ID) {
            return Some(dir.to_path_buf());
        }
        host.home()
            .map(|home| home.join(DESCRIPTOR.default_config_dir))
    }

    /// The project instruction file of one root, or the Problem that stopped
    /// it from becoming an Item.
    fn instruction_file(&self, host: &Host, root: &Path) -> Option<Result<Item, Problem>> {
        let path = root.join(PROJECT_INSTRUCTION_FILE);
        let link = host.symlink_metadata(&path).ok()?;
        let content = match host.read(&path) {
            Ok(content) => content,
            Err(_) => {
                return Some(Err(Problem {
                    surface: PROJECT_INSTRUCTION_FILE.to_string(),
                    path,
                    kind: Some(Kind::InstructionFile),
                    reason: ProblemReason::Unreadable,
                }));
            }
        };

        let mut item = Item::file(
            AGENT_ID,
            Scope::Project(root.to_path_buf()),
            Kind::InstructionFile,
            PROJECT_INSTRUCTION_FILE,
            path.clone(),
            // Repository Provenance is the workspace adapter's to compute, in
            // process and never by running git. Until it does, the file's
            // origin is not determined.
            Provenance::Unknown,
            // Claude Code loads a project instruction file only once the
            // project is trusted, which is read from its own registry. A
            // Folder Scan runs before that, so Activation is not determined.
            Activation::Unknown,
            content,
        );
        if link.file_type().is_symlink() {
            item.is_symlink = true;
            item.link_target = host
                .read_link(&path)
                .map(|target| target.display().to_string())
                .unwrap_or_default();
        }
        Some(Ok(item))
    }
}

impl SurfaceAdapter for ClaudeCode {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn detect(&self, host: &Host) -> Detection {
        let config_dir = self.config_dir(host);
        let installed = config_dir.as_deref().is_some_and(Path::is_dir);
        Detection {
            installed,
            // The version comes from on-disk metadata and never from running
            // the Agent binary. Reading it lands with milestone 1.
            version: None,
            config_dir,
        }
    }

    fn projects(&self, _host: &Host) -> Vec<ProjectRegistration> {
        // The project registry of Claude Code is read with milestone 1. A
        // Folder Scan does not need it: the user points at one folder.
        Vec::new()
    }

    fn enumerate(&self, host: &Host, roots: &[PathBuf]) -> Enumeration {
        let mut enumeration = Enumeration::default();
        for root in roots {
            match self.instruction_file(host, root) {
                Some(Ok(item)) => enumeration.items.push(item),
                Some(Err(problem)) => enumeration.problems.push(problem),
                None => {}
            }
        }
        enumeration
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// A temporary directory of this test's own. Tests never run against the
    /// real home.
    fn temporary_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "agentsweep-claude-code-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a temporary project root");
        root
    }

    #[test]
    fn the_agent_id_is_machine_readable() {
        assert!(!AGENT_ID.is_empty());
        assert!(AGENT_ID.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn the_descriptor_declares_the_kinds_it_yields() {
        let descriptor = ClaudeCode::new().descriptor();
        assert_eq!(descriptor.agent, AGENT_ID);
        assert_eq!(descriptor.kinds, [Kind::InstructionFile]);
        assert_eq!(descriptor.surfaces.len(), 1);
        assert_eq!(descriptor.capabilities[0].1, [Primitive::MoveOut]);
    }

    #[test]
    fn a_project_root_with_an_instruction_file_yields_one_item() {
        let root = temporary_root("one-item");
        fs::write(root.join("CLAUDE.md"), b"# demo\n").expect("a planted instruction file");
        let host = Host::for_folder_scan(root.clone());

        let enumeration = ClaudeCode::new().enumerate(&host, host.project_roots());

        assert_eq!(enumeration.items.len(), 1);
        let item = &enumeration.items[0];
        assert_eq!(item.kind, Kind::InstructionFile);
        assert_eq!(item.scope, Scope::Project(root.clone()));
        assert_eq!(item.path, root.join("CLAUDE.md"));
        assert!(item.id.as_str().ends_with("/instruction-file/CLAUDE.md"));
        assert!(!item.registered);
        assert!(enumeration.problems.is_empty());
        fs::remove_dir_all(&root).expect("the temporary root goes away");
    }

    #[test]
    fn a_project_root_without_an_instruction_file_yields_nothing() {
        let root = temporary_root("no-item");
        let host = Host::for_folder_scan(root.clone());

        let enumeration = ClaudeCode::new().enumerate(&host, host.project_roots());

        assert!(enumeration.items.is_empty());
        assert!(enumeration.problems.is_empty());
        fs::remove_dir_all(&root).expect("the temporary root goes away");
    }

    #[test]
    fn the_item_id_is_the_same_across_two_enumerations() {
        let root = temporary_root("stable-id");
        fs::write(root.join("CLAUDE.md"), b"# demo\n").expect("a planted instruction file");
        let host = Host::for_folder_scan(root.clone());
        let adapter = ClaudeCode::new();

        let first = adapter.enumerate(&host, host.project_roots());
        let second = adapter.enumerate(&host, host.project_roots());

        assert_eq!(first.items[0].id, second.items[0].id);
        assert_eq!(first.items[0].content_hash, second.items[0].content_hash);
        fs::remove_dir_all(&root).expect("the temporary root goes away");
    }

    #[test]
    fn a_missing_config_directory_means_the_agent_is_not_installed() {
        let root = temporary_root("not-installed");
        let host = Host::new(root.clone(), Vec::new());
        assert!(!ClaudeCode::new().detect(&host).installed);
        fs::create_dir_all(root.join(".claude")).expect("a config directory");
        assert!(ClaudeCode::new().detect(&host).installed);
        fs::remove_dir_all(&root).expect("the temporary root goes away");
    }
}
