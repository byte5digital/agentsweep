//! The Codex Surface Adapter.
//!
//! It knows where Codex reads instructions and executable configuration from,
//! enumerates the Items on those Surfaces and enforces the primitives its
//! descriptor declares. It never executes the Agent binary: presence comes from
//! the config directory or a stat on the search path, and the version from
//! on-disk metadata.
//!
//! **The eight config layers.** Codex merges `package < mdm < system < cloud <
//! user < profile < project < session flags`, with the legacy managed file
//! above all of them (`docs/research/codex-surfaces.md` section 1.1). Three of
//! the eight are not files this scanner can read: the package defaults ship
//! inside the binary, the MDM preference is a managed preference rather than a
//! path, and the session flags are command line arguments. The cloud enterprise
//! bundle is documented as living under the config directory without a file
//! name, so nothing is guessed for it either. What is enumerated is every layer
//! that is a file on disk: the system layer, the legacy managed and
//! `requirements.toml` files, the user layer, every profile layer beside it and
//! each project layer, together with the hooks file, the execution policy
//! directory, the skills directory and the instruction files that sit beside
//! each of them.
//!
//! **One view per kind, across Agents.** A Codex `[mcp_servers.x]` table and a
//! Claude Code `"mcpServers": {"x": …}` object reach
//! [`agentsweep_core::views::McpView`] as one shape, and a hook written as TOML
//! and the same hook written as JSON share one identity, because both are read
//! into JSON first and hashed through the normal form the core defines. That is
//! what lets one MCP Rule and one hook Rule cover both Agents.
//!
//! Three things this adapter never does. It never reads git or an env file:
//! that is the workspace adapter's, once, for every Agent, and the core stamps
//! the Repository Provenance it computed onto the Items here. It never follows
//! a relocation it found in a configuration file; `CODEX_HOME` is an explicit
//! AgentSweep setting the Host carries. And it never lets a sensitive value
//! into a parsed view: an MCP `env` block and an `http_headers` block reach a
//! view as key names only.

#![warn(missing_docs)]

pub mod document;
pub mod enforce;
pub mod hooks;
pub mod mcp;
pub mod registry;
pub mod settings;

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::{
    Descriptor, Detection, Enumeration, Primitive, Problem, ProblemReason, ProjectRegistration,
    Surface, SurfaceAdapter, WatchRoots,
};
use agentsweep_core::host::Host;
use agentsweep_core::item::{
    Activation, FileFacts, InactiveReason, Item, ItemId, Kind, Provenance, Scope, canonical_entry,
};
use agentsweep_core::quarantine::{
    self, Conflict, EnforcementError, Receipt, RestoreReport, Store,
};
use agentsweep_core::views::{HookView, McpView, ParsedView, SettingsView, SkillView};
use serde_json::{Value, json};

use crate::document::{Document, Format};
use crate::hooks::{Handler, Pin};
use crate::registry::Registry;
use crate::settings::Entry;

/// The Agent id this adapter declares.
pub const AGENT_ID: &str = "codex";

/// The name shown to a person.
pub const DISPLAY_NAME: &str = "Codex";

/// The config file of every layer that has a folder.
pub const CONFIG_FILE: &str = "config.toml";

/// What the file name of a profile layer ends in, beside the config file in
/// the config directory.
pub const PROFILE_SUFFIX: &str = ".config.toml";

/// The hooks file of every layer that has a folder.
pub const HOOKS_FILE: &str = "hooks.json";

/// The execution policy directory of every layer that has a folder.
pub const RULES_DIRECTORY: &str = "rules";

/// What an execution policy file is called.
pub const RULES_EXTENSION: &str = "rules";

/// The execution policy file the "always allow" flow of the interface appends
/// to. It is the Agent's own writing, which is why spec section 4.6.5 keeps it
/// out of Drift.
pub const AGENT_WRITTEN_RULES: &str = "default.rules";

/// The skills directory of a config layer.
pub const SKILLS_DIRECTORY: &str = "skills";

/// The agent-neutral directory both a home and a project root may carry skills
/// in, beside the Codex ones.
pub const AGENTS_DIRECTORY: &str = ".agents";

/// The directory that makes a project root a Codex config layer.
pub const PROJECT_DIRECTORY: &str = ".codex";

/// The component of a skills directory that holds the skills Codex re-extracts
/// from the binary on every start.
pub const BUNDLED_SKILLS: &str = ".system";

/// What a skill is: the directory that holds this file.
pub const SKILL_FILE: &str = "SKILL.md";

/// The instruction files one directory may hold, in the order Codex reads
/// them. The first non-empty one wins and the others are never read.
pub const INSTRUCTION_FILES: [&str; 2] = ["AGENTS.override.md", "AGENTS.md"];

/// The managed directory, read-only for AgentSweep and reached only through
/// the Host's system root.
pub const MANAGED_DIRECTORY: &str = "/etc/codex";

/// The administrator's constraints file, which can take hooks and the user's
/// own execution policy away.
pub const REQUIREMENTS_FILE: &str = "requirements.toml";

/// The older name of the same file, reinterpreted as `requirements.toml`.
pub const LEGACY_MANAGED_FILE: &str = "managed_config.toml";

/// The name of the binary, looked for by a stat on the search path and never
/// run.
pub const BINARY_NAME: &str = "codex";

/// Where the version is read from, under the config directory, in the order
/// the adapter tries them. Both are written by Codex itself; neither costs a
/// process.
const VERSION_SOURCES: [&str; 2] = ["version.json", "packages/standalone/current"];

/// The feature switch that turns every hook off from any enabled layer, and
/// the name it had before.
const HOOKS_FEATURE: [&str; 2] = ["features.hooks", "features.codex_hooks"];

/// How many bytes of a resolved command are read to say what kind of file it
/// is. A magic number sits at the front or nowhere.
const FILE_TYPE_PREFIX: usize = 4096;

static KINDS: &[Kind] = &[
    Kind::InstructionFile,
    Kind::Skill,
    Kind::McpServer,
    Kind::Hook,
    Kind::SettingsEntry,
    Kind::ExecPolicy,
];

/// The static surface table of spec section 3.5, copied from the surface
/// inventory. The three layers that are not files (the package defaults, the
/// MDM preference and the `-c` session flags) are not here, because a Surface
/// is something this scanner can read.
static SURFACES: &[Surface] = &[
    Surface {
        kind: Kind::SettingsEntry,
        locator: "/etc/codex/config.toml",
    },
    Surface {
        kind: Kind::SettingsEntry,
        locator: "/etc/codex/requirements.toml",
    },
    Surface {
        kind: Kind::SettingsEntry,
        locator: "/etc/codex/managed_config.toml",
    },
    Surface {
        kind: Kind::McpServer,
        locator: "/etc/codex/config.toml#mcp_servers",
    },
    Surface {
        kind: Kind::Hook,
        locator: "/etc/codex/hooks.json",
    },
    Surface {
        kind: Kind::ExecPolicy,
        locator: "/etc/codex/rules",
    },
    Surface {
        kind: Kind::Skill,
        locator: "/etc/codex/skills",
    },
    Surface {
        kind: Kind::SettingsEntry,
        locator: "~/.codex/config.toml",
    },
    Surface {
        kind: Kind::SettingsEntry,
        locator: "~/.codex/<profile>.config.toml",
    },
    Surface {
        kind: Kind::McpServer,
        locator: "~/.codex/config.toml#mcp_servers",
    },
    Surface {
        kind: Kind::Hook,
        locator: "~/.codex/hooks.json",
    },
    Surface {
        kind: Kind::Hook,
        locator: "~/.codex/config.toml#hooks",
    },
    Surface {
        kind: Kind::ExecPolicy,
        locator: "~/.codex/rules",
    },
    Surface {
        kind: Kind::Skill,
        locator: "~/.codex/skills",
    },
    Surface {
        kind: Kind::Skill,
        locator: "~/.agents/skills",
    },
    Surface {
        kind: Kind::InstructionFile,
        locator: "~/.codex/AGENTS.md",
    },
    Surface {
        kind: Kind::SettingsEntry,
        locator: ".codex/config.toml",
    },
    Surface {
        kind: Kind::McpServer,
        locator: ".codex/config.toml#mcp_servers",
    },
    Surface {
        kind: Kind::Hook,
        locator: ".codex/hooks.json",
    },
    Surface {
        kind: Kind::Hook,
        locator: ".codex/config.toml#hooks",
    },
    Surface {
        kind: Kind::ExecPolicy,
        locator: ".codex/rules",
    },
    Surface {
        kind: Kind::Skill,
        locator: ".codex/skills",
    },
    Surface {
        kind: Kind::Skill,
        locator: ".agents/skills",
    },
    Surface {
        kind: Kind::InstructionFile,
        locator: "AGENTS.md",
    },
];

/// What one Quarantine does to each kind this adapter yields (spec section
/// 5.2). An entry is removed from the file that holds it; a file is moved out
/// by the core. NativeDisable is the first half of the plugin composite and
/// this slice yields no plugin, so nothing declares it yet.
static CAPABILITIES: &[(Kind, &[Primitive])] = &[
    (Kind::InstructionFile, &[Primitive::MoveOut]),
    (Kind::Skill, &[Primitive::MoveOut]),
    (Kind::McpServer, &[Primitive::RemoveEntry]),
    (Kind::Hook, &[Primitive::RemoveEntry]),
    (Kind::SettingsEntry, &[Primitive::RemoveEntry]),
    (Kind::ExecPolicy, &[Primitive::MoveOut]),
];

static DESCRIPTOR: Descriptor = Descriptor {
    agent: AGENT_ID,
    display_name: DISPLAY_NAME,
    kinds: KINDS,
    default_config_dir: ".codex",
    surfaces: SURFACES,
    capabilities: CAPABILITIES,
};

/// The Codex Surface Adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct Codex;

/// One config layer: the folder its hooks, execution policy and skills sit in,
/// and the config document it may hold.
#[derive(Clone, Debug)]
struct Layer {
    scope: Scope,
    folder: PathBuf,
    config: Option<Document>,
    /// Whether Codex was told to trust the layer. A layer that is not a
    /// project's is always trusted; a project layer Codex was not told to
    /// trust is loaded and then left out of the effective configuration, and
    /// on a Folder Scan there is no table to ask, so nothing is claimed.
    trusted: Option<bool>,
    /// True when the layer is the administrator's. Its hooks are pre-trusted
    /// and its Items are never AgentSweep's to touch.
    managed: bool,
    /// True when Codex holds session history for the project this layer
    /// belongs to, which is what `settings.trust_has_sessions` reports.
    has_sessions: bool,
}

/// What the layers above a project say about hooks, execution policy and
/// skills, which is what decides Activation.
#[derive(Clone, Debug, Default)]
struct Gates {
    /// Hooks are off for every session, from a layer that applies to all of
    /// them.
    hooks_off: bool,
    /// The administrator dropped every hook that is not theirs.
    managed_hooks_only: bool,
    /// The administrator dropped the user's and the projects' execution
    /// policy.
    managed_rules_only: bool,
    /// The bundled skills are off.
    bundled_skills_off: bool,
    /// The names and absolute paths `[[skills.config]]` switched off.
    disabled_skills: Vec<String>,
    /// The `[hooks.state]` table of the user layer, the only one Codex reads a
    /// hook pin from.
    hook_state: Value,
}

impl Layer {
    /// True when Codex would take this layer into account at all, which a
    /// project layer it was not told to trust is not.
    fn loaded(&self) -> bool {
        self.trusted != Some(false)
    }

    /// The Activation everything in this layer starts with.
    fn activation(&self) -> Activation {
        match self.trusted {
            Some(true) => Activation::Active,
            Some(false) => Activation::Inactive(InactiveReason::UntrustedProject),
            None => Activation::Unknown,
        }
    }
}

impl Codex {
    /// A new adapter. It holds no state; the Host carries the machine.
    pub fn new() -> Codex {
        Codex
    }

    /// The config directory in effect: the override AgentSweep holds for this
    /// Agent, otherwise the default directory under the home. Relocation is
    /// never followed from an env file or a settings block.
    pub fn config_dir(&self, host: &Host) -> Option<PathBuf> {
        if let Some(dir) = host.config_dir(AGENT_ID) {
            return Some(dir.to_path_buf());
        }
        host.home()
            .map(|home| home.join(DESCRIPTOR.default_config_dir))
    }

    /// The version Codex left on disk, absent when nothing readable says which
    /// one is installed. The binary is never run to ask it.
    pub fn version(&self, host: &Host, config_dir: &Path) -> Option<String> {
        for source in VERSION_SOURCES {
            let path = config_dir.join(source);
            let found = if source.ends_with(".json") {
                host.read_prefix(&path, 64 * 1024)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .and_then(|value| {
                        value
                            .get("version")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
            } else {
                // The standalone install points `current` at
                // `releases/<version>-<triple>`, so the link names the version
                // without anything being run.
                host.read_link(&path)
                    .ok()
                    .and_then(|target| {
                        target
                            .file_name()
                            .map(|name| name.to_string_lossy().to_string())
                    })
                    .and_then(|name| leading_version(&name))
            };
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// The layers that are not a project's, low to high: the system layer, the
    /// user layer, the profile layers beside it, and the administrator's
    /// constraints file above them all.
    fn global_layers(&self, host: &Host, enumeration: &mut Enumeration) -> Vec<Layer> {
        let mut layers = Vec::new();
        if let Some(directory) = host.system_path(MANAGED_DIRECTORY) {
            layers.push(Layer {
                scope: Scope::Managed,
                config: self.config_of(host, &Scope::Managed, &directory, enumeration),
                folder: directory,
                trusted: Some(true),
                managed: true,
                has_sessions: false,
            });
        }
        if let Some(directory) = self.config_dir(host) {
            layers.push(Layer {
                scope: Scope::User,
                config: self.config_of(host, &Scope::User, &directory, enumeration),
                folder: directory.clone(),
                trusted: Some(true),
                managed: false,
                has_sessions: false,
            });
            for path in self.profile_files(host, &directory) {
                let config = self.load(host, &Scope::User, &path, Kind::SettingsEntry, enumeration);
                layers.push(Layer {
                    scope: Scope::User,
                    config,
                    // A profile is a file rather than a folder, so it brings no
                    // hooks, execution policy or skills of its own.
                    folder: PathBuf::new(),
                    trusted: Some(true),
                    managed: false,
                    has_sessions: false,
                });
            }
        }
        if let Some(directory) = host.system_path(MANAGED_DIRECTORY) {
            for name in [LEGACY_MANAGED_FILE, REQUIREMENTS_FILE] {
                let path = directory.join(name);
                let config = self.load(
                    host,
                    &Scope::Managed,
                    &path,
                    Kind::SettingsEntry,
                    enumeration,
                );
                if config.is_some() {
                    layers.push(Layer {
                        scope: Scope::Managed,
                        config,
                        folder: PathBuf::new(),
                        trusted: Some(true),
                        managed: true,
                        has_sessions: false,
                    });
                }
            }
        }
        layers
    }

    /// The profile layers beside the user config file, in a stable order.
    fn profile_files(&self, host: &Host, config_dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = host.read_dir(config_dir) else {
            return Vec::new();
        };
        entries
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(PROFILE_SUFFIX))
            })
            .collect()
    }

    fn config_of(
        &self,
        host: &Host,
        scope: &Scope,
        folder: &Path,
        enumeration: &mut Enumeration,
    ) -> Option<Document> {
        self.load(
            host,
            scope,
            &folder.join(CONFIG_FILE),
            Kind::SettingsEntry,
            enumeration,
        )
    }

    fn load(
        &self,
        host: &Host,
        scope: &Scope,
        path: &Path,
        kind: Kind,
        enumeration: &mut Enumeration,
    ) -> Option<Document> {
        let format = if path.extension().is_some_and(|kind| kind == "json") {
            Format::Json
        } else {
            Format::Toml
        };
        match document::load(host, scope, path, kind, format) {
            Ok(document) => document,
            Err(problem) => {
                enumeration.problems.push(problem);
                None
            }
        }
    }

    /// What the layers above a project say, which is what Activation is read
    /// from.
    fn gates(&self, layers: &[Layer]) -> Gates {
        let mut gates = Gates {
            hook_state: json!({}),
            ..Gates::default()
        };
        for layer in layers {
            let Some(config) = &layer.config else {
                continue;
            };
            gates.hooks_off |= HOOKS_FEATURE
                .iter()
                .any(|switch| config.flag(switch) == Some(false));
            gates.managed_hooks_only |=
                layer.managed && config.flag("allow_managed_hooks_only") == Some(true);
            gates.managed_rules_only |= layer.managed
                && config.flag("ignore_user_and_project_exec_policy_rules") == Some(true);
            gates.bundled_skills_off |= config.flag("skills.bundled.enabled") == Some(false);
            gates.disabled_skills.extend(disabled_skills(config));
            if layer.scope == Scope::User
                && let Some(state) = config.at("hooks.state")
            {
                gates.hook_state = state.clone();
            }
        }
        gates
    }

    /// Everything one layer holds: its config entries, its MCP servers, its
    /// hooks, its execution policy and its skills.
    fn layer_items(
        &self,
        host: &Host,
        layer: &Layer,
        gates: &Gates,
        registered: bool,
        enumeration: &mut Enumeration,
    ) {
        if let Some(config) = &layer.config {
            for entry in settings::entries(config) {
                enumeration
                    .items
                    .push(self.settings_item(host, layer, config, &entry, registered));
            }
            for (name, table) in config.members("mcp_servers") {
                enumeration
                    .items
                    .push(self.server_item(host, layer, config, &name, &table, registered));
            }
            self.hook_items(
                host,
                layer,
                config,
                "hooks.hooks",
                gates,
                registered,
                enumeration,
            );
        }
        if layer.folder.as_os_str().is_empty() {
            return;
        }
        if let Some(file) = self.load(
            host,
            &layer.scope,
            &layer.folder.join(HOOKS_FILE),
            Kind::Hook,
            enumeration,
        ) {
            self.hook_items(host, layer, &file, "hooks", gates, registered, enumeration);
        }
        self.exec_policy_items(host, layer, gates, registered, enumeration);
        self.skill_items(
            host,
            &layer.scope,
            &layer.folder.join(SKILLS_DIRECTORY),
            layer.trusted,
            gates,
            registered,
            enumeration,
        );
    }

    /// One config key as an Item.
    fn settings_item(
        &self,
        host: &Host,
        layer: &Layer,
        document: &Document,
        entry: &Entry,
        registered: bool,
    ) -> Item {
        let dotted = entry.key_path.dotted();
        let locator = format!("{}#{}", document.surface, entry.key_path.pointer());
        let activation =
            if matches!(layer.scope, Scope::Project(_)) && entry.declared.project_denied {
                // Codex strips the key out of a project layer and names it in a
                // startup warning, so the value is written down and never loaded.
                Activation::Inactive(InactiveReason::Disabled)
            } else {
                layer.activation()
            };
        let mut view = SettingsView::of(&dotted, &entry.value);
        view.trust_has_sessions = layer.has_sessions;
        let mut item = Item::entry(
            AGENT_ID,
            layer.scope.clone(),
            Kind::SettingsEntry,
            &locator,
            document.path.clone(),
            provenance_of(document),
            activation,
            canonical_key(&dotted, &entry.value),
        )
        .with_view(ParsedView::Settings(view));
        item.registered = registered;
        self.note_link(host, &mut item);
        item
    }

    /// One MCP server as an Item. Its locator is the server name alone (spec
    /// section 4.6.1), so a swapped command under an unchanged name is the
    /// same Item with other content, which is what MCPoison looks like.
    fn server_item(
        &self,
        host: &Host,
        layer: &Layer,
        document: &Document,
        name: &str,
        table: &Value,
        registered: bool,
    ) -> Item {
        let locator = format!("{}#{name}", document.surface);
        let mut view = McpView::of(name, &mcp::shared_shape(table));
        mcp::attach_command_facts(&mut view, host, table, layer.scope.root());
        let activation = if table.get("enabled").and_then(Value::as_bool) == Some(false) {
            Activation::Inactive(InactiveReason::Disabled)
        } else {
            layer.activation()
        };
        let mut item = Item::entry(
            AGENT_ID,
            layer.scope.clone(),
            Kind::McpServer,
            &locator,
            document.path.clone(),
            provenance_of(document),
            activation,
            canonical_entry(table),
        )
        .with_view(ParsedView::Mcp(view));
        item.registered = registered;
        self.note_link(host, &mut item);
        item
    }

    /// Every hook handler one document registers, as Items.
    #[allow(clippy::too_many_arguments)]
    fn hook_items(
        &self,
        host: &Host,
        layer: &Layer,
        document: &Document,
        events_path: &str,
        gates: &Gates,
        registered: bool,
        enumeration: &mut Enumeration,
    ) {
        let base = layer.scope.root().map(Path::to_path_buf);
        for found in hooks::handlers(document, events_path) {
            let locator = format!(
                "{}#{}",
                document.surface,
                HookView::locator(&found.event, &found.matcher, &found.handler)
            );
            let mut view = HookView::of(&found.event, &found.matcher, &found.handler);
            if let Some(resolved) = host.resolve_command_line(&view.command, base.as_deref()) {
                view.command_file_type = file_type_of(host, &resolved);
                view.command_resolved = resolved.display().to_string();
            }
            let mut item = Item::entry(
                AGENT_ID,
                layer.scope.clone(),
                Kind::Hook,
                &locator,
                document.path.clone(),
                provenance_of(document),
                hook_activation(layer, document, gates, &found),
                canonical_entry(&HookView::normal_form(
                    &found.event,
                    &found.matcher,
                    &found.handler,
                )),
            )
            .with_view(ParsedView::Hook(view));
            item.registered = registered;
            self.note_link(host, &mut item);
            enumeration.items.push(item);
        }
    }

    /// Every execution policy file of one layer.
    fn exec_policy_items(
        &self,
        host: &Host,
        layer: &Layer,
        gates: &Gates,
        registered: bool,
        enumeration: &mut Enumeration,
    ) {
        let directory = layer.folder.join(RULES_DIRECTORY);
        for path in host.read_dir(&directory).unwrap_or_default() {
            if !path.extension().is_some_and(|kind| kind == RULES_EXTENSION) {
                continue;
            }
            let agent_written = layer.scope == Scope::User
                && path
                    .file_name()
                    .is_some_and(|name| name == AGENT_WRITTEN_RULES);
            let activation = if gates.managed_rules_only && !layer.managed && layer.loaded() {
                Activation::Inactive(InactiveReason::Disabled)
            } else {
                layer.activation()
            };
            let provenance = if agent_written {
                // The "always allow" flow of the interface appends to this one
                // file, which is why spec section 4.6.5 keeps it out of Drift.
                Provenance::AgentWritten
            } else {
                file_provenance(&layer.scope)
            };
            let locator = document::surface_name(host, &layer.scope, &path);
            match self.file_item(
                host,
                &layer.scope,
                Kind::ExecPolicy,
                &locator,
                &path,
                provenance,
                activation,
                registered,
            ) {
                Ok(item) => enumeration.items.push(item),
                Err(problem) => enumeration.problems.push(problem),
            }
        }
    }

    /// Every skill under one root.
    ///
    /// A skill is a directory tree and the tree shape is the next ticket's, so
    /// what is yielded here is the `SKILL.md` that carries the name, the
    /// description and the body Codex injects. The locator is already the
    /// skill directory, so the identity survives the move to a tree Item.
    #[allow(clippy::too_many_arguments)]
    fn skill_items(
        &self,
        host: &Host,
        scope: &Scope,
        root: &Path,
        trusted: Option<bool>,
        gates: &Gates,
        registered: bool,
        enumeration: &mut Enumeration,
    ) {
        for directory in skill_directories(host, root) {
            let path = directory.join(SKILL_FILE);
            let locator = document::surface_name(host, scope, &directory);
            let bundled = directory
                .components()
                .any(|component| component.as_os_str() == BUNDLED_SKILLS);
            let name = directory
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            let switched_off = (bundled && gates.bundled_skills_off)
                || gates
                    .disabled_skills
                    .iter()
                    .any(|off| *off == name || Path::new(off) == path);
            let activation = if switched_off {
                Activation::Inactive(InactiveReason::Disabled)
            } else if trusted == Some(true) {
                Activation::Active
            } else {
                // Whether Codex loads `.codex/skills` from a disabled project
                // layer is unverified (`docs/research/codex-surfaces.md`
                // section 2), so nothing is claimed.
                Activation::Unknown
            };
            let provenance = if bundled {
                // Codex rewrites the whole directory from the copy embedded in
                // the binary whenever the fingerprint differs.
                Provenance::AgentWritten
            } else {
                file_provenance(scope)
            };
            let view = ParsedView::Skill(SkillView {
                name,
                ..SkillView::default()
            });
            match self.file_item(
                host,
                scope,
                Kind::Skill,
                &locator,
                &path,
                provenance,
                activation,
                registered,
            ) {
                Ok(item) => enumeration.items.push(item.with_view(view)),
                Err(problem) => enumeration.problems.push(problem),
            }
        }
    }

    /// The instruction files of one directory. Codex reads the first non-empty
    /// one and never looks at the rest, so the rest are written down as
    /// Inactive rather than left out.
    fn instruction_items(
        &self,
        host: &Host,
        scope: &Scope,
        directory: &Path,
        registered: bool,
        enumeration: &mut Enumeration,
    ) {
        let mut read_already = false;
        for name in INSTRUCTION_FILES {
            let path = directory.join(name);
            if host.symlink_metadata(&path).is_err() {
                continue;
            }
            let activation = if read_already {
                Activation::Inactive(InactiveReason::Disabled)
            } else {
                Activation::Active
            };
            let locator = document::surface_name(host, scope, &path);
            match self.file_item(
                host,
                scope,
                Kind::InstructionFile,
                &locator,
                &path,
                file_provenance(scope),
                activation,
                registered,
            ) {
                Ok(item) => {
                    read_already |= item.size > 0;
                    enumeration.items.push(item);
                }
                Err(problem) => enumeration.problems.push(problem),
            }
        }
    }

    /// One file on a Surface as an Item, or the Problem that stopped it from
    /// becoming one.
    ///
    /// The locator is given rather than derived, because a skill is named by
    /// the directory it lives in and not by the one file of it that is read
    /// here.
    #[allow(clippy::too_many_arguments)]
    fn file_item(
        &self,
        host: &Host,
        scope: &Scope,
        kind: Kind,
        locator: &str,
        path: &Path,
        provenance: Provenance,
        activation: Activation,
        registered: bool,
    ) -> Result<Item, Problem> {
        let content = host.read(path).map_err(|_| Problem {
            surface: locator.to_string(),
            path: path.to_path_buf(),
            kind: Some(kind),
            reason: ProblemReason::Unreadable,
        })?;
        let mut item = Item::file(
            AGENT_ID,
            scope.clone(),
            kind,
            locator,
            path.to_path_buf(),
            provenance,
            activation,
            content,
        );
        item.registered = registered;
        self.note_link(host, &mut item);
        Ok(item)
    }

    /// Records that the file an Item was read from is a symbolic link.
    fn note_link(&self, host: &Host, item: &mut Item) {
        let Ok(metadata) = host.symlink_metadata(&item.path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            item.is_symlink = true;
            item.link_target = host
                .read_link(&item.path)
                .map(|target| target.display().to_string())
                .unwrap_or_default();
        }
    }

    /// Everything this adapter reads at one pooled project root.
    fn project_level(
        &self,
        host: &Host,
        root: &Path,
        registry: &Registry,
        gates: &Gates,
        enumeration: &mut Enumeration,
    ) {
        let scope = Scope::Project(root.to_path_buf());
        let trusted = registry.trusted(host, root);
        let registered = registry.knows(host, root);
        let folder = root.join(PROJECT_DIRECTORY);
        let layer = Layer {
            scope: scope.clone(),
            config: self.config_of(host, &scope, &folder, enumeration),
            folder,
            trusted,
            managed: false,
            has_sessions: registry.has_sessions(root),
        };
        // A trusted project may turn hooks off for its own sessions, and the
        // project denylist does not cover `features`.
        let mut gates = gates.clone();
        if let Some(config) = &layer.config
            && layer.loaded()
        {
            gates.hooks_off |= HOOKS_FEATURE
                .iter()
                .any(|switch| config.flag(switch) == Some(false));
            gates.disabled_skills.extend(disabled_skills(config));
        }
        self.layer_items(host, &layer, &gates, registered, enumeration);

        self.skill_items(
            host,
            &scope,
            &root.join(AGENTS_DIRECTORY).join(SKILLS_DIRECTORY),
            // The `.agents/skills` walk does not consult project trust.
            Some(true),
            &gates,
            registered,
            enumeration,
        );
        self.instruction_items(host, &scope, root, registered, enumeration);
    }
}

impl SurfaceAdapter for Codex {
    fn descriptor(&self) -> &'static Descriptor {
        &DESCRIPTOR
    }

    fn detect(&self, host: &Host) -> Detection {
        let config_dir = self.config_dir(host);
        let on_search_path = host
            .search_path()
            .iter()
            .any(|directory| directory.join(BINARY_NAME).is_file());
        let installed = config_dir.as_deref().is_some_and(Path::is_dir) || on_search_path;
        let version = config_dir
            .as_deref()
            .and_then(|directory| self.version(host, directory));
        Detection {
            installed,
            version,
            config_dir,
        }
    }

    fn projects(&self, host: &Host) -> Vec<ProjectRegistration> {
        let mut aside = Enumeration::default();
        let layers = self.global_layers(host, &mut aside);
        let registry = Registry::read(host, self.config_dir(host).as_deref(), &configs(&layers));
        registry
            .roots()
            .into_iter()
            .map(|root| ProjectRegistration {
                native_trust: registry.native_trust(host, &root),
                registered_in: registry.registered_in(host, &root).to_string(),
                root,
            })
            .collect()
    }

    fn enumerate(&self, host: &Host, roots: &[PathBuf]) -> Enumeration {
        let mut enumeration = Enumeration::default();
        let layers = self.global_layers(host, &mut enumeration);
        let registry = Registry::read(host, self.config_dir(host).as_deref(), &configs(&layers));
        let gates = self.gates(&layers);

        for layer in &layers {
            self.layer_items(host, layer, &gates, true, &mut enumeration);
        }
        if let Some(home) = host.home() {
            self.skill_items(
                host,
                &Scope::User,
                &home.join(AGENTS_DIRECTORY).join(SKILLS_DIRECTORY),
                Some(true),
                &gates,
                true,
                &mut enumeration,
            );
        }
        if let Some(directory) = self.config_dir(host) {
            self.instruction_items(host, &Scope::User, &directory, true, &mut enumeration);
        }
        let config_dir = self.config_dir(host);
        for root in roots {
            // A project root whose `.codex` directory is the config directory
            // is the user layer under another name, and Codex skips it rather
            // than loading the same layer twice.
            if config_dir.as_deref() == Some(root.join(PROJECT_DIRECTORY).as_path()) {
                continue;
            }
            self.project_level(host, root, &registry, &gates, &mut enumeration);
        }
        enumeration
    }

    /// A Codex configuration directory is watched with everything below it,
    /// because what sits in it is a tree of files nobody enumerated in advance.
    /// Every other Surface is a file at a known path, so the directory it sits
    /// in is watched for its own entries only, which keeps the home and a
    /// project root off the recursive list.
    fn watch_roots(&self, enumeration: &Enumeration) -> WatchRoots {
        let mut roots = WatchRoots::default();
        for item in &enumeration.items {
            match config_directory_of(&item.path) {
                Some(directory) => roots.watch_recursively(directory),
                None => {
                    if let Some(parent) = item.path.parent() {
                        roots.watch(parent.to_path_buf());
                    }
                }
            }
        }
        roots.sort();
        roots
    }

    /// A changed configuration file maps back to every entry read out of it,
    /// and a changed script maps back to the hook or the MCP server that runs
    /// it, so that editing what a hook calls re-scans the hook.
    fn items_for_path(&self, enumeration: &Enumeration, path: &Path) -> Vec<ItemId> {
        enumeration
            .items
            .iter()
            .filter(|item| item.path == path || resolved_command_of(item) == Some(path))
            .map(|item| item.id.clone())
            .collect()
    }

    /// An instruction file, a skill and an execution policy are one file or
    /// one directory, so one MoveOut is the whole Quarantine, exactly as it is
    /// for the other Agent. Every other kind this adapter yields is an entry
    /// and waits for the entry primitives.
    fn enforce(
        &self,
        host: &Host,
        store: &dyn Store,
        item: &Item,
        primitives: &[Primitive],
    ) -> Result<Receipt, EnforcementError> {
        enforce::enforce(self, host, store, item, primitives)
    }

    /// Puts the Item back by replaying its Receipt in reverse.
    fn restore(
        &self,
        host: &Host,
        store: &dyn Store,
        receipt: &Receipt,
        conflict: Conflict,
    ) -> RestoreReport {
        quarantine::replay_in_reverse(host, store, receipt, conflict)
    }
}

/// The config documents of a list of layers, low to high, which is the order
/// the trust table is merged in.
fn configs(layers: &[Layer]) -> Vec<Document> {
    layers
        .iter()
        .filter_map(|layer| layer.config.clone())
        .collect()
}

/// The nearest ancestor of a path that is a Codex or an agent-neutral
/// configuration directory, which are the directories that are watched with
/// everything below them.
pub(crate) fn config_directory_of(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory.file_name() == Some(PROJECT_DIRECTORY.as_ref())
            || directory.file_name() == Some(AGENTS_DIRECTORY.as_ref())
        {
            return Some(directory.to_path_buf());
        }
        current = directory.parent();
    }
    None
}

/// The file an Item would really run, when it is the kind of Item that runs
/// one.
pub(crate) fn resolved_command_of(item: &Item) -> Option<&Path> {
    let resolved = match &item.view {
        ParsedView::Hook(view) => &view.command_resolved,
        ParsedView::Mcp(view) => &view.command_resolved,
        _ => return None,
    };
    if resolved.is_empty() {
        return None;
    }
    Some(Path::new(resolved))
}

/// Every directory under one skills root that holds a `SKILL.md`, in a stable
/// order. The bundled skills sit one level further in, under `.system`, so the
/// walk goes two levels deep and no further.
fn skill_directories(host: &Host, root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = host.read_dir(root) else {
        return found;
    };
    for entry in entries {
        if !entry.is_dir() {
            continue;
        }
        if host.symlink_metadata(&entry.join(SKILL_FILE)).is_ok() {
            found.push(entry);
            continue;
        }
        for nested in host.read_dir(&entry).unwrap_or_default() {
            if nested.is_dir() && host.symlink_metadata(&nested.join(SKILL_FILE)).is_ok() {
                found.push(nested);
            }
        }
    }
    found
}

/// The names and paths `[[skills.config]]` switched off in one layer.
fn disabled_skills(config: &Document) -> Vec<String> {
    config
        .at("skills.config")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.get("enabled").and_then(Value::as_bool) == Some(false))
                .filter_map(|entry| {
                    entry
                        .get("name")
                        .or_else(|| entry.get("path"))
                        .and_then(Value::as_str)
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The canonical form of one config key: the key and its value, unless the key
/// names one element of a list, which has no name of its own and whose place is
/// already in the id.
pub(crate) fn canonical_key(dotted: &str, value: &Value) -> Vec<u8> {
    let last = dotted.rsplit('.').next().unwrap_or_default();
    if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()) {
        return canonical_entry(value);
    }
    canonical_entry(&json!({ dotted: value.clone() }))
}

/// The Provenance an entry read from one document starts with.
///
/// A file in a project is left undetermined for the workspace adapter to
/// stamp, because whether git tracks it is the difference between the user's
/// own configuration and a repository's. Everything else is the user's own or
/// an administrator's, and no repository ever tracks it.
fn provenance_of(document: &Document) -> Provenance {
    if document.surface.starts_with('~') || document.surface.starts_with('/') {
        Provenance::Manual
    } else {
        Provenance::Unknown
    }
}

/// The Provenance a file on a Surface starts with, by the Scope it sits in.
fn file_provenance(scope: &Scope) -> Provenance {
    match scope {
        Scope::Project(_) => Provenance::Unknown,
        _ => Provenance::Manual,
    }
}

/// Whether one registered hook handler would run on the next launch.
///
/// A managed hook is pre-trusted. Every other one runs only while its
/// normalised hash is pinned in the user `config.toml`: a hash that differs is
/// `Modified` and Codex silently skips it, which is Inactive with the reason
/// stale hook hash. No pin at all is not the same thing: an interactive session
/// offers to trust the hook at startup and a headless one skips it, and neither
/// answer is on disk.
fn hook_activation(
    layer: &Layer,
    document: &Document,
    gates: &Gates,
    handler: &Handler,
) -> Activation {
    if gates.hooks_off {
        return Activation::Inactive(InactiveReason::Disabled);
    }
    if layer.trusted != Some(true) {
        return layer.activation();
    }
    if layer.managed {
        return Activation::Active;
    }
    if gates.managed_hooks_only {
        return Activation::Inactive(InactiveReason::Disabled);
    }
    let key = hooks::state_key(&document.path, handler);
    match hooks::pin_of(&gates.hook_state, &key, handler) {
        Pin::Trusted => Activation::Active,
        Pin::Stale => Activation::Inactive(InactiveReason::StaleHookHash),
        Pin::Disabled => Activation::Inactive(InactiveReason::Disabled),
        Pin::Absent | Pin::Unverifiable => Activation::Unknown,
    }
}

/// What kind of file a resolved command is, empty when there is nothing there
/// to read.
fn file_type_of(host: &Host, path: &Path) -> String {
    match host.read_prefix(path, FILE_TYPE_PREFIX) {
        Ok(prefix) => FileFacts::of(&prefix).file_type.as_str().to_string(),
        Err(_) => String::new(),
    }
}

/// The version at the front of a release directory name such as
/// `0.144.5-aarch64-apple-darwin`, absent when the name does not start with
/// one.
fn leading_version(name: &str) -> Option<String> {
    let version: String = name
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let version = version.trim_end_matches('.').to_string();
    (version.contains('.') && version.starts_with(|c: char| c.is_ascii_digit())).then_some(version)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    use agentsweep_core::adapter::eligibility;
    use agentsweep_core::item::Shape;

    use super::*;

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A fake home and a fake project of this test's own. Nothing here ever
    /// touches the real machine.
    struct Machine {
        root: PathBuf,
    }

    impl Machine {
        fn new(name: &str) -> Machine {
            let root = std::env::temp_dir().join(format!(
                "agentsweep-codex-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("home").join(".codex")).expect("a fake config directory");
            fs::create_dir_all(root.join("project")).expect("a fake project root");
            Machine { root }
        }

        fn home(&self) -> PathBuf {
            self.root.join("home")
        }

        fn project(&self) -> PathBuf {
            self.root.join("project")
        }

        fn write(&self, relative: &str, content: &str) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("a folder of the fake machine");
            }
            fs::write(&path, content).expect("a file of the fake machine");
            path
        }

        fn host(&self) -> Host {
            Host::new(self.home(), vec![self.project()])
        }

        fn enumerate(&self) -> Enumeration {
            let host = self.host();
            Codex::new().enumerate(&host, host.project_roots())
        }
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// The one Item whose id carries this fragment. A hook's locator ends in
    /// the hash of its handler, so naming one by its event is naming part of
    /// the middle.
    fn found<'e>(enumeration: &'e Enumeration, fragment: &str) -> &'e Item {
        enumeration
            .items
            .iter()
            .find(|item| item.id.as_str().contains(fragment))
            .unwrap_or_else(|| panic!("no Item carries {fragment}"))
    }

    /// A user hooks file with two handlers: one this test can pin and one it
    /// cannot.
    fn hooks_file() -> &'static str {
        "{\"hooks\": {\"SessionStart\": [{\"hooks\": [\
         {\"type\": \"command\", \"command\": \"bash ~/.codex/start.sh\", \"timeout\": 10}]}]}}"
    }

    /// The state key and hash Codex would write for the one handler of
    /// [`hooks_file`].
    fn pin_of(machine: &Machine) -> (String, String) {
        let path = machine.home().join(".codex").join(HOOKS_FILE);
        let document = Document::inline(
            path.clone(),
            "~/.codex/hooks.json".to_string(),
            serde_json::from_str(hooks_file()).expect("the hooks file"),
        );
        let handler = hooks::handlers(&document, "hooks")
            .into_iter()
            .next()
            .expect("one handler");
        (
            hooks::state_key(&path, &handler),
            hooks::pin_hash(&handler).expect("a command handler"),
        )
    }

    /// Spec section 5.2: an adapter may declare only what the core's table
    /// says a Quarantine does to that kind.
    #[test]
    fn every_kind_this_adapter_yields_declares_a_primitive_the_core_allows() {
        for kind in DESCRIPTOR.kinds {
            let declared = DESCRIPTOR.capabilities_for(*kind);
            assert!(!declared.is_empty(), "{kind}");
            for primitive in declared {
                assert!(
                    eligibility(*kind).primitives.contains(primitive),
                    "{kind} declares {primitive:?}"
                );
            }
        }
        for surface in DESCRIPTOR.surfaces {
            assert!(
                DESCRIPTOR.kinds.contains(&surface.kind),
                "{}",
                surface.locator
            );
        }
    }

    /// Presence is the config directory or a stat on the search path, and the
    /// version is read off disk. Nothing here starts a process.
    #[test]
    fn the_version_is_read_from_the_metadata_codex_leaves_behind() {
        let machine = Machine::new("version");
        machine.write("home/.codex/version.json", "{\"version\": \"0.144.5\"}");

        let detection = Codex::new().detect(&machine.host());
        assert!(detection.installed);
        assert_eq!(detection.version.as_deref(), Some("0.144.5"));
        assert_eq!(detection.config_dir, Some(machine.home().join(".codex")));
    }

    /// The standalone install points a link at the release directory, and the
    /// name of that directory carries the version.
    #[test]
    fn the_standalone_install_names_its_version_in_the_link_it_points_at() {
        assert_eq!(
            leading_version("0.144.5-aarch64-apple-darwin"),
            Some("0.144.5".to_string())
        );
        assert_eq!(leading_version("current"), None);
        assert_eq!(leading_version("2026-aarch64"), None);
    }

    /// A relocated config directory is an AgentSweep setting the Host carries,
    /// never something followed out of a file.
    #[test]
    fn the_config_directory_is_the_one_agentsweep_was_told_about() {
        let machine = Machine::new("relocated");
        let elsewhere = machine.root.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("a relocated config directory");
        let host = machine.host().with_config_dir(AGENT_ID, elsewhere.clone());
        assert_eq!(Codex::new().config_dir(&host), Some(elsewhere));
    }

    /// The Inventory is the trust table plus the session logs, and nothing is
    /// found by crawling for folders.
    #[test]
    fn the_projects_are_the_trust_table_and_the_session_logs() {
        let machine = Machine::new("projects");
        machine.write(
            "home/.codex/config.toml",
            &format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                machine.project().display()
            ),
        );
        machine.write(
            "home/.codex/sessions/2026/09/22/rollout-one.jsonl",
            "{\"payload\":{\"cwd\":\"/src/seen\"}}\n",
        );

        let projects = Codex::new().projects(&machine.host());
        let listed: Vec<String> = projects
            .iter()
            .map(|project| format!("{} {}", project.root.display(), project.native_trust))
            .collect();
        assert!(
            listed.contains(&format!("{} trusted", machine.project().display())),
            "{listed:?}"
        );
        assert!(listed.contains(&"/src/seen ".to_string()), "{listed:?}");
        assert_eq!(
            projects
                .iter()
                .find(|project| project.root == Path::new("/src/seen"))
                .map(|project| project.registered_in.as_str()),
            Some("~/.codex/sessions")
        );
    }

    /// Acceptance: a handler whose recorded hash is not its own is Inactive
    /// with the reason stale hook hash, and the same handler with the hash
    /// Codex would have written is Active.
    #[test]
    fn a_handler_whose_state_pin_does_not_match_is_inactive_with_a_stale_hash() {
        let machine = Machine::new("pin");
        machine.write("home/.codex/hooks.json", hooks_file());
        let (key, hash) = pin_of(&machine);

        machine.write(
            "home/.codex/config.toml",
            &format!("[hooks.state.\"{key}\"]\ntrusted_hash = \"{hash}\"\n"),
        );
        let pinned = machine.enumerate();
        assert_eq!(
            found(&pinned, "hooks.json#SessionStart//").activation,
            Activation::Active
        );

        machine.write(
            "home/.codex/config.toml",
            &format!("[hooks.state.\"{key}\"]\ntrusted_hash = \"sha256:00\"\n"),
        );
        let stale = machine.enumerate();
        let item = found(&stale, "hooks.json#SessionStart//");
        assert_eq!(
            item.activation,
            Activation::Inactive(InactiveReason::StaleHookHash)
        );
        assert_eq!(item.activation.reason(), "stale_hook_hash");

        machine.write("home/.codex/config.toml", "model = \"gpt-5-codex\"\n");
        let unpinned = machine.enumerate();
        assert_eq!(
            found(&unpinned, "hooks.json#SessionStart//").activation,
            Activation::Unknown,
            "an unpinned hook is offered for review, and neither answer is on disk"
        );
    }

    /// A handler the user switched off, and the feature switch that takes
    /// every hook away from any enabled layer.
    #[test]
    fn a_hook_can_be_switched_off_one_at_a_time_or_all_at_once() {
        let machine = Machine::new("hooks-off");
        machine.write("home/.codex/hooks.json", hooks_file());
        let (key, hash) = pin_of(&machine);

        machine.write(
            "home/.codex/config.toml",
            &format!("[hooks.state.\"{key}\"]\ntrusted_hash = \"{hash}\"\nenabled = false\n"),
        );
        assert_eq!(
            found(&machine.enumerate(), "hooks.json#SessionStart//").activation,
            Activation::Inactive(InactiveReason::Disabled)
        );

        machine.write(
            "home/.codex/config.toml",
            &format!(
                "[features]\nhooks = false\n\n[hooks.state.\"{key}\"]\ntrusted_hash = \"{hash}\"\n"
            ),
        );
        assert_eq!(
            found(&machine.enumerate(), "hooks.json#SessionStart//").activation,
            Activation::Inactive(InactiveReason::Disabled)
        );
    }

    /// An administrator's hook is pre-trusted and needs no pin, and
    /// `allow_managed_hooks_only` takes the user's away.
    #[test]
    fn an_administrators_hook_is_pre_trusted_and_can_take_the_users_away() {
        let machine = Machine::new("managed-hooks");
        machine.write("home/.codex/hooks.json", hooks_file());
        machine.write(
            "system/etc/codex/hooks.json",
            "{\"hooks\": {\"Stop\": [{\"hooks\": [\
             {\"type\": \"command\", \"command\": \"/opt/site/bin/review\"}]}]}}",
        );
        machine.write(
            "system/etc/codex/requirements.toml",
            "allow_managed_hooks_only = true\n",
        );

        let host = machine.host().with_system_root(machine.root.join("system"));
        let enumeration = Codex::new().enumerate(&host, host.project_roots());
        assert_eq!(
            found(&enumeration, "hooks.json#Stop//").activation,
            Activation::Active
        );
        assert_eq!(
            found(&enumeration, "hooks.json#SessionStart//").activation,
            Activation::Inactive(InactiveReason::Disabled)
        );
    }

    /// A project layer Codex was not told to trust is loaded and then left out
    /// of the effective configuration, so nothing in it takes effect.
    #[test]
    fn an_untrusted_project_layer_is_inactive_and_its_root_is_not_registered() {
        let machine = Machine::new("untrusted");
        machine.write("home/.codex/config.toml", "model = \"gpt-5-codex\"\n");
        machine.write(
            "project/.codex/config.toml",
            "approval_policy = \"never\"\n[mcp_servers.planted]\ncommand = \"php\"\n",
        );

        let enumeration = machine.enumerate();
        let entry = found(&enumeration, ".codex/config.toml#/approval_policy");
        assert_eq!(
            entry.activation,
            Activation::Inactive(InactiveReason::UntrustedProject)
        );
        assert!(!entry.registered);
        assert_eq!(
            found(&enumeration, ".codex/config.toml#planted").activation,
            Activation::Inactive(InactiveReason::UntrustedProject)
        );
    }

    /// Codex strips the provider, notify and telemetry keys out of a project
    /// layer even when the project is trusted, so a copy of one is written
    /// down and never loaded.
    #[test]
    fn a_key_a_project_may_never_set_is_inactive_in_a_trusted_project() {
        let machine = Machine::new("denied");
        machine.write(
            "home/.codex/config.toml",
            &format!(
                "[projects.\"{}\"]\ntrust_level = \"trusted\"\n",
                machine.project().display()
            ),
        );
        machine.write(
            "project/.codex/config.toml",
            "notify = [\"/usr/bin/true\"]\napproval_policy = \"never\"\n",
        );

        let enumeration = machine.enumerate();
        assert_eq!(
            found(&enumeration, ".codex/config.toml#/notify").activation,
            Activation::Inactive(InactiveReason::Disabled)
        );
        let honoured = enumeration
            .items
            .iter()
            .find(|item| {
                item.id.as_str().contains("/project:")
                    && item
                        .id
                        .as_str()
                        .ends_with(".codex/config.toml#/approval_policy")
            })
            .expect("the project's approval policy");
        assert_eq!(honoured.activation, Activation::Active);
        assert!(honoured.registered);
    }

    /// A skill is a directory, and until tree Items land it is the `SKILL.md`
    /// that carries the body Codex injects. The locator is the directory, so
    /// the identity survives that change.
    #[test]
    fn a_skill_is_named_by_its_directory_and_read_from_its_skill_file() {
        let machine = Machine::new("skills");
        machine.write(
            "home/.codex/skills/demo/SKILL.md",
            "---\nname: demo\ndescription: nothing\n---\n",
        );
        machine.write(
            "home/.codex/skills/.system/skill-installer/SKILL.md",
            "---\nname: skill-installer\ndescription: nothing\n---\n",
        );
        machine.write(
            "home/.codex/config.toml",
            "[skills]\nbundled = { enabled = false }\n",
        );

        let enumeration = machine.enumerate();
        let demo = found(&enumeration, "skill/~/.codex/skills/demo");
        assert_eq!(demo.shape, Shape::File);
        assert_eq!(
            demo.path,
            machine.home().join(".codex/skills/demo/SKILL.md")
        );
        assert_eq!(demo.activation, Activation::Active);

        let bundled = found(&enumeration, "skills/.system/skill-installer");
        assert_eq!(
            bundled.activation,
            Activation::Inactive(InactiveReason::Disabled)
        );
        assert_eq!(
            bundled.provenance,
            Provenance::AgentWritten,
            "Codex rewrites the bundled skills from the copy in its binary"
        );
    }

    /// The instruction file Codex reads is the first non-empty one, and the
    /// one it shadows is written down rather than left out.
    #[test]
    fn an_instruction_file_shadowed_by_an_override_is_inactive() {
        let machine = Machine::new("instructions");
        machine.write("project/AGENTS.override.md", "# Override\n");
        machine.write("project/AGENTS.md", "# Shadowed\n");

        let enumeration = machine.enumerate();
        assert_eq!(
            found(&enumeration, "instruction-file/AGENTS.override.md").activation,
            Activation::Active
        );
        assert_eq!(
            found(&enumeration, "instruction-file/AGENTS.md").activation,
            Activation::Inactive(InactiveReason::Disabled)
        );
    }

    /// The `default.rules` file the interface appends to is the Agent's own
    /// writing, which is what keeps it out of Drift.
    #[test]
    fn the_execution_policy_the_agent_writes_itself_says_so() {
        let machine = Machine::new("rules");
        machine.write(
            "home/.codex/rules/default.rules",
            "prefix_rule(pattern=[\"git\", \"status\"], decision=\"allow\")\n",
        );
        machine.write(
            "home/.codex/rules/mine.rules",
            "prefix_rule(pattern=[\"ls\"], decision=\"allow\")\n",
        );

        let enumeration = machine.enumerate();
        assert_eq!(
            found(&enumeration, "exec-policy/~/.codex/rules/default.rules").provenance,
            Provenance::AgentWritten
        );
        assert_eq!(
            found(&enumeration, "exec-policy/~/.codex/rules/mine.rules").provenance,
            Provenance::Manual
        );
    }

    /// A config layer that cannot be parsed is a Problem rather than silence:
    /// Codex would have read it and AgentSweep cannot say what is in it.
    #[test]
    fn a_config_layer_that_cannot_be_parsed_travels_as_a_problem() {
        let machine = Machine::new("broken");
        machine.write("home/.codex/config.toml", "approval_policy = \n");

        let enumeration = machine.enumerate();
        assert_eq!(enumeration.problems.len(), 1, "{:?}", enumeration.problems);
        assert_eq!(enumeration.problems[0].reason, ProblemReason::Unparseable);
        assert_eq!(enumeration.problems[0].surface, "~/.codex/config.toml");
    }

    /// A profile layer is a file beside the user config, and the config file
    /// itself is not one of them.
    #[test]
    fn a_profile_layer_is_read_and_the_user_layer_is_not_read_twice() {
        let machine = Machine::new("profiles");
        machine.write(
            "home/.codex/config.toml",
            "approval_policy = \"on-request\"\n",
        );
        machine.write(
            "home/.codex/work.config.toml",
            "sandbox_mode = \"read-only\"\n",
        );

        let enumeration = machine.enumerate();
        assert_eq!(
            found(&enumeration, "~/.codex/work.config.toml#/sandbox_mode")
                .view
                .name(),
            "settings"
        );
        assert_eq!(
            enumeration
                .items
                .iter()
                .filter(|item| item.id.as_str().ends_with("config.toml#/approval_policy"))
                .count(),
            1
        );
    }

    /// The contract's own checks, on an enumeration built here rather than on
    /// a fixture tree.
    #[test]
    fn a_planted_machine_satisfies_the_watch_root_and_view_contract() {
        let machine = Machine::new("contract");
        machine.write("home/.codex/config.toml", "approval_policy = \"never\"\n");
        machine.write("home/.codex/hooks.json", hooks_file());
        machine.write("home/.codex/skills/demo/SKILL.md", "---\nname: demo\n---\n");
        machine.write("project/AGENTS.md", "# Notes\n");

        let enumeration = machine.enumerate();
        let adapter = Codex::new();
        let roots = adapter.watch_roots(&enumeration);
        for item in &enumeration.items {
            assert!(
                roots.covers(&item.path),
                "{} is watched by no root",
                item.id
            );
            assert!(
                adapter
                    .items_for_path(&enumeration, &item.path)
                    .contains(&item.id),
                "{} does not map back from its own path",
                item.id
            );
        }
        assert!(
            roots.recursive.contains(&machine.home().join(".codex")),
            "{roots:?}"
        );
    }

    /// A home that is also a pooled project root is the user layer under
    /// another name, and Codex skips the coinciding project layer rather than
    /// loading it twice.
    #[test]
    fn a_project_root_whose_codex_directory_is_the_config_directory_is_read_once() {
        let machine = Machine::new("coinciding");
        machine.write("home/.codex/config.toml", "approval_policy = \"never\"\n");

        let host = Host::new(machine.home(), vec![machine.home(), machine.project()]);
        let enumeration = Codex::new().enumerate(&host, host.project_roots());
        assert_eq!(
            enumeration
                .items
                .iter()
                .filter(|item| item.id.as_str().ends_with("config.toml#/approval_policy"))
                .count(),
            1,
            "{:?}",
            enumeration
                .items
                .iter()
                .map(|item| item.id.to_string())
                .collect::<Vec<_>>()
        );
    }

    /// A changed hook script maps back to the hook that runs it, so editing
    /// what a hook calls re-scans the hook.
    #[test]
    fn a_changed_script_maps_back_to_the_hook_that_runs_it() {
        let machine = Machine::new("script");
        machine.write("home/.codex/hooks.json", hooks_file());
        let script = machine.write("home/.codex/start.sh", "#!/bin/sh\necho nothing\n");

        let enumeration = machine.enumerate();
        let mapped = Codex::new().items_for_path(&enumeration, &script);
        assert_eq!(mapped.len(), 1, "{mapped:?}");
        assert!(mapped[0].as_str().contains("SessionStart"));
    }
}
