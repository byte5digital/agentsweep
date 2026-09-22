//! The view globals a Rule sees.
//!
//! This module is the Rust side of the struct-global schema in
//! `rules/README.md` ("What a rule sees") and of ADR 0004. Before each scan the
//! core defines one global per view kind plus the common `item` global, always
//! with the full schema. Fields that are not meaningful for the Item's kind
//! hold defaults: strings `""`, booleans `false`, integers `0`. Every array
//! holds at least one element, because YARA-X rejects an empty array, and a
//! sibling `<name>_n` carries the real count.
//!
//! [`Views::schema`] and [`Views::globals`] come out of the same code, so the
//! shape the Compiler fixes and the shape the Scanner sets can never drift
//! apart. Only the `item` global is populated in this slice; every other view
//! is defined with its defaults so that every Rule in the corpus compiles.

use serde_json::{Map, Value, json};

use crate::item::{Item, ScanUnit};

/// The names of the globals, in the order the core defines them.
pub const GLOBAL_NAMES: [&str; 10] = [
    "item",
    "mcp",
    "hook",
    "settings",
    "skill",
    "plugin",
    "marketplace",
    "subagent",
    "env",
    "repo",
];

/// Renders a list of strings as an array a Rule can iterate: never empty, and
/// the real count travels beside it in the sibling `_n` field.
fn strings(values: &[String]) -> Value {
    if values.is_empty() {
        json!([""])
    } else {
        Value::Array(values.iter().map(|v| Value::String(v.clone())).collect())
    }
}

/// Renders a list of structs the same way, falling back to one all-default
/// struct when the list is empty.
fn structs(values: Vec<Value>, empty: Value) -> Value {
    if values.is_empty() {
        Value::Array(vec![empty])
    } else {
        Value::Array(values)
    }
}

/// The common `item` global: the facts every Rule may read, whatever the kind.
#[derive(Clone, Debug, Default)]
pub struct ItemView {
    /// The Agent whose Surface Adapter yielded the Item.
    pub agent: String,
    /// The Surface kind, in the spelling the `kinds` meta uses.
    pub kind: String,
    /// `file`, `tree` or `entry`.
    pub shape: String,
    /// `managed`, `user` or `project`.
    pub scope: String,
    /// The project root, empty outside Project Scope.
    pub project_root: String,
    /// Where the Item sits on disk.
    pub path: String,
    /// How the Item got onto the Surface.
    pub provenance: String,
    /// The marketplace ref, plugin id or commit behind the Provenance.
    pub provenance_ref: String,
    /// `active`, `inactive` or `unknown`.
    pub activation: String,
    /// Why the Item is inactive, empty otherwise.
    pub activation_reason: String,
    /// False when the Item sits in a root its own Agent does not know.
    pub registered: bool,
    /// The size of the content in bytes.
    pub size: i64,
    /// True when the Surface entry is a symbolic link.
    pub is_symlink: bool,
    /// `unchanged`, `changed`, `added` or `none`.
    pub baseline: String,
    /// True when the Provenance is an official marketplace.
    pub provenance_official: bool,
    /// The resolved link target, empty when the Item is not a link.
    pub link_target: String,
    /// `text`, `executable`, `binary`, `archive`, `office`, `bytecode`,
    /// `image` or `unknown`.
    pub file_type: String,
    /// True when the content carries right-to-left script.
    pub has_rtl_script: bool,
    /// The share of whitespace in the content, in whole percent.
    pub whitespace_percent: i64,
    /// The longest run of consecutive blank lines.
    pub max_blank_run: i64,
    /// The relative path within a tree, set per file scanned.
    pub file: String,
}

impl ItemView {
    /// Builds the view from an Item and the unit being scanned.
    pub fn of(item: &Item, unit: &ScanUnit<'_>) -> ItemView {
        ItemView {
            agent: item.agent.clone(),
            kind: item.kind.as_str().to_string(),
            shape: item.shape.as_str().to_string(),
            scope: item.scope.as_str().to_string(),
            project_root: item
                .scope
                .root()
                .map(|root| root.display().to_string())
                .unwrap_or_default(),
            path: item.path.display().to_string(),
            provenance: item.provenance.as_str().to_string(),
            provenance_ref: item.provenance.reference().to_string(),
            activation: item.activation.as_str().to_string(),
            activation_reason: item.activation.reason().to_string(),
            registered: item.registered,
            size: item.size as i64,
            is_symlink: item.is_symlink,
            baseline: item.baseline.as_str().to_string(),
            provenance_official: item.provenance.is_official(),
            link_target: item.link_target.clone(),
            file_type: item.facts.file_type.as_str().to_string(),
            has_rtl_script: item.facts.has_rtl_script,
            whitespace_percent: item.facts.whitespace_percent,
            max_blank_run: item.facts.max_blank_run,
            file: unit.file.to_string(),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "agent": self.agent,
            "kind": self.kind,
            "shape": self.shape,
            "scope": self.scope,
            "project_root": self.project_root,
            "path": self.path,
            "provenance": self.provenance,
            "provenance_ref": self.provenance_ref,
            "activation": self.activation,
            "activation_reason": self.activation_reason,
            "registered": self.registered,
            "size": self.size,
            "is_symlink": self.is_symlink,
            "baseline": self.baseline,
            "provenance_official": self.provenance_official,
            "link_target": self.link_target,
            "file_type": self.file_type,
            "has_rtl_script": self.has_rtl_script,
            "whitespace_percent": self.whitespace_percent,
            "max_blank_run": self.max_blank_run,
            "file": self.file,
        })
    }
}

/// The `mcp` view: one MCP server entry.
#[derive(Clone, Debug, Default)]
pub struct McpView {
    /// The server name.
    pub name: String,
    /// `stdio`, `http` or `sse`.
    pub transport: String,
    /// The launch command as written.
    pub command: String,
    /// The command as the Surface Adapter resolved it.
    pub command_resolved: String,
    /// The resolved command sits in a temporary directory.
    pub command_in_temp: bool,
    /// The resolved command sits in the downloads directory.
    pub command_in_downloads: bool,
    /// The resolved command sits under a dot-directory of the home that is not
    /// a known tool manager.
    pub command_in_unknown_hidden_home: bool,
    /// The resolved command is world-writable.
    pub command_world_writable: bool,
    /// The launch arguments.
    pub args: Vec<String>,
    /// The real number of arguments.
    pub args_n: i64,
    /// The package the command installs or runs.
    pub package: String,
    /// The pinned package version, empty when unpinned.
    pub package_version: String,
    /// The endpoint for a remote transport.
    pub url: String,
    /// The host of that endpoint.
    pub url_host: String,
    /// The keys of the entry's env block; the values are sensitive.
    pub env_keys: Vec<String>,
    /// The real number of env keys.
    pub env_keys_n: i64,
    /// The keys of the entry's header block; the values are sensitive.
    pub header_keys: Vec<String>,
    /// The real number of header keys.
    pub header_keys_n: i64,
    /// True when an Authorization header carries a literal value.
    pub has_literal_authorization: bool,
}

impl McpView {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "command_resolved": self.command_resolved,
            "command_in_temp": self.command_in_temp,
            "command_in_downloads": self.command_in_downloads,
            "command_in_unknown_hidden_home": self.command_in_unknown_hidden_home,
            "command_world_writable": self.command_world_writable,
            "args": strings(&self.args),
            "args_n": self.args_n,
            "package": self.package,
            "package_version": self.package_version,
            "url": self.url,
            "url_host": self.url_host,
            "env_keys": strings(&self.env_keys),
            "env_keys_n": self.env_keys_n,
            "header_keys": strings(&self.header_keys),
            "header_keys_n": self.header_keys_n,
            "has_literal_authorization": self.has_literal_authorization,
        })
    }
}

/// The `hook` view: one hook handler entry.
#[derive(Clone, Debug, Default)]
pub struct HookView {
    /// The event the handler is registered for.
    pub event: String,
    /// The matcher the handler is registered under.
    pub matcher: String,
    /// The handler type.
    pub handler_type: String,
    /// The command as written.
    pub command: String,
    /// The command as the Surface Adapter resolved it.
    pub command_resolved: String,
    /// The file type of the resolved command.
    pub command_file_type: String,
    /// The endpoint a non-command handler posts to.
    pub url: String,
}

impl HookView {
    fn to_value(&self) -> Value {
        json!({
            "event": self.event,
            "matcher": self.matcher,
            "type": self.handler_type,
            "command": self.command,
            "command_resolved": self.command_resolved,
            "command_file_type": self.command_file_type,
            "url": self.url,
        })
    }
}

/// The `settings` view: one settings key.
#[derive(Clone, Debug, Default)]
pub struct SettingsView {
    /// The dotted key path, an array index written as `.N`.
    pub key_path: String,
    /// The value in string form.
    pub value: String,
    /// The host of the value when it is a URL.
    pub value_host: String,
    /// True when the Agent holds session history for the project a trust entry
    /// names.
    pub trust_has_sessions: bool,
}

impl SettingsView {
    fn to_value(&self) -> Value {
        json!({
            "key_path": self.key_path,
            "value": self.value,
            "value_host": self.value_host,
            "trust_has_sessions": self.trust_has_sessions,
        })
    }
}

/// The `skill` view: one skill directory.
#[derive(Clone, Debug, Default)]
pub struct SkillView {
    /// The skill name.
    pub name: String,
    /// The tools the skill declares.
    pub allowed_tools: Vec<String>,
    /// The real number of declared tools.
    pub allowed_tools_n: i64,
    /// True when the skill pulls context in at load time.
    pub has_dynamic_context: bool,
}

impl SkillView {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "allowed_tools": strings(&self.allowed_tools),
            "allowed_tools_n": self.allowed_tools_n,
            "has_dynamic_context": self.has_dynamic_context,
        })
    }
}

/// The `plugin` view: one installed plugin version.
#[derive(Clone, Debug, Default)]
pub struct PluginView {
    /// The plugin name.
    pub name: String,
    /// The edit distance to the nearest reserved marketplace name.
    pub name_reserved_distance: i64,
    /// The executables the plugin ships in its `bin` directory.
    pub bin_names: Vec<String>,
    /// The real number of those executables.
    pub bin_names_n: i64,
    /// True when the plugin declares monitors.
    pub has_monitors: bool,
}

impl PluginView {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "name_reserved_distance": self.name_reserved_distance,
            "bin_names": strings(&self.bin_names),
            "bin_names_n": self.bin_names_n,
            "has_monitors": self.has_monitors,
        })
    }
}

/// One entry of a marketplace listing.
#[derive(Clone, Debug, Default)]
pub struct MarketplaceEntry {
    /// The entry name.
    pub name: String,
    /// `github`, `git`, `url`, `command` or `local`.
    pub source_kind: String,
    /// The host the source points at.
    pub source_host: String,
    /// True when the entry pins a ref.
    pub pinned: bool,
    /// True when the entry declares a headers helper.
    pub has_headers_helper: bool,
}

impl MarketplaceEntry {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "source_kind": self.source_kind,
            "source_host": self.source_host,
            "pinned": self.pinned,
            "has_headers_helper": self.has_headers_helper,
        })
    }
}

/// The `marketplace` view: one marketplace clone.
#[derive(Clone, Debug, Default)]
pub struct MarketplaceView {
    /// The marketplace name.
    pub name: String,
    /// The owner the marketplace declares.
    pub owner: String,
    /// The edit distance to the nearest reserved marketplace name.
    pub name_reserved_distance: i64,
    /// The plugins the marketplace lists.
    pub entries: Vec<MarketplaceEntry>,
    /// The real number of listed plugins.
    pub entries_n: i64,
}

impl MarketplaceView {
    fn to_value(&self) -> Value {
        let entries = self
            .entries
            .iter()
            .map(MarketplaceEntry::to_value)
            .collect();
        json!({
            "name": self.name,
            "owner": self.owner,
            "name_reserved_distance": self.name_reserved_distance,
            "entries": structs(entries, MarketplaceEntry::default().to_value()),
            "entries_n": self.entries_n,
        })
    }
}

/// The `subagent` view: one subagent definition.
#[derive(Clone, Debug, Default)]
pub struct SubagentView {
    /// The subagent name.
    pub name: String,
    /// The permission mode the definition declares.
    pub permission_mode: String,
}

impl SubagentView {
    fn to_value(&self) -> Value {
        json!({
            "name": self.name,
            "permission_mode": self.permission_mode,
        })
    }
}

/// The `env` view: one env file. The values are sensitive and reach Rules only
/// as the bytes under scan.
#[derive(Clone, Debug, Default)]
pub struct EnvView {
    /// The keys the file sets.
    pub keys: Vec<String>,
    /// The real number of keys.
    pub keys_n: i64,
}

impl EnvView {
    /// The view of an env file that sets these keys. The count travels with
    /// the list so the two can never drift apart. The values are never here:
    /// marking them sensitive means the parsed view holds the key names only,
    /// and the bytes a Rule matches on stay local.
    pub fn of(keys: Vec<String>) -> EnvView {
        EnvView {
            keys_n: keys.len() as i64,
            keys,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "keys": strings(&self.keys),
            "keys_n": self.keys_n,
        })
    }
}

/// One exec-capable key of a repository's git configuration.
#[derive(Clone, Debug, Default)]
pub struct RepoExecKey {
    /// The dotted key.
    pub key: String,
    /// The value in string form.
    pub value: String,
    /// True when the value resolves outside the repository.
    pub value_outside_repo: bool,
}

impl RepoExecKey {
    fn to_value(&self) -> Value {
        json!({
            "key": self.key,
            "value": self.value,
            "value_outside_repo": self.value_outside_repo,
        })
    }
}

/// The `repo` view: the git files an Agent executes before trust.
#[derive(Clone, Debug, Default)]
pub struct RepoView {
    /// The exec-capable keys of the repository's git configuration.
    pub exec_keys: Vec<RepoExecKey>,
    /// The real number of those keys.
    pub exec_keys_n: i64,
    /// True when the gitdir pointer resolves outside the repository.
    pub gitdir_outside_repo: bool,
    /// True when the worktree commondir resolves outside the repository.
    pub commondir_outside_repo: bool,
    /// The non-sample executables in the hooks directory.
    pub hook_executables: Vec<String>,
    /// The real number of those executables.
    pub hook_executables_n: i64,
}

impl RepoView {
    /// The view of one exec-capable git configuration key.
    pub fn of_exec_key(key: RepoExecKey) -> RepoView {
        RepoView {
            exec_keys: vec![key],
            exec_keys_n: 1,
            ..RepoView::default()
        }
    }

    /// The view of the non-sample executables in a repository's hooks
    /// directory. Every hook Item of one repository names them all, so a Rule
    /// can see what company a hook keeps.
    pub fn of_hook_executables(names: Vec<String>) -> RepoView {
        RepoView {
            hook_executables_n: names.len() as i64,
            hook_executables: names,
            ..RepoView::default()
        }
    }

    fn to_value(&self) -> Value {
        let exec_keys = self.exec_keys.iter().map(RepoExecKey::to_value).collect();
        json!({
            "exec_keys": structs(exec_keys, RepoExecKey::default().to_value()),
            "exec_keys_n": self.exec_keys_n,
            "gitdir_outside_repo": self.gitdir_outside_repo,
            "commondir_outside_repo": self.commondir_outside_repo,
            "hook_executables": strings(&self.hook_executables),
            "hook_executables_n": self.hook_executables_n,
        })
    }
}

/// The parsed view a Surface Adapter attached to one Item.
///
/// The kind decides which one: Repository Metadata carries `repo`, an env file
/// carries `env`, and Execution Policies, Workflows, instruction files and
/// Generic Items carry none, because Rules on them are byte Rules. A view is
/// computed by the adapter and never by a Rule.
#[derive(Clone, Debug, Default)]
pub enum ParsedView {
    /// The Item's kind has no view, or its adapter has not parsed it yet.
    #[default]
    None,
    /// One MCP server entry.
    Mcp(McpView),
    /// One hook handler entry.
    Hook(HookView),
    /// One settings key.
    Settings(SettingsView),
    /// One skill directory.
    Skill(SkillView),
    /// One installed plugin version.
    Plugin(PluginView),
    /// One marketplace clone.
    Marketplace(MarketplaceView),
    /// One subagent definition.
    Subagent(SubagentView),
    /// One env file.
    Env(EnvView),
    /// The git files an Agent executes before trust.
    Repo(RepoView),
}

impl ParsedView {
    /// The name of the global this view populates, empty when there is none.
    pub fn name(&self) -> &'static str {
        match self {
            ParsedView::None => "",
            ParsedView::Mcp(_) => "mcp",
            ParsedView::Hook(_) => "hook",
            ParsedView::Settings(_) => "settings",
            ParsedView::Skill(_) => "skill",
            ParsedView::Plugin(_) => "plugin",
            ParsedView::Marketplace(_) => "marketplace",
            ParsedView::Subagent(_) => "subagent",
            ParsedView::Env(_) => "env",
            ParsedView::Repo(_) => "repo",
        }
    }
}

/// Every global a Rule sees, in one value.
#[derive(Clone, Debug, Default)]
pub struct Views {
    /// The common view.
    pub item: ItemView,
    /// The MCP server view.
    pub mcp: McpView,
    /// The hook handler view.
    pub hook: HookView,
    /// The settings key view.
    pub settings: SettingsView,
    /// The skill view.
    pub skill: SkillView,
    /// The plugin view.
    pub plugin: PluginView,
    /// The marketplace view.
    pub marketplace: MarketplaceView,
    /// The subagent view.
    pub subagent: SubagentView,
    /// The env file view.
    pub env: EnvView,
    /// The repository metadata view.
    pub repo: RepoView,
}

impl Views {
    /// The views for one unit of one Item: the common `item` global, plus the
    /// parsed view the Surface Adapter attached when the Item's kind has one.
    /// Every other global keeps its documented defaults.
    pub fn of(item: &Item, unit: &ScanUnit<'_>) -> Views {
        let mut views = Views {
            item: ItemView::of(item, unit),
            ..Views::default()
        };
        match &item.view {
            ParsedView::None => {}
            ParsedView::Mcp(view) => views.mcp = view.clone(),
            ParsedView::Hook(view) => views.hook = view.clone(),
            ParsedView::Settings(view) => views.settings = view.clone(),
            ParsedView::Skill(view) => views.skill = view.clone(),
            ParsedView::Plugin(view) => views.plugin = view.clone(),
            ParsedView::Marketplace(view) => views.marketplace = view.clone(),
            ParsedView::Subagent(view) => views.subagent = view.clone(),
            ParsedView::Env(view) => views.env = view.clone(),
            ParsedView::Repo(view) => views.repo = view.clone(),
        }
        views
    }

    /// What is wrong with these views, empty when nothing is.
    ///
    /// Two invariants hold whatever an adapter attached: the shape of every
    /// global is the schema's, because YARA-X fixes a global's type when it
    /// compiles the pack, and every `<name>_n` carries the real count of its
    /// list, because the rendered list is padded to one element when the real
    /// count is zero. The conformance suite runs this over every Item of every
    /// adapter.
    pub fn validate(&self) -> Vec<String> {
        let mut violations = Vec::new();
        for ((name, schema), (_, value)) in Views::schema().iter().zip(self.globals()) {
            if shape_of(schema) != shape_of(&value) {
                violations.push(format!(
                    "the shape of `{name}` is not the schema's: {} instead of {}",
                    shape_of(&value),
                    shape_of(schema)
                ));
                continue;
            }
            let Some(fields) = value.as_object() else {
                continue;
            };
            for (field, value) in fields {
                let Some(rendered) = value.as_array() else {
                    continue;
                };
                let count = fields
                    .get(&format!("{field}_n"))
                    .and_then(Value::as_i64)
                    .unwrap_or(-1);
                let real = if count == 0 { 1 } else { count };
                if real != rendered.len() as i64 {
                    violations.push(format!(
                        "`{name}.{field}` holds {} elements and `{field}_n` says {count}",
                        rendered.len()
                    ));
                }
            }
        }
        violations
    }

    /// Every global with its name, ready to be handed to YARA-X.
    pub fn globals(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("item", self.item.to_value()),
            ("mcp", self.mcp.to_value()),
            ("hook", self.hook.to_value()),
            ("settings", self.settings.to_value()),
            ("skill", self.skill.to_value()),
            ("plugin", self.plugin.to_value()),
            ("marketplace", self.marketplace.to_value()),
            ("subagent", self.subagent.to_value()),
            ("env", self.env.to_value()),
            ("repo", self.repo.to_value()),
        ]
    }

    /// The full schema with every documented default. The Compiler fixes the
    /// shape of the globals from this, and because [`Views::globals`] builds
    /// the same values the Scanner can always set them afterwards.
    pub fn schema() -> Vec<(&'static str, Value)> {
        Views::default().globals()
    }
}

/// Reads a field out of a rendered view, for tests and for the corpus runner.
pub fn field<'v>(view: &'v Value, name: &str) -> Option<&'v Value> {
    view.as_object()
        .and_then(|object: &Map<String, Value>| object.get(name))
}

/// The type shape of a rendered value, ignoring the values themselves. YARA-X
/// fixes a global's type when it compiles the pack, so this is what may not
/// change between the schema and a populated view.
pub fn shape_of(value: &Value) -> String {
    match value {
        Value::String(_) => "string".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Number(_) => "integer".to_string(),
        Value::Array(items) => format!("[{}]", shape_of(&items[0])),
        Value::Object(fields) => {
            let mut parts: Vec<String> = fields
                .iter()
                .map(|(name, value)| format!("{name}:{}", shape_of(value)))
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
        Value::Null => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_defines_every_global_of_the_rule_contract() {
        let names: Vec<&str> = Views::schema().iter().map(|(name, _)| *name).collect();
        assert_eq!(names, GLOBAL_NAMES);
    }

    #[test]
    fn the_schema_and_a_populated_view_have_the_same_shape() {
        let item = crate::item::Item::file(
            "claude-code",
            crate::item::Scope::User,
            crate::item::Kind::InstructionFile,
            "CLAUDE.md",
            std::path::PathBuf::from("/home/CLAUDE.md"),
            crate::item::Provenance::Manual,
            crate::item::Activation::Active,
            b"# demo\n".to_vec(),
        );
        let units = item.scan_units();
        let populated = Views::of(&item, &units[0]).globals();
        for ((schema_name, schema), (name, value)) in Views::schema().iter().zip(populated.iter()) {
            assert_eq!(schema_name, name);
            assert_eq!(
                shape_of(schema),
                shape_of(value),
                "the shape of `{name}` drifted from the schema"
            );
        }
    }

    #[test]
    fn no_array_is_ever_empty_and_every_one_has_a_count() {
        for (name, value) in Views::schema() {
            let object = value.as_object().expect("a view is an object");
            for (field, value) in object {
                if let Some(items) = value.as_array() {
                    assert!(!items.is_empty(), "`{name}.{field}` is empty");
                    assert!(
                        object.contains_key(&format!("{field}_n")),
                        "`{name}.{field}` has no sibling count"
                    );
                }
            }
        }
    }

    #[test]
    fn strings_default_to_empty_booleans_to_false_and_integers_to_zero() {
        for (_, value) in Views::schema() {
            for (_, value) in value.as_object().expect("a view is an object") {
                match value {
                    Value::String(text) => assert!(text.is_empty()),
                    Value::Bool(flag) => assert!(!flag),
                    Value::Number(number) => assert_eq!(number.as_i64(), Some(0)),
                    Value::Array(_) => {}
                    other => panic!("a view field may not be {other}"),
                }
            }
        }
    }

    #[test]
    fn an_empty_list_still_renders_one_element() {
        assert_eq!(strings(&[]), json!([""]));
        assert_eq!(strings(&["a".to_string()]), json!(["a"]));
    }

    /// A view an adapter attached reaches the Rule that reads it, and the
    /// count of a list it carries is the list's real length.
    #[test]
    fn an_attached_view_reaches_its_global_and_validates() {
        let mut item = crate::item::Item::file(
            "workspace",
            crate::item::Scope::Project(std::path::PathBuf::from("/src/demo")),
            crate::item::Kind::EnvFile,
            ".env",
            std::path::PathBuf::from("/src/demo/.env"),
            crate::item::Provenance::Unknown,
            crate::item::Activation::Unknown,
            b"CODEX_HOME=./.codex\n".to_vec(),
        );
        item.view = ParsedView::Env(EnvView::of(vec!["CODEX_HOME".to_string()]));

        let units = item.scan_units();
        let views = Views::of(&item, &units[0]);

        assert_eq!(views.env.keys, ["CODEX_HOME"]);
        assert_eq!(views.env.keys_n, 1);
        assert!(views.validate().is_empty(), "{:?}", views.validate());
    }

    #[test]
    fn a_count_that_does_not_match_its_list_is_a_violation() {
        let views = Views {
            env: EnvView {
                keys: vec!["A".to_string(), "B".to_string()],
                keys_n: 1,
            },
            ..Views::default()
        };
        let violations = views.validate();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("env.keys"), "{violations:?}");
    }

    #[test]
    fn the_defaults_of_every_view_validate() {
        assert!(Views::default().validate().is_empty());
    }
}
