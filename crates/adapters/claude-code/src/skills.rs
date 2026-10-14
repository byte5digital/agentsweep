//! Skills, and the command files that load the same way.
//!
//! A skill is a directory with a `SKILL.md` in it: the body is injected as a
//! user message, the inline `` !` `` spans and the fenced `!` blocks run before
//! it is sent, and everything else in the folder is there to be run by it. So
//! the Item is the whole tree and not the one Markdown file.
//!
//! A folder of the skills directory that carries a plugin manifest is not a
//! skill at all: Claude Code loads it as a plugin named `<name>@skills-dir`,
//! with hooks, MCP servers and agents of its own and no install record
//! anywhere (`docs/research/claude-code-surfaces.md`). It is yielded as the
//! Plugin it is.
//!
//! A legacy command file is one Markdown file with the same frontmatter and
//! the same injection, which is why it is a Skill Item of file shape and
//! carries the `skill` view (Rule 0012 names skills and commands together).

use std::path::Path;

use agentsweep_core::adapter::Enumeration;
use agentsweep_core::host::Host;
use agentsweep_core::item::{Invocation, Item, Kind, TreeCaps};
use agentsweep_core::views::{MarketplaceView, ParsedView, PluginView, SkillView};
use serde_json::Value;

use crate::tree::{self, Placement};

/// The file a skill directory has to hold to be one.
pub const SKILL_FILE: &str = "SKILL.md";

/// The manifest that turns a folder of the skills directory into a plugin.
pub const PLUGIN_MANIFEST: &str = ".claude-plugin/plugin.json";

/// The manifest of a marketplace clone.
pub const MARKETPLACE_MANIFEST: &str = ".claude-plugin/marketplace.json";

/// The marketplace name Claude Code gives a plugin it found in the skills
/// directory, where nothing was installed and nothing recorded it.
pub const SKILLS_DIRECTORY_MARKETPLACE: &str = "skills-dir";

/// The folder name Claude Code reserves in the skills directory for what it
/// syncs from the web app. Inside it is one folder per account, and the skills
/// are one level below that, so they are reached two levels down rather than
/// one (`docs/research/claude-code-surfaces.md`).
pub const SYNCED_DIRECTORY: &str = "synced";

/// Every skill one skills directory holds.
///
/// An entry that is a symbolic link is followed one level: the Item keeps the
/// link's location as its identity and records the target it read (spec
/// section 3.3). A folder without a `SKILL.md` and without a plugin manifest is
/// not listed by Claude Code and is not an Item either.
pub fn skills_in(
    host: &Host,
    caps: TreeCaps,
    placement: &Placement,
    directory: &Path,
    enumeration: &mut Enumeration,
) {
    for path in tree::directories_in(host, directory) {
        if path
            .file_name()
            .is_some_and(|name| name == SYNCED_DIRECTORY)
        {
            for account in tree::directories_in(host, &path) {
                for synced in tree::directories_in(host, &account) {
                    skill_at(host, caps, placement, &synced, enumeration);
                }
            }
            continue;
        }
        skill_at(host, caps, placement, &path, enumeration);
    }
}

/// One folder of a skills directory, as the Item Claude Code would load from
/// it: a skill, or the plugin a folder with a plugin manifest really is.
fn skill_at(
    host: &Host,
    caps: TreeCaps,
    placement: &Placement,
    path: &Path,
    enumeration: &mut Enumeration,
) {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let contents = tree::contents_of(host, path);
    if contents.join(PLUGIN_MANIFEST).is_file() {
        let id = format!("{name}@{SKILLS_DIRECTORY_MARKETPLACE}");
        let plugin = tree::read(host, caps, placement, Kind::Plugin, path);
        let view = plugin_view(&plugin, &id);
        let plugin = invoked_through(plugin, &name);
        tree::yielded(host, enumeration, plugin.with_view(view));
        return;
    }
    if !contents.join(SKILL_FILE).is_file() {
        return;
    }
    let item = tree::read(host, caps, placement, Kind::Skill, path);
    let view = SkillView::of(&name, item.tree.content_of(SKILL_FILE));
    let item = item.invoked_as(Invocation::skill(view.name.clone()));
    tree::yielded(host, enumeration, item.with_view(ParsedView::Skill(view)));
}

/// Every legacy command file one commands directory holds, nested ones
/// included: Claude Code reaches a nested command as `/dir:name`.
pub fn commands_in(
    host: &Host,
    placement: &Placement,
    directory: &Path,
    enumeration: &mut Enumeration,
) {
    for path in tree::files_in(host, directory, &[".md"], true) {
        let Some(result) = tree::file(host, placement, Kind::Skill, &path) else {
            continue;
        };
        match result {
            Ok(item) => {
                let name = path.file_stem().unwrap_or_default().to_string_lossy();
                let view = SkillView::of(&name, &item.content);
                let item = item.invoked_as(Invocation::skill(view.name.clone()));
                enumeration
                    .items
                    .push(item.with_view(ParsedView::Skill(view)));
            }
            Err(problem) => enumeration.problems.push(problem),
        }
    }
}

/// The `plugin` view of one plugin tree: what its manifest declares, what it
/// ships in `bin` and whether it runs monitors in the background.
pub fn plugin_view(item: &Item, id: &str) -> ParsedView {
    let manifest = manifest_of(item, PLUGIN_MANIFEST);
    let mut view = PluginView::of(id, &manifest, item.tree.names_in("bin"));
    view.has_monitors |= item.tree.holds("monitors/monitors.json");
    ParsedView::Plugin(view)
}

/// The directory of a plugin tree its skills sit in, one folder each.
const PLUGIN_SKILLS: &str = "skills";

/// The directory of a plugin tree its command files sit in.
const PLUGIN_COMMANDS: &str = "commands";

/// The file a plugin tree declares its MCP servers in.
const PLUGIN_SERVERS: &str = ".mcp.json";

/// One plugin tree with the names Claude Code invokes what it brings by:
/// every skill and command as `<plugin>:<name>`, and every MCP server as
/// `plugin:<plugin>:<server>` with the source class `plugin`
/// (`docs/research/claude-code-surfaces.md`).
pub fn invoked_through(mut item: Item, plugin: &str) -> Item {
    let mut skills: Vec<String> = Vec::new();
    for file in &item.tree.files {
        let parts: Vec<&str> = file.path.split('/').collect();
        match parts.as_slice() {
            [PLUGIN_SKILLS, folder, SKILL_FILE] => {
                skills.push(SkillView::of(folder, &file.content).name);
            }
            [PLUGIN_COMMANDS, name] if name.ends_with(".md") => {
                let stem = name.trim_end_matches(".md");
                skills.push(SkillView::of(stem, &file.content).name);
            }
            _ => {}
        }
    }
    skills.sort();
    for skill in skills {
        item = item.invoked_as(Invocation::skill(format!("{plugin}:{skill}")));
    }
    let servers = manifest_of(&item, PLUGIN_SERVERS);
    if let Some(servers) = servers.get("mcpServers").and_then(Value::as_object) {
        let names: Vec<String> = servers.keys().cloned().collect();
        for server in names {
            item = item.invoked_as(Invocation::mcp_server(
                plugin_server_name(plugin, &server),
                SOURCE_PLUGIN,
            ));
        }
    }
    item
}

/// The source class Claude Code reports for a plugin's MCP server.
pub const SOURCE_PLUGIN: &str = "plugin";

/// The name Claude Code registers one plugin's MCP server under.
pub fn plugin_server_name(plugin: &str, server: &str) -> String {
    format!("plugin:{plugin}:{server}")
}

/// The `marketplace` view of one marketplace clone.
pub fn marketplace_view(item: &Item, name: &str) -> ParsedView {
    let manifest = manifest_of(item, MARKETPLACE_MANIFEST);
    ParsedView::Marketplace(MarketplaceView::of(name, &manifest))
}

/// One manifest inside a tree, parsed. A manifest that is not there or cannot
/// be parsed yields an empty one: the view then holds what the tree itself
/// says, and the bytes of the file still reach every Tier.
fn manifest_of(item: &Item, relative: &str) -> Value {
    serde_json::from_slice(item.tree.content_of(relative)).unwrap_or(Value::Null)
}
