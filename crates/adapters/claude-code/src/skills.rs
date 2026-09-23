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
use agentsweep_core::item::{Item, Kind, TreeCaps};
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
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let contents = tree::contents_of(host, &path);
        if contents.join(PLUGIN_MANIFEST).is_file() {
            let id = format!("{name}@{SKILLS_DIRECTORY_MARKETPLACE}");
            let plugin = tree::read(host, caps, placement, Kind::Plugin, &path);
            let view = plugin_view(&plugin, &id);
            tree::yielded(host, enumeration, plugin.with_view(view));
            continue;
        }
        if !contents.join(SKILL_FILE).is_file() {
            continue;
        }
        let item = tree::read(host, caps, placement, Kind::Skill, &path);
        let view = SkillView::of(&name, item.tree.content_of(SKILL_FILE));
        tree::yielded(host, enumeration, item.with_view(ParsedView::Skill(view)));
    }
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
