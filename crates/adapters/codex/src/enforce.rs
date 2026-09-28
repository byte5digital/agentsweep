//! What one Quarantine does to a Codex Surface.
//!
//! Every entry this Agent yields sits in a file it shares: an MCP server and a
//! config key in a TOML config layer, a hook handler either in `hooks.json` or
//! in the inline `[hooks]` table of that same layer. So RemoveEntry is a
//! format-preserving edit of a config layer, or an order-preserving rewrite of
//! the hooks file, and nothing else in either of them moves (spec section
//! 5.3).
//!
//! **Finding the entry again.** An Item is named by its locator and hashed by
//! its canonical form, and a hook's identity deliberately carries no position,
//! so enforcement walks the file the way the enumeration walked it and takes
//! the entry whose canonical form hashes to the one the Finding was raised on.
//! That is the search and the compare-and-swap at once: an entry that was
//! edited since is not the entry the Finding is about, and the action fails
//! with "file is changing" after one more read rather than removing the wrong
//! one.
//!
//! **The script a hook points at** is moved with the entry when it sits inside
//! a scanned Surface root, and left alone otherwise (spec section 5.2).
//!
//! **Codex's own switch comes first** (the owner's decision of 2026-09-28,
//! amending spec section 5.2). An MCP server is switched off with
//! `enabled = false` in its own table, which Codex honours whether or not the
//! key was written before. A hook is switched off in the `[hooks.state]`
//! record the user layer keeps for it, and a skill in the `[[skills.config]]`
//! entry that names it, but only where that record or entry writes an
//! `enabled` key already: a hook or a skill without one is taken out by
//! RemoveEntry or MoveOut as before. The switch is the whole Quarantine, the
//! Item stays where it is, and Restore flips the switch back to what it was,
//! byte for byte where nothing else touched the file.

use std::path::PathBuf;

use agentsweep_core::adapter::Primitive;
use agentsweep_core::composite::{Step, carry_out};
use agentsweep_core::entry_edit::{EntryPath, Format};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, Kind, Scope, Shape, canonical_entry, sha256_hex};
use agentsweep_core::quarantine::{
    EnforcementError, MoveOutPlan, Receipt, Store, current_hash, move_out_only, settled,
};
use agentsweep_core::views::{HookView, ParsedView};
use serde_json::Value;

use crate::{
    CONFIG_FILE, Codex, HOOKS_FILE, PROJECT_DIRECTORY, canonical_key, config_directory_of, hooks,
    resolved_command_of,
};

/// Carries out one Quarantine of one Codex Item.
pub fn enforce(
    adapter: &Codex,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    if primitives == [Primitive::NativeDisable] {
        return switch_off(adapter, host, store, item);
    }
    match item.kind {
        Kind::McpServer | Kind::Hook | Kind::SettingsEntry => {
            entry(adapter, host, store, item, primitives)
        }
        _ => move_out_only(
            host,
            store,
            item,
            agentsweep_core::item::TreeCaps::default(),
            primitives,
        ),
    }
}

/// Where Codex's own switch for one Item sits: the config layer that holds it
/// and the key path of its `enabled` inside that layer. Absent when the Item
/// has none, which is what sends it to the row's own primitive.
///
/// An administrator's Item has no switch AgentSweep may flip, and neither
/// does a server written in a hooks file, which Codex never reads a server
/// from.
pub(crate) fn switch_of(adapter: &Codex, host: &Host, item: &Item) -> Option<(PathBuf, EntryPath)> {
    if item.scope == Scope::Managed {
        return None;
    }
    match item.kind {
        Kind::McpServer => {
            if format_of(item) != Format::Toml {
                return None;
            }
            let document = crate::document::load(
                host,
                &item.scope,
                &item.path,
                item.kind,
                crate::document::Format::Toml,
            )
            .ok()??;
            let table = EntryPath::of(&["mcp_servers", item.inside_file()]);
            at(&document.value, &table)?.as_object()?;
            Some((item.path.clone(), table.child("enabled")))
        }
        Kind::Hook => {
            let handler = handler_of(host, item)?;
            let key = hooks::state_key(&item.path, &handler);
            let layer = adapter.config_dir(host)?.join(CONFIG_FILE);
            let at = EntryPath::of(&["hooks", "state", key.as_str(), "enabled"]);
            written_switch(host, &layer, &at)
        }
        Kind::Skill => {
            let name = match &item.view {
                ParsedView::Skill(view) => view.name.clone(),
                _ => String::new(),
            };
            let mut layers = Vec::new();
            if let Some(root) = item.scope.root() {
                layers.push(root.join(PROJECT_DIRECTORY).join(CONFIG_FILE));
            }
            layers.extend(adapter.config_dir(host).map(|dir| dir.join(CONFIG_FILE)));
            layers
                .iter()
                .find_map(|layer| skill_switch(host, layer, &name, item))
        }
        _ => None,
    }
}

/// The `[[skills.config]]` entry of one layer that names this skill and writes
/// an `enabled` key, by name or by the path of its `SKILL.md`.
fn skill_switch(
    host: &Host,
    layer: &std::path::Path,
    name: &str,
    item: &Item,
) -> Option<(PathBuf, EntryPath)> {
    let document = crate::document::load(
        host,
        &item.scope,
        layer,
        Kind::SettingsEntry,
        crate::document::Format::Toml,
    )
    .ok()??;
    let entries = document.at("skills.config")?.as_array()?;
    let index = entries.iter().position(|entry| {
        let names = |field: &str| entry.get(field).and_then(Value::as_str);
        let named = (!name.is_empty() && names("name") == Some(name))
            || names("path").is_some_and(|path| std::path::Path::new(path) == item.path);
        named && entry.get("enabled").is_some_and(Value::is_boolean)
    })?;
    let at = EntryPath::of(&["skills", "config", &index.to_string(), "enabled"]);
    Some((layer.to_path_buf(), at))
}

/// The switch at one key path of one layer, when the layer writes it already.
fn written_switch(
    host: &Host,
    layer: &std::path::Path,
    at: &EntryPath,
) -> Option<(PathBuf, EntryPath)> {
    let text = String::from_utf8(host.read(layer).ok()?).ok()?;
    let held = agentsweep_core::entry_edit::read_entry(Format::Toml, &text, at)?;
    held.is_boolean().then(|| (layer.to_path_buf(), at.clone()))
}

/// One Item switched off with Codex's own switch, and left where it is.
fn switch_off(
    adapter: &Codex,
    host: &Host,
    store: &dyn Store,
    item: &Item,
) -> Result<Receipt, EnforcementError> {
    let refuse = || EnforcementError::Unsupported {
        kind: item.kind,
        primitive: Primitive::NativeDisable,
    };
    if !matches!(item.kind, Kind::McpServer | Kind::Hook | Kind::Skill) {
        return Err(refuse());
    }
    // The compare-and-swap is over the Item itself: the entry as the Finding
    // saw it, or the skill file as it was read.
    match item.shape {
        Shape::Entry => {
            located(host, item)?;
        }
        _ => settled(&item.content_hash, &item.path, &mut || {
            current_hash(host, &item.path, item.shape, Default::default())
        })?,
    }
    let (layer, at) = switch_of(adapter, host, item).ok_or_else(refuse)?;
    let steps = [Step::NativeDisable {
        file: &layer,
        format: Format::Toml,
        entry: at,
        value: Value::Bool(false),
        detail: switched_detail(item),
    }];
    carry_out(host, store, item, &steps)
}

/// One line for the Activity: what was switched off, never what it held.
fn switched_detail(item: &Item) -> String {
    match &item.view {
        ParsedView::Mcp(view) => {
            format!(
                "the MCP server {} was switched off in its own table",
                view.name
            )
        }
        ParsedView::Hook(view) => format!(
            "the {} handler was switched off in the hook state Codex keeps",
            match view.event.is_empty() {
                true => "hook".to_string(),
                false => view.event.clone(),
            }
        ),
        ParsedView::Skill(view) => {
            format!(
                "the skill {} was switched off in the skills config",
                view.name
            )
        }
        _ => "the Item was switched off with Codex's own switch".to_string(),
    }
}

/// How the file one entry sits in is written: a hooks file is JSON, every
/// config layer is TOML.
fn format_of(item: &Item) -> Format {
    match item.path.file_name().is_some_and(|name| name == HOOKS_FILE) {
        true => Format::Json,
        false => Format::Toml,
    }
}

/// One entry out of the file that holds it, and the hook script that entry
/// points at when the script is on a Surface this scanner covers.
fn entry(
    adapter: &Codex,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    if primitives != [Primitive::RemoveEntry] {
        return Err(EnforcementError::Unsupported {
            kind: item.kind,
            primitive: primitives.first().copied().unwrap_or(Primitive::MoveOut),
        });
    }
    let found = located(host, item)?;
    let script = hook_script(adapter, host, item);
    // The script is not the Item, so the hash it moves on is the one it has
    // now: what the Finding was raised on is the entry that points at it.
    let hash = script
        .as_deref()
        .map(|script| current_hash(host, script, Shape::File, Default::default()))
        .transpose()?
        .unwrap_or_default();
    let mut steps = vec![Step::RemoveEntry {
        file: &item.path,
        format: format_of(item),
        entry: found,
        detail: removed_detail(item),
    }];
    if let Some(script) = &script {
        steps.push(Step::MoveOut(MoveOutPlan {
            source: script,
            contents: script,
            shape: Shape::File,
            expected_hash: &hash,
            caps: Default::default(),
            detail: "the script the hook ran sat inside a scanned Surface and moved with it"
                .to_string(),
        }));
    }
    carry_out(host, store, item, &steps)
}

/// Finds the entry the Item is about in the file as it stands, retrying once
/// when what is there is not what the Finding was raised on (spec section
/// 5.3).
fn located(host: &Host, item: &Item) -> Result<EntryPath, EnforcementError> {
    let mut found = None;
    settled(&item.content_hash, &item.path, &mut || {
        let Some((entry, hash)) = search(host, item) else {
            return Err(EnforcementError::Missing {
                path: item.path.clone(),
            });
        };
        found = Some(entry);
        Ok(hash)
    })?;
    found.ok_or_else(|| EnforcementError::Missing {
        path: item.path.clone(),
    })
}

/// Where the entry sits and what its canonical form hashes to, as the file
/// stands now.
fn search(host: &Host, item: &Item) -> Option<(EntryPath, String)> {
    let format = match format_of(item) {
        Format::Json => crate::document::Format::Json,
        Format::Toml => crate::document::Format::Toml,
    };
    let document =
        crate::document::load(host, &item.scope, &item.path, item.kind, format).ok()??;
    match item.kind {
        Kind::SettingsEntry => {
            let entry = EntryPath::from_pointer(item.inside_file())?;
            let held = at(&document.value, &entry)?;
            let dotted = entry.segments().join(".");
            Some((entry, sha256_hex(&canonical_key(&dotted, held))))
        }
        Kind::McpServer => {
            let entry = EntryPath::of(&["mcp_servers", item.inside_file()]);
            let held = at(&document.value, &entry)?;
            Some((entry, sha256_hex(&canonical_entry(held))))
        }
        Kind::Hook => {
            let events = match format_of(item) {
                Format::Json => "hooks",
                Format::Toml => "hooks.hooks",
            };
            let mut first = None;
            for handler in hooks::handlers(&document, events) {
                let form =
                    HookView::normal_form(&handler.event, &handler.matcher, &handler.handler);
                let hash = sha256_hex(&canonical_entry(&form));
                let mut entry = EntryPath::default();
                for segment in events.split('.') {
                    entry = entry.child(segment);
                }
                let entry = entry
                    .child(handler.event.clone())
                    .child(handler.group_index.to_string())
                    .child("hooks")
                    .child(handler.handler_index.to_string());
                if hash == item.content_hash {
                    return Some((entry, hash));
                }
                first.get_or_insert((entry, hash));
            }
            first
        }
        _ => None,
    }
}

/// The hook handler the Item is, found by its canonical form, which is where
/// the key of its `[hooks.state]` record comes from.
fn handler_of(host: &Host, item: &Item) -> Option<hooks::Handler> {
    let format = match format_of(item) {
        Format::Json => crate::document::Format::Json,
        Format::Toml => crate::document::Format::Toml,
    };
    let document =
        crate::document::load(host, &item.scope, &item.path, item.kind, format).ok()??;
    let events = match format_of(item) {
        Format::Json => "hooks",
        Format::Toml => "hooks.hooks",
    };
    hooks::handlers(&document, events)
        .into_iter()
        .find(|handler| {
            let form = HookView::normal_form(&handler.event, &handler.matcher, &handler.handler);
            sha256_hex(&canonical_entry(&form)) == item.content_hash
        })
}

/// The value at one key path.
fn at<'a>(value: &'a Value, entry: &EntryPath) -> Option<&'a Value> {
    let mut current = value;
    for segment in entry.segments() {
        current = match current {
            Value::Object(fields) => fields.get(segment)?,
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// The script a hook entry runs, when it sits inside a Surface this scanner
/// covers and is therefore AgentSweep's to move (spec section 5.2).
fn hook_script(adapter: &Codex, host: &Host, item: &Item) -> Option<PathBuf> {
    if item.kind != Kind::Hook {
        return None;
    }
    let resolved = resolved_command_of(item)?;
    if host.symlink_metadata(resolved).is_err() {
        return None;
    }
    let inside_config = adapter
        .config_dir(host)
        .is_some_and(|dir| resolved.starts_with(dir));
    match inside_config || config_directory_of(resolved).is_some() {
        true => Some(resolved.to_path_buf()),
        false => None,
    }
}

/// One line for the Activity: what was removed, never what it held.
fn removed_detail(item: &Item) -> String {
    match &item.view {
        ParsedView::Mcp(view) => format!("the MCP server {} was removed from the file", view.name),
        ParsedView::Hook(view) => format!(
            "the {} handler was removed from the file",
            match view.event.is_empty() {
                true => "hook".to_string(),
                false => view.event.clone(),
            }
        ),
        ParsedView::Settings(view) => {
            format!("the config key {} was removed from the file", view.key_path)
        }
        _ => "the entry was removed from the file".to_string(),
    }
}
