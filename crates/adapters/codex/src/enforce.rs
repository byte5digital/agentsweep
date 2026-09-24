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
//! This adapter declares no NativeDisable. Codex has its own switches, an
//! `enabled = false` on a server and the state pin on a hook, but a native
//! disable is never a Quarantine's only step and no kind here is a composite,
//! so nothing would ever be the step beside it.

use std::path::PathBuf;

use agentsweep_core::adapter::Primitive;
use agentsweep_core::composite::{Step, carry_out};
use agentsweep_core::entry_edit::{EntryPath, Format};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, Kind, Shape, canonical_entry, sha256_hex};
use agentsweep_core::quarantine::{
    EnforcementError, MoveOutPlan, Receipt, Store, current_hash, move_out_only, settled,
};
use agentsweep_core::views::{HookView, ParsedView};
use serde_json::Value;

use crate::{Codex, HOOKS_FILE, canonical_key, config_directory_of, hooks, resolved_command_of};

/// Carries out one Quarantine of one Codex Item.
pub fn enforce(
    adapter: &Codex,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
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
