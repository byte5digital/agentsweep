//! What one Quarantine does to a Claude Code Surface.
//!
//! The eligibility table of spec section 5.2 says which primitives one kind
//! takes; this module says where each of them lands in this Agent's files. A
//! skill or an instruction file is one MoveOut and the core does all of it. An
//! MCP server, a hook handler and a settings key are entries in a file the
//! Agent shares with everything else it reads there, so each is found again in
//! the file as it stands and dropped out of it. A plugin and a marketplace are
//! composites: the Agent's own switch first, or the registry record first, and
//! the directory after.
//!
//! **Finding the entry again.** An Item is named by its locator and hashed by
//! its canonical form, and neither says which line of which file it was read
//! from. So enforcement walks the file the way the enumeration walked it and
//! takes the entry whose canonical form hashes to the one the Finding was
//! raised on. That is the compare-and-swap of spec section 5.3 and the search
//! at once: an entry that was edited since is not the entry the Finding is
//! about, and the action fails with "file is changing" after one more read
//! rather than removing the wrong one.
//!
//! **The script a hook points at** is moved with the entry when it sits inside
//! a scanned Surface root, and left alone otherwise (spec section 5.2). It is
//! not the Item, so the hash it is moved on is the one it has now.

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::Primitive;
use agentsweep_core::composite::{Step, carry_out};
use agentsweep_core::entry_edit::{EntryPath, Format};
use agentsweep_core::host::Host;
use agentsweep_core::item::{Item, Kind, Scope, Shape, canonical_entry, sha256_hex};
use agentsweep_core::quarantine::{
    EnforcementError, MoveOutPlan, Receipt, Store, current_hash, settled,
};
use agentsweep_core::views::{HookView, ParsedView};
use serde_json::Value;

use crate::{
    ClaudeCode, USER_SETTINGS_FILE, canonical_key, config_directory_of, hooks, plugins, registry,
    resolved_command_of,
};

/// Carries out one Quarantine of one Claude Code Item.
pub fn enforce(
    adapter: &ClaudeCode,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    match item.kind {
        Kind::McpServer | Kind::Hook | Kind::SettingsEntry => {
            entry(adapter, host, store, item, primitives)
        }
        Kind::Plugin => plugin(adapter, host, store, item, primitives),
        Kind::Marketplace => marketplace(adapter, host, store, item, primitives),
        _ => {
            agentsweep_core::quarantine::move_out_only(host, store, item, adapter.caps, primitives)
        }
    }
}

/// One entry out of the file that holds it, and the hook script that entry
/// points at when the script is on a Surface this scanner covers.
fn entry(
    adapter: &ClaudeCode,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    expect(item, primitives, &[Primitive::RemoveEntry])?;
    let found = located(host, item)?;
    let script = hook_script(adapter, host, item);
    // The script is not the Item, so the hash it moves on is the one it has
    // now: what the Finding was raised on is the entry that points at it.
    let hash = script
        .as_deref()
        .map(|script| script_hash(host, script, adapter.caps))
        .unwrap_or_default();
    let mut steps = vec![Step::RemoveEntry {
        file: &item.path,
        format: Format::Json,
        entry: found.clone(),
        detail: removed_detail(item),
    }];
    if let Some(script) = &script {
        steps.push(Step::MoveOut(MoveOutPlan {
            source: script,
            contents: script,
            shape: Shape::File,
            expected_hash: &hash,
            caps: adapter.caps,
            detail: "the script the hook ran sat inside a scanned Surface and moved with it"
                .to_string(),
        }));
    }
    carry_out(host, store, item, &steps)
}

/// A plugin: the Agent's own switch off, then the version directory out (spec
/// section 5.2). Both Agents re-fetch plugins after session start, so the
/// switch is what survives the re-fetch and the MoveOut is what takes the code
/// away.
fn plugin(
    adapter: &ClaudeCode,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    expect(
        item,
        primitives,
        &[Primitive::NativeDisable, Primitive::MoveOut],
    )?;
    let settings = config_dir(adapter, host)?.join(USER_SETTINGS_FILE);
    let id = plugin_id(host, adapter, item).ok_or_else(|| EnforcementError::NotEligible {
        reason: "no registry record and no cache path says which plugin this version is"
            .to_string(),
    })?;
    if host.symlink_metadata(&settings).is_err() {
        // The Agent's own switch lives in the user settings file, and a
        // Quarantine may not invent one: there would be nothing to put back.
        return Err(EnforcementError::Missing { path: settings });
    }
    let steps = [
        Step::NativeDisable {
            file: &settings,
            format: Format::Json,
            entry: EntryPath::of(&["enabledPlugins", &id]),
            value: Value::Bool(false),
            detail: "the plugin was switched off in the Agent's own settings".to_string(),
        },
        Step::MoveOut(move_out_plan(item, adapter)),
    ];
    carry_out(host, store, item, &steps)
}

/// A marketplace: the registry record out, then the clone out.
fn marketplace(
    adapter: &ClaudeCode,
    host: &Host,
    store: &dyn Store,
    item: &Item,
    primitives: &[Primitive],
) -> Result<Receipt, EnforcementError> {
    expect(
        item,
        primitives,
        &[Primitive::RemoveEntry, Primitive::MoveOut],
    )?;
    let registry = config_dir(adapter, host)?
        .join(plugins::DIRECTORY)
        .join(plugins::MARKETPLACE_REGISTRY);
    let name = item
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let entry = marketplace_record(host, &registry, &name).ok_or_else(|| {
        EnforcementError::NotEligible {
            reason: format!("no record for {name} in {}", plugins::MARKETPLACE_REGISTRY),
        }
    })?;
    let steps = [
        Step::RemoveEntry {
            file: &registry,
            format: Format::Json,
            entry,
            detail: "the marketplace is no longer one the Agent knows".to_string(),
        },
        Step::MoveOut(move_out_plan(item, adapter)),
    ];
    carry_out(host, store, item, &steps)
}

/// Finds the entry the Item is about in the file as it stands, retrying once
/// when what is there is not what the Finding was raised on (spec section
/// 5.3).
fn located(host: &Host, item: &Item) -> Result<EntryPath, EnforcementError> {
    let mut found = None;
    settled(&item.content_hash, &item.path, &mut || {
        let text = read(host, &item.path)?;
        let Some((entry, hash)) = search(item, &text) else {
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
fn search(item: &Item, text: &str) -> Option<(EntryPath, String)> {
    let value: Value = serde_json::from_str(text).ok()?;
    match item.kind {
        Kind::SettingsEntry => {
            let entry = EntryPath::from_pointer(item.inside_file())?;
            let held = at(&value, &entry)?;
            let dotted = entry.segments().join(".");
            Some((entry, sha256_hex(&canonical_key(&dotted, held))))
        }
        Kind::McpServer => {
            let name = item.inside_file();
            for entry in server_paths(item, name) {
                if let Some(held) = at(&value, &entry) {
                    return Some((entry, sha256_hex(&canonical_entry(held))));
                }
            }
            None
        }
        Kind::Hook => {
            let document = crate::document::Document {
                path: item.path.clone(),
                surface: String::new(),
                value,
            };
            let handlers = hooks::handlers(&document);
            let mut first = None;
            for found in handlers {
                let form = HookView::normal_form(&found.event, &found.matcher, &found.handler);
                let hash = sha256_hex(&canonical_entry(&form));
                let entry = EntryPath::of(&[
                    "hooks".to_string(),
                    found.event.clone(),
                    found.group_index.to_string(),
                    "hooks".to_string(),
                    found.handler_index.to_string(),
                ]);
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

/// The key paths an MCP server of this Item could sit at. A server private to
/// one project lives under that project's record in the user registry; every
/// other one is a member of the file's own `mcpServers`.
fn server_paths(item: &Item, name: &str) -> Vec<EntryPath> {
    let mut paths = Vec::new();
    if let Scope::Project(root) = &item.scope
        && item
            .path
            .file_name()
            .is_some_and(|file| file == registry::FILE_NAME)
    {
        paths.push(EntryPath::of(&[
            "projects".to_string(),
            root.display().to_string(),
            "mcpServers".to_string(),
            name.to_string(),
        ]));
    }
    paths.push(EntryPath::of(&["mcpServers", name]));
    paths
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
fn hook_script(adapter: &ClaudeCode, host: &Host, item: &Item) -> Option<PathBuf> {
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

/// The plugin id the Agent's own switch is keyed by: what the install registry
/// says about this version directory, and what the cache path says when no
/// record points at it any more.
fn plugin_id(host: &Host, adapter: &ClaudeCode, item: &Item) -> Option<String> {
    let registry = adapter
        .config_dir(host)?
        .join(plugins::DIRECTORY)
        .join(plugins::INSTALL_REGISTRY);
    if let Ok(bytes) = host.read(&registry)
        && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        && let Some(plugins) = value.get("plugins").and_then(Value::as_object)
    {
        for (id, records) in plugins {
            let written = match records {
                Value::Array(records) => records.clone(),
                other => vec![other.clone()],
            };
            for record in written {
                let path = record
                    .get("installPath")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !path.is_empty() && Path::new(path) == item.path {
                    return Some(id.clone());
                }
            }
        }
    }
    // A version nothing points at any more still sits at
    // `plugins/cache/<marketplace>/<name>/<version>`, which names it.
    let mut parts = item.path.ancestors().skip(1);
    let name = parts.next()?.file_name()?.to_string_lossy().to_string();
    let marketplace = parts.next()?.file_name()?.to_string_lossy().to_string();
    let cache = parts.next()?;
    match cache.file_name()? == plugins::CACHE {
        true => Some(format!("{name}@{marketplace}")),
        false => None,
    }
}

/// Where the record of one marketplace sits in the registry, which writes its
/// records either under a `marketplaces` key or at the top level.
fn marketplace_record(host: &Host, registry: &Path, name: &str) -> Option<EntryPath> {
    let value: Value = serde_json::from_slice(&host.read(registry).ok()?).ok()?;
    let wrapped = EntryPath::of(&["marketplaces", name]);
    if at(&value, &wrapped).is_some() {
        return Some(wrapped);
    }
    let bare = EntryPath::of(&[name]);
    at(&value, &bare).is_some().then_some(bare)
}

/// The MoveOut of the directory a plugin or a marketplace is.
fn move_out_plan<'a>(item: &'a Item, adapter: &ClaudeCode) -> MoveOutPlan<'a> {
    MoveOutPlan {
        source: &item.path,
        contents: &item.path,
        shape: item.shape,
        expected_hash: &item.content_hash,
        caps: adapter.caps,
        detail: String::new(),
    }
}

/// The config directory in effect, which every registry and the user settings
/// file sit under.
fn config_dir(adapter: &ClaudeCode, host: &Host) -> Result<PathBuf, EnforcementError> {
    adapter
        .config_dir(host)
        .ok_or_else(|| EnforcementError::NotEligible {
            reason: "there is no configuration directory to write in".to_string(),
        })
}

/// Refuses a row of primitives this adapter does not carry out for the kind,
/// before anything is written.
fn expect(item: &Item, asked: &[Primitive], row: &[Primitive]) -> Result<(), EnforcementError> {
    match asked == row {
        true => Ok(()),
        false => Err(EnforcementError::Unsupported {
            kind: item.kind,
            primitive: asked.first().copied().unwrap_or(Primitive::MoveOut),
        }),
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
            format!(
                "the settings key {} was removed from the file",
                view.key_path
            )
        }
        _ => "the entry was removed from the file".to_string(),
    }
}

/// The text of one configuration file.
fn read(host: &Host, path: &Path) -> Result<String, EnforcementError> {
    let bytes = host.read(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => EnforcementError::Missing {
            path: path.to_path_buf(),
        },
        _ => EnforcementError::Store(error),
    })?;
    String::from_utf8(bytes).map_err(|_| EnforcementError::Edit {
        path: path.to_path_buf(),
        reason: "the file is not text".to_string(),
    })
}

/// The hash the script a hook points at has right now.
fn script_hash(host: &Host, script: &Path, caps: agentsweep_core::item::TreeCaps) -> String {
    current_hash(host, script, Shape::File, caps).unwrap_or_default()
}
