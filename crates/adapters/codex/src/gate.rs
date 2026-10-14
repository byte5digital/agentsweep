//! The Gate's own entries in the Codex user hooks file, and the pins that let
//! Codex run them.
//!
//! Spec section 7.2: two hook groups in the user `hooks.json` of the effective
//! Codex home, `UserPromptSubmit` with no matcher and `PreToolUse` with the
//! matcher `Bash|mcp__.*`, each with one command handler and an explicit
//! `timeout` of five seconds. Codex has no exec form: the handler's `command`
//! is one plain string that Codex hands to a shell, so the path of the
//! in-bundle command line interface is quoted to stay one word, followed by
//! `gate --agent codex`. The file carries Codex's own event names; only the
//! state key writes them in snake case.
//!
//! **The pin.** Codex runs a user hook only while
//! `[hooks.state."<key>"].trusted_hash` in the user `config.toml` equals the
//! hash it computes for the handler, so each group written is followed by its
//! record, computed with the recipe [`hooks::pin_hash`] already reproduces and
//! filed under the positional key of [`hooks::state_key`]. Because that key
//! counts groups, the groups are appended after every group already written
//! and never inserted, so no pin the user has is renumbered. The TOML is
//! edited with the format-preserving editor, so every comment and the order of
//! every table stay where they were. The pin records are Codex's own
//! `[hooks.state]` entries, which are never an Item and never raise Drift
//! (spec section 4.6.5).
//!
//! Both files go through the compare-and-swap of spec section 5.3 and are
//! created when absent. The config layer is parsed before the hooks file is
//! touched, so a layer that does not parse refuses the whole write rather than
//! leaving an unpinned group behind. Removal takes away exactly the groups
//! whose only handler is AgentSweep's, and the records filed under their keys,
//! and nothing else. Every entry written or taken away is named by the id and
//! hash the enumeration gives its Hook Item, which is what the daemon records.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use agentsweep_core::adapter::Enumeration;
use agentsweep_core::entry_edit::{
    EditError, EntryPath, Format as EditFormat, append_json, drop_json, drop_toml, insert_toml,
    parses, read_entry,
};
use agentsweep_core::gate_registration::{
    GATE_TIMEOUT_SECONDS, GateCheck, GateCommand, GateEntry, GateError, GateWrite, SurfaceWriter,
    rewrite,
};
use agentsweep_core::host::Host;
use agentsweep_core::item::{ItemId, Kind, Scope, sha256_hex};
use serde_json::{Value, json};

use crate::document::{Document, json_of, parse_toml, surface_name};
use crate::hooks::{self, Handler, Pin};
use crate::{AGENT_ID, CONFIG_FILE, Codex, HOOKS_FEATURE, HOOKS_FILE};

/// The matcher of the `PreToolUse` group: a shell command and every MCP tool.
pub const PRE_TOOL_USE_MATCHER: &str = "Bash|mcp__.*";

/// The events the Gate listens on, by Codex's own names in `hooks.json`, each
/// with the matcher its group carries.
pub const EVENTS: [(&str, Option<&str>); 2] = [
    ("UserPromptSubmit", None),
    ("PreToolUse", Some(PRE_TOOL_USE_MATCHER)),
];

/// One word as a POSIX shell reads it back unchanged: inside single quotes,
/// where nothing is special, with every single quote of its own closed,
/// escaped and opened again.
pub fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// The plain command string the Gate's handler runs: the quoted path of the
/// command line interface and `gate --agent codex`. This string, quoted as it
/// is, is what the pin hashes.
pub fn command_line(command: &GateCommand) -> String {
    let mut line = quoted(&command.program.display().to_string());
    for argument in GateCommand::arguments(AGENT_ID) {
        line.push(' ');
        line.push_str(&argument);
    }
    line
}

/// The handler every Gate group holds, keys in the order they are written.
pub fn handler(command: &GateCommand) -> Value {
    json!({
        "type": "command",
        "command": command_line(command),
        "timeout": GATE_TIMEOUT_SECONDS,
    })
}

/// The group the Gate appends for one event.
pub fn group(matcher: Option<&str>, command: &GateCommand) -> Value {
    match matcher {
        Some(matcher) => json!({"matcher": matcher, "hooks": [handler(command)]}),
        None => json!({"hooks": [handler(command)]}),
    }
}

/// True when a group holds AgentSweep's handler and nothing else.
fn is_ours(group: &Value, ours: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|handlers| handlers.len() == 1 && handlers[0] == *ours)
}

/// True when a group under `event` holds one command handler that carries
/// AgentSweep's arguments and timeout, and nothing else, under the matcher
/// the Gate gives the event, but runs a command line interface at another
/// path. That is AgentSweep's own entry after the bundle moved, and the
/// registration replaces it (the owner's decision of 2026-10-14).
fn is_moved(event: &str, group: &Value, ours: &Value) -> bool {
    let Some((_, matcher)) = EVENTS.iter().find(|(name, _)| *name == event) else {
        return false;
    };
    if group.get("matcher").and_then(Value::as_str) != *matcher {
        return false;
    }
    let Some([handler]) = group
        .get("hooks")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    else {
        return false;
    };
    let Some(fields) = handler.as_object() else {
        return false;
    };
    let arguments = format!(" {}", GateCommand::arguments(AGENT_ID).join(" "));
    fields.len() == 3
        && handler.get("type") == ours.get("type")
        && handler.get("timeout") == ours.get("timeout")
        && handler
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|line| line.ends_with(&arguments))
        && handler.get("command") != ours.get("command")
}

/// What taking groups out of a hooks file did: the text left, the entries
/// that went with the keys of their pins, and the pins of the groups that
/// moved up, from their old key to their new one.
#[derive(Clone, Debug, Default)]
struct Dropped {
    text: String,
    entries: Vec<GateEntry>,
    keys: Vec<String>,
    rekeys: Vec<(String, String)>,
}

/// Takes every group `picks` chooses out of a hooks file, and works out where
/// the groups after them in the same event move to.
///
/// Codex files a pin under the position of its group, so a group that goes
/// shifts every later group of its event one place up, and its pin would no
/// longer match. Each shifted handler's key is named twice, old and new, in
/// the order the groups are written, so that moving the records one after
/// the other never writes over a record still to be moved.
fn drop_groups(
    host: &Host,
    path: &Path,
    text: &str,
    picks: &dyn Fn(&str, &Value) -> bool,
) -> Result<Dropped, EditError> {
    let document = hooks_document(host, path, text)?;
    let mut dropped = Dropped {
        text: text.to_string(),
        ..Dropped::default()
    };
    for (event, groups) in document.members("hooks") {
        let Some(groups) = groups.as_array() else {
            continue;
        };
        let gone: Vec<usize> = groups
            .iter()
            .enumerate()
            .filter(|(_, group)| picks(&event, group))
            .map(|(index, _)| index)
            .collect();
        if gone.is_empty() {
            continue;
        }
        for handler in hooks::handlers(&document, "hooks") {
            if handler.event != event {
                continue;
            }
            if gone.contains(&handler.group_index) {
                let locator = handler.locator(&document);
                dropped.keys.push(hooks::state_key(path, &handler));
                dropped.entries.push(GateEntry {
                    item_id: ItemId::new(AGENT_ID, &Scope::User, Kind::Hook, &locator),
                    locator,
                    content_hash: sha256_hex(&handler.content()),
                    path: path.to_path_buf(),
                });
                continue;
            }
            let ahead = gone
                .iter()
                .filter(|index| **index < handler.group_index)
                .count();
            if ahead == 0 {
                continue;
            }
            let mut moved = handler.clone();
            moved.group_index -= ahead;
            dropped.rekeys.push((
                hooks::state_key(path, &handler),
                hooks::state_key(path, &moved),
            ));
        }
        (dropped.text, _) = drop_json(
            &dropped.text,
            &EntryPath::of(&["hooks", event.as_str()]),
            &|group| picks(&event, group),
        )?;
    }
    Ok(dropped)
}

/// Drops the pin records filed under `keys`, then files every record of
/// `rekeys` again under its new key, and says how many records moved.
fn refile_pins(
    text: &str,
    keys: &[String],
    rekeys: &[(String, String)],
) -> Result<(String, bool, usize), EditError> {
    let mut text = text.to_string();
    let mut changed = false;
    for key in keys {
        let dropped;
        (text, dropped) = drop_toml(&text, &record_path(key))?;
        changed |= dropped;
    }
    let mut moved = 0;
    for (from, to) in rekeys {
        let Some(record) = read_entry(EditFormat::Toml, &text, &record_path(from)) else {
            continue;
        };
        (text, _) = drop_toml(&text, &record_path(from))?;
        text = insert_toml(&text, &record_path(to), &record)?;
        changed = true;
        moved += 1;
    }
    Ok((text, changed, moved))
}

/// What the configuration layers say about hooks for the Gate: managed
/// policy that drops the user's hooks, or the user's own switch.
fn hooks_switched_off(adapter: &Codex, host: &Host) -> Option<GateCheck> {
    let layers = adapter.global_layers(host, &mut Enumeration::default());
    let off = |config: &Document| {
        HOOKS_FEATURE
            .iter()
            .any(|switch| config.flag(switch) == Some(false))
    };
    let managed = layers.iter().any(|layer| {
        layer.managed
            && layer.config.as_ref().is_some_and(|config| {
                config.flag("allow_managed_hooks_only") == Some(true) || off(config)
            })
    });
    if managed {
        return Some(GateCheck::ManagedPolicy);
    }
    let home = adapter.config_dir(host)?;
    let user = layers.iter().any(|layer| {
        layer.scope == Scope::User && layer.folder == home && layer.config.as_ref().is_some_and(off)
    });
    user.then_some(GateCheck::SwitchedOffByUser)
}

/// The two files the Gate writes, in the effective Codex home.
struct Files {
    hooks: PathBuf,
    config: PathBuf,
}

fn files(adapter: &Codex, host: &Host) -> Result<Files, GateError> {
    let directory = adapter
        .config_dir(host)
        .ok_or(GateError::NoConfigDirectory)?;
    Ok(Files {
        hooks: directory.join(HOOKS_FILE),
        config: directory.join(CONFIG_FILE),
    })
}

/// The hooks file as the enumeration would read it from this text.
fn hooks_document(host: &Host, path: &Path, text: &str) -> Result<Document, EditError> {
    let value: Value =
        serde_json::from_str(text).map_err(|error| EditError::Unparseable(error.to_string()))?;
    Ok(Document::inline(
        path.to_path_buf(),
        surface_name(host, &Scope::User, path),
        value,
    ))
}

/// The `[hooks.state]` table of a user config layer, empty when it has none.
fn state_of(text: &str) -> Result<Value, EditError> {
    let value =
        json_of(&parse_toml(text).map_err(|error| EditError::Unparseable(error.to_string()))?);
    Ok(value
        .get("hooks")
        .and_then(|hooks| hooks.get("state"))
        .cloned()
        .unwrap_or_else(|| json!({})))
}

/// One Gate handler in the hooks file: where Codex counts it from, the key
/// and the hash of its pin, and the Hook Item it is.
#[derive(Clone, Debug)]
struct Found {
    event: &'static str,
    handler: Handler,
    key: String,
    pin: String,
    entry: GateEntry,
}

/// The Gate's groups in a hooks document: every group whose only handler is
/// AgentSweep's, under the event and the matcher the Gate gives it. A handler
/// of AgentSweep's in a group the user shares is not one of them.
fn ours_in(document: &Document, command: &GateCommand) -> Vec<Found> {
    let ours = handler(command);
    let mut found = Vec::new();
    for handler in hooks::handlers(document, "hooks") {
        let Some((event, _)) = EVENTS.iter().find(|(event, matcher)| {
            handler.event == *event
                && handler.has_matcher == matcher.is_some()
                && handler.matcher == matcher.unwrap_or_default()
        }) else {
            continue;
        };
        let sole = document
            .value
            .get("hooks")
            .and_then(|hooks| hooks.get(*event))
            .and_then(|groups| groups.get(handler.group_index))
            .is_some_and(|group| is_ours(group, &ours));
        let Some(pin) = hooks::pin_hash(&handler) else {
            continue;
        };
        if !sole {
            continue;
        }
        let locator = handler.locator(document);
        found.push(Found {
            event,
            key: hooks::state_key(&document.path, &handler),
            pin,
            entry: GateEntry {
                item_id: ItemId::new(AGENT_ID, &Scope::User, Kind::Hook, &locator),
                locator,
                content_hash: sha256_hex(&handler.content()),
                path: document.path.clone(),
            },
            handler,
        });
    }
    found
}

/// The key path of one pin record.
fn record_path(key: &str) -> EntryPath {
    EntryPath::of(&["hooks", "state", key])
}

/// Reads a file that may be absent, as text.
fn read_text(host: &Host, path: &Path) -> Result<Option<String>, GateError> {
    match host.read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| GateError::Unparseable {
                path: path.to_path_buf(),
                reason: "the file is not text".to_string(),
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(GateError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

/// Refuses before anything is written when the config layer does not parse,
/// so a write that spans both files is never left half done by it.
fn config_parses(host: &Host, path: &Path) -> Result<(), GateError> {
    let Some(text) = read_text(host, path)? else {
        return Ok(());
    };
    parses(EditFormat::Toml, &text).map_err(|error| GateError::Unparseable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Appends a group for every event that carries none of AgentSweep's, pins
/// every Gate group whose pin is not trusted, and names every entry it wrote
/// or pinned.
pub fn register(
    adapter: &Codex,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<GateWrite, GateError> {
    let files = files(adapter, host)?;
    config_parses(host, &files.config)?;
    let ours = handler(command);

    // The groups first: the keys of their pins are counted from where they
    // end up, which is known only once the hooks file is written. A group of
    // AgentSweep's under another path goes before anything is appended, and
    // the user's groups after it move up with their pins.
    let mut groups: Vec<Found> = Vec::new();
    let mut dropped = Dropped::default();
    let appended = rewrite(host, writer, &files.hooks, &mut |current| {
        dropped = drop_groups(
            host,
            &files.hooks,
            current.unwrap_or("{}"),
            &|event, group| is_moved(event, group, &ours),
        )?;
        let mut text = dropped.text.clone();
        let present: BTreeSet<&str> = ours_in(&hooks_document(host, &files.hooks, &text)?, command)
            .iter()
            .map(|found| found.event)
            .collect();
        let mut appended = Vec::new();
        for (event, matcher) in EVENTS {
            if present.contains(event) {
                continue;
            }
            text = append_json(
                &text,
                &EntryPath::of(&["hooks", event]),
                &group(matcher, command),
            )?;
            appended.push(event);
        }
        groups = ours_in(&hooks_document(host, &files.hooks, &text)?, command);
        match appended.is_empty() && dropped.entries.is_empty() {
            true => Ok(None),
            false => Ok(Some((text, appended))),
        }
    })?
    .unwrap_or_default();

    let mut pins_rekeyed = 0;
    let pinned = rewrite(host, writer, &files.config, &mut |current| {
        let (mut text, refiled, moved) =
            refile_pins(current.unwrap_or_default(), &dropped.keys, &dropped.rekeys)?;
        pins_rekeyed = moved;
        let state = state_of(&text)?;
        let mut pinned = Vec::new();
        for found in &groups {
            if hooks::pin_of(&state, &found.key, &found.handler) == Pin::Trusted {
                continue;
            }
            text = insert_toml(
                &text,
                &record_path(&found.key),
                &json!({"trusted_hash": found.pin}),
            )?;
            pinned.push(found.entry.item_id.clone());
        }
        match pinned.is_empty() && !refiled {
            true => Ok(None),
            false => Ok(Some((text, pinned))),
        }
    })?
    .unwrap_or_default();

    let written = groups
        .into_iter()
        .filter(|found| appended.contains(&found.event) || pinned.contains(&found.entry.item_id))
        .map(|found| found.entry)
        .collect();
    Ok(GateWrite {
        written,
        removed: dropped.entries,
        pins_rekeyed,
    })
}

/// Whether every event carries a Gate group whose pin Codex would trust and
/// no group of AgentSweep's sits under another path, and whether managed
/// policy or the user's own layer switch hooks off.
pub fn check(adapter: &Codex, host: &Host, command: &GateCommand) -> GateCheck {
    if let Some(off) = hooks_switched_off(adapter, host) {
        return off;
    }
    let all = || EVENTS.iter().map(|(event, _)| event.to_string()).collect();
    let Ok(files) = files(adapter, host) else {
        return GateCheck::Missing(all());
    };
    let hooks_text = match read_text(host, &files.hooks) {
        Ok(text) => text.unwrap_or_else(|| "{}".to_string()),
        Err(_) => return GateCheck::Unreadable(files.hooks),
    };
    let Ok(document) = hooks_document(host, &files.hooks, &hooks_text) else {
        return GateCheck::Unreadable(files.hooks);
    };
    let config_text = match read_text(host, &files.config) {
        Ok(text) => text.unwrap_or_default(),
        Err(_) => return GateCheck::Unreadable(files.config),
    };
    let Ok(state) = state_of(&config_text) else {
        return GateCheck::Unreadable(files.config);
    };
    let trusted: BTreeSet<&str> = ours_in(&document, command)
        .iter()
        .filter(|found| hooks::pin_of(&state, &found.key, &found.handler) == Pin::Trusted)
        .map(|found| found.event)
        .collect();
    let ours = handler(command);
    let moved = |event: &str| {
        document
            .value
            .get("hooks")
            .and_then(|hooks| hooks.get(event))
            .and_then(Value::as_array)
            .is_some_and(|groups| groups.iter().any(|group| is_moved(event, group, &ours)))
    };
    let missing: Vec<String> = EVENTS
        .iter()
        .filter(|(event, _)| !trusted.contains(event) || moved(event))
        .map(|(event, _)| event.to_string())
        .collect();
    match missing.is_empty() {
        true => GateCheck::Registered,
        false => GateCheck::Missing(missing),
    }
}

/// Takes away the groups whose only handler is AgentSweep's and the pin
/// records filed under their keys, files the pins of the groups after them
/// again under their new position, and names the entries taken away.
pub fn remove(
    adapter: &Codex,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<GateWrite, GateError> {
    let files = files(adapter, host)?;
    config_parses(host, &files.config)?;
    let ours = handler(command);

    // The keys are counted on the hooks file as it was before the groups
    // went, which is where Codex filed the pins.
    let mut dropped = Dropped::default();
    rewrite(host, writer, &files.hooks, &mut |current| {
        dropped = Dropped::default();
        let Some(current) = current else {
            return Ok(None);
        };
        dropped = drop_groups(host, &files.hooks, current, &|_, group| {
            is_ours(group, &ours)
        })?;
        match dropped.entries.is_empty() {
            true => Ok(None),
            false => Ok(Some((dropped.text.clone(), ()))),
        }
    })?;

    let mut pins_rekeyed = 0;
    rewrite(host, writer, &files.config, &mut |current| {
        let Some(current) = current else {
            return Ok(None);
        };
        let (text, changed, moved) = refile_pins(current, &dropped.keys, &dropped.rekeys)?;
        pins_rekeyed = moved;
        match changed {
            true => Ok(Some((text, ()))),
            false => Ok(None),
        }
    })?;
    Ok(GateWrite {
        written: Vec::new(),
        removed: dropped.entries,
        pins_rekeyed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use agentsweep_core::adapter::SurfaceAdapter;
    use agentsweep_core::gate_registration::{WriteError, hash_now};
    use agentsweep_core::item::{Activation, Shape, canonical_entry};

    /// Where the bundle puts the command line interface. It does not exist on
    /// the machine the test runs on, and nothing runs it.
    const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";

    /// The compare and the write, as the daemon's writer does them.
    struct Writer;

    impl SurfaceWriter for Writer {
        fn write_if_unchanged(
            &self,
            path: &Path,
            expected: Option<&str>,
            text: &str,
        ) -> Result<(), WriteError> {
            if hash_now(path).map_err(WriteError::Io)?.as_deref() != expected {
                return Err(WriteError::Changed);
            }
            std::fs::write(path, text).map_err(WriteError::Io)
        }
    }

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A temporary home with an installed Codex. Nothing here touches the
    /// real machine.
    struct Home {
        root: PathBuf,
    }

    impl Home {
        fn new() -> Home {
            let root = std::env::temp_dir().join(format!(
                "agentsweep-codex-gate-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join(".codex")).expect("a Codex home");
            Home { root }
        }

        fn host(&self) -> Host {
            Host::new(self.root.clone(), Vec::new())
        }

        fn hooks(&self) -> PathBuf {
            self.root.join(".codex/hooks.json")
        }

        fn config(&self) -> PathBuf {
            self.root.join(".codex/config.toml")
        }

        /// The user's own hooks file and config layer, with a pin of the
        /// user's own for the user's own group.
        fn with_users_own(self) -> Home {
            std::fs::write(self.hooks(), USERS_HOOKS).expect("a hooks file");
            std::fs::write(self.config(), self.users_config()).expect("a config layer");
            self
        }

        /// The key and hash Codex filed the user's own handler under.
        fn users_pin(&self) -> (String, String) {
            let document = hooks_document(&self.host(), &self.hooks(), USERS_HOOKS)
                .expect("the user's hooks file");
            let handler = hooks::handlers(&document, "hooks")
                .into_iter()
                .next()
                .expect("the user's handler");
            (
                hooks::state_key(&self.hooks(), &handler),
                hooks::pin_hash(&handler).expect("a command handler"),
            )
        }

        fn users_config(&self) -> String {
            let (key, hash) = self.users_pin();
            format!(
                "# The user's own layer. Nothing here is a real endpoint.\n\
                 model = \"gpt-5-codex\"\n\
                 \n\
                 [features]\n\
                 hooks = true\n\
                 \n\
                 # Trusted by the user in the review.\n\
                 [hooks.state.\"{key}\"]\n\
                 trusted_hash = \"{hash}\"\n\
                 \n\
                 [mcp_servers.notes]\n\
                 command = \"npx\"\n\
                 args = [\"-y\", \"notes-server\"]\n\
                 \n\
                 # Shown in the terminal.\n\
                 [tui]\n\
                 notifications = true\n"
            )
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// A user hooks file with a group of the user's own, written with two
    /// spaces as Codex's own examples are.
    const USERS_HOOKS: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/.codex/lint.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
"#;

    fn command() -> GateCommand {
        GateCommand::at(CLI)
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("the file")).expect("JSON")
    }

    fn state(path: &Path) -> Value {
        state_of(&std::fs::read_to_string(path).expect("the layer")).expect("TOML")
    }

    /// The table headers of a layer and its comment lines, in order.
    fn shape(text: &str) -> Vec<String> {
        text.lines()
            .filter(|line| line.starts_with('[') || line.starts_with('#'))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn registering_appends_two_groups_and_two_pins_and_moves_nothing_else() {
        let home = Home::new().with_users_own();
        let config_before = home.users_config();
        let (users_key, users_hash) = home.users_pin();
        let adapter = Codex::new();

        let written = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("registered")
            .written;

        assert_eq!(written.len(), 2, "{written:?}");
        let after = read_json(&home.hooks());
        let before: Value = serde_json::from_str(USERS_HOOKS).expect("JSON");
        let pre = after["hooks"]["PreToolUse"].as_array().expect("groups");
        assert_eq!(pre.len(), 2);
        assert_eq!(
            pre[0], before["hooks"]["PreToolUse"][0],
            "the user's own first"
        );
        let ours = json!({
            "type": "command",
            "command": format!("'{CLI}' gate --agent codex"),
            "timeout": 5
        });
        assert_eq!(
            pre[1],
            json!({"matcher": "Bash|mcp__.*", "hooks": [ours.clone()]})
        );
        assert_eq!(
            after["hooks"]["UserPromptSubmit"],
            json!([{"hooks": [ours.clone()]}])
        );

        let records = state(&home.config());
        let records = records.as_object().expect("records");
        assert_eq!(records.len(), 3, "the user's pin and the two of the Gate");
        assert_eq!(records[&users_key]["trusted_hash"], users_hash.as_str());
        let hooks_path = home.hooks().display().to_string();
        for key in [
            format!("{hooks_path}:pre_tool_use:1:0"),
            format!("{hooks_path}:user_prompt_submit:0:0"),
        ] {
            assert!(records.contains_key(&key), "no record under {key}");
        }

        let config_after = std::fs::read_to_string(home.config()).expect("the layer");
        let gate_headers = |text: &str| {
            shape(text)
                .into_iter()
                .filter(|line| {
                    !line.contains(":pre_tool_use:1:0") && !line.contains(":user_prompt_submit:0:0")
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            gate_headers(&config_after),
            shape(&config_before),
            "every comment and every table where it was"
        );
        for line in config_before.lines() {
            assert!(config_after.contains(line), "{line} went missing");
        }

        // Registering again finds every entry in place and writes nothing.
        let hooks_now = std::fs::read_to_string(home.hooks()).expect("the hooks file");
        let again = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("nothing to do")
            .written;
        assert!(again.is_empty(), "{again:?}");
        assert_eq!(
            std::fs::read_to_string(home.hooks()).expect("the file"),
            hooks_now
        );
        assert_eq!(
            std::fs::read_to_string(home.config()).expect("the file"),
            config_after
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );
    }

    /// The pin is the adapter's own computation for the handler written, by
    /// key and by hash, and the recipe is spelled out once more by hand so the
    /// two cannot drift together; the enumeration reads both Hook Items as
    /// active, by the id and the hash the registration named.
    #[test]
    fn the_pin_written_is_the_adapters_own_and_both_hook_items_are_active() {
        let home = Home::new().with_users_own();
        let adapter = Codex::new();
        let written = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("registered")
            .written;

        let text = std::fs::read_to_string(home.hooks()).expect("the hooks file");
        let document = hooks_document(&home.host(), &home.hooks(), &text).expect("JSON");
        let records = state(&home.config());
        let gate: Vec<Handler> = hooks::handlers(&document, "hooks")
            .into_iter()
            .filter(|found| {
                found.handler["command"]
                    .as_str()
                    .is_some_and(|c| c.contains("gate --agent codex"))
            })
            .collect();
        assert_eq!(gate.len(), 2);
        for handler in &gate {
            let key = hooks::state_key(&home.hooks(), handler);
            assert_eq!(
                records[&key]["trusted_hash"].as_str(),
                hooks::pin_hash(handler).as_deref(),
                "{key}"
            );
            assert_eq!(hooks::pin_of(&records, &key, handler), Pin::Trusted);
        }
        let by_hand = format!(
            "{{\"event_name\":\"pre_tool_use\",\"hooks\":[{{\"async\":false,\
             \"command\":\"'{CLI}' gate --agent codex\",\"timeout\":5,\"type\":\"command\"}}],\
             \"matcher\":\"Bash|mcp__.*\"}}"
        );
        let key = format!("{}:pre_tool_use:1:0", home.hooks().display());
        assert_eq!(
            records[&key]["trusted_hash"],
            format!("sha256:{}", sha256_hex(by_hand.as_bytes())).as_str()
        );
        let parsed: Value = serde_json::from_str(&by_hand).expect("JSON");
        assert_eq!(
            canonical_entry(&parsed),
            by_hand.as_bytes(),
            "sorted and compact"
        );

        let enumeration = adapter.enumerate(&home.host(), &[]);
        for entry in &written {
            let item = enumeration
                .items
                .iter()
                .find(|item| item.id == entry.item_id)
                .unwrap_or_else(|| panic!("{} is not enumerated", entry.item_id));
            assert_eq!(item.kind, Kind::Hook);
            assert_eq!(item.shape, Shape::Entry);
            assert_eq!(item.content_hash, entry.content_hash);
            assert_eq!(item.path, home.hooks());
            assert_eq!(item.activation, Activation::Active, "{}", entry.item_id);
            assert!(entry.item_id.as_str().ends_with(&entry.locator));
        }
    }

    /// Splits a command string the way a POSIX shell splits words, for the
    /// quoting this module writes: single quotes, a backslash outside them.
    fn shell_words(line: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut in_word = false;
        let mut quoted = false;
        let mut letters = line.chars();
        while let Some(letter) = letters.next() {
            match (quoted, letter) {
                (true, '\'') => quoted = false,
                (true, other) => word.push(other),
                (false, '\'') => {
                    quoted = true;
                    in_word = true;
                }
                (false, '\\') => {
                    word.extend(letters.next());
                    in_word = true;
                }
                (false, ' ') => {
                    if in_word {
                        words.push(std::mem::take(&mut word));
                        in_word = false;
                    }
                }
                (false, other) => {
                    word.push(other);
                    in_word = true;
                }
            }
        }
        if in_word {
            words.push(word);
        }
        words
    }

    #[test]
    fn a_bundle_path_with_a_space_stays_one_word_for_the_shell() {
        for program in [
            "/Applications/Agent Sweep.app/Contents/MacOS/agentsweep",
            "/Users/u/Apps/it's here/AgentSweep.app/Contents/MacOS/agentsweep",
        ] {
            let line = command_line(&GateCommand::at(program));
            assert_eq!(
                shell_words(&line),
                [program, "gate", "--agent", "codex"],
                "{line}"
            );
        }
        assert_eq!(
            command_line(&GateCommand::at(
                "/Applications/Agent Sweep.app/Contents/MacOS/agentsweep"
            )),
            "'/Applications/Agent Sweep.app/Contents/MacOS/agentsweep' gate --agent codex"
        );
    }

    #[test]
    fn removing_takes_away_the_two_groups_and_the_two_pins_and_nothing_else() {
        let home = Home::new().with_users_own();
        let adapter = Codex::new();
        let written = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("registered")
            .written;

        let removed = adapter
            .remove_gate(&home.host(), &Writer, &command())
            .expect("removed")
            .removed;

        assert_eq!(removed, written);
        assert_eq!(
            std::fs::read_to_string(home.hooks()).expect("the hooks file"),
            USERS_HOOKS
        );
        assert_eq!(
            std::fs::read_to_string(home.config()).expect("the layer"),
            home.users_config()
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Missing(vec![
                "UserPromptSubmit".to_string(),
                "PreToolUse".to_string()
            ])
        );
        let again = adapter
            .remove_gate(&home.host(), &Writer, &command())
            .expect("nothing to remove")
            .removed;
        assert!(again.is_empty());
    }

    #[test]
    fn missing_files_are_created_with_only_the_gates_groups_and_pins() {
        let home = Home::new();
        let adapter = Codex::new();
        let written = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("registered")
            .written;
        assert_eq!(written.len(), 2);
        let after = read_json(&home.hooks());
        assert_eq!(
            after["hooks"]
                .as_object()
                .expect("events")
                .keys()
                .collect::<Vec<_>>(),
            ["UserPromptSubmit", "PreToolUse"]
        );
        let hooks_path = home.hooks().display().to_string();
        assert_eq!(
            state(&home.config())
                .as_object()
                .expect("records")
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                format!("{hooks_path}:pre_tool_use:0:0"),
                format!("{hooks_path}:user_prompt_submit:0:0"),
            ])
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );

        adapter
            .remove_gate(&home.host(), &Writer, &command())
            .expect("removed");
        assert_eq!(
            std::fs::read_to_string(home.config()).expect("the layer"),
            ""
        );
    }

    /// A pin that no longer matches, or that the user switched off, is the
    /// check's failure and the next registration writes the pin alone.
    #[test]
    fn a_pin_that_does_not_match_is_written_again_and_nothing_else() {
        let home = Home::new().with_users_own();
        let adapter = Codex::new();
        adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("registered");
        let hooks_before = std::fs::read_to_string(home.hooks()).expect("the hooks file");
        let key = format!("{}:pre_tool_use:1:0", home.hooks().display());
        let pinned = std::fs::read_to_string(home.config()).expect("the layer");
        let hash = state(&home.config())[&key]["trusted_hash"]
            .as_str()
            .expect("a hash")
            .to_string();
        std::fs::write(home.config(), pinned.replace(&hash, "sha256:00")).expect("a stale pin");
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Missing(vec!["PreToolUse".to_string()])
        );

        let again = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("pinned again")
            .written;

        assert_eq!(again.len(), 1);
        assert!(again[0].locator.contains("#PreToolUse/"), "{:?}", again[0]);
        assert_eq!(
            std::fs::read_to_string(home.hooks()).expect("the file"),
            hooks_before
        );
        assert_eq!(state(&home.config())[&key]["trusted_hash"], hash.as_str());
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );
    }

    /// The files under the Codex home override are written and the default
    /// ones are not touched.
    #[test]
    fn the_codex_home_override_is_where_both_files_are_written() {
        let home = Home::new().with_users_own();
        let elsewhere = home.root.join("relocated");
        std::fs::create_dir_all(&elsewhere).expect("a relocated Codex home");
        let host = home.host().with_config_dir(AGENT_ID, elsewhere.clone());

        let written = Codex::new()
            .register_gate(&host, &Writer, &command())
            .expect("registered")
            .written;

        assert_eq!(written.len(), 2);
        assert!(
            written
                .iter()
                .all(|entry| entry.path == elsewhere.join("hooks.json"))
        );
        let hooks_path = elsewhere.join("hooks.json").display().to_string();
        assert!(
            state(&elsewhere.join("config.toml"))
                .as_object()
                .expect("records")
                .keys()
                .all(|key| key.starts_with(&hooks_path))
        );
        assert_eq!(
            std::fs::read_to_string(home.hooks()).expect("the default"),
            USERS_HOOKS
        );
        assert_eq!(
            std::fs::read_to_string(home.config()).expect("the default"),
            home.users_config()
        );
    }

    /// A config layer that does not parse refuses the registration before the
    /// hooks file is touched, so no unpinned group is left behind.
    #[test]
    fn a_config_layer_that_does_not_parse_refuses_before_anything_is_written() {
        let home = Home::new();
        std::fs::write(home.hooks(), USERS_HOOKS).expect("a hooks file");
        std::fs::write(home.config(), "model = ").expect("a broken layer");
        let adapter = Codex::new();
        let refused = adapter.register_gate(&home.host(), &Writer, &command());
        assert!(
            matches!(refused, Err(GateError::Unparseable { .. })),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read_to_string(home.hooks()).expect("the file"),
            USERS_HOOKS
        );
        assert_eq!(
            std::fs::read_to_string(home.config()).expect("the file"),
            "model = "
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Unreadable(home.config())
        );

        std::fs::write(home.config(), "").expect("an empty layer");
        std::fs::write(home.hooks(), "{ \"hooks\": ").expect("a broken hooks file");
        let refused = adapter.register_gate(&home.host(), &Writer, &command());
        assert!(
            matches!(refused, Err(GateError::Unparseable { .. })),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read_to_string(home.config()).expect("the file"),
            ""
        );
    }
}

#[cfg(test)]
mod check_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use agentsweep_core::adapter::SurfaceAdapter;
    use agentsweep_core::gate_registration::{WriteError, hash_now};
    use agentsweep_core::item::Activation;

    /// Where the bundle puts the command line interface, and where an older
    /// copy of the bundle put it. Nothing runs either.
    const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";
    const OLD_CLI: &str = "/Volumes/Old/AgentSweep.app/Contents/MacOS/agentsweep";

    struct Writer;

    impl SurfaceWriter for Writer {
        fn write_if_unchanged(
            &self,
            path: &Path,
            expected: Option<&str>,
            text: &str,
        ) -> Result<(), WriteError> {
            if hash_now(path).map_err(WriteError::Io)?.as_deref() != expected {
                return Err(WriteError::Changed);
            }
            std::fs::write(path, text).map_err(WriteError::Io)
        }
    }

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A temporary machine with an installed Codex and a stand-in for the
    /// administrator's directory beside its home. Nothing here touches the
    /// real machine.
    struct Machine {
        root: PathBuf,
    }

    impl Machine {
        fn new() -> Machine {
            let root = std::env::temp_dir().join(format!(
                "agentsweep-codex-gate-check-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("home/.codex")).expect("a Codex home");
            std::fs::create_dir_all(root.join("system/etc/codex")).expect("a managed directory");
            Machine { root }
        }

        fn host(&self) -> Host {
            Host::new(self.root.join("home"), Vec::new()).with_system_root(self.root.join("system"))
        }

        fn hooks(&self) -> PathBuf {
            self.root.join("home/.codex/hooks.json")
        }

        fn config(&self) -> PathBuf {
            self.root.join("home/.codex/config.toml")
        }

        fn write(&self, relative: &str, content: &str) {
            std::fs::write(self.root.join(relative), content).expect("a file");
        }
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn records(path: &Path) -> Value {
        state_of(&std::fs::read_to_string(path).unwrap_or_default()).expect("TOML")
    }

    /// The user's own `PreToolUse` group, appended after whatever is there,
    /// and pinned under the key Codex counts for it, as its review does.
    fn add_users_group(machine: &Machine) -> (String, String) {
        let users = json!({"matcher": "Bash", "hooks": [
            {"type": "command", "command": "bash ~/.codex/lint.sh", "timeout": 30}
        ]});
        let text = std::fs::read_to_string(machine.hooks()).unwrap_or_else(|_| "{}".to_string());
        let text =
            append_json(&text, &EntryPath::of(&["hooks", "PreToolUse"]), &users).expect("appended");
        std::fs::write(machine.hooks(), &text).expect("the hooks file");
        let document = hooks_document(&machine.host(), &machine.hooks(), &text).expect("JSON");
        let handler = hooks::handlers(&document, "hooks")
            .into_iter()
            .find(|found| found.handler["command"] == "bash ~/.codex/lint.sh")
            .expect("the user's handler");
        let key = hooks::state_key(&machine.hooks(), &handler);
        let hash = hooks::pin_hash(&handler).expect("a command handler");
        let config = std::fs::read_to_string(machine.config()).unwrap_or_default();
        let config = insert_toml(&config, &record_path(&key), &json!({"trusted_hash": hash}))
            .expect("a pin");
        std::fs::write(machine.config(), config).expect("the config layer");
        (key, hash)
    }

    /// The owner's decision of 2026-10-14 on Codex pin positions: removing
    /// AgentSweep's group moves the user's group after it one place up, and
    /// its pin goes with it under the new key with the same hash, so Codex
    /// still runs the user's hook.
    #[test]
    fn removal_refiles_the_pin_of_a_users_group_that_moved_up() {
        let machine = Machine::new();
        let adapter = Codex::new();
        adapter
            .register_gate(&machine.host(), &Writer, &GateCommand::at(CLI))
            .expect("registered");
        let (old_key, hash) = add_users_group(&machine);
        assert!(old_key.ends_with(":pre_tool_use:1:0"), "{old_key}");

        let removed = adapter
            .remove_gate(&machine.host(), &Writer, &GateCommand::at(CLI))
            .expect("removed");

        assert_eq!(removed.removed.len(), 2, "{removed:?}");
        assert_eq!(removed.pins_rekeyed, 1);
        let new_key = old_key.replace(":pre_tool_use:1:0", ":pre_tool_use:0:0");
        let after = records(&machine.config());
        assert_eq!(after[&new_key]["trusted_hash"], hash.as_str(), "{after}");
        assert!(after.get(&old_key).is_none(), "{after}");
        assert_eq!(after.as_object().map(|records| records.len()), Some(1));

        let enumeration = adapter.enumerate(&machine.host(), &[]);
        let users = enumeration
            .items
            .iter()
            .find(|item| item.id.as_str().contains("hooks.json#PreToolUse/Bash/"))
            .expect("the user's Hook Item");
        assert_eq!(users.activation, Activation::Active, "Codex trusts it");
    }

    /// The owner's decision of 2026-10-14: AgentSweep's groups under another
    /// path go, with their pins, the user's group behind them keeps its
    /// trust, and the fresh groups are pinned.
    #[test]
    fn registering_replaces_the_groups_under_another_cli_path() {
        let machine = Machine::new();
        let adapter = Codex::new();
        let before = adapter
            .register_gate(&machine.host(), &Writer, &GateCommand::at(OLD_CLI))
            .expect("registered under the old path")
            .written;
        let (_, hash) = add_users_group(&machine);
        assert!(matches!(
            adapter.check_gate(&machine.host(), &GateCommand::at(CLI)),
            GateCheck::Missing(_)
        ));

        let moved = adapter
            .register_gate(&machine.host(), &Writer, &GateCommand::at(CLI))
            .expect("registered under the new path");

        assert_eq!(moved.written.len(), 2, "{moved:?}");
        let mut removed = moved.removed.clone();
        let mut expected = before;
        removed.sort_by(|a, b| a.locator.cmp(&b.locator));
        expected.sort_by(|a, b| a.locator.cmp(&b.locator));
        assert_eq!(removed, expected);
        let text = std::fs::read_to_string(machine.hooks()).expect("the hooks file");
        assert!(!text.contains("/Volumes/Old"), "{text}");
        assert_eq!(
            adapter.check_gate(&machine.host(), &GateCommand::at(CLI)),
            GateCheck::Registered
        );
        let after = records(&machine.config());
        let users_key = format!("{}:pre_tool_use:0:0", machine.hooks().display());
        assert_eq!(after[&users_key]["trusted_hash"], hash.as_str(), "{after}");
        assert_eq!(after.as_object().map(|records| records.len()), Some(3));
    }

    /// `enabled = false` on the pin of AgentSweep's own entry is mended like
    /// any other failure of the pin.
    #[test]
    fn a_pin_switched_off_is_written_again() {
        let machine = Machine::new();
        let adapter = Codex::new();
        adapter
            .register_gate(&machine.host(), &Writer, &GateCommand::at(CLI))
            .expect("registered");
        let key = format!("{}:user_prompt_submit:0:0", machine.hooks().display());
        let text = std::fs::read_to_string(machine.config()).expect("the layer");
        let hash = records(&machine.config())[&key]["trusted_hash"].clone();
        let text = insert_toml(
            &text,
            &record_path(&key),
            &json!({"trusted_hash": hash, "enabled": false}),
        )
        .expect("switched off");
        std::fs::write(machine.config(), text).expect("the layer");
        assert_eq!(
            adapter.check_gate(&machine.host(), &GateCommand::at(CLI)),
            GateCheck::Missing(vec!["UserPromptSubmit".to_string()])
        );

        let mended = adapter
            .register_gate(&machine.host(), &Writer, &GateCommand::at(CLI))
            .expect("mended");

        assert_eq!(mended.written.len(), 1, "{mended:?}");
        assert!(records(&machine.config())[&key].get("enabled").is_none());
        assert_eq!(
            adapter.check_gate(&machine.host(), &GateCommand::at(CLI)),
            GateCheck::Registered
        );
    }

    #[test]
    fn managed_policy_that_drops_user_hooks_is_reported() {
        for (file, content) in [
            (
                "system/etc/codex/requirements.toml",
                "allow_managed_hooks_only = true\n",
            ),
            (
                "system/etc/codex/config.toml",
                "[features]\nhooks = false\n",
            ),
        ] {
            let machine = Machine::new();
            machine.write(file, content);
            assert_eq!(
                Codex::new().check_gate(&machine.host(), &GateCommand::at(CLI)),
                GateCheck::ManagedPolicy,
                "{file}"
            );
        }
    }

    /// The user layer's `[features] hooks = false` is the user's own choice:
    /// reported, never written.
    #[test]
    fn the_users_hooks_switch_is_reported_and_never_written() {
        let machine = Machine::new();
        machine.write("home/.codex/config.toml", "[features]\nhooks = false\n");
        let adapter = Codex::new();
        assert_eq!(
            adapter.check_gate(&machine.host(), &GateCommand::at(CLI)),
            GateCheck::SwitchedOffByUser
        );
        adapter
            .register_gate(&machine.host(), &Writer, &GateCommand::at(CLI))
            .expect("registered");
        let text = std::fs::read_to_string(machine.config()).expect("the layer");
        assert!(text.starts_with("[features]\nhooks = false\n"), "{text}");
        assert_eq!(
            adapter.check_gate(&machine.host(), &GateCommand::at(CLI)),
            GateCheck::SwitchedOffByUser
        );
    }
}
