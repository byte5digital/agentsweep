//! The Gate's own entries in the Claude Code user settings file.
//!
//! Spec section 7.2: three hook groups in the user settings file of the
//! effective config directory, `UserPromptSubmit` with no matcher,
//! `PreToolUse` with the matcher `Skill|Bash|mcp__.*` and
//! `UserPromptExpansion` with no matcher, each with one handler that runs the
//! in-bundle command line interface in exec form (the absolute path as
//! `command`, `gate --agent claude-code` as `args`, no shell) with an explicit
//! `timeout` of five seconds.
//!
//! Each group is appended after the groups already written, so nothing the
//! user registered moves. Another tool may append its own handler into a
//! group AgentSweep wrote, so AgentSweep's handler is recognised by the
//! handler itself, wherever it sits (spec section 7.6): a group is appended
//! only for an event that carries no handler of AgentSweep's under the Gate's
//! matcher. A handler that carries AgentSweep's arguments and timeout under
//! another command line interface path is AgentSweep's own entry after the
//! bundle moved, and registering takes it out, so there is exactly one
//! AgentSweep entry per event (the owner's decision of 2026-10-14). An entry
//! edited in any other way is never repaired in place: a fresh one is
//! appended and the edited one stays, a Hook Item whose locator changed.
//! Removal takes out exactly AgentSweep's handlers, command, arguments and
//! timeout alike, and a group only when that left it empty; another tool's
//! handler in a shared group stays where it is. Every entry written or taken
//! away is named by the id and hash the enumeration gives its Hook Item,
//! which is what the daemon records.
//!
//! The check also reads what switches hooks off. A managed
//! `allowManagedHooksOnly` or `disableAllHooks` is managed policy, and
//! nothing is written; a User-scope `disableAllHooks` is the user's own
//! choice, which AgentSweep reports and never writes (spec section 7.6 as
//! amended on 2026-10-14).

use std::collections::BTreeSet;
use std::path::PathBuf;

use agentsweep_core::adapter::Enumeration;
use agentsweep_core::entry_edit::{EditError, EntryPath, append_json, drop_json_members};
use agentsweep_core::gate_registration::{
    GATE_TIMEOUT_SECONDS, GateCheck, GateCommand, GateEntry, GateError, GateWrite, SurfaceWriter,
    rewrite,
};
use agentsweep_core::host::Host;
use agentsweep_core::item::{ItemId, Kind, Scope, sha256_hex};
use serde_json::{Value, json};

use crate::document::{Document, surface_name};
use crate::{AGENT_ID, ClaudeCode, USER_SETTINGS_FILE, hooks};

/// The matcher of the `PreToolUse` group: a skill call, a shell command and
/// every MCP tool.
pub const PRE_TOOL_USE_MATCHER: &str = "Skill|Bash|mcp__.*";

/// The events the Gate listens on, each with the matcher its group carries.
pub const EVENTS: [(&str, Option<&str>); 3] = [
    ("UserPromptSubmit", None),
    ("PreToolUse", Some(PRE_TOOL_USE_MATCHER)),
    ("UserPromptExpansion", None),
];

/// The handler every Gate group holds, keys in the order they are written.
pub fn handler(command: &GateCommand) -> Value {
    json!({
        "type": "command",
        "command": command.program.display().to_string(),
        "args": GateCommand::arguments(AGENT_ID),
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

/// True when `handler`, under `event`, is AgentSweep's own: exactly the
/// handler the Gate writes, under one of the Gate's events, whatever group it
/// sits in and whatever else that group holds.
fn is_ours(event: &str, handler: &Value, ours: &Value) -> bool {
    EVENTS.iter().any(|(name, _)| *name == event) && handler == ours
}

/// The user settings file of the effective config directory.
fn settings_file(adapter: &ClaudeCode, host: &Host) -> Result<PathBuf, GateError> {
    adapter
        .config_dir(host)
        .map(|directory| directory.join(USER_SETTINGS_FILE))
        .ok_or(GateError::NoConfigDirectory)
}

/// The document as the enumeration would read it from this text.
fn document(host: &Host, path: &std::path::Path, text: &str) -> Result<Document, EditError> {
    let value: Value =
        serde_json::from_str(text).map_err(|error| EditError::Unparseable(error.to_string()))?;
    Ok(Document {
        path: path.to_path_buf(),
        surface: surface_name(host, &Scope::User, path),
        value,
    })
}

/// True when a handler sits under the matcher the Gate gives its event.
fn under_gate_matcher(event: &str, matcher: &str) -> bool {
    EVENTS
        .iter()
        .any(|(name, gate)| *name == event && matcher == gate.unwrap_or_default())
}

/// The events that carry AgentSweep's handler, unchanged, under the matcher
/// the Gate gives them, whether its group holds it alone or shares it.
fn registered_events(document: &Document, command: &GateCommand) -> BTreeSet<&'static str> {
    let ours = handler(command);
    let mut found = BTreeSet::new();
    for handler in hooks::handlers(document) {
        for (event, matcher) in EVENTS {
            if handler.event == event
                && handler.matcher == matcher.unwrap_or_default()
                && handler.handler == ours
            {
                found.insert(event);
            }
        }
    }
    found
}

/// True when `handler`, in `group` under `event`, carries AgentSweep's
/// arguments and timeout under the matcher the Gate gives the event, but runs
/// a command line interface at another path. That is AgentSweep's own entry
/// after the bundle moved, and the registration replaces it (the owner's
/// decision of 2026-10-14), whatever else the group holds.
fn is_moved(event: &str, group: &Value, handler: &Value, ours: &Value) -> bool {
    let Some((_, matcher)) = EVENTS.iter().find(|(name, _)| *name == event) else {
        return false;
    };
    if group.get("matcher").and_then(Value::as_str) != *matcher {
        return false;
    }
    let Some(fields) = handler.as_object() else {
        return false;
    };
    fields.len() == 4
        && handler.get("type") == ours.get("type")
        && handler.get("args") == ours.get("args")
        && handler.get("timeout") == ours.get("timeout")
        && handler.get("command").is_some_and(Value::is_string)
        && handler.get("command") != ours.get("command")
}

/// The Gate's events that carry a handler of AgentSweep's under another path.
fn moved_events(document: &Document, command: &GateCommand) -> BTreeSet<&'static str> {
    let ours = handler(command);
    let carries = |event: &str, group: &Value| {
        group
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|handlers| {
                handlers
                    .iter()
                    .any(|handler| is_moved(event, group, handler, &ours))
            })
    };
    EVENTS
        .iter()
        .map(|(event, _)| *event)
        .filter(|event| {
            document
                .value
                .get("hooks")
                .and_then(|hooks| hooks.get(*event))
                .and_then(Value::as_array)
                .is_some_and(|groups| groups.iter().any(|group| carries(event, group)))
        })
        .collect()
}

/// The handlers `picks` takes, given the event, the group they sit in and
/// the handler itself, as Hook Items.
fn entries_where(
    document: &Document,
    picks: &dyn Fn(&str, &Value, &Value) -> bool,
) -> Vec<GateEntry> {
    hooks::handlers(document)
        .into_iter()
        .filter(|found| {
            document
                .value
                .get("hooks")
                .and_then(|hooks| hooks.get(&found.event))
                .and_then(|groups| groups.get(found.group_index))
                .is_some_and(|group| picks(&found.event, group, &found.handler))
        })
        .map(|found| {
            let locator = found.locator(document);
            GateEntry {
                item_id: ItemId::new(AGENT_ID, &Scope::User, Kind::Hook, &locator),
                locator,
                content_hash: sha256_hex(&found.content()),
                path: document.path.clone(),
            }
        })
        .collect()
}

/// Takes out every handler that is AgentSweep's under another path, a group
/// only when that left it empty, appends a group for every event that does
/// not carry AgentSweep's handler unchanged, and names the entries written
/// and taken away.
pub fn register(
    adapter: &ClaudeCode,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<GateWrite, GateError> {
    let path = settings_file(adapter, host)?;
    let ours = handler(command);
    let written = rewrite(host, writer, &path, &mut |current| {
        let mut text = current.unwrap_or("{}").to_string();
        let moved =
            |event: &str, group: &Value, handler: &Value| is_moved(event, group, handler, &ours);
        let removed = entries_where(&document(host, &path, &text)?, &moved);
        for (event, _) in EVENTS {
            (text, _) = drop_json_members(
                &text,
                &EntryPath::of(&["hooks", event]),
                "hooks",
                &|group, handler| moved(event, group, handler),
            )?;
        }
        let present = registered_events(&document(host, &path, &text)?, command);
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
        if appended.is_empty() && removed.is_empty() {
            return Ok(None);
        }
        let written = entries_where(&document(host, &path, &text)?, &|event, group, handler| {
            let matcher = group.get("matcher").and_then(Value::as_str);
            appended.contains(&event)
                && under_gate_matcher(event, matcher.unwrap_or_default())
                && *handler == ours
        });
        Ok(Some((
            text,
            GateWrite {
                written,
                removed,
                pins_rekeyed: 0,
            },
        )))
    })?;
    Ok(written.unwrap_or_default())
}

/// True when a managed settings file drops the user's hooks:
/// `allowManagedHooksOnly`, or `disableAllHooks`, which no lower layer can
/// set back.
fn managed_policy_blocks(adapter: &ClaudeCode, host: &Host) -> bool {
    adapter
        .managed_documents(host, &mut Enumeration::default())
        .iter()
        .any(|document| {
            document.flag("allowManagedHooksOnly") == Some(true)
                || document.flag("disableAllHooks") == Some(true)
        })
}

/// Whether every event carries AgentSweep's entry unchanged, and whether
/// managed policy or the user's own settings switch hooks off.
pub fn check(adapter: &ClaudeCode, host: &Host, command: &GateCommand) -> GateCheck {
    if managed_policy_blocks(adapter, host) {
        return GateCheck::ManagedPolicy;
    }
    let Ok(path) = settings_file(adapter, host) else {
        return GateCheck::Missing(EVENTS.iter().map(|(e, _)| e.to_string()).collect());
    };
    let text = match host.read(&path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "{}".to_string(),
        Err(_) => return GateCheck::Unreadable(path),
    };
    let Ok(document) = document(host, &path, &text) else {
        return GateCheck::Unreadable(path);
    };
    if document.flag("disableAllHooks") == Some(true) {
        return GateCheck::SwitchedOffByUser;
    }
    let present = registered_events(&document, command);
    let moved = moved_events(&document, command);
    let missing: Vec<String> = EVENTS
        .iter()
        .filter(|(event, _)| !present.contains(event) || moved.contains(event))
        .map(|(event, _)| event.to_string())
        .collect();
    match missing.is_empty() {
        true => GateCheck::Registered,
        false => GateCheck::Missing(missing),
    }
}

/// Takes out AgentSweep's handlers, a group only when that left it empty,
/// and names the entries taken away. Another tool's handler in a shared group
/// stays where it is.
pub fn remove(
    adapter: &ClaudeCode,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<GateWrite, GateError> {
    let path = settings_file(adapter, host)?;
    let ours = handler(command);
    let removed = rewrite(host, writer, &path, &mut |current| {
        let Some(current) = current else {
            return Ok(None);
        };
        let entries = entries_where(&document(host, &path, current)?, &|event, _, handler| {
            is_ours(event, handler, &ours)
        });
        if entries.is_empty() {
            return Ok(None);
        }
        let mut text = current.to_string();
        for (event, _) in EVENTS {
            (text, _) = drop_json_members(
                &text,
                &EntryPath::of(&["hooks", event]),
                "hooks",
                &|_, handler| is_ours(event, handler, &ours),
            )?;
        }
        Ok(Some((text, entries)))
    })?;
    Ok(GateWrite {
        removed: removed.unwrap_or_default(),
        ..GateWrite::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    use agentsweep_core::adapter::SurfaceAdapter;
    use agentsweep_core::gate_registration::{WriteError, hash_now};
    use agentsweep_core::item::Shape;

    /// Where the bundle puts the command line interface. It does not exist on
    /// the machine the test runs on, and nothing runs it.
    const CLI: &str = "/Applications/AgentSweep.app/Contents/MacOS/agentsweep";

    /// The compare and the write, as the daemon's writer does them, and
    /// optionally somebody else's edit between the read and the write.
    struct Writer {
        interfere: Cell<usize>,
    }

    impl Writer {
        fn plain() -> Writer {
            Writer {
                interfere: Cell::new(0),
            }
        }
    }

    impl SurfaceWriter for Writer {
        fn write_if_unchanged(
            &self,
            path: &Path,
            expected: Option<&str>,
            text: &str,
        ) -> Result<(), WriteError> {
            if self.interfere.get() > 0 {
                self.interfere.set(self.interfere.get() - 1);
                let before = std::fs::read_to_string(path).unwrap_or_default();
                std::fs::write(path, before.replacen("\"opus", "\"opus+", 1)).expect("an edit");
            }
            if hash_now(path).map_err(WriteError::Io)?.as_deref() != expected {
                return Err(WriteError::Changed);
            }
            std::fs::write(path, text).map_err(WriteError::Io)
        }
    }

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A temporary home with an installed Claude Code. Nothing here touches
    /// the real machine.
    struct Home {
        root: PathBuf,
    }

    impl Home {
        fn new() -> Home {
            let root = std::env::temp_dir().join(format!(
                "agentsweep-claude-code-gate-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join(".claude")).expect("a config directory");
            Home { root }
        }

        fn host(&self) -> Host {
            Host::new(self.root.clone(), Vec::new())
        }

        fn settings(&self) -> PathBuf {
            self.root.join(".claude/settings.json")
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn command() -> GateCommand {
        GateCommand::at(CLI)
    }

    /// A user settings file with other keys and a hook group of the user's
    /// own, written the way Claude Code writes it.
    const USERS_OWN: &str = r#"{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/lint.sh",
            "timeout": 30
          }
        ]
      }
    ]
  },
  "permissions": {
    "allow": [
      "Bash(cargo test *)"
    ]
  }
}
"#;

    fn read(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("the file")).expect("JSON")
    }

    fn keys(value: &Value) -> Vec<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn registering_appends_three_groups_after_the_users_own_and_moves_nothing_else() {
        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let adapter = ClaudeCode::new();

        let written = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered")
            .written;

        assert_eq!(written.len(), 3, "{written:?}");
        let after = read(&home.settings());
        let before: Value = serde_json::from_str(USERS_OWN).expect("JSON");
        assert_eq!(keys(&after), ["model", "hooks", "permissions"]);
        assert_eq!(after["model"], before["model"]);
        assert_eq!(after["permissions"], before["permissions"]);
        assert_eq!(
            keys(&after["hooks"]),
            ["PreToolUse", "UserPromptSubmit", "UserPromptExpansion"]
        );
        let pre = after["hooks"]["PreToolUse"].as_array().expect("groups");
        assert_eq!(pre.len(), 2);
        assert_eq!(
            pre[0], before["hooks"]["PreToolUse"][0],
            "the user's own group first"
        );
        let ours = json!({
            "type": "command",
            "command": CLI,
            "args": ["gate", "--agent", "claude-code"],
            "timeout": 5
        });
        assert_eq!(
            pre[1],
            json!({"matcher": "Skill|Bash|mcp__.*", "hooks": [ours.clone()]})
        );
        for event in ["UserPromptSubmit", "UserPromptExpansion"] {
            assert_eq!(
                after["hooks"][event],
                json!([{"hooks": [ours.clone()]}]),
                "{event}"
            );
        }
        assert_eq!(
            keys(&pre[1]["hooks"][0]),
            ["type", "command", "args", "timeout"]
        );
        let text = std::fs::read_to_string(home.settings()).expect("the file");
        assert!(text.starts_with("{\n  \"model\": \"opus\",\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash\""), "{text}");
        assert!(text.ends_with("}\n"));

        // Registering again finds every entry in place and writes nothing.
        let again = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("nothing to do")
            .written;
        assert!(again.is_empty(), "{again:?}");
        assert_eq!(read(&home.settings()), after);
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );
    }

    /// The entries named are the Hook Items the enumeration yields, by id and
    /// by hash, so the events the daemon records stand behind exactly them.
    #[test]
    fn the_entries_written_are_the_hook_items_the_enumeration_yields() {
        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let adapter = ClaudeCode::new();
        let written = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered")
            .written;

        let enumeration = adapter.enumerate(&home.host(), &[]);
        let hooks: Vec<_> = enumeration
            .items
            .iter()
            .filter(|item| item.kind == Kind::Hook && item.shape == Shape::Entry)
            .collect();
        assert_eq!(hooks.len(), 4, "the user's own and the three of the Gate");
        for entry in &written {
            let item = hooks
                .iter()
                .find(|item| item.id == entry.item_id)
                .unwrap_or_else(|| panic!("{} is not enumerated", entry.item_id));
            assert_eq!(item.content_hash, entry.content_hash);
            assert_eq!(item.path, home.settings());
            assert!(entry.item_id.as_str().ends_with(&entry.locator));
        }
    }

    #[test]
    fn a_missing_settings_file_is_created_with_only_the_three_groups() {
        let home = Home::new();
        let written = ClaudeCode::new()
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered")
            .written;
        assert_eq!(written.len(), 3);
        let after = read(&home.settings());
        assert_eq!(keys(&after), ["hooks"]);
        assert_eq!(
            keys(&after["hooks"]),
            ["UserPromptSubmit", "PreToolUse", "UserPromptExpansion"]
        );
        for event in ["UserPromptSubmit", "PreToolUse", "UserPromptExpansion"] {
            assert_eq!(after["hooks"][event].as_array().expect("groups").len(), 1);
        }
    }

    /// The file under the AgentSweep config-dir override is written and the
    /// default one is not touched.
    #[test]
    fn the_config_dir_override_is_the_file_written() {
        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let elsewhere = home.root.join("relocated");
        std::fs::create_dir_all(&elsewhere).expect("a relocated config directory");
        let host = home.host().with_config_dir(AGENT_ID, elsewhere.clone());

        let written = ClaudeCode::new()
            .register_gate(&host, &Writer::plain(), &command())
            .expect("registered")
            .written;

        assert!(
            written
                .iter()
                .all(|entry| entry.path == elsewhere.join("settings.json"))
        );
        assert_eq!(keys(&read(&elsewhere.join("settings.json"))), ["hooks"]);
        assert_eq!(
            std::fs::read_to_string(home.settings()).expect("the default file"),
            USERS_OWN
        );
    }

    /// Spec section 5.3: a change between the read and the write is read once
    /// more; a second one fails the write and the change stays as written.
    #[test]
    fn a_file_that_changes_under_the_write_is_read_once_more_then_left_alone() {
        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let adapter = ClaudeCode::new();

        let once = Writer {
            interfere: Cell::new(1),
        };
        let written = adapter
            .register_gate(&home.host(), &once, &command())
            .expect("written on the second read")
            .written;
        assert_eq!(written.len(), 3);
        assert_eq!(
            read(&home.settings())["model"],
            "opus+",
            "the other change is kept"
        );

        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let always = Writer {
            interfere: Cell::new(2),
        };
        let failed = adapter.register_gate(&home.host(), &always, &command());
        assert!(
            matches!(failed, Err(GateError::FileIsChanging { .. })),
            "{failed:?}"
        );
        let left = std::fs::read_to_string(home.settings()).expect("the file");
        assert_eq!(
            left,
            USERS_OWN.replacen("\"opus", "\"opus++", 1),
            "never written over"
        );
    }

    #[test]
    fn a_settings_file_that_does_not_parse_is_never_written_over() {
        let home = Home::new();
        std::fs::write(home.settings(), "{ \"model\": ").expect("a broken file");
        let adapter = ClaudeCode::new();
        let refused = adapter.register_gate(&home.host(), &Writer::plain(), &command());
        assert!(
            matches!(refused, Err(GateError::Unparseable { .. })),
            "{refused:?}"
        );
        let refused = adapter.remove_gate(&home.host(), &Writer::plain(), &command());
        assert!(
            matches!(refused, Err(GateError::Unparseable { .. })),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read_to_string(home.settings()).expect("the file"),
            "{ \"model\": "
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Unreadable(home.settings())
        );
    }

    #[test]
    fn removing_takes_away_the_three_groups_and_nothing_else() {
        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let adapter = ClaudeCode::new();
        let written = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered")
            .written;

        let removed = adapter
            .remove_gate(&home.host(), &Writer::plain(), &command())
            .expect("removed")
            .removed;

        assert_eq!(removed, written);
        assert_eq!(
            std::fs::read_to_string(home.settings()).expect("the file"),
            USERS_OWN
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Missing(vec![
                "UserPromptSubmit".to_string(),
                "PreToolUse".to_string(),
                "UserPromptExpansion".to_string()
            ])
        );
        let again = adapter
            .remove_gate(&home.host(), &Writer::plain(), &command())
            .expect("nothing to remove")
            .removed;
        assert!(again.is_empty());
    }

    /// A group whose handler differs from AgentSweep's in command, arguments
    /// or timeout is not AgentSweep's to take away. From a group where
    /// AgentSweep's handler sits beside one of the user's, only AgentSweep's
    /// handler goes and the group stays with the user's.
    #[test]
    fn removing_leaves_every_handler_that_is_not_exactly_agentsweeps() {
        let home = Home::new();
        let ours = handler(&command());
        let mut other_timeout = ours.clone();
        other_timeout["timeout"] = json!(6);
        let mut other_args = ours.clone();
        other_args["args"] = json!(["gate", "--agent", "codex"]);
        let mut other_command = ours.clone();
        other_command["command"] = json!("/opt/elsewhere/agentsweep");
        let shared = json!({"hooks": [ours.clone(), {"type": "command", "command": "./mine.sh"}]});
        let file = json!({"hooks": {"UserPromptSubmit": [
            {"hooks": [other_timeout]},
            {"hooks": [other_args]},
            {"hooks": [other_command]},
            shared,
            {"hooks": [ours]}
        ]}});
        let text = format!("{}\n", serde_json::to_string_pretty(&file).expect("JSON"));
        std::fs::write(home.settings(), &text).expect("a settings file");

        let removed = ClaudeCode::new()
            .remove_gate(&home.host(), &Writer::plain(), &command())
            .expect("removed")
            .removed;

        assert_eq!(removed.len(), 2);
        let after = read(&home.settings());
        let mut expected = file.clone();
        let groups = expected["hooks"]["UserPromptSubmit"]
            .as_array_mut()
            .expect("groups");
        groups.pop();
        groups[3] = json!({"hooks": [{"type": "command", "command": "./mine.sh"}]});
        assert_eq!(after, expected);
    }

    /// Another tool's handler, the way a tool that installs hooks on every
    /// event writes one. Nothing runs it.
    fn theirs() -> Value {
        json!({"type": "command", "command": "/usr/local/bin/othertool hook claude", "timeout": 10})
    }

    /// How many of AgentSweep's handlers each event of the file holds.
    fn count_ours(value: &Value) -> Vec<(String, usize)> {
        let ours = handler(&command());
        EVENTS
            .iter()
            .map(|(event, _)| {
                let count = value["hooks"][*event]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
                    .filter(|found| **found == ours)
                    .count();
                (event.to_string(), count)
            })
            .collect()
    }

    /// A group another tool shares with AgentSweep's handler, in either
    /// order: registering twice adds no second handler of AgentSweep's, and
    /// removing takes out AgentSweep's handler alone, leaving the other
    /// tool's handler in its group (spec section 7.6).
    #[test]
    fn a_shared_group_gets_no_second_handler_and_keeps_the_other_tools_on_removal() {
        for theirs_first in [false, true] {
            let home = Home::new();
            let adapter = ClaudeCode::new();
            let ours = handler(&command());
            let shared = match theirs_first {
                true => json!([theirs(), ours.clone()]),
                false => json!([ours.clone(), theirs()]),
            };
            let file = json!({"model": "opus", "hooks": {
                "UserPromptSubmit": [{"hooks": shared}],
                "PreToolUse": [{"matcher": PRE_TOOL_USE_MATCHER, "hooks": [ours.clone()]}]
            }});
            std::fs::write(
                home.settings(),
                format!("{}\n", serde_json::to_string_pretty(&file).expect("JSON")),
            )
            .expect("a settings file");

            let first = adapter
                .register_gate(&home.host(), &Writer::plain(), &command())
                .expect("registered");
            let second = adapter
                .register_gate(&home.host(), &Writer::plain(), &command())
                .expect("nothing to do");

            assert_eq!(first.written.len(), 1, "UserPromptExpansion alone");
            assert!(second.is_empty(), "{second:?}");
            let registered = read(&home.settings());
            assert_eq!(
                count_ours(&registered),
                vec![
                    ("UserPromptSubmit".to_string(), 1),
                    ("PreToolUse".to_string(), 1),
                    ("UserPromptExpansion".to_string(), 1),
                ],
                "theirs first: {theirs_first}"
            );
            assert_eq!(
                adapter.check_gate(&home.host(), &command()),
                GateCheck::Registered
            );

            let removed = adapter
                .remove_gate(&home.host(), &Writer::plain(), &command())
                .expect("removed");

            assert_eq!(removed.removed.len(), 3, "{removed:?}");
            assert_eq!(
                read(&home.settings()),
                json!({"model": "opus", "hooks": {"UserPromptSubmit": [{"hooks": [theirs()]}]}}),
                "theirs first: {theirs_first}"
            );
            assert!(
                adapter
                    .remove_gate(&home.host(), &Writer::plain(), &command())
                    .expect("nothing to remove")
                    .is_empty()
            );
        }
    }

    /// AgentSweep's handler under another path inside a shared group is
    /// replaced: it goes, the other tool's handler stays in its group, and
    /// the fresh handler comes in a group of its own.
    #[test]
    fn registering_replaces_a_handler_under_another_path_inside_a_shared_group() {
        let home = Home::new();
        let old = handler(&GateCommand::at(
            "/Volumes/Old/AgentSweep.app/Contents/MacOS/agentsweep",
        ));
        let file = json!({"hooks": {"UserPromptSubmit": [{"hooks": [old, theirs()]}]}});
        std::fs::write(
            home.settings(),
            serde_json::to_string_pretty(&file).expect("JSON"),
        )
        .expect("a settings file");
        let adapter = ClaudeCode::new();

        let moved = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered under the new path");

        assert_eq!(moved.removed.len(), 1, "{moved:?}");
        assert_eq!(moved.written.len(), 3, "{moved:?}");
        let after = read(&home.settings());
        assert_eq!(
            after["hooks"]["UserPromptSubmit"],
            json!([{"hooks": [theirs()]}, {"hooks": [handler(&command())]}])
        );
        assert!(!after.to_string().contains("/Volumes/Old"), "{after}");
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );
    }

    /// The default of the trait: an adapter that has not learned a Gate says
    /// so and writes nothing.
    #[test]
    fn the_workspace_adapter_has_no_gate() {
        let home = Home::new();
        let workspace = agentsweep_adapter_workspace::Workspace::new();
        assert_eq!(
            workspace.check_gate(&home.host(), &command()),
            GateCheck::NoGate
        );
        assert!(matches!(
            workspace.register_gate(&home.host(), &Writer::plain(), &command()),
            Err(GateError::NoGate)
        ));
        assert!(matches!(
            workspace.remove_gate(&home.host(), &Writer::plain(), &command()),
            Err(GateError::NoGate)
        ));
        assert!(!home.settings().exists());
    }

    /// The owner's decision of 2026-10-14: an entry with AgentSweep's
    /// arguments and timeout under another path is AgentSweep's after the
    /// bundle moved, and registering leaves exactly one entry per event.
    #[test]
    fn registering_replaces_the_entries_under_another_cli_path() {
        let home = Home::new();
        std::fs::write(home.settings(), USERS_OWN).expect("a settings file");
        let adapter = ClaudeCode::new();
        let old = GateCommand::at("/Volumes/Old/AgentSweep.app/Contents/MacOS/agentsweep");
        let before = adapter
            .register_gate(&home.host(), &Writer::plain(), &old)
            .expect("registered under the old path")
            .written;
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Missing(vec![
                "UserPromptSubmit".to_string(),
                "PreToolUse".to_string(),
                "UserPromptExpansion".to_string()
            ])
        );

        let moved = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered under the new path");

        assert_eq!(moved.written.len(), 3, "{moved:?}");
        let mut removed = moved.removed.clone();
        let mut expected = before.clone();
        removed.sort_by(|a, b| a.locator.cmp(&b.locator));
        expected.sort_by(|a, b| a.locator.cmp(&b.locator));
        assert_eq!(removed, expected);
        let after = read(&home.settings());
        let text = after.to_string();
        assert!(!text.contains("/Volumes/Old"), "{text}");
        assert_eq!(after["hooks"]["PreToolUse"][0]["matcher"], "Bash");
        for event in ["UserPromptSubmit", "PreToolUse", "UserPromptExpansion"] {
            let ours: Vec<&Value> = after["hooks"][event]
                .as_array()
                .expect("groups")
                .iter()
                .filter(|group| group["hooks"][0]["args"][0] == "gate")
                .collect();
            assert_eq!(ours.len(), 1, "{event}: {after}");
        }
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );
    }

    /// An entry edited in any other way is not repaired in place: a fresh one
    /// is appended and the edited one stays where it is.
    #[test]
    fn an_edited_entry_stays_beside_the_fresh_one() {
        let home = Home::new();
        let adapter = ClaudeCode::new();
        adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered");
        let mut file = read(&home.settings());
        file["hooks"]["UserPromptSubmit"][0]["hooks"][0]["timeout"] = json!(60);
        file["hooks"]["PreToolUse"][0]["hooks"][0]["args"] =
            json!(["gate", "--agent", "claude-code", "--quiet"]);
        std::fs::write(
            home.settings(),
            serde_json::to_string_pretty(&file).expect("JSON"),
        )
        .expect("an edit");
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Missing(vec![
                "UserPromptSubmit".to_string(),
                "PreToolUse".to_string()
            ])
        );

        let mended = adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("mended");

        assert_eq!(mended.written.len(), 2, "{mended:?}");
        assert!(mended.removed.is_empty(), "{mended:?}");
        let after = read(&home.settings());
        assert_eq!(
            after["hooks"]["UserPromptSubmit"][0],
            file["hooks"]["UserPromptSubmit"][0]
        );
        assert_eq!(
            after["hooks"]["PreToolUse"][0],
            file["hooks"]["PreToolUse"][0]
        );
        assert_eq!(
            after["hooks"]["UserPromptSubmit"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            after["hooks"]["PreToolUse"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::Registered
        );
    }

    fn managed_home(content: &str) -> (Home, Host) {
        let home = Home::new();
        let directory = home
            .root
            .join("system")
            .join(crate::MANAGED_DIRECTORY.trim_start_matches('/'));
        std::fs::create_dir_all(&directory).expect("a managed directory");
        std::fs::write(directory.join(crate::MANAGED_SETTINGS_FILE), content)
            .expect("a managed settings file");
        let host = home.host().with_system_root(home.root.join("system"));
        (home, host)
    }

    /// Managed policy that drops the user's hooks is reported; the check
    /// never says registered or missing there.
    #[test]
    fn managed_policy_that_drops_user_hooks_is_reported() {
        for policy in [
            "{\"allowManagedHooksOnly\": true}",
            "{\"disableAllHooks\": true}",
        ] {
            let (_home, host) = managed_home(policy);
            assert_eq!(
                ClaudeCode::new().check_gate(&host, &command()),
                GateCheck::ManagedPolicy,
                "{policy}"
            );
        }
        let (_home, host) = managed_home("{\"allowManagedHooksOnly\": false}");
        assert!(matches!(
            ClaudeCode::new().check_gate(&host, &command()),
            GateCheck::Missing(_)
        ));
    }

    /// A User-scope `disableAllHooks` is the user's own choice: the check
    /// reports it and registering never writes it.
    #[test]
    fn a_user_disable_all_hooks_is_reported_and_never_written() {
        let home = Home::new();
        std::fs::write(home.settings(), "{\n  \"disableAllHooks\": true\n}\n")
            .expect("a settings file");
        let adapter = ClaudeCode::new();
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::SwitchedOffByUser
        );
        adapter
            .register_gate(&home.host(), &Writer::plain(), &command())
            .expect("registered");
        let after = read(&home.settings());
        assert_eq!(after["disableAllHooks"], json!(true));
        assert_eq!(
            adapter.check_gate(&home.host(), &command()),
            GateCheck::SwitchedOffByUser
        );
    }
}
