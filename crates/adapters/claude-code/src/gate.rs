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
//! user registered moves. Removal takes away exactly the groups whose only
//! handler is AgentSweep's, command, arguments and timeout alike, and nothing
//! else. Every entry written or taken away is named by the id and hash the
//! enumeration gives its Hook Item, which is what the daemon records.

use std::collections::BTreeSet;
use std::path::PathBuf;

use agentsweep_core::entry_edit::{EditError, EntryPath, append_json, drop_json};
use agentsweep_core::gate_registration::{
    GATE_TIMEOUT_SECONDS, GateCheck, GateCommand, GateEntry, GateError, SurfaceWriter, rewrite,
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

/// True when a group holds AgentSweep's handler and nothing else.
fn is_ours(group: &Value, ours: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|handlers| handlers.len() == 1 && handlers[0] == *ours)
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

/// The events that carry AgentSweep's handler, unchanged, under the matcher
/// the Gate gives them.
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

/// The Gate entries of a document, in the events given, as Hook Items. A
/// handler of AgentSweep's in a group the user shares is not one of them.
fn entries(document: &Document, command: &GateCommand, events: &[&str]) -> Vec<GateEntry> {
    let ours = handler(command);
    hooks::handlers(document)
        .into_iter()
        .filter(|found| events.contains(&found.event.as_str()))
        .filter(|found| {
            document
                .value
                .get("hooks")
                .and_then(|hooks| hooks.get(&found.event))
                .and_then(|groups| groups.get(found.group_index))
                .is_some_and(|group| is_ours(group, &ours))
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

/// Appends a group for every event that does not carry AgentSweep's entry
/// unchanged, and names the entries written.
pub fn register(
    adapter: &ClaudeCode,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<Vec<GateEntry>, GateError> {
    let path = settings_file(adapter, host)?;
    let written = rewrite(host, writer, &path, &mut |current| {
        let mut text = current.unwrap_or("{}").to_string();
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
        if appended.is_empty() {
            return Ok(None);
        }
        let entries = entries(&document(host, &path, &text)?, command, &appended);
        Ok(Some((text, entries)))
    })?;
    Ok(written.unwrap_or_default())
}

/// Whether every event carries AgentSweep's entry unchanged.
pub fn check(adapter: &ClaudeCode, host: &Host, command: &GateCommand) -> GateCheck {
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
    let present = registered_events(&document, command);
    let missing: Vec<String> = EVENTS
        .iter()
        .filter(|(event, _)| !present.contains(event))
        .map(|(event, _)| event.to_string())
        .collect();
    match missing.is_empty() {
        true => GateCheck::Registered,
        false => GateCheck::Missing(missing),
    }
}

/// Takes away the groups whose only handler is AgentSweep's, and names the
/// entries taken away.
pub fn remove(
    adapter: &ClaudeCode,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<Vec<GateEntry>, GateError> {
    let path = settings_file(adapter, host)?;
    let ours = handler(command);
    let events: Vec<&str> = EVENTS.iter().map(|(event, _)| *event).collect();
    let removed = rewrite(host, writer, &path, &mut |current| {
        let Some(current) = current else {
            return Ok(None);
        };
        let entries = entries(&document(host, &path, current)?, command, &events);
        if entries.is_empty() {
            return Ok(None);
        }
        let mut text = current.to_string();
        for event in &events {
            (text, _) = drop_json(&text, &EntryPath::of(&["hooks", event]), &|group| {
                is_ours(group, &ours)
            })?;
        }
        Ok(Some((text, entries)))
    })?;
    Ok(removed.unwrap_or_default())
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
            .expect("registered");

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
            .expect("nothing to do");
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
            .expect("registered");

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
            .expect("registered");
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
            .expect("registered");

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
            .expect("written on the second read");
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
            .expect("registered");

        let removed = adapter
            .remove_gate(&home.host(), &Writer::plain(), &command())
            .expect("removed");

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
            .expect("nothing to remove");
        assert!(again.is_empty());
    }

    /// A group whose handler differs from AgentSweep's in command, arguments
    /// or timeout, and a group where AgentSweep's handler sits beside one of
    /// the user's, are not AgentSweep's to take away.
    #[test]
    fn removing_leaves_every_group_that_is_not_exactly_agentsweeps() {
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
            .expect("removed");

        assert_eq!(removed.len(), 1);
        let after = read(&home.settings());
        let mut expected = file.clone();
        expected["hooks"]["UserPromptSubmit"]
            .as_array_mut()
            .expect("groups")
            .pop();
        assert_eq!(after, expected);
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
}
