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

use agentsweep_core::entry_edit::{
    EditError, EntryPath, Format as EditFormat, append_json, drop_json, drop_toml, insert_toml,
    parses,
};
use agentsweep_core::gate_registration::{
    GATE_TIMEOUT_SECONDS, GateCheck, GateCommand, GateEntry, GateError, SurfaceWriter, rewrite,
};
use agentsweep_core::host::Host;
use agentsweep_core::item::{ItemId, Kind, Scope, sha256_hex};
use serde_json::{Value, json};

use crate::document::{Document, json_of, parse_toml, surface_name};
use crate::hooks::{self, Handler, Pin};
use crate::{AGENT_ID, CONFIG_FILE, Codex, HOOKS_FILE};

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
) -> Result<Vec<GateEntry>, GateError> {
    let files = files(adapter, host)?;
    config_parses(host, &files.config)?;

    // The groups first: the keys of their pins are counted from where they
    // end up, which is known only once the hooks file is written.
    let mut groups: Vec<Found> = Vec::new();
    let appended = rewrite(host, writer, &files.hooks, &mut |current| {
        let mut text = current.unwrap_or("{}").to_string();
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
        match appended.is_empty() {
            true => Ok(None),
            false => Ok(Some((text, appended))),
        }
    })?
    .unwrap_or_default();

    let pinned = rewrite(host, writer, &files.config, &mut |current| {
        let mut text = current.unwrap_or_default().to_string();
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
        match pinned.is_empty() {
            true => Ok(None),
            false => Ok(Some((text, pinned))),
        }
    })?
    .unwrap_or_default();

    Ok(groups
        .into_iter()
        .filter(|found| appended.contains(&found.event) || pinned.contains(&found.entry.item_id))
        .map(|found| found.entry)
        .collect())
}

/// Whether every event carries a Gate group whose pin Codex would trust.
pub fn check(adapter: &Codex, host: &Host, command: &GateCommand) -> GateCheck {
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
    let missing: Vec<String> = EVENTS
        .iter()
        .filter(|(event, _)| !trusted.contains(event))
        .map(|(event, _)| event.to_string())
        .collect();
    match missing.is_empty() {
        true => GateCheck::Registered,
        false => GateCheck::Missing(missing),
    }
}

/// Takes away the groups whose only handler is AgentSweep's and the pin
/// records filed under their keys, and names the entries taken away.
pub fn remove(
    adapter: &Codex,
    host: &Host,
    writer: &dyn SurfaceWriter,
    command: &GateCommand,
) -> Result<Vec<GateEntry>, GateError> {
    let files = files(adapter, host)?;
    config_parses(host, &files.config)?;
    let ours = handler(command);

    // The keys are counted on the hooks file as it was before the groups
    // went, which is where Codex filed the pins.
    let mut keys: Vec<String> = Vec::new();
    let removed = rewrite(host, writer, &files.hooks, &mut |current| {
        keys.clear();
        let Some(current) = current else {
            return Ok(None);
        };
        let found = ours_in(&hooks_document(host, &files.hooks, current)?, command);
        if found.is_empty() {
            return Ok(None);
        }
        keys = found.iter().map(|found| found.key.clone()).collect();
        let mut text = current.to_string();
        for (event, _) in EVENTS {
            (text, _) = drop_json(&text, &EntryPath::of(&["hooks", event]), &|group| {
                is_ours(group, &ours)
            })?;
        }
        let entries = found.into_iter().map(|found| found.entry).collect();
        Ok(Some((text, entries)))
    })?
    .unwrap_or_default();

    rewrite(host, writer, &files.config, &mut |current| {
        let Some(current) = current else {
            return Ok(None);
        };
        let mut text = current.to_string();
        let mut dropped_any = false;
        for key in &keys {
            let dropped;
            (text, dropped) = drop_toml(&text, &record_path(key))?;
            dropped_any |= dropped;
        }
        match dropped_any {
            true => Ok(Some((text, ()))),
            false => Ok(None),
        }
    })?;
    Ok(removed)
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
            .expect("registered");

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
            .expect("nothing to do");
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
            .expect("registered");

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
            .expect("registered");

        let removed = adapter
            .remove_gate(&home.host(), &Writer, &command())
            .expect("removed");

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
            .expect("nothing to remove");
        assert!(again.is_empty());
    }

    #[test]
    fn missing_files_are_created_with_only_the_gates_groups_and_pins() {
        let home = Home::new();
        let adapter = Codex::new();
        let written = adapter
            .register_gate(&home.host(), &Writer, &command())
            .expect("registered");
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
            .expect("pinned again");

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
            .expect("registered");

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
