//! The hook handlers a Codex layer registers, and the state pin that decides
//! whether one of them runs.
//!
//! A hooks block is three levels deep in both Agents: an event, the groups
//! registered for it, and the handlers of each group. The Item is the handler,
//! because that is what runs and what an attacker adds; the event and the
//! matcher travel with it because they say when it runs. Codex writes the block
//! either as `hooks.json` beside a config layer or as an inline `[hooks]` table
//! in that layer's `config.toml`, so the events sit at `hooks` in the one and
//! at `hooks.hooks` in the other, and the caller says which.
//!
//! The handlers are yielded in the order they are written and never sorted: a
//! group's position is not part of a hook's identity (spec section 4.6.1), so
//! reordering has to leave every AgentSweep id where it was. Codex's own state
//! key is the opposite: it is positional, so the group and handler index travel
//! with each handler as well.
//!
//! **The state pin.** A non-managed Codex hook runs only when
//! `[hooks.state."<key>"].trusted_hash` in the user `config.toml` equals the
//! hash Codex computes for the handler; a hook whose hash differs is `Modified`
//! and is silently not run, and one with no entry at all is `Untrusted`
//! (`docs/research/load-time-interception.md` section 3.3, verified against
//! five real pins). [`pin_hash`] reproduces that hash and [`state_key`] the key
//! it is filed under, which is what lets the adapter say Inactive with the
//! reason stale hook hash rather than guess.

use std::path::Path;

use agentsweep_core::item::{canonical_entry, sha256_hex};
use agentsweep_core::views::HookView;
use serde_json::{Map, Value, json};

use crate::document::Document;

/// The timeout Codex fills in when a command handler declares none. It is part
/// of the hashed identity, so it has to be written even when the file is
/// silent about it.
pub const DEFAULT_TIMEOUT_SECONDS: i64 = 600;

/// The additional-context limit Codex fills in when a command handler declares
/// none. Unlike the timeout it is left out of the hashed identity when it is
/// the default.
pub const DEFAULT_ADDITIONAL_CONTEXT_LIMIT: i64 = 2500;

/// One hook handler, with the event and the matcher it is registered under and
/// the position Codex's own state key counts from.
#[derive(Clone, Debug)]
pub struct Handler {
    /// The event that fires it.
    pub event: String,
    /// The matcher it is registered under, empty when the group declares none.
    pub matcher: String,
    /// True when the group wrote a matcher at all. Codex leaves the field out
    /// of the hashed identity when it did not, which is not the same as an
    /// empty one.
    pub has_matcher: bool,
    /// The position of the group within the event.
    pub group_index: usize,
    /// The position of the handler within the group.
    pub handler_index: usize,
    /// The handler itself, as it is written.
    pub handler: Value,
}

impl Handler {
    /// The locator of the Hook Item this handler is, in the document it was
    /// read from: `<file>#<event>/<matcher>/<hash prefix>` (spec section
    /// 4.6.1). The enumeration and the Gate's own writes name it the same way.
    pub fn locator(&self, document: &Document) -> String {
        format!(
            "{}#{}",
            document.surface,
            HookView::locator(&self.event, &self.matcher, &self.handler)
        )
    }

    /// The content the Hook Item is hashed over: the canonical normal form.
    pub fn content(&self) -> Vec<u8> {
        canonical_entry(&HookView::normal_form(
            &self.event,
            &self.matcher,
            &self.handler,
        ))
    }
}

/// Every hook handler a document registers under one key path, events in
/// sorted order and the handlers of one event in the order they are written.
///
/// `events_path` is `hooks` for a `hooks.json` file and `hooks.hooks` for the
/// inline table of a `config.toml`, where the `[hooks]` table carries the same
/// shape as the file plus Codex's own `state` records.
pub fn handlers(document: &Document, events_path: &str) -> Vec<Handler> {
    let mut found = Vec::new();
    for (event, groups) in document.members(events_path) {
        let Some(groups) = groups.as_array() else {
            continue;
        };
        for (group_index, group) in groups.iter().enumerate() {
            let written = group.get("matcher").and_then(Value::as_str);
            let Some(handlers) = group.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            for (handler_index, handler) in handlers.iter().enumerate() {
                found.push(Handler {
                    event: event.clone(),
                    matcher: written.unwrap_or_default().to_string(),
                    has_matcher: written.is_some(),
                    group_index,
                    handler_index,
                    handler: handler.clone(),
                });
            }
        }
    }
    found
}

/// What the user `config.toml` records about one registered handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pin {
    /// The recorded hash is the handler's: Codex runs it.
    Trusted,
    /// A hash is recorded and it is not this handler's. Codex calls the hook
    /// `Modified` and does not run it until it is reviewed again.
    Stale,
    /// The user switched the handler off with `enabled = false`.
    Disabled,
    /// Nothing is recorded for the handler. Codex calls it `Untrusted`: an
    /// interactive session offers to trust it at startup, a headless one skips
    /// it silently.
    Absent,
    /// The handler is of a kind whose normalised form AgentSweep cannot
    /// reproduce, so no comparison is honest.
    Unverifiable,
}

/// The state key Codex files a handler's trust under:
/// `<source>:<event in snake case>:<group index>:<handler index>`, where the
/// source is the hooks file as it is displayed.
///
/// The indices are positional, so inserting a group ahead of an existing one
/// renumbers it and invalidates its pin.
pub fn state_key(source: &Path, handler: &Handler) -> String {
    format!(
        "{}:{}:{}:{}",
        source.display(),
        snake_case(&handler.event),
        handler.group_index,
        handler.handler_index
    )
}

/// The hash Codex records as `trusted_hash`, absent when the handler is of a
/// kind whose normalised form is not part of the verified recipe.
///
/// The recipe (`docs/research/load-time-interception.md` section 3.3, verified
/// against five pins Codex 0.144.5 wrote): the identity
/// `{event_name, matcher?, hooks: [normalised handler]}` with every absent
/// field left out, rendered with its object keys sorted and without
/// insignificant whitespace, hashed with sha256 and prefixed `sha256:`. The
/// command is hashed as it is written, with no environment substitution.
pub fn pin_hash(handler: &Handler) -> Option<String> {
    let identity = identity(handler)?;
    Some(format!(
        "sha256:{}",
        sha256_hex(&canonical_entry(&identity))
    ))
}

/// The identity Codex hashes, absent for a handler that is not a command.
fn identity(handler: &Handler) -> Option<Value> {
    let normalised = normalised_command_handler(&handler.handler)?;
    let mut identity = Map::new();
    identity.insert("event_name".to_string(), json!(snake_case(&handler.event)));
    if handler.has_matcher {
        identity.insert("matcher".to_string(), json!(handler.matcher));
    }
    identity.insert("hooks".to_string(), json!([normalised]));
    Some(Value::Object(identity))
}

/// One command handler in the form Codex hashes: the type and the command, the
/// effective timeout and the async flag always written, the status message
/// when there is one and the context limit only when it is not the default.
///
/// A `prompt` or `agent` handler is parsed and then skipped by Codex, and the
/// normalised form of an `mcp_tool` handler is not part of the verified
/// recipe, so neither yields an identity to compare against.
fn normalised_command_handler(handler: &Value) -> Option<Value> {
    let command = field(handler, "command")?;
    let declared = handler.get("type").and_then(Value::as_str).unwrap_or("");
    if !declared.is_empty() && declared != "command" {
        return None;
    }
    let mut normalised = Map::new();
    normalised.insert("type".to_string(), json!("command"));
    normalised.insert("command".to_string(), json!(command));
    normalised.insert(
        "timeout".to_string(),
        json!(number(handler, "timeout").unwrap_or(DEFAULT_TIMEOUT_SECONDS)),
    );
    normalised.insert(
        "async".to_string(),
        json!(flag(handler, "async").unwrap_or(false)),
    );
    if let Some(message) =
        field(handler, "statusMessage").or_else(|| field(handler, "status_message"))
    {
        normalised.insert("statusMessage".to_string(), json!(message));
    }
    let limit = number(handler, "additionalContextLimit")
        .or_else(|| number(handler, "additional_context_limit"));
    if let Some(limit) = limit.filter(|limit| *limit != DEFAULT_ADDITIONAL_CONTEXT_LIMIT) {
        normalised.insert("additionalContextLimit".to_string(), json!(limit));
    }
    Some(Value::Object(normalised))
}

/// What the recorded state says about one handler.
///
/// `state` is the `[hooks.state]` table of the user `config.toml`, which is the
/// only layer Codex reads a pin from.
pub fn pin_of(state: &Value, key: &str, handler: &Handler) -> Pin {
    let Some(record) = state.get(key) else {
        return Pin::Absent;
    };
    if record.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Pin::Disabled;
    }
    let Some(computed) = pin_hash(handler) else {
        return Pin::Unverifiable;
    };
    match record.get("trusted_hash").and_then(Value::as_str) {
        Some(recorded) if recorded == computed => Pin::Trusted,
        Some(_) => Pin::Stale,
        None => Pin::Absent,
    }
}

/// One event name as Codex writes it in a state key: `PreToolUse` becomes
/// `pre_tool_use`.
pub fn snake_case(event: &str) -> String {
    let mut out = String::with_capacity(event.len() + 4);
    for (index, letter) in event.chars().enumerate() {
        if letter.is_ascii_uppercase() && index > 0 {
            out.push('_');
        }
        out.extend(letter.to_lowercase());
    }
    out
}

fn field(handler: &Value, name: &str) -> Option<String> {
    handler
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn number(handler: &Value, name: &str) -> Option<i64> {
    handler.get(name).and_then(Value::as_i64)
}

fn flag(handler: &Value, name: &str) -> Option<bool> {
    handler.get(name).and_then(Value::as_bool)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn document(value: Value) -> Document {
        Document::inline(
            PathBuf::from("/home/u/.codex/hooks.json"),
            "~/.codex/hooks.json".to_string(),
            value,
        )
    }

    fn written() -> Value {
        json!({"hooks": {
            "SessionStart": [
                {"hooks": [{"type": "command", "command": "bash ~/.codex/start.sh", "timeout": 10}]}
            ],
            "PreToolUse": [
                {"matcher": "shell", "hooks": [
                    {"type": "command", "command": "./one.sh"},
                    {"type": "command", "command": "./two.sh"}
                ]}
            ]
        }})
    }

    #[test]
    fn every_handler_of_every_event_becomes_one_entry_with_its_position() {
        let found = handlers(&document(written()), "hooks");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].event, "PreToolUse");
        assert_eq!(found[0].matcher, "shell");
        assert_eq!((found[0].group_index, found[0].handler_index), (0, 0));
        assert_eq!((found[1].group_index, found[1].handler_index), (0, 1));
        assert_eq!(found[2].event, "SessionStart");
        assert!(!found[2].has_matcher);
    }

    /// The inline table of a `config.toml` carries the same shape as the file,
    /// one level further in, beside Codex's own `state` records.
    #[test]
    fn the_inline_table_of_a_config_layer_registers_the_same_handlers() {
        let inline = document(json!({"hooks": {
            "state": {"x": {"trusted_hash": "sha256:00"}},
            "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./stop.sh"}]}]},
        }}));
        let found = handlers(&inline, "hooks.hooks");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event, "Stop");
        assert!(handlers(&inline, "hooks").is_empty());
    }

    /// Spec section 4.6.1: reordering the handlers of one event is not Drift,
    /// so no position may reach the AgentSweep identity, even though Codex's
    /// own state key is positional.
    #[test]
    fn reordering_leaves_every_agentsweep_identity_where_it_was() {
        let locators = |value: Value| {
            let mut ids: Vec<String> = handlers(&document(value), "hooks")
                .iter()
                .map(|found| HookView::locator(&found.event, &found.matcher, &found.handler))
                .collect();
            ids.sort();
            ids
        };
        let before = locators(
            json!({"hooks": {"PreToolUse": [{"matcher": "shell", "hooks": [
                {"type": "command", "command": "./one.sh"},
                {"type": "command", "command": "./two.sh"}
            ]}]}}),
        );
        let after = locators(
            json!({"hooks": {"PreToolUse": [{"matcher": "shell", "hooks": [
                {"type": "command", "command": "./two.sh"},
                {"type": "command", "command": "./one.sh"}
            ]}]}}),
        );
        assert_eq!(before, after);
    }

    #[test]
    fn an_event_name_is_written_in_snake_case_in_a_state_key() {
        assert_eq!(snake_case("PreToolUse"), "pre_tool_use");
        assert_eq!(snake_case("SessionStart"), "session_start");
        assert_eq!(snake_case("Stop"), "stop");
        assert_eq!(snake_case("UserPromptSubmit"), "user_prompt_submit");
    }

    #[test]
    fn a_state_key_names_the_file_the_event_and_the_two_positions() {
        let found = handlers(&document(written()), "hooks");
        assert_eq!(
            state_key(Path::new("/home/u/.codex/hooks.json"), &found[1]),
            "/home/u/.codex/hooks.json:pre_tool_use:0:1"
        );
    }

    /// The recipe of `docs/research/load-time-interception.md` section 3.3: a
    /// group without a matcher leaves the field out, the timeout and the async
    /// flag are always written, and the default context limit is not.
    #[test]
    fn the_hashed_identity_is_the_one_codex_writes_down() {
        let found = handlers(&document(written()), "hooks");
        let session_start = &found[2];
        let identity = identity(session_start).expect("a command handler");
        assert_eq!(
            String::from_utf8(canonical_entry(&identity)).expect("text"),
            "{\"event_name\":\"session_start\",\"hooks\":[{\"async\":false,\
             \"command\":\"bash ~/.codex/start.sh\",\"timeout\":10,\"type\":\"command\"}]}"
        );
        assert!(
            pin_hash(session_start)
                .expect("a hash")
                .starts_with("sha256:")
        );
    }

    #[test]
    fn a_group_with_a_matcher_carries_it_and_a_default_timeout_is_filled_in() {
        let found = handlers(&document(written()), "hooks");
        let identity = identity(&found[0]).expect("a command handler");
        assert_eq!(identity["matcher"], "shell");
        assert_eq!(identity["hooks"][0]["timeout"], DEFAULT_TIMEOUT_SECONDS);
        assert_eq!(identity["hooks"][0]["async"], Value::Bool(false));
    }

    #[test]
    fn a_context_limit_is_written_only_when_it_is_not_the_default() {
        let one = json!({"type": "command", "command": "x", "additionalContextLimit": 2500});
        let other = json!({"type": "command", "command": "x", "additionalContextLimit": 9000});
        assert!(
            normalised_command_handler(&one)
                .expect("a handler")
                .get("additionalContextLimit")
                .is_none()
        );
        assert_eq!(
            normalised_command_handler(&other).expect("a handler")["additionalContextLimit"],
            9000
        );
    }

    /// Codex normalises an `mcp_tool` handler in a way the fact base does not
    /// record, so nothing is compared rather than a mismatch invented.
    #[test]
    fn a_handler_that_is_not_a_command_yields_no_hash_to_compare() {
        let found = handlers(
            &document(json!({"hooks": {"Stop": [{"hooks": [
                {"type": "mcp_tool", "server": "notes", "tool": "append"}
            ]}]}})),
            "hooks",
        );
        assert!(pin_hash(&found[0]).is_none());
        assert_eq!(
            pin_of(&json!({"k": {"trusted_hash": "sha256:00"}}), "k", &found[0]),
            Pin::Unverifiable
        );
    }

    #[test]
    fn the_recorded_state_says_trusted_stale_disabled_or_nothing_at_all() {
        let found = handlers(&document(written()), "hooks");
        let handler = &found[2];
        let hash = pin_hash(handler).expect("a hash");
        let state = json!({
            "matching": {"trusted_hash": hash},
            "other": {"trusted_hash": "sha256:0000000000"},
            "off": {"trusted_hash": hash, "enabled": false},
        });
        assert_eq!(pin_of(&state, "matching", handler), Pin::Trusted);
        assert_eq!(pin_of(&state, "other", handler), Pin::Stale);
        assert_eq!(pin_of(&state, "off", handler), Pin::Disabled);
        assert_eq!(pin_of(&state, "nothing", handler), Pin::Absent);
    }
}
