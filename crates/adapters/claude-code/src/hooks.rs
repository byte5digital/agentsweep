//! The hook handlers a settings file registers.
//!
//! A `hooks` block is three levels deep: an event, the groups registered for
//! it, and the handlers of each group. The Item is the handler, because that is
//! what runs and what an attacker adds; the event and the matcher travel with
//! it because they say when it runs.
//!
//! The handlers are yielded in the order they are written and never sorted: a
//! group's position is not part of a hook's identity (spec section 4.6.1), so
//! reordering has to leave every id where it was.

use serde_json::Value;

use crate::document::Document;

/// One hook handler, with the event and the matcher it is registered under.
#[derive(Clone, Debug)]
pub struct Handler {
    /// The event that fires it.
    pub event: String,
    /// The matcher it is registered under, empty when the group declares none.
    pub matcher: String,
    /// The handler itself, as it is written.
    pub handler: Value,
}

/// Every hook handler a document registers, events in sorted order and the
/// handlers of one event in the order they are written.
pub fn handlers(document: &Document) -> Vec<Handler> {
    let mut found = Vec::new();
    for (event, groups) in document.members("hooks") {
        let Some(groups) = groups.as_array() else {
            continue;
        };
        for group in groups {
            let matcher = group
                .get("matcher")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let Some(handlers) = group.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            for handler in handlers {
                found.push(Handler {
                    event: event.clone(),
                    matcher: matcher.clone(),
                    handler: handler.clone(),
                });
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsweep_core::views::HookView;
    use serde_json::json;

    fn document(value: Value) -> Document {
        Document {
            path: std::path::PathBuf::from("/home/u/.claude/settings.json"),
            surface: "~/.claude/settings.json".to_string(),
            value,
        }
    }

    fn written() -> Value {
        json!({"hooks": {
            "SessionStart": [
                {"hooks": [{"type": "command", "command": "bash ~/.claude/hooks/start.sh"}]}
            ],
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "./one.sh"},
                    {"type": "command", "command": "./two.sh"}
                ]}
            ]
        }})
    }

    #[test]
    fn every_handler_of_every_event_becomes_one_entry() {
        let found = handlers(&document(written()));
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].event, "PreToolUse");
        assert_eq!(found[0].matcher, "Bash");
        assert_eq!(found[2].event, "SessionStart");
        assert_eq!(found[2].matcher, "");
    }

    /// Spec section 4.6.1: reordering the handlers of one event is not Drift,
    /// so no position may reach the identity.
    #[test]
    fn reordering_the_handlers_of_one_event_leaves_every_identity_where_it_was() {
        let reordered = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "./two.sh"},
            {"type": "command", "command": "./one.sh"}
        ]}]}});
        let locators = |value: Value| {
            let mut ids: Vec<String> = handlers(&document(value))
                .iter()
                .map(|found| HookView::locator(&found.event, &found.matcher, &found.handler))
                .collect();
            ids.sort();
            ids
        };
        let before = locators(
            json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": "./one.sh"},
                {"type": "command", "command": "./two.sh"}
            ]}]}}),
        );
        assert_eq!(before, locators(reordered));
    }

    #[test]
    fn a_settings_file_without_hooks_registers_none() {
        assert!(handlers(&document(json!({"model": "opus"}))).is_empty());
        assert!(handlers(&document(json!({"hooks": {"Stop": "off"}}))).is_empty());
    }
}
