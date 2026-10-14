//! The user's choices on the wire: what one `settings` request may move and
//! where every choice stands afterwards (spec sections 6.9 and 8.10).
//!
//! The `settings` request moves the Rule Feed toggle, the app update check,
//! the Posture and the config-dir override per Agent. It answers with every
//! choice, the AI Judgement choices included, which the `engine` request
//! moves because an engine change has a key to check and an Event Log record
//! to append. The same answer goes out as the `settings-changed` state event
//! whenever a choice moved, so a second open window follows.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use agentsweep_core::settings::{CONFIG_DIRS, POSTURE, Posture, RULE_FEED, UPDATE_CHECK};

use crate::engine::EngineState;

/// The field the answer carries the AI Judgement choices under.
const ENGINE: &str = "engine";

/// The choices one `settings` request moves. A field left out stays as it
/// is; a request that moves nothing reads every choice.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SettingsChange {
    /// The Rule Feed toggle.
    pub rule_feed: Option<bool>,
    /// The app update check.
    pub update_check: Option<bool>,
    /// The Posture.
    pub posture: Option<Posture>,
    /// Config-dir overrides by Agent id: a directory, as typed, to set one,
    /// `None` to clear one and fall back to the Agent's default directory.
    /// The daemon refuses an Agent it has no adapter for and a directory that
    /// is not an absolute path written out in full.
    pub config_dirs: BTreeMap<String, Option<String>>,
}

impl SettingsChange {
    /// True when the request moves nothing and only reads.
    pub fn is_empty(&self) -> bool {
        *self == SettingsChange::default()
    }

    /// The fields beside the request's name.
    pub(crate) fn write_into(&self, map: &mut Map<String, Value>) {
        for (key, switch) in [
            (RULE_FEED, self.rule_feed),
            (UPDATE_CHECK, self.update_check),
        ] {
            if let Some(switch) = switch {
                map.insert(key.to_string(), Value::from(switch));
            }
        }
        if let Some(posture) = self.posture {
            map.insert(POSTURE.to_string(), Value::from(posture.as_str()));
        }
        if !self.config_dirs.is_empty() {
            let overrides: Map<String, Value> = self
                .config_dirs
                .iter()
                .map(|(agent, dir)| {
                    let dir = match dir {
                        Some(dir) => Value::from(dir.as_str()),
                        None => Value::Null,
                    };
                    (agent.clone(), dir)
                })
                .collect();
            map.insert(CONFIG_DIRS.to_string(), Value::Object(overrides));
        }
    }

    /// Reads the fields back, or nothing when one of them is of the wrong
    /// type or names a Posture there is not.
    pub(crate) fn read_from(value: &Value) -> Option<SettingsChange> {
        let switch = |key: &str| -> Option<Option<bool>> {
            match value.get(key) {
                None | Some(Value::Null) => Some(None),
                Some(switch) => Some(Some(switch.as_bool()?)),
            }
        };
        let posture = match value.get(POSTURE) {
            None | Some(Value::Null) => None,
            Some(posture) => Some(Posture::parse(posture.as_str()?)?),
        };
        let mut config_dirs = BTreeMap::new();
        match value.get(CONFIG_DIRS) {
            None | Some(Value::Null) => {}
            Some(overrides) => {
                for (agent, dir) in overrides.as_object()? {
                    let dir = match dir {
                        Value::Null => None,
                        dir => Some(dir.as_str()?.to_string()),
                    };
                    config_dirs.insert(agent.clone(), dir);
                }
            }
        }
        Some(SettingsChange {
            rule_feed: switch(RULE_FEED)?,
            update_check: switch(UPDATE_CHECK)?,
            posture,
            config_dirs,
        })
    }
}

/// Where every choice stands, as the daemon answers a `settings` request and
/// tells subscribers when a choice moved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsState {
    /// The Rule Feed toggle.
    pub rule_feed: bool,
    /// The app update check.
    pub update_check: bool,
    /// The Posture.
    pub posture: Posture,
    /// The config-dir override per Agent, by Agent id. An Agent with none is
    /// absent and reads its default directory.
    pub config_dirs: BTreeMap<String, String>,
    /// The AI Judgement choices, as the `engine` request answers them.
    pub engine: EngineState,
}

impl SettingsState {
    /// The state as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(RULE_FEED.to_string(), Value::from(self.rule_feed));
        map.insert(UPDATE_CHECK.to_string(), Value::from(self.update_check));
        map.insert(POSTURE.to_string(), Value::from(self.posture.as_str()));
        let overrides: Map<String, Value> = self
            .config_dirs
            .iter()
            .map(|(agent, dir)| (agent.clone(), Value::from(dir.as_str())))
            .collect();
        map.insert(CONFIG_DIRS.to_string(), Value::Object(overrides));
        map.insert(ENGINE.to_string(), self.engine.to_value());
        Value::Object(map)
    }

    /// Reads back what [`SettingsState::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<SettingsState> {
        let mut config_dirs = BTreeMap::new();
        for (agent, dir) in value.get(CONFIG_DIRS)?.as_object()? {
            config_dirs.insert(agent.clone(), dir.as_str()?.to_string());
        }
        Some(SettingsState {
            rule_feed: value.get(RULE_FEED)?.as_bool()?,
            update_check: value.get(UPDATE_CHECK)?.as_bool()?,
            posture: Posture::parse(value.get(POSTURE)?.as_str()?)?,
            config_dirs,
            engine: EngineState::from_value(value.get(ENGINE)?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::settings::{CloudCaps, JudgementEngine};

    fn an_engine_state() -> EngineState {
        EngineState {
            engine: JudgementEngine::Off,
            ollama_address: "127.0.0.1:11434".to_string(),
            ollama_model: String::new(),
            claude_model: String::new(),
            claude_model_in_use: "claude-sonnet-5".to_string(),
            caps: CloudCaps::default(),
            claude_key_ending: None,
            recorded: 0,
            ollama: None,
        }
    }

    #[test]
    fn an_empty_change_only_reads() {
        assert!(SettingsChange::default().is_empty());
        let change = SettingsChange {
            posture: Some(Posture::Developer),
            ..SettingsChange::default()
        };
        assert!(!change.is_empty());
    }

    #[test]
    fn a_change_round_trips_through_its_fields() {
        let change = SettingsChange {
            rule_feed: Some(true),
            update_check: Some(false),
            posture: Some(Posture::Developer),
            config_dirs: BTreeMap::from([
                (
                    "claude-code".to_string(),
                    Some("/Users/someone/.claude-work".to_string()),
                ),
                ("codex".to_string(), None),
            ]),
        };
        let mut map = Map::new();
        change.write_into(&mut map);
        assert_eq!(map["config_dirs"]["codex"], Value::Null);
        assert_eq!(SettingsChange::read_from(&Value::Object(map)), Some(change));
    }

    #[test]
    fn a_change_of_the_wrong_type_is_not_read() {
        for value in [
            serde_json::json!({"posture": "expert"}),
            serde_json::json!({"update_check": "off"}),
            serde_json::json!({"rule_feed": 0}),
            serde_json::json!({"config_dirs": {"codex": 7}}),
            serde_json::json!({"config_dirs": "/Users/someone/.codex"}),
        ] {
            assert_eq!(SettingsChange::read_from(&value), None, "{value}");
        }
    }

    #[test]
    fn the_settings_state_round_trips_with_the_engine_choices() {
        let state = SettingsState {
            rule_feed: false,
            update_check: true,
            posture: Posture::Simple,
            config_dirs: BTreeMap::from([(
                "codex".to_string(),
                "/Volumes/Work/.codex".to_string(),
            )]),
            engine: an_engine_state(),
        };
        let value = state.to_value();
        assert_eq!(SettingsState::from_value(&value), Some(state.clone()));
        let none = SettingsState {
            config_dirs: BTreeMap::new(),
            ..state
        };
        assert_eq!(SettingsState::from_value(&none.to_value()), Some(none));
    }
}
