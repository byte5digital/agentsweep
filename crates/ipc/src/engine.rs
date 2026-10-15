//! The AI Judgement choices on the wire: what a client may change and what the
//! daemon answers with (spec sections 4.4 and 8.10).
//!
//! The Claude API key travels one way only, from the client to the daemon,
//! in the `set-claude-key` request. Nothing the daemon sends back carries it:
//! the engine state says whether a key is set and its last four characters,
//! and nothing more.

use serde_json::{Map, Value};

use agentsweep_core::apple::AppleAvailability;
use agentsweep_core::ollama::{OllamaModel, OllamaPresence};
use agentsweep_core::settings::{
    CLAUDE_MODEL, CLOUD_CENTS_PER_MONTH, CLOUD_ITEMS_PER_DAY, CLOUD_ITEMS_PER_SCAN, CloudCaps,
    JUDGEMENT_ENGINE, JudgementEngine, OLLAMA_ADDRESS, OLLAMA_MODEL,
};

/// The field the engine state names the key's last four characters under.
const CLAUDE_KEY_ENDING: &str = "claude_key_ending";
/// The field the engine state names the Claude model in use under.
const CLAUDE_MODEL_IN_USE: &str = "claude_model_in_use";
/// The field that says how many Event Log events a request appended.
const RECORDED: &str = "recorded";
/// The field Ollama's presence and its models are named under.
const OLLAMA: &str = "ollama";
/// The field Apple on-device's availability and its reason are named under.
const APPLE: &str = "apple";

/// The choices one `engine` request moves. A field left out stays as it is;
/// a request that moves nothing reads the engine state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineChange {
    /// The engine to make the one active engine, or off.
    pub engine: Option<JudgementEngine>,
    /// The Ollama address, as typed. The daemon refuses one off this Mac.
    pub ollama_address: Option<String>,
    /// The Ollama model, empty for none.
    pub ollama_model: Option<String>,
    /// The Claude model id override, empty for the default.
    pub claude_model: Option<String>,
    /// The cloud cap per Scan.
    pub items_per_scan: Option<u32>,
    /// The cloud cap per day.
    pub items_per_day: Option<u32>,
    /// The cloud cap per month, in US cents.
    pub cents_per_month: Option<u32>,
}

impl EngineChange {
    /// True when the request moves nothing and only reads.
    pub fn is_empty(&self) -> bool {
        *self == EngineChange::default()
    }

    /// The fields beside the request's name.
    pub(crate) fn write_into(&self, map: &mut Map<String, Value>) {
        if let Some(engine) = self.engine {
            map.insert(JUDGEMENT_ENGINE.to_string(), Value::from(engine.as_str()));
        }
        for (key, text) in [
            (OLLAMA_ADDRESS, &self.ollama_address),
            (OLLAMA_MODEL, &self.ollama_model),
            (CLAUDE_MODEL, &self.claude_model),
        ] {
            if let Some(text) = text {
                map.insert(key.to_string(), Value::from(text.as_str()));
            }
        }
        for (key, number) in [
            (CLOUD_ITEMS_PER_SCAN, self.items_per_scan),
            (CLOUD_ITEMS_PER_DAY, self.items_per_day),
            (CLOUD_CENTS_PER_MONTH, self.cents_per_month),
        ] {
            if let Some(number) = number {
                map.insert(key.to_string(), Value::from(number));
            }
        }
    }

    /// Reads the fields back, or nothing when one of them is of the wrong
    /// type or names an engine there is not.
    pub(crate) fn read_from(value: &Value) -> Option<EngineChange> {
        let text = |key: &str| -> Option<Option<String>> {
            match value.get(key) {
                None | Some(Value::Null) => Some(None),
                Some(text) => Some(Some(text.as_str()?.to_string())),
            }
        };
        let number = |key: &str| -> Option<Option<u32>> {
            match value.get(key) {
                None | Some(Value::Null) => Some(None),
                Some(number) => Some(Some(u32::try_from(number.as_u64()?).ok()?)),
            }
        };
        Some(EngineChange {
            engine: match text(JUDGEMENT_ENGINE)? {
                None => None,
                Some(name) => Some(JudgementEngine::parse(&name)?),
            },
            ollama_address: text(OLLAMA_ADDRESS)?,
            ollama_model: text(OLLAMA_MODEL)?,
            claude_model: text(CLAUDE_MODEL)?,
            items_per_scan: number(CLOUD_ITEMS_PER_SCAN)?,
            items_per_day: number(CLOUD_ITEMS_PER_DAY)?,
            cents_per_month: number(CLOUD_CENTS_PER_MONTH)?,
        })
    }
}

/// Where the AI Judgement choices stand, as the daemon answers every engine
/// request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineState {
    /// The one active engine, or off.
    pub engine: JudgementEngine,
    /// Where Ollama is asked.
    pub ollama_address: String,
    /// The Ollama model, empty for none.
    pub ollama_model: String,
    /// The Claude model id override, empty for the default.
    pub claude_model: String,
    /// The Claude model AI Judgement asks: the override or the default.
    pub claude_model_in_use: String,
    /// The caps on the cloud engine.
    pub caps: CloudCaps,
    /// The last four characters of the Claude API key, absent when no key is
    /// set. Never more of the key than that.
    pub claude_key_ending: Option<String>,
    /// How many Event Log events the request appended: zero for a read, one
    /// for each engine change it made.
    pub recorded: u32,
    /// Whether Ollama runs at the address above and the models it has
    /// already pulled, absent when the daemon did not ask: only the answer to
    /// an `engine` request asks.
    pub ollama: Option<OllamaPresence>,
    /// Whether Apple's on-device model can judge here, and the reason when
    /// it cannot, as the Apple judgement helper answers its check; absent
    /// when the daemon did not ask: only the answer to an `engine` request
    /// asks.
    pub apple: Option<AppleAvailability>,
}

impl EngineState {
    /// The state as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        EngineChange {
            engine: Some(self.engine),
            ollama_address: Some(self.ollama_address.clone()),
            ollama_model: Some(self.ollama_model.clone()),
            claude_model: Some(self.claude_model.clone()),
            items_per_scan: Some(self.caps.items_per_scan),
            items_per_day: Some(self.caps.items_per_day),
            cents_per_month: Some(self.caps.cents_per_month),
        }
        .write_into(&mut map);
        map.insert(
            CLAUDE_MODEL_IN_USE.to_string(),
            Value::from(self.claude_model_in_use.as_str()),
        );
        map.insert(
            CLAUDE_KEY_ENDING.to_string(),
            match &self.claude_key_ending {
                Some(ending) => Value::from(ending.as_str()),
                None => Value::Null,
            },
        );
        map.insert(RECORDED.to_string(), Value::from(self.recorded));
        if let Some(presence) = &self.ollama {
            map.insert(OLLAMA.to_string(), presence_value(presence));
        }
        if let Some(availability) = &self.apple {
            map.insert(APPLE.to_string(), availability_value(availability));
        }
        Value::Object(map)
    }

    /// Reads back what [`EngineState::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<EngineState> {
        let fields = EngineChange::read_from(value)?;
        Some(EngineState {
            engine: fields.engine?,
            ollama_address: fields.ollama_address?,
            ollama_model: fields.ollama_model?,
            claude_model: fields.claude_model?,
            claude_model_in_use: value.get(CLAUDE_MODEL_IN_USE)?.as_str()?.to_string(),
            caps: CloudCaps {
                items_per_scan: fields.items_per_scan?,
                items_per_day: fields.items_per_day?,
                cents_per_month: fields.cents_per_month?,
            },
            claude_key_ending: match value.get(CLAUDE_KEY_ENDING)? {
                Value::Null => None,
                ending => Some(ending.as_str()?.to_string()),
            },
            recorded: u32::try_from(value.get(RECORDED)?.as_u64()?).ok()?,
            ollama: match value.get(OLLAMA) {
                None | Some(Value::Null) => None,
                Some(presence) => Some(read_presence(presence)?),
            },
            apple: match value.get(APPLE) {
                None | Some(Value::Null) => None,
                Some(availability) => Some(read_availability(availability)?),
            },
        })
    }
}

/// Ollama's presence as the wire carries it: `running` false, or `running`
/// true with the version and every model pulled.
fn presence_value(presence: &OllamaPresence) -> Value {
    match presence {
        OllamaPresence::Absent => serde_json::json!({ "running": false }),
        OllamaPresence::Running { version, models } => serde_json::json!({
            "running": true,
            "version": version,
            "models": models
                .iter()
                .map(|model| serde_json::json!({
                    "name": model.name,
                    "digest": model.digest,
                    "parameter_size": model.parameter_size,
                    "large_enough": model.large_enough,
                }))
                .collect::<Vec<Value>>(),
        }),
    }
}

/// Reads back what [`presence_value`] wrote.
fn read_presence(value: &Value) -> Option<OllamaPresence> {
    if !value.get("running")?.as_bool()? {
        return Some(OllamaPresence::Absent);
    }
    let text = |value: &Value, key: &str| Some(value.get(key)?.as_str()?.to_string());
    let models = value
        .get("models")?
        .as_array()?
        .iter()
        .map(|model| {
            Some(OllamaModel {
                name: text(model, "name")?,
                digest: text(model, "digest")?,
                parameter_size: text(model, "parameter_size")?,
                large_enough: model.get("large_enough")?.as_bool()?,
            })
        })
        .collect::<Option<Vec<OllamaModel>>>()?;
    Some(OllamaPresence::Running {
        version: text(value, "version")?,
        models,
    })
}

/// Apple's availability as the wire carries it: `available` true with the
/// model version and the context size where known, or `available` false with
/// the reason.
fn availability_value(availability: &AppleAvailability) -> Value {
    match availability {
        AppleAvailability::Available {
            model_version,
            context_size,
        } => serde_json::json!({
            "available": true,
            "model_version": model_version,
            "context_size": context_size,
        }),
        AppleAvailability::Unavailable { reason } => serde_json::json!({
            "available": false,
            "reason": reason,
        }),
    }
}

/// Reads back what [`availability_value`] wrote.
fn read_availability(value: &Value) -> Option<AppleAvailability> {
    if !value.get("available")?.as_bool()? {
        return Some(AppleAvailability::Unavailable {
            reason: value.get("reason")?.as_str()?.to_string(),
        });
    }
    Some(AppleAvailability::Available {
        model_version: value.get("model_version")?.as_str()?.to_string(),
        context_size: match value.get("context_size") {
            None | Some(Value::Null) => None,
            Some(size) => Some(u32::try_from(size.as_u64()?).ok()?),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_change_only_reads() {
        assert!(EngineChange::default().is_empty());
        let change = EngineChange {
            engine: Some(JudgementEngine::Ollama),
            ..EngineChange::default()
        };
        assert!(!change.is_empty());
    }

    #[test]
    fn a_change_round_trips_through_its_fields() {
        let change = EngineChange {
            engine: Some(JudgementEngine::Claude),
            ollama_address: Some("localhost:11434".to_string()),
            ollama_model: Some("qwen3:8b".to_string()),
            claude_model: Some(String::new()),
            items_per_scan: Some(10),
            items_per_day: None,
            cents_per_month: Some(250),
        };
        let mut map = Map::new();
        change.write_into(&mut map);
        assert_eq!(EngineChange::read_from(&Value::Object(map)), Some(change));
    }

    #[test]
    fn a_change_naming_no_engine_there_is_is_not_read() {
        let value = serde_json::json!({"judgement_engine": "typesafe"});
        assert_eq!(EngineChange::read_from(&value), None);
        let value = serde_json::json!({"cloud_items_per_scan": -3});
        assert_eq!(EngineChange::read_from(&value), None);
    }

    #[test]
    fn the_engine_state_round_trips_and_carries_four_characters_of_the_key() {
        let state = EngineState {
            engine: JudgementEngine::Claude,
            ollama_address: "127.0.0.1:11434".to_string(),
            ollama_model: String::new(),
            claude_model: String::new(),
            claude_model_in_use: "claude-sonnet-5".to_string(),
            caps: CloudCaps::default(),
            claude_key_ending: Some("4f2a".to_string()),
            recorded: 1,
            ollama: None,
            apple: None,
        };
        let value = state.to_value();
        assert_eq!(EngineState::from_value(&value), Some(state));
        let none = EngineState {
            claude_key_ending: None,
            ..EngineState::from_value(&value).expect("a state")
        };
        assert_eq!(EngineState::from_value(&none.to_value()), Some(none));
    }

    #[test]
    fn ollama_s_presence_and_models_round_trip() {
        let mut state = EngineState {
            engine: JudgementEngine::Off,
            ollama_address: "127.0.0.1:11434".to_string(),
            ollama_model: String::new(),
            claude_model: String::new(),
            claude_model_in_use: "claude-sonnet-5".to_string(),
            caps: CloudCaps::default(),
            claude_key_ending: None,
            recorded: 0,
            ollama: Some(OllamaPresence::Absent),
            apple: None,
        };
        assert_eq!(
            EngineState::from_value(&state.to_value()),
            Some(state.clone())
        );
        state.ollama = Some(OllamaPresence::Running {
            version: "0.12.6".to_string(),
            models: vec![OllamaModel {
                name: "qwen3:1.7b".to_string(),
                digest: "1111".to_string(),
                parameter_size: "1.7B".to_string(),
                large_enough: false,
            }],
        });
        assert_eq!(
            EngineState::from_value(&state.to_value()),
            Some(state.clone())
        );
        let value = state.to_value();
        assert_eq!(value["ollama"]["models"][0]["large_enough"], false);
    }

    #[test]
    fn apple_s_availability_and_its_reason_round_trip() {
        let mut state = EngineState {
            engine: JudgementEngine::Apple,
            ollama_address: "127.0.0.1:11434".to_string(),
            ollama_model: String::new(),
            claude_model: String::new(),
            claude_model_in_use: "claude-sonnet-5".to_string(),
            caps: CloudCaps::default(),
            claude_key_ending: None,
            recorded: 0,
            ollama: None,
            apple: Some(AppleAvailability::Available {
                model_version: "26.6.2 (25G83)".to_string(),
                context_size: Some(4096),
            }),
        };
        assert_eq!(
            EngineState::from_value(&state.to_value()),
            Some(state.clone())
        );
        state.apple = Some(AppleAvailability::Unavailable {
            reason: "apple_intelligence_not_enabled".to_string(),
        });
        let value = state.to_value();
        assert_eq!(value["apple"]["available"], false);
        assert_eq!(value["apple"]["reason"], "apple_intelligence_not_enabled");
        assert_eq!(EngineState::from_value(&value), Some(state));
    }
}
