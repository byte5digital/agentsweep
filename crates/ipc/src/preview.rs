//! "Preview a request" on the wire (spec sections 4.4 and 8.10): what the
//! daemon would hand one Judgement Engine about one Item, or about the fixed
//! sample Item when none is named. Nothing is sent and nothing is cached.
//!
//! What travels back is already redacted: the fixed system prompt and the
//! user turn with the redacted Judgement Request inside its nonce block.

use serde_json::{Map, Value};

use agentsweep_core::settings::JudgementEngine;

/// The answer to a `preview-request`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestPreview {
    /// The engine the request was built for.
    pub engine: JudgementEngine,
    /// The Item it is about, by id; the sample Item's id when none was named.
    pub item: String,
    /// True when it is the fixed sample Item shipped in the binary.
    pub sample: bool,
    /// The request, or why that engine would be asked nothing.
    pub outcome: PreviewOutcome,
}

/// What a preview shows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreviewOutcome {
    /// Exactly what the engine would receive, apart from the nonce, which is
    /// fresh for every request.
    Request {
        /// The fixed system prompt.
        system: String,
        /// The user turn: the redacted Judgement Request inside its nonce
        /// block.
        user: String,
        /// The nonce this preview's block is delimited by.
        nonce: String,
        /// The version of the system prompt.
        prompt_version: String,
        /// What the request measured.
        tokens: usize,
        /// The engine's budget.
        budget: usize,
        /// True when the content was cut to windows around the matches.
        windowed: bool,
    },
    /// Too large for this engine, even in windows around every match.
    TooLarge {
        /// What the windowed request measured.
        tokens: usize,
        /// The engine's budget.
        budget: usize,
    },
}

impl RequestPreview {
    /// The answer as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("engine".into(), Value::from(self.engine.as_str()));
        map.insert("item".into(), Value::from(self.item.as_str()));
        map.insert("sample".into(), Value::from(self.sample));
        match &self.outcome {
            PreviewOutcome::Request {
                system,
                user,
                nonce,
                prompt_version,
                tokens,
                budget,
                windowed,
            } => {
                map.insert("outcome".into(), Value::from("request"));
                map.insert("system".into(), Value::from(system.as_str()));
                map.insert("user".into(), Value::from(user.as_str()));
                map.insert("nonce".into(), Value::from(nonce.as_str()));
                map.insert(
                    "prompt_version".into(),
                    Value::from(prompt_version.as_str()),
                );
                map.insert("tokens".into(), Value::from(*tokens as u64));
                map.insert("budget".into(), Value::from(*budget as u64));
                map.insert("windowed".into(), Value::from(*windowed));
            }
            PreviewOutcome::TooLarge { tokens, budget } => {
                map.insert("outcome".into(), Value::from("too-large"));
                map.insert("tokens".into(), Value::from(*tokens as u64));
                map.insert("budget".into(), Value::from(*budget as u64));
            }
        }
        Value::Object(map)
    }

    /// Reads back what [`RequestPreview::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<RequestPreview> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let count = |field: &str| value.get(field).and_then(Value::as_u64).map(|n| n as usize);
        let outcome = match text("outcome")? {
            "request" => PreviewOutcome::Request {
                system: text("system")?.to_string(),
                user: text("user")?.to_string(),
                nonce: text("nonce")?.to_string(),
                prompt_version: text("prompt_version")?.to_string(),
                tokens: count("tokens")?,
                budget: count("budget")?,
                windowed: value.get("windowed")?.as_bool()?,
            },
            "too-large" => PreviewOutcome::TooLarge {
                tokens: count("tokens")?,
                budget: count("budget")?,
            },
            _ => return None,
        };
        Some(RequestPreview {
            engine: JudgementEngine::parse(text("engine")?)?,
            item: text("item")?.to_string(),
            sample: value.get("sample")?.as_bool()?,
            outcome,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_outcomes_read_back_what_they_write() {
        for preview in [
            RequestPreview {
                engine: JudgementEngine::Claude,
                item: "claude-code/user/skill/~/.claude/skills/notes-helper".to_string(),
                sample: true,
                outcome: PreviewOutcome::Request {
                    system: "system".to_string(),
                    user: "user".to_string(),
                    nonce: "00ff".to_string(),
                    prompt_version: "1".to_string(),
                    tokens: 120,
                    budget: 32_000,
                    windowed: false,
                },
            },
            RequestPreview {
                engine: JudgementEngine::Apple,
                item: "claude-code/user/skill/~/.claude/skills/long".to_string(),
                sample: false,
                outcome: PreviewOutcome::TooLarge {
                    tokens: 9_000,
                    budget: 4_096,
                },
            },
        ] {
            assert_eq!(
                RequestPreview::from_value(&preview.to_value()),
                Some(preview)
            );
        }
    }
}
