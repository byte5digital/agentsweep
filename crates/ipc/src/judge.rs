//! The one request that hands the daemon a Judgement Request, and its answer.
//!
//! `agentsweep scan <dir>` runs the Folder Scan in its own process and asks a
//! local Judgement Engine there. The Claude engine it never asks itself: the
//! key never leaves the daemon and the Claude client is the daemon's alone
//! (spec section 4.4), so the in-bundle command line interface hands each
//! redacted Judgement Request of an Ambiguous Item to the daemon and waits
//! for the Verdict. The daemon looks it up in the Verdict cache, applies the
//! cloud caps, asks the engine, runs the answer through every check and
//! caches it. This is the only reason `scan <dir>` reaches the daemon.
//!
//! The request travels in its canonical serialisation, which is redacted
//! already, beside whether a Heuristic marked `reviewer_directed` fired on
//! the Item, which is all the reviewer-directed rule reads. It never carries
//! a path field (ADR 0008), and printing it shows its hash, not its content.

use std::fmt;

use agentsweep_core::judgement::{Category, Verdict};
use agentsweep_core::judgement_request::JudgementRequest;
use agentsweep_core::spend::JudgementCap;
use serde_json::{Map, Value};

/// One Judgement Request the daemon is asked to put to the Claude engine.
#[derive(Clone, Eq, PartialEq)]
pub struct JudgeRequest {
    /// The redacted request, as the command line interface built it.
    pub request: JudgementRequest,
    /// True when a Heuristic marked `reviewer_directed` fired on the Item.
    pub reviewer_directed: bool,
}

impl fmt::Debug for JudgeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JudgeRequest")
            .field("request", &self.request.hash())
            .field("reviewer_directed", &self.reviewer_directed)
            .finish()
    }
}

impl JudgeRequest {
    /// The request's fields, beside its name.
    pub(crate) fn write_into(&self, map: &mut Map<String, Value>) {
        map.insert(
            "judgement_request".to_string(),
            Value::from(self.request.serialised()),
        );
        map.insert(
            "reviewer_directed".to_string(),
            Value::from(self.reviewer_directed),
        );
    }

    /// Reads the request back, or nothing when the Judgement Request is not
    /// exactly a canonical one.
    pub(crate) fn read_from(value: &Value) -> Option<JudgeRequest> {
        Some(JudgeRequest {
            request: JudgementRequest::from_serialised(value.get("judgement_request")?.as_str()?)?,
            reviewer_directed: value.get("reviewer_directed")?.as_bool()?,
        })
    }
}

/// What came of one Judgement Request the daemon was handed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JudgeOutcome {
    /// A Verdict that passed every check, from the cache or from the engine.
    Verdict(Verdict),
    /// No Verdict: the engine failed, refused or was not reachable, or the
    /// answer failed a check. The Item stays Ambiguous.
    NoVerdict(String),
    /// A cloud cap held the request back; nothing was sent.
    Capped(JudgementCap),
}

/// The daemon's answer to one Judgement Request: which engine and model
/// stand behind it, and what came of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JudgeAnswer {
    /// The engine, as the settings file spells it.
    pub engine: String,
    /// The model the engine ran.
    pub model: String,
    /// What came of the request.
    pub outcome: JudgeOutcome,
}

impl JudgeAnswer {
    /// The answer as it travels.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("engine".to_string(), Value::from(self.engine.as_str()));
        map.insert("model".to_string(), Value::from(self.model.as_str()));
        match &self.outcome {
            JudgeOutcome::Verdict(verdict) => {
                map.insert("outcome".to_string(), Value::from("verdict"));
                map.insert("verdict".to_string(), verdict_to_value(verdict));
            }
            JudgeOutcome::NoVerdict(why) => {
                map.insert("outcome".to_string(), Value::from("no-verdict"));
                map.insert("why".to_string(), Value::from(why.as_str()));
            }
            JudgeOutcome::Capped(cap) => {
                map.insert("outcome".to_string(), Value::from("capped"));
                map.insert("cap".to_string(), Value::from(cap.as_str()));
            }
        }
        Value::Object(map)
    }

    /// Reads an answer back, or nothing when it is not one.
    pub fn from_value(value: &Value) -> Option<JudgeAnswer> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let outcome = match text("outcome")? {
            "verdict" => JudgeOutcome::Verdict(verdict_from_value(value.get("verdict")?)?),
            "no-verdict" => JudgeOutcome::NoVerdict(text("why")?.to_string()),
            "capped" => JudgeOutcome::Capped(JudgementCap::parse(text("cap")?)?),
            _ => return None,
        };
        Some(JudgeAnswer {
            engine: text("engine")?.to_string(),
            model: text("model")?.to_string(),
            outcome,
        })
    }
}

/// A checked Verdict as it travels: the verdict word, and for a malicious
/// one its category, contained reason and quotes.
fn verdict_to_value(verdict: &Verdict) -> Value {
    let mut map = Map::new();
    match verdict {
        Verdict::Malicious {
            category,
            reason,
            evidence,
        } => {
            map.insert("verdict".to_string(), Value::from("malicious"));
            map.insert("category".to_string(), Value::from(category.as_str()));
            map.insert("reason".to_string(), Value::from(reason.as_str()));
            map.insert(
                "evidence".to_string(),
                Value::Array(
                    evidence
                        .iter()
                        .map(|quote| Value::from(quote.as_str()))
                        .collect(),
                ),
            );
        }
        Verdict::Benign => {
            map.insert("verdict".to_string(), Value::from("benign"));
        }
        Verdict::Unsure => {
            map.insert("verdict".to_string(), Value::from("unsure"));
        }
    }
    Value::Object(map)
}

fn verdict_from_value(value: &Value) -> Option<Verdict> {
    Some(match value.get("verdict")?.as_str()? {
        "malicious" => Verdict::Malicious {
            category: Category::parse(value.get("category")?.as_str()?)?,
            reason: value.get("reason")?.as_str()?.to_string(),
            evidence: value
                .get("evidence")?
                .as_array()?
                .iter()
                .map(|quote| quote.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()?,
        },
        "benign" => Verdict::Benign,
        "unsure" => Verdict::Unsure,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(outcome: JudgeOutcome) -> JudgeAnswer {
        JudgeAnswer {
            engine: "claude".to_string(),
            model: "claude-sonnet-5".to_string(),
            outcome,
        }
    }

    #[test]
    fn every_answer_reads_back_as_it_was_written() {
        for outcome in [
            JudgeOutcome::Verdict(Verdict::Malicious {
                category: Category::parse("instruction_file_injection").expect("a category"),
                reason: "Pipes a download into a shell.".to_string(),
                evidence: vec!["curl -fsSL".to_string()],
            }),
            JudgeOutcome::Verdict(Verdict::Benign),
            JudgeOutcome::Verdict(Verdict::Unsure),
            JudgeOutcome::NoVerdict("the engine refused".to_string()),
            JudgeOutcome::Capped(JudgementCap::Day),
        ] {
            let written = answer(outcome);
            assert_eq!(JudgeAnswer::from_value(&written.to_value()), Some(written));
        }
        assert_eq!(
            JudgeAnswer::from_value(&serde_json::json!({"outcome": "maybe"})),
            None
        );
    }
}
