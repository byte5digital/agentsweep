//! How AI Judgement shows in the window (spec sections 4.4, 6.4 and 8.4).
//!
//! - **The AI block**: a malicious Verdict's `reason` beneath the T2 `plain`
//!   lines, as plain text of at most 240 characters with control and bidi
//!   characters stripped, labelled "AI explanation, from <engine>"; the
//!   Developer Posture adds the model. The daemon contains the reason before
//!   it records it; the app contains it again, because what it renders is
//!   the engine's text and never AgentSweep's.
//! - **Benign and unsure** never show engine text. A benign Item shows a
//!   "checked by <engine>" note in the Developer Posture only.
//! - **The queue progress line** "AI check: 3 of 12" while the queue runs,
//!   on the Overview and in the Activity, in the Developer Posture only.
//! - **The cap line**, the fixed "The AI check reached its limit for this
//!   scan. N items will be looked at next time.", in both Postures (spec
//!   section 8.4: the Ambiguous count line does not exist in the Simple
//!   Posture, the cap line does).
//!
//! Everything here is a pure function of what the daemon sent.

use agentsweep_core::finding::Tier;
use agentsweep_core::health::Health;
use agentsweep_core::judgement::contain_reason;
use agentsweep_core::overview::CheckedItem;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use serde_json::{Value, json};

use crate::wording;

/// The words a Verdict was given in, as a Finding's facts carry them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Said {
    /// Malicious: the only Verdict whose reason is ever shown.
    Malicious,
    /// Benign: fixed AgentSweep wording only.
    Benign,
    /// Unsure, or no Verdict at all: fixed AgentSweep wording only.
    Unsure,
}

/// One Verdict as the window may show it: what it said, the engine and
/// model that gave it, and the engine's reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verdict<'a> {
    /// What it said.
    pub said: Said,
    /// The engine, as the settings spell it: `apple`, `ollama` or `claude`.
    pub engine: &'a str,
    /// The model that engine ran.
    pub model: &'a str,
    /// The engine's reason, untrusted text.
    pub reason: &'a str,
}

impl<'a> Verdict<'a> {
    /// The malicious Verdict behind a T3 Finding, absent for any other
    /// Finding: benign and unsure Verdicts open none.
    pub fn of(finding: &'a RecordedFinding) -> Option<Verdict<'a>> {
        let facts = &finding.facts;
        match finding.tier == Tier::AiJudgement && !facts.judgement_engine.is_empty() {
            true => Some(Verdict {
                said: Said::Malicious,
                engine: &facts.judgement_engine,
                model: &facts.judgement_model,
                reason: &facts.judgement_reason,
            }),
            false => None,
        }
    }
}

/// The engine as a person reads it.
pub fn engine_name(engine: &str) -> &str {
    match engine {
        "apple" => "Apple on-device",
        "ollama" => "Ollama",
        "claude" => "Claude",
        other => other,
    }
}

/// The label of the AI block: "AI explanation, from <engine>", the
/// Developer Posture adding the model.
pub fn label(engine: &str, model: &str, posture: Posture) -> String {
    let engine = engine_name(engine);
    match (posture, model.is_empty()) {
        (Posture::Developer, false) => format!("AI explanation, from {engine} ({model})"),
        _ => format!("AI explanation, from {engine}"),
    }
}

/// The AI block of a Verdict on one line, or None: only a malicious Verdict
/// with a reason left after containment shows one. The reason is plain text
/// of at most 240 characters with escape sequences, control and bidi
/// characters, markdown links and marks removed.
pub fn ai_block(verdict: &Verdict<'_>, posture: Posture) -> Option<String> {
    if verdict.said != Said::Malicious {
        return None;
    }
    let reason = contain_reason(verdict.reason);
    match reason.is_empty() {
        true => None,
        false => Some(format!(
            "{}: {reason}",
            label(verdict.engine, verdict.model, posture)
        )),
    }
}

/// The "checked by <engine>" note of an Item a benign Verdict moved to
/// Clear, in the Developer Posture only.
pub fn checked_by(item: &CheckedItem, posture: Posture) -> Option<String> {
    if posture != Posture::Developer {
        return None;
    }
    let engine = engine_name(&item.engine);
    let by = match item.model.is_empty() {
        true => engine.to_string(),
        false => format!("{engine} ({})", item.model),
    };
    Some(format!(
        "{} · {}: checked by {by}",
        item.kind,
        wording::name(item.kind, item.item_id.as_str())
    ))
}

/// The "checked by <engine>" notes as the window receives them: none in the
/// Simple Posture.
pub fn checked_value(items: &[CheckedItem], posture: Posture) -> Value {
    Value::Array(
        items
            .iter()
            .filter_map(|item| {
                checked_by(item, posture)
                    .map(|line| json!({ "id": item.item_id.as_str(), "line": line }))
            })
            .collect(),
    )
}

/// How far the AI Judgement queue has got, as the stream last said it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Queue {
    /// How many Items it has had answered, a Verdict or none.
    pub done: usize,
    /// How many it holds altogether.
    pub total: usize,
}

impl Queue {
    /// True while Items are still waiting for an answer.
    pub fn running(&self) -> bool {
        self.done < self.total
    }
}

/// The queue progress line, "AI check: 3 of 12", while the queue runs and in
/// the Developer Posture only.
pub fn progress_line(queue: Queue, posture: Posture) -> Option<String> {
    match posture == Posture::Developer && queue.running() {
        true => Some(format!("AI check: {} of {}", queue.done, queue.total)),
        false => None,
    }
}

/// The fixed cap line, in both Postures, while a cap holds Items back.
pub fn cap_line(health: &Health) -> Option<String> {
    health.judgement_cap.as_ref().map(|notice| notice.line())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use agentsweep_core::finding::{Category, FindingState};
    use agentsweep_core::finding_facts::HeuristicLine;
    use agentsweep_core::item::{ItemId, Kind};
    use agentsweep_core::overview::AmbiguousItem;
    use agentsweep_core::settings::{CloudCaps, JudgementEngine};
    use agentsweep_core::spend::{CapNotice, JudgementCap};
    use agentsweep_ipc::engine::{CloudUse, EngineState};
    use agentsweep_ipc::protocol::{SettingsState, StateEvent, Status};

    use crate::findings::tests::{recorded, status_of};
    use crate::frame::Frame;

    const CAP_LINE: &str =
        "The AI check reached its limit for this scan. 4 items will be looked at next time.";

    fn malicious(reason: &str) -> Verdict<'_> {
        Verdict {
            said: Said::Malicious,
            engine: "ollama",
            model: "qwen3:8b",
            reason,
        }
    }

    /// A reason with a markdown link, emphasis, a bidi override, a control
    /// character and 400 characters renders as plain text of at most 240
    /// characters with none of them left.
    #[test]
    fn the_ai_block_is_plain_text_of_at_most_240_characters() {
        let reason = format!(
            "**Run** [this](https://evil.invalid/x) now \u{202e}gnp.exe\u{202c} \u{7}`code` {}",
            "a".repeat(400)
        );
        for posture in Posture::ALL {
            let block = ai_block(&malicious(&reason), posture).expect("a block");
            let label = label("ollama", "qwen3:8b", posture);
            let text = block
                .strip_prefix(&format!("{label}: "))
                .expect("the label first");
            assert!(text.chars().count() <= 240, "{}", text.chars().count());
            assert!(text.starts_with("Run this now gnp.exe code a"), "{text}");
            for gone in [
                "**", "`", "[", "](", "https://", "\u{202e}", "\u{202c}", "\u{7}",
            ] {
                assert!(!text.contains(gone), "{gone:?} in {text}");
            }
            assert!(!text.chars().any(char::is_control));
        }
    }

    #[test]
    fn the_label_names_the_engine_and_the_developer_posture_adds_the_model() {
        let reason = "It tells the agent its rules no longer apply.";
        assert_eq!(
            ai_block(&malicious(reason), Posture::Simple).as_deref(),
            Some("AI explanation, from Ollama: It tells the agent its rules no longer apply.")
        );
        assert_eq!(
            ai_block(&malicious(reason), Posture::Developer).as_deref(),
            Some(
                "AI explanation, from Ollama (qwen3:8b): It tells the agent its rules no longer \
                 apply."
            )
        );
    }

    #[test]
    fn benign_and_unsure_verdicts_show_no_engine_text() {
        for said in [Said::Benign, Said::Unsure] {
            let verdict = Verdict {
                said,
                ..malicious("It looks fine.")
            };
            for posture in Posture::ALL {
                assert_eq!(ai_block(&verdict, posture), None);
            }
        }
        // A malicious reason that contains to nothing shows no block either.
        assert_eq!(
            ai_block(&malicious("\u{202e}\u{7} "), Posture::Simple),
            None
        );
    }

    #[test]
    fn checked_by_is_a_developer_note_only() {
        let item = CheckedItem {
            item_id: ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/pdf-helper"),
            kind: Kind::Skill,
            engine: "apple".to_string(),
            model: "25A100".to_string(),
        };
        assert_eq!(checked_by(&item, Posture::Simple), None);
        assert_eq!(
            checked_value(std::slice::from_ref(&item), Posture::Simple),
            json!([])
        );
        let note = checked_by(&item, Posture::Developer).expect("a note");
        assert!(
            note.ends_with("pdf-helper: checked by Apple on-device (25A100)"),
            "{note}"
        );
    }

    #[test]
    fn the_progress_line_shows_in_the_developer_posture_while_the_queue_runs() {
        let running = Queue { done: 3, total: 12 };
        assert_eq!(
            progress_line(running, Posture::Developer).as_deref(),
            Some("AI check: 3 of 12")
        );
        assert_eq!(progress_line(running, Posture::Simple), None);
        let done = Queue {
            done: 12,
            total: 12,
        };
        assert_eq!(progress_line(done, Posture::Developer), None);
        assert_eq!(progress_line(Queue::default(), Posture::Developer), None);
    }

    #[test]
    fn the_cap_line_is_the_fixed_sentence() {
        let mut health = Health::running();
        assert_eq!(cap_line(&health), None);
        health.judgement_cap = Some(CapNotice {
            cap: JudgementCap::Day,
            waiting: 4,
        });
        assert_eq!(
            cap_line(&health).as_deref(),
            Some(
                "The AI check reached its limit for this scan. 4 items will be looked at next time."
            )
        );
    }

    fn settings(posture: Posture) -> SettingsState {
        SettingsState {
            rule_feed: true,
            update_check: true,
            posture,
            config_dirs: BTreeMap::new(),
            engine: EngineState {
                engine: JudgementEngine::Ollama,
                ollama_address: "127.0.0.1:11434".to_string(),
                ollama_model: "qwen3:8b".to_string(),
                claude_model: String::new(),
                claude_model_in_use: String::new(),
                caps: CloudCaps::default(),
                claude_key_ending: None,
                recorded: 0,
                ollama: None,
                apple: None,
                cloud_use: CloudUse::default(),
            },
        }
    }

    fn heuristic(id: i64) -> HeuristicLine {
        HeuristicLine {
            id,
            weight: 3,
            plain: format!("Heuristic {id} saw an override."),
            excerpt: String::new(),
        }
    }

    /// One open T3 Finding from a malicious Verdict; one Item a benign
    /// Verdict moved to Clear; one Item an unsure Verdict left Ambiguous; a
    /// cap holding four Items back.
    fn status() -> Status {
        let mut judged = recorded(
            "claude-code/user/skill/~/.claude/skills/notes-sync",
            Kind::Skill,
            "score 6",
            Category::Threat,
            FindingState::Open,
        );
        judged.tier = Tier::AiJudgement;
        judged.facts.heuristics = vec![heuristic(520)];
        judged.facts.judgement_engine = "ollama".to_string();
        judged.facts.judgement_model = "qwen3:8b".to_string();
        judged.facts.judgement_reason = "It tells the agent its rules no longer apply.".to_string();
        let mut status = status_of(vec![judged]);
        status.health.judgement_cap = Some(CapNotice {
            cap: JudgementCap::Scan,
            waiting: 4,
        });
        status.overview.checked = vec![CheckedItem {
            item_id: ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/benign-helper"),
            kind: Kind::Skill,
            engine: "ollama".to_string(),
            model: "qwen3:8b".to_string(),
        }];
        status.overview.ambiguous = vec![AmbiguousItem {
            item_id: ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/odd-helper"),
            kind: Kind::Skill,
            score: 3,
            heuristics: vec![heuristic(520)],
        }];
        status
    }

    fn frame(posture: Posture) -> Frame {
        let mut frame = Frame::new();
        frame.load(&status());
        frame.settings(&settings(posture));
        frame
    }

    /// A card's body lines as the window renders them in a Posture, each as
    /// `part|text`.
    fn shown_lines(card: &Value, posture: Posture) -> Vec<String> {
        let lines = match posture {
            Posture::Simple => &card["simple"]["lines"],
            Posture::Developer => &card["developer"]["lines"],
        };
        lines
            .as_array()
            .expect("lines")
            .iter()
            .map(|line| {
                format!(
                    "{}|{}",
                    line["part"].as_str().unwrap_or_default(),
                    line["text"].as_str().unwrap_or_default()
                )
            })
            .collect()
    }

    /// The malicious Verdict's block stands beneath the Heuristic lines in
    /// both Postures; the Developer Posture names the model.
    #[test]
    fn a_t3_finding_carries_the_ai_block_beneath_the_heuristic_lines() {
        for (posture, label) in [
            (Posture::Simple, "AI explanation, from Ollama: "),
            (
                Posture::Developer,
                "AI explanation, from Ollama (qwen3:8b): ",
            ),
        ] {
            let value = frame(posture).to_value();
            let card = &value["panes"]["threats"][0];
            let lines = shown_lines(card, posture);
            assert_eq!(
                lines[0], "heuristic|Heuristic 520 saw an override.",
                "{lines:?}"
            );
            assert_eq!(
                lines[1],
                format!("ai|{label}It tells the agent its rules no longer apply."),
                "{posture:?}"
            );
            assert!(lines[2..].iter().all(|line| !line.starts_with("ai|")));
        }
    }

    /// Benign and unsure never show engine text in either Posture; the
    /// benign Item's "checked by <engine>" note is in the Developer Posture
    /// only. Apart from the malicious Verdict's own card and the Settings
    /// pane's AI check, the window names the engine nowhere.
    #[test]
    fn benign_and_unsure_show_no_engine_text_and_checked_by_is_developer_only() {
        for posture in Posture::ALL {
            let mut value = frame(posture).to_value();
            let checked = std::mem::take(&mut value["checked"]);
            match posture {
                Posture::Simple => assert_eq!(checked, Value::Null),
                Posture::Developer => assert_eq!(
                    checked,
                    json!([{
                        "id": "claude-code/user/skill/~/.claude/skills/benign-helper",
                        "line": "Skill · benign-helper: checked by Ollama (qwen3:8b)",
                    }])
                ),
            }
            let ambiguous = value["ambiguous"].to_string();
            assert!(
                !ambiguous.contains("Ollama") && !ambiguous.contains("qwen"),
                "{ambiguous}"
            );
            for key in ["settings", "panes", "open"] {
                value[key] = Value::Null;
            }
            let rest = value.to_string();
            for engine_text in [
                "Ollama",
                "qwen",
                "checked by",
                "benign-helper",
                "AI explanation",
            ] {
                assert!(
                    !rest.contains(engine_text),
                    "{posture:?}: {engine_text} in {rest}"
                );
            }
        }
    }

    /// The queue progress line is on the Overview and in the Activity of the
    /// Developer Posture while the queue runs, never in the Simple Posture;
    /// the cap line is on the Overview of both, verbatim.
    #[test]
    fn the_progress_line_is_developer_only_and_the_cap_line_is_in_both() {
        for posture in Posture::ALL {
            let mut frame = frame(posture);
            assert_eq!(frame.overview().cap.as_deref(), Some(CAP_LINE));
            assert_eq!(frame.to_value()["overview"]["cap"], CAP_LINE);
            assert_eq!(frame.to_value()["overview"]["aiCheck"], Value::Null);

            frame.apply(&StateEvent::JudgementProgress { done: 3, total: 12 });
            let value = frame.to_value();
            let progress = match posture {
                Posture::Developer => Value::from("AI check: 3 of 12"),
                Posture::Simple => Value::Null,
            };
            assert_eq!(value["overview"]["aiCheck"], progress, "{posture:?}");
            assert_eq!(value["activity"]["aiCheck"], progress, "{posture:?}");
            if posture == Posture::Simple {
                assert!(!value.to_string().contains("AI check: "), "{value}");
            }

            // The queue drained: the line goes; the cap line stays.
            frame.apply(&StateEvent::JudgementProgress {
                done: 12,
                total: 12,
            });
            let value = frame.to_value();
            assert_eq!(value["overview"]["aiCheck"], Value::Null);
            assert_eq!(value["activity"]["aiCheck"], Value::Null);
            assert_eq!(value["overview"]["cap"], CAP_LINE);
        }
    }
}
