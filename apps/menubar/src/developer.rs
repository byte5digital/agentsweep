//! How a Finding reads in the Developer Posture (spec sections 8.2 and 8.4):
//! the title `<Kind> · <name>` with chips for Severity (the four glossary
//! values), Tier, category, Probation, Scope and Activation, above the same
//! body lines the Simple Posture shows and the technical table, shown always.
//!
//! The Items whose Score fell in the Ambiguous Band are listed here too, in
//! the Developer Posture's Threat Findings pane only: the Ambiguous Band is
//! never a Finding (spec section 4.3), so each Item shows its Score and its
//! Heuristic lines and offers nothing beyond its technical details. The
//! Simple Posture never shows an Ambiguous Item or an Ambiguous count (spec
//! section 8.4); [`crate::frame::Frame::to_value`] leaves them out there.
//!
//! Everything here is a pure function of what the daemon sent.

use agentsweep_core::adapter::{Primitive, eligibility};
use agentsweep_core::finding::{FindingState, RuleStatus, Tier};
use agentsweep_core::overview::AmbiguousItem;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use serde_json::{Value, json};

use crate::wording::{self, heuristic_row, rows_value};

/// One chip beside the Developer title.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chip {
    /// Which fact it shows: `severity`, `tier`, `category`, `probation`,
    /// `scope` or `activation`.
    pub fact: &'static str,
    /// What it says.
    pub text: String,
}

/// The Developer title and its chips.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Heading {
    /// `<Kind> · <name>`.
    pub title: String,
    /// The chips, in the order spec section 8.4 lists them. A fact that is
    /// not known (the Activation of an Item in the quarantine store) or does
    /// not apply (Probation on a stable Rule) has no chip.
    pub chips: Vec<Chip>,
}

impl Heading {
    /// The value the window receives.
    pub fn to_value(&self) -> Value {
        json!({
            "title": self.title,
            "chips": self
                .chips
                .iter()
                .map(|chip| json!({ "fact": chip.fact, "text": chip.text }))
                .collect::<Vec<_>>(),
        })
    }

    /// The text of the chip for one fact, if there is one.
    pub fn chip(&self, fact: &str) -> Option<&str> {
        self.chips
            .iter()
            .find(|chip| chip.fact == fact)
            .map(|chip| chip.text.as_str())
    }
}

/// The title `<Kind> · <name>`: the kind as the glossary spells it, the name
/// as the Simple Posture reads it off the Item id.
fn titled(kind: agentsweep_core::item::Kind, item_id: &str) -> String {
    format!("{kind} · {}", wording::name(kind, item_id))
}

/// The Developer title and chips of one Finding.
pub fn heading(finding: &RecordedFinding) -> Heading {
    let facts = &finding.facts;
    let mut chips = vec![
        Chip {
            fact: "severity",
            text: finding.severity.as_str().to_string(),
        },
        Chip {
            fact: "tier",
            text: finding.tier.as_str().to_string(),
        },
        Chip {
            fact: "category",
            text: finding.category.as_str().to_string(),
        },
    ];
    if finding.tier == Tier::Rules && finding.rule_id > 0 && finding.status == RuleStatus::Probation
    {
        chips.push(Chip {
            fact: "probation",
            text: "probation".to_string(),
        });
    }
    if !facts.scope.is_empty() {
        chips.push(Chip {
            fact: "scope",
            text: facts.scope.clone(),
        });
    }
    let activation = match (facts.activation.as_str(), facts.inactive_reason.as_str()) {
        ("", _) => None,
        (activation, "") => Some(activation.to_string()),
        (activation, reason) => Some(format!("{activation} ({reason})")),
    };
    if let Some(text) = activation {
        chips.push(Chip {
            fact: "activation",
            text,
        });
    }
    Heading {
        title: titled(finding.kind, finding.item_id.as_str()),
        chips,
    }
}

/// True when **Reveal in Finder** is offered on a Finding: in the Developer
/// Posture only (spec section 8.5), on a quarantined Item only, and only
/// where its Quarantine moved something into the store. An entry taken out
/// of its file, a line switched off in place and an Item whose Quarantine is
/// the Agent's own switch keep no payload.
pub fn offers_reveal(finding: &RecordedFinding, posture: Posture) -> bool {
    posture == Posture::Developer
        && finding.state == FindingState::Stopped
        && !finding.receipt_id.is_empty()
        && !finding.switched
        && eligibility(finding.kind)
            .primitives
            .contains(&Primitive::MoveOut)
}

/// The technical table of one Ambiguous Item: its id, kind, Score, Band and
/// one row per fired Heuristic with its Weight and redacted excerpt.
pub fn ambiguous_technical(item: &AmbiguousItem) -> Vec<(String, String)> {
    let mut rows = vec![
        ("Item".to_string(), item.item_id.as_str().to_string()),
        ("Kind".to_string(), item.kind.to_string()),
        ("Score".to_string(), item.score.to_string()),
        ("Band".to_string(), "Ambiguous".to_string()),
    ];
    rows.extend(item.heuristics.iter().map(heuristic_row));
    rows
}

/// One Ambiguous Item as the Developer Posture lists it: its title, its
/// Score line, its Heuristic lines and its technical table. No action.
pub fn ambiguous_card(item: &AmbiguousItem) -> Value {
    json!({
        "id": item.item_id.as_str(),
        "title": titled(item.kind, item.item_id.as_str()),
        "score": format!("Score {}, Ambiguous Band", item.score),
        "lines": item
            .heuristics
            .iter()
            .map(|line| format!("{:04} · weight {} · {}", line.id, line.weight, line.plain))
            .collect::<Vec<_>>(),
        "technical": rows_value(ambiguous_technical(item)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::finding::{Category, Severity};
    use agentsweep_core::finding_facts::HeuristicLine;
    use agentsweep_core::item::{ItemId, Kind};

    use crate::findings::tests::recorded;

    fn finding(item: &str, kind: Kind, source: &str, category: Category) -> RecordedFinding {
        let mut finding = recorded(item, kind, source, category, FindingState::Open);
        finding.facts.scope = "user".to_string();
        finding.facts.activation = "active".to_string();
        finding
    }

    #[test]
    fn a_probation_rule_finding_shows_every_chip() {
        let mut planted = finding(
            "claude-code/project:/src/acme/instruction-file/CLAUDE.md",
            Kind::InstructionFile,
            "rule 0003",
            Category::Threat,
        );
        planted.severity = Severity::Critical;
        planted.facts.scope = "project".to_string();
        planted.facts.activation = "inactive".to_string();
        planted.facts.inactive_reason = "untrusted_project".to_string();
        let heading = heading(&planted);
        assert_eq!(heading.title, "InstructionFile · CLAUDE.md");
        assert_eq!(
            heading
                .chips
                .iter()
                .map(|chip| (chip.fact, chip.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("severity", "critical"),
                ("tier", "T1"),
                ("category", "threat"),
                ("probation", "probation"),
                ("scope", "project"),
                ("activation", "inactive (untrusted_project)"),
            ]
        );
    }

    #[test]
    fn a_suspicious_finding_is_t2_without_a_probation_chip() {
        let mut suspicious = finding(
            "claude-code/user/skill/~/.claude/skills/doc-refresher",
            Kind::Skill,
            "score 5",
            Category::Threat,
        );
        suspicious.severity = Severity::Medium;
        let heading = heading(&suspicious);
        assert_eq!(heading.title, "Skill · doc-refresher");
        assert_eq!(heading.chip("tier"), Some("T2"));
        assert_eq!(heading.chip("severity"), Some("medium"));
        assert_eq!(heading.chip("probation"), None);
        assert_eq!(heading.chip("activation"), Some("active"));
    }

    #[test]
    fn a_drift_question_names_the_server_and_is_high_t2() {
        let mut moved = finding(
            "claude-code/user/mcp-server/~/.claude.json#notes",
            Kind::McpServer,
            "drift",
            Category::Threat,
        );
        moved.tier = Tier::Heuristics;
        let heading = heading(&moved);
        assert_eq!(heading.title, "McpServer · notes");
        assert_eq!(heading.chip("severity"), Some("high"));
        assert_eq!(heading.chip("tier"), Some("T2"));
        assert_eq!(heading.chip("probation"), None, "no Rule behind it");
        assert_eq!(heading.chip("scope"), Some("user"));
    }

    #[test]
    fn an_exposure_shows_its_category_and_severity_value() {
        let mut exposure = finding(
            "claude-code/user/mcp-server/~/.claude.json#github",
            Kind::McpServer,
            "rule 0010",
            Category::Exposure,
        );
        exposure.severity = Severity::Low;
        exposure.status = RuleStatus::Stable;
        let heading = heading(&exposure);
        assert_eq!(heading.title, "McpServer · github");
        assert_eq!(heading.chip("category"), Some("exposure"));
        assert_eq!(heading.chip("severity"), Some("low"));
        assert_eq!(heading.chip("probation"), None, "a stable Rule");
        let value = heading.to_value();
        assert_eq!(value["title"], "McpServer · github");
        assert_eq!(value["chips"][1]["fact"], "tier");
    }

    #[test]
    fn reveal_in_finder_is_offered_in_developer_on_a_moved_out_item_only() {
        let skill = "claude-code/user/skill/~/.claude/skills/pdf-helper";
        let mut stopped = recorded(
            skill,
            Kind::Skill,
            "rule 0001",
            Category::Threat,
            FindingState::Stopped,
        );
        assert!(offers_reveal(&stopped, Posture::Developer));
        assert!(!offers_reveal(&stopped, Posture::Simple), "Developer only");

        let open = recorded(
            skill,
            Kind::Skill,
            "rule 0001",
            Category::Threat,
            FindingState::Open,
        );
        assert!(!offers_reveal(&open, Posture::Developer), "not quarantined");

        stopped.switched = true;
        assert!(!offers_reveal(&stopped, Posture::Developer), "a switch");

        let entry = recorded(
            "claude-code/user/mcp-server/~/.claude.json#notes",
            Kind::McpServer,
            "rule 0004",
            Category::Threat,
            FindingState::Stopped,
        );
        assert!(!offers_reveal(&entry, Posture::Developer), "no payload");
        let line = recorded(
            "workspace/project:/src/x/repository-metadata/.git/config#core.fsmonitor",
            Kind::RepositoryMetadata,
            "rule 0009",
            Category::Threat,
            FindingState::Stopped,
        );
        assert!(
            !offers_reveal(&line, Posture::Developer),
            "switched off in place"
        );
    }

    #[test]
    fn an_ambiguous_item_shows_its_score_and_heuristics_and_no_action() {
        let item = AmbiguousItem {
            item_id: ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/notes"),
            kind: Kind::Skill,
            score: 3,
            heuristics: vec![HeuristicLine {
                id: 521,
                weight: 3,
                plain: "It asks the agent to keep a secret.".to_string(),
                excerpt: "sha256:0123456789ab".to_string(),
            }],
        };
        let card = ambiguous_card(&item);
        assert_eq!(card["title"], "Skill · notes");
        assert_eq!(card["score"], "Score 3, Ambiguous Band");
        assert_eq!(
            card["lines"][0],
            "0521 · weight 3 · It asks the agent to keep a secret."
        );
        assert!(card.get("actions").is_none());
        let rows = ambiguous_technical(&item);
        assert!(rows.contains(&("Score".to_string(), "3".to_string())));
        assert!(rows.contains(&(
            "Heuristic 0521".to_string(),
            "weight 3 · sha256:0123456789ab".to_string()
        )));
    }
}
