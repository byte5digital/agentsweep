//! What two Heuristics on one Item add up to, through the path a Scan takes.
//!
//! The Fixture is the skill rule 0533 ships: one sentence that tells the agent
//! to drop the instructions it already has (0520, weight 3) and one command
//! whose name is broken up so it cannot be read (0533, weight 3). The corpus
//! runner proves both fire; this proves what the core then makes of them, with
//! the bundled Rule Pack and the Band thresholds that pack's manifest states.

use std::path::PathBuf;

use agentsweep_core::finding::{Category, Source, Tier};
use agentsweep_core::heuristics::{Band, SUSPICIOUS_PLAIN};
use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};
use agentsweep_core::pack::Manifest;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan::Scanners;

/// The Fixture itself, so the Fixture and this test can never drift apart.
const SKILL: &str = include_str!(
    "../../../rules/0533-command-name-splitting/bad/skill-overrides-and-splits-a-command/tree/SKILL.md"
);

/// The skill as the Surface Adapter would hand it over.
fn skill(content: &str) -> Item {
    Item::file(
        "claude-code",
        Scope::User,
        Kind::Skill,
        "skills/doc-refresher",
        PathBuf::from("/Users/example/.claude/skills/doc-refresher/SKILL.md"),
        Provenance::Manual,
        Activation::Active,
        content.as_bytes().to_vec(),
    )
}

/// The same skill with the override sentence taken out, so what is left is the
/// split command on its own.
fn without_the_override_sentence(content: &str) -> String {
    content
        .lines()
        .filter(|line| !line.starts_with("Ignore all previous instructions"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn two_heuristics_of_weight_three_score_six_and_land_suspicious() {
    let pack = RulePack::bundled().expect("the bundled pack compiles");
    let mut scanners = Scanners::with_bands(&pack, Manifest::bundled().bands);

    let item = skill(SKILL);
    let assessment = scanners.assess(&item).expect("the skill is scanned");

    let fired: Vec<(i64, i64)> = assessment
        .fired
        .iter()
        .map(|heuristic| (heuristic.id, heuristic.weight))
        .collect();
    assert_eq!(
        fired,
        vec![(520, 3), (533, 3)],
        "the override phrasing and the split command, each once"
    );
    assert_eq!(assessment.score, 6);
    assert_eq!(assessment.band, Band::Suspicious);
    assert!(
        !assessment.awaits_judgement(),
        "a Suspicious Item is a Finding, not a question for an engine"
    );

    assert_eq!(assessment.findings.len(), 1, "one Finding for the Item");
    let finding = &assessment.findings[0];
    assert_eq!(finding.source, Source::Score(6));
    assert_eq!(finding.tier, Tier::Heuristics);
    assert_eq!(finding.category, Category::Threat);
    assert_eq!(finding.plain, SUSPICIOUS_PLAIN);
    let listed: Vec<i64> = finding.heuristics.iter().map(|h| h.id).collect();
    assert_eq!(listed, vec![520, 533], "both are named under the Finding");
    assert!(
        finding
            .heuristics
            .iter()
            .any(|heuristic| heuristic.reviewer_directed),
        "the override phrasing is written for whatever reads the file next, so a benign Verdict on this Item counts as unsure"
    );
}

#[test]
fn the_split_command_on_its_own_stays_in_the_ambiguous_band() {
    let pack = RulePack::bundled().expect("the bundled pack compiles");
    let mut scanners = Scanners::with_bands(&pack, Manifest::bundled().bands);

    let item = skill(&without_the_override_sentence(SKILL));
    let assessment = scanners.assess(&item).expect("the skill is scanned");

    let fired: Vec<i64> = assessment.fired.iter().map(|h| h.id).collect();
    assert_eq!(fired, vec![533], "only the split command is left");
    assert_eq!(assessment.score, 3);
    assert_eq!(assessment.band, Band::Ambiguous);
    assert!(
        assessment.findings.is_empty(),
        "the Ambiguous Band raises no Finding"
    );
    assert!(assessment.awaits_judgement());
}
