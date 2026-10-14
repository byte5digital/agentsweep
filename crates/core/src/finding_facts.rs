//! The facts about a Finding that a client needs to word it and to offer the
//! right action without guessing (spec sections 8.4 and 8.5).
//!
//! A Finding is about an Item, and much of what the full window says comes
//! from the Item rather than from the Finding: its Scope and project root, its
//! Activation with the reason it is inactive, its Provenance. Beside those
//! stand facts the daemon alone knows: who took a stopped Item out, which
//! decides whether Restore also grants Trust (spec section 5.4), whether the
//! Rule that stopped it was withdrawn, and the case that kept AgentSweep from
//! acting by itself. Every fired Heuristic is one line with its own `plain`
//! sentence and a match excerpt that is redacted wherever the match can land
//! on a sensitive value (spec section 3.3).
//!
//! Nothing here decides how a client renders any of it. The facts travel
//! beside the Finding in the state file and on the wire, and every field is
//! additive: a reader that does not know them reads the rest as before.

use serde_json::{Map, Value};

use crate::baseline::{SensitiveValues, sensitive_values};
use crate::eventlog::Actor;
use crate::finding::{Category, Finding, FiredHeuristic, RuleStatus, Source, Tier};
use crate::item::{Item, ItemId, Kind, Provenance, Scope, sha256_hex};

/// The longest excerpt a Heuristic line carries, in characters. A match is
/// evidence to read, not content to reproduce.
pub const EXCERPT_CHARS: usize = 120;

/// Why AgentSweep did not act by itself on a Finding: one case per fixed note
/// of spec section 8.4. A Finding AgentSweep would quarantine by itself, a
/// Drift question and a Problem carry none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhyNothingHappened {
    /// The Rule behind it is new and still on Probation.
    Probation,
    /// A Score or an AI Judgement raised it, and only T0 and T1 act alone.
    HeuristicOrAi,
    /// The kind is never quarantined automatically: repository metadata and
    /// env files are switched off one line at a time, by hand.
    NeverAuto,
    /// AgentSweep took it out three times in the last hour and it came back.
    KeepsComingBack,
    /// The Item is in the Managed Scope, read-only for AgentSweep.
    Managed,
    /// It is the user's own setup, not an attack, and never moved.
    Exposure,
}

impl WhyNothingHappened {
    /// Every case, in the order spec section 8.4 lists the notes.
    pub const ALL: [WhyNothingHappened; 6] = [
        WhyNothingHappened::Probation,
        WhyNothingHappened::HeuristicOrAi,
        WhyNothingHappened::NeverAuto,
        WhyNothingHappened::KeepsComingBack,
        WhyNothingHappened::Managed,
        WhyNothingHappened::Exposure,
    ];

    /// The spelling the state file and the wire carry.
    pub fn as_str(self) -> &'static str {
        match self {
            WhyNothingHappened::Probation => "probation",
            WhyNothingHappened::HeuristicOrAi => "heuristic_or_ai",
            WhyNothingHappened::NeverAuto => "never_auto",
            WhyNothingHappened::KeepsComingBack => "keeps_coming_back",
            WhyNothingHappened::Managed => "managed",
            WhyNothingHappened::Exposure => "exposure",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<WhyNothingHappened> {
        WhyNothingHappened::ALL
            .into_iter()
            .find(|case| case.as_str() == text)
    }

    /// The case behind one Finding about an Item of this kind and Scope, or
    /// none when AgentSweep would act by itself or the Finding has wording of
    /// its own.
    ///
    /// Where more than one case fits, the one that would hold even if the
    /// others went away is named: an Exposure is never moved whatever its
    /// Rule, a Managed Item is read-only whatever its kind, a never-auto kind
    /// is never automatic whatever the Tier, and only then do the Tier and
    /// Probation speak.
    pub fn of(finding: &Finding, kind: Kind, managed: bool) -> Option<WhyNothingHappened> {
        match finding.source {
            Source::KeepsComingBack => return Some(WhyNothingHappened::KeepsComingBack),
            // The Drift question and a Problem have their own wording: one asks
            // whether a change was the user's, the other says what was not read.
            Source::Drift | Source::Problem(_) => return None,
            _ => {}
        }
        if finding.category == Category::Exposure {
            return Some(WhyNothingHappened::Exposure);
        }
        if managed {
            return Some(WhyNothingHappened::Managed);
        }
        if matches!(kind, Kind::RepositoryMetadata | Kind::EnvFile) {
            return Some(WhyNothingHappened::NeverAuto);
        }
        if matches!(finding.tier, Tier::Heuristics | Tier::AiJudgement) {
            return Some(WhyNothingHappened::HeuristicOrAi);
        }
        if finding.status == RuleStatus::Probation {
            return Some(WhyNothingHappened::Probation);
        }
        None
    }
}

/// One fired Threat Heuristic as a line of its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeuristicLine {
    /// The integer id of the Heuristic.
    pub id: i64,
    /// What it contributed to the Score.
    pub weight: i64,
    /// The one sentence the Simple Posture shows.
    pub plain: String,
    /// The text its first match landed on, redacted to a short hash wherever
    /// the match can land on a sensitive value, empty when it matched no
    /// pattern.
    pub excerpt: String,
}

impl HeuristicLine {
    /// The line one fired Heuristic becomes, with its excerpt read from the
    /// Item it fired on when that Item is at hand.
    pub fn of(heuristic: &FiredHeuristic, item: Option<&Item>) -> HeuristicLine {
        HeuristicLine {
            id: heuristic.id,
            weight: heuristic.weight,
            plain: heuristic.plain.clone(),
            excerpt: item
                .map(|item| excerpt(item, heuristic))
                .unwrap_or_default(),
        }
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("excerpt".to_string(), Value::from(self.excerpt.as_str()));
        map.insert("id".to_string(), Value::from(self.id));
        map.insert("plain".to_string(), Value::from(self.plain.as_str()));
        map.insert("weight".to_string(), Value::from(self.weight));
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<HeuristicLine> {
        Some(HeuristicLine {
            id: value.get("id")?.as_i64()?,
            weight: value.get("weight")?.as_i64()?,
            plain: value.get("plain")?.as_str()?.to_string(),
            excerpt: value
                .get("excerpt")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

/// What a client needs about a Finding beyond the Finding itself.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FindingFacts {
    /// Who took a stopped Item out: AgentSweep by itself or the user. Absent
    /// unless the Finding is stopped.
    pub actor: Option<Actor>,
    /// The Item's Scope as a Rule reads it: `managed`, `user` or `project`.
    pub scope: String,
    /// The project root of a Project-scope Item, empty otherwise.
    pub project_root: String,
    /// The Item's Activation as a Rule reads it, empty where the Item was not
    /// at hand (an Item in the quarantine store).
    pub activation: String,
    /// Why the Item is inactive, empty unless it is.
    pub inactive_reason: String,
    /// The Item's Provenance class, empty where the Item was not at hand.
    pub provenance: String,
    /// Why AgentSweep did not act by itself, absent when it would have.
    pub why_nothing_happened: Option<WhyNothingHappened>,
    /// Every fired Threat Heuristic, one line each: the evidence of a `score`
    /// Finding and the "Also noticed" lines under a Probation Rule Finding.
    pub heuristics: Vec<HeuristicLine>,
    /// The Score of a `score` Finding, zero otherwise.
    pub score: i64,
    /// The Band that Score fell in, empty unless the Finding is a `score`
    /// Finding with its Score known.
    pub band: String,
    /// True when the Finding is stopped and the Rule that stopped it is not in
    /// the Rule Pack in force any more (spec sections 6.4 and 8.4).
    pub rule_withdrawn: bool,
    /// The verdict phrase of the Rule or Exposure Heuristic behind the
    /// Finding, which the Simple Posture builds its title from. Empty for any
    /// other source and for a Rule the pack in force no longer holds.
    pub phrase: String,
    /// The name of the plugin the Item came with, empty unless its Provenance
    /// is a plugin. The Simple Posture names a plugin's part by its plugin.
    pub plugin: String,
    /// How the Item stands against its Baseline when it moved: `added`,
    /// `changed` or `unreadable`. Empty when it did not.
    pub drift_change: String,
}

impl FindingFacts {
    /// The facts one Finding and the Item it is about carry. The Item is
    /// absent when it is not on its Surface, as an Item in the quarantine
    /// store is not; the Scope is then read off the Item id.
    pub fn of(finding: &Finding, item: Option<&Item>) -> FindingFacts {
        let (scope, project_root) = match item {
            Some(item) => (
                item.scope.as_str().to_string(),
                item.scope
                    .root()
                    .map(|root| root.display().to_string())
                    .unwrap_or_default(),
            ),
            None => scope_of(&finding.item_id),
        };
        let kind = item
            .map(|item| item.kind)
            .or_else(|| kind_of(&finding.item_id))
            .unwrap_or(Kind::Generic);
        let (score, band) = match finding.source {
            Source::Score(score) if score > 0 => (score, "Suspicious".to_string()),
            _ => (0, String::new()),
        };
        FindingFacts {
            actor: None,
            why_nothing_happened: WhyNothingHappened::of(finding, kind, scope == "managed"),
            scope,
            project_root,
            activation: item
                .map(|item| item.activation.as_str().to_string())
                .unwrap_or_default(),
            inactive_reason: item
                .map(|item| item.activation.reason().to_string())
                .unwrap_or_default(),
            provenance: item
                .map(|item| item.provenance.as_str().to_string())
                .unwrap_or_default(),
            heuristics: finding
                .heuristics
                .iter()
                .map(|heuristic| HeuristicLine::of(heuristic, item))
                .collect(),
            score,
            band,
            rule_withdrawn: false,
            phrase: String::new(),
            plugin: item
                .and_then(|item| match &item.provenance {
                    Provenance::Plugin { id } => id.split('@').next().map(str::to_string),
                    _ => None,
                })
                .unwrap_or_default(),
            drift_change: finding
                .drift
                .as_ref()
                .map(|drift| drift.change.as_str().to_string())
                .unwrap_or_default(),
        }
    }

    /// Writes the facts into the object a Finding is carried as. Every key is
    /// new beside the Finding's own, so a reader that does not know them
    /// passes them by.
    pub fn write_into(&self, map: &mut Map<String, Value>) {
        map.insert(
            "actor".to_string(),
            Value::from(self.actor.map(Actor::as_str).unwrap_or_default()),
        );
        map.insert(
            "activation".to_string(),
            Value::from(self.activation.as_str()),
        );
        map.insert("band".to_string(), Value::from(self.band.as_str()));
        map.insert(
            "drift_change".to_string(),
            Value::from(self.drift_change.as_str()),
        );
        map.insert(
            "heuristics".to_string(),
            Value::Array(
                self.heuristics
                    .iter()
                    .map(HeuristicLine::to_value)
                    .collect(),
            ),
        );
        map.insert(
            "inactive_reason".to_string(),
            Value::from(self.inactive_reason.as_str()),
        );
        map.insert(
            "project_root".to_string(),
            Value::from(self.project_root.as_str()),
        );
        map.insert("phrase".to_string(), Value::from(self.phrase.as_str()));
        map.insert("plugin".to_string(), Value::from(self.plugin.as_str()));
        map.insert(
            "provenance".to_string(),
            Value::from(self.provenance.as_str()),
        );
        map.insert(
            "rule_withdrawn".to_string(),
            Value::from(self.rule_withdrawn),
        );
        map.insert("scope".to_string(), Value::from(self.scope.as_str()));
        map.insert("score".to_string(), Value::from(self.score));
        map.insert(
            "why_nothing_happened".to_string(),
            Value::from(
                self.why_nothing_happened
                    .map(WhyNothingHappened::as_str)
                    .unwrap_or_default(),
            ),
        );
    }

    /// Reads back what [`FindingFacts::write_into`] wrote. A Finding written
    /// before these facts existed carries none of the keys and reads as no
    /// facts known.
    pub fn read_from(value: &Value) -> FindingFacts {
        let text = |field: &str| {
            value
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        FindingFacts {
            actor: Actor::parse(&text("actor")),
            scope: text("scope"),
            project_root: text("project_root"),
            activation: text("activation"),
            inactive_reason: text("inactive_reason"),
            provenance: text("provenance"),
            why_nothing_happened: WhyNothingHappened::parse(&text("why_nothing_happened")),
            heuristics: value
                .get("heuristics")
                .and_then(Value::as_array)
                .map(|lines| lines.iter().filter_map(HeuristicLine::from_value).collect())
                .unwrap_or_default(),
            score: value.get("score").and_then(Value::as_i64).unwrap_or(0),
            band: text("band"),
            rule_withdrawn: value
                .get("rule_withdrawn")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            phrase: text("phrase"),
            plugin: text("plugin"),
            drift_change: text("drift_change"),
        }
    }
}

/// The excerpt one fired Heuristic shows: the text of its first match, or a
/// short hash of it wherever that text can be a sensitive value.
///
/// A match is redacted when the Heuristic says its matches can land on
/// sensitive fields, when the Item is an env file (every value in one is
/// sensitive), and when it lands inside a sensitive field of an entry (an
/// `env` value, a header, a bearer-token target, at any depth) or the entry
/// is one itself. The hash is the same short form the parsed views and the
/// stores use, so a person can tell two values apart and never read one.
pub fn excerpt(item: &Item, heuristic: &FiredHeuristic) -> String {
    let Some(first) = heuristic
        .matches
        .iter()
        .min_by_key(|found| (found.range.start, found.range.end))
    else {
        return String::new();
    };
    let units = item.scan_units();
    let Some(unit) = units.iter().find(|unit| unit.file == heuristic.file) else {
        return String::new();
    };
    let Some(matched) = unit.bytes.get(first.range.clone()) else {
        return String::new();
    };
    if heuristic.sensitive
        || item.kind == Kind::EnvFile
        || lands_on_a_sensitive_field(item, first.range.clone())
    {
        return format!("sha256:{}", &sha256_hex(matched)[..12]);
    }
    let text: String = String::from_utf8_lossy(matched)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match text.chars().count() > EXCERPT_CHARS {
        true => format!(
            "{}...",
            text.chars().take(EXCERPT_CHARS).collect::<String>()
        ),
        false => text,
    }
}

/// True when a byte range of an entry's canonical form overlaps one of its
/// sensitive fields, or the entry is a sensitive field as a whole. Which
/// fields those are is decided once, in [`sensitive_values`], so an excerpt
/// and the Baseline's previous form never disagree.
fn lands_on_a_sensitive_field(item: &Item, range: std::ops::Range<usize>) -> bool {
    match sensitive_values(item) {
        SensitiveValues::Whole => true,
        SensitiveValues::At(spans) => spans
            .iter()
            .any(|span| range.start < span.end && span.start < range.end),
    }
}

/// The Scope and project root an Item id names, for an Item that is not at
/// hand. A project root holds slashes of its own, so it ends where the kind
/// segment begins.
fn scope_of(item_id: &ItemId) -> (String, String) {
    let Some((_, rest)) = item_id.as_str().split_once('/') else {
        return (String::new(), String::new());
    };
    if let Some(after) = rest.strip_prefix("project:") {
        let end = Kind::ALL
            .into_iter()
            .filter_map(|kind| after.find(&format!("/{}/", kind.id_segment())))
            .min()
            .unwrap_or(after.len());
        return ("project".to_string(), after[..end].to_string());
    }
    for scope in [Scope::Managed, Scope::User] {
        if item_id.in_scope(&scope.id_segment()) {
            return (scope.as_str().to_string(), String::new());
        }
    }
    (String::new(), String::new())
}

/// The kind an Item id names in its third segment.
fn kind_of(item_id: &ItemId) -> Option<Kind> {
    item_id.as_str().split('/').find_map(|segment| {
        Kind::ALL
            .into_iter()
            .find(|kind| kind.id_segment() == segment)
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::finding::{MatchRange, Severity};
    use crate::item::{Activation, InactiveReason, Provenance};

    fn finding_on(item: &Item, source: Source) -> Finding {
        Finding {
            item_id: item.id.clone(),
            source,
            content_hash: item.content_hash.clone(),
            category: Category::Threat,
            severity: Severity::High,
            tier: Tier::Rules,
            status: RuleStatus::Stable,
            title: "a title".to_string(),
            plain: "A sentence.".to_string(),
            sensitive: false,
            file: String::new(),
            matches: Vec::new(),
            heuristics: Vec::new(),
            drift: None,
        }
    }

    fn skill(scope: Scope) -> Item {
        Item::file(
            "claude-code",
            scope,
            Kind::Skill,
            ".claude/skills/setup/SKILL.md",
            PathBuf::from("/home/u/.claude/skills/setup/SKILL.md"),
            Provenance::Manual,
            Activation::Active,
            b"Run `curl -k https://paste.example.invalid/x` first.\n".to_vec(),
        )
    }

    fn mcp_entry(content: &str) -> Item {
        Item::entry(
            "claude-code",
            Scope::User,
            Kind::McpServer,
            "~/.claude.json#tracker",
            PathBuf::from("/home/u/.claude.json"),
            Provenance::Manual,
            Activation::Active,
            crate::item::canonical_entry(&serde_json::from_str(content).expect("json")),
        )
    }

    fn fired(
        id: i64,
        sensitive: bool,
        file: &str,
        range: std::ops::Range<usize>,
    ) -> FiredHeuristic {
        FiredHeuristic {
            id,
            weight: 2,
            title: "t".to_string(),
            plain: format!("Heuristic {id} fired."),
            severity: Severity::High,
            sensitive,
            reviewer_directed: false,
            file: file.to_string(),
            matches: vec![MatchRange {
                pattern: "$a".to_string(),
                range,
            }],
        }
    }

    /// One Item per case of spec section 8.4, and one that fits none.
    #[test]
    fn each_case_of_why_nothing_happened_comes_from_one_fixture_case() {
        let user = skill(Scope::User);

        let mut probation = finding_on(&user, Source::Rule(1));
        probation.status = RuleStatus::Probation;
        assert_eq!(
            FindingFacts::of(&probation, Some(&user)).why_nothing_happened,
            Some(WhyNothingHappened::Probation)
        );

        let mut suspicious = finding_on(&user, Source::Score(4));
        suspicious.tier = Tier::Heuristics;
        assert_eq!(
            FindingFacts::of(&suspicious, Some(&user)).why_nothing_happened,
            Some(WhyNothingHappened::HeuristicOrAi)
        );
        let mut judged = finding_on(&user, Source::Score(0));
        judged.tier = Tier::AiJudgement;
        assert_eq!(
            FindingFacts::of(&judged, Some(&user)).why_nothing_happened,
            Some(WhyNothingHappened::HeuristicOrAi)
        );

        let git = Item::entry(
            "workspace",
            Scope::Project(PathBuf::from("/src/demo")),
            Kind::RepositoryMetadata,
            ".git/config#core.hooksPath",
            PathBuf::from("/src/demo/.git/config"),
            Provenance::Unknown,
            Activation::Active,
            b"\"hooks\"".to_vec(),
        );
        assert_eq!(
            FindingFacts::of(&finding_on(&git, Source::Rule(8)), Some(&git)).why_nothing_happened,
            Some(WhyNothingHappened::NeverAuto)
        );

        let back = finding_on(&user, Source::KeepsComingBack);
        assert_eq!(
            FindingFacts::of(&back, Some(&user)).why_nothing_happened,
            Some(WhyNothingHappened::KeepsComingBack)
        );

        let managed = skill(Scope::Managed);
        assert_eq!(
            FindingFacts::of(&finding_on(&managed, Source::Rule(1)), Some(&managed))
                .why_nothing_happened,
            Some(WhyNothingHappened::Managed)
        );

        let mut exposure = finding_on(&user, Source::Rule(10));
        exposure.category = Category::Exposure;
        assert_eq!(
            FindingFacts::of(&exposure, Some(&user)).why_nothing_happened,
            Some(WhyNothingHappened::Exposure)
        );

        // An automatically quarantined stable T1 Threat fits none.
        let stable = finding_on(&user, Source::Rule(1));
        assert_eq!(
            FindingFacts::of(&stable, Some(&user)).why_nothing_happened,
            None
        );
        // Nor does the Drift question, which asks rather than explains.
        let mut drift = finding_on(&user, Source::Drift);
        drift.tier = Tier::Heuristics;
        assert_eq!(
            FindingFacts::of(&drift, Some(&user)).why_nothing_happened,
            None
        );
    }

    #[test]
    fn the_item_gives_its_scope_root_activation_and_provenance() {
        let mut item = skill(Scope::Project(PathBuf::from("/src/demo")));
        item.activation = Activation::Inactive(InactiveReason::UntrustedProject);
        item.provenance = Provenance::Repository {
            commit: "abc".to_string(),
        };
        let facts = FindingFacts::of(&finding_on(&item, Source::Rule(1)), Some(&item));
        assert_eq!(facts.scope, "project");
        assert_eq!(facts.project_root, "/src/demo");
        assert_eq!(facts.activation, "inactive");
        assert_eq!(facts.inactive_reason, "untrusted_project");
        assert_eq!(facts.provenance, "repository");
    }

    #[test]
    fn a_plugin_part_names_its_plugin_and_a_moved_item_its_change() {
        let mut item = skill(Scope::User);
        item.provenance = Provenance::Plugin {
            id: "shipit@community-tools".to_string(),
        };
        let mut finding = finding_on(&item, Source::Drift);
        finding.drift = Some(crate::drift::Drift {
            change: crate::drift::Change::Added,
            since: None,
            accepted_hash: String::new(),
            last_seen_hash: item.content_hash.clone(),
            line: "new since your last Scan".to_string(),
            detail: Vec::new(),
        });
        let facts = FindingFacts::of(&finding, Some(&item));
        assert_eq!(facts.plugin, "shipit");
        assert_eq!(facts.drift_change, "added");
        assert_eq!(facts.phrase, "", "the phrase is the Rule Pack's to give");

        let still = FindingFacts::of(&finding_on(&skill(Scope::User), Source::Rule(1)), None);
        assert_eq!(still.plugin, "");
        assert_eq!(still.drift_change, "");
    }

    #[test]
    fn an_item_not_at_hand_still_names_its_scope_from_its_id() {
        let item = skill(Scope::Project(PathBuf::from("/src/my skill/demo")));
        let facts = FindingFacts::of(&finding_on(&item, Source::Rule(1)), None);
        assert_eq!(facts.scope, "project");
        assert_eq!(facts.project_root, "/src/my skill/demo");
        assert_eq!(facts.activation, "");
        let managed = skill(Scope::Managed);
        let facts = FindingFacts::of(&finding_on(&managed, Source::Rule(1)), None);
        assert_eq!(facts.scope, "managed");
        assert_eq!(
            facts.why_nothing_happened,
            Some(WhyNothingHappened::Managed)
        );
    }

    #[test]
    fn a_score_finding_carries_one_line_per_heuristic_with_score_and_band() {
        let item = skill(Scope::User);
        let mut finding = finding_on(&item, Source::Score(4));
        finding.tier = Tier::Heuristics;
        finding.heuristics = vec![fired(511, false, "", 5..12), fired(512, false, "", 13..39)];
        let facts = FindingFacts::of(&finding, Some(&item));
        assert_eq!(facts.score, 4);
        assert_eq!(facts.band, "Suspicious");
        assert_eq!(facts.heuristics.len(), 2);
        assert_eq!(facts.heuristics[0].id, 511);
        assert_eq!(facts.heuristics[0].weight, 2);
        assert_eq!(facts.heuristics[0].plain, "Heuristic 511 fired.");
        assert_eq!(facts.heuristics[0].excerpt, "curl -k");
        assert_eq!(facts.heuristics[1].excerpt, "https://paste.example.inva");
    }

    #[test]
    fn a_sensitive_heuristic_shows_only_a_hash_of_its_match() {
        let item = skill(Scope::User);
        let line = HeuristicLine::of(&fired(534, true, "", 5..12), Some(&item));
        assert_eq!(
            line.excerpt,
            format!("sha256:{}", &sha256_hex(b"curl -k")[..12])
        );
        assert!(!line.excerpt.contains("curl"));
    }

    #[test]
    fn a_match_inside_an_mcp_env_value_is_redacted_and_one_outside_is_not() {
        let item = mcp_entry(
            r#"{"command": "curl", "args": ["-k"], "env": {"TOKEN": "sk-not-a-real-token-0000"}}"#,
        );
        let text = String::from_utf8(item.content.clone()).expect("utf-8");
        let secret = text.find("sk-not").expect("the value");
        let inside = fired(512, false, "", secret..secret + 10);
        let excerpt = excerpt(&item, &inside);
        assert!(excerpt.starts_with("sha256:"), "{excerpt}");
        assert!(!excerpt.contains("sk-not"));

        let command = text.find("curl").expect("the command");
        let outside = fired(511, false, "", command..command + 4);
        assert_eq!(super::excerpt(&item, &outside), "curl");
    }

    fn entry(agent: &str, kind: Kind, locator: &str, content: &str) -> Item {
        Item::entry(
            agent,
            Scope::User,
            kind,
            locator,
            PathBuf::from("/home/u/config"),
            Provenance::Manual,
            Activation::Active,
            crate::item::canonical_entry(&serde_json::from_str(content).expect("json")),
        )
    }

    fn excerpt_of(item: &Item, text: &str) -> String {
        let content = String::from_utf8(item.content.clone()).expect("utf-8");
        let start = content.find(text).expect("the text");
        excerpt(item, &fired(512, false, "", start..start + text.len()))
    }

    /// A Claude Code settings entry for one environment variable holds the
    /// value itself: a match on it shows only a hash.
    #[test]
    fn a_match_in_a_settings_entry_for_one_environment_variable_is_redacted() {
        let item = entry(
            "claude-code",
            Kind::SettingsEntry,
            "~/.claude/settings.json#/env/TRACKER_TOKEN",
            r#"{"env.TRACKER_TOKEN": "hunter2hunter2"}"#,
        );
        let excerpt = excerpt_of(&item, "hunter2hunter2");
        assert!(excerpt.starts_with("sha256:"), "{excerpt}");
    }

    /// A match inside a Codex server's `http_headers` or `env_http_headers`
    /// shows only a hash, and one on its URL shows the text.
    #[test]
    fn a_match_inside_a_codex_server_header_is_redacted_and_one_on_its_url_is_not() {
        let item = entry(
            "codex",
            Kind::McpServer,
            "~/.codex/config.toml#tracker",
            r#"{"url": "https://tracker.example.invalid/mcp",
                "http_headers": {"Authorization": "Bearer hunter2hunter2"},
                "env_http_headers": {"X-Tenant": "TRACKER_TENANT_VARIABLE"}}"#,
        );
        for value in ["hunter2hunter2", "TRACKER_TENANT_VARIABLE"] {
            let excerpt = excerpt_of(&item, value);
            assert!(excerpt.starts_with("sha256:"), "{value}: {excerpt}");
        }
        assert_eq!(
            excerpt_of(&item, "tracker.example.invalid"),
            "tracker.example.invalid"
        );
    }

    /// A sensitive field below the top level, here the headers of an HTTP
    /// hook, is found where the canonical form writes it.
    #[test]
    fn a_match_inside_a_nested_sensitive_field_is_redacted() {
        let item = entry(
            "claude-code",
            Kind::Hook,
            "~/.claude/settings.json#PostToolUse/Bash/0123456789ab",
            r#"{"event_name": "PostToolUse", "matcher": "Bash", "hooks": [{
                "type": "http", "url": "https://hooks.example.invalid",
                "headers": {"Authorization": "Bearer hunter2hunter2"}}]}"#,
        );
        assert!(excerpt_of(&item, "hunter2hunter2").starts_with("sha256:"));
        assert_eq!(
            excerpt_of(&item, "hooks.example.invalid"),
            "hooks.example.invalid"
        );
    }

    #[test]
    fn a_long_match_is_cut_and_control_characters_are_spaces() {
        let mut item = skill(Scope::User);
        item.content = format!("a\nb{}", "x".repeat(300)).into_bytes();
        let line = HeuristicLine::of(&fired(503, false, "", 0..303), Some(&item));
        assert!(line.excerpt.starts_with("a b"));
        assert!(line.excerpt.ends_with("..."));
        assert_eq!(line.excerpt.chars().count(), EXCERPT_CHARS + 3);
    }

    #[test]
    fn the_facts_round_trip_and_a_finding_without_them_reads_as_none_known() {
        let facts = FindingFacts {
            actor: Some(Actor::Auto),
            scope: "project".to_string(),
            project_root: "/src/demo".to_string(),
            activation: "inactive".to_string(),
            inactive_reason: "untrusted_project".to_string(),
            provenance: "repository".to_string(),
            why_nothing_happened: Some(WhyNothingHappened::Probation),
            heuristics: vec![HeuristicLine {
                id: 520,
                weight: 3,
                plain: "p".to_string(),
                excerpt: "e".to_string(),
            }],
            score: 3,
            band: "Suspicious".to_string(),
            rule_withdrawn: true,
            phrase: "contains hidden instructions".to_string(),
            plugin: "shipit".to_string(),
            drift_change: "changed".to_string(),
        };
        let mut map = Map::new();
        facts.write_into(&mut map);
        assert_eq!(FindingFacts::read_from(&Value::Object(map)), facts);
        assert_eq!(
            FindingFacts::read_from(&serde_json::json!({"id": "x"})),
            FindingFacts::default()
        );
        for case in WhyNothingHappened::ALL {
            assert_eq!(WhyNothingHappened::parse(case.as_str()), Some(case));
        }
    }
}
