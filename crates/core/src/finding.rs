//! The Finding: one suspicious observation about one Item.
//!
//! A Finding is identified by the Item id, its source and the content hash
//! (spec section 4.5). One Finding per Rule per Item. The vocabularies here
//! are the ones `CONTEXT.md` fixes; the Finding states and the Event Log arrive
//! with milestones 4 and 6.

use std::fmt;
use std::ops::Range;

use crate::item::ItemId;

/// Whether the content was planted by an attacker or is the user's own risky
/// configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Category {
    /// Attacker-planted. The only category that may ever be quarantined
    /// automatically.
    Threat,
    /// The user's own risky configuration. Never quarantined at any Tier.
    Exposure,
}

impl Category {
    /// The spelling a Rule uses in its `category` meta.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Threat => "threat",
            Category::Exposure => "exposure",
        }
    }

    /// Reads back the spelling a Rule uses.
    pub fn parse(text: &str) -> Option<Category> {
        match text {
            "threat" => Some(Category::Threat),
            "exposure" => Some(Category::Exposure),
            _ => None,
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How bad a Finding is if it is true. Never encodes confidence; the Tier does
/// that.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    /// Hygiene.
    Low,
    /// An Exposure with a real leak path.
    Medium,
    /// The Agent's behaviour, permissions or endpoints are hijacked.
    High,
    /// Code runs as the user, or credentials leave.
    Critical,
}

impl Severity {
    /// The spelling a Rule uses in its `severity` meta.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Reads back the spelling a Rule uses.
    pub fn parse(text: &str) -> Option<Severity> {
        match text {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rung of the detection ladder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    /// The Allowlist.
    Allowlist,
    /// The Rules.
    Rules,
    /// The Heuristics.
    Heuristics,
    /// AI Judgement.
    AiJudgement,
}

impl Tier {
    /// The short label the Developer Posture and the CLI print.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Allowlist => "T0",
            Tier::Rules => "T1",
            Tier::Heuristics => "T2",
            Tier::AiJudgement => "T3",
        }
    }

    /// Reads back the `tier` meta of a Rule, which is 1 or 2.
    pub fn from_meta(tier: i64) -> Option<Tier> {
        match tier {
            1 => Some(Tier::Rules),
            2 => Some(Tier::Heuristics),
            _ => None,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a Rule stands between shipping and stability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleStatus {
    /// Flags and offers Quarantine, never quarantines by itself.
    Probation,
    /// May quarantine automatically, on auto-eligible kinds only.
    Stable,
    /// Keeps its id and never fires.
    Retired,
}

impl RuleStatus {
    /// The spelling a Rule uses in its `status` meta.
    pub fn as_str(self) -> &'static str {
        match self {
            RuleStatus::Probation => "probation",
            RuleStatus::Stable => "stable",
            RuleStatus::Retired => "retired",
        }
    }

    /// Reads back the spelling a Rule uses.
    pub fn parse(text: &str) -> Option<RuleStatus> {
        match text {
            "probation" => Some(RuleStatus::Probation),
            "stable" => Some(RuleStatus::Stable),
            "retired" => Some(RuleStatus::Retired),
            _ => None,
        }
    }
}

impl fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What produced a Finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// One Rule, by id. An Exposure Heuristic names itself the same way,
    /// because it raises its own Finding rather than a Score.
    Rule(i64),
    /// The Score of the Threat Heuristics that fired on the Item, which put it
    /// in the Suspicious Band. The Finding is about the Item, not about one
    /// Rule, and the number is Developer Posture detail.
    Score(i64),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Rule(id) => write!(f, "rule {id:04}"),
            Source::Score(score) => write!(f, "score {score}"),
        }
    }
}

/// One Threat Heuristic that fired on an Item, with the Weight it contributed
/// to the Score. The same list is the evidence of a Suspicious Finding and the
/// "Also noticed" detail under a Probation Rule Finding.
#[derive(Clone, Debug)]
pub struct FiredHeuristic {
    /// The integer id of the Heuristic.
    pub id: i64,
    /// What it contributed to the Score: 1, 2 or 3.
    pub weight: i64,
    /// The developer-facing one line.
    pub title: String,
    /// The one sentence the Simple Posture shows.
    pub plain: String,
    /// How bad it is if true.
    pub severity: Severity,
    /// True when matches can land on sensitive fields.
    pub sensitive: bool,
    /// True when it fires on text addressing a reviewer, a scanner or an AI,
    /// which keeps a benign Verdict from clearing the Item.
    pub reviewer_directed: bool,
    /// The file of a tree Item it fired on, empty otherwise.
    pub file: String,
    /// Where its patterns matched.
    pub matches: Vec<MatchRange>,
}

/// Where in the scanned bytes a pattern matched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchRange {
    /// The pattern identifier, as the Rule names it.
    pub pattern: String,
    /// The byte range in the unit that was scanned.
    pub range: Range<usize>,
}

/// One suspicious observation about one Item.
#[derive(Clone, Debug)]
pub struct Finding {
    /// The Item the observation is about.
    pub item_id: ItemId,
    /// What produced it.
    pub source: Source,
    /// The content hash the observation was made on.
    pub content_hash: String,
    /// Threat or Exposure.
    pub category: Category,
    /// How bad it is if true.
    pub severity: Severity,
    /// Which Tier produced it.
    pub tier: Tier,
    /// Whether the Rule behind it is on Probation.
    pub status: RuleStatus,
    /// The developer-facing one line.
    pub title: String,
    /// The one sentence the Simple Posture shows.
    pub plain: String,
    /// True when matches can land on sensitive fields, so output is redacted.
    pub sensitive: bool,
    /// The file of a tree Item that carries the match, empty otherwise.
    pub file: String,
    /// Where the patterns matched.
    pub matches: Vec<MatchRange>,
    /// The Threat Heuristics that fired on the Item: the evidence of a
    /// Suspicious Finding, and the supporting detail under a Probation Rule
    /// Finding. Empty on everything else.
    pub heuristics: Vec<FiredHeuristic>,
}

impl Finding {
    /// True when the Rule behind the Finding is still on Probation, which is
    /// what keeps it from quarantining by itself.
    pub fn on_probation(&self) -> bool {
        self.status == RuleStatus::Probation
    }

    /// The Heuristics that fired on the same Item and are shown under this
    /// Finding as "Also noticed" rather than as a second Finding. Empty unless
    /// a Rule produced the Finding.
    pub fn also_noticed(&self) -> &[FiredHeuristic] {
        match self.tier {
            Tier::Rules => &self.heuristics,
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_vocabulary_round_trips_through_the_rule_meta_spelling() {
        for category in [Category::Threat, Category::Exposure] {
            assert_eq!(Category::parse(category.as_str()), Some(category));
        }
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }
        for status in [
            RuleStatus::Probation,
            RuleStatus::Stable,
            RuleStatus::Retired,
        ] {
            assert_eq!(RuleStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(Tier::from_meta(1), Some(Tier::Rules));
        assert_eq!(Tier::from_meta(2), Some(Tier::Heuristics));
        assert_eq!(Tier::from_meta(3), None);
    }

    #[test]
    fn a_rule_source_prints_the_four_digit_id() {
        assert_eq!(Source::Rule(1).to_string(), "rule 0001");
        assert_eq!(Source::Rule(900).to_string(), "rule 0900");
    }

    #[test]
    fn a_score_source_prints_the_score_behind_the_band() {
        assert_eq!(Source::Score(4).to_string(), "score 4");
    }

    #[test]
    fn severity_orders_from_hygiene_to_code_execution() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
