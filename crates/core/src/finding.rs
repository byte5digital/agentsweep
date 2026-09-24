//! The Finding: one suspicious observation about one Item.
//!
//! A Finding is identified by the Item id, its source and the content hash
//! (spec section 4.5), which is what [`FindingId`] renders. One Finding per
//! Rule per Item. Where a Finding stands is [`FindingState`], and it is never
//! stored: [`standing`] reads it back off the Event Log's derived views and
//! the Findings of the current Scan.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use crate::adapter::{Problem, ProblemReason};
use crate::derived::{QuarantineManifest, TrustTable};
use crate::item::{ItemId, Kind};

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
    /// A path no adapter could turn into an Item (spec section 3.3). No Rule
    /// ever ran over it, which is the whole point: what was not read cannot be
    /// called clear.
    Problem(ProblemReason),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Rule(id) => write!(f, "rule {id:04}"),
            Source::Score(score) => write!(f, "score {score}"),
            Source::Problem(reason) => write!(f, "problem {}", reason.as_str()),
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
    /// The informational Exposure Finding one Problem becomes (spec section
    /// 3.3).
    ///
    /// A path an adapter could not turn into an Item was never read by a Rule,
    /// so a Scan that says nothing about it would be claiming to have seen
    /// what it did not: a tree over the caps, an unreadable settings file and
    /// a Surface shape this version does not support all have to keep a folder
    /// from counting as clear. It is Exposure, because nobody planted it, and
    /// low, because the answer is "look yourself" rather than "something is
    /// wrong". The Tier is the deterministic one: nothing here was guessed,
    /// and the Source says the observation is a Problem rather than a Rule.
    pub fn of_problem(problem: &Problem) -> Finding {
        let path = problem.path.display().to_string();
        let item_id = match problem.kind {
            Some(kind) => ItemId::from_recorded(&format!("{}/{path}", kind.id_segment())),
            None => ItemId::from_recorded(&path),
        };
        Finding {
            item_id,
            source: Source::Problem(problem.reason),
            content_hash: String::new(),
            category: Category::Exposure,
            severity: Severity::Low,
            tier: Tier::Rules,
            status: RuleStatus::Stable,
            title: format!("{} at {}", problem.reason.title(), problem.surface),
            plain: problem.reason.plain().to_string(),
            sensitive: false,
            file: String::new(),
            matches: Vec::new(),
            heuristics: Vec::new(),
        }
    }

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

/// The identity of one Finding: the Item it is about, what produced it and the
/// content it was made on (spec section 4.5).
///
/// The content hash is part of the identity, so a Finding on content that
/// changed is a new Finding and the old one is gone. The Score is not part of
/// it: one `score` Finding per Item, whatever the Score happens to be.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FindingId(String);

impl FindingId {
    /// The id of a Finding from its three parts.
    pub fn new(item_id: &ItemId, source: Source, content_hash: &str) -> FindingId {
        let source = match source {
            Source::Rule(id) => format!("rule/{id:04}"),
            Source::Score(_) => "score".to_string(),
            Source::Problem(reason) => format!("problem/{}", reason.as_str()),
        };
        FindingId(format!("{item_id}|{source}|{content_hash}"))
    }

    /// The id of one Finding.
    pub fn of(finding: &Finding) -> FindingId {
        FindingId::new(&finding.item_id, finding.source, &finding.content_hash)
    }

    /// The id as one string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Takes an id back from the form a record of the Event Log carries.
    pub fn from_recorded(text: &str) -> FindingId {
        FindingId(text.to_string())
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where one Finding stands (spec section 4.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingState {
    /// The Item still carries the content and nothing has been done about it.
    Open,
    /// The Item was quarantined, so the Agent cannot load it.
    Stopped,
    /// The user said this content of this kind is safe.
    Trusted,
    /// The user said the change was their own doing. The Baseline milestone is
    /// what puts a Finding here; nothing does yet.
    Acknowledged,
    /// The content is no longer there. Kept in the Activity.
    Gone,
}

impl FindingState {
    /// Every state, in the order spec section 4.5 lists them.
    pub const ALL: [FindingState; 5] = [
        FindingState::Open,
        FindingState::Stopped,
        FindingState::Trusted,
        FindingState::Acknowledged,
        FindingState::Gone,
    ];

    /// The spelling the state file and the command line interface carry.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingState::Open => "open",
            FindingState::Stopped => "stopped",
            FindingState::Trusted => "trusted",
            FindingState::Acknowledged => "acknowledged",
            FindingState::Gone => "gone",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<FindingState> {
        FindingState::ALL
            .into_iter()
            .find(|state| state.as_str() == text)
    }

    /// True when the Finding still asks something of the user, which is what
    /// the Gate refuses a turn on.
    pub fn is_open(self) -> bool {
        self == FindingState::Open
    }
}

impl fmt::Display for FindingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One Finding with where it stands.
#[derive(Clone, Debug)]
pub struct Standing {
    /// Its identity.
    pub id: FindingId,
    /// The observation itself.
    pub finding: Finding,
    /// Where it stands.
    pub state: FindingState,
    /// The Receipt that stopped it, empty unless it is stopped.
    pub receipt_id: String,
}

/// What the Event Log decided, which is half of where a Finding stands.
#[derive(Clone, Copy, Debug)]
pub struct Decided<'a> {
    /// What the quarantine store holds.
    pub quarantined: &'a QuarantineManifest,
    /// Which content hashes carry Trust.
    pub trusted: &'a TrustTable,
}

/// Every Finding that stands right now, derived from the Event Log and the
/// current Scan and never stored (spec section 4.5).
///
/// A Finding the last Scan raised and this one did not is not dropped: it is
/// gone, and the Activity keeps it. `kinds` says which kind each Item is,
/// because Trust is bound to a kind and a content hash while a Finding carries
/// only the hash.
pub fn standing(
    previous: &[Finding],
    current: &[Finding],
    kinds: &BTreeMap<ItemId, Kind>,
    decided: Decided<'_>,
) -> Vec<Standing> {
    let mut placed: Vec<Standing> = Vec::new();
    let mut seen: Vec<FindingId> = Vec::new();
    let found_now: Vec<FindingId> = current.iter().map(FindingId::of).collect();

    for finding in current.iter().chain(previous.iter()) {
        let id = FindingId::of(finding);
        if seen.contains(&id) {
            continue;
        }
        seen.push(id.clone());
        let stopped = decided.quarantined.entries().find(|entry| {
            entry.item_id == finding.item_id && entry.content_hash == finding.content_hash
        });
        let kind = kinds
            .get(&finding.item_id)
            .copied()
            .or_else(|| stopped.and_then(|entry| entry.kind));
        let state = if stopped.is_some() {
            FindingState::Stopped
        } else if kind.is_some_and(|kind| decided.trusted.trusts(kind, &finding.content_hash)) {
            FindingState::Trusted
        } else if found_now.contains(&id) {
            FindingState::Open
        } else {
            FindingState::Gone
        };
        placed.push(Standing {
            id,
            finding: finding.clone(),
            state,
            receipt_id: stopped
                .map(|entry| entry.receipt_id.clone())
                .unwrap_or_default(),
        });
    }
    placed
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

    #[test]
    fn every_state_round_trips_through_the_spelling_it_is_written_as() {
        for state in FindingState::ALL {
            assert_eq!(FindingState::parse(state.as_str()), Some(state));
        }
        assert!(FindingState::Open.is_open());
        assert!(!FindingState::Stopped.is_open());
    }

    #[test]
    fn a_finding_is_identified_by_the_item_the_source_and_the_content() {
        let item = a_finding(Source::Rule(12), "a");
        assert_eq!(
            FindingId::of(&item).as_str(),
            "claude-code/user/skill/demo|rule/0012|aaaaaaaa"
        );
        // The same Rule on content that changed is a different Finding.
        assert_ne!(
            FindingId::of(&item),
            FindingId::of(&a_finding(Source::Rule(12), "b"))
        );
        // One score Finding per Item, whatever the Score is.
        assert_eq!(
            FindingId::of(&a_finding(Source::Score(4), "a")),
            FindingId::of(&a_finding(Source::Score(7), "a"))
        );
    }

    fn a_finding(source: Source, hash: &str) -> Finding {
        Finding {
            item_id: ItemId::new(
                "claude-code",
                &crate::item::Scope::User,
                Kind::Skill,
                "demo",
            ),
            source,
            content_hash: hash.repeat(8),
            category: Category::Threat,
            severity: Severity::Critical,
            tier: Tier::Rules,
            status: RuleStatus::Stable,
            title: "a planted skill".to_string(),
            plain: "This skill would run a script from the internet.".to_string(),
            sensitive: false,
            file: String::new(),
            matches: Vec::new(),
            heuristics: Vec::new(),
        }
    }

    /// The manifest and the Trust table as the Event Log yields them, written
    /// to a real chain and read back.
    fn decided_by(events: Vec<crate::eventlog::Event>) -> (QuarantineManifest, TrustTable) {
        use crate::eventlog::{EventLog, EventLogWriter};
        use crate::keychain::MemoryKeySource;

        let directory = tempfile::TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
        for event in &events {
            writer.append(event).expect("an appended event");
        }
        let view = log.read(&keys).expect("a readable log");
        (view.quarantine_manifest(), view.trust_table())
    }

    #[test]
    fn a_finding_stands_where_the_event_log_and_the_current_scan_put_it() {
        use crate::eventlog::{Action, Actor, Event, Primitive, ReceiptStep};

        let open = a_finding(Source::Rule(12), "a");
        let stopped = a_finding(Source::Rule(13), "b");
        let trusted = a_finding(Source::Rule(14), "c");
        let vanished = a_finding(Source::Rule(15), "d");

        let mut quarantine = Event::new(Action::Quarantine, Actor::Auto)
            .about(&stopped.item_id, Kind::Skill, &stopped.content_hash)
            .because_of("f", Tier::Rules, 13);
        quarantine.receipt_id = "q-00000000000000000000000000000001".to_string();
        quarantine.steps = vec![ReceiptStep::new(Primitive::MoveOut, "/nowhere/demo")];
        let trust = Event::new(Action::Trust, Actor::User).about(
            &trusted.item_id,
            Kind::Skill,
            &trusted.content_hash,
        );
        let (quarantined, trust_table) = decided_by(vec![quarantine, trust]);

        let kinds = BTreeMap::from([(open.item_id.clone(), Kind::Skill)]);
        let placed = standing(
            std::slice::from_ref(&vanished),
            &[open.clone(), stopped.clone(), trusted.clone()],
            &kinds,
            Decided {
                quarantined: &quarantined,
                trusted: &trust_table,
            },
        );

        let state = |finding: &Finding| {
            placed
                .iter()
                .find(|one| one.id == FindingId::of(finding))
                .map(|one| one.state)
        };
        assert_eq!(state(&open), Some(FindingState::Open));
        assert_eq!(state(&stopped), Some(FindingState::Stopped));
        assert_eq!(state(&trusted), Some(FindingState::Trusted));
        assert_eq!(state(&vanished), Some(FindingState::Gone));
        assert_eq!(placed.len(), 4);
        let stopped_by = placed
            .iter()
            .find(|one| one.state == FindingState::Stopped)
            .expect("the stopped Finding");
        assert_eq!(stopped_by.receipt_id, "q-00000000000000000000000000000001");
    }
}
