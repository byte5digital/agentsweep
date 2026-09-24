//! Coverage: which Surfaces AgentSweep had already looked at.
//!
//! Coverage is what keeps `none` apart from `added` (spec section 4.6.2). It is
//! recorded per adapter, root and kind, written before a newly registered root
//! or a newly detected Agent is enumerated, and it lives in the Baseline chain
//! beside the Item records, because compaction drops the coverage of roots that
//! left every registry along with the records under them.
//!
//! An Item first seen where no coverage existed reads `none` and is never
//! Drift: the first Scan of a Mac, a project entering a registry, a newly
//! installed Agent, a kind an app update added. An Item first seen where
//! coverage did exist reads `added`, and that is a question worth asking.
//!
//! The root of a coverage record is the Scope segment of the Items under it:
//! `managed`, `user` or `project:<root>`. One record therefore covers every
//! Item one adapter yields of one kind in one Scope, which is what makes a hook
//! that appears next week `added` rather than `none`: the coverage is written
//! for every kind the adapter yields, not only for the kinds that happened to
//! produce an Item.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::adapter::Descriptor;
use crate::envelope::Timestamp;
use crate::item::{Kind, Scope};

/// One stretch of Surface AgentSweep has looked at: one adapter, one root, one
/// kind.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CoverageKey {
    /// The adapter that covers it.
    pub agent: String,
    /// The Scope segment the Items under it carry: `managed`, `user` or
    /// `project:<root>`.
    pub root: String,
    /// The Surface kind.
    pub kind: Kind,
}

impl CoverageKey {
    /// The coverage one adapter holds over one Scope and one kind.
    pub fn new(agent: &str, root: &str, kind: Kind) -> CoverageKey {
        CoverageKey {
            agent: agent.to_string(),
            root: root.to_string(),
            kind,
        }
    }

    /// The coverage an Item of this agent, Scope and kind sits under.
    pub fn of(agent: &str, scope: &Scope, kind: Kind) -> CoverageKey {
        CoverageKey::new(agent, &scope.id_segment(), kind)
    }
}

/// One coverage record of the Baseline chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageRecord {
    /// What it covers.
    pub key: CoverageKey,
    /// When the Surface was first covered.
    pub covered_at: Timestamp,
}

impl CoverageRecord {
    /// A record covering one adapter, root and kind from this moment on.
    pub fn new(key: CoverageKey, covered_at: Timestamp) -> CoverageRecord {
        CoverageRecord { key, covered_at }
    }

    /// The payload a record carries.
    pub fn to_payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("about".to_string(), Value::from("coverage"));
        map.insert("agent".to_string(), Value::from(self.key.agent.as_str()));
        map.insert(
            "covered_at".to_string(),
            Value::from(self.covered_at.to_string()),
        );
        map.insert("kind".to_string(), Value::from(self.key.kind.as_str()));
        map.insert("root".to_string(), Value::from(self.key.root.as_str()));
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<CoverageRecord> {
        let text = |field: &str| payload.get(field).and_then(Value::as_str);
        if text("about")? != "coverage" {
            return None;
        }
        Some(CoverageRecord {
            key: CoverageKey::new(text("agent")?, text("root")?, Kind::parse(text("kind")?)?),
            covered_at: Timestamp::parse(text("covered_at")?)?,
        })
    }
}

/// What one Scan enumerated, as the coverage it stands for.
///
/// The Scan pass compares it with the coverage the Baseline already holds: what
/// is new is written, and what was already there is what tells `added` from
/// `none`. A Folder Scan hands an empty plan, so every Item it sees reads
/// `none`.
#[derive(Clone, Debug, Default)]
pub struct CoveragePlan {
    keys: BTreeSet<CoverageKey>,
}

impl CoveragePlan {
    /// A plan covering nothing yet.
    pub fn new() -> CoveragePlan {
        CoveragePlan::default()
    }

    /// Records that this adapter looked at this Scope for this kind.
    pub fn covers(&mut self, agent: &str, scope: &Scope, kind: Kind) {
        self.keys.insert(CoverageKey::of(agent, scope, kind));
    }

    /// Records that one adapter looked at one Scope for every kind it yields.
    ///
    /// This is the call a Scan makes per adapter and per root, and it is why a
    /// hook that appears weeks later is `added`: the coverage was written for
    /// the kind, not for the Items that happened to exist.
    pub fn enumerated(&mut self, descriptor: &Descriptor, scope: &Scope) {
        for kind in descriptor.kinds {
            self.covers(descriptor.agent, scope, *kind);
        }
    }

    /// True when the plan covers this adapter, Scope and kind.
    pub fn holds(&self, key: &CoverageKey) -> bool {
        self.keys.contains(key)
    }

    /// Everything the plan covers.
    pub fn keys(&self) -> impl Iterator<Item = &CoverageKey> {
        self.keys.iter()
    }

    /// How many stretches of Surface the plan covers.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when the Scan enumerated nothing, which is what a Folder Scan
    /// hands over.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The coverage the Baseline holds, as one read of the chain left it.
///
/// Each stretch keeps the moment it was first covered, because compaction
/// writes the coverage afresh and a Surface is not newly covered for having
/// been written down again.
#[derive(Clone, Debug, Default)]
pub struct Coverage {
    keys: BTreeMap<CoverageKey, Timestamp>,
}

impl Coverage {
    /// Coverage over nothing: the first Scan of a Mac, and every Scan that
    /// reads no Baseline at all.
    pub fn none() -> Coverage {
        Coverage::default()
    }

    /// Takes one record into the coverage. The first moment a stretch was
    /// covered is the one that stands.
    pub fn record(&mut self, record: &CoverageRecord) {
        self.keys
            .entry(record.key.clone())
            .or_insert(record.covered_at);
    }

    /// When this stretch was first covered, if it is covered at all.
    pub fn covered_at(&self, key: &CoverageKey) -> Option<Timestamp> {
        self.keys.get(key).copied()
    }

    /// True when this adapter, Scope and kind were already covered, which is
    /// what makes an Item first seen now `added` rather than `none`.
    pub fn covers(&self, agent: &str, scope: &Scope, kind: Kind) -> bool {
        self.keys.contains_key(&CoverageKey::of(agent, scope, kind))
    }

    /// True when this stretch of Surface is covered.
    pub fn holds(&self, key: &CoverageKey) -> bool {
        self.keys.contains_key(key)
    }

    /// Everything that is covered, with the moment each stretch was first
    /// covered.
    pub fn stretches(&self) -> impl Iterator<Item = (&CoverageKey, Timestamp)> {
        self.keys.iter().map(|(key, at)| (key, *at))
    }

    /// Everything that is covered.
    pub fn keys(&self) -> impl Iterator<Item = &CoverageKey> {
        self.keys.keys()
    }

    /// How many stretches of Surface are covered.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when nothing is covered yet.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The records this plan adds to what is already covered, in a fixed
    /// order. What is already covered is not written again.
    pub fn additions(&self, plan: &CoveragePlan, at: Timestamp) -> Vec<CoverageRecord> {
        plan.keys()
            .filter(|key| !self.holds(key))
            .map(|key| CoverageRecord::new(key.clone(), at))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn moment() -> Timestamp {
        Timestamp::parse("2026-09-24T10:00:00.000Z").expect("a readable moment")
    }

    #[test]
    fn a_coverage_record_round_trips_through_its_payload() {
        let record = CoverageRecord::new(
            CoverageKey::of(
                "claude-code",
                &Scope::Project(PathBuf::from("/src/demo")),
                Kind::Hook,
            ),
            moment(),
        );
        let payload = record.to_payload();
        assert_eq!(CoverageRecord::from_payload(&payload), Some(record));
    }

    #[test]
    fn an_item_record_is_not_read_back_as_coverage() {
        let payload = serde_json::json!({"about": "item", "item_id": "a/user/skill/x"});
        assert_eq!(CoverageRecord::from_payload(&payload), None);
    }

    /// The coverage of a Scope is written for every kind the adapter yields,
    /// so a kind that produces its first Item weeks later is `added` rather
    /// than `none`.
    #[test]
    fn a_plan_covers_every_kind_the_adapter_yields() {
        let descriptor = Descriptor {
            agent: "demo",
            display_name: "Demo",
            kinds: &[Kind::Hook, Kind::McpServer],
            default_config_dir: "~/.demo",
            surfaces: &[],
            capabilities: &[],
            agent_written_keys: &[],
        };
        let mut plan = CoveragePlan::new();
        plan.enumerated(&descriptor, &Scope::User);
        assert_eq!(plan.len(), 2);
        assert!(plan.holds(&CoverageKey::of("demo", &Scope::User, Kind::Hook)));
        assert!(plan.holds(&CoverageKey::of("demo", &Scope::User, Kind::McpServer)));
    }

    #[test]
    fn only_what_is_not_covered_yet_is_written() {
        let mut coverage = Coverage::none();
        coverage.record(&CoverageRecord::new(
            CoverageKey::of("demo", &Scope::User, Kind::Hook),
            moment(),
        ));

        let mut plan = CoveragePlan::new();
        plan.covers("demo", &Scope::User, Kind::Hook);
        plan.covers("demo", &Scope::User, Kind::McpServer);

        let additions = coverage.additions(&plan, moment());
        assert_eq!(additions.len(), 1);
        assert_eq!(additions[0].key.kind, Kind::McpServer);
    }

    #[test]
    fn a_project_root_is_covered_on_its_own() {
        let mut coverage = Coverage::none();
        coverage.record(&CoverageRecord::new(
            CoverageKey::of("demo", &Scope::User, Kind::Skill),
            moment(),
        ));
        let root = Scope::Project(PathBuf::from("/src/demo"));
        assert!(coverage.covers("demo", &Scope::User, Kind::Skill));
        assert!(!coverage.covers("demo", &root, Kind::Skill));
    }
}
