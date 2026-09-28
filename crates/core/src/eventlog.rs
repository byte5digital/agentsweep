//! The Event Log: the single tamper-evident record of what AgentSweep did.
//!
//! `events.jsonl` is the source of truth (ADR 0003, spec section 5.5). Every
//! Quarantine, Restore, Trust decision, Acknowledge, purge and change of
//! Judgement Engine is one record in the chain of [`crate::chain`]. What is in
//! quarantine and what is trusted are read back from it and never stored
//! anywhere else; [`crate::derived`] rebuilds both. The Event Log is never
//! compacted.
//!
//! A change of the Rule Pack in force is a record too, of its own kind
//! (`rule-pack`, [`RulePackRecord`]) rather than an action: the Activity reads
//! the withdrawn Rules and the Findings they took with them from it, and the
//! derived views pass it by.
//!
//! Sensitive values never appear in a record. MCP environment variables,
//! headers, tokens and the contents of an env file reach a record only through
//! [`Redacted`], which has no constructor that takes a value without hashing
//! it.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::chain::{Chain, ChainError, ChainState};
use crate::envelope::{ChainId, RecordKind, Timestamp};
use crate::finding::{FindingId, RuleStatus, Tier};
use crate::item::{ItemId, Kind, sha256_hex};
use crate::keychain::KeySource;
use crate::packs::PackOrigin;
use crate::paths::DataDirectory;

/// Who caused the event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Actor {
    /// AgentSweep itself, on a stable Rule at T0 or T1.
    Auto,
    /// The person in front of the Mac.
    User,
    /// A step replayed in reverse by Restore.
    Restore,
}

impl Actor {
    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Actor::Auto => "auto",
            Actor::User => "user",
            Actor::Restore => "restore",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<Actor> {
        match text {
            "auto" => Some(Actor::Auto),
            "user" => Some(Actor::User),
            "restore" => Some(Actor::Restore),
            _ => None,
        }
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happened. The closed list of spec section 5.5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// An Item was taken out of its Surface.
    Quarantine,
    /// A Receipt was replayed in reverse.
    Restore,
    /// Only the native disable step of a plugin Quarantine was reversed.
    ReEnable,
    /// A content hash of a kind was declared safe.
    Trust,
    /// Trust on a content hash was withdrawn.
    Untrust,
    /// A quarantined Item was deleted permanently.
    Purge,
    /// A removed entry came back and was removed again.
    ReEnforce,
    /// The user said a Drift was their own doing.
    Acknowledge,
    /// The Judgement Engine was enabled, switched, disabled, or its key was
    /// added or removed.
    EngineChanged,
    /// The Baseline chain was compacted, with the old and new head hashes.
    BaselineCompacted,
    /// The Gate was registered with an Agent.
    GateRegistered,
    /// The Gate was removed from an Agent.
    GateRemoved,
}

impl Action {
    /// Every action, in the order spec section 5.5 lists them.
    pub const ALL: [Action; 12] = [
        Action::Quarantine,
        Action::Restore,
        Action::ReEnable,
        Action::Trust,
        Action::Untrust,
        Action::Purge,
        Action::ReEnforce,
        Action::Acknowledge,
        Action::EngineChanged,
        Action::BaselineCompacted,
        Action::GateRegistered,
        Action::GateRemoved,
    ];

    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Quarantine => "quarantine",
            Action::Restore => "restore",
            Action::ReEnable => "re-enable",
            Action::Trust => "trust",
            Action::Untrust => "untrust",
            Action::Purge => "purge",
            Action::ReEnforce => "re-enforce",
            Action::Acknowledge => "acknowledge",
            Action::EngineChanged => "engine-changed",
            Action::BaselineCompacted => "baseline-compacted",
            Action::GateRegistered => "gate-registered",
            Action::GateRemoved => "gate-removed",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<Action> {
        Action::ALL
            .into_iter()
            .find(|action| action.as_str() == text)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one step of a Receipt physically did. The primitive table of spec
/// section 5.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Primitive {
    /// A file or tree was moved into the quarantine store.
    MoveOut,
    /// An entry was dropped from its config file.
    RemoveEntry,
    /// The Agent's own switch was turned off: the first half of the plugin
    /// composite, or the whole Quarantine of an Item the Agent has a switch
    /// for.
    NativeDisable,
    /// The content was commented out where it lies.
    NeutraliseInPlace,
}

impl Primitive {
    /// Every primitive.
    pub const ALL: [Primitive; 4] = [
        Primitive::MoveOut,
        Primitive::RemoveEntry,
        Primitive::NativeDisable,
        Primitive::NeutraliseInPlace,
    ];

    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Primitive::MoveOut => "move-out",
            Primitive::RemoveEntry => "remove-entry",
            Primitive::NativeDisable => "native-disable",
            Primitive::NeutraliseInPlace => "neutralise-in-place",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<Primitive> {
        Primitive::ALL
            .into_iter()
            .find(|primitive| primitive.as_str() == text)
    }
}

impl fmt::Display for Primitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a step, or the action as a whole, came out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// It did what it said.
    Ok,
    /// Its precondition was gone, so it did nothing.
    Skipped,
    /// It could not be done.
    Failed,
}

impl Outcome {
    /// Every outcome.
    pub const ALL: [Outcome; 3] = [Outcome::Ok, Outcome::Skipped, Outcome::Failed];

    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Skipped => "skipped",
            Outcome::Failed => "failed",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<Outcome> {
        Outcome::ALL.into_iter().find(|out| out.as_str() == text)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether Agent sessions looked to be running when the action was taken.
/// Detected read-only; AgentSweep never signals or kills a session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SessionsRunning {
    /// At least one session looked live.
    Yes,
    /// None looked live.
    No,
    /// Detection was not available for that Agent.
    #[default]
    Unknown,
}

impl SessionsRunning {
    /// Every state.
    pub const ALL: [SessionsRunning; 3] = [
        SessionsRunning::Yes,
        SessionsRunning::No,
        SessionsRunning::Unknown,
    ];

    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionsRunning::Yes => "yes",
            SessionsRunning::No => "no",
            SessionsRunning::Unknown => "unknown",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<SessionsRunning> {
        SessionsRunning::ALL
            .into_iter()
            .find(|state| state.as_str() == text)
    }
}

/// A sensitive value as a record may carry it: hashed, never in the clear.
///
/// There is no way to build one from a value without hashing it, which is what
/// keeps MCP environment variables, headers, tokens and env file contents out
/// of the Event Log and the Baseline.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Redacted(String);

impl Redacted {
    /// Hashes a sensitive value.
    pub fn of(value: impl AsRef<[u8]>) -> Redacted {
        Redacted(format!("sha256:{}", sha256_hex(value.as_ref())))
    }

    /// The hash, as the record carries it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads back what a record carries, refusing anything that is not a hash.
    fn parse(text: &str) -> Option<Redacted> {
        let digest = text.strip_prefix("sha256:")?;
        let hex = digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        hex.then(|| Redacted(text.to_string()))
    }
}

impl fmt::Display for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One step of a Receipt, with what it did and how it came out. Restore
/// replays the steps in reverse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptStep {
    /// What the step did.
    pub primitive: Primitive,
    /// How it came out.
    pub outcome: Outcome,
    /// The path it acted on: the Item for a move, the config file for an
    /// entry. Paths are not sensitive values; contents are.
    pub path: String,
    /// What inside the file the step addressed: a server name, a key path, a
    /// hook event and matcher. Empty for a file or tree.
    pub locator: String,
    /// One line for the Activity, free of content and of sensitive values.
    pub detail: String,
}

impl ReceiptStep {
    /// A step that did what it said.
    pub fn new(primitive: Primitive, path: impl Into<String>) -> ReceiptStep {
        ReceiptStep {
            primitive,
            outcome: Outcome::Ok,
            path: path.into(),
            locator: String::new(),
            detail: String::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("detail".to_string(), Value::from(self.detail.as_str()));
        map.insert("locator".to_string(), Value::from(self.locator.as_str()));
        map.insert("outcome".to_string(), Value::from(self.outcome.as_str()));
        map.insert("path".to_string(), Value::from(self.path.as_str()));
        map.insert(
            "primitive".to_string(),
            Value::from(self.primitive.as_str()),
        );
        Value::Object(map)
    }

    fn parse(value: &Value) -> Option<ReceiptStep> {
        Some(ReceiptStep {
            primitive: Primitive::parse(value.get("primitive")?.as_str()?)?,
            outcome: Outcome::parse(value.get("outcome")?.as_str()?)?,
            path: value.get("path")?.as_str()?.to_string(),
            locator: value.get("locator")?.as_str()?.to_string(),
            detail: value.get("detail")?.as_str()?.to_string(),
        })
    }
}

/// The detail key under which an event carries the content hash AgentSweep's
/// own write left at the Item.
pub const LEFT_HASH: &str = "left_hash";

/// The prefix of the detail keys under which an event carries the content hash
/// AgentSweep's own write left at *another* Item.
///
/// One write moves more than the Item it is about: switching a plugin off
/// rewrites an `enabledPlugins` entry, and commenting a key out in place
/// leaves the file it sits in at a new hash. Those Items would otherwise read
/// `changed` on the next Scan with nothing to account for it, and the user
/// would be asked about a change AgentSweep made itself (ADR 0007).
pub const LEFT_HASH_AT: &str = "left_hash:";

/// One record of the Event Log, with the fields of spec section 5.5. The
/// timestamp is the envelope's; everything else is here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// What happened.
    pub action: Action,
    /// Who caused it.
    pub actor: Actor,
    /// The Item it was about, absent for an event about no single Item.
    pub item_id: Option<ItemId>,
    /// The Surface kind of that Item.
    pub kind: Option<Kind>,
    /// The content hash the action was bound to, empty where none applies.
    pub content_hash: String,
    /// The Finding behind the action, empty where none applies.
    pub finding_id: String,
    /// The Tier that produced that Finding.
    pub tier: Option<Tier>,
    /// The Rule behind it, zero where no Rule applies.
    pub rule_id: i64,
    /// The Receipt this action belongs to, empty where none applies.
    pub receipt_id: String,
    /// The steps, in the order they were taken.
    pub steps: Vec<ReceiptStep>,
    /// How the action as a whole came out.
    pub result: Outcome,
    /// Whether Agent sessions looked to be running.
    pub sessions_running: SessionsRunning,
    /// Sensitive values, by name, as hashes. Never a value in the clear.
    pub sensitive: BTreeMap<String, Redacted>,
    /// Further facts that carry no content and nothing sensitive: an engine
    /// name, the Baseline head hashes, an Agent name.
    pub detail: BTreeMap<String, String>,
}

impl Event {
    /// An event with nothing filled in but what happened and who caused it.
    pub fn new(action: Action, actor: Actor) -> Event {
        Event {
            action,
            actor,
            item_id: None,
            kind: None,
            content_hash: String::new(),
            finding_id: String::new(),
            tier: None,
            rule_id: 0,
            receipt_id: String::new(),
            steps: Vec::new(),
            result: Outcome::Ok,
            sessions_running: SessionsRunning::Unknown,
            sensitive: BTreeMap::new(),
            detail: BTreeMap::new(),
        }
    }

    /// Names the Item and its kind.
    pub fn about(mut self, item_id: &ItemId, kind: Kind, content_hash: &str) -> Event {
        self.item_id = Some(item_id.clone());
        self.kind = Some(kind);
        self.content_hash = content_hash.to_string();
        self
    }

    /// Names the Finding, the Tier and the Rule behind the action.
    pub fn because_of(mut self, finding_id: &str, tier: Tier, rule_id: i64) -> Event {
        self.finding_id = finding_id.to_string();
        self.tier = Some(tier);
        self.rule_id = rule_id;
        self
    }

    /// Records a sensitive value as its hash and nothing else.
    pub fn hiding(mut self, name: &str, value: impl AsRef<[u8]>) -> Event {
        self.sensitive.insert(name.to_string(), Redacted::of(value));
        self
    }

    /// Records a fact that carries no content and nothing sensitive.
    pub fn noting(mut self, name: impl Into<String>, fact: impl Into<String>) -> Event {
        self.detail.insert(name.into(), fact.into());
        self
    }

    /// Records the content hash AgentSweep's own write left at the Item.
    ///
    /// A Quarantine, a Restore, a re-enforce, a Re-enable or a Gate
    /// registration changes what is on the Surface, and the next Scan would
    /// otherwise find a hash nothing accounts for and ask the user whether the
    /// change was theirs. The hash written here is the closed list's half of
    /// that answer (ADR 0007): the action is known, and it is known by the
    /// bytes it left, not by the path it touched.
    pub fn leaving(self, content_hash: &str) -> Event {
        self.noting(LEFT_HASH, content_hash)
    }

    /// Records the content hash the same write left at another Item: the
    /// settings entry a native disable flipped, the file an in-place
    /// neutralisation rewrote.
    pub fn also_leaving(self, item_id: &ItemId, content_hash: &str) -> Event {
        self.noting(format!("{LEFT_HASH_AT}{item_id}"), content_hash)
    }

    /// Every Item this write left at a known hash, the Item the event is about
    /// included. What the known actions are rebuilt from.
    pub fn left_behind(&self) -> Vec<(ItemId, String)> {
        let mut left = Vec::new();
        if let (Some(item_id), Some(hash)) = (&self.item_id, self.detail.get(LEFT_HASH)) {
            left.push((item_id.clone(), hash.clone()));
        }
        for (name, hash) in &self.detail {
            if let Some(item_id) = name.strip_prefix(LEFT_HASH_AT) {
                left.push((ItemId::from_recorded(item_id), hash.clone()));
            }
        }
        left
    }

    /// The payload a record carries.
    pub fn to_payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("action".to_string(), Value::from(self.action.as_str()));
        map.insert("actor".to_string(), Value::from(self.actor.as_str()));
        map.insert(
            "content_hash".to_string(),
            Value::from(self.content_hash.as_str()),
        );
        map.insert(
            "detail".to_string(),
            Value::Object(
                self.detail
                    .iter()
                    .map(|(name, fact)| (name.clone(), Value::from(fact.as_str())))
                    .collect(),
            ),
        );
        map.insert(
            "finding_id".to_string(),
            Value::from(self.finding_id.as_str()),
        );
        map.insert(
            "item_id".to_string(),
            Value::from(self.item_id.as_ref().map_or("", ItemId::as_str)),
        );
        map.insert(
            "kind".to_string(),
            Value::from(self.kind.map_or("", Kind::as_str)),
        );
        map.insert(
            "receipt_id".to_string(),
            Value::from(self.receipt_id.as_str()),
        );
        map.insert("result".to_string(), Value::from(self.result.as_str()));
        map.insert("rule_id".to_string(), Value::from(self.rule_id));
        map.insert(
            "sensitive".to_string(),
            Value::Object(
                self.sensitive
                    .iter()
                    .map(|(name, hash)| (name.clone(), Value::from(hash.as_str())))
                    .collect(),
            ),
        );
        map.insert(
            "sessions_running".to_string(),
            Value::from(self.sessions_running.as_str()),
        );
        map.insert(
            "steps".to_string(),
            Value::Array(self.steps.iter().map(ReceiptStep::to_value).collect()),
        );
        map.insert(
            "tier".to_string(),
            Value::from(self.tier.map_or("", Tier::as_str)),
        );
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<Event> {
        let text = |field: &str| payload.get(field).and_then(Value::as_str);
        let item_id = text("item_id")?;
        let kind = text("kind")?;
        let tier = text("tier")?;
        let mut event = Event::new(
            Action::parse(text("action")?)?,
            Actor::parse(text("actor")?)?,
        );
        event.item_id = (!item_id.is_empty()).then(|| ItemId::from_recorded(item_id));
        event.kind = (!kind.is_empty()).then(|| Kind::parse(kind)).flatten();
        event.tier = (!tier.is_empty()).then(|| tier_from_label(tier)).flatten();
        event.content_hash = text("content_hash")?.to_string();
        event.finding_id = text("finding_id")?.to_string();
        event.receipt_id = text("receipt_id")?.to_string();
        event.result = Outcome::parse(text("result")?)?;
        event.sessions_running = SessionsRunning::parse(text("sessions_running")?)?;
        event.rule_id = payload.get("rule_id")?.as_i64()?;
        for step in payload.get("steps")?.as_array()? {
            event.steps.push(ReceiptStep::parse(step)?);
        }
        for (name, value) in payload.get("sensitive")?.as_object()? {
            event
                .sensitive
                .insert(name.clone(), Redacted::parse(value.as_str()?)?);
        }
        for (name, value) in payload.get("detail")?.as_object()? {
            event
                .detail
                .insert(name.clone(), value.as_str()?.to_string());
        }
        Some(event)
    }
}

/// Reads back the label [`Tier::as_str`] prints.
fn tier_from_label(label: &str) -> Option<Tier> {
    [
        Tier::Allowlist,
        Tier::Rules,
        Tier::Heuristics,
        Tier::AiJudgement,
    ]
    .into_iter()
    .find(|tier| tier.as_str() == label)
}

/// One event as the Event Log holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedEvent {
    /// Where in the chain it sits.
    pub sequence: u64,
    /// Which key generation wrote it.
    pub epoch: u64,
    /// When it was written.
    pub recorded_at: Timestamp,
    /// False for a record no key in hand can verify, which is every record
    /// written before the protection state was reset.
    pub verified: bool,
    /// What happened.
    pub event: Event,
}

/// Why the Rule Pack in force changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackChange {
    /// A pack from the Rule Feed verified and was put in force.
    Accepted,
    /// The stored pack from the Rule Feed was discarded at start, because it
    /// no longer verified, the bundled pack had caught up with it, or it
    /// needs a newer AgentSweep. The pack named is the one in force instead.
    Discarded,
}

impl PackChange {
    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            PackChange::Accepted => "accepted",
            PackChange::Discarded => "discarded",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<PackChange> {
        match text {
            "accepted" => Some(PackChange::Accepted),
            "discarded" => Some(PackChange::Discarded),
            _ => None,
        }
    }
}

impl fmt::Display for PackChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Rules of one pack by id, with where each stands. What two packs are
/// compared by.
pub type PackRules = BTreeMap<i64, RuleStatus>;

/// One change of the Rule Pack in force, the payload of a `rule-pack` record.
///
/// It is not an action on an Item and not one of the actions of spec section
/// 5.5, so it is a record kind of its own beside the entries, like a chain
/// restart. It carries ids and versions only: nothing of any Item's content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RulePackRecord {
    /// Why the pack in force changed.
    pub change: PackChange,
    /// The version of the pack in force from here on.
    pub pack_version: u64,
    /// Its signed release moment, as the manifest states it.
    pub released_at: String,
    /// Where it came from.
    pub origin: PackOrigin,
    /// The version of the stored pack that was discarded, zero when it was
    /// not readable or nothing was discarded.
    pub discarded_version: u64,
    /// The Rules the pack in force before carried and this one does not.
    pub withdrawn: Vec<i64>,
    /// The Findings that went gone because their Rule was withdrawn.
    pub gone: Vec<FindingId>,
    /// The Rules that were on Probation before and are stable now.
    pub left_probation: Vec<i64>,
}

impl RulePackRecord {
    /// A change to a pack, with nothing yet said about what it withdrew.
    pub fn new(
        change: PackChange,
        pack_version: u64,
        released_at: &str,
        origin: PackOrigin,
    ) -> RulePackRecord {
        RulePackRecord {
            change,
            pack_version,
            released_at: released_at.to_string(),
            origin,
            discarded_version: 0,
            withdrawn: Vec::new(),
            gone: Vec::new(),
            left_probation: Vec::new(),
        }
    }

    /// Fills in what the pack in force now changed against the one before:
    /// the Rules it no longer carries and the Rules that left Probation.
    pub fn comparing(mut self, before: &PackRules, after: &PackRules) -> RulePackRecord {
        self.withdrawn = before
            .keys()
            .filter(|id| !after.contains_key(id))
            .copied()
            .collect();
        self.left_probation = before
            .iter()
            .filter(|(id, status)| {
                **status == RuleStatus::Probation && after.get(id) == Some(&RuleStatus::Stable)
            })
            .map(|(id, _)| *id)
            .collect();
        self
    }

    /// The payload a record carries.
    pub fn to_payload(&self) -> Value {
        let ids = |ids: &[i64]| Value::Array(ids.iter().map(|id| Value::from(*id)).collect());
        let mut map = Map::new();
        map.insert("change".to_string(), Value::from(self.change.as_str()));
        map.insert(
            "discarded_version".to_string(),
            Value::from(self.discarded_version),
        );
        map.insert(
            "gone".to_string(),
            Value::Array(
                self.gone
                    .iter()
                    .map(|id| Value::from(id.as_str()))
                    .collect(),
            ),
        );
        map.insert("left_probation".to_string(), ids(&self.left_probation));
        map.insert("origin".to_string(), Value::from(self.origin.as_str()));
        map.insert("pack_version".to_string(), Value::from(self.pack_version));
        map.insert(
            "released_at".to_string(),
            Value::from(self.released_at.as_str()),
        );
        map.insert("withdrawn".to_string(), ids(&self.withdrawn));
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<RulePackRecord> {
        let text = |field: &str| payload.get(field).and_then(Value::as_str);
        let ids = |field: &str| -> Option<Vec<i64>> {
            payload
                .get(field)?
                .as_array()?
                .iter()
                .map(Value::as_i64)
                .collect()
        };
        Some(RulePackRecord {
            change: PackChange::parse(text("change")?)?,
            pack_version: payload.get("pack_version")?.as_u64()?,
            released_at: text("released_at")?.to_string(),
            origin: PackOrigin::parse(text("origin")?)?,
            discarded_version: payload.get("discarded_version")?.as_u64()?,
            withdrawn: ids("withdrawn")?,
            gone: payload
                .get("gone")?
                .as_array()?
                .iter()
                .map(|id| id.as_str().map(FindingId::from_recorded))
                .collect::<Option<Vec<_>>>()?,
            left_probation: ids("left_probation")?,
        })
    }

    /// The Activity lines this change stands for, built from the record
    /// alone: which pack is in force and why, each Finding a withdrawn Rule
    /// took with it, each withdrawn Rule that took none, and each Rule that
    /// left Probation.
    pub fn activity(&self) -> Vec<String> {
        let version = self.pack_version;
        let origin = self.origin;
        let released = self.released_at.get(..10).unwrap_or(&self.released_at);
        let mut lines = vec![match (self.change, self.discarded_version) {
            (PackChange::Accepted, _) => {
                format!("Rule Pack {version} ({origin}) is in force, released {released}.")
            }
            (PackChange::Discarded, 0) => format!(
                "The stored Rule Pack from the Rule Feed was discarded; Rule Pack {version} \
                 ({origin}) is in force."
            ),
            (PackChange::Discarded, discarded) => format!(
                "Rule Pack {discarded} from the Rule Feed was discarded; Rule Pack {version} \
                 ({origin}) is in force."
            ),
        }];
        let mut accounted = std::collections::BTreeSet::new();
        for finding in &self.gone {
            let mut parts = finding.as_str().split('|');
            let item = parts.next().unwrap_or_default();
            let rule = parts
                .next()
                .and_then(|source| source.strip_prefix("rule/"))
                .and_then(|id| id.parse::<i64>().ok())
                .unwrap_or_default();
            accounted.insert(rule);
            lines.push(format!(
                "Rule {rule:04} was withdrawn by Rule Pack {version}, so its Finding on {item} \
                 is gone."
            ));
        }
        for rule in self.withdrawn.iter().filter(|id| !accounted.contains(id)) {
            lines.push(format!(
                "Rule {rule:04} was withdrawn by Rule Pack {version}."
            ));
        }
        for rule in &self.left_probation {
            lines.push(format!(
                "Rule {rule:04} left Probation with Rule Pack {version}."
            ));
        }
        lines
    }
}

/// One change of the Rule Pack as the Event Log holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedRulePack {
    /// Where in the chain it sits, which the live Activity event carries too.
    pub sequence: u64,
    /// When it was written.
    pub recorded_at: Timestamp,
    /// False for a record no key in hand can verify.
    pub verified: bool,
    /// What changed.
    pub record: RulePackRecord,
}

/// The Event Log, `events.jsonl`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventLog {
    chain: Chain,
}

impl EventLog {
    /// The Event Log kept at this path.
    pub fn at(path: impl Into<PathBuf>) -> EventLog {
        EventLog {
            chain: Chain::at(path, ChainId::Events),
        }
    }

    /// The Event Log of a data directory.
    pub fn in_data_directory(directory: &DataDirectory) -> EventLog {
        EventLog::at(directory.event_log())
    }

    /// The chain underneath, for the verification routine both chains share.
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Reads and verifies the whole log.
    pub fn read(&self, keys: &dyn KeySource) -> Result<EventLogView, ChainError> {
        let verification = self.chain.verify(keys)?;
        let mut events = Vec::with_capacity(verification.records.len());
        let mut rule_packs = Vec::new();
        let mut restarts = 0usize;
        let mut unreadable = 0usize;
        for record in &verification.records {
            match record.envelope.record {
                RecordKind::Entry => {}
                RecordKind::ChainRestart => {
                    restarts += 1;
                    continue;
                }
                RecordKind::RulePack => {
                    match RulePackRecord::from_payload(&record.envelope.payload) {
                        Some(change) => rule_packs.push(RecordedRulePack {
                            sequence: record.envelope.sequence,
                            recorded_at: record.envelope.recorded_at,
                            verified: record.verified,
                            record: change,
                        }),
                        None => unreadable += 1,
                    }
                    continue;
                }
            }
            match Event::from_payload(&record.envelope.payload) {
                Some(event) => events.push(RecordedEvent {
                    sequence: record.envelope.sequence,
                    epoch: record.envelope.epoch,
                    recorded_at: record.envelope.recorded_at,
                    verified: record.verified,
                    event,
                }),
                None => unreadable += 1,
            }
        }
        Ok(EventLogView {
            state: verification.state,
            head: verification.head,
            unverified: verification.records.iter().filter(|r| !r.verified).count(),
            events,
            rule_packs,
            restarts,
            unreadable,
        })
    }
}

/// The whole Event Log as one read left it.
#[derive(Clone, Debug)]
pub struct EventLogView {
    /// What verification found.
    pub state: ChainState,
    /// Every event of the last verifiable prefix, in the order written.
    pub events: Vec<RecordedEvent>,
    /// Every change of the Rule Pack in force, in the order written. The
    /// derived views never see these: they are not actions on an Item.
    pub rule_packs: Vec<RecordedRulePack>,
    /// The hash of the last record in the file.
    pub head: String,
    /// How many records no key in hand can verify.
    pub unverified: usize,
    /// How many times the chain was restarted because the key went missing.
    pub restarts: usize,
    /// How many records carried a payload that is not what their kind says.
    pub unreadable: usize,
}

impl EventLogView {
    /// What is in the quarantine store, rebuilt from the log.
    pub fn quarantine_manifest(&self) -> crate::derived::QuarantineManifest {
        crate::derived::QuarantineManifest::rebuild(&self.events)
    }

    /// Which content hashes carry Trust, rebuilt from the log.
    pub fn trust_table(&self) -> crate::derived::TrustTable {
        crate::derived::TrustTable::rebuild(&self.events)
    }

    /// The Activity lines the changes of the Rule Pack stand for, each with
    /// the sequence and the moment of the record it was built from, in the
    /// order written.
    pub fn pack_activity(&self) -> Vec<(u64, Timestamp, String)> {
        self.rule_packs
            .iter()
            .flat_map(|recorded| {
                recorded
                    .record
                    .activity()
                    .into_iter()
                    .map(|line| (recorded.sequence, recorded.recorded_at, line))
            })
            .collect()
    }
}

#[cfg(feature = "daemon")]
pub use writer::EventLogWriter;

#[cfg(feature = "daemon")]
mod writer {
    use super::{Event, EventLog, RulePackRecord};

    use crate::chain::{ChainError, ChainState, ChainWriter};
    use crate::envelope::{Envelope, RecordKind};
    use crate::keychain::KeySource;

    /// The write side of the Event Log.
    ///
    /// The daemon is the only writer (spec section 6.2), which this type
    /// carries: it exists only in a build with the `daemon` feature.
    #[derive(Debug)]
    pub struct EventLogWriter {
        writer: ChainWriter,
    }

    impl EventLogWriter {
        /// Verifies the log, then opens it for appending, returning the state
        /// verification found along with the writer.
        pub fn open(
            log: &EventLog,
            keys: &dyn KeySource,
        ) -> Result<(EventLogWriter, ChainState), ChainError> {
            let (writer, state) = ChainWriter::open(log.chain().clone(), keys)?;
            Ok((EventLogWriter { writer }, state))
        }

        /// Appends one event and flushes it to the disk.
        pub fn append(&mut self, event: &Event) -> Result<Envelope, ChainError> {
            self.writer.append(event.to_payload())
        }

        /// Appends one change of the Rule Pack in force, as a `rule-pack`
        /// record beside the events, and flushes it to the disk.
        pub fn record_rule_pack(
            &mut self,
            change: &RulePackRecord,
        ) -> Result<Envelope, ChainError> {
            self.writer
                .append_beside(RecordKind::RulePack, change.to_payload())
        }

        /// The hash a record appended now would link to.
        pub fn head(&self) -> &str {
            self.writer.head()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Scope;
    use crate::keychain::MemoryKeySource;

    use std::path::PathBuf;
    use tempfile::TempDir;

    fn item() -> ItemId {
        ItemId::new(
            "claude-code",
            &Scope::Project(PathBuf::from("/src/demo")),
            Kind::McpServer,
            ".mcp.json#leak",
        )
    }

    fn quarantine_event() -> Event {
        let mut event = Event::new(Action::Quarantine, Actor::Auto)
            .about(&item(), Kind::McpServer, &"a".repeat(64))
            .because_of("finding-1", Tier::Rules, 14)
            .hiding("env.API_TOKEN", "sk-live-not-a-real-token")
            .noting("agent", "claude-code");
        event.receipt_id = "r-0001".to_string();
        event.sessions_running = SessionsRunning::Yes;
        event.steps = vec![ReceiptStep {
            primitive: Primitive::RemoveEntry,
            outcome: Outcome::Ok,
            path: "/src/demo/.mcp.json".to_string(),
            locator: "mcpServers.leak".to_string(),
            detail: "the entry was dropped".to_string(),
        }];
        event
    }

    #[test]
    fn a_record_carries_every_field_of_the_specification() {
        let payload = quarantine_event().to_payload();
        for field in [
            "action",
            "actor",
            "content_hash",
            "detail",
            "finding_id",
            "item_id",
            "kind",
            "receipt_id",
            "result",
            "rule_id",
            "sensitive",
            "sessions_running",
            "steps",
            "tier",
        ] {
            assert!(payload.get(field).is_some(), "no {field}");
        }
        assert_eq!(payload["action"], Value::from("quarantine"));
        assert_eq!(payload["actor"], Value::from("auto"));
        assert_eq!(payload["kind"], Value::from("McpServer"));
        assert_eq!(payload["tier"], Value::from("T1"));
        assert_eq!(payload["rule_id"], Value::from(14));
        assert_eq!(payload["sessions_running"], Value::from("yes"));
        assert_eq!(
            payload["steps"][0]["primitive"],
            Value::from("remove-entry")
        );
    }

    #[test]
    fn an_event_round_trips_through_its_payload() {
        let event = quarantine_event();
        let read = Event::from_payload(&event.to_payload()).expect("a readable payload");
        assert_eq!(read, event);
    }

    #[test]
    fn an_event_about_no_single_item_round_trips_too() {
        let event = Event::new(Action::EngineChanged, Actor::User)
            .noting("engine", "ollama")
            .noting("state", "enabled");
        let read = Event::from_payload(&event.to_payload()).expect("a readable payload");
        assert_eq!(read, event);
        assert!(read.item_id.is_none());
        assert!(read.kind.is_none());
        assert!(read.tier.is_none());
    }

    #[test]
    fn a_sensitive_value_reaches_the_record_only_as_a_hash() {
        let event = quarantine_event();
        let hash = event.sensitive.get("env.API_TOKEN").expect("the hash");
        assert_eq!(
            hash.as_str(),
            format!("sha256:{}", sha256_hex(b"sk-live-not-a-real-token"))
        );
        let written = serde_json::to_string(&event.to_payload()).expect("a payload");
        assert!(!written.contains("sk-live-not-a-real-token"), "{written}");
    }

    #[test]
    fn the_secret_never_reaches_the_file_on_disk() {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
        writer
            .append(&quarantine_event())
            .expect("an appended event");

        let bytes = std::fs::read(log.chain().path()).expect("a readable log");
        let text = String::from_utf8(bytes).expect("a text file");
        assert!(!text.contains("sk-live-not-a-real-token"), "{text}");
        assert!(text.contains(&sha256_hex(b"sk-live-not-a-real-token")));
    }

    #[test]
    fn a_written_event_is_read_back_whole() {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let (mut writer, state) = EventLogWriter::open(&log, &keys).expect("an open log");
        assert_eq!(state, ChainState::Intact);
        writer
            .append(&quarantine_event())
            .expect("an appended event");
        writer
            .append(&Event::new(Action::Trust, Actor::User).about(
                &item(),
                Kind::McpServer,
                &"a".repeat(64),
            ))
            .expect("an appended event");

        let view = log.read(&keys).expect("a readable log");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.events.len(), 2);
        assert_eq!(view.events[0].event, quarantine_event());
        assert_eq!(view.events[0].sequence, 0);
        assert!(view.events.iter().all(|recorded| recorded.verified));
        assert_eq!(view.unverified, 0);
        assert_eq!(view.restarts, 0);
        assert_eq!(view.unreadable, 0);
        assert!(view.rule_packs.is_empty(), "an older log has none");
        assert!(view.pack_activity().is_empty());
    }

    #[test]
    fn a_reset_protection_state_leaves_the_old_events_readable_and_unverified() {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            writer
                .append(&quarantine_event())
                .expect("an appended event");
        }
        keys.forget().expect("the key goes away");
        assert_eq!(
            log.read(&keys).expect("a readable log").state,
            ChainState::KeyMissing
        );

        let (mut writer, state) = EventLogWriter::open(&log, &keys).expect("an open log");
        assert_eq!(state, ChainState::KeyMissing);
        writer
            .append(&Event::new(Action::Acknowledge, Actor::User))
            .expect("an appended event");

        let view = log.read(&keys).expect("a readable log");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.restarts, 1);
        assert_eq!(view.events.len(), 2);
        assert!(!view.events[0].verified);
        assert!(view.events[1].verified);
        assert_eq!(view.unverified, 1);
    }

    #[test]
    fn every_vocabulary_round_trips_through_the_spelling_a_record_carries() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
        for actor in [Actor::Auto, Actor::User, Actor::Restore] {
            assert_eq!(Actor::parse(actor.as_str()), Some(actor));
        }
        for primitive in Primitive::ALL {
            assert_eq!(Primitive::parse(primitive.as_str()), Some(primitive));
        }
        for outcome in Outcome::ALL {
            assert_eq!(Outcome::parse(outcome.as_str()), Some(outcome));
        }
        for state in SessionsRunning::ALL {
            assert_eq!(SessionsRunning::parse(state.as_str()), Some(state));
        }
        for tier in [
            Tier::Allowlist,
            Tier::Rules,
            Tier::Heuristics,
            Tier::AiJudgement,
        ] {
            assert_eq!(tier_from_label(tier.as_str()), Some(tier));
        }
    }

    #[test]
    fn a_hash_is_the_only_thing_a_redaction_reads_back() {
        assert!(Redacted::parse("sha256:not-a-hash").is_none());
        assert!(Redacted::parse("sk-live-not-a-real-token").is_none());
        let hash = Redacted::of(b"value");
        assert_eq!(Redacted::parse(hash.as_str()), Some(hash));
    }

    #[test]
    fn the_event_log_is_the_events_chain_of_the_data_directory() {
        let directory = DataDirectory::at("/tmp/agentsweep-test");
        let log = EventLog::in_data_directory(&directory);
        assert_eq!(log.chain().path(), directory.event_log());
        assert_eq!(log.chain().id(), ChainId::Events);
    }

    fn a_pack_change() -> RulePackRecord {
        let gone = FindingId::new(&item(), crate::finding::Source::Rule(1), &"b".repeat(64));
        let mut change = RulePackRecord::new(
            PackChange::Accepted,
            2,
            "2026-10-01T09:30:00Z",
            PackOrigin::Fetched,
        );
        change.withdrawn = vec![1, 7];
        change.gone = vec![gone];
        change.left_probation = vec![2];
        change
    }

    #[test]
    fn a_pack_change_round_trips_through_its_payload() {
        let change = a_pack_change();
        let read = RulePackRecord::from_payload(&change.to_payload()).expect("a pack change");
        assert_eq!(read, change);
        let payload = change.to_payload();
        assert_eq!(payload["change"], Value::from("accepted"));
        assert_eq!(payload["origin"], Value::from("fetched"));
        assert_eq!(payload["withdrawn"], serde_json::json!([1, 7]));
        assert!(
            Event::from_payload(&payload).is_none(),
            "it is not an event"
        );

        let mut discarded = RulePackRecord::new(
            PackChange::Discarded,
            1,
            "2026-09-25T00:00:00Z",
            PackOrigin::Bundled,
        );
        discarded.discarded_version = 2;
        assert_eq!(
            RulePackRecord::from_payload(&discarded.to_payload()),
            Some(discarded)
        );
    }

    #[test]
    fn comparing_two_packs_names_the_withdrawn_rules_and_those_that_left_probation() {
        let before: PackRules = [
            (1, RuleStatus::Probation),
            (2, RuleStatus::Probation),
            (3, RuleStatus::Stable),
            (4, RuleStatus::Probation),
        ]
        .into_iter()
        .collect();
        let after: PackRules = [
            (2, RuleStatus::Stable),
            (3, RuleStatus::Stable),
            (4, RuleStatus::Probation),
            (21, RuleStatus::Probation),
        ]
        .into_iter()
        .collect();
        let change = RulePackRecord::new(PackChange::Accepted, 2, "", PackOrigin::Fetched)
            .comparing(&before, &after);
        assert_eq!(change.withdrawn, vec![1]);
        assert_eq!(change.left_probation, vec![2]);
    }

    #[test]
    fn the_activity_of_a_pack_change_is_built_from_the_record_alone() {
        let lines = a_pack_change().activity();
        assert_eq!(
            lines[0],
            "Rule Pack 2 (fetched) is in force, released 2026-10-01."
        );
        assert_eq!(
            lines[1],
            format!(
                "Rule 0001 was withdrawn by Rule Pack 2, so its Finding on {} is gone.",
                item()
            )
        );
        assert_eq!(lines[2], "Rule 0007 was withdrawn by Rule Pack 2.");
        assert_eq!(lines[3], "Rule 0002 left Probation with Rule Pack 2.");
        assert_eq!(lines.len(), 4);
    }

    /// A `rule-pack` record sits in the chain like any other and verifies;
    /// the derived views and the events pass it by without counting it as
    /// unreadable.
    #[test]
    fn a_pack_change_is_part_of_the_chain_and_the_derived_views_pass_it_by() {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
        writer
            .append(&quarantine_event())
            .expect("an appended event");
        let written = writer
            .record_rule_pack(&a_pack_change())
            .expect("an appended pack change");
        writer
            .append(&Event::new(Action::Trust, Actor::User).about(
                &item(),
                Kind::McpServer,
                &"c".repeat(64),
            ))
            .expect("an appended event");
        assert_eq!(written.record, RecordKind::RulePack);

        let view = log.read(&keys).expect("a readable log");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.unreadable, 0);
        assert_eq!(view.events.len(), 2);
        assert_eq!(view.events[1].sequence, 2);
        assert_eq!(view.rule_packs.len(), 1);
        assert_eq!(view.rule_packs[0].sequence, 1);
        assert!(view.rule_packs[0].verified);
        assert_eq!(view.rule_packs[0].record, a_pack_change());
        assert_eq!(view.quarantine_manifest().len(), 1);
        assert!(view.trust_table().trusts(Kind::McpServer, &"c".repeat(64)));

        let activity = view.pack_activity();
        assert_eq!(activity.len(), 4);
        assert!(activity.iter().all(|(sequence, _, _)| *sequence == 1));
    }

    /// Compacting the Baseline anchors itself in the Event Log and leaves
    /// every record already there, the changes of the Rule Pack included.
    #[test]
    fn a_baseline_compaction_keeps_every_pack_change_in_the_event_log() {
        let directory = TempDir::new().expect("a temporary directory");
        let data = DataDirectory::at(directory.path());
        let log = EventLog::in_data_directory(&data);
        let keys = MemoryKeySource::empty();
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            writer
                .record_rule_pack(&a_pack_change())
                .expect("an appended pack change");
        }
        let retention = crate::baseline::Retention::of(std::collections::BTreeSet::new());
        crate::baseline::compact(&data, &keys, &retention, Timestamp::now())
            .expect("the Baseline compacts");

        let view = log.read(&keys).expect("a readable log");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.rule_packs.len(), 1);
        assert_eq!(view.rule_packs[0].record, a_pack_change());
        assert_eq!(view.events.len(), 1);
        assert_eq!(view.events[0].event.action, Action::BaselineCompacted);
    }
}
