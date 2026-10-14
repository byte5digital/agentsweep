//! The two integrity states on the wire (spec sections 5.5 and 8.6): reading
//! the records of either chain, and the two answers.
//!
//! "Look at the records" and "Show what changed" read the same thing: the
//! records of one chain, a page at a time, each with whether the key in hand
//! verifies it and whether the derived views read it. A record says which
//! Item, Finding, Receipt and Rule it is about, the content hash it names and
//! the paths it names, and nothing else: the sensitive fields are hashes in
//! the store already and are left out here, and so is every free-text detail.
//!
//! "Start a fresh record" and "Scan again, trusting nothing" take no field at
//! all, so neither can carry a path.

use serde_json::{Map, Value};

use agentsweep_core::chain::ChainState;
use agentsweep_core::envelope::{ChainId, Timestamp};

use crate::protocol::{chain_state_from_value, chain_state_to_value};

/// How many records one `records` answer carries at most. The Baseline holds
/// one record per Item, which is more than one frame should.
pub const RECORDS_PAGE: usize = 500;

/// One record of a chain, as a client is shown it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecordLine {
    /// Its position in the chain.
    pub sequence: u64,
    /// Its record kind (`entry`, `chain-restart`, `rule-pack`, `integrity`),
    /// or `unreadable` for a line that does not read as a record at all.
    pub record: String,
    /// When it says it was written, absent for an unreadable line.
    pub recorded_at: Option<Timestamp>,
    /// True when its MAC verifies under the key in hand. A record of an
    /// earlier key generation never does.
    pub verified: bool,
    /// True when the derived views read it: false for a record set aside by
    /// an answered break and for every record from an unanswered break on.
    pub counted: bool,
    /// What it records: the action of an event, `item` or `coverage` on the
    /// Baseline, the acknowledgement of an `integrity` record, the cause of a
    /// chain restart. Empty where nothing says.
    pub what: String,
    /// The Item it is about, empty for none.
    pub item_id: String,
    /// The Finding it is about, empty for none.
    pub finding_id: String,
    /// The Receipt it is about, empty for none.
    pub receipt_id: String,
    /// The Rule behind it, zero for none.
    pub rule_id: i64,
    /// The content hash it names, empty for none.
    pub content_hash: String,
    /// The paths it names: a Receipt's steps, a Baseline record's Item, a
    /// stretch of coverage's root.
    pub paths: Vec<String>,
}

impl RecordLine {
    /// The record as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "content_hash".to_string(),
            Value::from(self.content_hash.as_str()),
        );
        map.insert("counted".to_string(), Value::from(self.counted));
        map.insert(
            "finding_id".to_string(),
            Value::from(self.finding_id.as_str()),
        );
        map.insert("item_id".to_string(), Value::from(self.item_id.as_str()));
        map.insert(
            "paths".to_string(),
            Value::Array(
                self.paths
                    .iter()
                    .map(|path| Value::from(path.as_str()))
                    .collect(),
            ),
        );
        map.insert(
            "receipt_id".to_string(),
            Value::from(self.receipt_id.as_str()),
        );
        map.insert("record".to_string(), Value::from(self.record.as_str()));
        map.insert(
            "recorded_at".to_string(),
            match self.recorded_at {
                Some(at) => Value::from(at.to_string()),
                None => Value::Null,
            },
        );
        map.insert("rule_id".to_string(), Value::from(self.rule_id));
        map.insert("sequence".to_string(), Value::from(self.sequence));
        map.insert("verified".to_string(), Value::from(self.verified));
        map.insert("what".to_string(), Value::from(self.what.as_str()));
        Value::Object(map)
    }

    /// Reads back what [`RecordLine::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<RecordLine> {
        let text = |field: &str| value.get(field)?.as_str().map(str::to_string);
        Some(RecordLine {
            sequence: value.get("sequence")?.as_u64()?,
            record: text("record")?,
            recorded_at: match value.get("recorded_at")? {
                Value::Null => None,
                at => Some(Timestamp::parse(at.as_str()?)?),
            },
            verified: value.get("verified")?.as_bool()?,
            counted: value.get("counted")?.as_bool()?,
            what: text("what")?,
            item_id: text("item_id")?,
            finding_id: text("finding_id")?,
            receipt_id: text("receipt_id")?,
            rule_id: value.get("rule_id")?.as_i64()?,
            content_hash: text("content_hash")?,
            paths: value
                .get("paths")?
                .as_array()?
                .iter()
                .map(|path| path.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()?,
        })
    }
}

/// One page of the records of one chain: the answer to `records`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainRecords {
    /// Which chain.
    pub chain: ChainId,
    /// Its state as Health shows it: broken at the sequence where it stops
    /// being trustworthy, key missing while a restart is unanswered, or
    /// intact.
    pub state: ChainState,
    /// The records from the sequence asked for, in order, at most
    /// [`RECORDS_PAGE`] of them.
    pub records: Vec<RecordLine>,
    /// The sequence to ask from for the next page, absent on the last one.
    pub next: Option<u64>,
}

impl ChainRecords {
    /// The page as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("chain".to_string(), Value::from(self.chain.as_str()));
        map.insert(
            "next".to_string(),
            self.next.map_or(Value::Null, Value::from),
        );
        map.insert(
            "records".to_string(),
            Value::Array(self.records.iter().map(RecordLine::to_value).collect()),
        );
        map.insert("state".to_string(), chain_state_to_value(&self.state));
        Value::Object(map)
    }

    /// Reads back what [`ChainRecords::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<ChainRecords> {
        Some(ChainRecords {
            chain: ChainId::parse(value.get("chain")?.as_str()?)?,
            state: chain_state_from_value(value.get("state")?)?,
            records: value
                .get("records")?
                .as_array()?
                .iter()
                .map(RecordLine::from_value)
                .collect::<Option<Vec<RecordLine>>>()?,
            next: match value.get("next")? {
                Value::Null => None,
                next => Some(next.as_u64()?),
            },
        })
    }
}

/// What one of the two answers did: the answer to `acknowledge-key-missing`
/// and `acknowledge-chain-broken`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityAnswer {
    /// Which acknowledgement was recorded, as the `integrity` record spells
    /// it.
    pub acknowledgement: String,
    /// The chains it answered for.
    pub chains: Vec<ChainId>,
    /// True when it asked for a Full Scan, which "Scan again, trusting
    /// nothing" does; false when it joined one already waiting or asked for
    /// none.
    pub scan_started: bool,
}

impl IntegrityAnswer {
    /// The answer as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "acknowledgement".to_string(),
            Value::from(self.acknowledgement.as_str()),
        );
        map.insert(
            "chains".to_string(),
            Value::Array(
                self.chains
                    .iter()
                    .map(|chain| Value::from(chain.as_str()))
                    .collect(),
            ),
        );
        map.insert("scan_started".to_string(), Value::from(self.scan_started));
        Value::Object(map)
    }

    /// Reads back what [`IntegrityAnswer::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<IntegrityAnswer> {
        Some(IntegrityAnswer {
            acknowledgement: value.get("acknowledgement")?.as_str()?.to_string(),
            chains: value
                .get("chains")?
                .as_array()?
                .iter()
                .map(|chain| ChainId::parse(chain.as_str()?))
                .collect::<Option<Vec<ChainId>>>()?,
            scan_started: value.get("scan_started")?.as_bool()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_of_records_round_trips() {
        let page = ChainRecords {
            chain: ChainId::Events,
            state: ChainState::KeyMissing,
            records: vec![
                RecordLine {
                    sequence: 1,
                    record: "entry".to_string(),
                    recorded_at: Timestamp::parse("2026-10-14T09:00:00.000Z"),
                    verified: false,
                    counted: false,
                    what: "trust".to_string(),
                    item_id: "claude-code/user/skill/setup".to_string(),
                    rule_id: 1,
                    content_hash: "ab".repeat(32),
                    paths: vec!["/home/.claude/skills/setup".to_string()],
                    ..RecordLine::default()
                },
                RecordLine {
                    sequence: 2,
                    record: "unreadable".to_string(),
                    ..RecordLine::default()
                },
            ],
            next: Some(3),
        };
        assert_eq!(ChainRecords::from_value(&page.to_value()), Some(page));
    }

    #[test]
    fn an_answer_round_trips() {
        let answer = IntegrityAnswer {
            acknowledgement: "chain-broken".to_string(),
            chains: vec![ChainId::Events, ChainId::Baseline],
            scan_started: true,
        };
        assert_eq!(
            IntegrityAnswer::from_value(&answer.to_value()),
            Some(answer)
        );
    }
}
