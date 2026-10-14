//! The user's answers to the two integrity states (spec sections 5.5 and 8.6).
//!
//! A chain whose key is missing has already started again under a new key by
//! the time anyone sees it, and a chain that broke while the key was in hand
//! freezes automatic Quarantine (ADR 0003). Neither is over until the user has
//! answered: "Start a fresh record" for the first, "Scan again, trusting
//! nothing" for the second. Each answer is an `integrity` record beside the
//! events on the Event Log, naming which acknowledgement it is, so the answer
//! is itself on record and a daemon that starts again reads it back.
//!
//! The answer to a broken chain is also written into that chain, after the
//! break. It names the sequence where the chain stopped being trustworthy and
//! the hash of the line found there, and it carries a MAC under the key in
//! hand, which nobody without the key can forge. Verification picks the chain
//! up again from it: the records before the break count as they did, the
//! records between the break and the answer are set aside unverified and
//! never reach a derived view, and the records after the answer count again.
//! That is how Trust records and accepted Baseline hashes written after the
//! break come to be ignored, so everything trusted since is judged again,
//! while the Event Log keeps every record it was handed.

use serde_json::{Map, Value};

use crate::chain::{KEY_MISSING, Verification};
use crate::envelope::{ChainId, RecordKind, Timestamp};

/// The spelling of the answer to a broken chain.
pub const CHAIN_BROKEN: &str = "chain-broken";

/// Which of the two acknowledgements an `integrity` record is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrityRecord {
    /// "Scan again, trusting nothing": a broken chain was looked at. Written
    /// once into the Event Log for every broken chain, and once more into
    /// the broken chain itself when that is the Baseline.
    ChainBroken {
        /// The chain that broke.
        chain: ChainId,
        /// The sequence where it stopped being trustworthy.
        sequence: u64,
        /// The SHA-256 of the line found at that sequence when the user
        /// answered, so an answer never covers a line changed after it.
        broken: String,
    },
    /// "Start a fresh record": the chains that started again under a new key
    /// are taken as they are.
    KeyMissing,
}

impl IntegrityRecord {
    /// Which acknowledgement it is, as the record spells it.
    pub fn acknowledgement(&self) -> &'static str {
        match self {
            IntegrityRecord::ChainBroken { .. } => CHAIN_BROKEN,
            IntegrityRecord::KeyMissing => KEY_MISSING,
        }
    }

    /// The payload the record carries.
    pub fn to_payload(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "acknowledgement".to_string(),
            Value::from(self.acknowledgement()),
        );
        if let IntegrityRecord::ChainBroken {
            chain,
            sequence,
            broken,
        } = self
        {
            map.insert("broken".to_string(), Value::from(broken.as_str()));
            map.insert("chain".to_string(), Value::from(chain.as_str()));
            map.insert("sequence".to_string(), Value::from(*sequence));
        }
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<IntegrityRecord> {
        match payload.get("acknowledgement")?.as_str()? {
            CHAIN_BROKEN => Some(IntegrityRecord::ChainBroken {
                chain: ChainId::parse(payload.get("chain")?.as_str()?)?,
                sequence: payload.get("sequence")?.as_u64()?,
                broken: payload.get("broken")?.as_str()?.to_string(),
            }),
            KEY_MISSING => Some(IntegrityRecord::KeyMissing),
            _ => None,
        }
    }
}

/// Which chains started again under a new key without the user having
/// answered "Start a fresh record" since.
///
/// That is the "protection state was reset" rung once the restart is behind
/// it: the restarted chain verifies again under its new key, so verification
/// alone would let the rung go by itself on the next read. It stays until the
/// user answers, and an answer stays answered across a daemon restart because
/// it is read back off the Event Log.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResetUnanswered {
    /// The Event Log started again and nobody answered since.
    pub events: bool,
    /// The Baseline started again and nobody answered since.
    pub baseline: bool,
}

impl ResetUnanswered {
    /// Reads both chains. The Event Log restart is compared with the answer by
    /// sequence, because both are on the Event Log; the Baseline restart by
    /// the moment it was written, because the answer is on the other chain.
    pub fn of(events: &Verification, baseline: &Verification) -> ResetUnanswered {
        let answered = events
            .records
            .iter()
            .filter(|record| record.envelope.record == RecordKind::Integrity)
            .filter(|record| {
                IntegrityRecord::from_payload(&record.envelope.payload)
                    == Some(IntegrityRecord::KeyMissing)
            })
            .map(|record| (record.envelope.sequence, record.envelope.recorded_at))
            .next_back();
        let restarted = |verification: &Verification| -> Option<(u64, Timestamp)> {
            verification
                .records
                .iter()
                .filter(|record| record.envelope.record == RecordKind::ChainRestart)
                .filter(|record| {
                    record
                        .envelope
                        .payload
                        .get("cause")
                        .and_then(Value::as_str)
                        .unwrap_or(KEY_MISSING)
                        == KEY_MISSING
                })
                .map(|record| (record.envelope.sequence, record.envelope.recorded_at))
                .next_back()
        };
        ResetUnanswered {
            events: match (restarted(events), answered) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some((restart, _)), Some((answer, _))) => restart > answer,
            },
            baseline: match (restarted(baseline), answered) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some((_, restart)), Some((_, answer))) => restart > answer,
            },
        }
    }

    /// True when either chain is waiting for the answer.
    pub fn any(self) -> bool {
        self.events || self.baseline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_acknowledgements_round_trip_through_their_payload() {
        let broken = IntegrityRecord::ChainBroken {
            chain: ChainId::Baseline,
            sequence: 4,
            broken: "ab".repeat(32),
        };
        for record in [broken, IntegrityRecord::KeyMissing] {
            let payload = record.to_payload();
            assert_eq!(
                payload["acknowledgement"].as_str(),
                Some(record.acknowledgement())
            );
            assert_eq!(IntegrityRecord::from_payload(&payload), Some(record));
        }
        assert_eq!(
            IntegrityRecord::from_payload(&serde_json::json!({"acknowledgement": "other"})),
            None
        );
    }

    /// The reset stays unanswered across any number of reads, and only the
    /// answer on the Event Log ends it, for both chains at once.
    #[test]
    fn a_restart_stays_unanswered_until_start_a_fresh_record_is_on_the_event_log() {
        use crate::chain::{Chain, ChainWriter};
        use crate::keychain::{KeySource, MemoryKeySource};
        use serde_json::json;

        let directory = tempfile::TempDir::new().expect("a temporary directory");
        let events = Chain::at(directory.path().join("events.jsonl"), ChainId::Events);
        let baseline = Chain::at(directory.path().join("baseline.jsonl"), ChainId::Baseline);
        let keys = MemoryKeySource::empty();
        for chain in [&events, &baseline] {
            let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("a chain");
            writer
                .append(json!({ "action": "trust" }))
                .expect("a record");
        }
        let read = || {
            ResetUnanswered::of(
                &events.verify(&keys).expect("the Event Log"),
                &baseline.verify(&keys).expect("the Baseline"),
            )
        };
        assert_eq!(read(), ResetUnanswered::default());

        keys.forget().expect("the key goes away");
        let found = [&events, &baseline].map(|chain| chain.verify(&keys).expect("a chain"));
        for (chain, verification) in [&events, &baseline].into_iter().zip(found) {
            ChainWriter::open_verified(chain.clone(), verification, &keys)
                .expect("a restarted chain");
        }
        let unanswered = read();
        assert!(unanswered.events && unanswered.baseline);
        assert_eq!(read(), unanswered, "reading again changes nothing");

        let (mut writer, _) = ChainWriter::open(events.clone(), &keys).expect("the Event Log");
        writer
            .append_beside(
                RecordKind::Integrity,
                IntegrityRecord::KeyMissing.to_payload(),
            )
            .expect("the answer");
        assert!(!read().any());
    }
}
