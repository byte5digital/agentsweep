//! Reading, verifying and extending a hash chain.
//!
//! This is the primitive under both the Event Log and the Baseline (ADR 0003).
//! Reading and verifying is open to every process; appending is not. The write
//! side is behind the `daemon` feature, which only the daemon crate turns on,
//! so the application and the CLI cannot compile a call that writes a record.
//!
//! Verification keeps two failure states apart, because they mean different
//! things to the person in front of the Mac. A record that does not verify
//! while the key is in hand is [`ChainState::Broken`], shown as "records
//! tampered". A well-formed chain with no key at all is
//! [`ChainState::KeyMissing`], shown as "protection state was reset": a
//! migrated Mac, a reset Keychain or a restored backup. Nothing is ever
//! silently dropped, a half-written last line least of all.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::envelope::{ChainId, Envelope, EnvelopeError, GENESIS, RecordKind};
use crate::integrity::IntegrityRecord;
use crate::item::sha256_hex;
use crate::keychain::{KeyError, KeySource};

/// Why a chain does not verify.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BreakReason {
    /// The line is not a record, or not in the form AgentSweep writes.
    Malformed(String),
    /// The last write did not finish: the file ends mid-record.
    Truncated,
    /// The record belongs to another chain, or sits at the wrong position.
    OutOfOrder,
    /// The record does not link to the one before it.
    LinkBroken,
    /// A key generation started where no chain restart says it should.
    EpochOutOfOrder,
    /// The record's MAC is not the one the key in hand produces.
    MacFailed,
}

impl fmt::Display for BreakReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BreakReason::Malformed(detail) => write!(f, "the record is malformed: {detail}"),
            BreakReason::Truncated => f.write_str("the file ends mid-record"),
            BreakReason::OutOfOrder => f.write_str("the record sits at the wrong position"),
            BreakReason::LinkBroken => f.write_str("the record does not link to the one before it"),
            BreakReason::EpochOutOfOrder => {
                f.write_str("a key generation starts without a chain restart")
            }
            BreakReason::MacFailed => f.write_str("the record's MAC does not verify"),
        }
    }
}

/// What verification found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainState {
    /// Every record verifies under the key in hand, or there is nothing yet to
    /// verify.
    Intact,
    /// The chain is well formed but no key exists to verify it with. Not an
    /// attack: a migrated Mac, a reset Keychain, a restored backup.
    KeyMissing,
    /// A record does not verify while the key is in hand.
    Broken {
        /// Where the chain stops being trustworthy.
        sequence: u64,
        /// What went wrong there.
        reason: BreakReason,
    },
}

impl ChainState {
    /// The fixed wording for this state, empty when all is well. The Health
    /// precedence of spec section 6.6 puts "records tampered" above
    /// "protection state was reset".
    pub fn headline(&self) -> &'static str {
        match self {
            ChainState::Intact => "",
            ChainState::KeyMissing => "protection state was reset",
            ChainState::Broken { .. } => "records tampered",
        }
    }

    /// True when automatic Quarantine must stay frozen until the user
    /// acknowledges (ADR 0003).
    pub fn freezes_automatic_quarantine(&self) -> bool {
        matches!(self, ChainState::Broken { .. })
    }
}

/// The cause a chain restart record carries when the key went missing and a
/// new key and a new chain started.
pub const KEY_MISSING: &str = "key-missing";

/// The cause a chain restart record carries when the chain was compacted: the
/// records that were kept, written afresh and anchored to the chain they
/// replace (spec section 4.6.6).
pub const COMPACTION: &str = "compaction";

/// One record as verification read it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// The record itself.
    pub envelope: Envelope,
    /// The hash the next record links to.
    pub hash: String,
    /// False for a record of an earlier key generation, which no key in hand
    /// can verify. It stays readable and says so.
    pub verified: bool,
}

/// What reading and verifying a whole chain found.
#[derive(Clone, Debug)]
pub struct Verification {
    /// Which chain was read.
    pub chain: ChainId,
    /// What verification found.
    pub state: ChainState,
    /// The last verifiable prefix: every record up to the break, or all of
    /// them when there is none. A break the user answered is not a break here:
    /// the records before it and the records from the answer on are in, the
    /// ones between are in [`Verification::set_aside`].
    pub records: Vec<Record>,
    /// The records between a break the user answered and the answer, readable
    /// and never verified: the chain cannot vouch for them, so no derived view
    /// reads them (spec section 8.6, "Scan again, trusting nothing").
    pub set_aside: Vec<Record>,
    /// Every record from an unanswered break on, the record at the break
    /// first, each marked verified when its own MAC verifies under the key in
    /// hand. What "Show what changed" lists. A line that does not read as a
    /// record at all is missing here. Empty while the chain is not broken.
    pub beyond: Vec<Record>,
    /// The SHA-256 of the line at an unanswered break, which the answer to it
    /// names. Absent while the chain is not broken.
    pub broken_line: Option<String>,
    /// The hash of the last line in the file, whatever its state, which is
    /// what a new record links to. [`GENESIS`] for an empty file.
    pub head: String,
    /// The key generation the records in hand belong to.
    pub epoch: u64,
    /// The position the next record takes: the number of lines in the file.
    pub next_sequence: u64,
    /// False when the file ends mid-record.
    pub terminated: bool,
}

impl Verification {
    /// How many records no key in hand can verify.
    pub fn unverified(&self) -> usize {
        self.records
            .iter()
            .filter(|record| !record.verified)
            .count()
    }

    /// True when the chain was restarted at least once because the key went
    /// missing, which the Developer Posture says cannot rule out tampering.
    pub fn was_restarted(&self) -> bool {
        self.records
            .iter()
            .any(|record| record.envelope.record == RecordKind::ChainRestart)
    }
}

/// Why a chain could not be read or written.
#[derive(Debug)]
pub enum ChainError {
    /// The file could not be read or written.
    Io(io::Error),
    /// The key could not be read or stored.
    Key(KeyError),
    /// The write would have been unsafe, and was not made.
    Refused(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Io(error) => write!(f, "the chain file could not be used: {error}"),
            ChainError::Key(error) => write!(f, "{error}"),
            ChainError::Refused(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<io::Error> for ChainError {
    fn from(error: io::Error) -> ChainError {
        ChainError::Io(error)
    }
}

impl From<KeyError> for ChainError {
    fn from(error: KeyError) -> ChainError {
        ChainError::Key(error)
    }
}

/// One append-only hash-chained file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chain {
    path: PathBuf,
    id: ChainId,
}

impl Chain {
    /// The chain kept at this path.
    pub fn at(path: impl Into<PathBuf>, id: ChainId) -> Chain {
        Chain {
            path: path.into(),
            id,
        }
    }

    /// Where the chain is kept.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Which chain it is.
    pub fn id(&self) -> ChainId {
        self.id
    }

    /// Reads every record and says whether the chain is intact, broken or
    /// unverifiable for want of a key.
    pub fn verify(&self, keys: &dyn KeySource) -> Result<Verification, ChainError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(ChainError::Io(error)),
        };
        let key = keys.load()?;
        Ok(self.verify_bytes(&bytes, key.as_ref()))
    }

    fn verify_bytes(&self, bytes: &[u8], key: Option<&crate::keychain::ChainKey>) -> Verification {
        let lines = split_lines(bytes);
        let terminated = bytes.is_empty() || bytes.ends_with(b"\n");
        let head = lines
            .last()
            .map_or_else(|| GENESIS.to_string(), |line| sha256_hex(line));

        let mut records: Vec<Record> = Vec::with_capacity(lines.len());
        let mut set_aside: Vec<Record> = Vec::new();
        // The records read past a structural break, kept in case an answer
        // further on sets them aside.
        let mut stranded: Vec<Record> = Vec::new();
        let mut structural: Option<(u64, BreakReason)> = None;
        let mut previous = GENESIS.to_string();
        let mut epoch = 0u64;
        // The earliest sequence an answer may reach back to: never over an
        // answer before it.
        let mut floor = 0u64;

        for (index, line) in lines.iter().enumerate() {
            let sequence = index as u64;
            let truncated = index + 1 == lines.len() && !terminated;
            let parsed = match truncated {
                true => Err(EnvelopeError::Malformed(String::new())),
                false => Envelope::parse(line),
            };

            // An answer to a break picks the chain up again from itself.
            if let Ok(envelope) = &parsed
                && let Some(reach) = self.answers(
                    envelope,
                    &lines,
                    index,
                    floor,
                    epoch,
                    structural.as_ref().map(|(at, _)| *at),
                )
            {
                let from = records
                    .iter()
                    .position(|record| record.envelope.sequence >= reach)
                    .unwrap_or(records.len());
                set_aside.extend(records.split_off(from));
                set_aside.append(&mut stranded);
                structural = None;
                previous = sha256_hex(line);
                epoch = envelope.epoch;
                floor = sequence;
                records.push(Record {
                    envelope: envelope.clone(),
                    hash: previous.clone(),
                    verified: false,
                });
                continue;
            }

            if structural.is_some() {
                if let Ok(envelope) = parsed {
                    stranded.push(Record {
                        envelope,
                        hash: sha256_hex(line),
                        verified: false,
                    });
                }
                continue;
            }

            let envelope = match parsed {
                Ok(envelope) => envelope,
                Err(_) if truncated => {
                    structural = Some((sequence, BreakReason::Truncated));
                    continue;
                }
                Err(EnvelopeError::NotCanonical) => {
                    let detail = "not the form AgentSweep writes".to_string();
                    structural = Some((sequence, BreakReason::Malformed(detail)));
                    continue;
                }
                Err(EnvelopeError::Malformed(detail)) => {
                    structural = Some((sequence, BreakReason::Malformed(detail)));
                    continue;
                }
            };
            let expected_epoch = match envelope.record {
                RecordKind::ChainRestart if index > 0 => epoch + 1,
                _ => epoch,
            };
            let reason = if envelope.chain != self.id || envelope.sequence != sequence {
                Some(BreakReason::OutOfOrder)
            } else if envelope.previous != previous {
                Some(BreakReason::LinkBroken)
            } else if envelope.epoch != expected_epoch {
                Some(BreakReason::EpochOutOfOrder)
            } else {
                None
            };
            if let Some(reason) = reason {
                structural = Some((sequence, reason));
                stranded.push(Record {
                    envelope,
                    hash: sha256_hex(line),
                    verified: false,
                });
                continue;
            }
            epoch = envelope.epoch;
            previous = sha256_hex(line);
            records.push(Record {
                envelope,
                hash: previous.clone(),
                verified: false,
            });
        }

        let mut state = ChainState::Intact;
        let mut mac_break: Option<(u64, BreakReason)> = None;
        match key {
            None if records.is_empty() && set_aside.is_empty() && structural.is_none() => {}
            None => state = ChainState::KeyMissing,
            Some(key) => {
                let current = records.last().map_or(0, |record| record.envelope.epoch);
                for record in &mut records {
                    if record.envelope.epoch != current {
                        continue;
                    }
                    if !record.envelope.mac_matches(key) {
                        mac_break = Some((record.envelope.sequence, BreakReason::MacFailed));
                        break;
                    }
                    record.verified = true;
                }
            }
        }

        let earliest = match (structural, mac_break) {
            (Some(one), Some(other)) if other.0 < one.0 => Some(other),
            (Some(one), _) => Some(one),
            (None, other) => other,
        };
        let mut beyond = Vec::new();
        let mut broken_line = None;
        if let Some((sequence, reason)) = earliest {
            records.retain(|record| record.envelope.sequence < sequence);
            set_aside.retain(|record| record.envelope.sequence < sequence);
            for (index, line) in lines.iter().enumerate().skip(sequence as usize) {
                if index + 1 == lines.len() && !terminated {
                    continue;
                }
                if let Ok(envelope) = Envelope::parse(line) {
                    let verified = key.is_some_and(|key| envelope.mac_matches(key));
                    beyond.push(Record {
                        envelope,
                        hash: sha256_hex(line),
                        verified,
                    });
                }
            }
            broken_line = lines.get(sequence as usize).map(|line| sha256_hex(line));
            state = ChainState::Broken { sequence, reason };
        }
        for record in &mut set_aside {
            record.verified = false;
        }

        Verification {
            chain: self.id,
            state,
            records,
            set_aside,
            beyond,
            broken_line,
            head,
            epoch,
            next_sequence: lines.len() as u64,
            terminated,
        }
    }

    /// The sequence an answer to a break reaches back to, when this record is
    /// one: an `integrity` record of this chain at its own place, linked to
    /// the line before it, in the key generation in force there, that names a
    /// break at or after `floor` and before itself, no later than a structural
    /// break found on the way, and the line that is there now.
    ///
    /// Its MAC is checked with every other record of its generation once the
    /// whole chain is read, so an answer nobody with the key wrote breaks the
    /// chain where it stands.
    fn answers(
        &self,
        envelope: &Envelope,
        lines: &[&[u8]],
        index: usize,
        floor: u64,
        epoch: u64,
        structural: Option<u64>,
    ) -> Option<u64> {
        if envelope.record != RecordKind::Integrity
            || envelope.chain != self.id
            || envelope.sequence != index as u64
            || index == 0
            || envelope.epoch != epoch
            || envelope.previous != sha256_hex(lines[index - 1])
        {
            return None;
        }
        let IntegrityRecord::ChainBroken {
            chain,
            sequence,
            broken,
        } = IntegrityRecord::from_payload(&envelope.payload)?
        else {
            return None;
        };
        let reaches = chain == self.id
            && sequence >= floor
            && sequence < envelope.sequence
            && structural.is_none_or(|at| sequence <= at)
            && sha256_hex(lines[sequence as usize]) == broken;
        reaches.then_some(sequence)
    }
}

/// The lines of a chain file, without their newlines. A file ending mid-record
/// yields that partial line too: it is evidence, not something to drop.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    body.split(|byte| *byte == b'\n').collect()
}

#[cfg(feature = "daemon")]
pub use writer::{ChainWriter, Compacted};

#[cfg(feature = "daemon")]
mod writer {
    use std::fs::{File, OpenOptions};
    use std::io::Write as _;

    use serde_json::{Map, Value};

    use super::{Chain, ChainError, ChainState, Verification};
    use crate::envelope::{Envelope, RecordKind, Timestamp};
    use crate::keychain::{ChainKey, KeySource};

    /// The write side of a chain.
    ///
    /// Only the daemon may hold one: this type exists only in a build with the
    /// `daemon` feature, and the daemon crate is the only crate that turns it
    /// on (spec section 6.2). Every append is one line, written whole and
    /// flushed to the disk before the call returns.
    pub struct ChainWriter {
        chain: Chain,
        file: File,
        key: ChainKey,
        epoch: u64,
        next_sequence: u64,
        head: String,
    }

    impl ChainWriter {
        /// Verifies the chain, then opens it for appending.
        ///
        /// On [`ChainState::KeyMissing`] a fresh key is generated and a chain
        /// restart is appended, pointing at the old chain's last record, so
        /// the new chain witnesses the old head. The state verification found
        /// is returned with the writer: the caller decides what to show and
        /// whether automatic Quarantine stays frozen.
        pub fn open(
            chain: Chain,
            keys: &dyn KeySource,
        ) -> Result<(ChainWriter, ChainState), ChainError> {
            let verification = chain.verify(keys)?;
            ChainWriter::open_verified(chain, verification, keys)
        }

        /// Opens the chain for appending after a verification made before.
        ///
        /// Both chains share the one key, and opening the first after the key
        /// went missing generates the new one. The second, verified only then,
        /// would read its old records against the new key as tampered rather
        /// than as unverifiable. Verifying both before opening either keeps
        /// "protection state was reset" what it is on both chains (spec
        /// section 5.5). Nothing may be appended in between.
        pub fn open_verified(
            chain: Chain,
            verification: Verification,
            keys: &dyn KeySource,
        ) -> Result<(ChainWriter, ChainState), ChainError> {
            if let Some(parent) = chain.path().parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(chain.path())?;
            if !verification.terminated {
                // The last write did not finish. Close that line off rather
                // than run a new record into it; verification keeps reporting
                // the break, and nothing already written is touched.
                file.write_all(b"\n")?;
                file.sync_all()?;
            }

            let restarting = verification.state == ChainState::KeyMissing;
            let key = match keys.load()? {
                Some(key) => key,
                None => keys.renew()?,
            };
            let mut writer = ChainWriter {
                epoch: verification.epoch,
                next_sequence: verification.next_sequence,
                head: verification.head.clone(),
                chain,
                file,
                key,
            };
            if restarting {
                writer.restart(&verification)?;
            }
            Ok((writer, verification.state))
        }

        /// The hash a record appended now would link to.
        pub fn head(&self) -> &str {
            &self.head
        }

        /// The key generation records are written under.
        pub fn epoch(&self) -> u64 {
            self.epoch
        }

        /// The position the next record takes.
        pub fn next_sequence(&self) -> u64 {
            self.next_sequence
        }

        /// Appends one record and flushes it to the disk.
        pub fn append(&mut self, payload: Value) -> Result<Envelope, ChainError> {
            self.write(RecordKind::Entry, payload)
        }

        /// Appends one record of a kind beside the entries: a change of the
        /// Rule Pack in force. A chain restart is never written this way; only
        /// opening a chain whose key went missing, and compaction, write one.
        pub(crate) fn append_beside(
            &mut self,
            kind: RecordKind,
            payload: Value,
        ) -> Result<Envelope, ChainError> {
            if kind == RecordKind::ChainRestart {
                return Err(ChainError::Refused(
                    "a chain restart is written only when a chain starts again".to_string(),
                ));
            }
            self.write(kind, payload)
        }

        fn restart(&mut self, verification: &Verification) -> Result<Envelope, ChainError> {
            self.epoch = verification.epoch + 1;
            let payload = anchor(
                super::KEY_MISSING,
                &verification.head,
                verification.next_sequence,
                "the key was missing, so a new key and a new chain start here",
            );
            self.write(RecordKind::ChainRestart, payload)
        }

        fn write(&mut self, kind: RecordKind, payload: Value) -> Result<Envelope, ChainError> {
            let record = Envelope::seal(
                self.chain.id(),
                self.epoch,
                self.next_sequence,
                Timestamp::now(),
                &self.head,
                kind,
                payload,
                &self.key,
            );
            let mut line = record.line();
            line.push(b'\n');
            self.file.write_all(&line)?;
            self.file.sync_all()?;
            self.head = record.hash();
            self.next_sequence += 1;
            Ok(record)
        }
    }

    /// What one compaction replaced, so the Event Log can anchor the old chain
    /// and the new one to each other (spec section 4.6.6).
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Compacted {
        /// The hash of the last record of the chain that was replaced.
        pub old_head: String,
        /// How many records it held.
        pub old_records: u64,
        /// The hash of the last record of the chain that took its place.
        pub new_head: String,
        /// How many records that one holds.
        pub new_records: u64,
    }

    /// The payload of a record that anchors one chain to the one it follows.
    fn anchor(cause: &str, old_head: &str, old_records: u64, reason: &str) -> Value {
        let mut payload = Map::new();
        payload.insert("cause".to_string(), Value::from(cause));
        payload.insert("old_head".to_string(), Value::from(old_head));
        payload.insert("old_records".to_string(), Value::from(old_records));
        payload.insert("reason".to_string(), Value::from(reason));
        Value::Object(payload)
    }

    impl ChainWriter {
        /// Writes a fresh chain holding only what is handed over, anchored to
        /// the chain it replaces.
        ///
        /// The new file opens with a chain restart naming the old head and how
        /// many records it held, so the chain that was dropped is witnessed by
        /// the one that took its place. It refuses on anything but an intact
        /// chain: rewriting records no key in hand can verify would launder
        /// them into a chain that verifies, which is the one thing compaction
        /// may not do (ADR 0007).
        pub fn compact(
            chain: Chain,
            keys: &dyn KeySource,
            payloads: &[Value],
        ) -> Result<(ChainWriter, Compacted), ChainError> {
            // The Event Log is never compacted (spec section 5.5): every
            // record in it stays, the changes of the Rule Pack included.
            if chain.id() == crate::envelope::ChainId::Events {
                return Err(ChainError::Refused(
                    "the Event Log is never compacted".to_string(),
                ));
            }
            let verification = chain.verify(keys)?;
            if verification.state != ChainState::Intact {
                return Err(ChainError::Refused(
                    "a chain that does not verify is never rewritten".to_string(),
                ));
            }
            let key = match keys.load()? {
                Some(key) => key,
                None => {
                    return Err(ChainError::Refused(
                        "the key is missing, and a Baseline is never rebuilt without one"
                            .to_string(),
                    ));
                }
            };
            let path = chain.path().to_path_buf();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let beside = path.with_extension("compacting");
            let file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&beside)?;
            let mut writer = ChainWriter {
                chain,
                file,
                key,
                epoch: 0,
                next_sequence: 0,
                head: crate::envelope::GENESIS.to_string(),
            };
            writer.write(
                RecordKind::ChainRestart,
                anchor(
                    super::COMPACTION,
                    &verification.head,
                    verification.next_sequence,
                    "the Baseline was compacted, and this chain holds what it kept",
                ),
            )?;
            for payload in payloads {
                writer.append(payload.clone())?;
            }
            writer.file.sync_all()?;
            std::fs::rename(&beside, &path)?;
            // The handle above points at the file that was renamed into place,
            // which is the one to go on appending to.
            let compacted = Compacted {
                old_head: verification.head,
                old_records: verification.next_sequence,
                new_head: writer.head.clone(),
                new_records: writer.next_sequence,
            };
            Ok((writer, compacted))
        }
    }

    impl std::fmt::Debug for ChainWriter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ChainWriter")
                .field("chain", &self.chain)
                .field("epoch", &self.epoch)
                .field("next_sequence", &self.next_sequence)
                .finish_non_exhaustive()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Timestamp;
    use crate::keychain::{ChainKey, MemoryKeySource};

    use serde_json::json;
    use tempfile::TempDir;

    fn chain_in(directory: &TempDir) -> Chain {
        Chain::at(directory.path().join("events.jsonl"), ChainId::Events)
    }

    fn appended(chain: &Chain, keys: &MemoryKeySource, payloads: &[&str]) {
        let (mut writer, _) = ChainWriter::open(chain.clone(), keys).expect("an open chain");
        for payload in payloads {
            writer
                .append(json!({ "action": payload }))
                .expect("an appended record");
        }
    }

    #[test]
    fn appending_and_verifying_round_trips() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust", "restore"]);

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert_eq!(verification.records.len(), 3);
        assert_eq!(verification.next_sequence, 3);
        assert_eq!(verification.unverified(), 0);
        assert!(verification.records.iter().all(|record| record.verified));
        assert_eq!(verification.records[0].envelope.previous, GENESIS);
        assert_eq!(
            verification.records[1].envelope.previous,
            verification.records[0].hash
        );
        assert_eq!(verification.head, verification.records[2].hash);
    }

    #[test]
    fn an_absent_chain_is_intact_and_empty() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let verification = chain
            .verify(&MemoryKeySource::empty())
            .expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert!(verification.records.is_empty());
        assert_eq!(verification.head, GENESIS);
    }

    #[test]
    fn editing_one_byte_of_a_record_breaks_the_chain() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust", "restore"]);

        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let edited = text.replacen(r#""action":"trust""#, r#""action":"untrust""#, 1);
        assert_ne!(edited, text);
        std::fs::write(chain.path(), &edited).expect("a writable chain");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(
            verification.state,
            ChainState::Broken {
                sequence: 1,
                reason: BreakReason::MacFailed,
            }
        );
        assert_eq!(verification.state.headline(), "records tampered");
        assert!(verification.state.freezes_automatic_quarantine());
        assert_eq!(verification.records.len(), 1);
    }

    /// The acceptance criterion in full: not one chosen byte but every byte of
    /// the file, one at a time. A record carries a MAC over its own fields and
    /// the hash of the record before it, and it is written in one form only,
    /// so there is nowhere left for a change to hide.
    #[test]
    fn changing_any_one_byte_of_the_file_is_detected() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust", "restore"]);
        let written = std::fs::read(chain.path()).expect("a readable chain");

        for position in 0..written.len() {
            let mut edited = written.clone();
            edited[position] ^= 0x01;
            std::fs::write(chain.path(), &edited).expect("a writable chain");
            let verification = chain.verify(&keys).expect("a readable chain");
            assert!(
                matches!(verification.state, ChainState::Broken { .. }),
                "byte {position} changed and the chain still verified"
            );
            assert_eq!(verification.state.headline(), "records tampered");
        }

        std::fs::write(chain.path(), &written).expect("a writable chain");
        assert_eq!(
            chain.verify(&keys).expect("a readable chain").state,
            ChainState::Intact
        );
    }

    #[test]
    fn nothing_the_chain_writes_to_disk_holds_the_key() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let secret: [u8; 32] =
            std::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(11));
        let keys = MemoryKeySource::holding(ChainKey::from_bytes(secret));
        appended(&chain, &keys, &["quarantine", "trust"]);

        let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        for file in std::fs::read_dir(directory.path()).expect("a readable directory") {
            let path = file.expect("an entry").path();
            let bytes = std::fs::read(&path).expect("a readable file");
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "{} holds the key",
                path.display()
            );
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(&hex), "{} holds the key", path.display());
        }
    }

    #[test]
    fn editing_a_record_without_the_key_breaks_the_link_it_carries() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust", "restore"]);

        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let edited = text.replacen(r#""action":"trust""#, r#""action":"untrust""#, 1);
        std::fs::write(chain.path(), &edited).expect("a writable chain");
        keys.forget().expect("the key goes away");

        // Without the key no MAC can be checked, but the links still can be,
        // so this is tampering rather than a reset protection state.
        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(
            verification.state,
            ChainState::Broken {
                sequence: 2,
                reason: BreakReason::LinkBroken,
            }
        );
    }

    #[test]
    fn editing_the_last_record_breaks_its_mac() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust"]);

        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let edited = text.replacen(r#""action":"trust""#, r#""action":"untrus""#, 1);
        std::fs::write(chain.path(), &edited).expect("a writable chain");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(
            verification.state,
            ChainState::Broken {
                sequence: 1,
                reason: BreakReason::MacFailed,
            }
        );
        assert_eq!(verification.records.len(), 1);
    }

    #[test]
    fn a_reformatted_record_is_broken_even_though_it_says_the_same() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine"]);

        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let spaced = text.replacen(r#"{"chain""#, r#"{ "chain""#, 1);
        std::fs::write(chain.path(), &spaced).expect("a writable chain");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert!(matches!(
            verification.state,
            ChainState::Broken {
                sequence: 0,
                reason: BreakReason::Malformed(_),
            }
        ));
    }

    #[test]
    fn a_dropped_record_breaks_the_chain() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust", "restore"]);

        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1);
        std::fs::write(chain.path(), lines.join("\n") + "\n").expect("a writable chain");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert!(matches!(
            verification.state,
            ChainState::Broken {
                sequence: 1,
                reason: BreakReason::OutOfOrder,
            }
        ));
    }

    #[test]
    fn a_truncated_last_line_is_a_broken_chain_and_is_never_dropped() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust"]);

        let mut bytes = std::fs::read(chain.path()).expect("a readable chain");
        bytes.truncate(bytes.len() - 20);
        std::fs::write(chain.path(), &bytes).expect("a writable chain");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(
            verification.state,
            ChainState::Broken {
                sequence: 1,
                reason: BreakReason::Truncated,
            }
        );
        assert!(!verification.terminated);
        assert_eq!(verification.records.len(), 1);

        // The partial line stays in the file; the next record starts a line of
        // its own rather than running into it.
        let (mut writer, state) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        assert_eq!(state.headline(), "records tampered");
        writer
            .append(json!({"action": "acknowledge"}))
            .expect("an appended record");
        let after = std::fs::read(chain.path()).expect("a readable chain");
        assert!(after.starts_with(&bytes));
        assert_eq!(after.iter().filter(|byte| **byte == b'\n').count(), 3);
    }

    #[test]
    fn removing_the_key_yields_key_missing_with_the_chain_intact() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust"]);
        keys.forget().expect("the key goes away");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::KeyMissing);
        assert_eq!(verification.state.headline(), "protection state was reset");
        assert!(!verification.state.freezes_automatic_quarantine());
        assert_eq!(verification.records.len(), 2);
        assert_eq!(verification.unverified(), 2);
    }

    #[test]
    fn a_new_chain_starts_pointing_at_the_old_head() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust"]);
        let old = chain.verify(&keys).expect("a readable chain");
        let old_head = old.head.clone();
        keys.forget().expect("the key goes away");

        let (mut writer, state) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        assert_eq!(state, ChainState::KeyMissing);
        writer
            .append(json!({"action": "acknowledge"}))
            .expect("an appended record");

        let after = chain.verify(&keys).expect("a readable chain");
        assert_eq!(after.state, ChainState::Intact);
        assert_eq!(after.records.len(), 4);
        assert!(after.was_restarted());

        let restart = &after.records[2];
        assert_eq!(restart.envelope.record, RecordKind::ChainRestart);
        assert_eq!(restart.envelope.previous, old_head);
        assert_eq!(restart.envelope.payload["old_head"], json!(old_head));
        assert_eq!(restart.envelope.epoch, 1);

        // The records of the old chain stay readable and say they cannot be
        // verified; the records of the new chain verify.
        assert_eq!(after.unverified(), 2);
        assert!(!after.records[0].verified);
        assert!(!after.records[1].verified);
        assert!(after.records[2].verified);
        assert!(after.records[3].verified);
    }

    #[test]
    fn a_chain_sealed_with_another_key_is_broken_not_key_missing() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine"]);

        let stranger = MemoryKeySource::holding(ChainKey::from_bytes([4u8; 32]));
        let verification = chain.verify(&stranger).expect("a readable chain");
        assert_eq!(
            verification.state,
            ChainState::Broken {
                sequence: 0,
                reason: BreakReason::MacFailed,
            }
        );
    }

    #[test]
    fn a_record_of_another_chain_does_not_belong_in_this_one() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        let key = keys.renew().expect("a fresh key");
        let foreign = Envelope::seal(
            ChainId::Baseline,
            0,
            0,
            Timestamp::from_unix_ms(0),
            GENESIS,
            RecordKind::Entry,
            json!({"item_id": "claude-code/user/skill/demo"}),
            &key,
        );
        let mut line = foreign.line();
        line.push(b'\n');
        std::fs::write(chain.path(), &line).expect("a writable chain");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert!(matches!(
            verification.state,
            ChainState::Broken {
                sequence: 0,
                reason: BreakReason::OutOfOrder,
            }
        ));
    }

    #[test]
    fn both_chains_use_the_one_writer_and_the_one_verification() {
        let directory = TempDir::new().expect("a temporary directory");
        let keys = MemoryKeySource::empty();
        for id in [ChainId::Events, ChainId::Baseline] {
            let chain = Chain::at(directory.path().join(format!("{id}.jsonl")), id);
            let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
            writer
                .append(json!({"one": 1}))
                .expect("an appended record");
            let verification = chain.verify(&keys).expect("a readable chain");
            assert_eq!(verification.state, ChainState::Intact);
            assert_eq!(verification.chain, id);
        }
    }

    /// The write side is a boundary, not a note in a comment: it exists only
    /// in a build with the `daemon` feature, and the daemon crate is the only
    /// crate that asks for it. The application and the CLI link a core in
    /// which [`ChainWriter`] does not exist at all.
    #[test]
    fn the_daemon_is_the_only_crate_that_can_write_a_chain() {
        let core = include_str!("../Cargo.toml");
        assert!(
            core.contains("daemon = [\"dep:security-framework\"]"),
            "the core must gate the write side and the Keychain behind one feature"
        );

        let daemon = include_str!("../../daemon/Cargo.toml");
        assert!(
            daemon.contains("features = [\"daemon\"]"),
            "the daemon crate must turn the feature on"
        );

        for (name, manifest) in [
            ("cli", include_str!("../../cli/Cargo.toml")),
            (
                "claude-code adapter",
                include_str!("../../adapters/claude-code/Cargo.toml"),
            ),
            (
                "codex adapter",
                include_str!("../../adapters/codex/Cargo.toml"),
            ),
            (
                "workspace adapter",
                include_str!("../../adapters/workspace/Cargo.toml"),
            ),
        ] {
            assert!(
                !manifest.contains("\"daemon\""),
                "the {name} crate must not turn the daemon feature on"
            );
        }
    }

    #[test]
    fn a_reopened_writer_continues_the_chain() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine"]);
        appended(&chain, &keys, &["trust"]);

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert_eq!(verification.records.len(), 2);
        assert_eq!(verification.records[1].envelope.sequence, 1);
    }

    #[test]
    fn a_record_beside_the_entries_links_and_verifies_like_one() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        writer
            .append(json!({ "action": "quarantine" }))
            .expect("an appended record");
        writer
            .append_beside(RecordKind::RulePack, json!({ "pack_version": 2 }))
            .expect("an appended record");
        writer
            .append(json!({ "action": "trust" }))
            .expect("an appended record");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert_eq!(verification.records.len(), 3);
        assert_eq!(
            verification.records[1].envelope.record,
            RecordKind::RulePack
        );
        assert!(verification.records.iter().all(|record| record.verified));
        assert!(!verification.was_restarted());
    }

    #[test]
    fn a_chain_restart_is_never_appended_beside_the_entries() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        assert!(matches!(
            writer.append_beside(RecordKind::ChainRestart, json!({})),
            Err(ChainError::Refused(_))
        ));
        assert!(chain.verify(&keys).expect("a chain").records.is_empty());
    }

    /// Spec section 5.5: the Event Log is never compacted, so every record in
    /// it, a change of the Rule Pack included, stays where it was written.
    #[test]
    fn the_event_log_is_never_compacted_and_keeps_every_record() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        {
            let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
            writer
                .append_beside(RecordKind::RulePack, json!({ "pack_version": 2 }))
                .expect("an appended record");
        }
        let before = std::fs::read(chain.path()).expect("a readable chain");

        let refused = ChainWriter::compact(chain.clone(), &keys, &[]);
        assert!(matches!(refused, Err(ChainError::Refused(_))));
        assert_eq!(std::fs::read(chain.path()).expect("a chain"), before);
    }

    /// Appends four records and edits the second, which breaks the chain at
    /// sequence 1 by its MAC and at sequence 2 by its link.
    fn an_edited_chain(directory: &TempDir, keys: &MemoryKeySource) -> Chain {
        let chain = chain_in(directory);
        appended(&chain, keys, &["quarantine", "trust", "restore", "untrust"]);
        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let edited = text.replacen(r#""action":"trust""#, r#""action":"trusd""#, 1);
        assert_ne!(edited, text);
        std::fs::write(chain.path(), &edited).expect("a writable chain");
        chain
    }

    fn answer(verification: &Verification) -> serde_json::Value {
        let ChainState::Broken { sequence, .. } = verification.state else {
            panic!("a broken chain: {:?}", verification.state);
        };
        IntegrityRecord::ChainBroken {
            chain: verification.chain,
            sequence,
            broken: verification.broken_line.clone().expect("the broken line"),
        }
        .to_payload()
    }

    fn sequences(records: &[Record]) -> Vec<u64> {
        records
            .iter()
            .map(|record| record.envelope.sequence)
            .collect()
    }

    #[test]
    fn a_broken_chain_lists_every_record_from_the_break_with_its_own_mac() {
        let directory = TempDir::new().expect("a temporary directory");
        let keys = MemoryKeySource::empty();
        let chain = an_edited_chain(&directory, &keys);

        let verification = chain.verify(&keys).expect("a readable chain");
        assert!(matches!(
            verification.state,
            ChainState::Broken { sequence: 1, .. }
        ));
        assert_eq!(sequences(&verification.records), vec![0]);
        assert_eq!(sequences(&verification.beyond), vec![1, 2, 3]);
        let flags: Vec<bool> = verification.beyond.iter().map(|r| r.verified).collect();
        assert_eq!(flags, vec![false, true, true], "only the edited record");
        assert!(verification.set_aside.is_empty());
        let lines = std::fs::read(chain.path()).expect("a readable chain");
        let second = lines.split(|byte| *byte == b'\n').nth(1).expect("a line");
        assert_eq!(verification.broken_line, Some(sha256_hex(second)));
    }

    /// "Scan again, trusting nothing": the answer picks the chain up again, so
    /// what is written after it counts, and what was written between the break
    /// and the answer is set aside, readable and never verified.
    #[test]
    fn an_answered_break_picks_the_chain_up_again_and_sets_the_records_since_aside() {
        let directory = TempDir::new().expect("a temporary directory");
        let keys = MemoryKeySource::empty();
        let chain = an_edited_chain(&directory, &keys);
        let broken = chain.verify(&keys).expect("a readable chain");

        let (mut writer, state) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        assert!(state.freezes_automatic_quarantine());
        writer
            .append_beside(RecordKind::Integrity, answer(&broken))
            .expect("the answer");
        writer
            .append(json!({ "action": "quarantine" }))
            .expect("a record after the answer");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert!(!verification.state.freezes_automatic_quarantine());
        assert_eq!(sequences(&verification.records), vec![0, 4, 5]);
        assert!(verification.records.iter().all(|record| record.verified));
        assert_eq!(sequences(&verification.set_aside), vec![1, 2, 3]);
        assert!(verification.set_aside.iter().all(|record| !record.verified));
        assert!(verification.beyond.is_empty());
        assert_eq!(verification.broken_line, None);
    }

    #[test]
    fn an_answer_nobody_with_the_key_wrote_leaves_the_chain_broken() {
        let directory = TempDir::new().expect("a temporary directory");
        let keys = MemoryKeySource::empty();
        let chain = an_edited_chain(&directory, &keys);
        let broken = chain.verify(&keys).expect("a readable chain");

        let forger = MemoryKeySource::empty();
        let (mut writer, _) = ChainWriter::open(chain.clone(), &forger).expect("an open chain");
        writer
            .append_beside(RecordKind::Integrity, answer(&broken))
            .expect("a forged answer");

        let verification = chain.verify(&keys).expect("a readable chain");
        assert!(verification.state.freezes_automatic_quarantine());
        assert_eq!(sequences(&verification.records), vec![0]);

        // The answer the key in hand writes afterwards still picks it up.
        let again = chain.verify(&keys).expect("a readable chain");
        let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        writer
            .append_beside(RecordKind::Integrity, answer(&again))
            .expect("the answer");
        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert_eq!(sequences(&verification.records), vec![0, 5]);
    }

    #[test]
    fn an_answer_to_another_line_than_the_one_there_now_is_no_answer() {
        let directory = TempDir::new().expect("a temporary directory");
        let keys = MemoryKeySource::empty();
        let chain = an_edited_chain(&directory, &keys);
        let ChainState::Broken { sequence, .. } = chain.verify(&keys).expect("a chain").state
        else {
            panic!("a broken chain");
        };

        let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        let stale = IntegrityRecord::ChainBroken {
            chain: ChainId::Events,
            sequence,
            broken: GENESIS.to_string(),
        };
        writer
            .append_beside(RecordKind::Integrity, stale.to_payload())
            .expect("an answer naming another line");
        let verification = chain.verify(&keys).expect("a readable chain");
        assert!(matches!(
            verification.state,
            ChainState::Broken { sequence: 1, .. }
        ));
    }

    /// A break of the last record is found by its MAC alone; the answer that
    /// follows it links to it like any record and still sets it aside.
    #[test]
    fn an_answer_to_an_edited_last_record_sets_it_aside() {
        let directory = TempDir::new().expect("a temporary directory");
        let chain = chain_in(&directory);
        let keys = MemoryKeySource::empty();
        appended(&chain, &keys, &["quarantine", "trust"]);
        let text = std::fs::read_to_string(chain.path()).expect("a readable chain");
        let edited = text.replacen(r#""action":"trust""#, r#""action":"trusd""#, 1);
        std::fs::write(chain.path(), &edited).expect("a writable chain");
        let broken = chain.verify(&keys).expect("a readable chain");

        let (mut writer, _) = ChainWriter::open(chain.clone(), &keys).expect("an open chain");
        writer
            .append_beside(RecordKind::Integrity, answer(&broken))
            .expect("the answer");
        let verification = chain.verify(&keys).expect("a readable chain");
        assert_eq!(verification.state, ChainState::Intact);
        assert_eq!(sequences(&verification.records), vec![0, 2]);
        assert_eq!(sequences(&verification.set_aside), vec![1]);
    }
}
