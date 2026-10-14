//! Answering the two integrity states through the daemon (spec sections 5.5
//! and 8.6).
//!
//! The daemon finds both states when it opens the chains: a key that went
//! missing restarts both chains under a new key, and a chain that broke while
//! the key was in hand freezes automatic Quarantine (ADR 0003). Here are the
//! three requests behind the four buttons of spec section 8.6:
//!
//! - **records** ("Look at the records", "Show what changed"): one page of the
//!   records of either chain, each with whether the key in hand verifies it
//!   and whether the derived views read it, and the state of the chain, which
//!   for a broken chain names the sequence where it stops being trustworthy.
//!   Paths and ids only: the sensitive fields are hashes in the store and are
//!   left out here, with every free-text detail.
//! - **acknowledge-key-missing** ("Start a fresh record"): the restarted
//!   chains are taken as they are and the "protection state was reset" rung
//!   clears. Until then it stays, across restarts of the daemon, ranked below
//!   every Threat rung.
//! - **acknowledge-chain-broken** ("Scan again, trusting nothing"): every
//!   broken chain gets the answer after its break, which picks it up again;
//!   the records between the break and the answer are set aside, so Trust
//!   records and accepted Baseline hashes written after the break are ignored
//!   and a Full Scan judges everything trusted since again. Automatic
//!   Quarantine is unfrozen.
//!
//! Each answer is an `integrity` record on the Event Log, so it is itself on
//! record. Both write, so both wait for a running Scan the way every action
//! does; reading the records writes nothing and waits for nothing.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;

use agentsweep_core::baseline::{Baseline, BaselineWriter};
use agentsweep_core::chain::{ChainState, KEY_MISSING, Record, Verification};
use agentsweep_core::envelope::{ChainId, RecordKind};
use agentsweep_core::eventlog::{EventLog, EventLogWriter};
use agentsweep_core::integrity::{CHAIN_BROKEN, IntegrityRecord, ResetUnanswered};
use agentsweep_core::state::Trigger;
use agentsweep_ipc::integrity::{ChainRecords, IntegrityAnswer, RECORDS_PAGE, RecordLine};
use agentsweep_ipc::protocol::RequestError;

use crate::service::Daemon;

/// The state Health shows for one chain: what verification found, or key
/// missing while a restart of that chain is unanswered.
pub(crate) fn shown(found: &ChainState, unanswered: bool) -> ChainState {
    match (found, unanswered) {
        (ChainState::Intact, true) => ChainState::KeyMissing,
        _ => found.clone(),
    }
}

/// A chain the request could not read or write.
fn failed(error: impl std::fmt::Display) -> RequestError {
    RequestError::new("failed", format!("the records: {error}"))
}

/// One record as a client is shown it.
fn line_of(record: &Record, counted: bool) -> RecordLine {
    let payload = &record.envelope.payload;
    let text = |field: &str| {
        payload
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let what = match record.envelope.record {
        RecordKind::ChainRestart => payload
            .get("cause")
            .and_then(Value::as_str)
            .unwrap_or(KEY_MISSING)
            .to_string(),
        _ => ["action", "about", "acknowledgement", "change"]
            .into_iter()
            .map(text)
            .find(|what| !what.is_empty())
            .unwrap_or_default(),
    };
    let mut paths: Vec<String> = payload
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|step| step.get("path").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    paths.extend(
        [text("path"), text("root")]
            .into_iter()
            .filter(|path| !path.is_empty()),
    );
    let content_hash = match text("content_hash") {
        hash if hash.is_empty() => text("accepted_hash"),
        hash => hash,
    };
    RecordLine {
        sequence: record.envelope.sequence,
        record: record.envelope.record.as_str().to_string(),
        recorded_at: Some(record.envelope.recorded_at),
        verified: record.verified,
        counted,
        what,
        item_id: text("item_id"),
        finding_id: text("finding_id"),
        receipt_id: text("receipt_id"),
        rule_id: payload
            .get("rule_id")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        content_hash,
        paths,
    }
}

/// The answer a broken chain gets: its break and the line found there.
fn answer_for(verification: &Verification) -> Option<IntegrityRecord> {
    match verification.state {
        ChainState::Broken { sequence, .. } => Some(IntegrityRecord::ChainBroken {
            chain: verification.chain,
            sequence,
            broken: verification.broken_line.clone()?,
        }),
        _ => None,
    }
}

impl Daemon {
    /// Whether a restart of each chain is still unanswered.
    fn unanswered(&self) -> ResetUnanswered {
        *self.reset.lock().expect("the reset is not poisoned")
    }

    /// One page of the records of one chain.
    pub(crate) fn records(&self, chain: ChainId, from: u64) -> Result<Value, RequestError> {
        let verification = match chain {
            ChainId::Events => EventLog::in_data_directory(&self.directory)
                .chain()
                .verify(&*self.keys),
            ChainId::Baseline => Baseline::in_data_directory(&self.directory)
                .chain()
                .verify(&*self.keys),
        }
        .map_err(failed)?;
        let unanswered = match chain {
            ChainId::Events => self.unanswered().events,
            ChainId::Baseline => self.unanswered().baseline,
        };

        let mut lines: BTreeMap<u64, RecordLine> = BTreeMap::new();
        for record in &verification.records {
            lines.insert(record.envelope.sequence, line_of(record, true));
        }
        for record in verification.set_aside.iter().chain(&verification.beyond) {
            lines.insert(record.envelope.sequence, line_of(record, false));
        }
        // A line that does not read as a record is still a line of the file.
        for sequence in 0..verification.next_sequence {
            lines.entry(sequence).or_insert_with(|| RecordLine {
                sequence,
                record: "unreadable".to_string(),
                ..RecordLine::default()
            });
        }

        let mut page: Vec<RecordLine> = lines
            .into_values()
            .filter(|line| line.sequence >= from)
            .take(RECORDS_PAGE + 1)
            .collect();
        let next = match page.len() > RECORDS_PAGE {
            true => page.pop().map(|line| line.sequence),
            false => None,
        };
        Ok(ChainRecords {
            chain,
            state: shown(&verification.state, unanswered),
            records: page,
            next,
        }
        .to_value())
    }

    /// "Start a fresh record".
    pub(crate) fn acknowledge_key_missing(self: &Arc<Daemon>) -> Result<Value, RequestError> {
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        let unanswered = self.unanswered();
        if !unanswered.any() {
            return Err(RequestError::new(
                "not-allowed",
                "the protection state was not reset, so there is nothing to answer",
            ));
        }
        let (mut log, _) =
            EventLogWriter::open(&EventLog::in_data_directory(&self.directory), &*self.keys)
                .map_err(failed)?;
        log.record_integrity(&IntegrityRecord::KeyMissing)
            .map_err(failed)?;
        *self.reset.lock().expect("the reset is not poisoned") = ResetUnanswered::default();
        {
            let mut health = self.health.lock().expect("the health is not poisoned");
            let health = &mut *health;
            for state in [&mut health.events, &mut health.baseline] {
                if *state == ChainState::KeyMissing {
                    *state = ChainState::Intact;
                }
            }
        }
        say!("the reset of the protection state was answered: a fresh record");
        self.tell_health();

        let chains = [
            (unanswered.events, ChainId::Events),
            (unanswered.baseline, ChainId::Baseline),
        ]
        .into_iter()
        .filter_map(|(restarted, chain)| restarted.then_some(chain))
        .collect();
        Ok(IntegrityAnswer {
            acknowledgement: KEY_MISSING.to_string(),
            chains,
            scan_started: false,
        }
        .to_value())
    }

    /// "Scan again, trusting nothing".
    pub(crate) fn acknowledge_chain_broken(self: &Arc<Daemon>) -> Result<Value, RequestError> {
        let writing = self.writing.lock().expect("the write lock is not poisoned");
        let log = EventLog::in_data_directory(&self.directory);
        let baseline = Baseline::in_data_directory(&self.directory);
        let events_found = log.chain().verify(&*self.keys).map_err(failed)?;
        let baseline_found = baseline.chain().verify(&*self.keys).map_err(failed)?;
        let events_answer = answer_for(&events_found);
        let baseline_answer = answer_for(&baseline_found);
        if events_answer.is_none() && baseline_answer.is_none() {
            return Err(RequestError::new(
                "not-allowed",
                "no record was changed by something else, so there is nothing to answer",
            ));
        }

        // The Baseline's answer goes into the Baseline, where verification
        // picks the chain up again from it. Every answer goes onto the Event
        // Log, the Event Log's own first: that one picks the Event Log up
        // again, so the one after it is read rather than set aside.
        let mut chains = Vec::new();
        if let Some(answer) = &baseline_answer {
            let (mut writer, _) =
                BaselineWriter::open_verified(&baseline, baseline_found, &*self.keys)
                    .map_err(failed)?;
            writer.record_integrity(answer).map_err(failed)?;
        }
        let (mut writer, _) =
            EventLogWriter::open_verified(&log, events_found, &*self.keys).map_err(failed)?;
        for answer in [&events_answer, &baseline_answer].into_iter().flatten() {
            writer.record_integrity(answer).map_err(failed)?;
            if let IntegrityRecord::ChainBroken {
                chain, sequence, ..
            } = answer
            {
                say!("the break of the {chain} chain at {sequence} was answered");
                chains.push(*chain);
            }
        }

        let unanswered = self.unanswered();
        let events_now = log.chain().verify(&*self.keys).map_err(failed)?.state;
        let baseline_now = baseline.chain().verify(&*self.keys).map_err(failed)?.state;
        {
            let mut health = self.health.lock().expect("the health is not poisoned");
            health.events = shown(&events_now, unanswered.events);
            health.baseline = shown(&baseline_now, unanswered.baseline);
        }
        // Nothing the Tiers decided before is taken on trust, and the Scan
        // waits for this write to finish before it starts.
        self.forget_evaluations();
        drop(writing);
        let scan_started = self.scan(Trigger::ScanNow);
        self.tell_health();

        Ok(IntegrityAnswer {
            acknowledgement: CHAIN_BROKEN.to_string(),
            chains,
            scan_started,
        }
        .to_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restart_nobody_answered_shows_as_key_missing_and_a_break_as_itself() {
        assert_eq!(shown(&ChainState::Intact, false), ChainState::Intact);
        assert_eq!(shown(&ChainState::Intact, true), ChainState::KeyMissing);
        let broken = ChainState::Broken {
            sequence: 2,
            reason: agentsweep_core::chain::BreakReason::MacFailed,
        };
        assert_eq!(shown(&broken, true), broken);
    }
}
