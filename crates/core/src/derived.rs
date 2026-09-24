//! The views derived from the Event Log.
//!
//! What is in the quarantine store and what carries Trust are never stored
//! separately (ADR 0003). They are rebuilt from `events.jsonl` every time the
//! daemon starts and then checked against the store, so a manifest that
//! disagrees with the audit log cannot exist: there is only the log.
//!
//! A view built from a log whose protection state was reset carries records
//! from before the reset as well. They are flagged unverified rather than
//! dropped, because dropping them would silently un-quarantine and untrust
//! everything a migrated Mac had decided.

use std::collections::BTreeMap;
use std::io;

use crate::envelope::Timestamp;
use crate::eventlog::{Action, Actor, Outcome, Primitive, ReceiptStep, RecordedEvent};
use crate::finding::Tier;
use crate::item::{ItemId, Kind};
use crate::paths::DataDirectory;

/// One Item the quarantine store holds, as the Event Log describes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineEntry {
    /// The Receipt this Quarantine wrote, which names the store directory.
    pub receipt_id: String,
    /// The Item that was taken out.
    pub item_id: ItemId,
    /// Its Surface kind.
    pub kind: Option<Kind>,
    /// The content hash it was taken out on.
    pub content_hash: String,
    /// When it was taken out.
    pub quarantined_at: Timestamp,
    /// Whether AgentSweep or the user did it.
    pub actor: Actor,
    /// The Tier behind the Finding.
    pub tier: Option<Tier>,
    /// The Rule behind the Finding, zero where no Rule applies.
    pub rule_id: i64,
    /// The Finding behind it.
    pub finding_id: String,
    /// The steps, in the order they were taken. Restore replays them in
    /// reverse.
    pub steps: Vec<ReceiptStep>,
    /// How the Quarantine came out.
    pub result: Outcome,
    /// How often the entry came back and was removed again. Three within an
    /// hour raises the "keeps coming back" Finding.
    pub re_enforced: u32,
    /// False once Re-enable reversed the native disable step of a plugin.
    pub natively_disabled: bool,
    /// True when a Restore was tried and did not finish.
    pub restore_unfinished: bool,
    /// False when the record it was built from belongs to a key generation no
    /// key in hand can verify.
    pub verified: bool,
}

impl QuarantineEntry {
    /// True when a payload sits in the store for this Receipt: a file or a
    /// tree was moved out.
    pub fn has_payload(&self) -> bool {
        self.steps
            .iter()
            .any(|step| step.primitive == Primitive::MoveOut && step.outcome == Outcome::Ok)
    }
}

/// What the quarantine store holds, rebuilt from the Event Log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QuarantineManifest {
    entries: BTreeMap<String, QuarantineEntry>,
}

impl QuarantineManifest {
    /// Folds the log into the manifest, in the order the events were written.
    pub fn rebuild(events: &[RecordedEvent]) -> QuarantineManifest {
        let mut manifest = QuarantineManifest::default();
        for recorded in events {
            let event = &recorded.event;
            if event.receipt_id.is_empty() {
                continue;
            }
            match event.action {
                Action::Quarantine => {
                    let Some(item_id) = event.item_id.clone() else {
                        continue;
                    };
                    manifest.entries.insert(
                        event.receipt_id.clone(),
                        QuarantineEntry {
                            receipt_id: event.receipt_id.clone(),
                            item_id,
                            kind: event.kind,
                            content_hash: event.content_hash.clone(),
                            quarantined_at: recorded.recorded_at,
                            actor: event.actor,
                            tier: event.tier,
                            rule_id: event.rule_id,
                            finding_id: event.finding_id.clone(),
                            steps: event.steps.clone(),
                            result: event.result,
                            re_enforced: 0,
                            natively_disabled: event
                                .steps
                                .iter()
                                .any(|step| step.primitive == Primitive::NativeDisable),
                            restore_unfinished: false,
                            verified: recorded.verified,
                        },
                    );
                }
                Action::Restore if event.result == Outcome::Ok => {
                    manifest.entries.remove(&event.receipt_id);
                }
                Action::Restore => {
                    if let Some(entry) = manifest.entries.get_mut(&event.receipt_id) {
                        entry.restore_unfinished = true;
                    }
                }
                Action::Purge => {
                    manifest.entries.remove(&event.receipt_id);
                }
                Action::ReEnable => {
                    if let Some(entry) = manifest.entries.get_mut(&event.receipt_id) {
                        entry.natively_disabled = false;
                    }
                }
                Action::ReEnforce => {
                    if let Some(entry) = manifest.entries.get_mut(&event.receipt_id) {
                        entry.re_enforced += 1;
                    }
                }
                _ => {}
            }
        }
        manifest
    }

    /// Every Item in the store, by Receipt id.
    pub fn entries(&self) -> impl Iterator<Item = &QuarantineEntry> {
        self.entries.values()
    }

    /// How many Items the store holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// One Item by its Receipt id.
    pub fn for_receipt(&self, receipt_id: &str) -> Option<&QuarantineEntry> {
        self.entries.get(receipt_id)
    }

    /// True when this Item is in the store.
    pub fn holds(&self, item_id: &ItemId) -> bool {
        self.entries.values().any(|entry| &entry.item_id == item_id)
    }

    /// Checks the manifest against the store on disk, which the daemon does
    /// every time it starts. Nothing is changed; the answer is what disagrees.
    pub fn reconcile(&self, directory: &DataDirectory) -> io::Result<Reconciliation> {
        let store = directory.quarantine();
        let mut reconciliation = Reconciliation::default();
        for entry in self.entries() {
            if entry.has_payload() && !directory.quarantine_payload(&entry.receipt_id).exists() {
                reconciliation
                    .missing_payloads
                    .push(entry.receipt_id.clone());
            }
        }
        match std::fs::read_dir(&store) {
            Ok(listing) => {
                for found in listing {
                    let found = found?;
                    if !found.file_type()?.is_dir() {
                        continue;
                    }
                    let name = found.file_name().to_string_lossy().to_string();
                    if !self.entries.contains_key(&name) {
                        reconciliation.unknown_payloads.push(name);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        reconciliation.missing_payloads.sort();
        reconciliation.unknown_payloads.sort();
        Ok(reconciliation)
    }
}

/// Where the manifest and the store on disk disagree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reconciliation {
    /// Receipt ids the log says have a payload that the store does not hold.
    pub missing_payloads: Vec<String>,
    /// Directories in the store no event accounts for.
    pub unknown_payloads: Vec<String>,
}

impl Reconciliation {
    /// True when the store holds exactly what the log says it holds.
    pub fn agrees(&self) -> bool {
        self.missing_payloads.is_empty() && self.unknown_payloads.is_empty()
    }
}

/// One content hash of one kind the user called safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRecord {
    /// The kind the Trust was granted for.
    pub kind: Kind,
    /// The content hash it is bound to. A changed file is new content.
    pub content_hash: String,
    /// The Item it was granted on, for display only: Trust is
    /// location-independent.
    pub granted_on: Option<ItemId>,
    /// When it was granted.
    pub granted_at: Timestamp,
    /// Whether AgentSweep's own Restore or the user granted it.
    pub actor: Actor,
    /// False when the record it was built from belongs to a key generation no
    /// key in hand can verify.
    pub verified: bool,
}

/// Which content hashes carry Trust, rebuilt from the Event Log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustTable {
    records: BTreeMap<(Kind, String), TrustRecord>,
}

impl TrustTable {
    /// Folds the log into the table, in the order the events were written.
    pub fn rebuild(events: &[RecordedEvent]) -> TrustTable {
        let mut table = TrustTable::default();
        for recorded in events {
            let event = &recorded.event;
            let (Some(kind), false) = (event.kind, event.content_hash.is_empty()) else {
                continue;
            };
            let key = (kind, event.content_hash.clone());
            match event.action {
                Action::Trust => {
                    table.records.insert(
                        key,
                        TrustRecord {
                            kind,
                            content_hash: event.content_hash.clone(),
                            granted_on: event.item_id.clone(),
                            granted_at: recorded.recorded_at,
                            actor: event.actor,
                            verified: recorded.verified,
                        },
                    );
                }
                Action::Untrust => {
                    table.records.remove(&key);
                }
                _ => {}
            }
        }
        table
    }

    /// True when this content of this kind carries Trust, wherever it appears.
    pub fn trusts(&self, kind: Kind, content_hash: &str) -> bool {
        self.records.contains_key(&(kind, content_hash.to_string()))
    }

    /// One record, for display.
    pub fn record(&self, kind: Kind, content_hash: &str) -> Option<&TrustRecord> {
        self.records.get(&(kind, content_hash.to_string()))
    }

    /// Every record the user granted.
    pub fn records(&self) -> impl Iterator<Item = &TrustRecord> {
        self.records.values()
    }

    /// How many content hashes carry Trust.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when nothing carries Trust.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Why a change to an Item needs no question.
///
/// ADR 0007 keeps the list closed and never infers who wrote a file: there is
/// no time window after an Agent session and no guess at the writing process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownAction {
    /// AgentSweep wrote the content itself: a Quarantine, a Restore, a
    /// re-enforce, a Re-enable or a Gate registration.
    Write,
    /// The user said the change was their own doing.
    Acknowledge,
}

impl KnownAction {
    /// What the Baseline records as having moved the accepted hash.
    pub fn accepted_by(self) -> crate::baseline::AcceptedBy {
        match self {
            KnownAction::Write => crate::baseline::AcceptedBy::AgentsweepWrite,
            KnownAction::Acknowledge => crate::baseline::AcceptedBy::Acknowledge,
        }
    }
}

/// One known action, with the Event Log record behind it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandsBehind {
    /// Which known action it was.
    pub action: KnownAction,
    /// Where in the Event Log it sits, which the Baseline record names.
    pub event: String,
}

/// The changes AgentSweep already knows the reason for, rebuilt from the Event
/// Log.
///
/// A Scan applies these before the Rules run, so content AgentSweep wrote
/// itself or the user acknowledged reads `unchanged` and never raises the "was
/// that you?" question (spec section 4.6.3). Trust is the third known action
/// and lives in [`TrustTable`], because it is bound to a content hash and a
/// kind rather than to one Item.
///
/// An action is remembered by the content hash it names, never by the path it
/// touched: knowing that AgentSweep once wrote a file is not knowing that the
/// bytes there now are the ones it wrote.
#[derive(Clone, Debug, Default)]
pub struct KnownActions {
    by_item: BTreeMap<ItemId, BTreeMap<String, StandsBehind>>,
}

impl KnownActions {
    /// Nothing is known, which is what a Scan without an Event Log runs
    /// against.
    pub fn none() -> KnownActions {
        KnownActions::default()
    }

    /// Rebuilds the known actions from the Event Log.
    pub fn rebuild(events: &[RecordedEvent]) -> KnownActions {
        let mut known = KnownActions::default();
        for recorded in events {
            let action = match recorded.event.action {
                Action::Quarantine
                | Action::Restore
                | Action::ReEnable
                | Action::ReEnforce
                | Action::GateRegistered => KnownAction::Write,
                Action::Acknowledge => KnownAction::Acknowledge,
                _ => continue,
            };
            let Some(item_id) = recorded.event.item_id.clone() else {
                continue;
            };
            let event = recorded.sequence.to_string();
            let mut hashes = vec![recorded.event.content_hash.clone()];
            if let Some(left) = recorded.event.detail.get(crate::eventlog::LEFT_HASH) {
                hashes.push(left.clone());
            }
            for hash in hashes.into_iter().filter(|hash| !hash.is_empty()) {
                known.by_item.entry(item_id.clone()).or_default().insert(
                    hash,
                    StandsBehind {
                        action,
                        event: event.clone(),
                    },
                );
            }
        }
        known
    }

    /// The known action behind this content of this Item, if there is one.
    pub fn stands_behind(&self, item_id: &ItemId, content_hash: &str) -> Option<&StandsBehind> {
        self.by_item.get(item_id)?.get(content_hash)
    }

    /// How many Items carry a known action.
    pub fn len(&self) -> usize {
        self.by_item.len()
    }

    /// True when no change has a known reason behind it.
    pub fn is_empty(&self) -> bool {
        self.by_item.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::{Event, EventLog, EventLogWriter};
    use crate::item::Scope;
    use crate::keychain::{KeySource, MemoryKeySource};

    use tempfile::TempDir;

    fn item(locator: &str) -> ItemId {
        ItemId::new("claude-code", &Scope::User, Kind::Skill, locator)
    }

    fn quarantine(receipt: &str, locator: &str, hash: &str) -> Event {
        let mut event = Event::new(Action::Quarantine, Actor::Auto)
            .about(&item(locator), Kind::Skill, hash)
            .because_of("finding-1", Tier::Rules, 12);
        event.receipt_id = receipt.to_string();
        event.steps = vec![ReceiptStep::new(
            Primitive::MoveOut,
            format!("/Users/nobody/.claude/skills/{locator}"),
        )];
        event
    }

    fn with_receipt(action: Action, actor: Actor, receipt: &str) -> Event {
        let mut event = Event::new(action, actor);
        event.receipt_id = receipt.to_string();
        event
    }

    /// Writes the events to a real chain and reads them back, so every test
    /// here folds what the Event Log actually holds rather than a list built
    /// in memory.
    fn recorded(events: Vec<Event>) -> Vec<RecordedEvent> {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
        for event in &events {
            writer.append(event).expect("an appended event");
        }
        log.read(&keys).expect("a readable log").events
    }

    #[test]
    fn the_manifest_holds_what_was_quarantined_and_not_restored() {
        let events = recorded(vec![
            quarantine("r-1", "leak", &"a".repeat(64)),
            quarantine("r-2", "wipe", &"b".repeat(64)),
            with_receipt(Action::Restore, Actor::User, "r-1"),
        ]);
        let manifest = QuarantineManifest::rebuild(&events);
        assert_eq!(manifest.len(), 1);
        assert!(manifest.for_receipt("r-1").is_none());
        let entry = manifest.for_receipt("r-2").expect("the entry");
        assert_eq!(entry.item_id, item("wipe"));
        assert_eq!(entry.kind, Some(Kind::Skill));
        assert_eq!(entry.rule_id, 12);
        assert_eq!(entry.tier, Some(Tier::Rules));
        assert!(entry.has_payload());
        assert!(manifest.holds(&item("wipe")));
        assert!(!manifest.holds(&item("leak")));
    }

    #[test]
    fn a_purge_takes_the_item_out_of_the_manifest() {
        let events = recorded(vec![
            quarantine("r-1", "leak", &"a".repeat(64)),
            with_receipt(Action::Purge, Actor::User, "r-1"),
        ]);
        assert!(QuarantineManifest::rebuild(&events).is_empty());
    }

    #[test]
    fn a_restore_that_did_not_finish_leaves_the_item_quarantined() {
        let mut restore = with_receipt(Action::Restore, Actor::User, "r-1");
        restore.result = Outcome::Failed;
        let events = recorded(vec![quarantine("r-1", "leak", &"a".repeat(64)), restore]);
        let manifest = QuarantineManifest::rebuild(&events);
        let entry = manifest.for_receipt("r-1").expect("the entry");
        assert!(entry.restore_unfinished);
    }

    #[test]
    fn re_enforcement_is_counted_and_re_enable_reverses_only_the_native_disable() {
        let mut plugin = Event::new(Action::Quarantine, Actor::Auto).about(
            &item("marketplace-plugin"),
            Kind::Plugin,
            &"c".repeat(64),
        );
        plugin.receipt_id = "r-9".to_string();
        plugin.steps = vec![
            ReceiptStep::new(Primitive::NativeDisable, "/Users/nobody/.claude.json"),
            ReceiptStep::new(Primitive::MoveOut, "/Users/nobody/.claude/plugins/x/1.2"),
        ];
        let events = recorded(vec![
            plugin,
            with_receipt(Action::ReEnforce, Actor::Auto, "r-9"),
            with_receipt(Action::ReEnforce, Actor::Auto, "r-9"),
            with_receipt(Action::ReEnable, Actor::User, "r-9"),
        ]);
        let manifest = QuarantineManifest::rebuild(&events);
        let entry = manifest.for_receipt("r-9").expect("the entry");
        assert_eq!(entry.re_enforced, 2);
        assert!(!entry.natively_disabled);
        assert_eq!(entry.steps.len(), 2);
        assert!(entry.has_payload());
    }

    #[test]
    fn the_trust_table_holds_what_was_trusted_and_not_untrusted() {
        let hash = "d".repeat(64);
        let other = "e".repeat(64);
        let events = recorded(vec![
            Event::new(Action::Trust, Actor::User).about(&item("leak"), Kind::Skill, &hash),
            Event::new(Action::Trust, Actor::Restore).about(&item("wipe"), Kind::McpServer, &other),
            Event::new(Action::Untrust, Actor::User).about(&item("leak"), Kind::Skill, &hash),
        ]);
        let table = TrustTable::rebuild(&events);
        assert_eq!(table.len(), 1);
        assert!(!table.trusts(Kind::Skill, &hash));
        assert!(table.trusts(Kind::McpServer, &other));
        let record = table.record(Kind::McpServer, &other).expect("the record");
        assert_eq!(record.actor, Actor::Restore);
        assert_eq!(record.granted_on, Some(item("wipe")));
    }

    #[test]
    fn trust_is_bound_to_the_hash_and_to_the_kind() {
        let hash = "f".repeat(64);
        let events = recorded(vec![Event::new(Action::Trust, Actor::User).about(
            &item("leak"),
            Kind::Skill,
            &hash,
        )]);
        let table = TrustTable::rebuild(&events);
        assert!(table.trusts(Kind::Skill, &hash));
        assert!(!table.trusts(Kind::Subagent, &hash));
        assert!(!table.trusts(Kind::Skill, &"0".repeat(64)));
    }

    #[test]
    fn both_views_come_from_the_log_and_from_nowhere_else() {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let hash = "a".repeat(64);
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            writer
                .append(&quarantine("r-1", "leak", &hash))
                .expect("an appended event");
            writer
                .append(&Event::new(Action::Trust, Actor::Restore).about(
                    &item("leak"),
                    Kind::Skill,
                    &hash,
                ))
                .expect("an appended event");
        }

        // Nothing but the chain file exists, and a fresh read rebuilds both
        // views, as a daemon restart does.
        let files: Vec<_> = std::fs::read_dir(directory.path())
            .expect("a readable directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(files, vec![std::ffi::OsString::from("events.jsonl")]);

        let view = log.read(&keys).expect("a readable log");
        assert_eq!(view.quarantine_manifest().len(), 1);
        assert!(view.trust_table().trusts(Kind::Skill, &hash));
    }

    #[test]
    fn the_views_of_a_reset_protection_state_keep_the_old_decisions_and_flag_them() {
        let directory = TempDir::new().expect("a temporary directory");
        let log = EventLog::at(directory.path().join("events.jsonl"));
        let keys = MemoryKeySource::empty();
        let hash = "a".repeat(64);
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            writer
                .append(&quarantine("r-1", "leak", &hash))
                .expect("an appended event");
            writer
                .append(&Event::new(Action::Trust, Actor::User).about(
                    &item("leak"),
                    Kind::Skill,
                    &hash,
                ))
                .expect("an appended event");
        }
        keys.forget().expect("the key goes away");
        {
            let (mut writer, _) = EventLogWriter::open(&log, &keys).expect("an open log");
            writer
                .append(&quarantine("r-2", "wipe", &"b".repeat(64)))
                .expect("an appended event");
        }

        let view = log.read(&keys).expect("a readable log");
        let manifest = view.quarantine_manifest();
        assert_eq!(manifest.len(), 2);
        assert!(!manifest.for_receipt("r-1").expect("the entry").verified);
        assert!(manifest.for_receipt("r-2").expect("the entry").verified);

        let table = view.trust_table();
        assert!(table.trusts(Kind::Skill, &hash));
        assert!(
            !table
                .record(Kind::Skill, &hash)
                .expect("the record")
                .verified
        );
    }

    #[test]
    fn reconciling_names_a_payload_the_store_lost_and_one_it_does_not_account_for() {
        let temporary = TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        directory.create().expect("a writable store");
        let events = recorded(vec![
            quarantine("r-1", "leak", &"a".repeat(64)),
            quarantine("r-2", "wipe", &"b".repeat(64)),
        ]);
        let manifest = QuarantineManifest::rebuild(&events);

        std::fs::create_dir_all(directory.quarantine().join("r-1")).expect("a writable store");
        std::fs::write(directory.quarantine_payload("r-1"), b"moved out")
            .expect("a writable store");
        std::fs::create_dir_all(directory.quarantine().join("r-stray")).expect("a writable store");

        let reconciliation = manifest.reconcile(&directory).expect("a readable store");
        assert!(!reconciliation.agrees());
        assert_eq!(reconciliation.missing_payloads, vec!["r-2".to_string()]);
        assert_eq!(reconciliation.unknown_payloads, vec!["r-stray".to_string()]);
    }

    #[test]
    fn a_store_that_holds_exactly_what_the_log_says_agrees() {
        let temporary = TempDir::new().expect("a temporary directory");
        let directory = DataDirectory::at(temporary.path());
        directory.create().expect("a writable store");
        let events = recorded(vec![quarantine("r-1", "leak", &"a".repeat(64))]);
        let manifest = QuarantineManifest::rebuild(&events);
        std::fs::create_dir_all(directory.quarantine().join("r-1")).expect("a writable store");
        std::fs::write(directory.quarantine_payload("r-1"), b"moved out")
            .expect("a writable store");

        assert!(
            manifest
                .reconcile(&directory)
                .expect("a readable store")
                .agrees()
        );
    }

    /// ADR 0007's closed list: AgentSweep's own writes and the user's
    /// Acknowledge, and nothing else.
    #[test]
    fn only_agentsweeps_own_writes_and_an_acknowledge_are_known_actions() {
        let hash = "b".repeat(64);
        let events = recorded(vec![
            Event::new(Action::Quarantine, Actor::Auto).about(&item("leak"), Kind::Skill, &hash),
            Event::new(Action::Acknowledge, Actor::User).about(
                &item("drifted"),
                Kind::Skill,
                &hash,
            ),
            Event::new(Action::Purge, Actor::User).about(&item("purged"), Kind::Skill, &hash),
        ]);
        let known = KnownActions::rebuild(&events);

        assert_eq!(
            known
                .stands_behind(&item("leak"), &hash)
                .map(|stands| stands.action),
            Some(KnownAction::Write)
        );
        assert_eq!(
            known
                .stands_behind(&item("drifted"), &hash)
                .map(|stands| stands.action),
            Some(KnownAction::Acknowledge)
        );
        assert_eq!(known.stands_behind(&item("purged"), &hash), None);
        assert_eq!(known.len(), 2);
    }

    /// A known action is known by the bytes it left, so the same Item at
    /// another hash is a change nothing accounts for.
    #[test]
    fn a_known_action_covers_the_hash_it_names_and_no_other() {
        let left = "c".repeat(64);
        let taken = "a".repeat(64);
        let events = recorded(vec![
            Event::new(Action::Restore, Actor::User)
                .about(&item("moved"), Kind::Skill, &taken)
                .leaving(&left),
        ]);
        let known = KnownActions::rebuild(&events);

        assert!(known.stands_behind(&item("moved"), &left).is_some());
        assert!(known.stands_behind(&item("moved"), &taken).is_some());
        assert!(
            known
                .stands_behind(&item("moved"), &"d".repeat(64))
                .is_none()
        );
    }

    #[test]
    fn a_known_action_names_the_event_behind_it() {
        let hash = "e".repeat(64);
        let events = recorded(vec![
            Event::new(Action::Trust, Actor::User).about(&item("first"), Kind::Skill, &hash),
            Event::new(Action::ReEnforce, Actor::Auto).about(&item("second"), Kind::Skill, &hash),
        ]);
        let known = KnownActions::rebuild(&events);
        let stands = known
            .stands_behind(&item("second"), &hash)
            .expect("the re-enforce is a known action");
        assert_eq!(stands.event, "1");
    }

    #[test]
    fn nothing_is_known_without_an_event_log() {
        assert!(KnownActions::none().is_empty());
    }
}
