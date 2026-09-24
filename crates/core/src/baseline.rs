//! The Baseline: the content hash AgentSweep last accepted for each Item.
//!
//! `baseline.jsonl` is the second hash-chained file beside the Event Log: same
//! record envelope, same Keychain key, same verification routine, daemon-only
//! writer (ADR 0003 as amended, spec section 4.6.6). It is kept apart from the
//! Event Log because it is far noisier and because, unlike the Event Log, it
//! may be compacted.
//!
//! One record per Item, and one record per stretch of [`crate::coverage`]. The
//! current Baseline is the derived view of the chain: the last record for an
//! Item id wins. A record is written only when something about the Item moved,
//! never once per Scan, which is what keeps the chain quiet on a Mac where
//! nothing changes.
//!
//! The Baseline holds no content. A tree is a manifest of paths, sizes, modes
//! and hashes; an entry is a hash per top-level field plus the canonical form
//! of the accepted entry with its sensitive fields left out. Nothing else about
//! an Item's bytes is written down.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::chain::{Chain, ChainError, ChainState};
use crate::coverage::{Coverage, CoverageRecord};
use crate::envelope::{ChainId, RecordKind, Timestamp};
use crate::item::{Item, ItemId, Kind, Shape, sha256_hex};
use crate::keychain::KeySource;
use crate::paths::DataDirectory;

/// What moved the accepted hash to where it stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptedBy {
    /// The Item was first seen before its Surface was covered, so there was
    /// nothing to compare it with.
    Bootstrap,
    /// A Scan ended with no open Finding on the Item.
    CleanScan,
    /// AgentSweep wrote the content itself: a Quarantine, a Restore, a
    /// re-enforce, a Re-enable, a Gate registration.
    AgentsweepWrite,
    /// The content carries Trust for its kind.
    Trust,
    /// The user said the change was their own doing.
    Acknowledge,
}

impl AcceptedBy {
    /// Every reason, in the order spec section 4.6.2 lists them.
    pub const ALL: [AcceptedBy; 5] = [
        AcceptedBy::Bootstrap,
        AcceptedBy::CleanScan,
        AcceptedBy::AgentsweepWrite,
        AcceptedBy::Trust,
        AcceptedBy::Acknowledge,
    ];

    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            AcceptedBy::Bootstrap => "bootstrap",
            AcceptedBy::CleanScan => "clean-scan",
            AcceptedBy::AgentsweepWrite => "agentsweep-write",
            AcceptedBy::Trust => "trust",
            AcceptedBy::Acknowledge => "acknowledge",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<AcceptedBy> {
        AcceptedBy::ALL
            .into_iter()
            .find(|reason| reason.as_str() == text)
    }

    /// True when a known action stands behind the acceptance rather than a
    /// Scan that found nothing (ADR 0007's closed list).
    pub fn is_known_action(self) -> bool {
        matches!(
            self,
            AcceptedBy::AgentsweepWrite | AcceptedBy::Trust | AcceptedBy::Acknowledge
        )
    }
}

impl std::fmt::Display for AcceptedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the Item was there the last time AgentSweep looked.
///
/// Disappearance is never a Finding. A record is marked absent and kept, and
/// an Item that comes back with the accepted hash is `unchanged` again (spec
/// section 4.6.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// The Item was enumerated.
    Present,
    /// The Item was gone, from this moment on.
    Absent {
        /// When it was first missed.
        since: Timestamp,
    },
}

impl Presence {
    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Presence::Present => "present",
            Presence::Absent { .. } => "absent",
        }
    }

    /// True when the Item was gone the last time AgentSweep looked.
    pub fn is_absent(self) -> bool {
        matches!(self, Presence::Absent { .. })
    }
}

/// Whether a key in hand can vouch for where a record came from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Origin {
    /// The record verifies under the key in hand.
    #[default]
    Verified,
    /// No key can verify it: the protection state was reset and the old
    /// Baseline carries over rather than being rebuilt from disk (ADR 0007).
    UnverifiedOrigin,
}

impl Origin {
    /// The spelling a record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Verified => "verified",
            Origin::UnverifiedOrigin => "unverified-origin",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<Origin> {
        match text {
            "verified" => Some(Origin::Verified),
            "unverified-origin" => Some(Origin::UnverifiedOrigin),
            _ => None,
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One file of a tree as the Baseline remembers it: enough to name the file
/// that changed, and no content at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestFile {
    /// The path relative to the tree root.
    pub path: String,
    /// The size in bytes.
    pub size: u64,
    /// The permission bits.
    pub mode: u32,
    /// The hash of the file's bytes.
    pub sha256: String,
}

impl ManifestFile {
    /// The manifest of one tree Item, empty for the other two shapes.
    pub fn of(item: &Item) -> Vec<ManifestFile> {
        if item.shape != Shape::Tree {
            return Vec::new();
        }
        item.tree
            .files
            .iter()
            .map(|file| ManifestFile {
                path: file.path.clone(),
                size: file.size,
                mode: file.mode,
                sha256: file.sha256.clone(),
            })
            .collect()
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("mode".to_string(), Value::from(self.mode));
        map.insert("path".to_string(), Value::from(self.path.as_str()));
        map.insert("sha256".to_string(), Value::from(self.sha256.as_str()));
        map.insert("size".to_string(), Value::from(self.size));
        Value::Object(map)
    }

    fn parse(value: &Value) -> Option<ManifestFile> {
        Some(ManifestFile {
            path: value.get("path")?.as_str()?.to_string(),
            size: value.get("size")?.as_u64()?,
            mode: value.get("mode")?.as_u64()? as u32,
            sha256: value.get("sha256")?.as_str()?.to_string(),
        })
    }
}

/// The top-level fields of an entry whose values never leave the machine in
/// the clear (spec section 3.3).
///
/// The Baseline keeps a hash per field for every field alike, so a swapped
/// credential still moves the Item's hash; what these names govern is the one
/// place a value could be written out, which is
/// [`BaselineRecord::previous_form`].
pub fn sensitive_fields(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::McpServer | Kind::SettingsEntry => &["env", "headers"],
        _ => &[],
    }
}

/// A hash per top-level field of an entry, in sorted order.
///
/// A file or a tree Item has none: its hash is over the bytes or over the
/// manifest, and the field hashes exist so that a Drift Finding can say which
/// field of an entry moved without holding the field.
pub fn field_hashes(item: &Item) -> BTreeMap<String, String> {
    if item.shape != Shape::Entry {
        return BTreeMap::new();
    }
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(&item.content) else {
        return BTreeMap::new();
    };
    fields
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                sha256_hex(&crate::item::canonical_entry(value)),
            )
        })
        .collect()
}

/// The canonical form of an entry with its sensitive fields left out, which is
/// the only content the Baseline ever holds.
///
/// Empty for a file or a tree, and empty for an entry whose own key names a
/// sensitive field: an entry that *is* a credential block is remembered by its
/// field hashes alone.
pub fn redacted_form(item: &Item) -> String {
    if item.shape != Shape::Entry {
        return String::new();
    }
    let sensitive = sensitive_fields(item.kind);
    let key = item.inside_file().rsplit(['/', '.']).next().unwrap_or("");
    if sensitive.contains(&key) {
        return String::new();
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&item.content) else {
        return String::new();
    };
    let value = match parsed {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .filter(|(name, _)| !sensitive.contains(&name.as_str()))
                .collect(),
        ),
        other => other,
    };
    String::from_utf8_lossy(&crate::item::canonical_entry(&value)).to_string()
}

/// One Item as the Baseline remembers it (spec section 4.6.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineRecord {
    /// Which Item the record is about.
    pub item_id: ItemId,
    /// Its Surface kind.
    pub kind: Kind,
    /// The hash AgentSweep last accepted.
    pub accepted_hash: String,
    /// When it was accepted.
    pub accepted_at: Timestamp,
    /// What moved it there.
    pub accepted_by: AcceptedBy,
    /// The Event Log record behind a known action, empty where none applies.
    pub accepted_event: String,
    /// The hash the last Scan saw.
    pub last_seen_hash: String,
    /// When that hash was first seen. It moves with the hash, not with every
    /// Scan: a Mac where nothing changes writes no records.
    pub last_seen_at: Timestamp,
    /// When the Item first stopped matching the accepted hash, absent while
    /// the two agree.
    pub first_differed_at: Option<Timestamp>,
    /// Whether the Item was there the last time AgentSweep looked.
    pub state: Presence,
    /// Whether a key in hand can vouch for the record.
    pub origin: Origin,
    /// The manifest of the accepted form of a tree Item.
    pub accepted_manifest: Vec<ManifestFile>,
    /// The manifest of the last-seen form, kept only while it differs from the
    /// accepted one.
    pub last_seen_manifest: Vec<ManifestFile>,
    /// A hash per top-level field of the accepted form of an entry Item.
    pub accepted_fields: BTreeMap<String, String>,
    /// The same for the last-seen form, kept only while the two differ.
    pub last_seen_fields: BTreeMap<String, String>,
    /// The canonical form of the accepted entry with its sensitive fields left
    /// out, which is the "before" a Drift Finding shows.
    pub previous_form: String,
}

impl BaselineRecord {
    /// The first record of an Item: what was seen is what is accepted.
    pub fn accepting(item: &Item, at: Timestamp, by: AcceptedBy) -> BaselineRecord {
        let manifest = ManifestFile::of(item);
        let fields = field_hashes(item);
        BaselineRecord {
            item_id: item.id.clone(),
            kind: item.kind,
            accepted_hash: item.content_hash.clone(),
            accepted_at: at,
            accepted_by: by,
            accepted_event: String::new(),
            last_seen_hash: item.content_hash.clone(),
            last_seen_at: at,
            first_differed_at: None,
            state: Presence::Present,
            origin: Origin::Verified,
            accepted_manifest: manifest,
            last_seen_manifest: Vec::new(),
            accepted_fields: fields,
            last_seen_fields: BTreeMap::new(),
            previous_form: redacted_form(item),
        }
    }

    /// The record after the Item was seen again at this hash without being
    /// accepted: the accepted form stays where it is, and what differs is kept
    /// beside it so a Drift Finding can name the file or the field.
    pub fn seeing(&self, item: &Item, at: Timestamp) -> BaselineRecord {
        let mut moved = self.clone();
        moved.kind = item.kind;
        moved.state = Presence::Present;
        moved.origin = Origin::Verified;
        if moved.last_seen_hash != item.content_hash {
            moved.last_seen_hash = item.content_hash.clone();
            moved.last_seen_at = at;
        }
        if item.content_hash == moved.accepted_hash {
            moved.first_differed_at = None;
            moved.last_seen_manifest = Vec::new();
            moved.last_seen_fields = BTreeMap::new();
        } else {
            moved.first_differed_at = moved.first_differed_at.or(Some(at));
            moved.last_seen_manifest = ManifestFile::of(item);
            moved.last_seen_fields = field_hashes(item);
        }
        moved
    }

    /// The record after the hash was accepted: the last-seen forms fold into
    /// the accepted one and nothing differs any more.
    pub fn accepted(&self, item: &Item, at: Timestamp, by: AcceptedBy) -> BaselineRecord {
        let mut moved = BaselineRecord::accepting(item, at, by);
        moved.last_seen_at = if self.last_seen_hash == item.content_hash {
            self.last_seen_at
        } else {
            at
        };
        moved
    }

    /// The record after the Item was not enumerated by a Full Scan.
    /// Disappearance is never a Finding; the record is marked and kept.
    pub fn absent(&self, at: Timestamp) -> BaselineRecord {
        let mut gone = self.clone();
        gone.state = Presence::Absent { since: at };
        gone.origin = Origin::Verified;
        gone
    }

    /// True when the record says something the one before it did not, which is
    /// the only reason to write it.
    pub fn moved_from(&self, previous: &BaselineRecord) -> bool {
        self != previous
    }

    /// The payload a record carries.
    pub fn to_payload(&self) -> Value {
        let strings = |fields: &BTreeMap<String, String>| {
            Value::Object(
                fields
                    .iter()
                    .map(|(name, hash)| (name.clone(), Value::from(hash.as_str())))
                    .collect(),
            )
        };
        let files = |manifest: &[ManifestFile]| {
            Value::Array(manifest.iter().map(ManifestFile::to_value).collect())
        };

        let mut map = Map::new();
        map.insert("about".to_string(), Value::from("item"));
        map.insert(
            "absent_since".to_string(),
            Value::from(match self.state {
                Presence::Absent { since } => since.to_string(),
                Presence::Present => String::new(),
            }),
        );
        map.insert(
            "accepted_at".to_string(),
            Value::from(self.accepted_at.to_string()),
        );
        map.insert(
            "accepted_by".to_string(),
            Value::from(self.accepted_by.as_str()),
        );
        map.insert(
            "accepted_event".to_string(),
            Value::from(self.accepted_event.as_str()),
        );
        map.insert(
            "accepted_fields".to_string(),
            strings(&self.accepted_fields),
        );
        map.insert(
            "accepted_hash".to_string(),
            Value::from(self.accepted_hash.as_str()),
        );
        map.insert(
            "accepted_manifest".to_string(),
            files(&self.accepted_manifest),
        );
        map.insert(
            "first_differed_at".to_string(),
            Value::from(
                self.first_differed_at
                    .map(|at| at.to_string())
                    .unwrap_or_default(),
            ),
        );
        map.insert("item_id".to_string(), Value::from(self.item_id.as_str()));
        map.insert("kind".to_string(), Value::from(self.kind.as_str()));
        map.insert(
            "last_seen_at".to_string(),
            Value::from(self.last_seen_at.to_string()),
        );
        map.insert(
            "last_seen_fields".to_string(),
            strings(&self.last_seen_fields),
        );
        map.insert(
            "last_seen_hash".to_string(),
            Value::from(self.last_seen_hash.as_str()),
        );
        map.insert(
            "last_seen_manifest".to_string(),
            files(&self.last_seen_manifest),
        );
        map.insert("origin".to_string(), Value::from(self.origin.as_str()));
        map.insert(
            "previous_form".to_string(),
            Value::from(self.previous_form.as_str()),
        );
        map.insert("state".to_string(), Value::from(self.state.as_str()));
        Value::Object(map)
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<BaselineRecord> {
        let text = |field: &str| payload.get(field).and_then(Value::as_str);
        if text("about")? != "item" {
            return None;
        }
        let strings = |field: &str| -> Option<BTreeMap<String, String>> {
            payload
                .get(field)?
                .as_object()?
                .iter()
                .map(|(name, value)| Some((name.clone(), value.as_str()?.to_string())))
                .collect()
        };
        let files = |field: &str| -> Option<Vec<ManifestFile>> {
            payload
                .get(field)?
                .as_array()?
                .iter()
                .map(ManifestFile::parse)
                .collect()
        };
        let moment = |field: &str| -> Option<Option<Timestamp>> {
            match text(field)? {
                "" => Some(None),
                written => Timestamp::parse(written).map(Some),
            }
        };

        let absent_since = moment("absent_since")?;
        let state = match (text("state")?, absent_since) {
            ("present", _) => Presence::Present,
            ("absent", Some(since)) => Presence::Absent { since },
            _ => return None,
        };
        Some(BaselineRecord {
            item_id: ItemId::from_recorded(text("item_id")?),
            kind: Kind::parse(text("kind")?)?,
            accepted_hash: text("accepted_hash")?.to_string(),
            accepted_at: Timestamp::parse(text("accepted_at")?)?,
            accepted_by: AcceptedBy::parse(text("accepted_by")?)?,
            accepted_event: text("accepted_event")?.to_string(),
            last_seen_hash: text("last_seen_hash")?.to_string(),
            last_seen_at: Timestamp::parse(text("last_seen_at")?)?,
            first_differed_at: moment("first_differed_at")?,
            state,
            origin: Origin::parse(text("origin")?)?,
            accepted_manifest: files("accepted_manifest")?,
            last_seen_manifest: files("last_seen_manifest")?,
            accepted_fields: strings("accepted_fields")?,
            last_seen_fields: strings("last_seen_fields")?,
            previous_form: text("previous_form")?.to_string(),
        })
    }
}

/// One record of the Baseline chain: an Item, or a stretch of coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaselineEntry {
    /// What AgentSweep accepted for one Item.
    Item(Box<BaselineRecord>),
    /// Which Surface AgentSweep had already looked at.
    Coverage(CoverageRecord),
}

impl BaselineEntry {
    /// The payload a record carries.
    pub fn to_payload(&self) -> Value {
        match self {
            BaselineEntry::Item(record) => record.to_payload(),
            BaselineEntry::Coverage(record) => record.to_payload(),
        }
    }

    /// Reads back the payload a record carries.
    pub fn from_payload(payload: &Value) -> Option<BaselineEntry> {
        match payload.get("about").and_then(Value::as_str)? {
            "item" => BaselineRecord::from_payload(payload)
                .map(|record| BaselineEntry::Item(Box::new(record))),
            "coverage" => CoverageRecord::from_payload(payload).map(BaselineEntry::Coverage),
            _ => None,
        }
    }
}

/// The Baseline chain, `baseline.jsonl`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Baseline {
    chain: Chain,
}

impl Baseline {
    /// The Baseline kept at this path.
    pub fn at(path: impl Into<PathBuf>) -> Baseline {
        Baseline {
            chain: Chain::at(path, ChainId::Baseline),
        }
    }

    /// The Baseline of a data directory.
    pub fn in_data_directory(directory: &DataDirectory) -> Baseline {
        Baseline::at(directory.baseline())
    }

    /// The chain underneath, for the verification routine both chains share.
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Reads and verifies the whole Baseline.
    ///
    /// A record no key in hand can verify still carries over, as
    /// `unverified-origin`: the Baseline is never rebuilt from disk, because
    /// deleting the Keychain item and editing a hook would otherwise launder
    /// the edit into a fresh Baseline (ADR 0007).
    pub fn read(&self, keys: &dyn KeySource) -> Result<BaselineView, ChainError> {
        let verification = self.chain.verify(keys)?;
        let mut view = BaselineView {
            state: verification.state.clone(),
            head: verification.head.clone(),
            unverified: verification.records.iter().filter(|r| !r.verified).count(),
            restarts: 0,
            unreadable: 0,
            records: BTreeMap::new(),
            coverage: Coverage::none(),
        };
        let key_missing = verification.state == ChainState::KeyMissing;
        for record in &verification.records {
            if record.envelope.record == RecordKind::ChainRestart {
                view.restarts += 1;
                continue;
            }
            match BaselineEntry::from_payload(&record.envelope.payload) {
                Some(BaselineEntry::Item(mut held)) => {
                    if key_missing || !record.verified {
                        held.origin = Origin::UnverifiedOrigin;
                    }
                    view.records.insert(held.item_id.clone(), *held);
                }
                Some(BaselineEntry::Coverage(covered)) => view.coverage.record(&covered),
                None => view.unreadable += 1,
            }
        }
        Ok(view)
    }
}

/// The Baseline as one read of the chain left it: the last record per Item and
/// everything that is covered.
#[derive(Clone, Debug)]
pub struct BaselineView {
    /// What verification found.
    pub state: ChainState,
    /// The hash of the last record in the file.
    pub head: String,
    /// How many records no key in hand can verify.
    pub unverified: usize,
    /// How many times the chain was restarted because the key went missing.
    pub restarts: usize,
    /// How many records carried a payload that is neither an Item nor
    /// coverage.
    pub unreadable: usize,
    records: BTreeMap<ItemId, BaselineRecord>,
    coverage: Coverage,
}

impl BaselineView {
    /// No Baseline at all: what a Folder Scan and the in-process command line
    /// interface run against, where every Item reads `none` and Drift is
    /// unavailable (spec section 6.2).
    pub fn none() -> BaselineView {
        BaselineView {
            state: ChainState::Intact,
            head: crate::envelope::GENESIS.to_string(),
            unverified: 0,
            restarts: 0,
            unreadable: 0,
            records: BTreeMap::new(),
            coverage: Coverage::none(),
        }
    }

    /// What the Baseline holds for one Item, if anything.
    pub fn record(&self, item_id: &ItemId) -> Option<&BaselineRecord> {
        self.records.get(item_id)
    }

    /// Every Item the Baseline holds, in id order.
    pub fn records(&self) -> impl Iterator<Item = &BaselineRecord> {
        self.records.values()
    }

    /// How many Items the Baseline holds.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when the Baseline holds no Item at all.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Which Surfaces were already covered.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// True when no key in hand can vouch for the Baseline, which is the
    /// key-missing state carrying the old records over (ADR 0007).
    pub fn carried_over(&self) -> bool {
        self.state == ChainState::KeyMissing
    }
}

#[cfg(feature = "daemon")]
pub use writer::BaselineWriter;

#[cfg(feature = "daemon")]
mod writer {
    use super::{Baseline, BaselineEntry, BaselineRecord};

    use crate::chain::{ChainError, ChainState, ChainWriter};
    use crate::coverage::CoverageRecord;
    use crate::envelope::Envelope;
    use crate::keychain::KeySource;

    /// The write side of the Baseline.
    ///
    /// The daemon is the only writer (spec section 6.2), which this type
    /// carries: it exists only in a build with the `daemon` feature, so the
    /// application and the in-process command line interface cannot compile a
    /// call that appends a Baseline record.
    #[derive(Debug)]
    pub struct BaselineWriter {
        writer: ChainWriter,
    }

    impl BaselineWriter {
        /// Verifies the Baseline, then opens it for appending, answering with
        /// what verification found.
        pub fn open(
            baseline: &Baseline,
            keys: &dyn KeySource,
        ) -> Result<(BaselineWriter, ChainState), ChainError> {
            let (writer, state) = ChainWriter::open(baseline.chain().clone(), keys)?;
            Ok((BaselineWriter { writer }, state))
        }

        /// Appends one record and flushes it to the disk.
        pub fn append(&mut self, entry: &BaselineEntry) -> Result<Envelope, ChainError> {
            self.writer.append(entry.to_payload())
        }

        /// Appends what AgentSweep accepted for one Item.
        pub fn accept(&mut self, record: &BaselineRecord) -> Result<Envelope, ChainError> {
            self.append(&BaselineEntry::Item(Box::new(record.clone())))
        }

        /// Appends one stretch of coverage, which a Scan writes before it
        /// enumerates a newly registered root or a newly detected Agent.
        pub fn cover(&mut self, record: &CoverageRecord) -> Result<Envelope, ChainError> {
            self.append(&BaselineEntry::Coverage(record.clone()))
        }

        /// The hash a record appended now would link to.
        pub fn head(&self) -> &str {
            self.writer.head()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::coverage::CoverageKey;
    use crate::item::{Activation, Provenance, Scope, canonical_entry};
    use crate::keychain::{ChainKey, MemoryKeySource};

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    fn mcp_entry(name: &str, body: &Value) -> Item {
        Item::entry(
            "claude-code",
            Scope::User,
            Kind::McpServer,
            &format!("~/.claude.json#mcpServers/{name}"),
            PathBuf::from("/nowhere/.claude.json"),
            Provenance::Manual,
            Activation::Active,
            canonical_entry(body),
        )
    }

    fn instruction_file(content: &str) -> Item {
        Item::file(
            "claude-code",
            Scope::User,
            Kind::InstructionFile,
            "~/.claude/CLAUDE.md",
            PathBuf::from("/nowhere/.claude/CLAUDE.md"),
            Provenance::Manual,
            Activation::Active,
            content.as_bytes().to_vec(),
        )
    }

    #[test]
    fn a_record_round_trips_through_its_payload() {
        let item = mcp_entry(
            "tracker",
            &serde_json::json!({"command": "npx", "args": ["server"]}),
        );
        let record = BaselineRecord::accepting(
            &item,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );
        let payload = record.to_payload();
        assert_eq!(
            BaselineRecord::from_payload(&payload).as_ref(),
            Some(&record)
        );
        assert_eq!(
            BaselineEntry::from_payload(&payload),
            Some(BaselineEntry::Item(Box::new(record)))
        );
    }

    /// The Baseline holds no content except the accepted form of an entry, and
    /// that form is written without its sensitive fields (spec section 4.6.2).
    #[test]
    fn no_sensitive_value_reaches_a_record() {
        let item = mcp_entry(
            "tracker",
            &serde_json::json!({
                "type": "http",
                "url": "https://tracker.example.invalid/mcp",
                "headers": {"Authorization": "Bearer hunter2hunter2"},
                "env": {"SECRET": "hunter2hunter2"},
            }),
        );
        let record = BaselineRecord::accepting(
            &item,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::CleanScan,
        );
        let written = String::from_utf8(crate::item::canonical_entry(&record.to_payload()))
            .expect("the payload is text");
        assert!(!written.contains("hunter2"), "{written}");
        assert!(record.previous_form.contains("tracker.example.invalid"));
        assert!(!record.previous_form.contains("Authorization"));
        // The fields are still remembered, as hashes, so a swapped credential
        // still moves the Item.
        assert!(record.accepted_fields.contains_key("env"));
        assert!(record.accepted_fields.contains_key("headers"));
    }

    #[test]
    fn a_file_item_carries_neither_manifest_nor_fields() {
        let record = BaselineRecord::accepting(
            &instruction_file("# demo\n"),
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );
        assert!(record.accepted_manifest.is_empty());
        assert!(record.accepted_fields.is_empty());
        assert_eq!(record.previous_form, "");
    }

    /// The last-seen form is kept beside the accepted one only while the two
    /// differ, and folds back in the moment the hash is accepted.
    #[test]
    fn the_last_seen_form_is_kept_only_while_it_differs() {
        let first = mcp_entry("t", &serde_json::json!({"command": "npx"}));
        let accepted = BaselineRecord::accepting(
            &first,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );

        let second = mcp_entry("t", &serde_json::json!({"command": "/tmp/x"}));
        let seen = accepted.seeing(&second, moment("2026-09-24T10:00:00.000Z"));
        assert_eq!(seen.accepted_hash, first.content_hash);
        assert_eq!(seen.last_seen_hash, second.content_hash);
        assert_eq!(
            seen.first_differed_at,
            Some(moment("2026-09-24T10:00:00.000Z"))
        );
        assert!(!seen.last_seen_fields.is_empty());

        let taken = seen.accepted(
            &second,
            moment("2026-09-24T11:00:00.000Z"),
            AcceptedBy::CleanScan,
        );
        assert_eq!(taken.accepted_hash, second.content_hash);
        assert_eq!(taken.first_differed_at, None);
        assert!(taken.last_seen_fields.is_empty());
    }

    #[test]
    fn the_first_differed_moment_does_not_move_on_a_second_look() {
        let first = mcp_entry("t", &serde_json::json!({"command": "npx"}));
        let accepted = BaselineRecord::accepting(
            &first,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );
        let second = mcp_entry("t", &serde_json::json!({"command": "/tmp/x"}));
        let once = accepted.seeing(&second, moment("2026-09-24T10:00:00.000Z"));
        let twice = once.seeing(&second, moment("2026-09-24T12:00:00.000Z"));
        assert_eq!(
            twice.first_differed_at,
            Some(moment("2026-09-24T10:00:00.000Z"))
        );
        // The last-seen moment belongs to the hash, not to the Scan.
        assert_eq!(twice.last_seen_at, moment("2026-09-24T10:00:00.000Z"));
        assert!(!twice.moved_from(&once));
    }

    #[test]
    fn a_tree_item_remembers_its_manifest_and_no_content() {
        let home = TempDir::new().expect("a temporary home");
        let root = home.path().join("skill");
        std::fs::create_dir_all(&root).expect("a skill directory");
        std::fs::write(root.join("SKILL.md"), b"# demo\n").expect("a skill file");

        let host = crate::host::Host::new(home.path().to_path_buf(), Vec::new());
        let tree = crate::item::Tree::of(&host, &root, crate::item::TreeCaps::default());
        let item = Item::tree(
            "claude-code",
            Scope::User,
            Kind::Skill,
            "skill",
            root.clone(),
            Provenance::Manual,
            Activation::Active,
            tree,
        );
        let record = BaselineRecord::accepting(
            &item,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );
        assert_eq!(record.accepted_manifest.len(), 1);
        assert_eq!(record.accepted_manifest[0].path, "SKILL.md");
        let written = String::from_utf8(crate::item::canonical_entry(&record.to_payload()))
            .expect("the payload is text");
        assert!(!written.contains("# demo"), "{written}");
    }

    /// Both chains are the same primitive, so the Baseline verifies with the
    /// routine the Event Log uses and refuses a record of the other chain.
    #[test]
    fn the_baseline_verifies_with_the_event_logs_own_routine() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let baseline = Baseline::in_data_directory(&data);

        let item = instruction_file("# demo\n");
        let record = BaselineRecord::accepting(
            &item,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );
        {
            let (mut writer, state) =
                BaselineWriter::open(&baseline, &keys).expect("the Baseline opens");
            assert_eq!(state, ChainState::Intact);
            writer.accept(&record).expect("the record is written");
            writer
                .cover(&CoverageRecord::new(
                    CoverageKey::of("claude-code", &Scope::User, Kind::InstructionFile),
                    moment("2026-09-24T09:00:00.000Z"),
                ))
                .expect("the coverage is written");
        }

        let view = baseline.read(&keys).expect("the Baseline reads back");
        assert_eq!(view.state, ChainState::Intact);
        assert_eq!(view.len(), 1);
        assert_eq!(view.record(&item.id), Some(&record));
        assert!(
            view.coverage()
                .covers("claude-code", &Scope::User, Kind::InstructionFile)
        );
        assert_eq!(view.unreadable, 0);
    }

    /// ADR 0007: the Baseline is never rebuilt from disk when the key goes
    /// missing. The old records carry over as unverified-origin and Drift is
    /// still computed against them.
    #[test]
    fn a_missing_key_carries_the_old_baseline_over_as_unverified_origin() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let baseline = Baseline::in_data_directory(&data);
        let item = instruction_file("# demo\n");
        let record = BaselineRecord::accepting(
            &item,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::Bootstrap,
        );
        {
            let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
            let (mut writer, _) =
                BaselineWriter::open(&baseline, &keys).expect("the Baseline opens");
            writer.accept(&record).expect("the record is written");
        }

        let empty = MemoryKeySource::empty();
        let view = baseline.read(&empty).expect("the Baseline still reads");
        assert_eq!(view.state, ChainState::KeyMissing);
        assert!(view.carried_over());
        let carried = view.record(&item.id).expect("the record carries over");
        assert_eq!(carried.origin, Origin::UnverifiedOrigin);
        assert_eq!(carried.accepted_hash, record.accepted_hash);
    }

    #[test]
    fn a_later_record_supersedes_the_one_before_it() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let baseline = Baseline::in_data_directory(&data);

        let first = instruction_file("# demo\n");
        let second = instruction_file("# demo, changed\n");
        let mut second_at_the_same_id = second.clone();
        second_at_the_same_id.id = first.id.clone();
        {
            let (mut writer, _) =
                BaselineWriter::open(&baseline, &keys).expect("the Baseline opens");
            let one = BaselineRecord::accepting(
                &first,
                moment("2026-09-24T09:00:00.000Z"),
                AcceptedBy::Bootstrap,
            );
            writer.accept(&one).expect("the first record");
            let two = one.accepted(
                &second_at_the_same_id,
                moment("2026-09-24T10:00:00.000Z"),
                AcceptedBy::CleanScan,
            );
            writer.accept(&two).expect("the second record");
        }

        let view = baseline.read(&keys).expect("the Baseline reads back");
        assert_eq!(view.len(), 1);
        assert_eq!(
            view.record(&first.id)
                .map(|held| held.accepted_hash.as_str()),
            Some(second.content_hash.as_str())
        );
    }

    #[test]
    fn a_baseline_that_was_never_written_holds_nothing() {
        let view = BaselineView::none();
        assert!(view.is_empty());
        assert!(view.coverage().is_empty());
        assert!(!view.carried_over());
    }
}
