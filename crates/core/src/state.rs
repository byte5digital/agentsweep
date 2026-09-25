//! The state file: what the daemon caches so a client can be answered at once.
//!
//! Findings derive from the Event Log and the current Scan and are never
//! stored as the truth (spec section 4.5). What `state.json` holds is the
//! derivation the daemon last made, so a client that asks a second after the
//! daemon started is answered without a Scan: the open Findings with the
//! moment each was first seen and the moment the user was told about it, the
//! last thirty Scan summaries, the protected folder classes that were readable
//! and the moment of the last Full Scan (spec section 6.5).
//!
//! The whole file carries one HMAC under the chain key, it is written to a
//! temporary file, flushed and renamed, and a file that is missing or does not
//! verify is rebuilt by the next Full Scan rather than read. There is no
//! SQLite and there is no second source of truth: everything here can be
//! derived again from the logs.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::envelope::{Timestamp, canonical, hex_to_bytes, hmac_sha256_hex, hmac_sha256_verify};
use crate::finding::{
    Category, FindingId, FindingState, RuleStatus, Severity, Source, Standing, Tier,
};
use crate::item::{ItemId, Kind};
use crate::keychain::{KeyError, KeySource};
use crate::paths::DataDirectory;
use crate::scan_pass::ScanKind;

/// How many Scan summaries the state file keeps (spec section 6.5).
pub const SCANS_KEPT: usize = 30;

/// What started one Scan. The closed list of spec section 6.4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trigger {
    /// The daemon started.
    DaemonStart,
    /// The last completed Full Scan is at least a day old.
    Due,
    /// The user asked for it.
    ScanNow,
    /// The watcher reported a change, a `Rescan` flag or an error.
    Watcher,
    /// A newer Rule Pack was accepted.
    RulePack,
    /// The user pointed at one folder before opening it with an Agent.
    Folder,
}

impl Trigger {
    /// Every trigger, in the order spec section 6.4 lists them.
    pub const ALL: [Trigger; 6] = [
        Trigger::DaemonStart,
        Trigger::Due,
        Trigger::ScanNow,
        Trigger::Watcher,
        Trigger::RulePack,
        Trigger::Folder,
    ];

    /// The spelling a summary carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Trigger::DaemonStart => "daemon-start",
            Trigger::Due => "due",
            Trigger::ScanNow => "scan-now",
            Trigger::Watcher => "watcher",
            Trigger::RulePack => "rule-pack",
            Trigger::Folder => "folder",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<Trigger> {
        Trigger::ALL
            .into_iter()
            .find(|trigger| trigger.as_str() == text)
    }
}

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One Scan as the state file remembers it (spec section 6.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanSummary {
    /// Which Scan kind ran.
    pub kind: ScanKind,
    /// What started it.
    pub trigger: Trigger,
    /// When it started.
    pub started_at: Timestamp,
    /// How long it took, in milliseconds.
    pub duration_ms: i64,
    /// How many Items it enumerated.
    pub items: usize,
    /// How many Threat Findings it raised.
    pub threats: usize,
    /// How many Exposure Findings it raised.
    pub exposures: usize,
    /// How many Items fell in the Clear Band.
    pub clear: usize,
    /// How many Items fell in the Ambiguous Band, which is the AI Judgement
    /// queue and carries no Finding.
    pub ambiguous: usize,
    /// How many Items fell in the Suspicious Band.
    pub suspicious: usize,
    /// The version of the Rule Pack that ran.
    pub rule_pack: u64,
    /// The Judgement Engine that was active, empty when there is none.
    pub engine: String,
}

impl ScanSummary {
    /// When the Scan finished.
    pub fn finished_at(&self) -> Timestamp {
        Timestamp::from_unix_ms(self.started_at.as_unix_ms() + self.duration_ms)
    }

    /// How many Findings of either category it raised.
    pub fn findings(&self) -> usize {
        self.threats + self.exposures
    }

    /// The summary as the state file carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("ambiguous".to_string(), Value::from(self.ambiguous as u64));
        map.insert("clear".to_string(), Value::from(self.clear as u64));
        map.insert("duration_ms".to_string(), Value::from(self.duration_ms));
        map.insert("engine".to_string(), Value::from(self.engine.as_str()));
        map.insert("exposures".to_string(), Value::from(self.exposures as u64));
        map.insert("items".to_string(), Value::from(self.items as u64));
        map.insert("kind".to_string(), Value::from(self.kind.as_str()));
        map.insert("rule_pack".to_string(), Value::from(self.rule_pack));
        map.insert(
            "started_at".to_string(),
            Value::from(self.started_at.to_string()),
        );
        map.insert(
            "suspicious".to_string(),
            Value::from(self.suspicious as u64),
        );
        map.insert("threats".to_string(), Value::from(self.threats as u64));
        map.insert("trigger".to_string(), Value::from(self.trigger.as_str()));
        Value::Object(map)
    }

    /// Reads back what [`ScanSummary::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<ScanSummary> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let count = |field: &str| value.get(field).and_then(Value::as_u64).map(|n| n as usize);
        Some(ScanSummary {
            kind: parse_scan_kind(text("kind")?)?,
            trigger: Trigger::parse(text("trigger")?)?,
            started_at: Timestamp::parse(text("started_at")?)?,
            duration_ms: value.get("duration_ms")?.as_i64()?,
            items: count("items")?,
            threats: count("threats")?,
            exposures: count("exposures")?,
            clear: count("clear")?,
            ambiguous: count("ambiguous")?,
            suspicious: count("suspicious")?,
            rule_pack: value.get("rule_pack")?.as_u64()?,
            engine: text("engine")?.to_string(),
        })
    }
}

/// Reads back the spelling [`ScanKind::as_str`] writes.
fn parse_scan_kind(text: &str) -> Option<ScanKind> {
    match text {
        "full" => Some(ScanKind::Full),
        "change" => Some(ScanKind::Change),
        "folder" => Some(ScanKind::Folder),
        _ => None,
    }
}

/// One Finding as the state file remembers it.
///
/// It is the Finding and where it stands, flattened to what a client renders,
/// with the two moments the daemon alone keeps: when it was first seen, and
/// when the user was told about it. The Finding itself is derived again by
/// every Scan; these two are not derivable and are why the file exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedFinding {
    /// The Finding's identity.
    pub id: FindingId,
    /// The Item it is about.
    pub item_id: ItemId,
    /// That Item's Surface kind.
    pub kind: Kind,
    /// What produced it, as [`Source`] renders itself.
    pub source: String,
    /// The Rule behind it, zero where no Rule applies.
    pub rule_id: i64,
    /// Threat or Exposure.
    pub category: Category,
    /// How bad it is if true.
    pub severity: Severity,
    /// Which Tier produced it.
    pub tier: Tier,
    /// Whether the Rule behind it is on Probation.
    pub status: RuleStatus,
    /// Where it stands.
    pub state: FindingState,
    /// The content hash it was made on.
    pub content_hash: String,
    /// The developer-facing one line.
    pub title: String,
    /// The one sentence the Simple Posture shows.
    pub plain: String,
    /// The file of a tree Item that carries the match, empty otherwise.
    pub file: String,
    /// The Drift context line, empty when the Item stands where the Baseline
    /// left it.
    pub drift: String,
    /// The Receipt that stopped it, empty unless it is stopped.
    pub receipt_id: String,
    /// The content hash of a newer version of a quarantined plugin that the
    /// last Scan found and raised no Threat Finding on, which is what offers
    /// Re-enable ("Fixed version available", spec section 5.4). Empty
    /// otherwise.
    pub fixed_version: String,
    /// When AgentSweep first saw it.
    pub first_seen: Timestamp,
    /// When the user was told about it, absent when they have not been.
    pub notified_at: Option<Timestamp>,
}

impl RecordedFinding {
    /// One standing Finding as the state file will carry it.
    pub fn of(standing: &Standing, first_seen: Timestamp) -> RecordedFinding {
        let finding = &standing.finding;
        RecordedFinding {
            id: standing.id.clone(),
            item_id: finding.item_id.clone(),
            kind: kind_of(standing),
            source: finding.source.to_string(),
            rule_id: match finding.source {
                Source::Rule(id) => id,
                _ => 0,
            },
            category: finding.category,
            severity: finding.severity,
            tier: finding.tier,
            status: finding.status,
            state: standing.state,
            content_hash: finding.content_hash.clone(),
            title: finding.title.clone(),
            plain: finding.plain.clone(),
            file: finding.file.clone(),
            drift: finding
                .drift
                .as_ref()
                .map(|drift| drift.line.clone())
                .unwrap_or_default(),
            receipt_id: standing.receipt_id.clone(),
            fixed_version: String::new(),
            first_seen,
            notified_at: None,
        }
    }

    /// The same record with the moment the user was told about it.
    pub fn notified(mut self, at: Option<Timestamp>) -> RecordedFinding {
        self.notified_at = at;
        self
    }

    /// True when the Finding still asks something of the user.
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    /// The record as the state file carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("category".to_string(), Value::from(self.category.as_str()));
        map.insert(
            "content_hash".to_string(),
            Value::from(self.content_hash.as_str()),
        );
        map.insert("drift".to_string(), Value::from(self.drift.as_str()));
        map.insert("file".to_string(), Value::from(self.file.as_str()));
        map.insert(
            "first_seen".to_string(),
            Value::from(self.first_seen.to_string()),
        );
        map.insert(
            "fixed_version".to_string(),
            Value::from(self.fixed_version.as_str()),
        );
        map.insert("id".to_string(), Value::from(self.id.as_str()));
        map.insert("item_id".to_string(), Value::from(self.item_id.as_str()));
        map.insert("kind".to_string(), Value::from(self.kind.as_str()));
        map.insert(
            "notified_at".to_string(),
            Value::from(
                self.notified_at
                    .map(|at| at.to_string())
                    .unwrap_or_default(),
            ),
        );
        map.insert("plain".to_string(), Value::from(self.plain.as_str()));
        map.insert(
            "receipt_id".to_string(),
            Value::from(self.receipt_id.as_str()),
        );
        map.insert("rule_id".to_string(), Value::from(self.rule_id));
        map.insert("severity".to_string(), Value::from(self.severity.as_str()));
        map.insert("source".to_string(), Value::from(self.source.as_str()));
        map.insert("state".to_string(), Value::from(self.state.as_str()));
        map.insert("status".to_string(), Value::from(self.status.as_str()));
        map.insert("tier".to_string(), Value::from(self.tier.as_str()));
        map.insert("title".to_string(), Value::from(self.title.as_str()));
        Value::Object(map)
    }

    /// Reads back what [`RecordedFinding::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<RecordedFinding> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let moment = |field: &str| -> Option<Option<Timestamp>> {
            match text(field)? {
                "" => Some(None),
                written => Timestamp::parse(written).map(Some),
            }
        };
        Some(RecordedFinding {
            id: FindingId::from_recorded(text("id")?),
            item_id: ItemId::from_recorded(text("item_id")?),
            kind: Kind::parse(text("kind")?)?,
            source: text("source")?.to_string(),
            rule_id: value.get("rule_id")?.as_i64()?,
            category: Category::parse(text("category")?)?,
            severity: Severity::parse(text("severity")?)?,
            tier: parse_tier(text("tier")?)?,
            status: RuleStatus::parse(text("status")?)?,
            state: FindingState::parse(text("state")?)?,
            content_hash: text("content_hash")?.to_string(),
            title: text("title")?.to_string(),
            plain: text("plain")?.to_string(),
            file: text("file")?.to_string(),
            drift: text("drift")?.to_string(),
            receipt_id: text("receipt_id")?.to_string(),
            // Absent in a state file written before Re-enable was offered,
            // which reads as no fixed version known.
            fixed_version: text("fixed_version").unwrap_or_default().to_string(),
            first_seen: Timestamp::parse(text("first_seen")?)?,
            notified_at: moment("notified_at")?,
        })
    }
}

/// The kind of the Item a standing Finding is about, read off its id.
///
/// The Finding carries the Item id rather than the Item, and the third segment
/// of an id names the kind. A Problem Finding whose id names no kind reads as
/// [`Kind::Generic`], which is the kind the core uses for what it has not
/// learned the specifics of.
fn kind_of(standing: &Standing) -> Kind {
    standing
        .id
        .as_str()
        .split('/')
        .find_map(|segment| {
            Kind::ALL
                .into_iter()
                .find(|kind| kind.id_segment() == segment)
        })
        .unwrap_or(Kind::Generic)
}

/// Reads back the label [`Tier::as_str`] prints.
fn parse_tier(text: &str) -> Option<Tier> {
    match text {
        "T0" => Some(Tier::Allowlist),
        "T1" => Some(Tier::Rules),
        "T2" => Some(Tier::Heuristics),
        "T3" => Some(Tier::AiJudgement),
        _ => None,
    }
}

/// Everything the state file holds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    /// The Findings the last Scan left standing, open ones and all.
    pub findings: Vec<RecordedFinding>,
    /// The last thirty Scan summaries, oldest first.
    pub scans: Vec<ScanSummary>,
    /// The protected folder classes AgentSweep has read successfully before,
    /// so it never makes the first read into one by itself.
    pub readable_classes: BTreeSet<String>,
    /// When the last Full Scan finished.
    pub last_full_scan: Option<Timestamp>,
}

impl State {
    /// A state nothing is known in yet, which is what a rebuild starts from.
    pub fn empty() -> State {
        State::default()
    }

    /// The Findings that still ask something of the user.
    pub fn open(&self) -> impl Iterator<Item = &RecordedFinding> {
        self.findings.iter().filter(|finding| finding.is_open())
    }

    /// How many Findings are open.
    pub fn open_count(&self) -> usize {
        self.open().count()
    }

    /// When AgentSweep first saw this Finding, if it has seen it before.
    pub fn first_seen(&self, id: &FindingId) -> Option<Timestamp> {
        self.findings
            .iter()
            .find(|finding| &finding.id == id)
            .map(|finding| finding.first_seen)
    }

    /// When the user was told about this Finding, if they have been.
    pub fn notified_at(&self, id: &FindingId) -> Option<Timestamp> {
        self.findings
            .iter()
            .find(|finding| &finding.id == id)
            .and_then(|finding| finding.notified_at)
    }

    /// The most recent Scan summary.
    pub fn last_scan(&self) -> Option<&ScanSummary> {
        self.scans.last()
    }

    /// Takes one more Scan summary, keeping the last [`SCANS_KEPT`].
    pub fn record_scan(&mut self, summary: ScanSummary) {
        if summary.kind == ScanKind::Full {
            self.last_full_scan = Some(summary.finished_at());
        }
        self.scans.push(summary);
        if self.scans.len() > SCANS_KEPT {
            let excess = self.scans.len() - SCANS_KEPT;
            self.scans.drain(..excess);
        }
    }

    /// The state as the file carries it, without the MAC around it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "findings".to_string(),
            Value::Array(
                self.findings
                    .iter()
                    .map(RecordedFinding::to_value)
                    .collect(),
            ),
        );
        map.insert(
            "last_full_scan".to_string(),
            Value::from(
                self.last_full_scan
                    .map(|at| at.to_string())
                    .unwrap_or_default(),
            ),
        );
        map.insert(
            "readable_classes".to_string(),
            Value::Array(
                self.readable_classes
                    .iter()
                    .map(|class| Value::from(class.as_str()))
                    .collect(),
            ),
        );
        map.insert(
            "scans".to_string(),
            Value::Array(self.scans.iter().map(ScanSummary::to_value).collect()),
        );
        Value::Object(map)
    }

    /// Reads back what [`State::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<State> {
        let findings = value
            .get("findings")?
            .as_array()?
            .iter()
            .map(RecordedFinding::from_value)
            .collect::<Option<Vec<_>>>()?;
        let scans = value
            .get("scans")?
            .as_array()?
            .iter()
            .map(ScanSummary::from_value)
            .collect::<Option<Vec<_>>>()?;
        let readable_classes = value
            .get("readable_classes")?
            .as_array()?
            .iter()
            .map(|class| class.as_str().map(str::to_string))
            .collect::<Option<BTreeSet<_>>>()?;
        let last_full_scan = match value.get("last_full_scan")?.as_str()? {
            "" => None,
            written => Some(Timestamp::parse(written)?),
        };
        Some(State {
            findings,
            scans,
            readable_classes,
            last_full_scan,
        })
    }
}

/// Why the state file could not be read or written.
#[derive(Debug)]
pub enum StateError {
    /// There is no state file, which is every first start.
    Missing,
    /// The file could not be read or written.
    Io(io::Error),
    /// The key could not be read or stored.
    Key(KeyError),
    /// The file is there and its whole-file MAC is not the one the key in hand
    /// produces.
    MacFailed,
    /// The file is there and is not a state file.
    Malformed(String),
}

impl StateError {
    /// True when the next Full Scan is to rebuild the file rather than read
    /// it. Everything but an input or output failure is.
    pub fn rebuilds(&self) -> bool {
        !matches!(self, StateError::Io(_) | StateError::Key(_))
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Missing => f.write_str("there is no state file yet"),
            StateError::Io(error) => write!(f, "the state file could not be used: {error}"),
            StateError::Key(error) => write!(f, "{error}"),
            StateError::MacFailed => f.write_str("the state file does not verify"),
            StateError::Malformed(detail) => write!(f, "the state file is malformed: {detail}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<io::Error> for StateError {
    fn from(error: io::Error) -> StateError {
        StateError::Io(error)
    }
}

impl From<KeyError> for StateError {
    fn from(error: KeyError) -> StateError {
        StateError::Key(error)
    }
}

/// The state file, `state.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    /// The state file at this path.
    pub fn at(path: impl Into<PathBuf>) -> StateFile {
        StateFile { path: path.into() }
    }

    /// The state file of a data directory.
    pub fn in_data_directory(directory: &DataDirectory) -> StateFile {
        StateFile::at(directory.state_file())
    }

    /// Where it is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the file and verifies its whole-file MAC.
    ///
    /// A missing file, a file that is not a state file and a file whose MAC
    /// does not verify are all reported rather than repaired: the daemon shows
    /// the note and the next Full Scan writes a fresh one (spec section 6.5).
    pub fn read(&self, keys: &dyn KeySource) -> Result<State, StateError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StateError::Missing);
            }
            Err(error) => return Err(StateError::Io(error)),
        };
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|error| StateError::Malformed(error.to_string()))?;
        let mac = document
            .get("mac")
            .and_then(Value::as_str)
            .ok_or_else(|| StateError::Malformed("no mac".to_string()))?;
        let state = document
            .get("state")
            .ok_or_else(|| StateError::Malformed("no state".to_string()))?;

        let Some(key) = keys.load()? else {
            // No key can vouch for the file, which is the key-missing state.
            // The records are not read under another key: they are rebuilt.
            return Err(StateError::MacFailed);
        };
        let Some(expected) = hex_to_bytes(mac) else {
            return Err(StateError::Malformed("the mac is not hex".to_string()));
        };
        if !hmac_sha256_verify(&key, &canonical(state), &expected) {
            return Err(StateError::MacFailed);
        }
        State::from_value(state)
            .ok_or_else(|| StateError::Malformed("the state is not readable".to_string()))
    }
}

#[cfg(feature = "daemon")]
pub use writer::StateWriter;

#[cfg(feature = "daemon")]
mod writer {
    use super::{State, StateError, StateFile, canonical, hmac_sha256_hex};

    use std::io::Write as _;

    use serde_json::{Map, Value};

    use crate::keychain::KeySource;

    /// The write side of the state file.
    ///
    /// The daemon is the only writer (spec section 6.2), which this type
    /// carries: it exists only in a build with the `daemon` feature, so the
    /// application and the command line interface cannot compile a call that
    /// writes `state.json`.
    #[derive(Debug)]
    pub struct StateWriter;

    impl StateWriter {
        /// Writes the state atomically: a temporary file beside the real one,
        /// flushed to the disk, then renamed over it.
        ///
        /// The rename is what makes it atomic, and the flush before it is what
        /// keeps a power cut from leaving a file that is named right and is
        /// empty. The file is created 0600 and the whole of it carries one
        /// HMAC under the chain key.
        pub fn write(
            file: &StateFile,
            keys: &dyn KeySource,
            state: &State,
        ) -> Result<(), StateError> {
            let key = match keys.load()? {
                Some(key) => key,
                None => keys.renew()?,
            };
            let body = state.to_value();
            let mut document = Map::new();
            document.insert(
                "mac".to_string(),
                Value::from(hmac_sha256_hex(&key, &canonical(&body))),
            );
            document.insert("state".to_string(), body);
            let bytes = canonical(&Value::Object(document));

            let path = file.path();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
            let mut handle = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                handle.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            handle.write_all(&bytes)?;
            handle.sync_all()?;
            drop(handle);
            std::fs::rename(&temporary, path)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    use crate::finding::Finding;
    use crate::keychain::MemoryKeySource;

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    fn summary(trigger: Trigger, at: &str) -> ScanSummary {
        ScanSummary {
            kind: ScanKind::Full,
            trigger,
            started_at: moment(at),
            duration_ms: 1_234,
            items: 42,
            threats: 1,
            exposures: 2,
            clear: 39,
            ambiguous: 2,
            suspicious: 1,
            rule_pack: 7,
            engine: String::new(),
        }
    }

    fn standing() -> Standing {
        let finding = Finding {
            item_id: ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/setup"),
            source: Source::Rule(1),
            content_hash: "a".repeat(64),
            category: Category::Threat,
            severity: Severity::Critical,
            tier: Tier::Rules,
            status: RuleStatus::Probation,
            title: "A skill that pipes a download into a shell".to_string(),
            plain: "This skill downloads and runs a script.".to_string(),
            sensitive: false,
            file: "SKILL.md".to_string(),
            matches: Vec::new(),
            heuristics: Vec::new(),
            drift: None,
        };
        Standing {
            id: FindingId::of(&finding),
            finding,
            state: FindingState::Open,
            receipt_id: String::new(),
        }
    }

    /// A state with one of everything in it, so a round trip proves the whole
    /// form rather than an empty object.
    fn a_state() -> State {
        let mut state = State::empty();
        state.findings.push(RecordedFinding::of(
            &standing(),
            moment("2026-09-01T09:00:00.000Z"),
        ));
        state.record_scan(summary(Trigger::DaemonStart, "2026-09-24T08:00:00.000Z"));
        state.readable_classes.insert("documents".to_string());
        state
    }

    #[test]
    fn a_state_file_round_trips_through_its_own_form() {
        let state = a_state();
        assert_eq!(State::from_value(&state.to_value()), Some(state));
    }

    /// The Item's kind is read off the Item id, because a Finding carries the
    /// id and not the Item. Trust is bound to a kind, so getting this wrong
    /// would offer the wrong action.
    #[test]
    fn a_recorded_finding_names_the_kind_of_the_item_it_is_about() {
        let recorded = RecordedFinding::of(&standing(), moment("2026-09-01T09:00:00.000Z"));
        assert_eq!(recorded.kind, Kind::Skill);
        assert_eq!(recorded.source, "rule 0001");
        assert_eq!(recorded.rule_id, 1);
        assert!(recorded.is_open());
    }

    #[test]
    fn the_state_file_keeps_the_last_thirty_scan_summaries() {
        let mut state = State::empty();
        for minute in 0..35 {
            state.record_scan(summary(
                Trigger::Due,
                &format!("2026-09-24T08:{minute:02}:00.000Z"),
            ));
        }
        assert_eq!(state.scans.len(), SCANS_KEPT);
        assert_eq!(
            state.scans[0].started_at,
            moment("2026-09-24T08:05:00.000Z")
        );
        assert_eq!(
            state.last_scan().expect("a last Scan").started_at,
            moment("2026-09-24T08:34:00.000Z")
        );
    }

    #[test]
    fn a_full_scan_summary_moves_the_last_full_scan_moment() {
        let mut state = State::empty();
        assert_eq!(state.last_full_scan, None);
        state.record_scan(summary(Trigger::DaemonStart, "2026-09-24T08:00:00.000Z"));
        assert_eq!(
            state.last_full_scan,
            Some(moment("2026-09-24T08:00:01.234Z"))
        );
    }

    /// A Folder Scan records nothing, so it never moves the last Full Scan
    /// moment even though its summary is kept for the Activity.
    #[test]
    fn a_folder_scan_summary_does_not_move_the_last_full_scan_moment() {
        let mut state = State::empty();
        let mut folder = summary(Trigger::Folder, "2026-09-24T08:00:00.000Z");
        folder.kind = ScanKind::Folder;
        state.record_scan(folder);
        assert_eq!(state.last_full_scan, None);
    }

    #[test]
    fn every_trigger_reads_back_the_spelling_it_writes() {
        for trigger in Trigger::ALL {
            assert_eq!(Trigger::parse(trigger.as_str()), Some(trigger));
        }
    }

    #[test]
    fn a_missing_state_file_is_reported_rather_than_invented() {
        let temporary = TempDir::new().expect("a temporary directory");
        let file = StateFile::at(temporary.path().join("state.json"));
        let keys = MemoryKeySource::empty();
        let error = file.read(&keys).expect_err("no state file yet");
        assert!(matches!(error, StateError::Missing), "{error}");
        assert!(error.rebuilds());
    }

    #[cfg(feature = "daemon")]
    mod writing {
        use super::*;

        use crate::keychain::ChainKey;

        #[test]
        fn a_written_state_file_is_read_back_whole() {
            let temporary = TempDir::new().expect("a temporary directory");
            let directory = DataDirectory::at(temporary.path());
            let file = StateFile::in_data_directory(&directory);
            let keys = MemoryKeySource::empty();

            let state = a_state();
            StateWriter::write(&file, &keys, &state).expect("a written state file");
            assert_eq!(file.read(&keys).expect("a readable state file"), state);
        }

        /// One byte of the file is enough: the MAC covers the whole of it.
        #[test]
        fn an_edited_state_file_does_not_verify() {
            let temporary = TempDir::new().expect("a temporary directory");
            let file = StateFile::at(temporary.path().join("state.json"));
            let keys = MemoryKeySource::empty();
            StateWriter::write(&file, &keys, &a_state()).expect("a written state file");

            let written = std::fs::read_to_string(file.path()).expect("a readable state file");
            let edited = written.replace("\"items\":42", "\"items\":41");
            assert_ne!(edited, written, "the field the edit moves is in the file");
            std::fs::write(file.path(), edited).expect("an edited state file");

            let error = file.read(&keys).expect_err("the edit is caught");
            assert!(matches!(error, StateError::MacFailed), "{error}");
            assert!(error.rebuilds());
        }

        /// The key is the one both chains use. A state file written under
        /// another one is rebuilt rather than believed.
        #[test]
        fn a_state_file_from_another_key_does_not_verify() {
            let temporary = TempDir::new().expect("a temporary directory");
            let file = StateFile::at(temporary.path().join("state.json"));
            let mine = MemoryKeySource::empty();
            StateWriter::write(&file, &mine, &a_state()).expect("a written state file");

            let theirs = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
            let error = file.read(&theirs).expect_err("another key does not verify");
            assert!(matches!(error, StateError::MacFailed), "{error}");
        }

        /// The write is a rename over the old file, so a reader either sees
        /// the state before it or the state after it and never half of either.
        #[test]
        fn writing_the_state_leaves_no_temporary_file_behind() {
            let temporary = TempDir::new().expect("a temporary directory");
            let directory = DataDirectory::at(temporary.path());
            let file = StateFile::in_data_directory(&directory);
            let keys = MemoryKeySource::empty();
            StateWriter::write(&file, &keys, &a_state()).expect("a written state file");
            StateWriter::write(&file, &keys, &State::empty()).expect("a second state file");

            let left: Vec<String> = std::fs::read_dir(directory.root())
                .expect("a readable data directory")
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .collect();
            assert_eq!(left, vec!["state.json".to_string()], "{left:?}");
        }

        /// Nobody but the user may read what the daemon cached: a Finding
        /// names Item ids and paths.
        #[cfg(unix)]
        #[test]
        fn the_state_file_is_readable_by_the_user_alone() {
            use std::os::unix::fs::PermissionsExt;

            let temporary = TempDir::new().expect("a temporary directory");
            let file = StateFile::at(temporary.path().join("state.json"));
            let keys = MemoryKeySource::empty();
            StateWriter::write(&file, &keys, &a_state()).expect("a written state file");

            let mode = std::fs::metadata(file.path())
                .expect("a state file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
    }
}
