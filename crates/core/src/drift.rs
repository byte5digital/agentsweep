//! Drift: what changed without a known action behind it, and when that is
//! worth a question.
//!
//! Drift is a condition on every Item and context on any Finding about it
//! ("changed since your last Scan on <date>"). It raises a Finding of its own
//! only on the user's own executable configuration, and only in the rows of
//! the table in spec section 4.6.5. Everywhere else the condition is a fact
//! the Heuristic tier weighs and a Scan that leaves the Item without a Finding
//! accepts the new content.
//!
//! Nothing here infers who wrote anything (ADR 0007). The decision is a pure
//! function of the [`BaselineRecord`] the last Scan left and the Item this one
//! enumerated: the known actions have already been applied, so an Item
//! AgentSweep wrote itself, one whose content carries Trust and one the user
//! acknowledged arrive reading `unchanged` and are never Drift.
//!
//! A Drift Finding is a Threat at T2 with Severity high that is never
//! quarantined automatically and never quarantined by Drift alone. When
//! another Threat Finding is open on the Item, the question folds into that
//! Finding as its context line and no standalone Finding exists: resolving
//! that Finding settles the Drift.
//!
//! The write side of the answer is [`Acknowledgement`], which advances the
//! accepted hash as a compare-and-swap on the last-seen hash and does nothing
//! else. Acknowledge is not Trust: every Tier still scans the content and a
//! later Rule Pack may still flag it.

use std::collections::{BTreeMap, BTreeSet};

use crate::adapter::{Descriptor, Problem, ProblemReason};
use crate::baseline::{BaselineRecord, ManifestFile, field_hashes};
use crate::envelope::Timestamp;
use crate::finding::{Category, Finding, RuleStatus, Severity, Source, Tier};
use crate::item::{Activation, BaselineState, Item, ItemId, Kind, Provenance, Shape};
use crate::views::ParsedView;

/// The developer-facing one line of a Drift Finding.
pub const DRIFT_TITLE: &str =
    "The user's own executable configuration moved without a known action";

/// The one sentence the Simple Posture shows above the detail. It asks the one
/// question AgentSweep can answer neither way.
pub const DRIFT_PLAIN: &str = "Something that runs when the agent starts changed, and AgentSweep has no record of \
     doing it. Was that you?";

/// What the Activity keeps when content comes back to the hash that was
/// accepted, which closes a Drift Finding by itself (spec section 4.6.4).
pub const CHANGED_BACK: &str = "changed back";

/// How the Item stands against its Baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    /// First seen under existing coverage.
    Added,
    /// The hash differs from the accepted one.
    Changed,
    /// A path the Baseline had readable could not be read or parsed this time.
    Unreadable(ProblemReason),
}

impl Change {
    /// The spelling a record and the command line interface carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Added => "added",
            Change::Changed => "changed",
            Change::Unreadable(_) => "unreadable",
        }
    }
}

/// How one Item stands against its Baseline, as a Finding carries it.
///
/// This is the context line on any Finding about the Item and, on a Finding
/// whose source is [`Source::Drift`], the Finding itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Drift {
    /// What moved.
    pub change: Change,
    /// When the accepted form was accepted, which the line reads back. Absent
    /// where nothing was ever accepted.
    pub since: Option<Timestamp>,
    /// The hash AgentSweep last accepted, empty for an Item that is `added`.
    pub accepted_hash: String,
    /// The hash on screen, which an Acknowledge compares against.
    pub last_seen_hash: String,
    /// The line the user reads.
    pub line: String,
    /// What differs: the files of a tree, the fields of an entry.
    pub detail: Vec<String>,
}

impl Drift {
    /// The Drift the Item stands in, or nothing when it stands where the
    /// Baseline left it.
    ///
    /// This is the condition, not the question: every Item of every kind and
    /// Scope answers it, and [`decide`] says which of them is worth asking the
    /// user about.
    pub fn of(item: &Item, record: Option<&BaselineRecord>) -> Option<Drift> {
        let change = match item.baseline {
            BaselineState::Added => Change::Added,
            BaselineState::Changed => Change::Changed,
            BaselineState::Unchanged | BaselineState::None => return None,
        };
        let detail = match record {
            Some(held) => differences(held, item),
            None => Vec::new(),
        };
        let since = record.map(|held| held.accepted_at);
        Some(Drift {
            change,
            since,
            accepted_hash: record
                .map(|held| held.accepted_hash.clone())
                .unwrap_or_default(),
            last_seen_hash: item.content_hash.clone(),
            line: line_for(change, since),
            detail,
        })
    }

    /// The Drift a Problem on a path the Baseline had readable stands for.
    pub fn of_problem(problem: &Problem, record: &BaselineRecord) -> Drift {
        let change = Change::Unreadable(problem.reason);
        Drift {
            change,
            since: Some(record.accepted_at),
            accepted_hash: record.accepted_hash.clone(),
            last_seen_hash: record.last_seen_hash.clone(),
            line: line_for(change, Some(record.accepted_at)),
            detail: vec![problem.path.display().to_string()],
        }
    }
}

/// The context line, which reads back the date the accepted form was accepted
/// on.
fn line_for(change: Change, since: Option<Timestamp>) -> String {
    let when = match since {
        Some(at) => format!(" on {}", at.day()),
        None => String::new(),
    };
    match change {
        Change::Added => format!("new since your last Scan{when}"),
        Change::Changed => format!("changed since your last Scan{when}"),
        Change::Unreadable(reason) => {
            format!(
                "could not be read this time, and was readable{when} ({})",
                reason.as_str()
            )
        }
    }
}

/// What differs between the accepted form and the Item in hand: the files of a
/// tree, the fields of an entry, and nothing at all for a file, whose bytes
/// are the whole of it.
fn differences(record: &BaselineRecord, item: &Item) -> Vec<String> {
    match item.shape {
        Shape::Tree => changed_files(&record.accepted_manifest, &ManifestFile::of(item)),
        Shape::Entry => changed_fields(&record.accepted_fields, &field_hashes(item)),
        Shape::File => Vec::new(),
    }
}

/// The files of a tree that appeared, vanished or changed, in path order.
fn changed_files(accepted: &[ManifestFile], seen: &[ManifestFile]) -> Vec<String> {
    let held: BTreeMap<&str, &str> = accepted
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    let now: BTreeMap<&str, &str> = seen
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    names.extend(held.keys().copied());
    names.extend(now.keys().copied());
    names
        .into_iter()
        .filter(|path| held.get(path) != now.get(path))
        .map(|path| path.to_string())
        .collect()
}

/// The top-level fields of an entry whose hash moved, in sorted order.
fn changed_fields(
    accepted: &BTreeMap<String, String>,
    seen: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    names.extend(accepted.keys().map(String::as_str));
    names.extend(seen.keys().map(String::as_str));
    names
        .into_iter()
        .filter(|name| accepted.get(*name) != seen.get(*name))
        .map(|name| name.to_string())
        .collect()
}

/// The settings keys each Agent writes for itself, as its Surface Adapter
/// declares them.
///
/// Spec section 4.6.5 keeps the Items an Agent writes itself out of Drift, and
/// the two that are Items rather than internal records are keyed rather than
/// stamped: Claude Code's `permissions.allow` grows on every "always allow"
/// and is a declared executing key all the same. The core never hardcodes an
/// Agent's key: the declaration comes off the [`Descriptor`].
#[derive(Clone, Debug, Default)]
pub struct Declarations {
    by_agent: BTreeMap<String, Vec<String>>,
}

impl Declarations {
    /// Nothing is declared, which is what a Scan without an adapter table runs
    /// against.
    pub fn none() -> Declarations {
        Declarations::default()
    }

    /// The declarations of every adapter in one place.
    pub fn of(descriptors: &[Descriptor]) -> Declarations {
        descriptors
            .iter()
            .fold(Declarations::none(), |declared, descriptor| {
                declared.and(descriptor)
            })
    }

    /// The same declarations with one more adapter's added.
    pub fn and(mut self, descriptor: &Descriptor) -> Declarations {
        self.by_agent.insert(
            descriptor.agent.to_string(),
            descriptor
                .agent_written_keys
                .iter()
                .map(|key| (*key).to_string())
                .collect(),
        );
        self
    }

    /// True when this Agent writes this settings key for itself, so a change
    /// to it is never a question for the user.
    pub fn agent_writes(&self, agent: &str, key_path: &str) -> bool {
        let Some(keys) = self.by_agent.get(agent) else {
            return false;
        };
        keys.iter().any(|declared| {
            key_path == declared
                || (key_path.starts_with(declared.as_str())
                    && key_path.as_bytes().get(declared.len()) == Some(&b'.'))
        })
    }
}

/// The kinds a Drift Finding is ever raised for (spec section 4.6.5). Every
/// other kind still carries the condition and still sets `item.baseline`.
pub const ASKED_ABOUT: [Kind; 6] = [
    Kind::Hook,
    Kind::McpServer,
    Kind::SettingsEntry,
    Kind::ExecPolicy,
    Kind::Plugin,
    Kind::Marketplace,
];

/// What one plugin's registry record did between two Scans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Update {
    /// The record moved as a whole: a new version, a new install path, the
    /// commit it records. One Activity line, no Finding.
    Consistent {
        /// The version the Baseline had accepted, empty where none was
        /// recorded.
        from: String,
        /// The version the install registry points at now.
        to: String,
    },
    /// The files under the version directory moved and the record did not,
    /// which is the question worth asking.
    InPlace,
    /// Nothing moved that a Drift decision reads.
    None,
}

/// The fact name a plugin's version is remembered under.
pub const VERSION: &str = "version";

/// The fact name a plugin's install directory is remembered under.
pub const INSTALL_PATH: &str = "install_path";

/// The fact name the commit an install registry records is remembered under.
pub const COMMIT: &str = "commit";

/// The fact name a marketplace's source is remembered under.
pub const SOURCE: &str = "source";

/// What a plugin's registry record did between the accepted form and this one.
///
/// A **consistent update** is the registry record moving as a whole: a new
/// version directory, and every fact that was recorded on both sides moving
/// with it. That raises no question, only an Activity line. A tree that moved
/// under an unchanged record is the MCPoison shape one level up, and that is
/// the question.
pub fn update_of(record: &BaselineRecord, item: &Item) -> Update {
    let held = |name: &str| record.accepted_facts.get(name).cloned().unwrap_or_default();
    let seen = |name: &str| item.baseline_facts.get(name).cloned().unwrap_or_default();
    let moved = |name: &str| {
        let (before, after) = (held(name), seen(name));
        !before.is_empty() && !after.is_empty() && before != after
    };
    let stood_still = |name: &str| {
        let (before, after) = (held(name), seen(name));
        !before.is_empty() && !after.is_empty() && before == after
    };
    if record.accepted_hash == item.content_hash {
        return Update::None;
    }
    // A new version directory is what an update looks like on disk, and
    // nothing that was recorded on both sides may have stayed behind.
    let recorded = [VERSION, INSTALL_PATH, COMMIT];
    if moved(INSTALL_PATH) && !recorded.iter().any(|name| stood_still(name)) {
        return Update::Consistent {
            from: held(VERSION),
            to: seen(VERSION),
        };
    }
    Update::InPlace
}

/// Everything a Drift decision needs beside the Item and its Baseline record.
#[derive(Clone, Copy, Debug)]
pub struct Watched<'a> {
    /// The settings keys each Agent writes for itself.
    pub declarations: &'a Declarations,
    /// The marketplaces a Drift Finding is open on. While one stands, no
    /// plugin update from that marketplace counts as consistent (spec section
    /// 4.6.5).
    pub unsettled_marketplaces: &'a BTreeSet<String>,
}

impl Watched<'_> {
    /// True when this plugin came from a marketplace whose own Drift question
    /// is still open.
    fn marketplace_unsettled(&self, item: &Item) -> bool {
        match &item.provenance {
            Provenance::Marketplace { name, .. } => self.unsettled_marketplaces.contains(name),
            _ => false,
        }
    }
}

/// What a Scan does about one Item's Drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Nothing moved, or nothing that this kind is ever asked about.
    Silent,
    /// The user is asked whether the change was theirs.
    Ask,
    /// The registry record moved as a whole: one Activity line, no question.
    Updated {
        /// The version that was accepted.
        from: String,
        /// The version in use now.
        to: String,
    },
}

/// Whether this Item's Drift is worth a question, in the rows of the table of
/// spec section 4.6.5.
///
/// Only User Scope, only an active Item, only the six kinds of [`ASKED_ABOUT`],
/// never an Item the Agent writes itself, and never an Item whose state is
/// `none`, which is what a first Scan and a Folder Scan see.
pub fn decide(
    item: &Item,
    state: BaselineState,
    record: Option<&BaselineRecord>,
    watched: Watched<'_>,
) -> Decision {
    if item.scope != crate::item::Scope::User || item.activation != Activation::Active {
        return Decision::Silent;
    }
    if !ASKED_ABOUT.contains(&item.kind) {
        return Decision::Silent;
    }
    if item.provenance == Provenance::AgentWritten {
        return Decision::Silent;
    }
    let change = match state {
        BaselineState::Added => Change::Added,
        BaselineState::Changed => Change::Changed,
        BaselineState::Unchanged | BaselineState::None => return Decision::Silent,
    };
    match item.kind {
        Kind::Hook | Kind::McpServer | Kind::ExecPolicy => Decision::Ask,
        Kind::SettingsEntry => match settings_key(item) {
            // The Agent's own record of what the user allowed is not a
            // question anybody can answer, and both Agents write one.
            Some(key) if watched.declarations.agent_writes(&item.agent, &key) => Decision::Silent,
            // A settings key is an Item at all only because its adapter
            // declared it executing or redirecting (spec section 3.5).
            Some(_) => Decision::Ask,
            None => Decision::Silent,
        },
        Kind::Plugin => match (change, record) {
            (Change::Added, _) => Decision::Ask,
            (_, None) => Decision::Ask,
            (_, Some(held)) => match update_of(held, item) {
                Update::Consistent { .. } if watched.marketplace_unsettled(item) => Decision::Ask,
                Update::Consistent { from, to } => Decision::Updated { from, to },
                Update::InPlace => Decision::Ask,
                Update::None => Decision::Silent,
            },
        },
        // A fetch rewrites every clone, so the tree is not the question. Where
        // the marketplace points is.
        Kind::Marketplace => match (change, record) {
            (Change::Added, _) => Decision::Ask,
            (_, None) => Decision::Ask,
            (_, Some(held)) => match source_moved(held, item) {
                true => Decision::Ask,
                false => Decision::Silent,
            },
        },
        _ => Decision::Silent,
    }
}

/// True when a marketplace points somewhere else than the Baseline accepted.
fn source_moved(record: &BaselineRecord, item: &Item) -> bool {
    let accepted = record.accepted_facts.get(SOURCE);
    let seen = item.baseline_facts.get(SOURCE);
    match (accepted, seen) {
        (Some(before), Some(after)) => before != after,
        // Nothing was ever recorded about where it points, so nothing about
        // the clone's own bytes is a reason to ask.
        _ => false,
    }
}

/// The dotted settings key one settings entry is about.
fn settings_key(item: &Item) -> Option<String> {
    match &item.view {
        ParsedView::Settings(view) => Some(view.key_path.clone()),
        _ => None,
    }
}

/// The Drift Finding one Item raises: a Threat at T2, Severity fixed at high,
/// source `drift`, never quarantined automatically (spec section 4.6.5).
pub fn finding(item: &Item, drift: &Drift) -> Finding {
    Finding {
        item_id: item.id.clone(),
        source: Source::Drift,
        content_hash: item.content_hash.clone(),
        category: Category::Threat,
        severity: Severity::High,
        tier: Tier::Heuristics,
        status: RuleStatus::Stable,
        title: DRIFT_TITLE.to_string(),
        plain: DRIFT_PLAIN.to_string(),
        sensitive: false,
        file: drift.detail.first().cloned().unwrap_or_default(),
        matches: Vec::new(),
        heuristics: Vec::new(),
        drift: Some(drift.clone()),
    }
}

/// The Drift Finding a Problem on a path the Baseline had readable raises.
pub fn finding_of_problem(record: &BaselineRecord, drift: &Drift) -> Finding {
    Finding {
        item_id: record.item_id.clone(),
        source: Source::Drift,
        content_hash: record.accepted_hash.clone(),
        category: Category::Threat,
        severity: Severity::High,
        tier: Tier::Heuristics,
        status: RuleStatus::Stable,
        title: DRIFT_TITLE.to_string(),
        plain: DRIFT_PLAIN.to_string(),
        sensitive: false,
        file: String::new(),
        matches: Vec::new(),
        heuristics: Vec::new(),
        drift: Some(drift.clone()),
    }
}

/// Whether a Problem stands on a path the Baseline had readable, which is the
/// last row of the table (spec section 4.6.5).
///
/// The Baseline remembers the path each Item was read from, so the question is
/// asked of the record rather than guessed from the Item id. A record that was
/// already absent says nothing: what is gone is not what stopped being
/// readable.
pub fn was_readable(record: &BaselineRecord, problem: &Problem) -> bool {
    if problem.reason == ProblemReason::Unsupported {
        return false;
    }
    if record.state.is_absent() || !record.item_id.is_user() {
        return false;
    }
    record.path == problem.path.display().to_string()
}

/// A line the Activity keeps that is not a Finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Note {
    /// The Item it is about.
    pub item_id: ItemId,
    /// Its Surface kind.
    pub kind: Kind,
    /// The line itself, free of content and of sensitive values.
    pub line: String,
}

impl Note {
    /// The line a consistent plugin update leaves: no question, and no silence
    /// either.
    pub fn updated(item: &Item, from: &str, to: &str) -> Note {
        let name = plugin_name(item);
        let line = match (from.is_empty(), to.is_empty()) {
            (false, false) => format!("Plugin {name} updated {from} to {to}"),
            _ => format!("Plugin {name} updated"),
        };
        Note {
            item_id: item.id.clone(),
            kind: item.kind,
            line,
        }
    }

    /// The line content coming back to the accepted hash leaves, which closes
    /// an open Drift Finding by itself.
    pub fn changed_back(item: &Item) -> Note {
        Note {
            item_id: item.id.clone(),
            kind: item.kind,
            line: CHANGED_BACK.to_string(),
        }
    }
}

/// The marketplace one Item is or came from, by the name it locates under
/// (spec section 4.6.1).
pub fn marketplace_name(item: &Item) -> String {
    match &item.provenance {
        Provenance::Marketplace { name, .. } if !name.is_empty() => name.clone(),
        _ => item.locator().to_string(),
    }
}

/// The plugin's own name, which is everything before the marketplace.
fn plugin_name(item: &Item) -> String {
    match &item.view {
        ParsedView::Plugin(view) if !view.name.is_empty() => view.name.clone(),
        _ => item.locator().to_string(),
    }
}

#[cfg(feature = "daemon")]
pub use writer::{AcknowledgeError, Acknowledged, Acknowledgement};

#[cfg(feature = "daemon")]
mod writer {
    use std::fmt;

    use super::*;

    use crate::baseline::{Baseline, BaselineView, BaselineWriter};
    use crate::chain::{ChainError, ChainState};
    use crate::eventlog::{Action, Actor, Event, EventLog, EventLogWriter};
    use crate::keychain::KeySource;
    use crate::paths::DataDirectory;

    /// Why an Acknowledge did not happen.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum AcknowledgeError {
        /// The Baseline holds no record for that Item, so there is nothing to
        /// advance and nothing was ever asked about.
        Unknown(ItemId),
        /// The Item moved on since the question was put on screen. Nothing is
        /// accepted; the Finding refreshes and asks again (spec section
        /// 4.6.5).
        Stale {
            /// The hash the caller answered about.
            answered: String,
            /// The hash the Item stands at now, which the refreshed Finding
            /// carries.
            last_seen: String,
        },
        /// A chain could not be read or written.
        Chain(String),
    }

    impl fmt::Display for AcknowledgeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                AcknowledgeError::Unknown(item_id) => {
                    write!(f, "the Baseline holds no record for {item_id}")
                }
                AcknowledgeError::Stale { .. } => f.write_str(
                    "this item changed again while the question was on screen, so nothing was \
                     accepted",
                ),
                AcknowledgeError::Chain(detail) => f.write_str(detail),
            }
        }
    }

    impl std::error::Error for AcknowledgeError {}

    impl From<ChainError> for AcknowledgeError {
        fn from(error: ChainError) -> AcknowledgeError {
            AcknowledgeError::Chain(error.to_string())
        }
    }

    /// What one Acknowledge left behind.
    #[derive(Clone, Debug)]
    pub struct Acknowledged {
        /// The Baseline record as it now stands.
        pub record: BaselineRecord,
        /// Where the Event Log record sits, which the Baseline record names.
        pub event: String,
    }

    /// The user's answer that a Drift was their own doing.
    ///
    /// It holds the write side of both chains, because an Acknowledge is one
    /// Event Log action and one Baseline advance and the two do not come
    /// apart. The daemon is the only process that can hold one (spec section
    /// 6.2).
    pub struct Acknowledgement<'k> {
        keys: &'k dyn KeySource,
        baseline: Baseline,
        records: BaselineWriter,
        events: EventLogWriter,
    }

    impl<'k> Acknowledgement<'k> {
        /// Opens both chains of one data directory, answering with what
        /// verifying each of them found: the Event Log first, the Baseline
        /// second.
        pub fn open(
            directory: &DataDirectory,
            keys: &'k dyn KeySource,
        ) -> Result<(Acknowledgement<'k>, ChainState, ChainState), ChainError> {
            let log = EventLog::in_data_directory(directory);
            let (events, log_state) = EventLogWriter::open(&log, keys)?;
            let baseline = Baseline::in_data_directory(directory);
            let (records, baseline_state) = BaselineWriter::open(&baseline, keys)?;
            Ok((
                Acknowledgement {
                    keys,
                    baseline,
                    records,
                    events,
                },
                log_state,
                baseline_state,
            ))
        }

        /// The Baseline as it stands, verified.
        pub fn read(&self) -> Result<BaselineView, ChainError> {
            self.baseline.read(self.keys)
        }

        /// Moves the accepted hash to the content as it is now, and nothing
        /// else.
        ///
        /// The hash the user was shown is a compare-and-swap on the last-seen
        /// hash: if the Item moved on, nothing is accepted and the caller is
        /// told what it stands at now so the Finding can be asked again. Every
        /// Tier still scans the content afterwards; Acknowledge is not Trust.
        pub fn acknowledge(
            &mut self,
            item_id: &ItemId,
            answered: &str,
            finding_id: &str,
        ) -> Result<Acknowledged, AcknowledgeError> {
            let view = self.read()?;
            let held = view
                .record(item_id)
                .ok_or_else(|| AcknowledgeError::Unknown(item_id.clone()))?;
            if held.last_seen_hash != answered {
                return Err(AcknowledgeError::Stale {
                    answered: answered.to_string(),
                    last_seen: held.last_seen_hash.clone(),
                });
            }

            let event = Event::new(Action::Acknowledge, Actor::User)
                .about(item_id, held.kind, &held.last_seen_hash)
                // The answer is one of the closed list of known actions, and
                // it is known by the bytes it stands behind (ADR 0007).
                .leaving(&held.last_seen_hash)
                .noting("accepted_before", held.accepted_hash.as_str());
            // The Drift Finding the answer settles: T2, and no Rule behind it.
            let event = match finding_id.is_empty() {
                true => event,
                false => event.because_of(finding_id, Tier::Heuristics, 0),
            };
            let recorded = self.events.append(&event)?;
            let at = recorded.recorded_at;
            let sequence = recorded.sequence.to_string();

            let record = held.acknowledged(at, &sequence);
            self.records.accept(&record)?;
            Ok(Acknowledged {
                record,
                event: sequence,
            })
        }
    }

    impl fmt::Debug for Acknowledgement<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Acknowledgement")
                .field("baseline", &self.baseline)
                .finish_non_exhaustive()
        }
    }
}
