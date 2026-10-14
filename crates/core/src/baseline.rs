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

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::chain::{Chain, ChainError, ChainState};
use crate::coverage::{Coverage, CoverageKey, CoverageRecord};
use crate::envelope::{ChainId, RecordKind, Timestamp};
use crate::finding::Category;
use crate::item::{Item, ItemId, Kind, Shape, sha256_hex};
use crate::keychain::KeySource;
use crate::paths::DataDirectory;
use crate::state::RecordedFinding;

/// What moved the accepted hash to where it stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptedBy {
    /// The Item was first seen before its Surface was covered, so there was
    /// nothing to compare it with.
    Bootstrap,
    /// A Scan ended with no open Threat Finding on the Item.
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

/// The fields of an entry whose values never leave the machine in the clear
/// (spec section 3.3): MCP `env` values, headers and bearer-token targets, as
/// both Agents spell them.
///
/// A field counts wherever it sits: as any segment of the entry's locator
/// (Claude Code's settings entry `env.<NAME>` is the value itself), or at any
/// depth of the entry's content (the headers of a Codex telemetry exporter,
/// those of an HTTP hook). A name with a dot is a run of segments, so
/// `shell_environment_policy.set` is sensitive and a lone `set` is not.
///
/// The Baseline keeps a hash per field for every field alike, so a swapped
/// credential still moves the Item's hash; what these names govern is where a
/// value could be written out: [`BaselineRecord::previous_form`] through
/// [`redacted_form`], and a Heuristic excerpt through [`sensitive_values`].
pub fn sensitive_fields(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::McpServer => &[
            "env",
            "headers",
            "http_headers",
            "env_http_headers",
            "bearer_token_env_var",
        ],
        Kind::SettingsEntry => &[
            "env",
            "headers",
            "http_headers",
            "env_http_headers",
            "bearer_token_env_var",
            "experimental_bearer_token",
            "shell_environment_policy.set",
        ],
        Kind::Hook => &["headers"],
        _ => &[],
    }
}

/// True when a path, as its segments, names a sensitive field of this kind
/// anywhere along it.
pub fn names_a_sensitive_field(kind: Kind, segments: &[&str]) -> bool {
    sensitive_fields(kind).iter().any(|name| {
        let run: Vec<&str> = name.split('.').collect();
        segments
            .windows(run.len())
            .any(|window| window == run.as_slice())
    })
}

/// Where the sensitive values of an entry sit in its content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensitiveValues {
    /// The byte ranges of the content, each one a sensitive field written as
    /// its quoted name, a colon and its value. Empty when nothing is.
    At(Vec<std::ops::Range<usize>>),
    /// All of it: the locator names a sensitive field, or the content cannot
    /// be read field by field and a value that might be a secret is treated
    /// as one rather than guessed about.
    Whole,
}

/// Where an Item's sensitive values are. A file or a tree has none in this
/// sense: an env file is sensitive as a kind, and its callers say so.
pub fn sensitive_values(item: &Item) -> SensitiveValues {
    if item.shape != Shape::Entry || sensitive_fields(item.kind).is_empty() {
        return SensitiveValues::At(Vec::new());
    }
    if locator_is_sensitive(item) {
        return SensitiveValues::Whole;
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&item.content) else {
        return SensitiveValues::Whole;
    };
    if crate::item::canonical_entry(&parsed) != item.content {
        return SensitiveValues::Whole;
    }
    let mut spans = Vec::new();
    spans_of(item.kind, &parsed, 0, &mut Vec::new(), &mut spans);
    SensitiveValues::At(spans)
}

fn locator_is_sensitive(item: &Item) -> bool {
    let segments: Vec<&str> = item
        .inside_file()
        .split(['/', '.'])
        .filter(|segment| !segment.is_empty())
        .collect();
    names_a_sensitive_field(item.kind, &segments)
}

/// The segments a key of an entry adds to the path: Claude Code and Codex
/// both write a settings entry under its dotted key path.
fn key_segments(key: &str) -> impl Iterator<Item = String> + '_ {
    key.split('.').map(str::to_string)
}

/// Collects the sensitive pairs of a value whose canonical form starts at
/// `at`. The offsets follow the canonical form exactly: braces and brackets,
/// a comma between members, every key quoted and followed by a colon.
fn spans_of(
    kind: Kind,
    value: &Value,
    at: usize,
    path: &mut Vec<String>,
    spans: &mut Vec<std::ops::Range<usize>>,
) {
    let canonical = crate::item::canonical_entry;
    let mut offset = at + 1;
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    offset += 1;
                }
                let name = canonical(&Value::String(key.clone())).len();
                let field = &fields[key];
                let end = offset + name + 1 + canonical(field).len();
                let depth = path.len();
                path.extend(key_segments(key));
                let segments: Vec<&str> = path.iter().map(String::as_str).collect();
                if names_a_sensitive_field(kind, &segments) {
                    spans.push(offset..end);
                } else {
                    spans_of(kind, field, offset + name + 1, path, spans);
                }
                path.truncate(depth);
                offset = end;
            }
        }
        Value::Array(items) => {
            for (index, member) in items.iter().enumerate() {
                if index > 0 {
                    offset += 1;
                }
                path.push(index.to_string());
                spans_of(kind, member, offset, path, spans);
                path.pop();
                offset += canonical(member).len();
            }
        }
        _ => {}
    }
}

/// A value with every sensitive field left out, at any depth.
fn without_sensitive(kind: Kind, value: &Value, path: &mut Vec<String>) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .filter_map(|(key, field)| {
                    let depth = path.len();
                    path.extend(key_segments(key));
                    let segments: Vec<&str> = path.iter().map(String::as_str).collect();
                    let kept = match names_a_sensitive_field(kind, &segments) {
                        true => None,
                        false => Some((key.clone(), without_sensitive(kind, field, path))),
                    };
                    path.truncate(depth);
                    kept
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(index, member)| {
                    path.push(index.to_string());
                    let kept = without_sensitive(kind, member, path);
                    path.pop();
                    kept
                })
                .collect(),
        ),
        scalar => scalar.clone(),
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
/// Empty for a file or a tree, and empty for an entry whose locator names a
/// sensitive field in any segment: an entry that *is* a credential block, or
/// one credential, is remembered by its field hashes alone. A sensitive field
/// at any depth of the content is left out (see [`sensitive_fields`]).
pub fn redacted_form(item: &Item) -> String {
    if item.shape != Shape::Entry || locator_is_sensitive(item) {
        return String::new();
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&item.content) else {
        return String::new();
    };
    let value = without_sensitive(item.kind, &parsed, &mut Vec::new());
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
    /// The facts the accepted form carried beside its hash, as the Surface
    /// Adapter declared them: the version an install registry pointed a plugin
    /// at, the directory that version lived in, the commit it recorded, the
    /// source a marketplace pointed at. What tells a consistent plugin update
    /// from a tree that moved under an unchanged record (spec section 4.6.5).
    pub accepted_facts: BTreeMap<String, String>,
    /// The same for the last-seen form, kept only while the two differ.
    pub last_seen_facts: BTreeMap<String, String>,
    /// Where the Item was read from, as the last Scan saw it. Not part of the
    /// Item's identity: it is what a Problem is matched against, so that a
    /// path the Baseline had readable and cannot be read now is the last row
    /// of the Drift table.
    pub path: String,
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
            accepted_facts: item.baseline_facts.clone(),
            last_seen_facts: BTreeMap::new(),
            path: item.path.display().to_string(),
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
        moved.path = item.path.display().to_string();
        if item.content_hash == moved.accepted_hash {
            moved.first_differed_at = None;
            moved.last_seen_manifest = Vec::new();
            moved.last_seen_fields = BTreeMap::new();
        } else {
            moved.first_differed_at = moved.first_differed_at.or(Some(at));
            moved.last_seen_manifest = ManifestFile::of(item);
            moved.last_seen_fields = field_hashes(item);
        }
        // The facts are their own comparison: a marketplace points somewhere
        // else without one byte of its clone moving, and the form that is
        // waiting to be accepted is the one that was seen.
        moved.last_seen_facts = match item.baseline_facts == moved.accepted_facts {
            true => BTreeMap::new(),
            false => item.baseline_facts.clone(),
        };
        moved
    }

    /// The record after the hash was accepted: the last-seen forms fold into
    /// the accepted one and nothing differs any more.
    ///
    /// A Scan that finds the Item at the hash that was already accepted does
    /// not accept it again. The moment on the record is when AgentSweep first
    /// took this content, because that is the date a Drift Finding reads back
    /// ("changed since your last Scan on <date>"), and because a record that
    /// moved only its own timestamps is a record not worth writing.
    pub fn accepted(
        &self,
        item: &Item,
        at: Timestamp,
        by: AcceptedBy,
        event: &str,
    ) -> BaselineRecord {
        let mut moved = BaselineRecord::accepting(item, at, by);
        if self.accepted_hash == item.content_hash {
            moved.accepted_at = self.accepted_at;
            moved.accepted_by = self.accepted_by;
            moved.accepted_event = self.accepted_event.clone();
            moved.last_seen_at = self.last_seen_at;
        } else {
            moved.accepted_event = event.to_string();
        }
        moved
    }

    /// The record after the user said the change was their own doing.
    ///
    /// Acknowledge moves the accepted hash to the last-seen form and nothing
    /// else (ADR 0007): the form that was on screen becomes the accepted one,
    /// the Item stops differing, and every Tier goes on scanning the content.
    /// The canonical form of the newly accepted entry is not in hand here, so
    /// it is cleared rather than left describing a form nobody accepted; the
    /// next Scan that reads the Item writes it back.
    pub fn acknowledged(&self, at: Timestamp, event: &str) -> BaselineRecord {
        let mut moved = self.clone();
        moved.accepted_hash = self.last_seen_hash.clone();
        moved.accepted_at = at;
        moved.accepted_by = AcceptedBy::Acknowledge;
        moved.accepted_event = event.to_string();
        moved.first_differed_at = None;
        moved.origin = Origin::Verified;
        if !self.last_seen_manifest.is_empty() {
            moved.accepted_manifest = self.last_seen_manifest.clone();
        }
        if !self.last_seen_fields.is_empty() {
            moved.accepted_fields = self.last_seen_fields.clone();
        }
        if !self.last_seen_facts.is_empty() {
            moved.accepted_facts = self.last_seen_facts.clone();
        }
        moved.last_seen_manifest = Vec::new();
        moved.last_seen_fields = BTreeMap::new();
        moved.last_seen_facts = BTreeMap::new();
        moved.previous_form = String::new();
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
        map.insert("accepted_facts".to_string(), strings(&self.accepted_facts));
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
            "last_seen_facts".to_string(),
            strings(&self.last_seen_facts),
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
        map.insert("path".to_string(), Value::from(self.path.as_str()));
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
            accepted_facts: strings("accepted_facts")?,
            last_seen_facts: strings("last_seen_facts")?,
            path: text("path")?.to_string(),
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
            compactions: 0,
            unreadable: 0,
            records: BTreeMap::new(),
            coverage: Coverage::none(),
        };
        let key_missing = verification.state == ChainState::KeyMissing;
        for record in &verification.records {
            if record.envelope.record == RecordKind::ChainRestart {
                match cause_of(&record.envelope.payload) {
                    crate::chain::COMPACTION => view.compactions += 1,
                    _ => view.restarts += 1,
                }
                continue;
            }
            // The answer to a break is the chain's own, not an Item's.
            if record.envelope.record == RecordKind::Integrity {
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

/// Why a chain restart record sits where it does. A record written before the
/// cause was carried says nothing, and the key going missing is what a restart
/// meant then.
fn cause_of(payload: &Value) -> &str {
    payload
        .get("cause")
        .and_then(Value::as_str)
        .unwrap_or(crate::chain::KEY_MISSING)
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
    /// How many times the chain was compacted, which restarts it as well.
    pub compactions: usize,
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
            compactions: 0,
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

/// How long a record of an Item that is gone is kept (spec section 4.6.6).
///
/// Disappearance is never a Finding: the record is marked absent and kept, so
/// an Item that comes back within the ninety days is `unchanged` or `changed`
/// against what was accepted. After compaction it is `added`.
pub const ABSENT_FOR: i64 = 90 * 86_400_000;

/// What compaction keeps.
#[derive(Clone, Debug)]
pub struct Retention {
    /// How long a record of an Item that is gone is kept, in milliseconds.
    pub absent_for: i64,
    /// The Scope segments of the roots that are still in a registry, as
    /// [`crate::item::Scope::id_segment`] spells them. The records and the
    /// coverage of a project root that left every registry are dropped; a root
    /// that comes back bootstraps as `none`.
    pub live_roots: BTreeSet<String>,
    /// The Items an open Threat Finding refers to. No compaction ever drops
    /// one of them, whatever else it drops. An Exposure does not hold the
    /// Baseline and keeps no record either (spec section 4.6.4 as amended).
    pub referenced: BTreeSet<ItemId>,
}

impl Default for Retention {
    /// Everything a root still in a registry holds, and every record of an
    /// Item that has been gone for less than ninety days. A retention that
    /// names no live root drops every project record, so the roots are always
    /// worth naming.
    fn default() -> Retention {
        Retention {
            absent_for: ABSENT_FOR,
            live_roots: BTreeSet::new(),
            referenced: BTreeSet::new(),
        }
    }
}

impl Retention {
    /// What to keep, given the roots that are still registered.
    pub fn of(live_roots: BTreeSet<String>) -> Retention {
        Retention {
            live_roots,
            ..Retention::default()
        }
    }

    /// The same, with the Items an open Threat Finding stands on named.
    pub fn referring_to(mut self, referenced: BTreeSet<ItemId>) -> Retention {
        self.referenced = referenced;
        self
    }

    /// The same, with the Items named that the open Threat Findings among
    /// these stand on. Only a Threat Finding holds the accepted hash, so only
    /// a Threat Finding keeps a record compaction would drop otherwise.
    pub fn held_by<'f>(self, findings: impl IntoIterator<Item = &'f RecordedFinding>) -> Retention {
        let referenced = findings
            .into_iter()
            .filter(|finding| finding.is_open() && finding.category == Category::Threat)
            .map(|finding| finding.item_id.clone())
            .collect();
        self.referring_to(referenced)
    }

    /// True when this record survives a compaction run at this moment.
    pub fn keeps(&self, record: &BaselineRecord, at: Timestamp) -> bool {
        if self.referenced.contains(&record.item_id) {
            return true;
        }
        if record.item_id.is_project()
            && !self
                .live_roots
                .iter()
                .any(|root| record.item_id.in_scope(root))
        {
            return false;
        }
        match record.state {
            Presence::Present => true,
            Presence::Absent { since } => at.as_unix_ms() - since.as_unix_ms() <= self.absent_for,
        }
    }

    /// True when this stretch of coverage survives a compaction run.
    pub fn covers(&self, key: &CoverageKey) -> bool {
        !key.root.starts_with("project:") || self.live_roots.contains(&key.root)
    }
}

/// What one compaction would write and what it would drop.
#[derive(Clone, Debug, Default)]
pub struct CompactionPlan {
    /// The coverage the fresh chain opens with.
    pub coverage: Vec<CoverageRecord>,
    /// The records it holds, in Item id order.
    pub keep: Vec<BaselineRecord>,
    /// The Items whose records are dropped.
    pub dropped: Vec<ItemId>,
    /// The stretches of coverage that are dropped.
    pub uncovered: Vec<CoverageKey>,
}

impl CompactionPlan {
    /// What compaction would make of the Baseline as it stands.
    ///
    /// A pure function of the view and the retention: nothing is written here,
    /// so the daemon can say what a compaction would drop before it runs one.
    pub fn of(view: &BaselineView, retention: &Retention, at: Timestamp) -> CompactionPlan {
        let mut plan = CompactionPlan::default();
        // A stretch of Surface keeps the moment it was first covered: writing
        // it down again is not covering it again.
        for (key, covered_at) in view.coverage().stretches() {
            match retention.covers(key) {
                true => plan
                    .coverage
                    .push(CoverageRecord::new(key.clone(), covered_at)),
                false => plan.uncovered.push(key.clone()),
            }
        }
        for record in view.records() {
            match retention.keeps(record, at) {
                true => plan.keep.push(record.clone()),
                false => plan.dropped.push(record.item_id.clone()),
            }
        }
        plan
    }

    /// Everything the fresh chain holds, in the order it is written: coverage
    /// first, then one record per Item.
    pub fn entries(&self) -> Vec<BaselineEntry> {
        let covered = self.coverage.iter().cloned().map(BaselineEntry::Coverage);
        let kept = self
            .keep
            .iter()
            .cloned()
            .map(|record| BaselineEntry::Item(Box::new(record)));
        covered.chain(kept).collect()
    }

    /// True when the chain would say exactly what it says now, which is a
    /// compaction not worth running.
    pub fn changes_nothing(&self) -> bool {
        self.dropped.is_empty() && self.uncovered.is_empty()
    }
}

/// How long a completed Full Scan waits before compaction may run again (spec
/// section 4.6.6: at most once a day).
pub const COMPACT_EVERY: i64 = 86_400_000;

/// True when compaction may run now, given when it last ran.
pub fn compaction_due(last: Option<Timestamp>, at: Timestamp) -> bool {
    match last {
        None => true,
        Some(last) => at.as_unix_ms() - last.as_unix_ms() >= COMPACT_EVERY,
    }
}

#[cfg(feature = "daemon")]
pub use writer::{BaselineWriter, Compaction, compact};

#[cfg(feature = "daemon")]
mod writer {
    use super::{Baseline, BaselineEntry, BaselineRecord, BaselineView, CompactionPlan, Retention};

    use crate::chain::{ChainError, ChainState, ChainWriter, Compacted};
    use crate::coverage::CoverageRecord;
    use crate::envelope::{Envelope, RecordKind, Timestamp};
    use crate::eventlog::{Action, Actor, Event, EventLog, EventLogWriter};
    use crate::integrity::IntegrityRecord;
    use crate::keychain::KeySource;
    use crate::paths::DataDirectory;

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

        /// Opens the Baseline for appending after a verification made before,
        /// so both chains are verified before a missing key is renewed for
        /// either (see [`ChainWriter::open_verified`]).
        pub fn open_verified(
            baseline: &Baseline,
            verification: crate::chain::Verification,
            keys: &dyn KeySource,
        ) -> Result<(BaselineWriter, ChainState), ChainError> {
            let (writer, state) =
                ChainWriter::open_verified(baseline.chain().clone(), verification, keys)?;
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

        /// Appends the answer to a broken Baseline, which verification picks
        /// the chain up again from (spec section 8.6). The Event Log carries
        /// the same answer, so it is on record where every answer is.
        pub fn record_integrity(
            &mut self,
            answer: &IntegrityRecord,
        ) -> Result<Envelope, ChainError> {
            self.writer
                .append_beside(RecordKind::Integrity, answer.to_payload())
        }

        /// The hash a record appended now would link to.
        pub fn head(&self) -> &str {
            self.writer.head()
        }
    }

    /// What one compaction did.
    #[derive(Clone, Debug)]
    pub struct Compaction {
        /// What was kept and what was dropped.
        pub plan: CompactionPlan,
        /// The old and the new head, which the Event Log record anchors to
        /// each other.
        pub chain: Compacted,
    }

    /// Writes a fresh Baseline chain of what is still worth keeping and
    /// anchors it in the Event Log (spec section 4.6.6).
    ///
    /// It runs after a completed Full Scan and at most once a day. What it
    /// drops is what a record is kept for no longer: an Item that has been
    /// absent for more than ninety days, and the records and the coverage of a
    /// project root that left every registry. A record any open Threat
    /// Finding refers to is never dropped, whatever else is.
    ///
    /// The Event Log is never compacted, and the one record appended to it
    /// carries the old head and the new one, so the chain that was replaced
    /// stays witnessed by the log that outlives it.
    pub fn compact(
        directory: &DataDirectory,
        keys: &dyn KeySource,
        retention: &Retention,
        at: Timestamp,
    ) -> Result<Compaction, ChainError> {
        let baseline = Baseline::in_data_directory(directory);
        let view: BaselineView = baseline.read(keys)?;
        if view.state != ChainState::Intact {
            return Err(ChainError::Refused(
                "a Baseline that does not verify is read, never rewritten".to_string(),
            ));
        }
        let plan = CompactionPlan::of(&view, retention, at);
        let payloads: Vec<serde_json::Value> = plan
            .entries()
            .iter()
            .map(BaselineEntry::to_payload)
            .collect();
        let (_, chain) = ChainWriter::compact(baseline.chain().clone(), keys, &payloads)?;

        let log = EventLog::in_data_directory(directory);
        let (mut events, _) = EventLogWriter::open(&log, keys)?;
        let event = Event::new(Action::BaselineCompacted, Actor::Auto)
            .noting("old_head", chain.old_head.as_str())
            .noting("new_head", chain.new_head.as_str())
            .noting("old_records", chain.old_records.to_string())
            .noting("new_records", chain.new_records.to_string())
            .noting("dropped", plan.dropped.len().to_string())
            .noting("uncovered", plan.uncovered.len().to_string());
        events.append(&event)?;
        Ok(Compaction { plan, chain })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::coverage::CoverageKey;
    use crate::eventlog::{Action, EventLog};
    use crate::finding::{
        Category, Finding, FindingId, FindingState, RuleStatus, Severity, Source, Standing, Tier,
    };
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

    fn entry(agent: &str, kind: Kind, locator: &str, body: &Value) -> Item {
        Item::entry(
            agent,
            Scope::User,
            kind,
            locator,
            PathBuf::from("/nowhere/config"),
            Provenance::Manual,
            Activation::Active,
            canonical_entry(body),
        )
    }

    /// A Claude Code settings entry for one environment variable is the value
    /// itself under a key path that starts with `env`: the locator names the
    /// sensitive field, not its last segment.
    #[test]
    fn a_settings_entry_for_one_environment_variable_keeps_no_value() {
        let item = entry(
            "claude-code",
            Kind::SettingsEntry,
            "~/.claude/settings.json#/env/TRACKER_TOKEN",
            &serde_json::json!({"env.TRACKER_TOKEN": "hunter2hunter2"}),
        );
        assert_eq!(redacted_form(&item), "");
        let record = BaselineRecord::accepting(
            &item,
            moment("2026-09-24T09:00:00.000Z"),
            AcceptedBy::CleanScan,
        );
        let written = String::from_utf8(crate::item::canonical_entry(&record.to_payload()))
            .expect("the payload is text");
        assert!(!written.contains("hunter2"), "{written}");
    }

    /// A Codex MCP table writes its headers as `http_headers` and the
    /// variables that fill them as `env_http_headers`; neither value is kept.
    #[test]
    fn a_codex_server_keeps_none_of_its_header_values() {
        let item = entry(
            "codex",
            Kind::McpServer,
            "~/.codex/config.toml#tracker",
            &serde_json::json!({
                "url": "https://tracker.example.invalid/mcp",
                "http_headers": {"Authorization": "Bearer hunter2hunter2"},
                "env_http_headers": {"X-Tenant": "TRACKER_TENANT_VARIABLE"},
                "bearer_token_env_var": "TRACKER_BEARER_VARIABLE",
            }),
        );
        let form = redacted_form(&item);
        assert!(form.contains("tracker.example.invalid"), "{form}");
        assert!(!form.contains("hunter2"), "{form}");
        assert!(!form.contains("TRACKER_TENANT_VARIABLE"), "{form}");
        assert!(!form.contains("TRACKER_BEARER_VARIABLE"), "{form}");
    }

    /// A sensitive field below the top level is left out too: a provider's
    /// literal bearer token, the headers of a telemetry exporter, the
    /// variables a shell environment policy sets, and the headers of an HTTP
    /// hook.
    #[test]
    fn a_sensitive_field_at_any_depth_is_left_out() {
        let cases = [
            entry(
                "codex",
                Kind::SettingsEntry,
                "~/.codex/config.toml#/model_providers/proxy/experimental_bearer_token",
                &serde_json::json!({"model_providers.proxy.experimental_bearer_token": "hunter2hunter2"}),
            ),
            entry(
                "codex",
                Kind::SettingsEntry,
                "~/.codex/config.toml#/otel",
                &serde_json::json!({"otel": {"exporter": {"otlp-http": {
                    "endpoint": "https://otel.example.invalid",
                    "headers": {"x-api-key": "hunter2hunter2"},
                }}}}),
            ),
            entry(
                "codex",
                Kind::SettingsEntry,
                "~/.codex/config.toml#/shell_environment_policy/set",
                &serde_json::json!({"shell_environment_policy.set": {"TOKEN": "hunter2hunter2"}}),
            ),
            entry(
                "claude-code",
                Kind::Hook,
                "~/.claude/settings.json#PostToolUse/Bash/0123456789ab",
                &serde_json::json!({
                    "event_name": "PostToolUse",
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "http",
                        "url": "https://hooks.example.invalid",
                        "headers": {"Authorization": "Bearer hunter2hunter2"},
                    }],
                }),
            ),
        ];
        for item in cases {
            let form = redacted_form(&item);
            assert!(!form.contains("hunter2"), "{}: {form}", item.locator());
        }
        // What is not sensitive stays, so a Drift Finding still has a before.
        let otel = entry(
            "codex",
            Kind::SettingsEntry,
            "~/.codex/config.toml#/otel",
            &serde_json::json!({"otel": {"exporter": {"otlp-http": {
                "endpoint": "https://otel.example.invalid",
                "headers": {"x-api-key": "hunter2hunter2"},
            }}}}),
        );
        assert!(redacted_form(&otel).contains("otel.example.invalid"));
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
            "",
        );
        assert_eq!(taken.accepted_hash, second.content_hash);
        assert_eq!(taken.accepted_at, moment("2026-09-24T11:00:00.000Z"));
        assert_eq!(taken.first_differed_at, None);
        assert!(taken.last_seen_fields.is_empty());

        // Seeing the same content again is not accepting it again: the moment
        // on the record is when AgentSweep first took this content.
        let again = taken.accepted(
            &second,
            moment("2026-09-24T12:00:00.000Z"),
            AcceptedBy::CleanScan,
            "",
        );
        assert_eq!(again.accepted_at, moment("2026-09-24T11:00:00.000Z"));
        assert!(!again.moved_from(&taken));
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

    /// Spec section 4.6.6: on a broken chain, Drift is computed against the
    /// last verifiable prefix. Nothing after the break is read, and nothing is
    /// bulk-accepted to paper over it.
    #[test]
    fn a_broken_chain_leaves_the_baseline_at_its_last_verifiable_prefix() {
        let directory = TempDir::new().expect("a temporary data directory");
        let data = DataDirectory::at(directory.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let baseline = Baseline::in_data_directory(&data);

        let first = instruction_file("# demo\n");
        let second = mcp_entry("t", &serde_json::json!({"command": "/opt/tools/t"}));
        {
            let (mut writer, _) =
                BaselineWriter::open(&baseline, &keys).expect("the Baseline opens");
            for item in [&first, &second] {
                writer
                    .accept(&BaselineRecord::accepting(
                        item,
                        moment("2026-09-24T09:00:00.000Z"),
                        AcceptedBy::Bootstrap,
                    ))
                    .expect("the record is written");
            }
        }

        let written = std::fs::read_to_string(baseline.chain().path()).expect("a readable chain");
        let tampered: Vec<String> = written
            .lines()
            .enumerate()
            .map(|(index, line)| {
                if index == 1 {
                    line.replace("\"accepted_by\":\"bootstrap\"", "\"accepted_by\":\"trust\"")
                } else {
                    line.to_string()
                }
            })
            .collect();
        std::fs::write(
            baseline.chain().path(),
            format!("{}\n", tampered.join("\n")),
        )
        .expect("a writable chain");

        let view = baseline.read(&keys).expect("the Baseline still reads");
        assert!(matches!(view.state, ChainState::Broken { sequence: 1, .. }));
        assert_eq!(view.len(), 1);
        assert!(view.record(&first.id).is_some());
        assert!(view.record(&second.id).is_none());
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
                "",
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

    /// Only an open Threat Finding keeps a record compaction would drop
    /// otherwise: the record behind a standing Exposure goes with everything
    /// else that has been gone for more than ninety days, and so does the
    /// record behind a Threat Finding that no longer stands.
    #[test]
    fn compaction_keeps_a_record_only_while_a_threat_finding_refers_to_it() {
        let accepted = moment("2026-01-01T09:00:00.000Z");
        let gone = moment("2026-06-01T09:00:00.000Z");
        let threatened = user_file("threatened.md");
        let exposed = user_file("exposed.md");
        let stopped = user_file("stopped.md");

        let mut view = BaselineView::none();
        for item in [&threatened, &exposed, &stopped] {
            let record = BaselineRecord::accepting(item, accepted, AcceptedBy::CleanScan);
            view.records.insert(item.id.clone(), record.absent(gone));
        }
        let findings = [
            recorded(&threatened, Category::Threat, FindingState::Open),
            recorded(&exposed, Category::Exposure, FindingState::Open),
            recorded(&stopped, Category::Threat, FindingState::Stopped),
        ];

        let live: BTreeSet<String> = ["user".to_string()].into_iter().collect();
        let retention = Retention::of(live).held_by(findings.iter());
        let plan = CompactionPlan::of(&view, &retention, moment("2026-09-24T09:00:00.000Z"));

        let kept: Vec<&ItemId> = plan.keep.iter().map(|record| &record.item_id).collect();
        assert_eq!(kept, [&threatened.id], "{:?}", plan.dropped);
        assert!(
            plan.dropped.contains(&exposed.id),
            "an Exposure keeps nothing"
        );
        assert!(
            plan.dropped.contains(&stopped.id),
            "a stopped Threat keeps nothing"
        );
    }

    /// One Finding as the state file records it, on one Item.
    fn recorded(item: &Item, category: Category, state: FindingState) -> RecordedFinding {
        let finding = Finding {
            item_id: item.id.clone(),
            source: Source::Rule(1),
            content_hash: item.content_hash.clone(),
            category,
            severity: Severity::High,
            tier: Tier::Rules,
            status: RuleStatus::Probation,
            title: "A Finding".to_string(),
            plain: "A Finding.".to_string(),
            sensitive: false,
            file: String::new(),
            matches: Vec::new(),
            heuristics: Vec::new(),
            drift: None,
        };
        let standing = Standing {
            id: FindingId::of(&finding),
            finding,
            state,
            receipt_id: String::new(),
        };
        RecordedFinding::of(&standing, moment("2026-09-01T09:00:00.000Z"))
    }

    /// Spec section 4.6.6: compaction writes a fresh chain of what is still
    /// worth keeping and anchors the old head and the new one in the Event
    /// Log. It drops what a record is kept for no longer, and never a record
    /// an open Threat Finding refers to.
    #[test]
    fn compaction_drops_what_is_kept_for_no_longer_and_anchors_both_heads() {
        let home = TempDir::new().expect("a temporary data directory");
        let directory = DataDirectory::at(home.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let baseline = Baseline::in_data_directory(&directory);

        let present = user_file("present.md");
        let long_gone = user_file("long-gone.md");
        let lately_gone = user_file("lately-gone.md");
        let live_project = project_file("/src/live");
        let dead_project = project_file("/src/dead");
        let referenced = user_file("referenced.md");

        let accepted = moment("2026-01-01T09:00:00.000Z");
        let (mut writer, state) = BaselineWriter::open(&baseline, &keys).expect("it opens");
        assert_eq!(state, ChainState::Intact);
        for key in [
            CoverageKey::of("claude-code", &Scope::User, Kind::InstructionFile),
            CoverageKey::of(
                "claude-code",
                &Scope::Project(PathBuf::from("/src/live")),
                Kind::InstructionFile,
            ),
            CoverageKey::of(
                "claude-code",
                &Scope::Project(PathBuf::from("/src/dead")),
                Kind::InstructionFile,
            ),
        ] {
            writer
                .cover(&CoverageRecord::new(key, accepted))
                .expect("the coverage is written");
        }
        let mut kept: Vec<BaselineRecord> = Vec::new();
        for item in [
            &present,
            &long_gone,
            &lately_gone,
            &live_project,
            &dead_project,
            &referenced,
        ] {
            let record = BaselineRecord::accepting(item, accepted, AcceptedBy::CleanScan);
            writer.accept(&record).expect("the record is written");
            kept.push(record);
        }
        // Two Items are gone: one long enough to be dropped, one not. A third
        // is gone as well and an open Finding still refers to it.
        for (record, when) in [
            (&kept[1], "2026-06-01T09:00:00.000Z"),
            (&kept[2], "2026-09-01T09:00:00.000Z"),
            (&kept[5], "2026-06-01T09:00:00.000Z"),
        ] {
            writer
                .accept(&record.absent(moment(when)))
                .expect("the record is written");
        }
        drop(writer);

        let before = baseline.read(&keys).expect("the Baseline reads");
        assert_eq!(before.len(), 6);
        let old_head = before.head.clone();

        let live: BTreeSet<String> = ["user".to_string(), "project:/src/live".to_string()]
            .into_iter()
            .collect();
        let retention = Retention::of(live).referring_to(
            [kept[5].item_id.clone()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
        let at = moment("2026-09-24T09:00:00.000Z");
        let compaction = compact(&directory, &keys, &retention, at).expect("it compacts");

        // What was dropped: the record absent for more than ninety days, and
        // the root that left every registry.
        let dropped: Vec<String> = compaction
            .plan
            .dropped
            .iter()
            .map(|id| id.to_string())
            .collect();
        assert_eq!(dropped.len(), 2, "{dropped:?}");
        assert!(
            dropped.iter().any(|id| id.ends_with("long-gone.md")),
            "{dropped:?}"
        );
        assert!(
            dropped.iter().any(|id| id.contains("/src/dead")),
            "{dropped:?}"
        );
        assert_eq!(compaction.plan.uncovered.len(), 1);
        assert_eq!(compaction.plan.uncovered[0].root, "project:/src/dead");

        // What the fresh chain holds, read back through the ordinary routine.
        let after = baseline.read(&keys).expect("the compacted Baseline reads");
        assert_eq!(after.state, ChainState::Intact);
        assert_eq!(after.len(), 4, "{:?}", after.records().collect::<Vec<_>>());
        assert!(after.record(&present.id).is_some());
        assert!(
            after.record(&referenced.id).is_some(),
            "a record an open Threat Finding refers to is never dropped"
        );
        assert!(after.record(&lately_gone.id).is_some());
        assert!(after.record(&long_gone.id).is_none());
        assert!(after.record(&dead_project.id).is_none());
        assert_eq!(after.compactions, 1);
        assert_eq!(after.restarts, 0);
        assert!(
            after
                .coverage()
                .covers("claude-code", &Scope::User, Kind::InstructionFile)
        );
        assert!(!after.coverage().covers(
            "claude-code",
            &Scope::Project(PathBuf::from("/src/dead")),
            Kind::InstructionFile
        ));

        // And the Event Log carries the one record that anchors the chain
        // that was replaced to the one that took its place.
        assert_eq!(compaction.chain.old_head, old_head);
        assert_eq!(compaction.chain.new_head, after.head);
        let log = EventLog::in_data_directory(&directory)
            .read(&keys)
            .expect("the log reads");
        assert_eq!(log.events.len(), 1);
        let event = &log.events[0].event;
        assert_eq!(event.action, Action::BaselineCompacted);
        assert_eq!(event.detail.get("old_head"), Some(&old_head));
        assert_eq!(event.detail.get("new_head"), Some(&after.head));
    }

    /// A Baseline no key in hand can verify is read, never rewritten: writing
    /// it afresh would launder records nobody can vouch for into a chain that
    /// verifies (ADR 0007).
    #[test]
    fn compaction_refuses_a_baseline_that_does_not_verify() {
        let home = TempDir::new().expect("a temporary data directory");
        let directory = DataDirectory::at(home.path());
        let keys = MemoryKeySource::holding(ChainKey::generate().expect("a key"));
        let baseline = Baseline::in_data_directory(&directory);
        let item = instruction_file("# demo\n");
        let (mut writer, _) = BaselineWriter::open(&baseline, &keys).expect("it opens");
        writer
            .accept(&BaselineRecord::accepting(
                &item,
                moment("2026-09-24T09:00:00.000Z"),
                AcceptedBy::CleanScan,
            ))
            .expect("the record is written");
        drop(writer);

        let stranger = MemoryKeySource::holding(ChainKey::from_bytes([7u8; 32]));
        let refused = compact(
            &directory,
            &stranger,
            &Retention::of(BTreeSet::new()),
            moment("2026-09-25T09:00:00.000Z"),
        )
        .expect_err("it refuses");
        assert!(refused.to_string().contains("never rewritten"), "{refused}");

        let after = baseline.read(&keys).expect("the Baseline reads");
        assert_eq!(after.len(), 1, "nothing was rewritten");
    }

    /// Compaction runs after a completed Full Scan and at most once a day.
    #[test]
    fn compaction_is_due_once_a_day() {
        let at = moment("2026-09-24T09:00:00.000Z");
        assert!(compaction_due(None, at));
        assert!(!compaction_due(
            Some(moment("2026-09-24T08:00:00.000Z")),
            at
        ));
        assert!(compaction_due(Some(moment("2026-09-23T08:00:00.000Z")), at));
    }

    fn user_file(name: &str) -> Item {
        Item::file(
            "claude-code",
            Scope::User,
            Kind::InstructionFile,
            &format!("~/.claude/{name}"),
            PathBuf::from("/nowhere/.claude").join(name),
            Provenance::Manual,
            Activation::Active,
            format!("# {name}\n").into_bytes(),
        )
    }

    fn project_file(root: &str) -> Item {
        Item::file(
            "claude-code",
            Scope::Project(PathBuf::from(root)),
            Kind::InstructionFile,
            "CLAUDE.md",
            PathBuf::from(root).join("CLAUDE.md"),
            Provenance::Manual,
            Activation::Active,
            b"# project\n".to_vec(),
        )
    }
}
