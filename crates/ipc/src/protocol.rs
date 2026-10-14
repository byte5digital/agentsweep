//! The vocabulary: the handshake, the requests, the responses and the state
//! events (spec section 6.3).
//!
//! It is a closed list on purpose. The daemon holds the machine's file access,
//! the Keychain key behind both chains and the only write path into the
//! quarantine store, so what a peer may ask for is enumerated here rather than
//! left to whatever a caller can spell (ADR 0008). Every action addresses a
//! Finding, an Item or a Receipt by its id, which the daemon resolves against
//! what it knows; an id it does not know is a clean refusal. The only requests
//! that take a path are revealing a Receipt and the Folder Scan:
//! [`Request::takes_a_path`] says so, and a message that carries a path on any
//! other request is not a message at all. The one other path on the wire is
//! the config-dir override per Agent of the `settings` request, a directory
//! the user named, which travels under its own field.
//!
//! Every message is one JSON object with a `type`. The types are laid out here
//! and nowhere else, so the daemon, the application and the command line
//! interface cannot drift apart about what a field is called.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};

use agentsweep_core::chain::{BreakReason, ChainState};
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::eventlog::{Actor, Outcome, Primitive, ReceiptStep, SessionsRunning};
use agentsweep_core::finding::{Category, FindingId, FindingState};
use agentsweep_core::health::{Health, Protection, StateFileHealth};
use agentsweep_core::item::{ItemId, Kind};
use agentsweep_core::keychain::ClaudeKey;
use agentsweep_core::packs::PackOrigin;
use agentsweep_core::quarantine::Conflict;
use agentsweep_core::state::{IgnoredPack, RecordedFinding, ScanSummary, Trigger};

pub use crate::engine::{EngineChange, EngineState};
pub use crate::settings::{SettingsChange, SettingsState};

/// Which peer is speaking. The daemon answers both the same way in this
/// milestone; the role is carried because the notification flow of spec
/// section 6.7 tells the application from the command line interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// The menu bar application.
    App,
    /// The in-bundle command line interface.
    Cli,
}

impl Role {
    /// Every role.
    pub const ALL: [Role; 2] = [Role::App, Role::Cli];

    /// The spelling the handshake carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::App => "app",
            Role::Cli => "cli",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|role| role.as_str() == text)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a client says first: which version it is and what it is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    /// The client's version. Application, daemon and command line interface
    /// always share one.
    pub version: String,
    /// What the client is.
    pub role: Role,
}

impl Hello {
    /// The handshake this build sends.
    pub fn of(role: Role) -> Hello {
        Hello {
            version: agentsweep_core::VERSION.to_string(),
            role,
        }
    }
}

/// The fixed sentence a version mismatch is refused with (spec section 6.3).
pub const RESTART_AGENTSWEEP: &str = "restart AgentSweep";

/// Why the daemon will not talk to this peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The peer is a different version of AgentSweep. The application then
    /// re-registers the daemon; a person is told to restart AgentSweep.
    VersionMismatch {
        /// The version the daemon is.
        daemon_version: String,
        /// The version the peer said it was.
        peer_version: String,
    },
    /// The peer does not carry AgentSweep's code signature, or does not run as
    /// the same user (ADR 0008).
    UnsignedPeer {
        /// What the check found, for the daemon's own log.
        detail: String,
    },
    /// The peer said something other than a handshake first.
    NotAHandshake {
        /// What it said instead.
        detail: String,
    },
}

impl Refusal {
    /// The short machine-readable reason the message carries.
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::VersionMismatch { .. } => "version-mismatch",
            Refusal::UnsignedPeer { .. } => "unsigned-peer",
            Refusal::NotAHandshake { .. } => "not-a-handshake",
        }
    }

    /// What the check found, which the sentence is built from. It is a fact
    /// about the peer, never a value read off the machine.
    pub fn detail(&self) -> String {
        match self {
            Refusal::VersionMismatch {
                daemon_version,
                peer_version,
            } => format!("the daemon is {daemon_version} and the peer is {peer_version}"),
            Refusal::UnsignedPeer { detail } | Refusal::NotAHandshake { detail } => detail.clone(),
        }
    }

    /// The sentence the peer is given.
    pub fn message(&self) -> String {
        match self {
            Refusal::VersionMismatch { .. } => RESTART_AGENTSWEEP.to_string(),
            Refusal::UnsignedPeer { detail } => {
                format!("AgentSweep answers only its own signed programs: {detail}")
            }
            Refusal::NotAHandshake { detail } => {
                format!("AgentSweep expects a handshake first: {detail}")
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for Refusal {}

/// What a peer may ask the daemon for. The closed list.
///
/// A target is the id of a Finding, an Item or a Receipt, as the status and
/// the Activity print them. It is a string on the wire and nothing else: the
/// daemon looks it up among what it knows and never treats it as a place on
/// disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// Health, the last Scan summary and the Findings that stand.
    Status,
    /// Run a Full Scan now. One that is already running is joined rather than
    /// started again (spec section 6.4).
    ScanNow,
    /// Send every state event from now until the connection closes.
    Subscribe,
    /// Take the Item of one Threat Finding out of its Surface, by the
    /// primitive table of spec section 5.2. A manual Quarantine: any Tier, any
    /// Threat, never a Managed Item.
    Quarantine {
        /// A Finding id, or the id of an Item with one open Threat Finding.
        target: String,
    },
    /// Put a quarantined Item back by replaying its Receipt in reverse. What
    /// AgentSweep took out by itself comes back with Trust for that exact
    /// content (spec section 5.4).
    Restore {
        /// A Receipt id, or a Finding or Item id that one Receipt stopped.
        target: String,
        /// What to do when the original place holds something else now.
        conflict: Conflict,
    },
    /// Record that the content of one Finding's Item is safe, bound to its
    /// hash and kind ("Trust this version", "Keep it as it is").
    Trust {
        /// A Finding id, or the id of an Item with open Findings.
        target: String,
    },
    /// Answer a Drift Finding with "that was me": the accepted hash moves to
    /// the content as it is now and nothing else (spec section 4.6.5).
    Acknowledge {
        /// A Drift Finding id, or the id of an Item with an open one.
        target: String,
    },
    /// The one-click fix of Exposures 0018 and 0019: the entry is taken out
    /// of its settings file, restorably (spec section 8.5).
    Fix {
        /// The Exposure Finding's id, or its Item's.
        target: String,
    },
    /// Switch a quarantined plugin back on for its newer, clean version,
    /// reversing only the native disable (spec section 5.4).
    ReEnable {
        /// A Receipt id, or the stopped plugin Finding's or Item's id.
        target: String,
    },
    /// Every Receipt in the quarantine store with the path its Item was taken
    /// from, or only those taken from at or below one path. The one request of
    /// this list that takes a path (ADR 0008).
    RevealReceipt {
        /// The original place to look for, absent for every Receipt.
        path: Option<String>,
    },
    /// Read the Rule Feed toggle, or set it. Off means no request at all and
    /// the bundled Rule Pack only (spec section 9.4). Answers with where the
    /// toggle stands afterwards. Kept for the command line interface; the
    /// application moves the toggle through [`Request::Settings`].
    RuleFeed {
        /// The toggle's new position, absent to read it.
        enabled: Option<bool>,
    },
    /// Whether Agent sessions appear to be running right now, detected
    /// read-only the way every action detects it. What a client asks before
    /// it confirms a Quarantine, so the confirmation can say so (spec section
    /// 8.5). Nothing is acted on.
    Sessions,
    /// A Folder Scan of one folder the user pointed at: read and judged,
    /// nothing recorded (spec section 6.4). The second request of this list
    /// that takes a path (ADR 0008). Answers with a [`FolderScanResult`].
    Folder {
        /// The folder, as an absolute path.
        path: String,
    },
    /// Read the AI Judgement choices, or change some of them: the active
    /// Judgement Engine, the Ollama address and model, the Claude model id
    /// override and the cloud caps (spec section 4.4). Answers with an
    /// [`EngineState`]. A change the daemon refuses leaves every choice as it
    /// was.
    Engine {
        /// What to move; nothing to read only.
        change: EngineChange,
    },
    /// Hand the Claude API key to the daemon, which keeps it in the login
    /// Keychain and nowhere else. The client never stores it (spec section
    /// 4.4). Answers with an [`EngineState`] naming the key's last four
    /// characters.
    SetClaudeKey {
        /// The key. Its `Debug` is redacted, so the request can be printed.
        key: ClaudeKey,
    },
    /// Remove the Claude API key from the Keychain. An active Claude engine is
    /// turned off with it. Answers with an [`EngineState`].
    RemoveClaudeKey,
    /// Read every choice the user made, or move some of them: the Rule Feed
    /// toggle, the app update check, the Posture and the config-dir override
    /// per Agent (spec sections 6.9 and 8.10). Answers with a
    /// [`SettingsState`]. A change the daemon refuses leaves every choice as
    /// it was. The override is a directory the user named, the one path on
    /// the wire outside revealing a Receipt and the Folder Scan (ADR 0008);
    /// it travels under `config_dirs`, never as a `path`.
    Settings {
        /// What to move; nothing to read only.
        change: SettingsChange,
    },
}

impl Request {
    /// The spelling of every request.
    pub const NAMES: [&'static str; 17] = [
        "status",
        "scan-now",
        "subscribe",
        "quarantine",
        "restore",
        "trust",
        "acknowledge",
        "fix",
        "re-enable",
        "reveal-receipt",
        "rule-feed",
        "sessions",
        "folder-scan",
        "engine",
        "set-claude-key",
        "remove-claude-key",
        "settings",
    ];

    /// The spelling a request carries.
    pub fn as_str(&self) -> &'static str {
        match self {
            Request::Status => "status",
            Request::ScanNow => "scan-now",
            Request::Subscribe => "subscribe",
            Request::Quarantine { .. } => "quarantine",
            Request::Restore { .. } => "restore",
            Request::Trust { .. } => "trust",
            Request::Acknowledge { .. } => "acknowledge",
            Request::Fix { .. } => "fix",
            Request::ReEnable { .. } => "re-enable",
            Request::RevealReceipt { .. } => "reveal-receipt",
            Request::RuleFeed { .. } => "rule-feed",
            Request::Sessions => "sessions",
            Request::Folder { .. } => "folder-scan",
            Request::Engine { .. } => "engine",
            Request::SetClaudeKey { .. } => "set-claude-key",
            Request::RemoveClaudeKey => "remove-claude-key",
            Request::Settings { .. } => "settings",
        }
    }

    /// True for the requests that may carry a `path` field: revealing a
    /// Receipt and the Folder Scan. Every other one addresses ids only (ADR
    /// 0008), but for the config-dir override of the `settings` request,
    /// which travels under its own field, never as a `path`.
    pub fn takes_a_path(name: &str) -> bool {
        matches!(name, "reveal-receipt" | "folder-scan")
    }

    /// The id the request addresses, where it addresses one.
    pub fn target(&self) -> Option<&str> {
        match self {
            Request::Quarantine { target }
            | Request::Restore { target, .. }
            | Request::Trust { target }
            | Request::Acknowledge { target }
            | Request::Fix { target }
            | Request::ReEnable { target } => Some(target),
            _ => None,
        }
    }

    /// The request's fields, beside its name.
    fn write_into(&self, map: &mut Map<String, Value>) {
        map.insert("request".to_string(), Value::from(self.as_str()));
        if let Some(target) = self.target() {
            map.insert("target".to_string(), Value::from(target));
        }
        match self {
            Request::Restore { conflict, .. } => {
                map.insert(
                    "conflict".to_string(),
                    Value::from(conflict_name(*conflict)),
                );
            }
            Request::RevealReceipt { path: Some(path) } | Request::Folder { path } => {
                map.insert("path".to_string(), Value::from(path.as_str()));
            }
            Request::RuleFeed {
                enabled: Some(enabled),
            } => {
                map.insert("enabled".to_string(), Value::from(*enabled));
            }
            Request::Engine { change } => change.write_into(map),
            Request::Settings { change } => change.write_into(map),
            Request::SetClaudeKey { key } => {
                map.insert("key".to_string(), Value::from(key.expose()));
            }
            _ => {}
        }
    }

    /// Reads one request back out of a message, or nothing when it is not
    /// one of the closed list: an unknown name, a missing target, or a path on
    /// a request that takes none.
    fn read_from(value: &Value) -> Option<Request> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let name = text("request")?;
        if value.get("path").is_some() && !Request::takes_a_path(name) {
            return None;
        }
        let target = || text("target").map(str::to_string);
        Some(match name {
            "status" => Request::Status,
            "scan-now" => Request::ScanNow,
            "subscribe" => Request::Subscribe,
            "quarantine" => Request::Quarantine { target: target()? },
            "restore" => Request::Restore {
                target: target()?,
                conflict: match text("conflict") {
                    None => Conflict::Refuse,
                    Some(name) => parse_conflict(name)?,
                },
            },
            "trust" => Request::Trust { target: target()? },
            "acknowledge" => Request::Acknowledge { target: target()? },
            "fix" => Request::Fix { target: target()? },
            "re-enable" => Request::ReEnable { target: target()? },
            "reveal-receipt" => Request::RevealReceipt {
                path: match value.get("path") {
                    None | Some(Value::Null) => None,
                    Some(path) => Some(path.as_str()?.to_string()),
                },
            },
            "rule-feed" => Request::RuleFeed {
                enabled: match value.get("enabled") {
                    None | Some(Value::Null) => None,
                    Some(enabled) => Some(enabled.as_bool()?),
                },
            },
            "sessions" => Request::Sessions,
            "folder-scan" => Request::Folder {
                path: text("path")?.to_string(),
            },
            "engine" => Request::Engine {
                change: EngineChange::read_from(value)?,
            },
            "set-claude-key" => Request::SetClaudeKey {
                key: ClaudeKey::new(text("key")?).ok()?,
            },
            "remove-claude-key" => Request::RemoveClaudeKey,
            "settings" => Request::Settings {
                change: SettingsChange::read_from(value)?,
            },
            _ => return None,
        })
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The spelling of a Restore's conflict choice.
pub fn conflict_name(conflict: Conflict) -> &'static str {
    match conflict {
        Conflict::Refuse => "refuse",
        Conflict::Replace => "replace",
        Conflict::Beside => "beside",
    }
}

/// Reads back that spelling.
pub fn parse_conflict(text: &str) -> Option<Conflict> {
    match text {
        "refuse" => Some(Conflict::Refuse),
        "replace" => Some(Conflict::Replace),
        "beside" => Some(Conflict::Beside),
        _ => None,
    }
}

/// Why a request was not carried out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestError {
    /// The short machine-readable reason.
    pub code: String,
    /// The sentence a person reads.
    pub message: String,
}

impl RequestError {
    /// An error with a code and a sentence.
    pub fn new(code: &str, message: impl Into<String>) -> RequestError {
        RequestError {
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// The request is not one the daemon knows.
    pub fn unknown(what: &str) -> RequestError {
        RequestError::new("unknown-request", format!("`{what}` is not a request"))
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RequestError {}

/// What the daemon sends without being asked, to every subscriber.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateEvent {
    /// A Scan began.
    ScanStarted {
        /// What started it.
        trigger: Trigger,
        /// When.
        at: Timestamp,
    },
    /// A Scan got this far.
    ScanProgress {
        /// How many Items it has looked at.
        done: usize,
        /// How many it has, zero while it is still enumerating.
        total: usize,
    },
    /// A Scan ended, with its summary.
    ScanFinished {
        /// What it found.
        summary: Box<ScanSummary>,
    },
    /// One Finding appeared, moved or went away.
    FindingChanged {
        /// Which Finding.
        id: FindingId,
        /// Where it stands now, as [`agentsweep_core::finding::FindingState`]
        /// spells it, or `gone` when it is no longer raised.
        state: String,
        /// The Finding as the status carries it now, with its facts, absent
        /// when it is gone. Additive: a daemon from before sends none, and a
        /// client that does not know it reads the id and the state as before.
        finding: Option<Box<RecordedFinding>>,
    },
    /// A line for the Activity that is not a Finding: a Rule Pack accepted,
    /// a Rule withdrawn with the Findings it took with it. It is the live
    /// signal; what stays is the Event Log record the line was built from.
    Activity {
        /// The line, free of content and of sensitive values.
        line: String,
        /// The sequence of the Event Log record the line was built from, so a
        /// client can tell it from the same line in the status. Absent for a
        /// line no record stands behind.
        sequence: Option<u64>,
    },
    /// Health moved: a Scan started or ended, a chain was verified, the Rule
    /// Feed or the pack in force changed, or an action settled a Finding. It
    /// carries the whole struct, so a subscriber renders the sentence without
    /// asking for the status again (spec section 6.3).
    HealthChanged {
        /// Every state the machine is in now.
        health: Box<Health>,
    },
    /// A choice the user made moved, through any request and from any window.
    /// It carries every choice, so a second open window follows without
    /// asking again.
    SettingsChanged {
        /// Where every choice stands now.
        settings: Box<SettingsState>,
    },
}

impl StateEvent {
    /// The spelling the message carries.
    pub fn name(&self) -> &'static str {
        match self {
            StateEvent::ScanStarted { .. } => "scan-started",
            StateEvent::ScanProgress { .. } => "scan-progress",
            StateEvent::ScanFinished { .. } => "scan-finished",
            StateEvent::FindingChanged { .. } => "finding-changed",
            StateEvent::Activity { .. } => "activity",
            StateEvent::HealthChanged { .. } => "health-changed",
            StateEvent::SettingsChanged { .. } => "settings-changed",
        }
    }
}

/// What a `status` request answers with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Every state the machine is in.
    pub health: Health,
    /// The most recent Scan, absent before the first one finished.
    pub scan: Option<ScanSummary>,
    /// The Findings the last Scan left standing.
    pub findings: Vec<RecordedFinding>,
    /// The Activity lines the Event Log keeps, oldest first: every change of
    /// the Rule Pack in force, with what it withdrew.
    pub activity: Vec<ActivityLine>,
}

/// One Activity line read from the Event Log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityLine {
    /// The sequence of the record it was built from.
    pub sequence: u64,
    /// When that record was written.
    pub recorded_at: Timestamp,
    /// The line, free of content and of sensitive values.
    pub line: String,
}

impl ActivityLine {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("line".to_string(), Value::from(self.line.as_str()));
        map.insert(
            "recorded_at".to_string(),
            Value::from(self.recorded_at.to_string()),
        );
        map.insert("sequence".to_string(), Value::from(self.sequence));
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<ActivityLine> {
        Some(ActivityLine {
            sequence: value.get("sequence")?.as_u64()?,
            recorded_at: Timestamp::parse(value.get("recorded_at")?.as_str()?)?,
            line: value.get("line")?.as_str()?.to_string(),
        })
    }
}

impl Status {
    /// The status a client renders when no daemon answered.
    pub fn unreachable(reason: &str) -> Status {
        Status {
            health: Health::unreachable(reason),
            scan: None,
            findings: Vec::new(),
            activity: Vec::new(),
        }
    }

    /// The Findings that still ask something of the user.
    pub fn open(&self) -> impl Iterator<Item = &RecordedFinding> {
        self.findings.iter().filter(|finding| finding.is_open())
    }

    /// The status as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "activity".to_string(),
            Value::Array(self.activity.iter().map(ActivityLine::to_value).collect()),
        );
        map.insert(
            "findings".to_string(),
            Value::Array(
                self.findings
                    .iter()
                    .map(RecordedFinding::to_value)
                    .collect(),
            ),
        );
        map.insert("health".to_string(), health_to_value(&self.health));
        map.insert(
            "scan".to_string(),
            self.scan
                .as_ref()
                .map(ScanSummary::to_value)
                .unwrap_or(Value::Null),
        );
        Value::Object(map)
    }

    /// Reads back what [`Status::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<Status> {
        let findings = value
            .get("findings")?
            .as_array()?
            .iter()
            .map(RecordedFinding::from_value)
            .collect::<Option<Vec<_>>>()?;
        let scan = match value.get("scan")? {
            Value::Null => None,
            summary => Some(ScanSummary::from_value(summary)?),
        };
        // A daemon from before the Activity was read from the Event Log sends
        // none, which reads as an empty Activity rather than as no status.
        let activity = match value.get("activity") {
            None => Vec::new(),
            Some(lines) => lines
                .as_array()?
                .iter()
                .map(ActivityLine::from_value)
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Status {
            health: health_from_value(value.get("health")?)?,
            scan,
            findings,
            activity,
        })
    }
}

/// One Health as the wire carries it.
///
/// Health is not stored anywhere, so its form lives with the protocol rather
/// than with the struct: what the daemon computes, a client renders.
pub fn health_to_value(health: &Health) -> Value {
    let mut map = Map::new();
    map.insert(
        "baseline".to_string(),
        chain_state_to_value(&health.baseline),
    );
    map.insert("events".to_string(), chain_state_to_value(&health.events));
    map.insert("headline".to_string(), Value::from(health.headline()));
    map.insert("items".to_string(), Value::from(health.items as u64));
    map.insert(
        "last_full_scan".to_string(),
        Value::from(
            health
                .last_full_scan
                .map(|at| at.to_string())
                .unwrap_or_default(),
        ),
    );
    map.insert(
        "notes".to_string(),
        Value::Array(health.notes().into_iter().map(Value::from).collect()),
    );
    map.insert(
        "open_exposures".to_string(),
        Value::from(health.open_exposures as u64),
    );
    map.insert(
        "open_threats".to_string(),
        Value::from(health.open_threats as u64),
    );
    map.insert(
        "projects_need_permission".to_string(),
        Value::from(health.projects_need_permission as u64),
    );
    map.insert(
        "feed_unreachable".to_string(),
        Value::from(
            health
                .feed_unreachable
                .map(|at| at.to_string())
                .unwrap_or_default(),
        ),
    );
    map.insert(
        "ignored_pack".to_string(),
        match &health.ignored_pack {
            None => Value::Null,
            Some(ignored) => {
                let mut pack = Map::new();
                pack.insert(
                    "minimum_engine_version".to_string(),
                    Value::from(ignored.minimum_engine_version.as_str()),
                );
                pack.insert(
                    "pack_version".to_string(),
                    Value::from(ignored.pack_version),
                );
                Value::Object(pack)
            }
        },
    );
    map.insert("rule_feed".to_string(), Value::from(health.rule_feed));
    map.insert("rule_pack".to_string(), Value::from(health.rule_pack));
    map.insert(
        "rule_pack_origin".to_string(),
        Value::from(health.rule_pack_origin.as_str()),
    );
    map.insert(
        "rules_released_at".to_string(),
        Value::from(health.rules_released_at.as_str()),
    );
    map.insert(
        "rules_updated".to_string(),
        Value::from(health.rules_updated().unwrap_or_default()),
    );
    map.insert(
        "protection".to_string(),
        Value::from(match &health.protection {
            Protection::On => "on",
            Protection::Off(_) => "off",
        }),
    );
    map.insert(
        "protection_reason".to_string(),
        Value::from(health.protection.reason()),
    );
    map.insert("scanning".to_string(), Value::from(health.scanning));
    map.insert(
        "settings_unreadable".to_string(),
        Value::from(health.settings_unreadable),
    );
    map.insert(
        "state_file".to_string(),
        Value::from(health.state_file.as_str()),
    );
    Value::Object(map)
}

/// Reads back what [`health_to_value`] wrote.
pub fn health_from_value(value: &Value) -> Option<Health> {
    let text = |field: &str| value.get(field).and_then(Value::as_str);
    let count = |field: &str| value.get(field).and_then(Value::as_u64).map(|n| n as usize);
    let protection = match text("protection")? {
        "on" => Protection::On,
        "off" => Protection::Off(text("protection_reason")?.to_string()),
        _ => return None,
    };
    let last_full_scan = match text("last_full_scan")? {
        "" => None,
        written => Some(Timestamp::parse(written)?),
    };
    let feed_unreachable = match text("feed_unreachable")? {
        "" => None,
        written => Some(Timestamp::parse(written)?),
    };
    let ignored_pack = match value.get("ignored_pack")? {
        Value::Null => None,
        pack => Some(IgnoredPack {
            pack_version: pack.get("pack_version")?.as_u64()?,
            minimum_engine_version: pack.get("minimum_engine_version")?.as_str()?.to_string(),
        }),
    };
    Some(Health {
        protection,
        events: chain_state_from_value(value.get("events")?)?,
        baseline: chain_state_from_value(value.get("baseline")?)?,
        projects_need_permission: count("projects_need_permission")?,
        state_file: StateFileHealth::parse(text("state_file")?)?,
        settings_unreadable: value.get("settings_unreadable")?.as_bool()?,
        scanning: value.get("scanning")?.as_bool()?,
        last_full_scan,
        items: count("items")?,
        open_threats: count("open_threats")?,
        open_exposures: count("open_exposures")?,
        rule_pack: value.get("rule_pack")?.as_u64()?,
        rule_pack_origin: PackOrigin::parse(text("rule_pack_origin")?)?,
        rules_released_at: text("rules_released_at")?.to_string(),
        rule_feed: value.get("rule_feed")?.as_bool()?,
        ignored_pack,
        feed_unreachable,
    })
}

/// One chain state as the wire carries it: what verification found, and where
/// it stopped when it found a break.
fn chain_state_to_value(state: &ChainState) -> Value {
    let mut map = Map::new();
    let (name, sequence, reason) = match state {
        ChainState::Intact => ("intact", 0u64, String::new()),
        ChainState::KeyMissing => ("key-missing", 0, String::new()),
        ChainState::Broken { sequence, reason } => ("broken", *sequence, reason.to_string()),
    };
    map.insert("reason".to_string(), Value::from(reason));
    map.insert("sequence".to_string(), Value::from(sequence));
    map.insert("state".to_string(), Value::from(name));
    Value::Object(map)
}

/// Reads back what [`chain_state_to_value`] wrote.
///
/// The break reason is a sentence rather than a code, because nothing acts on
/// it: the Developer Posture prints it and the precedence reads the state. It
/// comes back as [`BreakReason::Malformed`] carrying that sentence.
fn chain_state_from_value(value: &Value) -> Option<ChainState> {
    match value.get("state")?.as_str()? {
        "intact" => Some(ChainState::Intact),
        "key-missing" => Some(ChainState::KeyMissing),
        "broken" => Some(ChainState::Broken {
            sequence: value.get("sequence")?.as_u64()?,
            reason: BreakReason::Malformed(value.get("reason")?.as_str()?.to_string()),
        }),
        _ => None,
    }
}

/// Whether the sessions of one Agent appear to be running.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSessions {
    /// The Agent, by adapter id.
    pub agent: String,
    /// What detection found for it.
    pub running: SessionsRunning,
    /// How many live sessions it found, zero when it could not tell.
    pub live: usize,
}

/// Whether Agent sessions appear to be running, which every action result
/// states (spec section 5.3).
///
/// Detected read-only, from the session files an Agent keeps and a liveness
/// check on the process id they name. AgentSweep never signals or stops a
/// session; it tells the user to restart one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sessions {
    /// The answer across every Agent: yes when any session is live, unknown
    /// when an installed Agent could not be asked, no otherwise.
    pub running: SessionsRunning,
    /// The answer per Agent.
    pub agents: Vec<AgentSessions>,
}

impl Sessions {
    /// Nothing was detected, which is what a request that acted on nothing
    /// carries.
    pub fn unknown() -> Sessions {
        Sessions {
            running: SessionsRunning::Unknown,
            agents: Vec::new(),
        }
    }

    /// The answer across Agents, from the answers per Agent.
    pub fn of(agents: Vec<AgentSessions>) -> Sessions {
        let running = if agents.iter().any(|one| one.running == SessionsRunning::Yes) {
            SessionsRunning::Yes
        } else if agents
            .iter()
            .any(|one| one.running == SessionsRunning::Unknown)
        {
            SessionsRunning::Unknown
        } else {
            SessionsRunning::No
        };
        Sessions { running, agents }
    }

    /// The sentence a person reads under an action.
    pub fn sentence(&self) -> String {
        let named = |wanted: SessionsRunning| -> Vec<String> {
            self.agents
                .iter()
                .filter(|one| one.running == wanted)
                .map(|one| match one.live {
                    0 => one.agent.clone(),
                    live => format!("{} ({live})", one.agent),
                })
                .collect()
        };
        match self.running {
            SessionsRunning::Yes => format!(
                "Agent sessions appear to be running: {}. Restart them so they stop using what \
                 changed.",
                named(SessionsRunning::Yes).join(", ")
            ),
            SessionsRunning::No => "No Agent session appears to be running.".to_string(),
            SessionsRunning::Unknown => {
                let unknown = named(SessionsRunning::Unknown);
                match unknown.is_empty() {
                    true => "AgentSweep could not tell whether Agent sessions are running; \
                             restart any that are open."
                        .to_string(),
                    false => format!(
                        "AgentSweep could not tell whether sessions of {} are running; restart \
                         any that are open.",
                        unknown.join(", ")
                    ),
                }
            }
        }
    }

    /// The answer as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "agents".to_string(),
            Value::Array(
                self.agents
                    .iter()
                    .map(|one| {
                        let mut agent = Map::new();
                        agent.insert("agent".to_string(), Value::from(one.agent.as_str()));
                        agent.insert("live".to_string(), Value::from(one.live as u64));
                        agent.insert("running".to_string(), Value::from(one.running.as_str()));
                        Value::Object(agent)
                    })
                    .collect(),
            ),
        );
        map.insert("running".to_string(), Value::from(self.running.as_str()));
        Value::Object(map)
    }

    /// Reads back what [`Sessions::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<Sessions> {
        let agents = value
            .get("agents")?
            .as_array()?
            .iter()
            .map(|one| {
                Some(AgentSessions {
                    agent: one.get("agent")?.as_str()?.to_string(),
                    running: SessionsRunning::parse(one.get("running")?.as_str()?)?,
                    live: one.get("live")?.as_u64()? as usize,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Sessions {
            running: SessionsRunning::parse(value.get("running")?.as_str()?)?,
            agents,
        })
    }
}

/// What one action did, which the daemon answers every action request with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReport {
    /// Which request it answers, as [`Request::as_str`] spells it.
    pub action: String,
    /// The Finding it acted on, empty when it addressed a Receipt alone.
    pub finding_id: String,
    /// The Item it acted on.
    pub item_id: String,
    /// The Receipt it wrote or replayed, empty for Trust and Acknowledge.
    pub receipt_id: String,
    /// Where the Finding stands now, as [`FindingState`] spells it.
    pub state: String,
    /// How it came out as a whole.
    pub result: Outcome,
    /// What it physically did, step by step, with each step's outcome.
    pub steps: Vec<ReceiptStep>,
    /// True when it wrote a Trust record: a Trust, or the Restore of what
    /// AgentSweep took out by itself.
    pub trusted: bool,
    /// Whether Agent sessions appear to be running.
    pub sessions: Sessions,
    /// The sentence a person reads first.
    pub message: String,
}

impl ActionReport {
    /// The report as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("action".to_string(), Value::from(self.action.as_str()));
        map.insert(
            "finding_id".to_string(),
            Value::from(self.finding_id.as_str()),
        );
        map.insert("item_id".to_string(), Value::from(self.item_id.as_str()));
        map.insert("message".to_string(), Value::from(self.message.as_str()));
        map.insert(
            "receipt_id".to_string(),
            Value::from(self.receipt_id.as_str()),
        );
        map.insert("result".to_string(), Value::from(self.result.as_str()));
        map.insert("sessions".to_string(), self.sessions.to_value());
        map.insert("state".to_string(), Value::from(self.state.as_str()));
        map.insert(
            "steps".to_string(),
            Value::Array(self.steps.iter().map(step_to_value).collect()),
        );
        map.insert("trusted".to_string(), Value::from(self.trusted));
        Value::Object(map)
    }

    /// Reads back what [`ActionReport::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<ActionReport> {
        let text = |field: &str| value.get(field).and_then(Value::as_str).map(str::to_string);
        Some(ActionReport {
            action: text("action")?,
            finding_id: text("finding_id")?,
            item_id: text("item_id")?,
            receipt_id: text("receipt_id")?,
            state: text("state")?,
            result: Outcome::parse(&text("result")?)?,
            steps: value
                .get("steps")?
                .as_array()?
                .iter()
                .map(step_from_value)
                .collect::<Option<Vec<_>>>()?,
            trusted: value.get("trusted")?.as_bool()?,
            sessions: Sessions::from_value(value.get("sessions")?)?,
            message: text("message")?,
        })
    }
}

/// One Receipt step as the wire carries it.
fn step_to_value(step: &ReceiptStep) -> Value {
    let mut map = Map::new();
    map.insert("detail".to_string(), Value::from(step.detail.as_str()));
    map.insert("locator".to_string(), Value::from(step.locator.as_str()));
    map.insert("outcome".to_string(), Value::from(step.outcome.as_str()));
    map.insert("path".to_string(), Value::from(step.path.as_str()));
    map.insert(
        "primitive".to_string(),
        Value::from(step.primitive.as_str()),
    );
    Value::Object(map)
}

/// Reads back what [`step_to_value`] wrote.
fn step_from_value(value: &Value) -> Option<ReceiptStep> {
    let text = |field: &str| value.get(field).and_then(Value::as_str);
    Some(ReceiptStep {
        primitive: Primitive::parse(text("primitive")?)?,
        outcome: Outcome::parse(text("outcome")?)?,
        path: text("path")?.to_string(),
        locator: text("locator")?.to_string(),
        detail: text("detail")?.to_string(),
    })
}

/// One Receipt in the quarantine store, with the place its Item was taken
/// from printed beside its id (spec section 5.1). The store's own names say
/// nothing; this is where the legibility comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealedReceipt {
    /// The Receipt's id.
    pub receipt_id: String,
    /// The Item it took out.
    pub item_id: ItemId,
    /// That Item's kind, absent when the record named none.
    pub kind: Option<Kind>,
    /// Where the Item sat before it was taken out.
    pub original_path: String,
    /// Where its payload sits in the store, empty when nothing moved (an entry
    /// taken out of its file keeps no payload).
    pub payload_path: String,
    /// Whether AgentSweep or the user took it out.
    pub actor: Actor,
    /// When.
    pub quarantined_at: Timestamp,
    /// The Finding behind it.
    pub finding_id: String,
    /// The Rule behind it, zero where none applies.
    pub rule_id: i64,
    /// How often it came back and was taken out again.
    pub re_enforced: u32,
}

impl RevealedReceipt {
    /// The Receipt as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("actor".to_string(), Value::from(self.actor.as_str()));
        map.insert(
            "finding_id".to_string(),
            Value::from(self.finding_id.as_str()),
        );
        map.insert("item_id".to_string(), Value::from(self.item_id.as_str()));
        map.insert(
            "kind".to_string(),
            Value::from(self.kind.map(Kind::as_str).unwrap_or_default()),
        );
        map.insert(
            "original_path".to_string(),
            Value::from(self.original_path.as_str()),
        );
        map.insert(
            "payload_path".to_string(),
            Value::from(self.payload_path.as_str()),
        );
        map.insert(
            "quarantined_at".to_string(),
            Value::from(self.quarantined_at.to_string()),
        );
        map.insert("re_enforced".to_string(), Value::from(self.re_enforced));
        map.insert(
            "receipt_id".to_string(),
            Value::from(self.receipt_id.as_str()),
        );
        map.insert("rule_id".to_string(), Value::from(self.rule_id));
        Value::Object(map)
    }

    /// Reads back what [`RevealedReceipt::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<RevealedReceipt> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        Some(RevealedReceipt {
            receipt_id: text("receipt_id")?.to_string(),
            item_id: ItemId::from_recorded(text("item_id")?),
            kind: match text("kind")? {
                "" => None,
                kind => Some(Kind::parse(kind)?),
            },
            original_path: text("original_path")?.to_string(),
            payload_path: text("payload_path")?.to_string(),
            actor: Actor::parse(text("actor")?)?,
            quarantined_at: Timestamp::parse(text("quarantined_at")?)?,
            finding_id: text("finding_id")?.to_string(),
            rule_id: value.get("rule_id")?.as_i64()?,
            re_enforced: value.get("re_enforced")?.as_u64()? as u32,
        })
    }
}

/// The answer to a reveal-receipt request.
pub fn receipts_to_value(receipts: &[RevealedReceipt]) -> Value {
    Value::Array(receipts.iter().map(RevealedReceipt::to_value).collect())
}

/// Reads back what [`receipts_to_value`] wrote.
pub fn receipts_from_value(value: &Value) -> Option<Vec<RevealedReceipt>> {
    value
        .as_array()?
        .iter()
        .map(RevealedReceipt::from_value)
        .collect()
}

/// The answer of a Folder Scan that found nothing (spec section 8.9).
pub const SAFE_TO_OPEN: &str = "Safe to open.";

/// The answer of a Folder Scan that found something, a Problem included.
pub const DO_NOT_OPEN_YET: &str = "Do not open yet.";

/// What every Folder Scan answer says under its verdict.
pub const NOTHING_RECORDED: &str = "Nothing was recorded.";

/// One Finding of a Folder Scan, with the lines a person reads under it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderFinding {
    /// The Finding, flattened the way the status carries one. It is open, and
    /// nothing is offered on it: a Folder Scan records nothing to act on.
    pub finding: RecordedFinding,
    /// The Heuristics that fired on its Item, one line each: id, Weight and
    /// plain sentence. Never matched text.
    pub heuristics: Vec<String>,
}

/// What a Folder Scan found, which the daemon answers a `folder-scan` request
/// with. Nothing of it was recorded anywhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderScanResult {
    /// The folder as it resolved.
    pub root: String,
    /// How many Items it enumerated and judged.
    pub items: usize,
    /// How many of them fell in the Ambiguous Band: named, nothing to do.
    pub ambiguous: usize,
    /// Every Finding, a Problem included, in the order the Items were found.
    pub findings: Vec<FolderFinding>,
    /// The version of the Rule Pack in force that judged the folder. The
    /// in-process `agentsweep scan <dir>` uses the bundled pack instead, so
    /// the two may answer differently, and each names the pack it used.
    pub rule_pack: u64,
}

impl FolderScanResult {
    /// True when nothing was found: "safe to open". A Problem is a Finding, so
    /// a Surface that could not be read through never counts as clear.
    pub fn is_safe(&self) -> bool {
        self.findings.is_empty()
    }

    /// The one-line answer.
    pub fn verdict(&self) -> &'static str {
        match self.is_safe() {
            true => SAFE_TO_OPEN,
            false => DO_NOT_OPEN_YET,
        }
    }

    /// The result as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("ambiguous".to_string(), Value::from(self.ambiguous as u64));
        map.insert(
            "findings".to_string(),
            Value::Array(
                self.findings
                    .iter()
                    .map(|one| {
                        let mut finding = Map::new();
                        finding.insert("finding".to_string(), one.finding.to_value());
                        finding.insert(
                            "heuristics".to_string(),
                            Value::Array(
                                one.heuristics
                                    .iter()
                                    .map(|line| Value::from(line.as_str()))
                                    .collect(),
                            ),
                        );
                        Value::Object(finding)
                    })
                    .collect(),
            ),
        );
        map.insert("items".to_string(), Value::from(self.items as u64));
        map.insert("root".to_string(), Value::from(self.root.as_str()));
        map.insert("rule_pack".to_string(), Value::from(self.rule_pack));
        Value::Object(map)
    }

    /// Reads back what [`FolderScanResult::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<FolderScanResult> {
        let findings = value
            .get("findings")?
            .as_array()?
            .iter()
            .map(|one| {
                Some(FolderFinding {
                    finding: RecordedFinding::from_value(one.get("finding")?)?,
                    heuristics: one
                        .get("heuristics")?
                        .as_array()?
                        .iter()
                        .map(|line| line.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(FolderScanResult {
            root: value.get("root")?.as_str()?.to_string(),
            items: value.get("items")?.as_u64()? as usize,
            ambiguous: value.get("ambiguous")?.as_u64()? as usize,
            findings,
            rule_pack: value.get("rule_pack")?.as_u64()?,
        })
    }
}

/// One action the daemon allows on a Finding as it stands, which is what a
/// client offers beside it (spec section 8.5). A client never works this out
/// for itself from anything but a Finding the daemon sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Offer {
    /// Take the Item out: any open Threat Finding, never a Managed Item.
    Quarantine,
    /// Put a stopped Item back.
    Restore,
    /// Switch a stopped plugin back on for its newer, clean version.
    ReEnable,
    /// Call this exact content safe ("Trust this version", "Keep it as it
    /// is" on an Exposure).
    Trust,
    /// "Yes, that was me" on a Drift Finding.
    Acknowledge,
    /// The one-click fix of Exposures 0018 and 0019.
    Fix,
}

impl Offer {
    /// The request name each offer is carried out by.
    pub fn as_str(self) -> &'static str {
        match self {
            Offer::Quarantine => "quarantine",
            Offer::Restore => "restore",
            Offer::ReEnable => "re-enable",
            Offer::Trust => "trust",
            Offer::Acknowledge => "acknowledge",
            Offer::Fix => "fix",
        }
    }
}

/// The source spelling a Drift Finding carries.
const DRIFT_SOURCE: &str = "drift";

/// The Rule ids whose Exposure offers the one-click fix.
const FIXABLE_EXPOSURES: [i64; 2] = agentsweep_core::enforcement::FIXABLE_EXPOSURES;

/// What the daemon allows on one Finding as it stands.
///
/// A Managed Item is only ever flagged, an Exposure is never quarantined, a
/// Problem has no content to trust, and a Finding that is no longer open is
/// only restored or re-enabled (spec sections 5.2 and 8.5).
pub fn offers(finding: &RecordedFinding) -> Vec<Offer> {
    let managed = finding.item_id.in_scope("managed");
    let problem = finding.content_hash.is_empty() || finding.source.starts_with("problem");
    match finding.state {
        FindingState::Stopped => {
            let mut offered = vec![Offer::Restore];
            if !finding.fixed_version.is_empty() {
                offered.push(Offer::ReEnable);
            }
            offered
        }
        FindingState::Open if problem => Vec::new(),
        FindingState::Open => {
            let mut offered = Vec::new();
            match finding.category {
                Category::Threat => {
                    if !managed {
                        offered.push(Offer::Quarantine);
                    }
                    offered.push(Offer::Trust);
                    if finding.source == DRIFT_SOURCE {
                        offered.push(Offer::Acknowledge);
                    }
                }
                Category::Exposure => {
                    offered.push(Offer::Trust);
                    if !managed
                        && FIXABLE_EXPOSURES.contains(&finding.rule_id)
                        && finding.kind == Kind::SettingsEntry
                    {
                        offered.push(Offer::Fix);
                    }
                }
            }
            offered
        }
        FindingState::Trusted | FindingState::Acknowledged | FindingState::Gone => Vec::new(),
    }
}

/// One message on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    /// A client's handshake.
    Hello(Hello),
    /// The daemon's answer to a handshake it accepted.
    Welcome {
        /// The daemon's version.
        version: String,
        /// The daemon's launch agent label.
        daemon: String,
    },
    /// The daemon's answer to a handshake it refused. The connection closes
    /// after it.
    Refused(Refusal),
    /// A client's request, with the id its answer will carry.
    Request {
        /// The id the answer carries.
        id: String,
        /// What is being asked.
        request: Request,
    },
    /// The daemon's answer to one request.
    Response {
        /// The id of the request it answers.
        id: String,
        /// What the request answered with, or why it did not.
        result: Result<Value, RequestError>,
    },
    /// One state event on the subscribe stream.
    Event(StateEvent),
}

impl Message {
    /// The message as the wire carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        match self {
            Message::Hello(hello) => {
                map.insert("type".to_string(), Value::from("hello"));
                map.insert("version".to_string(), Value::from(hello.version.as_str()));
                map.insert("role".to_string(), Value::from(hello.role.as_str()));
            }
            Message::Welcome { version, daemon } => {
                map.insert("type".to_string(), Value::from("welcome"));
                map.insert("version".to_string(), Value::from(version.as_str()));
                map.insert("daemon".to_string(), Value::from(daemon.as_str()));
            }
            Message::Refused(refusal) => {
                map.insert("type".to_string(), Value::from("refused"));
                map.insert("reason".to_string(), Value::from(refusal.reason()));
                map.insert("message".to_string(), Value::from(refusal.message()));
                map.insert("detail".to_string(), Value::from(refusal.detail()));
                if let Refusal::VersionMismatch { daemon_version, .. } = refusal {
                    map.insert("version".to_string(), Value::from(daemon_version.as_str()));
                }
            }
            Message::Request { id, request } => {
                map.insert("type".to_string(), Value::from("request"));
                map.insert("id".to_string(), Value::from(id.as_str()));
                request.write_into(&mut map);
            }
            Message::Response { id, result } => {
                map.insert("type".to_string(), Value::from("response"));
                map.insert("id".to_string(), Value::from(id.as_str()));
                match result {
                    Ok(value) => {
                        map.insert("ok".to_string(), Value::from(true));
                        map.insert("result".to_string(), value.clone());
                    }
                    Err(error) => {
                        map.insert("ok".to_string(), Value::from(false));
                        let mut failure = Map::new();
                        failure.insert("code".to_string(), Value::from(error.code.as_str()));
                        failure.insert("message".to_string(), Value::from(error.message.as_str()));
                        map.insert("error".to_string(), Value::Object(failure));
                    }
                }
            }
            Message::Event(event) => {
                map.insert("type".to_string(), Value::from("event"));
                map.insert("event".to_string(), Value::from(event.name()));
                match event {
                    StateEvent::ScanStarted { trigger, at } => {
                        map.insert("trigger".to_string(), Value::from(trigger.as_str()));
                        map.insert("at".to_string(), Value::from(at.to_string()));
                    }
                    StateEvent::ScanProgress { done, total } => {
                        map.insert("done".to_string(), Value::from(*done as u64));
                        map.insert("total".to_string(), Value::from(*total as u64));
                    }
                    StateEvent::ScanFinished { summary } => {
                        map.insert("summary".to_string(), summary.to_value());
                    }
                    StateEvent::FindingChanged { id, state, finding } => {
                        map.insert("id".to_string(), Value::from(id.as_str()));
                        map.insert("state".to_string(), Value::from(state.as_str()));
                        if let Some(finding) = finding {
                            map.insert("finding".to_string(), finding.to_value());
                        }
                    }
                    StateEvent::Activity { line, sequence } => {
                        map.insert("line".to_string(), Value::from(line.as_str()));
                        if let Some(sequence) = sequence {
                            map.insert("sequence".to_string(), Value::from(*sequence));
                        }
                    }
                    StateEvent::HealthChanged { health } => {
                        map.insert("health".to_string(), health_to_value(health));
                    }
                    StateEvent::SettingsChanged { settings } => {
                        map.insert("settings".to_string(), settings.to_value());
                    }
                }
            }
        }
        Value::Object(map)
    }

    /// Reads back what [`Message::to_value`] wrote, or nothing when the object
    /// is not a message of this protocol.
    pub fn from_value(value: &Value) -> Option<Message> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        match text("type")? {
            "hello" => Some(Message::Hello(Hello {
                version: text("version")?.to_string(),
                role: Role::parse(text("role")?)?,
            })),
            "welcome" => Some(Message::Welcome {
                version: text("version")?.to_string(),
                daemon: text("daemon")?.to_string(),
            }),
            "refused" => {
                let detail = text("detail").unwrap_or_default().to_string();
                Some(Message::Refused(match text("reason")? {
                    "version-mismatch" => Refusal::VersionMismatch {
                        daemon_version: text("version").unwrap_or_default().to_string(),
                        peer_version: agentsweep_core::VERSION.to_string(),
                    },
                    "unsigned-peer" => Refusal::UnsignedPeer { detail },
                    _ => Refusal::NotAHandshake { detail },
                }))
            }
            "request" => Some(Message::Request {
                id: text("id")?.to_string(),
                request: Request::read_from(value)?,
            }),
            "response" => {
                let id = text("id")?.to_string();
                let result = if value.get("ok")?.as_bool()? {
                    Ok(value.get("result").cloned().unwrap_or(Value::Null))
                } else {
                    let error = value.get("error")?;
                    Err(RequestError {
                        code: error.get("code")?.as_str()?.to_string(),
                        message: error.get("message")?.as_str()?.to_string(),
                    })
                };
                Some(Message::Response { id, result })
            }
            "event" => {
                let count = |field: &str| value.get(field).and_then(Value::as_u64);
                Some(Message::Event(match text("event")? {
                    "scan-started" => StateEvent::ScanStarted {
                        trigger: Trigger::parse(text("trigger")?)?,
                        at: Timestamp::parse(text("at")?)?,
                    },
                    "scan-progress" => StateEvent::ScanProgress {
                        done: count("done")? as usize,
                        total: count("total")? as usize,
                    },
                    "scan-finished" => StateEvent::ScanFinished {
                        summary: Box::new(ScanSummary::from_value(value.get("summary")?)?),
                    },
                    "finding-changed" => StateEvent::FindingChanged {
                        id: FindingId::from_recorded(text("id")?),
                        state: text("state")?.to_string(),
                        finding: value
                            .get("finding")
                            .and_then(RecordedFinding::from_value)
                            .map(Box::new),
                    },
                    "activity" => StateEvent::Activity {
                        line: text("line")?.to_string(),
                        sequence: value.get("sequence").and_then(Value::as_u64),
                    },
                    "health-changed" => StateEvent::HealthChanged {
                        health: Box::new(health_from_value(value.get("health")?)?),
                    },
                    "settings-changed" => StateEvent::SettingsChanged {
                        settings: Box::new(SettingsState::from_value(value.get("settings")?)?),
                    },
                    _ => return None,
                }))
            }
            _ => None,
        }
    }
}

/// What the daemon answers a handshake with when it accepts it.
pub fn welcome() -> Message {
    Message::Welcome {
        version: agentsweep_core::VERSION.to_string(),
        daemon: agentsweep_core::DAEMON_LABEL.to_string(),
    }
}

/// Whether this handshake is one the daemon may answer, on version alone.
///
/// Application, daemon and command line interface always share one version
/// (spec section 6.3), so anything else is a half-finished update and the
/// answer is to restart AgentSweep rather than to guess at compatibility.
pub fn check_version(hello: &Hello) -> Result<(), Refusal> {
    if hello.version == agentsweep_core::VERSION {
        return Ok(());
    }
    Err(Refusal::VersionMismatch {
        daemon_version: agentsweep_core::VERSION.to_string(),
        peer_version: hello.version.clone(),
    })
}

/// The Findings of a status answer, by Item, so a client can group them the
/// way the Findings window does.
pub fn by_item(status: &Status) -> BTreeMap<String, Vec<&RecordedFinding>> {
    let mut grouped: BTreeMap<String, Vec<&RecordedFinding>> = BTreeMap::new();
    for finding in &status.findings {
        grouped
            .entry(finding.item_id.as_str().to_string())
            .or_default()
            .push(finding);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::scan_pass::ScanKind;

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    fn summary() -> ScanSummary {
        ScanSummary {
            kind: ScanKind::Full,
            trigger: Trigger::DaemonStart,
            started_at: moment("2026-09-24T08:00:00.000Z"),
            duration_ms: 900,
            items: 17,
            threats: 1,
            exposures: 0,
            clear: 16,
            ambiguous: 1,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        }
    }

    fn round_trip(message: Message) {
        let value = message.to_value();
        assert_eq!(Message::from_value(&value), Some(message), "{value}");
    }

    #[test]
    fn every_message_of_the_protocol_round_trips() {
        round_trip(Message::Hello(Hello::of(Role::Cli)));
        round_trip(Message::Hello(Hello::of(Role::App)));
        round_trip(welcome());
        round_trip(Message::Refused(Refusal::UnsignedPeer {
            detail: "no code signature".to_string(),
        }));
        round_trip(Message::Refused(Refusal::NotAHandshake {
            detail: "a request".to_string(),
        }));
        for request in every_request() {
            round_trip(Message::Request {
                id: "7".to_string(),
                request,
            });
        }
        round_trip(Message::Response {
            id: "7".to_string(),
            result: Ok(Value::from(true)),
        });
        round_trip(Message::Response {
            id: "7".to_string(),
            result: Err(RequestError::unknown("nonsense")),
        });
        round_trip(Message::Event(StateEvent::ScanStarted {
            trigger: Trigger::ScanNow,
            at: moment("2026-09-24T08:00:00.000Z"),
        }));
        round_trip(Message::Event(StateEvent::ScanProgress {
            done: 3,
            total: 17,
        }));
        round_trip(Message::Event(StateEvent::ScanFinished {
            summary: Box::new(summary()),
        }));
        round_trip(Message::Event(StateEvent::FindingChanged {
            id: FindingId::from_recorded("claude-code/user/skill/x|rule/0001|abc"),
            state: "open".to_string(),
            finding: None,
        }));
        round_trip(Message::Event(StateEvent::Activity {
            line: "Rule Pack 2 accepted".to_string(),
            sequence: None,
        }));
        round_trip(Message::Event(StateEvent::Activity {
            line: "Rule 0001 was withdrawn by Rule Pack 2.".to_string(),
            sequence: Some(7),
        }));
        round_trip(Message::Event(StateEvent::HealthChanged {
            health: Box::new(Health {
                scanning: true,
                open_threats: 2,
                open_exposures: 1,
                ..Health::running()
            }),
        }));
        round_trip(Message::Event(StateEvent::SettingsChanged {
            settings: Box::new(SettingsState {
                rule_feed: true,
                update_check: false,
                posture: agentsweep_core::settings::Posture::Developer,
                config_dirs: BTreeMap::from([(
                    "codex".to_string(),
                    "/Volumes/Work/.codex".to_string(),
                )]),
                engine: EngineState {
                    engine: agentsweep_core::settings::JudgementEngine::Off,
                    ollama_address: "127.0.0.1:11434".to_string(),
                    ollama_model: String::new(),
                    claude_model: String::new(),
                    claude_model_in_use: "claude-sonnet-5".to_string(),
                    caps: agentsweep_core::settings::CloudCaps::default(),
                    claude_key_ending: None,
                    recorded: 0,
                },
            }),
        }));
    }

    /// A version mismatch round trips as the refusal rather than as the two
    /// versions: what a peer does with it is restart, and the sentence says so.
    #[test]
    fn a_version_mismatch_carries_the_fixed_sentence() {
        let refusal = Refusal::VersionMismatch {
            daemon_version: "9.9.9".to_string(),
            peer_version: agentsweep_core::VERSION.to_string(),
        };
        assert_eq!(refusal.reason(), "version-mismatch");
        assert_eq!(refusal.message(), RESTART_AGENTSWEEP);
        let value = Message::Refused(refusal).to_value();
        assert_eq!(value["message"], Value::from(RESTART_AGENTSWEEP));
        assert_eq!(value["version"], Value::from("9.9.9"));
    }

    #[test]
    fn a_handshake_of_this_version_is_accepted_and_any_other_is_not() {
        assert!(check_version(&Hello::of(Role::Cli)).is_ok());
        let older = Hello {
            version: "0.0.1".to_string(),
            role: Role::App,
        };
        let refusal = check_version(&older).expect_err("another version is refused");
        assert_eq!(refusal.message(), RESTART_AGENTSWEEP);
    }

    #[test]
    fn a_status_round_trips_with_its_health_and_its_findings() {
        let mut health = Health::running();
        health.items = 17;
        health.open_threats = 1;
        health.open_exposures = 2;
        health.rule_pack = 3;
        health.rule_pack_origin = agentsweep_core::packs::PackOrigin::Fetched;
        health.rules_released_at = "2026-10-01T09:30:00Z".to_string();
        health.rule_feed = false;
        health.settings_unreadable = true;
        health.ignored_pack = Some(IgnoredPack {
            pack_version: 4,
            minimum_engine_version: "0.3.0".to_string(),
        });
        health.feed_unreachable = Some(moment("2026-08-01T10:00:00.000Z"));
        health.last_full_scan = Some(moment("2026-09-24T08:00:00.900Z"));
        health.events = ChainState::Broken {
            sequence: 4,
            reason: BreakReason::MacFailed,
        };
        let status = Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
            activity: vec![ActivityLine {
                sequence: 4,
                recorded_at: moment("2026-09-24T08:00:01.000Z"),
                line: "Rule 0001 was withdrawn by Rule Pack 2.".to_string(),
            }],
        };
        let value = status.to_value();
        let back = Status::from_value(&value).expect("a readable status");
        assert_eq!(back.scan, status.scan);
        assert_eq!(back.activity, status.activity);
        assert_eq!(back.health.headline(), "Records tampered.");
        assert!(back.health.records_tampered());
        assert_eq!(back.health.open_threats, 1);
        assert_eq!(back.health.open_exposures, 2);
    }

    /// A client that cannot reach the daemon says Protection is off, because
    /// silence is never an all-clear (spec section 6.2).
    #[test]
    fn an_unreachable_daemon_is_a_status_of_its_own() {
        let status = Status::unreachable("no daemon answered");
        assert_eq!(status.health.headline(), "Protection is off.");
        assert_eq!(status.open().count(), 0);
    }

    #[test]
    fn every_role_and_request_reads_back_the_spelling_it_writes() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        let mut spelled: Vec<&str> = every_request().iter().map(Request::as_str).collect();
        spelled.dedup();
        assert_eq!(spelled, Request::NAMES);
    }

    /// One of every request, with the fields it carries.
    fn every_request() -> Vec<Request> {
        let finding = "claude-code/user/skill/~/.claude/skills/x|rule/0001|abc".to_string();
        vec![
            Request::Status,
            Request::ScanNow,
            Request::Subscribe,
            Request::Quarantine {
                target: finding.clone(),
            },
            Request::Restore {
                target: "q-0123456789abcdef0123456789abcdef".to_string(),
                conflict: Conflict::Beside,
            },
            Request::Trust {
                target: finding.clone(),
            },
            Request::Acknowledge {
                target: finding.clone(),
            },
            Request::Fix {
                target: finding.clone(),
            },
            Request::ReEnable {
                target: finding.clone(),
            },
            Request::RevealReceipt {
                path: Some("/Users/someone/.claude.json".to_string()),
            },
            Request::RevealReceipt { path: None },
            Request::RuleFeed { enabled: None },
            Request::RuleFeed {
                enabled: Some(false),
            },
            Request::RuleFeed {
                enabled: Some(true),
            },
            Request::Sessions,
            Request::Folder {
                path: "/Users/someone/src/demo".to_string(),
            },
            Request::Engine {
                change: EngineChange::default(),
            },
            Request::Engine {
                change: EngineChange {
                    engine: Some(agentsweep_core::settings::JudgementEngine::Ollama),
                    ollama_address: Some("127.0.0.1:11434".to_string()),
                    ollama_model: Some("qwen3:8b".to_string()),
                    claude_model: Some(String::new()),
                    items_per_scan: Some(25),
                    items_per_day: Some(200),
                    cents_per_month: Some(500),
                },
            },
            Request::SetClaudeKey {
                key: ClaudeKey::new(A_KEY).expect("a key"),
            },
            Request::RemoveClaudeKey,
            Request::Settings {
                change: SettingsChange::default(),
            },
            Request::Settings {
                change: SettingsChange {
                    rule_feed: Some(false),
                    update_check: Some(false),
                    posture: Some(agentsweep_core::settings::Posture::Developer),
                    config_dirs: BTreeMap::from([
                        (
                            "claude-code".to_string(),
                            Some("/Users/someone/.claude-work".to_string()),
                        ),
                        ("codex".to_string(), None),
                    ]),
                },
            },
        ]
    }

    /// A defanged stand-in: the shape of a key, never a real one.
    const A_KEY: &str = "sk-ant-api03-defanged-wire-test-0000-9c1d";

    /// The key crosses the wire once, to the daemon, and a printed request
    /// never shows it.
    #[test]
    fn the_claude_key_travels_in_its_request_and_is_never_printed() {
        let request = Request::SetClaudeKey {
            key: ClaudeKey::new(A_KEY).expect("a key"),
        };
        let printed = format!("{request:?}");
        assert!(!printed.contains(A_KEY), "{printed}");
        assert!(!printed.contains("9c1d"), "{printed}");
        let message = Message::Request {
            id: "1".to_string(),
            request,
        };
        let wire = message.to_value();
        assert_eq!(wire["key"], A_KEY);
        assert_eq!(Message::from_value(&wire), Some(message));
        let implausible = serde_json::json!({
            "type": "request", "id": "1", "request": "set-claude-key", "key": "short"
        });
        assert_eq!(Message::from_value(&implausible), None);
    }

    /// ADR 0008: no request takes a path except revealing a Receipt and the
    /// Folder Scan. A path on any other request makes the message one the
    /// daemon does not understand, so it is never read and never ignored
    /// silently.
    #[test]
    fn no_request_but_reveal_receipt_and_the_folder_scan_accepts_a_path() {
        let taking: Vec<&str> = Request::NAMES
            .into_iter()
            .filter(|name| Request::takes_a_path(name))
            .collect();
        assert_eq!(taking, vec!["reveal-receipt", "folder-scan"]);

        for name in Request::NAMES {
            let value = serde_json::json!({
                "type": "request",
                "id": "1",
                "request": name,
                "target": "claude-code/user/skill/x",
                "path": "/etc",
            });
            let read = Message::from_value(&value);
            match Request::takes_a_path(name) {
                true => assert!(read.is_some(), "{name}"),
                false => assert_eq!(read, None, "{name} took a path"),
            }
        }
        // Every request that addresses something addresses an id, and a
        // request that should name one and does not is not a message either.
        let bare = serde_json::json!({"type": "request", "id": "1", "request": "quarantine"});
        assert_eq!(Message::from_value(&bare), None);
        // A Folder Scan without its folder is not a request either.
        let nowhere = serde_json::json!({"type": "request", "id": "1", "request": "folder-scan"});
        assert_eq!(Message::from_value(&nowhere), None);
    }

    #[test]
    fn a_folder_scan_result_round_trips_and_answers_safe_only_when_empty() {
        let clear = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 3,
            ambiguous: 1,
            findings: Vec::new(),
            rule_pack: 4,
        };
        assert!(clear.is_safe());
        assert_eq!(clear.verdict(), SAFE_TO_OPEN);
        assert_eq!(FolderScanResult::from_value(&clear.to_value()), Some(clear));

        let found = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 3,
            ambiguous: 0,
            findings: vec![FolderFinding {
                finding: recorded(FindingState::Open, Category::Threat, "rule 0001", 1),
                heuristics: vec!["0501  weight 2  It downloads something.".to_string()],
            }],
            rule_pack: 4,
        };
        assert!(!found.is_safe());
        assert_eq!(found.verdict(), DO_NOT_OPEN_YET);
        assert_eq!(FolderScanResult::from_value(&found.to_value()), Some(found));
    }

    #[test]
    fn an_action_report_and_the_receipts_round_trip() {
        let report = ActionReport {
            action: "quarantine".to_string(),
            finding_id: "claude-code/user/skill/x|rule/0001|abc".to_string(),
            item_id: "claude-code/user/skill/x".to_string(),
            receipt_id: "q-0123456789abcdef0123456789abcdef".to_string(),
            state: "stopped".to_string(),
            result: Outcome::Ok,
            steps: vec![ReceiptStep::new(
                Primitive::MoveOut,
                "/home/.claude/skills/x",
            )],
            trusted: false,
            sessions: Sessions::of(vec![
                AgentSessions {
                    agent: "claude-code".to_string(),
                    running: SessionsRunning::Yes,
                    live: 2,
                },
                AgentSessions {
                    agent: "codex".to_string(),
                    running: SessionsRunning::Unknown,
                    live: 0,
                },
            ]),
            message: "Stopped.".to_string(),
        };
        assert_eq!(report.sessions.running, SessionsRunning::Yes);
        assert!(
            report.sessions.sentence().contains("claude-code (2)"),
            "{}",
            report.sessions.sentence()
        );
        assert_eq!(
            ActionReport::from_value(&report.to_value()),
            Some(report.clone())
        );

        let receipts = vec![RevealedReceipt {
            receipt_id: report.receipt_id.clone(),
            item_id: ItemId::from_recorded(&report.item_id),
            kind: Some(Kind::Skill),
            original_path: "/home/.claude/skills/x".to_string(),
            payload_path: "/data/quarantine/q-0123456789abcdef0123456789abcdef/payload".to_string(),
            actor: Actor::Auto,
            quarantined_at: moment("2026-09-24T08:00:00.000Z"),
            finding_id: report.finding_id.clone(),
            rule_id: 1,
            re_enforced: 2,
        }];
        assert_eq!(
            receipts_from_value(&receipts_to_value(&receipts)),
            Some(receipts)
        );
    }

    /// Nobody running and nobody askable read differently, and an Agent that
    /// could not be asked is named.
    #[test]
    fn the_sessions_sentence_says_what_detection_found() {
        let none = Sessions::of(vec![AgentSessions {
            agent: "claude-code".to_string(),
            running: SessionsRunning::No,
            live: 0,
        }]);
        assert_eq!(none.running, SessionsRunning::No);
        assert!(none.sentence().starts_with("No Agent session"));
        let unknown = Sessions::of(vec![AgentSessions {
            agent: "codex".to_string(),
            running: SessionsRunning::Unknown,
            live: 0,
        }]);
        assert!(
            unknown.sentence().contains("codex"),
            "{}",
            unknown.sentence()
        );
    }

    fn recorded(
        state: FindingState,
        category: Category,
        source: &str,
        rule_id: i64,
    ) -> RecordedFinding {
        use agentsweep_core::finding::{RuleStatus, Severity, Tier};
        RecordedFinding {
            id: FindingId::from_recorded("claude-code/user/settings-entry/x|rule/0018|abc"),
            item_id: ItemId::from_recorded("claude-code/user/settings-entry/x"),
            kind: Kind::SettingsEntry,
            source: source.to_string(),
            rule_id,
            category,
            severity: Severity::Medium,
            tier: Tier::Rules,
            status: RuleStatus::Probation,
            state,
            content_hash: "abc".to_string(),
            title: String::new(),
            plain: String::new(),
            file: String::new(),
            drift: String::new(),
            receipt_id: String::new(),
            fixed_version: String::new(),
            switched: false,
            facts: Default::default(),
            first_seen: moment("2026-09-24T08:00:00.000Z"),
            notified_at: None,
        }
    }

    /// The keys a Finding carried on the wire before its facts did, which is
    /// what a client from before reads and all it reads.
    const KEYS_BEFORE_THE_FACTS: [&str; 20] = [
        "category",
        "content_hash",
        "drift",
        "file",
        "first_seen",
        "fixed_version",
        "id",
        "item_id",
        "kind",
        "notified_at",
        "plain",
        "receipt_id",
        "rule_id",
        "severity",
        "source",
        "state",
        "status",
        "switched",
        "tier",
        "title",
    ];

    /// The facts are additive: every key a client from before reads is still
    /// there with the value it had, so such a client reads the status as it
    /// did; a client that knows the facts reads them back; and a status from
    /// a daemon from before reads as no facts known.
    #[test]
    fn an_older_client_reads_a_status_whose_findings_carry_facts() {
        use agentsweep_core::eventlog::Actor;
        use agentsweep_core::finding_facts::{FindingFacts, HeuristicLine, WhyNothingHappened};

        let mut finding = recorded(FindingState::Stopped, Category::Threat, "rule 0001", 1);
        finding.switched = true;
        let plain = finding.clone();
        finding.facts = FindingFacts {
            actor: Some(Actor::Auto),
            scope: "project".to_string(),
            project_root: "/src/demo".to_string(),
            activation: "inactive".to_string(),
            inactive_reason: "untrusted_project".to_string(),
            provenance: "repository".to_string(),
            why_nothing_happened: Some(WhyNothingHappened::Probation),
            heuristics: vec![HeuristicLine {
                id: 520,
                weight: 3,
                plain: "It tells the agent to ignore what it was told.".to_string(),
                excerpt: "ignore previous instructions".to_string(),
            }],
            score: 3,
            band: "Suspicious".to_string(),
            rule_withdrawn: true,
        };
        let status = Status {
            health: Health::default(),
            scan: None,
            findings: vec![finding.clone()],
            activity: Vec::new(),
        };
        let value = status.to_value();

        let written = value["findings"][0].as_object().expect("an object");
        let before = plain.to_value();
        for key in KEYS_BEFORE_THE_FACTS {
            assert_eq!(written.get(key), before.get(key), "{key}");
        }

        let back = Status::from_value(&value).expect("a readable status");
        assert_eq!(back.findings, vec![finding]);

        let mut older = value.clone();
        let object = older["findings"][0].as_object_mut().expect("an object");
        object.retain(|key, _| KEYS_BEFORE_THE_FACTS.contains(&key.as_str()));
        let back = Status::from_value(&older).expect("a status from before");
        assert_eq!(back.findings, vec![plain]);
    }

    /// The stream carries the Finding as it stands now beside its id and
    /// state, and a client that does not know it reads the id and the state.
    #[test]
    fn a_finding_changed_event_carries_the_finding_when_there_is_one() {
        let finding = recorded(FindingState::Stopped, Category::Threat, "rule 0001", 1);
        let event = Message::Event(StateEvent::FindingChanged {
            id: finding.id.clone(),
            state: "stopped".to_string(),
            finding: Some(Box::new(finding.clone())),
        });
        let value = event.to_value();
        assert_eq!(value["state"], "stopped");
        assert_eq!(Message::from_value(&value), Some(event));

        let mut older = value.clone();
        older.as_object_mut().expect("an object").remove("finding");
        assert_eq!(
            Message::from_value(&older),
            Some(Message::Event(StateEvent::FindingChanged {
                id: finding.id.clone(),
                state: "stopped".to_string(),
                finding: None,
            }))
        );
    }

    /// What a client offers comes from the Finding as the daemon sent it
    /// (spec section 8.5).
    #[test]
    fn the_offers_follow_the_primitive_table_and_the_state() {
        let threat = recorded(FindingState::Open, Category::Threat, "rule 0001", 1);
        assert_eq!(offers(&threat), vec![Offer::Quarantine, Offer::Trust]);

        let drift = recorded(FindingState::Open, Category::Threat, "drift", 0);
        assert_eq!(
            offers(&drift),
            vec![Offer::Quarantine, Offer::Trust, Offer::Acknowledge]
        );

        let exposure = recorded(FindingState::Open, Category::Exposure, "rule 0018", 18);
        assert_eq!(offers(&exposure), vec![Offer::Trust, Offer::Fix]);
        let other = recorded(FindingState::Open, Category::Exposure, "rule 0010", 10);
        assert_eq!(offers(&other), vec![Offer::Trust]);

        let mut managed = threat.clone();
        managed.item_id = ItemId::from_recorded("claude-code/managed/settings-entry/x");
        assert_eq!(offers(&managed), vec![Offer::Trust]);

        let mut stopped = recorded(FindingState::Stopped, Category::Threat, "rule 0001", 1);
        assert_eq!(offers(&stopped), vec![Offer::Restore]);
        stopped.fixed_version = "def".to_string();
        assert_eq!(offers(&stopped), vec![Offer::Restore, Offer::ReEnable]);

        let trusted = recorded(FindingState::Trusted, Category::Threat, "rule 0001", 1);
        assert!(offers(&trusted).is_empty());
    }

    /// The vocabulary is closed: a request nobody defined is not one.
    #[test]
    fn a_request_outside_the_vocabulary_is_not_a_message() {
        let value = serde_json::json!({"type": "request", "id": "1", "request": "read-file"});
        assert_eq!(Message::from_value(&value), None);
    }
}
