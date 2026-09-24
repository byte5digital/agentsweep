//! The vocabulary: the handshake, the requests, the responses and the state
//! events (spec section 6.3).
//!
//! It is a closed list on purpose. The daemon holds the machine's file access,
//! the Keychain key behind both chains and the only write path into the
//! quarantine store, so what a peer may ask for is enumerated here rather than
//! left to whatever a caller can spell (ADR 0008). No request takes a path in
//! this milestone at all; the two that will, a Folder Scan and revealing a
//! Receipt, arrive with theirs.
//!
//! Every message is one JSON object with a `type`. The types are laid out here
//! and nowhere else, so the daemon, the application and the command line
//! interface cannot drift apart about what a field is called.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};

use agentsweep_core::chain::{BreakReason, ChainState};
use agentsweep_core::envelope::Timestamp;
use agentsweep_core::finding::FindingId;
use agentsweep_core::health::{Health, Protection, StateFileHealth};
use agentsweep_core::state::{RecordedFinding, ScanSummary, Trigger};

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

/// What a peer may ask the daemon for. The closed list of this milestone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// Health, the last Scan summary and the Findings that stand.
    Status,
    /// Run a Full Scan now. One that is already running is joined rather than
    /// started again (spec section 6.4).
    ScanNow,
    /// Send every state event from now until the connection closes.
    Subscribe,
}

impl Request {
    /// Every request.
    pub const ALL: [Request; 3] = [Request::Status, Request::ScanNow, Request::Subscribe];

    /// The spelling a request carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Request::Status => "status",
            Request::ScanNow => "scan-now",
            Request::Subscribe => "subscribe",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<Request> {
        Request::ALL
            .into_iter()
            .find(|request| request.as_str() == text)
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
}

impl Status {
    /// The status a client renders when no daemon answered.
    pub fn unreachable(reason: &str) -> Status {
        Status {
            health: Health::unreachable(reason),
            scan: None,
            findings: Vec::new(),
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
        Some(Status {
            health: health_from_value(value.get("health")?)?,
            scan,
            findings,
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
        "open_findings".to_string(),
        Value::from(health.open_findings as u64),
    );
    map.insert(
        "projects_need_permission".to_string(),
        Value::from(health.projects_need_permission as u64),
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
    Some(Health {
        protection,
        events: chain_state_from_value(value.get("events")?)?,
        baseline: chain_state_from_value(value.get("baseline")?)?,
        projects_need_permission: count("projects_need_permission")?,
        state_file: StateFileHealth::parse(text("state_file")?)?,
        scanning: value.get("scanning")?.as_bool()?,
        last_full_scan,
        items: count("items")?,
        open_findings: count("open_findings")?,
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
                map.insert("request".to_string(), Value::from(request.as_str()));
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
                    StateEvent::FindingChanged { id, state } => {
                        map.insert("id".to_string(), Value::from(id.as_str()));
                        map.insert("state".to_string(), Value::from(state.as_str()));
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
                request: Request::parse(text("request")?)?,
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
        for request in Request::ALL {
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
        health.open_findings = 1;
        health.last_full_scan = Some(moment("2026-09-24T08:00:00.900Z"));
        health.events = ChainState::Broken {
            sequence: 4,
            reason: BreakReason::MacFailed,
        };
        let status = Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
        };
        let value = status.to_value();
        let back = Status::from_value(&value).expect("a readable status");
        assert_eq!(back.scan, status.scan);
        assert_eq!(back.health.headline(), "Records tampered.");
        assert!(back.health.records_tampered());
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
        for request in Request::ALL {
            assert_eq!(Request::parse(request.as_str()), Some(request));
        }
    }

    /// The vocabulary is closed: a request nobody defined is not one.
    #[test]
    fn a_request_outside_the_vocabulary_is_not_a_message() {
        let value = serde_json::json!({"type": "request", "id": "1", "request": "read-file"});
        assert_eq!(Message::from_value(&value), None);
    }
}
