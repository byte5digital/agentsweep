//! The app's requests to the daemon: one shared connection for the status,
//! the settings, the sessions, "Scan now" and every action, and a connection
//! of its own for each Folder Scan, which answers only once it has finished.
//!
//! Every action is the request the command line interface sends for it, and
//! its answer is rendered in the command line interface's words: the
//! daemon's own sentence first, then the Finding, Item, Receipt and steps,
//! then whether Agent sessions appear to be running. A refusal or a daemon
//! that does not answer comes back as one sentence saying nothing was done.
//!
//! The shared connection is made on first use and made again when the daemon
//! went away. A request that may be asked twice (the status, the settings,
//! the sessions, "Scan now", which joins a running Full Scan) is asked again
//! once on a new connection; an action is asked again only when it provably
//! never reached the daemon, so nothing is ever carried out twice.

use std::io::ErrorKind;
use std::sync::Mutex;

use agentsweep_core::envelope::ChainId;
use agentsweep_core::eventlog::Outcome;
use agentsweep_core::item::ItemId;
use agentsweep_core::keychain::ClaudeKey;
use agentsweep_core::quarantine::{Conflict, RestoreReport};
use agentsweep_core::settings::JudgementEngine;
use agentsweep_ipc::engine::{EngineChange, EngineState};
use agentsweep_ipc::integrity::{ChainRecords, IntegrityAnswer};
use agentsweep_ipc::notifications::Unnotified;
use agentsweep_ipc::preview::RequestPreview;
use agentsweep_ipc::protocol::{
    ActionReport, FolderScanResult, RevealedReceipt, Sessions, SettingsChange, SettingsState,
    Status, UninstallChoice, UninstallReport,
};
use agentsweep_ipc::{Client, ClientError};
use serde_json::{Value, json};

use crate::actions::{after_quarantine, sessions_sentence};
use crate::link::Socket;

/// One action, as the window asks for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionRequest {
    /// A manual Quarantine, or for a never-auto kind switching its line off.
    Quarantine(String),
    /// A Restore, or switching a never-auto kind's line back on.
    Restore(String, Conflict),
    /// Trust this version, or keep an Exposure as it is.
    Trust(String),
    /// "Yes, that was me" on a Drift question.
    Acknowledge(String),
    /// The one-click fix of Exposures 0018 and 0019.
    Fix(String),
    /// A stopped plugin back on for its newer, clean version.
    ReEnable(String),
    /// Delete permanently: what the store keeps of a quarantined Item is
    /// deleted for good.
    Purge(String),
    /// Stop trusting this: the Trust on one Finding's content is withdrawn.
    Untrust(String),
}

impl ActionRequest {
    /// The request a window command names, or nothing for a name that is not
    /// an action.
    pub fn of(command: &str, target: &str, conflict: Option<&str>) -> Option<ActionRequest> {
        let target = target.to_string();
        Some(match command {
            "quarantine" => ActionRequest::Quarantine(target),
            "restore" => ActionRequest::Restore(
                target,
                match conflict.unwrap_or("refuse") {
                    "refuse" => Conflict::Refuse,
                    "replace" => Conflict::Replace,
                    "beside" => Conflict::Beside,
                    _ => return None,
                },
            ),
            "trust" => ActionRequest::Trust(target),
            "acknowledge" => ActionRequest::Acknowledge(target),
            "fix" => ActionRequest::Fix(target),
            "re_enable" => ActionRequest::ReEnable(target),
            "purge" => ActionRequest::Purge(target),
            "untrust" => ActionRequest::Untrust(target),
            _ => return None,
        })
    }

    fn send(&self, client: &mut Client) -> Result<ActionReport, ClientError> {
        match self {
            ActionRequest::Quarantine(target) => client.quarantine(target),
            ActionRequest::Restore(target, conflict) => client.restore(target, *conflict),
            ActionRequest::Trust(target) => client.trust(target),
            ActionRequest::Acknowledge(target) => client.acknowledge(target),
            ActionRequest::Fix(target) => client.fix(target),
            ActionRequest::ReEnable(target) => client.re_enable(target),
            ActionRequest::Purge(target) => client.purge(target),
            ActionRequest::Untrust(target) => client.untrust(target, None),
        }
    }

    /// The Finding the request acts on.
    pub fn target(&self) -> &str {
        match self {
            ActionRequest::Quarantine(target)
            | ActionRequest::Restore(target, _)
            | ActionRequest::Trust(target)
            | ActionRequest::Acknowledge(target)
            | ActionRequest::Fix(target)
            | ActionRequest::ReEnable(target)
            | ActionRequest::Purge(target)
            | ActionRequest::Untrust(target) => target,
        }
    }
}

/// The app's way of asking the daemon.
#[derive(Debug)]
pub struct Asking {
    socket: Socket,
    client: Mutex<Option<Client>>,
}

impl Asking {
    /// Asks the daemon at `socket`, connecting on first use.
    pub fn new(socket: Socket) -> Asking {
        Asking {
            socket,
            client: Mutex::new(None),
        }
    }

    /// Asks on the shared connection. `twice` says whether the request may
    /// be asked again on a new connection after the old one failed.
    fn with<T>(
        &self,
        twice: bool,
        ask: impl Fn(&mut Client) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let mut held = self.client.lock().expect("the client is not poisoned");
        let mut attempt = 0;
        loop {
            attempt += 1;
            let client = match held.as_mut() {
                Some(client) => client,
                None => held.insert(self.socket.connect()?),
            };
            match ask(client) {
                Ok(answer) => return Ok(answer),
                Err(error @ (ClientError::Io(_) | ClientError::Unexpected(_))) => {
                    // The connection is no use any more either way.
                    *held = None;
                    if attempt == 1 && (twice || never_sent(&error)) {
                        continue;
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Health, the last Scan summary and every Finding.
    pub fn status(&self) -> Result<Status, ClientError> {
        self.with(true, Client::status)
    }

    /// Where every choice the user made stands, the Posture among them.
    pub fn settings(&self) -> Result<SettingsState, ClientError> {
        self.with(true, Client::settings)
    }

    /// Every change the user has not been told about yet (spec section
    /// 6.7). Nothing is written, so it may be asked twice.
    pub fn unnotified(&self) -> Result<Vec<Unnotified>, ClientError> {
        self.with(true, Client::unnotified)
    }

    /// Confirms what the app raised, so the daemon writes `notified_at`.
    /// Confirming twice writes the same, so it may be asked twice.
    pub fn notified(&self, ids: &[String]) -> Result<usize, ClientError> {
        self.with(true, |client| client.notified(ids))
    }

    /// Moves the choices the Settings pane asks for and answers where every
    /// choice stands afterwards. Asking twice sets the same values again, so
    /// it may be.
    pub fn change_settings(&self, change: &SettingsChange) -> Result<SettingsState, ClientError> {
        self.with(true, |client| client.change_settings(change.clone()))
    }

    /// Turns the Gate switch on or off and answers where it stands
    /// afterwards. Asking twice sets the same value again, which changes
    /// nothing the second time, so it may be.
    pub fn set_gate_hooks(&self, enabled: bool) -> Result<bool, ClientError> {
        self.with(true, |client| client.set_gate_hooks(enabled))
    }

    /// Where the AI Judgement choices stand, with whether Ollama runs and
    /// whether Apple's on-device model is available. It only reads.
    pub fn engine(&self) -> Result<EngineState, ClientError> {
        self.with(true, Client::engine)
    }

    /// Moves some AI Judgement choices. Asking twice sets the same values
    /// again and records nothing the second time, so it may be.
    pub fn change_engine(&self, change: &EngineChange) -> Result<EngineState, ClientError> {
        self.with(true, |client| client.change_engine(change.clone()))
    }

    /// Hands the Claude API key to the daemon. It is sent once: asked again
    /// only when it provably never reached the daemon. The key is consumed
    /// here and wiped when its last copy drops.
    pub fn set_claude_key(&self, key: ClaudeKey) -> Result<EngineState, ClientError> {
        self.with(false, |client| client.set_claude_key(key.clone()))
    }

    /// Removes the Claude API key, which turns an active Claude engine off.
    pub fn remove_claude_key(&self) -> Result<EngineState, ClientError> {
        self.with(false, Client::remove_claude_key)
    }

    /// "Preview a request" for one Item, or for the sample Item. It only
    /// reads.
    pub fn preview_request(
        &self,
        item: Option<&str>,
        engine: JudgementEngine,
    ) -> Result<RequestPreview, ClientError> {
        self.with(true, |client| client.preview_request(item, engine))
    }

    /// Whether Agent sessions appear to be running right now.
    pub fn sessions(&self) -> Result<Sessions, ClientError> {
        self.with(true, Client::sessions)
    }

    /// Every Receipt in the quarantine store with its original place and its
    /// payload, through the reveal-receipt request. It only reads.
    pub fn receipts(&self) -> Result<Vec<RevealedReceipt>, ClientError> {
        self.with(true, |client| client.reveal_receipts(None))
    }

    /// Uninstall with the user's choice: the request `agentsweep uninstall`
    /// sends (spec section 9.6). Asked again only when it provably never
    /// reached the daemon.
    pub fn uninstall(&self, choice: UninstallChoice) -> Result<UninstallReport, ClientError> {
        self.with(false, |client| client.uninstall(choice))
    }

    /// Asks for a Full Scan; true when this started one, false when it joined
    /// one already under way.
    pub fn scan_now(&self) -> Result<bool, ClientError> {
        self.with(true, Client::scan_now)
    }

    /// One page of a chain's records from one sequence on ("Look at the
    /// records", "Show what changed"). It only reads, so it may be asked
    /// twice.
    pub fn records(&self, chain: ChainId, from: u64) -> Result<ChainRecords, ClientError> {
        self.with(true, |client| client.records(chain, from))
    }

    /// "Start a fresh record". It writes, so it is asked again only when it
    /// provably never left.
    pub fn acknowledge_key_missing(&self) -> Result<IntegrityAnswer, ClientError> {
        self.with(false, Client::acknowledge_key_missing)
    }

    /// "Scan again, trusting nothing", asked like "Start a fresh record".
    pub fn acknowledge_chain_broken(&self) -> Result<IntegrityAnswer, ClientError> {
        self.with(false, Client::acknowledge_chain_broken)
    }

    /// Asks for the first reads into the protected locations that Need
    /// Permission (spec section 9.7); true when the daemon started them.
    /// Asked once only, so the operating system's prompt is asked for once.
    pub fn check_now(&self) -> Result<bool, ClientError> {
        self.with(false, Client::check_now)
    }

    /// Carries out one action and renders the answer for the window.
    pub fn act(&self, request: &ActionRequest) -> Value {
        match self.with(false, |client| request.send(client)) {
            Ok(report) => report_view(&report, request.target()),
            Err(error) => refusal_view(&error),
        }
    }

    /// A Folder Scan, on a connection of its own so the shared one stays free
    /// for the actions while it runs.
    pub fn folder_scan(&self, path: &str) -> Result<FolderScanResult, ClientError> {
        self.socket.connect()?.folder_scan(path)
    }
}

/// True when a failed request provably never reached the daemon: the
/// connection was already closed when it was written.
fn never_sent(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Io(io) if matches!(
            io.kind(),
            ErrorKind::BrokenPipe | ErrorKind::NotConnected | ErrorKind::ConnectionReset
        )
    )
}

/// What "Scan now" says once the daemon took it on, as the command line
/// interface says it.
pub fn scan_now_line(started: bool) -> &'static str {
    match started {
        true => "A Full Scan started.",
        false => "A Full Scan is already under way. Following it.",
    }
}

/// The two choices a Restore conflict offers, as (label, conflict): each
/// sends the Restore again with that choice (spec sections 5.4 and 8.5).
pub const CONFLICT_CHOICES: [(&str, &str); 2] = [
    ("Replace the new file", "replace"),
    ("Restore beside it", "beside"),
];

/// One action's answer as the window shows it beside the Finding: the
/// daemon's sentence, the lines under it, and the lines the command line
/// interface prints, which go under Details (the owner's decision of
/// 2026-10-14 for ticket 73).
///
/// The lines under the sentence say whether the Agent appears to be running
/// in the window's words. After a Quarantine that was carried out they are
/// its confirmation: the sessions sentence, the restart request and, on
/// Project Scope, that git will show the change ([`after_quarantine`]). The
/// conflict choices are there only when the daemon answered a Restore with a
/// conflict.
pub fn report_view(report: &ActionReport, target: &str) -> Value {
    let conflict = report.action == "restore"
        && report.result != Outcome::Ok
        && RestoreReport::of(report.steps.clone()).conflicted;
    let mut details = Vec::new();
    if !report.finding_id.is_empty() {
        details.push(format!("Finding  {}", report.finding_id));
    }
    details.push(format!("Item     {}", report.item_id));
    if !report.receipt_id.is_empty() {
        details.push(format!("Receipt  {}", report.receipt_id));
    }
    details.push(format!("Now      {}", report.state));
    if report.trusted {
        details.push("Trust    granted to this exact version".to_string());
    }
    for step in &report.steps {
        details.push(format!(
            "{} {}  {}{}",
            step.primitive.as_str(),
            step.outcome.as_str(),
            step.path,
            match step.detail.is_empty() {
                true => String::new(),
                false => format!("  ({})", step.detail),
            }
        ));
    }
    let done = report.result != Outcome::Failed;
    let lines = match (report.action.as_str(), done) {
        ("quarantine", true) => {
            after_quarantine(&ItemId::from_recorded(&report.item_id), &report.sessions)
        }
        _ => vec![sessions_sentence(&report.sessions)],
    };
    let choices: Vec<Value> = match conflict {
        true => CONFLICT_CHOICES
            .iter()
            .map(|(label, choice)| {
                json!({ "label": label, "command": "restore", "conflict": choice, "target": target })
            })
            .collect(),
        false => Vec::new(),
    };
    json!({
        "done": done,
        "message": match conflict {
            // The daemon's sentence names the command line options; the
            // window offers the two choices as buttons instead.
            true => "Something else is at the original place now, so nothing was put back. \
                     Replace the new file, or restore beside it."
                .to_string(),
            false => report.message.clone(),
        },
        "lines": lines,
        "details": details,
        "conflict": conflict,
        "choices": choices,
        "target": target,
    })
}

/// A request that was not carried out, in the command line interface's words.
pub fn refusal_view(error: &ClientError) -> Value {
    json!({
        "done": false,
        "message": refusal(error),
        "lines": [],
        "details": [],
        "conflict": false,
        "choices": [],
        "target": "",
    })
}

/// The sentence for a request that was not carried out.
pub fn refusal(error: &ClientError) -> String {
    match error {
        ClientError::Unreachable(_) => format!(
            "Protection is off: {}. Nothing was done.",
            error.unreachable()
        ),
        ClientError::Request(refusal) => format!("Nothing was done: {}.", refusal.message),
        other => format!("AgentSweep could not be asked: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::eventlog::{Primitive, ReceiptStep, SessionsRunning};
    use agentsweep_ipc::protocol::{AgentSessions, RequestError};

    fn report(action: &str, result: Outcome, steps: Vec<ReceiptStep>) -> ActionReport {
        ActionReport {
            action: action.to_string(),
            finding_id: "claude-code/user/skill/x|rule/0001|abc".to_string(),
            item_id: "claude-code/user/skill/x".to_string(),
            receipt_id: "q-0123456789abcdef0123456789abcdef".to_string(),
            state: "stopped".to_string(),
            result,
            steps,
            trusted: false,
            sessions: Sessions::of(vec![AgentSessions {
                agent: "claude-code".to_string(),
                running: SessionsRunning::Yes,
                live: 1,
            }]),
            message: "Quarantined the skill 'x'. `agentsweep restore q-0123` puts it back."
                .to_string(),
        }
    }

    #[test]
    fn every_window_command_is_the_request_of_the_same_name() {
        assert_eq!(
            ActionRequest::of("quarantine", "f", None),
            Some(ActionRequest::Quarantine("f".to_string()))
        );
        assert_eq!(
            ActionRequest::of("restore", "f", Some("beside")),
            Some(ActionRequest::Restore("f".to_string(), Conflict::Beside))
        );
        assert_eq!(
            ActionRequest::of("restore", "f", None),
            Some(ActionRequest::Restore("f".to_string(), Conflict::Refuse))
        );
        assert_eq!(ActionRequest::of("restore", "f", Some("sideways")), None);
        assert_eq!(
            ActionRequest::of("purge", "f", None),
            Some(ActionRequest::Purge("f".to_string()))
        );
        assert_eq!(
            ActionRequest::of("untrust", "f", None),
            Some(ActionRequest::Untrust("f".to_string()))
        );
        for command in [
            "trust",
            "acknowledge",
            "fix",
            "re_enable",
            "purge",
            "untrust",
        ] {
            let request = ActionRequest::of(command, "f", None).expect("an action");
            assert_eq!(request.target(), "f");
        }
        assert_eq!(ActionRequest::of("status", "f", None), None);
    }

    /// The answer reads as the command line interface prints it, with the
    /// sessions sentence under it.
    #[test]
    fn an_action_answer_is_rendered_in_the_cli_words() {
        let mut step = ReceiptStep::new(Primitive::MoveOut, "/home/.claude/skills/x");
        step.outcome = Outcome::Ok;
        let view = report_view(&report("quarantine", Outcome::Ok, vec![step]), "f");
        assert_eq!(view["done"], true);
        assert!(
            view["message"]
                .as_str()
                .expect("a sentence")
                .starts_with("Quarantined the skill 'x'.")
        );
        let details: Vec<&str> = view["details"]
            .as_array()
            .expect("details")
            .iter()
            .map(|line| line.as_str().expect("a line"))
            .collect();
        assert_eq!(
            details,
            vec![
                "Finding  claude-code/user/skill/x|rule/0001|abc",
                "Item     claude-code/user/skill/x",
                "Receipt  q-0123456789abcdef0123456789abcdef",
                "Now      stopped",
                "move-out ok  /home/.claude/skills/x",
            ]
        );
        // After a Quarantine: the sessions sentence in the window's words
        // and the restart request; a user-level skill has no git line.
        assert_eq!(
            view["lines"],
            json!([
                "1 Claude Code session appears to be running.",
                "Restart it so it picks up the change.",
            ])
        );
        assert_eq!(view["conflict"], false);
        assert_eq!(view["choices"], json!([]));

        // Any other answer carries the sessions sentence alone.
        let trusted = report_view(&report("trust", Outcome::Ok, Vec::new()), "f");
        assert_eq!(
            trusted["lines"],
            json!(["1 Claude Code session appears to be running."])
        );
        // A Quarantine that failed asks for no restart.
        let failed = report_view(&report("quarantine", Outcome::Failed, Vec::new()), "f");
        assert_eq!(
            failed["lines"],
            json!(["1 Claude Code session appears to be running."])
        );
    }

    /// A project's Item adds that git will show the change.
    #[test]
    fn a_quarantine_in_a_project_says_git_will_show_it() {
        let mut quarantined = report("quarantine", Outcome::Ok, Vec::new());
        quarantined.item_id =
            "claude-code/project:/src/demo/instruction-file/CLAUDE.md".to_string();
        let view = report_view(&quarantined, "f");
        let lines = view["lines"].as_array().expect("lines");
        assert_eq!(lines.last().expect("a line"), crate::wording::PROJECT_LINE);
    }

    /// A Restore that met something else at the original place offers the
    /// two choices rather than naming command line options.
    #[test]
    fn a_restore_conflict_offers_replace_or_beside() {
        let mut step = ReceiptStep::new(Primitive::MoveOut, "/home/.claude/skills/x");
        step.outcome = Outcome::Failed;
        step.detail = "something else is at /home/.claude/skills/x".to_string();
        let view = report_view(&report("restore", Outcome::Failed, vec![step]), "f");
        assert_eq!(view["conflict"], true);
        assert_eq!(view["done"], false);
        assert_eq!(view["target"], "f");
        // Each choice sends the Restore again with its own conflict answer.
        let sent: Vec<ActionRequest> = view["choices"]
            .as_array()
            .expect("choices")
            .iter()
            .map(|choice| {
                ActionRequest::of(
                    choice["command"].as_str().expect("a command"),
                    choice["target"].as_str().expect("a target"),
                    choice["conflict"].as_str(),
                )
                .expect("an action")
            })
            .collect();
        assert_eq!(
            sent,
            vec![
                ActionRequest::Restore("f".to_string(), Conflict::Replace),
                ActionRequest::Restore("f".to_string(), Conflict::Beside),
            ]
        );
        assert_eq!(view["choices"][0]["label"], "Replace the new file");
        assert_eq!(view["choices"][1]["label"], "Restore beside it");
        assert!(
            !view["message"]
                .as_str()
                .expect("a sentence")
                .contains("--replace")
        );
    }

    #[test]
    fn a_refusal_says_nothing_was_done() {
        let refused = ClientError::Request(RequestError::new(
            "not-allowed",
            "only an open Threat Finding is quarantined",
        ));
        assert_eq!(
            refusal(&refused),
            "Nothing was done: only an open Threat Finding is quarantined."
        );
        let away = ClientError::Unreachable(std::io::Error::from(ErrorKind::NotFound));
        assert_eq!(
            refusal(&away),
            "Protection is off: no daemon answered. Nothing was done."
        );
        assert_eq!(refusal_view(&away)["done"], false);
    }

    /// Only a request the daemon never received is sent again.
    #[test]
    fn only_a_request_that_never_left_is_asked_again() {
        assert!(never_sent(&ClientError::Io(std::io::Error::from(
            ErrorKind::BrokenPipe
        ))));
        assert!(!never_sent(&ClientError::Io(std::io::Error::new(
            ErrorKind::ConnectionAborted,
            "the daemon closed the connection before answering",
        ))));
        assert!(!never_sent(&ClientError::Unexpected("x".to_string())));
    }

    #[test]
    fn scan_now_says_whether_it_started_or_joined() {
        assert_eq!(scan_now_line(true), "A Full Scan started.");
        assert_eq!(
            scan_now_line(false),
            "A Full Scan is already under way. Following it."
        );
    }

    #[test]
    fn no_daemon_is_protection_off_for_every_request() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let asking = Asking::new(Socket::At(directory.path().join("nobody.sock")));
        assert!(asking.status().expect_err("nobody").is_unreachable());
        assert!(asking.sessions().expect_err("nobody").is_unreachable());
        assert!(asking.scan_now().expect_err("nobody").is_unreachable());
        assert!(asking.receipts().expect_err("nobody").is_unreachable());
        assert!(
            asking
                .folder_scan("/")
                .expect_err("nobody")
                .is_unreachable()
        );
        let acted = asking.act(&ActionRequest::Trust("f".to_string()));
        assert_eq!(
            acted["message"],
            "Protection is off: no daemon answered. Nothing was done."
        );
    }
}
