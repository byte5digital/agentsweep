//! The action commands: `quarantine`, `restore`, `trust`, `acknowledge`,
//! `fix`, `re-enable` and `reveal-receipt`.
//!
//! Each is one request to the daemon and nothing else. The command line
//! interface never moves, rewrites or trusts anything itself: the daemon is the
//! only writer of the Event Log and the quarantine store (ADR 0008), so every
//! action goes through it, and an in-process Scan never acts. What the user
//! types is an id the status printed, a Finding's, an Item's or a Receipt's,
//! and the daemon resolves it; only `reveal-receipt` takes a path, and the
//! daemon compares it with what its records say.

use std::fmt::Write as _;
use std::path::PathBuf;

use agentsweep_core::quarantine::Conflict;
use agentsweep_ipc::protocol::{ActionReport, RevealedReceipt, Role};
use agentsweep_ipc::{Client, ClientError};

/// The exit code of an action that was carried out.
pub const DONE: u8 = 0;

/// The exit code of an action the daemon refused or that did not finish.
pub const NOT_DONE: u8 = 1;

/// The exit code of a command line that was not understood.
pub const USAGE_ERROR: u8 = 2;

/// The exit code when no daemon answered, which is Protection off: nothing
/// was done, and nothing could have been.
pub const UNREACHABLE: u8 = 3;

/// One action command, as it was typed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// What to do.
    pub action: Action,
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// What the user asked for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Take an Item out.
    Quarantine(String),
    /// Put one back.
    Restore(String, Conflict),
    /// Call a content safe.
    Trust(String),
    /// Say a change was theirs.
    Acknowledge(String),
    /// The one-click fix of Exposures 0018 and 0019.
    Fix(String),
    /// Switch a stopped plugin back on for its newer version.
    ReEnable(String),
    /// List the Receipts with where their Items came from.
    RevealReceipt(Option<String>),
}

/// The command names this module answers.
pub const COMMANDS: [&str; 7] = [
    "quarantine",
    "restore",
    "trust",
    "acknowledge",
    "fix",
    "re-enable",
    "reveal-receipt",
];

/// Reads one action command line: the command, its one id (or, for
/// `reveal-receipt`, its optional path), and the options it takes.
pub fn parse(command: &str, arguments: &[String]) -> Result<Invocation, String> {
    let mut socket = None;
    let mut conflict = None;
    let mut positional: Vec<String> = Vec::new();
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--socket" => {
                let path = rest
                    .next()
                    .ok_or_else(|| "`--socket` takes a path".to_string())?;
                socket = Some(PathBuf::from(path));
            }
            "--replace" | "--beside" if command == "restore" => {
                if conflict.is_some() {
                    return Err("`--replace` and `--beside` exclude each other".to_string());
                }
                conflict = Some(match argument.as_str() {
                    "--replace" => Conflict::Replace,
                    _ => Conflict::Beside,
                });
            }
            option if option.starts_with("--") => {
                return Err(format!("`{option}` is not an option of `{command}`"));
            }
            value => positional.push(value.to_string()),
        }
    }

    let action = if command == "reveal-receipt" {
        match positional.as_slice() {
            [] => Action::RevealReceipt(None),
            [path] => Action::RevealReceipt(Some(path.clone())),
            _ => return Err("`reveal-receipt` takes at most one path".to_string()),
        }
    } else {
        let [target] = positional.as_slice() else {
            return Err(format!(
                "`{command}` takes one id: a Finding id, an Item id or a Receipt id, as \
                 `agentsweep status` prints them"
            ));
        };
        let target = target.clone();
        match command {
            "quarantine" => Action::Quarantine(target),
            "restore" => Action::Restore(target, conflict.unwrap_or(Conflict::Refuse)),
            "trust" => Action::Trust(target),
            "acknowledge" => Action::Acknowledge(target),
            "fix" => Action::Fix(target),
            "re-enable" => Action::ReEnable(target),
            other => return Err(format!("`{other}` is not an action")),
        }
    };
    Ok(Invocation { action, socket })
}

/// Asks the daemon and renders the answer, with the exit code.
pub fn run(invocation: &Invocation) -> (String, u8) {
    let connected = match &invocation.socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    };
    let mut client = match connected {
        Ok(client) => client,
        Err(error) => return unanswered(&error),
    };
    let answered = match &invocation.action {
        Action::RevealReceipt(path) => {
            return match client.reveal_receipts(path.as_deref()) {
                Ok(receipts) => (render_receipts(&receipts), DONE),
                Err(error) => unanswered(&error),
            };
        }
        Action::Quarantine(target) => client.quarantine(target),
        Action::Restore(target, conflict) => client.restore(target, *conflict),
        Action::Trust(target) => client.trust(target),
        Action::Acknowledge(target) => client.acknowledge(target),
        Action::Fix(target) => client.fix(target),
        Action::ReEnable(target) => client.re_enable(target),
    };
    match answered {
        Ok(report) => {
            let code = match report.result {
                agentsweep_core::eventlog::Outcome::Failed => NOT_DONE,
                _ => DONE,
            };
            (render_report(&report), code)
        }
        Err(error) => unanswered(&error),
    }
}

/// What a request that was not carried out prints.
fn unanswered(error: &ClientError) -> (String, u8) {
    match error {
        ClientError::Unreachable(_) => (
            format!(
                "Protection is off: {}. Nothing was done.\n",
                error.unreachable()
            ),
            UNREACHABLE,
        ),
        ClientError::Request(refusal) => (
            format!("Nothing was done: {}.\n", refusal.message),
            NOT_DONE,
        ),
        other => (
            format!("AgentSweep could not be asked: {other}\n"),
            NOT_DONE,
        ),
    }
}

/// One action's answer, as the terminal prints it: what happened, which
/// Finding, Item and Receipt, each step, and whether Agent sessions appear
/// to be running.
pub fn render_report(report: &ActionReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", report.message);
    let _ = writeln!(out);
    if !report.finding_id.is_empty() {
        let _ = writeln!(out, "  Finding  {}", report.finding_id);
    }
    let _ = writeln!(out, "  Item     {}", report.item_id);
    if !report.receipt_id.is_empty() {
        let _ = writeln!(out, "  Receipt  {}", report.receipt_id);
    }
    let _ = writeln!(out, "  Now      {}", report.state);
    if report.trusted {
        let _ = writeln!(out, "  Trust    granted to this exact version");
    }
    for step in &report.steps {
        let _ = writeln!(
            out,
            "  {} {}  {}{}",
            step.primitive.as_str(),
            step.outcome.as_str(),
            step.path,
            match step.detail.is_empty() {
                true => String::new(),
                false => format!("  ({})", step.detail),
            }
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", report.sessions.sentence());
    out
}

/// The Receipts, each id with the path its Item was taken from beside it.
pub fn render_receipts(receipts: &[RevealedReceipt]) -> String {
    if receipts.is_empty() {
        return "Nothing is in quarantine.\n".to_string();
    }
    let mut out = String::new();
    for receipt in receipts {
        let _ = writeln!(out, "{}  {}", receipt.receipt_id, receipt.original_path);
        let _ = writeln!(
            out,
            "    {} \u{b7} {} \u{b7} by {} \u{b7} {}",
            receipt.item_id,
            receipt
                .kind
                .map(|kind| kind.as_str())
                .unwrap_or("unknown kind"),
            receipt.actor.as_str(),
            receipt.quarantined_at
        );
        if !receipt.payload_path.is_empty() {
            let _ = writeln!(out, "    payload {}", receipt.payload_path);
        }
        if receipt.re_enforced > 0 {
            let _ = writeln!(
                out,
                "    came back and was taken out again {} times",
                receipt.re_enforced
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::envelope::Timestamp;
    use agentsweep_core::eventlog::{Actor, Outcome, Primitive, ReceiptStep, SessionsRunning};
    use agentsweep_core::item::{ItemId, Kind};
    use agentsweep_ipc::protocol::{AgentSessions, Sessions};

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn every_action_takes_one_id_and_restore_takes_a_conflict_choice() {
        let finding = "claude-code/user/skill/x|rule/0001|abc";
        assert_eq!(
            parse("quarantine", &words(&[finding]))
                .expect("a command")
                .action,
            Action::Quarantine(finding.to_string())
        );
        assert_eq!(
            parse("restore", &words(&["q-1", "--beside"]))
                .expect("a command")
                .action,
            Action::Restore("q-1".to_string(), Conflict::Beside)
        );
        assert_eq!(
            parse("restore", &words(&["q-1"]))
                .expect("a command")
                .action,
            Action::Restore("q-1".to_string(), Conflict::Refuse)
        );
        let invocation =
            parse("trust", &words(&["--socket", "/tmp/a.sock", finding])).expect("a command");
        assert_eq!(invocation.socket, Some(PathBuf::from("/tmp/a.sock")));
        assert!(parse("trust", &[]).is_err());
        assert!(parse("trust", &words(&["a", "b"])).is_err());
        assert!(parse("trust", &words(&["a", "--beside"])).is_err());
        assert!(parse("restore", &words(&["a", "--replace", "--beside"])).is_err());
        assert_eq!(
            parse("reveal-receipt", &[]).expect("a command").action,
            Action::RevealReceipt(None)
        );
        assert_eq!(
            parse("reveal-receipt", &words(&["/home/x/.claude.json"]))
                .expect("a command")
                .action,
            Action::RevealReceipt(Some("/home/x/.claude.json".to_string()))
        );
    }

    #[test]
    fn a_report_says_what_was_done_and_whether_sessions_are_running() {
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
            sessions: Sessions::of(vec![AgentSessions {
                agent: "claude-code".to_string(),
                running: SessionsRunning::Yes,
                live: 1,
            }]),
            message: "Quarantined the skill 'x'.".to_string(),
        };
        let rendered = render_report(&report);
        assert!(
            rendered.starts_with("Quarantined the skill 'x'."),
            "{rendered}"
        );
        assert!(rendered.contains("Receipt  q-0123"), "{rendered}");
        assert!(rendered.contains("Now      stopped"), "{rendered}");
        assert!(rendered.contains("move-out ok"), "{rendered}");
        assert!(
            rendered.contains("Agent sessions appear to be running: claude-code (1)"),
            "{rendered}"
        );
    }

    /// The receipt id and the original path share one line (spec section
    /// 5.1): the store's own names say nothing.
    #[test]
    fn a_receipt_prints_its_original_path_beside_its_id() {
        let receipts = vec![RevealedReceipt {
            receipt_id: "q-0123456789abcdef0123456789abcdef".to_string(),
            item_id: ItemId::from_recorded("claude-code/user/skill/x"),
            kind: Some(Kind::Skill),
            original_path: "/home/.claude/skills/x".to_string(),
            payload_path: String::new(),
            actor: Actor::Auto,
            quarantined_at: Timestamp::parse("2026-09-24T08:00:00.000Z").expect("a moment"),
            finding_id: String::new(),
            rule_id: 1,
            re_enforced: 0,
        }];
        let rendered = render_receipts(&receipts);
        assert!(
            rendered
                .lines()
                .next()
                .expect("a line")
                .contains("q-0123456789abcdef0123456789abcdef  /home/.claude/skills/x"),
            "{rendered}"
        );
        assert_eq!(render_receipts(&[]), "Nothing is in quarantine.\n");
    }

    /// Nothing is ever done without a daemon: the command says Protection is
    /// off and exits with its own code.
    #[test]
    fn no_daemon_is_protection_off_and_nothing_done() {
        let nowhere = std::env::temp_dir().join(format!(
            "agentsweep-actions-nobody-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&nowhere);
        let (rendered, code) = run(&Invocation {
            action: Action::Trust("claude-code/user/skill/x".to_string()),
            socket: Some(nowhere),
        });
        assert!(rendered.starts_with("Protection is off"), "{rendered}");
        assert!(rendered.contains("Nothing was done"), "{rendered}");
        assert_eq!(code, UNREACHABLE);
    }
}
