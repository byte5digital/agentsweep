//! `agentsweep status`: what the daemon found, as a person reads it.
//!
//! This is a client and nothing else. It asks the daemon over its socket and
//! renders what comes back: one Health sentence by the precedence of spec
//! section 6.6, the last Scan summary and the Findings that are open. It scans
//! nothing, writes nothing and never reads a store: those are the daemon's
//! (ADR 0008).
//!
//! A daemon that does not answer is not an error to print. It is Protection
//! off, which is always shown and never implied.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use agentsweep_core::finding::FindingState;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::{RecordedFinding, ScanSummary};
use agentsweep_ipc::Client;
use agentsweep_ipc::protocol::{Role, Status, offers};

/// The line that says the Gate switch is off, in the Developer wording of
/// spec section 8.10, with the command that switches it on.
pub const GATE_HOOKS_OFF: &str =
    "Gate: hooks in Claude Code and Codex are off (agentsweep gate-hooks on).";

/// Asks the daemon and renders the answer.
///
/// The socket is the documented one unless a socket is named, which is how a
/// hand run reaches a daemon that is not the installed one.
pub fn status(socket: Option<&Path>) -> (String, u8) {
    let connected = match socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    };
    let mut client = match connected {
        Ok(client) => client,
        Err(error) if error.is_unreachable() => {
            return (
                render(&Status::unreachable(&error.unreachable())),
                crate::actions::UNREACHABLE,
            );
        }
        Err(error) => return (format!("AgentSweep could not be asked: {error}\n"), 2),
    };
    match client.status() {
        Ok(status) => {
            let open = status.open().count();
            (render(&status), if open > 0 { 1 } else { 0 })
        }
        Err(error) => (format!("AgentSweep could not be asked: {error}\n"), 2),
    }
}

/// The socket a `--socket <path>` argument names, if there is one.
pub fn socket_argument(arguments: &[String]) -> Result<Option<PathBuf>, String> {
    match arguments {
        [] => Ok(None),
        [flag, path] if flag == "--socket" => Ok(Some(PathBuf::from(path))),
        [flag] if flag == "--socket" => Err("`--socket` takes a path".to_string()),
        [unknown, ..] => Err(format!("`{unknown}` is not an option of `status`")),
    }
}

/// One status, as the terminal prints it. The command line interface is a
/// developer surface, so a Health line that comes in a pair prints its
/// Developer sentence (the owner's decision of 2026-10-14).
pub fn render(status: &Status) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", status.health.headline_in(Posture::Developer));
    for note in status.health.notes_in(Posture::Developer) {
        let _ = writeln!(out, "  {note}");
    }
    // The Gate switch is shown when it is off, never implied (spec section
    // 8.10).
    if !status.health.gate_hooks && !status.health.protection.is_off() {
        let _ = writeln!(out, "  {GATE_HOOKS_OFF}");
    }

    // The projects whose own settings switch an Agent's hooks off, which the
    // Gate shows rather than fights (spec section 7.6).
    let gate_off = status.overview.gate_off();
    if !gate_off.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Gate off in this project:");
        for (root, agent) in gate_off {
            let name = status
                .overview
                .agents
                .iter()
                .find(|record| record.agent == agent)
                .map(|record| record.display_name.as_str())
                .unwrap_or(agent);
            let _ = writeln!(out, "  {root}  {name}");
        }
    }

    match &status.scan {
        Some(scan) => {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", scan_line(scan));
        }
        None if !status.health.protection.is_off() => {
            let _ = writeln!(out);
            let _ = writeln!(out, "No Scan has finished yet.");
        }
        None => {}
    }

    let open: Vec<&RecordedFinding> = status.open().collect();
    if !open.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{}:",
            count(open.len(), "open Finding", "open Findings")
        );
        let mut current = "";
        for finding in open {
            if finding.item_id.as_str() != current {
                current = finding.item_id.as_str();
                let name = Path::new(current)
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_default();
                let _ = writeln!(out);
                let _ = writeln!(out, "  {} \u{b7} {}", finding.kind, name);
                let _ = writeln!(out, "  {current}");
            }
            let _ = writeln!(
                out,
                "    {}  {}  {}  {}  {}",
                finding.source,
                finding.severity,
                finding.category,
                finding.tier,
                probation(finding)
            );
            let _ = writeln!(out, "    {}", finding.plain);
            if !finding.drift.is_empty() {
                let _ = writeln!(out, "    {}", finding.drift);
            }
            let _ = writeln!(out, "    id {}", finding.id);
            let offered: Vec<&str> = offers(finding).iter().map(|offer| offer.as_str()).collect();
            if !offered.is_empty() {
                let _ = writeln!(out, "    agentsweep {} <id>", offered.join(" | "));
            }
        }
    }

    // What was decided stays visible: the user can always see what is in
    // quarantine and what they trusted, and put it back.
    let decided: Vec<&RecordedFinding> = status
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.state,
                FindingState::Stopped | FindingState::Trusted | FindingState::Acknowledged
            )
        })
        .collect();
    if !decided.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Stopped and decided:");
        for finding in decided {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  {}  {} \u{b7} {}",
                finding.state,
                finding.kind,
                name_of(finding.item_id.as_str())
            );
            let _ = writeln!(out, "  {}", finding.item_id);
            let _ = writeln!(
                out,
                "    {}  {}  {}",
                finding.source, finding.severity, finding.category
            );
            let _ = writeln!(out, "    id {}", finding.id);
            if !finding.receipt_id.is_empty() {
                let _ = writeln!(out, "    receipt {}", finding.receipt_id);
            }
            if !finding.fixed_version.is_empty() {
                let _ = writeln!(
                    out,
                    "    A fixed version is available: agentsweep re-enable {}",
                    finding.receipt_id
                );
            }
        }
    }
    out
}

/// The name a person knows an Item by: the last part of its locator.
fn name_of(item_id: &str) -> String {
    Path::new(item_id)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// The last Scan, on one line.
pub fn scan_line(scan: &ScanSummary) -> String {
    format!(
        "Last {} Scan ({}) at {}: {}, {}, {} in the Ambiguous Band, {} ms, Rule Pack {}.",
        scan.kind,
        scan.trigger,
        scan.started_at,
        count(scan.items, "Item", "Items"),
        count(scan.findings(), "Finding", "Findings"),
        scan.ambiguous,
        scan.duration_ms,
        scan.rule_pack
    )
}

/// Whether the Rule behind a Finding may act by itself yet.
fn probation(finding: &RecordedFinding) -> &'static str {
    match finding.status {
        agentsweep_core::finding::RuleStatus::Probation => "on probation",
        agentsweep_core::finding::RuleStatus::Stable => "stable",
        agentsweep_core::finding::RuleStatus::Retired => "retired",
    }
}

pub fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        0 => format!("no {many}"),
        1 => format!("1 {one}"),
        _ => format!("{n} {many}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::envelope::Timestamp;
    use agentsweep_core::finding::{Category, FindingId, FindingState, RuleStatus, Severity, Tier};
    use agentsweep_core::health::{GateLine, GateTrouble, Health, Protection, StateFileHealth};
    use agentsweep_core::item::{ItemId, Kind};
    use agentsweep_core::scan_pass::ScanKind;
    use agentsweep_core::state::Trigger;

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    fn summary() -> ScanSummary {
        ScanSummary {
            kind: ScanKind::Full,
            trigger: Trigger::DaemonStart,
            started_at: moment("2026-09-24T08:00:00.000Z"),
            duration_ms: 812,
            items: 17,
            threats: 1,
            exposures: 0,
            clear: 15,
            ambiguous: 1,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        }
    }

    fn finding() -> RecordedFinding {
        RecordedFinding {
            id: FindingId::from_recorded(
                "claude-code/user/skill/~/.claude/skills/setup|rule/0001|a",
            ),
            item_id: ItemId::from_recorded("claude-code/user/skill/~/.claude/skills/setup"),
            kind: Kind::Skill,
            source: "rule 0001".to_string(),
            rule_id: 1,
            category: Category::Threat,
            severity: Severity::Critical,
            tier: Tier::Rules,
            status: RuleStatus::Probation,
            state: FindingState::Open,
            content_hash: "a".repeat(64),
            title: "A skill that pipes a download into a shell".to_string(),
            plain: "This skill downloads and runs a script.".to_string(),
            file: "SKILL.md".to_string(),
            drift: "changed since your last Scan".to_string(),
            receipt_id: String::new(),
            fixed_version: String::new(),
            switched: false,
            facts: Default::default(),
            first_seen: moment("2026-09-24T08:00:00.000Z"),
            notified_at: None,
        }
    }

    /// A daemon that does not answer reads Protection off, which is always
    /// shown and never implied (spec section 6.6).
    #[test]
    fn no_daemon_reads_protection_off() {
        let rendered = render(&Status::unreachable("no daemon answered"));
        assert!(rendered.starts_with("Protection is off.\n"), "{rendered}");
        assert!(rendered.contains("no daemon answered"), "{rendered}");
        assert!(!rendered.contains("All clear"), "{rendered}");
    }

    /// The command line interface is a developer surface: a Gate line prints
    /// its Developer sentence, a second one as a note (the owner's decision
    /// of 2026-10-14).
    #[test]
    fn a_gate_line_prints_its_developer_sentence() {
        let mut health = Health::running();
        health.gate_lines = vec![
            GateLine {
                agent: "claude-code".to_string(),
                name: "Claude Code".to_string(),
                trouble: GateTrouble::RegistrationFailed,
            },
            GateLine {
                agent: "codex".to_string(),
                name: "Codex".to_string(),
                trouble: GateTrouble::ManagedPolicy,
            },
        ];
        let status = Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(
            rendered.starts_with("Gate registration failed: Claude Code.\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("  Gate blocked by managed policy.\n"),
            "{rendered}"
        );
        assert!(!rendered.contains("could not be added"), "{rendered}");
    }

    /// Spec section 8.10: a Gate switched off is said, not implied, and a Gate
    /// that is on adds no line.
    #[test]
    fn a_gate_switched_off_is_said() {
        let status = |gate_hooks: bool| Status {
            health: Health {
                gate_hooks,
                ..Health::running()
            },
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status(false));
        assert!(
            rendered.contains(&format!("  {GATE_HOOKS_OFF}\n")),
            "{rendered}"
        );
        assert!(!render(&status(true)).contains("Gate:"));
    }

    /// Spec section 7.6: the projects that switched the check off are listed
    /// with their Agent, and Health counts them on the Gate rung.
    #[test]
    fn the_projects_gate_off_are_listed_with_their_agent() {
        use agentsweep_core::overview::{
            AgentRecord, Overview, ProjectAgent, ProjectCheck, ProjectRecord,
        };
        let agent = |agent: &str, gate_off: bool| ProjectAgent {
            agent: agent.to_string(),
            registered: true,
            gate_off,
        };
        let overview = Overview {
            agents: vec![AgentRecord {
                agent: "claude-code".to_string(),
                display_name: "Claude Code".to_string(),
                installed: true,
                ..AgentRecord::default()
            }],
            projects: vec![
                ProjectRecord {
                    root: "/work/app".to_string(),
                    agents: vec![agent("claude-code", true), agent("codex", true)],
                    check: ProjectCheck::Checked,
                },
                ProjectRecord {
                    root: "/work/other".to_string(),
                    agents: vec![agent("claude-code", false)],
                    check: ProjectCheck::Checked,
                },
            ],
            ambiguous: Vec::new(),
            checked: Vec::new(),
        };
        let mut health = Health::running();
        health.projects_gate_off = overview.projects_gate_off();
        let status = Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview,
        };
        let rendered = render(&status);
        assert!(
            rendered.starts_with("Gate off in 1 project.\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "Gate off in this project:\n  /work/app  Claude Code\n  /work/app  codex\n"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("/work/other"), "{rendered}");
    }

    #[test]
    fn a_clear_machine_reads_the_headline_and_the_last_scan() {
        let mut health = Health::running();
        health.items = 17;
        health.last_full_scan = Some(moment("2026-09-24T08:00:00.812Z"));
        let status = Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(
            rendered.starts_with("All clear, last checked"),
            "{rendered}"
        );
        assert!(rendered.contains("17 Items"), "{rendered}");
        assert!(rendered.contains("Rule Pack 1"), "{rendered}");
        assert!(rendered.contains("812 ms"), "{rendered}");
        assert!(!rendered.contains("open Finding"), "{rendered}");
    }

    /// The status names the Rule Pack in force and the date of its signed
    /// release, and says so when the feed is off.
    #[test]
    fn the_status_says_when_the_rules_were_updated() {
        let mut health = Health::running();
        health.rule_pack = 3;
        health.rule_pack_origin = agentsweep_core::packs::PackOrigin::Fetched;
        health.rules_released_at = "2026-10-01T09:30:00Z".to_string();
        let status = Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(
            rendered.contains("Rules updated 2026-10-01 (Rule Pack 3, fetched)."),
            "{rendered}"
        );
    }

    #[test]
    fn an_open_finding_is_shown_with_everything_the_user_needs() {
        let mut health = Health::running();
        health.open_threats = 1;
        health.last_full_scan = Some(moment("2026-09-24T08:00:00.812Z"));
        let status = Status {
            health,
            scan: Some(summary()),
            findings: vec![finding()],
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(
            rendered.starts_with("1 thing needs your decision: 1 Threat."),
            "{rendered}"
        );
        assert!(rendered.contains("1 open Finding:"), "{rendered}");
        assert!(rendered.contains("Skill \u{b7} setup"), "{rendered}");
        assert!(rendered.contains("rule 0001"), "{rendered}");
        assert!(rendered.contains("critical"), "{rendered}");
        assert!(rendered.contains("on probation"), "{rendered}");
        assert!(
            rendered.contains("This skill downloads and runs a script."),
            "{rendered}"
        );
        assert!(
            rendered.contains("changed since your last Scan"),
            "{rendered}"
        );
    }

    /// Two open Findings and nothing else wrong: the status line is the rung
    /// of the Health precedence that asks for the user's decision, with the
    /// Threat and the Exposure counted apart; with none open it is all clear.
    #[test]
    fn two_open_findings_are_two_things_that_need_your_decision() {
        let mut exposure = finding();
        exposure.category = agentsweep_core::finding::Category::Exposure;
        let mut health = Health::running();
        health.open_threats = 1;
        health.open_exposures = 1;
        health.last_full_scan = Some(moment("2026-09-24T08:00:00.812Z"));
        let status = Status {
            health,
            scan: Some(summary()),
            findings: vec![finding(), exposure],
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(
            rendered.starts_with("2 things need your decision: 1 Threat and 1 Exposure.\n"),
            "{rendered}"
        );
        assert!(!rendered.contains("Findings are open."), "{rendered}");

        let quiet = Status {
            health: Health {
                last_full_scan: Some(moment("2026-09-24T08:00:00.812Z")),
                ..Health::running()
            },
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        assert!(
            render(&quiet).starts_with("All clear"),
            "{}",
            render(&quiet)
        );
    }

    /// A Finding that was stopped, trusted or acknowledged is not open, so it
    /// is not in the list of what asks something of the user. It is listed as
    /// decided, with the Receipt that puts it back.
    #[test]
    fn a_finding_that_no_longer_asks_anything_is_listed_as_decided() {
        let mut stopped = finding();
        stopped.state = FindingState::Stopped;
        stopped.receipt_id = "q-0123456789abcdef0123456789abcdef".to_string();
        let status = Status {
            health: Health::running(),
            scan: Some(summary()),
            findings: vec![stopped],
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(!rendered.contains("open Finding"), "{rendered}");
        assert!(rendered.contains("Stopped and decided:"), "{rendered}");
        assert!(rendered.contains("stopped  Skill"), "{rendered}");
        assert!(
            rendered.contains("receipt q-0123456789abcdef0123456789abcdef"),
            "{rendered}"
        );
    }

    /// Every open Finding prints its id and the actions the daemon allows on
    /// it, so the user can act on it from the terminal.
    #[test]
    fn an_open_finding_prints_its_id_and_what_can_be_done_about_it() {
        let status = Status {
            health: Health::running(),
            scan: Some(summary()),
            findings: vec![finding()],
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(
            rendered.contains("id claude-code/user/skill/~/.claude/skills/setup|rule/0001|a"),
            "{rendered}"
        );
        assert!(
            rendered.contains("agentsweep quarantine | trust <id>"),
            "{rendered}"
        );
    }

    /// A daemon that has just started and has not finished its first Full Scan
    /// says so rather than showing nothing.
    #[test]
    fn a_daemon_with_no_finished_scan_says_so() {
        let mut health = Health::running();
        health.scanning = true;
        health.state_file = StateFileHealth::Missing;
        let status = Status {
            health,
            scan: None,
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        let rendered = render(&status);
        assert!(rendered.starts_with("Checking now."), "{rendered}");
        assert!(rendered.contains("No Scan has finished yet."), "{rendered}");
        assert!(rendered.contains("rebuilt"), "{rendered}");
    }

    /// Protection off wins over everything, so nothing under it invites the
    /// user to act on a Scan that never ran.
    #[test]
    fn protection_off_shows_no_scan_line_at_all() {
        let status = Status {
            health: Health {
                protection: Protection::Off("no daemon answered".to_string()),
                ..Health::default()
            },
            scan: None,
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Default::default(),
        };
        assert!(!render(&status).contains("No Scan"), "{}", render(&status));
    }

    /// The whole command, against a socket nothing is listening on. It never
    /// touches the documented socket, because the path is named.
    #[test]
    fn the_command_reads_protection_off_and_exits_three_when_no_daemon_answers() {
        let nowhere = std::env::temp_dir().join(format!(
            "agentsweep-status-nobody-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&nowhere);
        let (rendered, code) = status(Some(&nowhere));
        assert!(rendered.starts_with("Protection is off."), "{rendered}");
        assert_eq!(code, crate::actions::UNREACHABLE);
    }

    #[test]
    fn the_socket_option_is_the_only_one_status_takes() {
        assert_eq!(socket_argument(&[]).expect("no option"), None);
        assert_eq!(
            socket_argument(&["--socket".to_string(), "/tmp/a.sock".to_string()])
                .expect("a socket"),
            Some(PathBuf::from("/tmp/a.sock"))
        );
        assert!(socket_argument(&["--socket".to_string()]).is_err());
        assert!(socket_argument(&["--all".to_string()]).is_err());
    }
}
