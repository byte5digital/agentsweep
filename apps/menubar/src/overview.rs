//! What the Overview pane shows (spec section 8.1): the status sentence, one
//! line per Agent, the last check, the date the Rule Pack in force was
//! released, the two Scan actions with the progress of a running Scan, and in
//! the Developer Posture the last Scan on one line.
//!
//! Everything here is a pure function of what the daemon said: the Health,
//! the Agent records of the last Full Scan, the last Scan's summary and the
//! Scan in hand as the subscribe stream reports it. The status sentence is
//! [`Health::headline_in`] the Posture, the one the popover and the command
//! line interface print. When the daemon is unreachable the pane says "Protection is off."
//! and offers nothing else (spec section 6.2): no Agent, no date and neither
//! Scan action.
//!
//! The integrity and Protection banners replace the status sentence here as
//! in the popover ([`crate::banner`]). The Gate's Health lines the sentence
//! does not say, and "Gate off in this project" for each project that
//! switched the check off, come from [`crate::gate`] (spec sections 8.1 and
//! 8.6); neither offers an action. The AI check's lines are
//! [`crate::verdict`]'s: the cap line in both Postures, and the queue
//! progress line in the Developer Posture, which the window's frame fills in
//! from the stream. The lines for projects that Need Permission are another
//! screen's; the window leaves their place in the layout and this view
//! carries nothing for them yet.

use agentsweep_core::health::Health;
use agentsweep_core::overview::{AgentRecord, Overview};
use agentsweep_core::settings::Posture;
use agentsweep_core::state::ScanSummary;
use agentsweep_ipc::protocol::Status;
use serde_json::{Value, json};

use crate::banner::{self, Daemon, Shown};
use crate::findings::{ScanLine, count, progress_line};
use crate::gate::{self, ProjectOff};

/// One Agent as the Overview names it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentLine {
    /// The machine-readable Agent id.
    pub agent: String,
    /// True when the Agent is installed on this machine.
    pub installed: bool,
    /// The line itself.
    pub line: String,
}

/// Everything the Overview pane renders, in one value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverviewView {
    /// True when Protection is off: the pane then shows the sentence alone.
    pub off: bool,
    /// The status sentence, by the Health precedence (spec section 6.6).
    pub sentence: String,
    /// One line per Agent AgentSweep has an adapter for, installed or not.
    pub agents: Vec<AgentLine>,
    /// When the last Full Scan finished, RFC 3339, absent before the first
    /// and while Protection is off. The window writes it in local time, as
    /// the popover does.
    pub last_check: Option<String>,
    /// "Rules updated <date>", from the signed `released_at` of the Rule Pack
    /// in force (spec section 9.4), absent when no pack is known.
    pub rules_updated: Option<String>,
    /// True when the pane offers **Scan now** and **Scan a folder**.
    pub actions: bool,
    /// True while a Scan runs.
    pub scanning: bool,
    /// The running Scan's progress, empty when none runs.
    pub progress: String,
    /// The last Scan on one line: trigger, Item count, duration, Finding
    /// counts, Bands, Rule Pack and engine. The Developer Posture only.
    pub summary: Option<String>,
    /// The banner that replaces the sentence, when one stands.
    pub banner: Option<Shown>,
    /// The Gate's Health lines the sentence does not say (spec section
    /// 6.6), in the Posture.
    pub gate_lines: Vec<String>,
    /// "Gate off in this project", one per project that switched the check
    /// off for itself (spec section 7.6). Shown, never fought: no action.
    pub gate_off: Vec<ProjectOff>,
    /// "AI check: 3 of 12" while the AI Judgement queue runs, in the
    /// Developer Posture only ([`crate::verdict::progress_line`]). The
    /// window's frame follows the queue and fills it in.
    pub ai_check: Option<String>,
    /// The fixed cap line while a cap of AI Judgement holds Items back, in
    /// both Postures ([`crate::verdict::cap_line`]).
    pub cap: Option<String>,
}

impl OverviewView {
    /// The value the window receives under `overview`.
    pub fn to_value(&self) -> Value {
        json!({
            "off": self.off,
            "sentence": self.banner.is_none().then_some(self.sentence.as_str()),
            "banner": self.banner.as_ref().map(Shown::to_value),
            "agents": self
                .agents
                .iter()
                .map(|agent| json!({
                    "agent": agent.agent,
                    "installed": agent.installed,
                    "line": agent.line,
                }))
                .collect::<Vec<_>>(),
            "lastCheck": self.last_check,
            "rulesUpdated": self.rules_updated,
            "actions": self.actions,
            "scan": { "running": self.scanning, "progress": self.progress },
            "summary": self.summary,
            "gate": {
                "lines": self.gate_lines,
                "projects": self
                    .gate_off
                    .iter()
                    .map(|project| json!({ "project": project.project, "line": project.line }))
                    .collect::<Vec<_>>(),
            },
            "aiCheck": self.ai_check,
            "cap": self.cap,
        })
    }
}

/// The Overview of a status answer, in a Posture. A Scan the status says is
/// running shows as one that is still looking for what to check; the stream
/// tells the rest.
pub fn of_status(status: &Status, posture: Posture) -> OverviewView {
    let scan = ScanLine {
        running: status.health.scanning,
        ..ScanLine::default()
    };
    view(
        &status.health,
        &status.overview,
        status.scan.as_ref(),
        &scan,
        posture,
    )
}

/// The Overview of what the window holds: the Health, the Agent records,
/// the last Scan's summary and the Scan in hand, in a Posture.
pub fn view(
    health: &Health,
    overview: &Overview,
    last_scan: Option<&ScanSummary>,
    scan: &ScanLine,
    posture: Posture,
) -> OverviewView {
    if health.protection.is_off() {
        return OverviewView {
            off: true,
            sentence: health.headline(),
            agents: Vec::new(),
            last_check: None,
            rules_updated: None,
            actions: false,
            scanning: false,
            progress: String::new(),
            summary: None,
            banner: banner::choose(health, &Daemon::Off).map(|banner| banner.shown(posture)),
            gate_lines: Vec::new(),
            gate_off: Vec::new(),
            ai_check: None,
            cap: None,
        };
    }
    let sentence = health.headline_in(posture);
    OverviewView {
        off: false,
        gate_lines: gate::health_lines(health, posture)
            .into_iter()
            .filter(|line| *line != sentence)
            .collect(),
        gate_off: gate::projects_off(overview, posture),
        sentence,
        agents: overview
            .agents
            .iter()
            .map(|record| AgentLine {
                agent: record.agent.clone(),
                installed: record.installed,
                line: agent_line(record, posture),
            })
            .collect(),
        last_check: health.last_full_scan.map(|at| at.to_string()),
        rules_updated: rules_updated(health, posture),
        actions: true,
        scanning: scan.running,
        progress: match scan.running {
            true => progress(scan.done, scan.total, posture),
            false => String::new(),
        },
        summary: match posture {
            Posture::Developer => last_scan.map(summary_line),
            Posture::Simple => None,
        },
        banner: banner::choose(health, &Daemon::Answering).map(|banner| banner.shown(posture)),
        ai_check: None,
        cap: crate::verdict::cap_line(health),
    }
}

/// One Agent on one line: its name and version, or "version unknown" where
/// none could be read from disk, how many projects its registry names and
/// how many Items the last Full Scan found on its Surfaces; or that it is not
/// installed.
pub fn agent_line(record: &AgentRecord, posture: Posture) -> String {
    let name = match record.display_name.is_empty() {
        true => record.agent.as_str(),
        false => record.display_name.as_str(),
    };
    if !record.installed {
        return format!("{name} is not installed.");
    }
    let named = match &record.version {
        Some(version) => format!("{name} {version}"),
        None => format!("{name}, version unknown"),
    };
    let items = match posture {
        Posture::Developer => count(record.items, "Item", "Items"),
        Posture::Simple => match record.items {
            0 => "nothing checked".to_string(),
            1 => "1 thing checked".to_string(),
            many => format!("{many} things checked"),
        },
    };
    format!(
        "{named}: {}, {items}.",
        count(record.projects, "project", "projects")
    )
}

/// "Rules updated <date>" from the signed `released_at`; the Developer
/// Posture adds the pack's version and where it came from, as the command
/// line interface does.
pub fn rules_updated(health: &Health, posture: Posture) -> Option<String> {
    let day = health.rules_updated()?;
    Some(match posture {
        Posture::Simple => format!("Rules updated {day}."),
        Posture::Developer => format!(
            "Rules updated {day} (Rule Pack {}, {}).",
            health.rule_pack, health.rule_pack_origin
        ),
    })
}

/// A running Scan's progress: plain in the Simple Posture, the command line
/// interface's line in the Developer Posture.
pub fn progress(done: usize, total: usize, posture: Posture) -> String {
    match (posture, total) {
        (Posture::Developer, _) => progress_line(done, total),
        (Posture::Simple, 0) => "Looking for what to check.".to_string(),
        (Posture::Simple, _) => format!("Checked {done} of {total}."),
    }
}

/// The last Scan on one line (spec section 8.1): trigger, Item count,
/// duration, Finding counts, Bands, Rule Pack and engine.
pub fn summary_line(scan: &ScanSummary) -> String {
    let engine = match scan.engine.is_empty() {
        true => "no Judgement Engine".to_string(),
        false => format!("engine {}", scan.engine),
    };
    format!(
        "Last {} Scan ({}) at {}: {}, {} ms, {} and {}, Bands {} clear, {} ambiguous, {} \
         suspicious, Rule Pack {}, {engine}.",
        scan.kind,
        scan.trigger,
        scan.started_at,
        count(scan.items, "Item", "Items"),
        scan.duration_ms,
        count(scan.threats, "Threat Finding", "Threat Findings"),
        count(scan.exposures, "Exposure Finding", "Exposure Findings"),
        scan.clear,
        scan.ambiguous,
        scan.suspicious,
        scan.rule_pack,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::envelope::Timestamp;
    use agentsweep_core::overview::{ProjectAgent, ProjectRecord};
    use agentsweep_core::packs::PackOrigin;
    use agentsweep_core::scan_pass::ScanKind;
    use agentsweep_core::state::Trigger;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a moment")
    }

    fn agent(id: &str, name: &str, installed: bool, version: Option<&str>) -> AgentRecord {
        AgentRecord {
            agent: id.to_string(),
            display_name: name.to_string(),
            installed,
            version: version.map(str::to_string),
            config_dir: format!("~/.{id}"),
            projects: usize::from(installed) * 2,
            items: usize::from(installed) * 41,
            layers_not_read: Vec::new(),
        }
    }

    fn summary() -> ScanSummary {
        ScanSummary {
            kind: ScanKind::Full,
            trigger: Trigger::ScanNow,
            started_at: at("2026-10-15T08:00:00.000Z"),
            duration_ms: 812,
            items: 43,
            threats: 1,
            exposures: 2,
            clear: 40,
            ambiguous: 2,
            suspicious: 1,
            rule_pack: 3,
            engine: String::new(),
        }
    }

    /// A running daemon after a Full Scan: Claude Code with its version,
    /// Codex installed with no version on disk, one open Threat.
    fn status() -> Status {
        let mut health = Health::running();
        health.last_full_scan = Some(at("2026-10-15T08:00:00.812Z"));
        health.open_threats = 1;
        health.rule_pack = 3;
        health.rule_pack_origin = PackOrigin::Fetched;
        health.rules_released_at = "2026-10-01T09:30:00Z".to_string();
        Status {
            health,
            scan: Some(summary()),
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Overview {
                agents: vec![
                    agent("claude-code", "Claude Code", true, Some("2.1.3")),
                    agent("codex", "Codex", true, None),
                ],
                projects: vec![ProjectRecord {
                    root: "~/work/demo".to_string(),
                    agents: vec![ProjectAgent {
                        agent: "claude-code".to_string(),
                        registered: true,
                        gate_off: false,
                    }],
                    ..ProjectRecord::default()
                }],
                ambiguous: Vec::new(),
                checked: Vec::new(),
            },
        }
    }

    fn lines(view: &OverviewView) -> Vec<&str> {
        view.agents
            .iter()
            .map(|agent| agent.line.as_str())
            .collect()
    }

    #[test]
    fn the_simple_overview_has_the_sentence_the_agents_and_no_summary() {
        let status = status();
        let view = of_status(&status, Posture::Simple);
        assert!(!view.off);
        assert_eq!(view.sentence, status.health.headline());
        assert_eq!(
            view.sentence, "1 thing needs your decision: 1 Threat.",
            "the popover's sentence"
        );
        assert_eq!(
            lines(&view),
            vec![
                "Claude Code 2.1.3: 2 projects, 41 things checked.",
                "Codex, version unknown: 2 projects, 41 things checked.",
            ]
        );
        assert_eq!(view.last_check.as_deref(), Some("2026-10-15T08:00:00.812Z"));
        assert_eq!(
            view.rules_updated.as_deref(),
            Some("Rules updated 2026-10-01.")
        );
        assert!(view.actions);
        assert_eq!(view.summary, None, "the summary is the Developer Posture's");
    }

    #[test]
    fn the_developer_overview_adds_the_one_line_scan_summary() {
        let status = status();
        let view = of_status(&status, Posture::Developer);
        assert_eq!(view.sentence, status.health.headline());
        assert_eq!(
            lines(&view),
            vec![
                "Claude Code 2.1.3: 2 projects, 41 Items.",
                "Codex, version unknown: 2 projects, 41 Items.",
            ]
        );
        assert_eq!(
            view.summary.as_deref(),
            Some(
                "Last full Scan (scan-now) at 2026-10-15T08:00:00.000Z: 43 Items, 812 ms, \
                 1 Threat Finding and 2 Exposure Findings, Bands 40 clear, 2 ambiguous, \
                 1 suspicious, Rule Pack 3, no Judgement Engine."
            )
        );
        assert_eq!(
            view.rules_updated.as_deref(),
            Some("Rules updated 2026-10-01 (Rule Pack 3, fetched).")
        );
        assert!(view.actions);
        // The engine is named once one ran.
        let judged = ScanSummary {
            engine: "ollama".to_string(),
            ..summary()
        };
        assert!(summary_line(&judged).ends_with("Rule Pack 3, engine ollama."));
    }

    /// Both Postures name the same Agents in the same order; only the wording
    /// moves.
    #[test]
    fn both_postures_list_the_same_agents() {
        let status = status();
        let simple = of_status(&status, Posture::Simple);
        let developer = of_status(&status, Posture::Developer);
        let ids = |view: &OverviewView| -> Vec<(String, bool)> {
            view.agents
                .iter()
                .map(|agent| (agent.agent.clone(), agent.installed))
                .collect()
        };
        assert_eq!(ids(&simple), ids(&developer));
        assert_eq!(simple.sentence, developer.sentence);
        assert_eq!(simple.last_check, developer.last_check);
    }

    #[test]
    fn an_agent_not_installed_says_so_and_an_unknown_version_is_said() {
        let absent = agent("codex", "Codex", false, None);
        let unknown = agent("claude-code", "Claude Code", true, None);
        for posture in Posture::ALL {
            assert_eq!(agent_line(&absent, posture), "Codex is not installed.");
            let line = agent_line(&unknown, posture);
            assert!(line.starts_with("Claude Code, version unknown: "), "{line}");
        }
        // A record with no display name falls back to its id rather than an
        // empty name.
        let nameless = AgentRecord {
            display_name: String::new(),
            ..agent("codex", "", true, Some("0.4.0"))
        };
        assert!(agent_line(&nameless, Posture::Simple).starts_with("codex 0.4.0: "));
        let one = AgentRecord {
            projects: 1,
            items: 1,
            ..agent("codex", "Codex", true, Some("0.4.0"))
        };
        assert_eq!(
            agent_line(&one, Posture::Simple),
            "Codex 0.4.0: 1 project, 1 thing checked."
        );
        assert_eq!(
            agent_line(&one, Posture::Developer),
            "Codex 0.4.0: 1 project, 1 Item."
        );
    }

    /// Protection off: the sentence and nothing else, in either Posture.
    #[test]
    fn protection_off_shows_only_the_sentence_and_no_scan_action() {
        let mut status = status();
        status.health = Health::unreachable("the daemon stopped answering");
        for posture in Posture::ALL {
            let view = of_status(&status, posture);
            assert!(view.off);
            assert_eq!(view.sentence, "Protection is off.");
            assert!(view.agents.is_empty());
            assert_eq!(view.last_check, None);
            assert_eq!(view.rules_updated, None);
            assert_eq!(view.summary, None);
            assert!(!view.actions, "neither Scan action is offered");
            assert_eq!(view.to_value()["actions"], false);
        }
    }

    /// A running Scan shows its progress in both Postures, each in its own
    /// words.
    #[test]
    fn a_running_scan_shows_its_progress() {
        let mut status = status();
        status.health.scanning = true;
        let view = of_status(&status, Posture::Simple);
        assert_eq!(view.sentence, "Checking now.");
        assert!(view.scanning);
        assert_eq!(view.progress, "Looking for what to check.");

        let scan = ScanLine {
            running: true,
            done: 12,
            total: 43,
            ..ScanLine::default()
        };
        let simple = view_of(&status, &scan, Posture::Simple);
        assert_eq!(simple.progress, "Checked 12 of 43.");
        let developer = view_of(&status, &scan, Posture::Developer);
        assert_eq!(developer.progress, "Checked 12 of 43 Items.");

        let idle = view_of(&status, &ScanLine::default(), Posture::Developer);
        assert_eq!(idle.progress, "");
        assert!(!idle.scanning);
    }

    fn view_of(status: &Status, scan: &ScanLine, posture: Posture) -> OverviewView {
        view(
            &status.health,
            &status.overview,
            status.scan.as_ref(),
            scan,
            posture,
        )
    }

    /// Before the first Full Scan nothing is listed and no date is made up.
    #[test]
    fn nothing_known_yet_lists_nothing_and_invents_no_date() {
        let status = Status {
            health: Health::running(),
            scan: None,
            findings: Vec::new(),
            activity: Vec::new(),
            overview: Overview::default(),
        };
        let view = of_status(&status, Posture::Developer);
        assert!(view.agents.is_empty());
        assert_eq!(view.last_check, None);
        assert_eq!(view.rules_updated, None);
        assert_eq!(view.summary, None);
        assert!(view.actions);
    }

    #[test]
    fn the_window_receives_every_field_by_name() {
        let value = of_status(&status(), Posture::Developer).to_value();
        assert_eq!(value["off"], false);
        assert_eq!(value["agents"][1]["agent"], "codex");
        assert_eq!(value["agents"][1]["installed"], true);
        assert_eq!(value["lastCheck"], "2026-10-15T08:00:00.812Z");
        assert!(value["rulesUpdated"].is_string());
        assert_eq!(value["actions"], true);
        assert_eq!(value["scan"]["running"], false);
        assert_eq!(value["scan"]["progress"], "");
        assert!(value["summary"].is_string());
    }

    #[test]
    fn no_line_carries_an_em_dash() {
        let mut status = status();
        status
            .overview
            .agents
            .push(agent("other", "Other", false, None));
        for posture in Posture::ALL {
            let value = of_status(&status, posture).to_value().to_string();
            assert!(!value.contains('\u{2014}'), "{value}");
        }
    }
    /// Spec sections 7.6, 8.1 and 8.6: a project whose own settings switch
    /// the check off is named with "Gate off in this project", and the line
    /// carries nothing that could change the project's settings.
    #[test]
    fn a_project_with_the_gate_off_is_shown_and_not_fought() {
        let mut status = status();
        status.overview.projects[0].agents[0].gate_off = true;
        status.health.projects_gate_off = 1;
        status.health.open_threats = 0;
        for (posture, project, sentence) in [
            (Posture::Simple, "demo", "1 project switched off the check."),
            (
                Posture::Developer,
                "~/work/demo (Claude Code)",
                "Gate off in 1 project.",
            ),
        ] {
            let view = of_status(&status, posture);
            assert_eq!(view.sentence, sentence);
            assert!(view.gate_lines.is_empty(), "the sentence says it once");
            let value = view.to_value();
            assert_eq!(
                value["gate"]["projects"],
                serde_json::json!([{ "project": project, "line": "Gate off in this project" }])
            );
            let entry = value["gate"]["projects"][0].as_object().expect("an entry");
            assert_eq!(entry.len(), 2, "no action beside the line: {entry:?}");
        }
    }

    /// The Gate lines the sentence does not say are listed on the Overview,
    /// in the Posture's wording.
    #[test]
    fn the_gate_lines_under_a_worse_rung_are_listed() {
        use agentsweep_core::health::{GateLine, GateTrouble};

        let mut status = status();
        status.health.projects_need_permission = 1;
        status.health.projects_gate_off = 2;
        status.health.gate_lines = vec![GateLine {
            agent: "claude-code".to_string(),
            name: "Claude Code".to_string(),
            trouble: GateTrouble::RegistrationFailed,
        }];
        let simple = of_status(&status, Posture::Simple);
        assert_eq!(
            simple.gate_lines,
            [
                "2 projects switched off the check.",
                "The check could not be added to Claude Code."
            ]
        );
        let developer = of_status(&status, Posture::Developer);
        assert_eq!(
            developer.gate_lines,
            [
                "Gate off in 2 projects.",
                "Gate registration failed: Claude Code."
            ]
        );
        assert!(developer.gate_off.is_empty(), "no project record says so");
    }
}
