//! What the Findings window shows: every Finding the daemon's `status`
//! carries, split into the open ones that ask something of the user and the
//! ones already stopped or decided, each with exactly the actions the daemon
//! allows on it ([`crate::actions`]); and the Scan in hand, followed from the
//! subscribe stream. While a Scan runs every action waits for it to finish
//! (decision 22 of the owner), so the window disables the action buttons and
//! says why; Health on the stream says when they may be pressed again.
//!
//! The list is the daemon's, never worked out here. It is loaded from a
//! status answer and then kept current from the state events: a Finding that
//! changed moves at once, and whatever the event does not carry (a Receipt id,
//! a Finding a Scan newly raised) is fetched again from the status, which
//! [`Follow::Refresh`] asks the caller to do. The user never refreshes by hand.
//!
//! The Scan lines here are taken from the command line interface. How a
//! Finding reads is [`crate::wording`]'s; its buttons and their
//! confirmations are [`crate::actions`]'s.

use agentsweep_core::adapter::{Primitive, eligibility};
use agentsweep_core::finding::{Category, FindingState, RuleStatus};
use agentsweep_core::health::Health;
use agentsweep_core::item::Kind;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::{RecordedFinding, ScanSummary};
use agentsweep_ipc::protocol::{StateEvent, Status};
use serde_json::{Value, json};

pub use crate::actions::{Action, trust_confirmation};
use crate::actions::{card_in, offered};

/// What the caller does after an event was applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Follow {
    /// Nothing changed that the window shows.
    Nothing,
    /// The view changed: send it to the window.
    Render,
    /// The view changed and needs what only the status carries: ask for the
    /// status, [`Findings::load`] it, then send the view.
    Refresh,
}

/// The Scan in hand, as the window and the popover show it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanLine {
    /// True while a Scan runs.
    pub running: bool,
    /// Its progress, or the last Scan on one line once none runs.
    pub line: String,
    /// How many Items the running Scan has checked, zero once none runs.
    pub done: usize,
    /// How many Items it found to check, zero while it is still looking and
    /// once none runs.
    pub total: usize,
}

/// The Findings window's list, kept from the status and the stream.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Findings {
    findings: Vec<RecordedFinding>,
    loaded: bool,
    scan: ScanLine,
    off: Option<String>,
}

impl Findings {
    /// A list before anything was asked.
    pub fn new() -> Findings {
        Findings::default()
    }

    /// Takes the list from a status answer, which is the whole truth.
    pub fn load(&mut self, status: &Status) {
        self.findings = status.findings.clone();
        self.loaded = true;
        self.off = match status.health.protection.is_off() {
            true => Some(status.health.protection.reason().to_string()),
            false => None,
        };
        if !self.scan.running || !status.health.scanning {
            self.scan = ScanLine {
                running: status.health.scanning,
                line: match (&status.scan, status.health.scanning) {
                    (_, true) => progress_line(0, 0),
                    (Some(summary), false) => scan_line(summary),
                    (None, false) => String::new(),
                },
                ..ScanLine::default()
            };
        }
    }

    /// No daemon answers: Protection is off and nothing can be acted on. What
    /// was listed is dropped, because silence is never an all-clear and an
    /// action on it could not be carried out anyway.
    pub fn off(&mut self, reason: &str) -> Follow {
        let was = self.clone();
        self.findings.clear();
        self.loaded = false;
        self.scan = ScanLine::default();
        self.off = Some(reason.to_string());
        match *self == was {
            true => Follow::Nothing,
            false => Follow::Render,
        }
    }

    /// Applies one state event and says what the caller does next.
    pub fn apply(&mut self, event: &StateEvent) -> Follow {
        match event {
            StateEvent::ScanStarted { .. } => {
                self.scan = ScanLine {
                    running: true,
                    line: progress_line(0, 0),
                    ..ScanLine::default()
                };
                Follow::Render
            }
            StateEvent::ScanProgress { done, total } => {
                self.scan = ScanLine {
                    running: true,
                    line: progress_line(*done, *total),
                    done: *done,
                    total: *total,
                };
                Follow::Render
            }
            // A Scan raises and settles Findings as it ends; the status says
            // which.
            StateEvent::ScanFinished { summary } => {
                self.scan = ScanLine {
                    running: false,
                    line: scan_line(summary),
                    ..ScanLine::default()
                };
                Follow::Refresh
            }
            StateEvent::FindingChanged { id, state, .. } => {
                let Some(at) = self.findings.iter().position(|finding| &finding.id == id) else {
                    // A Finding this list has not seen: only the status
                    // carries what it says.
                    return Follow::Refresh;
                };
                if state == "gone" {
                    self.findings.remove(at);
                    return Follow::Render;
                }
                let Some(now) = FindingState::parse(state) else {
                    return Follow::Refresh;
                };
                let finding = &mut self.findings[at];
                let was = finding.state;
                finding.state = now;
                match now {
                    // Stopped carries a Receipt id and open drops one; the
                    // status has both. The move itself shows at once.
                    FindingState::Stopped | FindingState::Open if was != now => Follow::Refresh,
                    _ if was == now => Follow::Nothing,
                    _ => Follow::Render,
                }
            }
            StateEvent::HealthChanged { health } => self.health(health),
            // The AI check's progress is a Developer Posture and Activity line,
            // never the Scan line.
            StateEvent::Activity { .. }
            | StateEvent::SettingsChanged { .. }
            | StateEvent::JudgementProgress { .. } => Follow::Nothing,
            // The list holds no Overview; the window's frame keeps it.
            StateEvent::OverviewChanged { .. } => Follow::Nothing,
        }
    }

    /// A Health on the stream: Protection back on, or a count of open
    /// Findings the list does not match, asks for the status again. Whether a
    /// Scan runs follows Health too, which is what disables the actions and
    /// enables them again; the Scan's own progress and end come as events of
    /// their own and write the line.
    fn health(&mut self, health: &Health) -> Follow {
        if health.protection.is_off() {
            return self.off(health.protection.reason());
        }
        let back = self.off.take().is_some();
        let open = self.findings.iter().filter(|f| f.is_open()).count();
        let running = self.scan.running != health.scanning;
        if running {
            self.scan.running = health.scanning;
            if health.scanning && self.scan.line.is_empty() {
                self.scan.line = progress_line(0, 0);
            }
        }
        match (
            back || !self.loaded || open != health.open_findings(),
            running,
        ) {
            (true, _) => Follow::Refresh,
            (false, true) => Follow::Render,
            (false, false) => Follow::Nothing,
        }
    }

    /// Why the actions cannot be pressed right now, absent when they can:
    /// every action waits for a running Scan to finish.
    pub fn actions_wait(&self) -> Option<&'static str> {
        match self.scan.running && self.off.is_none() {
            true => Some(ACTIONS_WAIT),
            false => None,
        }
    }

    /// The open Findings, which ask something of the user.
    pub fn open(&self) -> impl Iterator<Item = &RecordedFinding> {
        self.findings.iter().filter(|finding| finding.is_open())
    }

    /// The Findings already stopped, trusted or acknowledged: what was
    /// decided stays visible, and a stopped one can be put back.
    pub fn decided(&self) -> impl Iterator<Item = &RecordedFinding> {
        self.findings.iter().filter(|finding| {
            matches!(
                finding.state,
                FindingState::Stopped | FindingState::Trusted | FindingState::Acknowledged
            )
        })
    }

    /// Every Finding the list holds, in the order the status gave them.
    pub fn all(&self) -> &[RecordedFinding] {
        &self.findings
    }

    /// True once a status answer was loaded.
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// The Finding with this id, if the list holds it.
    pub fn get(&self, id: &str) -> Option<&RecordedFinding> {
        self.findings
            .iter()
            .find(|finding| finding.id.as_str() == id)
    }

    /// The Scan in hand.
    pub fn scan(&self) -> &ScanLine {
        &self.scan
    }

    /// The value the window receives.
    pub fn to_value(&self) -> Value {
        let open: Vec<&RecordedFinding> = self.open().collect();
        json!({
            "off": self.off,
            "loaded": self.loaded,
            "scan": { "running": self.scan.running, "line": self.scan.line },
            "actionsWait": self.actions_wait(),
            "counts": {
                "threats": open.iter().filter(|f| f.category == Category::Threat).count(),
                "exposures": open.iter().filter(|f| f.category == Category::Exposure).count(),
            },
            "open": open.into_iter().map(card).collect::<Vec<_>>(),
            // A stopped Item's buttons read the same in both Postures, and
            // its card carries the restore-and-trust confirmation.
            "decided": self
                .decided()
                .map(|finding| card_in(finding, Posture::Simple))
                .collect::<Vec<_>>(),
        })
    }
}

/// Why the action buttons are disabled while a Scan runs. Placeholder.
pub const ACTIONS_WAIT: &str =
    "Checking now. Actions wait until the check has finished, then they can be used again.";

/// True for the kinds a Quarantine neutralises in place and that are never
/// quarantined automatically: Repository Metadata and env files (spec
/// section 5.2). Read off the eligibility table, not listed here.
pub fn neutralised_in_place(kind: Kind) -> bool {
    eligibility(kind).primitives == [Primitive::NeutraliseInPlace]
}

/// The buttons one Finding offers, labelled for the Simple Posture; the
/// frame renders each pane's cards in the Posture in force
/// ([`crate::actions::card_in`]).
pub fn actions(finding: &RecordedFinding) -> Vec<Action> {
    offered(finding, Posture::Simple)
}

/// The name a person knows an Item by: the last part of its locator.
pub fn name_of(item_id: &str) -> &str {
    let locator = item_id.rsplit(['/', '#']).next().unwrap_or(item_id);
    if locator.is_empty() { item_id } else { locator }
}

/// Whether the Rule behind a Finding may act by itself yet, as the command
/// line interface says it.
pub fn probation(status: RuleStatus) -> &'static str {
    match status {
        RuleStatus::Probation => "on probation",
        RuleStatus::Stable => "stable",
        RuleStatus::Retired => "retired",
    }
}

/// One Finding as the window renders it, with its actions.
pub fn card(finding: &RecordedFinding) -> Value {
    let mut value = plain_card(finding);
    value["actions"] = Value::Array(actions(finding).iter().map(Action::to_value).collect());
    value["note"] = Value::from(note(finding));
    value["trustConfirm"] = trust_confirmation(finding);
    value["simple"] = crate::wording::simple(finding).to_value();
    value["technical"] = crate::wording::technical_value(finding);
    value
}

/// One Finding as the window renders it, without actions: what a Folder Scan
/// shows, since it recorded nothing to act on.
pub fn plain_card(finding: &RecordedFinding) -> Value {
    json!({
        "id": finding.id.as_str(),
        "itemId": finding.item_id.as_str(),
        "kind": finding.kind.to_string(),
        "name": name_of(finding.item_id.as_str()),
        "source": finding.source,
        "category": finding.category.as_str(),
        "severity": finding.severity.as_str(),
        "tier": finding.tier.to_string(),
        "probation": probation(finding.status),
        "state": finding.state.as_str(),
        "plain": finding.plain,
        "drift": finding.drift,
        "file": finding.file,
        "receiptId": finding.receipt_id,
        "fixedVersion": !finding.fixed_version.is_empty(),
        "actions": [],
        "note": "",
    })
}

/// The one fixed note a card carries, where one applies. Placeholder.
fn note(finding: &RecordedFinding) -> &'static str {
    if finding.item_id.in_scope("managed") {
        return "This is controlled by whoever administers this Mac, so AgentSweep only flags it.";
    }
    if neutralised_in_place(finding.kind) && finding.is_open() {
        return "AgentSweep never edits this by itself. One click switches off the single line, \
                and one more switches it back on.";
    }
    if !finding.fixed_version.is_empty() {
        return "A fixed version is available.";
    }
    ""
}

/// One progress event on one line, as the command line interface prints it.
pub fn progress_line(done: usize, total: usize) -> String {
    match total {
        0 => "Looking for what to check.".to_string(),
        _ => format!("Checked {done} of {}.", count(total, "Item", "Items")),
    }
}

/// The last Scan, on one line, as the command line interface prints it.
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

/// A count with its noun, as the command line interface writes one.
pub fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        0 => format!("no {many}"),
        1 => format!("1 {one}"),
        _ => format!("{n} {many}"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use agentsweep_core::envelope::Timestamp;
    use agentsweep_core::finding::{FindingId, Severity, Tier};
    use agentsweep_core::item::ItemId;
    use agentsweep_core::scan_pass::ScanKind;
    use agentsweep_core::state::Trigger;

    fn moment(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a readable moment")
    }

    /// One recorded Finding of a given source on a given Item.
    pub(crate) fn recorded(
        item: &str,
        kind: Kind,
        source: &str,
        category: Category,
        state: FindingState,
    ) -> RecordedFinding {
        let rule_id = source
            .strip_prefix("rule ")
            .and_then(|id| id.parse().ok())
            .unwrap_or(0);
        RecordedFinding {
            id: FindingId::from_recorded(&format!("{item}|{}|abc", source.replace(' ', "/"))),
            item_id: ItemId::from_recorded(item),
            kind,
            source: source.to_string(),
            rule_id,
            category,
            severity: Severity::High,
            tier: match source {
                s if s.starts_with("score") => Tier::Heuristics,
                _ => Tier::Rules,
            },
            status: RuleStatus::Probation,
            state,
            content_hash: match source.starts_with("problem") {
                true => String::new(),
                false => "abc".to_string(),
            },
            title: String::new(),
            plain: format!("What {source} saw."),
            file: String::new(),
            drift: String::new(),
            receipt_id: match state {
                FindingState::Stopped => "q-0123456789abcdef0123456789abcdef".to_string(),
                _ => String::new(),
            },
            fixed_version: String::new(),
            switched: false,
            facts: Default::default(),
            first_seen: moment("2026-09-24T08:00:00.000Z"),
            notified_at: None,
        }
    }

    const SKILL: &str = "claude-code/user/skill/~/.claude/skills/setup";
    const MCP: &str = "claude-code/user/mcp-server/~/.claude.json#tracker";
    const SETTING: &str = "claude-code/user/settings-entry/~/.claude/settings.json#sandbox";
    const GIT: &str = "workspace/project:/src/demo/repository-metadata/.git/config#core.hooksPath";
    const ENV: &str = "workspace/project:/src/demo/env-file/.env#ANTHROPIC_BASE_URL";

    fn every_source() -> Vec<RecordedFinding> {
        vec![
            recorded(
                SKILL,
                Kind::Skill,
                "rule 0001",
                Category::Threat,
                FindingState::Open,
            ),
            recorded(
                SKILL,
                Kind::Skill,
                "score 7",
                Category::Threat,
                FindingState::Open,
            ),
            recorded(
                MCP,
                Kind::McpServer,
                "drift",
                Category::Threat,
                FindingState::Open,
            ),
            recorded(
                SETTING,
                Kind::SettingsEntry,
                "problem unreadable",
                Category::Exposure,
                FindingState::Open,
            ),
            recorded(
                MCP,
                Kind::McpServer,
                "keeps coming back",
                Category::Threat,
                FindingState::Open,
            ),
        ]
    }

    pub(crate) fn status_of(findings: Vec<RecordedFinding>) -> Status {
        Status {
            health: Health {
                open_threats: findings
                    .iter()
                    .filter(|f| f.is_open() && f.category == Category::Threat)
                    .count(),
                open_exposures: findings
                    .iter()
                    .filter(|f| f.is_open() && f.category == Category::Exposure)
                    .count(),
                ..Health::running()
            },
            scan: None,
            findings,
            activity: Vec::new(),
            overview: Default::default(),
        }
    }

    /// Every open Finding of the status is in the window with its id and
    /// state; what was decided is listed apart; a gone one is not listed.
    #[test]
    fn the_list_is_the_status_with_the_same_ids_and_states() {
        let mut all = every_source();
        all.push(recorded(
            SKILL,
            Kind::Skill,
            "rule 0004",
            Category::Threat,
            FindingState::Stopped,
        ));
        all.push(recorded(
            MCP,
            Kind::McpServer,
            "rule 0002",
            Category::Threat,
            FindingState::Trusted,
        ));
        all.push(recorded(
            MCP,
            Kind::McpServer,
            "rule 0003",
            Category::Threat,
            FindingState::Gone,
        ));
        let status = status_of(all.clone());
        let mut list = Findings::new();
        list.load(&status);
        let view = list.to_value();

        let open_ids: Vec<&str> = view["open"]
            .as_array()
            .expect("open")
            .iter()
            .map(|card| card["id"].as_str().expect("an id"))
            .collect();
        let expected: Vec<&str> = status.open().map(|f| f.id.as_str()).collect();
        assert_eq!(open_ids, expected);
        for card in view["open"].as_array().expect("open") {
            assert_eq!(card["state"], "open");
        }
        let decided: Vec<(&str, &str)> = view["decided"]
            .as_array()
            .expect("decided")
            .iter()
            .map(|card| {
                (
                    card["id"].as_str().expect("an id"),
                    card["state"].as_str().expect("a state"),
                )
            })
            .collect();
        assert_eq!(
            decided,
            vec![
                (all[5].id.as_str(), "stopped"),
                (all[6].id.as_str(), "trusted")
            ]
        );
        assert_eq!(view["counts"]["threats"], 4);
        assert_eq!(view["counts"]["exposures"], 1);
        let first = &view["open"][0];
        assert_eq!(first["kind"], "Skill");
        assert_eq!(first["name"], "setup");
        assert_eq!(first["severity"], "high");
        assert_eq!(first["tier"], "T1");
        assert_eq!(first["probation"], "on probation");
        assert_eq!(first["plain"], "What rule 0001 saw.");
    }

    /// The stream moves a Finding at once; whatever the event does not carry
    /// is fetched again from the status.
    #[test]
    fn a_finding_changed_on_the_stream_moves_at_once() {
        let all = every_source();
        let mut list = Findings::new();
        list.load(&status_of(all.clone()));

        let trusted = StateEvent::FindingChanged {
            id: all[0].id.clone(),
            state: "trusted".to_string(),
            finding: None,
        };
        assert_eq!(list.apply(&trusted), Follow::Render);
        assert_eq!(
            list.get(all[0].id.as_str()).expect("listed").state,
            FindingState::Trusted
        );
        assert_eq!(list.apply(&trusted), Follow::Nothing, "nothing moved");

        let stopped = StateEvent::FindingChanged {
            id: all[1].id.clone(),
            state: "stopped".to_string(),
            finding: None,
        };
        assert_eq!(list.apply(&stopped), Follow::Refresh, "the Receipt id");
        assert_eq!(
            list.get(all[1].id.as_str()).expect("listed").state,
            FindingState::Stopped
        );

        let gone = StateEvent::FindingChanged {
            id: all[2].id.clone(),
            state: "gone".to_string(),
            finding: None,
        };
        assert_eq!(list.apply(&gone), Follow::Render);
        assert!(list.get(all[2].id.as_str()).is_none());

        let unknown = StateEvent::FindingChanged {
            id: FindingId::from_recorded("claude-code/user/skill/new|rule/0001|def"),
            state: "open".to_string(),
            finding: None,
        };
        assert_eq!(list.apply(&unknown), Follow::Refresh);
    }

    /// A Scan is followed from start to end, and its end fetches the list.
    #[test]
    fn a_scan_is_followed_from_the_stream() {
        let mut list = Findings::new();
        list.load(&status_of(Vec::new()));
        let started = StateEvent::ScanStarted {
            trigger: Trigger::ScanNow,
            at: moment("2026-09-25T08:00:00.000Z"),
        };
        assert_eq!(list.apply(&started), Follow::Render);
        assert!(list.scan().running);
        assert_eq!(list.scan().line, "Looking for what to check.");
        list.apply(&StateEvent::ScanProgress { done: 3, total: 17 });
        assert_eq!(list.scan().line, "Checked 3 of 17 Items.");
        let summary = ScanSummary {
            kind: ScanKind::Full,
            trigger: Trigger::ScanNow,
            started_at: moment("2026-09-25T08:00:00.000Z"),
            duration_ms: 900,
            items: 17,
            threats: 1,
            exposures: 0,
            clear: 16,
            ambiguous: 0,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        };
        let finished = StateEvent::ScanFinished {
            summary: Box::new(summary),
        };
        assert_eq!(list.apply(&finished), Follow::Refresh);
        assert!(!list.scan().running);
        assert!(
            list.scan().line.starts_with("Last full Scan (scan-now)"),
            "{}",
            list.scan().line
        );
        assert_eq!(
            list.apply(&StateEvent::Activity {
                line: "Rule Pack 2 accepted.".to_string(),
                sequence: Some(3),
            }),
            Follow::Nothing
        );
    }

    /// A Health whose count of open Findings the list does not match, the
    /// first Health of a new connection included, asks for the status; a
    /// Health of Protection off empties the list.
    #[test]
    fn the_health_on_the_stream_keeps_the_list_honest() {
        let mut list = Findings::new();
        let health = Health {
            open_threats: 1,
            ..Health::running()
        };
        let changed = StateEvent::HealthChanged {
            health: Box::new(health.clone()),
        };
        assert_eq!(list.apply(&changed), Follow::Refresh, "never loaded");
        list.load(&status_of(vec![every_source().remove(0)]));
        assert_eq!(list.apply(&changed), Follow::Nothing, "in step");

        let off = StateEvent::HealthChanged {
            health: Box::new(Health::unreachable("the daemon stopped answering")),
        };
        assert_eq!(list.apply(&off), Follow::Render);
        assert_eq!(list.open().count(), 0);
        assert_eq!(list.to_value()["off"], "the daemon stopped answering");
        assert_eq!(list.apply(&changed), Follow::Refresh, "back on");
    }

    /// While Health says a Scan runs the window disables the actions and says
    /// why; the subscribe stream enables them again, whether the end of the
    /// Scan or the Health after it arrives first.
    fn summary() -> ScanSummary {
        ScanSummary {
            kind: ScanKind::Full,
            trigger: Trigger::ScanNow,
            started_at: moment("2026-09-25T08:00:00.000Z"),
            duration_ms: 900,
            items: 17,
            threats: 1,
            exposures: 0,
            clear: 16,
            ambiguous: 0,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        }
    }

    #[test]
    fn the_actions_wait_while_a_scan_runs() {
        let mut list = Findings::new();
        list.load(&status_of(every_source()));
        assert_eq!(list.to_value()["actionsWait"], Value::Null);

        let open = list.open().count();
        let counted = |scanning: bool| {
            let mut status = status_of(every_source());
            status.health.scanning = scanning;
            assert_eq!(status.health.open_findings(), open);
            StateEvent::HealthChanged {
                health: Box::new(status.health),
            }
        };

        // Health says "checking now" before the Scan's own start arrives.
        assert_eq!(list.apply(&counted(true)), Follow::Render);
        assert_eq!(list.to_value()["actionsWait"], ACTIONS_WAIT);
        assert_eq!(list.to_value()["scan"]["running"], true);
        assert_eq!(list.apply(&counted(true)), Follow::Nothing);
        assert_eq!(
            list.apply(&StateEvent::ScanProgress { done: 1, total: 4 }),
            Follow::Render
        );
        assert_eq!(list.to_value()["actionsWait"], ACTIONS_WAIT);

        // The Scan finished, and Health still counts the queue busy: the
        // actions keep waiting until Health lets go.
        assert_eq!(
            list.apply(&StateEvent::ScanFinished {
                summary: Box::new(summary()),
            }),
            Follow::Refresh
        );
        assert_eq!(list.apply(&counted(true)), Follow::Render);
        assert_eq!(list.to_value()["actionsWait"], ACTIONS_WAIT);
        assert!(
            list.scan().line.starts_with("Last full Scan"),
            "the line keeps the finished Scan: {}",
            list.scan().line
        );
        assert_eq!(list.apply(&counted(false)), Follow::Render);
        assert_eq!(list.to_value()["actionsWait"], Value::Null);

        // A Scan the stream announces itself disables them the same way.
        assert_eq!(
            list.apply(&StateEvent::ScanStarted {
                trigger: Trigger::Watcher,
                at: moment("2026-09-24T09:00:00.000Z"),
            }),
            Follow::Render
        );
        assert_eq!(list.to_value()["actionsWait"], ACTIONS_WAIT);
        list.apply(&StateEvent::ScanFinished {
            summary: Box::new(summary()),
        });
        assert_eq!(list.apply(&counted(false)), Follow::Nothing);
        assert_eq!(list.to_value()["actionsWait"], Value::Null);

        // With Protection off nothing is offered, so nothing waits either.
        list.apply(&counted(true));
        list.off("the daemon stopped answering");
        assert_eq!(list.to_value()["actionsWait"], Value::Null);
    }

    /// The fixed note of a never-auto kind and of a Managed Item.
    #[test]
    fn a_never_auto_kind_and_a_managed_item_carry_their_note() {
        for (item, kind) in [(GIT, Kind::RepositoryMetadata), (ENV, Kind::EnvFile)] {
            assert!(neutralised_in_place(kind));
            let open = recorded(
                item,
                kind,
                "rule 0007",
                Category::Threat,
                FindingState::Open,
            );
            assert!(!note(&open).is_empty());
        }
        assert!(!neutralised_in_place(Kind::Skill));
        let mut managed = recorded(
            "claude-code/managed/settings-entry/x#y",
            Kind::SettingsEntry,
            "rule 0001",
            Category::Threat,
            FindingState::Open,
        );
        managed.item_id = ItemId::from_recorded("claude-code/managed/settings-entry/x#y");
        assert!(note(&managed).contains("administers"));
    }

    /// The list's own lines keep the house style: no em-dashes.
    #[test]
    fn no_string_carries_an_em_dash() {
        let mut list = Findings::new();
        let mut all = every_source();
        all.push(recorded(
            ENV,
            Kind::EnvFile,
            "rule 0007",
            Category::Threat,
            FindingState::Open,
        ));
        list.load(&status_of(all.clone()));
        let mut text = list.to_value().to_string();
        for finding in &all {
            text.push_str(&trust_confirmation(finding).to_string());
        }
        assert!(!text.contains('\u{2014}'));
    }
}
