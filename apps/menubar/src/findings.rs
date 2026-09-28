//! What the Findings window shows: every Finding the daemon's `status`
//! carries, split into the open ones that ask something of the user and the
//! ones already stopped or decided, each with exactly the actions the daemon
//! allows on it ([`offers`]); and the Scan in hand, followed from the
//! subscribe stream.
//!
//! The list is the daemon's, never worked out here. It is loaded from a
//! status answer and then kept current from the state events: a Finding that
//! changed moves at once, and whatever the event does not carry (a Receipt id,
//! a Finding a Scan newly raised) is fetched again from the status, which
//! [`Follow::Refresh`] asks the caller to do. The user never refreshes by hand.
//!
//! Wording here is placeholder, taken from the command line interface where
//! it has a sentence and from the action vocabulary of spec section 8.5
//! otherwise. It commits to nothing about the Postures of spec section 8.

use agentsweep_core::adapter::{Primitive, eligibility};
use agentsweep_core::finding::{Category, FindingState, RuleStatus};
use agentsweep_core::health::Health;
use agentsweep_core::item::Kind;
use agentsweep_core::state::{RecordedFinding, ScanSummary};
use agentsweep_ipc::protocol::{Offer, Sessions, StateEvent, Status, offers};
use serde_json::{Value, json};

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
                };
                Follow::Render
            }
            StateEvent::ScanProgress { done, total } => {
                self.scan = ScanLine {
                    running: true,
                    line: progress_line(*done, *total),
                };
                Follow::Render
            }
            // A Scan raises and settles Findings as it ends; the status says
            // which.
            StateEvent::ScanFinished { summary } => {
                self.scan = ScanLine {
                    running: false,
                    line: scan_line(summary),
                };
                Follow::Refresh
            }
            StateEvent::FindingChanged { id, state } => {
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
            StateEvent::Activity { .. } => Follow::Nothing,
        }
    }

    /// A Health on the stream: Protection back on, or a count of open
    /// Findings the list does not match, asks for the status again.
    fn health(&mut self, health: &Health) -> Follow {
        if health.protection.is_off() {
            return self.off(health.protection.reason());
        }
        let back = self.off.take().is_some();
        let open = self.findings.iter().filter(|f| f.is_open()).count();
        match back || !self.loaded || open != health.open_findings {
            true => Follow::Refresh,
            // The Scan's own progress and end come as events of their own.
            false => Follow::Nothing,
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
            "counts": {
                "threats": open.iter().filter(|f| f.category == Category::Threat).count(),
                "exposures": open.iter().filter(|f| f.category == Category::Exposure).count(),
            },
            "open": open.into_iter().map(card).collect::<Vec<_>>(),
            "decided": self.decided().map(card).collect::<Vec<_>>(),
        })
    }
}

/// One action a card offers: the command the window invokes, its label, the
/// id it addresses, and the confirmation it asks first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    /// The Tauri command, which is the request of the same name.
    pub command: &'static str,
    /// What the button says. Placeholder wording.
    pub label: String,
    /// The Finding id the request addresses.
    pub target: String,
    /// What a Restore does when something else stands at the original place:
    /// `refuse` first, `replace` or `beside` once the user chose.
    pub conflict: Option<&'static str>,
    /// The confirmation asked before the request goes out, if any:
    /// `quarantine` (which states whether Agent sessions appear to be
    /// running) or `trust` (which explains hash-bound Trust).
    pub confirm: Option<&'static str>,
}

impl Action {
    fn to_value(&self) -> Value {
        json!({
            "command": self.command,
            "label": self.label,
            "target": self.target,
            "conflict": self.conflict,
            "confirm": self.confirm,
        })
    }
}

/// True for the kinds a Quarantine neutralises in place and that are never
/// quarantined automatically: Repository Metadata and env files (spec
/// section 5.2). Read off the eligibility table, not listed here.
pub fn neutralised_in_place(kind: Kind) -> bool {
    eligibility(kind).primitives == [Primitive::NeutraliseInPlace]
}

/// The actions the daemon allows on one Finding, labelled for the window.
///
/// For the never-auto kinds a manual Quarantine is the NeutraliseInPlace
/// primitive and its Restore switches the line back on, so the pair is the
/// neutralise-in-place toggle of spec section 8.5.
pub fn actions(finding: &RecordedFinding) -> Vec<Action> {
    let toggle = neutralised_in_place(finding.kind);
    let target = finding.id.as_str().to_string();
    offers(finding)
        .into_iter()
        .map(|offer| {
            let (command, label, confirm, conflict) = match offer {
                Offer::Quarantine => (
                    "quarantine",
                    match (toggle, finding.source.as_str()) {
                        (true, _) => "Switch this line off",
                        (false, "drift") => "No, remove it",
                        (false, _) => "Quarantine",
                    },
                    Some("quarantine"),
                    None,
                ),
                Offer::Restore => (
                    "restore",
                    match toggle {
                        true => "Switch the line back on",
                        false => "Restore",
                    },
                    None,
                    Some("refuse"),
                ),
                Offer::ReEnable => ("re_enable", "Re-enable", None, None),
                Offer::Trust => (
                    "trust",
                    match finding.category {
                        Category::Threat => "Trust this version",
                        Category::Exposure => "Keep it as it is",
                    },
                    Some("trust"),
                    None,
                ),
                Offer::Acknowledge => ("acknowledge", "Yes, that was me", None, None),
                Offer::Fix => ("fix", "Take this setting out", None, None),
            };
            Action {
                command,
                label: label.to_string(),
                target: target.clone(),
                conflict,
                confirm,
            }
        })
        .collect()
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

/// What the Quarantine confirmation says: what is taken out, whether Agent
/// sessions appear to be running (asked of the daemon just before), and for a
/// project's Item that git will show the change.
pub fn quarantine_confirmation(finding: &RecordedFinding, sessions: &Sessions) -> Value {
    let what = match neutralised_in_place(finding.kind) {
        true => format!(
            "Switch off the line in {} '{}'? AgentSweep comments it out; switching it back on \
             undoes that.",
            finding.kind,
            name_of(finding.item_id.as_str())
        ),
        false => format!(
            "Quarantine {} '{}'? AgentSweep takes it out of where the Agent loads it; Restore \
             puts it back.",
            finding.kind,
            name_of(finding.item_id.as_str())
        ),
    };
    json!({
        "question": what,
        "sessions": sessions.sentence(),
        "sessionsRunning": sessions.running.as_str(),
        "project": match finding.item_id.is_project() {
            true => "This file belongs to a project, so git will show the change. Restore undoes it.",
            false => "",
        },
    })
}

/// What the Trust confirmation says: Trust is bound to this exact content.
pub fn trust_confirmation(finding: &RecordedFinding) -> Value {
    json!({
        "question": match finding.category {
            Category::Threat => format!(
                "Trust this version of {} '{}'?",
                finding.kind,
                name_of(finding.item_id.as_str())
            ),
            Category::Exposure => format!(
                "Keep {} '{}' as it is?",
                finding.kind,
                name_of(finding.item_id.as_str())
            ),
        },
        "sessions": "",
        "sessionsRunning": "",
        "project": "Trust is bound to this exact content. Any change to it is checked afresh.",
    })
}

/// One progress event on one line, as the command line interface prints it.
pub fn progress_line(done: usize, total: usize) -> String {
    match total {
        0 => "Finding the Items to check.".to_string(),
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
    use agentsweep_core::eventlog::SessionsRunning;
    use agentsweep_core::finding::{FindingId, Severity, Tier};
    use agentsweep_core::item::ItemId;
    use agentsweep_core::scan_pass::ScanKind;
    use agentsweep_core::state::Trigger;
    use agentsweep_ipc::protocol::AgentSessions;

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

    fn status_of(findings: Vec<RecordedFinding>) -> Status {
        Status {
            health: Health {
                open_findings: findings.iter().filter(|f| f.is_open()).count(),
                ..Health::running()
            },
            scan: None,
            findings,
            activity: Vec::new(),
        }
    }

    fn commands(finding: &RecordedFinding) -> Vec<(&'static str, String)> {
        actions(finding)
            .into_iter()
            .map(|action| (action.command, action.label))
            .collect()
    }

    fn pairs(list: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        list.iter()
            .map(|(command, label)| (*command, label.to_string()))
            .collect()
    }

    /// Every source a Finding can have gets exactly the actions the daemon
    /// allows on it, labelled from the vocabulary of spec section 8.5.
    #[test]
    fn each_source_offers_what_the_daemon_allows() {
        let all = every_source();
        assert_eq!(
            commands(&all[0]),
            pairs(&[
                ("quarantine", "Quarantine"),
                ("trust", "Trust this version")
            ])
        );
        assert_eq!(
            commands(&all[1]),
            pairs(&[
                ("quarantine", "Quarantine"),
                ("trust", "Trust this version")
            ])
        );
        assert_eq!(
            commands(&all[2]),
            pairs(&[
                ("quarantine", "No, remove it"),
                ("trust", "Trust this version"),
                ("acknowledge", "Yes, that was me"),
            ])
        );
        assert!(commands(&all[3]).is_empty(), "a Problem offers nothing");
        assert_eq!(
            commands(&all[4]),
            pairs(&[
                ("quarantine", "Quarantine"),
                ("trust", "Trust this version")
            ])
        );
        // Every action addresses the Finding it sits on, and a Quarantine and
        // a Trust ask first.
        for action in actions(&all[0]) {
            assert_eq!(action.target, all[0].id.as_str());
            assert!(action.confirm.is_some(), "{action:?}");
        }
    }

    /// The fix of Exposures 0018 and 0019 and the Exposure wording of Trust.
    #[test]
    fn an_exposure_is_kept_or_fixed_and_never_quarantined() {
        let fixable = recorded(
            SETTING,
            Kind::SettingsEntry,
            "rule 0019",
            Category::Exposure,
            FindingState::Open,
        );
        assert_eq!(
            commands(&fixable),
            pairs(&[
                ("trust", "Keep it as it is"),
                ("fix", "Take this setting out")
            ])
        );
        let other = recorded(
            SETTING,
            Kind::SettingsEntry,
            "rule 0010",
            Category::Exposure,
            FindingState::Open,
        );
        assert_eq!(commands(&other), pairs(&[("trust", "Keep it as it is")]));
    }

    /// Repository Metadata and env files are neutralised in place: the
    /// Quarantine switches the line off and the Restore switches it back on.
    #[test]
    fn a_never_auto_kind_is_a_toggle_for_its_line() {
        for (item, kind) in [(GIT, Kind::RepositoryMetadata), (ENV, Kind::EnvFile)] {
            assert!(neutralised_in_place(kind));
            let open = recorded(
                item,
                kind,
                "rule 0007",
                Category::Threat,
                FindingState::Open,
            );
            assert_eq!(
                commands(&open),
                pairs(&[
                    ("quarantine", "Switch this line off"),
                    ("trust", "Trust this version")
                ])
            );
            assert!(!note(&open).is_empty());
            let off = recorded(
                item,
                kind,
                "rule 0007",
                Category::Threat,
                FindingState::Stopped,
            );
            assert_eq!(
                commands(&off),
                pairs(&[("restore", "Switch the line back on")])
            );
        }
        assert!(!neutralised_in_place(Kind::Skill));
    }

    /// Stopped offers Restore (and Re-enable once a fixed version is there);
    /// trusted, acknowledged and gone offer nothing.
    #[test]
    fn each_state_offers_what_the_daemon_allows() {
        let mut stopped = recorded(
            SKILL,
            Kind::Plugin,
            "rule 0001",
            Category::Threat,
            FindingState::Stopped,
        );
        assert_eq!(commands(&stopped), pairs(&[("restore", "Restore")]));
        assert_eq!(actions(&stopped)[0].conflict, Some("refuse"));
        stopped.fixed_version = "def".to_string();
        assert_eq!(
            commands(&stopped),
            pairs(&[("restore", "Restore"), ("re_enable", "Re-enable")])
        );
        for state in [
            FindingState::Trusted,
            FindingState::Acknowledged,
            FindingState::Gone,
        ] {
            let decided = recorded(SKILL, Kind::Skill, "rule 0001", Category::Threat, state);
            assert!(commands(&decided).is_empty(), "{state}");
        }
        let mut managed = recorded(
            "claude-code/managed/settings-entry/x#y",
            Kind::SettingsEntry,
            "rule 0001",
            Category::Threat,
            FindingState::Open,
        );
        managed.item_id = ItemId::from_recorded("claude-code/managed/settings-entry/x#y");
        assert_eq!(
            commands(&managed),
            pairs(&[("trust", "Trust this version")])
        );
        assert!(note(&managed).contains("administers"));
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
        };
        assert_eq!(list.apply(&stopped), Follow::Refresh, "the Receipt id");
        assert_eq!(
            list.get(all[1].id.as_str()).expect("listed").state,
            FindingState::Stopped
        );

        let gone = StateEvent::FindingChanged {
            id: all[2].id.clone(),
            state: "gone".to_string(),
        };
        assert_eq!(list.apply(&gone), Follow::Render);
        assert!(list.get(all[2].id.as_str()).is_none());

        let unknown = StateEvent::FindingChanged {
            id: FindingId::from_recorded("claude-code/user/skill/new|rule/0001|def"),
            state: "open".to_string(),
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
        assert_eq!(list.scan().line, "Finding the Items to check.");
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
            open_findings: 1,
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

    /// The Quarantine confirmation says whether Agent sessions appear to be
    /// running, in the words every action result uses, and that git will show
    /// the change for a project's Item.
    #[test]
    fn the_quarantine_confirmation_states_the_sessions() {
        let finding = recorded(
            SKILL,
            Kind::Skill,
            "rule 0001",
            Category::Threat,
            FindingState::Open,
        );
        let running = Sessions::of(vec![AgentSessions {
            agent: "claude-code".to_string(),
            running: SessionsRunning::Yes,
            live: 2,
        }]);
        let asked = quarantine_confirmation(&finding, &running);
        assert_eq!(asked["sessions"], running.sentence());
        assert!(
            asked["sessions"]
                .as_str()
                .expect("a sentence")
                .starts_with("Agent sessions appear to be running: claude-code (2)")
        );
        assert_eq!(asked["sessionsRunning"], "yes");
        assert_eq!(asked["project"], "");
        assert!(
            asked["question"]
                .as_str()
                .expect("a question")
                .contains("'setup'")
        );

        let nobody = Sessions::of(vec![AgentSessions {
            agent: "claude-code".to_string(),
            running: SessionsRunning::No,
            live: 0,
        }]);
        let project = recorded(
            ENV,
            Kind::EnvFile,
            "rule 0007",
            Category::Threat,
            FindingState::Open,
        );
        let asked = quarantine_confirmation(&project, &nobody);
        assert!(
            asked["sessions"]
                .as_str()
                .expect("a sentence")
                .starts_with("No Agent session")
        );
        assert!(
            asked["question"]
                .as_str()
                .expect("a question")
                .starts_with("Switch off the line")
        );
        assert!(
            asked["project"]
                .as_str()
                .expect("a line")
                .contains("git will show")
        );

        let unknown = quarantine_confirmation(&finding, &Sessions::unknown());
        assert!(
            unknown["sessions"]
                .as_str()
                .expect("a sentence")
                .contains("could not tell")
        );
    }

    /// Placeholder wording still keeps the house style: no em-dashes.
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
            text.push_str(&quarantine_confirmation(finding, &Sessions::unknown()).to_string());
            text.push_str(&trust_confirmation(finding).to_string());
        }
        assert!(!text.contains('\u{2014}'));
    }
}
