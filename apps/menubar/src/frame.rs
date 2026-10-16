//! The window's frame (spec section 8.1): the sidebar with its six entries
//! and their counts, the two Finding panes the open Findings land in, and the
//! Posture the whole window is shown in.
//!
//! The Posture is the user's setting, read from the daemon's `settings`
//! answer and followed from the `settings-changed` state event, so an open
//! window re-labels itself the moment it moves. It changes wording and
//! density only, never what is listed (spec section 8.2): both Postures give
//! the same entries with the same counts, and only their names differ.
//!
//! Counts are kept from the list of [`Findings`], which is the daemon's
//! status followed from the stream; nothing is counted twice or worked out
//! apart from it. The Overview pane is rendered from the Health, the Agent
//! records and the last Scan's summary the frame keeps beside the list, from
//! the same status and the same stream ([`crate::overview`]). Which pane is
//! selected is the window's own business and is not kept here.

use std::collections::BTreeSet;

use agentsweep_core::finding::{Category, FindingState};
use agentsweep_core::health::Health;
use agentsweep_core::overview::Overview;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::ScanSummary;
use agentsweep_ipc::protocol::{SettingsState, StateEvent, Status};
use serde_json::{Value, json};

use crate::actions::card_in;
use crate::activity::Activity;
use crate::developer::{ambiguous_card, offers_reveal};
use crate::findings::{Findings, Follow};
use crate::overview::{self, OverviewView};
use crate::popover::View;
use crate::settings_pane;

/// One entry of the sidebar, in the order spec section 8.1 lists them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pane {
    /// The status sentence, the Agents and the last checks.
    Overview,
    /// The open Threat Findings.
    Threats,
    /// The open Exposure Findings.
    Exposures,
    /// The Items in quarantine, with the trusted ones at its foot.
    Quarantine,
    /// The Event Log, where every other decision is.
    Activity,
    /// The user's choices.
    Settings,
}

impl Pane {
    /// Every entry, in sidebar order.
    pub const ALL: [Pane; 6] = [
        Pane::Overview,
        Pane::Threats,
        Pane::Exposures,
        Pane::Quarantine,
        Pane::Activity,
        Pane::Settings,
    ];

    /// The name the window addresses the pane by.
    pub fn id(self) -> &'static str {
        match self {
            Pane::Overview => "overview",
            Pane::Threats => "threats",
            Pane::Exposures => "exposures",
            Pane::Quarantine => "quarantine",
            Pane::Activity => "activity",
            Pane::Settings => "settings",
        }
    }

    /// What the sidebar calls the pane in a Posture: the plain names in
    /// Simple, the glossary terms in Developer (spec section 8.1).
    pub fn label(self, posture: Posture) -> &'static str {
        match (self, posture) {
            (Pane::Overview, _) => "Overview",
            (Pane::Threats, Posture::Simple) => "Needs your decision",
            (Pane::Threats, Posture::Developer) => "Threat Findings",
            (Pane::Exposures, Posture::Simple) => "Worth fixing",
            (Pane::Exposures, Posture::Developer) => "Exposure Findings",
            (Pane::Quarantine, _) => "Quarantine",
            (Pane::Activity, Posture::Simple) => "Activity",
            (Pane::Activity, Posture::Developer) => "Event Log",
            (Pane::Settings, _) => "Settings",
        }
    }
}

/// One sidebar entry as the window renders it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Which pane it opens.
    pub pane: Pane,
    /// Its name in the Posture in force.
    pub label: &'static str,
    /// Its count, absent for an entry that counts nothing.
    pub count: Option<usize>,
}

/// The six entries in order, named for `posture`, counted from `findings`:
/// the open Threat Findings, the open Exposure Findings and the Items in
/// quarantine. Overview, Activity and Settings count nothing.
pub fn sidebar(findings: &Findings, posture: Posture) -> Vec<Entry> {
    let open = |category: Category| findings.open().filter(|f| f.category == category).count();
    let quarantined: BTreeSet<&str> = findings
        .all()
        .iter()
        .filter(|f| f.state == FindingState::Stopped)
        .map(|f| f.item_id.as_str())
        .collect();
    Pane::ALL
        .into_iter()
        .map(|pane| Entry {
            pane,
            label: pane.label(posture),
            count: match pane {
                Pane::Threats => Some(open(Category::Threat)),
                Pane::Exposures => Some(open(Category::Exposure)),
                Pane::Quarantine => Some(quarantined.len()),
                Pane::Overview | Pane::Activity | Pane::Settings => None,
            },
        })
        .collect()
}

/// What the window holds: the list of Findings, what the Overview names
/// beside it, and the Posture it is shown in.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Frame {
    findings: Findings,
    posture: Posture,
    /// The Health as the daemon last said it. Before anything was asked it
    /// is Protection off, because silence is never an all-clear.
    health: Health,
    /// The Agents, the projects and the Ambiguous Items of the last status
    /// or `overview-changed` event.
    overview: Overview,
    /// The most recent Scan's summary.
    last_scan: Option<ScanSummary>,
    /// Every choice as the daemon last answered, for the Settings pane;
    /// absent until it answered.
    choices: Option<SettingsState>,
    /// Where the user's own rules folder is, for the Settings pane.
    rules_folder: Option<String>,
    /// The Activity lines of the last status, followed from the stream.
    activity: Activity,
}

/// A follow-up that at least sends the view again.
fn at_least_render(follow: Follow) -> Follow {
    match follow {
        Follow::Nothing => Follow::Render,
        other => other,
    }
}

impl Frame {
    /// A frame before anything was asked, in the default Posture.
    pub fn new() -> Frame {
        Frame::default()
    }

    /// The list of Findings.
    pub fn findings(&self) -> &Findings {
        &self.findings
    }

    /// The Posture the window is shown in.
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// Takes the list, the Health, the Agent records and the last Scan from
    /// a status answer.
    pub fn load(&mut self, status: &Status) {
        self.findings.load(status);
        self.health = status.health.clone();
        self.overview = status.overview.clone();
        self.last_scan = status.scan.clone();
        self.activity.load(status);
    }

    /// The Activity the Activity pane lists.
    pub fn activity(&self) -> &Activity {
        &self.activity
    }

    /// Takes every choice, the Posture among them, from a `settings` answer
    /// or a `settings-changed` event, and says whether the window needs to
    /// be sent again.
    pub fn settings(&mut self, settings: &SettingsState) -> Follow {
        match self.choices.as_ref() == Some(settings) {
            true => Follow::Nothing,
            false => {
                self.posture = settings.posture;
                self.choices = Some(settings.clone());
                Follow::Render
            }
        }
    }

    /// Names the user's own rules folder for the Settings pane.
    pub fn set_rules_folder(&mut self, folder: impl Into<String>) {
        self.rules_folder = Some(folder.into());
    }

    /// The Settings pane as it stands.
    pub fn settings_pane(&self) -> Value {
        settings_pane::view(
            self.choices.as_ref(),
            &self.health,
            self.posture,
            self.rules_folder.as_deref(),
        )
    }

    /// No daemon answers: see [`Findings::off`]. The Overview drops what it
    /// named with the list, so the pane says "Protection is off." and nothing
    /// else. The Posture stays as it was last read, since the window keeps
    /// being shown in it.
    pub fn off(&mut self, reason: &str) -> Follow {
        let was = self.clone();
        self.findings.off(reason);
        self.health = Health::unreachable(reason);
        self.overview = Overview::default();
        self.last_scan = None;
        self.activity.clear();
        match *self == was {
            true => Follow::Nothing,
            false => Follow::Render,
        }
    }

    /// Takes the popover's view from the link: one that says Protection is
    /// off empties the window too, which is how the window hears of a daemon
    /// that went away. Any other view changes nothing here; the stream says
    /// the rest.
    pub fn view(&mut self, view: &View) -> Follow {
        match view.protection_off {
            true => self.off(&view.detail),
            false => Follow::Nothing,
        }
    }

    /// Applies one state event: a moved choice may change the Posture, a
    /// Health or an `overview-changed` event moves the Overview, an
    /// `activity` event grows the Activity, and every other event goes to
    /// the list.
    pub fn apply(&mut self, event: &StateEvent) -> Follow {
        match event {
            StateEvent::SettingsChanged { settings } => self.settings(settings),
            StateEvent::HealthChanged { health } if health.protection.is_off() => {
                self.off(health.protection.reason())
            }
            StateEvent::HealthChanged { health } => {
                let follow = self.findings.apply(event);
                match self.health == **health {
                    true => follow,
                    false => {
                        self.health = (**health).clone();
                        at_least_render(follow)
                    }
                }
            }
            StateEvent::OverviewChanged { overview } => match self.overview == **overview {
                true => Follow::Nothing,
                false => {
                    self.overview = (**overview).clone();
                    Follow::Render
                }
            },
            StateEvent::ScanFinished { summary } => {
                self.last_scan = Some((**summary).clone());
                at_least_render(self.findings.apply(event))
            }
            StateEvent::Activity { .. } => self.activity.apply(event),
            other => self.findings.apply(other),
        }
    }

    /// The Overview pane as it stands.
    pub fn overview(&self) -> OverviewView {
        overview::view(
            &self.health,
            &self.overview,
            self.last_scan.as_ref(),
            self.findings.scan(),
            self.posture,
        )
    }

    /// The sidebar as it stands.
    pub fn sidebar(&self) -> Vec<Entry> {
        sidebar(&self.findings, self.posture)
    }

    /// The value the window receives: the list as before, the Posture, the
    /// sidebar, the Overview, and the open Findings split into the two
    /// Finding panes. The Developer Posture adds the Ambiguous Items and
    /// offers Reveal in Finder on the quarantined Items that have a payload;
    /// the Simple Posture carries no Ambiguous Item and no Ambiguous count
    /// anywhere (spec section 8.4), so the last Scan's line, which names
    /// the Ambiguous Band, is left out of it.
    pub fn to_value(&self) -> Value {
        let mut value = self.findings.to_value();
        match self.posture {
            Posture::Developer => {
                value["ambiguous"] =
                    Value::Array(self.overview.ambiguous.iter().map(ambiguous_card).collect());
                let decided: Vec<_> = self.findings.decided().collect();
                if let Some(cards) = value["decided"].as_array_mut() {
                    for (card, finding) in cards.iter_mut().zip(decided) {
                        card["reveal"] = Value::from(offers_reveal(finding, self.posture));
                    }
                }
            }
            Posture::Simple => {
                if !self.findings.scan().running {
                    value["scan"]["line"] = Value::from("");
                }
            }
        }
        value["overview"] = self.overview().to_value();
        value["activity"] = self.activity.view(self.posture);
        value["settings"] = self.settings_pane();
        let pane = |category: Category| -> Vec<Value> {
            self.findings
                .open()
                .filter(|f| f.category == category)
                .map(|finding| card_in(finding, self.posture))
                .collect()
        };
        value["posture"] = Value::from(self.posture.as_str());
        value["sidebar"] = Value::Array(
            self.sidebar()
                .into_iter()
                .map(|entry| {
                    json!({
                        "pane": entry.pane.id(),
                        "label": entry.label,
                        "count": entry.count,
                    })
                })
                .collect(),
        );
        value["panes"] = json!({
            "threats": pane(Category::Threat),
            "exposures": pane(Category::Exposure),
        });
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use agentsweep_core::envelope::Timestamp;
    use agentsweep_core::finding_facts::HeuristicLine;
    use agentsweep_core::item::ItemId;
    use agentsweep_core::item::Kind;
    use agentsweep_core::overview::{AgentRecord, AmbiguousItem};
    use agentsweep_core::scan_pass::ScanKind;
    use agentsweep_core::settings::{CloudCaps, JudgementEngine};
    use agentsweep_core::state::Trigger;
    use agentsweep_ipc::engine::EngineState;

    use crate::findings::tests::{recorded, status_of};
    use crate::overview::summary_line;
    use crate::popover::Off;

    const SKILL: &str = "claude-code/user/skill/~/.claude/skills/setup";
    const MCP: &str = "claude-code/user/mcp-server/~/.claude.json#tracker";
    const SETTING: &str = "claude-code/user/settings-entry/~/.claude/settings.json#sandbox";

    fn settings(posture: Posture) -> SettingsState {
        SettingsState {
            rule_feed: true,
            update_check: true,
            posture,
            config_dirs: BTreeMap::new(),
            engine: EngineState {
                engine: JudgementEngine::Off,
                ollama_address: "127.0.0.1:11434".to_string(),
                ollama_model: String::new(),
                claude_model: String::new(),
                claude_model_in_use: String::new(),
                caps: CloudCaps::default(),
                claude_key_ending: None,
                recorded: 0,
                ollama: None,
                apple: None,
                cloud_use: agentsweep_ipc::engine::CloudUse::default(),
            },
        }
    }

    /// Two open Threats on two Items, one open Exposure, and two stopped
    /// Findings on one Item, which is one Item in quarantine.
    fn status() -> Status {
        status_of(vec![
            recorded(
                SKILL,
                Kind::Skill,
                "rule 0001",
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
                "rule 0019",
                Category::Exposure,
                FindingState::Open,
            ),
            recorded(
                "claude-code/user/skill/~/.claude/skills/other",
                Kind::Skill,
                "rule 0002",
                Category::Threat,
                FindingState::Stopped,
            ),
            recorded(
                "claude-code/user/skill/~/.claude/skills/other",
                Kind::Skill,
                "rule 0004",
                Category::Threat,
                FindingState::Stopped,
            ),
            recorded(
                MCP,
                Kind::McpServer,
                "rule 0003",
                Category::Threat,
                FindingState::Trusted,
            ),
        ])
    }

    fn rows(entries: &[Entry]) -> Vec<(&'static str, &'static str, Option<usize>)> {
        entries
            .iter()
            .map(|entry| (entry.pane.id(), entry.label, entry.count))
            .collect()
    }

    #[test]
    fn the_sidebar_has_six_entries_in_order_with_their_counts() {
        let mut frame = Frame::new();
        frame.load(&status());
        assert_eq!(frame.posture(), Posture::Simple, "the default");
        assert_eq!(
            rows(&frame.sidebar()),
            vec![
                ("overview", "Overview", None),
                ("threats", "Needs your decision", Some(2)),
                ("exposures", "Worth fixing", Some(1)),
                ("quarantine", "Quarantine", Some(1)),
                ("activity", "Activity", None),
                ("settings", "Settings", None),
            ]
        );
    }

    #[test]
    fn the_developer_posture_renames_entries_to_the_glossary_terms() {
        let mut frame = Frame::new();
        frame.load(&status());
        assert_eq!(
            frame.settings(&settings(Posture::Developer)),
            Follow::Render
        );
        assert_eq!(
            rows(&frame.sidebar()),
            vec![
                ("overview", "Overview", None),
                ("threats", "Threat Findings", Some(2)),
                ("exposures", "Exposure Findings", Some(1)),
                ("quarantine", "Quarantine", Some(1)),
                ("activity", "Event Log", None),
                ("settings", "Settings", None),
            ]
        );
        // The same answer again moves nothing.
        assert_eq!(
            frame.settings(&settings(Posture::Developer)),
            Follow::Nothing
        );
    }

    /// Both Postures count the same: a Posture changes names, never what is
    /// listed. The buttons on a card follow the Posture (spec section 8.5),
    /// so the panes are compared by the Findings they hold.
    #[test]
    fn a_posture_changes_names_and_never_counts() {
        let mut frame = Frame::new();
        frame.load(&status());
        let counts = |frame: &Frame| -> Vec<Option<usize>> {
            frame.sidebar().iter().map(|entry| entry.count).collect()
        };
        let listed = |frame: &Frame| -> Vec<Vec<String>> {
            let panes = frame.to_value()["panes"].clone();
            ["threats", "exposures"]
                .iter()
                .map(|pane| {
                    panes[pane]
                        .as_array()
                        .expect("a pane")
                        .iter()
                        .map(|card| card["id"].as_str().expect("an id").to_string())
                        .collect()
                })
                .collect()
        };
        let simple = counts(&frame);
        let simple_panes = listed(&frame);
        frame.settings(&settings(Posture::Developer));
        assert_eq!(counts(&frame), simple);
        assert_eq!(listed(&frame), simple_panes);
    }

    /// The panes carry the buttons of the Posture in force: Trust on a Drift
    /// question sits behind the technical details in Simple only.
    #[test]
    fn the_panes_carry_the_buttons_of_the_posture() {
        let mut frame = Frame::new();
        frame.load(&status());
        let trust_on_drift = |frame: &Frame| -> Value {
            let value = frame.to_value();
            let drift = value["panes"]["threats"]
                .as_array()
                .expect("threats")
                .iter()
                .find(|card| card["source"] == "drift")
                .expect("the Drift question")
                .clone();
            drift["actions"]
                .as_array()
                .expect("actions")
                .iter()
                .find(|action| action["command"] == "trust")
                .expect("Trust")
                .clone()
        };
        assert_eq!(trust_on_drift(&frame)["technical"], true);
        frame.settings(&settings(Posture::Developer));
        assert_eq!(trust_on_drift(&frame)["technical"], false);
    }

    /// A Finding stopped on the stream leaves Needs your decision and its
    /// Item counts in Quarantine at once.
    #[test]
    fn a_count_follows_a_stream_event() {
        let status = status();
        let mut frame = Frame::new();
        frame.load(&status);
        let stopped = StateEvent::FindingChanged {
            id: status.findings[0].id.clone(),
            state: "stopped".to_string(),
            finding: None,
        };
        assert_ne!(frame.apply(&stopped), Follow::Nothing);
        let counts: Vec<Option<usize>> = frame.sidebar().iter().map(|e| e.count).collect();
        assert_eq!(counts, vec![None, Some(1), Some(1), Some(2), None, None]);

        let gone = StateEvent::FindingChanged {
            id: status.findings[2].id.clone(),
            state: "gone".to_string(),
            finding: None,
        };
        assert_eq!(frame.apply(&gone), Follow::Render);
        assert_eq!(frame.sidebar()[2].count, Some(0));
    }

    /// The `settings-changed` event re-labels the frame without a status.
    #[test]
    fn a_settings_changed_event_relabels_the_frame() {
        let mut frame = Frame::new();
        frame.load(&status());
        let moved = StateEvent::SettingsChanged {
            settings: Box::new(settings(Posture::Developer)),
        };
        assert_eq!(frame.apply(&moved), Follow::Render);
        assert_eq!(frame.to_value()["posture"], "developer");
        assert_eq!(frame.to_value()["sidebar"][1]["label"], "Threat Findings");
        assert_eq!(frame.apply(&moved), Follow::Nothing);
        let back = StateEvent::SettingsChanged {
            settings: Box::new(settings(Posture::Simple)),
        };
        assert_eq!(frame.apply(&back), Follow::Render);
        assert_eq!(
            frame.to_value()["sidebar"][1]["label"],
            "Needs your decision"
        );
    }

    /// The open Findings land in the two Finding panes by category, with the
    /// same ids and in the order the status gave them; nothing stopped or
    /// decided is in either.
    #[test]
    fn the_open_findings_land_in_the_two_finding_panes() {
        let status = status();
        let mut frame = Frame::new();
        frame.load(&status);
        let view = frame.to_value();
        let ids = |cards: &Value| -> Vec<String> {
            cards
                .as_array()
                .expect("cards")
                .iter()
                .map(|card| card["id"].as_str().expect("an id").to_string())
                .collect()
        };
        let of = |category: Category| -> Vec<String> {
            status
                .open()
                .filter(|f| f.category == category)
                .map(|f| f.id.to_string())
                .collect()
        };
        assert_eq!(ids(&view["panes"]["threats"]), of(Category::Threat));
        assert_eq!(ids(&view["panes"]["exposures"]), of(Category::Exposure));
        assert_eq!(ids(&view["panes"]["threats"]).len(), 2);
        // Each card keeps its actions.
        assert!(
            !view["panes"]["threats"][0]["actions"]
                .as_array()
                .expect("actions")
                .is_empty()
        );
    }

    /// Protection off empties the panes and keeps the Posture.
    #[test]
    fn protection_off_empties_the_panes_and_keeps_the_posture() {
        let mut frame = Frame::new();
        frame.load(&status());
        frame.settings(&settings(Posture::Developer));
        assert_eq!(frame.off("the daemon stopped answering"), Follow::Render);
        let view = frame.to_value();
        assert_eq!(view["posture"], "developer");
        assert_eq!(view["panes"]["threats"], json!([]));
        assert_eq!(view["sidebar"][1]["count"], 0);
    }

    fn claude_code() -> Overview {
        Overview {
            agents: vec![AgentRecord {
                agent: "claude-code".to_string(),
                display_name: "Claude Code".to_string(),
                installed: true,
                version: Some("2.1.3".to_string()),
                projects: 1,
                items: 7,
                ..AgentRecord::default()
            }],
            ..Overview::default()
        }
    }

    fn moment() -> Timestamp {
        Timestamp::parse("2026-10-15T08:00:00.000Z").expect("a moment")
    }

    fn finished() -> ScanSummary {
        ScanSummary {
            kind: ScanKind::Full,
            trigger: Trigger::ScanNow,
            started_at: moment(),
            duration_ms: 40,
            items: 7,
            threats: 2,
            exposures: 1,
            clear: 7,
            ambiguous: 0,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        }
    }

    /// The window carries the Overview; the Developer summary line shows only
    /// in the Developer Posture and the Agent lines in both.
    #[test]
    fn the_frame_carries_the_overview_in_each_posture() {
        let mut status = status();
        status.overview = claude_code();
        status.scan = Some(finished());
        let mut frame = Frame::new();
        frame.load(&status);
        let simple = frame.to_value()["overview"].clone();
        assert_eq!(simple["sentence"], status.health.headline());
        assert_eq!(
            simple["agents"][0]["line"],
            "Claude Code 2.1.3: 1 project, 7 things checked."
        );
        assert_eq!(simple["summary"], Value::Null);
        assert_eq!(simple["actions"], true);

        frame.settings(&settings(Posture::Developer));
        let developer = frame.to_value()["overview"].clone();
        assert_eq!(
            developer["agents"][0]["line"],
            "Claude Code 2.1.3: 1 project, 7 Items."
        );
        assert_eq!(developer["summary"], summary_line(&finished()));
    }

    /// The Agents, the progress and the last Scan follow the stream, and the
    /// sentence follows Health on it.
    #[test]
    fn the_overview_follows_the_stream() {
        let mut frame = Frame::new();
        frame.load(&status());
        frame.settings(&settings(Posture::Developer));
        assert!(frame.overview().agents.is_empty());

        let moved = StateEvent::OverviewChanged {
            overview: Box::new(claude_code()),
        };
        assert_eq!(frame.apply(&moved), Follow::Render);
        assert_eq!(frame.overview().agents.len(), 1);
        assert_eq!(frame.apply(&moved), Follow::Nothing);

        let started = StateEvent::ScanStarted {
            trigger: Trigger::ScanNow,
            at: moment(),
        };
        assert_eq!(frame.apply(&started), Follow::Render);
        let progress = StateEvent::ScanProgress { done: 3, total: 7 };
        assert_eq!(frame.apply(&progress), Follow::Render);
        let running = frame.overview();
        assert!(running.scanning);
        assert_eq!(running.progress, "Checked 3 of 7 Items.");

        let checking = Health {
            scanning: true,
            ..status().health
        };
        frame.apply(&StateEvent::HealthChanged {
            health: Box::new(checking),
        });
        assert_eq!(frame.overview().sentence, "Checking now.");

        let summary = finished();
        let ended = StateEvent::ScanFinished {
            summary: Box::new(summary.clone()),
        };
        assert_eq!(frame.apply(&ended), Follow::Refresh);
        let done = frame.overview();
        assert!(!done.scanning);
        assert_eq!(done.progress, "");
        assert_eq!(done.summary, Some(summary_line(&summary)));
        let quiet = StateEvent::HealthChanged {
            health: Box::new(status().health),
        };
        assert_eq!(frame.apply(&quiet), Follow::Render);
        assert_eq!(frame.overview().sentence, status().health.headline());
    }

    /// A daemon that stops answering leaves the sentence alone in the
    /// Overview and no Scan action; a Health on the stream once it answers
    /// again asks for the status, which fills it once more.
    #[test]
    fn the_overview_shows_only_protection_off_and_recovers_from_the_stream() {
        let mut status = status();
        status.overview = claude_code();
        let mut frame = Frame::new();
        frame.load(&status);
        assert!(frame.overview().actions);

        let off = View::off(&Off::Unreachable(
            "the daemon stopped answering".to_string(),
        ));
        assert_eq!(frame.view(&off), Follow::Render);
        let shown = frame.overview();
        assert!(shown.off);
        assert_eq!(shown.sentence, "Protection is off.");
        assert!(shown.agents.is_empty() && !shown.actions);
        assert_eq!(frame.view(&off), Follow::Nothing, "already off");
        // A view that says nothing is off leaves the frame to the stream.
        assert_eq!(frame.view(&View::of(&status.health)), Follow::Nothing);
        assert!(frame.overview().off);

        let back = StateEvent::HealthChanged {
            health: Box::new(status.health.clone()),
        };
        assert_eq!(frame.apply(&back), Follow::Refresh);
        frame.load(&status);
        let shown = frame.overview();
        assert!(!shown.off && shown.actions);
        assert_eq!(shown.agents.len(), 1);

        // Off on the stream itself does what the link's view does.
        let gone = StateEvent::HealthChanged {
            health: Box::new(Health::unreachable("the daemon stopped answering")),
        };
        assert_eq!(frame.apply(&gone), Follow::Render);
        assert!(frame.overview().off);
        assert_eq!(frame.to_value()["overview"]["actions"], false);
    }

    /// A moved toggle reaches the Settings pane from the stream, and the
    /// pane carries the Health note of an unreadable settings file.
    #[test]
    fn the_settings_pane_follows_the_answer_and_the_health() {
        let mut frame = Frame::new();
        frame.load(&status());
        frame.set_rules_folder("/home/Library/Application Support/de.byte5.agentsweep/rules.d");
        assert_eq!(frame.settings(&settings(Posture::Simple)), Follow::Render);
        let pane = frame.to_value()["settings"].clone();
        assert_eq!(pane["background"]["toggles"][0]["on"], true);
        assert_eq!(
            pane["advanced"]["rules"]["path"],
            "/home/Library/Application Support/de.byte5.agentsweep/rules.d"
        );

        let mut moved = settings(Posture::Simple);
        moved.rule_feed = false;
        moved
            .config_dirs
            .insert("codex".to_string(), "/Users/x/.codex-work".to_string());
        let event = StateEvent::SettingsChanged {
            settings: Box::new(moved),
        };
        assert_eq!(frame.apply(&event), Follow::Render);
        let pane = frame.to_value()["settings"].clone();
        assert_eq!(pane["background"]["toggles"][0]["on"], false);
        assert_eq!(pane["background"]["toggles"][1]["on"], true);
        assert_eq!(
            pane["advanced"]["configDirs"][1]["dir"],
            "/Users/x/.codex-work"
        );
        assert_eq!(frame.apply(&event), Follow::Nothing);

        let mut health = status().health;
        health.settings_unreadable = true;
        let unreadable = StateEvent::HealthChanged {
            health: Box::new(health),
        };
        assert_eq!(frame.apply(&unreadable), Follow::Render);
        let pane = frame.to_value()["settings"].clone();
        assert_eq!(pane["note"], agentsweep_core::health::SETTINGS_UNREADABLE);
        assert_eq!(pane["available"], true);
    }

    /// Full Disk Access is named under the Settings pane's Advanced section
    /// and nowhere else in what the window receives.
    #[test]
    fn full_disk_access_is_only_under_advanced() {
        let mut frame = Frame::new();
        frame.load(&status());
        for posture in Posture::ALL {
            frame.settings(&settings(posture));
            let mut value = frame.to_value();
            assert!(value.to_string().contains(settings_pane::FULL_DISK_ACCESS));
            value["settings"]["advanced"]["fullDiskAccess"] = Value::Null;
            assert!(
                !value.to_string().contains(settings_pane::FULL_DISK_ACCESS),
                "{value}"
            );
            for pane in settings_pane::FULL_DISK_ACCESS_PANES {
                assert!(
                    !value
                        .to_string()
                        .contains(pane.split('?').nth(1).unwrap_or(pane))
                );
            }
        }
    }

    const MURKY: &str = "claude-code/user/skill/~/.claude/skills/murky";

    /// A status whose last Full Scan left one Item in the Ambiguous Band.
    fn with_an_ambiguous_item() -> Status {
        let mut status = status();
        status.overview = claude_code();
        status.overview.ambiguous = vec![AmbiguousItem {
            item_id: ItemId::from_recorded(MURKY),
            kind: Kind::Skill,
            score: 3,
            heuristics: vec![HeuristicLine {
                id: 521,
                weight: 3,
                plain: "It asks the agent to keep a secret.".to_string(),
                excerpt: "keep this between us".to_string(),
            }],
        }];
        status.scan = Some(ScanSummary {
            ambiguous: 1,
            ..finished()
        });
        status
    }

    /// Spec section 8.4: the Simple Posture shows no Ambiguous Item and no
    /// Ambiguous count, wherever the window could read one: the list, the
    /// Overview, the panes and the last Scan's line, after a status and after
    /// the stream moved the Overview and ended a Scan.
    #[test]
    fn the_simple_view_holds_no_ambiguous_item_and_no_ambiguous_count() {
        let status = with_an_ambiguous_item();
        let mut frame = Frame::new();
        frame.load(&status);
        let assert_clean = |frame: &Frame| {
            let serialised = frame.to_value().to_string().to_lowercase();
            for needle in ["mbiguous", "murky", "keep this between us", "keep a secret"] {
                assert!(
                    !serialised.contains(needle),
                    "the Simple view holds `{needle}`: {serialised}"
                );
            }
            assert!(frame.to_value().get("ambiguous").is_none());
        };
        assert_clean(&frame);
        frame.apply(&StateEvent::OverviewChanged {
            overview: Box::new(status.overview.clone()),
        });
        frame.apply(&StateEvent::ScanFinished {
            summary: Box::new(status.scan.clone().expect("a summary")),
        });
        assert_clean(&frame);

        frame.settings(&settings(Posture::Developer));
        let developer = frame.to_value();
        assert_eq!(developer["ambiguous"][0]["title"], "Skill · murky");
        assert_eq!(
            developer["ambiguous"][0]["score"],
            "Score 3, Ambiguous Band"
        );
        assert!(developer["ambiguous"][0].get("actions").is_none());
        assert!(
            developer["scan"]["line"]
                .as_str()
                .expect("the line")
                .contains("1 in the Ambiguous Band")
        );
    }

    /// Reveal in Finder is offered on the quarantined skill in the Developer
    /// Posture and on nothing in the Simple Posture.
    #[test]
    fn reveal_in_finder_is_offered_in_developer_only() {
        let mut frame = Frame::new();
        frame.load(&status());
        let simple = frame.to_value();
        for card in simple["decided"].as_array().expect("decided") {
            assert_eq!(card["reveal"], false, "{card}");
        }
        frame.settings(&settings(Posture::Developer));
        let value = frame.to_value();
        let mut offered = 0;
        for card in value["decided"].as_array().expect("decided") {
            assert_eq!(card["reveal"], card["state"] == "stopped", "{card}");
            offered += usize::from(card["reveal"] == true);
        }
        assert_eq!(offered, 2, "the two stopped Findings on the skill");
        for card in value["panes"]["threats"].as_array().expect("threats") {
            assert_eq!(card["reveal"], false, "an open Finding");
        }
    }

    #[test]
    fn no_label_carries_an_em_dash() {
        for posture in Posture::ALL {
            for pane in Pane::ALL {
                assert!(!pane.label(posture).contains('\u{2014}'));
            }
        }
    }
}
