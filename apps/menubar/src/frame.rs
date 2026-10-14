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
//! apart from it. Which pane is selected is the window's own business and is
//! not kept here.

use std::collections::BTreeSet;

use agentsweep_core::finding::{Category, FindingState};
use agentsweep_core::settings::Posture;
use agentsweep_ipc::protocol::{SettingsState, StateEvent, Status};
use serde_json::{Value, json};

use crate::findings::{Findings, Follow, card};

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

/// What the window holds: the list of Findings and the Posture it is shown
/// in.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Frame {
    findings: Findings,
    posture: Posture,
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

    /// Takes the list from a status answer.
    pub fn load(&mut self, status: &Status) {
        self.findings.load(status);
    }

    /// Takes the Posture from a `settings` answer or a `settings-changed`
    /// event, and says whether the window needs to be sent again.
    pub fn settings(&mut self, settings: &SettingsState) -> Follow {
        match self.posture == settings.posture {
            true => Follow::Nothing,
            false => {
                self.posture = settings.posture;
                Follow::Render
            }
        }
    }

    /// No daemon answers: see [`Findings::off`]. The Posture stays as it was
    /// last read, since the window keeps being shown in it.
    pub fn off(&mut self, reason: &str) -> Follow {
        self.findings.off(reason)
    }

    /// Applies one state event: a moved choice may change the Posture, every
    /// other event goes to the list.
    pub fn apply(&mut self, event: &StateEvent) -> Follow {
        match event {
            StateEvent::SettingsChanged { settings } => self.settings(settings),
            other => self.findings.apply(other),
        }
    }

    /// The sidebar as it stands.
    pub fn sidebar(&self) -> Vec<Entry> {
        sidebar(&self.findings, self.posture)
    }

    /// The value the window receives: the list as before, the Posture, the
    /// sidebar, and the open Findings split into the two Finding panes.
    pub fn to_value(&self) -> Value {
        let mut value = self.findings.to_value();
        let pane = |category: Category| -> Vec<Value> {
            self.findings
                .open()
                .filter(|f| f.category == category)
                .map(card)
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

    use agentsweep_core::item::Kind;
    use agentsweep_core::settings::{CloudCaps, JudgementEngine};
    use agentsweep_ipc::engine::EngineState;

    use crate::findings::tests::{recorded, status_of};

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
    /// listed.
    #[test]
    fn a_posture_changes_names_and_never_counts() {
        let mut frame = Frame::new();
        frame.load(&status());
        let counts = |frame: &Frame| -> Vec<Option<usize>> {
            frame.sidebar().iter().map(|entry| entry.count).collect()
        };
        let simple = counts(&frame);
        let simple_panes = frame.to_value()["panes"].clone();
        frame.settings(&settings(Posture::Developer));
        assert_eq!(counts(&frame), simple);
        assert_eq!(frame.to_value()["panes"], simple_panes);
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

    #[test]
    fn no_label_carries_an_em_dash() {
        for posture in Posture::ALL {
            for pane in Pane::ALL {
                assert!(!pane.label(posture).contains('\u{2014}'));
            }
        }
    }
}
