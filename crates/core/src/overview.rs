//! What the Overview names beside the Findings (spec section 8.1): one record
//! per Agent, one record per pooled project root, and the Items whose Score
//! fell in the Ambiguous Band, which the Developer Posture shows and the
//! Simple Posture never does (spec sections 8.2 and 8.4).
//!
//! The daemon knows all of it after a Full Scan. The Agent and project
//! records are the last Full Scan's alone, because only a Full Scan detects
//! every Agent and pools every root; the Ambiguous list is kept by every
//! recording Scan for the Items it looked at, the way the Findings are.
//!
//! Paths of project roots and config directories are carried because the
//! Overview names them. Nothing sensitive is: a Heuristic line's excerpt is
//! redacted exactly as a Finding's is (spec section 3.3).
//!
//! Every key is additive. A state file or a status written before these
//! records existed reads as nothing known yet.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::finding_facts::HeuristicLine;
use crate::item::{ItemId, Kind};

/// The version an Agent record carries when none could be read from disk.
pub const VERSION_UNKNOWN: &str = "unknown";

/// One Agent as the last Full Scan found it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentRecord {
    /// The machine-readable Agent id.
    pub agent: String,
    /// The name shown to a person.
    pub display_name: String,
    /// True when the Agent is installed on this machine.
    pub installed: bool,
    /// The version read from disk, absent when it could not be read. The
    /// Agent binary is never executed to learn it (spec section 3.2).
    pub version: Option<String>,
    /// The config directory in effect, empty when there is none.
    pub config_dir: String,
    /// How many pooled project roots this Agent's own registry names.
    pub projects: usize,
    /// How many Items the last Full Scan enumerated on this Agent's Surfaces.
    pub items: usize,
    /// The config layers this Agent merges that AgentSweep does not read, in
    /// plain words, so nothing reads as checked when it was not (spec
    /// section 3.3).
    pub layers_not_read: Vec<String>,
}

impl AgentRecord {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("agent".to_string(), Value::from(self.agent.as_str()));
        map.insert(
            "config_dir".to_string(),
            Value::from(self.config_dir.as_str()),
        );
        map.insert(
            "display_name".to_string(),
            Value::from(self.display_name.as_str()),
        );
        map.insert("installed".to_string(), Value::from(self.installed));
        map.insert("items".to_string(), Value::from(self.items as u64));
        map.insert(
            "layers_not_read".to_string(),
            Value::Array(
                self.layers_not_read
                    .iter()
                    .map(|layer| Value::from(layer.as_str()))
                    .collect(),
            ),
        );
        map.insert("projects".to_string(), Value::from(self.projects as u64));
        map.insert(
            "version".to_string(),
            Value::from(self.version.as_deref().unwrap_or(VERSION_UNKNOWN)),
        );
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<AgentRecord> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let count = |field: &str| value.get(field).and_then(Value::as_u64).map(|n| n as usize);
        Some(AgentRecord {
            agent: text("agent")?.to_string(),
            display_name: text("display_name")?.to_string(),
            installed: value.get("installed")?.as_bool()?,
            version: match text("version")? {
                VERSION_UNKNOWN | "" => None,
                version => Some(version.to_string()),
            },
            config_dir: text("config_dir").unwrap_or_default().to_string(),
            projects: count("projects")?,
            items: count("items")?,
            layers_not_read: value
                .get("layers_not_read")
                .and_then(Value::as_array)
                .map(|layers| {
                    layers
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// Whether the last Full Scan read a project, or the project Needs
/// Permission and was not read at all.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProjectCheck {
    /// The last Full Scan read it.
    #[default]
    Checked,
    /// The operating system will not let AgentSweep read it until the user
    /// allows it. Never counts towards an all-clear.
    NeedsPermission,
}

impl ProjectCheck {
    /// The spelling the state file and the wire carry.
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectCheck::Checked => "checked",
            ProjectCheck::NeedsPermission => "needs_permission",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<ProjectCheck> {
        match text {
            "checked" => Some(ProjectCheck::Checked),
            "needs_permission" => Some(ProjectCheck::NeedsPermission),
            _ => None,
        }
    }
}

/// One Agent at one project root: whether its own registry names the root.
/// Every installed Agent scans its Surfaces at every pooled root, so an Agent
/// that does not know the root is listed with `registered: false` (spec
/// section 3.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectAgent {
    /// The Agent id.
    pub agent: String,
    /// True when this Agent's registry names the root.
    pub registered: bool,
}

/// One pooled project root as the last Full Scan found it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectRecord {
    /// The project root.
    pub root: String,
    /// The Agents whose Surfaces were looked for at this root, each saying
    /// whether its own registry names it.
    pub agents: Vec<ProjectAgent>,
    /// Whether the last Full Scan read it.
    pub check: ProjectCheck,
}

impl ProjectRecord {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "agents".to_string(),
            Value::Array(
                self.agents
                    .iter()
                    .map(|agent| {
                        let mut entry = Map::new();
                        entry.insert("agent".to_string(), Value::from(agent.agent.as_str()));
                        entry.insert("registered".to_string(), Value::from(agent.registered));
                        Value::Object(entry)
                    })
                    .collect(),
            ),
        );
        map.insert("check".to_string(), Value::from(self.check.as_str()));
        map.insert("root".to_string(), Value::from(self.root.as_str()));
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<ProjectRecord> {
        Some(ProjectRecord {
            root: value.get("root")?.as_str()?.to_string(),
            agents: value
                .get("agents")?
                .as_array()?
                .iter()
                .map(|entry| {
                    Some(ProjectAgent {
                        agent: entry.get("agent")?.as_str()?.to_string(),
                        registered: entry.get("registered")?.as_bool()?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            check: ProjectCheck::parse(value.get("check")?.as_str()?)?,
        })
    }
}

/// One Item whose Score fell in the Ambiguous Band and on which nothing else
/// raised a Finding: no Finding of its own, the AI Judgement queue's
/// population (spec section 4.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousItem {
    /// The Item.
    pub item_id: ItemId,
    /// Its Surface kind.
    pub kind: Kind,
    /// Its Score.
    pub score: i64,
    /// Every fired Threat Heuristic, one line each, with the excerpt redacted
    /// as a Finding's is.
    pub heuristics: Vec<HeuristicLine>,
}

impl AmbiguousItem {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "heuristics".to_string(),
            Value::Array(
                self.heuristics
                    .iter()
                    .map(HeuristicLine::to_value)
                    .collect(),
            ),
        );
        map.insert("item_id".to_string(), Value::from(self.item_id.as_str()));
        map.insert("kind".to_string(), Value::from(self.kind.as_str()));
        map.insert("score".to_string(), Value::from(self.score));
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<AmbiguousItem> {
        Some(AmbiguousItem {
            item_id: ItemId::from_recorded(value.get("item_id")?.as_str()?),
            kind: Kind::parse(value.get("kind")?.as_str()?)?,
            score: value.get("score")?.as_i64()?,
            heuristics: value
                .get("heuristics")?
                .as_array()?
                .iter()
                .map(HeuristicLine::from_value)
                .collect::<Option<Vec<_>>>()?,
        })
    }
}

/// Everything the Overview names beside the Findings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Overview {
    /// One record per Agent AgentSweep has an adapter for, installed or not.
    pub agents: Vec<AgentRecord>,
    /// One record per pooled project root, in a stable order.
    pub projects: Vec<ProjectRecord>,
    /// The Items in the Ambiguous Band, in enumeration order.
    pub ambiguous: Vec<AmbiguousItem>,
}

impl Overview {
    /// Takes what a Change Scan found: it speaks for the Items it looked at
    /// and for nothing else, so their entries are replaced by what it says and
    /// every other entry stays where it was. The Agent and project records are
    /// the last Full Scan's and are left alone.
    pub fn take_change(&mut self, looked_at: &BTreeSet<ItemId>, ambiguous: &[AmbiguousItem]) {
        self.ambiguous
            .retain(|entry| !looked_at.contains(&entry.item_id));
        self.ambiguous.extend(ambiguous.iter().cloned());
    }

    /// Writes the three lists into an object under the keys `agents`,
    /// `projects` and `ambiguous`. Every key is new beside its neighbours, so
    /// a reader that does not know them passes them by.
    pub fn write_into(&self, map: &mut Map<String, Value>) {
        map.insert(
            "agents".to_string(),
            Value::Array(self.agents.iter().map(AgentRecord::to_value).collect()),
        );
        map.insert(
            "ambiguous".to_string(),
            Value::Array(self.ambiguous.iter().map(AmbiguousItem::to_value).collect()),
        );
        map.insert(
            "projects".to_string(),
            Value::Array(self.projects.iter().map(ProjectRecord::to_value).collect()),
        );
    }

    /// The three lists as an object of their own.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        self.write_into(&mut map);
        Value::Object(map)
    }

    /// Reads back what [`Overview::write_into`] wrote. A list that is missing
    /// reads as empty, which is what an older writer means; a list that is
    /// there and malformed makes the whole read fail.
    pub fn read_from(value: &Value) -> Option<Overview> {
        fn list<T>(value: &Value, key: &str, read: fn(&Value) -> Option<T>) -> Option<Vec<T>> {
            match value.get(key) {
                None => Some(Vec::new()),
                Some(entries) => entries.as_array()?.iter().map(read).collect(),
            }
        }
        Some(Overview {
            agents: list(value, "agents", AgentRecord::from_value)?,
            projects: list(value, "projects", ProjectRecord::from_value)?,
            ambiguous: list(value, "ambiguous", AmbiguousItem::from_value)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: i64, weight: i64) -> HeuristicLine {
        HeuristicLine {
            id,
            weight,
            plain: format!("Heuristic {id} fired."),
            excerpt: "developer mode is enabled".to_string(),
        }
    }

    fn ambiguous(locator: &str, score: i64) -> AmbiguousItem {
        AmbiguousItem {
            item_id: ItemId::from_recorded(&format!("claude-code/user/skill/{locator}")),
            kind: Kind::Skill,
            score,
            heuristics: vec![line(520, score)],
        }
    }

    fn an_overview() -> Overview {
        Overview {
            agents: vec![
                AgentRecord {
                    agent: "claude-code".to_string(),
                    display_name: "Claude Code".to_string(),
                    installed: true,
                    version: Some("2.1.4".to_string()),
                    config_dir: "/home/.claude".to_string(),
                    projects: 2,
                    items: 7,
                    layers_not_read: Vec::new(),
                },
                AgentRecord {
                    agent: "codex".to_string(),
                    display_name: "Codex".to_string(),
                    installed: false,
                    version: None,
                    config_dir: String::new(),
                    projects: 0,
                    items: 0,
                    layers_not_read: vec!["the cloud enterprise bundle".to_string()],
                },
            ],
            projects: vec![ProjectRecord {
                root: "/work/app".to_string(),
                agents: vec![
                    ProjectAgent {
                        agent: "claude-code".to_string(),
                        registered: true,
                    },
                    ProjectAgent {
                        agent: "codex".to_string(),
                        registered: false,
                    },
                ],
                check: ProjectCheck::Checked,
            }],
            ambiguous: vec![ambiguous("helper", 3)],
        }
    }

    #[test]
    fn an_overview_round_trips_through_its_own_form() {
        let overview = an_overview();
        assert_eq!(Overview::read_from(&overview.to_value()), Some(overview));
    }

    #[test]
    fn a_version_that_could_not_be_read_is_written_as_unknown() {
        let value = an_overview().to_value();
        assert_eq!(value["agents"][1]["version"], "unknown");
        assert_eq!(value["agents"][0]["version"], "2.1.4");
    }

    #[test]
    fn an_object_written_before_the_overview_reads_as_nothing_known() {
        let older = serde_json::json!({"findings": [], "scans": []});
        assert_eq!(Overview::read_from(&older), Some(Overview::default()));
    }

    #[test]
    fn a_malformed_list_is_not_read_as_empty() {
        let broken = serde_json::json!({"projects": [{"root": "/work/app"}]});
        assert_eq!(Overview::read_from(&broken), None);
    }

    #[test]
    fn a_project_check_reads_back_the_spelling_it_writes() {
        for check in [ProjectCheck::Checked, ProjectCheck::NeedsPermission] {
            assert_eq!(ProjectCheck::parse(check.as_str()), Some(check));
        }
        assert_eq!(ProjectCheck::parse("skipped"), None);
    }

    #[test]
    fn a_change_scan_speaks_only_for_the_items_it_looked_at() {
        let mut overview = an_overview();
        overview.ambiguous.push(ambiguous("other", 2));
        let before = overview.clone();

        // The helper was looked at and is Clear now; a new Item came in.
        let looked_at: BTreeSet<ItemId> = [
            ItemId::from_recorded("claude-code/user/skill/helper"),
            ItemId::from_recorded("claude-code/user/skill/fresh"),
        ]
        .into_iter()
        .collect();
        overview.take_change(&looked_at, &[ambiguous("fresh", 2)]);

        let ids: Vec<&str> = overview
            .ambiguous
            .iter()
            .map(|entry| entry.item_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "claude-code/user/skill/other",
                "claude-code/user/skill/fresh"
            ]
        );
        assert_eq!(overview.agents, before.agents);
        assert_eq!(overview.projects, before.projects);
    }
}
