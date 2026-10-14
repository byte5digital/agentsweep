//! The facts the Gate answers from, kept in the state file.
//!
//! The daemon answers the Gate from the state file and does no scanning on the
//! request path (spec section 7.3), so what a Scan learned about the Items it
//! flagged has to be written down beside the Findings: which project roots are
//! pooled, and for every open Threat Finding the facts spec section 7.1
//! matches on. Those are the Agent, the Scope with its project root, the kind,
//! whether the Item is a User-scope instruction file, the Item's place on disk
//! and the names the Agent invokes it by.
//!
//! The names are the Surface Adapter's ([`Item::invocations`]); nothing here
//! works one out. Nothing here is a sensitive value either: a place on disk is
//! a path and a name is a name, and no env, header, token or `.env` content is
//! ever read into a fact. The facts are written only for open Threat Findings
//! and leave with the Finding when it is stopped, trusted, acknowledged or
//! gone. They never reach a client: the state file is not on the wire, and the
//! only answer built from them is the Gate's own verdict.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::finding::{Category, FindingId, Standing};
use crate::item::{Invocation, Invoked, Item, Kind, Scope};
use crate::views::ParsedView;

/// What the Gate matches one open Threat Finding on (spec section 7.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateFacts {
    /// The Agent whose Surface Adapter yielded the Item.
    pub agent: String,
    /// `managed`, `user` or `project`.
    pub scope: String,
    /// The project root of a Project-scope Item, absent otherwise.
    pub project_root: Option<PathBuf>,
    /// The Surface kind.
    pub kind: Kind,
    /// True for a User-scope instruction file, which blocks every turn.
    pub user_instruction_file: bool,
    /// Where the Item sits on disk: the tree root for a tree, the file for a
    /// file, the file an entry is written in for an entry, and the link's own
    /// location where the Item is a link.
    pub path: PathBuf,
    /// The path the link resolves to where the Item is a link, absent
    /// otherwise.
    pub resolved: Option<PathBuf>,
    /// The script a Hook entry runs, as its Surface Adapter resolved the
    /// command, absent for every other kind and for a hook whose command
    /// resolves to nothing on disk.
    pub script: Option<PathBuf>,
    /// The names the Agent invokes the Item by.
    pub names: Vec<Invocation>,
}

impl GateFacts {
    /// The facts of one Item, read off what its Surface Adapter yielded.
    ///
    /// This is the one function that turns an Item into Gate facts: a Scan
    /// calls it for every open Threat Finding it leaves, and so does a Threat
    /// Finding opened outside a Scan, such as a malicious Verdict that arrives
    /// after its Scan (spec section 6.4).
    pub fn of(item: &Item) -> GateFacts {
        let script = match &item.view {
            ParsedView::Hook(view) if !view.command_resolved.is_empty() => {
                Some(PathBuf::from(&view.command_resolved))
            }
            _ => None,
        };
        GateFacts {
            agent: item.agent.clone(),
            scope: item.scope.as_str().to_string(),
            project_root: item.scope.root().map(PathBuf::from),
            kind: item.kind,
            user_instruction_file: item.kind == Kind::InstructionFile && item.scope == Scope::User,
            path: item.path.clone(),
            resolved: match item.is_symlink && !item.link_target.is_empty() {
                true => Some(PathBuf::from(&item.link_target)),
                false => None,
            },
            script,
            names: item.invocations.clone(),
        }
    }

    /// The facts as the state file carries them.
    pub fn to_value(&self) -> Value {
        let path = |path: &Option<PathBuf>| {
            Value::from(
                path.as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
            )
        };
        let mut map = Map::new();
        map.insert("agent".to_string(), Value::from(self.agent.as_str()));
        map.insert("kind".to_string(), Value::from(self.kind.as_str()));
        map.insert(
            "names".to_string(),
            Value::Array(
                self.names
                    .iter()
                    .map(|invocation| {
                        let mut name = Map::new();
                        name.insert(
                            "invoked".to_string(),
                            Value::from(invocation.invoked.as_str()),
                        );
                        name.insert("name".to_string(), Value::from(invocation.name.as_str()));
                        name.insert(
                            "source".to_string(),
                            Value::from(invocation.source.as_str()),
                        );
                        Value::Object(name)
                    })
                    .collect(),
            ),
        );
        map.insert(
            "path".to_string(),
            Value::from(self.path.display().to_string()),
        );
        map.insert("project_root".to_string(), path(&self.project_root));
        map.insert("resolved".to_string(), path(&self.resolved));
        map.insert("scope".to_string(), Value::from(self.scope.as_str()));
        map.insert("script".to_string(), path(&self.script));
        map.insert(
            "user_instruction_file".to_string(),
            Value::from(self.user_instruction_file),
        );
        Value::Object(map)
    }

    /// Reads back what [`GateFacts::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<GateFacts> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let path = |field: &str| -> Option<Option<PathBuf>> {
            match text(field)? {
                "" => Some(None),
                written => Some(Some(PathBuf::from(written))),
            }
        };
        let names = value
            .get("names")?
            .as_array()?
            .iter()
            .map(|name| {
                Some(Invocation {
                    invoked: Invoked::parse(name.get("invoked")?.as_str()?)?,
                    name: name.get("name")?.as_str()?.to_string(),
                    source: name.get("source")?.as_str()?.to_string(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(GateFacts {
            agent: text("agent")?.to_string(),
            scope: text("scope")?.to_string(),
            project_root: path("project_root")?,
            kind: Kind::parse(text("kind")?)?,
            user_instruction_file: value.get("user_instruction_file")?.as_bool()?,
            path: PathBuf::from(text("path")?),
            resolved: path("resolved")?,
            script: path("script")?,
            names,
        })
    }
}

/// The Gate facts of every open Threat Finding among `standing`, by Finding,
/// for the Items the Finding is about. A Finding whose Item is not among
/// `items` has none, and neither has an Exposure Finding or one that is
/// stopped, trusted, acknowledged or gone. The Ambiguous Band is no Finding at
/// all, so it never reaches this.
pub fn for_open_threats(standing: &[Standing], items: &[Item]) -> BTreeMap<FindingId, GateFacts> {
    standing
        .iter()
        .filter(|placed| placed.state.is_open() && placed.finding.category == Category::Threat)
        .filter_map(|placed| {
            let item = items
                .iter()
                .find(|item| item.id == placed.finding.item_id)?;
            Some((placed.id.clone(), GateFacts::of(item)))
        })
        .collect()
}

/// What the state file keeps for the Gate: the pooled project roots and the
/// facts of every open Threat Finding.
///
/// A state file written before the Gate facts existed has none of this, which
/// reads as absent rather than as empty: the Gate then answers "state
/// unavailable" until the next Full Scan writes it (spec section 7.3).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GateRecord {
    /// The project roots the last Scan pooled, in a stable order.
    pub roots: Vec<PathBuf>,
    /// The facts of every open Threat Finding, by Finding.
    pub facts: BTreeMap<FindingId, GateFacts>,
}

impl GateRecord {
    /// The record as the state file carries it.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "facts".to_string(),
            Value::Array(
                self.facts
                    .iter()
                    .map(|(id, facts)| {
                        let mut one = Map::new();
                        one.insert("facts".to_string(), facts.to_value());
                        one.insert("finding".to_string(), Value::from(id.as_str()));
                        Value::Object(one)
                    })
                    .collect(),
            ),
        );
        map.insert(
            "roots".to_string(),
            Value::Array(
                self.roots
                    .iter()
                    .map(|root| Value::from(root.display().to_string()))
                    .collect(),
            ),
        );
        Value::Object(map)
    }

    /// Reads back what [`GateRecord::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<GateRecord> {
        let roots = value
            .get("roots")?
            .as_array()?
            .iter()
            .map(|root| root.as_str().map(PathBuf::from))
            .collect::<Option<Vec<_>>>()?;
        let facts = value
            .get("facts")?
            .as_array()?
            .iter()
            .map(|one| {
                Some((
                    FindingId::from_recorded(one.get("finding")?.as_str()?),
                    GateFacts::from_value(one.get("facts")?)?,
                ))
            })
            .collect::<Option<BTreeMap<_, _>>>()?;
        Some(GateRecord { roots, facts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingState, RuleStatus, Severity, Source, Tier};
    use crate::item::{Activation, Provenance};
    use crate::views::{HookView, McpView};

    fn skill() -> Item {
        Item::file(
            "claude-code",
            Scope::User,
            Kind::Skill,
            "~/.claude/skills/setup",
            PathBuf::from("/home/u/.claude/skills/setup"),
            Provenance::Manual,
            Activation::Active,
            b"---\nname: setup\n---\n".to_vec(),
        )
        .invoked_as(Invocation::skill("setup"))
    }

    fn standing(item: &Item, category: Category, state: FindingState) -> Standing {
        let finding = Finding {
            item_id: item.id.clone(),
            source: Source::Rule(1),
            content_hash: item.content_hash.clone(),
            category,
            severity: Severity::Critical,
            tier: Tier::Rules,
            status: RuleStatus::Probation,
            title: "t".to_string(),
            plain: "p".to_string(),
            sensitive: false,
            file: String::new(),
            matches: Vec::new(),
            heuristics: Vec::new(),
            drift: None,
        };
        Standing {
            id: FindingId::of(&finding),
            finding,
            state,
            receipt_id: String::new(),
        }
    }

    #[test]
    fn the_facts_of_an_item_are_what_its_adapter_yielded() {
        let item = skill().through_link(std::path::Path::new("/home/u/.agents/skills/setup"));
        let facts = GateFacts::of(&item);
        assert_eq!(facts.agent, "claude-code");
        assert_eq!(facts.scope, "user");
        assert_eq!(facts.project_root, None);
        assert_eq!(facts.kind, Kind::Skill);
        assert!(!facts.user_instruction_file);
        assert_eq!(facts.path, PathBuf::from("/home/u/.claude/skills/setup"));
        assert_eq!(
            facts.resolved,
            Some(PathBuf::from("/home/u/.agents/skills/setup"))
        );
        assert_eq!(facts.names, vec![Invocation::skill("setup")]);
    }

    #[test]
    fn a_user_instruction_file_says_so_and_a_project_one_does_not() {
        let user = Item::file(
            "claude-code",
            Scope::User,
            Kind::InstructionFile,
            "~/.claude/CLAUDE.md",
            PathBuf::from("/home/u/.claude/CLAUDE.md"),
            Provenance::Manual,
            Activation::Active,
            b"x".to_vec(),
        );
        assert!(GateFacts::of(&user).user_instruction_file);
        let project = Item::file(
            "claude-code",
            Scope::Project(PathBuf::from("/work/p")),
            Kind::InstructionFile,
            "CLAUDE.md",
            PathBuf::from("/work/p/CLAUDE.md"),
            Provenance::Unknown,
            Activation::Active,
            b"x".to_vec(),
        );
        let facts = GateFacts::of(&project);
        assert!(!facts.user_instruction_file);
        assert_eq!(facts.scope, "project");
        assert_eq!(facts.project_root, Some(PathBuf::from("/work/p")));
    }

    #[test]
    fn a_hook_entry_carries_the_script_its_adapter_resolved() {
        let view = HookView {
            command_resolved: "/home/u/.claude/hooks/run.sh".to_string(),
            ..HookView::default()
        };
        let hook = Item::entry(
            "claude-code",
            Scope::User,
            Kind::Hook,
            "~/.claude/settings.json#PreToolUse/Bash/0123456789ab",
            PathBuf::from("/home/u/.claude/settings.json"),
            Provenance::Manual,
            Activation::Active,
            b"{}".to_vec(),
        )
        .with_view(ParsedView::Hook(view));
        assert_eq!(
            GateFacts::of(&hook).script,
            Some(PathBuf::from("/home/u/.claude/hooks/run.sh"))
        );
        assert_eq!(GateFacts::of(&skill()).script, None);
    }

    #[test]
    fn only_open_threat_findings_carry_facts() {
        let item = skill();
        let open = standing(&item, Category::Threat, FindingState::Open);
        let exposure = standing(&item, Category::Exposure, FindingState::Open);
        let mut others = Vec::new();
        for state in [
            FindingState::Stopped,
            FindingState::Trusted,
            FindingState::Acknowledged,
            FindingState::Gone,
        ] {
            let mut placed = standing(&item, Category::Threat, state);
            placed.id = FindingId::from_recorded(&format!("{}-{state}", placed.id.as_str()));
            others.push(placed);
        }
        let mut all = vec![open.clone(), exposure];
        all.extend(others);
        let facts = for_open_threats(&all, std::slice::from_ref(&item));
        assert_eq!(facts.len(), 1, "{facts:?}");
        assert!(facts.contains_key(&open.id));
    }

    #[test]
    fn a_record_round_trips_through_its_own_form() {
        let item = skill().invoked_as(Invocation::mcp_server("plugin:p:s", "plugin"));
        let mut record = GateRecord {
            roots: vec![PathBuf::from("/work/a"), PathBuf::from("/work/b")],
            facts: BTreeMap::new(),
        };
        record.facts.insert(
            FindingId::from_recorded("one"),
            GateFacts::of(&item.through_link(std::path::Path::new("/x"))),
        );
        let read = GateRecord::from_value(&record.to_value()).expect("a record");
        assert_eq!(read, record);
    }

    /// Sensitive values never become a fact: the facts of an MCP server with
    /// an env value, a header and a token hold its name and its place, and
    /// none of the values.
    #[test]
    fn no_sensitive_value_is_among_the_facts() {
        let entry = serde_json::json!({
            "command": "/opt/tools/tracker",
            "env": { "TRACKER_TOKEN": "fixture-env-value-0123" },
            "headers": { "Authorization": "Bearer fixture-header-value-4567" },
            "url": "https://tracker.example.invalid/mcp?token=fixture-url-token-89ab",
        });
        let server = Item::entry(
            "claude-code",
            Scope::User,
            Kind::McpServer,
            "~/.claude.json#tracker",
            PathBuf::from("/home/u/.claude.json"),
            Provenance::Manual,
            Activation::Active,
            crate::item::canonical_entry(&entry),
        )
        .with_view(ParsedView::Mcp(McpView::of("tracker", &entry)))
        .invoked_as(Invocation::mcp_server("tracker", "user"));
        let written = GateFacts::of(&server).to_value().to_string();
        for value in [
            "fixture-env-value-0123",
            "fixture-header-value-4567",
            "fixture-url-token-89ab",
            "TRACKER_TOKEN",
        ] {
            assert!(!written.contains(value), "{value} in {written}");
        }
        assert!(written.contains("tracker"));
    }
}
