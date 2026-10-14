//! The `gate` request on the wire: what the Gate asks the daemon and the
//! verdict it is answered with (spec section 7.3, ADR 0008).
//!
//! It is the third and last request that takes a path. It carries the Agent,
//! the hook event, `cwd`, and optionally the tool call's Item-naming fields: a
//! skill name, an MCP server name with the source the Agent reports, skill
//! names the command line interface extracted from a prompt, and the path
//! tokens of a shell command. The prompt text and the shell command never
//! travel; only what was extracted from them does.
//!
//! The answer says `clear`, `block` or `unknown`, and on `block` a count of
//! open Findings and one fixed reason code. It never carries Finding text, an
//! id or a path, so whatever runs the hook learns nothing about the machine
//! beyond the verdict.
//!
//! Neither a request nor its fields are ever printed in full: the `Debug` of a
//! request names the Agent and the event and nothing else, so a log line built
//! from one cannot carry `cwd`, a path token or a name.

use std::fmt;

use serde_json::{Map, Value};

/// The Agents a Gate is registered in (spec section 7.2).
pub const GATE_AGENTS: [&str; 2] = ["claude-code", "codex"];

/// The hook event a `gate` request was sent from, as the Agent names it in
/// `hook_event_name`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateEvent {
    /// A turn: the project and the User-scope instruction files are checked,
    /// beside any skill names extracted from the prompt.
    UserPromptSubmit,
    /// A tool call: only the Item the call names is checked.
    PreToolUse,
    /// Claude Code's direct `/skill-name` path: the skill it names is checked
    /// as a tool call's would be.
    UserPromptExpansion,
}

impl GateEvent {
    /// Every event.
    pub const ALL: [GateEvent; 3] = [
        GateEvent::UserPromptSubmit,
        GateEvent::PreToolUse,
        GateEvent::UserPromptExpansion,
    ];

    /// The spelling the request carries, the Agent's own.
    pub fn as_str(self) -> &'static str {
        match self {
            GateEvent::UserPromptSubmit => "UserPromptSubmit",
            GateEvent::PreToolUse => "PreToolUse",
            GateEvent::UserPromptExpansion => "UserPromptExpansion",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<GateEvent> {
        GateEvent::ALL
            .into_iter()
            .find(|event| event.as_str() == text)
    }

    /// True for the event that starts a turn, the only one the project and
    /// the User-scope instruction files block (spec section 7.1).
    pub fn is_turn(self) -> bool {
        self == GateEvent::UserPromptSubmit
    }
}

/// An MCP server as a tool call names it: by name, with the source class the
/// Agent reports beside it where it reports one.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct McpServerRef {
    /// The server's name.
    pub name: String,
    /// The source class (Claude Code's `mcp_server.source`), absent where the
    /// Agent gives none, in which case the name alone is matched.
    pub source: Option<String>,
}

/// The Item-naming fields of one call, or the skill names extracted at a turn.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct GateTool {
    /// The tool's name (`Skill`, `Bash`, `mcp__server__tool`), absent at a
    /// turn.
    pub name: Option<String>,
    /// The skill a `Skill` call or a `/skill-name` expansion names.
    pub skill: Option<String>,
    /// The MCP server an `mcp__` call reaches.
    pub mcp_server: Option<McpServerRef>,
    /// Skill names the command line interface extracted from a prompt.
    pub skills: Vec<String>,
    /// The path-like tokens of a shell command, as written: absolute,
    /// relative to `cwd`, starting with `~/`, or bare.
    pub paths: Vec<String>,
}

/// One `gate` request.
#[derive(Clone, Eq, PartialEq)]
pub struct GateRequest {
    /// The Agent the hook runs in, as [`GATE_AGENTS`] spells it.
    pub agent: String,
    /// The hook event.
    pub event: GateEvent,
    /// The working directory the Agent reported, an absolute path.
    pub cwd: String,
    /// The Item-naming fields, absent when there are none.
    pub tool: Option<GateTool>,
}

impl fmt::Debug for GateRequest {
    /// The Agent and the event, never `cwd`, a path token or a name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateRequest")
            .field("agent", &self.agent)
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for GateTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GateTool { .. }")
    }
}

impl fmt::Debug for McpServerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpServerRef { .. }")
    }
}

impl GateRequest {
    /// The fields beside the request's name.
    pub(crate) fn write_into(&self, map: &mut Map<String, Value>) {
        map.insert("agent".to_string(), Value::from(self.agent.as_str()));
        map.insert("cwd".to_string(), Value::from(self.cwd.as_str()));
        map.insert("event".to_string(), Value::from(self.event.as_str()));
        if let Some(tool) = &self.tool {
            map.insert("tool".to_string(), tool.to_value());
        }
    }

    /// Reads the fields back, or nothing when one is missing, of the wrong
    /// type, or names an Agent or an event there is not.
    pub(crate) fn read_from(value: &Value) -> Option<GateRequest> {
        let text = |field: &str| value.get(field).and_then(Value::as_str);
        let agent = text("agent")?;
        if !GATE_AGENTS.contains(&agent) {
            return None;
        }
        Some(GateRequest {
            agent: agent.to_string(),
            event: GateEvent::parse(text("event")?)?,
            cwd: text("cwd")?.to_string(),
            tool: match value.get("tool") {
                None | Some(Value::Null) => None,
                Some(tool) => Some(GateTool::from_value(tool)?),
            },
        })
    }
}

impl GateTool {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        if let Some(server) = &self.mcp_server {
            let mut one = Map::new();
            one.insert("name".to_string(), Value::from(server.name.as_str()));
            if let Some(source) = &server.source {
                one.insert("source".to_string(), Value::from(source.as_str()));
            }
            map.insert("mcp_server".to_string(), Value::Object(one));
        }
        if let Some(name) = &self.name {
            map.insert("name".to_string(), Value::from(name.as_str()));
        }
        let list = |items: &[String]| {
            Value::Array(
                items
                    .iter()
                    .map(|item| Value::from(item.as_str()))
                    .collect(),
            )
        };
        map.insert("paths".to_string(), list(&self.paths));
        if let Some(skill) = &self.skill {
            map.insert("skill".to_string(), Value::from(skill.as_str()));
        }
        map.insert("skills".to_string(), list(&self.skills));
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<GateTool> {
        let optional = |field: &str| -> Option<Option<String>> {
            match value.get(field) {
                None | Some(Value::Null) => Some(None),
                Some(text) => Some(Some(text.as_str()?.to_string())),
            }
        };
        let list = |field: &str| -> Option<Vec<String>> {
            match value.get(field) {
                None | Some(Value::Null) => Some(Vec::new()),
                Some(items) => items
                    .as_array()?
                    .iter()
                    .map(|item| item.as_str().map(str::to_string))
                    .collect(),
            }
        };
        let mcp_server = match value.get("mcp_server") {
            None | Some(Value::Null) => None,
            Some(server) => Some(McpServerRef {
                name: server.get("name")?.as_str()?.to_string(),
                source: match server.get("source") {
                    None | Some(Value::Null) => None,
                    Some(source) => Some(source.as_str()?.to_string()),
                },
            }),
        };
        Some(GateTool {
            name: optional("name")?,
            skill: optional("skill")?,
            mcp_server,
            skills: list("skills")?,
            paths: list("paths")?,
        })
    }
}

/// Why a `gate` request was answered `block`: one fixed code the command line
/// interface turns into the wording of spec section 7.5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateReason {
    /// The project `cwd` resolves to has an open Threat Finding on a
    /// Project-scope Item.
    Project,
    /// One of the Agent's User-scope instruction files has an open Threat
    /// Finding.
    UserInstructions,
    /// The call names a User-scope Item with an open Threat Finding.
    Item,
}

impl GateReason {
    /// Every reason.
    pub const ALL: [GateReason; 3] = [
        GateReason::Project,
        GateReason::UserInstructions,
        GateReason::Item,
    ];

    /// The spelling the answer carries.
    pub fn as_str(self) -> &'static str {
        match self {
            GateReason::Project => "project",
            GateReason::UserInstructions => "user_instructions",
            GateReason::Item => "item",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<GateReason> {
        GateReason::ALL
            .into_iter()
            .find(|reason| reason.as_str() == text)
    }
}

/// What a `gate` request is answered with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateVerdict {
    /// Nothing the Gate matches on is flagged: allow.
    Clear,
    /// Refuse the turn or the call.
    Block {
        /// How many open Findings stand behind the block.
        count: usize,
        /// Which check blocked.
        reason: GateReason,
    },
    /// The daemon cannot say: the Gate facts are unavailable, or `cwd` is
    /// under no pooled root and no User-scope check applies. The command line
    /// interface treats it as `clear`.
    Unknown,
}

impl GateVerdict {
    /// The spelling of the verdict alone.
    pub fn name(self) -> &'static str {
        match self {
            GateVerdict::Clear => "clear",
            GateVerdict::Block { .. } => "block",
            GateVerdict::Unknown => "unknown",
        }
    }

    /// The answer as the wire carries it: the verdict, and on `block` the
    /// count and the reason code. Nothing else, ever.
    pub fn to_value(self) -> Value {
        let mut map = Map::new();
        map.insert("verdict".to_string(), Value::from(self.name()));
        if let GateVerdict::Block { count, reason } = self {
            map.insert("count".to_string(), Value::from(count as u64));
            map.insert("reason".to_string(), Value::from(reason.as_str()));
        }
        Value::Object(map)
    }

    /// Reads back what [`GateVerdict::to_value`] wrote.
    pub fn from_value(value: &Value) -> Option<GateVerdict> {
        match value.get("verdict")?.as_str()? {
            "clear" => Some(GateVerdict::Clear),
            "unknown" => Some(GateVerdict::Unknown),
            "block" => Some(GateVerdict::Block {
                count: value.get("count")?.as_u64()? as usize,
                reason: GateReason::parse(value.get("reason")?.as_str()?)?,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    }

    /// The answer carries the verdict, and on `block` the count and the
    /// reason code, and no other key whatever the verdict.
    #[test]
    fn the_answer_carries_only_verdict_count_and_reason() {
        for reason in GateReason::ALL {
            let block = GateVerdict::Block { count: 3, reason };
            let value = block.to_value();
            assert_eq!(
                keys(&value),
                BTreeSet::from([
                    "count".to_string(),
                    "reason".to_string(),
                    "verdict".to_string()
                ])
            );
            assert_eq!(GateVerdict::from_value(&value), Some(block));
        }
        for verdict in [GateVerdict::Clear, GateVerdict::Unknown] {
            let value = verdict.to_value();
            assert_eq!(keys(&value), BTreeSet::from(["verdict".to_string()]));
            assert_eq!(GateVerdict::from_value(&value), Some(verdict));
        }
        assert_eq!(
            GateVerdict::from_value(&serde_json::json!({"verdict": "maybe"})),
            None
        );
    }

    #[test]
    fn every_event_and_reason_reads_back_the_spelling_it_writes() {
        for event in GateEvent::ALL {
            assert_eq!(GateEvent::parse(event.as_str()), Some(event));
        }
        for reason in GateReason::ALL {
            assert_eq!(GateReason::parse(reason.as_str()), Some(reason));
        }
        assert!(GateEvent::UserPromptSubmit.is_turn());
        assert!(!GateEvent::PreToolUse.is_turn());
        assert!(!GateEvent::UserPromptExpansion.is_turn());
    }

    /// A printed request names the Agent and the event and nothing it was
    /// asked about.
    #[test]
    fn a_printed_request_carries_neither_cwd_nor_a_token_nor_a_name() {
        let request = GateRequest {
            agent: "claude-code".to_string(),
            event: GateEvent::PreToolUse,
            cwd: "/work/secret-project".to_string(),
            tool: Some(GateTool {
                name: Some("Bash".to_string()),
                skill: Some("hidden-skill".to_string()),
                mcp_server: Some(McpServerRef {
                    name: "hidden-server".to_string(),
                    source: Some("user".to_string()),
                }),
                skills: vec!["extracted-skill".to_string()],
                paths: vec!["./hidden-token.sh".to_string()],
            }),
        };
        let printed = format!("{request:?}");
        for hidden in [
            "secret-project",
            "hidden-skill",
            "hidden-server",
            "extracted-skill",
            "hidden-token",
        ] {
            assert!(!printed.contains(hidden), "{hidden} in {printed}");
        }
        assert!(printed.contains("claude-code"));
    }
}
