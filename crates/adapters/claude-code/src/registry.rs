//! The user registry, `~/.claude.json`.
//!
//! Claude Code has no project registry it enumerates on startup; a project is
//! the directory a session was started in. What it does keep is this file,
//! written by the Agent itself, with one record per directory it has ever been
//! started in: whether the trust dialog was accepted, the MCP servers that are
//! private to that directory, and which of the project's own `.mcp.json`
//! servers were approved. That is where `projects` gets its roots and their
//! native trust state, and where Activation comes from for everything below a
//! project root.
//!
//! The file also holds the user-scope MCP servers, which is why a scanner that
//! only looked at `~/.claude/settings.json` would miss half the Surface.

use std::path::{Path, PathBuf};

use agentsweep_core::adapter::Problem;
use agentsweep_core::host::Host;
use agentsweep_core::item::{Kind, Scope};
use serde_json::Value;

use crate::document::{self, Document};

/// The name of the registry file, directly under the home.
pub const FILE_NAME: &str = ".claude.json";

/// What the registry says about one directory Claude Code has been started in.
#[derive(Clone, Debug)]
pub struct Record {
    /// The directory, as the registry spells it.
    pub root: PathBuf,
    /// What the record holds.
    value: Value,
}

impl Record {
    /// The Agent's own trust state for the directory, as written on disk.
    pub fn native_trust(&self) -> &'static str {
        match self
            .value
            .get("hasTrustDialogAccepted")
            .and_then(Value::as_bool)
        {
            Some(true) => "trusted",
            Some(false) => "untrusted",
            None => "unknown",
        }
    }

    /// True when the trust dialog was accepted for this exact directory.
    pub fn is_trusted(&self) -> bool {
        self.native_trust() == "trusted"
    }

    /// True when the record itself shows the directory has been worked in:
    /// Claude Code keeps the prompts of a directory in the record's `history`,
    /// so a record with one is a directory somebody has actually used.
    ///
    /// It is half of what `settings.trust_has_sessions` reports; the other
    /// half is the transcript directory beside it, which the adapter checks,
    /// because `cleanupPeriodDays` sweeps transcripts and the record stays.
    pub fn has_history(&self) -> bool {
        self.value
            .get("history")
            .and_then(Value::as_array)
            .is_some_and(|entries| !entries.is_empty())
    }

    /// The MCP servers that are private to this directory, in sorted order.
    pub fn servers(&self) -> Vec<(String, Value)> {
        sorted_members(&self.value, "mcpServers")
    }

    /// The names of the project's own `.mcp.json` servers this directory
    /// approved, and the ones it rejected.
    pub fn mcpjson_choices(&self) -> (Vec<String>, Vec<String>) {
        (
            strings(&self.value, "enabledMcpjsonServers"),
            strings(&self.value, "disabledMcpjsonServers"),
        )
    }
}

/// The registry, read and parsed.
#[derive(Clone, Debug)]
pub struct Registry {
    /// The parsed file.
    pub document: Document,
}

impl Registry {
    /// Reads the registry from the home, absent when there is no home or no
    /// file. An unreadable or unparseable one is a Problem: Claude Code would
    /// have read it, and what is in it decides Activation.
    pub fn load(host: &Host) -> Result<Option<Registry>, Problem> {
        let Some(home) = host.home() else {
            return Ok(None);
        };
        let path = home.join(FILE_NAME);
        let document = document::load(host, &Scope::User, &path, Kind::McpServer)?;
        Ok(document.map(|document| Registry { document }))
    }

    /// The MCP servers that belong to the user rather than to one project.
    pub fn user_servers(&self) -> Vec<(String, Value)> {
        sorted_members(&self.document.value, "mcpServers")
    }

    /// Every directory the registry knows, in sorted order.
    pub fn records(&self) -> Vec<Record> {
        self.document
            .members("projects")
            .into_iter()
            .map(|(root, value)| Record {
                root: PathBuf::from(root),
                value,
            })
            .collect()
    }

    /// What the registry says about one directory, absent when it knows none.
    pub fn record(&self, root: &Path) -> Option<Record> {
        self.records()
            .into_iter()
            .find(|record| record.root == root)
    }
}

fn sorted_members(value: &Value, field: &str) -> Vec<(String, Value)> {
    let Some(object) = value.get(field).and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut members: Vec<(String, Value)> = object
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    members.sort_by(|one, other| one.0.cmp(&other.0));
    members
}

fn strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry(value: Value) -> Registry {
        Registry {
            document: Document {
                path: PathBuf::from("/home/u/.claude.json"),
                surface: "~/.claude.json".to_string(),
                value,
            },
        }
    }

    #[test]
    fn a_record_carries_the_trust_state_the_agent_wrote() {
        let read = registry(json!({"projects": {
            "/src/demo": {"hasTrustDialogAccepted": true},
            "/src/other": {"hasTrustDialogAccepted": false},
            "/src/fresh": {},
        }}));
        let records = read.records();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].root, PathBuf::from("/src/demo"));
        assert_eq!(records[0].native_trust(), "trusted");
        assert!(records[0].is_trusted());
        assert_eq!(records[1].native_trust(), "unknown");
        assert_eq!(records[2].native_trust(), "untrusted");
    }

    /// What `settings.trust_has_sessions` reads off the record: a directory
    /// with prompts behind it has been worked in, an empty record has not.
    #[test]
    fn a_record_with_prompts_behind_it_shows_the_directory_was_worked_in() {
        let read = registry(json!({"projects": {
            "/src/demo": {"history": [{"display": "fix the build"}]},
            "/src/fresh": {"history": []},
            "/src/bare": {"hasTrustDialogAccepted": true},
        }}));
        let records = read.records();
        assert!(records[1].has_history(), "{:?}", records[1].root);
        assert!(!records[0].has_history());
        assert!(!records[2].has_history());
    }

    #[test]
    fn the_user_servers_and_the_private_servers_of_a_project_are_kept_apart() {
        let read = registry(json!({
            "mcpServers": {"notes": {"command": "npx"}},
            "projects": {"/src/demo": {"mcpServers": {"lint": {"command": "./lint"}}}},
        }));
        assert_eq!(read.user_servers().len(), 1);
        assert_eq!(read.user_servers()[0].0, "notes");

        let record = read.record(Path::new("/src/demo")).expect("the record");
        assert_eq!(record.servers()[0].0, "lint");
        assert!(read.record(Path::new("/src/elsewhere")).is_none());
    }

    #[test]
    fn a_projects_own_server_choices_are_read_back() {
        let read = registry(json!({"projects": {"/src/demo": {
            "enabledMcpjsonServers": ["boost"],
            "disabledMcpjsonServers": ["tracker"],
        }}}));
        let record = read.record(Path::new("/src/demo")).expect("the record");
        let (enabled, disabled) = record.mcpjson_choices();
        assert_eq!(enabled, ["boost"]);
        assert_eq!(disabled, ["tracker"]);
    }
}
