//! Codex MCP server tables, normalised into the shape every MCP Rule reads.
//!
//! Codex writes an MCP server as `[mcp_servers.<name>]` in TOML, Claude Code
//! writes one as an object under `mcpServers` in JSON, and one Rule has to
//! cover both (spec section 3.3). So the table is converted here into the
//! agent-neutral shape [`agentsweep_core::views::McpView`] is written against,
//! and the view does the rest.
//!
//! What the Item carries as content is the table as it was written, not the
//! converted shape: `cwd`, `startup_timeout_sec` and `required` are part of
//! what an attacker may change, and an entry hash that dropped them would let
//! a change through the Baseline unseen.
//!
//! An `env` block and an `http_headers` block are sensitive (spec section
//! 3.3). The view never carries a value out of them, and [`redacted`] is how
//! such an entry is written down for a person: every sensitive value replaced
//! by a short hash of itself.

use std::path::{Path, PathBuf};

use agentsweep_adapter_workspace::command_in_unknown_hidden_home;
use agentsweep_core::host::Host;
use agentsweep_core::item::sha256_hex;
use agentsweep_core::views::{McpView, value_string};
use serde_json::{Map, Value, json};

/// The fields of a Codex MCP table whose values are credentials rather than
/// configuration.
const SENSITIVE_FIELDS: [&str; 2] = ["env", "http_headers"];

/// One Codex MCP table in the shape both Agents' MCP Rules are written
/// against: `type`, `command`, `args`, `env`, `url`, `headers`.
///
/// Codex names no transport in the file. A table with a `command` starts a
/// process and speaks over standard streams; a table with a `url` is reached
/// over streamable HTTP. Naming the transport here rather than leaving it
/// empty is the adapter answering a question the file does not spell out,
/// which is the adapter's job and never a Rule's.
///
/// `env_http_headers` maps a header to the environment variable that fills it,
/// so it travels as a header whose value is that reference. It is the
/// difference between a header AgentSweep can see the credential of and one it
/// cannot, and writing the reference keeps the two apart.
pub fn shared_shape(table: &Value) -> Value {
    let mut shape = Map::new();
    let command = table.get("command").and_then(Value::as_str).unwrap_or("");
    let url = table.get("url").and_then(Value::as_str).unwrap_or("");
    if !command.is_empty() {
        shape.insert("type".to_string(), json!("stdio"));
        shape.insert("command".to_string(), json!(command));
    } else if !url.is_empty() {
        shape.insert("type".to_string(), json!("http"));
    }
    if !url.is_empty() {
        shape.insert("url".to_string(), json!(url));
    }
    if let Some(args) = table.get("args") {
        shape.insert("args".to_string(), args.clone());
    }
    if let Some(env) = table.get("env") {
        shape.insert("env".to_string(), env.clone());
    }

    let mut headers = Map::new();
    if let Some(written) = table.get("http_headers").and_then(Value::as_object) {
        for (name, value) in written {
            headers.insert(name.clone(), value.clone());
        }
    }
    if let Some(from_env) = table.get("env_http_headers").and_then(Value::as_object) {
        for (name, variable) in from_env {
            headers.insert(
                name.clone(),
                json!(format!("${{{}}}", value_string(variable))),
            );
        }
    }
    if !headers.is_empty() {
        shape.insert("headers".to_string(), Value::Object(headers));
    }
    Value::Object(shape)
}

/// Fills in the facts of an MCP entry that need the machine: where the command
/// lands and what kind of place that is.
///
/// A launcher such as `npx` or `php` is not where the code is; the script it is
/// handed is. So the four location facts hold when the resolved command or any
/// path-shaped argument lands somewhere no real tool is installed, which is how
/// a server that runs `node ~/.dev-utils/index.js` is reported although `node`
/// itself is perfectly ordinary.
///
/// A Codex table may set a `cwd` of its own, and a relative command is
/// resolved against it rather than against the project root.
pub fn attach_command_facts(view: &mut McpView, host: &Host, table: &Value, base: Option<&Path>) {
    let declared = table.get("cwd").and_then(Value::as_str).unwrap_or("");
    let working_directory = host.resolve_command(declared, base);
    let base = working_directory.as_deref().or(base);

    let resolved = host.resolve_command(&view.command, base);
    view.command_resolved = resolved
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    let mut candidates: Vec<PathBuf> = resolved.into_iter().collect();
    for argument in &view.args {
        if looks_like_a_path(argument)
            && let Some(path) = host.resolve_command(argument, base)
        {
            candidates.push(path);
        }
    }

    for candidate in &candidates {
        view.command_in_temp |= host.in_temporary_directory(candidate);
        view.command_in_downloads |= host.in_downloads(candidate);
        view.command_world_writable |= host.is_world_writable(candidate);
        if let Some(home) = host.home() {
            view.command_in_unknown_hidden_home |= command_in_unknown_hidden_home(home, candidate);
        }
    }
}

/// True when an argument names a file rather than a flag or a package.
fn looks_like_a_path(argument: &str) -> bool {
    !argument.starts_with('-')
        && !argument.contains("://")
        && (argument.starts_with('/') || argument.starts_with("~/") || argument.starts_with("./"))
}

/// One MCP table written down for a person: every sensitive value replaced by
/// a short hash of itself.
///
/// The raw bytes still reach the local Tiers, which is how Rule 0010 finds a
/// plaintext token at all. This is what a Finding, a store and a log are
/// allowed to carry instead.
pub fn redacted(table: &Value) -> String {
    let mut written = table.clone();
    for field in SENSITIVE_FIELDS {
        let Some(values) = written.get_mut(field).and_then(Value::as_object_mut) else {
            continue;
        };
        for value in values.values_mut() {
            *value = Value::String(hashed(&value_string(value)));
        }
    }
    String::from_utf8_lossy(&agentsweep_core::item::canonical_entry(&written)).to_string()
}

/// The excerpt a Finding on a sensitive field shows: the hash of the value and
/// never the value.
pub fn hashed(value: &str) -> String {
    format!("sha256:{}", &sha256_hex(value.as_bytes())[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host::new(PathBuf::from("/home/u"), vec![PathBuf::from("/src/demo")])
    }

    /// A Codex table and the Claude Code object that means the same thing
    /// reach the view as one entry, which is what lets one MCP Rule cover both
    /// Agents.
    #[test]
    fn a_codex_table_and_a_claude_code_object_reach_the_view_the_same_way() {
        let table = json!({
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-everything"],
            "startup_timeout_sec": 10,
        });
        let codex = McpView::of("notes", &shared_shape(&table));
        let claude_code = McpView::of(
            "notes",
            &json!({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything"]}),
        );
        assert_eq!(codex.transport, "stdio");
        assert_eq!(codex.transport, claude_code.transport);
        assert_eq!(codex.package, claude_code.package);
        assert_eq!(codex.args, claude_code.args);
    }

    /// Codex names no transport, so the adapter does: a `url` table is reached
    /// over streamable HTTP and a Rule may not be left to guess that.
    #[test]
    fn a_url_table_is_an_http_server_and_its_header_keys_travel_without_values() {
        let table = json!({
            "url": "https://tracker.example.invalid/mcp",
            "http_headers": {"X-Tenant": "demo"},
            "env_http_headers": {"Authorization": "TRACKER_TOKEN"},
        });
        let view = McpView::of("tracker", &shared_shape(&table));
        assert_eq!(view.transport, "http");
        assert_eq!(view.url_host, "tracker.example.invalid");
        assert_eq!(view.header_keys, ["Authorization", "X-Tenant"]);
        assert!(
            !view.has_literal_authorization,
            "a header filled from the environment carries no credential"
        );
    }

    #[test]
    fn a_header_written_out_in_the_file_is_a_literal_authorization() {
        let table = json!({
            "url": "https://tracker.example.invalid/mcp",
            "http_headers": {"Authorization": "Bearer ghp_0123456789abcdefghijklmnop"},
        });
        assert!(McpView::of("tracker", &shared_shape(&table)).has_literal_authorization);
    }

    /// SANDWORM wrote a server into `~/.dev-utils` and launched it with an
    /// ordinary `node`. The location fact has to land on the script.
    #[test]
    fn a_launcher_with_a_script_in_a_hidden_home_directory_is_reported() {
        let table = json!({"command": "node", "args": ["~/.dev-utils/index.js"]});
        let mut view = McpView::of("dev-utils", &shared_shape(&table));
        attach_command_facts(&mut view, &host(), &table, None);
        assert!(view.command_in_unknown_hidden_home);
        assert!(!view.command_in_temp);
    }

    #[test]
    fn a_server_downloaded_and_run_from_the_downloads_folder_is_reported() {
        let table = json!({"command": "/home/u/Downloads/server", "args": ["--stdio"]});
        let mut view = McpView::of("x", &shared_shape(&table));
        attach_command_facts(&mut view, &host(), &table, None);
        assert_eq!(view.command_resolved, "/home/u/Downloads/server");
        assert!(view.command_in_downloads);
    }

    /// A relative command is resolved against the table's own `cwd`, which is
    /// a field Claude Code has no equivalent of.
    #[test]
    fn a_relative_command_is_resolved_against_the_tables_own_working_directory() {
        let table = json!({"command": "./bin/server", "cwd": "/home/u/Downloads/kit"});
        let mut view = McpView::of("kit", &shared_shape(&table));
        attach_command_facts(&mut view, &host(), &table, Some(Path::new("/src/demo")));
        assert_eq!(view.command_resolved, "/home/u/Downloads/kit/bin/server");
        assert!(view.command_in_downloads);
    }

    #[test]
    fn a_redacted_table_carries_no_value_of_a_sensitive_field() {
        let table = json!({
            "command": "npx",
            "env": {"TOKEN": "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"},
            "http_headers": {"Authorization": "Bearer hunter2hunter2"},
        });
        let written = redacted(&table);
        assert!(!written.contains("ghp_"), "{written}");
        assert!(!written.contains("hunter2"), "{written}");
        assert!(written.contains("sha256:"), "{written}");
        assert!(written.contains("npx"), "{written}");
        assert_eq!(written, redacted(&table));
    }
}
