//! MCP server entries, and the facts about them that need the machine.
//!
//! The view itself is agent-neutral and lives in the core, so one MCP Rule
//! covers `~/.claude.json`, a project `.mcp.json` and Codex's `[mcp_servers.*]`
//! alike. What is here is the part that only a Surface Adapter can answer:
//! where the command lands on this machine, and whether that is a place no
//! real tool is installed in.
//!
//! An `env` block and a `headers` block are sensitive (spec section 3.3). The
//! view never carries a value out of them, and [`redacted`] is how such an
//! entry is written down for a person: every sensitive value replaced by a
//! short hash of itself, so what is shown says whether a value changed and
//! never what it is.

use std::path::PathBuf;

use agentsweep_adapter_workspace::command_in_unknown_hidden_home;
use agentsweep_core::host::Host;
use agentsweep_core::item::sha256_hex;
use agentsweep_core::views::{McpView, value_string};
use serde_json::Value;

/// The fields of an MCP entry whose values are credentials rather than
/// configuration.
const SENSITIVE_FIELDS: [&str; 2] = ["env", "headers"];

/// Fills in the facts of an MCP entry that need the machine: where the command
/// lands and what kind of place that is.
///
/// A launcher such as `npx` or `node` is not where the code is; the script it
/// is handed is. So the four location facts hold when the resolved command or
/// any path-shaped argument lands somewhere no real tool is installed, which is
/// how a server that runs `node ~/.dev-utils/index.js` is reported although
/// `node` itself is perfectly ordinary.
pub fn attach_command_facts(view: &mut McpView, host: &Host, base: Option<&std::path::Path>) {
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

/// One MCP entry written down for a person: every sensitive value replaced by a
/// short hash of itself.
///
/// The raw bytes still reach the local Tiers, which is how Rule 0010 finds a
/// plaintext token at all. This is what a Finding, a store and a log are
/// allowed to carry instead.
pub fn redacted(entry: &Value) -> String {
    let mut written = entry.clone();
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
    use serde_json::json;

    fn host() -> Host {
        Host::new(PathBuf::from("/home/u"), vec![PathBuf::from("/src/demo")])
    }

    /// SANDWORM wrote a server into `~/.dev-utils` and launched it with an
    /// ordinary `node`. The location fact has to land on the script.
    #[test]
    fn a_launcher_with_a_script_in_a_hidden_home_directory_is_reported() {
        let entry = json!({"command": "node", "args": ["~/.dev-utils/index.js"]});
        let mut view = McpView::of("dev-utils", &entry);
        attach_command_facts(&mut view, &host(), None);
        assert!(view.command_in_unknown_hidden_home);
        assert!(!view.command_in_temp);
    }

    #[test]
    fn a_command_written_into_a_temporary_directory_is_reported() {
        let entry = json!({"command": "/tmp/.lint/server", "args": ["--stdio"]});
        let mut view = McpView::of("lint", &entry);
        attach_command_facts(&mut view, &host(), None);
        assert_eq!(view.command_resolved, "/tmp/.lint/server");
        assert!(view.command_in_temp);
    }

    #[test]
    fn a_launcher_from_a_known_tool_manager_is_not_reported() {
        let entry = json!({"command": "node", "args": ["~/.nvm/versions/node/v22/lib/server.js"]});
        let mut view = McpView::of("notes", &entry);
        attach_command_facts(&mut view, &host(), None);
        assert!(!view.command_in_unknown_hidden_home);
        assert!(!view.command_in_temp);
        assert!(!view.command_in_downloads);
    }

    #[test]
    fn a_server_downloaded_and_run_from_the_downloads_folder_is_reported() {
        let entry = json!({"command": "/home/u/Downloads/server"});
        let mut view = McpView::of("x", &entry);
        attach_command_facts(&mut view, &host(), None);
        assert!(view.command_in_downloads);
    }

    /// What is written down never carries a credential, and the same value
    /// always writes down the same way so that a change is still visible.
    #[test]
    fn a_redacted_entry_carries_no_value_of_a_sensitive_field() {
        let entry = json!({
            "command": "npx",
            "env": {"TOKEN": "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"},
            "headers": {"Authorization": "Bearer hunter2hunter2"},
        });
        let written = redacted(&entry);
        assert!(!written.contains("ghp_"), "{written}");
        assert!(!written.contains("hunter2"), "{written}");
        assert!(written.contains("sha256:"), "{written}");
        assert!(written.contains("npx"), "{written}");
        assert_eq!(written, redacted(&entry));
        assert_ne!(
            redacted(&entry),
            redacted(&json!({"command": "npx", "env": {"TOKEN": "other"}}))
        );
    }
}
