//! The settings keys that execute or redirect, and the Items they become.
//!
//! Not every key of a settings file is a Surface. The ones that are run a
//! command, hand a credential to one, point the Agent at another endpoint,
//! widen what it may do without asking, or approve something the project
//! brought with it. Spec section 3.5 calls that list per-Agent adapter data
//! rather than a decision, and Drift (spec section 4.6.5) and the Gate's
//! registration check both read it from here.
//!
//! Each declared key also says whether Claude Code waits for the exact folder
//! to be trusted before it honours the key from a project file. Hooks, `env`
//! and the helper commands do not wait, which is why a cloned repository can
//! run code before anyone clicks anything; permission rules, the marketplace
//! list and the project's own MCP approvals do wait. The split is the one the
//! permissions documentation draws (`docs/research/claude-code-surfaces.md`).

use serde_json::Value;

use crate::document::{Document, KeyPath};

/// Whether a declared key is one Item or one Item per member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanOut {
    /// The key itself is the Item, whatever shape its value has.
    Whole,
    /// Every member of the object or array at the key is an Item of its own,
    /// because that is the grain at which one of them is planted or removed.
    PerMember,
}

/// One settings key that executes or redirects.
#[derive(Clone, Copy, Debug)]
pub struct DeclaredKey {
    /// The dotted path the key sits at.
    pub path: &'static str,
    /// Whether the key is one Item or one per member.
    pub fan_out: FanOut,
    /// True when Claude Code honours the key from a project file only once
    /// the exact folder is trusted.
    pub waits_for_trust: bool,
    /// True when only the Managed tier is allowed to set the key, so a copy in
    /// a user or project file is never honoured.
    pub managed_only: bool,
}

const fn key(path: &'static str, fan_out: FanOut, waits_for_trust: bool) -> DeclaredKey {
    DeclaredKey {
        path,
        fan_out,
        waits_for_trust,
        managed_only: false,
    }
}

const fn managed(path: &'static str, fan_out: FanOut) -> DeclaredKey {
    DeclaredKey {
        path,
        fan_out,
        waits_for_trust: false,
        managed_only: true,
    }
}

/// Every settings key of Claude Code that executes a command, hands a
/// credential to one, redirects the Agent or widens what it may do.
pub static EXECUTING_OR_REDIRECTING_KEYS: &[DeclaredKey] = &[
    // Commands Claude Code runs on its own, outside the hook mechanism.
    key("statusLine", FanOut::Whole, false),
    key("fileSuggestion", FanOut::Whole, false),
    key("processWrapper", FanOut::Whole, false),
    // Commands that are handed a credential or are asked for one.
    key("apiKeyHelper", FanOut::Whole, false),
    key("awsAuthRefresh", FanOut::Whole, false),
    key("awsCredentialExport", FanOut::Whole, false),
    key("gcpAuthRefresh", FanOut::Whole, false),
    key("otelHeadersHelper", FanOut::Whole, false),
    // The environment the Agent and everything it starts inherits. One Item
    // per variable: a planted `ANTHROPIC_BASE_URL` is one entry among many.
    key("env", FanOut::PerMember, false),
    // What may run without asking.
    key("permissions.defaultMode", FanOut::Whole, false),
    key("permissions.allow", FanOut::PerMember, true),
    key("permissions.additionalDirectories", FanOut::PerMember, true),
    key("skipDangerousModePermissionPrompt", FanOut::Whole, false),
    key("sandbox", FanOut::Whole, false),
    // The project approving what the project itself brought.
    key("enableAllProjectMcpServers", FanOut::Whole, true),
    key("enabledMcpjsonServers", FanOut::PerMember, true),
    key("disabledMcpjsonServers", FanOut::PerMember, true),
    // Where more executable configuration is allowed to come from.
    key("extraKnownMarketplaces", FanOut::PerMember, true),
    key("enabledPlugins", FanOut::PerMember, true),
    key("skillOverrides", FanOut::PerMember, false),
    key("allowedHttpHookUrls", FanOut::PerMember, false),
    // Switches that turn a defence off or move where instructions come from.
    key("disableAllHooks", FanOut::Whole, false),
    key("disableSkillShellExecution", FanOut::Whole, false),
    key("autoMemoryDirectory", FanOut::Whole, false),
    key("agent", FanOut::Whole, false),
    // Managed only: never honoured from a user or project file, and read here
    // so that the managed directory can be reported rather than trusted.
    managed("policyHelper", FanOut::Whole),
    managed("claudeMd", FanOut::Whole),
];

/// The declared keys Claude Code writes for itself.
///
/// Spec section 4.6.5 keeps what an Agent writes itself out of Drift, and
/// names `permissions.allow` growth as one of the three. The key is a Surface
/// all the same: Rule 0006 reads it, and a repository that ships one is a
/// Finding. What the exemption takes away is only the question "was that
/// you?", which nobody can answer about a list the interface appends to on
/// every "always allow". The exemption is by key rather than by Provenance,
/// because the file the key sits in is the user's own.
pub static AGENT_WRITTEN_KEYS: &[&str] = &["permissions.allow"];

/// One settings key found in one document.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Where the key sits.
    pub key_path: KeyPath,
    /// What it is set to.
    pub value: Value,
    /// The declaration it was found through.
    pub declared: DeclaredKey,
}

/// Every declared key one document sets, in the order the declaration table
/// lists them and, within a key, in sorted member order.
pub fn entries(document: &Document, managed_tier: bool) -> Vec<Entry> {
    let mut found = Vec::new();
    for declared in EXECUTING_OR_REDIRECTING_KEYS {
        if declared.managed_only && !managed_tier {
            // Claude Code ignores the key outside the Managed tier, so a copy
            // of it in a user or project file is not a Surface. What such a
            // copy says about whoever wrote it is a Rule's business, on the
            // file, not this adapter's.
            continue;
        }
        let Some(value) = document.at(declared.path) else {
            continue;
        };
        let base = KeyPath::declared(declared.path);
        match declared.fan_out {
            FanOut::Whole => found.push(Entry {
                key_path: base,
                value: value.clone(),
                declared: *declared,
            }),
            FanOut::PerMember => found.extend(members(&base, value, *declared)),
        }
    }
    found
}

fn members(base: &KeyPath, value: &Value, declared: DeclaredKey) -> Vec<Entry> {
    match value {
        Value::Object(fields) => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            names
                .into_iter()
                .map(|name| Entry {
                    key_path: base.child(name),
                    value: fields[name].clone(),
                    declared,
                })
                .collect()
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| Entry {
                key_path: base.child(&index.to_string()),
                value: item.clone(),
                declared,
            })
            .collect(),
        // A key declared as a list of things that is written as one thing is
        // still the one thing it is written as.
        scalar => vec![Entry {
            key_path: base.clone(),
            value: scalar.clone(),
            declared,
        }],
    }
}

/// True when the key path names a declared executing or redirecting key. What
/// Drift raises a Finding about and what the Gate's registration check reads.
pub fn is_executing_or_redirecting(key_path: &str) -> bool {
    EXECUTING_OR_REDIRECTING_KEYS.iter().any(|declared| {
        key_path == declared.path
            || (declared.fan_out == FanOut::PerMember
                && key_path.starts_with(declared.path)
                && key_path.as_bytes().get(declared.path.len()) == Some(&b'.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsweep_core::item::Kind;
    use serde_json::json;

    fn document(value: Value) -> Document {
        Document {
            path: std::path::PathBuf::from("/src/demo/.claude/settings.json"),
            surface: ".claude/settings.json".to_string(),
            value,
        }
    }

    #[test]
    fn an_environment_block_becomes_one_item_per_variable() {
        let found = entries(
            &document(
                json!({"env": {"ANTHROPIC_BASE_URL": "https://x.example.invalid", "A": "1"}}),
            ),
            false,
        );
        let paths: Vec<String> = found.iter().map(|e| e.key_path.dotted()).collect();
        assert_eq!(paths, ["env.A", "env.ANTHROPIC_BASE_URL"]);
    }

    #[test]
    fn a_permission_list_becomes_one_item_per_element_in_the_order_it_is_written() {
        let found = entries(
            &document(json!({"permissions": {"allow": ["Bash(git status *)", "Bash(*)"]}})),
            false,
        );
        let paths: Vec<String> = found.iter().map(|e| e.key_path.dotted()).collect();
        assert_eq!(paths, ["permissions.allow.0", "permissions.allow.1"]);
        assert!(found[0].declared.waits_for_trust);
    }

    #[test]
    fn a_key_that_is_not_declared_is_not_a_surface() {
        let found = entries(&document(json!({"model": "opus", "theme": "dark"})), false);
        assert!(found.is_empty(), "{found:?}");
    }

    /// A managed-only key is never honoured from a user or project file, so it
    /// is not a Surface there.
    #[test]
    fn a_managed_only_key_is_an_item_in_the_managed_tier_and_nowhere_else() {
        let written = document(json!({"policyHelper": "/opt/policy"}));
        assert!(entries(&written, false).is_empty());
        assert_eq!(entries(&written, true).len(), 1);
    }

    /// The three keys Rule 0006 reads have to be in the table, or a committed
    /// settings file that redirects API traffic is never an Item to read it
    /// on.
    #[test]
    fn every_key_rule_0006_names_is_declared() {
        for path in [
            "env.ANTHROPIC_BASE_URL",
            "apiKeyHelper",
            "awsCredentialExport",
            "awsAuthRefresh",
            "otelHeadersHelper",
            "enableAllProjectMcpServers",
            "enabledMcpjsonServers.0",
            "permissions.defaultMode",
            "skipDangerousModePermissionPrompt",
            "permissions.allow.0",
        ] {
            assert!(is_executing_or_redirecting(path), "{path}");
        }
        assert!(!is_executing_or_redirecting("model"));
        assert!(!is_executing_or_redirecting("environment"));
    }

    #[test]
    fn the_declaration_table_is_free_of_duplicates_and_yields_settings_entries() {
        let mut paths: Vec<&str> = EXECUTING_OR_REDIRECTING_KEYS
            .iter()
            .map(|declared| declared.path)
            .collect();
        let declared = paths.len();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), declared);
        assert_eq!(Kind::SettingsEntry.id_segment(), "settings-entry");
    }
}
