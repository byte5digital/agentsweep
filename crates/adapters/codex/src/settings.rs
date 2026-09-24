//! The Codex config keys that execute or redirect, and the Items they become.
//!
//! Spec section 3.5 calls this list per-Agent adapter data rather than a
//! decision: it is read off the surface inventory in
//! `docs/research/codex-surfaces.md`. Drift (spec section 4.6.5) and the Gate's
//! registration check (spec section 7.6) both read it from here, and so does
//! the Rule tier, through the `settings` view.
//!
//! Two of the declared keys are Codex's own bookkeeping rather than a Surface
//! of its own. `[projects."<path>"]` is the trust table and `[hooks.state.…]`
//! is the hook trust pin; both are written by Codex, both are read here to
//! compute Activation, the registered flag and the project list, and neither
//! becomes an Item, the same way Claude Code's `~/.claude.json` project
//! records do not. They stay in the table because Drift and the Gate ask it
//! whether a key executes or redirects, not whether it is an Item.
//!
//! Each declared key also says whether a project layer is allowed to set it at
//! all: Codex strips a fixed list of provider, auth, notify, profile and
//! telemetry keys out of `<dir>/.codex/config.toml` with a startup warning,
//! and a key that was stripped would not be loaded whatever else is true of
//! it.

use serde_json::Value;

use crate::document::{Document, KeyPath};

/// Whether a declared key is one Item, one per member, or one per field of
/// each member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanOut {
    /// The key itself is the Item, whatever shape its value has.
    Whole,
    /// Every member of the table or array at the key is an Item of its own,
    /// because that is the grain at which one of them is planted or removed.
    PerMember,
    /// Every field of every member is an Item: `model_providers.<id>.base_url`
    /// is the thing that redirects, not the provider table around it.
    PerMemberField,
}

/// One Codex config key that executes or redirects.
#[derive(Clone, Copy, Debug)]
pub struct DeclaredKey {
    /// The dotted path the key sits at.
    pub path: &'static str,
    /// Whether the key is one Item, one per member or one per field.
    pub fan_out: FanOut,
    /// True when a project layer may never set the key: Codex strips it and
    /// names it in a startup warning, so a project copy is never loaded.
    pub project_denied: bool,
    /// True when the key is Codex's own record rather than a Surface of its
    /// own. It is read for Activation and never yielded as an Item.
    pub agent_record: bool,
}

const fn key(path: &'static str, fan_out: FanOut) -> DeclaredKey {
    DeclaredKey {
        path,
        fan_out,
        project_denied: false,
        agent_record: false,
    }
}

/// A key a project layer may never set (`loader/mod.rs:76-93`).
const fn denied(path: &'static str, fan_out: FanOut) -> DeclaredKey {
    DeclaredKey {
        path,
        fan_out,
        project_denied: true,
        agent_record: false,
    }
}

/// A key Codex writes for itself: read for Activation, never an Item.
const fn record(path: &'static str, fan_out: FanOut) -> DeclaredKey {
    DeclaredKey {
        path,
        fan_out,
        project_denied: false,
        agent_record: true,
    }
}

/// Every Codex config key that executes a command, hands a credential to one,
/// redirects the Agent, widens what it may do or moves where its instructions
/// come from.
pub static EXECUTING_OR_REDIRECTING_KEYS: &[DeclaredKey] = &[
    // Commands Codex runs on its own, outside the hook mechanism.
    denied("notify", FanOut::Whole),
    key("desktop.custom_file_handlers", FanOut::PerMemberField),
    // Where the model traffic goes and which credential goes with it. A
    // provider's `auth.command` is a token-fetching subprocess, so the
    // provider table fans out to its fields.
    denied("model_providers", FanOut::PerMemberField),
    denied("model_provider", FanOut::Whole),
    denied("openai_base_url", FanOut::Whole),
    denied("chatgpt_base_url", FanOut::Whole),
    denied("otel", FanOut::Whole),
    // What may run without asking, and what holds it back.
    key("approval_policy", FanOut::Whole),
    key("approvals_reviewer", FanOut::Whole),
    key("sandbox_mode", FanOut::Whole),
    key("sandbox_workspace_write", FanOut::PerMember),
    key("default_permissions", FanOut::Whole),
    key("permissions", FanOut::PerMember),
    // The environment every shell tool call inherits.
    key("shell_environment_policy", FanOut::PerMember),
    // The feature switches, `hooks` above all: one of them turns a whole
    // defence off from any enabled layer, a trusted project's included.
    key("features", FanOut::PerMember),
    // Where more executable configuration is allowed to come from.
    key("plugins", FanOut::PerMember),
    key("marketplaces", FanOut::PerMember),
    key("skills.config", FanOut::PerMember),
    key("skills.bundled.enabled", FanOut::Whole),
    key("skills.include_instructions", FanOut::Whole),
    key("agents", FanOut::PerMemberField),
    // Where the instructions come from.
    key("model_instructions_file", FanOut::Whole),
    key("developer_instructions", FanOut::Whole),
    key("compact_prompt", FanOut::Whole),
    key("experimental_compact_prompt_file", FanOut::Whole),
    key("project_doc_fallback_filenames", FanOut::Whole),
    key("project_root_markers", FanOut::Whole),
    // Administrator only, in `requirements.toml`: they take hooks and the
    // user's own execution policy away.
    key("allow_managed_hooks_only", FanOut::Whole),
    key("ignore_user_and_project_exec_policy_rules", FanOut::Whole),
    // Codex's own records. Read for Activation, never an Item.
    record("projects", FanOut::PerMember),
    record("hooks.state", FanOut::PerMember),
];

/// The declared keys Codex writes for itself.
///
/// Both of them are `record` keys above, so neither is ever an Item and
/// neither can raise a Drift Finding in the first place. They are named here
/// as well because the exemption of spec section 4.6.5 is by key, and a later
/// slice that does yield one of them as an Item must not start asking about
/// what the Agent wrote itself.
pub static AGENT_WRITTEN_KEYS: &[&str] = &["hooks.state", "projects"];

/// One config key found in one document.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Where the key sits.
    pub key_path: KeyPath,
    /// What it is set to.
    pub value: Value,
    /// The declaration it was found through.
    pub declared: DeclaredKey,
}

/// Every declared key one document sets that is an Item, in the order the
/// declaration table lists them and, within a key, in sorted member order.
pub fn entries(document: &Document) -> Vec<Entry> {
    let mut found = Vec::new();
    for declared in EXECUTING_OR_REDIRECTING_KEYS {
        if declared.agent_record {
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
            FanOut::PerMemberField => {
                for member in members(&base, value, *declared) {
                    let fields = members(&member.key_path, &member.value, *declared);
                    if fields.is_empty() {
                        found.push(member);
                    } else {
                        found.extend(fields);
                    }
                }
            }
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
        // A key declared as a table of things that is written as one thing is
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
            || (declared.fan_out != FanOut::Whole
                && key_path.starts_with(declared.path)
                && key_path.as_bytes().get(declared.path.len()) == Some(&b'.'))
    })
}

/// True when a project layer may never set this key, so Codex would strip it.
pub fn denied_in_a_project(key_path: &str) -> bool {
    EXECUTING_OR_REDIRECTING_KEYS
        .iter()
        .filter(|declared| declared.project_denied)
        .any(|declared| {
            key_path == declared.path
                || (key_path.starts_with(declared.path)
                    && key_path.as_bytes().get(declared.path.len()) == Some(&b'.'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::Document;
    use serde_json::json;

    fn document(value: Value) -> Document {
        Document::inline(
            std::path::PathBuf::from("/home/u/.codex/config.toml"),
            "~/.codex/config.toml".to_string(),
            value,
        )
    }

    #[test]
    fn a_provider_table_becomes_one_item_per_field_that_redirects() {
        let found = entries(&document(json!({"model_providers": {
            "proxy": {"base_url": "https://proxy.example.invalid/v1", "env_key": "PROXY_KEY"}
        }})));
        let paths: Vec<String> = found.iter().map(|e| e.key_path.dotted()).collect();
        assert_eq!(
            paths,
            [
                "model_providers.proxy.base_url",
                "model_providers.proxy.env_key"
            ]
        );
    }

    #[test]
    fn the_feature_switches_become_one_item_each() {
        let found = entries(&document(
            json!({"features": {"hooks": false, "apps": true}}),
        ));
        let paths: Vec<String> = found.iter().map(|e| e.key_path.dotted()).collect();
        assert_eq!(paths, ["features.apps", "features.hooks"]);
    }

    /// The trust table and the hook pins are Codex's own record of what the
    /// user accepted. They decide Activation and are never Items themselves,
    /// and their keys carry absolute paths that must not reach a content hash.
    #[test]
    fn codexs_own_records_are_read_but_never_yielded() {
        let written = document(json!({
            "projects": {"/Users/u/demo": {"trust_level": "trusted"}},
            "hooks": {"state": {"/Users/u/.codex/hooks.json:session_start:0:0": {
                "trusted_hash": "sha256:00"
            }}},
        }));
        assert!(entries(&written).is_empty(), "{:?}", entries(&written));
        assert!(is_executing_or_redirecting("projects./Users/u/demo"));
        assert!(is_executing_or_redirecting("hooks.state.x"));
    }

    #[test]
    fn a_key_that_is_not_declared_is_not_a_surface() {
        let found = entries(&document(json!({"model": "gpt", "tui": {"theme": "dark"}})));
        assert!(found.is_empty(), "{found:?}");
    }

    /// The keys Rules 0006 and 0019 read have to be in the table, or a Codex
    /// config that turns the approvals off is never an Item to read them on.
    #[test]
    fn every_key_the_v1_rules_name_is_declared() {
        for path in [
            "approval_policy",
            "sandbox_mode",
            "notify",
            "model_providers.proxy.base_url",
            "model_providers.proxy.env_key",
            "model_providers.proxy.auth",
            "features.hooks",
        ] {
            assert!(is_executing_or_redirecting(path), "{path}");
        }
        assert!(!is_executing_or_redirecting("model"));
        assert!(!is_executing_or_redirecting("approval_policy_extra"));
    }

    /// Codex strips the provider, notify and telemetry keys out of a project
    /// layer, so a project copy of one is never loaded.
    #[test]
    fn the_project_layer_denylist_is_the_one_codex_strips() {
        for path in [
            "notify",
            "model_providers.proxy.base_url",
            "otel",
            "chatgpt_base_url",
        ] {
            assert!(denied_in_a_project(path), "{path}");
        }
        for path in ["approval_policy", "sandbox_mode", "features.hooks"] {
            assert!(!denied_in_a_project(path), "{path}");
        }
    }

    #[test]
    fn the_declaration_table_is_free_of_duplicates() {
        let mut paths: Vec<&str> = EXECUTING_OR_REDIRECTING_KEYS
            .iter()
            .map(|declared| declared.path)
            .collect();
        let declared = paths.len();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), declared);
    }
}
