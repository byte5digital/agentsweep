//! The Gate's verdict, worked out from the facts the state file keeps (spec
//! sections 7.1 and 7.3).
//!
//! Nothing here scans, reads a Surface, opens or stats a file, consults `PATH`
//! or waits for a running Scan: the answer comes from the pooled project roots
//! and the Gate facts of the open Threat Findings alone, which every Scan
//! writes (ticket 37's [`agentsweep_core::gate_facts`]).
//!
//! What blocks:
//!
//! - On a turn, the project `cwd` resolves to (the deepest pooled root that is
//!   `cwd` or lies above it) while it has an open Threat Finding on a
//!   Project-scope Item; that check alone needs a pooled root.
//! - On a turn, wherever `cwd` is, one of the Agent's User-scope instruction
//!   files with an open Threat Finding.
//! - On any event, wherever `cwd` is, a User-scope Item with an open Threat
//!   Finding that the request names: by skill name, by MCP server name and
//!   source (the name alone when no source is given), or by a path token that
//!   resolves to inside a skill's or a plugin's tree or onto a Hook's script.
//!
//! A path token resolves lexically: absolute as written, `~/` against the
//! home, anything else joined to `cwd`, with `.` and `..` folded. A bare name
//! therefore counts only when joining it to `cwd` lands on a flagged place,
//! and never by its file name alone.
//!
//! The answer is `unknown` when the facts are unavailable, and when `cwd` is
//! under no pooled root and no User-scope check applies.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use agentsweep_core::finding::FindingId;
use agentsweep_core::gate_facts::{GateFacts, GateRecord};
use agentsweep_core::item::{Invoked, Kind};
use agentsweep_ipc::gate::{GateReason, GateRequest, GateTool, GateVerdict};

/// The Gate's verdict on one request.
///
/// `record` is what the state file holds for the Gate, absent when no Full
/// Scan of this version has written it; `open_threats` are the open Threat
/// Findings the state holds, the only ones whose facts count; `home` is the
/// home a `~/` token resolves against.
pub fn verdict(
    record: Option<&GateRecord>,
    open_threats: &BTreeSet<FindingId>,
    request: &GateRequest,
    home: &Path,
) -> GateVerdict {
    let Some(record) = record else {
        return GateVerdict::Unknown;
    };
    let facts: Vec<&GateFacts> = record
        .facts
        .iter()
        .filter(|(id, _)| open_threats.contains(id))
        .map(|(_, facts)| facts)
        .collect();
    let cwd = Path::new(&request.cwd);
    let cwd = cwd.is_absolute().then(|| fold(cwd));
    let project = cwd
        .as_deref()
        .and_then(|cwd| project_of(&record.roots, cwd));

    if request.event.is_turn() {
        if let Some(root) = &project {
            let count = facts
                .iter()
                .filter(|facts| facts.scope == "project")
                .filter(|facts| facts.project_root.as_deref().map(fold).as_ref() == Some(root))
                .count();
            if count > 0 {
                return GateVerdict::Block {
                    count,
                    reason: GateReason::Project,
                };
            }
        }
        let count = facts
            .iter()
            .filter(|facts| facts.user_instruction_file && facts.agent == request.agent)
            .count();
        if count > 0 {
            return GateVerdict::Block {
                count,
                reason: GateReason::UserInstructions,
            };
        }
    }

    if let Some(tool) = &request.tool {
        let tokens: Vec<PathBuf> = tool
            .paths
            .iter()
            .filter_map(|token| resolve(token, cwd.as_deref(), home))
            .collect();
        let count = facts
            .iter()
            .filter(|facts| facts.scope == "user")
            .filter(|facts| {
                named(facts, tool, &request.agent)
                    || tokens.iter().any(|token| inside(facts, token))
            })
            .count();
        if count > 0 {
            return GateVerdict::Block {
                count,
                reason: GateReason::Item,
            };
        }
    }

    match project {
        Some(_) => GateVerdict::Clear,
        None => GateVerdict::Unknown,
    }
}

/// The deepest pooled root that is `cwd` or lies above it.
fn project_of(roots: &[PathBuf], cwd: &Path) -> Option<PathBuf> {
    roots
        .iter()
        .map(|root| fold(root))
        .filter(|root| cwd.starts_with(root))
        .max_by_key(|root| root.components().count())
}

/// True when the request names the Item by one of the names its Agent
/// invokes it by. Names belong to one Agent, so only that Agent's Items
/// match.
fn named(facts: &GateFacts, tool: &GateTool, agent: &str) -> bool {
    if facts.agent != agent {
        return false;
    }
    let skills: Vec<&str> = tool
        .skill
        .iter()
        .chain(tool.skills.iter())
        .map(|name| name.strip_prefix('$').unwrap_or(name))
        .filter(|name| !name.is_empty())
        .collect();
    facts
        .names
        .iter()
        .any(|invocation| match invocation.invoked {
            Invoked::Skill => skills.contains(&invocation.name.as_str()),
            Invoked::McpServer => tool.mcp_server.as_ref().is_some_and(|server| {
                server.name == invocation.name
                    && server
                        .source
                        .as_deref()
                        .is_none_or(|source| source == invocation.source)
            }),
        })
}

/// True when a resolved path token lies inside the Item's tree, or is the
/// script a Hook entry runs. Only a skill's and a plugin's trees and a Hook's
/// script are places a shell command runs a flagged Item from (spec section
/// 7.1); a token naming a config file that holds a flagged entry names the
/// file, not the entry.
fn inside(facts: &GateFacts, token: &Path) -> bool {
    match facts.kind {
        Kind::Skill | Kind::Plugin => std::iter::once(&facts.path)
            .chain(facts.resolved.iter())
            .any(|place| token.starts_with(fold(place))),
        Kind::Hook => facts
            .script
            .as_ref()
            .is_some_and(|script| fold(script) == token),
        _ => false,
    }
}

/// Where a path token points, lexically: absolute as written, `~` and `~/`
/// against the home, anything else joined to `cwd`. Nothing is opened or
/// stat'ed. A relative token with no absolute `cwd` points nowhere.
fn resolve(token: &str, cwd: Option<&Path>, home: &Path) -> Option<PathBuf> {
    if token.is_empty() {
        return None;
    }
    let joined = if token == "~" {
        home.to_path_buf()
    } else if let Some(rest) = token.strip_prefix("~/") {
        home.join(rest)
    } else if Path::new(token).is_absolute() {
        PathBuf::from(token)
    } else {
        cwd?.join(token)
    };
    Some(fold(&joined))
}

/// The path with `.` dropped and every `..` folded into its parent, without
/// touching the disk.
fn fold(path: &Path) -> PathBuf {
    let mut folded = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                folded.pop();
            }
            other => folded.push(other.as_os_str()),
        }
    }
    folded
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsweep_core::item::Invocation;
    use agentsweep_ipc::gate::{GateEvent, McpServerRef};

    const HOME: &str = "/home/u";

    fn user(kind: Kind, path: &str) -> GateFacts {
        GateFacts {
            agent: "claude-code".to_string(),
            scope: "user".to_string(),
            project_root: None,
            kind,
            user_instruction_file: false,
            path: PathBuf::from(path),
            resolved: None,
            script: None,
            names: Vec::new(),
        }
    }

    fn record(facts: Vec<GateFacts>) -> (GateRecord, BTreeSet<FindingId>) {
        let mut record = GateRecord {
            roots: vec![PathBuf::from("/work/one"), PathBuf::from("/work/one/inner")],
            ..GateRecord::default()
        };
        let mut open = BTreeSet::new();
        for (n, facts) in facts.into_iter().enumerate() {
            let id = FindingId::from_recorded(&format!("finding-{n}"));
            open.insert(id.clone());
            record.facts.insert(id, facts);
        }
        (record, open)
    }

    fn request(event: GateEvent, cwd: &str, tool: Option<GateTool>) -> GateRequest {
        GateRequest {
            agent: "claude-code".to_string(),
            event,
            cwd: cwd.to_string(),
            tool,
        }
    }

    fn call(cwd: &str, tool: GateTool) -> GateRequest {
        request(GateEvent::PreToolUse, cwd, Some(tool))
    }

    fn tokens(paths: &[&str]) -> GateTool {
        GateTool {
            name: Some("Bash".to_string()),
            paths: paths.iter().map(|path| path.to_string()).collect(),
            ..GateTool::default()
        }
    }

    fn ask(facts: Vec<GateFacts>, request: &GateRequest) -> GateVerdict {
        let (record, open) = record(facts);
        verdict(Some(&record), &open, request, Path::new(HOME))
    }

    fn block(count: usize, reason: GateReason) -> GateVerdict {
        GateVerdict::Block { count, reason }
    }

    #[test]
    fn no_facts_is_unknown_and_nothing_flagged_under_a_root_is_clear() {
        let turn = request(GateEvent::UserPromptSubmit, "/work/one/src", None);
        let open = BTreeSet::new();
        assert_eq!(
            verdict(None, &open, &turn, Path::new(HOME)),
            GateVerdict::Unknown
        );
        assert_eq!(ask(Vec::new(), &turn), GateVerdict::Clear);
        let elsewhere = request(GateEvent::UserPromptSubmit, "/tmp/x", None);
        assert_eq!(ask(Vec::new(), &elsewhere), GateVerdict::Unknown);
        let relative = request(GateEvent::UserPromptSubmit, "work/one", None);
        assert_eq!(ask(Vec::new(), &relative), GateVerdict::Unknown);
    }

    #[test]
    fn a_turn_resolves_to_the_deepest_pooled_root_and_counts_its_findings() {
        let mut outer = user(Kind::InstructionFile, "/work/one/CLAUDE.md");
        outer.scope = "project".to_string();
        outer.project_root = Some(PathBuf::from("/work/one"));
        let mut second = outer.clone();
        second.path = PathBuf::from("/work/one/AGENTS.md");
        second.agent = "codex".to_string();
        let turn = |cwd: &str| request(GateEvent::UserPromptSubmit, cwd, None);
        // Any Agent's Project-scope Item blocks the project.
        assert_eq!(
            ask(
                vec![outer.clone(), second.clone()],
                &turn("/work/one/src/./deep/..")
            ),
            block(2, GateReason::Project)
        );
        // The inner project is its own project.
        assert_eq!(
            ask(vec![outer.clone(), second], &turn("/work/one/inner/x")),
            GateVerdict::Clear
        );
        // A tool call is never blocked by the project.
        assert_eq!(
            ask(vec![outer.clone()], &call("/work/one", GateTool::default())),
            GateVerdict::Clear
        );
        // Nor is the expansion of a skill.
        assert_eq!(
            ask(
                vec![outer],
                &request(GateEvent::UserPromptExpansion, "/work/one", None)
            ),
            GateVerdict::Clear
        );
    }

    #[test]
    fn a_users_own_instruction_file_blocks_every_turn_of_its_agent_wherever_cwd_is() {
        let mut instructions = user(Kind::InstructionFile, "/home/u/.claude/CLAUDE.md");
        instructions.user_instruction_file = true;
        for cwd in ["/work/one", "/tmp/elsewhere"] {
            assert_eq!(
                ask(
                    vec![instructions.clone()],
                    &request(GateEvent::UserPromptSubmit, cwd, None)
                ),
                block(1, GateReason::UserInstructions),
                "{cwd}"
            );
        }
        let mut codex = request(GateEvent::UserPromptSubmit, "/work/one", None);
        codex.agent = "codex".to_string();
        assert_eq!(ask(vec![instructions.clone()], &codex), GateVerdict::Clear);
        // A flagged User-scope skill does not block a turn.
        let mut skill = user(Kind::Skill, "/home/u/.claude/skills/setup");
        skill.names = vec![Invocation::skill("setup")];
        assert_eq!(
            ask(
                vec![skill],
                &request(GateEvent::UserPromptSubmit, "/work/one", None)
            ),
            GateVerdict::Clear
        );
    }

    #[test]
    fn a_call_names_a_flagged_skill_or_server_by_the_names_its_agent_uses() {
        let mut skill = user(Kind::Skill, "/home/u/.claude/skills/setup");
        skill.names = vec![Invocation::skill("setup")];
        let mut server = user(Kind::McpServer, "/home/u/.claude.json");
        server.names = vec![Invocation::mcp_server("tracker", "user")];
        let flagged = vec![skill, server];
        let by_skill = GateTool {
            skill: Some("setup".to_string()),
            ..GateTool::default()
        };
        assert_eq!(
            ask(flagged.clone(), &call("/tmp/x", by_skill.clone())),
            block(1, GateReason::Item)
        );
        // Another Agent's skill of the same name is another skill.
        let mut codex = call("/work/one", by_skill);
        codex.agent = "codex".to_string();
        assert_eq!(ask(flagged.clone(), &codex), GateVerdict::Clear);
        // Skill names extracted from a prompt, as a `$name` mention spells them.
        let extracted = GateTool {
            skills: vec!["other".to_string(), "$setup".to_string()],
            ..GateTool::default()
        };
        assert_eq!(
            ask(
                flagged.clone(),
                &request(GateEvent::UserPromptSubmit, "/work/one", Some(extracted))
            ),
            block(1, GateReason::Item)
        );
        let server_call = |source: Option<&str>| GateTool {
            name: Some("mcp__tracker__list".to_string()),
            mcp_server: Some(McpServerRef {
                name: "tracker".to_string(),
                source: source.map(str::to_string),
            }),
            ..GateTool::default()
        };
        for source in [Some("user"), None] {
            assert_eq!(
                ask(flagged.clone(), &call("/work/one", server_call(source))),
                block(1, GateReason::Item),
                "{source:?}"
            );
        }
        assert_eq!(
            ask(flagged, &call("/work/one", server_call(Some("project")))),
            GateVerdict::Clear
        );
    }

    #[test]
    fn a_path_token_blocks_inside_a_flagged_tree_or_on_a_flagged_script() {
        let skill = user(Kind::Skill, "/home/u/.claude/skills/setup");
        let mut linked = user(Kind::Skill, "/home/u/.claude/skills/linked");
        linked.resolved = Some(PathBuf::from("/home/u/.agents/skills/linked"));
        let plugin = user(Kind::Plugin, "/home/u/.claude/plugins/cache/m/p/1.0");
        let mut hook = user(Kind::Hook, "/home/u/.claude/settings.json");
        hook.script = Some(PathBuf::from("/home/u/.claude/hooks/guard.sh"));
        let flagged = vec![skill, linked, plugin, hook];
        let blocked = |cwd: &str, token: &str| ask(flagged.clone(), &call(cwd, tokens(&[token])));
        for (cwd, token) in [
            ("/work/one", "/home/u/.claude/skills/setup/scripts/run.sh"),
            ("/work/one", "~/.claude/skills/setup/scripts/run.sh"),
            ("/home/u/.claude/skills", "./setup/scripts/run.sh"),
            ("/home/u/.claude/skills/setup/scripts", "run.sh"),
            ("/work/one", "../../home/u/.claude/skills/setup/x"),
            ("/work/one", "/home/u/.agents/skills/linked/scripts/a.sh"),
            (
                "/work/one",
                "/home/u/.claude/plugins/cache/m/p/1.0/bin/tool",
            ),
            ("/tmp/x", "~/.claude/hooks/guard.sh"),
            ("/home/u/.claude/hooks", "guard.sh"),
        ] {
            assert_eq!(
                blocked(cwd, token),
                block(1, GateReason::Item),
                "{token} in {cwd}"
            );
        }
        for (cwd, token) in [
            // A bare command name equal to a flagged script's file name.
            ("/work/one", "guard.sh"),
            ("/work/one", "run.sh"),
            // A sibling whose name only starts like the tree.
            ("/work/one", "/home/u/.claude/skills/setup-two/x"),
            // The settings file a flagged Hook entry is written in.
            ("/work/one", "~/.claude/settings.json"),
        ] {
            assert_eq!(blocked(cwd, token), GateVerdict::Clear, "{token} in {cwd}");
        }
        // Path tokens match whichever Agent's Item they point into.
        let mut codex = call("/work/one", tokens(&["~/.claude/hooks/guard.sh"]));
        codex.agent = "codex".to_string();
        assert_eq!(ask(flagged, &codex), block(1, GateReason::Item));
    }

    #[test]
    fn only_user_scope_items_block_a_call_and_only_open_threats_count() {
        let mut project_skill = user(Kind::Skill, "/work/one/.claude/skills/x");
        project_skill.scope = "project".to_string();
        project_skill.project_root = Some(PathBuf::from("/work/one"));
        project_skill.names = vec![Invocation::skill("x")];
        let by_name = GateTool {
            skill: Some("x".to_string()),
            ..GateTool::default()
        };
        assert_eq!(
            ask(
                vec![project_skill.clone()],
                &call("/tmp/x", by_name.clone())
            ),
            GateVerdict::Unknown
        );
        // Facts whose Finding is no longer an open Threat Finding count for
        // nothing.
        let (record, _) = record(vec![user(Kind::Skill, "/home/u/.claude/skills/x")]);
        let gone = BTreeSet::new();
        assert_eq!(
            verdict(
                Some(&record),
                &gone,
                &call("/work/one", tokens(&["~/.claude/skills/x/run.sh"])),
                Path::new(HOME)
            ),
            GateVerdict::Clear
        );
    }

    #[test]
    fn the_project_check_comes_first_then_the_instruction_files_then_the_item() {
        let mut project = user(Kind::InstructionFile, "/work/one/CLAUDE.md");
        project.scope = "project".to_string();
        project.project_root = Some(PathBuf::from("/work/one"));
        let mut instructions = user(Kind::InstructionFile, "/home/u/.claude/CLAUDE.md");
        instructions.user_instruction_file = true;
        let mut skill = user(Kind::Skill, "/home/u/.claude/skills/setup");
        skill.names = vec![Invocation::skill("setup")];
        let extracted = Some(GateTool {
            skills: vec!["setup".to_string()],
            ..GateTool::default()
        });
        let turn = request(GateEvent::UserPromptSubmit, "/work/one", extracted);
        assert_eq!(
            ask(vec![project, instructions.clone(), skill.clone()], &turn),
            block(1, GateReason::Project)
        );
        assert_eq!(
            ask(vec![instructions, skill.clone()], &turn),
            block(1, GateReason::UserInstructions)
        );
        assert_eq!(ask(vec![skill], &turn), block(1, GateReason::Item));
    }
}
