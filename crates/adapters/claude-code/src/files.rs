//! The Surfaces that are one file: instruction files, rule files, output
//! styles, the Agent's own memory, subagent definitions and workflows.
//!
//! What they have in common is that Claude Code reads the file itself. An
//! instruction file and a rule file are injected as prose, an output style
//! replaces the task instructions, a memory file is written by the Agent and
//! injected every session, a subagent definition carries tools and a
//! permission mode, and a workflow is a script that runs as a slash command.
//! Only the subagent has a parsed view; Rules on the others are byte Rules
//! (`rules/README.md`).

use std::path::Path;

use agentsweep_core::adapter::Enumeration;
use agentsweep_core::host::Host;
use agentsweep_core::item::Kind;
use agentsweep_core::views::{ParsedView, SubagentView};

use crate::tree::{self, Placement};

/// The suffix of every file Claude Code reads as prose.
const MARKDOWN: [&str; 1] = [".md"];

/// The suffix of a workflow, which is a script rather than prose.
const WORKFLOW: [&str; 1] = [".js"];

/// One instruction file at a path that is known in advance, such as the
/// `CLAUDE.md` of a project root. A file that is not there is not a Problem:
/// nobody has to have one.
pub fn instruction_file(
    host: &Host,
    placement: &Placement,
    path: &Path,
    enumeration: &mut Enumeration,
) {
    let Some(result) = tree::file(host, placement, Kind::InstructionFile, path) else {
        return;
    };
    match result {
        Ok(item) => enumeration.items.push(item),
        Err(problem) => enumeration.problems.push(problem),
    }
}

/// Every instruction file one directory holds: the rules directory, the output
/// styles and the Agent's own memory. The rules directory is walked all the way
/// down, because a rule file may sit in a subdirectory of it.
pub fn instruction_files_in(
    host: &Host,
    placement: &Placement,
    directory: &Path,
    recursive: bool,
    enumeration: &mut Enumeration,
) {
    for path in tree::files_in(host, directory, &MARKDOWN, recursive) {
        instruction_file(host, placement, &path, enumeration);
    }
}

/// Every subagent definition one agents directory holds. The user's is walked
/// all the way down; a definition carries the tools, the permission mode and
/// the inline MCP servers the subagent may start.
pub fn subagents_in(
    host: &Host,
    placement: &Placement,
    directory: &Path,
    enumeration: &mut Enumeration,
) {
    for path in tree::files_in(host, directory, &MARKDOWN, true) {
        let Some(result) = tree::file(host, placement, Kind::Subagent, &path) else {
            continue;
        };
        match result {
            Ok(item) => {
                let name = path.file_stem().unwrap_or_default().to_string_lossy();
                let view = SubagentView::of(&name, &item.content);
                enumeration
                    .items
                    .push(item.with_view(ParsedView::Subagent(view)));
            }
            Err(problem) => enumeration.problems.push(problem),
        }
    }
}

/// Every workflow one workflows directory holds. A workflow is JavaScript that
/// runs when someone types its name, so the file itself is the Surface.
pub fn workflows_in(
    host: &Host,
    placement: &Placement,
    directory: &Path,
    enumeration: &mut Enumeration,
) {
    for path in tree::files_in(host, directory, &WORKFLOW, false) {
        let Some(result) = tree::file(host, placement, Kind::Workflow, &path) else {
            continue;
        };
        match result {
            Ok(item) => enumeration.items.push(item),
            Err(problem) => enumeration.problems.push(problem),
        }
    }
}
