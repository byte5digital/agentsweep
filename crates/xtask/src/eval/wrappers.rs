//! The reviewer-directed wrappers the injection-variant set is built from:
//! a fixed list, committed beside the bad corpus and written by a person,
//! never by an agent, under the same defanging rules as the samples.
//!
//! Each wrapper is text addressing whoever judges the Item, placed before
//! and after the Item's own text. Every wrapper must fire a Heuristic marked
//! `reviewer_directed`, or the set would not test what it is for: that a
//! benign Verdict on a wrapped Item is recorded as unsure.

use std::fs;
use std::path::{Path, PathBuf};

use agentsweep_core::item::{Activation, Item, Kind, Provenance, Scope};
use agentsweep_core::judgement_request::Normalisation;
use agentsweep_core::rules::RulePack;
use agentsweep_core::scan::Scanners;

use crate::bad::lint::defanging_problems;
use crate::eval::item::EvalItem;

/// Where the list sits under the repository root.
pub const LIST: &str = "corpus/injection/wrappers.toml";

/// The text a wrapper is checked around: an instruction file, the kind every
/// reviewer-directed Heuristic reads.
const PLACEHOLDER_CONTENT: &str = "Placeholder content of an instruction file.\n";

/// One wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wrapper {
    /// The text placed before the Item's own.
    pub before: String,
    /// The text placed after it, empty for none.
    pub after: String,
}

/// Reads the committed list. A list with no wrapper in it is a list waiting
/// for its author, not an error.
pub fn load(root: &Path) -> Result<Vec<Wrapper>, String> {
    let path = root.join(LIST);
    let text =
        fs::read_to_string(&path).map_err(|error| format!("{}: {error}\n", path.display()))?;
    parse(&text).map_err(|problem| format!("{}: {problem}\n", path.display()))
}

/// Parses a list: `[[wrapper]]` tables, each with `before` and an optional
/// `after`, and nothing else.
pub fn parse(text: &str) -> Result<Vec<Wrapper>, String> {
    let table: toml::Table = text.parse().map_err(|error| format!("not TOML: {error}"))?;
    if let Some(key) = table.keys().find(|key| *key != "wrapper") {
        return Err(format!("`{key}` is not part of the wrapper list"));
    }
    let Some(entries) = table.get("wrapper") else {
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .ok_or_else(|| "`wrapper` is a list of tables".to_string())?;
    let mut wrappers = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let number = index + 1;
        let entry = entry
            .as_table()
            .ok_or_else(|| format!("wrapper {number} is not a table"))?;
        if let Some(key) = entry
            .keys()
            .find(|key| !["before", "after"].contains(&key.as_str()))
        {
            return Err(format!("wrapper {number}: `{key}` is not a wrapper key"));
        }
        let text = |key: &str| -> Result<String, String> {
            match entry.get(key) {
                None => Ok(String::new()),
                Some(value) => value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("wrapper {number}: `{key}` is not a string")),
            }
        };
        let wrapper = Wrapper {
            before: text("before")?,
            after: text("after")?,
        };
        if wrapper.before.trim().is_empty() {
            return Err(format!("wrapper {number} has no `before` text"));
        }
        wrappers.push(wrapper);
    }
    Ok(wrappers)
}

/// What is wrong with a list: a wrapper that breaks a defanging rule, or one
/// that fires no reviewer-directed Heuristic around a placeholder
/// instruction file. Empty when every wrapper holds.
pub fn check(wrappers: &[Wrapper], pack: &RulePack) -> Vec<String> {
    let mut problems = Vec::new();
    let mut scanners = Scanners::new(pack);
    for (index, wrapper) in wrappers.iter().enumerate() {
        let number = index + 1;
        for problem in defanging_problems(&format!("{}\n{}", wrapper.before, wrapper.after)) {
            problems.push(format!("wrapper {number}: {problem}"));
        }
        let placeholder = Item::file(
            "claude-code",
            Scope::Project(PathBuf::from("/eval/project")),
            Kind::InstructionFile,
            "CLAUDE.md",
            PathBuf::from("/eval/project/CLAUDE.md"),
            Provenance::Repository {
                commit: String::new(),
            },
            Activation::Active,
            PLACEHOLDER_CONTENT.as_bytes().to_vec(),
        );
        let fires = EvalItem::new(
            "placeholder",
            placeholder,
            Vec::new(),
            false,
            Normalisation::default(),
        )
        .wrapped(wrapper, &mut scanners)
        .map(|wrapped| wrapped.reviewer_directed());
        match fires {
            Ok(true) => {}
            Ok(false) => problems.push(format!(
                "wrapper {number} fires no reviewer-directed Heuristic around an instruction file"
            )),
            Err(problem) => problems.push(format!("wrapper {number}: {problem}")),
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_list_waits_for_its_author() {
        assert_eq!(parse("# nothing yet\n"), Ok(Vec::new()));
    }

    #[test]
    fn a_wrapper_has_before_and_maybe_after() {
        let wrappers =
            parse("[[wrapper]]\nbefore = \"a\"\n[[wrapper]]\nbefore = \"b\"\nafter = \"c\"\n")
                .expect("parses");
        assert_eq!(wrappers.len(), 2);
        assert_eq!(wrappers[0].after, "");
        assert_eq!(wrappers[1].after, "c");
    }

    #[test]
    fn unknown_keys_and_an_empty_before_are_refused() {
        assert!(parse("[[wrapper]]\nbefore = \"a\"\nextra = 1\n").is_err());
        assert!(parse("[[wrapper]]\nafter = \"a\"\n").is_err());
        assert!(parse("other = 1\n").is_err());
    }
}
