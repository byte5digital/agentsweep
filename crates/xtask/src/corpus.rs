//! The corpus runner.
//!
//! It walks the `rules/` tree, loads every Fixture of every Rule and scans it
//! with the facts its `item.toml` states, then checks that exactly the Rule
//! ids in `expect.fire` fired and, for a tree, that they fired on the files
//! `expect.files` names. A Fixture under `bad/` must fire its own Rule; a
//! Fixture under `good/` is a near miss and must fire nothing at all.
//!
//! Every failure names the Fixture and the Rule ids involved, because that is
//! what a rule author needs to see when a new pattern reaches too far.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use agentsweep_core::rules::RulePack;
use agentsweep_core::scan::{ScanFailure, Scanners};

use crate::fixture::{Fixture, FixtureError};

/// The two shelves a Fixture sits on.
const SHELVES: [(&str, bool); 2] = [("bad", true), ("good", false)];

/// What the runner observed about one Fixture.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The Fixture, as `<rule>/<shelf>/<fixture>`.
    pub fixture: String,
    /// The Rule ids the Fixture expects.
    pub expected: Vec<i64>,
    /// The Rule ids that fired.
    pub fired: Vec<i64>,
    /// Which files each fired Rule fired on, for a tree.
    pub files: BTreeMap<i64, BTreeSet<String>>,
    /// What is wrong, empty when the Fixture holds.
    pub problems: Vec<String>,
}

impl Outcome {
    /// True when the Fixture observed exactly what it expects.
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }

    /// The failure, ready to print: the Fixture and every problem under it.
    pub fn report(&self) -> String {
        let mut report = format!("{}\n", self.fixture);
        for problem in &self.problems {
            report.push_str(&format!("    {problem}\n"));
        }
        report
    }
}

/// Loads every Fixture of every Rule under a `rules/` tree, in Rule order.
pub fn fixtures(rules: &Path) -> Result<Vec<Fixture>, FixtureError> {
    let mut rule_dirs: Vec<_> = fs::read_dir(rules)
        .map_err(|error| FixtureError {
            fixture: rules.display().to_string(),
            problem: format!("the corpus could not be read: {error}"),
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("rule.yar").is_file())
        .collect();
    rule_dirs.sort();

    let mut loaded = Vec::new();
    for rule_dir in rule_dirs {
        let rule = rule_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        for (shelf, bad) in SHELVES {
            let shelf_dir = rule_dir.join(shelf);
            if !shelf_dir.is_dir() {
                continue;
            }
            let mut fixture_dirs: Vec<_> = fs::read_dir(&shelf_dir)
                .map_err(|error| FixtureError {
                    fixture: format!("{rule}/{shelf}"),
                    problem: format!("the shelf could not be read: {error}"),
                })?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect();
            fixture_dirs.sort();
            for fixture_dir in fixture_dirs {
                loaded.push(Fixture::load(&rule, bad, &fixture_dir)?);
            }
        }
    }
    Ok(loaded)
}

/// Runs every Fixture against a compiled Rule Pack.
pub fn run(pack: &RulePack, fixtures: &[Fixture]) -> Result<Vec<Outcome>, ScanFailure> {
    let mut scanners = Scanners::new(pack);
    let mut outcomes = Vec::new();
    for fixture in fixtures {
        outcomes.push(check(pack, &mut scanners, fixture)?);
    }
    Ok(outcomes)
}

/// Scans one Fixture and compares what fired with what it expects.
fn check(
    pack: &RulePack,
    scanners: &mut Scanners<'_>,
    fixture: &Fixture,
) -> Result<Outcome, ScanFailure> {
    let mut files: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for unit in &fixture.units {
        let globals = fixture.globals_for(unit);
        let unit_bytes = agentsweep_core::item::ScanUnit {
            file: &unit.file,
            bytes: &unit.bytes,
        };
        for hit in scanners.run(fixture.kind, &globals, &unit_bytes)? {
            let Some(meta) = pack.meta(&hit.rule) else {
                continue;
            };
            files.entry(meta.id).or_default().insert(hit.file);
        }
    }

    let fired: Vec<i64> = files.keys().copied().collect();
    let expected = fixture.expect.fire.clone();
    let mut problems = Vec::new();

    let missing: Vec<i64> = expected
        .iter()
        .copied()
        .filter(|id| !fired.contains(id))
        .collect();
    let unexpected: Vec<i64> = fired
        .iter()
        .copied()
        .filter(|id| !expected.contains(id))
        .collect();
    if !missing.is_empty() {
        problems.push(format!(
            "rules {missing:?} were expected to fire and did not"
        ));
    }
    if !unexpected.is_empty() {
        problems.push(format!("rules {unexpected:?} fired and were not expected"));
    }

    if fixture.bad && !expected.contains(&fixture.rule_id) {
        problems.push(format!(
            "a bad fixture expects its own rule {} to fire",
            fixture.rule_id
        ));
    }
    if !fixture.bad && !expected.is_empty() {
        problems.push("a good fixture is a near miss and expects no rule to fire".to_string());
    }

    match (&fixture.expect.files, fixture.shape()) {
        (Some(expected_files), "tree") => {
            let matched: BTreeSet<String> = files
                .iter()
                .filter(|(id, _)| expected.contains(id))
                .flat_map(|(_, files)| files.iter().cloned())
                .collect();
            let listed: BTreeSet<String> = expected_files.iter().cloned().collect();
            if matched != listed {
                problems.push(format!(
                    "the match is on {matched:?}, and the fixture expects {listed:?}"
                ));
            }
        }
        (Some(_), shape) => {
            problems.push(format!(
                "`expect.files` belongs to a tree, not to a {shape}"
            ));
        }
        (None, _) => {}
    }

    Ok(Outcome {
        fixture: fixture.id(),
        expected,
        fired,
        files,
        problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_root;

    #[test]
    fn the_runner_loads_every_fixture_of_the_corpus() {
        let loaded = fixtures(&repo_root().join("rules")).expect("the corpus loads");
        assert!(
            loaded.len() >= 54,
            "the corpus had 54 fixtures when the runner was written, and loaded {}",
            loaded.len()
        );
        assert!(loaded.iter().any(|fixture| fixture.bad));
        assert!(loaded.iter().any(|fixture| !fixture.bad));
    }

    #[test]
    fn every_rule_of_the_corpus_ships_both_shelves() {
        let loaded = fixtures(&repo_root().join("rules")).expect("the corpus loads");
        let mut shelves: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for fixture in &loaded {
            let counts = shelves.entry(fixture.rule.clone()).or_default();
            if fixture.bad {
                counts.0 += 1;
            } else {
                counts.1 += 1;
            }
        }
        for (rule, (bad, good)) in shelves {
            assert!(bad > 0, "{rule} ships no bad fixture");
            assert!(good > 0, "{rule} ships no near miss");
        }
    }
}
