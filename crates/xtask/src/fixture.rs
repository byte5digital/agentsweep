//! One Fixture: the Item a Rule must fire on, or stay silent on.
//!
//! A Fixture directory holds `item.toml` and exactly one of `content` (a file
//! Item, or the canonical serialised entry of an entry Item) or `tree/` (the
//! files of a tree Item), as `rules/README.md` fixes it.
//!
//! `item.toml` states what the Surface Adapter would have produced. The loader
//! lays those facts over the view schema of the rule contract, so a Fixture
//! names only what matters and everything else keeps its documented default.
//! Because the overlay is driven by [`Views::schema`], a view field added with
//! a new Rule is settable from a Fixture the moment it exists, and a key that
//! is not in the schema is a load failure rather than a fact that silently
//! never reaches the Rule.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use agentsweep_core::item::{FileFacts, Kind, is_document};
use agentsweep_core::views::Views;
use serde_json::{Number, Value};

/// The `[expect]` section: what the corpus runner must observe.
pub const EXPECT: &str = "expect";

/// One unit of bytes the Rules are run over: the whole file, the canonical
/// serialised entry, or one file of a tree.
#[derive(Clone, Debug)]
pub struct Unit {
    /// The relative path within a tree, empty for a file or an entry Item.
    pub file: String,
    /// The bytes to scan.
    pub bytes: Vec<u8>,
}

/// What a Fixture expects of the Rules.
#[derive(Clone, Debug, Default)]
pub struct Expect {
    /// The Rule ids that must fire, empty for a near miss.
    pub fire: Vec<i64>,
    /// For a tree, which files carry the match. Absent when the Fixture does
    /// not say.
    pub files: Option<Vec<String>>,
}

/// What went wrong while loading a Fixture.
#[derive(Clone, Debug)]
pub struct FixtureError {
    /// The Fixture directory.
    pub fixture: String,
    /// What is wrong with it.
    pub problem: String,
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixture {}: {}", self.fixture, self.problem)
    }
}

impl Error for FixtureError {}

/// One Fixture, loaded and ready to scan.
#[derive(Clone, Debug)]
pub struct Fixture {
    /// The Rule directory the Fixture belongs to, such as
    /// `0001-decode-pipe-exec`.
    pub rule: String,
    /// The id of that Rule, read from the directory name.
    pub rule_id: i64,
    /// True for a Fixture under `bad/`, false for a near miss under `good/`.
    pub bad: bool,
    /// The Fixture directory name.
    pub name: String,
    /// Where the Fixture sits on disk.
    pub path: PathBuf,
    /// The Surface kind, which is what the pack pre-filters the Rules on.
    pub kind: Kind,
    /// Every view global, the schema with the Fixture's facts laid over it.
    pub globals: Vec<(&'static str, Value)>,
    /// The units the Rules are run over.
    pub units: Vec<Unit>,
    /// What the Fixture expects.
    pub expect: Expect,
}

impl Fixture {
    /// Loads one Fixture directory. `rule` is the Rule directory name and
    /// `bad` says which of the two shelves the Fixture sits on.
    pub fn load(rule: &str, bad: bool, path: &Path) -> Result<Fixture, FixtureError> {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let id = format!("{rule}/{}/{name}", if bad { "bad" } else { "good" });
        let fail = |problem: String| FixtureError {
            fixture: id.clone(),
            problem,
        };

        let rule_id: i64 = rule
            .split('-')
            .next()
            .and_then(|prefix| prefix.parse().ok())
            .ok_or_else(|| fail(format!("the rule directory `{rule}` has no id prefix")))?;

        let text = fs::read_to_string(path.join("item.toml"))
            .map_err(|error| fail(format!("item.toml could not be read: {error}")))?;
        let table: toml::Table = text
            .parse()
            .map_err(|error| fail(format!("item.toml is not TOML: {error}")))?;

        let mut globals = Views::schema();
        let mut expect = Expect::default();
        for (section, value) in &table {
            let table = value
                .as_table()
                .ok_or_else(|| fail(format!("`{section}` is not a section")))?;
            if section == EXPECT {
                expect = read_expect(table).map_err(&fail)?;
                continue;
            }
            let view = globals
                .iter_mut()
                .find(|(name, _)| name == section)
                .map(|(_, view)| view)
                .ok_or_else(|| fail(format!("`{section}` is not a view of the rule contract")))?;
            overlay(view, section, table).map_err(&fail)?;
        }

        let spelling = globals
            .iter()
            .find(|(name, _)| *name == "item")
            .and_then(|(_, view)| view.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let kind = Kind::parse(spelling)
            .ok_or_else(|| fail(format!("`{spelling}` is not a Surface kind")))?;

        let units = read_units(path).map_err(&fail)?;

        Ok(Fixture {
            rule: rule.to_string(),
            rule_id,
            bad,
            name,
            path: path.to_path_buf(),
            kind,
            globals,
            units,
            expect,
        })
    }

    /// How the Fixture is named in a failure: the Rule, the shelf and the
    /// Fixture directory.
    pub fn id(&self) -> String {
        format!(
            "{}/{}/{}",
            self.rule,
            if self.bad { "bad" } else { "good" },
            self.name
        )
    }

    /// The globals for one unit: `item.file`, and, inside a tree, the facts
    /// that are the scanned file's own rather than the Item's.
    ///
    /// The core derives `file_type`, `has_rtl_script`, `whitespace_percent`
    /// and `max_blank_run` per file of a tree, because Rule 0015 asks whether
    /// *this* file of a skill is a native executable. Deriving them here the
    /// same way is what lets a tree Fixture hold a binary beside a SKILL.md
    /// and have each read as what it is; what `item.toml` states about them is
    /// the Item's own fact, which is what a file or an entry Fixture uses.
    /// `file_is_document` is the same kind of per file fact, read off the
    /// file's place in the tree the way the core reads it.
    pub fn globals_for(&self, unit: &Unit) -> Vec<(&'static str, Value)> {
        let mut globals = self.globals.clone();
        let tree = self.shape() == "tree";
        let Some((_, view)) = globals.iter_mut().find(|(name, _)| *name == "item") else {
            return globals;
        };
        if let Some(file) = view.get_mut("file") {
            *file = Value::String(unit.file.clone());
        }
        if tree {
            let facts = FileFacts::of(&unit.bytes);
            set(
                view,
                "file_type",
                Value::String(facts.file_type.as_str().to_string()),
            );
            set(view, "has_rtl_script", Value::Bool(facts.has_rtl_script));
            set(
                view,
                "whitespace_percent",
                Value::Number(Number::from(facts.whitespace_percent)),
            );
            set(
                view,
                "max_blank_run",
                Value::Number(Number::from(facts.max_blank_run)),
            );
            set(
                view,
                "file_is_document",
                Value::Bool(is_document(&unit.file)),
            );
        }
        globals
    }

    /// The shape the Fixture states, `file`, `tree` or `entry`.
    pub fn shape(&self) -> &str {
        self.globals
            .iter()
            .find(|(name, _)| *name == "item")
            .and_then(|(_, view)| view.get("shape"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

/// Sets one field of a view that the schema already defines.
fn set(view: &mut Value, field: &str, value: Value) {
    if let Some(slot) = view.get_mut(field) {
        *slot = value;
    }
}

/// Reads the `[expect]` section.
fn read_expect(table: &toml::map::Map<String, toml::Value>) -> Result<Expect, String> {
    let mut expect = Expect::default();
    for (key, value) in table {
        match key.as_str() {
            "fire" => {
                let ids = value
                    .as_array()
                    .ok_or_else(|| "`expect.fire` is not a list of rule ids".to_string())?;
                for id in ids {
                    expect.fire.push(
                        id.as_integer()
                            .ok_or_else(|| format!("`{id:?}` is not a rule id"))?,
                    );
                }
            }
            "files" => {
                let files = value
                    .as_array()
                    .ok_or_else(|| "`expect.files` is not a list of files".to_string())?;
                let mut listed = Vec::new();
                for file in files {
                    listed.push(
                        file.as_str()
                            .ok_or_else(|| format!("`{file:?}` is not a file"))?
                            .to_string(),
                    );
                }
                expect.files = Some(listed);
            }
            other => return Err(format!("`expect.{other}` is not an expectation")),
        }
    }
    expect.fire.sort_unstable();
    Ok(expect)
}

/// Lays the facts of one section over that view of the schema.
fn overlay(
    view: &mut Value,
    section: &str,
    table: &toml::map::Map<String, toml::Value>,
) -> Result<(), String> {
    for (key, value) in table {
        let slot = view
            .get_mut(key)
            .ok_or_else(|| format!("`{section}.{key}` is not a field of the `{section}` view"))?;
        *slot = convert(slot, value, &format!("{section}.{key}"))?;
    }
    Ok(())
}

/// Converts one TOML value to the JSON shape the schema fixes for that field.
/// The schema decides the type, so a Fixture can never change the shape of a
/// global the Compiler has already fixed.
fn convert(schema: &Value, value: &toml::Value, at: &str) -> Result<Value, String> {
    match schema {
        Value::String(_) => value
            .as_str()
            .map(|text| Value::String(text.to_string()))
            .ok_or_else(|| format!("`{at}` is a string in the schema")),
        Value::Bool(_) => value
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| format!("`{at}` is a boolean in the schema")),
        Value::Number(_) => value
            .as_integer()
            .map(|number| Value::Number(Number::from(number)))
            .ok_or_else(|| format!("`{at}` is an integer in the schema")),
        Value::Array(default) => {
            let element = default
                .first()
                .ok_or_else(|| format!("`{at}` has no element schema"))?;
            let listed = value
                .as_array()
                .ok_or_else(|| format!("`{at}` is a list in the schema"))?;
            if listed.is_empty() {
                // YARA-X rejects an empty array, so the schema's one default
                // element stands in and the sibling count carries the truth.
                return Ok(schema.clone());
            }
            let mut converted = Vec::new();
            for (index, item) in listed.iter().enumerate() {
                converted.push(convert(element, item, &format!("{at}.{index}"))?);
            }
            Ok(Value::Array(converted))
        }
        Value::Object(_) => {
            let table = value
                .as_table()
                .ok_or_else(|| format!("`{at}` is a struct in the schema"))?;
            let mut object = schema.clone();
            overlay(&mut object, at, table)?;
            Ok(object)
        }
        other => Err(format!("`{at}` may not be {other} in the schema")),
    }
}

/// Reads the bytes of a Fixture: one file, or every file of a tree.
fn read_units(path: &Path) -> Result<Vec<Unit>, String> {
    let content = path.join("content");
    let tree = path.join("tree");
    match (content.is_file(), tree.is_dir()) {
        (true, true) => Err("carries both `content` and `tree/`".to_string()),
        (false, false) => Err("carries neither `content` nor `tree/`".to_string()),
        (true, false) => Ok(vec![Unit {
            file: String::new(),
            bytes: fs::read(&content).map_err(|error| format!("content: {error}"))?,
        }]),
        (false, true) => {
            let mut units = Vec::new();
            read_tree(&tree, "", &mut units)?;
            if units.is_empty() {
                return Err("`tree/` holds no file".to_string());
            }
            Ok(units)
        }
    }
}

/// Reads one tree, depth first and in name order, so a failure always names
/// the same file for the same corpus.
fn read_tree(dir: &Path, prefix: &str, units: &mut Vec<Unit>) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|error| format!("tree: {error}"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()
        .map_err(|error| format!("tree: {error}"))?;
    entries.sort();

    for entry in entries {
        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let relative = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.is_dir() {
            read_tree(&entry, &relative, units)?;
        } else {
            units.push(Unit {
                file: relative,
                bytes: fs::read(&entry).map_err(|error| format!("tree: {error}"))?,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_root;

    fn load(rule: &str, bad: bool, name: &str) -> Result<Fixture, FixtureError> {
        let path = repo_root()
            .join("rules")
            .join(rule)
            .join(if bad { "bad" } else { "good" })
            .join(name);
        Fixture::load(rule, bad, &path)
    }

    #[test]
    fn a_file_fixture_carries_one_unit_and_the_facts_of_its_item_toml() {
        let fixture =
            load("0001-decode-pipe-exec", true, "hook-curl-pipe-sh").expect("the fixture loads");
        assert_eq!(fixture.kind, Kind::Hook);
        assert_eq!(fixture.units.len(), 1);
        assert!(fixture.units[0].file.is_empty());
        assert_eq!(fixture.expect.fire, vec![1]);

        let (_, hook) = fixture
            .globals
            .iter()
            .find(|(name, _)| *name == "hook")
            .expect("the hook view");
        assert_eq!(hook["event"], Value::String("SessionStart".to_string()));
    }

    #[test]
    fn a_tree_fixture_carries_one_unit_per_file_in_name_order() {
        let fixture =
            load("0001-decode-pipe-exec", true, "skill-curl-tmp-node").expect("the fixture loads");
        let files: Vec<&str> = fixture
            .units
            .iter()
            .map(|unit| unit.file.as_str())
            .collect();
        assert_eq!(files, vec!["SKILL.md", "setup-installation.md"]);
        assert_eq!(
            fixture.expect.files.as_deref(),
            Some(&["setup-installation.md".to_string()][..])
        );
    }

    #[test]
    fn a_fact_the_fixture_does_not_state_keeps_its_documented_default() {
        let fixture =
            load("0001-decode-pipe-exec", true, "hook-curl-pipe-sh").expect("the fixture loads");
        let (_, item) = fixture
            .globals
            .iter()
            .find(|(name, _)| *name == "item")
            .expect("the item view");
        assert_eq!(item["baseline"], Value::String(String::new()));
        assert_eq!(item["whitespace_percent"], Value::Number(Number::from(0)));
        assert_eq!(item["is_symlink"], Value::Bool(false));
    }

    #[test]
    fn the_unit_being_scanned_sets_the_file_a_rule_reads() {
        let fixture = load("0900-ioc-hosts", true, "skill-known-host").expect("the fixture loads");
        for unit in &fixture.units {
            let globals = fixture.globals_for(unit);
            let (_, item) = globals
                .iter()
                .find(|(name, _)| *name == "item")
                .expect("the item view");
            assert_eq!(item["file"], Value::String(unit.file.clone()));
        }
    }

    #[test]
    fn a_readme_in_a_tree_fixture_reads_as_a_document_and_its_neighbours_do_not() {
        let fixture = load(
            "0001-decode-pipe-exec",
            false,
            "plugin-readme-documents-an-install",
        )
        .expect("the fixture loads");
        let flags: Vec<(String, Value)> = fixture
            .units
            .iter()
            .map(|unit| {
                let globals = fixture.globals_for(unit);
                let (_, item) = globals
                    .iter()
                    .find(|(name, _)| *name == "item")
                    .expect("the item view");
                (unit.file.clone(), item["file_is_document"].clone())
            })
            .collect();
        assert!(
            flags.contains(&("README.md".to_string(), Value::Bool(true))),
            "{flags:?}"
        );
        assert!(
            flags
                .iter()
                .filter(|(file, _)| file != "README.md")
                .all(|(_, flag)| *flag == Value::Bool(false)),
            "{flags:?}"
        );
    }

    #[test]
    fn a_key_that_is_not_in_the_schema_is_a_load_failure() {
        let mut view = Views::schema()
            .into_iter()
            .find(|(name, _)| *name == "mcp")
            .expect("the mcp view")
            .1;
        let table: toml::Table = "commnd = \"npx\"\n".parse().expect("a table");
        let problem = overlay(&mut view, "mcp", &table).expect_err("a typo does not load");
        assert!(problem.contains("mcp.commnd"), "{problem}");
    }

    #[test]
    fn a_fact_of_the_wrong_type_is_a_load_failure() {
        let mut view = Views::schema()
            .into_iter()
            .find(|(name, _)| *name == "item")
            .expect("the item view")
            .1;
        let table: toml::Table = "registered = \"yes\"\n".parse().expect("a table");
        let problem = overlay(&mut view, "item", &table).expect_err("a string is not a boolean");
        assert!(problem.contains("boolean"), "{problem}");
    }

    #[test]
    fn a_list_of_structs_lands_on_the_default_element() {
        let mut view = Views::schema()
            .into_iter()
            .find(|(name, _)| *name == "repo")
            .expect("the repo view")
            .1;
        let table: toml::Table =
            "exec_keys = [{ key = \"core.fsmonitor\", value_outside_repo = true }]\n"
                .parse()
                .expect("a table");
        overlay(&mut view, "repo", &table).expect("the struct list lands");
        assert_eq!(
            view["exec_keys"][0]["key"],
            Value::String("core.fsmonitor".to_string())
        );
        assert_eq!(view["exec_keys"][0]["value"], Value::String(String::new()));
        assert_eq!(
            view["exec_keys"][0]["value_outside_repo"],
            Value::Bool(true)
        );
    }
}
