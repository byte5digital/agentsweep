//! One Item of an eval set: the Item the request builder is handed, the
//! Threat Heuristics that fired on it, and whether it sits in the Ambiguous
//! Band with nothing else to say about it, which is the population the
//! product asks.
//!
//! An Item comes from one of three places: a Surface Adapter on a laid-out
//! sample or benign source, a Heuristic's bad Fixture, or a wrapper around
//! either. A Fixture is no Item, only the facts and bytes one would have, so
//! it is made into one here and keeps its stated facts: a wrapped copy is
//! scanned again under them, as the corpus runner scans the Fixture itself.

use std::path::PathBuf;

use agentsweep_core::finding::FiredHeuristic;
use agentsweep_core::heuristics::{Assessment, assess_hits};
use agentsweep_core::item::{
    Activation, FileFacts, InactiveReason, Item, Provenance, Scope, Shape, Tree, TreeFile,
    canonical_entry, sha256_hex,
};
use agentsweep_core::judgement_request::Normalisation;
use agentsweep_core::scan::Scanners;
use serde_json::Value;

use crate::eval::wrappers::Wrapper;
use crate::fixture::{Fixture, Unit};

/// Where a Fixture's project-scoped Item is said to sit. No file is ever
/// read there; the Judgement Request names only the Scope, never the root.
const FIXTURE_PROJECT: &str = "/eval/project";

/// The key an entry Item carries a wrapper under. An entry is canonical JSON,
/// so the wrapper goes in as one more string value rather than around the
/// bytes, which would leave an entry no adapter ever produces.
pub const ENTRY_WRAPPER_KEY: &str = "description";

/// One Item of an eval set.
#[derive(Clone, Debug)]
pub struct EvalItem {
    /// How the Item is named in a failure: the Fixture, or the sample and
    /// the ItemId without the temporary directory.
    pub name: String,
    /// The Item the request builder is handed.
    pub item: Item,
    /// The Threat Heuristics that fired on it, as the Assessment holds them.
    pub fired: Vec<FiredHeuristic>,
    /// True when the Item is Ambiguous and nothing else raised a Finding on
    /// it: an Item the daemon would hand to AI Judgement.
    pub awaits_judgement: bool,
    /// The home directory and username the request normalises.
    pub normalisation: Normalisation,
    stated: Option<Fixture>,
}

impl EvalItem {
    /// An Item with what the Tiers made of it stated rather than scanned.
    pub fn new(
        name: &str,
        item: Item,
        fired: Vec<FiredHeuristic>,
        awaits_judgement: bool,
        normalisation: Normalisation,
    ) -> EvalItem {
        EvalItem {
            name: name.to_string(),
            item,
            fired,
            awaits_judgement,
            normalisation,
            stated: None,
        }
    }

    /// An Item a Surface Adapter produced, with its Assessment.
    pub fn of_assessment(
        name: &str,
        item: Item,
        assessment: &Assessment,
        normalisation: Normalisation,
    ) -> EvalItem {
        EvalItem::new(
            name,
            item,
            assessment.fired.clone(),
            assessment.awaits_judgement(),
            normalisation,
        )
    }

    /// An Item a Surface Adapter produced, assessed here.
    pub fn assessed(
        name: &str,
        item: Item,
        normalisation: Normalisation,
        scanners: &mut Scanners<'_>,
    ) -> Result<EvalItem, String> {
        let assessment = assess(scanners, &item, None)?;
        Ok(EvalItem::of_assessment(
            name,
            item,
            &assessment,
            normalisation,
        ))
    }

    /// The Item a Fixture describes, scanned under the facts it states.
    pub fn of_fixture(fixture: &Fixture, scanners: &mut Scanners<'_>) -> Result<EvalItem, String> {
        let item = item_of_fixture(fixture)?;
        let assessment = assess(scanners, &item, Some(fixture))?;
        let mut eval =
            EvalItem::of_assessment(&fixture.id(), item, &assessment, Normalisation::default());
        eval.stated = Some(fixture.clone());
        Ok(eval)
    }

    /// True when a Heuristic marked `reviewer_directed` fired on the Item.
    pub fn reviewer_directed(&self) -> bool {
        self.fired
            .iter()
            .any(|heuristic| heuristic.reviewer_directed)
    }

    /// The same Item wrapped in one wrapper's text, assessed again the way
    /// the Item itself was.
    pub fn wrapped(
        &self,
        wrapper: &Wrapper,
        scanners: &mut Scanners<'_>,
    ) -> Result<EvalItem, String> {
        let item = wrap_item(&self.item, &self.fired, wrapper);
        let assessment = assess(scanners, &item, self.stated.as_ref())
            .map_err(|problem| format!("{} wrapped: {problem}", self.name))?;
        let mut wrapped = EvalItem::of_assessment(
            &format!("{} wrapped", self.name),
            item,
            &assessment,
            self.normalisation.clone(),
        );
        wrapped.stated = self.stated.clone();
        Ok(wrapped)
    }
}

/// The detection ladder over one Item, with the globals the Item's own views
/// give or, for a Fixture, the globals it states.
fn assess(
    scanners: &mut Scanners<'_>,
    item: &Item,
    stated: Option<&Fixture>,
) -> Result<Assessment, String> {
    let Some(fixture) = stated else {
        return scanners
            .assess(item)
            .map_err(|error| format!("the scan failed: {error}"));
    };
    let mut hits = Vec::new();
    for unit in item.scan_units() {
        let globals = fixture.globals_for(&Unit {
            file: unit.file.to_string(),
            bytes: unit.bytes.to_vec(),
        });
        hits.extend(
            scanners
                .run(item.kind, &globals, &unit)
                .map_err(|error| format!("the scan failed: {error}"))?,
        );
    }
    Ok(assess_hits(scanners.pack(), scanners.bands(), item, &hits))
}

/// The Item a Fixture describes: its kind, shape, Scope, Provenance and
/// Activation from `item.toml`, its bytes from `content` or `tree/`.
fn item_of_fixture(fixture: &Fixture) -> Result<Item, String> {
    let empty = Value::Null;
    let view = fixture
        .globals
        .iter()
        .find(|(name, _)| *name == "item")
        .map(|(_, view)| view)
        .unwrap_or(&empty);
    let text = |key: &str| view.get(key).and_then(Value::as_str).unwrap_or_default();

    let agent = match text("agent") {
        "" => "claude-code",
        agent => agent,
    };
    let scope = match text("scope") {
        "managed" => Scope::Managed,
        "project" => Scope::Project(PathBuf::from(match text("project_root") {
            "" => FIXTURE_PROJECT,
            root => root,
        })),
        _ => Scope::User,
    };
    let reference = text("provenance_ref").to_string();
    let provenance = match text("provenance") {
        "manual" => Provenance::Manual,
        "marketplace" => Provenance::Marketplace {
            name: reference.clone(),
            pinned_ref: reference,
            official: view
                .get("provenance_official")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        "plugin" => Provenance::Plugin { id: reference },
        "agent_written" => Provenance::AgentWritten,
        "repository" => Provenance::Repository { commit: reference },
        _ => Provenance::Unknown,
    };
    let activation = match text("activation") {
        "active" => Activation::Active,
        "inactive" => Activation::Inactive(match text("activation_reason") {
            "untrusted_project" => InactiveReason::UntrustedProject,
            "orphaned" => InactiveReason::Orphaned,
            "stale_hook_hash" => InactiveReason::StaleHookHash,
            _ => InactiveReason::Disabled,
        }),
        _ => Activation::Unknown,
    };
    let path = PathBuf::from(text("path"));
    let locator = fixture.id();
    let first = || {
        fixture
            .units
            .first()
            .map(|unit| unit.bytes.clone())
            .ok_or_else(|| format!("{locator}: the fixture has no content"))
    };

    Ok(match fixture.shape() {
        "tree" => {
            let mut files: Vec<TreeFile> = fixture
                .units
                .iter()
                .map(|unit| tree_file(&unit.file, unit.bytes.clone()))
                .collect();
            files.sort_by(|a, b| a.path.cmp(&b.path));
            let total_bytes = files.iter().map(|file| file.size).sum();
            let tree = Tree {
                files,
                total_bytes,
                over_caps: false,
            };
            Item::tree(
                agent,
                scope,
                fixture.kind,
                &locator,
                path,
                provenance,
                activation,
                tree,
            )
        }
        "entry" => Item::entry(
            agent,
            scope,
            fixture.kind,
            &locator,
            path,
            provenance,
            activation,
            first()?,
        ),
        _ => Item::file(
            agent,
            scope,
            fixture.kind,
            &locator,
            path,
            provenance,
            activation,
            first()?,
        ),
    })
}

/// One scanned file of a tree, with the facts and hash its bytes give.
fn tree_file(path: &str, content: Vec<u8>) -> TreeFile {
    TreeFile {
        path: path.to_string(),
        size: content.len() as u64,
        mode: 0o644,
        sha256: sha256_hex(&content),
        scanned: true,
        facts: FileFacts::of(&content),
        content,
        ..TreeFile::default()
    }
}

/// The Item with a wrapper around its text: a file around its bytes, a tree
/// around the first file a Heuristic matched in (or its `SKILL.md`, or its
/// first scanned file), an entry under [`ENTRY_WRAPPER_KEY`]. The facts, the
/// size and the content hash follow the new bytes.
pub fn wrap_item(item: &Item, fired: &[FiredHeuristic], wrapper: &Wrapper) -> Item {
    let mut wrapped = item.clone();
    match item.shape {
        Shape::File => set_content(&mut wrapped, wrap_text(&item.content, wrapper)),
        Shape::Entry => {
            let bytes = match serde_json::from_slice::<Value>(&item.content) {
                Ok(Value::Object(mut entry)) => {
                    let existing = entry
                        .get(ENTRY_WRAPPER_KEY)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let text = [wrapper.before.as_str(), &existing, wrapper.after.as_str()]
                        .iter()
                        .filter(|part| !part.is_empty())
                        .copied()
                        .collect::<Vec<_>>()
                        .join("\n");
                    entry.insert(ENTRY_WRAPPER_KEY.to_string(), Value::String(text));
                    canonical_entry(&Value::Object(entry))
                }
                _ => wrap_text(&item.content, wrapper),
            };
            set_content(&mut wrapped, bytes);
        }
        Shape::Tree => {
            let chosen = fired
                .iter()
                .map(|heuristic| heuristic.file.as_str())
                .find(|file| !file.is_empty() && item.tree.holds(file))
                .or_else(|| item.tree.holds("SKILL.md").then_some("SKILL.md"))
                .or_else(|| {
                    item.tree
                        .files
                        .iter()
                        .find(|file| file.scanned)
                        .map(|file| file.path.as_str())
                })
                .map(str::to_string);
            if let Some(path) = chosen
                && let Some(file) = wrapped.tree.files.iter_mut().find(|file| file.path == path)
            {
                let content = wrap_text(&file.content, wrapper);
                *file = TreeFile {
                    mode: file.mode,
                    ..tree_file(&path, content)
                };
            }
            wrapped.tree.total_bytes = wrapped.tree.files.iter().map(|file| file.size).sum();
            wrapped.content = wrapped.tree.manifest();
            wrapped.content_hash = sha256_hex(&wrapped.content);
            wrapped.size = wrapped.tree.total_bytes;
        }
    }
    wrapped
}

fn set_content(item: &mut Item, content: Vec<u8>) {
    item.size = content.len() as u64;
    item.facts = FileFacts::of(&content);
    item.content_hash = sha256_hex(&content);
    item.content = content;
}

/// Text with the wrapper's `before` ahead of it and its `after` behind it.
/// A leading frontmatter block stays first, so a skill or a subagent still
/// reads as one.
pub fn wrap_text(bytes: &[u8], wrapper: &Wrapper) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = match text
        .strip_prefix("---\n")
        .and_then(|rest| rest.find("\n---\n"))
    {
        Some(end) => text.split_at(4 + end + 5),
        None => ("", text.as_ref()),
    };
    let mut out = String::from(head);
    if !wrapper.before.is_empty() {
        out.push_str(&wrapper.before);
        out.push_str("\n\n");
    }
    out.push_str(body);
    if !wrapper.after.is_empty() {
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&wrapper.after);
        out.push('\n');
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapper() -> Wrapper {
        Wrapper {
            before: "BEFORE".to_string(),
            after: "AFTER".to_string(),
        }
    }

    #[test]
    fn a_wrapper_goes_around_the_text() {
        let wrapped = wrap_text(b"body\n", &wrapper());
        assert_eq!(
            String::from_utf8(wrapped).unwrap(),
            "BEFORE\n\nbody\n\nAFTER\n"
        );
    }

    #[test]
    fn frontmatter_stays_first() {
        let wrapped = wrap_text(b"---\nname: x\n---\nbody", &wrapper());
        assert_eq!(
            String::from_utf8(wrapped).unwrap(),
            "---\nname: x\n---\nBEFORE\n\nbody\n\nAFTER\n"
        );
    }
}
