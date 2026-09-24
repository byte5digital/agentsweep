//! The steps one Quarantine takes, and how they are undone.
//!
//! A Surface Adapter knows which file holds the entry, where in it the entry
//! sits and what else has to happen around it: a plugin is switched off in the
//! Agent's own settings before its version directory moves, a marketplace
//! loses its registry record before its clone moves, a hook entry takes the
//! script it points at with it when the script sits inside a scanned Surface
//! root (spec section 5.2). What that does to the file system is not the
//! adapter's, and neither is writing it down: the adapter describes the steps
//! and hands them here.
//!
//! One Quarantine is one Receipt, whatever the primitive table says the kind
//! takes, and the steps are carried out in the order the row lists them. A
//! step that fails takes the ones before it back with it, so a Quarantine
//! either happened or did not: there is no half-disabled plugin whose
//! directory is still in place and whose Receipt was never written.
//!
//! [`reverse`] is the other half, and it is the core's rather than the
//! adapter's for the same reason. A Receipt comes back from the Event Log
//! alone (spec section 5.3), so every step has to say what it did in terms the
//! core can undo without asking anybody: the file, the key path inside it and,
//! in the store beside the payload, what was taken out of it.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::entry_edit::{self, EntryPath, Format};
use crate::eventlog::{Outcome, Primitive, ReceiptStep};
use crate::host::Host;
use crate::item::Item;
use crate::quarantine::{
    Conflict, EnforcementError, MoveOutPlan, Receipt, ReceiptId, RestoreReport, Store,
};

/// One step of one Quarantine, as the Surface Adapter describes it.
#[derive(Clone, Debug)]
pub enum Step<'a> {
    /// Drop one entry out of a shared config file.
    RemoveEntry {
        /// The file that holds it.
        file: &'a Path,
        /// How that file is written.
        format: Format,
        /// Where in it the entry sits.
        entry: EntryPath,
        /// One line for the Activity, free of content and of sensitive
        /// values.
        detail: String,
    },
    /// Flip the Agent's own switch. Never a Quarantine's only step (spec
    /// section 5.2).
    NativeDisable {
        /// The file that holds the switch.
        file: &'a Path,
        /// How that file is written.
        format: Format,
        /// Where in it the switch sits.
        entry: EntryPath,
        /// What to set it to.
        value: Value,
        /// One line for the Activity.
        detail: String,
    },
    /// Comment the chosen lines out where they lie, for the kinds that are
    /// never quarantined automatically.
    NeutraliseInPlace {
        /// The file the lines are in.
        file: &'a Path,
        /// Which lines, counted from zero.
        lines: Vec<usize>,
        /// One line for the Activity.
        detail: String,
    },
    /// Move a file or a tree into the quarantine store.
    MoveOut(MoveOutPlan<'a>),
}

impl Step<'_> {
    /// Which primitive the step is.
    pub fn primitive(&self) -> Primitive {
        match self {
            Step::RemoveEntry { .. } => Primitive::RemoveEntry,
            Step::NativeDisable { .. } => Primitive::NativeDisable,
            Step::NeutraliseInPlace { .. } => Primitive::NeutraliseInPlace,
            Step::MoveOut(_) => Primitive::MoveOut,
        }
    }

    /// The file the step acts on.
    pub fn path(&self) -> &Path {
        match self {
            Step::RemoveEntry { file, .. }
            | Step::NativeDisable { file, .. }
            | Step::NeutraliseInPlace { file, .. } => file,
            Step::MoveOut(plan) => plan.source,
        }
    }
}

/// Carries out the steps of one Quarantine, in order, and writes the Receipt.
///
/// Nothing is left half done: a step that fails takes back the ones before it
/// and the error says which one it was. The Receipt that comes back is what
/// the Event Log records and what Restore replays in reverse.
pub fn carry_out(
    host: &Host,
    store: &dyn Store,
    item: &Item,
    steps: &[Step<'_>],
) -> Result<Receipt, EnforcementError> {
    let id = store.begin()?;
    let mut receipt = Receipt::new(id.clone(), item);
    for (slot, step) in steps.iter().enumerate() {
        match take(host, store, &id, slot, step) {
            Ok(taken) => receipt.steps.push(taken),
            Err(error) => {
                // What was already done goes back, so a Quarantine that could
                // not be finished leaves the Surface as it found it and no
                // record is written for it.
                for (slot, taken) in receipt.steps.iter().enumerate().rev() {
                    reverse(host, store, &id, slot, taken, Conflict::Replace);
                }
                return Err(error);
            }
        }
    }
    Ok(receipt)
}

/// One step, carried out.
fn take(
    host: &Host,
    store: &dyn Store,
    receipt: &ReceiptId,
    slot: usize,
    step: &Step<'_>,
) -> Result<ReceiptStep, EnforcementError> {
    match step {
        Step::MoveOut(plan) => store.move_out(host, receipt, plan),
        Step::RemoveEntry {
            file,
            format,
            entry,
            detail,
        } => {
            let text = read(host, file)?;
            let edit = entry_edit::remove_entry(*format, &text, entry)
                .map_err(|error| edit_failed(file, error))?;
            store.keep(receipt, slot, &edit.kept)?;
            store.rewrite(file, &edit.text)?;
            Ok(ReceiptStep {
                primitive: Primitive::RemoveEntry,
                outcome: Outcome::Ok,
                path: file.display().to_string(),
                locator: entry.pointer(),
                detail: detail.clone(),
            })
        }
        Step::NativeDisable {
            file,
            format,
            entry,
            value,
            detail,
        } => {
            let text = read(host, file)?;
            let edit = entry_edit::set_entry(*format, &text, entry, value)
                .map_err(|error| edit_failed(file, error))?;
            store.keep(receipt, slot, &edit.kept)?;
            store.rewrite(file, &edit.text)?;
            Ok(ReceiptStep {
                primitive: Primitive::NativeDisable,
                outcome: Outcome::Ok,
                path: file.display().to_string(),
                locator: entry.pointer(),
                detail: detail.clone(),
            })
        }
        Step::NeutraliseInPlace {
            file,
            lines,
            detail,
        } => {
            let text = read(host, file)?;
            let written = entry_edit::comment_out(&text, receipt.as_str(), lines);
            if written == text {
                return Err(EnforcementError::NotEligible {
                    reason: format!("there is nothing left to comment out in {}", file.display()),
                });
            }
            store.rewrite(file, &written)?;
            Ok(ReceiptStep {
                primitive: Primitive::NeutraliseInPlace,
                outcome: Outcome::Ok,
                path: file.display().to_string(),
                locator: String::new(),
                detail: detail.clone(),
            })
        }
    }
}

/// Undoes one step of a Receipt, whatever primitive it was.
///
/// The outcome is the step's own: `ok` when it did what it said, `skipped`
/// when its precondition is gone and `failed` on a conflict, which is what
/// spec section 5.4 asks a partial Restore to report per step.
pub fn reverse(
    host: &Host,
    store: &dyn Store,
    receipt: &ReceiptId,
    slot: usize,
    step: &ReceiptStep,
    conflict: Conflict,
) -> ReceiptStep {
    let mut replayed = step.clone();
    if step.outcome != Outcome::Ok {
        // A step that did nothing has nothing to take back.
        replayed.outcome = Outcome::Skipped;
        replayed.detail = "the step was never carried out".to_string();
        return replayed;
    }
    match step.primitive {
        Primitive::MoveOut => store.move_back(receipt, step, conflict),
        Primitive::RemoveEntry | Primitive::NativeDisable => {
            put_entry_back(host, store, receipt, slot, replayed, conflict)
        }
        Primitive::NeutraliseInPlace => switch_back(host, store, receipt, replayed),
    }
}

fn put_entry_back(
    host: &Host,
    store: &dyn Store,
    receipt: &ReceiptId,
    slot: usize,
    mut replayed: ReceiptStep,
    conflict: Conflict,
) -> ReceiptStep {
    let path = PathBuf::from(&replayed.path);
    let Some(kept) = store.kept(receipt, slot) else {
        replayed.outcome = Outcome::Skipped;
        replayed.detail = "the store no longer holds what was taken out".to_string();
        return replayed;
    };
    let text = match read(host, &path) {
        Ok(text) => text,
        Err(error) => {
            replayed.outcome = Outcome::Skipped;
            replayed.detail = format!("{error}");
            return replayed;
        }
    };
    let replace = matches!(conflict, Conflict::Replace);
    match entry_edit::put_back(&text, &kept, replace) {
        Ok(written) => match store.rewrite(&path, &written) {
            Ok(()) => {
                store.forget(receipt, slot);
                replayed.outcome = Outcome::Ok;
                replayed.detail = match kept.was_set {
                    true => format!("the switch at {} is back as it was", kept.path),
                    false => format!("put back at {}", kept.path),
                };
                replayed
            }
            Err(error) => {
                replayed.outcome = Outcome::Failed;
                replayed.detail = format!("{} could not be written: {error}", path.display());
                replayed
            }
        },
        Err(entry_edit::EditError::Taken(where_it_sat)) => {
            replayed.outcome = Outcome::Failed;
            replayed.detail =
                format!("something else is at {where_it_sat}: replace it or leave it there");
            replayed
        }
        Err(error) => {
            replayed.outcome = Outcome::Failed;
            replayed.detail = format!("{error}");
            replayed
        }
    }
}

fn switch_back(
    host: &Host,
    store: &dyn Store,
    receipt: &ReceiptId,
    mut replayed: ReceiptStep,
) -> ReceiptStep {
    let path = PathBuf::from(&replayed.path);
    let text = match read(host, &path) {
        Ok(text) => text,
        Err(error) => {
            replayed.outcome = Outcome::Skipped;
            replayed.detail = format!("{error}");
            return replayed;
        }
    };
    let (written, switched) = entry_edit::switch_back(&text, receipt.as_str());
    if switched == 0 {
        replayed.outcome = Outcome::Skipped;
        replayed.detail = "nothing in the file is commented out by this Receipt".to_string();
        return replayed;
    }
    match store.rewrite(&path, &written) {
        Ok(()) => {
            replayed.outcome = Outcome::Ok;
            replayed.detail = match switched {
                1 => "one line is in force again".to_string(),
                many => format!("{many} lines are in force again"),
            };
        }
        Err(error) => {
            replayed.outcome = Outcome::Failed;
            replayed.detail = format!("{} could not be written: {error}", path.display());
        }
    }
    replayed
}

/// Replays only the steps of one primitive, in reverse.
///
/// Re-enable is what this is for: a newer version of a quarantined plugin is
/// on disk and carries no Threat Finding, so the Agent's own switch goes back
/// on and the old version stays in the store (spec section 5.4). Nothing else
/// of the Receipt is touched.
pub fn replay_only(
    host: &Host,
    store: &dyn Store,
    receipt: &Receipt,
    primitive: Primitive,
    conflict: Conflict,
) -> RestoreReport {
    let mut steps = Vec::new();
    for (slot, step) in receipt.steps.iter().enumerate().rev() {
        if step.primitive == primitive {
            steps.push(reverse(host, store, &receipt.id, slot, step, conflict));
        }
    }
    RestoreReport::of(steps)
}

/// The text of one configuration file.
fn read(host: &Host, path: &Path) -> Result<String, EnforcementError> {
    let bytes = host.read(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => EnforcementError::Missing {
            path: path.to_path_buf(),
        },
        _ => EnforcementError::Store(error),
    })?;
    String::from_utf8(bytes).map_err(|_| EnforcementError::Edit {
        path: path.to_path_buf(),
        reason: "the file is not text".to_string(),
    })
}

fn edit_failed(path: &Path, error: entry_edit::EditError) -> EnforcementError {
    EnforcementError::Edit {
        path: path.to_path_buf(),
        reason: error.to_string(),
    }
}

#[cfg(all(test, feature = "daemon"))]
mod tests {
    use super::*;

    use crate::item::{Activation, Item, Kind, Provenance, Scope, sha256_hex};
    use crate::paths::DataDirectory;
    use crate::quarantine::QuarantineStore;

    use serde_json::json;
    use tempfile::TempDir;

    /// A Surface of two files and a store beside it, both temporary.
    struct Bench {
        _root: TempDir,
        surface: TempDir,
        store: QuarantineStore,
        host: Host,
    }

    impl Bench {
        fn new() -> Bench {
            let root = TempDir::new().expect("a temporary directory");
            let surface = TempDir::new().expect("a temporary directory");
            let store = QuarantineStore::open(&DataDirectory::at(root.path().join("data")))
                .expect("an open store");
            let host = Host::new(surface.path().to_path_buf(), Vec::new());
            Bench {
                _root: root,
                surface,
                store,
                host,
            }
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.surface.path().join(name);
            std::fs::write(&path, text).expect("a file");
            path
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.surface.path().join(name)).expect("the file")
        }

        fn item(&self, kind: Kind, path: &Path, content: &str) -> Item {
            Item::entry(
                "demo",
                Scope::User,
                kind,
                "demo#entry",
                path.to_path_buf(),
                Provenance::Manual,
                Activation::Active,
                content.as_bytes().to_vec(),
            )
        }
    }

    const SETTINGS: &str = "{\n  \"enabledPlugins\": {\n    \"notes@demo\": true\n  }\n}\n";
    const SERVERS: &str =
        "{\n  \"mcpServers\": {\n    \"planted\": {\n      \"command\": \"node\"\n    }\n  }\n}\n";

    fn entry(segments: &[&str]) -> EntryPath {
        EntryPath::of(segments)
    }

    #[test]
    fn one_entry_comes_out_of_its_file_and_goes_back_byte_for_byte() {
        let bench = Bench::new();
        let file = bench.write(".mcp.json", SERVERS);
        let item = bench.item(Kind::McpServer, &file, "{\"command\":\"node\"}");
        let steps = [Step::RemoveEntry {
            file: &file,
            format: Format::Json,
            entry: entry(&["mcpServers", "planted"]),
            detail: "the server was removed from the file".to_string(),
        }];

        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");

        assert!(!bench.read(".mcp.json").contains("planted"));
        assert_eq!(receipt.steps.len(), 1);
        assert_eq!(receipt.steps[0].primitive, Primitive::RemoveEntry);
        assert_eq!(receipt.steps[0].locator, "/mcpServers/planted");
        assert_eq!(receipt.result(), Outcome::Ok);

        let report = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Refuse,
        );

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(bench.read(".mcp.json"), SERVERS);
    }

    /// The plugin composite of spec section 5.2: the Agent's own switch first,
    /// then the version directory.
    #[test]
    fn a_composite_takes_both_steps_and_gives_both_back_in_reverse() {
        let bench = Bench::new();
        let settings = bench.write("settings.json", SETTINGS);
        let version = bench.surface.path().join("cache/notes/1.2.0");
        std::fs::create_dir_all(&version).expect("a version directory");
        std::fs::write(version.join("plugin.json"), "{\"name\":\"notes\"}\n").expect("a manifest");
        let tree = crate::item::Tree::of(&bench.host, &version, crate::item::TreeCaps::default());
        let item = Item::tree(
            "demo",
            Scope::User,
            Kind::Plugin,
            "notes@demo",
            version.clone(),
            Provenance::Manual,
            Activation::Active,
            tree,
        );
        let steps = [
            Step::NativeDisable {
                file: &settings,
                format: Format::Json,
                entry: entry(&["enabledPlugins", "notes@demo"]),
                value: Value::from(false),
                detail: "the plugin was switched off in the Agent's own settings".to_string(),
            },
            Step::MoveOut(MoveOutPlan {
                source: &version,
                contents: &version,
                shape: crate::item::Shape::Tree,
                expected_hash: &item.content_hash,
                caps: crate::item::TreeCaps::default(),
                detail: String::new(),
            }),
        ];

        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");

        assert_eq!(receipt.steps.len(), 2);
        assert_eq!(receipt.steps[0].primitive, Primitive::NativeDisable);
        assert_eq!(receipt.steps[1].primitive, Primitive::MoveOut);
        assert!(
            bench
                .read("settings.json")
                .contains("\"notes@demo\": false")
        );
        assert!(!version.exists());

        let report = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Refuse,
        );

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(bench.read("settings.json"), SETTINGS);
        assert!(version.join("plugin.json").is_file());
    }

    /// Re-enable reverses the native disable and nothing else: the old version
    /// stays in the store (spec section 5.4).
    #[test]
    fn replaying_only_the_native_disable_leaves_the_payload_where_it_is() {
        let bench = Bench::new();
        let settings = bench.write("settings.json", SETTINGS);
        let file = bench.write("payload.txt", "planted\n");
        let item = bench.item(Kind::Plugin, &file, "planted\n");
        let hash = sha256_hex(b"planted\n");
        let steps = [
            Step::NativeDisable {
                file: &settings,
                format: Format::Json,
                entry: entry(&["enabledPlugins", "notes@demo"]),
                value: Value::from(false),
                detail: String::new(),
            },
            Step::MoveOut(MoveOutPlan {
                source: &file,
                contents: &file,
                shape: crate::item::Shape::File,
                expected_hash: &hash,
                caps: crate::item::TreeCaps::default(),
                detail: String::new(),
            }),
        ];
        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");

        let report = replay_only(
            &bench.host,
            &bench.store,
            &receipt,
            Primitive::NativeDisable,
            Conflict::Refuse,
        );

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.steps.len(), 1);
        assert_eq!(bench.read("settings.json"), SETTINGS);
        assert!(!file.exists(), "the old version left the store");
        assert!(
            crate::quarantine::Store::payload_of(&bench.store, &receipt.id).is_file(),
            "the payload is gone from the store"
        );
    }

    /// A Quarantine that cannot be finished leaves the Surface as it found it,
    /// so the Event Log never records a step that was taken alone.
    #[test]
    fn a_step_that_fails_takes_the_steps_before_it_back() {
        let bench = Bench::new();
        let settings = bench.write("settings.json", SETTINGS);
        let steps = [
            Step::NativeDisable {
                file: &settings,
                format: Format::Json,
                entry: entry(&["enabledPlugins", "notes@demo"]),
                value: Value::from(false),
                detail: String::new(),
            },
            Step::RemoveEntry {
                file: &settings,
                format: Format::Json,
                entry: entry(&["nothing", "here"]),
                detail: String::new(),
            },
        ];
        let item = bench.item(Kind::Plugin, &settings, "x");

        let error =
            carry_out(&bench.host, &bench.store, &item, &steps).expect_err("the second step fails");

        assert!(matches!(error, EnforcementError::Edit { .. }), "{error}");
        assert_eq!(bench.read("settings.json"), SETTINGS);
    }

    #[test]
    fn a_neutralised_line_is_switched_back_on_by_its_own_receipt() {
        let bench = Bench::new();
        let file = bench.write(
            ".env",
            "DATABASE_URL=postgres://localhost/demo\nCODEX_HOME=./.codex\n",
        );
        let item = bench.item(Kind::EnvFile, &file, "x");
        let steps = [Step::NeutraliseInPlace {
            file: &file,
            lines: vec![1],
            detail: "the line that re-points the Agent was commented out".to_string(),
        }];

        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");

        let after = bench.read(".env");
        assert!(
            after.contains("DATABASE_URL=postgres://localhost/demo\n"),
            "{after}"
        );
        assert!(
            after.contains(&format!(
                "# agentsweep: quarantined {} CODEX_HOME",
                receipt.id
            )),
            "{after}"
        );

        let report = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Refuse,
        );

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(
            bench.read(".env"),
            "DATABASE_URL=postgres://localhost/demo\nCODEX_HOME=./.codex\n"
        );
    }

    #[test]
    fn a_step_whose_file_is_gone_is_skipped_rather_than_failed() {
        let bench = Bench::new();
        let file = bench.write(".mcp.json", SERVERS);
        let item = bench.item(Kind::McpServer, &file, "{}");
        let steps = [Step::RemoveEntry {
            file: &file,
            format: Format::Json,
            entry: entry(&["mcpServers", "planted"]),
            detail: String::new(),
        }];
        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");
        std::fs::remove_file(&file).expect("the file goes away");

        let report = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Refuse,
        );

        assert_eq!(report.result, Outcome::Skipped);
        assert_eq!(report.steps[0].outcome, Outcome::Skipped);
    }

    #[test]
    fn an_entry_whose_key_something_else_took_is_refused_and_replaced_only_when_asked() {
        let bench = Bench::new();
        let file = bench.write(".mcp.json", SERVERS);
        let item = bench.item(Kind::McpServer, &file, "{}");
        let steps = [Step::RemoveEntry {
            file: &file,
            format: Format::Json,
            entry: entry(&["mcpServers", "planted"]),
            detail: String::new(),
        }];
        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");
        std::fs::write(
            &file,
            serde_json::to_string_pretty(&json!({"mcpServers": {"planted": {"command": "php"}}}))
                .expect("a file")
                + "\n",
        )
        .expect("the entry comes back under another command");

        let refused = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Refuse,
        );
        assert_eq!(refused.result, Outcome::Failed);
        assert!(refused.conflicted, "{refused:?}");

        let replaced = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Replace,
        );
        assert!(replaced.is_complete(), "{replaced:?}");
        assert_eq!(bench.read(".mcp.json"), SERVERS);
    }
    /// Spec section 5.5: a sensitive value reaches a record as a hash and
    /// never in the clear. The entry itself is content, so it lives in the
    /// store beside the payload, which is where quarantined content belongs.
    #[test]
    fn the_token_of_a_removed_server_is_in_the_store_and_in_no_step() {
        const TOKEN: &str = "sk-live-not-a-real-token";
        let bench = Bench::new();
        let written = format!(
            "{{\n  \"mcpServers\": {{\n    \"tracker\": {{\n      \"env\": {{\n        \"API_TOKEN\": \"{TOKEN}\"\n      }}\n    }}\n  }}\n}}\n"
        );
        let file = bench.write(".mcp.json", &written);
        let item = bench.item(Kind::McpServer, &file, "{\"env\":{}}");
        let steps = [Step::RemoveEntry {
            file: &file,
            format: Format::Json,
            entry: entry(&["mcpServers", "tracker"]),
            detail: "the MCP server tracker was removed from the file".to_string(),
        }];

        let receipt = carry_out(&bench.host, &bench.store, &item, &steps).expect("a Quarantine");

        // The steps are what the Event Log records, so nothing in them may
        // hold the value.
        for step in &receipt.steps {
            assert!(!step.detail.contains(TOKEN), "{step:?}");
            assert!(!step.locator.contains(TOKEN), "{step:?}");
            assert!(!step.path.contains(TOKEN), "{step:?}");
        }
        assert!(!bench.read(".mcp.json").contains(TOKEN));
        // The entry is in the store, which is where what was quarantined
        // belongs and what a Restore puts back.
        let kept = crate::quarantine::Store::kept(&bench.store, &receipt.id, 0).expect("the entry");
        assert!(kept.value.expect("the entry").to_string().contains(TOKEN));

        let report = crate::quarantine::replay_in_reverse(
            &bench.host,
            &bench.store,
            &receipt,
            Conflict::Refuse,
        );

        assert!(report.is_complete(), "{report:?}");
        assert_eq!(bench.read(".mcp.json"), written);
    }
    /// Spec section 5.2: NativeDisable is never the sole primitive, only an
    /// addition. A switch on its own leaves the code where it is, and both
    /// Agents re-fetch a plugin after session start.
    #[test]
    fn a_native_disable_is_never_a_quarantines_only_step() {
        for row in crate::adapter::ELIGIBILITY {
            let disables = row
                .primitives
                .contains(&crate::adapter::Primitive::NativeDisable);
            assert!(
                !disables || row.primitives.len() > 1,
                "{} is switched off and nothing else",
                row.kind
            );
        }
    }
}
