//! The **Scan a folder** dialog (spec section 8.9): a folder picker and a
//! drop zone that takes one folder, the equivalent `agentsweep scan <dir>` in
//! the Developer Posture, and the one-off answer of a Folder Scan the daemon
//! ran, "safe to open" or "do not open yet", with the Findings beneath in the
//! Posture's wording and the line that nothing was recorded.
//!
//! The popover and the Overview open the same dialog. A drop is resolved
//! here to one absolute folder path before the Folder Scan request is sent,
//! which stays the only path the app sends for a Scan (ADR 0008); a file,
//! several items or nothing is refused without asking the daemon. A Folder
//! Scan may run beside another Scan (spec section 6.4), so nothing here waits
//! on the Health "checking now" rung.
//!
//! The answer's wording is the command line interface's for
//! `agentsweep scan <dir>`, less the line about Drift: that line says the
//! in-process pass reaches no daemon, and this one was the daemon's. It names
//! the Rule Pack in force that judged the folder, because the command line
//! interface uses the bundled pack and the two may answer differently.

use std::path::{Path, PathBuf};

use agentsweep_core::settings::Posture;
use agentsweep_ipc::protocol::{FolderFinding, FolderScanResult, NOTHING_RECORDED};
use serde_json::{Value, json};

use crate::asking::{Asking, refusal};
use crate::findings::{count, plain_card};
use crate::wording::{self, Part};

/// What one dropped path turned out to be on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnDisk {
    /// A folder.
    Folder,
    /// Anything else that exists: a file, a device, a socket.
    File,
    /// Nothing the app could find.
    Missing,
}

/// Why a drop was not turned into a Folder Scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DropRefusal {
    /// The drop carried no item.
    Nothing,
    /// The drop carried more than one item; the count.
    Several(usize),
    /// The one item was not a folder.
    File(PathBuf),
    /// The one item could not be found.
    Missing(PathBuf),
}

impl DropRefusal {
    /// The sentence the dialog shows; nothing was asked of the daemon.
    pub fn line(&self) -> String {
        match self {
            DropRefusal::Nothing => {
                "Nothing was dropped. Drop one folder here, or choose one.".to_string()
            }
            DropRefusal::Several(n) => {
                format!("{n} items were dropped. Drop one folder at a time, or choose one.")
            }
            DropRefusal::File(_) => {
                "That is a file, not a folder. Drop the folder it is in, or choose one.".to_string()
            }
            DropRefusal::Missing(_) => {
                "That could not be found. Drop one folder here, or choose one.".to_string()
            }
        }
    }
}

/// The one folder a drop names, or why it names none: the drop must carry
/// exactly one item, and that item must be a folder at an absolute path.
/// Each item comes with what the app found on disk for it ([`look`]).
pub fn dropped_folder(dropped: &[(PathBuf, OnDisk)]) -> Result<PathBuf, DropRefusal> {
    match dropped {
        [] => Err(DropRefusal::Nothing),
        [(path, OnDisk::Folder)] if path.is_absolute() => Ok(path.clone()),
        [(path, OnDisk::File)] => Err(DropRefusal::File(path.clone())),
        [(path, _)] => Err(DropRefusal::Missing(path.clone())),
        several => Err(DropRefusal::Several(several.len())),
    }
}

/// What one dropped path is on disk, at the absolute path it resolves to,
/// links followed. A path that does not resolve is missing as it was given.
pub fn look(path: &Path) -> (PathBuf, OnDisk) {
    match std::fs::canonicalize(path) {
        Ok(resolved) if resolved.is_dir() => (resolved, OnDisk::Folder),
        Ok(resolved) => (resolved, OnDisk::File),
        Err(_) => (path.to_path_buf(), OnDisk::Missing),
    }
}

/// The paths of one drop onto the dialog, resolved to the one absolute folder
/// path the Folder Scan request will carry, or the refusal.
pub fn resolve_drop(paths: &[String]) -> Result<String, DropRefusal> {
    let looked: Vec<(PathBuf, OnDisk)> = paths.iter().map(|path| look(Path::new(path))).collect();
    dropped_folder(&looked).map(|folder| folder.display().to_string())
}

/// The folder quoted for a shell: in single quotes, a single quote inside
/// written as `'\''`, so any folder name pastes as one argument.
pub fn shell_quoted(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

/// The command line that runs the same check from a terminal, shown in the
/// Developer Posture only.
pub fn command_line(root: &str) -> String {
    format!("agentsweep scan {}", shell_quoted(root))
}

/// The command line for a chosen folder in the Posture the dialog is shown
/// in: the string in the Developer Posture, null in the Simple Posture.
fn command(root: &str, posture: Posture) -> Value {
    match posture {
        Posture::Developer => Value::from(command_line(root)),
        Posture::Simple => Value::Null,
    }
}

/// The value the dialog receives when it opens with no folder chosen yet.
pub fn choosing_view() -> Value {
    json!({ "state": "choosing" })
}

/// The value the dialog receives when a drop named no folder.
pub fn refused_view(refused: &DropRefusal) -> Value {
    json!({ "state": "refused", "line": refused.line() })
}

/// The value the dialog receives for a finished Folder Scan, in the Posture
/// the window is shown in. The Ambiguous count line exists in the Developer
/// Posture only (spec section 8.4), with the line that the AI check did not
/// finish when it left some of them without an answer.
pub fn result_view(result: &FolderScanResult, posture: Posture) -> Value {
    json!({
        "state": "done",
        "root": result.root,
        "command": command(&result.root, posture),
        "safe": result.is_safe(),
        "verdict": result.verdict(),
        "summary": format!(
            "{}, {}.",
            count(result.items, "Item", "Items"),
            count(result.findings.len(), "Finding", "Findings")
        ),
        "ambiguous": match (result.ambiguous, posture) {
            (0, _) | (_, Posture::Simple) => String::new(),
            (n, Posture::Developer) => {
                let band = format!(
                    "{} in the Ambiguous Band, nothing to do.",
                    count(n, "Item", "Items")
                );
                match result.unfinished_line() {
                    None => band,
                    Some(line) => format!("{band} {line}"),
                }
            }
        },
        "recorded": NOTHING_RECORDED,
        "rulePack": format!("Checked with Rule Pack {}, the one in force.", result.rule_pack),
        "findings": result.findings.iter().map(folder_card).collect::<Vec<_>>(),
    })
}

/// One Finding of a Folder Scan as the dialog renders it: the Simple
/// wording, the Developer heading and the technical table of tickets 71 and
/// 72, and no actions, since nothing was recorded to act on. Two body lines
/// of the Simple wording speak of what AgentSweep did to an Item it watches,
/// and nothing was done to this one, so they are left out: why nothing
/// happened by itself, and that git will show a change Restore undoes.
pub fn folder_card(one: &FolderFinding) -> Value {
    let finding = &one.finding;
    let mut simple = wording::simple(finding);
    simple
        .lines
        .retain(|line| !matches!(line.part, Part::WhyNothingHappened | Part::Project));
    simple.admin_message = None;
    let mut card = plain_card(finding);
    card["heuristics"] = Value::from(one.heuristics.clone());
    card["simple"] = simple.to_value();
    card["developer"] = crate::developer::heading(finding).to_value();
    card["technical"] = wording::technical_value(finding);
    card
}

/// The value the dialog receives while the Folder Scan runs.
pub fn running_view(root: &str, posture: Posture) -> Value {
    json!({
        "state": "running",
        "root": root,
        "command": command(root, posture),
        "line": format!("Checking {root}."),
    })
}

/// The value the dialog receives when the Folder Scan could not be run.
pub fn failed_view(root: &str, why: &str, posture: Posture) -> Value {
    json!({ "state": "failed", "root": root, "command": command(root, posture), "line": why })
}

/// Asks the daemon for a Folder Scan of one absolute folder path and answers
/// with the dialog's view of how it ended.
pub fn scan(asking: &Asking, root: &str, posture: Posture) -> Value {
    match asking.folder_scan(root) {
        Ok(result) => result_view(&result, posture),
        Err(error) => failed_view(
            root,
            &refusal(&error).replace("Nothing was done", "Nothing was checked"),
            posture,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::finding::{Category, FindingState};
    use agentsweep_core::item::Kind;
    use agentsweep_ipc::protocol::FolderFinding;

    use crate::findings::tests::recorded;

    #[test]
    fn a_folder_with_a_finding_is_do_not_open_yet_with_the_finding_beneath() {
        let mut finding = recorded(
            "claude-code/project:/src/demo/instruction-file/CLAUDE.md",
            Kind::InstructionFile,
            "rule 0001",
            Category::Threat,
            FindingState::Open,
        );
        finding.facts.why_nothing_happened =
            Some(agentsweep_core::finding_facts::WhyNothingHappened::Probation);
        let result = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 2,
            ambiguous: 1,
            unfinished: 0,
            findings: vec![FolderFinding {
                finding: finding.clone(),
                heuristics: vec!["0501  weight 2  It downloads something.".to_string()],
            }],
            rule_pack: 3,
        };
        let view = result_view(&result, Posture::Developer);
        assert_eq!(
            result_view(&result, Posture::Simple)["ambiguous"],
            "",
            "no Ambiguous count in the Simple Posture"
        );
        assert_eq!(view["verdict"], "Do not open yet.");
        assert_eq!(view["safe"], false);
        assert_eq!(view["summary"], "2 Items, 1 Finding.");
        assert_eq!(view["recorded"], "Nothing was recorded.");
        assert_eq!(
            view["rulePack"],
            "Checked with Rule Pack 3, the one in force."
        );
        assert_eq!(
            view["ambiguous"],
            "1 Item in the Ambiguous Band, nothing to do."
        );
        let card = &view["findings"][0];
        assert_eq!(card["id"], finding.id.as_str());
        assert_eq!(card["name"], "CLAUDE.md");
        assert_eq!(card["source"], "rule 0001");
        assert_eq!(card["probation"], "on probation");
        assert_eq!(card["actions"], json!([]), "a Folder Scan offers nothing");
        assert_eq!(
            card["heuristics"][0],
            "0501  weight 2  It downloads something."
        );
        // In the Posture's wording: the Simple title and the Developer
        // heading, with no line about what AgentSweep did to it.
        let simple = crate::wording::simple(&finding);
        assert_eq!(card["simple"]["title"], simple.title.as_str());
        assert_eq!(card["simple"]["severity"], simple.severity);
        assert_eq!(
            card["developer"]["title"],
            crate::developer::heading(&finding).to_value()["title"]
        );
        assert!(
            card["technical"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
        );
        let parts: Vec<&str> = card["simple"]["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .filter_map(|line| line["part"].as_str())
            .collect();
        let full: Vec<Part> = simple.lines.iter().map(|line| line.part).collect();
        assert!(full.contains(&Part::WhyNothingHappened), "{full:?}");
        assert!(full.contains(&Part::Project), "{full:?}");
        assert!(!parts.contains(&"why"), "{parts:?}");
        assert!(!parts.contains(&"project"), "{parts:?}");
        assert_eq!(card["simple"]["admin"], false);
    }

    #[test]
    fn a_clean_folder_is_safe_to_open() {
        let result = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 1,
            ambiguous: 0,
            unfinished: 0,
            findings: Vec::new(),
            rule_pack: 3,
        };
        let view = result_view(&result, Posture::Developer);
        assert_eq!(view["verdict"], "Safe to open.");
        assert_eq!(view["safe"], true);
        assert_eq!(view["summary"], "1 Item, no Findings.");
        assert_eq!(view["ambiguous"], "");
        assert_eq!(view["findings"], json!([]));
    }

    #[test]
    fn items_the_ai_check_did_not_finish_are_named_in_the_developer_posture() {
        let result = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 2,
            ambiguous: 2,
            unfinished: 1,
            findings: Vec::new(),
            rule_pack: 3,
        };
        assert_eq!(
            result_view(&result, Posture::Developer)["ambiguous"],
            "2 Items in the Ambiguous Band, nothing to do. \
             The AI check did not finish for 1 Item; it stays in the Ambiguous Band."
        );
        assert_eq!(result_view(&result, Posture::Simple)["ambiguous"], "");
    }

    #[test]
    fn a_running_and_a_failed_scan_say_where() {
        let running = running_view("/src/demo", Posture::Simple);
        assert_eq!(running["line"], "Checking /src/demo.");
        assert_eq!(running["command"], Value::Null);
        let failed = failed_view(
            "/src/demo",
            "Nothing was checked: `/src/demo` is not a folder.",
            Posture::Developer,
        );
        assert_eq!(failed["state"], "failed");
        assert_eq!(failed["command"], "agentsweep scan '/src/demo'");
    }

    fn folder() -> PathBuf {
        PathBuf::from("/src/demo")
    }

    #[test]
    fn one_dropped_folder_is_the_folder_to_scan() {
        assert_eq!(dropped_folder(&[(folder(), OnDisk::Folder)]), Ok(folder()));
    }

    #[test]
    fn a_dropped_file_is_refused() {
        let file = PathBuf::from("/src/demo/CLAUDE.md");
        let refused = dropped_folder(&[(file.clone(), OnDisk::File)]);
        assert_eq!(refused, Err(DropRefusal::File(file)));
        assert_eq!(
            refused.unwrap_err().line(),
            "That is a file, not a folder. Drop the folder it is in, or choose one."
        );
    }

    #[test]
    fn several_dropped_items_are_refused_even_when_all_are_folders() {
        let refused = dropped_folder(&[
            (folder(), OnDisk::Folder),
            (PathBuf::from("/src/other"), OnDisk::Folder),
        ]);
        assert_eq!(refused, Err(DropRefusal::Several(2)));
        assert_eq!(
            refused.unwrap_err().line(),
            "2 items were dropped. Drop one folder at a time, or choose one."
        );
    }

    #[test]
    fn a_drop_of_nothing_is_refused() {
        let refused = dropped_folder(&[]);
        assert_eq!(refused, Err(DropRefusal::Nothing));
        assert_eq!(
            refused.unwrap_err().line(),
            "Nothing was dropped. Drop one folder here, or choose one."
        );
    }

    #[test]
    fn a_missing_or_relative_item_is_refused() {
        let gone = PathBuf::from("/src/gone");
        assert_eq!(
            dropped_folder(&[(gone.clone(), OnDisk::Missing)]),
            Err(DropRefusal::Missing(gone))
        );
        let relative = PathBuf::from("demo");
        assert_eq!(
            dropped_folder(&[(relative.clone(), OnDisk::Folder)]),
            Err(DropRefusal::Missing(relative))
        );
    }

    #[test]
    fn a_drop_on_disk_resolves_to_one_absolute_folder() {
        let base = std::env::temp_dir().join(format!("agentsweep-drop-{}", std::process::id()));
        let inside = base.join("project");
        std::fs::create_dir_all(&inside).expect("a temporary folder");
        std::fs::write(inside.join("CLAUDE.md"), b"# demo\n").expect("a file");
        let resolved = resolve_drop(&[inside.display().to_string()]).expect("a folder");
        assert!(Path::new(&resolved).is_absolute());
        assert_eq!(
            PathBuf::from(&resolved),
            std::fs::canonicalize(&inside).expect("resolved")
        );
        assert!(matches!(
            resolve_drop(&[inside.join("CLAUDE.md").display().to_string()]),
            Err(DropRefusal::File(_))
        ));
        assert!(matches!(
            resolve_drop(&[base.join("gone").display().to_string()]),
            Err(DropRefusal::Missing(_))
        ));
        assert_eq!(resolve_drop(&[]), Err(DropRefusal::Nothing));
        std::fs::remove_dir_all(&base).expect("cleaned up");
    }

    #[test]
    fn the_folder_is_quoted_for_a_shell() {
        assert_eq!(command_line("/src/demo"), "agentsweep scan '/src/demo'");
        assert_eq!(
            command_line("/Users/me/My Projects/it's here"),
            "agentsweep scan '/Users/me/My Projects/it'\\''s here'"
        );
    }

    #[test]
    fn the_developer_view_shows_the_command_and_the_simple_view_does_not() {
        let result = FolderScanResult {
            root: "/src/my demo".to_string(),
            items: 1,
            ambiguous: 0,
            unfinished: 0,
            findings: Vec::new(),
            rule_pack: 3,
        };
        assert_eq!(
            result_view(&result, Posture::Developer)["command"],
            "agentsweep scan '/src/my demo'"
        );
        assert_eq!(
            result_view(&result, Posture::Simple)["command"],
            Value::Null
        );
        assert_eq!(
            running_view("/src/my demo", Posture::Developer)["command"],
            "agentsweep scan '/src/my demo'"
        );
        assert_eq!(
            running_view("/src/my demo", Posture::Simple)["command"],
            Value::Null
        );
    }

    #[test]
    fn a_refused_drop_names_no_folder_and_no_command() {
        let view = refused_view(&DropRefusal::Several(3));
        assert_eq!(view["state"], "refused");
        assert_eq!(view["command"], Value::Null);
        assert_eq!(choosing_view()["state"], "choosing");
    }

    /// Scan a folder in the popover and in the Overview send the same
    /// command, which opens the one dialog the window has. The dialog's
    /// buttons are not actions, so the "checking now" rung never greys them.
    #[test]
    fn the_popover_and_the_overview_open_the_same_dialog() {
        let popover = include_str!("../ui/popover.js");
        let window = include_str!("../ui/window.js");
        let page = include_str!("../ui/window.html");
        let opened_by = |script: &str| -> Vec<String> {
            script
                .split("addEventListener(\"click\", () =>")
                .skip(1)
                .filter_map(|rest| rest.split("invoke(\"").nth(1))
                .filter_map(|rest| rest.split('"').next())
                .filter(|command| command.contains("folder"))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(opened_by(popover), ["scan_folder"]);
        assert!(opened_by(window).contains(&"scan_folder".to_string()));
        assert!(page.contains("<button type=\"button\" id=\"scan-folder\">Scan a folder</button>"));
        assert_eq!(page.matches("<dialog id=\"folder-dialog\"").count(), 1);
        for word in [
            "choose_folder",
            "scan_dropped",
            "onDragDropEvent",
            "folder-dialog",
        ] {
            assert!(!popover.contains(word), "the popover has its own {word}");
        }
        let dialog = &page[page
            .find("<dialog id=\"folder-dialog\"")
            .expect("the dialog")..];
        let dialog = &dialog[..dialog.find("</dialog>").expect("its end")];
        assert!(!dialog.contains("data-action"));
        assert!(dialog.contains("id=\"folder-drop\""));
        assert!(dialog.contains("id=\"folder-choose\""));
    }
}
