//! What "Scan a folder" shows: the one-off answer of a Folder Scan the daemon
//! ran, "safe to open" or "do not open yet", with the Findings beneath and the
//! line that nothing was recorded (spec section 8.9).
//!
//! The wording is the command line interface's for `agentsweep scan <dir>`,
//! less the line about Drift: that line says the in-process pass reaches no
//! daemon, and this one was the daemon's. It names the Rule Pack in force that
//! judged the folder, because the command line interface uses the bundled
//! pack and the two may answer differently. Placeholder otherwise.

use agentsweep_ipc::protocol::{FolderScanResult, NOTHING_RECORDED};
use serde_json::{Value, json};

use crate::findings::{count, plain_card};

/// The value the window receives for a finished Folder Scan.
pub fn result_view(result: &FolderScanResult) -> Value {
    json!({
        "state": "done",
        "root": result.root,
        "safe": result.is_safe(),
        "verdict": result.verdict(),
        "summary": format!(
            "{}, {}.",
            count(result.items, "Item", "Items"),
            count(result.findings.len(), "Finding", "Findings")
        ),
        "ambiguous": match result.ambiguous {
            0 => String::new(),
            n => format!(
                "{} in the Ambiguous Band, nothing to do.",
                count(n, "Item", "Items")
            ),
        },
        "recorded": NOTHING_RECORDED,
        "rulePack": format!("Checked with Rule Pack {}, the one in force.", result.rule_pack),
        "findings": result
            .findings
            .iter()
            .map(|one| {
                let mut card = plain_card(&one.finding);
                card["heuristics"] = Value::from(one.heuristics.clone());
                card
            })
            .collect::<Vec<_>>(),
    })
}

/// The value the window receives while the Folder Scan runs.
pub fn running_view(root: &str) -> Value {
    json!({ "state": "running", "root": root, "line": format!("Checking {root}.") })
}

/// The value the window receives when the Folder Scan could not be run.
pub fn failed_view(root: &str, why: &str) -> Value {
    json!({ "state": "failed", "root": root, "line": why })
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
        let finding = recorded(
            "claude-code/project:/src/demo/instruction-file/CLAUDE.md",
            Kind::InstructionFile,
            "rule 0001",
            Category::Threat,
            FindingState::Open,
        );
        let result = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 2,
            ambiguous: 1,
            findings: vec![FolderFinding {
                finding: finding.clone(),
                heuristics: vec!["0501  weight 2  It downloads something.".to_string()],
            }],
            rule_pack: 3,
        };
        let view = result_view(&result);
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
    }

    #[test]
    fn a_clean_folder_is_safe_to_open() {
        let result = FolderScanResult {
            root: "/src/demo".to_string(),
            items: 1,
            ambiguous: 0,
            findings: Vec::new(),
            rule_pack: 3,
        };
        let view = result_view(&result);
        assert_eq!(view["verdict"], "Safe to open.");
        assert_eq!(view["safe"], true);
        assert_eq!(view["summary"], "1 Item, no Findings.");
        assert_eq!(view["ambiguous"], "");
        assert_eq!(view["findings"], json!([]));
    }

    #[test]
    fn a_running_and_a_failed_scan_say_where() {
        assert_eq!(running_view("/src/demo")["line"], "Checking /src/demo.");
        let failed = failed_view(
            "/src/demo",
            "Nothing was checked: `/src/demo` is not a folder.",
        );
        assert_eq!(failed["state"], "failed");
    }
}
