//! What a Scan tells the Overview beside its Findings (spec section 8.1).
//!
//! A Full Scan detects every Agent and pools every project root, so it alone
//! may say which Agents there are, which version each has on disk, how many
//! projects and Items each has, and which roots were pooled by whom. Every
//! recording Scan says which of the Items it looked at fell in the Ambiguous
//! Band. Nothing is decided here: the adapters detected, the registries
//! listed and the Tiers scored; this only puts what they said in the form the
//! status carries.

use std::collections::BTreeSet;
use std::path::PathBuf;

use agentsweep_core::adapter::Detection;
use agentsweep_core::finding::Finding;
use agentsweep_core::finding_facts::HeuristicLine;
use agentsweep_core::heuristics::Assessment;
use agentsweep_core::item::{Item, ItemId};
use agentsweep_core::judged::AppliedVerdict;
use agentsweep_core::judgement::Verdict;
use agentsweep_core::overview::{
    AgentRecord, AmbiguousItem, CheckedItem, Overview, ProjectAgent, ProjectCheck, ProjectRecord,
};

/// One Agent as pooling found it: what `detect` said and which of the roots
/// its own registry names still exist.
#[derive(Clone, Debug)]
pub struct Detected {
    /// The Agent id.
    pub agent: &'static str,
    /// The name shown to a person.
    pub display_name: &'static str,
    /// What `detect` found, read from disk alone.
    pub detection: Detection,
    /// The config layers the adapter does not read.
    pub layers_not_read: &'static [&'static str],
    /// The project roots this Agent's registry names that are still there.
    pub registered: Vec<PathBuf>,
}

/// The Agent and project records one Full Scan leaves, with an empty
/// Ambiguous list for the caller to fill.
///
/// Every Agent is listed, installed or not. Every pooled root is listed once,
/// with every installed Agent, since each of them looks for its Surfaces at
/// every pooled root, and with every Agent whose registry names it; each says
/// whether its own registry does (spec section 3.3). A root the Full Scan
/// pooled is a root it read; a withheld root Needs Permission and is listed
/// as such, never as checked (spec section 9.7).
pub fn of_the_full_scan(
    detected: &[Detected],
    roots: &[PathBuf],
    withheld: &[PathBuf],
    items: &[Item],
) -> Overview {
    let mut every: Vec<(&PathBuf, ProjectCheck)> = roots
        .iter()
        .map(|root| (root, ProjectCheck::Checked))
        .chain(
            withheld
                .iter()
                .map(|root| (root, ProjectCheck::NeedsPermission)),
        )
        .collect();
    every.sort_by(|a, b| a.0.cmp(b.0));
    let agents = detected
        .iter()
        .map(|found| AgentRecord {
            agent: found.agent.to_string(),
            display_name: found.display_name.to_string(),
            installed: found.detection.installed,
            version: found.detection.version.clone(),
            config_dir: found
                .detection
                .config_dir
                .as_ref()
                .map(|dir| dir.display().to_string())
                .unwrap_or_default(),
            projects: every
                .iter()
                .filter(|(root, _)| found.registered.contains(root))
                .count(),
            items: items
                .iter()
                .filter(|item| item.agent == found.agent)
                .count(),
            layers_not_read: found
                .layers_not_read
                .iter()
                .map(|layer| layer.to_string())
                .collect(),
        })
        .collect();
    let projects = every
        .iter()
        .map(|&(root, check)| ProjectRecord {
            root: root.display().to_string(),
            agents: detected
                .iter()
                .filter_map(|found| {
                    let registered = found.registered.contains(root);
                    (registered || found.detection.installed).then(|| ProjectAgent {
                        agent: found.agent.to_string(),
                        registered,
                        // What the adapters stated about the project's hook
                        // switch is taken once they have enumerated it.
                        gate_off: false,
                    })
                })
                .collect(),
            check,
        })
        .collect();
    Overview {
        agents,
        projects,
        ambiguous: Vec::new(),
        checked: Vec::new(),
    }
}

/// The Items whose Score fell in the Ambiguous Band and on which nothing
/// raised a Finding, in enumeration order. An Item whose Heuristics folded
/// into a Rule Finding, or that carries any Finding of its own, is in a
/// Finding list already and is not repeated here.
pub fn ambiguous(
    assessments: &[Assessment],
    items: &[Item],
    raised: &[Finding],
) -> Vec<AmbiguousItem> {
    let flagged: BTreeSet<&ItemId> = raised.iter().map(|finding| &finding.item_id).collect();
    assessments
        .iter()
        .filter(|assessment| assessment.awaits_judgement())
        .filter(|assessment| !flagged.contains(&assessment.item_id))
        .filter_map(|assessment| {
            let item = items.iter().find(|item| item.id == assessment.item_id)?;
            Some(AmbiguousItem {
                item_id: item.id.clone(),
                kind: item.kind,
                score: assessment.score,
                heuristics: assessment
                    .fired
                    .iter()
                    .map(|heuristic| HeuristicLine::of(heuristic, Some(item)))
                    .collect(),
            })
        })
        .collect()
}

/// The Items a cached benign Verdict moved to Clear, in enumeration order:
/// the "checked by <engine>" notes the Developer Posture shows. A malicious
/// Verdict is a Finding and an unsure one leaves the Item Ambiguous, so
/// neither is named here.
pub fn checked(judged: &[AppliedVerdict], items: &[Item]) -> Vec<CheckedItem> {
    judged
        .iter()
        .filter(|applied| applied.verdict == Verdict::Benign)
        .filter_map(|applied| {
            let item = items.iter().find(|item| item.id == applied.item_id)?;
            Some(CheckedItem {
                item_id: item.id.clone(),
                kind: item.kind,
                engine: applied.engine.clone(),
                model: applied.model.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detected(agent: &'static str, installed: bool, registered: &[&str]) -> Detected {
        Detected {
            agent,
            display_name: agent,
            detection: Detection {
                installed,
                version: installed.then(|| "1.2.3".to_string()),
                config_dir: installed.then(|| PathBuf::from(format!("/home/.{agent}"))),
            },
            layers_not_read: &[],
            registered: registered.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn every_pooled_root_is_listed_once_with_who_registered_it() {
        let found = [
            detected("claude-code", true, &["/work/a", "/work/b"]),
            detected("codex", true, &["/work/b"]),
            detected("absent", false, &[]),
        ];
        let roots = [PathBuf::from("/work/a"), PathBuf::from("/work/b")];
        let overview = of_the_full_scan(&found, &roots, &[], &[]);

        assert_eq!(overview.agents.len(), 3, "an Agent not installed is listed");
        assert_eq!(overview.agents[0].projects, 2);
        assert_eq!(overview.agents[1].projects, 1);
        assert!(!overview.agents[2].installed);
        assert_eq!(overview.agents[2].version, None);

        assert_eq!(overview.projects.len(), 2);
        let a = &overview.projects[0];
        assert_eq!(a.root, "/work/a");
        assert_eq!(
            a.agents,
            vec![
                ProjectAgent {
                    agent: "claude-code".to_string(),
                    registered: true,
                    gate_off: false,
                },
                ProjectAgent {
                    agent: "codex".to_string(),
                    registered: false,
                    gate_off: false,
                },
            ]
        );
        assert_eq!(a.check, ProjectCheck::Checked);
        assert!(
            overview.projects[1]
                .agents
                .iter()
                .all(|agent| agent.registered)
        );
    }

    /// A root that Needs Permission is listed among the others, in path
    /// order, counted for the Agent that registered it and never as checked.
    #[test]
    fn a_withheld_root_is_listed_as_needing_permission() {
        let found = [detected(
            "claude-code",
            true,
            &["/home/Documents/b", "/work/a"],
        )];
        let roots = [PathBuf::from("/work/a")];
        let withheld = [PathBuf::from("/home/Documents/b")];
        let overview = of_the_full_scan(&found, &roots, &withheld, &[]);

        assert_eq!(overview.agents[0].projects, 2);
        let listed: Vec<(&str, ProjectCheck)> = overview
            .projects
            .iter()
            .map(|project| (project.root.as_str(), project.check))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("/home/Documents/b", ProjectCheck::NeedsPermission),
                ("/work/a", ProjectCheck::Checked),
            ]
        );
    }
}
