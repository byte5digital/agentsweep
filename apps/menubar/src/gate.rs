//! Everything of the Gate the user sees (spec sections 6.6, 7.6, 8.1, 8.6
//! and 8.10), over the daemon's Gate state and switch.
//!
//! - The Health lines of the Gate rung, in the Simple and the Developer
//!   wording: [`health_lines`], which is the Health's own pair of sentences,
//!   so the popover, the Overview and the command line interface say the
//!   same about the same machine.
//! - "Gate off in this project" per affected project on the Overview:
//!   [`projects_off`]. A state of the project, shown and not fought: the
//!   line offers no action, and nothing in the app changes a project's
//!   settings.
//! - The Settings switch **Stop the AI from using flagged items** with its
//!   fixed subtitle; in the Developer Posture "Gate: hooks in Claude Code and
//!   Codex" with the two entry locations: [`switch_view`]. Switching it
//!   sends the daemon's `gate-hooks` request ([`switch`]) and the pane
//!   follows the answer. The daemon writes and removes the entries; the app
//!   writes nothing into an Agent's files itself.

use std::collections::BTreeMap;
use std::path::Path;

use agentsweep_core::health::Health;
use agentsweep_core::overview::Overview;
use agentsweep_core::settings::Posture;
use serde_json::{Value, json};

use crate::asking::{Asking, refusal};
use crate::settings_pane::OVERRIDABLE_AGENTS;

/// What the Overview says of a project that switched the check off for
/// itself (spec section 7.6), in both Postures.
pub const GATE_OFF_HERE: &str = "Gate off in this project";

/// The switch's label in the Simple Posture (spec section 8.10).
pub const SWITCH_LABEL: &str = "Stop the AI from using flagged items";

/// The switch's label in the Developer Posture (spec section 8.10).
pub const SWITCH_LABEL_DEVELOPER: &str = "Gate: hooks in Claude Code and Codex";

/// The switch's fixed subtitle, in both Postures (spec section 8.10).
pub const SWITCH_SUBTITLE: &str = "AgentSweep adds a small check to Claude Code and Codex that \
     refuses a step while something flagged waits for your decision. A project can switch it \
     off, so it is a backup, not the main protection.";

/// The file in each Agent's settings folder the Gate's entries go into
/// (spec section 7.2), by Agent id.
const ENTRY_FILES: [(&str, &str); 2] = [("claude-code", "settings.json"), ("codex", "hooks.json")];

/// The Health lines of the Gate rung in a Posture, in the order of spec
/// section 6.6: "N projects switched off the check" / "Gate off in N
/// projects" first, then one line per Agent where the Gate cannot stand,
/// such as "The check could not be added to Claude Code." / "Gate
/// registration failed: Claude Code." and "Your organisation's policy
/// blocks the check." / "Gate blocked by managed policy.". Empty while the
/// Gate stands everywhere.
pub fn health_lines(health: &Health, posture: Posture) -> Vec<String> {
    health.gate_sentences(posture)
}

/// One project that switched the check off for itself, as the Overview
/// lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOff {
    /// The project as the Posture names it: its folder name in the Simple
    /// Posture, its root and the Agents it switched off in the Developer
    /// Posture.
    pub project: String,
    /// "Gate off in this project".
    pub line: &'static str,
}

/// Every pooled project whose own settings switch the check off for at
/// least one Agent, in the order the last Full Scan listed them. Nothing
/// here can change the project's settings: the line is shown, not fought.
pub fn projects_off(overview: &Overview, posture: Posture) -> Vec<ProjectOff> {
    let name_of = |agent: &str| {
        overview
            .agents
            .iter()
            .find(|record| record.agent == agent && !record.display_name.is_empty())
            .map_or_else(|| agent.to_string(), |record| record.display_name.clone())
    };
    overview
        .projects
        .iter()
        .filter_map(|project| {
            let agents: Vec<String> = project
                .agents
                .iter()
                .filter(|agent| agent.gate_off)
                .map(|agent| name_of(&agent.agent))
                .collect();
            if agents.is_empty() {
                return None;
            }
            let project = match posture {
                Posture::Simple => Path::new(&project.root)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&project.root)
                    .to_string(),
                Posture::Developer => format!("{} ({})", project.root, agents.join(", ")),
            };
            Some(ProjectOff {
                project,
                line: GATE_OFF_HERE,
            })
        })
        .collect()
}

/// Where the Gate's entries are written, one per Agent: the Agent's
/// settings folder, or the folder the user chose for it in Advanced.
pub fn entry_locations(config_dirs: &BTreeMap<String, String>) -> Vec<String> {
    ENTRY_FILES
        .iter()
        .map(|(agent, file)| {
            let folder = config_dirs
                .get(*agent)
                .filter(|dir| !dir.is_empty())
                .map(|dir| dir.trim_end_matches('/').to_string())
                .or_else(|| {
                    OVERRIDABLE_AGENTS
                        .iter()
                        .find(|(id, _, _)| id == agent)
                        .map(|(_, _, default)| default.to_string())
                })
                .unwrap_or_default();
            format!("{folder}/{file}")
        })
        .collect()
}

/// The switch as the Settings pane renders it: on as the daemon last said
/// it, the label of the Posture, the fixed subtitle, and in the Developer
/// Posture the two entry locations. With Protection off it cannot be
/// moved, since only the daemon writes or removes the entries.
pub fn switch_view(
    health: &Health,
    config_dirs: &BTreeMap<String, String>,
    posture: Posture,
) -> Value {
    let developer = posture == Posture::Developer;
    json!({
        "label": if developer { SWITCH_LABEL_DEVELOPER } else { SWITCH_LABEL },
        "subtitle": SWITCH_SUBTITLE,
        "on": health.gate_hooks,
        "available": !health.protection.is_off(),
        "locations": developer.then(|| entry_locations(config_dirs)),
    })
}

/// Moves the switch through the daemon's `gate-hooks` request and answers
/// where it stands afterwards: off has taken the entries away from every
/// Agent, on has registered them again.
pub fn switch(asking: &Asking, on: bool) -> Result<bool, String> {
    asking.set_gate_hooks(on).map_err(|error| refusal(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::health::{GateLine, GateTrouble};
    use agentsweep_core::overview::{AgentRecord, ProjectAgent, ProjectRecord};

    fn line(trouble: GateTrouble) -> GateLine {
        GateLine {
            agent: "claude-code".to_string(),
            name: "Claude Code".to_string(),
            trouble,
        }
    }

    /// Spec section 6.6, rung 5, word for word in both Postures.
    #[test]
    fn each_of_the_three_health_lines_reads_as_the_specification_has_it() {
        let mut health = Health::running();
        health.projects_gate_off = 3;
        assert_eq!(
            health_lines(&health, Posture::Simple),
            ["3 projects switched off the check."]
        );
        assert_eq!(
            health_lines(&health, Posture::Developer),
            ["Gate off in 3 projects."]
        );

        health.projects_gate_off = 0;
        health.gate_lines = vec![line(GateTrouble::RegistrationFailed)];
        assert_eq!(
            health_lines(&health, Posture::Simple),
            ["The check could not be added to Claude Code."]
        );
        assert_eq!(
            health_lines(&health, Posture::Developer),
            ["Gate registration failed: Claude Code."]
        );

        health.gate_lines = vec![line(GateTrouble::ManagedPolicy)];
        assert_eq!(
            health_lines(&health, Posture::Simple),
            ["Your organisation's policy blocks the check."]
        );
        assert_eq!(
            health_lines(&health, Posture::Developer),
            ["Gate blocked by managed policy."]
        );

        health.gate_lines.clear();
        assert!(health_lines(&health, Posture::Simple).is_empty());
    }

    #[test]
    fn every_gate_line_is_listed_projects_first() {
        let mut health = Health::running();
        health.projects_gate_off = 1;
        health.gate_lines = vec![line(GateTrouble::RegistrationFailed)];
        assert_eq!(
            health_lines(&health, Posture::Developer),
            [
                "Gate off in 1 project.",
                "Gate registration failed: Claude Code."
            ]
        );
    }

    fn overview() -> Overview {
        let project = |root: &str, off: bool| ProjectRecord {
            root: root.to_string(),
            agents: vec![
                ProjectAgent {
                    agent: "claude-code".to_string(),
                    registered: true,
                    gate_off: off,
                },
                ProjectAgent {
                    agent: "codex".to_string(),
                    registered: true,
                    gate_off: false,
                },
            ],
            ..ProjectRecord::default()
        };
        Overview {
            agents: vec![AgentRecord {
                agent: "claude-code".to_string(),
                display_name: "Claude Code".to_string(),
                installed: true,
                version: None,
                config_dir: "~/.claude".to_string(),
                projects: 2,
                items: 0,
                layers_not_read: Vec::new(),
            }],
            projects: vec![project("~/work/quiet", false), project("~/work/demo", true)],
            ambiguous: Vec::new(),
            checked: Vec::new(),
        }
    }

    #[test]
    fn a_project_with_the_gate_off_is_named_with_the_fixed_line() {
        assert_eq!(
            projects_off(&overview(), Posture::Simple),
            [ProjectOff {
                project: "demo".to_string(),
                line: GATE_OFF_HERE,
            }]
        );
        assert_eq!(
            projects_off(&overview(), Posture::Developer),
            [ProjectOff {
                project: "~/work/demo (Claude Code)".to_string(),
                line: GATE_OFF_HERE,
            }]
        );
        assert_eq!(GATE_OFF_HERE, "Gate off in this project");
    }

    #[test]
    fn the_switch_has_the_fixed_subtitle_and_the_developer_entry_locations() {
        let health = Health::running();
        let none = BTreeMap::new();
        let simple = switch_view(&health, &none, Posture::Simple);
        assert_eq!(simple["label"], "Stop the AI from using flagged items");
        assert_eq!(
            simple["subtitle"],
            "AgentSweep adds a small check to Claude Code and Codex that refuses a step while \
             something flagged waits for your decision. A project can switch it off, so it is a \
             backup, not the main protection."
        );
        assert_eq!(simple["on"], true);
        assert_eq!(simple["locations"], Value::Null);

        let developer = switch_view(&health, &none, Posture::Developer);
        assert_eq!(developer["label"], "Gate: hooks in Claude Code and Codex");
        assert_eq!(developer["subtitle"], simple["subtitle"]);
        assert_eq!(
            developer["locations"],
            json!(["~/.claude/settings.json", "~/.codex/hooks.json"])
        );
    }

    #[test]
    fn a_chosen_settings_folder_moves_its_entry_location() {
        let dirs = BTreeMap::from([("codex".to_string(), "/Users/x/codex-home/".to_string())]);
        assert_eq!(
            entry_locations(&dirs),
            ["~/.claude/settings.json", "/Users/x/codex-home/hooks.json"]
        );
    }

    #[test]
    fn the_switch_follows_the_health_and_waits_for_a_daemon() {
        let mut health = Health::running();
        health.gate_hooks = false;
        let view = switch_view(&health, &BTreeMap::new(), Posture::Simple);
        assert_eq!(view["on"], false);
        assert_eq!(view["available"], true);
        let off = switch_view(
            &Health::unreachable("gone"),
            &BTreeMap::new(),
            Posture::Simple,
        );
        assert_eq!(off["available"], false);
    }
}
