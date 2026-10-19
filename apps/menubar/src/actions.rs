//! The actions of spec section 8.5 on one Finding, in the spec's own words,
//! and the confirmations that go with them.
//!
//! [`offered`] is a pure function of a Finding, its facts and the Posture: it
//! takes the offers the daemon allows ([`offers`]) and gives each its button,
//! its label, and the confirmation asked before the request goes out. Who took
//! a stopped Item out is a fact the daemon sent with the Finding (its actor),
//! so the button reads **Restore and trust this version** or **Restore**
//! before it is pressed, without asking the daemon first.
//!
//! Every action is still carried out by the daemon's request of the same
//! name; nothing here decides what is allowed. The confirmation texts are
//! written once, below: the Trust confirmation explains that Trust is bound
//! to this exact version, the restore-and-trust confirmation says that only
//! this exact version is trusted and quotes why the Item was stopped, and the
//! confirmation after a Quarantine says whether the Agent appears to be
//! running, asks for a restart and, on Project Scope, says git will show the
//! change (spec section 8.5, the owner's decision of 2026-10-14 for ticket 73).

use agentsweep_core::eventlog::{Actor, SessionsRunning};
use agentsweep_core::finding::Category;
use agentsweep_core::item::ItemId;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use agentsweep_ipc::protocol::{Offer, Sessions, offers};
use serde_json::{Value, json};

use crate::findings::{card, neutralised_in_place};
use crate::how_to::how_to;
use crate::wording::{self, Named, PROJECT_LINE};

/// The confirmation asked before an action's request goes out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confirm {
    /// Trust this version, or keep an Exposure as it is: explains hash-bound
    /// Trust ([`trust_confirmation`]).
    Trust,
    /// The Restore of what AgentSweep took out by itself, which trusts this
    /// exact version ([`restore_confirmation`]).
    RestoreAndTrust,
    /// Delete permanently, which cannot be undone
    /// ([`crate::quarantine::purge_confirmation`]).
    Purge,
}

impl Confirm {
    /// The name the window asks by.
    pub fn as_str(self) -> &'static str {
        match self {
            Confirm::Trust => "trust",
            Confirm::RestoreAndTrust => "restore-trust",
            Confirm::Purge => "purge",
        }
    }
}

/// One button on a Finding: the command the window invokes, its label, the
/// Finding it addresses, the confirmation asked first, and whether the
/// Simple Posture keeps it behind **Show technical details**.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    /// The Tauri command, which is the request of the same name.
    pub command: &'static str,
    /// What the button says, in the vocabulary of spec section 8.5.
    pub label: &'static str,
    /// The Finding id the request addresses.
    pub target: String,
    /// What a Restore does when something else stands at the original place:
    /// `refuse` first, `replace` or `beside` once the user chose.
    pub conflict: Option<&'static str>,
    /// The confirmation asked before the request goes out, if any.
    pub confirm: Option<Confirm>,
    /// True when the button shows only inside the technical details: Trust
    /// on a Drift question in the Simple Posture.
    pub technical: bool,
}

impl Action {
    /// The button as the window receives it.
    pub fn to_value(&self) -> Value {
        json!({
            "command": self.command,
            "label": self.label,
            "target": self.target,
            "conflict": self.conflict,
            "confirm": self.confirm.map(Confirm::as_str),
            "technical": self.technical,
        })
    }
}

/// True for a Drift question: the Finding Drift raised on its own, as
/// opposed to a Finding that carries Drift as a context line.
fn drift_question(finding: &RecordedFinding) -> bool {
    finding.source == "drift"
}

/// True when AgentSweep took the stopped Item out by itself, so its Restore
/// trusts this exact version (spec section 5.4). A Finding that names no
/// actor, as one from a state file written before the actor was sent, reads
/// as the user's own Quarantine, which restores without Trust.
pub fn stopped_automatically(finding: &RecordedFinding) -> bool {
    finding.facts.actor == Some(Actor::Auto)
}

/// The buttons one Finding offers in a Posture (spec section 8.5).
///
/// - **Quarantine** on any open Threat Finding at any Tier; **No, remove it**
///   on a Drift question; **Switch this line off** on a never-auto kind;
///   **Switch this off** where the Quarantine is the Agent's own switch.
/// - **Trust this version** on an open Threat behind its confirmation,
///   **Keep it as it is** on an Exposure. On a Drift question the Simple
///   Posture keeps it behind Show technical details; the Developer Posture
///   shows it with the others.
/// - **Yes, that was me** on a Drift question only; a Finding carrying Drift
///   as context offers no Acknowledge, because the daemon offers none.
/// - On a stopped Item, **Restore and trust this version** when AgentSweep
///   took it out and **Restore** when the user did; **Switch the line back
///   on** and **Switch it back on** for the never-auto kinds and the switched
///   Items. A switched Item AgentSweep switched off by itself still asks the
///   restore-and-trust confirmation, since its Restore trusts it too.
/// - **Re-enable** on a stopped plugin with a clean newer version, and the
///   one-click fix of Exposures 0018 and 0019.
pub fn offered(finding: &RecordedFinding, posture: Posture) -> Vec<Action> {
    let toggle = neutralised_in_place(finding.kind);
    let question = drift_question(finding);
    let target = finding.id.as_str().to_string();
    offers(finding)
        .into_iter()
        .map(|offer| {
            let action = |command, label, confirm, conflict| Action {
                command,
                label,
                target: target.clone(),
                conflict,
                confirm,
                technical: false,
            };
            match offer {
                Offer::Quarantine => action(
                    "quarantine",
                    match (toggle, question, finding.switched) {
                        (true, _, _) => "Switch this line off",
                        (false, true, _) => "No, remove it",
                        (false, false, true) => "Switch this off",
                        (false, false, false) => "Quarantine",
                    },
                    None,
                    None,
                ),
                Offer::Restore => {
                    let automatic = stopped_automatically(finding);
                    action(
                        "restore",
                        match (toggle, finding.switched, automatic) {
                            (true, _, _) => "Switch the line back on",
                            (false, true, _) => "Switch it back on",
                            (false, false, true) => "Restore and trust this version",
                            (false, false, false) => "Restore",
                        },
                        automatic.then_some(Confirm::RestoreAndTrust),
                        Some("refuse"),
                    )
                }
                Offer::ReEnable => action("re_enable", "Re-enable", None, None),
                Offer::Trust => Action {
                    technical: question && posture == Posture::Simple,
                    ..action(
                        "trust",
                        match finding.category {
                            Category::Threat => "Trust this version",
                            Category::Exposure => "Keep it as it is",
                        },
                        Some(Confirm::Trust),
                        None,
                    )
                },
                Offer::Acknowledge => action("acknowledge", "Yes, that was me", None, None),
                Offer::Fix => action("fix", "Take this setting out", None, None),
            }
        })
        .collect()
}

/// One Finding as the window renders it in a Posture: the card, with the
/// buttons and the confirmations that Posture offers, and on an open
/// Exposure its how-to ([`crate::how_to`]).
pub fn card_in(finding: &RecordedFinding, posture: Posture) -> Value {
    let mut value = card(finding);
    value["actions"] = Value::Array(
        offered(finding, posture)
            .iter()
            .map(Action::to_value)
            .collect(),
    );
    value["trustConfirm"] = trust_confirmation(finding);
    value["restoreConfirm"] = restore_confirmation(finding);
    value["howTo"] = how_to(finding, posture)
        .map(|how_to| how_to.to_value())
        .unwrap_or(Value::Null);
    value
}

/// A confirmation as the window shows it: the question, the lines under it,
/// and what the confirming button says.
fn confirmation(question: String, lines: Vec<String>, ok: &str) -> Value {
    json!({ "question": question, "lines": lines, "ok": ok })
}

/// What Trust says about itself, on a Threat.
pub const TRUST_EXPLAINED: &str = "Trust is bound to this exact version. AgentSweep stops \
     flagging it, and checks it again as soon as anything in it changes.";

/// What keeping an Exposure as it is says about itself.
pub const KEEP_EXPLAINED: &str = "This is bound to this exact version. AgentSweep stops \
     pointing it out, and asks again as soon as anything in it changes.";

/// What the restore-and-trust confirmation says about the Trust it grants.
pub const ONLY_THIS_VERSION: &str = "Only this exact version is trusted. If it changes in any \
     way, AgentSweep checks it again.";

/// The Trust confirmation: **Trust this version** explains hash-bound Trust,
/// and on an Exposure it reads **Keep it as it is**.
pub fn trust_confirmation(finding: &RecordedFinding) -> Value {
    let item = Named::of(finding).item();
    match finding.category {
        Category::Threat => confirmation(
            format!("Trust this version of {item}?"),
            vec![TRUST_EXPLAINED.to_string()],
            "Trust this version",
        ),
        Category::Exposure => confirmation(
            format!("Keep {item} as it is?"),
            vec![KEEP_EXPLAINED.to_string()],
            "Keep it as it is",
        ),
    }
}

/// Why a stopped Item was stopped, as the restore-and-trust confirmation
/// quotes it: the Finding's own sentence, or its title where it has none.
fn why_stopped(finding: &RecordedFinding) -> String {
    match finding.plain.trim() {
        "" => wording::simple(finding).title,
        plain => plain.to_string(),
    }
}

/// The restore-and-trust confirmation: only this exact version is trusted,
/// and why the Item was stopped, quoted. Asked only where the Restore trusts,
/// which is what AgentSweep took out by itself; null otherwise.
pub fn restore_confirmation(finding: &RecordedFinding) -> Value {
    if !stopped_automatically(finding) {
        return Value::Null;
    }
    let ok = offered(finding, Posture::Simple)
        .into_iter()
        .find(|action| action.command == "restore")
        .map_or("Restore and trust this version", |action| action.label);
    confirmation(
        format!(
            "Restore {} and trust this version?",
            Named::of(finding).item()
        ),
        vec![
            format!(
                "AgentSweep stopped it because: \"{}\"",
                why_stopped(finding)
            ),
            ONLY_THIS_VERSION.to_string(),
        ],
        ok,
    )
}

/// The Agent's name as a person knows it, from its adapter id.
fn agent_name(agent: &str) -> &str {
    match agent {
        "claude-code" => "Claude Code",
        "codex" => "Codex",
        other => other,
    }
}

/// The sessions of the Agent the Item belongs to; for an Item of the
/// workspace, which every Agent reads, the sessions of every Agent.
fn sessions_for(item_id: &ItemId, sessions: &Sessions) -> Sessions {
    let agent = item_id.as_str().split('/').next().unwrap_or("");
    match sessions.agents.iter().any(|one| one.agent == agent) {
        true => Sessions::of(
            sessions
                .agents
                .iter()
                .filter(|one| one.agent == agent)
                .cloned()
                .collect(),
        ),
        false => sessions.clone(),
    }
}

/// Joins names the way a sentence does: "a", "a or b", "a, b or c".
fn joined(names: &[String], last: &str) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., tail] => format!("{} {last} {tail}", init.join(", ")),
    }
}

/// Whether the Agent appears to be running, as one sentence: the count and
/// the Agent ("2 Claude Code sessions appear to be running"), never a project
/// or a process id, and the generic wording where detection is unavailable
/// (the owner's decision of 2026-10-14 for ticket 73).
pub fn sessions_sentence(sessions: &Sessions) -> String {
    let named = |wanted: SessionsRunning| -> Vec<&agentsweep_ipc::protocol::AgentSessions> {
        sessions
            .agents
            .iter()
            .filter(|one| one.running == wanted)
            .collect()
    };
    match sessions.running {
        SessionsRunning::Yes => {
            let live = named(SessionsRunning::Yes);
            let total: usize = live.iter().map(|one| one.live).sum();
            let parts: Vec<String> = live
                .iter()
                .map(|one| match one.live {
                    0 => agent_name(&one.agent).to_string(),
                    1 => format!("1 {} session", agent_name(&one.agent)),
                    n => format!("{n} {} sessions", agent_name(&one.agent)),
                })
                .collect();
            let verb = match total {
                1 => "appears",
                _ => "appear",
            };
            format!("{} {verb} to be running.", joined(&parts, "and"))
        }
        SessionsRunning::No => {
            let names: Vec<String> = named(SessionsRunning::No)
                .iter()
                .map(|one| agent_name(&one.agent).to_string())
                .collect();
            match names.is_empty() {
                true => "No coding agent session appears to be running.".to_string(),
                false => format!("No {} session appears to be running.", joined(&names, "or")),
            }
        }
        SessionsRunning::Unknown => {
            let names: Vec<String> = named(SessionsRunning::Unknown)
                .iter()
                .map(|one| agent_name(&one.agent).to_string())
                .collect();
            match names.is_empty() {
                true => "AgentSweep could not tell whether a coding agent is running.".to_string(),
                false => format!(
                    "AgentSweep could not tell whether {} is running.",
                    joined(&names, "or")
                ),
            }
        }
    }
}

/// The restart request, present where a session may be running: none is
/// asked when no session appears to be.
pub fn restart_request(sessions: &Sessions) -> Option<&'static str> {
    match sessions.running {
        SessionsRunning::Yes => {
            let total: usize = sessions
                .agents
                .iter()
                .filter(|one| one.running == SessionsRunning::Yes)
                .map(|one| one.live)
                .sum();
            Some(match total {
                1 => "Restart it so it picks up the change.",
                _ => "Restart them so they pick up the change.",
            })
        }
        SessionsRunning::Unknown => Some("If it is open, restart it so it picks up the change."),
        SessionsRunning::No => None,
    }
}

/// The confirmation after a Quarantine (spec section 8.5): whether the Agent
/// appears to be running, the restart request where one may be, and on
/// Project Scope that git will show the change. Read off the Item id the
/// daemon's answer names, so it needs nothing the window kept.
pub fn after_quarantine(item_id: &ItemId, sessions: &Sessions) -> Vec<String> {
    let own = sessions_for(item_id, sessions);
    let mut lines = vec![sessions_sentence(&own)];
    lines.extend(restart_request(&own).map(str::to_string));
    if item_id.is_project() {
        lines.push(PROJECT_LINE.to_string());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::finding::FindingState;
    use agentsweep_core::item::Kind;
    use agentsweep_ipc::protocol::AgentSessions;

    use crate::findings::tests::recorded;

    const SKILL: &str = "claude-code/user/skill/~/.claude/skills/setup";
    const MCP: &str = "claude-code/user/mcp-server/~/.claude.json#tracker";
    const SETTING: &str = "claude-code/user/settings-entry/~/.claude/settings.json#sandbox";
    const GIT: &str = "workspace/project:/src/demo/repository-metadata/.git/config#core.hooksPath";
    const ENV: &str = "workspace/project:/src/demo/env-file/.env#ANTHROPIC_BASE_URL";
    const CODEX: &str = "codex/user/mcp-server/~/.codex/config.toml#dropper";
    const PROJECT_FILE: &str = "claude-code/project:/src/demo/instruction-file/CLAUDE.md";

    fn open(item: &str, kind: Kind, source: &str, category: Category) -> RecordedFinding {
        recorded(item, kind, source, category, FindingState::Open)
    }

    fn stopped(item: &str, kind: Kind, actor: Option<Actor>) -> RecordedFinding {
        let mut finding = recorded(
            item,
            kind,
            "rule 0001",
            Category::Threat,
            FindingState::Stopped,
        );
        finding.facts.actor = actor;
        finding
    }

    /// The buttons as (command, label, technical) in order.
    fn buttons(
        finding: &RecordedFinding,
        posture: Posture,
    ) -> Vec<(&'static str, &'static str, bool)> {
        offered(finding, posture)
            .into_iter()
            .map(|action| (action.command, action.label, action.technical))
            .collect()
    }

    fn both(finding: &RecordedFinding) -> [Vec<(&'static str, &'static str, bool)>; 2] {
        [
            buttons(finding, Posture::Simple),
            buttons(finding, Posture::Developer),
        ]
    }

    /// Quarantine on any open Threat Finding at any Tier, with Trust this
    /// version beside it, in both Postures.
    #[test]
    fn a_threat_at_any_tier_offers_quarantine_and_trust() {
        for source in ["rule 0001", "score 7", "keeps coming back"] {
            let threat = open(SKILL, Kind::Skill, source, Category::Threat);
            for shown in both(&threat) {
                assert_eq!(
                    shown,
                    vec![
                        ("quarantine", "Quarantine", false),
                        ("trust", "Trust this version", false),
                    ],
                    "{source}"
                );
            }
            let trust = offered(&threat, Posture::Simple).remove(1);
            assert_eq!(trust.confirm, Some(Confirm::Trust));
            assert_eq!(trust.target, threat.id.as_str());
        }
        let mut ai = open(SKILL, Kind::Skill, "score 9", Category::Threat);
        ai.tier = agentsweep_core::finding::Tier::AiJudgement;
        assert_eq!(buttons(&ai, Posture::Simple)[0].1, "Quarantine");
    }

    /// An Exposure reads Keep it as it is and is never quarantined; 0019
    /// adds its one-click fix.
    #[test]
    fn an_exposure_reads_keep_it_as_it_is() {
        let exposure = open(
            SETTING,
            Kind::SettingsEntry,
            "rule 0010",
            Category::Exposure,
        );
        for shown in both(&exposure) {
            assert_eq!(shown, vec![("trust", "Keep it as it is", false)]);
        }
        let fixable = open(
            SETTING,
            Kind::SettingsEntry,
            "rule 0019",
            Category::Exposure,
        );
        assert_eq!(
            buttons(&fixable, Posture::Simple),
            vec![
                ("trust", "Keep it as it is", false),
                ("fix", "Take this setting out", false),
            ]
        );
    }

    /// A Drift question: Yes, that was me and No, remove it; Trust only
    /// behind Show technical details in Simple, and with the others in
    /// Developer.
    #[test]
    fn a_drift_question_keeps_trust_behind_the_details_in_simple_only() {
        let drift = open(MCP, Kind::McpServer, "drift", Category::Threat);
        assert_eq!(
            buttons(&drift, Posture::Simple),
            vec![
                ("quarantine", "No, remove it", false),
                ("trust", "Trust this version", true),
                ("acknowledge", "Yes, that was me", false),
            ]
        );
        assert_eq!(
            buttons(&drift, Posture::Developer),
            vec![
                ("quarantine", "No, remove it", false),
                ("trust", "Trust this version", false),
                ("acknowledge", "Yes, that was me", false),
            ]
        );
    }

    /// A Finding that carries Drift as its context line offers no
    /// Acknowledge, and its Trust is not hidden.
    #[test]
    fn drift_as_context_offers_no_acknowledge() {
        let mut changed = open(MCP, Kind::McpServer, "rule 0008", Category::Threat);
        changed.drift = "changed since your last Scan on 2026-10-01".to_string();
        for shown in both(&changed) {
            assert_eq!(
                shown,
                vec![
                    ("quarantine", "Quarantine", false),
                    ("trust", "Trust this version", false),
                ]
            );
        }
    }

    /// Never-auto kinds switch their line off and back on.
    #[test]
    fn a_never_auto_kind_switches_its_line() {
        for (item, kind) in [(GIT, Kind::RepositoryMetadata), (ENV, Kind::EnvFile)] {
            let threat = open(item, kind, "rule 0007", Category::Threat);
            assert_eq!(
                buttons(&threat, Posture::Simple)[0],
                ("quarantine", "Switch this line off", false)
            );
            let off = stopped(item, kind, Some(Actor::User));
            for shown in both(&off) {
                assert_eq!(shown, vec![("restore", "Switch the line back on", false)]);
            }
        }
    }

    /// Switched Items switch off and back on.
    #[test]
    fn a_switched_item_switches_off_and_back_on() {
        let mut threat = open(CODEX, Kind::McpServer, "rule 0001", Category::Threat);
        threat.switched = true;
        assert_eq!(
            buttons(&threat, Posture::Simple)[0],
            ("quarantine", "Switch this off", false)
        );
        let mut off = stopped(CODEX, Kind::McpServer, Some(Actor::User));
        off.switched = true;
        assert_eq!(
            buttons(&off, Posture::Simple),
            vec![("restore", "Switch it back on", false)]
        );
        assert_eq!(offered(&off, Posture::Simple)[0].confirm, None);
        // Switched off by AgentSweep, it still trusts on the way back.
        off.facts.actor = Some(Actor::Auto);
        let back = offered(&off, Posture::Simple).remove(0);
        assert_eq!(back.label, "Switch it back on");
        assert_eq!(back.confirm, Some(Confirm::RestoreAndTrust));
        assert_eq!(restore_confirmation(&off)["ok"], "Switch it back on");
    }

    /// The actor the daemon sent chooses the Restore before it is pressed:
    /// automatic reads Restore and trust this version behind its
    /// confirmation, manual reads Restore with none. Nothing here asks the
    /// daemon: the choice is a function of the Finding alone.
    #[test]
    fn the_actor_chooses_restore_and_trust_or_restore() {
        let automatic = stopped(SKILL, Kind::Skill, Some(Actor::Auto));
        let restore = offered(&automatic, Posture::Simple).remove(0);
        assert_eq!(restore.label, "Restore and trust this version");
        assert_eq!(restore.confirm, Some(Confirm::RestoreAndTrust));
        assert_eq!(restore.conflict, Some("refuse"));
        assert_eq!(
            buttons(&automatic, Posture::Developer)[0].1,
            "Restore and trust this version"
        );

        let manual = stopped(SKILL, Kind::Skill, Some(Actor::User));
        let restore = offered(&manual, Posture::Simple).remove(0);
        assert_eq!(restore.label, "Restore");
        assert_eq!(restore.confirm, None);
        assert_eq!(restore_confirmation(&manual), Value::Null);

        // A Finding from before the actor was sent restores without Trust.
        let unknown = stopped(SKILL, Kind::Skill, None);
        assert_eq!(buttons(&unknown, Posture::Simple)[0].1, "Restore");
    }

    /// Re-enable joins Restore on a stopped plugin with a clean newer
    /// version; trusted, acknowledged and gone offer nothing; a Managed Item
    /// is never quarantined; a Problem offers nothing.
    #[test]
    fn the_other_rows_of_the_vocabulary() {
        let mut plugin = stopped(SKILL, Kind::Plugin, Some(Actor::Auto));
        plugin.fixed_version = "def".to_string();
        assert_eq!(
            buttons(&plugin, Posture::Simple),
            vec![
                ("restore", "Restore and trust this version", false),
                ("re_enable", "Re-enable", false),
            ]
        );
        for state in [
            FindingState::Trusted,
            FindingState::Acknowledged,
            FindingState::Gone,
        ] {
            let decided = recorded(SKILL, Kind::Skill, "rule 0001", Category::Threat, state);
            assert!(buttons(&decided, Posture::Developer).is_empty(), "{state}");
        }
        let mut managed = open(
            "claude-code/managed/settings-entry/x#y",
            Kind::SettingsEntry,
            "rule 0001",
            Category::Threat,
        );
        managed.item_id = ItemId::from_recorded("claude-code/managed/settings-entry/x#y");
        assert_eq!(
            buttons(&managed, Posture::Simple),
            vec![("trust", "Trust this version", false)]
        );
        let problem = open(
            SETTING,
            Kind::SettingsEntry,
            "problem unreadable",
            Category::Exposure,
        );
        assert!(buttons(&problem, Posture::Simple).is_empty());
    }

    /// No Exposure of the bundled pack offers Quarantine in either Posture;
    /// each offers its how-to with Open the file, and 0018 and 0019 on a
    /// settings entry still offer their one-click fix (spec section 8.5).
    #[test]
    fn every_exposure_offers_its_how_to_and_never_quarantine() {
        let pack = agentsweep_core::rules::RulePack::bundled().expect("the bundled pack");
        let exposures: Vec<_> = pack
            .metas()
            .filter(|meta| meta.category == Category::Exposure)
            .collect();
        assert!(exposures.len() >= 6, "the v1 pack has six Exposures");
        for meta in exposures {
            for kind in meta.kinds.iter().copied() {
                let mut exposure = open(
                    SETTING,
                    kind,
                    &format!("rule {:04}", meta.id),
                    Category::Exposure,
                );
                exposure.facts.fix = meta.fix.clone().unwrap_or_default();
                exposure.facts.path = "/home/u/.claude/settings.json".to_string();
                for posture in Posture::ALL {
                    let shown = buttons(&exposure, posture);
                    assert!(
                        shown.iter().all(|(command, ..)| *command != "quarantine"),
                        "{} on {kind}: {shown:?}",
                        meta.name
                    );
                    let fixes = shown.iter().any(|(command, ..)| *command == "fix");
                    assert_eq!(
                        fixes,
                        matches!(meta.id, 18 | 19) && kind == Kind::SettingsEntry,
                        "{} on {kind}: {shown:?}",
                        meta.name
                    );
                    let card = card_in(&exposure, posture);
                    assert_eq!(card["howTo"]["label"], "Show me how to fix this");
                    assert_eq!(card["howTo"]["open"], "Open the file");
                    assert_eq!(card["howTo"]["steps"], meta.fix.as_deref().unwrap());
                }
            }
        }
        let threat = open(SKILL, Kind::Skill, "rule 0001", Category::Threat);
        assert!(card_in(&threat, Posture::Simple)["howTo"].is_null());
    }

    /// The card a Posture renders carries that Posture's buttons.
    #[test]
    fn the_card_carries_the_buttons_of_its_posture() {
        let drift = open(MCP, Kind::McpServer, "drift", Category::Threat);
        assert_eq!(
            card_in(&drift, Posture::Simple)["actions"][1]["technical"],
            true
        );
        assert_eq!(
            card_in(&drift, Posture::Developer)["actions"][1]["technical"],
            false
        );
        assert_eq!(
            card_in(&drift, Posture::Simple)["actions"][1]["confirm"],
            "trust"
        );
    }

    /// The Trust confirmation explains hash-bound Trust, verbatim, and reads
    /// Keep it as it is on an Exposure.
    #[test]
    fn the_trust_confirmation_explains_hash_bound_trust() {
        let threat = open(SKILL, Kind::Skill, "rule 0001", Category::Threat);
        assert_eq!(
            trust_confirmation(&threat),
            json!({
                "question": "Trust this version of the skill 'setup'?",
                "lines": [
                    "Trust is bound to this exact version. AgentSweep stops flagging it, and \
                     checks it again as soon as anything in it changes."
                ],
                "ok": "Trust this version",
            })
        );
        let exposure = open(
            SETTING,
            Kind::SettingsEntry,
            "rule 0010",
            Category::Exposure,
        );
        assert_eq!(
            trust_confirmation(&exposure),
            json!({
                "question": "Keep the setting 'sandbox' as it is?",
                "lines": [
                    "This is bound to this exact version. AgentSweep stops pointing it out, and \
                     asks again as soon as anything in it changes."
                ],
                "ok": "Keep it as it is",
            })
        );
    }

    /// The restore-and-trust confirmation says only this exact version is
    /// trusted and quotes why the Item was stopped, verbatim.
    #[test]
    fn the_restore_and_trust_confirmation_quotes_why_it_was_stopped() {
        let mut automatic = stopped(SKILL, Kind::Skill, Some(Actor::Auto));
        automatic.plain =
            "It downloads a script from the internet and runs it straight away.".to_string();
        assert_eq!(
            restore_confirmation(&automatic),
            json!({
                "question": "Restore the skill 'setup' and trust this version?",
                "lines": [
                    "AgentSweep stopped it because: \"It downloads a script from the internet \
                     and runs it straight away.\"",
                    "Only this exact version is trusted. If it changes in any way, AgentSweep \
                     checks it again."
                ],
                "ok": "Restore and trust this version",
            })
        );
        assert_eq!(
            card_in(&automatic, Posture::Simple)["restoreConfirm"],
            restore_confirmation(&automatic)
        );
    }

    /// A stopped Item in the list carries its Restore and, where AgentSweep
    /// took it out, the restore-and-trust confirmation.
    #[test]
    fn a_stopped_item_in_the_list_carries_its_restore() {
        let mut list = crate::findings::Findings::new();
        list.load(&crate::findings::tests::status_of(vec![
            stopped(SKILL, Kind::Skill, Some(Actor::Auto)),
            stopped(MCP, Kind::McpServer, Some(Actor::User)),
        ]));
        let value = list.to_value();
        let decided = value["decided"].as_array().expect("decided");
        assert_eq!(
            decided[0]["actions"][0]["label"],
            "Restore and trust this version"
        );
        assert_eq!(decided[0]["actions"][0]["confirm"], "restore-trust");
        assert_eq!(
            decided[0]["restoreConfirm"]["ok"],
            "Restore and trust this version"
        );
        assert_eq!(decided[1]["actions"][0]["label"], "Restore");
        assert_eq!(decided[1]["restoreConfirm"], Value::Null);
    }

    fn agent(agent: &str, running: SessionsRunning, live: usize) -> AgentSessions {
        AgentSessions {
            agent: agent.to_string(),
            running,
            live,
        }
    }

    /// The sessions sentence names the count and the Agent, never a project
    /// or a process id, and is generic where detection is unavailable.
    #[test]
    fn the_sessions_sentence_names_the_count_and_the_agent() {
        let two = Sessions::of(vec![agent("claude-code", SessionsRunning::Yes, 2)]);
        assert_eq!(
            sessions_sentence(&two),
            "2 Claude Code sessions appear to be running."
        );
        let one = Sessions::of(vec![
            agent("claude-code", SessionsRunning::Yes, 1),
            agent("codex", SessionsRunning::No, 0),
        ]);
        assert_eq!(
            sessions_sentence(&one),
            "1 Claude Code session appears to be running."
        );
        let mixed = Sessions::of(vec![
            agent("claude-code", SessionsRunning::Yes, 2),
            agent("codex", SessionsRunning::Yes, 1),
        ]);
        assert_eq!(
            sessions_sentence(&mixed),
            "2 Claude Code sessions and 1 Codex session appear to be running."
        );
        let none = Sessions::of(vec![
            agent("claude-code", SessionsRunning::No, 0),
            agent("codex", SessionsRunning::No, 0),
        ]);
        assert_eq!(
            sessions_sentence(&none),
            "No Claude Code or Codex session appears to be running."
        );
        assert_eq!(
            sessions_sentence(&Sessions::unknown()),
            "AgentSweep could not tell whether a coding agent is running."
        );
        let codex = Sessions::of(vec![agent("codex", SessionsRunning::Unknown, 0)]);
        assert_eq!(
            sessions_sentence(&codex),
            "AgentSweep could not tell whether Codex is running."
        );
    }

    /// After a Quarantine: the sessions sentence of the Item's own Agent,
    /// the restart request where a session may be running, and on Project
    /// Scope only the git line.
    #[test]
    fn the_after_quarantine_confirmation() {
        let sessions = Sessions::of(vec![
            agent("claude-code", SessionsRunning::Yes, 2),
            agent("codex", SessionsRunning::No, 0),
        ]);
        let skill = open(SKILL, Kind::Skill, "rule 0001", Category::Threat);
        assert_eq!(
            after_quarantine(&skill.item_id, &sessions),
            vec![
                "2 Claude Code sessions appear to be running.",
                "Restart them so they pick up the change.",
            ]
        );
        let codex = open(CODEX, Kind::McpServer, "rule 0001", Category::Threat);
        assert_eq!(
            after_quarantine(&codex.item_id, &sessions),
            vec!["No Codex session appears to be running."]
        );
        let project = open(
            PROJECT_FILE,
            Kind::InstructionFile,
            "rule 0004",
            Category::Threat,
        );
        assert_eq!(
            after_quarantine(&project.item_id, &sessions),
            vec![
                "2 Claude Code sessions appear to be running.",
                "Restart them so they pick up the change.",
                PROJECT_LINE,
            ]
        );
        // An env file belongs to every Agent; with nothing detected the
        // wording is generic and still asks for a restart.
        let env = open(ENV, Kind::EnvFile, "rule 0007", Category::Threat);
        assert_eq!(
            after_quarantine(&env.item_id, &Sessions::unknown()),
            vec![
                "AgentSweep could not tell whether a coding agent is running.",
                "If it is open, restart it so it picks up the change.",
                PROJECT_LINE,
            ]
        );
    }

    /// The house style holds: no em-dash in any label or confirmation.
    #[test]
    fn no_text_carries_an_em_dash() {
        let mut text = String::new();
        for finding in [
            open(SKILL, Kind::Skill, "rule 0001", Category::Threat),
            open(
                SETTING,
                Kind::SettingsEntry,
                "rule 0019",
                Category::Exposure,
            ),
            open(MCP, Kind::McpServer, "drift", Category::Threat),
            stopped(SKILL, Kind::Skill, Some(Actor::Auto)),
        ] {
            text.push_str(&card_in(&finding, Posture::Developer).to_string());
            text.push_str(&after_quarantine(&finding.item_id, &Sessions::unknown()).join(" "));
        }
        assert!(!text.contains('\u{2014}'));
    }
}
