//! The Quarantine pane (spec section 8.1): every Item in quarantine, and the
//! Trusted section at its foot.
//!
//! [`entries`] is a pure function of the stopped Findings the daemon's status
//! carries, the Activity lines of the Event Log and the Posture. The stopped
//! Findings are the daemon's view of the quarantine manifest: each names its
//! Receipt, who took the Item out (its actor) and whether the Rule that
//! stopped it was withdrawn. The moment it was stopped is the moment of the
//! Event Log's `quarantine` record for that Receipt.
//!
//! Each entry offers the actions of spec section 8.5: **Restore and trust this
//! version** or **Restore** as [`crate::actions::offered`] chooses them from
//! the actor, **Switch it back on** for a switched Item, which stays on its
//! Surface (spec section 5.2), **Re-enable** with "Fixed version available"
//! where a clean newer plugin version is present (spec section 5.4), and
//! **Delete permanently** behind a confirmation that says it cannot be undone
//! (spec section 5.1). A switched Item keeps nothing in the store, so it
//! offers no Delete permanently, as the daemon refuses one. An entry whose
//! Rule was withdrawn says so and offers Restore before any other action
//! (spec sections 6.4 and 8.4). The Developer Posture adds **Reveal in
//! Finder** and the Receipt id; the Simple Posture shows neither, not even
//! behind Show technical details.
//!
//! The Trusted section lists the Findings the user trusted, each with **Stop
//! trusting this** in both Postures (the owner's decision of 2026-10-14 for
//! ticket 74). Every action is still the daemon's request of the same name.

use std::collections::BTreeSet;

use agentsweep_core::envelope::Timestamp;
use agentsweep_core::eventlog::Actor;
use agentsweep_core::finding::FindingState;
use agentsweep_core::settings::Posture;
use agentsweep_core::state::RecordedFinding;
use agentsweep_ipc::protocol::ActivityLine;
use serde_json::{Value, json};

use crate::actions::{Action, Confirm, card_in, offered, stopped_automatically};
use crate::activity::Activity;
use crate::developer::{heading, offers_reveal};
use crate::findings::{Findings, neutralised_in_place};
use crate::wording::{Named, capitalised, rows_value, technical};

/// The line an entry whose Rule was withdrawn shows (spec section 8.4).
pub const WITHDRAWN: &str = "The rule that stopped this was withdrawn.";

/// The line a quarantined plugin with a clean newer version shows (spec
/// section 5.4).
pub const FIXED_VERSION: &str = "Fixed version available.";

/// What Delete permanently says before it is carried out (spec section 5.1).
pub const CANNOT_BE_UNDONE: &str = "This cannot be undone. AgentSweep deletes what it kept of \
     it, and it can never be restored.";

/// What the button of Delete permanently and its confirmation say.
pub const DELETE_PERMANENTLY: &str = "Delete permanently";

/// What the button of the Trusted section says.
pub const STOP_TRUSTING: &str = "Stop trusting this";

/// One Item in quarantine as the pane lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct QuarantineEntry<'a> {
    /// The stopped Finding that stands for the Item.
    pub finding: &'a RecordedFinding,
    /// Who took it out, absent where the daemon named nobody.
    pub stopped_by: Option<Actor>,
    /// Who took it out, as a sentence without its moment.
    pub stopped_line: String,
    /// When it was taken out: the moment of its `quarantine` record, absent
    /// where the Activity holds none.
    pub stopped_at: Option<Timestamp>,
    /// True when the Rule that stopped it is no longer in force.
    pub withdrawn: bool,
    /// True when a clean newer version of the plugin is present.
    pub fixed_version: bool,
    /// The buttons, in the order they are shown.
    pub actions: Vec<Action>,
    /// True when Reveal in Finder is offered: the Developer Posture only.
    pub reveal: bool,
    /// The Receipt id: the Developer Posture only.
    pub receipt_id: Option<String>,
}

/// Who took an Item out, as the entry says it.
fn stopped_line(finding: &RecordedFinding) -> String {
    let switched = finding.switched || neutralised_in_place(finding.kind);
    match (stopped_automatically(finding), switched) {
        (true, false) => "AgentSweep stopped it by itself",
        (true, true) => "AgentSweep switched it off by itself",
        (false, false) => "You stopped it",
        (false, true) => "You switched it off",
    }
    .to_string()
}

/// The moment the Event Log recorded the Quarantine of this Receipt, the
/// latest where it was quarantined more than once.
fn stopped_at(finding: &RecordedFinding, activity: &[ActivityLine]) -> Option<Timestamp> {
    activity
        .iter()
        .filter(|line| {
            line.action == "quarantine"
                && !finding.receipt_id.is_empty()
                && line.receipt_id == finding.receipt_id
        })
        .map(|line| line.recorded_at)
        .max()
}

/// The Delete permanently button: absent for a switched Item, whose
/// Quarantine left it where it stands and kept nothing in the store.
fn purge(finding: &RecordedFinding) -> Option<Action> {
    (!finding.switched).then(|| Action {
        command: "purge",
        label: DELETE_PERMANENTLY,
        target: finding.id.as_str().to_string(),
        conflict: None,
        confirm: Some(Confirm::Purge),
        technical: false,
    })
}

/// The buttons of one entry: what the daemon offers on the stopped Finding,
/// then Delete permanently. A withdrawn Rule puts Restore first.
fn entry_actions(finding: &RecordedFinding, posture: Posture) -> Vec<Action> {
    let mut actions = offered(finding, posture);
    if finding.facts.rule_withdrawn
        && let Some(at) = actions.iter().position(|a| a.command == "restore")
    {
        let restore = actions.remove(at);
        actions.insert(0, restore);
    }
    actions.extend(purge(finding));
    actions
}

/// Every Item in quarantine, one entry per Item in the order the status gave
/// them, read off the stopped Findings and the Activity in a Posture.
pub fn entries<'a>(
    findings: &'a [RecordedFinding],
    activity: &[ActivityLine],
    posture: Posture,
) -> Vec<QuarantineEntry<'a>> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    findings
        .iter()
        .filter(|f| f.state == FindingState::Stopped)
        .filter(|f| seen.insert(f.item_id.as_str()))
        .map(|finding| QuarantineEntry {
            finding,
            stopped_by: finding.facts.actor,
            stopped_line: stopped_line(finding),
            stopped_at: stopped_at(finding, activity),
            withdrawn: finding.facts.rule_withdrawn,
            fixed_version: !finding.fixed_version.is_empty(),
            actions: entry_actions(finding, posture),
            reveal: offers_reveal(finding, posture),
            receipt_id: (posture == Posture::Developer && !finding.receipt_id.is_empty())
                .then(|| finding.receipt_id.clone()),
        })
        .collect()
}

/// One trusted Finding as the Trusted section lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct TrustedEntry<'a> {
    /// The trusted Finding.
    pub finding: &'a RecordedFinding,
    /// What it is called in the Posture in force.
    pub title: String,
    /// **Stop trusting this**, in both Postures.
    pub action: Action,
}

/// Every Finding the user trusted, with Stop trusting this.
pub fn trusted(findings: &[RecordedFinding], posture: Posture) -> Vec<TrustedEntry<'_>> {
    findings
        .iter()
        .filter(|f| f.state == FindingState::Trusted)
        .map(|finding| TrustedEntry {
            finding,
            title: match posture {
                Posture::Simple => capitalised(&Named::of(finding).item()),
                Posture::Developer => heading(finding).title,
            },
            action: Action {
                command: "untrust",
                label: STOP_TRUSTING,
                target: finding.id.as_str().to_string(),
                conflict: None,
                confirm: None,
                technical: false,
            },
        })
        .collect()
}

/// The confirmation Delete permanently asks first: it says that it cannot be
/// undone (spec section 5.1).
pub fn purge_confirmation(finding: &RecordedFinding) -> Value {
    json!({
        "question": format!("Delete {} permanently?", Named::of(finding).item()),
        "lines": [CANNOT_BE_UNDONE],
        "ok": DELETE_PERMANENTLY,
    })
}

impl QuarantineEntry<'_> {
    /// The entry as the window receives it: the Finding's card in the
    /// Posture, with the entry's lines, its buttons, the Delete permanently
    /// confirmation, and Reveal in Finder and the Receipt id in the
    /// Developer Posture only.
    pub fn to_value(&self, posture: Posture) -> Value {
        let mut value = card_in(self.finding, posture);
        value["actions"] = Value::Array(self.actions.iter().map(Action::to_value).collect());
        value["purgeConfirm"] = purge_confirmation(self.finding);
        value["reveal"] = Value::from(self.reveal);
        value["receiptId"] = Value::from(self.receipt_id.clone().unwrap_or_default());
        if posture == Posture::Simple {
            let rows = technical(self.finding)
                .into_iter()
                .filter(|(label, _)| label != "Receipt")
                .collect();
            value["technical"] = rows_value(rows);
        }
        value["stopped"] = json!({
            "by": self.stopped_by.map(Actor::as_str),
            "line": self.stopped_line,
            "at": self.stopped_at.map(|at| at.to_string()),
        });
        value["withdrawn"] = Value::from(match self.withdrawn {
            true => WITHDRAWN,
            false => "",
        });
        value["fixedLine"] = Value::from(match self.fixed_version {
            true => FIXED_VERSION,
            false => "",
        });
        value
    }
}

impl TrustedEntry<'_> {
    /// The entry as the window receives it.
    pub fn to_value(&self) -> Value {
        json!({
            "id": self.finding.id.as_str(),
            "title": self.title,
            "action": self.action.to_value(),
        })
    }
}

/// The Quarantine pane as the window receives it: `entries`, one card per
/// Item in quarantine, and `trusted`, the Trusted section at its foot.
pub fn view(findings: &Findings, activity: &Activity, posture: Posture) -> Value {
    json!({
        "entries": entries(findings.all(), activity.lines(), posture)
            .iter()
            .map(|entry| entry.to_value(posture))
            .collect::<Vec<_>>(),
        "trusted": trusted(findings.all(), posture)
            .iter()
            .map(TrustedEntry::to_value)
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::finding::Category;
    use agentsweep_core::item::Kind;

    use crate::findings::tests::recorded;

    const SKILL: &str = "claude-code/user/skill/~/.claude/skills/setup";
    const MCP: &str = "codex/user/mcp-server/~/.codex/config.toml#dropper";
    const PLUGIN: &str = "claude-code/user/plugin/~/.claude/plugins/cache/shop/shipit";
    const HOOK: &str = "claude-code/user/hook/~/.claude/settings.json#PreToolUse/0";
    const RECEIPT: &str = "q-0123456789abcdef0123456789abcdef";
    const OTHER_RECEIPT: &str = "q-fedcba9876543210fedcba9876543210";

    fn stopped(item: &str, kind: Kind, actor: Actor) -> RecordedFinding {
        let mut finding = recorded(
            item,
            kind,
            "rule 0001",
            Category::Threat,
            FindingState::Stopped,
        );
        finding.facts.actor = Some(actor);
        finding
    }

    fn quarantined_at(at: &str, receipt: &str) -> ActivityLine {
        ActivityLine {
            recorded_at: Timestamp::parse(at).expect("a moment"),
            action: "quarantine".to_string(),
            receipt_id: receipt.to_string(),
            ..ActivityLine::default()
        }
    }

    /// The buttons of one entry as (command, label, confirm).
    fn buttons(entry: &QuarantineEntry) -> Vec<(&'static str, &'static str, Option<Confirm>)> {
        entry
            .actions
            .iter()
            .map(|a| (a.command, a.label, a.confirm))
            .collect()
    }

    /// What AgentSweep took out by itself restores with Trust, what the user
    /// took out restores without; both say who and when, and both end with
    /// Delete permanently behind its confirmation.
    #[test]
    fn an_automatic_and_a_manual_quarantine_name_their_actor_and_offers() {
        let auto = stopped(SKILL, Kind::Skill, Actor::Auto);
        let mut manual = stopped(HOOK, Kind::Hook, Actor::User);
        manual.receipt_id = OTHER_RECEIPT.to_string();
        let findings = vec![auto, manual];
        let activity = vec![
            quarantined_at("2026-10-01T09:00:00.000Z", RECEIPT),
            quarantined_at("2026-10-02T10:00:00.000Z", OTHER_RECEIPT),
            ActivityLine {
                action: "restore".to_string(),
                ..quarantined_at("2026-10-03T10:00:00.000Z", RECEIPT)
            },
        ];
        let listed = entries(&findings, &activity, Posture::Simple);
        assert_eq!(listed.len(), 2);

        assert_eq!(listed[0].stopped_by, Some(Actor::Auto));
        assert_eq!(listed[0].stopped_line, "AgentSweep stopped it by itself");
        assert_eq!(
            listed[0].stopped_at,
            Timestamp::parse("2026-10-01T09:00:00.000Z")
        );
        assert_eq!(
            buttons(&listed[0]),
            vec![
                (
                    "restore",
                    "Restore and trust this version",
                    Some(Confirm::RestoreAndTrust)
                ),
                ("purge", "Delete permanently", Some(Confirm::Purge)),
            ]
        );

        assert_eq!(listed[1].stopped_by, Some(Actor::User));
        assert_eq!(listed[1].stopped_line, "You stopped it");
        assert_eq!(
            listed[1].stopped_at,
            Timestamp::parse("2026-10-02T10:00:00.000Z")
        );
        assert_eq!(
            buttons(&listed[1]),
            vec![
                ("restore", "Restore", None),
                ("purge", "Delete permanently", Some(Confirm::Purge)),
            ]
        );
        let value = listed[1].to_value(Posture::Simple);
        assert_eq!(value["stopped"]["by"], "user");
        assert_eq!(value["stopped"]["at"], "2026-10-02T10:00:00.000Z");
        assert_eq!(value["restoreConfirm"], Value::Null);
    }

    /// A switched Item stays on its Surface: it offers Switch it back on and
    /// no Delete permanently, since the store keeps nothing of it.
    #[test]
    fn a_switched_item_offers_switch_it_back_on_and_no_delete() {
        let mut finding = stopped(MCP, Kind::McpServer, Actor::Auto);
        finding.switched = true;
        let findings = vec![finding];
        let listed = entries(&findings, &[], Posture::Developer);
        assert_eq!(
            listed[0].stopped_line,
            "AgentSweep switched it off by itself"
        );
        assert_eq!(listed[0].stopped_at, None);
        assert_eq!(
            buttons(&listed[0]),
            vec![(
                "restore",
                "Switch it back on",
                Some(Confirm::RestoreAndTrust)
            )]
        );
        assert!(!listed[0].reveal, "nothing in the store to reveal");
    }

    /// A quarantined plugin with a clean newer version says so and offers
    /// Re-enable beside Restore.
    #[test]
    fn a_plugin_with_a_fixed_version_offers_re_enable() {
        let mut finding = stopped(PLUGIN, Kind::Plugin, Actor::Auto);
        finding.fixed_version = "sha256:def".to_string();
        let findings = vec![finding];
        let listed = entries(&findings, &[], Posture::Simple);
        assert!(listed[0].fixed_version);
        let commands: Vec<&str> = listed[0].actions.iter().map(|a| a.command).collect();
        assert_eq!(commands, vec!["restore", "re_enable", "purge"]);
        assert_eq!(listed[0].actions[1].label, "Re-enable");
        let value = listed[0].to_value(Posture::Simple);
        assert_eq!(value["fixedLine"], "Fixed version available.");
        assert_eq!(value["withdrawn"], "");
    }

    /// An entry whose Rule was withdrawn shows the fixed line and offers
    /// Restore before any other action.
    #[test]
    fn a_withdrawn_rule_shows_its_line_and_offers_restore_first() {
        let mut finding = stopped(PLUGIN, Kind::Plugin, Actor::Auto);
        finding.facts.rule_withdrawn = true;
        finding.fixed_version = "sha256:def".to_string();
        let findings = vec![finding];
        for posture in [Posture::Simple, Posture::Developer] {
            let listed = entries(&findings, &[], posture);
            assert!(listed[0].withdrawn);
            assert_eq!(listed[0].actions[0].command, "restore");
            let value = listed[0].to_value(posture);
            assert_eq!(
                value["withdrawn"],
                "The rule that stopped this was withdrawn."
            );
            assert_eq!(value["actions"][0]["command"], "restore");
        }
    }

    /// Reveal in Finder and the Receipt id are the Developer Posture's: the
    /// Simple Posture shows neither, not even in its technical details.
    #[test]
    fn reveal_and_the_receipt_id_appear_in_developer_only() {
        let findings = vec![stopped(SKILL, Kind::Skill, Actor::User)];
        let developer = entries(&findings, &[], Posture::Developer);
        assert!(developer[0].reveal);
        assert_eq!(developer[0].receipt_id.as_deref(), Some(RECEIPT));
        let value = developer[0].to_value(Posture::Developer);
        assert_eq!(value["reveal"], true);
        assert_eq!(value["receiptId"], RECEIPT);
        assert!(value["technical"].to_string().contains(RECEIPT));

        let simple = entries(&findings, &[], Posture::Simple);
        assert!(!simple[0].reveal);
        assert_eq!(simple[0].receipt_id, None);
        let value = simple[0].to_value(Posture::Simple);
        assert_eq!(value["reveal"], false);
        assert_eq!(value["receiptId"], "");
        assert!(!value.to_string().contains(RECEIPT), "{value}");
    }

    /// Two stopped Findings on one Item make one entry, and what is not
    /// stopped is not listed.
    #[test]
    fn one_entry_per_item_in_quarantine() {
        let mut second = stopped(SKILL, Kind::Skill, Actor::Auto);
        second.source = "rule 0002".to_string();
        let open = recorded(
            HOOK,
            Kind::Hook,
            "rule 0003",
            Category::Threat,
            FindingState::Open,
        );
        let findings = vec![stopped(SKILL, Kind::Skill, Actor::Auto), second, open];
        assert_eq!(entries(&findings, &[], Posture::Simple).len(), 1);
    }

    /// Delete permanently asks first, and the question says it cannot be
    /// undone.
    #[test]
    fn delete_permanently_asks_first_and_says_it_cannot_be_undone() {
        let finding = stopped(SKILL, Kind::Skill, Actor::User);
        let asked = purge_confirmation(&finding);
        assert_eq!(asked["question"], "Delete the skill 'setup' permanently?");
        assert!(
            asked["lines"][0]
                .as_str()
                .expect("a line")
                .starts_with("This cannot be undone.")
        );
        assert_eq!(asked["ok"], "Delete permanently");
        assert_eq!(Confirm::Purge.as_str(), "purge");
    }

    /// The Trusted section lists what the user trusted, with Stop trusting
    /// this in both Postures, and nothing else.
    #[test]
    fn the_trusted_section_offers_stop_trusting_this_in_both_postures() {
        let trusted_one = recorded(
            HOOK,
            Kind::Hook,
            "rule 0003",
            Category::Threat,
            FindingState::Trusted,
        );
        let findings = vec![trusted_one, stopped(SKILL, Kind::Skill, Actor::User)];
        for posture in [Posture::Simple, Posture::Developer] {
            let listed = trusted(&findings, posture);
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].action.command, "untrust");
            assert_eq!(listed[0].action.label, "Stop trusting this");
            assert_eq!(listed[0].action.target, findings[0].id.as_str());
        }
    }
}
