//! The Settings pane (spec section 8.10), apart from the AI check, the Gate
//! switch and Uninstall, which fill their own places in it.
//!
//! - **Detail**: Keep it simple / I am a developer, the Posture.
//! - **Background**: the Rule Feed toggle and the app update toggle under one
//!   line disclosing both requests (spec section 1.1), on by default.
//! - **Install command line tool**: [`crate::cli_link`].
//! - **Advanced**: the config-dir override per Agent (the owner's decision of
//!   2026-10-14 for ticket 65, stored in the settings file), **Check
//!   everything without asking again** with the Full Disk Access
//!   instructions and a best-effort link to its pane (spec section 9.7), and
//!   the `rules.d/` folder with a button to show it in Finder.
//! - **What AgentSweep does not protect against**: the short paragraph of
//!   spec section 2.4 and a link to the full list in the README.
//!
//! Every choice moves through the daemon's `settings` request and the pane
//! shows what the daemon answered, never what was asked: the daemon is the
//! only writer of the settings file. An unreadable settings file is the
//! Health note here too, and every choice can still be made, which is what
//! writes the file again.
//!
//! Full Disk Access is optional and never nagged: this module is the only
//! place in the app that names it, and only its Advanced section carries it
//! (a test over the app's sources holds that).

use std::collections::BTreeMap;

use agentsweep_core::health::{Health, SETTINGS_UNREADABLE};
use agentsweep_core::settings::{ConfigDir, Posture, Settings};
use agentsweep_ipc::protocol::{SettingsChange, SettingsState};
use serde_json::{Value, json};

/// The two Detail choices, as onboarding words them (spec section 8.3).
pub const DETAIL_CHOICES: [(Posture, &str); 2] = [
    (Posture::Simple, "Keep it simple"),
    (Posture::Developer, "I am a developer"),
];

/// The one line naming both background requests (spec section 1.1).
pub const BACKGROUND_DISCLOSURE: &str = "In the background AgentSweep asks GitHub for newer \
     detection rules and for app updates. Neither request carries anything about you or this \
     Mac, and nothing else leaves it unless you turn on the Claude AI check.";

/// The Agents a config-dir override can be set for, as (id, name, default
/// directory): the two the daemon accepts an override for.
pub const OVERRIDABLE_AGENTS: [(&str, &str, &str); 2] = [
    ("claude-code", "Claude Code", "~/.claude"),
    ("codex", "Codex", "~/.codex"),
];

/// The name macOS gives the privilege. Only this module says it.
pub const FULL_DISK_ACCESS: &str = "Full Disk Access";

/// The title of the optional Full Disk Access setting.
pub const FULL_DISK_ACCESS_TITLE: &str = "Check everything without asking again";

/// What the Full Disk Access setting says, under its title.
pub const FULL_DISK_ACCESS_LINES: [&str; 3] = [
    "Optional. AgentSweep works without it: macOS asks once for each protected place your \
     projects are in, such as Documents.",
    "To let AgentSweep check every project without asking, give it Full Disk Access: open \
     System Settings, choose Privacy & Security, then Full Disk Access, and switch on \
     AgentSweep. If it is not in the list, add it with the + button from your Applications \
     folder.",
    "You can switch it off there again at any time.",
];

/// The button that opens the Full Disk Access pane.
pub const FULL_DISK_ACCESS_BUTTON: &str = "Open Full Disk Access settings";

/// What the pane says when no address of the Full Disk Access pane opened.
pub const FULL_DISK_ACCESS_UNOPENED: &str = "System Settings could not be opened. Open it \
     yourself and choose Privacy & Security, then Full Disk Access.";

/// Where the Full Disk Access pane is, in the order to try: Apple documents
/// none of these (research on first-run permissions, section 4), so each is
/// best effort, and the last opens Privacy & Security without an anchor.
pub const FULL_DISK_ACCESS_PANES: [&str; 3] = [
    "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles",
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
];

/// The heading of the not-protected section, here and in the README.
pub const NOT_PROTECTED_TITLE: &str = "What AgentSweep does not protect against";

/// The list of spec section 2.4, word for word, as the README carries it.
pub const NOT_PROTECTED: [&str; 9] = [
    "Runtime prompt injection through tool results, web pages, issues and pull requests.",
    "Behaviour of remote MCP servers and tool descriptions of servers whose source is not on \
     disk; rug pulls before the first Baseline exists.",
    "Payloads assembled only at runtime from network responses (the fetch pattern is flagged, \
     the payload is invisible).",
    "Malware already running with the user's privileges, including disabling AgentSweep itself.",
    "Admin or MDM-level tampering beyond the read-only checks.",
    "Integrity of the Agent binaries and of the user's general package dependencies (npm, \
     PyPI, Makefiles).",
    "Bugs in the Agents themselves (deep-link RCE, WebFetch exfiltration via pre-approved \
     domains).",
    "Social-engineering lures that never touch a Surface.",
    "Projects the Agents have not yet opened, unless the user runs a Folder Scan.",
];

/// The same nine lines in a few words each, in the same order, for the
/// short paragraph.
pub const NOT_PROTECTED_SHORT: [&str; 9] = [
    "prompt injection while an agent runs",
    "remote MCP servers",
    "payloads fetched only at run time",
    "malware already running as you",
    "admin or MDM tampering",
    "the agents' own programs and your package dependencies",
    "bugs in the agents themselves",
    "lures that never touch an agent's settings",
    "projects the agents have not opened yet, unless you scan the folder",
];

/// The README section the paragraph links to: GitHub's anchor for the
/// heading [`NOT_PROTECTED_TITLE`].
pub const NOT_PROTECTED_LINK: &str =
    "https://github.com/byte5digital/agentsweep#what-agentsweep-does-not-protect-against";

/// The short paragraph of spec section 2.4 for the Settings pane.
pub fn not_protected_paragraph() -> String {
    let (last, rest) = NOT_PROTECTED_SHORT
        .split_last()
        .expect("the list is not empty");
    format!(
        "AgentSweep checks what coding agents load from disk. It does not protect against \
         {}, or {last}. Some of these may be covered in a future version.",
        rest.join(", ")
    )
}

/// What the pane says of the `rules.d/` folder.
pub const RULES_FOLDER_LINE: &str = "Rules you put in this folder are checked too. Nothing \
     signs them, so they can only flag, never quarantine.";

/// The choices the pane shows: what the daemon answered, or every default
/// before it answered (spec section 6.9: a missing file means every
/// default).
fn choices(settings: Option<&SettingsState>) -> (bool, bool, Posture, BTreeMap<String, String>) {
    match settings {
        Some(state) => (
            state.rule_feed,
            state.update_check,
            state.posture,
            state.config_dirs.clone(),
        ),
        None => {
            let defaults = Settings::default();
            (
                defaults.rule_feed,
                defaults.update_check,
                defaults.posture,
                BTreeMap::new(),
            )
        }
    }
}

/// The pane as the window renders it, from the daemon's settings answer,
/// the Health, the Posture in force and where the `rules.d/` folder is.
/// With Protection off nothing can be changed, since only the daemon writes
/// a choice; an unreadable settings file changes nothing about that.
pub fn view(
    settings: Option<&SettingsState>,
    health: &Health,
    posture: Posture,
    rules_folder: Option<&str>,
) -> Value {
    let (rule_feed, update_check, chosen, config_dirs) = choices(settings);
    let developer = posture == Posture::Developer;
    let toggle = |key: &str, simple: &str, technical: &str, on: bool| {
        json!({
            "key": key,
            "label": if developer { technical } else { simple },
            "on": on,
        })
    };
    json!({
        "available": !health.protection.is_off(),
        "note": health.settings_unreadable.then_some(SETTINGS_UNREADABLE),
        "detail": {
            "title": "Detail",
            "choices": DETAIL_CHOICES
                .iter()
                .map(|(choice, label)| json!({
                    "posture": choice.as_str(),
                    "label": label,
                    "selected": *choice == chosen,
                }))
                .collect::<Vec<_>>(),
        },
        "background": {
            "title": "Background",
            "disclosure": BACKGROUND_DISCLOSURE,
            "toggles": [
                toggle("rule_feed", "Fetch newer detection rules", "Rule Feed", rule_feed),
                toggle("update_check", "Check for app updates", "App update check", update_check),
            ],
        },
        "cli": {
            "title": "Install command line tool",
            "line": "Puts agentsweep in ~/.local/bin so you can use it in a terminal. No \
                     administrator password is needed, and no shell profile is changed.",
            "button": "Install command line tool",
        },
        "advanced": {
            "title": "Advanced",
            "configDirs": OVERRIDABLE_AGENTS
                .iter()
                .map(|(agent, name, default)| json!({
                    "agent": agent,
                    "label": format!("{name} settings folder"),
                    "dir": config_dirs.get(*agent),
                    "default": default,
                }))
                .collect::<Vec<_>>(),
            "configDirsLine": "Read an agent's settings from another folder than its usual \
                               one. Leave it empty to use the usual folder.",
            "fullDiskAccess": {
                "title": FULL_DISK_ACCESS_TITLE,
                "lines": FULL_DISK_ACCESS_LINES,
                "button": FULL_DISK_ACCESS_BUTTON,
            },
            "rules": {
                "title": "Your own rules",
                "line": RULES_FOLDER_LINE,
                "path": rules_folder,
                "button": "Show in Finder",
            },
        },
        "notProtected": {
            "title": NOT_PROTECTED_TITLE,
            "paragraph": not_protected_paragraph(),
            "link": { "label": "The full list", "url": NOT_PROTECTED_LINK },
        },
    })
}

/// The change one control of the pane asks for, from what the window sends:
/// `{"posture": "developer"}`, `{"rule_feed": false}`,
/// `{"update_check": true}`, or `{"agent": "codex", "dir": "/path"}` where an
/// empty or absent `dir` clears the override. Nothing for anything else, and
/// nothing for a directory the daemon would refuse, which is said instead.
pub fn change_of(asked: &Value) -> Result<SettingsChange, String> {
    let unknown = || "That is not a setting AgentSweep knows.".to_string();
    let object = asked.as_object().ok_or_else(unknown)?;
    let mut change = SettingsChange::default();
    if let Some(posture) = object.get("posture") {
        change.posture = Some(
            posture
                .as_str()
                .and_then(Posture::parse)
                .ok_or_else(unknown)?,
        );
    } else if let Some(on) = object.get("rule_feed") {
        change.rule_feed = Some(on.as_bool().ok_or_else(unknown)?);
    } else if let Some(on) = object.get("update_check") {
        change.update_check = Some(on.as_bool().ok_or_else(unknown)?);
    } else if let Some(agent) = object.get("agent") {
        let agent = agent.as_str().ok_or_else(unknown)?;
        if !OVERRIDABLE_AGENTS.iter().any(|(id, _, _)| *id == agent) {
            return Err(unknown());
        }
        let dir = match object.get("dir").and_then(Value::as_str).map(str::trim) {
            None | Some("") => None,
            Some(dir) => Some(
                ConfigDir::parse(dir)
                    .map_err(|refused| format!("Nothing was changed: {}.", refused.reason))?
                    .as_str()
                    .to_string(),
            ),
        };
        change.config_dirs.insert(agent.to_string(), dir);
    }
    match change.is_empty() {
        true => Err(unknown()),
        false => Ok(change),
    }
}

/// What the pane says once the daemon answered a change.
pub const RECORDED: &str = "Saved.";

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::settings::{CloudCaps, JudgementEngine};
    use agentsweep_ipc::engine::EngineState;

    pub(crate) fn state(posture: Posture, rule_feed: bool, update_check: bool) -> SettingsState {
        SettingsState {
            rule_feed,
            update_check,
            posture,
            config_dirs: BTreeMap::new(),
            engine: EngineState {
                engine: JudgementEngine::Off,
                ollama_address: "127.0.0.1:11434".to_string(),
                ollama_model: String::new(),
                claude_model: String::new(),
                claude_model_in_use: String::new(),
                caps: CloudCaps::default(),
                claude_key_ending: None,
                recorded: 0,
                ollama: None,
                apple: None,
                cloud_use: agentsweep_ipc::engine::CloudUse::default(),
            },
        }
    }

    fn running() -> Health {
        let mut health = Health::unreachable("nobody");
        health.protection = agentsweep_core::health::Protection::On;
        health
    }

    #[test]
    fn the_pane_shows_what_the_daemon_answered() {
        let answered = state(Posture::Developer, false, true);
        let pane = view(Some(&answered), &running(), Posture::Developer, Some("/r"));
        assert_eq!(pane["available"], true);
        assert_eq!(pane["note"], Value::Null);
        assert_eq!(
            pane["detail"]["choices"],
            json!([
                { "posture": "simple", "label": "Keep it simple", "selected": false },
                { "posture": "developer", "label": "I am a developer", "selected": true },
            ])
        );
        assert_eq!(pane["background"]["disclosure"], BACKGROUND_DISCLOSURE);
        assert_eq!(pane["background"]["toggles"][0]["key"], "rule_feed");
        assert_eq!(pane["background"]["toggles"][0]["on"], false);
        assert_eq!(pane["background"]["toggles"][0]["label"], "Rule Feed");
        assert_eq!(pane["background"]["toggles"][1]["key"], "update_check");
        assert_eq!(pane["background"]["toggles"][1]["on"], true);
        assert_eq!(pane["advanced"]["rules"]["path"], "/r");
        assert_eq!(pane["advanced"]["configDirs"][0]["dir"], Value::Null);
    }

    /// Before the daemon answered, every choice is at its default: both
    /// background requests on, the Simple Posture.
    #[test]
    fn every_choice_is_on_by_default_before_an_answer() {
        let pane = view(None, &running(), Posture::Simple, None);
        assert_eq!(pane["background"]["toggles"][0]["on"], true);
        assert_eq!(pane["background"]["toggles"][1]["on"], true);
        assert_eq!(
            pane["background"]["toggles"][0]["label"],
            "Fetch newer detection rules"
        );
        assert_eq!(pane["detail"]["choices"][0]["selected"], true);
    }

    /// The one disclosure line names both requests and the third one.
    #[test]
    fn the_disclosure_names_both_background_requests() {
        assert!(BACKGROUND_DISCLOSURE.contains("detection rules"));
        assert!(BACKGROUND_DISCLOSURE.contains("app updates"));
        assert!(BACKGROUND_DISCLOSURE.contains("GitHub"));
        assert!(BACKGROUND_DISCLOSURE.contains("Claude"));
    }

    /// An unreadable settings file is the Health note here too, and the pane
    /// still offers every choice.
    #[test]
    fn an_unreadable_settings_file_shows_the_note_and_keeps_the_choices() {
        let mut health = running();
        health.settings_unreadable = true;
        let pane = view(None, &health, Posture::Simple, None);
        assert_eq!(pane["note"], SETTINGS_UNREADABLE);
        assert_eq!(pane["available"], true);
        assert_eq!(pane["detail"]["choices"].as_array().map(Vec::len), Some(2));
        // With no daemon, nothing can be changed.
        let off = view(None, &Health::unreachable("nobody"), Posture::Simple, None);
        assert_eq!(off["available"], false);
    }

    #[test]
    fn each_control_asks_for_its_own_change() {
        assert_eq!(
            change_of(&json!({ "posture": "developer" })),
            Ok(SettingsChange {
                posture: Some(Posture::Developer),
                ..SettingsChange::default()
            })
        );
        assert_eq!(
            change_of(&json!({ "rule_feed": false })),
            Ok(SettingsChange {
                rule_feed: Some(false),
                ..SettingsChange::default()
            })
        );
        assert_eq!(
            change_of(&json!({ "update_check": true })),
            Ok(SettingsChange {
                update_check: Some(true),
                ..SettingsChange::default()
            })
        );
        let set = change_of(&json!({ "agent": "codex", "dir": "/Users/x/.codex-work/" }))
            .expect("a change");
        assert_eq!(
            set.config_dirs.get("codex"),
            Some(&Some("/Users/x/.codex-work".to_string()))
        );
        let cleared = change_of(&json!({ "agent": "codex", "dir": "" })).expect("a change");
        assert_eq!(cleared.config_dirs.get("codex"), Some(&None));

        assert!(change_of(&json!({ "posture": "expert" })).is_err());
        assert!(change_of(&json!({ "agent": "cursor", "dir": "/x" })).is_err());
        assert!(change_of(&json!({ "colour": "blue" })).is_err());
        assert!(change_of(&json!("posture")).is_err());
        let refused =
            change_of(&json!({ "agent": "codex", "dir": "~/.codex" })).expect_err("refused");
        assert!(refused.starts_with("Nothing was changed:"), "{refused}");
    }

    /// The Full Disk Access link tries the anchored pane first and ends with
    /// the pane without an anchor.
    #[test]
    fn the_full_disk_access_link_falls_back_to_the_pane_without_an_anchor() {
        assert!(FULL_DISK_ACCESS_PANES[0].ends_with("?Privacy_AllFiles"));
        assert!(!FULL_DISK_ACCESS_PANES[2].contains('?'));
        assert!(
            FULL_DISK_ACCESS_PANES
                .iter()
                .all(|pane| pane.starts_with("x-apple.systempreferences:"))
        );
        let pane = view(None, &running(), Posture::Simple, None);
        assert_eq!(
            pane["advanced"]["fullDiskAccess"]["title"],
            FULL_DISK_ACCESS_TITLE
        );
        assert!(
            pane["advanced"]["fullDiskAccess"]["lines"][0]
                .as_str()
                .expect("a line")
                .starts_with("Optional.")
        );
    }

    /// The paragraph names each line of spec section 2.4 once, in order, and
    /// links to the README section whose heading it carries.
    #[test]
    fn the_paragraph_follows_the_list_of_section_2_4() {
        let paragraph = not_protected_paragraph();
        let mut from = 0;
        for short in NOT_PROTECTED_SHORT {
            let at = paragraph[from..]
                .find(short)
                .unwrap_or_else(|| panic!("{short} is not in order in {paragraph}"));
            from += at + short.len();
        }
        assert!(paragraph.contains("future version"));
        assert_eq!(NOT_PROTECTED.len(), NOT_PROTECTED_SHORT.len());
        let pane = view(None, &running(), Posture::Simple, None);
        assert_eq!(pane["notProtected"]["link"]["url"], NOT_PROTECTED_LINK);
        assert_eq!(pane["notProtected"]["paragraph"], paragraph);
    }
}
