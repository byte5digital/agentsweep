//! Needs Permission in the window (spec sections 8.6 and 9.7): the Overview
//! line "N projects not checked" with **Check now**, the projects concerned,
//! and after a denial or a lost grant a link to System Settings.
//!
//! The daemon never makes the first read into a protected location by
//! itself. A registered project there Needs Permission until the user clicks
//! **Check now**, which sends the `check-now` request so the operating
//! system's prompt appears right after the click. The button sends it once
//! and stays disabled until the daemon answers.
//!
//! The daemon does not say whether a project still Needs Permission because
//! the user said no, because a grant was taken back, or because the prompt
//! is still on screen. So the link to System Settings shows once a Check now
//! was answered and projects still Need Permission: a denied prompt does not
//! come back, and a withdrawn grant answers the next read with a denial, so
//! either way the next step is System Settings. Apple documents no address
//! for the pane; [`privacy_panes`] is the one place the best-effort
//! addresses live (research on first-run permissions, section 4).
//!
//! Full Disk Access is never required and never mentioned here (spec section
//! 9.7). The popover's sentence is the Health rung "N projects need
//! permission." as the command line interface prints it, and a project that
//! Needs Permission never counts towards an all-clear; both are the Health's
//! ([`agentsweep_core::health`]).

use std::path::Path;
use std::sync::Mutex;

use agentsweep_core::overview::{Overview, ProjectCheck};
use agentsweep_core::settings::Posture;
use agentsweep_ipc::ClientError;
use serde_json::{Value, json};

use crate::asking::Asking;
use crate::findings::count;
use crate::frame::Frame;

/// The button that sends `check-now`.
pub const CHECK_NOW: &str = "Check now";

/// The sentence beside the link to System Settings.
pub const PRIVACY_SENTENCE: &str = "If macOS did not allow it, switch on AgentSweep under \
     Files and Folders in Privacy & Security.";

/// The button that opens System Settings at Files and Folders.
pub const PRIVACY_BUTTON: &str = "Open Privacy & Security";

/// What the window says when no address of the pane opened.
pub const PRIVACY_UNOPENED: &str = "System Settings could not be opened. Open it yourself and \
     choose Privacy & Security, then Files and Folders.";

/// The addresses of System Settings at Files and Folders, in the order to
/// try: the Privacy and Security extension with the Files and Folders
/// anchor, then the same pane without an anchor. Apple documents neither;
/// the extension id and the anchor were found on macOS 26 and are a hand
/// check on 14, 15 and 26 (research on first-run permissions, section 4 and
/// unverified item 8). Replace this function, and only it, when a release
/// moves the pane.
pub fn privacy_panes() -> [&'static str; 2] {
    [
        "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_FilesAndFolders",
        "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
    ]
}

/// Where **Check now** stands in this run of the app.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CheckNow {
    /// Not clicked yet.
    #[default]
    Idle,
    /// Sent, and the daemon has not answered yet: the button is disabled.
    Sending,
    /// The daemon answered a Check now.
    Answered,
}

/// The link to System Settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyLink {
    /// The sentence beside it.
    pub sentence: String,
    /// The button's label.
    pub button: String,
}

/// The Overview's Needs Permission line, in one value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionView {
    /// "N projects not checked."
    pub line: String,
    /// The projects concerned: their paths in the Developer Posture, their
    /// folder names in the Simple Posture.
    pub projects: Vec<String>,
    /// The button's label.
    pub button: String,
    /// False while a Check now waits for the daemon's answer.
    pub enabled: bool,
    /// The link to System Settings, once a Check now was answered and
    /// projects still Need Permission.
    pub privacy: Option<PrivacyLink>,
}

impl PermissionView {
    /// The value the window receives under `overview.permission`.
    pub fn to_value(&self) -> Value {
        json!({
            "line": self.line,
            "projects": self.projects,
            "button": self.button,
            "enabled": self.enabled,
            "privacy": self.privacy.as_ref().map(|link| json!({
                "sentence": link.sentence,
                "button": link.button,
            })),
        })
    }
}

/// The Needs Permission line of the project records, in a Posture; nothing
/// when no project Needs Permission.
pub fn view(overview: &Overview, posture: Posture, check_now: CheckNow) -> Option<PermissionView> {
    let projects: Vec<String> = overview
        .projects
        .iter()
        .filter(|project| project.check == ProjectCheck::NeedsPermission)
        .map(|project| name(&project.root, posture))
        .collect();
    if projects.is_empty() {
        return None;
    }
    Some(PermissionView {
        line: format!(
            "{} not checked.",
            count(projects.len(), "project", "projects")
        ),
        projects,
        button: CHECK_NOW.to_string(),
        enabled: check_now != CheckNow::Sending,
        privacy: (check_now == CheckNow::Answered).then(|| PrivacyLink {
            sentence: PRIVACY_SENTENCE.to_string(),
            button: PRIVACY_BUTTON.to_string(),
        }),
    })
}

/// A project as a Posture names it: the path, or the folder's own name.
fn name(root: &str, posture: Posture) -> String {
    match posture {
        Posture::Developer => root.to_string(),
        Posture::Simple => Path::new(root)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(root)
            .to_string(),
    }
}

/// The click on **Check now**: marks it sent, renders the disabled button,
/// sends `check-now` once, marks it answered whatever the answer, and
/// renders again. A click while one waits sends nothing and answers
/// `Ok(false)`, as the daemon does for a Check now already under way.
pub fn check_now(
    frame: &Mutex<Frame>,
    asking: &Asking,
    render: impl Fn(),
) -> Result<bool, ClientError> {
    if !frame
        .lock()
        .expect("the frame is not poisoned")
        .check_now_sent()
    {
        return Ok(false);
    }
    render();
    let answer = asking.check_now();
    frame
        .lock()
        .expect("the frame is not poisoned")
        .check_now_answered();
    render();
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::overview::ProjectRecord;

    fn project(root: &str, check: ProjectCheck) -> ProjectRecord {
        ProjectRecord {
            root: root.to_string(),
            agents: Vec::new(),
            check,
        }
    }

    fn overview() -> Overview {
        Overview {
            projects: vec![
                project(
                    "/Users/someone/Documents/shop",
                    ProjectCheck::NeedsPermission,
                ),
                project("/Users/someone/Developer/tool", ProjectCheck::Checked),
                project("/Users/someone/Desktop/demo", ProjectCheck::NeedsPermission),
            ],
            ..Overview::default()
        }
    }

    #[test]
    fn the_developer_posture_names_the_projects_by_path() {
        let shown = view(&overview(), Posture::Developer, CheckNow::Idle).expect("a line");
        assert_eq!(shown.line, "2 projects not checked.");
        assert_eq!(
            shown.projects,
            vec![
                "/Users/someone/Documents/shop",
                "/Users/someone/Desktop/demo"
            ]
        );
        assert_eq!(shown.button, "Check now");
        assert!(shown.enabled);
        assert_eq!(shown.privacy, None, "nothing was asked yet");
    }

    #[test]
    fn the_simple_posture_names_the_projects_by_folder_name() {
        let shown = view(&overview(), Posture::Simple, CheckNow::Idle).expect("a line");
        assert_eq!(shown.line, "2 projects not checked.");
        assert_eq!(shown.projects, vec!["shop", "demo"]);
        let one = Overview {
            projects: vec![project("/Volumes/Stick/app", ProjectCheck::NeedsPermission)],
            ..Overview::default()
        };
        let shown = view(&one, Posture::Simple, CheckNow::Idle).expect("a line");
        assert_eq!(shown.line, "1 project not checked.");
        assert_eq!(shown.projects, vec!["app"]);
    }

    #[test]
    fn no_project_needing_permission_produces_no_line() {
        let checked = Overview {
            projects: vec![project(
                "/Users/someone/Developer/tool",
                ProjectCheck::Checked,
            )],
            ..Overview::default()
        };
        for posture in Posture::ALL {
            for state in [CheckNow::Idle, CheckNow::Sending, CheckNow::Answered] {
                assert_eq!(view(&checked, posture, state), None);
                assert_eq!(view(&Overview::default(), posture, state), None);
            }
        }
    }

    #[test]
    fn the_button_waits_for_the_answer_and_the_link_follows_it() {
        let sending = view(&overview(), Posture::Simple, CheckNow::Sending).expect("a line");
        assert!(!sending.enabled);
        assert_eq!(sending.privacy, None);
        let answered = view(&overview(), Posture::Simple, CheckNow::Answered).expect("a line");
        assert!(answered.enabled);
        let link = answered.privacy.expect("the link after an answer");
        assert_eq!(link.button, PRIVACY_BUTTON);
        assert_eq!(link.sentence, PRIVACY_SENTENCE);
    }

    /// The anchor first, the bare pane as the fallback, and both the Privacy
    /// and Security extension.
    #[test]
    fn the_privacy_link_tries_the_anchor_then_the_pane_without_one() {
        let [anchored, bare] = privacy_panes();
        assert_eq!(
            anchored,
            "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_FilesAndFolders"
        );
        assert_eq!(
            bare,
            "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension"
        );
        assert_eq!(anchored.split_once('?').map(|(pane, _)| pane), Some(bare));
        assert!(!bare.contains('?'), "the fallback carries no anchor");
    }

    /// Full Disk Access is never mentioned here (spec section 9.7), and no
    /// line carries an em-dash.
    #[test]
    fn nothing_here_mentions_full_disk_access() {
        let mut text = view(&overview(), Posture::Developer, CheckNow::Answered)
            .expect("a line")
            .to_value()
            .to_string();
        text.push_str(PRIVACY_UNOPENED);
        text.push_str(&privacy_panes().concat());
        assert!(!text.contains("Full Disk"), "{text}");
        assert!(!text.contains("AllFiles"), "{text}");
        assert!(!text.contains('\u{2014}'), "{text}");
    }

    #[test]
    fn the_window_receives_every_field_by_name() {
        let value = view(&overview(), Posture::Developer, CheckNow::Answered)
            .expect("a line")
            .to_value();
        assert_eq!(value["line"], "2 projects not checked.");
        assert_eq!(value["projects"][1], "/Users/someone/Desktop/demo");
        assert_eq!(value["button"], "Check now");
        assert_eq!(value["enabled"], true);
        assert_eq!(value["privacy"]["button"], PRIVACY_BUTTON);
        let idle = view(&overview(), Posture::Developer, CheckNow::Idle)
            .expect("a line")
            .to_value();
        assert!(idle["privacy"].is_null());
    }
}
