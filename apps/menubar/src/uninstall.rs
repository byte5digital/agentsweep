//! **Uninstall AgentSweep…** in Settings (spec sections 8.10 and 9.6).
//!
//! The pane offers three choices about what is in quarantine, **Restore all N
//! quarantined items**, **Keep them in quarantine** (the default) and
//! **Delete everything**, and then, in this order:
//!
//! 1. asks the daemon with the one `uninstall` request, the same request and
//!    the same default as `agentsweep uninstall`: the daemon takes the
//!    Gate's entries and the Codex pin away from every Agent and applies the
//!    choice, since it is the only writer of the stores;
//! 2. unregisters the daemon and the login item through [`Services`];
//! 3. moves the app to the Trash through [`Trash`].
//!
//! A daemon that does not answer stops the flow before anything is
//! unregistered: only the daemon can take its hooks out of the Agents'
//! settings, and the user is told to start AgentSweep first. Both seams have
//! stand-ins in the suite, so no test touches launchd, Login Items or the real
//! Trash; [`SystemTrash`] is the thin part that asks the operating system and
//! is checked by hand (`docs/hand-checks.md`).
//!
//! `agentsweep uninstall` asks the daemon the same way and then runs this
//! app's executable with `--finish-uninstall`, since the registrations are
//! the app's and only its own executable takes them off. That run is
//! [`finish`]: it quits a running AgentSweep through [`Running`], then
//! unregisters both. The command line cannot move the bundle it runs from,
//! so it asks the user to.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agentsweep_ipc::protocol::{UninstallChoice, UninstallReport};
use serde_json::{Value, json};

use crate::asking::{Asking, refusal};
use crate::supervision::{self, Services};

/// How long a running AgentSweep is given to quit.
pub const QUIT_WAIT: Duration = Duration::from_secs(10);

/// The copies of the app that run now, other than this process.
pub trait Running {
    /// Asks each to quit, as the Quit of its menu does, and waits at most
    /// `wait` for them to be gone. Answers how many still run.
    fn quit(&self, wait: Duration) -> usize;
}

/// The running applications, as the operating system lists them by the
/// bundle identifier.
#[derive(Debug, Default)]
pub struct SystemRunning;

#[cfg(target_os = "macos")]
impl Running for SystemRunning {
    fn quit(&self, wait: Duration) -> usize {
        use std::time::Instant;

        use objc2_app_kit::NSRunningApplication;
        use objc2_foundation::NSString;

        let own = libc::pid_t::try_from(std::process::id()).unwrap_or(-1);
        let bundle = NSString::from_str(agentsweep_core::BUNDLE_ID);
        let mut quitting: Vec<libc::pid_t> = Vec::new();
        for app in NSRunningApplication::runningApplicationsWithBundleIdentifier(&bundle) {
            let pid = app.processIdentifier();
            if pid > 0 && pid != own {
                app.terminate();
                quitting.push(pid);
            }
        }
        // The properties of a running application follow only on a main run
        // loop, which this process does not run, so whether it is gone is
        // asked of the kernel: a signal zero, which sends nothing.
        let deadline = Instant::now() + wait;
        loop {
            // SAFETY: `kill` with signal zero only checks that the process
            // exists; it sends nothing.
            quitting.retain(|pid| unsafe { libc::kill(*pid, 0) } == 0);
            if quitting.is_empty() || Instant::now() >= deadline {
                return quitting.len();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Off macOS nothing of the app runs as a registered application yet (spec
/// section 6.1).
#[cfg(not(target_os = "macos"))]
impl Running for SystemRunning {
    fn quit(&self, _wait: Duration) -> usize {
        0
    }
}

/// `--finish-uninstall`, which `agentsweep uninstall` runs once the daemon
/// has applied the choice: quits a running AgentSweep, so nothing of it is
/// left open, then unregisters the daemon and the login item, which stops
/// the daemon. Answers what could not be done, one line each.
pub fn finish(running: &dyn Running, services: &dyn Services) -> Vec<String> {
    let mut left = Vec::new();
    if running.quit(QUIT_WAIT) > 0 {
        left.push("AgentSweep did not quit".to_string());
    }
    left.extend(supervision::unregister_everything(services));
    left
}

/// Where the app is moved to the Trash.
pub trait Trash: Send + Sync {
    /// Moves the bundle at this path to the Trash.
    fn move_to_trash(&self, bundle: &Path) -> Result<(), String>;
}

/// The Trash itself, through the file manager of the operating system.
#[derive(Debug, Default)]
pub struct SystemTrash;

#[cfg(target_os = "macos")]
impl Trash for SystemTrash {
    fn move_to_trash(&self, bundle: &Path) -> Result<(), String> {
        use objc2_foundation::{NSFileManager, NSString, NSURL};

        let path = NSString::from_str(&bundle.to_string_lossy());
        let url = NSURL::fileURLWithPath(&path);
        let manager = NSFileManager::defaultManager();
        manager
            .trashItemAtURL_resultingItemURL_error(&url, None)
            .map_err(|error| error.localizedDescription().to_string())
    }
}

/// Off macOS there is no Trash to move the app to yet (spec section 6.1).
#[cfg(not(target_os = "macos"))]
impl Trash for SystemTrash {
    fn move_to_trash(&self, _bundle: &Path) -> Result<(), String> {
        Err("there is no Trash on this platform".to_string())
    }
}

/// The app bundle an executable runs out of: the nearest directory above it
/// whose name ends in `.app`. Nothing for a developer run outside a bundle.
pub fn bundle_of(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .skip(1)
        .find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension == "app")
        })
        .map(Path::to_path_buf)
}

/// The label of each choice, with the number of Items in quarantine.
pub fn label(choice: UninstallChoice, quarantined: usize) -> String {
    match choice {
        UninstallChoice::RestoreAll => match quarantined {
            1 => "Restore the 1 quarantined item".to_string(),
            quarantined => format!("Restore all {quarantined} quarantined items"),
        },
        UninstallChoice::Keep => "Keep them in quarantine".to_string(),
        UninstallChoice::DeleteEverything => "Delete everything".to_string(),
    }
}

/// What each choice says under its label.
fn explanation(choice: UninstallChoice) -> &'static str {
    match choice {
        UninstallChoice::RestoreAll => {
            "Each item goes back where it was taken from. One whose place holds something else \
             now stays in quarantine."
        }
        UninstallChoice::Keep => {
            "Nothing is put back and nothing is deleted. Installing AgentSweep again picks up \
             where it left off."
        }
        UninstallChoice::DeleteEverything => {
            "The quarantined items, AgentSweep's records, its logs, its caches and its settings \
             are deleted for good."
        }
    }
}

/// The Uninstall section of the Settings pane, at its foot.
pub fn section() -> Value {
    json!({
        "title": "Uninstall AgentSweep",
        "line": "Takes AgentSweep's hooks out of Claude Code and Codex, stops it, and moves the \
                 app to the Trash.",
        "button": "Uninstall AgentSweep…",
    })
}

/// The dialog the button opens, for the number of Items in quarantine. Keep
/// is the one selected.
pub fn view(quarantined: usize) -> Value {
    json!({
        "question": "What should happen to what is in quarantine?",
        "choices": UninstallChoice::ALL
            .iter()
            .map(|choice| json!({
                "choice": choice.as_str(),
                "label": label(*choice, quarantined),
                "line": explanation(*choice),
                "selected": *choice == UninstallChoice::default(),
            }))
            .collect::<Vec<_>>(),
        "ok": "Uninstall",
    })
}

/// The choice the dialog sent: `{"choice": "restore-all"}`, or Keep when it
/// names none.
pub fn choice_of(asked: &Value) -> Result<UninstallChoice, String> {
    match asked.get("choice") {
        None | Some(Value::Null) => Ok(UninstallChoice::default()),
        Some(choice) => choice
            .as_str()
            .and_then(UninstallChoice::parse)
            .ok_or_else(|| "That is not a choice AgentSweep knows. Nothing was done.".to_string()),
    }
}

/// What the Settings flow did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uninstalled {
    /// What the daemon did.
    pub report: UninstallReport,
    /// What could not be unregistered.
    pub unregistered: Vec<String>,
    /// Whether the app went to the Trash, or why not.
    pub trashed: Result<(), String>,
    /// The bundle the app runs out of, absent outside one.
    pub bundle: Option<PathBuf>,
}

impl Uninstalled {
    /// The lines the pane shows once it is done.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![self.report.message.clone()];
        for restored in &self.report.restored {
            lines.push(restored.message.clone());
        }
        lines.extend(
            self.report
                .failed
                .iter()
                .map(|failed| format!("Not done: {failed}")),
        );
        lines.extend(self.unregistered.iter().cloned());
        lines.push(match &self.trashed {
            Ok(()) => "AgentSweep is in the Trash and quits now.".to_string(),
            Err(why) => format!(
                "AgentSweep could not be moved to the Trash ({why}). Quit it, then drag it {}to \
                 the Trash.",
                match self.bundle.as_deref().and_then(Path::parent) {
                    Some(folder) => format!("from {} ", folder.display()),
                    None => String::new(),
                }
            ),
        });
        lines
    }
}

/// The Settings flow: the daemon first, then the registrations, then the
/// Trash. A daemon that does not answer, or refuses, stops it before
/// anything else is touched.
pub fn carry_out(
    asking: &Asking,
    services: &dyn Services,
    trash: &dyn Trash,
    bundle: Option<&Path>,
    choice: UninstallChoice,
) -> Result<Uninstalled, String> {
    let report = asking.uninstall(choice).map_err(|error| {
        format!(
            "{} Start AgentSweep and try again, so it can take its hooks out of Claude Code and \
             Codex first.",
            refusal(&error)
        )
    })?;
    let unregistered = supervision::unregister_everything(services);
    let trashed = match bundle {
        Some(bundle) => trash.move_to_trash(bundle),
        None => Err("this copy does not run out of an app bundle".to_string()),
    };
    Ok(Uninstalled {
        report,
        unregistered,
        trashed,
        bundle: bundle.map(Path::to_path_buf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundle_is_the_nearest_app_above_the_executable() {
        assert_eq!(
            bundle_of(Path::new(
                "/Applications/AgentSweep.app/Contents/MacOS/agentsweep-menubar"
            )),
            Some(PathBuf::from("/Applications/AgentSweep.app"))
        );
        assert_eq!(
            bundle_of(Path::new("/src/target/debug/agentsweep-menubar")),
            None
        );
    }

    /// Keep is the default, selected in the dialog and taken when the window
    /// names no choice; anything else it does not know is refused.
    #[test]
    fn keep_is_the_default_and_an_unknown_choice_is_refused() {
        assert_eq!(choice_of(&json!({})), Ok(UninstallChoice::Keep));
        assert_eq!(
            choice_of(&json!({"choice": "delete-everything"})),
            Ok(UninstallChoice::DeleteEverything)
        );
        assert!(choice_of(&json!({"choice": "everything"})).is_err());
        let view = view(2);
        let selected: Vec<&str> = view["choices"]
            .as_array()
            .expect("choices")
            .iter()
            .filter(|choice| choice["selected"] == true)
            .map(|choice| choice["choice"].as_str().expect("a choice"))
            .collect();
        assert_eq!(selected, vec!["keep"]);
        assert_eq!(
            view["choices"][0]["label"],
            "Restore all 2 quarantined items"
        );
        assert_eq!(section()["button"], "Uninstall AgentSweep…");
    }
}
