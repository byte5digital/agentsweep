//! Uninstall, as the daemon carries it out (spec section 9.6).
//!
//! The Settings flow and `agentsweep uninstall` send one `uninstall` request
//! with the user's choice. The daemon is the only writer of the stores and the
//! Agents' settings, so it does everything that touches them, in this order:
//!
//! 1. It stops taking work: no further Scan, Rule Feed fetch or landing
//!    Verdict, and from then on it answers nothing but `status` and
//!    `uninstall`. A Scan would otherwise register the Gate again, and a
//!    write would bring a deleted data directory back.
//! 2. It takes the Gate's entries and the Codex pin away from every Agent,
//!    on every choice (spec section 7.6), before the client unregisters it.
//! 3. It applies the choice. **Keep** leaves the store, the Event Log and
//!    the data directory as they are, so a reinstall resumes them. **Restore
//!    all** replays every Receipt as a single Restore would, under the same
//!    conflict rule (spec section 5.4): what meets something else at its
//!    original place is not put back and stays in quarantine, and the report
//!    says so. **Delete everything** removes everything AgentSweep made (the
//!    owner's decision of 2026-10-14): the data directory with the
//!    quarantined payloads, both Keychain items, the log directory, the
//!    caches and the app's preferences.
//!
//! Unregistering the daemon and the login item and moving the app to the
//! Trash are the app's. The daemon stays up and idle until then, or until its
//! bundle is gone, which stops it for good (spec section 9.5).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentsweep_core::BUNDLE_ID;
use agentsweep_core::quarantine::Conflict;
use agentsweep_ipc::protocol::{UninstallChoice, UninstallReport};

use crate::service::Daemon;

/// What Delete everything removes, as (what it is called, where it is), for
/// a data directory and a home. Each is AgentSweep's own and nothing else's:
/// a directory or a file named after AgentSweep or its bundle identifier.
pub fn what_delete_everything_removes(data: &Path, home: &Path) -> Vec<(&'static str, PathBuf)> {
    let library = home.join("Library");
    vec![
        ("the data directory", data.to_path_buf()),
        ("the log directory", crate::log::log_directory(home)),
        ("the caches", library.join("Caches").join(BUNDLE_ID)),
        (
            "the web view's storage",
            library.join("WebKit").join(BUNDLE_ID),
        ),
        (
            "the HTTP storage",
            library.join("HTTPStorages").join(BUNDLE_ID),
        ),
        (
            "the app's preferences",
            library
                .join("Preferences")
                .join(format!("{BUNDLE_ID}.plist")),
        ),
        (
            "the saved window state",
            library
                .join("Saved Application State")
                .join(format!("{BUNDLE_ID}.savedState")),
        ),
    ]
}

/// Removes one file or tree. Nothing there is not an error; a symbolic link
/// is removed itself and never followed.
fn remove(path: &Path) -> std::io::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    match metadata.is_dir() {
        true => std::fs::remove_dir_all(path)?,
        false => std::fs::remove_file(path)?,
    }
    Ok(true)
}

impl Daemon {
    /// Carries out Uninstall with the user's choice and answers with what it
    /// did. Waits for a running Scan, fetch or action to finish first.
    pub fn uninstall(self: &Arc<Daemon>, choice: UninstallChoice) -> UninstallReport {
        self.stop_for_uninstall();
        let _fetch = self.hold_the_fetch();
        self.judgement_queue.reset();
        let _writing = self.writing.lock().expect("the write lock is not poisoned");
        say!("uninstalling, with the choice {}", choice.as_str());

        let removal = self.take_the_gate_away();
        self.health
            .lock()
            .expect("the health is not poisoned")
            .gate_lines
            .clear();
        let mut report = UninstallReport {
            choice,
            gate_removed: removal.removed,
            gate_failed: removal.failed,
            ..UninstallReport::default()
        };
        match choice {
            UninstallChoice::Keep => self.keep(&mut report),
            UninstallChoice::RestoreAll => self.restore_all(&mut report),
            UninstallChoice::DeleteEverything => self.delete_everything(&mut report),
        }
        if !report.gate_failed.is_empty() {
            report.message.push_str(&format!(
                " AgentSweep's hooks could not be taken out of {}; remove them by hand.",
                report.gate_failed.join(" and ")
            ));
        }
        drop(_writing);
        self.tell_health();
        report
    }

    /// Keep: nothing of the store or the Event Log is touched.
    fn keep(&self, report: &mut UninstallReport) {
        let held = self.manifest().map(|manifest| manifest.len()).unwrap_or(0);
        report.message = format!(
            "AgentSweep's hooks are out of Claude Code and Codex. {} in quarantine, so \
             installing AgentSweep again picks up where it left off.",
            match held {
                1 => "The 1 quarantined item stays".to_string(),
                held => format!("The {held} quarantined items stay"),
            }
        );
    }

    /// Restore all: every Receipt replayed in reverse, each as a single
    /// Restore replays it, refusing where something else stands at the
    /// original place now.
    fn restore_all(self: &Arc<Daemon>, report: &mut UninstallReport) {
        let manifest = match self.manifest() {
            Ok(manifest) => manifest,
            Err(error) => {
                report.failed.push(error.message.clone());
                report.message =
                    "Nothing was restored: what is in quarantine could not be read.".to_string();
                return;
            }
        };
        let total = manifest.len();
        for entry in manifest.entries() {
            match self.restore_entry(entry, Conflict::Refuse) {
                Ok(restored) => report.restored.push(restored),
                Err(error) => report.failed.push(format!(
                    "{} was not restored: {}",
                    entry.receipt_id, error.message
                )),
            }
        }
        let done = report
            .restored
            .iter()
            .filter(|restored| restored.result == agentsweep_core::eventlog::Outcome::Ok)
            .count();
        say!("uninstalling: {done} of {total} quarantined Items restored");
        report.message = match (done, total) {
            (_, 0) => "Nothing was in quarantine.".to_string(),
            (done, total) if done == total => format!(
                "Restored all {total} quarantined {}.",
                if total == 1 { "item" } else { "items" }
            ),
            (done, total) => format!(
                "Restored {done} of {total} quarantined items. The others stay in quarantine; \
                 each line says why."
            ),
        };
    }

    /// Delete everything: what AgentSweep made goes, and the Keychain items
    /// with it. Nothing outside [`what_delete_everything_removes`] is
    /// touched.
    fn delete_everything(&self, report: &mut UninstallReport) {
        for (name, path) in
            what_delete_everything_removes(self.directory.root(), self.machine.home())
        {
            match remove(&path) {
                Ok(true) => report.deleted.push(name.to_string()),
                Ok(false) => {}
                Err(error) => {
                    say!("uninstalling: {name} could not be deleted: {error}");
                    report.failed.push(name.to_string());
                }
            }
        }
        match self.keys.forget() {
            Ok(()) => report.deleted.push("the Event Log key".to_string()),
            Err(error) => {
                say!("uninstalling: the Event Log key could not be removed: {error}");
                report.failed.push("the Event Log key".to_string());
            }
        }
        match self.claude_key.forget() {
            Ok(()) => report.deleted.push("the Claude API key".to_string()),
            Err(error) => {
                say!("uninstalling: the Claude API key could not be removed: {error}");
                report.failed.push("the Claude API key".to_string());
            }
        }
        report.message = match report.failed.is_empty() {
            true => {
                "Deleted everything AgentSweep made, the quarantined items with it.".to_string()
            }
            false => format!(
                "Deleted what AgentSweep made, apart from {}.",
                report.failed.join(", ")
            ),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every place Delete everything removes is under the data directory or
    /// the home's Library, and named after AgentSweep.
    #[test]
    fn delete_everything_removes_only_agentsweeps_own_places() {
        let data = Path::new("/sandbox/data");
        let home = Path::new("/sandbox/home");
        for (_, path) in what_delete_everything_removes(data, home) {
            assert!(
                path == data || path.starts_with(home.join("Library")),
                "{}",
                path.display()
            );
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            assert!(
                path == data || name.starts_with(BUNDLE_ID) || name == "AgentSweep",
                "{name}"
            );
        }
    }

    /// A symbolic link is removed itself, and what it points at stays.
    #[test]
    fn a_link_is_removed_and_never_followed() {
        let temporary = tempfile::TempDir::new().expect("a temporary directory");
        let target = temporary.path().join("elsewhere");
        std::fs::create_dir_all(&target).expect("a directory");
        std::fs::write(target.join("keep"), b"kept").expect("a file");
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("a link");
        assert!(remove(&link).expect("removed"));
        assert!(!link.exists());
        assert!(target.join("keep").is_file());
        assert!(!remove(&link).expect("nothing there"));
    }
}
