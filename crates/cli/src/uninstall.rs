//! `agentsweep uninstall [--keep | --restore-all | --delete-everything]`:
//! Uninstall from the command line (spec section 9.6).
//!
//! It sends the daemon the same `uninstall` request the Settings flow sends,
//! with the same default, Keep. The daemon does everything that touches the
//! Agents and the stores: it takes the Gate's entries and the Codex pin away,
//! then keeps, restores or deletes what is in quarantine. What the daemon
//! cannot do this command does not try either: it tells the user to move
//! AgentSweep to the Trash, and the daemon, seeing its bundle gone, stops for
//! good (the owner's decision of 2026-10-14).

use std::path::PathBuf;

use agentsweep_ipc::protocol::{Role, UninstallChoice, UninstallReport};
use agentsweep_ipc::{Client, ClientError};

use crate::actions::{DONE, NOT_DONE, UNREACHABLE};

/// One `uninstall` command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// What happens to what is in quarantine, Keep unless named.
    pub choice: UninstallChoice,
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// The flag of each choice.
fn flag(choice: UninstallChoice) -> &'static str {
    match choice {
        UninstallChoice::RestoreAll => "--restore-all",
        UninstallChoice::Keep => "--keep",
        UninstallChoice::DeleteEverything => "--delete-everything",
    }
}

/// Reads the command line after `uninstall`. At most one choice; none is
/// Keep.
pub fn parse(arguments: &[String]) -> Result<Invocation, String> {
    let mut choice = None;
    let mut socket = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == "--socket" {
            let path = rest
                .next()
                .ok_or_else(|| "`--socket` takes a path".to_string())?;
            socket = Some(PathBuf::from(path));
            continue;
        }
        let named = UninstallChoice::ALL
            .into_iter()
            .find(|choice| flag(*choice) == argument);
        match (named, choice) {
            (Some(named), None) => choice = Some(named),
            (Some(_), Some(_)) => {
                return Err("`uninstall` takes one of --keep, --restore-all and \
                            --delete-everything"
                    .to_string());
            }
            (None, _) => {
                return Err(format!(
                    "`uninstall` takes --keep, --restore-all or --delete-everything, not \
                     `{argument}`"
                ));
            }
        }
    }
    Ok(Invocation {
        choice: choice.unwrap_or_default(),
        socket,
    })
}

/// What the user does next, which no daemon can do for them.
pub const MOVE_TO_TRASH: &str = "Now move AgentSweep to the Trash: open Applications in the \
     Finder and drag AgentSweep to the Trash. AgentSweep stops for good when it is gone.";

/// Asks the daemon and says what it did.
pub fn run(invocation: &Invocation) -> (String, u8) {
    let connected = match &invocation.socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    };
    match connected.and_then(|mut client| client.uninstall(invocation.choice)) {
        Ok(report) => (
            render(&report),
            if report.complete() { DONE } else { NOT_DONE },
        ),
        Err(error @ ClientError::Unreachable(_)) => (
            format!(
                "Protection is off: {}. Nothing was changed. Start AgentSweep and ask again, \
                 so it can take its hooks out of Claude Code and Codex.\n",
                error.unreachable()
            ),
            UNREACHABLE,
        ),
        Err(error) => (
            format!("AgentSweep could not be asked: {error}\n"),
            NOT_DONE,
        ),
    }
}

/// The report as the terminal shows it: the sentence, one line per Item
/// restored or not, what was deleted, what failed, and the step left.
pub fn render(report: &UninstallReport) -> String {
    let mut out = format!("{}\n", report.message);
    for restored in &report.restored {
        out.push_str(&format!(
            "  {} ({}): {}\n",
            restored.item_id, restored.receipt_id, restored.message
        ));
    }
    if !report.deleted.is_empty() {
        out.push_str(&format!("Deleted: {}.\n", report.deleted.join(", ")));
    }
    for failed in &report.failed {
        out.push_str(&format!("Not done: {failed}\n"));
    }
    out.push_str(MOVE_TO_TRASH);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| word.to_string()).collect()
    }

    /// No flag is Keep, the same default as the Settings flow, which sends
    /// the same request through [`Client::uninstall`].
    #[test]
    fn no_flag_is_keep_and_each_flag_names_its_choice() {
        let bare = parse(&[]).expect("a command");
        assert_eq!(bare.choice, UninstallChoice::Keep);
        assert_eq!(bare.choice, UninstallChoice::default());
        for (word, choice) in [
            ("--keep", UninstallChoice::Keep),
            ("--restore-all", UninstallChoice::RestoreAll),
            ("--delete-everything", UninstallChoice::DeleteEverything),
        ] {
            assert_eq!(parse(&words(&[word])).expect("a command").choice, choice);
        }
        assert_eq!(
            parse(&words(&["--socket", "/tmp/a.sock", "--restore-all"])).expect("a command"),
            Invocation {
                choice: UninstallChoice::RestoreAll,
                socket: Some(PathBuf::from("/tmp/a.sock")),
            }
        );
        assert!(parse(&words(&["--keep", "--delete-everything"])).is_err());
        assert!(parse(&words(&["everything"])).is_err());
        assert!(parse(&words(&["--socket"])).is_err());
    }

    #[test]
    fn no_daemon_is_protection_off_and_nothing_changed() {
        let nowhere = std::env::temp_dir().join(format!(
            "agentsweep-uninstall-nobody-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&nowhere);
        let (rendered, code) = run(&Invocation {
            choice: UninstallChoice::DeleteEverything,
            socket: Some(nowhere),
        });
        assert!(rendered.starts_with("Protection is off"), "{rendered}");
        assert_eq!(code, UNREACHABLE);
    }

    /// The report ends with the one step the daemon cannot take.
    #[test]
    fn the_report_ends_by_asking_to_move_agentsweep_to_the_trash() {
        let rendered = render(&UninstallReport {
            choice: UninstallChoice::DeleteEverything,
            deleted: vec!["the data directory".to_string(), "the caches".to_string()],
            message: "Deleted everything AgentSweep made.".to_string(),
            ..UninstallReport::default()
        });
        assert!(rendered.starts_with("Deleted everything"), "{rendered}");
        assert!(rendered.contains("Deleted: the data directory, the caches."));
        assert!(
            rendered.trim_end().ends_with("when it is gone."),
            "{rendered}"
        );
    }
}
