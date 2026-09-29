//! A bare `agentsweep scan`: the daemon's Full Scan, followed from the
//! terminal.
//!
//! The command scans nothing itself. It subscribes to the daemon's state
//! events, asks for a Full Scan, prints each progress event as it arrives and
//! the summary when the Scan finishes, then exits the way `status` does: 0
//! when nothing is open, 1 when something is. A Full Scan that is already
//! running or waiting is joined rather than started twice (spec section 6.4).
//! A daemon that does not answer is Protection off, exit 3.

use std::io::Write;
use std::path::PathBuf;

use agentsweep_core::scan_pass::ScanKind;
use agentsweep_core::state::{ScanSummary, Trigger};
use agentsweep_ipc::protocol::{Role, StateEvent};
use agentsweep_ipc::{Client, ClientError};

use crate::actions::{DONE, NOT_DONE, UNREACHABLE};
use crate::status::{count, scan_line};

/// One bare `scan` command line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Invocation {
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// Reads the command line after a bare `scan`: nothing, or `--socket <path>`.
pub fn parse(arguments: &[String]) -> Result<Invocation, String> {
    match arguments {
        [] => Ok(Invocation::default()),
        [flag, path] if flag == "--socket" => Ok(Invocation {
            socket: Some(PathBuf::from(path)),
        }),
        [flag] if flag == "--socket" => Err("`--socket` takes a path".to_string()),
        [unknown, ..] => Err(format!("`{unknown}` is not an option of `scan`")),
    }
}

/// Asks the daemon for a Full Scan and follows it to the end, writing to
/// `out`. On a terminal the progress rewrites one line; anywhere else every
/// progress event is a line of its own. Answers with the exit code.
pub fn run(invocation: &Invocation, out: &mut dyn Write, terminal: bool) -> u8 {
    let connect = || match &invocation.socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    };

    // The stream first, so no event of the Scan this command asks for can go
    // by before anyone listens. A subscribed connection carries no requests,
    // so the request goes on a second one.
    let subscribed = connect().and_then(Client::subscribe);
    let mut subscription = match subscribed {
        Ok(subscription) => subscription,
        Err(error) => return unanswered(&error, out),
    };
    let mut asking = match connect() {
        Ok(client) => client,
        Err(error) => return unanswered(&error, out),
    };
    let started = match asking.scan_now() {
        Ok(started) => started,
        Err(error) => return unanswered(&error, out),
    };
    let _ = writeln!(
        out,
        "{}",
        match started {
            true => "A Full Scan started.",
            false => "A Full Scan is already under way. Following it.",
        }
    );
    let _ = out.flush();

    let summary = match follow(|| subscription.next_event(), started, out, terminal) {
        Ok(Some(summary)) => summary,
        Ok(None) => {
            let _ = writeln!(
                out,
                "Protection is off: the daemon went away before the Scan finished."
            );
            return UNREACHABLE;
        }
        Err(error) => return unanswered(&error, out),
    };

    let _ = writeln!(out, "{}", scan_line(&summary));
    // What is open now is the daemon's to say: a Finding this Scan raised may
    // already be stopped, and one an earlier Scan raised may still be open.
    let open = match asking.status() {
        Ok(status) => status.open().count(),
        Err(_) => summary.findings(),
    };
    let _ = writeln!(out, "{}", open_line(open));
    match open {
        0 => DONE,
        _ => NOT_DONE,
    }
}

/// Reads the stream until the Full Scan this command asked for or joined
/// finishes, printing progress on the way. Answers with its summary, or
/// `None` when the daemon closed the stream first.
///
/// A Scan this command started is the one whose start it sees with the
/// `scan-now` trigger, so a Full Scan that was finishing as the request went
/// in is not taken for it. A Scan it joined was already running, so the next
/// Full Scan to finish is the one.
pub fn follow(
    mut next: impl FnMut() -> Result<Option<StateEvent>, ClientError>,
    started: bool,
    out: &mut dyn Write,
    terminal: bool,
) -> Result<Option<ScanSummary>, ClientError> {
    let mut ours_began = !started;
    let mut width = 0;
    loop {
        let Some(event) = next()? else {
            if terminal && width > 0 {
                let _ = writeln!(out);
            }
            return Ok(None);
        };
        match event {
            StateEvent::ScanStarted {
                trigger: Trigger::ScanNow,
                ..
            } => {
                ours_began = true;
            }
            StateEvent::ScanProgress { done, total } => {
                let line = progress_line(done, total);
                if terminal {
                    width = width.max(line.len());
                    let _ = write!(out, "\r{line:<width$}");
                } else {
                    let _ = writeln!(out, "{line}");
                }
                let _ = out.flush();
            }
            StateEvent::ScanFinished { summary }
                if summary.kind == ScanKind::Full && ours_began =>
            {
                if terminal && width > 0 {
                    let _ = writeln!(out);
                }
                return Ok(Some(*summary));
            }
            _ => {}
        }
    }
}

/// One progress event on one line.
pub fn progress_line(done: usize, total: usize) -> String {
    match total {
        0 => "Looking for what to check.".to_string(),
        _ => format!("Checked {done} of {}.", count(total, "Item", "Items")),
    }
}

/// What stands once the Scan is over.
fn open_line(open: usize) -> String {
    match open {
        0 => "Nothing is open.".to_string(),
        1 => "1 Finding is open. `agentsweep status` shows it and what can be done.".to_string(),
        n => format!("{n} Findings are open. `agentsweep status` shows them and what can be done."),
    }
}

/// What a Scan that could not be asked for prints, with its exit code.
fn unanswered(error: &ClientError, out: &mut dyn Write) -> u8 {
    match error {
        ClientError::Unreachable(_) => {
            let _ = writeln!(
                out,
                "Protection is off: {}. No Scan was started.",
                error.unreachable()
            );
            UNREACHABLE
        }
        other => {
            let _ = writeln!(out, "AgentSweep could not be asked: {other}");
            NOT_DONE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use agentsweep_core::envelope::Timestamp;

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| word.to_string()).collect()
    }

    fn summary(kind: ScanKind, trigger: Trigger) -> Box<ScanSummary> {
        Box::new(ScanSummary {
            kind,
            trigger,
            started_at: Timestamp::parse("2026-09-25T08:00:00.000Z").expect("a moment"),
            duration_ms: 40,
            items: 3,
            threats: 1,
            exposures: 0,
            clear: 2,
            ambiguous: 0,
            suspicious: 0,
            rule_pack: 1,
            engine: String::new(),
        })
    }

    fn started(trigger: Trigger) -> StateEvent {
        StateEvent::ScanStarted {
            trigger,
            at: Timestamp::parse("2026-09-25T08:00:00.000Z").expect("a moment"),
        }
    }

    /// Plays a recorded stream into [`follow`] and answers with what it
    /// printed and the summary it stopped at.
    fn played(
        events: Vec<StateEvent>,
        began: bool,
        terminal: bool,
    ) -> (String, Option<ScanSummary>) {
        let mut events = events.into_iter();
        let mut out = Vec::new();
        let summary =
            follow(|| Ok(events.next()), began, &mut out, terminal).expect("the stream is read");
        (String::from_utf8(out).expect("text"), summary)
    }

    #[test]
    fn a_bare_scan_takes_only_a_socket() {
        assert_eq!(parse(&[]).expect("a command"), Invocation::default());
        assert_eq!(
            parse(&words(&["--socket", "/tmp/a.sock"]))
                .expect("a command")
                .socket,
            Some(PathBuf::from("/tmp/a.sock"))
        );
        assert!(parse(&words(&["--socket"])).is_err());
        assert!(parse(&words(&["--all"])).is_err());
    }

    /// Off a terminal, every progress event is a line of its own, and the
    /// stream is read up to the Full Scan this command started.
    #[test]
    fn progress_is_one_line_per_event_off_a_terminal() {
        let (printed, summary) = played(
            vec![
                started(Trigger::ScanNow),
                StateEvent::ScanProgress { done: 0, total: 0 },
                StateEvent::ScanProgress { done: 0, total: 3 },
                StateEvent::ScanProgress { done: 3, total: 3 },
                StateEvent::ScanFinished {
                    summary: summary(ScanKind::Full, Trigger::ScanNow),
                },
                StateEvent::ScanProgress { done: 9, total: 9 },
            ],
            true,
            false,
        );
        assert_eq!(
            printed,
            "Looking for what to check.\nChecked 0 of 3 Items.\nChecked 3 of 3 Items.\n"
        );
        assert_eq!(summary.expect("a summary").trigger, Trigger::ScanNow);
    }

    /// On a terminal the progress rewrites one line, which ends before the
    /// summary is printed.
    #[test]
    fn progress_rewrites_one_line_on_a_terminal() {
        let (printed, _) = played(
            vec![
                started(Trigger::ScanNow),
                StateEvent::ScanProgress { done: 0, total: 0 },
                StateEvent::ScanProgress { done: 3, total: 3 },
                StateEvent::ScanFinished {
                    summary: summary(ScanKind::Full, Trigger::ScanNow),
                },
            ],
            true,
            true,
        );
        assert_eq!(printed.matches('\r').count(), 2, "{printed:?}");
        assert_eq!(printed.matches('\n').count(), 1, "{printed:?}");
        // The shorter line is padded over the longer one it replaces.
        assert_eq!(
            printed,
            format!(
                "\r{}\r{:<26}\n",
                "Looking for what to check.", "Checked 3 of 3 Items."
            ),
        );
    }

    /// A Change Scan finishing, or a Full Scan that finished before the one
    /// this command started began, is not the one it waits for.
    #[test]
    fn only_the_full_scan_that_was_asked_for_ends_the_command() {
        let (_, summary) = played(
            vec![
                StateEvent::ScanFinished {
                    summary: summary(ScanKind::Full, Trigger::Due),
                },
                started(Trigger::Watcher),
                StateEvent::ScanFinished {
                    summary: summary(ScanKind::Change, Trigger::Watcher),
                },
                started(Trigger::ScanNow),
                StateEvent::ScanFinished {
                    summary: summary(ScanKind::Full, Trigger::ScanNow),
                },
            ],
            true,
            false,
        );
        let summary = summary.expect("a summary");
        assert_eq!(summary.kind, ScanKind::Full);
        assert_eq!(summary.trigger, Trigger::ScanNow);
    }

    /// A Full Scan that was already under way is joined: the next Full Scan to
    /// finish is it, whatever started it.
    #[test]
    fn a_joined_full_scan_ends_the_command_when_it_finishes() {
        let (_, summary) = played(
            vec![StateEvent::ScanFinished {
                summary: summary(ScanKind::Full, Trigger::Due),
            }],
            false,
            false,
        );
        assert_eq!(summary.expect("a summary").trigger, Trigger::Due);
    }

    #[test]
    fn a_stream_that_ends_first_is_no_summary() {
        let (_, summary) = played(vec![started(Trigger::ScanNow)], true, false);
        assert_eq!(summary, None);
    }

    /// Nothing is scanned without a daemon: the command says Protection is
    /// off and exits with its own code. The socket is named, so the
    /// documented one is never touched.
    #[test]
    fn no_daemon_is_protection_off_and_no_scan() {
        let nowhere = std::env::temp_dir().join(format!(
            "agentsweep-scan-now-nobody-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&nowhere);
        let mut out = Vec::new();
        let code = run(
            &Invocation {
                socket: Some(nowhere),
            },
            &mut out,
            false,
        );
        let printed = String::from_utf8(out).expect("text");
        assert_eq!(
            printed,
            "Protection is off: no daemon answered. No Scan was started.\n"
        );
        assert_eq!(code, UNREACHABLE);
    }
}
