//! The AgentSweep command line interface, binary `agentsweep`.
//!
//! In the bundle it is a client of the daemon; built from crates.io it is an
//! on-demand scanner. What is here is `scan <dir>`, the Folder Scan, which runs
//! entirely in this process, never reaches a daemon and never acts; `status`,
//! which reaches the daemon and does nothing else; and the action commands,
//! each of which is one request to the daemon, the only process that
//! quarantines, restores or trusts anything (ADR 0008). The Gate and the
//! crates.io build variant arrive with their own milestones.

mod actions;
mod developer;
mod folder_scan;
mod status;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
AgentSweep scans the local configuration surfaces of coding agents.

Usage:
  agentsweep status       Show what AgentSweep is protecting and what it found.
  agentsweep scan <dir>   Check one folder before you open it with an agent.
  agentsweep --version    Print the version.
  agentsweep --help       Print this message.

Acting on a Finding, through the running AgentSweep. <id> is a Finding id, an
Item id or a Receipt id, as `status` prints them:
  agentsweep quarantine <id>
                          Take the item of a threat out, so the agent cannot
                          load it. It can be restored.
  agentsweep restore <id> [--replace | --beside]
                          Put a quarantined item back. What AgentSweep stopped
                          by itself comes back trusted. When something else is
                          at the original place, --replace replaces it and
                          --beside restores beside it.
  agentsweep trust <id>   Say this exact version is safe. A change to it is
                          checked afresh.
  agentsweep acknowledge <id>
                          Say a change was yours. Every check still runs.
  agentsweep fix <id>     Take an unrestricted shell or a switched-off approval
                          out of your settings (rules 0018 and 0019).
  agentsweep re-enable <id>
                          Switch a stopped plugin back on for its newer,
                          clean version.
  agentsweep reveal-receipt [<path>]
                          List what is in quarantine, each receipt id beside
                          the path it was taken from.

`scan` exits 0 when the folder is safe to open and 1 when it found something.
`status` exits 0 when nothing is open, 1 when something is, and says Protection
is off when no daemon answers. An action exits 0 when it was done, 1 when it
was refused or did not finish, and 3 when no daemon answered, which is
Protection off. Every command that reaches the daemon takes
`--socket <path>` to reach one somewhere other than the documented socket.

Developer only, off unless asked for by name:
  agentsweep --developer-list-items [<home>]
                          List the Items the surface adapters would enumerate
                          for a home directory, so a real installation can be
                          compared with the surface inventory. It reads the
                          real machine, records nothing and prints no values.
                          Its output is never committed.
  agentsweep --developer-scan-items [<home>]
                          Scan the user-level surfaces of both agents with the
                          bundled rule pack and print the tier 1 hits and the
                          hit count per heuristic, the same report the benign
                          corpus prints in CI. It reads the real machine,
                          records nothing and prints no content. Its output is
                          never committed.";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("status") => status(&arguments[1..]),
        Some(command) if actions::COMMANDS.contains(&command) => act(command, &arguments[1..]),
        Some("scan") => scan(&arguments[1..]),
        Some("--developer-list-items") => developer_list_items(&arguments[1..]),
        Some("--developer-scan-items") => developer_scan_items(&arguments[1..]),
        Some("--version" | "-V") => {
            println!("{} {}", agentsweep_core::NAME, agentsweep_core::VERSION);
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("agentsweep: `{unknown}` is not a command.\n\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Asks the daemon what it is protecting and what it found.
fn status(arguments: &[String]) -> ExitCode {
    let socket = match status::socket_argument(arguments) {
        Ok(socket) => socket,
        Err(reason) => {
            eprintln!("agentsweep: {reason}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (rendered, code) = status::status(socket.as_deref());
    print!("{rendered}");
    ExitCode::from(code)
}

/// Asks the daemon to act on one Finding, Item or Receipt.
fn act(command: &str, arguments: &[String]) -> ExitCode {
    let invocation = match actions::parse(command, arguments) {
        Ok(invocation) => invocation,
        Err(reason) => {
            eprintln!("agentsweep: {reason}\n\n{USAGE}");
            return ExitCode::from(actions::USAGE_ERROR);
        }
    };
    let (rendered, code) = actions::run(&invocation);
    print!("{rendered}");
    ExitCode::from(code)
}

fn scan(arguments: &[String]) -> ExitCode {
    let [directory] = arguments else {
        eprintln!("agentsweep: `scan` takes one folder.\n\n{USAGE}");
        return ExitCode::from(2);
    };

    match folder_scan::folder_scan(&PathBuf::from(directory)) {
        Ok((root, report)) => {
            print!("{}", folder_scan::render(&root, &report));
            ExitCode::from(folder_scan::exit_code(&report))
        }
        Err(error) => {
            eprintln!("agentsweep: {directory} could not be scanned: {error}");
            ExitCode::from(2)
        }
    }
}

/// Developer only: what the surface adapters would enumerate for one home.
fn developer_list_items(arguments: &[String]) -> ExitCode {
    let home = match arguments {
        [] => None,
        [home] => Some(PathBuf::from(home)),
        _ => {
            eprintln!("agentsweep: `--developer-list-items` takes one folder.\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match developer::list_items(home) {
        Ok(listing) => {
            print!("{listing}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("agentsweep: the Items could not be listed: {error}");
            ExitCode::from(2)
        }
    }
}

/// Developer only: what the bundled Rule Pack makes of one real machine.
fn developer_scan_items(arguments: &[String]) -> ExitCode {
    let home = match arguments {
        [] => None,
        [home] => Some(PathBuf::from(home)),
        _ => {
            eprintln!("agentsweep: `--developer-scan-items` takes one folder.\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match developer::scan_items(home) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("agentsweep: the Items could not be scanned: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    /// The one flag that reads the real machine says so where a person sees
    /// it, and nothing runs it by accident.
    #[test]
    fn the_developer_listing_is_marked_developer_only_in_the_help_text() {
        let usage = super::USAGE;
        assert!(usage.contains("Developer only"), "{usage}");
        assert!(usage.contains("--developer-list-items"), "{usage}");
        assert!(usage.contains("--developer-scan-items"), "{usage}");
        assert_eq!(usage.matches("records nothing").count(), 2, "{usage}");
        assert_eq!(usage.matches("never committed").count(), 2, "{usage}");
    }

    #[test]
    fn the_binary_name_is_the_machine_readable_product_name() {
        assert_eq!(env!("CARGO_BIN_NAME"), agentsweep_core::NAME);
    }

    #[test]
    fn the_usage_names_the_folder_scan_the_app_shows_in_the_developer_posture() {
        assert!(super::USAGE.contains("agentsweep scan <dir>"));
    }

    /// The one command that reaches the daemon says what it says when no
    /// daemon answers, because Protection off is always shown.
    #[test]
    fn the_usage_names_status_and_what_it_says_without_a_daemon() {
        assert!(
            super::USAGE.contains("agentsweep status"),
            "{}",
            super::USAGE
        );
        assert!(
            super::USAGE.contains("Protection\nis off"),
            "{}",
            super::USAGE
        );
    }

    /// Every action command is in the help text, and so is what it exits
    /// with when no daemon answers.
    #[test]
    fn the_usage_names_every_action_command() {
        for command in super::actions::COMMANDS {
            assert!(
                super::USAGE.contains(&format!("agentsweep {command}")),
                "{command}"
            );
        }
        assert!(super::USAGE.contains("3 when no daemon answered"));
    }

    /// A Folder Scan runs in this process. Depending on the daemon crate would
    /// be the first step towards asking it something, and the daemon is the
    /// only writer of every store AgentSweep keeps.
    #[test]
    fn the_command_line_interface_does_not_depend_on_the_daemon() {
        let manifest = include_str!("../Cargo.toml");
        assert!(!manifest.contains("agentsweep-daemon"), "{manifest}");
    }
}
