//! The AgentSweep command line interface, binary `agentsweep`.
//!
//! In the bundle it is a client of the daemon; built from crates.io it is an
//! on-demand scanner. The client commands and the Gate arrive with milestone 7
//! of the build plan. What is here is `scan <dir>`, the Folder Scan, which runs
//! entirely in this process and never reaches a daemon.

mod developer;
mod folder_scan;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
AgentSweep scans the local configuration surfaces of coding agents.

Usage:
  agentsweep scan <dir>   Check one folder before you open it with an agent.
  agentsweep --version    Print the version.
  agentsweep --help       Print this message.

`scan` exits 0 when the folder is safe to open and 1 when it found something.

Developer only, off unless asked for by name:
  agentsweep --developer-list-items [<home>]
                          List the Items the surface adapters would enumerate
                          for a home directory, so a real installation can be
                          compared with the surface inventory. It reads the
                          real machine, records nothing and prints no values.
                          Its output is never committed.";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("scan") => scan(&arguments[1..]),
        Some("--developer-list-items") => developer_list_items(&arguments[1..]),
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

#[cfg(test)]
mod tests {
    /// The one flag that reads the real machine says so where a person sees
    /// it, and nothing runs it by accident.
    #[test]
    fn the_developer_listing_is_marked_developer_only_in_the_help_text() {
        let usage = super::USAGE;
        assert!(usage.contains("Developer only"), "{usage}");
        assert!(usage.contains("--developer-list-items"), "{usage}");
        assert!(usage.contains("records nothing"), "{usage}");
    }

    #[test]
    fn the_binary_name_is_the_machine_readable_product_name() {
        assert_eq!(env!("CARGO_BIN_NAME"), agentsweep_core::NAME);
    }

    #[test]
    fn the_usage_names_the_folder_scan_the_app_shows_in_the_developer_posture() {
        assert!(super::USAGE.contains("agentsweep scan <dir>"));
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
