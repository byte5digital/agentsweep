//! The AgentSweep daemon, binary `agentsweepd`.
//!
//! Everything it does is in the library beside this file. What is here is the
//! command line and the exit code, so that a test can start a daemon without
//! starting a process.

use std::process::ExitCode;

use agentsweep_daemon::options::{self, Invocation};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let invocation = match options::parse(&arguments) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("agentsweepd: {error}\n\n{}", agentsweep_daemon::USAGE);
            return ExitCode::from(2);
        }
    };
    match invocation {
        Invocation::Help => {
            println!("{}", agentsweep_daemon::USAGE);
            ExitCode::SUCCESS
        }
        Invocation::Version => {
            println!(
                "{} {}",
                agentsweep_core::DAEMON_LABEL,
                agentsweep_core::VERSION
            );
            ExitCode::SUCCESS
        }
        Invocation::Run(options) => {
            if let Err(error) = start_the_log(&options) {
                eprintln!("agentsweepd: the log could not be started: {error}");
            }
            match agentsweep_daemon::run(&options) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    tracing::error!("{error}");
                    eprintln!("agentsweepd: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Invocation::Budgets(options) => {
            // A measurement prints to the terminal and never adds to the log.
            let _ = agentsweep_daemon::log::start(None);
            match agentsweep_daemon::budgets::measure(&options) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("agentsweepd: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Starts the log where this run writes it: the rotated file under the home's
/// `Library/Logs/AgentSweep` for the installed daemon, the terminal for a
/// developer run.
fn start_the_log(options: &agentsweep_daemon::Options) -> std::io::Result<()> {
    if !options.writes_the_log_file() {
        return agentsweep_daemon::log::start(None);
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| std::io::Error::other("there is no home directory"))?;
    agentsweep_daemon::log::start(Some(&agentsweep_daemon::log::log_directory(&home)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_binary_name_is_the_machine_readable_product_name_with_a_d() {
        assert_eq!(
            env!("CARGO_BIN_NAME"),
            format!("{}d", agentsweep_core::NAME)
        );
    }
}
