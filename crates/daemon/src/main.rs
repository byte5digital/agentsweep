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
        Invocation::Run(options) => match agentsweep_daemon::run(&options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("agentsweepd: {error}");
                ExitCode::FAILURE
            }
        },
    }
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
