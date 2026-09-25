//! The AgentSweep menu bar app. Everything is in the library beside this file.
//!
//! The app takes no arguments. The one exception is a developer flag,
//! `--developer-unregister`, which unregisters the daemon and the login item
//! of the bundle it is run from and exits without opening anything. It is how
//! a hand check takes a test install off the machine (`docs/hand-checks.md`);
//! Uninstall proper arrives with its own milestone.

use std::process::ExitCode;

use agentsweep_menubar::supervision::{self, SystemServices};

fn main() -> ExitCode {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--developer-unregister")
    {
        let failures = supervision::unregister_everything(&SystemServices);
        for failure in &failures {
            eprintln!("agentsweep-menubar: {failure}");
        }
        return match failures.is_empty() {
            true => {
                println!("agentsweep-menubar: the daemon and the login item are unregistered");
                ExitCode::SUCCESS
            }
            false => ExitCode::FAILURE,
        };
    }
    agentsweep_menubar::app::run();
    ExitCode::SUCCESS
}
