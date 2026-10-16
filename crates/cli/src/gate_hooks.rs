//! `agentsweep gate-hooks [on | off]`: the Gate switch.
//!
//! The Gate is a hook of AgentSweep's in Claude Code and Codex that refuses a
//! step while something flagged waits for the user's decision (spec section
//! 7), on by default with one switch. The daemon is the only process that
//! writes the Agents' settings and the only one that keeps the switch, so
//! this command is one request to it and nothing else: without an argument it
//! says where the switch stands, with `on` or `off` it moves it.

use std::path::PathBuf;

use agentsweep_ipc::protocol::Role;
use agentsweep_ipc::{Client, ClientError};

use crate::actions::{DONE, NOT_DONE, UNREACHABLE};

/// One `gate-hooks` command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// The switch's new position, absent to read it.
    pub enabled: Option<bool>,
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// Reads the command line after `gate-hooks`.
pub fn parse(arguments: &[String]) -> Result<Invocation, String> {
    let mut enabled = None;
    let mut socket = None;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--socket" => {
                let path = rest
                    .next()
                    .ok_or_else(|| "`--socket` takes a path".to_string())?;
                socket = Some(PathBuf::from(path));
            }
            "on" | "off" if enabled.is_none() => enabled = Some(argument == "on"),
            other => return Err(format!("`gate-hooks` takes `on` or `off`, not `{other}`")),
        }
    }
    Ok(Invocation { enabled, socket })
}

/// Asks the daemon and says where the switch stands.
pub fn run(invocation: &Invocation) -> (String, u8) {
    let connected = match &invocation.socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    };
    let answered = connected.and_then(|mut client| match invocation.enabled {
        None => client.gate_hooks(),
        Some(enabled) => client.set_gate_hooks(enabled),
    });
    match answered {
        Ok(true) => (
            "The Gate is on: AgentSweep keeps a hook in Claude Code and Codex that \
             refuses a step while something flagged waits for your decision.\n"
                .to_string(),
            DONE,
        ),
        Ok(false) => (
            "The Gate is off: AgentSweep's hooks are taken out of Claude Code and \
             Codex and are not added again until you switch it on.\n"
                .to_string(),
            DONE,
        ),
        Err(error @ ClientError::Unreachable(_)) => (
            format!(
                "Protection is off: {}. Nothing was changed.\n",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &[&str]) -> Vec<String> {
        line.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn the_switch_is_read_without_an_argument_and_set_with_on_or_off() {
        assert_eq!(parse(&[]).expect("a command").enabled, None);
        assert_eq!(
            parse(&words(&["on"])).expect("a command").enabled,
            Some(true)
        );
        assert_eq!(
            parse(&words(&["off", "--socket", "/tmp/a.sock"])).expect("a command"),
            Invocation {
                enabled: Some(false),
                socket: Some(PathBuf::from("/tmp/a.sock"))
            }
        );
        assert!(parse(&words(&["maybe"])).is_err());
        assert!(parse(&words(&["on", "off"])).is_err());
        assert!(parse(&words(&["--socket"])).is_err());
    }

    #[test]
    fn no_daemon_is_protection_off_and_nothing_changed() {
        let nowhere = std::env::temp_dir().join(format!(
            "agentsweep-gate-hooks-nobody-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&nowhere);
        let (rendered, code) = run(&Invocation {
            enabled: Some(false),
            socket: Some(nowhere),
        });
        assert!(rendered.starts_with("Protection is off"), "{rendered}");
        assert_eq!(code, UNREACHABLE);
    }
}
