//! `agentsweep rule-feed [on | off]`: the one Rule Feed toggle.
//!
//! The Rule Feed is one of the three requests that ever leave the machine
//! (spec section 1.1), on by default with a toggle of its own. The daemon is
//! the only process that fetches and the only one that keeps the toggle, so
//! this command is one request to it and nothing else: without an argument it
//! says where the toggle stands, with `on` or `off` it moves it.

use std::path::PathBuf;

use agentsweep_ipc::protocol::Role;
use agentsweep_ipc::{Client, ClientError};

use crate::actions::{DONE, NOT_DONE, UNREACHABLE};

/// One `rule-feed` command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// The toggle's new position, absent to read it.
    pub enabled: Option<bool>,
    /// The socket to ask at, the documented one unless named.
    pub socket: Option<PathBuf>,
}

/// Reads the command line after `rule-feed`.
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
            other => return Err(format!("`rule-feed` takes `on` or `off`, not `{other}`")),
        }
    }
    Ok(Invocation { enabled, socket })
}

/// Asks the daemon and says where the toggle stands.
pub fn run(invocation: &Invocation) -> (String, u8) {
    let connected = match &invocation.socket {
        Some(socket) => Client::connect_at(socket, Role::Cli),
        None => Client::connect(Role::Cli),
    };
    let answered = connected.and_then(|mut client| match invocation.enabled {
        None => client.rule_feed(),
        Some(enabled) => client.set_rule_feed(enabled),
    });
    match answered {
        Ok(true) => (
            "The rule feed is on: AgentSweep asks GitHub once a day whether newer rules \
             exist.\n"
                .to_string(),
            DONE,
        ),
        Ok(false) => (
            "The rule feed is off: nothing is fetched, and the rules bundled with \
             AgentSweep are in force.\n"
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
    fn the_toggle_is_read_without_an_argument_and_set_with_on_or_off() {
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
            "agentsweep-rule-feed-nobody-{}.sock",
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
