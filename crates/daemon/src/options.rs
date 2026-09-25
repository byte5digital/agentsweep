//! What the daemon was started with.
//!
//! Every path the daemon touches can be named on the command line, for two
//! reasons. A test may not go near the real home, the real data directory, the
//! real socket or the login Keychain, and a developer running the daemon by
//! hand must be able to do the same. The defaults are what the shipped launch
//! agent gets, and nothing in the suite ever takes them.

use std::fmt;
use std::path::PathBuf;

use agentsweep_core::paths::DataDirectory;
use agentsweep_ipc::default_socket_path;

pub use crate::log::LogChoice;

/// The usage text, which says which flags are the developer's.
pub const USAGE: &str = "\
agentsweepd is the AgentSweep daemon. It watches the Surfaces of every Agent it
finds, runs the Scans and is the only writer of the Event Log, the Baseline, the
verdict cache and the state file.

Usage:
  agentsweepd              Run, with the data directory and socket of the
                           installed AgentSweep.
  agentsweepd --version    Print the version.
  agentsweepd --help       Print this message.

Developer only, off unless asked for by name:
  --data-dir <path>        Keep the stores here instead of in the real data
                           directory.
  --socket <path>          Listen here instead of on the documented socket.
  --home <path>            Scan this home directory instead of the real one.
                           The search path stays empty and no absolute system
                           path is read, so a fixture home reads the same
                           wherever it was copied to. A `system` directory
                           beside it stands in for the Managed layers.
  --key-source <memory>    Hold the chain key in this process instead of in the
                           login Keychain. Nothing survives the run.
  --log <stderr|file>      Write the log to the terminal, or to the rotated file
                           in ~/Library/Logs/AgentSweep. The installed daemon
                           writes the file and a developer run the terminal.
  --developer-budgets      Measure the Scan budgets of the specification
                           against this home, print them and stop. Binds no
                           socket and starts neither the watcher nor the due
                           check. Takes a data directory of its own and
                           `--key-source memory`.";

/// Where the chain key comes from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum KeySourceChoice {
    /// The item in the user's login Keychain, which is what the shipped daemon
    /// uses and the one thing that touches the Keychain at all.
    #[default]
    Keychain,
    /// A key that lives only as long as the process. For a test and for a
    /// developer's hand run, so neither goes near the real Keychain item.
    Memory,
}

impl KeySourceChoice {
    /// The spelling the flag takes.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySourceChoice::Keychain => "keychain",
            KeySourceChoice::Memory => "memory",
        }
    }

    /// Reads back that spelling.
    pub fn parse(text: &str) -> Option<KeySourceChoice> {
        match text {
            "keychain" => Some(KeySourceChoice::Keychain),
            "memory" => Some(KeySourceChoice::Memory),
            _ => None,
        }
    }
}

/// What was asked for on the command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invocation {
    /// Run the daemon.
    Run(Box<Options>),
    /// Measure the Scan budgets against this machine and stop.
    Budgets(Box<Options>),
    /// Print the version and stop.
    Version,
    /// Print the usage and stop.
    Help,
}

/// How this daemon was started.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    /// Where the stores live.
    pub data_dir: DataDirectory,
    /// Where the socket is.
    pub socket: PathBuf,
    /// The home directory to scan, absent when it is the process's own.
    pub home: Option<PathBuf>,
    /// Where the chain key comes from.
    pub key_source: KeySourceChoice,
    /// Where the log goes.
    pub log: LogChoice,
}

impl Options {
    /// What the shipped launch agent gets: the real data directory, the
    /// documented socket, the user's own home and the login Keychain.
    pub fn installed() -> Result<Options, OptionsError> {
        Ok(Options {
            data_dir: DataDirectory::for_user().ok_or(OptionsError::NoHome)?,
            socket: default_socket_path(),
            home: None,
            key_source: KeySourceChoice::Keychain,
            log: LogChoice::ByRun,
        })
    }

    /// Whether this run writes the rotated log file rather than the terminal.
    pub fn writes_the_log_file(&self) -> bool {
        self.log.writes_the_file(self.is_developer_run())
    }

    /// True when nothing about this run is the installed AgentSweep, which is
    /// what the daemon says in its first log line so that a hand run is never
    /// mistaken for the real one.
    pub fn is_developer_run(&self) -> bool {
        self.home.is_some() || self.key_source != KeySourceChoice::Keychain
    }

    /// The home directory this run scans: the one named, or the one the
    /// environment names.
    pub fn home_directory(&self) -> Result<PathBuf, OptionsError> {
        match &self.home {
            Some(home) => Ok(home.clone()),
            None => std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
                .ok_or(OptionsError::NoHome),
        }
    }
}

/// Why the command line could not be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptionsError {
    /// A flag nobody defined.
    Unknown(String),
    /// A flag that takes a value was given none.
    Missing(String),
    /// A flag was given a value it does not take.
    Bad {
        /// The flag.
        flag: String,
        /// What was given.
        value: String,
    },
    /// There is no home directory to work from.
    NoHome,
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionsError::Unknown(flag) => write!(f, "`{flag}` is not a flag"),
            OptionsError::Missing(flag) => write!(f, "`{flag}` takes a value"),
            OptionsError::Bad { flag, value } => write!(f, "`{flag}` does not take `{value}`"),
            OptionsError::NoHome => f.write_str("there is no home directory"),
        }
    }
}

impl std::error::Error for OptionsError {}

/// Reads the command line.
pub fn parse(arguments: &[String]) -> Result<Invocation, OptionsError> {
    let mut options = Options {
        data_dir: DataDirectory::at(PathBuf::new()),
        socket: default_socket_path(),
        home: None,
        key_source: KeySourceChoice::Keychain,
        log: LogChoice::ByRun,
    };
    let mut data_dir: Option<PathBuf> = None;

    let mut budgets = false;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let mut value = |flag: &str| -> Result<String, OptionsError> {
            rest.next()
                .cloned()
                .ok_or_else(|| OptionsError::Missing(flag.to_string()))
        };
        match argument.as_str() {
            "--help" | "-h" => return Ok(Invocation::Help),
            "--version" | "-V" => return Ok(Invocation::Version),
            "--developer-budgets" => budgets = true,
            "--data-dir" => data_dir = Some(PathBuf::from(value("--data-dir")?)),
            "--socket" => options.socket = PathBuf::from(value("--socket")?),
            "--home" => options.home = Some(PathBuf::from(value("--home")?)),
            "--key-source" => {
                let asked = value("--key-source")?;
                options.key_source =
                    KeySourceChoice::parse(&asked).ok_or_else(|| OptionsError::Bad {
                        flag: "--key-source".to_string(),
                        value: asked,
                    })?;
            }
            "--log" => {
                let asked = value("--log")?;
                options.log = LogChoice::parse(&asked).ok_or_else(|| OptionsError::Bad {
                    flag: "--log".to_string(),
                    value: asked,
                })?;
            }
            unknown => return Err(OptionsError::Unknown(unknown.to_string())),
        }
    }

    options.data_dir = match data_dir {
        Some(named) => DataDirectory::at(named),
        None => DataDirectory::for_user().ok_or(OptionsError::NoHome)?,
    };
    match budgets {
        true => Ok(Invocation::Budgets(Box::new(options))),
        false => Ok(Invocation::Run(Box::new(options))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    fn run(words: &[&str]) -> Options {
        match parse(&arguments(words)).expect("a readable command line") {
            Invocation::Run(options) => *options,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    #[test]
    fn a_daemon_started_with_nothing_takes_the_installed_paths() {
        let options = run(&[]);
        assert_eq!(options.socket, default_socket_path());
        assert_eq!(options.home, None);
        assert_eq!(options.key_source, KeySourceChoice::Keychain);
        assert!(!options.is_developer_run());
        assert!(options.writes_the_log_file());
        assert_eq!(options.data_dir, DataDirectory::for_user().expect("a home"));
    }

    /// Every path a test or a hand run must move is a flag, and naming one
    /// marks the run as a developer's.
    #[test]
    fn every_path_the_daemon_touches_can_be_named() {
        let options = run(&[
            "--data-dir",
            "/tmp/agentsweep-test/data",
            "--socket",
            "/tmp/agentsweep-test/sock",
            "--home",
            "/tmp/agentsweep-test/home",
            "--key-source",
            "memory",
        ]);
        assert_eq!(
            options.data_dir,
            DataDirectory::at("/tmp/agentsweep-test/data")
        );
        assert_eq!(options.socket, PathBuf::from("/tmp/agentsweep-test/sock"));
        assert_eq!(
            options.home_directory().expect("the named home"),
            PathBuf::from("/tmp/agentsweep-test/home")
        );
        assert_eq!(options.key_source, KeySourceChoice::Memory);
        assert!(options.is_developer_run());
        assert!(!options.writes_the_log_file());
    }

    /// A hand run may ask for either destination by name; the installed
    /// daemon, which names nothing, writes the file.
    #[test]
    fn the_log_goes_where_it_is_asked_to() {
        assert!(!run(&["--log", "stderr"]).writes_the_log_file());
        assert!(
            run(&["--home", "/tmp/agentsweep-test/home", "--log", "file"]).writes_the_log_file()
        );
        assert_eq!(
            parse(&arguments(&["--log", "syslog"])),
            Err(OptionsError::Bad {
                flag: "--log".to_string(),
                value: "syslog".to_string()
            })
        );
    }

    #[test]
    fn the_version_and_the_usage_are_asked_for_by_name() {
        assert_eq!(
            parse(&arguments(&["--version"])).expect("a readable command line"),
            Invocation::Version
        );
        assert_eq!(
            parse(&arguments(&["--help"])).expect("a readable command line"),
            Invocation::Help
        );
    }

    #[test]
    fn a_flag_nobody_defined_is_refused_rather_than_ignored() {
        assert_eq!(
            parse(&arguments(&["--scan-everything"])),
            Err(OptionsError::Unknown("--scan-everything".to_string()))
        );
        assert_eq!(
            parse(&arguments(&["--socket"])),
            Err(OptionsError::Missing("--socket".to_string()))
        );
        assert_eq!(
            parse(&arguments(&["--key-source", "file"])),
            Err(OptionsError::Bad {
                flag: "--key-source".to_string(),
                value: "file".to_string()
            })
        );
    }

    /// The only key source the shipped daemon has is the login Keychain, and
    /// the one that is not says so in the usage text.
    #[test]
    fn the_developer_flags_are_marked_developer_only_where_a_person_sees_them() {
        assert!(USAGE.contains("Developer only"), "{USAGE}");
        for flag in [
            "--data-dir",
            "--socket",
            "--home",
            "--key-source",
            "--log",
            "--developer-budgets",
        ] {
            assert!(USAGE.contains(flag), "{USAGE}");
        }
        assert_eq!(KeySourceChoice::default(), KeySourceChoice::Keychain);
        assert_eq!(
            KeySourceChoice::parse("memory"),
            Some(KeySourceChoice::Memory)
        );
    }
}
