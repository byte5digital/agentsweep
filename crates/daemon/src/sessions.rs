//! Whether Agent sessions appear to be running, which every action states.
//!
//! A running Claude Code session holds `~/.claude.json` in memory and writes it
//! back whole, and both Agents re-fetch plugins after a session starts, so what
//! AgentSweep took out may be in use or come back until the session restarts
//! (spec section 5.3). The user is told, and asked to restart; AgentSweep never
//! signals or stops a session itself.
//!
//! Detection is read-only and executes nothing. Claude Code keeps one file per
//! running session in `~/.claude/sessions/`, named by the process id and
//! carrying it as `pid` (`docs/research/claude-code-surfaces.md`), and a
//! session counts as live when that process exists: a `kill` with signal zero,
//! which delivers nothing and only asks whether the process is there. No
//! process listing is read and no program is run.
//!
//! Codex keeps its sessions as transcripts named by a session id, with no
//! process id on disk (`docs/research/codex-surfaces.md`), so there is nothing
//! whose liveness can be checked. An installed Codex therefore reads as
//! "could not tell", and the wording says so rather than guessing.

use std::path::Path;

use agentsweep_core::eventlog::SessionsRunning;
use agentsweep_ipc::protocol::{AgentSessions, Sessions};

/// The directory Claude Code keeps its configuration in, below the home.
const CLAUDE_CODE_DIRECTORY: &str = ".claude";

/// The directory below it that holds one file per running session.
const CLAUDE_CODE_SESSIONS: &str = "sessions";

/// The directory Codex keeps its configuration in, below the home.
const CODEX_DIRECTORY: &str = ".codex";

/// Whether sessions of either Agent appear to be running on the machine whose
/// home this is.
///
/// An Agent that is not installed says nothing either way and is left out.
pub fn detect(home: &Path) -> Sessions {
    detect_with(home, &Signal)
}

/// The same, asking a liveness check of the caller's choosing.
pub fn detect_with(home: &Path, liveness: &dyn Liveness) -> Sessions {
    let mut agents = Vec::new();
    if home.join(CLAUDE_CODE_DIRECTORY).is_dir() {
        agents.push(claude_code(home, liveness));
    }
    if home.join(CODEX_DIRECTORY).is_dir() {
        agents.push(AgentSessions {
            agent: "codex".to_string(),
            running: SessionsRunning::Unknown,
            live: 0,
        });
    }
    Sessions::of(agents)
}

/// Claude Code's sessions: every session file whose process is alive.
fn claude_code(home: &Path, liveness: &dyn Liveness) -> AgentSessions {
    let directory = home.join(CLAUDE_CODE_DIRECTORY).join(CLAUDE_CODE_SESSIONS);
    let live = match std::fs::read_dir(&directory) {
        Ok(listing) => listing
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .filter_map(|path| pid_of(&path))
            .filter(|pid| liveness.alive(*pid))
            .count(),
        // No sessions directory is no session: Claude Code writes one file per
        // session into it while the session runs.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => {
            return AgentSessions {
                agent: "claude-code".to_string(),
                running: SessionsRunning::Unknown,
                live: 0,
            };
        }
    };
    AgentSessions {
        agent: "claude-code".to_string(),
        running: match live {
            0 => SessionsRunning::No,
            _ => SessionsRunning::Yes,
        },
        live,
    }
}

/// The process id one session file names: its `pid` field, or the file's own
/// name where the field is missing. Nothing else of the file is read into
/// anything that lasts.
fn pid_of(path: &Path) -> Option<i32> {
    let from_field = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get("pid").and_then(serde_json::Value::as_i64));
    let from_name = || {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.parse::<i64>().ok())
    };
    let pid = from_field.or_else(from_name)?;
    // Zero and negative numbers name process groups to `kill`, never one
    // process, and a number past the range is not a process at all.
    i32::try_from(pid).ok().filter(|pid| *pid > 0)
}

/// Whether a process exists.
pub trait Liveness {
    /// True when a process with this id is running.
    fn alive(&self, pid: i32) -> bool;
}

/// The liveness check the shipped daemon uses: signal zero, which the kernel
/// checks and never delivers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Signal;

impl Liveness for Signal {
    fn alive(&self, pid: i32) -> bool {
        // SAFETY: `kill` with signal zero performs the existence and
        // permission check only and sends nothing. The id is a positive
        // process id, never a group.
        let answered = unsafe { libc::kill(pid, 0) };
        if answered == 0 {
            return true;
        }
        // A process of another user exists as surely as one of ours: the
        // check was refused, not answered with "no such process".
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("a temporary home")
    }

    fn session(home: &Path, name: &str, pid: i64) {
        let directory = home.join(".claude/sessions");
        std::fs::create_dir_all(&directory).expect("a sessions directory");
        std::fs::write(
            directory.join(name),
            format!("{{\"pid\": {pid}, \"sessionId\": \"demo\", \"cwd\": \"/src/demo\"}}"),
        )
        .expect("a session file");
    }

    #[test]
    fn a_session_file_naming_a_live_process_is_a_running_session() {
        let home = home();
        session(home.path(), "live.json", i64::from(std::process::id()));

        let sessions = detect(home.path());

        assert_eq!(sessions.running, SessionsRunning::Yes);
        assert_eq!(sessions.agents.len(), 1);
        assert_eq!(sessions.agents[0].live, 1);
    }

    /// A session file left behind by a session that ended names a process that
    /// no longer exists, and that is not a running session.
    #[test]
    fn a_session_file_naming_a_dead_process_is_not_a_running_session() {
        let home = home();
        // Beyond the highest process id macOS hands out.
        session(home.path(), "gone.json", 99_999_999);

        let sessions = detect(home.path());

        assert_eq!(sessions.running, SessionsRunning::No);
        assert!(sessions.sentence().starts_with("No Agent session"));
    }

    #[test]
    fn the_process_id_comes_from_the_file_name_when_the_field_is_missing() {
        let home = home();
        let directory = home.path().join(".claude/sessions");
        std::fs::create_dir_all(&directory).expect("a sessions directory");
        std::fs::write(directory.join("4242.json"), b"{}").expect("a session file");
        assert_eq!(pid_of(&directory.join("4242.json")), Some(4242));
        std::fs::write(directory.join("0.json"), b"{\"pid\": 0}").expect("a session file");
        assert_eq!(pid_of(&directory.join("0.json")), None, "zero is a group");
    }

    /// Codex names its sessions by id and keeps no process id on disk, so an
    /// installed Codex is "could not tell" rather than a guess.
    #[test]
    fn an_installed_codex_cannot_be_asked_and_says_so() {
        let home = home();
        std::fs::create_dir_all(home.path().join(".codex/sessions")).expect("a Codex home");
        std::fs::create_dir_all(home.path().join(".claude")).expect("a Claude Code home");

        let sessions = detect(home.path());

        assert_eq!(sessions.running, SessionsRunning::Unknown);
        assert!(
            sessions.sentence().contains("codex"),
            "{}",
            sessions.sentence()
        );
    }

    #[test]
    fn nothing_installed_is_nothing_running() {
        let home = home();
        let sessions = detect(home.path());
        assert_eq!(sessions.running, SessionsRunning::No);
        assert!(sessions.agents.is_empty());
    }

    /// The liveness check is a seam: what the daemon decides from it is the
    /// same whichever process happens to exist on the machine running the
    /// suite.
    #[test]
    fn the_liveness_check_decides() {
        struct Everyone;
        impl Liveness for Everyone {
            fn alive(&self, _pid: i32) -> bool {
                true
            }
        }
        let home = home();
        session(home.path(), "a.json", 99_999_999);
        assert_eq!(
            detect_with(home.path(), &Everyone).running,
            SessionsRunning::Yes
        );
    }
}
