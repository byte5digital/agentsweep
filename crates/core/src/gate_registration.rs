//! Writing the Gate's own entries into an Agent's user settings, and taking
//! them away again.
//!
//! The Gate is a user-scope hook in each Agent (spec section 7). Which file it
//! goes in and what an entry looks like there is Agent-specific file knowledge,
//! so it is the Surface Adapter's, behind three trait methods whose default is
//! "this Agent has no Gate" (the owner's decision of 2026-10-14, keeping ADR
//! 0002). What is the same for every Agent lives here: the command the Gate
//! runs, its timeout, what one written or removed entry is called, and the
//! compare-and-swap every write of a Surface file goes through.
//!
//! **The writer.** Only the daemon writes a Surface (spec section 6.2), so an
//! adapter never writes a file itself: it is handed a [`SurfaceWriter`], and
//! the one implementation that touches the disk, [`AtomicWriter`], exists only
//! in a build with the `daemon` feature. A test hands an adapter a writer of
//! its own, which is also how a file that changes between the read and the
//! write is proven.
//!
//! **The compare-and-swap** of spec section 5.3, for a write that adds rather
//! than takes away: [`rewrite`] reads the file, hands its text to the edit and
//! asks the writer to put the result in place only while the file still hashes
//! to what was just read. A file that moved in between is read once more and
//! edited again; a second miss fails the write with "file is changing" rather
//! than writing over somebody else's change. A file that does not exist is
//! read as absent, and the writer creates it only while it is still absent.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::entry_edit::EditError;
use crate::host::Host;
use crate::item::{ItemId, sha256_hex};

/// The `timeout` every Gate entry carries, in seconds (spec section 7.4).
pub const GATE_TIMEOUT_SECONDS: u64 = 5;

/// The command an Agent's hook runs for the Gate: the in-bundle command line
/// interface beside the daemon's own executable, never a shell line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateCommand {
    /// The absolute path of the command line interface.
    pub program: PathBuf,
}

impl GateCommand {
    /// The command at this path.
    pub fn at(program: impl Into<PathBuf>) -> GateCommand {
        GateCommand {
            program: program.into(),
        }
    }

    /// The command line interface beside the executable at `daemon`, which is
    /// where the bundle puts it.
    pub fn beside(daemon: &Path) -> Option<GateCommand> {
        Some(GateCommand::at(daemon.parent()?.join("agentsweep")))
    }

    /// The arguments the Gate runs the command with for one Agent:
    /// `gate --agent <agent id>`.
    pub fn arguments(agent: &str) -> [String; 3] {
        ["gate".to_string(), "--agent".to_string(), agent.to_string()]
    }
}

/// One Gate entry an adapter wrote or took away, named the way the Scan names
/// the Hook Item it is.
///
/// The id and the hash are what the `gate-registered` and `gate-removed`
/// events carry, so the known-action rebuild accepts exactly the Hook Item the
/// write left and the next Scan raises no Drift on it (spec sections 4.6.4 and
/// 7.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateEntry {
    /// The Hook Item, as the enumeration names it.
    pub item_id: ItemId,
    /// The entry locator: the part of the id after the kind.
    pub locator: String,
    /// The Hook Item's content hash.
    pub content_hash: String,
    /// The file the entry is written in.
    pub path: PathBuf,
}

/// What one Gate write did to an Agent's files: the entries it wrote, the
/// entries it took away, and how many pins of other groups it filed again
/// under a new key because a group ahead of them went.
///
/// A registration writes the entries an event is missing and takes away the
/// entries that carry AgentSweep's own arguments and timeout under another
/// command line interface path, so that after the bundle moved there is
/// exactly one AgentSweep entry per event (the owner's decision of
/// 2026-10-14). A removal only takes away. Codex files a pin under the
/// position of its group, so a group that goes shifts every group after it in
/// the same event; their pins are filed again under the new position with the
/// same hash, so the user's own trust survives (the owner's decision of
/// 2026-10-14).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GateWrite {
    /// The entries written.
    pub written: Vec<GateEntry>,
    /// The entries taken away.
    pub removed: Vec<GateEntry>,
    /// How many pins of groups that are not AgentSweep's were filed again
    /// under their new position.
    pub pins_rekeyed: usize,
}

impl GateWrite {
    /// True when the write changed nothing.
    pub fn is_empty(&self) -> bool {
        self.written.is_empty() && self.removed.is_empty() && self.pins_rekeyed == 0
    }
}

/// What looking at an Agent's Gate entries found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateCheck {
    /// This Agent has no Gate.
    NoGate,
    /// Every event carries AgentSweep's entry, unchanged, and no entry
    /// carries AgentSweep's arguments and timeout under another path.
    Registered,
    /// These events carry no unchanged AgentSweep entry, or carry one of
    /// AgentSweep's under another command line interface path, by the
    /// Agent's own event names.
    Missing(Vec<String>),
    /// The file the entries live in could not be read or parsed, so nothing
    /// can be said and nothing may be written over it.
    Unreadable(PathBuf),
    /// Managed policy drops the user's hooks: Claude Code's managed
    /// `allowManagedHooksOnly` or `disableAllHooks`, Codex's
    /// `allow_managed_hooks_only` in `requirements.toml` or a managed
    /// `[features] hooks = false`. Nothing is written for this Agent.
    ManagedPolicy,
    /// The user switched the Agent's hooks off in their own settings: a
    /// User-scope `disableAllHooks` in Claude Code, `[features] hooks = false`
    /// in the Codex user layer. That is the user's own choice and AgentSweep
    /// never writes it (the owner's decision of 2026-10-14); the entries
    /// themselves are still kept in place.
    SwitchedOffByUser,
}

/// Why a Gate write did not happen.
#[derive(Debug)]
pub enum GateError {
    /// This Agent has no Gate.
    NoGate,
    /// There is no configuration directory to write in.
    NoConfigDirectory,
    /// The file changed between the read and the write, twice.
    FileIsChanging {
        /// The file.
        path: PathBuf,
    },
    /// The file does not parse, or holds something other than what the entry
    /// goes in, and is never written over.
    Unparseable {
        /// The file.
        path: PathBuf,
        /// What the editor said.
        reason: String,
    },
    /// The file could not be read or written.
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        error: io::Error,
    },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::NoGate => f.write_str("this Agent has no Gate"),
            GateError::NoConfigDirectory => {
                f.write_str("there is no configuration directory to write in")
            }
            GateError::FileIsChanging { path } => {
                write!(f, "file is changing: {}", path.display())
            }
            GateError::Unparseable { path, reason } => {
                write!(f, "{} is not written over: {reason}", path.display())
            }
            GateError::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for GateError {}

/// Why one guarded write did not happen.
#[derive(Debug)]
pub enum WriteError {
    /// The file no longer hashes to what was read, or appeared or went away.
    Changed,
    /// The file could not be written.
    Io(io::Error),
}

/// How an adapter writes one Surface file whole.
pub trait SurfaceWriter {
    /// Puts `text` in place of the file at `path`, provided the file still
    /// hashes to `expected`, or is still absent when `expected` is `None`.
    fn write_if_unchanged(
        &self,
        path: &Path,
        expected: Option<&str>,
        text: &str,
    ) -> Result<(), WriteError>;
}

/// The hash a file has right now, absent when there is no file.
pub fn hash_now(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(sha256_hex(&bytes))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The writer the daemon uses: the compare against the hash just read, then a
/// temp file in the same directory, fsynced and renamed over the original
/// (spec section 5.3). A file that does not exist is created; the permission
/// bits of one that does are kept.
#[cfg(feature = "daemon")]
#[derive(Clone, Copy, Debug, Default)]
pub struct AtomicWriter;

#[cfg(feature = "daemon")]
impl SurfaceWriter for AtomicWriter {
    fn write_if_unchanged(
        &self,
        path: &Path,
        expected: Option<&str>,
        text: &str,
    ) -> Result<(), WriteError> {
        let now = hash_now(path).map_err(WriteError::Io)?;
        if now.as_deref() != expected {
            return Err(WriteError::Changed);
        }
        crate::quarantine::disk::write_atomically(path, text).map_err(WriteError::Io)
    }
}

/// What one edit of a file answers: the text to write and what to say about
/// it, `None` when there is nothing to change, or the reason it refuses.
pub type Edited<T> = Result<Option<(String, T)>, EditError>;

/// Reads one file, edits it and writes it back under the compare-and-swap,
/// reading once more when the file moved in between.
///
/// The edit is handed the text as it stands, `None` for a file that does not
/// exist, and answers with the text to write, or `None` when there is nothing
/// to change. It runs once per read, so what it decides is always decided on
/// the file as it was just read. A file that does not parse is the edit's to
/// refuse, and nothing is then written.
pub fn rewrite<T>(
    host: &Host,
    writer: &dyn SurfaceWriter,
    path: &Path,
    edit: &mut dyn FnMut(Option<&str>) -> Edited<T>,
) -> Result<Option<T>, GateError> {
    for _ in 0..2 {
        let current = match host.read(path) {
            Ok(bytes) => Some(
                String::from_utf8(bytes).map_err(|_| GateError::Unparseable {
                    path: path.to_path_buf(),
                    reason: "the file is not text".to_string(),
                })?,
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(GateError::Io {
                    path: path.to_path_buf(),
                    error,
                });
            }
        };
        let expected = current.as_deref().map(|text| sha256_hex(text.as_bytes()));
        let edited = edit(current.as_deref()).map_err(|error| GateError::Unparseable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        let Some((text, answer)) = edited else {
            return Ok(None);
        };
        match writer.write_if_unchanged(path, expected.as_deref(), &text) {
            Ok(()) => return Ok(Some(answer)),
            Err(WriteError::Changed) => continue,
            Err(WriteError::Io(error)) => {
                return Err(GateError::Io {
                    path: path.to_path_buf(),
                    error,
                });
            }
        }
    }
    Err(GateError::FileIsChanging {
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use tempfile::TempDir;

    /// A writer that changes the file under the edit a number of times before
    /// it lets a write through, which is what somebody else's write between
    /// the read and the rename looks like.
    struct Interfering {
        times: Cell<usize>,
    }

    impl SurfaceWriter for Interfering {
        fn write_if_unchanged(
            &self,
            path: &Path,
            expected: Option<&str>,
            text: &str,
        ) -> Result<(), WriteError> {
            if self.times.get() > 0 {
                self.times.set(self.times.get() - 1);
                let before = std::fs::read_to_string(path).unwrap_or_default();
                std::fs::write(path, format!("{before} ")).expect("a change");
            }
            AtomicWriter.write_if_unchanged(path, expected, text)
        }
    }

    fn appending(current: Option<&str>) -> Edited<()> {
        Ok(Some((format!("{}x", current.unwrap_or_default()), ())))
    }

    #[test]
    fn a_file_that_does_not_exist_is_created() {
        let temporary = TempDir::new().expect("a temporary directory");
        let path = temporary.path().join("settings.json");
        let host = Host::new(temporary.path().to_path_buf(), Vec::new());
        rewrite(&host, &AtomicWriter, &path, &mut appending).expect("written");
        assert_eq!(std::fs::read_to_string(&path).expect("the file"), "x");
    }

    #[test]
    fn a_file_that_moved_once_is_read_again_and_written() {
        let temporary = TempDir::new().expect("a temporary directory");
        let path = temporary.path().join("settings.json");
        std::fs::write(&path, "a").expect("a file");
        let host = Host::new(temporary.path().to_path_buf(), Vec::new());
        let writer = Interfering {
            times: Cell::new(1),
        };
        rewrite(&host, &writer, &path, &mut appending).expect("written on the second read");
        assert_eq!(std::fs::read_to_string(&path).expect("the file"), "a x");
    }

    /// Spec section 5.3: a second miss fails the write and the change that
    /// came in between stays as it was written.
    #[test]
    fn a_file_that_keeps_moving_is_never_written_over() {
        let temporary = TempDir::new().expect("a temporary directory");
        let path = temporary.path().join("settings.json");
        std::fs::write(&path, "a").expect("a file");
        let host = Host::new(temporary.path().to_path_buf(), Vec::new());
        let writer = Interfering {
            times: Cell::new(2),
        };
        let failed = rewrite(&host, &writer, &path, &mut appending);
        assert!(
            matches!(failed, Err(GateError::FileIsChanging { .. })),
            "{failed:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("the file"), "a  ");
    }

    #[test]
    fn an_edit_that_refuses_writes_nothing() {
        let temporary = TempDir::new().expect("a temporary directory");
        let path = temporary.path().join("settings.json");
        std::fs::write(&path, "{ not json").expect("a file");
        let host = Host::new(temporary.path().to_path_buf(), Vec::new());
        let refused = rewrite::<()>(&host, &AtomicWriter, &path, &mut |_| {
            Err(EditError::Unparseable("no".to_string()))
        });
        assert!(
            matches!(refused, Err(GateError::Unparseable { .. })),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the file"),
            "{ not json"
        );
    }

    #[test]
    fn the_command_sits_beside_the_daemon_and_names_the_agent() {
        let command = GateCommand::beside(Path::new(
            "/Applications/AgentSweep.app/Contents/MacOS/agentsweepd",
        ))
        .expect("a command");
        assert_eq!(
            command.program,
            PathBuf::from("/Applications/AgentSweep.app/Contents/MacOS/agentsweep")
        );
        assert_eq!(
            GateCommand::arguments("claude-code"),
            ["gate", "--agent", "claude-code"]
        );
    }
}
