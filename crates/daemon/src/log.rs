//! The daemon's log: `tracing` to `~/Library/Logs/AgentSweep/daemon.log`,
//! five files of five megabytes (spec section 6.9).
//!
//! A line names paths and ids and never content or a sensitive field. That
//! is a rule about what the daemon says rather than about where it goes, so it
//! is kept where each line is written, and nothing here filters.
//!
//! The shipped daemon writes the file. A developer run (one that names a home
//! or keeps its key in memory) and a run started with `--log stderr` write to
//! the standard error stream instead, so a hand run reads its own output and
//! never adds to the log of the installed AgentSweep.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// How many files the log keeps: the one being written and four before it.
pub const LOG_FILES: usize = 5;

/// How large one file grows before the log moves on to a fresh one.
pub const LOG_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// The name of the file being written.
pub const LOG_NAME: &str = "daemon.log";

/// Where the log goes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogChoice {
    /// Decided by the run: the file for the shipped daemon, the standard
    /// error stream for a developer run.
    #[default]
    ByRun,
    /// The standard error stream, whatever the run.
    Stderr,
    /// The rotated file, whatever the run.
    File,
}

impl LogChoice {
    /// Reads the value `--log` takes.
    pub fn parse(text: &str) -> Option<LogChoice> {
        match text {
            "stderr" => Some(LogChoice::Stderr),
            "file" => Some(LogChoice::File),
            _ => None,
        }
    }

    /// Whether this run writes the file, given whether it is a developer's.
    pub fn writes_the_file(self, developer_run: bool) -> bool {
        match self {
            LogChoice::ByRun => !developer_run,
            LogChoice::Stderr => false,
            LogChoice::File => true,
        }
    }
}

/// The directory the installed daemon logs to, under the given home.
pub fn log_directory(home: &Path) -> PathBuf {
    home.join("Library").join("Logs").join("AgentSweep")
}

/// A file that moves on to a fresh one once it would grow past its size,
/// keeping a fixed number of the files before it.
///
/// `daemon.log` is the one being written; `daemon.log.1` is the one before it
/// and `daemon.log.4` the oldest kept. A write that would take the file past
/// its size goes to a fresh file, whole: `tracing` hands over one line per
/// write, so no line is ever split across two files.
#[derive(Debug)]
pub struct RotatingFile {
    directory: PathBuf,
    name: String,
    limit: u64,
    files: usize,
    file: File,
    written: u64,
}

impl RotatingFile {
    /// The daemon's log in `directory`, at the documented size and count.
    pub fn daemon_log(directory: &Path) -> io::Result<RotatingFile> {
        RotatingFile::open(directory, LOG_NAME, LOG_FILE_BYTES, LOG_FILES)
    }

    /// A log named `name` in `directory` of `files` files of `limit` bytes.
    pub fn open(
        directory: &Path,
        name: &str,
        limit: u64,
        files: usize,
    ) -> io::Result<RotatingFile> {
        fs::create_dir_all(directory)?;
        let path = directory.join(name);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata()?.len();
        Ok(RotatingFile {
            directory: directory.to_path_buf(),
            name: name.to_string(),
            limit,
            files: files.max(1),
            file,
            written,
        })
    }

    /// The path of the file being written.
    pub fn path(&self) -> PathBuf {
        self.directory.join(&self.name)
    }

    fn numbered(&self, number: usize) -> PathBuf {
        self.directory.join(format!("{}.{number}", self.name))
    }

    /// Moves every kept file one number up, drops the oldest and starts a
    /// fresh file.
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let oldest = self.files - 1;
        if oldest == 0 {
            // A log of one file starts that file again.
            self.file = File::create(self.path())?;
            self.written = 0;
            return Ok(());
        }
        let _ = fs::remove_file(self.numbered(oldest));
        for number in (1..oldest).rev() {
            let from = self.numbered(number);
            if from.exists() {
                fs::rename(&from, self.numbered(number + 1))?;
            }
        }
        fs::rename(self.path(), self.numbered(1))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path())?;
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.written > 0 && self.written + buffer.len() as u64 > self.limit {
            self.rotate()?;
        }
        self.file.write_all(buffer)?;
        self.written += buffer.len() as u64;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Starts the log for this process: the rotated file in `directory`, or the
/// standard error stream when `directory` is absent. Called once, by the
/// binary; a test never starts it, so the suite writes no log at all.
pub fn start(directory: Option<&Path>) -> io::Result<()> {
    let builder = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::INFO);
    let installed = match directory {
        Some(directory) => builder
            .with_writer(Mutex::new(RotatingFile::daemon_log(directory)?))
            .try_init(),
        None => builder.with_writer(io::stderr).try_init(),
    };
    installed.map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .expect("a readable directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_documented_log_is_five_files_of_five_megabytes_under_the_logs_folder() {
        assert_eq!(LOG_FILES, 5);
        assert_eq!(LOG_FILE_BYTES, 5 * 1024 * 1024);
        assert_eq!(
            log_directory(Path::new("/Users/someone")).join(LOG_NAME),
            PathBuf::from("/Users/someone/Library/Logs/AgentSweep/daemon.log")
        );
    }

    /// Written far past its size, the log keeps exactly its count of files,
    /// none over the size, and the newest line is in the file being written.
    #[test]
    fn the_log_rotates_at_its_size_and_keeps_its_count_of_files() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let mut log =
            RotatingFile::open(directory.path(), LOG_NAME, 100, LOG_FILES).expect("a log");
        // One write per line, which is what `tracing` hands over: the
        // formatter renders the whole line before it writes any of it.
        for number in 0..200 {
            log.write_all(format!("line {number:04} of the log\n").as_bytes())
                .expect("a written line");
        }
        log.flush().expect("a flushed log");

        assert_eq!(
            files_in(directory.path()),
            vec![
                "daemon.log",
                "daemon.log.1",
                "daemon.log.2",
                "daemon.log.3",
                "daemon.log.4"
            ]
        );
        for name in files_in(directory.path()) {
            let size = fs::metadata(directory.path().join(&name))
                .expect("a file")
                .len();
            assert!(size <= 100, "{name} is {size} bytes");
        }
        let newest = fs::read_to_string(log.path()).expect("the newest file");
        assert!(newest.ends_with("line 0199 of the log\n"), "{newest}");
        let older = fs::read_to_string(directory.path().join("daemon.log.1")).expect("a file");
        assert!(older.lines().all(|line| line.starts_with("line ")));
    }

    /// A daemon that starts again appends to the file it left, and moves on
    /// once that file is full.
    #[test]
    fn a_restarted_daemon_appends_to_the_file_it_left() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        {
            let mut log = RotatingFile::open(directory.path(), LOG_NAME, 60, 3).expect("a log");
            log.write_all(b"the first start\n").expect("a line");
        }
        let mut log = RotatingFile::open(directory.path(), LOG_NAME, 60, 3).expect("a log");
        log.write_all(b"the second start\n").expect("a line");
        let text = fs::read_to_string(log.path()).expect("the log");
        assert_eq!(text, "the first start\nthe second start\n");
        log.write_all(b"a line that takes the file past its size\n")
            .expect("a line");
        assert_eq!(
            fs::read_to_string(directory.path().join("daemon.log.1")).expect("the older file"),
            "the first start\nthe second start\n"
        );
    }

    #[test]
    fn the_shipped_daemon_writes_the_file_and_a_developer_run_the_terminal() {
        assert!(LogChoice::ByRun.writes_the_file(false));
        assert!(!LogChoice::ByRun.writes_the_file(true));
        assert!(!LogChoice::Stderr.writes_the_file(false));
        assert!(LogChoice::File.writes_the_file(true));
        assert_eq!(LogChoice::parse("stderr"), Some(LogChoice::Stderr));
        assert_eq!(LogChoice::parse("file"), Some(LogChoice::File));
        assert_eq!(LogChoice::parse("syslog"), None);
    }
}
